#!/usr/bin/env python3
"""Contracts that keep Windows release signing fail-closed on real signer checks."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from windows_cross_store_artifact_gate import (  # noqa: E402
    AUTHENTICODE_LEAF_CN,
    AUTHENTICODE_LEAF_O,
    OWNER_AUTHENTICODE_BLOCKED,
    OWNER_AUTHENTICODE_LEAF_SHA256,
    WindowsArtifactGateError,
    authenticode_timestamp_present,
    owner_authenticode_pin_blocked,
    _require_offline_authenticode_proof,
    _require_owner_authenticode_leaf,
)


INSTALLER = (ROOT / "installer/windows/build_installer.ps1").read_text(encoding="utf-8")
INNO_SIGN = (ROOT / "tools/windows_inno_sign.ps1").read_text(encoding="utf-8")
PREPARE = (ROOT / "tools/windows_artifact_signing_prepare.ps1").read_text(
    encoding="utf-8"
)
ZIP_BUILD = (ROOT / "installer/windows/build_zip_installer.ps1").read_text(
    encoding="utf-8"
)
MSIX = (ROOT / "installer/windows/build_store_msix.ps1").read_text(encoding="utf-8")
MSI_X64 = (ROOT / "installer/windows/build_winn3_msi.ps1").read_text(encoding="utf-8")
MSI_ARM64 = (ROOT / "installer/windows/build_winn3_msi_arm64.ps1").read_text(
    encoding="utf-8"
)
TOOLCHAIN_PINS = (ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8")
PWSH = shutil.which("pwsh")
OWNER_PLACEHOLDER = "OWNER-BLOCKED: ABSENT"
LEAF_PIN_KEY = "tools.windows_authenticode.leaf_sha256"


def load_functions(path: pathlib.Path, names: tuple[str, ...]) -> str:
    """PowerShell prelude that defines the named functions from the real file."""
    quoted = ", ".join("'" + name + "'" for name in names)
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "$__ast = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{path}', [ref]$null, [ref]$null)\n"
        f"foreach ($__name in @({quoted})) {{\n"
        "    $__predicate = { param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -ceq $__name }.GetNewClosure()\n"
        "    $__def = @($__ast.FindAll($__predicate, $true)) | Select-Object -First 1\n"
        "    if (-not $__def) { throw \"function $__name is missing\" }\n"
        "    . ([scriptblock]::Create($__def.Extent.Text))\n"
        "}\n"
    )


def load_variable(path: pathlib.Path, name: str) -> str:
    """PowerShell prelude that sets one script variable from its real assignment."""
    return (
        "$__vast = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{path}', [ref]$null, [ref]$null)\n"
        "$__assignments = @($__vast.FindAll({ param($node) $node -is "
        "[System.Management.Automation.Language.AssignmentStatementAst] -and "
        f"$node.Left.Extent.Text -ceq '${name}' }}, $true))\n"
        f"if ($__assignments.Count -ne 1) {{ throw 'expected one assignment of ${name}' }}\n"
        f"Set-Variable -Scope Script -Name '{name}' -Value "
        "(& ([scriptblock]::Create($__assignments[0].Right.Extent.Text)))\n"
    )


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


PUBLISHER_FUNCTION = "function Assert-WinsAuthenticodePublisherIdentity {"
PUBLISHER_ACCEPTED = {
    "exact": "CN=WIN'S VPN INC., O=WIN'S VPN INC.",
    "quoted": "CN=\"WIN'S VPN INC.\", O=\"WIN'S VPN INC.\"",
    "reordered": "O=WIN'S VPN INC., CN=WIN'S VPN INC.",
    "extraou": "CN=WIN'S VPN INC., O=WIN'S VPN INC., OU=\"O=Other\"",
}
PUBLISHER_REFUSED = {
    "lookalike": "CN=WIN'S VPN INC. Lookalike, O=WIN'S VPN INC.",
    "noorg": "CN=WIN'S VPN INC.",
    "nocn": "O=WIN'S VPN INC.",
    "twocn": "CN=WIN'S VPN INC., CN=Other, O=WIN'S VPN INC.",
    "samecntwice": "CN=WIN'S VPN INC., CN=WIN'S VPN INC., O=WIN'S VPN INC.",
    "twoorg": "CN=WIN'S VPN INC., O=WIN'S VPN INC., O=Other",
    "lowercase": "CN=win's vpn inc., O=win's vpn inc.",
    "lowercn": "CN=win's vpn inc., O=WIN'S VPN INC.",
    "othercn": "CN=Someone Else, O=WIN'S VPN INC.",
    "trailingspace": "CN=\"WIN'S VPN INC. \", O=WIN'S VPN INC.",
    "quotedcomma": "CN=\"WIN'S VPN INC., O=WIN'S VPN INC.\", O=Evil",
    "escapedcomma": "CN=WIN'S VPN INC.\\, O=WIN'S VPN INC.",
    # PowerShell -cne is culture-aware and treats these as equal to the name.
    "zerowidth": "CN=WIN'S VPN INC.\u200b, O=WIN'S VPN INC.\u200b",
    "softhyphen": "CN=WIN'S\u00ad VPN INC., O=WIN'S\u00ad VPN INC.",
    "bom": "CN=\ufeffWIN'S VPN INC., O=WIN'S VPN INC.",
}
PUBLISHER_FIXTURE = (
    "function New-PublisherProbe { param($Name)\n"
    "    $key = [System.Security.Cryptography.RSA]::Create(2048)\n"
    "    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("
    "$Name, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, "
    "[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)\n"
    "    return $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), "
    "[DateTimeOffset]::UtcNow.AddDays(1)) }\n"
    "function Test-Publisher { param([string]$Label, $Certificate)\n"
    "    try { Assert-WinsAuthenticodePublisherIdentity -Certificate $Certificate -Path 'p'; "
    "Write-Output \"$Label ACCEPTED\" }\n"
    "    catch { Write-Output (\"$Label REFUSED \" + ($_.Exception.Message -replace '\\s+', ' ')) } }\n"
)


def publisher_probe_script() -> str:
    lines = []
    for label, subject in {**PUBLISHER_ACCEPTED, **PUBLISHER_REFUSED}.items():
        lines.append(f"Test-Publisher '{label}' (New-PublisherProbe {ps_quote(subject)})")
    # A line break inside the CN must not forge a decoded O= line.
    lines.append(
        "$builder = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameBuilder]::new()\n"
        "$builder.AddCommonName(\"WIN'S VPN INC.`nO=WIN'S VPN INC.\")\n"
        "Test-Publisher 'newline' (New-PublisherProbe $builder.Build())"
    )
    return PUBLISHER_FIXTURE + "\n".join(lines) + "\nWrite-Output 'PUBLISHER-PROBES-DONE'\n"


def run_pwsh(script: str, tmp: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
    )


CERT_FIXTURE = (
    "$rsa = [System.Security.Cryptography.RSA]::Create(2048)\n"
    "$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("
    "'CN=Leaf Pin Probe', $rsa, "
    "[System.Security.Cryptography.HashAlgorithmName]::SHA256, "
    "[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)\n"
    "$cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), "
    "[DateTimeOffset]::UtcNow.AddDays(1))\n"
    "$sha = [System.Security.Cryptography.SHA256]::Create()\n"
    "$leaf = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-', '').ToLowerInvariant()\n"
    "function Test-Refused { param([scriptblock]$Action, [string]$Marker)\n"
    "    try { & $Action } catch {\n"
    "        if ($_.Exception.Message -notmatch $Marker) { throw \"wrong refusal: $($_.Exception.Message)\" }\n"
    "        return }\n"
    "    throw \"accepted, expected refusal matching $Marker\" }\n"
)


class WindowsReleaseSigningContractTests(unittest.TestCase):
    def test_owner_authenticode_pin_stays_blocked(self) -> None:
        self.assertEqual(OWNER_AUTHENTICODE_LEAF_SHA256, "OWNER-BLOCKED: ABSENT")
        self.assertEqual(OWNER_AUTHENTICODE_BLOCKED, "OWNER-BLOCKED: ABSENT")
        self.assertTrue(owner_authenticode_pin_blocked())
        with self.assertRaisesRegex(
            WindowsArtifactGateError,
            r"owner/environment blocker:.*OWNER-BLOCKED: ABSENT",
        ):
            _require_owner_authenticode_leaf(
                {
                    "sha256": "a" * 64,
                    "common_name": "WIN'S VPN INC.",
                    "organization": "WIN'S VPN INC.",
                    "subject": "CN=WIN'S VPN INC.",
                }
            )
        with self.assertRaisesRegex(
            WindowsArtifactGateError, "outer Authenticode verification cannot be skipped"
        ):
            _require_offline_authenticode_proof(
                None,
                {"sha256": "a" * 64},
                target_id="windows-x64-installer",
                snapshot_sha256="b" * 64,
            )

    def test_build_signing_path_has_no_owner_placeholder(self) -> None:
        for source in (INSTALLER, INNO_SIGN):
            self.assertNotIn(OWNER_PLACEHOLDER, source)
            self.assertNotIn("$OwnerAuthenticodeLeafSha256", source)
        # The optional pin key is read, never invented: the committed pin file
        # carries no value until a real certificate is measured.
        self.assertNotIn("windows_authenticode", TOOLCHAIN_PINS)
        self.assertIn(
            "Read-WinsToolchainPin -PinPath $PinPath -Key 'tools.windows_authenticode.leaf_sha256'",
            INSTALLER,
        )
        self.assertIn("@('tools', 'windows_authenticode', 'leaf_sha256')", INNO_SIGN)
        self.assertIn(
            "authenticode_leaf_sha256 = $script:AuthenticodeLeafSha256", INSTALLER
        )
        # Store-only evidence tooling outside the build path keeps its own record.
        self.assertIn(
            "owner_authenticode_leaf_sha256 = 'OWNER-BLOCKED: ABSENT'", PREPARE
        )

    def test_package_producers_carry_no_owner_placeholder(self) -> None:
        # Depends on lane WP removing the placeholder from the ZIP, MSIX and
        # both MSI producers.
        for source in (ZIP_BUILD, MSIX, MSI_X64, MSI_ARM64):
            self.assertNotIn(OWNER_PLACEHOLDER, source)

    def test_signed_candidate_is_bound_by_real_signer_checks_not_a_placeholder(
        self,
    ) -> None:
        self.assertNotIn(
            "A signed release candidate cannot be produced until the owner records the public-trust leaf SHA-256.",
            INSTALLER,
        )
        self.assertNotIn("Refusing to sign a release candidate.", INNO_SIGN)
        product = INSTALLER[
            INSTALLER.index("function Assert-ProductSignature") :
            INSTALLER.index("function Assert-SafeSigningToken")
        ]
        chain = product.index("Assert-MicrosoftTrustedRootProgramChain")
        leaf = product.index(
            "$leafSha256 = Assert-WinsAuthenticodeLeafPin -Certificate $signature.SignerCertificate"
        )
        verify = product.index("verify /pa /all /v /tw")
        recorded = product.index("$script:AuthenticodeLeafSha256 = $leafSha256")
        self.assertLess(chain, leaf)
        self.assertLess(leaf, verify)
        self.assertLess(verify, recorded)
        self.assertIn("-ExpectedLeafSha256 $WindowsAuthenticodeLeafPin -Path $Path", product)
        pin_read = INSTALLER.index(
            "$WindowsAuthenticodeLeafPin = Get-WinsAuthenticodeLeafPin"
        )
        signing_loop = INSTALLER.index("Invoke-ProductSigning -Path $binary.FullName")
        self.assertLess(pin_read, signing_loop)
        for required in (
            "WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required for a signed release.",
            "Windows release signing is required. Configure WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1.",
            "$signTool = Find-SignTool -RequireApprovedMicrosoftSignature",
        ):
            self.assertIn(required, INSTALLER)

        already_signed = INNO_SIGN.index(
            "Refusing to sign an already-signed or partially signed Inno target."
        )
        leaf_pin = INNO_SIGN.index("$leafPin = Get-WinsAuthenticodeLeafPin")
        sign = INNO_SIGN.index("& $signTool @signArgs")
        verify = INNO_SIGN.index("& $signTool @verifyArgs")
        self.assertLess(already_signed, sign)
        self.assertLess(leaf_pin, sign)
        self.assertLess(sign, verify)
        self.assertIn(
            "-ExpectedThumbprint $configuration.Thumbprint -ExpectedLeafSha256 $leafPin",
            INNO_SIGN,
        )
        self.assertIn("Thumbprint = $thumbprint", INNO_SIGN)
        self.assertNotIn("& $signTool sign /v /fd SHA256 /tr $configuration.Timestamp", INNO_SIGN)

    @unittest.skipUnless(PWSH, "pwsh is unavailable for leaf-pin probes")
    def test_installer_leaf_pin_is_optional_exact_and_well_formed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pins = pathlib.Path(tmp)
            (pins / "absent.json").write_text(TOOLCHAIN_PINS, encoding="utf-8")
            script = (
                load_functions(
                    ROOT / "installer/windows/build_installer.ps1",
                    (
                        "Read-WinsToolchainPin",
                        "Get-WinsAuthenticodeLeafPin",
                        "Get-WinsCertificateSha256",
                        "Assert-WinsAuthenticodeLeafPin",
                    ),
                )
                + CERT_FIXTURE
                + f"$dir = '{pins}'\n"
                "if ($null -ne (Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $dir 'absent.json'))) { throw 'committed pins invented a leaf pin' }\n"
                "if ((Assert-WinsAuthenticodeLeafPin -Certificate $cert -ExpectedLeafSha256 $null -Path 'p') -cne $leaf) { throw 'absent pin did not report the leaf' }\n"
                "if ((Assert-WinsAuthenticodeLeafPin -Certificate $cert -ExpectedLeafSha256 $leaf -Path 'p') -cne $leaf) { throw 'exact pin refused' }\n"
                "Test-Refused -Marker 'does not match tools.windows_authenticode.leaf_sha256' -Action { Assert-WinsAuthenticodeLeafPin -Certificate $cert -ExpectedLeafSha256 ('0' * 64) -Path 'p' }\n"
                "[IO.File]::WriteAllText((Join-Path $dir 'present.json'), ('{\"tools\":{\"windows_authenticode\":{\"leaf_sha256\":\"' + $leaf + '\"}}}'))\n"
                "if ((Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $dir 'present.json')) -cne $leaf) { throw 'present pin not read' }\n"
                "[IO.File]::WriteAllText((Join-Path $dir 'upper.json'), ('{\"tools\":{\"windows_authenticode\":{\"leaf_sha256\":\"' + $leaf.ToUpperInvariant() + '\"}}}'))\n"
                "Test-Refused -Marker '64 lowercase hex' -Action { Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $dir 'upper.json') }\n"
                "[IO.File]::WriteAllText((Join-Path $dir 'short.json'), '{\"tools\":{\"windows_authenticode\":{\"leaf_sha256\":\"abc\"}}}')\n"
                "Test-Refused -Marker '64 lowercase hex' -Action { Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $dir 'short.json') }\n"
                "Write-Output 'LEAF-PIN-PROBES-OK'\n"
            )
            completed = run_pwsh(script, tmp)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("LEAF-PIN-PROBES-OK", completed.stdout)

    @unittest.skipUnless(PWSH, "pwsh is unavailable for signer-binding probes")
    def test_inno_wrapper_binds_store_thumbprint_and_optional_leaf_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pins = pathlib.Path(tmp)
            (pins / "absent.json").write_text(TOOLCHAIN_PINS, encoding="utf-8")
            script = (
                "Set-StrictMode -Version Latest\n"
                + load_functions(
                    ROOT / "tools/windows_inno_sign.ps1",
                    ("Get-WinsAuthenticodeLeafPin", "Assert-InnoSignerBinding"),
                )
                + CERT_FIXTURE
                + f"$dir = '{pins}'\n"
                "if ($null -ne (Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $dir 'absent.json'))) { throw 'committed pins invented a leaf pin' }\n"
                "if ((Assert-InnoSignerBinding -Certificate $cert -ExpectedThumbprint $null -ExpectedLeafSha256 $null) -cne $leaf) { throw 'unpinned binding did not report the leaf' }\n"
                "[void](Assert-InnoSignerBinding -Certificate $cert -ExpectedThumbprint $cert.Thumbprint.ToUpperInvariant() -ExpectedLeafSha256 $leaf)\n"
                "Test-Refused -Marker 'WINS_WINDOWS_SIGN_CERT_SHA1 certificate' -Action { Assert-InnoSignerBinding -Certificate $cert -ExpectedThumbprint ('A' * 40) -ExpectedLeafSha256 $null }\n"
                "Test-Refused -Marker 'does not match tools.windows_authenticode.leaf_sha256' -Action { Assert-InnoSignerBinding -Certificate $cert -ExpectedThumbprint $null -ExpectedLeafSha256 ('0' * 64) }\n"
                "[IO.File]::WriteAllText((Join-Path $dir 'present.json'), ('{\"tools\":{\"windows_authenticode\":{\"leaf_sha256\":\"' + $leaf + '\"}}}'))\n"
                "if ((Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $dir 'present.json')) -cne $leaf) { throw 'present pin not read' }\n"
                "[IO.File]::WriteAllText((Join-Path $dir 'bad.json'), '{\"tools\":{\"windows_authenticode\":{\"leaf_sha256\":\"not-a-digest\"}}}')\n"
                "Test-Refused -Marker '64 lowercase hex' -Action { Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $dir 'bad.json') }\n"
                "Write-Output 'SIGNER-BINDING-PROBES-OK'\n"
            )
            completed = run_pwsh(script, tmp)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("SIGNER-BINDING-PROBES-OK", completed.stdout)

    @unittest.skipUnless(PWSH, "pwsh is unavailable for the installer signing self-test")
    def test_installer_signing_self_test_exercises_the_leaf_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                [
                    PWSH,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(ROOT / "installer/windows/build_installer.ps1"),
                    "-SelfTestSigningPolicy",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "TMPDIR": tmp, "NO_COLOR": "1"},
            )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output)
        self.assertIn("WINDOWS AUTHENTICODE LEAF PIN SELF-TEST: PASS", output)
        self.assertIn("WINDOWS SIGNING POLICY SELF-TEST: PASS", output)

    def test_committed_publisher_identity_is_one_function_in_every_signer(self) -> None:
        self.assertEqual(AUTHENTICODE_LEAF_CN, "WIN'S VPN INC.")
        self.assertEqual(AUTHENTICODE_LEAF_O, AUTHENTICODE_LEAF_CN)
        sources = {
            "build_installer": INSTALLER,
            "inno_sign": INNO_SIGN,
            "zip": ZIP_BUILD,
            "msix": MSIX,
            "msi-x64": MSI_X64,
            "msi-arm64": MSI_ARM64,
        }
        functions = {}
        for name, source in sources.items():
            with self.subTest(source=name):
                self.assertEqual(source.count(PUBLISHER_FUNCTION), 1)
                self.assertEqual(
                    source.count(
                        '$WindowsAuthenticodePublisherName = "' + AUTHENTICODE_LEAF_CN + '"\n'
                    ),
                    1,
                )
                start = source.index(PUBLISHER_FUNCTION)
                functions[name] = source[start : source.index("\n}\n", start) + 3]
        self.assertEqual(len(set(functions.values())), 1)
        body = functions["build_installer"]
        self.assertIn(
            "[string]::Equals($cn[0], $WindowsAuthenticodePublisherName, [StringComparison]::Ordinal)",
            body,
        )
        self.assertIn(
            "[string]::Equals($org[0], $WindowsAuthenticodePublisherName, [StringComparison]::Ordinal)",
            body,
        )
        self.assertNotIn("-cne $WindowsAuthenticodePublisherName", body)
        self.assertIn("$cn.Count -ne 1", body)
        self.assertIn("$org.Count -ne 1", body)

        product = INSTALLER[
            INSTALLER.index("function Assert-ProductSignature") :
            INSTALLER.index("function Assert-SafeSigningToken")
        ]
        chain = product.index("Assert-MicrosoftTrustedRootProgramChain -Certificate $signature.SignerCertificate")
        identity = product.index(
            "Assert-WinsAuthenticodePublisherIdentity -Certificate $signature.SignerCertificate -Path $Path"
        )
        leaf = product.index("$leafSha256 = Assert-WinsAuthenticodeLeafPin")
        self.assertLess(chain, identity)
        self.assertLess(identity, leaf)
        # Third-party payload verification keeps its own signer and never
        # demands the Win's VPN publisher.
        third_party = INSTALLER[
            INSTALLER.index("function Assert-AuthenticodeSigner") :
            INSTALLER.index("# BEGIN-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT")
        ]
        self.assertNotIn("Assert-WinsAuthenticodePublisherIdentity", third_party)

        inno = INNO_SIGN[
            INNO_SIGN.index("function Assert-SignedTargetPolicy") :
            INNO_SIGN.index("if ($SelfTest) {")
        ]
        chain = inno.index("Assert-MicrosoftTrustedRootProgramChain -Certificate $signer")
        identity = inno.index("Assert-WinsAuthenticodePublisherIdentity -Certificate $signer -Path $Path")
        binding = inno.index("Assert-InnoSignerBinding -Certificate $signer")
        self.assertLess(chain, identity)
        self.assertLess(identity, binding)

        for name, source in (("zip", ZIP_BUILD), ("msix", MSIX), ("msi-x64", MSI_X64), ("msi-arm64", MSI_ARM64)):
            with self.subTest(producer=name):
                verify = source[
                    source.index("function Assert-WinsProducerSignature") :
                    source.index("function Invoke-WinsProducerSigning")
                ]
                chain = verify.index(
                    "Assert-WinsProducerTrustedRootChain -Certificate $signature.SignerCertificate -Path $Path"
                )
                identity = verify.index(
                    "Assert-WinsAuthenticodePublisherIdentity -Certificate $signature.SignerCertificate -Path $Path"
                )
                verify_call = verify.index("& $SignTool verify /pa /all /v /tw $Path")
                self.assertLess(chain, identity)
                self.assertLess(identity, verify_call)

    @unittest.skipUnless(PWSH, "pwsh is unavailable for publisher-identity probes")
    def test_committed_publisher_identity_accepts_only_the_exact_cn_and_o(self) -> None:
        for path in (
            ROOT / "installer/windows/build_installer.ps1",
            ROOT / "tools/windows_inno_sign.ps1",
            ROOT / "installer/windows/build_zip_installer.ps1",
        ):
            with self.subTest(source=path.name), tempfile.TemporaryDirectory() as tmp:
                script = (
                    "Set-StrictMode -Version Latest\n"
                    + load_functions(path, ("Assert-WinsAuthenticodePublisherIdentity",))
                    + load_variable(path, "WindowsAuthenticodePublisherName")
                    + publisher_probe_script()
                )
                completed = run_pwsh(script, tmp)
                output = completed.stdout + completed.stderr
                self.assertEqual(completed.returncode, 0, output)
                self.assertIn("PUBLISHER-PROBES-DONE", output)
                for label in PUBLISHER_ACCEPTED:
                    self.assertIn(f"{label} ACCEPTED", output)
                for label in (*PUBLISHER_REFUSED, "newline"):
                    self.assertIn(
                        f"{label} REFUSED Authenticode signer of p is not the reviewed "
                        "WIN'S VPN INC. publisher",
                        output,
                    )
                    self.assertNotIn(f"{label} ACCEPTED", output)

    @unittest.skipUnless(PWSH, "pwsh is unavailable for signer-identity probes")
    def test_installer_and_inno_signature_checks_refuse_a_regex_matching_lookalike(
        self,
    ) -> None:
        # README_FINAL_DEPLOYMENT.md sets WINS_WINDOWS_SIGNER_SUBJECT_REGEX to
        # "WIN'S VPN INC\.", which a lookalike subject also matches.
        fixture = (
            "$rootKey = [System.Security.Cryptography.RSA]::Create(2048)\n"
            "$rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("
            "'CN=Probe Root', $rootKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256, "
            "[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)\n"
            "$rootRequest.CertificateExtensions.Add("
            "[System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))\n"
            "$root = $rootRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))\n"
            "function New-IssuedProbe { param([string]$Name, [byte]$Serial)\n"
            "    $key = [System.Security.Cryptography.RSA]::Create(2048)\n"
            "    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("
            "$Name, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, "
            "[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)\n"
            "    return $request.Create($root, [DateTimeOffset]::UtcNow.AddDays(-1), "
            "[DateTimeOffset]::UtcNow.AddDays(20), [byte[]](1, 2, 3, $Serial)) }\n"
            "$script:Probe = New-IssuedProbe -Name \"CN=WIN'S VPN INC., O=WIN'S VPN INC.\" -Serial 1\n"
            "$exact = $script:Probe\n"
            "$lookalike = New-IssuedProbe -Name \"CN=WIN'S VPN INC. Lookalike, O=WIN'S VPN INC.\" -Serial 2\n"
            "function Get-AuthenticodeSignature { param([string]$LiteralPath)\n"
            "    return [pscustomobject]@{ Status = [System.Management.Automation.SignatureStatus]::Valid; "
            "SignerCertificate = $script:Probe; TimeStamperCertificate = $root } }\n"
            "function Assert-MicrosoftTrustedRootProgramChain { param($Certificate, [string]$Path) }\n"
            "function probe-signtool { $global:LASTEXITCODE = 0; "
            "return 'Successfully verified: x Timestamp Verified by: probe' }\n"
            "function Test-Signer { param([string]$Label, [scriptblock]$Body)\n"
            "    try { & $Body | Out-Null; Write-Output \"$Label ACCEPTED\" }\n"
            "    catch { Write-Output (\"$Label REFUSED \" + $_.Exception.Message) } }\n"
        )
        installer = (
            "$WindowsAuthenticodeLeafPin = $null\n"
            "Test-Signer 'installer-exact' { Assert-ProductSignature -Path 'C:\\x.exe' "
            "-SignerPattern \"WIN'S VPN INC\\.\" -SignTool 'probe-signtool' }\n"
            "$script:Probe = $lookalike\n"
            "Test-Signer 'installer-lookalike' { Assert-ProductSignature -Path 'C:\\x.exe' "
            "-SignerPattern \"WIN'S VPN INC\\.\" -SignTool 'probe-signtool' }\n"
        )
        inno = (
            "Test-Signer 'inno-exact' { Assert-SignedTargetPolicy -Path 'C:\\x.exe' "
            "-SignerPattern \"WIN'S VPN INC\\.\" -ExpectedThumbprint $exact.Thumbprint -ExpectedLeafSha256 $null }\n"
            "$script:Probe = $lookalike\n"
            "Test-Signer 'inno-lookalike' { Assert-SignedTargetPolicy -Path 'C:\\x.exe' "
            "-SignerPattern \"WIN'S VPN INC\\.\" -ExpectedThumbprint $null -ExpectedLeafSha256 $null }\n"
        )
        cases = (
            (
                ROOT / "installer/windows/build_installer.ps1",
                (
                    "Assert-ProductSignature",
                    "Assert-WinsAuthenticodePublisherIdentity",
                    "Assert-WinsAuthenticodeLeafPin",
                    "Get-WinsCertificateSha256",
                ),
                installer,
                "installer",
            ),
            (
                ROOT / "tools/windows_inno_sign.ps1",
                (
                    "Assert-SignedTargetPolicy",
                    "Assert-WinsAuthenticodePublisherIdentity",
                    "Assert-InnoSignerBinding",
                ),
                inno,
                "inno",
            ),
        )
        for path, names, body, label in cases:
            with self.subTest(source=path.name), tempfile.TemporaryDirectory() as tmp:
                script = (
                    load_functions(path, names)
                    + load_variable(path, "WindowsAuthenticodePublisherName")
                    + fixture
                    + body
                )
                completed = run_pwsh(script, tmp)
                output = " ".join((completed.stdout + completed.stderr).split())
                self.assertEqual(completed.returncode, 0, output)
                self.assertIn(f"{label}-exact ACCEPTED", output)
                self.assertIn(
                    f"{label}-lookalike REFUSED Authenticode signer of C:\\x.exe is not the "
                    "reviewed WIN'S VPN INC. publisher",
                    output,
                )

    def test_timestamp_is_verified_not_inferred_from_must_sign(self) -> None:
        self.assertIn("verify /pa /all /v /tw", INSTALLER)
        self.assertIn("verify /pa /all /v /tw", INNO_SIGN)
        self.assertIn("TimeStamperCertificate", INSTALLER)
        self.assertIn(
            "timestamp_verified = [bool]$script:AuthenticodeTimestampVerified",
            INSTALLER,
        )
        self.assertNotIn("timestamp_verified = [bool]$mustSign", INSTALLER)
        self.assertIn("$script:AuthenticodeTimestampVerified = $true", INSTALLER)
        verify = INSTALLER.index("verify /pa /all /v /tw")
        recorded = INSTALLER.index(
            "$script:AuthenticodeTimestampVerified = $true", verify
        )
        self.assertLess(verify, recorded)

    def test_self_signed_and_pfx_and_private_test_roots_are_forbidden(self) -> None:
        self.assertIn(
            "A self-signed certificate is forbidden for production distribution",
            INSTALLER,
        )
        self.assertIn(
            "A self-signed certificate is forbidden for production distribution",
            INNO_SIGN,
        )
        self.assertIn("PFX command-line signing", INSTALLER)
        self.assertIn("WINS_WINDOWS_SIGN_PFX_PASSWORD", INNO_SIGN)
        self.assertIn("Private test roots are forbidden", INNO_SIGN)
        self.assertNotIn("[switch]$AllowPrivateTestRoot", INSTALLER)
        self.assertNotIn("[switch]$AllowPrivateTestRoot", INNO_SIGN)
        self.assertNotIn("AllowPrivateTestRoot", INNO_SIGN)
        self.assertIn("Accepted = $false", INSTALLER)
        self.assertNotRegex(
            INSTALLER,
            r"Oid = '1\.3\.6\.1\.5\.5\.7\.3\.3'; Accepted = \$true",
        )

    def test_artifact_signing_dlib_is_not_trusted_from_localappdata(self) -> None:
        for source in (INSTALLER, INNO_SIGN, PREPARE):
            self.assertNotRegex(
                source,
                r"LOCALAPPDATA.*ArtifactSigningClientTools",
            )
            self.assertIn("Microsoft\\ArtifactSigningClientTools\\bin", source)
        self.assertIn("LocalAppData is deliberately excluded", INSTALLER)
        self.assertIn("LocalAppData is", INNO_SIGN)
        self.assertIn("deliberately excluded", INNO_SIGN)

    def test_prepare_script_never_claims_production_signing_ready(self) -> None:
        self.assertIn("production_signing_ready = $false", PREPARE)
        self.assertNotIn("production_signing_ready = ($blockers.Count -eq 0)", PREPARE)
        self.assertNotIn("production_signing_ready = ($blockers", PREPARE)
        self.assertIn("owner_authenticode_certificate_blocked", PREPARE)
        self.assertIn("identity_validation_requires_portal", PREPARE)
        self.assertGreaterEqual(PREPARE.count("production_signing_ready = $false"), 2)
        self.assertNotRegex(PREPARE, r"production_signing_ready\s*=\s*\$true")
        self.assertIn(
            "Join-Path $env:LOCALAPPDATA 'WinsVPN\\Signing\\artifact-signing-metadata.json'",
            PREPARE,
        )
        self.assertNotIn(
            "[string]$MetadataPath = (Join-Path $env:LOCALAPPDATA",
            PREPARE,
        )

    def test_unsigned_package_receipts_do_not_print_pass(self) -> None:
        # Depends on lane WP: the ZIP, MSIX and both MSI producers sign when a
        # signing identity is configured and otherwise label the output an
        # unsigned rehearsal. Neither path prints PASS, and the receipt's
        # timestamp_verified follows the real signature result.
        self.assertIn("ZIP BUILD: UNSIGNED REHEARSAL", ZIP_BUILD)
        self.assertNotIn("ZIP BUILD: PASS", ZIP_BUILD)
        self.assertIn("timestamp_verified = $zipSigned", ZIP_BUILD)
        self.assertIn(
            "$msixAuthenticodeStatus = if ($msixSigned) { 'signed' } else { 'unsigned' }",
            MSIX,
        )
        self.assertNotIn("WINDOWS STORE MSIX CANDIDATE: PASS", MSIX)
        self.assertIn("timestamp_verified = $msixSigned", MSIX)
        self.assertIn("WINN3 MSI BUILD: UNSIGNED REHEARSAL", MSI_X64)
        self.assertNotIn("MSI BUILD: PASS", MSI_X64)
        self.assertIn("WINN3 ARM64 MSI BUILD: UNSIGNED REHEARSAL", MSI_ARM64)
        self.assertNotIn("MSI BUILD: PASS", MSI_ARM64)
        for source in (MSI_X64, MSI_ARM64):
            self.assertIn("timestamp_verified = $msiSigned", source)
        for source in (ZIP_BUILD, MSIX, MSI_X64, MSI_ARM64):
            self.assertNotIn("timestamp_verified = $false", source)
            self.assertNotIn(OWNER_PLACEHOLDER, source)

    def test_msi_receipts_bind_staged_payload_hashes(self) -> None:
        for source in (MSI_X64, MSI_ARM64):
            self.assertIn("$entries = @()", source)
            self.assertIn("payload = @($entries)", source)
            entries = source.index("$entries += [ordered]@{ name = $f.Name")
            receipt = source.index("payload = @($entries)")
            self.assertLess(entries, receipt)

    def test_timestamp_attribute_presence_is_not_cryptographic_proof(self) -> None:
        self.assertFalse(
            authenticode_timestamp_present("wins_vpn.exe", b"MZ" + b"\x00" * 64)
        )

    def test_timestamp_policy_is_an_exact_allowlist(self) -> None:
        self.assertIn("http://timestamp.acs.microsoft.com", INNO_SIGN)
        self.assertIn("http://timestamp.digicert.com", INNO_SIGN)
        self.assertIn("https://timestamp.digicert.com", INNO_SIGN)
        self.assertNotIn("$configuration.Timestamp -notmatch '^https://'", INNO_SIGN)
        self.assertIn("Assert-ApprovedTimestampUrl", INNO_SIGN)
        self.assertIn("https://evil.example/ts /f C:\\pwn.pfx", INNO_SIGN)

    def test_inno_target_identity_refuses_engines_and_unsigned_local_names(self) -> None:
        for name in (
            "amneziawg.exe",
            "awg.exe",
            "xray.exe",
            "wins_vpn.exe",
            "wins_vpn_tunnel_service.exe",
            "winn.exe",
            "winn3.exe",
            "WinsVPN-UNSIGNED-LOCAL-Setup.exe",
        ):
            self.assertIn(name, INNO_SIGN)
        for name in (
            "WinsVPN-Setup.exe",
            "WinsVPN-Setup-arm64.exe",
            "WinsVPN-PartnerCenter.exe",
            "WinsVPN-PartnerCenter-arm64.exe",
            "uninst.e32.tmp",
        ):
            self.assertIn("'" + name + "'", INNO_SIGN)
        self.assertIn("Inno signing target is not a PE MZ image.", INNO_SIGN)
        self.assertIn("regular non-reparse file", INNO_SIGN)

    def test_partial_signing_and_post_sign_verification_are_fail_closed(self) -> None:
        self.assertIn("/as", INNO_SIGN)
        self.assertIn("SignTool argument $forbidden is forbidden for release signing.", INNO_SIGN)
        self.assertIn("'/as'", INNO_SIGN)
        self.assertNotRegex(INNO_SIGN, r"(?m)^\s*& \$signTool .* /as")
        self.assertIn("TimeStamperCertificate", INNO_SIGN)
        self.assertIn("Get-AuthenticodeSignature is required for post-sign verification.", INNO_SIGN)
        self.assertIn("partially signed artifact is not shippable", INNO_SIGN)
        self.assertNotIn("CreateFromSignedFile", INNO_SIGN)
        self.assertIn("SelfTest cannot be combined with -TargetFile.", INNO_SIGN)
        target = INNO_SIGN.index("$target = Assert-Target -Path $TargetFile")
        pin = INNO_SIGN.index("$leafPin = Get-WinsAuthenticodeLeafPin")
        self.assertLess(target, pin)

    def test_prepare_output_identity_is_jailed_and_round_tripped(self) -> None:
        self.assertIn("Assert-SigningStatePath", PREPARE)
        self.assertIn("LOCALAPPDATA\\WinsVPN\\Signing", PREPARE)
        self.assertIn("UserInfo", PREPARE)
        self.assertIn("artifact-signing-metadata.json", PREPARE)
        self.assertIn("artifact-signing-status.json", PREPARE)
        self.assertIn("round-trip identity mismatch", PREPARE)
        self.assertIn("must be distinct files", PREPARE)
        self.assertIn("https://evil:pw@eus.codesigning.azure.net", PREPARE)
        self.assertIn("Find-PrepareSignTool", PREPARE)
        self.assertNotIn("Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\\10\\bin')", PREPARE)

    def test_powershell_selftests_reject_hostile_inputs(self) -> None:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            self.skipTest("pwsh is unavailable for signing-wrapper self-tests")
        for script in (
            ROOT / "tools/windows_inno_sign.ps1",
            ROOT / "tools/windows_artifact_signing_prepare.ps1",
        ):
            completed = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-File", str(script), "-SelfTest"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=completed.stdout + completed.stderr,
            )

        with tempfile.TemporaryDirectory() as tmp:
            engine = pathlib.Path(tmp) / "amneziawg.exe"
            engine.write_bytes(b"MZ" + (b"\x00" * 64))
            setup = pathlib.Path(tmp) / "WinsVPN-Setup.exe"
            setup.write_bytes(b"MZ" + (b"\x00" * 64))
            mutex = subprocess.run(
                [
                    shell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(ROOT / "tools/windows_inno_sign.ps1"),
                    "-SelfTest",
                    "-TargetFile",
                    str(setup),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(mutex.returncode, 0)
            self.assertIn("SelfTest cannot be combined with -TargetFile", mutex.stderr + mutex.stdout)

            engine_sign = subprocess.run(
                [
                    shell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(ROOT / "tools/windows_inno_sign.ps1"),
                    "-TargetFile",
                    str(engine),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(engine_sign.returncode, 0)
            combined = engine_sign.stderr + engine_sign.stdout
            self.assertRegex(combined, r"engine/product payload|amneziawg\.exe")
            self.assertNotIn("WINDOWS INNO SIGNING WRAPPER SELF-TEST: PASS", combined)

            setup_sign = subprocess.run(
                [
                    shell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(ROOT / "tools/windows_inno_sign.ps1"),
                    "-TargetFile",
                    str(setup),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(setup_sign.returncode, 0)
            setup_out = setup_sign.stderr + setup_sign.stdout
            # No placeholder refusal: the run reaches the next real check,
            # which refuses here because no signer is available (macOS has no
            # Get-AuthenticodeSignature; Windows has no signer regex set).
            self.assertNotIn(OWNER_PLACEHOLDER, setup_out)
            self.assertNotIn("Refusing to sign a release candidate", setup_out)
            self.assertRegex(
                setup_out,
                r"Get-AuthenticodeSignature is required before release signing"
                r"|WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required",
            )


if __name__ == "__main__":
    unittest.main()
