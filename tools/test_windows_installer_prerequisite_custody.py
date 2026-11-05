#!/usr/bin/env python3
"""Fail-closed contracts for Windows elevated embedded-prerequisite byte custody."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER_PATH = ROOT / "installer/windows/build_installer.ps1"
INNO_PATH = ROOT / "installer/windows/winsvpn.iss"
PRODUCER = PRODUCER_PATH.read_text(encoding="utf-8")
INNO = INNO_PATH.read_text(encoding="utf-8")
PWSH = shutil.which("pwsh") or shutil.which("powershell")
BEGIN = "# BEGIN-WINDOWS-EMBEDDED-PREREQUISITE-CUSTODY"
END = "# END-WINDOWS-EMBEDDED-PREREQUISITE-CUSTODY"
SECRET_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "password=",
    "AccessToken",
    "WINS_WINDOWS_SIGN_PFX_PASSWORD",
)


def section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin)]


class WindowsInstallerPrerequisiteCustodySourceTests(unittest.TestCase):
    def test_prerequisites_are_bound_by_in_script_pins_not_sidecars(self) -> None:
        deps = ROOT / "installer/windows/dependencies"
        for name in (
            "VC_redist.x64.exe.provenance.json",
            "VC_redist.arm64.exe.provenance.json",
            "amneziawg-amd64.msi.provenance.json",
            "amneziawg-arm64.msi.provenance.json",
        ):
            self.assertFalse(
                (deps / name).exists(),
                f"{name} is not part of the custody contract; do not invent it",
            )
        custody = section(PRODUCER, BEGIN, END)
        self.assertNotIn("provenance", custody.lower())
        self.assertNotIn("owner-blocked", custody)
        self.assertNotIn("-ProvenancePath $VcRedistProvenance", PRODUCER)
        self.assertNotIn("-ProvenancePath $AmneziaWgMsiProvenance", PRODUCER)
        for pin in (
            "$VcRedistSha256 = @{",
            "$AmneziaWgSha256 = @{",
            '$VcRedistVersion = "14.44.35211.0"',
        ):
            self.assertIn(pin, PRODUCER)
        self.assertGreaterEqual(
            PRODUCER.count("-ExpectedSha256 $VcRedistSha256"), 3
        )
        self.assertGreaterEqual(
            PRODUCER.count("-ExpectedSha256 $AmneziaWgSha256"), 3
        )

    def test_producer_never_downloads_vc_redist_or_amnezia_msi(self) -> None:
        self.assertNotIn("Get-VerifiedDownload -Uri $VcRedistUrl", PRODUCER)
        self.assertNotIn("Get-VerifiedDownload -Uri $AmneziaWgUrl", PRODUCER)
        self.assertNotIn("Save-Download -Uri $VcRedistUrl", PRODUCER)
        self.assertNotIn("Save-Download -Uri $AmneziaWgUrl", PRODUCER)
        self.assertIn("SkipRuntimeDownload never fetches VC_redist", PRODUCER)
        self.assertNotIn("$VcRedistProvenance =", PRODUCER)
        self.assertNotIn("$AmneziaWgMsiProvenance =", PRODUCER)

    def test_staging_binds_regular_single_link_bytes_and_reverifies_before_iscc(
        self,
    ) -> None:
        custody = section(PRODUCER, BEGIN, END)
        for marker in (
            "reparse point rejected",
            "hardlink refused",
            "NumberOfLinks",
            "Get-WinsBoundedRegularFile",
            "Copy-WinsExactRegularFile",
            "Assert-WinsEmbeddedPrerequisiteCustody",
            "Assert-WinsPrerequisiteAuthenticodeSigner",
            "Assert-WinsPrerequisiteVcMetadata",
            "Assert-WinsPrerequisiteMsiMetadata",
            "architecture",
            "function Assert-WinsPrerequisitePin",
            "stale $Kind prerequisite bytes do not match the pinned SHA-256",
            "outside the accepted range",
        ):
            self.assertIn(marker, custody)
        self.assertNotIn("owner-blocked", custody)
        self.assertIn("Copy-WinsExactRegularFile -Source $entry.Value", PRODUCER)
        self.assertIn(
            "Re-verifying embedded prerequisite custody against the pinned SHA-256 after copy",
            PRODUCER,
        )
        self.assertIn(
            "Re-verifying embedded prerequisite custody immediately before ISCC",
            PRODUCER,
        )
        before_iscc = PRODUCER[
            PRODUCER.index("Re-verifying embedded prerequisite custody immediately before ISCC") :
            PRODUCER.index("& $iscc @innoArguments")
        ]
        self.assertIn("Assert-WinsEmbeddedPrerequisiteCustody", before_iscc)
        self.assertIn("/DVcRedistExpectedSha256=", before_iscc)
        self.assertIn("/DVcRedistExpectedBytes=", before_iscc)
        self.assertIn("/DVcRedistExpectedPublisher=", before_iscc)
        self.assertIn("/DVcRedistExpectedVersion=", before_iscc)
        self.assertIn("/DVcRedistExpectedArchitecture=", before_iscc)
        self.assertIn("/DAmneziaWgMsiExpectedSha256=", before_iscc)
        self.assertIn("/DAmneziaWgMsiExpectedBytes=", before_iscc)
        self.assertIn("/DAmneziaWgMsiExpectedPublisher=", before_iscc)
        self.assertIn("/DAmneziaWgMsiExpectedVersion=", before_iscc)
        self.assertIn("/DAmneziaWgMsiExpectedArchitecture=", before_iscc)
        self.assertLess(
            before_iscc.index("/DVcRedistExpectedSha256="),
            before_iscc.index("$innoArguments += $InnoScript"),
        )

    def test_installer_encodes_identities_without_secrets_or_empty_defaults(self) -> None:
        for name in (
            "VcRedistExpectedSha256",
            "VcRedistExpectedBytes",
            "VcRedistExpectedPublisher",
            "VcRedistExpectedVersion",
            "VcRedistExpectedArchitecture",
            "AmneziaWgMsiExpectedSha256",
            "AmneziaWgMsiExpectedBytes",
            "AmneziaWgMsiExpectedPublisher",
            "AmneziaWgMsiExpectedVersion",
            "AmneziaWgMsiExpectedArchitecture",
        ):
            self.assertIn(f'#error "{name} is required.', INNO)
            self.assertNotIn(f'#define {name} ""', INNO)
        for secret in SECRET_MARKERS:
            self.assertNotIn(secret, INNO)
            self.assertNotIn(secret, section(PRODUCER, BEGIN, END))

    def test_inno_setup_loader_is_the_64_bit_loader_the_release_freeze_requires(self) -> None:
        # Without [Setup] SetupArchitecture=x64, ISCC 7.1.0 embeds Setup.e32 and the
        # installer is a 32-bit PE (machine 0x14c), which finish-build refuses.
        setup_section = re.search(r"(?ms)^\[Setup\]\n(.*?)^\[", INNO)
        self.assertIsNotNone(setup_section)
        self.assertEqual(
            re.findall(r"(?m)^SetupArchitecture=(.*)$", setup_section.group(1)), ["x64"]
        )

    def test_arm64_installer_refuses_windows_before_11_and_x64_does_not(self) -> None:
        # The ARM64 installer carries the x64 Inno loader (Inno Setup 7.1.0 has no ARM64
        # loader), which Windows 10 on ARM cannot run at all. MinVersion makes Setup refuse
        # cleanly wherever the loader starts; the x64 installer keeps no such floor.
        setup_section = re.search(r"(?ms)^\[Setup\]\n(.*?)^\[", INNO).group(1)
        branch = re.search(r"(?ms)^#ifdef Arm64Build\n(.*?)^#endif\n", setup_section)
        self.assertIsNotNone(branch)
        self.assertEqual(re.findall(r"(?m)^MinVersion=(.*)$", branch.group(1)), ["10.0.22000"])
        self.assertEqual(re.findall(r"(?m)^MinVersion=", setup_section), ["MinVersion="])
        checklist = (ROOT / "docs/CROSS_STORE_RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
        readiness = (ROOT / "docs/DESKTOP_STORE_RELEASE_READINESS.md").read_text(encoding="utf-8")
        self.assertIn("The ARM64 installer is Windows 11 only.", checklist)
        self.assertIn("MinVersion=10.0.22000", checklist)
        self.assertIn("needs Windows 11", readiness)

    def test_inno_file_size_calls_use_the_two_argument_form(self) -> None:
        # Inno Setup's FileSize is FileSize(Name, var Size): Boolean. The one-argument
        # form aborts ISCC 7.1.0 with "Invalid number of parameters" at [Code] compile.
        calls = re.findall(r"\bFileSize\(([^()]*)\)", INNO)
        self.assertGreaterEqual(len(calls), 2)
        for arguments in calls:
            self.assertEqual(arguments.count(","), 1, arguments)

    def test_prepare_to_install_refuses_corruption_before_any_elevated_exec(self) -> None:
        prepare = section(
            INNO,
            "function PrepareToInstall(var NeedsRestart: Boolean): String;",
            "procedure CurStepChanged(CurStep: TSetupStep);",
        )
        extract = section(
            INNO,
            "function ExtractVerifiedEmbeddedPrerequisite",
            "function EmbeddedPrerequisiteMatchesExpected",
        )
        verify_script = section(
            INNO,
            "function WritePrerequisiteVerifierScript",
            "function PrepareToInstall",
        )
        self.assertIn("CompareText(ExtractedSha256, ExpectedSha256)", extract)
        self.assertIn("FileSize(ExtractedPath, ExtractedBytes) or (ExtractedBytes <> ExpectedBytes)", extract)
        self.assertNotIn("Exec(", extract)
        hash_check = prepare.index("ExtractVerifiedEmbeddedPrerequisite(")
        identity = prepare.index("VerifyEmbeddedPrerequisiteIdentity(")
        vc_exec = prepare.index("'/install /quiet /norestart'")
        msi_exec = prepare.index("'/i \"' + AmneziaMsiPath +")
        self.assertLess(hash_check, identity)
        self.assertLess(identity, vc_exec)
        self.assertLess(identity, msi_exec)
        self.assertLess(
            prepare.index("EmbeddedPrerequisiteMatchesExpected("),
            vc_exec,
        )
        self.assertLess(
            prepare.rindex("EmbeddedPrerequisiteMatchesExpected("),
            msi_exec,
        )
        self.assertIn("Get-AuthenticodeSignature", verify_script)
        self.assertIn("verification tooling is missing", verify_script)
        self.assertIn("wrong Authenticode signer, version", verify_script)
        self.assertIn("or architecture, or verification tooling failed", verify_script)
        self.assertIn("{sys}\\WindowsPowerShell\\v1.0\\powershell.exe", verify_script)
        self.assertNotIn("Invoke-WebRequest", INNO)
        self.assertNotIn("DownloadTemporaryFile", INNO)

    def test_verification_failure_cannot_silently_skip_to_exec(self) -> None:
        verify = section(
            INNO,
            "function VerifyEmbeddedPrerequisiteIdentity",
            "function ValidateStagedTunnelManager",
        )
        self.assertIn("Result := False;", verify)
        self.assertIn("Prerequisite verification tooling failed to start.", verify)
        self.assertNotRegex(verify, r"Result := True;\s*exit;")
        self.assertLess(verify.index("if ResultCode <> 0 then"), verify.rindex("Result := True;"))
        prepare = section(
            INNO,
            "function PrepareToInstall(var NeedsRestart: Boolean): String;",
            "procedure CurStepChanged(CurStep: TSetupStep);",
        )
        self.assertEqual(prepare.count("ExtractVerifiedEmbeddedPrerequisite("), 2)
        self.assertGreaterEqual(prepare.count("VerifyEmbeddedPrerequisiteIdentity("), 2)
        self.assertIn("The embedded VC runtime prerequisite changed before execution.", prepare)
        self.assertIn("The embedded AmneziaWG MSI prerequisite changed before execution.", prepare)


@unittest.skipUnless(PWSH, "pwsh is unavailable for live custody probes")
class WindowsInstallerPrerequisiteCustodyLiveTests(unittest.TestCase):
    def test_powershell_parse_and_self_test_refuse_adversarial_fixtures(self) -> None:
        parsed = subprocess.run(
            [
                PWSH,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "$errors = $null; "
                    "[void][Management.Automation.Language.Parser]::ParseFile("
                    f"'{PRODUCER_PATH}', [ref]$null, [ref]$errors); "
                    "if ($errors -and $errors.Count -gt 0) { "
                    "$errors | ForEach-Object { $_.ToString() } | Write-Output; exit 1 }"
                ),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(parsed.returncode, 0, parsed.stdout + parsed.stderr)

        completed = subprocess.run(
            [
                PWSH,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(PRODUCER_PATH),
                "-SelfTestPrerequisiteCustody",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output)
        self.assertIn("WINDOWS EMBEDDED PREREQUISITE CUSTODY SELF-TEST: PASS", output)
        self.assertNotIn("silently skipped", output)

    def test_custody_compares_bytes_to_the_pin_without_any_sidecar(self) -> None:
        custody = section(PRODUCER, BEGIN, END)
        vc_pin = re.search(
            r"\$VcRedistSha256 = @\{\s*'x64' = '([0-9a-f]{64})'", PRODUCER
        )
        self.assertIsNotNone(vc_pin)
        with tempfile.TemporaryDirectory(prefix="winsvpn-prereq-pin-") as raw:
            root = pathlib.Path(raw)
            (root / "custody.ps1").write_text(custody, encoding="utf-8")
            fixture = root / "VC_redist.x64.exe"
            fixture.write_bytes(b"winsvpn-prereq-pin-probe")
            digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
            committed = ROOT / "installer/windows/dependencies/VC_redist.x64.exe"
            common = (
                "-Kind 'vc_redist' -ExpectedVersion '14.44.35211.0' "
                "-ExpectedArchitecture 'x64' -ExpectedFileName 'VC_redist.x64.exe' "
                "-ExpectedPublisherPattern 'CN=Microsoft Corporation' "
                "-ExpectedOriginalFileName 'VC_redist.x64.exe' "
                "-ExpectedProductName 'Microsoft Visual C++ 2015-2022 Redistributable (x64)' "
            )
            script = (
                "$ErrorActionPreference = 'Stop'\n"
                f". '{root / 'custody.ps1'}'\n"
                "function Probe { param([string]$Name, [scriptblock]$Action)\n"
                "    try { [void](& $Action); Write-Output \"$Name|accepted\" }\n"
                "    catch { Write-Output (\"$Name|refused|\" + $_.Exception.Message) } }\n"
                f"Probe 'match' {{ Assert-WinsEmbeddedPrerequisiteCustody {common}-Path '{fixture}' -ExpectedSha256 '{digest}' -MaximumBytes 4096 }}\n"
                f"Probe 'mismatch' {{ Assert-WinsEmbeddedPrerequisiteCustody {common}-Path '{fixture}' -ExpectedSha256 '{'0' * 64}' -MaximumBytes 4096 }}\n"
                f"Probe 'oversize' {{ Assert-WinsEmbeddedPrerequisiteCustody {common}-Path '{fixture}' -ExpectedSha256 '{digest}' -MaximumBytes 4 }}\n"
                f"Probe 'committed' {{ Assert-WinsEmbeddedPrerequisiteCustody {common}-Path '{committed}' -ExpectedSha256 '{vc_pin.group(1)}' -MaximumBytes 104857600 }}\n"
            )
            completed = subprocess.run(
                [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                cwd=raw,
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "NO_COLOR": "1"},
            )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output)
        results = {}
        for line in completed.stdout.splitlines():
            name, _, rest = line.partition("|")
            if name in ("match", "mismatch", "oversize", "committed"):
                results[name] = rest
        self.assertEqual(set(results), {"match", "mismatch", "oversize", "committed"}, output)
        for name, outcome in results.items():
            self.assertNotRegex(outcome, r"(?i)provenance|owner", f"{name}: {outcome}")
        # Pinned bytes pass the pin and reach the real identity checks
        # (VERSIONINFO first; this fixture is not a Microsoft PE).
        self.assertRegex(results["match"], r"wrong prerequisite version")
        self.assertRegex(results["mismatch"], r"stale vc_redist prerequisite bytes do not match the pinned SHA-256")
        self.assertRegex(results["oversize"], r"refused")
        # The committed VC_redist matches its pin: any refusal comes from a
        # later identity check, never from the pin or a missing sidecar.
        self.assertNotRegex(results["committed"], r"stale|pinned SHA-256")

    def test_prerequisite_signer_subject_must_match_the_reviewed_publisher(
        self,
    ) -> None:
        # The signer is checked against the reviewed publisher pattern itself,
        # not against a sidecar copy of the subject.
        custody = section(PRODUCER, BEGIN, END)
        with tempfile.TemporaryDirectory(prefix="winsvpn-prereq-signer-") as raw:
            root = pathlib.Path(raw)
            (root / "custody.ps1").write_text(custody, encoding="utf-8")
            script = (
                "$ErrorActionPreference = 'Stop'\n"
                f". '{root / 'custody.ps1'}'\n"
                "$script:ProbeSubject = ''\n"
                "function Assert-AuthenticodeSigner { param($Path, $SignerPattern) }\n"
                "function Get-AuthenticodeSignature { param($LiteralPath)\n"
                "    [pscustomobject]@{ SignerCertificate = [pscustomobject]@{ Subject = $script:ProbeSubject } } }\n"
                "function Probe { param([string]$Name, [string]$Subject)\n"
                "    $script:ProbeSubject = $Subject\n"
                "    try { $r = Assert-WinsPrerequisiteAuthenticodeSigner -Path 'x' -PublisherPattern 'CN=Microsoft Corporation'\n"
                "          Write-Output \"$Name|accepted|$r\" }\n"
                "    catch { Write-Output (\"$Name|refused|\" + $_.Exception.Message) } }\n"
                "Probe 'microsoft' 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'\n"
                "Probe 'other' 'CN=Contoso Ltd, O=Contoso Ltd, C=US'\n"
                "Probe 'empty' ''\n"
            )
            completed = subprocess.run(
                [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                cwd=raw,
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "NO_COLOR": "1"},
            )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output)
        results = {}
        for line in completed.stdout.splitlines():
            name, _, rest = line.partition("|")
            if name in ("microsoft", "other", "empty"):
                results[name] = rest
        self.assertEqual(set(results), {"microsoft", "other", "empty"}, output)
        self.assertRegex(results["microsoft"], r"^accepted\|CN=Microsoft Corporation, O=Microsoft")
        self.assertRegex(results["other"], r"^refused\|wrong Authenticode signer")
        self.assertRegex(results["empty"], r"^refused\|wrong Authenticode signer")


if __name__ == "__main__":
    unittest.main()
