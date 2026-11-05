#!/usr/bin/env python3
"""Adversarial contracts for signed Inno staging vs withdrawn Mullvad payloads."""

from __future__ import annotations

import hashlib
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "installer/windows/build_installer.ps1"
INNO_SCRIPT = ROOT / "installer/windows/winsvpn.iss"
DEPENDENCIES = ROOT / "installer/windows/dependencies"
PWSH = shutil.which("pwsh") or shutil.which("powershell")

WITHDRAWN_MULLVAD_SHA256 = {
    "mullvad-split-tunnel.sys": "10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201",
    "mullvad-split-tunnel.cat": "c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d",
    "mullvad-split-tunnel.inf": "3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608",
    "mullvad-split-tunnel-arm64.sys": "6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534",
    "mullvad-split-tunnel-arm64.cat": "c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce",
    "mullvad-split-tunnel-arm64.inf": "0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1",
}

HARNESS = r"""
param(
    [string]$BuildScript,
    [string]$ReleaseRoot,
    [string]$DependenciesRoot
)
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $BuildScript, [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @(
    'Get-ValidatedInnoContainerRoot',
    'Assert-InnoNoReparsePointChain',
    'Get-ContainedInnoStagingFiles',
    'Assert-InnoStagingPayloadAllowed',
    'Assert-InnoStagingPayloadHashAllowed',
    'Assert-InnoStagingContainsNoWithdrawnMullvadPayloads'
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
    'affectedSplitTunnelDriverNames',
    'ForbiddenInnoMullvadPayloadLeafPrefixes',
    'ForbiddenInnoMullvadPayloadExtensions',
    'ForbiddenInnoMullvadPayloadSha256'
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
Assert-InnoStagingContainsNoWithdrawnMullvadPayloads `
    -Roots @($ReleaseRoot, $DependenciesRoot) `
    -Label 'Windows Inno source directory'
"""


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsInnoWithdrawnMullvadSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = BUILD_SCRIPT.read_text(encoding="utf-8")
        cls.inno = INNO_SCRIPT.read_text(encoding="utf-8")

    def test_reviewed_x64_and_arm64_identities_are_exclusion_hashes(self) -> None:
        for name, digest in WITHDRAWN_MULLVAD_SHA256.items():
            self.assertIn(digest, self.builder)
            path = DEPENDENCIES / name
            if path.is_file():
                self.assertEqual(sha256_file(path), digest)
        self.assertIn("$ForbiddenInnoMullvadPayloadSha256 = @(", self.builder)
        self.assertNotIn("SplitTunnelDriverArm64Sha256", self.builder)
        pins = self.builder[
            self.builder.index("$AmneziaWgSha256 =") : self.builder.index(
                "$affectedSplitTunnelDriverNames = @("
            )
        ]
        for digest in WITHDRAWN_MULLVAD_SHA256.values():
            self.assertNotIn(digest, pins)

    def test_recursive_sourcedir_is_why_the_producer_must_scan(self) -> None:
        self.assertIn("recursesubdirs createallsubdirs", self.inno)
        self.assertIn("Source: \"{#SourceDir}\\*\"", self.inno)
        self.assertIn(
            "withdrawn kernel split-tunnel SYS/CAT/INF bytes",
            self.inno,
        )
        for name in WITHDRAWN_MULLVAD_SHA256:
            self.assertNotIn(name, self.inno)

    def test_upgrade_deletes_only_exact_withdrawn_files_from_owned_roots(self) -> None:
        install_delete = self.inno[
            self.inno.index("[InstallDelete]") : self.inno.index("[Files]")
        ]
        stem = "{#WithdrawnMullvadSplitTunnelStem}"
        roots = ("{app}", "{autopf}\\WinsVPN")
        suffixes = (".sys", ".cat", ".inf", "-arm64.sys", "-arm64.cat", "-arm64.inf")
        expected = {
            f'Type: files; Name: "{root}\\{stem}{suffix}"'
            for root in roots
            for suffix in suffixes
        }
        entries = {
            line.strip()
            for line in install_delete.splitlines()
            if line.strip().startswith("Type:")
        }
        self.assertEqual(entries, expected)
        self.assertEqual(
            self.inno.count(
                '#define WithdrawnMullvadSplitTunnelStem "mullvad-split-tunnel"'
            ),
            1,
        )
        for unsafe in ("Type: filesandordirs", "Type: dirifempty", "*", "?"):
            self.assertNotIn(unsafe, install_delete)

        prepare = self.inno[
            self.inno.index("function PrepareToInstall(") : self.inno.index(
                "procedure RaiseFatalPostInstallException(",
            )
        ]
        self.assertIn("RemovePreviousTunnelManagerForUpgrade(Result)", prepare)
        self.assertIn(
            "after PrepareToInstall has safely stopped the previous privileged manager",
            install_delete,
        )

    def test_safe_traversal_is_used_instead_of_recurse_before_iscc(self) -> None:
        walker = self.builder[
            self.builder.index("function Get-ContainedInnoStagingFiles {") : self.builder.index(
                "function Assert-InnoStagingPayloadAllowed {"
            )
        ]
        self.assertNotIn("-Recurse", walker)
        self.assertIn("ReparsePoint", walker)
        self.assertIn("escaped its root", walker)
        iscc = self.builder.index("& $iscc @innoArguments")
        last_gate = self.builder.rindex(
            "Assert-InnoStagingContainsNoWithdrawnMullvadPayloads", 0, iscc
        )
        self.assertLess(
            self.builder.index("$innoArguments += '/DEnableSigning=1'"),
            last_gate,
        )
        self.assertLess(last_gate, iscc)


@unittest.skipUnless(PWSH, "pwsh or powershell is required for executable Inno staging tests")
class WindowsInnoWithdrawnMullvadAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="winsvpn-inno-mullvad-")
        self.root = pathlib.Path(self.temp.name)
        self.harness = self.root / "inno-mullvad-harness.ps1"
        self.harness.write_text(HARNESS.strip() + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_gate(self, release: pathlib.Path, deps: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                PWSH,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(self.harness),
                "-BuildScript",
                str(BUILD_SCRIPT),
                "-ReleaseRoot",
                str(release),
                "-DependenciesRoot",
                str(deps),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )

    def assert_rejected(
        self, release: pathlib.Path, deps: pathlib.Path, marker: str
    ) -> str:
        result = self.run_gate(release, deps)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn(marker, output)
        return output

    def test_self_test_switch_passes_without_packaging(self) -> None:
        result = subprocess.run(
            [
                PWSH,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(BUILD_SCRIPT),
                "-SelfTestWithdrawnMullvadStaging",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("WINDOWS WITHDRAWN MULLVAD INNO STAGING SELF-TEST: PASS", output)

    def test_accepts_clean_nested_payload(self) -> None:
        release = self.root / "clean-release"
        deps = self.root / "clean-deps"
        (release / "nested").mkdir(parents=True)
        deps.mkdir()
        (release / "ordinary.bin").write_bytes(b"ok")
        (release / "nested" / "also.bin").write_bytes(b"also-ok")
        (deps / "wintun.dll").write_bytes(b"not-a-driver-package")
        result = self.run_gate(release, deps)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_nested_and_renamed_mullvad_payloads(self) -> None:
        cases = [
            (
                "nested/mullvad-split-tunnel.sys",
                b"dummy-sys",
                "withdrawn kernel split-tunnel artifact",
            ),
            (
                "nested/MULLVAD-SPLIT-TUNNEL.CAT",
                b"dummy-cat",
                "withdrawn kernel split-tunnel artifact",
            ),
            (
                "drivers/mullvad-split-tunnel-arm64.inf",
                b"dummy-arm64-inf",
                "withdrawn kernel split-tunnel artifact",
            ),
            (
                "nested/renamed-driver.sys",
                b"not-the-reviewed-bytes",
                "kernel driver package files",
            ),
            (
                "nested/renamed-driver.cat",
                b"not-the-reviewed-catalog",
                "kernel driver package files",
            ),
            (
                "nested/renamed-driver.inf",
                b"not-the-reviewed-inf",
                "kernel driver package files",
            ),
        ]
        for name, digest in WITHDRAWN_MULLVAD_SHA256.items():
            path = DEPENDENCIES / name
            if path.is_file():
                cases.append(
                    (
                        f"nested/neutral-{name}.bin",
                        path.read_bytes(),
                        "withdrawn kernel split-tunnel bytes, including when renamed",
                    )
                )
                self.assertEqual(sha256_file(path), digest)

        for index, (relative, data, marker) in enumerate(cases):
            with self.subTest(relative=relative):
                release = self.root / f"release-{index}"
                deps = self.root / f"deps-{index}"
                target = release / pathlib.PurePosixPath(relative)
                target.parent.mkdir(parents=True)
                deps.mkdir()
                target.write_bytes(data)
                self.assert_rejected(release, deps, marker)

    def test_rejects_payload_injected_into_staged_dependencies(self) -> None:
        release = self.root / "release-deps-inject"
        deps = self.root / "deps-inject"
        release.mkdir()
        (release / "ordinary.bin").write_bytes(b"ok")
        (deps / "nested").mkdir(parents=True)
        (deps / "nested" / "mullvad-split-tunnel.inf").write_bytes(b"nested-inf")
        self.assert_rejected(release, deps, "withdrawn kernel split-tunnel artifact")

    def test_rejects_filesystem_root_source(self) -> None:
        deps = self.root / "deps-root"
        deps.mkdir()
        result = self.run_gate(pathlib.Path(self.root.anchor), deps)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("filesystem-root container", output)

    def test_rejects_reparse_point_before_reading_payload_bytes(self) -> None:
        release = self.root / "release-reparse"
        outside = self.root / "outside"
        deps = self.root / "deps-reparse"
        release.mkdir()
        outside.mkdir()
        deps.mkdir()
        (outside / "secret.bin").write_bytes(b"must-not-hash")
        try:
            os.symlink(outside, release / "linked", target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")
        self.assert_rejected(release, deps, "reparse point")


if __name__ == "__main__":
    unittest.main()
