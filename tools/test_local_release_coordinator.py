#!/usr/bin/env python3
"""Regression contracts for the host-specific local release coordinator."""

from __future__ import annotations

import pathlib
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "tools/local_release_gate.ps1").read_text(encoding="utf-8")
WORKFLOW_SOURCE = (ROOT / "tools/run_release_workflows.ps1").read_text(
    encoding="utf-8"
)


class LocalReleaseCoordinatorTests(unittest.TestCase):
    def test_all_git_known_authoritative_powershell_tools_are_parsed(self) -> None:
        gate = SOURCE.index('Invoke-Gate "PowerShell release tooling parse"')
        end = SOURCE.index("if (Test-Path -LiteralPath $DeploymentPreseedStore", gate)
        block = SOURCE[gate:end]
        for marker in (
            "git ls-files --cached --others --exclude-standard -- '*.ps1'",
            "$authoritativeRoots",
            "installer",
            "tools",
            "Sort-Object -Unique",
            "PowerShell release-tool inventory is unexpectedly small",
            "Parser]::ParseFile",
        ):
            self.assertIn(marker, block)
        self.assertNotIn('"tools/android_phone_stress.ps1"', block)

    def test_non_windows_host_fails_before_windows_path_resolution(self) -> None:
        guard = SOURCE.index("if (-not $RunningOnWindows)")
        user_profile = SOURCE.index("$env:USERPROFILE")
        local_app_data = SOURCE.index("$env:LOCALAPPDATA")
        self.assertLess(guard, user_profile)
        self.assertLess(guard, local_app_data)
        self.assertIn("cannot run on macOS or Linux", SOURCE[guard:user_profile])
        self.assertIn("Skipping the Windows gates is not publish-ready evidence", SOURCE)

    def test_android_producer_receives_the_frozen_release_index(self) -> None:
        gate = SOURCE.index('Invoke-Gate "Android release APK and AAB build"')
        next_gate = SOURCE.index("Invoke-Gate", gate + 1)
        block = SOURCE[gate:next_gate]
        self.assertIn('"tools/build_android_release.ps1" "-ReleaseInputIndex" $ReleaseInputIndex', block)
        self.assertNotIn('"-SkipPubGet"', block)

    def test_direct_flutter_mutations_hold_the_shared_release_lock(self) -> None:
        lock_definition = SOURCE.index("function Invoke-WithReleaseBuildLock")
        first_flutter = SOURCE.index('Invoke-Native "flutter"')
        self.assertLess(lock_definition, first_flutter)

        validation_start = SOURCE.index(
            "Invoke-WithReleaseBuildLock -Purpose 'flutter-validation'"
        )
        validation_end = SOURCE.index(
            'Invoke-Gate "Deployment script shellcheck"', validation_start
        )
        validation = SOURCE[validation_start:validation_end]
        for command in (
            'Invoke-Native "flutter" "pub" "get"',
            'Invoke-Native "flutter" "analyze" "lib" "test"',
            'Invoke-Native "flutter" "test"',
        ):
            self.assertIn(command, validation)

        android_start = SOURCE.index(
            "Invoke-WithReleaseBuildLock -Purpose 'android-cache-reset'"
        )
        android_end = SOURCE.index(
            'Invoke-Gate "Pre-Android-build release input index verification"',
            android_start,
        )
        android = SOURCE[android_start:android_end]
        self.assertIn('Invoke-Native "flutter" "pub" "get"', android)
        self.assertIn("Remove-Item -LiteralPath $target -Recurse -Force", android)
        self.assertIn(
            'Invoke-Native "android/gradlew.bat" "-p" "android" "testDebugUnitTest"',
            android,
        )
        self.assertEqual(SOURCE.count('Invoke-Native "flutter"'), 4)

    def test_local_release_lock_initialization_and_release_are_transactional(self) -> None:
        for marker in (
            '$BuildLockDir = Join-Path $RepoRoot ".dart_tool\\winsvpn-release-build.lock"',
            "owner.$PID.",
            "Move-Item -LiteralPath $temporaryOwnerFile",
            "$script:LocalReleaseBuildLockAcquired = $true",
            "Unable to initialize the local release build lock transactionally",
            "Move-Item -LiteralPath $BuildLockDir -Destination $releasedLockDir",
            "$script:LocalReleaseBuildLockAcquired = $false",
        ):
            self.assertIn(marker, SOURCE)
        self.assertNotIn(
            "Remove-Item -LiteralPath $BuildLockOwnerFile", SOURCE
        )
        rename = SOURCE.index(
            "Move-Item -LiteralPath $BuildLockDir -Destination $releasedLockDir"
        )
        release_flag = SOURCE.index(
            "$script:LocalReleaseBuildLockAcquired = $false", rename
        )
        self.assertLess(rename, release_flag)

    def test_windows_uses_one_privacy_bound_canonical_producer(self) -> None:
        self.assertNotIn('"flutter" "build" "windows"', SOURCE)
        self.assertNotIn("-SkipFlutterBuild", SOURCE)
        gate = SOURCE.index(
            'Invoke-Gate "Canonical Windows application and installer build"'
        )
        next_gate = SOURCE.index("Invoke-Gate", gate + 1)
        block = SOURCE[gate:next_gate]
        self.assertIn('"-File" "installer/windows/build_installer.ps1"', block)

        installer = (
            ROOT / "installer" / "windows" / "build_installer.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("Add-DartPluginRegistrantVirtualPackage", installer)
        self.assertIn(
            "& $script:FlutterCommand build windows --release --no-pub --obfuscate",
            installer,
        )
        self.assertIn(
            "$script:FlutterCommand = $flutterCommand.Source", installer
        )
        self.assertIn("Enter-ReleaseBuildLock", installer)
        for marker in (
            "Move-Item -LiteralPath $temporaryOwnerFile",
            "Unable to initialize the Windows release build lock transactionally",
            "Move-Item -LiteralPath $BuildLockDir -Destination $releasedLockDir",
        ):
            self.assertIn(marker, installer)
        self.assertNotIn(
            "Remove-Item -LiteralPath $BuildLockOwnerFile", installer
        )

    def test_retired_hosted_release_dispatcher_fails_closed_before_external_tools(self) -> None:
        lowered = WORKFLOW_SOURCE.lower()
        self.assertIn("is retired", lowered)
        self.assertIn("github is backup storage only", lowered)
        self.assertIn("throw", lowered)
        for forbidden in (
            '"gh"',
            "gh.exe",
            "workflow_dispatch",
            "id-token",
            "oidc",
            "cosign",
            "sign_staged",
            "upload-artifact",
        ):
            self.assertNotIn(forbidden, lowered, forbidden)

        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("PowerShell is unavailable for the retired-dispatcher execution check")
        with tempfile.TemporaryDirectory() as temp_name:
            marker = pathlib.Path(temp_name) / "external-tool-ran"
            fake = pathlib.Path(temp_name) / "gh"
            fake.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            fake.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = temp_name + os.pathsep + environment.get("PATH", "")
            completed = subprocess.run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(ROOT / "tools" / "run_release_workflows.ps1"),
                    "-Linux",
                    "-Apple",
                    "-Wait",
                    "-Ref",
                    "stale-automation",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("retired", completed.stderr.lower() + completed.stdout.lower())
            self.assertFalse(marker.exists())

    def test_coordinator_keeps_github_backup_only_and_refuses_ambient_iscc_go(self) -> None:
        lowered = SOURCE.lower()
        self.assertNotRegex(SOURCE, r"Get-Command\s+ISCC")
        self.assertNotIn("ISCC.exe", SOURCE)
        self.assertNotIn("Get-Command go", SOURCE)
        for forbidden in (
            "gh.exe",
            "workflow_dispatch",
            "actions/checkout",
            "github.event",
        ):
            self.assertNotIn(forbidden, SOURCE, forbidden)
        self.assertNotIn("workflow_dispatch", lowered)
        workflow = WORKFLOW_SOURCE.lower()
        self.assertIn("github is backup storage only", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
