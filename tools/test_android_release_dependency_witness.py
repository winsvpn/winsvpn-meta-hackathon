#!/usr/bin/env python3
"""Hostile direct tests for the Android release dependency witness adapter."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER = ROOT / "tools" / "build_android_release.ps1"
FREEZE = ROOT / "tools" / "release_dependency_freeze.py"
SWITCH = "--wins-release-dependency-build-attempt-v2"
PREFIX = "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_"
CONTRACT = "winsvpn-witnessed-build-attempt-v2"
NONCE = "0123456789abcdef" * 4
REVIEWED_POWERSHELL_VERSION = "7.6.4"
REVIEWED_POWERSHELL_OVERRIDE = "WINS_TEST_POWERSHELL"


def _account_home() -> pathlib.Path | None:
    if sys.platform == "win32":
        raw_home = os.environ.get("USERPROFILE", "")
    else:
        import pwd

        raw_home = pwd.getpwuid(os.getuid()).pw_dir
    if not raw_home:
        return None
    home = pathlib.Path(raw_home)
    return home if home.is_absolute() else None


def _reviewed_powershell_executable() -> pathlib.Path | None:
    override = os.environ.get(REVIEWED_POWERSHELL_OVERRIDE, "")
    if override:
        candidates = (pathlib.Path(override),)
    elif sys.platform == "win32":
        system_root = os.environ.get("SystemRoot", "")
        if not system_root or not pathlib.PureWindowsPath(system_root).is_absolute():
            candidates = ()
        else:
            candidates = (
                pathlib.Path(system_root)
                / "System32"
                / "WindowsPowerShell"
                / "v1.0"
                / "powershell.exe",
            )
    else:
        home = _account_home()
        candidates = tuple(
            candidate
            for candidate in (
                (
                    home
                    / "Library"
                    / "Application Support"
                    / "WinsVPN"
                    / "toolchains"
                    / f"powershell-{REVIEWED_POWERSHELL_VERSION}"
                    / "pwsh"
                    if home is not None
                    else None
                ),
                (
                    home
                    / ".homebrew"
                    / "Homebrew"
                    / "Cellar"
                    / "powershell"
                    / REVIEWED_POWERSHELL_VERSION
                    / "bin"
                    / "pwsh"
                    if home is not None
                    else None
                ),
                pathlib.Path(
                    f"/opt/homebrew/Cellar/powershell/"
                    f"{REVIEWED_POWERSHELL_VERSION}/bin/pwsh"
                ),
                pathlib.Path("/opt/microsoft/powershell/7/pwsh"),
            )
            if candidate is not None
        )
    for candidate in candidates:
        if not candidate.is_absolute():
            raise AssertionError("reviewed PowerShell override must be absolute")
        try:
            information = candidate.lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(information.st_mode) & 0o022
        ):
            raise AssertionError(
                f"reviewed PowerShell boundary is not a protected regular file: {candidate}"
            )
        return candidate
    if override:
        raise AssertionError(
            f"reviewed PowerShell override does not exist: {override}"
        )
    return None


PWSH = _reviewed_powershell_executable()


def _source() -> str:
    payload = PRODUCER.read_bytes()
    if b"\r" in payload or any(byte > 0x7F for byte in payload):
        raise AssertionError("producer must remain ASCII with LF line endings")
    return payload.decode("ascii")


def _function(source: str, name: str, next_name: str) -> str:
    start = source.index(f"function {name} {{")
    end = source.index(f"function {next_name} {{", start)
    return source[start:end]


class AndroidReleaseDependencyWitnessTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        if PWSH is None:
            raise RuntimeError(
                "reviewed absolute PowerShell executable is unavailable; "
                f"set {REVIEWED_POWERSHELL_OVERRIDE} to an accepted regular file"
            )

    def setUp(self) -> None:
        self.source = _source()

    def _environment(self, **overrides: str | None) -> dict[str, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith(PREFIX)
        }
        environment.update(
            {
                PREFIX + "CONTRACT": CONTRACT,
                PREFIX + "NONCE": NONCE,
                PREFIX + "OUTPUT": "app-release.apk",
                PREFIX + "PLATFORM": "android",
            }
        )
        for key, value in overrides.items():
            name = key if key.startswith(PREFIX) else PREFIX + key
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        return environment

    def _run(
        self,
        *,
        arguments: tuple[str, ...] = (SWITCH,),
        environment: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[bytes], int]:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = pathlib.Path(temporary_name)
            output = temporary / "app-release.apk"
            output.touch()
            completed = subprocess.run(
                [
                    str(PWSH),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(PRODUCER),
                    *arguments,
                ],
                cwd=temporary,
                env=environment or self._environment(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=20,
            )
            return completed, output.stat().st_size

    def _assert_silent_refusal(
        self,
        *,
        arguments: tuple[str, ...] = (SWITCH,),
        environment: dict[str, str] | None = None,
    ) -> None:
        completed, output_size = self._run(
            arguments=arguments,
            environment=environment,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(output_size, 0)

    def test_release_freeze_interface_is_semantically_bound_and_stable(self) -> None:
        controller_before = FREEZE.read_bytes()
        self.assertEqual(controller_before, FREEZE.read_bytes())
        for token in (
            "WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1",
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2",
            SWITCH,
            CONTRACT,
            "WINS_RELEASE_DEPENDENCY_NATIVE_HOST=windows",
            "WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME=powershell-file",
            PREFIX + "CONTRACT",
            PREFIX + "NONCE",
            PREFIX + "OUTPUT",
            PREFIX + "PLATFORM",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)
        specification = importlib.util.spec_from_file_location(
            "android_release_dependency_freeze_probe", FREEZE
        )
        if specification is None or specification.loader is None:
            self.fail("release freeze module could not be loaded")
        module = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = module
        try:
            specification.loader.exec_module(module)
            self.assertEqual(pathlib.Path(module.__file__).resolve(), FREEZE.resolve())
            self.assertEqual(
                pathlib.Path(
                    module._native_build_witness_adoption_gaps.__code__.co_filename
                ).resolve(),
                FREEZE.resolve(),
            )
            self.assertEqual(
                module.NATIVE_BUILD_WITNESS_MARKER,
                b"WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1",
            )
            self.assertEqual(module.BUILD_ATTEMPT_SWITCH, SWITCH)
            self.assertEqual(module.BUILD_ATTEMPT_CONTRACT, CONTRACT)
            self.assertEqual(
                module.NATIVE_BUILD_WITNESS_REQUIRED_ENV,
                tuple(PREFIX + suffix for suffix in ("CONTRACT", "NONCE", "OUTPUT", "PLATFORM")),
            )
            self.assertEqual(
                module.NATIVE_BUILD_WITNESS_ADAPTERS.get(
                    "tools/build_android_release.ps1"
                ),
                {
                    "platforms": ("android",),
                    "host": "windows",
                    "systems": ("windows",),
                    "runtime": "powershell-file",
                },
            )
            self.assertEqual(
                module._native_build_witness_adoption_gaps(
                    "android", PRODUCER.read_bytes()
                ),
                (),
            )
        finally:
            sys.modules.pop(specification.name, None)
        controller_after = FREEZE.read_bytes()
        self.assertEqual(controller_after, FREEZE.read_bytes())
        self.assertEqual(controller_after, controller_before)

    def test_switch_is_captured_before_normal_production_initialization(self) -> None:
        self.assertLess(
            self.source.index("[Parameter(ValueFromRemainingArguments = $true)]"),
            self.source.index("$ExpectedUploadCertificateSha256"),
        )
        self.assertLess(
            self.source.index("if ($script:ReleaseDependencyWitnessMode) {"),
            self.source.index("$ExpectedUploadCertificateSha256"),
        )
        self.assertIn(
            "elseif (@($ReleaseDependencyArguments).Count -ne 0)", self.source
        )

    def test_missing_wrong_and_extra_environment_inputs_fail_silently(self) -> None:
        cases = {
            "missing-contract": self._environment(CONTRACT=None),
            "missing-nonce": self._environment(NONCE=None),
            "missing-output": self._environment(OUTPUT=None),
            "missing-platform": self._environment(PLATFORM=None),
            "wrong-contract": self._environment(CONTRACT="wrong"),
            "wrong-platform": self._environment(PLATFORM="windows"),
            "short-nonce": self._environment(NONCE="0" * 63),
            "uppercase-nonce": self._environment(NONCE="A" * 64),
            "extra-prefixed": self._environment(UNREVIEWED="1"),
        }
        for label, environment in cases.items():
            with self.subTest(label=label):
                self._assert_silent_refusal(environment=environment)

    def test_duplicate_and_extra_switch_arguments_fail_silently(self) -> None:
        for arguments in (
            (SWITCH, SWITCH),
            (SWITCH, "extra"),
            ("extra", SWITCH),
        ):
            with self.subTest(arguments=arguments):
                self._assert_silent_refusal(arguments=arguments)

    def test_unsafe_output_names_fail_silently_before_host_dispatch(self) -> None:
        unsafe = (
            "../escape.apk",
            r"..\escape.apk",
            "subdir/app.apk",
            r"subdir\app.apk",
            "/absolute.apk",
            r"C:\absolute.apk",
            "app.apk:stream",
            "CON.apk",
            "NUL",
            "COM1.aab",
            "app.apk.",
            "app.apk ",
            ".hidden.apk",
            "other-release.apk",
            "",
        )
        for output in unsafe:
            with self.subTest(output=output):
                self._assert_silent_refusal(
                    environment=self._environment(OUTPUT=output)
                )

    def test_case_variant_required_name_is_rejected_as_non_exact(self) -> None:
        environment = self._environment(CONTRACT=None)
        environment[(PREFIX + "CONTRACT").lower()] = CONTRACT
        self._assert_silent_refusal(environment=environment)

    def test_duplicate_environment_entries_are_rejected_directly(self) -> None:
        helper = _function(
            self.source,
            "Read-WinsReleaseDependencyWitnessInputs",
            "Test-WinsReleaseDependencyOutputName",
        )
        script = f"""
$ErrorActionPreference = 'Stop'
$ReleaseDependencyBuildAttemptContract = '{CONTRACT}'
$ReleaseDependencyBuildAttemptPlatform = 'android'
$ReleaseDependencyBuildAttemptEnvironment = @(
    '{PREFIX}CONTRACT',
    '{PREFIX}NONCE',
    '{PREFIX}OUTPUT',
    '{PREFIX}PLATFORM'
)
{helper}
$entries = @(
    '{PREFIX}CONTRACT={CONTRACT}',
    '{PREFIX}NONCE={NONCE}',
    '{PREFIX}OUTPUT=app-release.apk',
    '{PREFIX}PLATFORM=android',
    '{PREFIX}NONCE={NONCE}'
)
try {{
    $null = Read-WinsReleaseDependencyWitnessInputs -Entries $entries
    exit 91
}} catch {{
    exit 0
}}
"""
        completed = subprocess.run(
            [str(PWSH), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_retained_output_is_opened_without_create_or_rename(self) -> None:
        start = self.source.index("function Open-WinsReleaseDependencyWitnessOutput {")
        end = self.source.index("if ($script:ReleaseDependencyWitnessMode) {", start)
        opener = self.source[start:end]
        self.assertIn("[IO.FileMode]::Open", opener)
        self.assertNotIn("[IO.FileMode]::Create", opener)
        self.assertNotIn("Move-Item", opener)
        self.assertNotIn("Rename-Item", opener)
        self.assertNotIn("Replace", opener)
        self.assertIn("[IO.FileShare]::ReadWrite", opener)
        witness_end = self.source.index("if ($InNeutralStage) {")
        witness_start = self.source.rindex(
            "if ($script:ReleaseDependencyWitnessMode) {", 0, witness_end
        )
        witness = self.source[witness_start:witness_end]
        self.assertIn(
            "$artifactStream.CopyTo($script:ReleaseDependencyWitnessOutput)", witness
        )
        self.assertEqual(
            witness.count("Open-WinsReleaseDependencyWitnessOutput"), 0
        )
        self.assertNotIn("Move-Item", witness)
        self.assertNotIn("Rename-Item", witness)

    def test_witness_build_waits_for_process_tree_and_suppresses_diagnostics(self) -> None:
        witness_end = self.source.index("if ($InNeutralStage) {")
        witness_start = self.source.rindex(
            "if ($script:ReleaseDependencyWitnessMode) {", 0, witness_end
        )
        witness = self.source[witness_start:witness_end]
        self.assertIn("Start-Process", witness)
        self.assertIn("-Wait -PassThru", witness)
        self.assertIn("-RedirectStandardOutput", witness)
        self.assertIn("-RedirectStandardError", witness)
        self.assertIn("$childProcess.ExitCode -ne 0", witness)
        self.assertIn("Remove-Item -LiteralPath $stage.Container -Recurse -Force", witness)

    def test_production_and_snapshot_are_each_rehashed_twice(self) -> None:
        block = self.source[
            self.source.index("$productionProducer =") :
            self.source.index("# SINGLE SOURCE OF TRUTH")
        ]
        self.assertEqual(block.count("$productionHashFirst"), 2)
        self.assertEqual(block.count("$productionHashSecond"), 3)
        self.assertEqual(block.count("$snapshotHashFirst"), 2)
        self.assertEqual(block.count("$snapshotHashSecond"), 4)
        self.assertIn("$productionHashSecond -cne $snapshotHashSecond", block)
        self.assertIn(
            "$script:ReleaseDependencyWitnessProducerSha256 = $snapshotHashSecond",
            block,
        )


if __name__ == "__main__":
    unittest.main()
