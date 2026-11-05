#!/usr/bin/env python3
"""Hostile direct tests for the Windows installer dependency witness adapter."""

from __future__ import annotations

import hashlib
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER = ROOT / "installer" / "windows" / "build_installer.ps1"
FREEZE = ROOT / "tools" / "release_dependency_freeze.py"
SWITCH = "--wins-release-dependency-build-attempt-v2"
PREFIX = "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_"
CONTRACT = "winsvpn-witnessed-build-attempt-v2"
NONCE = "0123456789abcdef" * 4
OUTPUT = "WinsVPN-Setup.exe"
REVIEWED_POWERSHELL_VERSION = "7.6.4"
REVIEWED_POWERSHELL_OVERRIDE = "WINS_TEST_POWERSHELL"
REVIEWED_POWERSHELL_WRAPPER_SHA256 = (
    "effd7c3629e79e30ef6633a6752c1095c4bb2c068bd925b5a36d45135a5aeb91"
)
REVIEWED_POWERSHELL_RUNTIME_SHA256 = (
    "c4f3ff2cb0eac37bcae7dc6410aa48ef527c8526ee01fd3f470b164029bb8b8d"
)
DESCRIPTOR_INPUTS = {
    "WINS_RELEASE_DEPENDENCY_REPOSITORY_FD": "30",
    "WINS_RELEASE_DEPENDENCY_SOURCE_FD": "31",
    "WINS_RELEASE_DEPENDENCY_ATTEMPT_FD": "32",
    "WINS_RELEASE_DEPENDENCY_OUTPUT_FD": "33",
}


def _account_home() -> pathlib.Path | None:
    if sys.platform == "win32":
        return None
    import pwd

    home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)
    return home if home.is_absolute() else None


def _checked_posix_executable(
    candidate: pathlib.Path, expected_sha256: str
) -> pathlib.Path:
    if not candidate.is_absolute():
        raise AssertionError("reviewed PowerShell path must be absolute")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise AssertionError(
            f"reviewed PowerShell path cannot be opened safely: {candidate}"
        ) from error
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or not stat.S_IMODE(before.st_mode) & 0o111
        ):
            raise AssertionError(
                "reviewed PowerShell path is not a protected executable "
                f"regular file: {candidate}"
            )
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(
        getattr(before, field) != getattr(after, field)
        for field in stable_fields
    ):
        raise AssertionError(
            f"reviewed PowerShell path changed while hashing: {candidate}"
        )
    if digest.hexdigest() != expected_sha256:
        raise AssertionError(
            f"reviewed PowerShell path has an unreviewed SHA-256: {candidate}"
        )
    return candidate


def _windows_system_powershell() -> pathlib.Path | None:
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        return None
    candidate = (
        pathlib.Path(buffer.value)
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    try:
        information = candidate.lstat()
    except OSError:
        return None
    return candidate if stat.S_ISREG(information.st_mode) else None


def _reviewed_powershell_executable() -> pathlib.Path | None:
    if sys.platform == "win32":
        return _windows_system_powershell()
    home = _account_home()
    if home is None:
        return None
    cellar = (
        home
        / ".homebrew"
        / "Homebrew"
        / "Cellar"
        / "powershell"
        / REVIEWED_POWERSHELL_VERSION
    )
    wrapper_override = os.environ.get(REVIEWED_POWERSHELL_OVERRIDE, "")
    wrapper = (
        pathlib.Path(wrapper_override)
        if wrapper_override
        else cellar / "bin" / "pwsh"
    )
    runtime = cellar / "libexec" / "pwsh"
    try:
        _checked_posix_executable(runtime, REVIEWED_POWERSHELL_RUNTIME_SHA256)
        return _checked_posix_executable(
            wrapper, REVIEWED_POWERSHELL_WRAPPER_SHA256
        )
    except AssertionError:
        if wrapper_override:
            raise
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


class WindowsInstallerDependencyWitnessTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        if PWSH is None:
            raise RuntimeError(
                "reviewed PowerShell 7.6.4 is unavailable or has drifted"
            )

    def setUp(self) -> None:
        self.source = _source()

    def test_powershell_selection_rejects_hostile_environment_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            fake = pathlib.Path(temporary_name) / "pwsh"
            fake.write_text("#!/bin/sh\nexit 97\n", encoding="ascii")
            fake.chmod(0o755)
            with mock.patch.dict(
                os.environ,
                {"HOME": temporary_name, "PATH": temporary_name},
                clear=False,
            ):
                self.assertEqual(_reviewed_powershell_executable(), PWSH)
            with mock.patch.dict(
                os.environ,
                {
                    "PATH": temporary_name,
                    REVIEWED_POWERSHELL_OVERRIDE: str(fake),
                },
                clear=False,
            ):
                if sys.platform == "win32":
                    self.assertEqual(_reviewed_powershell_executable(), PWSH)
                else:
                    with self.assertRaisesRegex(AssertionError, "SHA-256"):
                        _reviewed_powershell_executable()

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
                PREFIX + "OUTPUT": OUTPUT,
                PREFIX + "PLATFORM": "windows",
                **DESCRIPTOR_INPUTS,
            }
        )
        environment.pop("WINS_RELEASE_INPUT_INDEX", None)
        environment.pop("WINS_WINDOWS_BUILD_RECEIPT_DIR", None)
        for key, value in overrides.items():
            name = (
                key
                if key.startswith("WINS_RELEASE_DEPENDENCY_")
                else PREFIX + key
            )
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
    ) -> tuple[subprocess.CompletedProcess[bytes], bytes, tuple[int, int]]:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = pathlib.Path(temporary_name)
            output = temporary / OUTPUT
            output.touch(mode=0o600)
            before = output.stat()
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
            after = output.stat()
            return completed, output.read_bytes(), (
                int(before.st_dev == after.st_dev),
                int(before.st_ino == after.st_ino),
            )

    def _assert_silent_refusal(
        self,
        *,
        arguments: tuple[str, ...] = (SWITCH,),
        environment: dict[str, str] | None = None,
    ) -> None:
        completed, output, identity = self._run(
            arguments=arguments,
            environment=environment,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(output, b"")
        self.assertEqual(identity, (1, 1))

    def test_exact_reviewed_freeze_interface_is_adopted(self) -> None:
        controller = FREEZE.read_text(encoding="utf-8")
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
            *DESCRIPTOR_INPUTS,
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)
        for token in (
            "WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1",
            SWITCH,
            CONTRACT,
            PREFIX + "CONTRACT",
            PREFIX + "NONCE",
            PREFIX + "OUTPUT",
            PREFIX + "PLATFORM",
            *DESCRIPTOR_INPUTS,
        ):
            with self.subTest(controller_token=token):
                self.assertIn(token, controller)
        self.assertIn(
            '"installer/windows/build_installer.ps1": {', controller
        )
        self.assertIn('"host": "windows"', controller)
        self.assertIn('"runtime": "powershell-file"', controller)

    def test_switch_dispatch_precedes_normal_installer_initialization(self) -> None:
        self.assertLess(
            self.source.index("[Parameter(ValueFromRemainingArguments = $true)]"),
            self.source.index("[Net.ServicePointManager]::SecurityProtocol"),
        )
        self.assertLess(
            self.source.index("if ($script:ReleaseDependencyWitnessMode) {"),
            self.source.index("[Net.ServicePointManager]::SecurityProtocol"),
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
            "wrong-platform": self._environment(PLATFORM="android"),
            "short-nonce": self._environment(NONCE="0" * 63),
            "long-nonce": self._environment(NONCE="0" * 65),
            "uppercase-nonce": self._environment(NONCE="A" * 64),
            "nonhex-nonce": self._environment(NONCE="g" * 64),
            "extra-prefixed": self._environment(UNREVIEWED="1"),
            "duplicate-descriptors": self._environment(
                **{"WINS_RELEASE_DEPENDENCY_OUTPUT_FD": "30"}
            ),
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

    def test_unsafe_or_unreviewed_output_names_fail_silently(self) -> None:
        unsafe = (
            "../WinsVPN-Setup.exe",
            r"..\WinsVPN-Setup.exe",
            "subdir/WinsVPN-Setup.exe",
            r"subdir\WinsVPN-Setup.exe",
            "/WinsVPN-Setup.exe",
            r"C:\WinsVPN-Setup.exe",
            "WinsVPN-Setup.exe:stream",
            "CON.exe",
            "NUL",
            "WinsVPN-Setup.exe.",
            "WinsVPN-Setup.exe ",
            ".WinsVPN-Setup.exe",
            "other-installer.exe",
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
$ReleaseDependencyBuildAttemptPlatform = 'windows'
$ReleaseDependencyBuildAttemptEnvironment = @(
    '{PREFIX}CONTRACT',
    '{PREFIX}NONCE',
    '{PREFIX}OUTPUT',
    '{PREFIX}PLATFORM'
)
$ReleaseDependencyDescriptorEnvironment = @(
    'WINS_RELEASE_DEPENDENCY_REPOSITORY_FD',
    'WINS_RELEASE_DEPENDENCY_SOURCE_FD',
    'WINS_RELEASE_DEPENDENCY_ATTEMPT_FD',
    'WINS_RELEASE_DEPENDENCY_OUTPUT_FD'
)
{helper}
$entries = @(
    '{PREFIX}CONTRACT={CONTRACT}',
    '{PREFIX}NONCE={NONCE}',
    '{PREFIX}OUTPUT={OUTPUT}',
    '{PREFIX}PLATFORM=windows',
    'WINS_RELEASE_DEPENDENCY_REPOSITORY_FD=30',
    'WINS_RELEASE_DEPENDENCY_SOURCE_FD=31',
    'WINS_RELEASE_DEPENDENCY_ATTEMPT_FD=32',
    'WINS_RELEASE_DEPENDENCY_OUTPUT_FD=33',
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

    def test_all_eight_exact_installer_variants_are_mapped(self) -> None:
        expected = {
            "WinsVPN-Setup.exe",
            "WinsVPN-PartnerCenter.exe",
            "WinsVPN-Setup-arm64.exe",
            "WinsVPN-PartnerCenter-arm64.exe",
            "WinsVPN-UNSIGNED-LOCAL-Setup.exe",
            "WinsVPN-UNSIGNED-LOCAL-PartnerCenter.exe",
            "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe",
            "WinsVPN-UNSIGNED-LOCAL-PartnerCenter-arm64.exe",
        }
        declaration = self.source[
            self.source.index("$ReleaseDependencyBuildAttemptOutputs = @(") :
            self.source.index(")\n\ntrap {", self.source.index(
                "$ReleaseDependencyBuildAttemptOutputs = @(")
            )
        ]
        for name in expected:
            with self.subTest(name=name):
                self.assertIn(f"'{name}'", declaration)
        self.assertEqual(declaration.count(".exe'"), len(expected))
        variant = _function(
            self.source,
            "Get-WinsReleaseDependencyVariant",
            "Invoke-WinsReleaseDependencyJob",
        )
        self.assertIn("-arm64\\.exe$", variant)
        self.assertIn("PartnerCenter", variant)
        self.assertIn("^WinsVPN-UNSIGNED-LOCAL-", variant)

    def test_precreated_output_handle_is_retained_without_publication_reopen(self) -> None:
        opener = _function(
            self.source,
            "Open-WinsReleaseDependencyWitnessOutput",
            "Get-WinsReleaseDependencyVariant",
        )
        self.assertNotIn("[IO.FileMode]", opener)
        self.assertIn("OpenBorrowedDescriptor", opener)
        self.assertIn("WINS_RELEASE_DEPENDENCY_OUTPUT_FD", opener)
        self.assertNotIn("Move-Item", opener)
        self.assertNotIn("Rename-Item", opener)
        self.assertNotIn("Replace", opener)

        witness_start = self.source.index(
            "function Invoke-WinsReleaseDependencyWitnessBuild {"
        )
        witness = self.source[witness_start : self.source.index(
            "\nif ($script:ReleaseDependencyWitnessMode) {", witness_start
        )]
        publication = witness[witness.index("$isolatedArtifact =") :]
        self.assertEqual(publication.count("[IO.FileMode]::Open"), 1)
        self.assertIn(
            "$artifactStream.CopyTo($script:ReleaseDependencyWitnessOutput)",
            publication,
        )
        self.assertNotIn("Copy-Item", publication)
        self.assertNotIn("Move-Item", publication)
        self.assertNotIn("Rename-Item", publication)
        self.assertNotIn("Get-FileHash", publication)
        self.assertEqual(
            publication.count("ReleaseDependencyWitnessOutput.SafeFileHandle"), 1
        )

    def test_producer_and_snapshot_are_rehashed_before_and_after_export(self) -> None:
        witness_start = self.source.index(
            "function Invoke-WinsReleaseDependencyWitnessBuild {"
        )
        witness = self.source[witness_start : self.source.index(
            "\nif ($script:ReleaseDependencyWitnessMode) {", witness_start
        )]
        for token in (
            "$productionHashFirst",
            "$productionHashSecond",
            "$snapshotHashFirst",
            "$snapshotHashSecond",
            "$stageHashFirst",
            "$stageHashSecond",
            "$productionHashThird",
            "$snapshotHashThird",
        ):
            with self.subTest(token=token):
                self.assertIn(token, witness)
        self.assertIn("$productionHashSecond -cne $snapshotHashSecond", witness)
        self.assertIn("$stageHashSecond -cne $snapshotHashSecond", witness)
        self.assertIn("Get-WinsReleaseDependencyStreamSha256", witness)

    def test_real_isolated_build_runs_in_kill_on_close_job(self) -> None:
        for token in (
            "clone --no-hardlinks --no-tags",
            "-WinsReleaseDependencyIsolatedStage",
            "CREATE_SUSPENDED",
            "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
            "AssignProcessToJobObject",
            "QueryInformationJobObject",
            "ActiveProcesses(job)",
            "TerminateJobObject",
            "witnessed process left descendants alive",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)
        stage = self.source[
            self.source.index("if ($WinsReleaseDependencyIsolatedStage) {") :
            self.source.index(
                "# All release downloads in this script are HTTPS",
                self.source.index("if ($WinsReleaseDependencyIsolatedStage) {")
            )
        ]
        self.assertNotIn("Read-WinsReleaseDependencyWitnessInputs", stage)
        self.assertIn("^\\.winsvpn-windows-stage-[0-9a-f]{64}$", stage)
        self.assertIn("($RequireCodeSigning -eq $AllowUnsigned)", stage)
        self.assertIn("$privateEnvironment", self.source)
        self.assertIn(
            "$ReleaseDependencyDescriptorEnvironment", self.source
        )

    def test_existing_signing_and_timestamp_hardening_remains_on_child_path(self) -> None:
        for token in (
            "Assert-ApprovedTimestampUrl -Value $signingTimestampUrl",
            "Find-SignTool -RequireApprovedMicrosoftSignature",
            "Invoke-ProductSigning",
            "Assert-ProductSignature -Path $installer",
            "$script:AuthenticodeTimestampVerified",
            "Bind-WinsInnoCompilerCustody",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    @unittest.skipUnless(os.name == "nt", "Windows handle semantics only")
    def test_retained_output_blocks_rename_and_keeps_inode_on_windows(self) -> None:
        native = _function(
            self.source,
            "Initialize-WinsReleaseDependencyNativeTypes",
            "Open-WinsReleaseDependencyWitnessOutput",
        )
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = pathlib.Path(temporary_name)
            output = temporary / OUTPUT
            output.touch()
            descriptor = os.open(output, os.O_RDWR)
            os.set_inheritable(descriptor, True)
            import msvcrt

            inherited_handle = msvcrt.get_osfhandle(descriptor)
            script = f"""
$ErrorActionPreference = 'Stop'
{native}
Set-Location -LiteralPath '{temporary.as_posix().replace("'", "''")}'
$opened = [WinsVpn.ReleaseDependencyOutput]::OpenBorrowedDescriptor(
    {inherited_handle},
    [IO.FileAccess]::Write
)
try {{
    $renamed = $false
    try {{
        Move-Item -LiteralPath '{OUTPUT}' -Destination 'substituted.exe' -ErrorAction Stop
        $renamed = $true
    }} catch {{}}
    if ($renamed) {{ exit 92 }}
    $bytes = [Text.Encoding]::ASCII.GetBytes('installer-bytes')
    $opened.Write($bytes, 0, $bytes.Length)
    $opened.Flush($true)
    $identity = [WinsVpn.ReleaseDependencyOutput]::Inspect(
        $opened.SafeFileHandle
    )
    if ($identity[3] -ne 1 -or $identity[4] -ne $bytes.Length) {{ exit 93 }}
}} finally {{
    $opened.Dispose()
}}
"""
            try:
                completed = subprocess.run(
                    [str(PWSH), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                    close_fds=False,
                    timeout=20,
                )
            finally:
                os.close(descriptor)
            self.assertEqual(
                completed.returncode, 0, completed.stdout + completed.stderr
            )
            self.assertEqual(output.read_bytes(), b"installer-bytes")
            self.assertFalse((temporary / "substituted.exe").exists())


if __name__ == "__main__":
    unittest.main()
