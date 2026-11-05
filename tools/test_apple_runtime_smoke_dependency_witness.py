#!/usr/bin/env python3
"""Hostile direct tests for the Apple release dependency witness adapter."""

from __future__ import annotations

import os
import pathlib
import platform
import signal
import stat
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("apple_runtime_smoke.sh").resolve()
SWITCH = "--wins-release-dependency-build-attempt-v2"
CONTRACT = "winsvpn-witnessed-build-attempt-v2"
NONCE = "0123456789abcdef" * 4
REQUIRED_INPUTS = {
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT": CONTRACT,
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE": NONCE,
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT": "artifact.bin",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM": "ios",
}


class AppleRuntimeSmokeDependencyWitnessTest(unittest.TestCase):
    def _environment(self, **updates: str) -> dict[str, str]:
        environment = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            **REQUIRED_INPUTS,
        }
        environment.update(updates)
        return environment

    def _run(
        self,
        directory: pathlib.Path,
        *,
        arguments: tuple[str, ...] = (SWITCH,),
        environment: dict[str, str] | None = None,
    ) -> tuple[subprocess.Popen[bytes], bytes, bytes]:
        process = subprocess.Popen(
            ["/bin/bash", "-p", os.fspath(SCRIPT), *arguments],
            cwd=directory,
            env=environment if environment is not None else self._environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(timeout=10)
        return process, stdout, stderr

    def _new_output(
        self,
        directory: pathlib.Path,
        *,
        name: str = "artifact.bin",
        content: bytes = b"",
        mode: int = 0o600,
    ) -> pathlib.Path:
        output = directory / name
        output.write_bytes(content)
        output.chmod(mode)
        return output

    @staticmethod
    def _payload(target: str) -> bytes:
        return (
            "WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1\n"
            f"contract={CONTRACT}\n"
            f"nonce={NONCE}\n"
            "host=darwin\n"
            "runtime=bash-file\n"
            "platform=apple\n"
            f"target={target}\n"
        ).encode("ascii")

    def _assert_silent_rejection(
        self,
        directory: pathlib.Path,
        output: pathlib.Path | None,
        *,
        arguments: tuple[str, ...] = (SWITCH,),
        environment: dict[str, str] | None = None,
    ) -> None:
        before = output.read_bytes() if output is not None and output.is_file() else None
        identity = output.stat() if output is not None and output.exists() else None
        process, stdout, stderr = self._run(
            directory, arguments=arguments, environment=environment
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")
        if before is not None and identity is not None:
            after = output.stat()
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual((after.st_dev, after.st_ino), (identity.st_dev, identity.st_ino))

    def test_reviewed_interface_tokens_precede_normal_production_setup(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1",
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2",
            SWITCH,
            CONTRACT,
            "WINS_RELEASE_DEPENDENCY_NATIVE_HOST=darwin",
            "WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME=bash-file",
            "WINS_RELEASE_DEPENDENCY_NATIVE_PLATFORM=apple",
            *REQUIRED_INPUTS,
        ):
            self.assertIn(token, source)
        self.assertLess(source.index(SWITCH), source.index('ROOT_DIR="'))

    @unittest.skipUnless(platform.system() == "Darwin", "Darwin adapter only")
    def test_ios_and_macos_attempts_retain_the_precreated_output_inode(self) -> None:
        for target in ("ios", "macos"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                directory = pathlib.Path(temporary)
                output = self._new_output(directory)
                before = output.stat()
                process, stdout, stderr = self._run(
                    directory,
                    environment=self._environment(
                        WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM=target
                    ),
                )
                after = output.stat()

                self.assertEqual(process.returncode, 0)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"")
                self.assertEqual(output.read_bytes(), self._payload(target))
                self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
                self.assertEqual(after.st_nlink, 1)
                self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
                self.assertEqual(sorted(path.name for path in directory.iterdir()), [output.name])
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process.pid, 0)

    @unittest.skipUnless(platform.system() == "Darwin", "Darwin adapter only")
    def test_missing_wrong_and_extra_attempt_inputs_are_rejected_silently(self) -> None:
        cases: list[tuple[str, dict[str, str] | None, tuple[str, ...]]] = []
        for missing in REQUIRED_INPUTS:
            environment = self._environment()
            environment.pop(missing)
            cases.append((f"missing-{missing}", environment, (SWITCH,)))
        cases.extend(
            (
                ("wrong-contract", self._environment(
                    WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT="wrong"
                ), (SWITCH,)),
                ("short-nonce", self._environment(
                    WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE="a" * 63
                ), (SWITCH,)),
                ("long-nonce", self._environment(
                    WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE="a" * 65
                ), (SWITCH,)),
                ("uppercase-nonce", self._environment(
                    WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE="A" * 64
                ), (SWITCH,)),
                ("nonhex-nonce", self._environment(
                    WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE="g" * 64
                ), (SWITCH,)),
                ("wrong-platform", self._environment(
                    WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM="apple"
                ), (SWITCH,)),
                ("extra-input", self._environment(
                    WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_EXTRA="hostile"
                ), (SWITCH,)),
                ("extra-argument", self._environment(), (SWITCH, "extra")),
                ("duplicate-switch", self._environment(), (SWITCH, SWITCH)),
            )
        )

        for label, environment, arguments in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                directory = pathlib.Path(temporary)
                output = self._new_output(directory)
                self._assert_silent_rejection(
                    directory,
                    output,
                    arguments=arguments,
                    environment=environment,
                )

    @unittest.skipUnless(platform.system() == "Darwin", "Darwin adapter only")
    def test_unsafe_output_names_are_rejected_without_touching_other_files(self) -> None:
        unsafe_names = (
            "",
            ".",
            "..",
            "/tmp/artifact.bin",
            "../artifact.bin",
            "nested/artifact.bin",
            "nested\\artifact.bin",
            "-artifact.bin",
            "artifact\n.bin",
            "a" * 193,
        )
        for unsafe_name in unsafe_names:
            with self.subTest(output=repr(unsafe_name)), tempfile.TemporaryDirectory() as temporary:
                directory = pathlib.Path(temporary)
                decoy = self._new_output(directory, name="decoy.bin", content=b"unchanged")
                self._assert_silent_rejection(
                    directory,
                    decoy,
                    environment=self._environment(
                        WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT=unsafe_name
                    ),
                )
                self.assertEqual(
                    sorted(path.name for path in directory.iterdir()), [decoy.name]
                )

    @unittest.skipUnless(platform.system() == "Darwin", "Darwin adapter only")
    def test_hostile_output_inode_substitutes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            self._assert_silent_rejection(directory, None)

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            output = directory / "artifact.bin"
            output.mkdir(mode=0o700)
            self._assert_silent_rejection(directory, None)

        for label, content, mode in (
            ("nonempty", b"preexisting", 0o600),
            ("wrong-mode", b"", 0o644),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                directory = pathlib.Path(temporary)
                output = self._new_output(directory, content=content, mode=mode)
                self._assert_silent_rejection(directory, output)

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            retained = self._new_output(directory, name="retained.bin")
            output = directory / "artifact.bin"
            output.symlink_to(retained.name)
            before = retained.stat()
            self._assert_silent_rejection(directory, retained)
            self.assertTrue(output.is_symlink())
            self.assertEqual((retained.stat().st_dev, retained.stat().st_ino),
                             (before.st_dev, before.st_ino))

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            retained = self._new_output(directory, name="retained.bin")
            output = directory / "artifact.bin"
            os.link(retained, output)
            self._assert_silent_rejection(directory, output)
            self.assertEqual(retained.stat().st_nlink, 2)

    def test_non_witness_verify_dispatch_remains_on_the_normal_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            process, stdout, stderr = self._run(
                pathlib.Path(temporary),
                arguments=("--verify", "wrong-kind", "artifact"),
                environment={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        self.assertEqual(process.returncode, 64)
        self.assertEqual(stdout, b"")
        self.assertEqual(
            stderr,
            b"APPLE CROSS-STORE ARTIFACT GATE: FAIL: expected --verify "
            b"macos-developer-id-app <repo-relative-artifact>\n",
        )


if __name__ == "__main__":
    unittest.main()
