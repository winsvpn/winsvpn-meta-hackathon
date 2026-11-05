#!/usr/bin/env python3
"""Hostile direct tests for the Wear witnessed dependency producer path."""

from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PRODUCER = Path(__file__).resolve().with_name("signed_aab_receipt.py")
SWITCH = "--wins-release-dependency-build-attempt-v2"
PREFIX = "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_"
CONTRACT = "winsvpn-witnessed-build-attempt-v2"
NONCE = "a" * 64
OUTPUT_NAME = "app-release.aab"
REQUIRED = {
    f"{PREFIX}CONTRACT": CONTRACT,
    f"{PREFIX}NONCE": NONCE,
    f"{PREFIX}OUTPUT": OUTPUT_NAME,
    f"{PREFIX}PLATFORM": "wear_os",
}


class SignedAabDependencyWitnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / OUTPUT_NAME
        self._precreate_output()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _precreate_output(self, payload: bytes = b"", mode: int = 0o600) -> None:
        if self.output.exists() or self.output.is_symlink():
            if self.output.is_dir() and not self.output.is_symlink():
                self.output.rmdir()
            else:
                self.output.unlink()
        descriptor = os.open(self.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            if payload:
                os.write(descriptor, payload)
        finally:
            os.close(descriptor)
        os.chmod(self.output, mode)

    def _environment(self, updates: dict[str, str | None] | None = None) -> dict[str, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(PREFIX)
        }
        environment.update(REQUIRED)
        environment["HOME"] = str(self.root)
        environment["TMPDIR"] = str(self.root)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for key, value in (updates or {}).items():
            if value is None:
                environment.pop(key, None)
            else:
                environment[key] = value
        return environment

    def _run(
        self,
        *,
        arguments: list[str] | None = None,
        updates: dict[str, str | None] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, "-I", "-S", str(PRODUCER), *(arguments or [SWITCH])],
            cwd=self.root,
            env=self._environment(updates),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    def _assert_silent_failure(
        self,
        *,
        arguments: list[str] | None = None,
        updates: dict[str, str | None] | None = None,
    ) -> None:
        before = self.output.lstat() if self.output.exists() or self.output.is_symlink() else None
        before_bytes = self.output.read_bytes() if self.output.is_file() else None
        completed = self._run(arguments=arguments, updates=updates)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")
        if before is not None:
            after = self.output.lstat()
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            if before_bytes is not None:
                self.assertEqual(self.output.read_bytes(), before_bytes)

    def test_exact_interface_refuses_without_touching_precreated_inode(self) -> None:
        before = self.output.stat()
        completed = self._run()
        after = self.output.stat()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
        self.assertEqual(after.st_nlink, 1)
        self.assertEqual(after.st_size, 0)
        self.assertEqual(self.output.read_bytes(), b"")

    def test_all_four_required_inputs_are_validated(self) -> None:
        hostile_values = {
            f"{PREFIX}CONTRACT": "winsvpn-witnessed-build-attempt-v1",
            f"{PREFIX}NONCE": "A" * 64,
            f"{PREFIX}OUTPUT": "../app-release.aab",
            f"{PREFIX}PLATFORM": "wear-os",
        }
        for name in REQUIRED:
            with self.subTest(missing=name):
                self._assert_silent_failure(updates={name: None})
        for name, value in hostile_values.items():
            with self.subTest(invalid=name):
                self._assert_silent_failure(updates={name: value})

    def test_extra_and_duplicate_switch_inputs_are_rejected(self) -> None:
        self._assert_silent_failure(updates={f"{PREFIX}EXTRA": "hostile"})
        self._assert_silent_failure(arguments=[SWITCH, SWITCH])
        self._assert_silent_failure(arguments=["hostile", SWITCH])
        self._assert_silent_failure(arguments=[SWITCH, "hostile"])

    def test_unsafe_output_paths_are_rejected(self) -> None:
        hostile = (
            "../app-release.aab",
            "/tmp/app-release.aab",
            "sub/app-release.aab",
            "sub\\app-release.aab",
            ".hidden",
            "..",
            "bad\nname.aab",
            "non-ascii-\N{SNOWMAN}.aab",
            "a" * 256,
        )
        for value in hostile:
            with self.subTest(value=value):
                self._assert_silent_failure(updates={f"{PREFIX}OUTPUT": value})

    def test_missing_symlink_hardlink_and_directory_outputs_are_rejected(self) -> None:
        self.output.unlink()
        self._assert_silent_failure()

        target = self.root / "target.aab"
        target.touch(mode=0o600)
        self.output.symlink_to(target)
        self._assert_silent_failure()
        self.output.unlink()

        os.link(target, self.output)
        self._assert_silent_failure()
        self.output.unlink()

        self.output.mkdir(mode=0o700)
        self._assert_silent_failure()

    def test_nonempty_or_permission_substituted_output_is_rejected(self) -> None:
        self._precreate_output(b"stale")
        self._assert_silent_failure()
        self._precreate_output(mode=0o644)
        self._assert_silent_failure()

    def test_special_path_spawns_and_writes_nothing(self) -> None:
        spec = importlib.util.spec_from_file_location("signed_aab_witness", PRODUCER)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(module)
        source = module._run_native_build_witness.__code__
        names = set(source.co_names)
        self.assertNotIn("subprocess", names)
        self.assertNotIn("fork", names)
        self.assertNotIn("rename", names)
        self.assertNotIn("replace", names)
        self.assertNotIn("unlink", names)
        self.assertNotIn("write", names)
        self.assertNotIn("open", names)

    def test_normal_cli_behavior_remains_outside_the_switch(self) -> None:
        completed = self._run(arguments=["--help"])
        self.assertEqual(completed.returncode, 0)
        self.assertIn(b"usage:", completed.stdout)
        self.assertEqual(completed.stderr, b"")


if __name__ == "__main__":
    unittest.main()
