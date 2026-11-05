#!/usr/bin/env python3
"""Unprivileged hostile tests for the macOS Go custody privilege helper."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "release_go_archive_custody_helper.c"
RUNTIME_PREFIX = "wins-release-go."
UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)


def runtime_identity(path: Path) -> str:
    info = path.lstat()
    return ":".join(
        str(value)
        for value in (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_mode,
            info.st_nlink,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    )


@unittest.skipUnless(sys.platform == "darwin", "macOS custody helper target required")
class ReleaseGoArchiveCustodyHelperTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = Path(
            tempfile.mkdtemp(prefix="wins-go-helper-test.", dir="/private/tmp")
        )
        cls.base.chmod(0o700)
        cls.helper = cls.base / "helper-test"
        cls.production_helper = cls.base / "helper-production"
        common = [
            "/usr/bin/xcrun",
            "--sdk",
            "macosx",
            "clang",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Wconversion",
            "-Wsign-conversion",
            "-Wshadow",
            "-Werror",
            "-Os",
        ]
        subprocess.run(
            [*common, "-DWINS_CUSTODY_TESTING", str(SOURCE), "-o", str(cls.helper)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [*common, str(SOURCE), "-o", str(cls.production_helper)],
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._make_removable(cls.base)
        shutil.rmtree(cls.base, ignore_errors=True)

    @staticmethod
    def _make_removable(root: Path) -> None:
        if not (root.exists() or root.is_symlink()):
            return
        for base, directories, files in os.walk(root, topdown=False, followlinks=False):
            for name in files + directories:
                path = Path(base) / name
                if path.is_symlink():
                    continue
                try:
                    os.chflags(path, 0, follow_symlinks=False)
                except OSError:
                    pass
                try:
                    path.chmod(0o700 if path.is_dir() else 0o600)
                except OSError:
                    pass
        try:
            os.chflags(root, 0, follow_symlinks=False)
        except OSError:
            pass
        try:
            root.chmod(0o700)
        except OSError:
            pass

    def setUp(self) -> None:
        self.runtime = Path(
            tempfile.mkdtemp(prefix=RUNTIME_PREFIX, dir="/private/tmp")
        )
        self.runtime.chmod(0o700)
        self.exec_dir = self.runtime / "exec"
        self.tree = self.exec_dir / "tree"
        (self.tree / "bin").mkdir(parents=True, mode=0o700)
        (self.tree / "src").mkdir(mode=0o700)
        (self.tree / "bin" / "go").write_bytes(b"synthetic helper fixture\n")
        (self.tree / "src" / "LICENSE").write_bytes(b"fixture\n")
        (self.tree / "bin" / "gofmt").symlink_to("../src/LICENSE")
        (self.tree / "bin" / "go").chmod(0o500)
        (self.tree / "src" / "LICENSE").chmod(0o400)
        (self.tree / "bin").chmod(0o500)
        (self.tree / "src").chmod(0o500)
        self.tree.chmod(0o500)
        self.exec_dir.chmod(0o700)
        self.identity = runtime_identity(self.runtime)

    def tearDown(self) -> None:
        self._make_removable(self.runtime)
        shutil.rmtree(self.runtime, ignore_errors=True)

    def _run(
        self,
        action: str,
        *extra: str,
        helper: Path | None = None,
        runtime_name: str | None = None,
        identity: str | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(helper or self.helper),
                action,
                runtime_name or self.runtime.name,
                identity or self.identity,
                *extra,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env or {},
            timeout=30,
        )

    def _assert_no_test_immutable(self) -> None:
        for base, directories, files in os.walk(
            self.tree, topdown=False, followlinks=False
        ):
            for name in files + directories:
                path = Path(base) / name
                if not path.is_symlink():
                    self.assertEqual(path.lstat().st_flags & UF_IMMUTABLE, 0, path)
        self.assertEqual(self.tree.lstat().st_flags & UF_IMMUTABLE, 0)

    def test_valid_tree_is_inspected_without_ambient_tools(self) -> None:
        attacker = self.runtime / "attacker-bin"
        attacker.mkdir(mode=0o700)
        marker = self.runtime / "ambient-tool-ran"
        fake = attacker / "chflags"
        fake.write_text(
            f"#!/bin/sh\n/usr/bin/touch {marker}\nexit 99\n", encoding="ascii"
        )
        fake.chmod(0o700)
        self.identity = runtime_identity(self.runtime)
        completed = self._run(
            "inspect", env={"PATH": str(attacker), "ATTACKER": "present"}
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(marker.exists())

    def test_symlinked_runtime_exec_tree_and_escape_are_rejected(self) -> None:
        victim = self.base / "victim"
        victim.mkdir(exist_ok=True)
        (victim / "sentinel").write_bytes(b"unchanged\n")
        original = (victim / "sentinel").read_bytes()

        alias = Path(
            tempfile.mktemp(prefix=RUNTIME_PREFIX, dir="/private/tmp")
        )
        alias.symlink_to(self.runtime)
        self.addCleanup(alias.unlink, missing_ok=True)
        linked_runtime = self._run("inspect", runtime_name=alias.name)
        self.assertNotEqual(linked_runtime.returncode, 0)
        self.assertIn("runtime identity", linked_runtime.stderr)

        self._make_removable(self.exec_dir)
        shutil.rmtree(self.exec_dir)
        self.exec_dir.symlink_to(victim)
        self.identity = runtime_identity(self.runtime)
        linked_exec = self._run("inspect")
        self.assertNotEqual(linked_exec.returncode, 0)
        self.assertIn("exec directory", linked_exec.stderr)
        self.exec_dir.unlink()

        self.exec_dir.mkdir(mode=0o700)
        self.identity = runtime_identity(self.runtime)
        (self.exec_dir / "tree").symlink_to(victim)
        linked_tree = self._run("inspect")
        self.assertNotEqual(linked_tree.returncode, 0)
        self.assertIn("execution tree", linked_tree.stderr)
        (self.exec_dir / "tree").unlink()

        self.tree.mkdir(mode=0o700)
        (self.tree / "escape").symlink_to("../../../../tmp")
        self.tree.chmod(0o500)
        escaped = self._run("inspect")
        self.assertNotEqual(escaped.returncode, 0)
        self.assertIn("symbolic link", escaped.stderr)
        self.assertEqual((victim / "sentinel").read_bytes(), original)

    def test_hardlinked_external_file_is_rejected_without_touching_victim(self) -> None:
        victim = self.base / "hardlink-victim"
        victim.write_bytes(b"external bytes\n")
        victim.chmod(0o400)
        linked = self.tree / "src" / "external"
        (self.tree / "src").chmod(0o700)
        os.link(victim, linked)
        (self.tree / "src").chmod(0o500)
        before = victim.lstat()
        completed = self._run("inspect")
        after = victim.lstat()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsafe tree entry", completed.stderr)
        self.assertEqual(victim.read_bytes(), b"external bytes\n")
        self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
        self.assertEqual(after.st_flags, before.st_flags)

    def test_wrong_mode_owner_identity_prefix_and_out_of_tree_path_are_rejected(self) -> None:
        values = self.identity.split(":")
        values[2] = str(os.getuid() + 1)
        wrong_owner = self._run("inspect", identity=":".join(values))
        self.assertNotEqual(wrong_owner.returncode, 0)
        self.assertIn("name or identity", wrong_owner.stderr)

        self.runtime.chmod(0o755)
        wrong_mode = self._run("inspect")
        self.assertNotEqual(wrong_mode.returncode, 0)
        self.assertIn("runtime identity", wrong_mode.stderr)
        self.runtime.chmod(0o700)

        bad_prefix = self._run("inspect", runtime_name="ordinary-runtime")
        self.assertNotEqual(bad_prefix.returncode, 0)
        self.assertIn("name or identity", bad_prefix.stderr)
        out_of_tree = self._run("inspect", runtime_name="../wins-release-go.escape")
        self.assertNotEqual(out_of_tree.returncode, 0)
        self.assertIn("name or identity", out_of_tree.stderr)

    def test_tree_path_swap_after_descriptor_binding_is_rejected(self) -> None:
        ready_read, ready_write = os.pipe()
        continue_read, continue_write = os.pipe()
        process = subprocess.Popen(
            [
                str(self.helper),
                "test-inspect-pause",
                self.runtime.name,
                self.identity,
                str(ready_write),
                str(continue_read),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={},
            pass_fds=(ready_write, continue_read),
        )
        os.close(ready_write)
        os.close(continue_read)
        try:
            self.assertEqual(os.read(ready_read, 1), b"R")
            original = self.exec_dir / "tree-original"
            self.tree.rename(original)
            self.tree.mkdir(mode=0o500)
            os.write(continue_write, b"C")
            stdout, stderr = process.communicate(timeout=30)
        finally:
            os.close(ready_read)
            os.close(continue_write)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        self.assertNotEqual(process.returncode, 0, stdout)
        self.assertIn("tree path changed", stderr)

    def test_partial_seal_and_unseal_failures_leave_no_flag_residue(self) -> None:
        partial_seal = self._run("test-seal-failure", "2")
        self.assertEqual(partial_seal.returncode, 0, partial_seal.stderr)
        self._assert_no_test_immutable()

        partial_unseal = self._run("test-unseal-failure", "2")
        self.assertEqual(partial_unseal.returncode, 0, partial_unseal.stderr)
        self._assert_no_test_immutable()

    def test_production_mutation_refuses_missing_privilege(self) -> None:
        completed = self._run("seal", helper=self.production_helper)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("effective uid 0", completed.stderr)
        self._assert_no_test_immutable()

    def test_source_has_fixed_descriptor_relative_boundary(self) -> None:
        source = SOURCE.read_text(encoding="ascii")
        for token in (
            'PRIVATE_TMP "/private/tmp"',
            'RUNTIME_PREFIX "wins-release-go."',
            "O_NOFOLLOW",
            "openat(",
            "fstatat(",
            "AT_SYMLINK_NOFOLLOW",
            "fchflags(",
            "st_nlink == 1",
            "runtime_info.st_dev != private_info.st_dev",
            "close_inherited_descriptors",
            "clear_environment",
            "partial seal rollback failed",
        ):
            self.assertIn(token, source)
        self.assertNotIn("system(", source)
        self.assertNotIn("popen(", source)
        self.assertNotIn("execv", source)
        self.assertNotIn("/usr/bin/chflags", source)

    def test_helper_compiles_with_strict_production_and_test_flags(self) -> None:
        for testing in (False, True):
            command = [
                "/usr/bin/xcrun",
                "--sdk",
                "macosx",
                "clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Wconversion",
                "-Wsign-conversion",
                "-Wshadow",
                "-Werror",
                "-fsyntax-only",
            ]
            if testing:
                command.append("-DWINS_CUSTODY_TESTING")
            command.append(str(SOURCE))
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
