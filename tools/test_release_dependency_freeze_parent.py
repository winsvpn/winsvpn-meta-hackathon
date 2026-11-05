#!/usr/bin/env python3
"""Hostile static and invocation tests for the freeze worker parent."""

from __future__ import annotations

from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT / "tools" / "run_release_dependency_freeze.sh"
CONTROLLER = ROOT / "tools" / "release_dependency_freeze.py"


class ReleaseDependencyFreezeParentTest(unittest.TestCase):
    def test_shell_is_valid_and_relative_invocation_fails_closed(self) -> None:
        syntax = subprocess.run(
            ["/bin/bash", "-n", str(PARENT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        relative = subprocess.run(
            ["/bin/bash", "tools/run_release_dependency_freeze.sh", "freeze-shared"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotEqual(relative.returncode, 0)
        self.assertIn("absolute repository path", relative.stderr)

    def test_parent_opens_and_executes_the_held_descriptor(self) -> None:
        source = PARENT.read_text(encoding="ascii")
        self.assertIn('exec 9<"$controller"', source)
        self.assertIn('"$python" -I -S /dev/fd/9', source)
        self.assertIn("--_wins-release-dependency-worker-fd 9", source)
        self.assertNotIn("/usr/bin/sudo", source)
        self.assertNotIn("eval ", source)

    def test_parent_raises_the_open_file_soft_limit_before_the_worker(self) -> None:
        # The worker holds descriptors for every selected input and its ancestor
        # chain (about 14,845 for the Android set); PowerShell hands children a
        # soft limit of 10240.
        source = PARENT.read_text(encoding="ascii")
        self.assertIn("readonly required_open_files=131072", source)
        self.assertIn("readonly soft_open_files", source)
        self.assertIn('ulimit -Sn "$required_open_files"', source)
        self.assertLess(
            source.index('ulimit -Sn "$required_open_files"'),
            source.index('exec 9<"$controller"'),
        )
        # The live probe below needs the pinned darwin Python; say so instead of
        # passing without it (R22 Y3-12).
        if sys.platform != "darwin":
            self.skipTest("the parent ulimit probe runs only on darwin")
        pins = json.loads((ROOT / "tools" / "toolchain-pins.json").read_text(encoding="utf-8"))
        python = pins["tools"]["python"]["reviewed_executable_path"].get("darwin_arm64")
        if python is None or not Path(python).is_file():
            self.skipTest("the pinned darwin release Python is not installed")
        low_hard = subprocess.run(
            [
                "/bin/bash",
                "-c",
                'ulimit -Sn 512 && ulimit -Hn 512 && exec /bin/bash "$1" verify-index',
                "--",
                str(PARENT),
            ],
            cwd="/private/tmp",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(low_hard.returncode, 1)
        self.assertEqual(low_hard.stdout, "")
        self.assertIn(
            "RELEASE DEPENDENCY FREEZE PARENT: FAIL: cannot raise the open-file soft limit to 131072 (soft 512, hard 512)",
            low_hard.stderr,
        )
        low_soft = subprocess.run(
            [
                "/bin/bash",
                "-c",
                'ulimit -Sn 512 && exec /bin/bash "$1" verify-index',
                "--",
                str(PARENT),
            ],
            cwd="/private/tmp",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertNotIn("RELEASE DEPENDENCY FREEZE PARENT: FAIL", low_soft.stderr)
        self.assertIn("RELEASE DEPENDENCY FREEZE: FAIL:", low_soft.stderr)

    def test_controller_raises_open_file_soft_limit_and_fails_clearly(self) -> None:
        from unittest import mock
        import release_dependency_freeze as controller

        if controller.resource is None:
            self.skipTest("resource module is unavailable")
        infinity = getattr(controller.resource, "RLIM_INFINITY", -1)
        with (
            mock.patch.object(
                controller.resource, "getrlimit", return_value=(10240, infinity)
            ),
            mock.patch.object(controller.resource, "setrlimit") as setrlimit,
        ):
            controller._ensure_open_file_soft_limit()
            setrlimit.assert_called_once_with(
                controller.resource.RLIMIT_NOFILE,
                (controller.REQUIRED_OPEN_FILES, infinity),
            )
        with mock.patch.object(
            controller.resource, "getrlimit", return_value=(512, 4096)
        ):
            with self.assertRaisesRegex(
                controller.DependencyFreezeError,
                r"cannot raise the open-file soft limit to 131072 \(soft 512, hard 4096\)",
            ):
                controller._ensure_open_file_soft_limit()
        with (
            mock.patch.object(
                controller.resource, "getrlimit", return_value=(10240, infinity)
            ),
            mock.patch.object(
                controller.resource,
                "setrlimit",
                side_effect=OSError(22, "Invalid argument"),
            ),
        ):
            with self.assertRaisesRegex(
                controller.DependencyFreezeError,
                r"cannot raise the open-file soft limit to 131072 \(soft 10240, hard unlimited\): \[Errno 22\] Invalid argument",
            ):
                controller._ensure_open_file_soft_limit()

    def test_parent_forwards_every_argument_to_the_worker_unchanged(self) -> None:
        # New controller flags (for example create-index --platforms) reach the
        # worker only if the parent neither parses, filters nor reorders them.
        source = PARENT.read_text(encoding="ascii")
        self.assertTrue(
            source.rstrip().endswith('--_wins-release-dependency-worker-fd 9 "$@"')
        )
        self.assertEqual(source.count('"$@"'), 1)
        self.assertNotIn("shift", source)
        self.assertNotIn('case "$1"', source)
        self.assertNotIn("getopts", source)

    def test_environment_is_the_exact_reviewed_worker_environment(self) -> None:
        source = PARENT.read_text(encoding="ascii")
        expected = {
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONNOUSERSITE",
            "TMPDIR",
        }
        block = source.split("exec /usr/bin/env -i", 1)[1].split('"$python"', 1)[0]
        actual = {
            line.strip().split("=", 1)[0]
            for line in block.splitlines()
            if "=" in line
        }
        self.assertEqual(actual, expected)

    def test_parent_launches_only_the_sha256_pinned_interpreter(self) -> None:
        source = PARENT.read_text(encoding="ascii")
        self.assertNotIn("/Library/WinsVPN/ReleasePython", source)
        self.assertNotIn("DYLD_", source)
        self.assertIn('readonly pins="$tool_dir/toolchain-pins.json"', source)
        self.assertIn("object_pairs_hook=reject_duplicates", source)
        self.assertIn('python["reviewed_executable_path"][sys.argv[2]]', source)
        self.assertIn('python["executable_sha256"][sys.argv[2]]', source)
        self.assertIn('/usr/bin/shasum -a 256 -- "$python"', source)
        self.assertIn('[[ "$observed_sha256" == "$python_sha256" ]] ||', source)
        hash_check = source.index('[[ "$observed_sha256" == "$python_sha256" ]]')
        self.assertLess(hash_check, source.index('exec 9<"$controller"'))

    def test_parent_refuses_interpreter_whose_bytes_differ_from_pin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-freeze-parent-") as temporary:
            repo = Path(temporary).resolve()
            tools = repo / "tools"
            tools.mkdir(mode=0o700)
            for name in (
                "release_dependency_freeze.py",
                "run_release_dependency_freeze.sh",
                "toolchain-pins.json",
            ):
                shutil.copy2(ROOT / "tools" / name, tools / name)
            pins_path = tools / "toolchain-pins.json"
            pins = json.loads(pins_path.read_text(encoding="utf-8"))
            digests = pins["tools"]["python"]["executable_sha256"]
            for key in digests:
                digests[key] = "0" * 64
            pins_path.write_text(json.dumps(pins), encoding="utf-8")
            completed = subprocess.run(
                ["/bin/bash", str(tools / "run_release_dependency_freeze.sh"), "verify-index"],
                cwd="/private/tmp",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        if sys.platform != "darwin":
            self.assertIn("macOS release hosts only", completed.stderr)
            return
        python = pins["tools"]["python"]["reviewed_executable_path"].get("darwin_arm64")
        if python is None or not Path(python).is_file():
            self.assertIn("RELEASE DEPENDENCY FREEZE PARENT: FAIL", completed.stderr)
            return
        self.assertIn(
            "pinned release Python bytes do not match tools/toolchain-pins.json",
            completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
