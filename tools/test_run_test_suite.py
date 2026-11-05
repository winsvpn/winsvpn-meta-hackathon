#!/usr/bin/env python3
"""Tests for the release-critical Python suite runner itself.

Two invocation conventions coexist in tools/ (see run_test_suite.py's
module docstring), so the classification logic is the part most likely
to silently regress -- get it wrong and a file fails with an unrelated
ModuleNotFoundError instead of running its actual tests. This also
exercises the runner's pass/fail/exit-code contract end to end, since
that contract is what makes a CI job actually block on a real failure.
"""

from __future__ import annotations

import subprocess
import os
import sys
import tempfile
import unittest
from pathlib import Path

import run_test_suite as runner

ROOT = Path(__file__).resolve().parent.parent
RUNNER_SOURCE = (ROOT / "tools" / "run_test_suite.py").read_text(encoding="utf-8")


class NeedsPackageInvocationTests(unittest.TestCase):
    def test_bare_sibling_import_file_runs_as_direct_script(self) -> None:
        path = ROOT / "tools" / "test_release_source_freeze.py"
        self.assertIn("import release_source_freeze", path.read_text(encoding="utf-8"))
        self.assertFalse(runner.needs_package_invocation(path))

    def test_package_qualified_import_file_runs_as_module(self) -> None:
        path = ROOT / "tools" / "test_stage_control_triage_engine.py"
        self.assertIn("from tools.stage_control_triage_engine import", path.read_text(encoding="utf-8"))
        self.assertTrue(runner.needs_package_invocation(path))

    def test_from_tools_import_without_dotted_module_also_counts(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            path = Path(value) / "test_fixture.py"
            path.write_text("from tools import something\n", encoding="utf-8")
            self.assertTrue(runner.needs_package_invocation(path))

    def test_package_qualified_import_statement_runs_as_module(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            path = Path(value) / "test_fixture.py"
            path.write_text("import tools.something as subject\n", encoding="utf-8")
            self.assertTrue(runner.needs_package_invocation(path))

    def test_similarly_prefixed_package_does_not_count(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            path = Path(value) / "test_fixture.py"
            path.write_text("import toolsmith\n", encoding="utf-8")
            self.assertFalse(runner.needs_package_invocation(path))


class TestArgumentClassificationTests(unittest.TestCase):
    def _fixture(self, body: str) -> tuple[tempfile.TemporaryDirectory, Path]:
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "test_fixture.py"
        path.write_text(body, encoding="utf-8")
        return directory, path

    def test_required_subcommand_utility_uses_explicit_self_test(self) -> None:
        directory, path = self._fixture(
            "import argparse, sys\n"
            "parser = argparse.ArgumentParser()\n"
            "parser.add_subparsers(dest='cmd', required=True)\n"
            "if sys.argv[1] == '--self-test': pass\n"
        )
        with directory:
            self.assertEqual(runner.test_arguments(path), ["--self-test"])

    def test_required_subcommand_without_self_test_fails_closed(self) -> None:
        directory, path = self._fixture(
            "import argparse\n"
            "parser = argparse.ArgumentParser()\n"
            "parser.add_subparsers(dest='cmd', required=True)\n"
        )
        with directory:
            with self.assertRaisesRegex(runner.TestInvocationError, "no explicit"):
                runner.test_arguments(path)

    def test_ordinary_test_receives_no_arguments(self) -> None:
        directory, path = self._fixture("import unittest\n")
        with directory:
            self.assertEqual(runner.test_arguments(path), [])

    def test_linux_arm64_cli_utility_is_invoked_via_self_test(self) -> None:
        path = ROOT / "tools" / "test_linux_arm64_fallback_elf.py"
        self.assertEqual(runner.command_for(path)[-1], "--self-test")

    def test_pytest_roots_use_one_file_at_a_time_without_script_import_heuristics(self) -> None:
        path = ROOT / "router" / "tests" / "test_router.py"
        self.assertEqual(
            runner.command_for(path),
            [
                os.environ.get("WINS_RELEASE_CHILD_PYTHON", sys.executable),
                "-S",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "router/tests/test_router.py",
            ],
        )

    def test_server_unit_suites_and_web_policy_use_their_explicit_modes(self) -> None:
        script_server_path = ROOT / "server" / "test_winn3_serving_hub.py"
        pytest_server_path = ROOT / "server" / "test_smart_router_hub_selection.py"
        web_path = ROOT / "test" / "web_download_asset_decision_test.py"
        self.assertEqual(runner.discovery_mode(script_server_path), "script")
        self.assertEqual(runner.discovery_mode(pytest_server_path), "pytest")
        self.assertEqual(runner.discovery_mode(web_path), "script")
        self.assertEqual(
            runner.command_for(web_path),
            [
                os.environ.get("WINS_RELEASE_CHILD_PYTHON", sys.executable),
                "-S",
                str(web_path),
            ],
        )


class DiscoveryTests(unittest.TestCase):
    def test_release_discovery_covers_each_approved_root_once_in_sorted_order(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            expected = {
                "dashboard/test_dashboard.py",
                "extension/tools/test_extension.py",
                "router/tests/test_router.py",
                "server/test_control_plane.py",
                "test/web_download_asset_decision_test.py",
                "tools/gcp_probe_test.py",
                "tools/native_messaging/test_native_host.py",
                "tools/test_primary.py",
                "tools/test_dual_test.py",
            }
            for relative in expected:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# test fixture\n", encoding="utf-8")
            discovered = [path.relative_to(root).as_posix() for path in runner.discover_test_files(root)]
        self.assertEqual(discovered, sorted(expected))
        self.assertEqual(len(discovered), len(set(discovered)))

    def test_fixture_and_non_release_roots_are_explicitly_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            included = root / "tools/test_primary.py"
            excluded = (
                root / "tools/fixtures/test_helper.py",
                root / "router/tests/testdata/test_router_fixture.py",
                root / "docs/evidence/test_evidence.py",
                root / "staging-hub/tests/test_hub.py",
                root / "test/other_python_test.py",
            )
            included.parent.mkdir(parents=True, exist_ok=True)
            included.write_text("# included\n", encoding="utf-8")
            for path in excluded:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# excluded\n", encoding="utf-8")
            discovered = [path.relative_to(root).as_posix() for path in runner.discover_test_files(root)]
        self.assertEqual(discovered, ["tools/test_primary.py"])
        self.assertTrue(runner.EXCLUDED_TEST_ROOTS)

    def test_real_checkout_covers_all_approved_release_contracts(self) -> None:
        discovered = {path.relative_to(ROOT).as_posix() for path in runner.discover_test_files()}
        required = {
            "dashboard/test_dashboard.py",
            "extension/tools/core_tests.py",
            "extension/tools/test_packaging.py",
            "router/tests/test_router.py",
            "server/test_smart_router_hub_selection.py",
            "server/test_winn3_serving_hub.py",
            "test/web_download_asset_decision_test.py",
            "test/web_download_artifact_gate.py",
            "test/web_download_artifact_gate_test.py",
            "tools/gcp_deployment_inputs_test.py",
            "tools/gcp_proof_deploy_test.py",
        }
        self.assertTrue(required.issubset(discovered), sorted(required - discovered))
        for directory, pattern, _mode in runner.DISCOVERY_RULES:
            root = ROOT / directory
            expected = {
                path.relative_to(ROOT).as_posix()
                for path in root.glob(pattern)
                if path.is_file()
                and not path.is_symlink()
                and not runner._is_fixture_or_helper_path(path, ROOT)
            }
            self.assertTrue(expected.issubset(discovered), (directory, expected - discovered))

        server_tests = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "server").glob("test_*.py")
            if path.is_file() and not path.is_symlink()
        }
        self.assertTrue(server_tests)
        self.assertTrue(server_tests.issubset(discovered), sorted(server_tests - discovered))
        self.assertEqual(
            {path for path in discovered if path.startswith("test/")},
            {
                "test/web_download_asset_decision_test.py",
                "test/web_download_artifact_gate.py",
                "test/web_download_artifact_gate_test.py",
            },
        )


class RunnerEndToEndTests(unittest.TestCase):
    """Runs the real script (copied so __file__ resolves inside a throwaway
    tree) against synthetic pass/fail fixtures to check the CLI contract."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.fake_root = Path(self.tmpdir.name)
        (self.fake_root / "tools").mkdir()
        (self.fake_root / "tools" / "run_test_suite.py").write_text(RUNNER_SOURCE, encoding="utf-8")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _write(self, name: str, body: str) -> None:
        (self.fake_root / "tools" / name).write_text(body, encoding="utf-8")

    def _write_relative(self, relative: str, body: str) -> None:
        path = self.fake_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    def _run(
        self,
        extra_env: dict[str, str] | None = None,
        *arguments: str,
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            path
            for path in sys.path
            if path
            and (
                "site-packages" in path
                or path == os.environ.get("WINS_RELEASE_PYTHON_VENDOR")
            )
        )
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [
                sys.executable,
                str(self.fake_root / "tools" / "run_test_suite.py"),
                *arguments,
            ],
            cwd=self.fake_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_all_passing_files_exit_zero(self) -> None:
        self._write(
            "test_ok.py",
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_it(self): self.assertEqual(1, 1)\n"
            "if __name__ == '__main__': unittest.main()\n",
        )
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_browser_runtime_suite_can_be_split_without_changing_discovery(self) -> None:
        self._write("test_ok.py", "raise SystemExit(0)\n")
        self._write_relative("extension/tools/core_tests.py", "raise SystemExit(0)\n")

        browser = self._run(None, "--browser-runtime-only")
        self.assertEqual(browser.returncode, 0, browser.stdout + browser.stderr)
        self.assertIn("extension/tools/core_tests", browser.stdout)
        self.assertNotIn("tools/test_ok", browser.stdout)

        non_browser = self._run(None, "--exclude-browser-runtime")
        self.assertEqual(non_browser.returncode, 0, non_browser.stdout + non_browser.stderr)
        self.assertIn("tools/test_ok", non_browser.stdout)
        self.assertNotIn("extension/tools/core_tests", non_browser.stdout)

        listed = self._run(None, "--list")
        self.assertIn("extension/tools/core_tests.py", listed.stdout)
        self.assertIn("tools/test_ok.py", listed.stdout)

    def test_child_tests_do_not_inherit_active_release_python_custody(self) -> None:
        child_python = str(Path(sys.executable).resolve())
        self._write(
            "test_custody_env.py",
            "import os, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_clean(self):\n"
                "        for name in ('WINS_RELEASE_PYTHON_RUNTIME', 'WINS_RELEASE_PYTHON_RUNTIME_ID', 'WINS_RELEASE_PYTHON_BIN', 'WINS_RELEASE_PYTHON_VENDOR', 'WINS_RELEASE_CHILD_PYTHON'):\n"
            "            self.assertNotIn(name, os.environ)\n"
            "if __name__ == '__main__': unittest.main()\n",
        )
        result = self._run(
            {
                "WINS_RELEASE_PYTHON_RUNTIME": "/private/tmp/active",
                "WINS_RELEASE_PYTHON_RUNTIME_ID": "active",
                "WINS_RELEASE_PYTHON_BIN": child_python,
                "WINS_RELEASE_PYTHON_VENDOR": "/private/tmp/vendor",
                "WINS_RELEASE_CHILD_PYTHON": child_python,
            }
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1/1 release-critical Python test files passed", result.stdout)

    def test_a_single_failing_file_fails_the_whole_run(self) -> None:
        self._write(
            "test_ok.py",
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_it(self): self.assertEqual(1, 1)\n"
            "if __name__ == '__main__': unittest.main()\n",
        )
        self._write(
            "test_bad.py",
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_it(self): self.assertEqual(1, 2)\n"
            "if __name__ == '__main__': unittest.main()\n",
        )
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1/2 release-critical Python test files passed", result.stdout)
        self.assertIn("Failed: tools/test_bad", result.stdout)

    def test_no_test_files_is_reported_as_an_error_not_a_silent_pass(self) -> None:
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_import_tools_file_runs_as_package_module(self) -> None:
        (self.fake_root / "tools" / "__init__.py").write_text("", encoding="utf-8")
        (self.fake_root / "tools" / "subject.py").write_text("VALUE = 7\n", encoding="utf-8")
        self._write(
            "test_package_import.py",
            "import tools.subject as subject\n"
            "assert subject.VALUE == 7\n",
        )
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_required_subcommand_utility_runs_explicit_self_test(self) -> None:
        self._write(
            "test_cli_utility.py",
            "import argparse, sys\n"
            "def cli():\n"
            "    parser = argparse.ArgumentParser()\n"
            "    parser.add_subparsers(dest='cmd', required=True)\n"
            "    parser.parse_args()\n"
            "if __name__ == '__main__':\n"
            "    if len(sys.argv) > 1 and sys.argv[1] == '--self-test':\n"
            "        raise SystemExit(0)\n"
            "    cli()\n",
        )
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_pytest_style_router_file_is_executed_once(self) -> None:
        self._write_relative(
            "router/tests/test_router.py",
            "def test_router_contract():\n"
            "    assert 7 == 7\n",
        )
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("router/tests/test_router", result.stdout)

    def test_server_and_exact_web_policy_files_are_executed(self) -> None:
        self._write_relative(
            "server/test_control_plane.py",
            "raise SystemExit(0)\n",
        )
        self._write_relative(
            "server/test_smart_router_hub_selection.py",
            "def test_control_plane_contract():\n"
            "    assert 7 == 7\n",
        )
        self._write_relative(
            "test/web_download_asset_decision_test.py",
            "raise SystemExit(0)\n",
        )
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("server/test_control_plane", result.stdout)
        self.assertIn("test/web_download_asset_decision_test", result.stdout)

    def test_list_mode_emits_only_sorted_release_paths_without_execution(self) -> None:
        self._write("test_tools.py", "raise RuntimeError('must not execute while listing')\n")
        self._write_relative("dashboard/test_dashboard.py", "raise RuntimeError('must not execute while listing')\n")
        result = subprocess.run(
            [sys.executable, str(self.fake_root / "tools" / "run_test_suite.py"), "--list"],
            cwd=self.fake_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["dashboard/test_dashboard.py", "tools/test_tools.py"])

    def test_unclassified_required_subcommand_utility_fails_without_execution(self) -> None:
        marker = self.fake_root / "executed"
        self._write(
            "test_unsafe_cli.py",
            "import argparse\n"
            f"open({str(marker)!r}, 'w').close()\n"
            "parser = argparse.ArgumentParser()\n"
            "parser.add_subparsers(dest='cmd', required=True)\n"
            "parser.parse_args()\n",
        )
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RUNNER CLASSIFICATION ERROR", result.stdout)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
