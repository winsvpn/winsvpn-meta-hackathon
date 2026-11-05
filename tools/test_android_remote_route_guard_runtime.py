#!/usr/bin/env python3
"""Real isolated mocked-runtime tests for the privileged Android route guard."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import unittest


FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "android_remote_guard_mock_runtime.sh"


def _wsl_path(path: pathlib.Path) -> str:
    value = str(path.resolve())
    if len(value) >= 3 and value[1:3] == ":\\":
        return f"/mnt/{value[0].lower()}/{value[3:].replace(os.sep, '/')}"
    return value


@unittest.skipUnless(
    os.name == "nt" or sys.platform.startswith("linux"),
    "privileged route-guard runtime requires Linux or Windows WSL",
)
class AndroidRemoteGuardRuntimeTests(unittest.TestCase):
    maxDiff = None

    def run_case(self, name: str) -> None:
        if os.name == "nt":
            command = ["wsl.exe", "bash", _wsl_path(FIXTURE), name]
        else:
            command = ["bash", str(FIXTURE), name]
        result = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
        self.assertEqual(
            result.returncode,
            0,
            f"case={name}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def test_stdin_is_bounded_and_invalid_payload_is_cleaned(self) -> None:
        self.run_case("oversize")
        self.run_case("invalid-payload")

    def test_unsafe_symlink_and_owner_are_rejected(self) -> None:
        self.run_case("unsafe-symlink")
        self.run_case("unsafe-owner")

    def test_orphan_rule_and_timer_are_rejected(self) -> None:
        self.run_case("orphan-rule")
        self.run_case("orphan-unit")

    def test_systemd_run_failure_rolls_back_exact_operation(self) -> None:
        self.run_case("systemd-run-rollback")

    def test_observe_failure_rolls_back_exact_operation(self) -> None:
        self.run_case("observe-failure-rollback")

    def test_observe_uses_only_chain_files_and_never_argv_for_state(self) -> None:
        self.run_case("no-observe-argv-leak")


if __name__ == "__main__":
    unittest.main()
