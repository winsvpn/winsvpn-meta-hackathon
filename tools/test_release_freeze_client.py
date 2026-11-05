#!/usr/bin/env python3
"""Tests for tools/release_freeze_client.py (child-process access to the worker)."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import release_dependency_freeze as freeze  # noqa: E402
import release_freeze_client as client  # noqa: E402

ENVELOPE = {
    "ok": True,
    "fixture_only": False,
    "production_pass_allowed": True,
    "authority_kind": client.AUTHORITY_KIND,
    "command": "verify-receipt",
    "production_authority_authenticated": True,
    "production_build_witness": "NATIVE_WITNESSED",
    "publication_authorized": False,
}


class FreezeClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        (self.repo / "tools").mkdir()
        self.parent = self.repo / client.PARENT_RELATIVE
        self.original_pins = client.REVIEWED_WORKER_SHA256
        self.launch_pins = {}
        self.executable = self.repo / "release-python"
        self.executable.write_bytes(b"#!/bin/sh\nexit 1\n")
        self.executable.chmod(0o700)
        host_key = freeze._RELEASE_PYTHON_HOST_KEYS[os.uname().machine]
        pins = self.repo / "tools/toolchain-pins.json"
        pins.write_text(json.dumps({"tools": {"python": {
            "version": "3.14.7", "implementation": "cpython",
            "reviewed_executable_path": {host_key: str(self.executable)},
            "executable_sha256": {
                host_key: hashlib.sha256(self.executable.read_bytes()).hexdigest(),
            },
        }}}), encoding="utf-8")
        self.launch_pins["tools/toolchain-pins.json"] = hashlib.sha256(pins.read_bytes()).hexdigest()
        self.pin_patch = mock.patch.object(client, "REVIEWED_WORKER_SHA256", self.launch_pins)
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _stub(self, body: str) -> None:
        self.parent.write_text("#!/bin/bash\n" + body, encoding="utf-8")
        self.parent.chmod(stat.S_IRWXU)
        self.launch_pins[client.PARENT_RELATIVE] = hashlib.sha256(self.parent.read_bytes()).hexdigest()

    def _emit(self, payload: dict[str, object]) -> str:
        return "printf '%s\\n' '" + json.dumps(payload) + "'\n"

    def test_verify_build_receipt_passes_the_exact_arguments_and_returns_the_result(self) -> None:
        record = dict(ENVELOPE, platform="ios", artifact_sha256="a" * 64,
                      artifact_size_bytes=7, receipt_sha256="b" * 64)
        argv_log = self.repo / "argv.txt"
        argv_log.touch()
        self._stub(f'printf \'%s\\n\' "$@" > "{argv_log}"\n' + self._emit(record))
        result = client.verify_build_receipt(
            self.repo, self.repo / ".artifacts/i/RELEASE_INPUT_INDEX.json", "ios",
            self.repo / ".artifacts/r.json", self.repo / "Win's VPN.ipa",
        )
        self.assertEqual(result["artifact_sha256"], "a" * 64)
        self.assertEqual(
            argv_log.read_text(encoding="utf-8").splitlines(),
            [
                "verify-receipt", "--repo", str(self.repo),
                "--index", str(self.repo / ".artifacts/i/RELEASE_INPUT_INDEX.json"),
                "--platform", "ios",
                "--receipt", str(self.repo / ".artifacts/r.json"),
                "--artifact", str(self.repo / "Win's VPN.ipa"),
            ],
        )

    def test_a_secret_inventory_path_travels_as_one_flag_and_nothing_else_does(self) -> None:
        record = dict(ENVELOPE, platform="windows", artifact_sha256="a" * 64,
                      artifact_size_bytes=7, receipt_sha256="b" * 64)
        argv_log = self.repo / "argv.txt"
        argv_log.touch()
        self._stub(f'printf \'%s\\n\' "$@" > "{argv_log}"\n' + self._emit(record))
        client.verify_build_receipt(
            self.repo, "i.json", "windows", "r.json", "Setup.exe", "/owner/inventory.json"
        )
        self.assertEqual(
            argv_log.read_text(encoding="utf-8").splitlines(),
            [
                "verify-receipt", "--repo", str(self.repo), "--index", "i.json",
                "--platform", "windows", "--receipt", "r.json", "--artifact", "Setup.exe",
                "--secret-inventory-path", "/owner/inventory.json",
            ],
        )
        import inspect

        self.assertEqual(
            list(inspect.signature(client.verify_build_receipt).parameters),
            ["repo", "index", "platform", "receipt", "artifact", "secret_inventory_path"],
        )

    def test_a_refusal_by_the_worker_is_a_freeze_error_with_a_bounded_message(self) -> None:
        self._stub("echo 'RELEASE DEPENDENCY FREEZE: FAIL: Exact built artifact does not match' >&2\nexit 1\n")
        with self.assertRaisesRegex(freeze.DependencyFreezeError, "Exact built artifact does not match"):
            client.verify_build_receipt(self.repo, "i", "macos", "r", "a")

    def test_output_without_the_authority_envelope_is_refused(self) -> None:
        cases = {
            "not ok": self._emit(dict(ENVELOPE, ok=False)),
            "fixture": self._emit(dict(ENVELOPE, fixture_only=True)),
            "no pass": self._emit(dict(ENVELOPE, production_pass_allowed=False)),
            "not json": "echo not-json\n",
            "list": "echo '[]'\n",
            "missing": self._emit({"platform": "ios"}),
            "unauthenticated": self._emit(dict(ENVELOPE, production_authority_authenticated=False)),
            "publication": self._emit(dict(ENVELOPE, publication_authorized=True)),
            "wrong command": self._emit(dict(ENVELOPE, command="verify-index")),
            "wrong kind": self._emit(dict(ENVELOPE, authority_kind="other")),
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                self._stub(body)
                with self.assertRaises(client.FreezeClientError):
                    client.verify_build_receipt(self.repo, "i", "ios", "r", "a")

    def test_symlinked_or_missing_parent_and_missing_artifact_are_refused(self) -> None:
        with self.assertRaisesRegex(client.FreezeClientError, "unavailable"):
            client.verify_build_receipt(self.repo, "i", "ios", "r", "a")
        real = self.repo / "real.sh"
        real.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        os.symlink(real, self.parent)
        with self.assertRaisesRegex(client.FreezeClientError, "not a regular file"):
            client.verify_build_receipt(self.repo, "i", "ios", "r", "a")
        self.parent.unlink()
        self._stub(self._emit(ENVELOPE))
        with self.assertRaisesRegex(client.FreezeClientError, "requires the exact artifact"):
            client.verify_build_receipt(self.repo, "i", "ios", "r", None)

    def test_the_child_environment_carries_no_inherited_secret(self) -> None:
        env_log = self.repo / "env.txt"
        env_log.touch()
        self._stub(f'/usr/bin/env > "{env_log}"\n' + self._emit(ENVELOPE))
        os.environ["WINS_TEST_CLIENT_SECRET"] = "must-not-leak"
        try:
            client.verify_build_receipt(self.repo, "i", "ios", "r", "a")
        finally:
            del os.environ["WINS_TEST_CLIENT_SECRET"]
        names = {line.split("=", 1)[0] for line in env_log.read_text(encoding="utf-8").splitlines()}
        self.assertNotIn("WINS_TEST_CLIENT_SECRET", names)
        self.assertLessEqual(names, {"HOME", "LANG", "LC_ALL", "PATH", "PWD", "SHLVL", "_", "OLDPWD"})

    def test_changed_parent_is_refused_before_execution(self) -> None:
        self._stub(self._emit(ENVELOPE))
        self.parent.write_text("#!/bin/bash\necho forged\n")
        with mock.patch.object(client.subprocess, "run") as run:
            with self.assertRaisesRegex(client.FreezeClientError, "not reviewed"):
                client.verify_build_receipt(self.repo, "i", "ios", "r", "a")
            run.assert_not_called()

    def test_parent_mutation_during_execution_is_refused(self) -> None:
        self._stub(f'printf changed > "{self.parent}"\n' + self._emit(ENVELOPE))
        with self.assertRaises(freeze.DependencyFreezeError):
            client.verify_build_receipt(self.repo, "i", "ios", "r", "a")

    def test_changed_release_python_is_refused_before_execution(self) -> None:
        self._stub(self._emit(ENVELOPE))
        self.executable.write_bytes(b"#!/bin/sh\necho forged\n")
        with mock.patch.object(client.subprocess, "run") as run:
            with self.assertRaisesRegex(client.FreezeClientError, "executable is not reviewed"):
                client.verify_build_receipt(self.repo, "i", "ios", "r", "a")
            run.assert_not_called()

    def test_release_python_substitution_cannot_return_forged_success(self) -> None:
        self._stub(self._emit(ENVELOPE))
        original = self.executable.read_bytes()
        for restore in (False, True):
            with self.subTest(restore=restore):
                self.executable.write_bytes(original)

                def substituted_worker(*args, **kwargs):
                    # Model substitution after the parent's hash check and
                    # before exec. The untrusted executable prints the envelope.
                    self.executable.write_bytes(b"#!/bin/sh\necho forged\n")
                    if restore:
                        self.executable.write_bytes(original)
                    return client.subprocess.CompletedProcess(
                        [], 0, json.dumps(ENVELOPE).encode("utf-8"), b""
                    )

                with mock.patch.object(client.subprocess, "run", side_effect=substituted_worker):
                    with self.assertRaises(freeze.DependencyFreezeError):
                        client.verify_build_receipt(self.repo, "i", "ios", "r", "a")

    def test_launch_inputs_are_pinned_to_the_delivered_bytes(self) -> None:
        with mock.patch.object(client, "REVIEWED_WORKER_SHA256", self.original_pins):
            self.assertEqual(set(client.REVIEWED_WORKER_SHA256), {
                "tools/run_release_dependency_freeze.sh",
                "tools/release_dependency_freeze.py", "tools/toolchain-pins.json",
            })
            for relative, expected in client.REVIEWED_WORKER_SHA256.items():
                self.assertEqual(hashlib.sha256((TOOLS.parent / relative).read_bytes()).hexdigest(), expected)

    def test_delivered_launch_inputs_are_held_and_checked_before_the_parent_runs(self) -> None:
        # The stub tests pin only a fixture parent. This one runs the custody
        # helpers on the delivered parent, controller and pin manifest; the
        # parent itself is replaced by a recorded call and never executed.
        done = client.subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(ENVELOPE).encode("utf-8"), stderr=b""
        )
        with mock.patch.object(client, "REVIEWED_WORKER_SHA256", self.original_pins), \
                mock.patch.object(client.subprocess, "run", return_value=done) as run:
            result = client.verify_build_receipt(TOOLS.parent, "i", "ios", "r", "a")
        run.assert_called_once()
        self.assertEqual(
            run.call_args.args[0][1], str(TOOLS.parent.resolve() / client.PARENT_RELATIVE)
        )
        self.assertIs(result["ok"], True)

    def test_apple_consumers_use_the_client_not_the_library_entry(self) -> None:
        for name in ("freeze_apple_release_candidates.py", "validate_apple_submission_package.py"):
            with self.subTest(module=name):
                text = (TOOLS / name).read_text(encoding="utf-8")
                self.assertIn("from release_freeze_client import verify_build_receipt", text)
                self.assertNotIn("import verify_build_receipt", text.replace(
                    "from release_freeze_client import verify_build_receipt", ""))


if __name__ == "__main__":
    unittest.main()
