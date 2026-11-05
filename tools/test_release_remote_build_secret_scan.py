#!/usr/bin/env python3
"""finish names the secret inventory for a remote Windows installer; the worker scans.

A Windows build host cannot load the authenticated secret inventory, so its producer
defers the scan (tools/test_windows_secret_scan_deferral.py). tools/release_remote_build.py
finish hands the inventory path, and only the path, to the authenticated dependency-freeze
worker, which runs the exact scanner on the installer bytes it holds and binds the result
into its claim (tools/test_release_dependency_freeze.py covers the worker half). This tool
runs no scan and accepts no scan result, so a receipt cannot be made from a record the
caller wrote.

Run: python3 -B tools/test_release_remote_build_secret_scan.py
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import release_remote_build as orchestrator  # noqa: E402

TOOLCHAIN = {"name": "Flutter", "version": "3.47.6", "revision": "r", "target": "windows-x64-inno-unsigned"}
INVENTORY = "/var/empty/winsvpn-test/release-secret-inventory.json"


class SecretScanArgumentsTests(unittest.TestCase):
    def _arguments(self, platform: str, value: str | None):
        environment = {} if value is None else {"WINS_RELEASE_SECRET_INVENTORY": value}
        with mock.patch.dict(os.environ, environment):
            if value is None:
                os.environ.pop("WINS_RELEASE_SECRET_INVENTORY", None)
            return orchestrator.secret_scan_arguments(platform)

    def test_a_windows_finish_names_the_inventory_by_path_and_never_opens_it(self) -> None:
        # The file does not exist: the tool only forwards the path.
        self.assertFalse(os.path.exists(INVENTORY))
        self.assertEqual(
            self._arguments("windows", INVENTORY), ["--secret-inventory-path", INVENTORY]
        )

    def test_the_same_path_is_named_for_finish_and_for_verification(self) -> None:
        with mock.patch.dict(os.environ, {"WINS_RELEASE_SECRET_INVENTORY": INVENTORY}):
            self.assertEqual(orchestrator.secret_inventory_path("windows"), INVENTORY)
            self.assertIsNone(orchestrator.secret_inventory_path("linux"))

    def test_no_other_platform_names_an_inventory(self) -> None:
        for platform in ("linux", "android", "macos"):
            with self.subTest(platform=platform):
                self.assertEqual(self._arguments(platform, INVENTORY), [])

    def test_a_missing_or_malformed_inventory_path_refuses(self) -> None:
        with self.assertRaisesRegex(orchestrator.RemoteBuildError, "WINS_RELEASE_SECRET_INVENTORY"):
            self._arguments("windows", None)
        with self.assertRaisesRegex(orchestrator.RemoteBuildError, "WINS_RELEASE_SECRET_INVENTORY"):
            self._arguments("windows", "")
        for bad in ("relative/inventory.json", "/tmp/../inventory.json", "/tmp//inventory.json"):
            with self.subTest(path=bad):
                with self.assertRaisesRegex(orchestrator.RemoteBuildError, "absolute normalized path"):
                    self._arguments("windows", bad)

    def test_this_tool_runs_no_scan_and_accepts_no_scan_result(self) -> None:
        source = pathlib.Path(orchestrator.__file__).read_text(encoding="utf-8")
        self.assertFalse(hasattr(orchestrator, "release_host_secret_scan"))
        self.assertNotIn("--release-host-secret-scan", source)
        self.assertNotIn("RELEASE_HOST_SECRET_SCAN.json", source)
        self.assertNotIn("validate_release_artifact_privacy", source)


class FinishNamesTheInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        self.run = self.repo / ".artifacts" / "remote-builds" / "w1"
        self.run.mkdir(parents=True)
        self.index = self.repo / "index.json"
        self.index.write_text("{}", encoding="utf-8")
        self.artifact = self.run / "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        self.artifact.write_bytes(b"MZ-installer-fixture")
        (self.run / "REMOTE_RUN.json").write_text(
            json.dumps(
                {
                    "release": "1.0.16+33",
                    "platform": "windows",
                    "remote_host": "windows",
                    "build_begin_sha256": "00" * 32,
                    "toolchain": TOOLCHAIN,
                    "signing": "unsigned",
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        self.calls: list[str] = []
        self.worker_arguments: list[str] = []
        self.verify_inventory: object = "not called"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _finish(self, platform: str = "windows") -> dict[str, object]:
        run_record = self.run / "REMOTE_RUN.json"

        def run_build_step(repo, arguments):
            self.calls.append("finish-build")
            self.worker_arguments = list(arguments)
            (self.run / "BUILD_RECEIPT.json").write_text("{}", encoding="utf-8")
            return {"remote_attestation": {"run_record": {
                "sha256": hashlib.sha256(run_record.read_bytes()).hexdigest()}}}

        def verify_build_receipt(repo, index, platform, receipt, artifact, inventory=None):
            self.calls.append("verify-receipt")
            self.verify_inventory = inventory
            return {
                "receipt_sha256": hashlib.sha256(pathlib.Path(receipt).read_bytes()).hexdigest(),
                "artifact_sha256": hashlib.sha256(pathlib.Path(artifact).read_bytes()).hexdigest(),
            }

        with mock.patch.object(orchestrator.client, "run_build_step", run_build_step), \
                mock.patch.object(orchestrator.client, "verify_build_receipt", verify_build_receipt):
            return orchestrator.finish(
                repo=self.repo, index=self.index, platform=platform, remote_host=platform,
                run_id="w1", artifact=self.artifact, sign=False, cosign="",
                allow_unpinned_rehearsal_key=False, accept_remote_self_reported_execution=True,
            )

    def test_the_inventory_path_goes_to_the_worker_and_the_worker_alone(self) -> None:
        with mock.patch.dict(os.environ, {"WINS_RELEASE_SECRET_INVENTORY": INVENTORY}):
            result = self._finish()
        self.assertEqual(result["ok"], True)
        self.assertEqual(self.calls, ["finish-build", "verify-receipt"])
        position = self.worker_arguments.index("--secret-inventory-path")
        self.assertEqual(self.worker_arguments[position + 1], INVENTORY)
        self.assertNotIn("--release-host-secret-scan", self.worker_arguments)
        self.assertFalse((self.run / "RELEASE_HOST_SECRET_SCAN.json").exists())
        # Verification names the same inventory, so it runs the scan itself too.
        self.assertEqual(self.verify_inventory, INVENTORY)

    def test_a_missing_inventory_refuses_before_finish_build_is_called(self) -> None:
        with mock.patch.dict(os.environ, {}):
            os.environ.pop("WINS_RELEASE_SECRET_INVENTORY", None)
            with self.assertRaisesRegex(orchestrator.RemoteBuildError, "WINS_RELEASE_SECRET_INVENTORY"):
                self._finish()
        self.assertEqual(self.calls, [])
        self.assertFalse((self.run / "BUILD_RECEIPT.json").exists())


if __name__ == "__main__":
    unittest.main()
