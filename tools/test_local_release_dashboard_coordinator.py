#!/usr/bin/env python3
"""Behavioral contracts for the local dashboard coordinator delegator."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import local_release_coordinator as coordinator


ROOT = Path(__file__).resolve().parent.parent
COORDINATOR = ROOT / "tools" / "local_release_coordinator.py"
SYNC = ROOT / "tools" / "sync_progress.sh"
DASHBOARD_SERVER = ROOT / "dashboard" / "server.py"
SOURCE = COORDINATOR.read_text(encoding="ascii")
FORBIDDEN_COMMAND_RE = re.compile(
    r"(^|[;&|()\s])/?(?:[A-Za-z0-9._-]+/)*(git|curl|wget|ssh|scp)(?=\s|$)",
    flags=re.MULTILINE,
)
FAKE_SYNC = """#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

log = Path(os.environ["FAKE_SYNC_LOG"])
records = []
if log.is_file():
    records = json.loads(log.read_text(encoding="ascii"))
records.append(
    {
        "argv": list(sys.argv),
        "cwd": os.getcwd(),
        "env": {
            key: os.environ[key]
            for key in sorted(os.environ)
            if key.startswith("WINSVPN_DASHBOARD_")
        },
    }
)
log.write_text(json.dumps(records), encoding="ascii")
started = os.environ.get("FAKE_SYNC_STARTED")
if started:
    Path(started).write_text("started\\n", encoding="ascii")
delay = float(os.environ.get("FAKE_SYNC_SLEEP", "0"))
if delay > 0:
    time.sleep(delay)
body = os.environ.get("FAKE_SYNC_SNAPSHOT_BODY")
if body is not None:
    Path(os.environ["WINSVPN_DASHBOARD_SNAPSHOT"]).write_text(body, encoding="ascii")
raise SystemExit(int(os.environ.get("FAKE_SYNC_EXIT", "0")))
"""
FAKE_SERVER = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

log = Path(os.environ["FAKE_SERVER_LOG"])
records = []
if log.is_file():
    records = json.loads(log.read_text(encoding="ascii"))
records.append(list(sys.argv))
log.write_text(json.dumps(records), encoding="ascii")
raise SystemExit(int(os.environ.get("FAKE_SERVER_EXIT", "0")))
"""


class LocalReleaseDashboardCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.evidence = self.root / "evidence"
        self.repo.mkdir()
        self.evidence.mkdir()
        self.config = self.root / "state.json"
        self.config.write_text("{}\n", encoding="ascii")
        self.snapshot = self.root / "out" / "state.snapshot.json"
        self.cache = self.root / "out" / "cross-store-cache.json"
        self.log = self.root / "sync.log"
        self.server_log = self.root / "server.log"
        self.started = self.root / "started"
        self.fake = self._write_executable(self.root / "fake-sync", FAKE_SYNC)
        self.fake_server = self.root / "fake-server.py"
        self.fake_server.write_text(FAKE_SERVER, encoding="ascii")
        self._setenv("FAKE_SYNC_LOG", str(self.log))
        self._setenv("FAKE_SERVER_LOG", str(self.server_log))

    def _setenv(self, key: str, value: str) -> None:
        previous = os.environ.get(key)
        os.environ[key] = value

        def restore() -> None:
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous

        self.addCleanup(restore)

    def _write_executable(self, path: Path, body: str) -> Path:
        path.write_text(body, encoding="ascii")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def _args(self, extra: list[str] | None = None) -> list[str]:
        values = [
            "--repo-root",
            str(self.repo),
            "--config",
            str(self.config),
            "--evidence-root",
            str(self.evidence),
            "--snapshot",
            str(self.snapshot),
            "--cache",
            str(self.cache),
            "--sync-executable",
            str(self.fake),
            "--python",
            sys.executable,
            "--dashboard-server",
            str(DASHBOARD_SERVER),
        ]
        if extra:
            values.extend(extra)
        return values

    def _records(self) -> list[dict[str, object]]:
        if not self.log.is_file():
            return []
        payload = json.loads(self.log.read_text(encoding="ascii"))
        if not isinstance(payload, list):
            self.fail("fake sync log is not a list")
        return payload

    def _wait_file(self, path: Path, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if path.is_file():
                return
            time.sleep(0.05)
        self.fail(f"timed out waiting for {path}")

    def test_source_is_fail_closed_delegator_without_external_actions(self) -> None:
        self.assertIn("does not reimplement tools/sync_progress.sh", SOURCE)
        self.assertIn("STORE_UPLOAD_AUTHORIZED = False", SOURCE)
        self.assertNotIn("STORE_UPLOAD_AUTHORIZED = True", SOURCE)
        self.assertIn("shell=False", SOURCE)
        self.assertNotIn("shell=True", SOURCE)
        self.assertNotIn("os.system", SOURCE)
        self.assertNotIn("os.popen", SOURCE)
        self.assertNotIn("--refresh-cross-store-cache", SOURCE)
        executable_lines = "\n".join(
            line
            for line in SOURCE.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertNotRegex(executable_lines, FORBIDDEN_COMMAND_RE)
        self.assertEqual(coordinator.DEFAULT_SYNC_EXECUTABLE, SYNC)
        self.assertIs(coordinator.STORE_UPLOAD_AUTHORIZED, False)

    def test_one_shot_argv_uses_explicit_local_paths_and_no_shell(self) -> None:
        status = coordinator.main(self._args())
        self.assertEqual(status, 0)
        records = self._records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["argv"], [str(self.fake)])
        self.assertEqual(Path(str(records[0]["cwd"])).resolve(), self.repo.resolve())
        env = records[0]["env"]
        self.assertEqual(env["WINSVPN_DASHBOARD_REPO_ROOT"], str(self.repo))
        self.assertEqual(env["WINSVPN_DASHBOARD_CONFIG"], str(self.config))
        self.assertEqual(env["WINSVPN_DASHBOARD_EVIDENCE_DIR"], str(self.evidence))
        self.assertEqual(env["WINSVPN_DASHBOARD_SNAPSHOT"], str(self.snapshot))
        self.assertEqual(
            env["WINSVPN_DASHBOARD_CROSS_STORE_CACHE"], str(self.cache)
        )
        self.assertEqual(env["WINSVPN_DASHBOARD_PYTHON"], sys.executable)
        self.assertFalse(self.server_log.exists())
        self.assertFalse(self.snapshot.exists())
        self.assertFalse(coordinator.coordinator_lock_dir(self.snapshot).exists())
        self.assertNotEqual(
            str(coordinator.coordinator_lock_dir(self.snapshot)),
            str(self.snapshot) + ".lock",
        )

    def test_cli_subprocess_matches_in_process_argv_contract(self) -> None:
        environment = os.environ.copy()
        environment["FAKE_SYNC_LOG"] = str(self.log)
        completed = subprocess.run(
            [sys.executable, str(COORDINATOR), *self._args()],
            cwd=str(self.root),
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        records = self._records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["argv"], [str(self.fake)])

    def test_semicolon_executable_name_does_not_run_through_a_shell(self) -> None:
        pwned = self.repo / "pwned"
        fake = self._write_executable(self.repo / "sync; touch pwned", FAKE_SYNC)
        status = coordinator.main(
            self._args(["--sync-executable", str(fake)])
        )
        self.assertEqual(status, 0)
        self.assertFalse(pwned.exists())
        self.assertEqual(self._records()[0]["argv"], [str(fake)])

    def test_lock_refuses_a_second_run_without_invoking_sync(self) -> None:
        lock_dir = coordinator.coordinator_lock_dir(self.snapshot)
        lock_dir.parent.mkdir(parents=True, exist_ok=True)
        lock_dir.mkdir()
        status = coordinator.main(self._args())
        self.assertEqual(status, coordinator.EX_TEMPFAIL)
        self.assertEqual(self._records(), [])
        self.assertTrue(lock_dir.is_dir())

    def test_lock_serializes_an_in_flight_run(self) -> None:
        self._setenv("FAKE_SYNC_SLEEP", "1")
        self._setenv("FAKE_SYNC_STARTED", str(self.started))
        environment = os.environ.copy()
        first = subprocess.Popen(
            [sys.executable, str(COORDINATOR), *self._args()],
            cwd=str(self.root),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self._wait_file(self.started)
            second = coordinator.main(self._args())
            self.assertEqual(second, coordinator.EX_TEMPFAIL)
            _stdout, stderr = first.communicate(timeout=10)
            self.assertEqual(first.returncode, 0, stderr)
        finally:
            if first.returncode is None:
                first.kill()
                first.communicate()
        self.assertEqual(len(self._records()), 1)

    def test_bounded_watch_invokes_one_shot_sync_per_cycle(self) -> None:
        with mock.patch.object(coordinator.time, "sleep") as slept:
            status = coordinator.main(
                self._args(["--watch", "2", "--cycles", "3"])
            )
        self.assertEqual(status, 0)
        self.assertEqual(slept.call_count, 2)
        slept.assert_called_with(2)
        records = self._records()
        self.assertEqual(len(records), 3)
        for record in records:
            self.assertEqual(record["argv"], [str(self.fake)])
        self.assertFalse(self.server_log.exists())

    def test_watch_without_cycles_and_out_of_range_interval_fail_closed(self) -> None:
        self.assertEqual(
            coordinator.main(self._args(["--watch", "5"])),
            coordinator.EX_USAGE,
        )
        self.assertEqual(
            coordinator.main(self._args(["--watch", "1", "--cycles", "2"])),
            coordinator.EX_USAGE,
        )
        self.assertEqual(
            coordinator.main(self._args(["--watch", "61", "--cycles", "2"])),
            coordinator.EX_USAGE,
        )
        self.assertEqual(self._records(), [])

    def test_nonzero_sync_fail_closes_to_dashboard_failure_snapshot(self) -> None:
        self.snapshot.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot.write_text('{"overall_readiness":100}\n', encoding="ascii")
        self._setenv("FAKE_SYNC_EXIT", "11")
        status = coordinator.main(self._args())
        self.assertEqual(status, 11)
        payload = json.loads(self.snapshot.read_text(encoding="utf-8"))
        self.assertEqual(payload["source"], "invalid-local-evidence")
        self.assertEqual(payload["overall_readiness"], 0)
        self.assertIs(
            payload["current_posture"]["store_upload_authorized"], False
        )
        self.assertEqual(len(self._records()), 1)

    def test_failure_snapshot_writer_status_wins_and_argv_is_local_only(self) -> None:
        self._setenv("FAKE_SYNC_EXIT", "9")
        self._setenv("FAKE_SERVER_EXIT", "3")
        status = coordinator.main(
            self._args(["--dashboard-server", str(self.fake_server)])
        )
        self.assertEqual(status, 3)
        server_argv = json.loads(self.server_log.read_text(encoding="ascii"))
        self.assertEqual(
            server_argv,
            [
                [
                    str(self.fake_server),
                    "--failure-snapshot",
                    str(self.snapshot),
                ]
            ],
        )
        self.assertEqual(
            coordinator.failure_snapshot_argv(
                Path(sys.executable), self.fake_server, self.snapshot
            ),
            [
                sys.executable,
                str(self.fake_server),
                "--failure-snapshot",
                str(self.snapshot),
            ],
        )
        self.assertEqual(len(self._records()), 1)

    def test_watch_stops_on_first_nonzero_and_propagates(self) -> None:
        self._setenv("FAKE_SYNC_EXIT", "7")
        with mock.patch.object(coordinator.time, "sleep") as slept:
            status = coordinator.main(
                self._args(["--watch", "2", "--cycles", "4"])
            )
        self.assertEqual(status, 7)
        slept.assert_not_called()
        self.assertEqual(len(self._records()), 1)
        payload = json.loads(self.snapshot.read_text(encoding="utf-8"))
        self.assertEqual(payload["source"], "invalid-local-evidence")

    def test_authorized_snapshot_is_rejected_and_replaced(self) -> None:
        self._setenv(
            "FAKE_SYNC_SNAPSHOT_BODY",
            json.dumps({"store_upload_authorized": True}),
        )
        status = coordinator.main(self._args())
        self.assertEqual(status, coordinator.EX_USAGE)
        payload = json.loads(self.snapshot.read_text(encoding="utf-8"))
        self.assertEqual(payload["source"], "invalid-local-evidence")
        self.assertIs(
            payload["current_posture"]["store_upload_authorized"], False
        )

    def test_hard_off_env_and_external_commands_are_refused(self) -> None:
        self._setenv("WINSVPN_STORE_UPLOAD_AUTHORIZED", "true")
        self.assertEqual(coordinator.main(self._args()), coordinator.EX_USAGE)
        os.environ.pop("WINSVPN_STORE_UPLOAD_AUTHORIZED", None)
        git_named = self._write_executable(self.root / "git", FAKE_SYNC)
        self.assertEqual(
            coordinator.main(
                self._args(["--sync-executable", str(git_named)])
            ),
            coordinator.EX_USAGE,
        )
        self.assertEqual(
            coordinator.main(self._args(["--github-token", "nope"])),
            coordinator.EX_USAGE,
        )
        self.assertEqual(
            coordinator.main(self._args(["--repo-root", "repo"])),
            coordinator.EX_USAGE,
        )
        self.assertEqual(self._records(), [])

    def test_success_does_not_fabricate_receipts_or_invoke_dashboard_server(self) -> None:
        body = json.dumps(
            {
                "store_upload_authorized": False,
                "current_posture": {"store_upload_authorized": False},
            }
        )
        self._setenv("FAKE_SYNC_SNAPSHOT_BODY", body)
        status = coordinator.main(
            self._args(["--dashboard-server", str(self.fake_server)])
        )
        self.assertEqual(status, 0)
        self.assertEqual(self.snapshot.read_text(encoding="ascii"), body)
        self.assertFalse(self.server_log.exists())
        self.assertFalse(list(self.evidence.iterdir()))
        self.assertFalse((self.repo / "receipt.json").exists())

    def test_default_sync_executable_is_the_owned_local_script(self) -> None:
        request = coordinator.load_request(
            [
                "--repo-root",
                str(self.repo),
                "--config",
                str(self.config),
                "--evidence-root",
                str(self.evidence),
                "--snapshot",
                str(self.snapshot),
                "--cache",
                str(self.cache),
            ]
        )
        self.assertEqual(request.sync_executable, SYNC)
        self.assertEqual(
            coordinator.local_sync_argv(request.sync_executable), [str(SYNC)]
        )
        self.assertEqual(self._records(), [])


if __name__ == "__main__":
    unittest.main()
