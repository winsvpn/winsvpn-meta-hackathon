#!/usr/bin/env python3
"""Behavioral runtime tests for the local dashboard snapshot synchronizer."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from dashboard import server


REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG = REPO_ROOT / "dashboard" / "state.json"
SYNC = REPO_ROOT / "tools" / "sync_progress.sh"

FAKE_DASHBOARD = r'''#!/usr/bin/python3
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


root = Path(os.environ["FAKE_DASHBOARD_ROOT"])
arguments = sys.argv[2:]
count_path = root / "refresh-count"
log_path = root / "command.log"


def flag_value(name):
    index = arguments.index(name)
    return Path(arguments[index + 1])


def append_log(value):
    with log_path.open("a", encoding="ascii") as handle:
        handle.write(value + "\n")


def read_count():
    try:
        return int(count_path.read_text(encoding="ascii"))
    except (FileNotFoundError, ValueError):
        return 0


def iso_utc(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def write_atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name("." + path.name + ".fake.tmp")
    payload = (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


if "--refresh-cross-store-cache" in arguments:
    generation = read_count() + 1
    count_path.write_text(str(generation), encoding="ascii")
    append_log("refresh:" + str(generation))
    entered = os.environ.get("FAKE_REFRESH_ENTERED")
    release = os.environ.get("FAKE_REFRESH_RELEASE")
    if entered and release:
        Path(entered).write_text("entered\n", encoding="ascii")
        deadline = time.monotonic() + 10
        while not Path(release).exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not Path(release).exists():
            raise SystemExit(91)
    if os.environ.get("FAKE_FAIL_REFRESH_AT") == str(generation):
        raise SystemExit(int(os.environ.get("FAKE_REFRESH_EXIT", "42")))
    write_atomic(flag_value("--cache"), {"generation": generation})
    raise SystemExit(0)

if "--snapshot" in arguments:
    generation = read_count()
    snapshot = flag_value("--snapshot")
    expired = Path(str(snapshot) + ".expired-do-not-use").exists()
    append_log(
        "snapshot:"
        + str(generation)
        + ":expired="
        + ("1" if expired else "0")
    )
    if os.environ.get("FAKE_FAIL_SNAPSHOT_AT") == str(generation):
        raise SystemExit(int(os.environ.get("FAKE_SNAPSHOT_EXIT", "43")))
    generated = datetime.now(timezone.utc)
    write_atomic(
        snapshot,
        {
            "source": "verified-local-evidence",
            "generation": generation,
            "generated_at": iso_utc(generated),
            "snapshot_expires_at": iso_utc(generated + timedelta(seconds=15)),
            "overall_readiness": generation,
            "current_posture": {"store_upload_authorized": False},
        },
    )
    raise SystemExit(0)

if "--failure-snapshot" in arguments:
    generation = read_count()
    append_log("failure:" + str(generation))
    if os.environ.get("FAKE_FAIL_FAILURE_WRITER") == "1":
        raise SystemExit(int(os.environ.get("FAKE_FAILURE_EXIT", "44")))
    generated = datetime.now(timezone.utc)
    write_atomic(
        flag_value("--failure-snapshot"),
        {
            "source": "invalid-local-evidence",
            "generation": generation,
            "generated_at": iso_utc(generated),
            "snapshot_expires_at": iso_utc(generated + timedelta(seconds=15)),
            "overall_readiness": 0,
            "current_posture": {"store_upload_authorized": False},
        },
    )
    raise SystemExit(0)

raise SystemExit(64)
'''

FAKE_SLEEP = r'''#!/bin/sh
count_file="${FAKE_SLEEP_STATE:?}"
count=0
if [ -f "$count_file" ]; then
  IFS= read -r count < "$count_file"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
if [ "$count" -ge "${FAKE_SLEEP_FAIL_AT:-2}" ]; then
  exit "${FAKE_SLEEP_EXIT:-86}"
fi
exit 0
'''


class LiveSyncRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="winsvpn-dashboard-runtime-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.evidence = self.root / "evidence"
        self.output = self.root / "output" / "state.snapshot.json"
        self.cache = self.root / "cache" / "cross-store-cache.json"
        self.bin_dir = self.root / "bin"
        self.repo.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
        self.bin_dir.mkdir(mode=0o700)

        self.fake_dashboard = self.bin_dir / "fake-dashboard-python"
        self.fake_dashboard.write_text(
            textwrap.dedent(FAKE_DASHBOARD), encoding="ascii"
        )
        self.fake_dashboard.chmod(0o700)
        self.fake_sleep = self.bin_dir / "sleep"
        self.fake_sleep.write_text(textwrap.dedent(FAKE_SLEEP), encoding="ascii")
        self.fake_sleep.chmod(0o700)

        self.environment = os.environ.copy()
        self.environment.update(
            {
                "FAKE_DASHBOARD_ROOT": str(self.root),
                "FAKE_SLEEP_STATE": str(self.root / "sleep-count"),
                "PATH": str(self.bin_dir)
                + os.pathsep
                + self.environment.get("PATH", ""),
                "WINSVPN_DASHBOARD_PYTHON": str(self.fake_dashboard),
                "WINSVPN_DASHBOARD_CONFIG": str(CONFIG),
                "WINSVPN_DASHBOARD_EVIDENCE_DIR": str(self.evidence),
                "WINSVPN_DASHBOARD_SNAPSHOT": str(self.output),
                "WINSVPN_DASHBOARD_REPO_ROOT": str(self.repo),
                "WINSVPN_DASHBOARD_CROSS_STORE_CACHE": str(self.cache),
            }
        )

    def run_sync(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SYNC), *arguments],
            cwd=REPO_ROOT,
            env=environment or self.environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def command_log(self) -> list[str]:
        path = self.root / "command.log"
        if not path.exists():
            return []
        return path.read_text(encoding="ascii").splitlines()

    def wait_for_path(self, path: Path, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.01)
        self.fail("timed out waiting for " + str(path))

    def test_one_shot_refreshes_cache_then_snapshot(self) -> None:
        result = self.run_sync()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.command_log(),
            ["refresh:1", "snapshot:1:expired=0"],
        )
        self.assertEqual(
            json.loads(self.cache.read_text(encoding="ascii")),
            {"generation": 1},
        )
        snapshot = json.loads(self.output.read_text(encoding="ascii"))
        self.assertEqual(snapshot["source"], "verified-local-evidence")
        self.assertEqual(snapshot["generation"], 1)
        self.assertFalse(Path(str(self.output) + ".lock").exists())
        self.assertFalse(
            Path(str(self.output) + ".expired-do-not-use").exists()
        )

    def test_watch_mode_repeats_refresh_and_replaces_snapshot(self) -> None:
        result = self.run_sync("--watch", "2")

        self.assertEqual(result.returncode, 86, result.stderr)
        self.assertEqual(
            self.command_log(),
            [
                "refresh:1",
                "snapshot:1:expired=0",
                "refresh:2",
                "snapshot:2:expired=1",
            ],
        )
        snapshot = json.loads(self.output.read_text(encoding="ascii"))
        self.assertEqual(snapshot["generation"], 2)
        self.assertEqual(snapshot["overall_readiness"], 2)
        self.assertFalse(Path(str(self.output) + ".lock").exists())
        self.assertFalse(
            Path(str(self.output) + ".expired-do-not-use").exists()
        )

    def test_expired_snapshot_is_quarantined_during_refresh(self) -> None:
        self.output.parent.mkdir(parents=True, mode=0o700)
        stale = {
            "source": "verified-local-evidence",
            "generation": 99,
            "snapshot_expires_at": "2000-01-01T00:00:00Z",
            "overall_readiness": 100,
        }
        self.output.write_text(json.dumps(stale) + "\n", encoding="ascii")
        self.output.chmod(0o600)
        entered = self.root / "refresh-entered"
        release = self.root / "refresh-release"
        environment = self.environment.copy()
        environment.update(
            {
                "FAKE_REFRESH_ENTERED": str(entered),
                "FAKE_REFRESH_RELEASE": str(release),
            }
        )
        process = subprocess.Popen(
            ["bash", str(SYNC)],
            cwd=REPO_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.wait_for_path(entered)
            expired = Path(str(self.output) + ".expired-do-not-use")
            self.assertFalse(self.output.exists())
            self.assertEqual(
                json.loads(expired.read_text(encoding="ascii"))["generation"],
                99,
            )
            release.write_text("continue\n", encoding="ascii")
            _, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
        finally:
            if process.poll() is None:
                release.touch()
                process.terminate()
                process.communicate(timeout=5)

        self.assertEqual(
            json.loads(self.output.read_text(encoding="ascii"))["generation"],
            1,
        )
        self.assertFalse(
            Path(str(self.output) + ".expired-do-not-use").exists()
        )

    def test_failed_refresh_replaces_stale_success_with_failure(self) -> None:
        self.output.parent.mkdir(parents=True, mode=0o700)
        stale = {
            "source": "verified-local-evidence",
            "generation": 99,
            "snapshot_expires_at": "2000-01-01T00:00:00Z",
            "overall_readiness": 100,
            "current_posture": {"store_upload_authorized": False},
        }
        self.output.write_text(json.dumps(stale) + "\n", encoding="ascii")
        self.output.chmod(0o600)
        environment = self.environment.copy()
        environment["FAKE_FAIL_REFRESH_AT"] = "1"

        result = self.run_sync(environment=environment)

        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.command_log(), ["refresh:1", "failure:1"])
        replacement = json.loads(self.output.read_text(encoding="ascii"))
        self.assertEqual(replacement["source"], "invalid-local-evidence")
        self.assertEqual(replacement["generation"], 1)
        self.assertEqual(replacement["overall_readiness"], 0)
        self.assertIs(
            replacement["current_posture"]["store_upload_authorized"],
            False,
        )
        self.assertFalse(
            Path(str(self.output) + ".expired-do-not-use").exists()
        )
        self.assertFalse(Path(str(self.output) + ".lock").exists())

    def test_lock_excludes_second_sync(self) -> None:
        self.output.parent.mkdir(parents=True, mode=0o700)
        self.output.write_text('{"generation":99}\n', encoding="ascii")
        original = self.output.read_bytes()
        lock = Path(str(self.output) + ".lock")
        lock.mkdir(mode=0o700)
        (lock / "pid").write_text("12345\n", encoding="ascii")

        result = self.run_sync()

        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertIn("another sync owns", result.stderr)
        self.assertEqual(self.command_log(), [])
        self.assertEqual(self.output.read_bytes(), original)
        self.assertTrue(lock.is_dir())

    def test_write_json_atomic_replaces_complete_private_file(self) -> None:
        output = self.root / "atomic" / "state.json"
        output.parent.mkdir(mode=0o700)
        output.write_text('{"serial":0}\n', encoding="ascii")
        output.chmod(0o644)
        expected = {"serial": 1, "payload": "x" * (256 * 1024)}
        real_replace = os.replace
        replace_seen: list[bool] = []

        def observed_replace(source: Path, destination: Path) -> None:
            self.assertEqual(Path(destination), output)
            self.assertEqual(
                json.loads(output.read_text(encoding="ascii")),
                {"serial": 0},
            )
            self.assertEqual(
                json.loads(Path(source).read_text(encoding="utf-8")),
                expected,
            )
            self.assertEqual(stat.S_IMODE(Path(source).stat().st_mode), 0o600)
            replace_seen.append(True)
            real_replace(source, destination)

        with mock.patch.object(server.os, "replace", side_effect=observed_replace):
            server.write_json_atomic(output, expected)

        self.assertEqual(replace_seen, [True])
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), expected)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(list(output.parent.glob(".state.json.*.tmp")), [])

    def test_snapshot_expiry_is_bounded(self) -> None:
        now = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
        snapshot = server.build_snapshot(
            CONFIG,
            self.evidence,
            now,
            repo_root=self.repo,
            cache_path=self.root / "missing-cache.json",
        )
        config = server.load_config(CONFIG)
        generated = server.parse_utc(snapshot["generated_at"], "generated_at")
        expires = server.parse_utc(
            snapshot["snapshot_expires_at"], "snapshot_expires_at"
        )
        self.assertEqual(
            expires - generated,
            timedelta(seconds=max(10, config["refresh_seconds"] * 3)),
        )

        failure = server.build_failure_snapshot(now)
        failure_generated = server.parse_utc(
            failure["generated_at"], "failure generated_at"
        )
        failure_expires = server.parse_utc(
            failure["snapshot_expires_at"], "failure snapshot_expires_at"
        )
        self.assertEqual(
            failure_expires - failure_generated,
            timedelta(seconds=15),
        )

    def test_store_upload_authorization_is_hard_off(self) -> None:
        targets = [
            {"id": target_id, "status": "ready", "dimensions": []}
            for target_id in server.REQUIRED_TARGETS
        ]
        coverage = {
            "store_upload": {
                "verified": len(server.REQUIRED_UPLOAD_TARGET_IDS),
                "required_receipts": len(server.REQUIRED_UPLOAD_TARGET_IDS),
                "unavailable": 0,
            }
        }
        with (
            mock.patch.object(
                server,
                "_gcp_proof_posture",
                return_value={
                    "status": "verified",
                    "fresh": True,
                    "reason": "verified for authorization regression test",
                },
            ),
            mock.patch.object(
                server,
                "_agp_migration_posture",
                return_value={"status": "complete", "reason": "verified"},
            ),
            mock.patch.object(
                server,
                "_macos_release_python_posture",
                return_value={"status": "authenticated", "reason": "verified"},
            ),
        ):
            cleared = server._current_posture(
                targets,
                coverage,
                {"undisclosed_audits": 0, "owner": 0, "external": 0},
            )

        self.assertEqual(cleared["upload_receipts"]["status"], "complete")
        self.assertEqual(
            cleared["active_blocker_categories"],
            [
                {
                    "id": "publication_hold",
                    "status": "open",
                    "detail": server.PUBLICATION_HOLD,
                }
            ],
        )
        self.assertEqual(cleared["publication_hold"], "DO-NOT-UPLOAD")
        self.assertIs(cleared["store_upload_authorized"], False)
        self.assertIs(
            server.build_failure_snapshot()["current_posture"][
                "store_upload_authorized"
            ],
            False,
        )


if __name__ == "__main__":
    unittest.main()
