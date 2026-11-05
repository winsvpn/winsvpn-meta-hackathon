"""L03 control-plane shell fixes: run the installer's generated code locally.

Every case extracts the exact generated program (or function) from the
installer and runs it against synthetic fixtures in a temporary directory.
WINS_CP_INSTALLER may point at another copy of the installer (for example the
pristine release) to show which cases fail there.
"""
import ast
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


INSTALLER = Path(os.environ.get(
    "WINS_CP_INSTALLER", str(Path(__file__).with_name("wins_control_plane_setup_ONETOUCH.sh"))))
SOURCE = INSTALLER.read_text(encoding="utf-8")
BASH = shutil.which("bash")


def heredoc(header, delimiter):
    return SOURCE.split(header, 1)[1].split("\n" + delimiter + "\n", 1)[0]


def unit(path):
    return heredoc("cat > " + path + " <<'EOF'\n", "EOF")


def functions(program, names):
    body = [n for n in ast.parse(program).body if isinstance(n, ast.FunctionDef) and n.name in names]
    return ast.Module(body=body, type_ignores=[])


class AttestOutputTests(unittest.TestCase):
    """A pinned but hostile node cannot make the hub buffer unbounded output."""

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        code = heredoc("install_generated_file 0700 /usr/local/sbin/wins-fleet-attest <<'FLEETATTESTEOF'\n",
                       "FLEETATTESTEOF")
        self.mod = types.ModuleType("checker")
        exec(compile(code, "installed-checker", "exec"), self.mod.__dict__)
        self.mod.PYTHON = sys.executable
        self.fixture = Path(self.work.name) / "collector.py"
        self.app = object.__new__(self.mod.Attest)
        self.app.env = {}
        self.app.collector = str(self.fixture)

    def collect(self, extra):
        self.fixture.write_text("import json, sys\n"
                                "print(json.dumps({'v': 1, 'nonce': sys.argv[1]}))\n" + extra)
        return self.app.collect({"name": "fixture", "local": True})

    def test_normal_report_is_accepted(self):
        observation, failure = self.collect("")
        self.assertIsNone(failure)
        self.assertEqual(observation["v"], 1)
        self.assertNotIn("_nonce_mismatch", observation)

    def test_oversized_stdout_is_refused(self):
        observation, failure = self.collect("sys.stdout.write(' ' * (9 << 20))\n")
        self.assertIsNone(observation)
        self.assertEqual(failure, ("unreachable", "report output exceeds limit"))

    def test_oversized_stderr_is_refused(self):
        observation, failure = self.collect("sys.stderr.write('x' * (9 << 20))\n")
        self.assertIsNone(observation)
        self.assertEqual(failure, ("unreachable", "report output exceeds limit"))

    def test_runner_honors_timeout_and_input(self):
        runner = getattr(self.mod, "run_attest_bounded", None)
        self.assertIsNotNone(runner, "no bounded runner")
        with self.assertRaises(subprocess.TimeoutExpired):
            runner([sys.executable, "-I", "-c", "import time; time.sleep(5)"], None, {}, timeout=0.2)
        result = runner([sys.executable, "-I", "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
                        "fixture input", {}, timeout=5)
        self.assertEqual((result.returncode, result.stdout), (0, "fixture input"))


class MonitorStateTests(unittest.TestCase):
    """The root monitor never writes through links the hub can plant, and a
    rotated eve.json is read from its start."""

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.victim = self.root / "host-config"
        self.victim.write_text("fixture host configuration\n")
        self.eve = self.root / "eve.json"
        self.eve.write_text(json.dumps({"event_type": "stats"}) + "\n")
        self.sent = []
        self.ns = dict(Path=Path, os=os, tempfile=tempfile, time=time, json=json,
                       STATE_DIR=self.state, EVE_PATH=self.eve, THROTTLE_SECONDS=300,
                       event_hash=lambda value: "fixture", throttle_identity=lambda *args: None,
                       send_alert=lambda *args: self.sent.append(args))
        program = heredoc("cat > /usr/local/bin/wins-security-alert-monitor <<'PYEOF'\n", "PYEOF")
        exec(compile(functions(program, {"monitor_suricata", "throttle_ok", "write_journal_cursor"}),
                     "installed-monitor", "exec"), self.ns)

    def assert_victim_untouched(self):
        self.assertEqual(self.victim.read_text(), "fixture host configuration\n")

    def test_first_offset_write_cannot_follow_a_planted_link(self):
        offset = self.state / "suricata-eve.offset"
        offset.symlink_to(self.victim)
        self.ns["monitor_suricata"]()
        self.assert_victim_untouched()
        self.assertFalse(offset.is_symlink())

    def test_offset_update_cannot_follow_a_planted_link(self):
        self.ns["monitor_suricata"]()  # baseline offset and identity
        offset = self.state / "suricata-eve.offset"
        offset.unlink()
        offset.symlink_to(self.victim)
        with self.eve.open("a") as f:
            f.write(json.dumps({"event_type": "stats"}) + "\n")
        self.ns["monitor_suricata"]()
        self.assert_victim_untouched()
        self.assertFalse(offset.is_symlink())

    def test_throttle_stamp_cannot_follow_a_planted_link(self):
        stamp = self.state / "monitor-fixture.last"
        stamp.symlink_to(self.victim)
        self.assertTrue(self.ns["throttle_ok"](1, "fixture", "local", {}))
        self.assert_victim_untouched()
        self.assertFalse(stamp.is_symlink())
        self.assertGreater(float(stamp.read_text()), 0)

    def alert_line(self):
        return json.dumps({"event_type": "alert", "alert": {"severity": 1, "signature": "fixture"},
                           "src_ip": "192.0.2.10", "dest_ip": "192.0.2.20"}) + "\n"

    def test_replacement_log_larger_than_old_offset_is_read_from_start(self):
        self.ns["monitor_suricata"]()  # baseline at the old file's end
        old_size = self.eve.stat().st_size
        self.eve.rename(self.root / "eve.json.1")
        self.eve.write_text(self.alert_line())
        self.assertGreater(self.eve.stat().st_size, old_size)
        self.ns["monitor_suricata"]()
        self.assertEqual(len(self.sent), 1, "an alert in the rotated-in log was skipped")
        self.assertEqual((self.state / "suricata-eve.offset").read_text(), str(self.eve.stat().st_size))

    def test_state_from_before_the_identity_marker_keeps_its_offset(self):
        self.eve.write_text(self.alert_line())
        (self.state / "suricata-eve.offset").write_text(str(self.eve.stat().st_size))
        self.ns["monitor_suricata"]()
        self.assertEqual(self.sent, [], "an upgrade replayed alerts already reported")
        self.assertTrue((self.state / "suricata-eve.identity").is_file())

    def test_monitor_unit_confines_writes_to_its_state_directory(self):
        lines = unit("/etc/systemd/system/wins-security-alert-monitor.service").splitlines()
        for line in ("NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=read-only",
                     "ReadWritePaths=/var/lib/wins-security-alerts",
                     "CapabilityBoundingSet=CAP_DAC_READ_SEARCH"):
            self.assertIn(line, lines)


class PredeploySnapshotTests(unittest.TestCase):
    def test_backup_contains_committed_wal_rows(self):
        if not shutil.which("sqlite3"):
            self.skipTest("sqlite3 CLI is required")
        start = SOURCE.index("backup_existing_db() {\n")
        function = SOURCE[start:SOURCE.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as work:
            db = Path(work).resolve() / "vpn_users.db"
            live = sqlite3.connect(db)
            try:
                self.assertEqual(live.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                live.execute("CREATE TABLE fixture(value INTEGER)")
                live.execute("INSERT INTO fixture VALUES (1)")
                live.commit()
                live.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                live.execute("INSERT INTO fixture VALUES (2)")
                live.commit()
                self.assertGreater(Path(str(db) + "-wal").stat().st_size, 0)
                script = ("set -Eeuo pipefail\nDB_PATH=$1\nlog() { :; }\n"
                          "err() { printf '%s\\n' \"$*\" >&2; }\n" + function + "\nbackup_existing_db\n")
                done = subprocess.run([BASH, "-c", script, "fixture", str(db)],
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(done.returncode, 0, done.stderr)
            finally:
                live.close()
            backups = list(db.parent.glob("vpn_users.db.pre-fixed-*.bak"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
            with sqlite3.connect(backups[0]) as backup:
                count = backup.execute("SELECT count(*) FROM fixture").fetchone()[0]
            self.assertEqual(count, 2, "the pre-upgrade copy lost a committed WAL row")


class EnvReaderTests(unittest.TestCase):
    """Generated readers decode write_env_kv's single-quote encoding."""

    READERS = [
        ("cat > /usr/local/lib/wins_threat_triage.py <<'PYEOF'\n", "PYEOF", "load_env"),
        ("cat > /usr/local/bin/wins-security-alert-monitor <<'PYEOF'\n", "PYEOF", "load_env"),
        ("cat > /usr/local/bin/wins-security-events <<'PYEOF'\n", "PYEOF", "load_env"),
        ("cat > /usr/local/bin/wins-admin <<'PYEOF'\n", "PYEOF", None),
    ]
    FIXTURES = ["fixture's value", "'fixture edge'", '"fixture edge"', "fixture \\ value",
                "$(do-not-execute) `do-not-execute`", "", "plain"]

    def test_every_reader_preserves_writer_values(self):
        with tempfile.TemporaryDirectory() as work:
            env = Path(work) / "fixture.env"
            for header, delimiter, name in self.READERS:
                parsed = ast.parse(heredoc(header, delimiter))
                if name:
                    selected = [n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == name]
                else:
                    selected = [n for n in parsed.body if isinstance(n, ast.For)]
                self.assertEqual(len(selected), 1, header)
                for index, fixture in enumerate(self.FIXTURES):
                    with self.subTest(reader=header.split()[2], case=index):
                        # Exactly write_env_kv's encoding.
                        env.write_text("FIXTURE_VALUE='" + fixture.replace("'", "'\"'\"'") + "'\n")
                        ns = dict(Path=Path, os=os, ENV_PATHS=[env], ENV={})
                        with patch.dict(os.environ, {}, clear=True):
                            exec(compile(ast.Module(body=selected, type_ignores=[]), "reader", "exec"), ns)
                            result = ns[name](env) if name else ns["ENV"]
                        self.assertEqual(result.get("FIXTURE_VALUE"), fixture)


class MaintenanceStatusTests(unittest.TestCase):
    """Failed weekly maintenance steps reach the machine-readable status."""

    HELPER = heredoc("cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'\n", "EOF")

    def function(self, name):
        start = self.HELPER.index(name + "() {")
        first = self.HELPER[start:].splitlines()[0]
        if first.endswith(" }"):
            return first + "\n"
        return self.HELPER[start:self.HELPER.index("\n}", start) + 3] + "\n"

    def run_case(self, operation, warnings):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finish = self.HELPER[self.HELPER.rindex("if (( MAINT_WARNINGS > 0 )); then"):]
            script = "set -Eeuo pipefail\n" + "\n".join([
                'LOG_FILE="$1/log"', 'STATUS_FILE="$1/status"',
                "MAINT_WARNINGS=0", "MAINT_ROLE=fixture", "DISK_ROOT_PCT=0", "SWAP_STATE=fixture",
                "OS_REBOOT_REQUIRED=0", "OS_REBOOT_REASONS=none", "OS_RUNNING_KERNEL=fixture",
                "OS_EXPECTED_KERNEL=fixture", "OS_HELD=none", "OS_UPGRADABLE=none",
                "log() { :; }", "hostname() { printf 'fixture\\n'; }",
                self.function("maint_warn"), self.function("run_step"),
                self.function("wait_for_package_manager"), self.function("restore_unattended_upgrades"),
                self.function("write_maintenance_status"), operation, finish,
            ])
            done = subprocess.run([BASH, "-c", script, "fixture", str(root)],
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(done.returncode, 0, done.stderr)
            status = dict(line.split("=", 1) for line in (root / "status").read_text().splitlines())
            self.assertEqual(status["warnings"], str(warnings))
            self.assertEqual(status["outcome"], "completed-with-warnings" if warnings else "ok")

    def test_failed_step_is_counted(self):
        self.run_case("run_step 'fixture failed check' false", 1)

    def test_successful_step_stays_clear(self):
        self.run_case("run_step 'fixture successful check' true", 0)

    def test_busy_package_manager_is_counted(self):
        self.run_case("package_manager_busy() { return 0; }\nsleep() { :; }\n"
                      "if wait_for_package_manager; then :; fi", 1)

    def test_restore_failure_is_counted(self):
        self.run_case("systemctl() { return 1; }\nrestore_unattended_upgrades", 1)

    def test_nginx_refusal_is_counted(self):
        start = self.HELPER.index('if nginx -t >>"${LOG_FILE}"')
        block = self.HELPER[start:self.HELPER.index("\nfi\n", start) + 4]
        self.run_case("nginx() { return 1; }\n" + block, 1)


class BackupCustodyTests(unittest.TestCase):
    def test_backup_unit_cannot_read_signer_custody(self):
        lines = unit("/etc/systemd/system/wins-hub-backup.service").splitlines()
        self.assertIn("InaccessiblePaths=-/etc/winsvpn/descriptor-signer -/var/lib/wins-descriptor-signer", lines)
        self.assertIn("InaccessiblePaths=-/etc/wins-descriptor-signer-input", lines)


class BackupFreshnessTests(unittest.TestCase):
    """A verified remote-only backup is fresh; a stale one still warns."""

    FUNCTION = SOURCE.split("audit_backup_freshness() {\n", 1)[1].split(
        "\n}\n\n# WINS-FWOS-WEEKLY-BEGIN", 1)[0]

    def run_watchdog(self, age_seconds):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "remote-last-verified"
            marker.touch()
            if age_seconds:
                when = time.time() - age_seconds
                os.utime(marker, (when, when))
            script = ("set -Eeuo pipefail\n"
                      "systemctl() { case \"$1\" in is-enabled) return 0 ;; show) printf 'success\\n' ;; "
                      "*) return 1 ;; esac; }\n"
                      "maint_warn() { printf 'WARN %s\\n' \"$*\"; }\nlog() { printf 'INFO %s\\n' \"$*\"; }\n"
                      "audit_backup_freshness() {\n" + self.FUNCTION + "\n}\naudit_backup_freshness\n")
            env = dict(os.environ, WINS_LOCAL_BACKUP_DIR=str(root), WINS_BACKUP_MAX_AGE_DAYS="2",
                       WINS_HUB_DB_SNAPSHOT_PATH=str(root / "missing-snapshot"))
            done = subprocess.run([BASH, "-c", script], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout

    def test_recent_verified_remote_needs_no_local_archive(self):
        output = self.run_watchdog(0)
        self.assertIn("remote upload was integrity-verified", output)
        self.assertNotIn("WARN", output.replace("WARN hub database snapshot helper", ""))

    def test_stale_verified_remote_still_warns(self):
        self.assertIn("no hub backup archive is present locally", self.run_watchdog(3 * 24 * 60 * 60))

    def test_producer_touches_marker_only_after_cryptcheck(self):
        upload = SOURCE.split("if rclone cryptcheck ", 1)[1].split("    else\n      remote_verify_failed=1", 1)[0]
        self.assertIn("remote-last-verified", upload)
        self.assertLess(upload.index("remote_uploaded=1"), upload.index("remote-last-verified"))


if __name__ == "__main__":
    unittest.main()
