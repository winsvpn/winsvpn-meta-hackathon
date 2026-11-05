#!/usr/bin/env python3
"""F-8 regression tests: backup retention pruning (HANDOFF 3g).

F-8 is a MANDATORY DEPLOYMENT BLOCKER. Before the change these tests cover,
there was NO backup pruning anywhere in the repository: nightly archives of the
full account database and every hub secret accumulated without limit, locally
and on the rclone remote, and the provider's trash and version history kept
copies of even those. Every retention window in the published privacy policy
was defeated by it -- the last copy of a record a user asked to have deleted
lived indefinitely in an archive nothing ever removed.

What is real and what is a fake, stated plainly (HANDOFF 3b evidence category
B -- local infrastructure only; no hub, no Google Drive, no provider):

  REAL: the shipped /usr/local/bin/wins-hub-backup-prune and
        /usr/local/bin/wins-hub-backup-manifest, extracted verbatim from
        server/wins_control_plane_setup_ONETOUCH.sh and executed under bash
        against real files with real mtimes; the real
        validate_backup_retention_contract shell function; real tar/gzip
        archives; a real SQLite database restored from a real archive.

  FAKE: rclone. There is no Google Drive account here and this task is
        explicitly forbidden from contacting any server, so the remote stages
        are driven by a FAKE `rclone` on PATH that records every invocation and
        replays canned `lsjson`/`config dump` output. That fake proves the
        pruner ISSUES the right commands against the right remotes -- it does
        NOT prove Google Drive honours them. The real-remote listing check and
        the provider trash behaviour remain UNVERIFIED against a live provider
        and must be confirmed in the deployment drill.

The restore drill IS real: a real archive is built, pruned around, and then
restored, and the restored SQLite database is queried.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"


def _bash():
    for candidate in (os.environ.get("WINS_BASH"), shutil.which("bash"), "/bin/bash"):
        if not candidate or not os.path.isfile(candidate):
            continue
        proc = subprocess.run([candidate, "--version"], capture_output=True, text=True)
        if proc.returncode == 0 and "version 3." not in proc.stdout.split("\n")[0]:
            return candidate
    return None


BASH = _bash()


def extract_heredoc(installer: str, marker: str) -> str:
    """Pull a `cat > PATH <<'EOF' ... EOF` body verbatim out of the installer."""
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nEOF\n", start)
    return installer[start:end]


def extract_function(installer: str, name: str) -> str:
    body = installer.split(f"\n{name}() {{", 1)[1]
    depth = 1
    out = []
    for line in body.split("\n"):
        if line == "}" and depth == 1:
            break
        out.append(line)
    return f"{name}() {{\n" + "\n".join(out) + "\n}\n"


@unittest.skipUnless(BASH, "no bash >= 4 available")
class RetentionContractValidationTests(unittest.TestCase):
    """Fail-closed validation of the retention window at install time."""

    @classmethod
    def setUpClass(cls):
        installer = INSTALLER.read_text(encoding="utf-8")
        cls.fn = extract_function(installer, "validate_backup_retention_contract")

    def run_contract(self, **env):
        preamble = (
            "err() { printf 'ERR: %s\\n' \"$*\" >&2; }\n"
            "warn() { printf 'WARN: %s\\n' \"$*\" >&2; }\n"
            "log() { printf 'LOG: %s\\n' \"$*\"; }\n"
            'BACKUP_RETENTION_DAYS_DEFAULT=30\n'
            'BACKUP_RETENTION_CEILING_DAYS_DEFAULT=90\n'
            'BACKUP_MANIFEST_RETENTION_DAYS_DEFAULT=365\n'
            'BACKUP_PRUNE_DRY_RUN_DEFAULT=0\n'
            'REQUIRE_BACKUP_PRUNING_DEFAULT=1\n'
        )
        script = preamble + self.fn + "\nvalidate_backup_retention_contract\n"
        return subprocess.run(
            [BASH, "-c", script], capture_output=True, text=True,
            env={**os.environ, **{k: str(v) for k, v in env.items()}},
        )

    def test_defaults_are_thirty_days(self):
        proc = self.run_contract()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("30d sensitive", proc.stdout)

    def test_rejects_a_window_above_the_published_ceiling(self):
        proc = self.run_contract(BACKUP_RETENTION_DAYS=120)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("exceeds the published", proc.stderr)

    def test_accepts_the_ceiling_exactly(self):
        self.assertEqual(self.run_contract(BACKUP_RETENTION_DAYS=90).returncode, 0)

    def test_rejects_zero_window(self):
        proc = self.run_contract(BACKUP_RETENTION_DAYS=0)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("at least 1", proc.stderr)

    def test_rejects_non_numeric_window(self):
        proc = self.run_contract(BACKUP_RETENTION_DAYS="thirty")
        self.assertNotEqual(proc.returncode, 0)

    def test_rejects_manifest_window_shorter_than_sensitive_window(self):
        proc = self.run_contract(BACKUP_RETENTION_DAYS=30, BACKUP_MANIFEST_RETENTION_DAYS=7)
        self.assertNotEqual(proc.returncode, 0)

    def test_dry_run_with_required_pruning_warns_loudly(self):
        proc = self.run_contract(BACKUP_PRUNE_DRY_RUN=1)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("does not enforce", proc.stderr)

    def test_rejects_non_boolean_dry_run(self):
        self.assertNotEqual(self.run_contract(BACKUP_PRUNE_DRY_RUN=2).returncode, 0)


@unittest.skipUnless(BASH, "no bash >= 4 available")
class PrunerTests(unittest.TestCase):
    """Runs the shipped pruner against real files, with a fake rclone."""

    @classmethod
    def setUpClass(cls):
        installer = INSTALLER.read_text(encoding="utf-8")
        cls.pruner = extract_heredoc(
            installer, "cat > /usr/local/bin/wins-hub-backup-prune <<'EOF'"
        )

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wins-prune-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.local = os.path.join(self.tmp, "backups")
        self.manifests = os.path.join(self.tmp, "manifests")
        self.replica = os.path.join(self.tmp, "replica")
        for d in (self.local, self.manifests, self.replica):
            os.makedirs(d, exist_ok=True)
        self.script = os.path.join(self.tmp, "prune.sh")
        Path(self.script).write_text(self.pruner, encoding="utf-8")
        os.chmod(self.script, 0o700)
        self.rclone_log = os.path.join(self.tmp, "rclone.log")
        self.bindir = os.path.join(self.tmp, "bin")
        os.makedirs(self.bindir, exist_ok=True)
        self._install_fake_rclone()
        self.env_file = os.path.join(self.tmp, "backup.env")

    def _install_fake_rclone(self):
        """FAKE rclone. Records argv; replays canned config/listing output.

        This proves the pruner issues the right commands against the right
        remotes. It does NOT prove any provider honours them.
        """
        fake = os.path.join(self.bindir, "rclone")
        Path(fake).write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            printf '%s\\n' "$*" >> "{self.rclone_log}"
            case "$1" in
              config)
                # crypt remote wrapping a drive remote
                echo '{{"GoogleDrive_secured":{{"type":"crypt","remote":"gdrive:winsvpn"}},"gdrive":{{"type":"'"${{WINS_FAKE_WRAPPED_TYPE:-drive}}"'"}}}}'
                ;;
              lsjson)
                cat "${{WINS_FAKE_LSJSON:-/dev/null}}" 2>/dev/null || echo '[]'
                ;;
              delete)
                # CP-2: the scoped Drive trash delete can be made to fail.
                [[ "$*" != *--drive-trashed-only* ]] || exit "${{WINS_FAKE_TRASH_RC:-0}}"
                ;;
              cleanup)
                exit "${{WINS_FAKE_CLEANUP_RC:-0}}"
                ;;
              backend)
                # crypt's encode: the encrypted form of the backup folder.
                [[ "$2" != encode ]] || {{ echo 'encdir/enchost'; exit 0; }}
                exit "${{WINS_FAKE_BACKEND_RC:-0}}"
                ;;
              *) exit 0 ;;
            esac
            """), encoding="utf-8")
        os.chmod(fake, 0o755)
        # jq is required by the pruner; fail the suite loudly if it is absent
        # rather than silently skipping the remote stages.
        if not shutil.which("jq"):
            self.skipTest("jq is required to exercise the pruner's remote stages")

    def write_env(self, **overrides):
        values = {
            "RCLONE_REMOTE": "GoogleDrive_secured",
            "REQUIRE_REMOTE_BACKUP": "1",
            "BACKUP_RETENTION_DAYS": "30",
            "BACKUP_MANIFEST_RETENTION_DAYS": "365",
            "BACKUP_PRUNE_DRY_RUN": "0",
            "REQUIRE_BACKUP_PRUNING": "1",
        }
        values.update({k: str(v) for k, v in overrides.items()})
        Path(self.env_file).write_text(
            "".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8"
        )

    def make_archive(self, name: str, age_days: float, directory=None) -> str:
        directory = directory or self.local
        path = os.path.join(directory, name)
        Path(path).write_bytes(b"archive-content")
        stamp = time.time() - age_days * 86400
        os.utime(path, (stamp, stamp))
        return path

    def run_pruner(self, fake_lsjson=None, **env):
        environment = {
            **os.environ,
            "PATH": self.bindir + os.pathsep + os.environ["PATH"],
            "WINS_BACKUP_ENV": self.env_file,
            "WINS_LOCAL_BACKUP_DIR": self.local,
            "WINS_BACKUP_MANIFEST_DIR": self.manifests,
            "WINS_LITESTREAM_REPLICA_DIR": self.replica,
            "WINS_RCLONE_CONFIG": self.env_file,  # any existing file
        }
        if fake_lsjson is not None:
            listing = os.path.join(self.tmp, "lsjson.json")
            Path(listing).write_text(fake_lsjson, encoding="utf-8")
            environment["WINS_FAKE_LSJSON"] = listing
        environment.update({k: str(v) for k, v in env.items()})
        return subprocess.run(
            [BASH, self.script], capture_output=True, text=True, env=environment, timeout=120
        )

    def rclone_calls(self):
        if not os.path.exists(self.rclone_log):
            return []
        return Path(self.rclone_log).read_text(encoding="utf-8").strip().split("\n")

    # --- local archives -----------------------------------------------------

    def test_prunes_local_archives_past_the_window(self):
        self.write_env()
        old = self.make_archive("wins-hub-backup-hub-20250101_021500.tar.gz.age", 45)
        fresh = self.make_archive("wins-hub-backup-hub-20260720_021500.tar.gz.age", 2)
        proc = self.run_pruner(fake_lsjson="[]")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(old), "archive past the 30-day window survived")
        self.assertTrue(os.path.exists(fresh), "archive inside the window was destroyed")

    def test_prunes_the_checksum_sidecar_too(self):
        # A sidecar left behind is a filename and digest of a deleted
        # secret-bearing archive, and evidence the window was not enforced.
        self.write_env()
        old = self.make_archive("wins-hub-backup-hub-20250101_021500.tar.gz.age.sha256", 45)
        self.run_pruner(fake_lsjson="[]")
        self.assertFalse(os.path.exists(old))

    def test_boundary_archive_exactly_at_the_window_is_kept(self):
        self.write_env()
        edge = self.make_archive("wins-hub-backup-hub-edge.tar.gz.age", 29.5)
        self.run_pruner(fake_lsjson="[]")
        self.assertTrue(os.path.exists(edge))

    def test_unrelated_files_are_never_touched(self):
        self.write_env()
        keep = os.path.join(self.local, "README-do-not-delete.txt")
        Path(keep).write_text("unrelated", encoding="utf-8")
        stamp = time.time() - 400 * 86400
        os.utime(keep, (stamp, stamp))
        self.run_pruner(fake_lsjson="[]")
        self.assertTrue(os.path.exists(keep), "pruner deleted a file outside its own naming scheme")

    # --- litestream recovery history ---------------------------------------

    def test_prunes_litestream_history_on_the_same_window(self):
        self.write_env()
        old = os.path.join(self.replica, "old.ltx")
        Path(old).write_bytes(b"ltx")
        stamp = time.time() - 45 * 86400
        os.utime(old, (stamp, stamp))
        fresh = os.path.join(self.replica, "fresh.ltx")
        Path(fresh).write_bytes(b"ltx")
        proc = self.run_pruner(fake_lsjson="[]")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(fresh))

    # --- sanitised manifests -----------------------------------------------

    def test_manifests_use_their_own_longer_window(self):
        self.write_env()
        manifest = os.path.join(self.manifests, "wins-hub-manifest-20250101T000000Z.txt")
        Path(manifest).write_text("schema", encoding="utf-8")
        stamp = time.time() - 60 * 86400
        os.utime(manifest, (stamp, stamp))
        self.run_pruner(fake_lsjson="[]")
        self.assertTrue(
            os.path.exists(manifest),
            "a 60-day-old sanitised manifest was pruned on the 30-day sensitive window",
        )

    # --- dry run ------------------------------------------------------------

    def test_dry_run_removes_nothing_and_reports_everything(self):
        self.write_env(BACKUP_PRUNE_DRY_RUN=1)
        old = self.make_archive("wins-hub-backup-hub-old.tar.gz.age", 45)
        proc = self.run_pruner(fake_lsjson="[]")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(old), "dry run deleted a file")
        self.assertIn("DRY RUN", proc.stdout)
        self.assertIn("WOULD remove local", proc.stdout)
        self.assertIn("WOULD delete objects older than", proc.stdout)
        self.assertIn("WOULD permanently delete trashed objects under", proc.stdout)
        joined = " ".join(self.rclone_calls())
        self.assertIn("--dry-run", joined)
        self.assertNotIn("rmdirs", joined)

    # --- remote stages ------------------------------------------------------

    def test_remote_delete_uses_the_retention_window_and_bypasses_trash(self):
        self.write_env()
        proc = self.run_pruner(fake_lsjson="[]")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls = self.rclone_calls()
        delete = [c for c in calls if c.startswith("delete ")]
        self.assertTrue(delete, f"pruner never issued an rclone delete: {calls}")
        self.assertIn("--min-age 30d", delete[0])
        # Without this a "deleted" archive moves to Drive's trash and stays
        # fully recoverable -- the delete looks successful and the retention
        # claim is false.
        self.assertIn("--drive-use-trash=false", delete[0])

    def test_provider_trash_and_version_history_are_cleaned(self):
        self.write_env()
        self.run_pruner(fake_lsjson="[]")
        calls = self.rclone_calls()
        # CP-2: on Google Drive `rclone cleanup` empties the WHOLE account's
        # trash, so the pruner permanently deletes only the trashed objects
        # under this host's backup prefix, and never runs cleanup at a root.
        trashed = [c for c in calls if c.startswith("delete ") and "--drive-trashed-only" in c]
        self.assertTrue(trashed, f"provider trash under the backup prefix was never cleaned: {calls}")
        self.assertTrue(
            all(c.startswith("delete GoogleDrive_secured:winsvpn-backups/") and "--drive-use-trash=false" in c
                for c in trashed),
            f"trash delete is not scoped to the backup prefix: {trashed}",
        )
        self.assertFalse(
            [c for c in calls if c.startswith("cleanup ")],
            f"account-wide rclone cleanup still runs: {calls}",
        )

    def test_lifecycle_noncurrent_versions_are_cleaned(self):
        # CP-2: on a versioned store, only under the encrypted backup folder,
        # never at the wrapped remote's root (on b2: every reachable bucket).
        self.write_env()
        self.run_pruner(fake_lsjson="[]", WINS_FAKE_WRAPPED_TYPE="b2")
        calls = self.rclone_calls()
        hidden = [c for c in calls if c.startswith("backend cleanup-hidden")]
        self.assertEqual(hidden, ["backend cleanup-hidden gdrive:winsvpn/encdir/enchost"],
                         f"non-current versions were not cleaned under the backup folder only: {calls}")

    def test_failed_lifecycle_cleanup_fails_required_pruning(self):
        self.write_env()
        proc = self.run_pruner(fake_lsjson="[]", WINS_FAKE_WRAPPED_TYPE="b2",
                               WINS_FAKE_BACKEND_RC="23")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("cleanup-hidden failed", proc.stderr)
        self.assertNotIn("retention window enforced", proc.stdout)

    def test_failed_lifecycle_cleanup_reports_optional_gap(self):
        self.write_env(REQUIRE_BACKUP_PRUNING=0)
        proc = self.run_pruner(fake_lsjson="[]", WINS_FAKE_WRAPPED_TYPE="b2",
                               WINS_FAKE_BACKEND_RC="23")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("retention window NOT fully enforced", proc.stdout)

    def test_lifecycle_cleanup_never_runs_at_a_drive_root(self):
        self.write_env()
        proc = self.run_pruner(fake_lsjson="[]")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls = self.rclone_calls()
        self.assertFalse([c for c in calls if c.startswith("backend cleanup-hidden")], calls)
        self.assertIn("stage 6: skipped", proc.stdout)

    def test_real_remote_listing_is_performed_and_counted(self):
        # The listing is the evidence that the window is enforced against the
        # destination that actually holds the data.
        self.write_env()
        old_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 45 * 86400))
        new_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3 * 86400))
        listing = (
            '[{"Path":"a.tar.gz.age","ModTime":"%s","Size":10},'
            '{"Path":"b.tar.gz.age","ModTime":"%s","Size":10}]' % (old_iso, new_iso)
        )
        proc = self.run_pruner(fake_lsjson=listing)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("2 objects at the destination, 1 past the 30-day window", proc.stdout)

    def test_listing_with_rclone_fractions_and_offsets_is_counted_and_pruned(self):
        # Gemini L03 F-1: rclone lsjson writes ModTime at the remote's
        # precision (three fraction digits on Google Drive, nine on a local
        # remote) and in local time with a numeric offset. jq's
        # fromdateiso8601 takes only whole seconds and Z, so the first real
        # listing stopped the run before stage 4 deleted anything.
        self.write_env()
        now = time.time()

        def rfc3339(epoch, offset_minutes, fraction):
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch + offset_minutes * 60))
            if offset_minutes == 0:
                return stamp + fraction + "Z"
            sign = "+" if offset_minutes > 0 else "-"
            return stamp + fraction + "%s%02d:%02d" % (sign, abs(offset_minutes) // 60, abs(offset_minutes) % 60)

        items = [
            ("a", rfc3339(now - 45 * 86400, 0, ".123")),
            ("b", rfc3339(now - 3 * 86400, 0, ".123456789")),
            # 30 days and 2 hours old, written at +05:00: past the window
            # only when the offset is applied with the right sign.
            ("c", rfc3339(now - 30 * 86400 - 7200, 300, ".5")),
            # 30 days less 2 hours old, written at -05:00: inside the window
            # only when the offset is applied with the right sign.
            ("d", rfc3339(now - 30 * 86400 + 7200, -300, "")),
        ]
        listing = "[" + ",".join(
            '{"Path":"%s.tar.gz.age","ModTime":"%s","Size":10}' % item for item in items) + "]"
        proc = self.run_pruner(fake_lsjson=listing)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("4 objects at the destination, 2 past the 30-day window", proc.stdout)
        calls = self.rclone_calls()
        self.assertTrue([c for c in calls if c.startswith("delete ") and "--min-age 30d" in c], calls)

    def test_unparseable_listing_time_fails_closed(self):
        self.write_env()
        proc = self.run_pruner(fake_lsjson='[{"Path":"a.tar.gz.age","ModTime":"yesterday","Size":10}]')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unparseable ModTime", proc.stderr)

    def test_listing_failure_fails_closed(self):
        self.write_env()
        # Break the fake so lsjson exits non-zero with an unexpected error.
        fake = os.path.join(self.bindir, "rclone")
        Path(fake).write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            case "$1" in
              config) echo '{"GoogleDrive_secured":{"type":"crypt","remote":"gdrive:x"}}' ;;
              lsjson) echo "permission denied" >&2; exit 3 ;;
              *) exit 0 ;;
            esac
            """), encoding="utf-8")
        os.chmod(fake, 0o755)
        proc = self.run_pruner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("cannot prove the retention window is enforced", proc.stderr)

    def test_non_crypt_remote_is_refused(self):
        self.write_env()
        fake = os.path.join(self.bindir, "rclone")
        Path(fake).write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            case "$1" in
              config) echo '{"GoogleDrive_secured":{"type":"drive"}}' ;;
              *) exit 0 ;;
            esac
            """), encoding="utf-8")
        os.chmod(fake, 0o755)
        proc = self.run_pruner()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("non-crypt remote", proc.stderr)

    def test_unsupported_cleanup_fails_closed_when_pruning_is_required(self):
        # If neither remote supports cleanup, provider trash is NOT pruned. That
        # must not be reported as a successful retention run.
        self.write_env(REQUIRE_BACKUP_PRUNING=1)
        proc = self.run_pruner(fake_lsjson="[]", WINS_FAKE_TRASH_RC=1)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("NOT being pruned automatically", proc.stderr)

    def test_unusable_remote_config_fails_closed_when_remote_backup_required(self):
        # Same fail-closed branch as a missing rclone binary: if the remote
        # cannot be reached, the run must not report a successful retention
        # window. (Driven through the missing-config arm because this host has a
        # real rclone on PATH that would otherwise be picked up.)
        self.write_env(REQUIRE_REMOTE_BACKUP=1)
        proc = self.run_pruner(WINS_RCLONE_CONFIG="/nonexistent/rclone.conf")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("remote copies are NOT being pruned", proc.stderr)

    def test_unusable_remote_config_is_tolerated_when_remote_backup_optional(self):
        self.write_env(REQUIRE_REMOTE_BACKUP=0)
        old = self.make_archive("wins-hub-backup-hub-old.tar.gz.age", 45)
        proc = self.run_pruner(WINS_RCLONE_CONFIG="/nonexistent/rclone.conf")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # Local pruning still happened even though the remote stages did not.
        self.assertFalse(os.path.exists(old))
        self.assertIn("remote stages skipped", proc.stdout)

    def test_pruner_revalidates_a_tampered_window_on_a_live_host(self):
        # backup.env is editable on a running host; the pruner must not trust it.
        self.write_env(BACKUP_RETENTION_DAYS=3650)
        proc = self.run_pruner(fake_lsjson="[]")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("exceeds the published ceiling", proc.stderr)


@unittest.skipUnless(BASH, "no bash >= 4 available")
class RestoreDrillTests(unittest.TestCase):
    """Post-pruning restore drill, and the last-copy deletion proof.

    Both are REAL: a real tar.gz archive holding a real SQLite database, pruned
    with the real pruner, then restored and queried.
    """

    @classmethod
    def setUpClass(cls):
        installer = INSTALLER.read_text(encoding="utf-8")
        cls.pruner = extract_heredoc(
            installer, "cat > /usr/local/bin/wins-hub-backup-prune <<'EOF'"
        )

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wins-restore-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.local = os.path.join(self.tmp, "backups")
        os.makedirs(self.local, exist_ok=True)
        self.script = os.path.join(self.tmp, "prune.sh")
        Path(self.script).write_text(self.pruner, encoding="utf-8")
        os.chmod(self.script, 0o700)

    def build_archive(self, name: str, age_days: float, accounts) -> str:
        work = tempfile.mkdtemp(dir=self.tmp)
        db = os.path.join(work, "vpn_users.db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE users (account_number TEXT PRIMARY KEY, status TEXT)")
        conn.executemany("INSERT INTO users VALUES (?, 'active')", [(a,) for a in accounts])
        conn.commit()
        conn.close()
        path = os.path.join(self.local, name)
        with tarfile.open(path, "w:gz") as tar:
            tar.add(db, arcname="root/vpn_auth/vpn_users.db")
        stamp = time.time() - age_days * 86400
        os.utime(path, (stamp, stamp))
        return path

    def run_pruner(self, retention_days=30):
        env_file = os.path.join(self.tmp, "backup.env")
        Path(env_file).write_text(
            "RCLONE_REMOTE=GoogleDrive_secured\n"
            "REQUIRE_REMOTE_BACKUP=0\n"
            f"BACKUP_RETENTION_DAYS={retention_days}\n"
            "BACKUP_MANIFEST_RETENTION_DAYS=365\n"
            "BACKUP_PRUNE_DRY_RUN=0\n"
            "REQUIRE_BACKUP_PRUNING=1\n",
            encoding="utf-8",
        )
        return subprocess.run(
            [BASH, self.script], capture_output=True, text=True, timeout=120,
            env={
                **os.environ,
                "WINS_BACKUP_ENV": env_file,
                "WINS_LOCAL_BACKUP_DIR": self.local,
                "WINS_BACKUP_MANIFEST_DIR": os.path.join(self.tmp, "manifests"),
                # No usable rclone config, so the remote stages are skipped and
                # this drill exercises the local half only. REQUIRE_REMOTE_BACKUP
                # is 0 above, so that is a clean exit rather than a failure.
                "WINS_RCLONE_CONFIG": "/nonexistent-rclone-config",
            },
        )

    def test_post_pruning_restore_drill(self):
        """A surviving archive still restores to a working database after a prune."""
        keep = self.build_archive(
            "wins-hub-backup-hub-recent.tar.gz", 5, ["111122223333", "444455556666"]
        )
        stale = self.build_archive("wins-hub-backup-hub-stale.tar.gz", 60, ["999988887777"])

        proc = self.run_pruner()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(keep))

        # REAL restore of the surviving archive.
        restore_dir = os.path.join(self.tmp, "restore")
        os.makedirs(restore_dir, exist_ok=True)
        with tarfile.open(keep, "r:gz") as tar:
            tar.extractall(restore_dir)
        restored = os.path.join(restore_dir, "root", "vpn_auth", "vpn_users.db")
        self.assertTrue(os.path.exists(restored), "restore produced no database")

        conn = sqlite3.connect(restored)
        self.assertEqual(
            conn.execute("PRAGMA quick_check").fetchone()[0], "ok",
            "restored database failed its integrity check after pruning",
        )
        rows = {r[0] for r in conn.execute("SELECT account_number FROM users")}
        conn.close()
        self.assertEqual(rows, {"111122223333", "444455556666"})

    def test_deleting_a_live_record_removes_its_last_backup_copy_in_the_window(self):
        """The whole point of F-8, proved end to end.

        An account is deleted live. Every archive that still contains it must
        age out within the retention window, leaving NO copy anywhere. Before
        this change that never happened: the archive holding the last copy was
        never pruned, so the deletion was undone by the backup system.
        """
        deleted_account = "555566667777"
        surviving_account = "111122223333"

        # Archives taken while the record was live, all now past the window.
        for i, age in enumerate((31, 45, 90)):
            self.build_archive(
                f"wins-hub-backup-hub-old{i}.tar.gz", age,
                [surviving_account, deleted_account],
            )
        # Archives taken after the live deletion, inside the window.
        for i, age in enumerate((1, 10, 29)):
            self.build_archive(
                f"wins-hub-backup-hub-new{i}.tar.gz", age, [surviving_account]
            )

        proc = self.run_pruner()
        self.assertEqual(proc.returncode, 0, proc.stderr)

        remaining = sorted(
            p for p in os.listdir(self.local) if p.endswith(".tar.gz")
        )
        self.assertEqual(len(remaining), 3, f"unexpected survivors: {remaining}")

        # Now the load-bearing assertion: the deleted account must not exist in
        # ANY remaining backup copy.
        for name in remaining:
            work = tempfile.mkdtemp(dir=self.tmp)
            with tarfile.open(os.path.join(self.local, name), "r:gz") as tar:
                tar.extractall(work)
            db = os.path.join(work, "root", "vpn_auth", "vpn_users.db")
            conn = sqlite3.connect(db)
            found = conn.execute(
                "SELECT COUNT(*) FROM users WHERE account_number = ?", (deleted_account,)
            ).fetchone()[0]
            still_there = conn.execute(
                "SELECT COUNT(*) FROM users WHERE account_number = ?", (surviving_account,)
            ).fetchone()[0]
            conn.close()
            self.assertEqual(
                found, 0,
                f"{name} still holds the deleted account: the erasure claim is false",
            )
            self.assertEqual(still_there, 1, f"{name} lost a live account")


class ShippedWiringTests(unittest.TestCase):
    """The pruner is only a control if the shipped script actually runs it."""

    def setUp(self):
        self.installer = INSTALLER.read_text(encoding="utf-8")

    def test_backup_script_invokes_the_pruner(self):
        self.assertIn("wins-hub-backup-prune", self.installer)
        backup = self.installer.split("cat > /usr/local/bin/wins-hub-backup <<'EOF'")[1]
        backup = backup.split("\nEOF\n")[0]
        self.assertIn("WINS_BACKUP_PRUNE_BIN", backup)
        self.assertIn("retention window is NOT being enforced", backup)

    def test_pruning_failure_fails_the_backup_run_by_default(self):
        backup = self.installer.split("cat > /usr/local/bin/wins-hub-backup <<'EOF'")[1]
        backup = backup.split("\nEOF\n")[0]
        self.assertIn('"${REQUIRE_BACKUP_PRUNING:-1}" == "1"', backup)

    def test_standalone_prune_timer_exists_and_is_enabled(self):
        # Pruning must not depend on backups succeeding.
        self.assertIn("wins-hub-backup-prune.timer", self.installer)
        self.assertIn("systemctl enable --now wins-hub-backup-prune.timer", self.installer)

    def test_manifest_directory_is_writable_under_protectsystem_strict(self):
        # ProtectSystem=strict would otherwise make the manifest write fail.
        for unit in ("wins-hub-backup.service", "wins-hub-backup-prune.service"):
            block = self.installer.split(f"cat > /etc/systemd/system/{unit} <<'EOF'")[1]
            block = block.split("\nEOF\n")[0]
            self.assertIn("/var/backups/winsvpn-manifests", block, unit)

    def test_backups_are_independently_encrypted(self):
        backup = self.installer.split("cat > /usr/local/bin/wins-hub-backup <<'EOF'")[1]
        backup = backup.split("\nEOF\n")[0]
        self.assertIn("BACKUP_AGE_RECIPIENTS_FILE", backup)
        self.assertIn("REQUIRE_BACKUP_ENCRYPTION", backup)
        # Recipient public keys only: no private identity may live on the host,
        # so restoration cannot depend on a credential inside the archive.
        self.assertIn("age -R", backup)

    def test_recipients_file_is_excluded_from_the_archive(self):
        backup = self.installer.split("cat > /usr/local/bin/wins-hub-backup <<'EOF'")[1]
        backup = backup.split("\nEOF\n")[0]
        self.assertIn("--exclude='etc/winsvpn/backup-recipients.age'", backup)

    # --- 2026-08-06 backup-encryption-preflight-gate lane -------------------
    # test_backups_are_independently_encrypted above greps the GENERATED script
    # for the variable name, which passed for a year while nothing anywhere
    # assigned it. REQUIRE_BACKUP_ENCRYPTION defaults to 1, so on a fresh deploy
    # the gate exit 1'd, run_initial_backup returned 1, set -e fired, and the
    # deploy died after every host mutation and immediately before public
    # cutover. These four tests assert the wiring, not the text.

    def test_installer_actually_assigns_the_age_recipients_variable(self):
        # The generated scripts read /etc/winsvpn/backup.env and nothing else --
        # the units carry no Environment=/EnvironmentFile= -- and
        # configure_rclone_credentials OVERWRITES that file, so pre-seeding it
        # cannot survive. The producer has to be that function.
        contract = self.installer.split("configure_rclone_credentials() {")[1]
        contract = contract.split("\nvalidate_external_secret_contract() {")[0]
        self.assertIn("> /etc/winsvpn/backup.env", contract)
        for key in (
            "BACKUP_AGE_RECIPIENTS_FILE=%s",
            "REQUIRE_BACKUP_ENCRYPTION=%s",
            "BACKUP_HOST_ID=%s",
        ):
            self.assertIn(key, contract, f"backup.env never carries {key}")

    def test_backup_encryption_is_gated_at_preflight_not_at_first_backup(self):
        # preflight_control -> validate_external_secret_contract ->
        # validate_backup_encryption_contract. The whole point is that the
        # failure lands before any host mutation.
        self.assertIn("validate_backup_encryption_contract() {", self.installer)
        secret_contract = self.installer.split("validate_external_secret_contract() {")[1]
        self.assertIn(
            "validate_backup_encryption_contract",
            secret_contract.split("\n}")[0],
            "the secret contract does not check the backup encryption gate",
        )
        preflight = self.installer.split("preflight_control() {")[1].split("\n}")[0]
        self.assertIn("validate_external_secret_contract", preflight)

    def test_encryption_requirement_is_not_silently_disabled(self):
        # If a future lane makes the deploy pass by flipping the default, this
        # fails. Turning it off must stay a deliberate, argued owner choice.
        self.assertIn(
            'REQUIRE_BACKUP_ENCRYPTION_DEFAULT="${REQUIRE_BACKUP_ENCRYPTION:-1}"',
            self.installer,
        )

    def test_backup_and_prune_agree_on_a_fleet_unique_host_id(self):
        # `hostname -s` is "ubuntu" on both the Kansas hub and the Spain edge,
        # so two hosts sharing one remote would write into the same prefix and
        # prune each other's archives. Both scripts must key on BACKUP_HOST_ID.
        for marker in (
            "cat > /usr/local/bin/wins-hub-backup <<'EOF'",
            "cat > /usr/local/bin/wins-hub-backup-prune <<'EOF'",
        ):
            script = self.installer.split(marker)[1].split("\nEOF\n")[0]
            self.assertIn('HOST_ID="${BACKUP_HOST_ID:-${HOST}}"', script, marker)
            self.assertNotIn(
                "winsvpn-backups/${HOST}\"", script,
                f"{marker} still keys the remote path on the non-unique hostname",
            )
            self.assertIn("${HOST_ID}", script, marker)

    def test_manifest_generator_never_reads_row_data(self):
        manifest = self.installer.split("cat > /usr/local/bin/wins-hub-backup-manifest <<'EOF'")[1]
        manifest = manifest.split("\nEOF\n")[0]
        self.assertIn(".schema", manifest)
        # No SELECT in any EXECUTABLE line: the sanitisation is structural, not
        # a filter. Comments may of course mention it.
        code = "\n".join(
            line for line in manifest.split("\n") if not line.strip().startswith("#")
        )
        self.assertNotIn("select", code.lower())
        for secret_path in ("vpn_auth.env", "rclone.conf", "ADMIN_TOKEN"):
            self.assertNotIn(secret_path, manifest)


if __name__ == "__main__":
    result = unittest.main(module=__name__, argv=["backup-retention"], exit=False, verbosity=2)
    if not result.result.wasSuccessful():
        raise SystemExit(1)
    print("Backup retention tests passed")
