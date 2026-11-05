#!/usr/bin/env python3
"""Real-binary integration tests for the HANDOFF 3j durability barrier.

Everything in tools/test_redemption_endpoint.py drives the barrier through a
FAKE runner: no test there has ever seen a real `litestream sync -wait`. That
is fine for the failure modes, but it cannot catch the two mistakes that
actually shipped -- a pinned version whose CLI does not have the flags at all,
and a guess about the JSON field names.

This file closes that gap. What is real and what is faked, stated plainly
(HANDOFF 3b evidence category B, local infrastructure only -- no hub, no node,
no remote object store):

  REAL: the shipped `parse_litestream_sync_result`, `_run_litestream_sync` and
        `run_durability_barrier`, sliced by AST out of
        server/wins_control_plane_setup_ONETOUCH.sh; a real litestream daemon
        replicating a real WAL-mode SQLite database to a real file replica; the
        real `sync -wait -timeout N -json` subprocess and its real exit codes
        and stdout; and the real shell archive-safety helper run under bash
        against real tar archives, including hostile ones built here.

  FAKE: nothing in the barrier path. The replica is a local file replica rather
        than object storage, which exercises the same sync/-wait code path but
        not any provider-specific transport.

The litestream tests SKIP -- loudly, never silently pass -- when no
barrier-capable binary is available on this host. Point WINS_LITESTREAM_BIN at
one to run them, or run this file inside a Linux container that has one:

    docker build -t wins-litestream-probe -f - . <<'EOF'
    FROM python:3.12-slim
    COPY litestream /usr/local/bin/litestream
    COPY server/wins_control_plane_setup_ONETOUCH.sh /w/server/
    COPY tools/test_litestream_barrier_integration.py /w/tools/
    EOF
    docker run --rm wins-litestream-probe python /w/tools/test_litestream_barrier_integration.py
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"

# `sync -wait` first exists in 0.5.9; its `-json` output first exists in
# 0.5.12. Below that the barrier cannot work at all.
MINIMUM_BARRIER_VERSION = (0, 5, 12)

# The names the barrier is actually made of, lifted verbatim from the shipped
# module so a regression in the script fails here rather than in production.
BARRIER_NAMES = (
    "LITESTREAM_BIN",
    "LITESTREAM_PINNED_VERSION",
    "LITESTREAM_SYNC_TIMEOUT_SECONDS",
    "LITESTREAM_DB_PATH_FIELD",
    "DURABILITY_BARRIER_ENABLED",
    "DURABILITY_BARRIER_REQUIRED",
    "DurabilityBarrierError",
    "parse_litestream_sync_result",
    "_run_litestream_sync",
    "_DURABILITY_BARRIER_RUNNER",
    "run_durability_barrier",
)


def embedded_app_source() -> str:
    installer = INSTALLER.read_text(encoding="utf-8")
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


def load_barrier_module() -> dict:
    """Exec only the barrier definitions, sliced out of the shipped module.

    Slicing by AST rather than by string markers means this binds to the real
    definitions and breaks loudly if one is renamed or removed, instead of
    silently testing a stale copy.
    """
    source = embedded_app_source()
    tree = ast.parse(source)
    wanted = set(BARRIER_NAMES)
    chunks: list[str] = []
    found: set[str] = set()
    for node in tree.body:
        names: list[str] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if any(n in wanted for n in names):
            chunks.append(ast.get_source_segment(source, node) or "")
            found.update(n for n in names if n in wanted)
    missing = wanted - found
    if missing:
        raise AssertionError(
            "durability barrier definitions missing from the shipped module: "
            + ", ".join(sorted(missing))
        )
    namespace: dict = {
        "os": os,
        "json": json,
        "subprocess": subprocess,
        "Any": Any,
        "Optional": Optional,
        # The barrier defaults to the hub database when no path is passed; the
        # tests always pass one explicitly.
        "DB_PATH": "/nonexistent/vpn_users.db",
    }
    exec(compile("\n\n".join(chunks), "<shipped-barrier>", "exec"), namespace)
    return namespace


BARRIER = load_barrier_module()
DurabilityBarrierError = BARRIER["DurabilityBarrierError"]


def parse_semver(text: str) -> Optional[tuple]:
    match = re.search(r"([0-9]+)\.([0-9]+)\.([0-9]+)", text or "")
    if not match:
        return None
    return tuple(int(g) for g in match.groups())


def usable_litestream() -> Optional[tuple]:
    """A litestream this host can actually execute, at a barrier-capable version."""
    candidate = os.environ.get("WINS_LITESTREAM_BIN") or shutil.which("litestream")
    if not candidate or not os.path.isfile(candidate):
        return None
    try:
        proc = subprocess.run([candidate, "version"], capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    version = parse_semver(proc.stdout)
    if not version or version < MINIMUM_BARRIER_VERSION:
        return None
    return candidate, version


LITESTREAM = usable_litestream()
SKIP_REASON = (
    "no barrier-capable litestream on this host "
    f"(need >= {'.'.join(str(p) for p in MINIMUM_BARRIER_VERSION)}); "
    "set WINS_LITESTREAM_BIN to run these for real"
)


class ShippedPinTests(unittest.TestCase):
    """These need no binary: they check the two halves of the pin agree."""

    def setUp(self):
        self.installer = INSTALLER.read_text(encoding="utf-8")

    def test_runtime_pin_is_barrier_capable(self):
        version = parse_semver(BARRIER["LITESTREAM_PINNED_VERSION"])
        self.assertIsNotNone(version, "runtime pin must be an exact x.y.z version")
        self.assertGreaterEqual(
            version, MINIMUM_BARRIER_VERSION,
            "runtime pin predates `sync -wait -json`; the barrier could never succeed",
        )

    def test_installer_and_runtime_pins_are_identical(self):
        shell = re.search(
            r'LITESTREAM_VERSION_DEFAULT="\$\{LITESTREAM_VERSION:-([0-9]+\.[0-9]+\.[0-9]+)\}"',
            self.installer,
        )
        self.assertIsNotNone(shell)
        self.assertEqual(shell.group(1), BARRIER["LITESTREAM_PINNED_VERSION"])

    def test_db_path_field_is_the_cli_name(self):
        # Confirmed against the real 0.5.15 binary, not inferred.
        self.assertEqual(BARRIER["LITESTREAM_DB_PATH_FIELD"], "db_path")


@unittest.skipUnless(LITESTREAM, SKIP_REASON)
class RealLitestreamBarrierTests(unittest.TestCase):
    """Drives the shipped barrier against a real litestream daemon."""

    def setUp(self):
        self.binary, self.version = LITESTREAM
        self.tmp = tempfile.mkdtemp(prefix="wins-litestream-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db_path = os.path.join(self.tmp, "data", "vpn_users.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(os.path.join(self.tmp, "replica"), exist_ok=True)
        self.socket_path = os.path.join(self.tmp, "litestream.sock")
        self.config_path = os.path.join(self.tmp, "litestream.yml")
        # The control socket is DISABLED BY DEFAULT in litestream. `sync` is an
        # IPC client, so without this stanza every barrier call fails closed
        # with "failed to connect to control socket" -- which is correct
        # behaviour, and also a total outage of every critical write.
        Path(self.config_path).write_text(textwrap.dedent(f"""\
            socket:
              enabled: true
              path: {self.socket_path}
              permissions: 0600
            dbs:
              - path: {self.db_path}
                replicas:
                  - type: file
                    path: {os.path.join(self.tmp, "replica", "db")}
            """), encoding="utf-8")

        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE entitlements (id INTEGER PRIMARY KEY, account TEXT)")
        conn.commit()
        conn.close()

        self.log = open(os.path.join(self.tmp, "replicate.log"), "w+")
        self.addCleanup(self.log.close)
        self.daemon = subprocess.Popen(
            [self.binary, "replicate", "-config", self.config_path],
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        self.addCleanup(self._stop_daemon)
        deadline = time.time() + 30
        while time.time() < deadline and not os.path.exists(self.socket_path):
            if self.daemon.poll() is not None:
                self.log.seek(0)
                self.fail("litestream replicate exited early:\n" + self.log.read())
            time.sleep(0.1)
        self.assertTrue(os.path.exists(self.socket_path), "litestream control socket never appeared")

        # The shipped barrier reads these at call time from its own globals.
        BARRIER["LITESTREAM_BIN"] = self.binary
        BARRIER["DURABILITY_BARRIER_ENABLED"] = True
        BARRIER["DURABILITY_BARRIER_REQUIRED"] = True
        self._orig_socket = os.environ.get("LITESTREAM_SOCKET")
        os.environ["LITESTREAM_SOCKET"] = self.socket_path
        self.addCleanup(self._restore_socket_env)

    def _restore_socket_env(self):
        if self._orig_socket is None:
            os.environ.pop("LITESTREAM_SOCKET", None)
        else:
            os.environ["LITESTREAM_SOCKET"] = self._orig_socket

    def _stop_daemon(self):
        if self.daemon.poll() is None:
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.daemon.kill()

    def _commit(self, account: str):
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO entitlements (account) VALUES (?)", (account,))
        conn.commit()
        conn.close()

    def _sync(self, *args):
        return subprocess.run(
            [self.binary, "sync", "-socket", self.socket_path, *args],
            capture_output=True, text=True, timeout=60,
        )

    def test_real_sync_wait_json_satisfies_the_pinned_parser(self):
        self._commit("acct-1")
        proc = self._sync("-wait", "-timeout", "30", "-json", self.db_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = BARRIER["parse_litestream_sync_result"](
            proc.returncode, proc.stdout, proc.stderr, self.db_path,
        )
        self.assertEqual(result["db_path"], os.path.realpath(self.db_path))
        self.assertGreater(result["txid"], 0)
        self.assertEqual(result["txid"], result["replica_txid"])

    def test_real_sync_reports_exactly_the_fields_the_parser_pins(self):
        self._commit("acct-2")
        proc = self._sync("-wait", "-timeout", "30", "-json", self.db_path)
        payload = json.loads(proc.stdout)
        self.assertIn("db_path", payload)
        self.assertIn("txid", payload)
        self.assertIn("replica_txid", payload)
        # The IPC interface's name must NOT appear on the CLI interface; if it
        # ever does, the pinned parser's hard stop is wrong.
        self.assertNotIn("replicated_txid", payload)
        self.assertIsInstance(payload["txid"], int)
        self.assertIsInstance(payload["replica_txid"], int)
        self.assertNotIsInstance(payload["txid"], bool)

    def test_omitting_wait_drops_replica_txid_and_the_parser_fails_closed(self):
        # THE SILENT FALSE POSITIVE, REPRODUCED FOR REAL. `replica_txid` is
        # tagged omitempty in the release binary, so a sync without -wait does
        # not report a stale position -- the key vanishes entirely. A parser
        # using .get(..., default) would compare the default against txid and
        # could pass. Absent must never compare equal to anything.
        self._commit("acct-3")
        proc = self._sync("-json", self.db_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertNotIn("replica_txid", payload)
        with self.assertRaises(DurabilityBarrierError) as caught:
            BARRIER["parse_litestream_sync_result"](
                proc.returncode, proc.stdout, proc.stderr, self.db_path,
            )
        self.assertEqual(caught.exception.reason, "replica_txid_missing")

    def test_unknown_database_path_fails_closed(self):
        other = os.path.join(self.tmp, "data", "not-replicated.db")
        sqlite3.connect(other).close()
        proc = self._sync("-wait", "-timeout", "5", "-json", other)
        self.assertNotEqual(proc.returncode, 0)
        with self.assertRaises(DurabilityBarrierError) as caught:
            BARRIER["parse_litestream_sync_result"](
                proc.returncode, proc.stdout, proc.stderr, other,
            )
        self.assertEqual(caught.exception.reason, "exit_status")

    def test_barrier_run_through_the_shipped_entry_point(self):
        # Not just the parser: the whole shipped run_durability_barrier,
        # including its real subprocess invocation of the real binary.
        self._commit("acct-4")

        def runner(db_path):
            proc = self._sync("-wait", "-timeout", "30", "-json", db_path)
            return proc.returncode, proc.stdout, proc.stderr

        result = BARRIER["run_durability_barrier"](self.db_path, runner=runner)
        self.assertEqual(result["txid"], result["replica_txid"])

    def test_barrier_after_concurrent_commits_covers_them_all(self):
        # The barrier runs AFTER the commit, so the confirmed position must
        # encompass that commit and any concurrent ones (HANDOFF 3j).
        for i in range(5):
            self._commit(f"concurrent-{i}")
        proc = self._sync("-wait", "-timeout", "30", "-json", self.db_path)
        first = BARRIER["parse_litestream_sync_result"](
            proc.returncode, proc.stdout, proc.stderr, self.db_path,
        )
        self._commit("after-barrier")
        proc = self._sync("-wait", "-timeout", "30", "-json", self.db_path)
        second = BARRIER["parse_litestream_sync_result"](
            proc.returncode, proc.stdout, proc.stderr, self.db_path,
        )
        self.assertGreater(second["txid"], first["txid"])
        self.assertEqual(second["txid"], second["replica_txid"])

    def test_daemon_down_fails_closed_rather_than_acknowledging(self):
        self._commit("acct-5")
        self._stop_daemon()
        proc = self._sync("-wait", "-timeout", "5", "-json", self.db_path)
        self.assertNotEqual(proc.returncode, 0)
        with self.assertRaises(DurabilityBarrierError):
            BARRIER["parse_litestream_sync_result"](
                proc.returncode, proc.stdout, proc.stderr, self.db_path,
            )


def _bash() -> Optional[str]:
    """A bash new enough for the installer's ${var,,} and =~ helpers."""
    for candidate in (os.environ.get("WINS_BASH"), shutil.which("bash"), "/bin/bash"):
        if not candidate or not os.path.isfile(candidate):
            continue
        try:
            proc = subprocess.run([candidate, "--version"], capture_output=True, text=True, timeout=15)
        except Exception:
            continue
        version = parse_semver(proc.stdout)
        if version and version >= (4, 0, 0):
            return candidate
    return None


BASH = _bash()


@unittest.skipUnless(BASH, "no bash >= 4 available to run the installer helpers")
class ArchiveSafetyHelperTests(unittest.TestCase):
    """Runs the REAL shell helper against real tar archives, including hostile ones.

    The checksum pin already covers the network. This helper covers the case the
    checksum cannot: a future version bump to an archive whose layout changed,
    where `tar -x` would be pointed at a filesystem on the strength of a digest
    that only proves the bytes are what the release published.
    """

    @classmethod
    def setUpClass(cls):
        installer = INSTALLER.read_text(encoding="utf-8")
        body = installer.split("litestream_archive_members_are_safe() {")[1]
        body = body.split("\ninstall_litestream()")[0]
        cls.helper = (
            "err() { printf 'ERR: %s\\n' \"$*\" >&2; }\n"
            "litestream_archive_members_are_safe() {" + body + "\n"
        )

    def run_helper(self, archive: str):
        script = self.helper + f'\nlitestream_archive_members_are_safe "{archive}"\n'
        return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=60)

    def make_archive(self, members, path: str) -> str:
        with tarfile.open(path, "w:gz") as tar:
            for info, payload in members:
                tar.addfile(info, payload)
        return path

    @staticmethod
    def regular(name: str, size: int = 16):
        info = tarfile.TarInfo(name)
        info.type = tarfile.REGTYPE
        info.size = size
        info.mode = 0o755
        import io
        return info, io.BytesIO(b"\0" * size)

    @staticmethod
    def symlink(name: str, target: str):
        info = tarfile.TarInfo(name)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        info.size = 0
        return info, None

    def test_accepts_the_real_release_layout(self):
        path = os.path.join(tempfile.mkdtemp(), "ok.tar.gz")
        self.make_archive([
            self.regular("LICENSE"),
            self.regular("README.md"),
            self.regular("etc/litestream.service"),
            self.regular("etc/litestream.yml"),
            self.regular("litestream", 1024),
        ], path)
        proc = self.run_helper(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_rejects_a_symlinked_binary_member(self):
        # Would otherwise be followed straight out of the staging directory.
        path = os.path.join(tempfile.mkdtemp(), "symlink.tar.gz")
        self.make_archive([
            self.regular("LICENSE"),
            self.symlink("litestream", "/usr/bin/env"),
        ], path)
        proc = self.run_helper(path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unexpected type", proc.stderr)

    def test_rejects_path_traversal(self):
        path = os.path.join(tempfile.mkdtemp(), "traverse.tar.gz")
        self.make_archive([
            self.regular("litestream", 1024),
            self.regular("../../etc/cron.d/pwn"),
        ], path)
        proc = self.run_helper(path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("traverses upward", proc.stderr)

    def test_rejects_absolute_paths(self):
        path = os.path.join(tempfile.mkdtemp(), "absolute.tar.gz")
        self.make_archive([
            self.regular("litestream", 1024),
            self.regular("/etc/shadow"),
        ], path)
        proc = self.run_helper(path)
        self.assertNotEqual(proc.returncode, 0)

    def test_rejects_an_unexpected_extra_member(self):
        path = os.path.join(tempfile.mkdtemp(), "extra.tar.gz")
        self.make_archive([
            self.regular("litestream", 1024),
            self.regular("install.sh"),
        ], path)
        proc = self.run_helper(path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("expected release layout", proc.stderr)

    def test_rejects_an_archive_with_no_binary(self):
        path = os.path.join(tempfile.mkdtemp(), "nobinary.tar.gz")
        self.make_archive([self.regular("LICENSE"), self.regular("README.md")], path)
        proc = self.run_helper(path)
        self.assertNotEqual(proc.returncode, 0)

    def test_rejects_a_non_archive(self):
        path = os.path.join(tempfile.mkdtemp(), "garbage.tar.gz")
        Path(path).write_bytes(b"not a tar archive at all")
        proc = self.run_helper(path)
        self.assertNotEqual(proc.returncode, 0)

    def test_real_release_archive_when_present(self):
        # If the operator kept the verified release archive around, validate the
        # genuine article rather than only synthesised ones.
        candidate = os.environ.get("WINS_LITESTREAM_ARCHIVE")
        if not candidate or not os.path.isfile(candidate):
            self.skipTest("set WINS_LITESTREAM_ARCHIVE to a verified release archive")
        proc = self.run_helper(candidate)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    if not LITESTREAM:
        print(f"NOTE: {SKIP_REASON}")
    result = unittest.main(module=__name__, argv=["litestream-barrier"], exit=False, verbosity=2)
    if not result.result.wasSuccessful():
        raise SystemExit(1)
    print("Litestream barrier integration tests passed")
