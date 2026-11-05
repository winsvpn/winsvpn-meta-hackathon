#!/usr/bin/env python3
"""CANARY round (2026-10-13), items C-1 and C-2, against the shipped installer.

C-1. The hub database is in WAL mode, and SQLite deletes its -wal and -shm
files when the last connection closes. The canary units mount /root/vpn_auth
read-only, and a read-only connection that cannot create those files cannot
open a WAL database: "unable to open database file". The real hub module is
loaded from the installer and started through its own startup_event(), whose
WAL guard keeps both files while the hub runs; after it has gone idle, both
canary readers (the heredoc in wins-gateway-canary and the generated runtime's
open_canary_database) run in a child process against a read-only view of the
database directory and must see a row that is still only in the WAL. A reader
that starts while the hub is restarting waits for the guard, for at most 40
quarter-second waits.

C-2. The gateway canary probes only the configured public names. The
installer writes them to /etc/winsvpn/gateway-canary.env, the canary script
(one script for the scheduled and the prepublication unit) sources that file,
and no production name is left as a fallback.

Run: python3 -m pytest server/test_canary_c1_c2.py
"""
import _toolchain  # noqa: F401  (interpreter floor)
import asyncio
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

import test_account_deletion_hub as harness
import test_hub_h0_hardening as h0

SERVER = Path(__file__).resolve().parent
INSTALLER = SERVER / "wins_control_plane_setup_ONETOUCH.sh"
SOURCE = INSTALLER.read_text(encoding="utf-8")
CANARY_HEADER = "  cat > /usr/local/bin/wins-gateway-canary <<'EOF'\n"
CANARY_ENV_PATH = "/etc/winsvpn/gateway-canary.env"
STARTUP = SOURCE[SOURCE.index("async def startup_event():"):SOURCE.index("@app.exception_handler(Exception)")]


def canary_script():
    start = SOURCE.index(CANARY_HEADER) + len(CANARY_HEADER)
    return SOURCE[start:SOURCE.index("\nEOF\n", start) + 1]


def shell_function(text, name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", text, re.S | re.M)
    if not match:
        raise AssertionError(f"{name}() not found")
    return match.group(0)


def entries_reader():
    """The embedded Python of winn3_canary_entries(), byte for byte."""
    body = shell_function(canary_script(), "winn3_canary_entries")
    start = body.index("<<'PYEOF'\n") + len("<<'PYEOF'\n")
    return body[start:body.index("\nPYEOF\n", start) + 1]


RUNTIME_READER = (
    "import sys\n"
    "from contextlib import closing\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import wins_winn3_canary_runtime as runtime\n"
    "with closing(runtime.open_canary_database(sys.argv[2])) as connection:\n"
    "    connection.execute('BEGIN')\n"
    "    print(' '.join(row['slug'] for row in connection.execute('SELECT slug FROM nodes ORDER BY slug')))\n"
    "    connection.rollback()\n"
)


class HubDatabase(unittest.TestCase):
    """The real hub module on a temporary database, with its read-only views."""

    def setUp(self):
        self.mod = harness.load_hub()
        self.directory = Path(self.mod._DB).parent
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.addCleanup(self.writable)

    def wal_files(self):
        db = self.mod._DB
        return [Path(db + suffix) for suffix in ("-wal", "-shm") if Path(db + suffix).exists()]

    def read_only_view(self):
        for path in [Path(self.mod._DB), *self.wal_files()]:
            path.chmod(0o444)
        self.directory.chmod(0o555)

    def writable(self):
        if self.directory.exists():
            self.directory.chmod(0o755)
            for path in [Path(self.mod._DB), *self.wal_files()]:
                if path.exists():
                    path.chmod(0o644)

    def child(self, args, stdin=""):
        return subprocess.run([sys.executable, "-I", *args], input=stdin, capture_output=True, text=True,
                              timeout=60, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})

    def readers(self):
        return {"entries": (["-", self.mod._DB], entries_reader()),
                "runtime": (["-c", RUNTIME_READER, str(SERVER), self.mod._DB], "")}


class CanaryReadsAnIdleHubDatabase(HubDatabase):
    """C-1: the hub keeps the WAL files the read-only canary needs."""

    def setUp(self):
        super().setUp()
        self.mod.HIDE_CONTROL_ORIGIN = True
        self.mod.MONERO_WALLET_RPC_URL = ""
        self.mod.EMERGENCY_DISPATCH_ENABLED = False

        async def idle():
            await asyncio.Event().wait()

        # Every background loop idles, so no other connection can hold the
        # files open by chance while the readers run.
        loops = set(re.findall(r"create_task\((\w+)\(\)\)", STARTUP))
        self.assertIn("winn3_canary_result_sweep_loop", loops)
        for name in loops:
            setattr(self.mod, name, idle)

    def test_both_canary_readers_open_the_idle_database_read_only(self):
        async def exercise():
            before = asyncio.all_tasks()
            try:
                await self.mod.startup_event()

                def request():
                    # One hub request: a fresh connection that writes and closes.
                    with self.mod.get_db() as conn:
                        conn.execute("INSERT INTO nodes (slug, protocol_version) VALUES ('lab-alpha', 'winn/3')")
                        conn.execute("INSERT INTO winn3_canary_bindings VALUES "
                                     "('lab-alpha', 'pub', '10.10.0.9', '/k', '192.0.2.1:443', 'gw')")
                await asyncio.to_thread(request)
                if os.geteuid() != 0:
                    # Root ignores file modes; for root the file check below is the test.
                    self.read_only_view()
                    for args, stdin in self.readers().values():
                        started = time.monotonic()
                        proc = self.child(args, stdin)
                        self.assertEqual((proc.returncode, proc.stdout), (0, "lab-alpha\n"), proc.stderr)
                        self.assertLess(time.monotonic() - started, 5, "an idle hub must not make the reader wait")
                    self.writable()
                self.assertEqual([path.name for path in self.wal_files()],
                                 ["vpn_users.db-wal", "vpn_users.db-shm"],
                                 "an idle hub must keep the -wal and -shm files a read-only opener needs")
                # The committed rows are still in the WAL, so the readers had to apply it.
                self.assertGreater(Path(self.mod._DB + "-wal").stat().st_size, 0)
                with closing(sqlite3.connect(self.mod._DB)) as conn:
                    # The held connection pins no snapshot: a full checkpoint completes.
                    self.assertEqual(conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(), (0, 0, 0))
                await self.mod.stop_activation_delivery_worker()
                self.assertEqual(self.wal_files(), [], "the last close at shutdown removes the WAL files")
            finally:
                created = asyncio.all_tasks() - before
                for task in created:
                    task.cancel()
                await asyncio.gather(*created, return_exceptions=True)

        asyncio.run(exercise())

    def test_startup_retains_the_guard_and_the_shutdown_handler_releases_it(self):
        self.assertLess(STARTUP.index("await asyncio.to_thread(initialize_hub_schema)"),
                        STARTUP.index("    retain_hub_wal_sidecars()\n"))
        shutdown = [match.end() for match in re.finditer(r'@app\.on_event\("shutdown"\)\n', SOURCE)]
        self.assertEqual(len(shutdown), 1)
        handler = SOURCE[shutdown[0]:SOURCE.index("\n\n\n", shutdown[0])]
        self.assertTrue(handler.startswith("async def stop_activation_delivery_worker():"), handler)
        self.assertTrue(handler.endswith("\n    release_hub_wal_sidecars()"), handler)


class CanaryReadersBridgeAHubRestart(HubDatabase):
    """C-1: while the hub restarts there is no guard; a reader waits for it, within a bound."""

    def setUp(self):
        super().setUp()
        self.addCleanup(lambda: getattr(self.mod, "release_hub_wal_sidecars", lambda: None)())
        self.mod.initialize_hub_schema()
        with self.mod.get_db() as conn:
            conn.execute("INSERT INTO nodes (slug, protocol_version) VALUES ('lab-alpha', 'winn/3')")
            conn.execute("INSERT INTO winn3_canary_bindings VALUES "
                         "('lab-alpha', 'pub', '10.10.0.9', '/k', '192.0.2.1:443', 'gw')")
        self.assertEqual(self.wal_files(), [], "a stopped hub leaves neither file")

    def started_during_a_restart(self, reader):
        if os.geteuid() == 0:
            self.skipTest("root ignores file modes")
        args, stdin = self.readers()[reader]
        self.read_only_view()
        started = time.monotonic()
        proc = subprocess.Popen([sys.executable, "-I", *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        try:
            proc.stdin.write(stdin)
            proc.stdin.close()
            time.sleep(1.5)
            self.assertIsNone(proc.poll(), "the reader must wait while the hub is down")
            # The hub is back: its startup retains the guard, which creates the files.
            self.writable()
            self.mod.retain_hub_wal_sidecars()
            self.read_only_view()
            out, err = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual((proc.returncode, out), (0, "lab-alpha\n"), err)
        self.assertGreater(time.monotonic() - started, 1.5)

    def test_the_entries_reader_waits_out_a_hub_restart(self):
        self.started_during_a_restart("entries")

    def test_the_runtime_reader_waits_out_a_hub_restart(self):
        self.started_during_a_restart("runtime")

    def gives_up_after_forty_waits(self, read):
        missing = self.directory / "missing.db"
        sleeps = []
        with mock.patch.object(time, "sleep", sleeps.append), \
                mock.patch.object(sys, "argv", ["-", str(missing)]), \
                mock.patch.dict(os.environ, {"WINN3_CANARY_NODES": "", "WINN3_CANARY_NODE_SLUG": ""}), \
                self.assertRaises(sqlite3.OperationalError):
            read(missing)
        self.assertEqual(sleeps, [0.25] * 40)
        self.assertFalse(missing.exists())

    def test_the_entries_reader_gives_up_after_forty_waits(self):
        self.gives_up_after_forty_waits(
            lambda _: exec(compile(entries_reader(), "<winn3_canary_entries>", "exec"), {"__name__": "__main__"}))

    def test_the_runtime_reader_gives_up_after_forty_waits(self):
        import wins_winn3_canary_runtime as runtime
        self.gives_up_after_forty_waits(runtime.open_canary_database)


class TheHubWalGuardIsInert(HubDatabase):
    """C-1: the guard cannot create a database or write, holds no transaction,
    refuses a database that is not in WAL mode, and is idempotent (properties
    from the Sol and Gemini ColdWal tests, on the real hub module)."""

    def setUp(self):
        super().setUp()
        self.addCleanup(lambda: getattr(self.mod, "release_hub_wal_sidecars", lambda: None)())
        self.mod.initialize_hub_schema()

    def test_the_guard_is_query_only_idempotent_and_never_creates_a_database(self):
        self.mod.retain_hub_wal_sidecars()
        guard = self.mod._hub_wal_guard
        self.assertFalse(guard.in_transaction)
        with self.assertRaises(sqlite3.OperationalError):
            guard.execute("DELETE FROM nodes")
        self.mod.retain_hub_wal_sidecars()
        self.assertIs(self.mod._hub_wal_guard, guard)
        self.mod.release_hub_wal_sidecars()
        self.mod.release_hub_wal_sidecars()
        self.assertIsNone(self.mod._hub_wal_guard)
        with self.assertRaises(sqlite3.ProgrammingError):
            guard.execute("SELECT 1")
        missing = self.directory / "missing.db"
        with mock.patch.object(self.mod, "DB_PATH", str(missing)), self.assertRaises(sqlite3.OperationalError):
            self.mod.retain_hub_wal_sidecars()
        self.assertFalse(missing.exists())
        self.assertIsNone(self.mod._hub_wal_guard)
        with closing(sqlite3.connect(self.mod._DB)) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0], "delete")
        with self.assertRaises(sqlite3.OperationalError):
            self.mod.retain_hub_wal_sidecars()
        self.assertIsNone(self.mod._hub_wal_guard)


class CanaryProbesOnlyConfiguredNames(unittest.TestCase):
    """C-2: no production fallback for the hub and sync names."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="canary-c2-"))
        self.addCleanup(shutil.rmtree, self.work, True)
        self.bash = _toolchain.bash4()
        if not shutil.which("jq"):
            self.skipTest("the gateway canary needs jq")
        fake = self.work / "bin"
        fake.mkdir()
        (fake / "curl").write_text(
            "#!/bin/sh\n"
            "for arg; do url=\"$arg\"; done\n"
            "printf '%s\\n' \"$url\" >> \"$CURL_LOG\"\n"
            "case \" $* \" in\n"
            "  *' -D - '*) printf 'HTTP/1.1 200 OK\\r\\nstrict-transport-security: max-age=1\\r\\n"
            "content-security-policy: default-src none\\r\\nx-content-type-options: nosniff\\r\\n"
            "x-frame-options: DENY\\r\\nreferrer-policy: no-referrer\\r\\npermissions-policy: ()\\r\\n"
            "cache-control: no-store\\r\\n\\r\\n' ;;\n"
            "  *) printf '{\"ok\":true,\"nodes\":[]}' ;;\n"
            "esac\n")
        (fake / "curl").chmod(0o755)
        self.path = f"{fake}:{os.environ.get('PATH', '/usr/bin:/bin')}"
        database = self.work / "hub.db"
        with closing(sqlite3.connect(database)) as conn, conn:
            conn.execute("CREATE TABLE nodes (slug TEXT, retired_at TEXT, protocol_version TEXT)")
            conn.execute("CREATE TABLE winn3_canary_bindings (slug TEXT)")
        self.database = database
        (self.work / "vpn_auth.env").write_text(
            "ACTIVE_GATEWAY_BASE='https://sync.stage.invalid'\n"
            "ACTIVE_GATEWAY_RAW_URL='https://gist.stage.invalid/active-gateway.txt'\n")

    def write_env(self, hub, sync, target):
        """The installer's own write_gateway_canary_env(), writing to `target`."""
        function = shell_function(SOURCE, "write_gateway_canary_env")
        prelude = ("err() { printf 'ERR %s\\n' \"$*\" >&2; }\n"
                   "install() { :; }\n"
                   "install_generated_file() { cat > \"$CANARY_ENV_TARGET\"; chmod \"$1\" \"$CANARY_ENV_TARGET\"; }\n"
                   f"HUB_DOMAIN={hub}\nSYNC_DOMAINS=({sync})\n")
        return subprocess.run([self.bash, "-c", prelude + function + "write_gateway_canary_env\n"],
                              capture_output=True, text=True, timeout=30,
                              env={"PATH": self.path, "CANARY_ENV_TARGET": str(target)})

    def run_canary(self, canary_env):
        script = canary_script()
        for old, new in (('ENV_FILE="/root/vpn_auth.env"', f'ENV_FILE="{self.work}/vpn_auth.env"'),
                         (f'CANARY_ENV_FILE="{CANARY_ENV_PATH}"', f'CANARY_ENV_FILE="{canary_env}"'),
                         ('LOG_FILE="/var/lib/wins-canary-dispatch/gateway-canary.log"', f'LOG_FILE="{self.work}/canary.log"'),
                         ("mkdir -p /var/lib/wins-canary-dispatch\n", f"mkdir -p {self.work}\n")):
            self.assertLessEqual(script.count(old), 1)
            script = script.replace(old, new)
        log = self.work / "curl.log"
        log.unlink(missing_ok=True)
        proc = subprocess.run([self.bash, "-c", script], capture_output=True, text=True, timeout=120,
                              env={"PATH": self.path, "CURL_LOG": str(log), "DATABASE_PATH": str(self.database),
                                   "WINS_CANARY_SKIP_GATEWAY_RECORD": "1"})
        urls = log.read_text().split() if log.exists() else []
        return proc, [url for url in urls if url.startswith("https://")]

    def test_installer_writes_the_configured_names_and_refuses_bad_ones(self):
        target = self.work / "gateway-canary.env"
        proc = self.write_env("hub.stage.invalid", "sync.stage.invalid sync-b.stage.invalid", target)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(target.read_text(),
                         "HUB_DOMAIN='hub.stage.invalid'\nSYNC_DOMAINS='sync.stage.invalid sync-b.stage.invalid'\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        for hub, sync in (("'hub stage'", "sync.stage.invalid"), ("hub.stage.invalid", "\"sync'x.invalid\""),
                          ("hub.stage.invalid", ""), ("localhost", "sync.stage.invalid")):
            with self.subTest(hub=hub, sync=sync):
                target.unlink(missing_ok=True)
                self.assertEqual(self.write_env(hub, sync, target).returncode, 1)
                self.assertFalse(target.exists())
        self.assertIn(f"install_generated_file 0600 {CANARY_ENV_PATH}", shell_function(SOURCE, "write_gateway_canary_env"))
        self.assertIn("\nwrite_gateway_canary() {\n  install_h3_canary_artifacts\n  write_gateway_canary_env || return 1\n", SOURCE)

    def test_the_canary_probes_the_configured_names_only(self):
        canary_env = self.work / "gateway-canary.env"
        self.assertEqual(self.write_env("hub.stage.invalid", "sync.stage.invalid sync-b.stage.invalid",
                                        canary_env).returncode, 0)
        proc, urls = self.run_canary(canary_env)
        self.assertIn("OK hub domain health https://hub.stage.invalid/healthz security-headers", proc.stdout)
        self.assertEqual(sorted(set(urls)), [
            "https://hub.stage.invalid/healthz", "https://hub.stage.invalid/nodes",
            "https://sync-b.stage.invalid/healthz", "https://sync-b.stage.invalid/nodes",
            "https://sync.stage.invalid/healthz", "https://sync.stage.invalid/nodes"], proc.stdout + proc.stderr)
        self.assertEqual(len(urls), 9)

    def test_missing_configuration_fails_without_contacting_any_public_name(self):
        proc, urls = self.run_canary(self.work / "absent.env")
        self.assertEqual(urls, [], proc.stdout + proc.stderr)
        self.assertIn("FAIL public canary names unconfigured", proc.stdout)
        self.assertNotEqual(proc.returncode, 0)

    def test_no_default_name_and_one_script_for_both_units(self):
        script = canary_script()
        self.assertIsNone(re.search(r"\$\{(?:HUB_DOMAIN|SYNC_DOMAINS):-[^}]", script))
        self.assertIn(f'CANARY_ENV_FILE="{CANARY_ENV_PATH}"', script)
        # H0 (D7): a sourced file must be outside everything the hub app can write.
        self.assertFalse([path for path in h0.hub_writable_paths(SOURCE) if h0.under(CANARY_ENV_PATH, path)])
        # The canary heredoc holds column-0 braces, so cut to the next function.
        writer = SOURCE[SOURCE.index("\nwrite_gateway_canary() {\n"):SOURCE.index("\nrun_prepublication_gateway_canary() {\n")]
        self.assertIn("/etc/systemd/system/wins-gateway-canary.service \\\n"
                      "    > /etc/systemd/system/wins-gateway-canary-prepublication.service", writer)
        self.assertEqual(writer.count("ExecStart=/usr/local/bin/wins-gateway-canary\n"), 1)


def unit_text(name):
    header = f"  cat > /etc/systemd/system/{name} <<'EOF'\n"
    start = SOURCE.index(header) + len(header)
    return SOURCE[start:SOURCE.index("\nEOF\n", start) + 1]


class CanaryUnitsKeepTheReviewedBoundaries(unittest.TestCase):
    """CK-2 and the PRERELEASE-FIX guards: the canary units order after the hub
    and never pull it in, stay sandboxed with the database read-only, and the
    prepublication unit is still the sed copy of the scheduled unit."""

    def test_units_order_after_the_hub_without_pulling_it_in(self):
        for name in ("wins-gateway-canary.service", "wins-winn3-canary-requests.service"):
            with self.subTest(unit=name):
                unit = unit_text(name)
                self.assertIn("\nAfter=network-online.target wins-hub.service nginx.service\n", unit)
                self.assertIsNone(re.search(r"(?m)^(Requires|Wants|BindsTo|Requisite|PartOf|Upholds)=.*wins-hub", unit))
                self.assertIn("\nProtectSystem=strict\n", unit)
                self.assertIn("\nReadOnlyPaths=/root/vpn_auth\n", unit)
                self.assertNotIn("EnvironmentFile=", unit)
        writer = SOURCE[SOURCE.index("\nwrite_gateway_canary() {\n"):SOURCE.index("\nrun_prepublication_gateway_canary() {\n")]
        self.assertIn("  sed '/^\\[Service\\]$/a\\\n"
                      "Environment=WINS_CANARY_WINN3_ADVISORY=1\\\n"
                      "Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=1' \\\n"
                      "    /etc/systemd/system/wins-gateway-canary.service \\\n"
                      "    > /etc/systemd/system/wins-gateway-canary-prepublication.service\n", writer)
        runner = shell_function(SOURCE, "run_prepublication_gateway_canary")
        self.assertIn('  [[ "${canary_bin}" == "/usr/local/bin/wins-gateway-canary" ]] || {\n'
                      '    err "Prepublication canary must use the reviewed sandboxed gateway canary."\n', runner)


if __name__ == "__main__":
    unittest.main()
