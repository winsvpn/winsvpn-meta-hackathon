#!/usr/bin/env python3
"""Gemini L03 (control-plane shell layer) verified fixes, against the shipped installer.

F-2  wins_node_dataplane_probe.py refuses a node-registered xray_path that is
     not a whitespace-free printable path before it writes it into the raw
     WebSocket request line (register_node stores the path as sent).
I-1  the stealth sender skips its trailing 0.5 s drain wait once the nonce was
     seen or the capture has ended, and keeps it otherwise.
F-3  write_sqlite_bootstrap does not chmod through a link planted at the
     database name while its sqlite3 run holds the old file.
F-5  wins-admin reads only the root-owned /root/vpn_auth.env, so the app
     writable mirror cannot choose DATABASE_PATH.
F-6  the gateway canary refuses a node stealth host that is not a plain name
     and never lets curl expand a glob in a node URL.

Everything under test is extracted from wins_control_plane_setup_ONETOUCH.sh
byte for byte; no node, network, ssh or root is used.

Run:  python3 -m pytest -q server/test_hub_gemini_l03_fixes.py
      WINS_CP_INSTALLER=/path/to/installer python3 -m pytest -q server/test_hub_gemini_l03_fixes.py
"""
import ast
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import textwrap
import threading
import time
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
INSTALLER = Path(os.environ.get("WINS_CP_INSTALLER") or HERE / "wins_control_plane_setup_ONETOUCH.sh")
SOURCE = INSTALLER.read_text(encoding="utf-8")


def _bash():
    for candidate in (os.environ.get("WINS_BASH"), shutil.which("bash"), "/bin/bash"):
        if not candidate or not os.path.isfile(candidate):
            continue
        proc = subprocess.run([candidate, "--version"], capture_output=True, text=True)
        if proc.returncode == 0 and "version 3." not in proc.stdout.split("\n")[0]:
            return candidate
    return None


BASH = _bash()


def heredoc(header, end):
    start = SOURCE.index(header) + len(header)
    return SOURCE[start:SOURCE.index("\n" + end + "\n", start) + 1]


def shell_function(text, name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", text, re.S | re.M)
    if not match:
        raise AssertionError(f"{name}() not found")
    return match.group(0)


# ----------------------------------------------------------- the probe ----

PROBE_HEAD = "cat > /usr/local/lib/wins_node_dataplane_probe.py <<'DPPROBEEOF'\n"
STEALTH_ROW = {
    "xray_path": "/assets/0123456789abcdef", "xray_uuid": "00000000-0000-4000-8000-000000000000",
    "wg_port": 9110, "endpoint": "h.example.test:9110",
    "stealth_endpoint": "h.example.test:80", "xray_security": "none",
    "stealth_transports": '[{"security":"none","port":80}]',
}


class FakeSocket:
    def __init__(self, record):
        self.record = record

    def settimeout(self, _value):
        pass

    def sendall(self, data):
        self.record["sent"].append(bytes(data))

    def recv(self, _size):
        if self.record["replied"]:
            return b""
        self.record["replied"] = True
        return b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"

    def close(self):
        pass


class FakeProc:
    def __init__(self, exited=False):
        self.exited = exited

    def poll(self):
        return 0 if self.exited else None


def load_prober(record, hit_set, exited=False):
    namespace = {"__name__": "wins_node_dataplane_probe_gemini_l03"}
    exec(compile(heredoc(PROBE_HEAD, "DPPROBEEOF"), "wins_node_dataplane_probe.py", "exec"), namespace)
    namespace["log"] = lambda _msg: None

    def create_connection(address, timeout=None):
        record["connected"].append(address)
        return FakeSocket(record)

    namespace["socket"] = types.SimpleNamespace(
        create_connection=create_connection, inet_aton=socket.inet_aton)
    namespace["time"] = types.SimpleNamespace(
        sleep=lambda seconds: record["sleeps"].append(seconds), monotonic=time.monotonic, time=time.time)

    def run_capture(ssh_host, bpf, nonce, sender, interface="any"):
        hit = threading.Event()
        if hit_set:
            hit.set()
        record["sender_returned"] = sender(FakeProc(exited), hit)
        return "reachable", "fixture"

    namespace["_run_capture_probe"] = run_capture
    return namespace


def new_record():
    return {"sent": [], "connected": [], "sleeps": [], "replied": False}


class ProbeStealthPathTests(unittest.TestCase):
    """F-2: the probe never writes a node-chosen CR/LF into its request."""

    def probe(self, path):
        record = new_record()
        probe = load_prober(record, hit_set=True)
        row = dict(STEALTH_ROW, xray_path=path)
        return probe["probe_stealth"]("node", row, "none"), record

    def test_a_normal_path_is_still_probed(self):
        (verdict, _detail), record = self.probe("/assets/0123456789abcdef")
        self.assertEqual(verdict, "reachable")
        self.assertEqual(record["connected"], [("h.example.test", 80)])
        self.assertTrue(record["sent"][0].startswith(b"GET /assets/0123456789abcdef HTTP/1.1\r\nHost: h.example.test\r\n"))

    def test_a_path_with_crlf_is_refused_before_any_connection(self):
        smuggled = "/p HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nPOST /admin/maintenance HTTP/1.1\r\nX-Real-IP: 10.0.0.1"
        (verdict, detail), record = self.probe(smuggled)
        self.assertEqual((verdict, detail), ("probe_error", "malformed stealth path"))
        self.assertEqual(record["connected"], [])
        self.assertFalse(any(b"POST /admin" in chunk for chunk in record["sent"]))

    def test_whitespace_control_and_relative_paths_are_refused(self):
        for path in ("/a b", "/a\tb", "/a\x00b", "/a\x7fb", "relative", "/café"):
            with self.subTest(path=path):
                (verdict, detail), record = self.probe(path)
                self.assertEqual((verdict, detail), ("probe_error", "malformed stealth path"))
                self.assertEqual(record["connected"], [])


class ProbeStealthDrainTests(unittest.TestCase):
    """I-1: the trailing drain wait runs only while it can still matter."""

    def sleeps_after_frames(self, hit_set, exited=False):
        record = new_record()
        probe = load_prober(record, hit_set=hit_set, exited=exited)
        probe["probe_stealth"]("node", dict(STEALTH_ROW), "none")
        return record["sleeps"]

    def test_no_drain_wait_once_the_nonce_was_seen(self):
        self.assertNotIn(0.5, self.sleeps_after_frames(hit_set=True))

    def test_no_drain_wait_once_the_capture_ended(self):
        self.assertNotIn(0.5, self.sleeps_after_frames(hit_set=False, exited=True))

    def test_drain_wait_kept_while_the_capture_still_waits_for_the_nonce(self):
        sleeps = self.sleeps_after_frames(hit_set=False)
        self.assertEqual(sleeps[-1], 0.5, sleeps)


# --------------------------------------------- write_sqlite_bootstrap ----

@unittest.skipUnless(BASH, "no bash >= 4 available")
class SqliteBootstrapLinkTests(unittest.TestCase):
    """F-3: the post-run chmod refuses a link swapped in during sqlite3."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gemini-l03-bootstrap-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.app = os.path.join(self.dir, "vpn_auth")
        os.makedirs(self.app)
        self.shims = os.path.join(self.dir, "shims")
        os.makedirs(self.shims)
        self.victim = Path(self.dir, "victim")
        self.victim.write_text("host file\n")
        os.chmod(self.victim, 0o644)

    def shim_sqlite3(self, action):
        # Stands in for every sqlite3 run of the bootstrap (sqlite3 -cmd
        # '.timeout 30000' DB [SQL]): a schema heredoc is consumed, a column
        # probe answers "present", and on the first call the name is treated
        # the way the hub app can treat it while that run is in progress.
        Path(self.shims, "sqlite3").write_text(textwrap.dedent(f"""\
            #!{BASH}
            db="$3"
            if [[ $# -ge 4 ]]; then
              [[ "$4" == SELECT* ]] && echo 1
            else
              cat > /dev/null
            fi
            if [[ ! -e {os.path.join(self.dir, 'acted')!r} ]]; then
              : > {os.path.join(self.dir, 'acted')!r}
              {action}
            fi
            """))
        os.chmod(os.path.join(self.shims, "sqlite3"), 0o755)

    def run_bootstrap(self):
        script = textwrap.dedent(f"""\
            set -uo pipefail
            log() {{ echo "[INFO] $*"; }}
            err() {{ echo "[ERR] $*"; }}
            APP_DIR={self.app!r}
            DB_PATH={os.path.join(self.app, 'vpn_users.db')!r}
            """) + shell_function(SOURCE, "write_sqlite_bootstrap") + '\nwrite_sqlite_bootstrap\necho "rc=$?"\n'
        env = {"PATH": self.shims + os.pathsep + os.environ["PATH"], "HOME": self.dir, "LC_ALL": "C"}
        return subprocess.run([BASH, "--noprofile", "--norc", "-c", script], capture_output=True, text=True,
                              env=env, stdin=subprocess.DEVNULL, timeout=60)

    def test_a_link_planted_during_the_run_is_not_chmodded(self):
        self.shim_sqlite3(f'ln -s {str(self.victim)!r} "$db"')
        done = self.run_bootstrap()
        self.assertEqual(stat.S_IMODE(self.victim.stat().st_mode), 0o644, done.stdout + done.stderr)
        self.assertIn("rc=1", done.stdout)

    def test_a_regular_database_is_still_made_owner_only(self):
        self.shim_sqlite3(': > "$db"; chmod 644 "$db"')
        done = self.run_bootstrap()
        self.assertIn("rc=0", done.stdout, done.stdout + done.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.app, "vpn_users.db")).st_mode), 0o600)


# ------------------------------------------------------------ wins-admin ----

class AdminEnvSourceTests(unittest.TestCase):
    """F-5: the app-writable mirror cannot steer wins-admin's database path."""

    def load_env(self, root):
        tree = ast.parse(heredoc("cat > /usr/local/bin/wins-admin <<'PYEOF'\n", "PYEOF"))
        wanted = []
        for node in tree.body:
            if isinstance(node, ast.For):
                wanted.append(node)
            elif isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id in {"ENV_PATHS", "ENV", "DB"} for t in node.targets):
                wanted.append(node)

        class Reroot(ast.NodeTransformer):
            def visit_Constant(self, node):
                if isinstance(node.value, str) and node.value.startswith("/root/"):
                    return ast.copy_location(ast.Constant(root + node.value), node)
                return node

        module = ast.fix_missing_locations(Reroot().visit(ast.Module(body=wanted, type_ignores=[])))
        namespace = {"Path": Path}
        exec(compile(module, "wins-admin", "exec"), namespace)
        return namespace

    def test_legacy_mirror_cannot_choose_the_database(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "root", "vpn_auth"))
            Path(root, "root", "vpn_auth.env").write_text(
                "DATABASE_PATH='/root/vpn_auth/vpn_users.db'\nADMIN_TOKEN='root-owned'\n")
            Path(root, "root", "vpn_auth", ".env").write_text(
                "DATABASE_PATH='/etc/nologin'\nDATABASEPATH='/etc/nologin'\n"
                "ADMIN_TOKEN='planted'\nPLANTED_ONLY='1'\n")
            namespace = self.load_env(root)
        self.assertEqual(namespace["DB"], "/root/vpn_auth/vpn_users.db")
        self.assertEqual(namespace["ENV"].get("ADMIN_TOKEN"), "root-owned")
        self.assertNotIn("PLANTED_ONLY", namespace["ENV"])


# ------------------------------------------------------ the gateway canary ----

@unittest.skipUnless(BASH and shutil.which("jq") and shutil.which("base64"), "bash >= 4, jq and base64 required")
class CanaryNodeUrlTests(unittest.TestCase):
    """F-6: node stealth hosts reach curl only as plain names, never as globs."""

    CANARY_HEADER = "  cat > /usr/local/bin/wins-gateway-canary <<'EOF'\n"

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gemini-l03-canary-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bin = os.path.join(self.dir, "bin")
        os.makedirs(self.bin)
        self.calls = os.path.join(self.dir, "curl.calls")
        self.nodes = os.path.join(self.dir, "nodes.json")
        Path(self.bin, "curl").write_text(textwrap.dedent(f"""\
            #!{BASH}
            for arg in "$@"; do
              if [[ "${{arg}}" == http://127.0.0.1:8000/nodes ]]; then cat {self.nodes!r}; exit 0; fi
            done
            printf '%s\\x1f' "$@" >> {self.calls!r}; printf '\\n' >> {self.calls!r}
            exit 7
            """))
        os.chmod(os.path.join(self.bin, "curl"), 0o755)

    def run_loop(self, stealth_endpoint):
        node = {"slug": "n1", "stealth_endpoint": stealth_endpoint, "xray_security": "none",
                "regional_aliases": [], "stealth_transports": [{"port": 80, "security": "none"}]}
        Path(self.nodes).write_text(json.dumps({"nodes": [node]}))
        script = SOURCE[SOURCE.index(self.CANARY_HEADER) + len(self.CANARY_HEADER):]
        script = script[:script.index("\nEOF\n")]
        loop = script[script.index('nodes_json="$(curl'):script.index("\nrun_external_winn3_canary || true")]
        harness = "\n".join([
            "set -Eeuo pipefail",
            "failed=0",
            "log() { printf '%s\\n' \"$*\"; }",
            'fail() { failed=1; log "FAIL $*"; }',
            'ok() { log "OK $*"; }',
            "CURL_UA=fixture",
            "CANARY_MAX_BYTES=8388608",
            shell_function(script, "check_url"),
            shell_function(script, "endpoint_host"),
            shell_function(script, "health_url"),
            loop,
            'echo "failed=${failed}"',
        ])
        env = {"PATH": self.bin + os.pathsep + os.environ["PATH"], "LC_ALL": "C", "HOME": self.dir}
        done = subprocess.run([BASH, "--noprofile", "--norc", "-c", harness],
                              capture_output=True, text=True, env=env, timeout=60, stdin=subprocess.DEVNULL)
        calls = []
        if os.path.exists(self.calls):
            calls = [line.rstrip("\x1f").split("\x1f") for line in Path(self.calls).read_text().splitlines()]
        return done, calls

    def test_a_plain_host_is_fetched_with_globbing_off(self):
        done, calls = self.run_loop("n1.example.test:80")
        self.assertEqual(len(calls), 1, done.stdout + done.stderr)
        self.assertIn("-g", calls[0])
        self.assertEqual(calls[0][-1], "http://n1.example.test/healthz")

    def test_glob_query_and_userinfo_hosts_are_refused(self):
        for endpoint in ("10.255.[0-255].[1-254]:80", "127.0.0.1:9095?x#:80", "a@127.0.0.1:80",
                         "n{1,2,3}.example.test:80"):
            with self.subTest(endpoint=endpoint):
                if os.path.exists(self.calls):
                    os.unlink(self.calls)
                done, calls = self.run_loop(endpoint)
                self.assertEqual(calls, [], done.stdout + done.stderr)
                self.assertIn("FAIL node n1 transport invalid-host", done.stdout)
                self.assertIn("failed=1", done.stdout)


if __name__ == "__main__":
    unittest.main()
