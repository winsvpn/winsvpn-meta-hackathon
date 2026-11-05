#!/usr/bin/env python3
"""The hub's data-plane prober (wins_node_dataplane_probe.py), as SHIPPED.

The prober is extracted from the `cat > .../wins_node_dataplane_probe.py
<<'DPPROBEEOF'` heredoc inside wins_control_plane_setup_ONETOUCH.sh and exec'd.
Nothing here is a reimplementation, so a regression in the installer copy (the
copy every `--deploy` writes over the live one) fails these tests.

WHAT IS UNDER TEST

  L103  per-probe capture markers. The plaintext and TLS stealth probes both
        capture `tcpdump -c 1` on loopback:<awg port>. With one marker per run,
        a late plaintext datagram ended the TLS capture before the TLS probe
        sent anything, and a healthy TLS route was recorded as 'unreachable'
        (46 of 52 us-chicago1 TLS failures in 48 h). The capture channel is
        replaced by a local `sh -c` that prints what tcpdump would (L103's
        offline simulation, adapted to the installer copy): no node, no
        network, no ssh.

  green a probe_error pauses the healthy-proof streak instead of resetting it,
        while unreachable, a stale heartbeat or a closure still reset it.
        Exercised against a real SQLite file through the real apply_verdicts.

  IA-CP-11  every ssh the prober spawns gets a narrowed environment: the
        cloudflared Access service token and the basics, never the rest of
        the hub EnvironmentFile.

Run:  python3 server/test_hub_dataplane_probe_marker_green.py
      WINS_CP_INSTALLER=/path/to/installer python3 server/test_...py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLER = os.environ.get("WINS_CP_INSTALLER") or os.path.join(
    HERE, "wins_control_plane_setup_ONETOUCH.sh")
DP_INSTALLER = os.environ.get("WINS_DP_INSTALLER") or os.path.join(
    HERE, "wins_data_plane_setup_ONETOUCH.sh")
HEAD = "cat > /usr/local/lib/wins_node_dataplane_probe.py <<'DPPROBEEOF'\n"

NONCE = "a" * 32
OTHER = "b" * 32
HDR = "17:00:00.000000 IP 127.0.0.1.40000 > 127.0.0.1.9110: UDP, length 36"


def prober_source():
    with open(INSTALLER, encoding="utf-8") as fh:
        text = fh.read()
    start = text.index(HEAD) + len(HEAD)
    return text[start:text.index("\nDPPROBEEOF\n", start) + 1]


def load_prober():
    namespace = {"__name__": "wins_node_dataplane_probe_test"}
    exec(compile(prober_source(), "wins_node_dataplane_probe.py", "exec"), namespace)
    namespace["log"] = lambda _msg: None
    return namespace


def fake_tcpdump(lines, delay=0.3):
    body = "; ".join(f"printf '%s\\n' {line!r}" for line in lines)
    return ["sh", "-c", f"printf 'listening on lo, link-type EN10MB\\n'; sleep {delay}; {body}"]


def run_capture(probe, captured_lines):
    probe["node_ssh_command"] = lambda host, remote: fake_tcpdump(captured_lines)
    probe["CAPTURE_READY_TIMEOUT"] = 2
    probe["SEND_START_DELAY"] = 0.05
    return probe["_run_capture_probe"]("node", "udp", NONCE, lambda proc, hit: 1, interface="lo")


STEALTH_ROW = {
    "xray_path": "/p", "xray_uuid": "00000000-0000-4000-8000-000000000000",
    "wg_port": 9110, "endpoint": "h.example.test:9110",
    "stealth_endpoint": "h.example.test:80", "xray_security": "none",
    "stealth_transports": '[{"security":"none","port":80},{"security":"tls","port":443}]',
}


def captured_bpfs(probe):
    """BPF of the UDP, plaintext stealth and TLS stealth captures of one run."""
    bpfs = []

    def fake(ssh, bpf, nonce, sender, interface="any"):
        bpfs.append(bpf)
        return "unreachable", "x"

    probe["_run_capture_probe"] = fake
    probe["probe_udp"]("node", "198.51.100.7", 9110)
    probe["probe_stealth"]("node", STEALTH_ROW, "none")
    probe["probe_stealth"]("node", STEALTH_ROW, "tls")
    return bpfs


def marker_of(bpf):
    return re.search(r"udp\[8:4\] = 0x([0-9a-f]{8})", bpf).group(1)


class CaptureMarkerTests(unittest.TestCase):
    """L103: per-probe markers, and a consumed capture is not a verdict."""

    def test_a_capture_consumed_by_another_probes_datagram_is_probe_error(self):
        probe = load_prober()
        verdict, detail = run_capture(probe, [
            HDR, "E..@..@.JN4I" + OTHER, "1 packet captured", "1 packet received by filter"])
        self.assertEqual(verdict, "probe_error", detail)
        self.assertIn("consumed", detail)

    def test_the_probes_own_nonce_is_still_reachable(self):
        probe = load_prober()
        verdict, _ = run_capture(probe, [HDR, "E..@..@.JN4I" + NONCE, "1 packet captured"])
        self.assertEqual(verdict, "reachable")

    def test_an_expired_window_with_nothing_captured_is_still_unreachable(self):
        probe = load_prober()
        verdict, _ = run_capture(probe, ["0 packets captured", "0 packets received by filter"])
        self.assertEqual(verdict, "unreachable")

    def test_a_capture_that_never_started_is_probe_error(self):
        probe = load_prober()
        probe["node_ssh_command"] = lambda host, remote: ["sh", "-c", "echo 'ssh: connect refused'"]
        probe["CAPTURE_READY_TIMEOUT"] = 1
        verdict, _ = probe["_run_capture_probe"]("node", "udp", NONCE, lambda p, h: 1)
        self.assertEqual(verdict, "probe_error")

    def test_plaintext_and_tls_captures_never_share_a_marker(self):
        # Many draws: a shared per-run marker is equal every time; independent
        # per-probe markers collide with probability 62**-4 per pair.
        for _ in range(20):
            bpfs = captured_bpfs(load_prober())
            self.assertEqual(len(bpfs), 3)
            udp, plain, tls = (marker_of(b) for b in bpfs)
            self.assertNotEqual(plain, tls, "plaintext and TLS stealth captures share a marker")
            self.assertNotEqual(udp, plain)

    def test_repeated_probes_in_one_process_draw_fresh_markers(self):
        probe = load_prober()
        seen = set()
        for _ in range(10):
            seen.update(marker_of(b) for b in captured_bpfs(probe))
        self.assertGreater(len(seen), 25, "markers are not drawn per probe")

    def test_every_marker_is_four_alphanumeric_ascii_bytes(self):
        probe = load_prober()
        for bpf in captured_bpfs(probe) * 5:
            raw = bytes.fromhex(marker_of(bpf))
            self.assertEqual(len(raw), 4)
            self.assertRegex(raw.decode("ascii"), r"^[A-Za-z0-9]{4}$")

    def test_the_datagram_carries_the_same_marker_its_capture_filters_on(self):
        probe = load_prober()
        sent = {}

        def fake(ssh, bpf, nonce, sender, interface="any"):
            class Sock:
                def __init__(self, *a, **k):
                    pass

                def settimeout(self, _):
                    pass

                def sendto(self, payload, _addr):
                    sent.setdefault("payload", payload)

                def close(self):
                    pass

            class Hit:
                def is_set(self):
                    return bool(sent)

            class Proc:
                def poll(self):
                    return None

            real_socket = probe["socket"].socket
            probe["socket"].socket = Sock
            try:
                sender(Proc(), Hit())
            finally:
                probe["socket"].socket = real_socket
            sent["bpf"] = bpf
            sent["nonce"] = nonce
            return "reachable", "x"

        probe["_run_capture_probe"] = fake
        probe["SEND_INTERVAL"] = 0
        probe["probe_udp"]("node", "198.51.100.7", 9110)
        self.assertEqual(sent["payload"][:4].hex(), marker_of(sent["bpf"]))
        self.assertEqual(sent["payload"][4:].decode(), sent["nonce"])


class ProbeSshEnvironmentTests(unittest.TestCase):
    """IA-CP-11: the prober's ssh children get a narrowed environment."""

    def test_capture_ssh_gets_only_the_access_token_and_basics(self):
        probe = load_prober()
        seen = {}
        real_popen = subprocess.Popen

        def spy(args, **kwargs):
            seen["env"] = kwargs.get("env")
            return real_popen(["sh", "-c", "echo 'listening on lo'; echo '0 packets captured'"],
                              stdout=kwargs.get("stdout"), stderr=kwargs.get("stderr"),
                              text=kwargs.get("text"))

        saved = dict(os.environ)
        os.environ.update({
            "ADMIN_TOKEN": "admin-secret-value", "SMTP_PASS": "smtp-secret-value",
            "REDEMPTION_KEYS": "v1:" + "c" * 64,
            "TUNNEL_SERVICE_TOKEN_ID": "abc.access", "TUNNEL_SERVICE_TOKEN_SECRET": "s" * 40,
        })
        probe["subprocess"].Popen = spy
        probe["CAPTURE_READY_TIMEOUT"] = 1
        probe["SEND_START_DELAY"] = 0
        try:
            probe["_run_capture_probe"]("node", "udp", NONCE, lambda p, h: 0)
        finally:
            probe["subprocess"].Popen = real_popen
            os.environ.clear()
            os.environ.update(saved)
        env = seen["env"]
        self.assertIsNotNone(env, "ssh inherited the whole hub environment")
        for leaked in ("ADMIN_TOKEN", "SMTP_PASS", "REDEMPTION_KEYS"):
            self.assertNotIn(leaked, env)
        self.assertEqual(env["TUNNEL_SERVICE_TOKEN_ID"], "abc.access")
        self.assertEqual(env["TUNNEL_SERVICE_TOKEN_SECRET"], "s" * 40)
        self.assertIn("PATH", env)

    def test_the_self_test_injection_ssh_is_narrowed_too(self):
        probe = load_prober()
        seen = {}

        def fake_run(args, **kwargs):
            seen["env"] = kwargs.get("env")
            return subprocess.CompletedProcess(args, 0, "", "")

        def fake_capture(ssh, bpf, nonce, sender, interface="any"):
            sender(type("P", (), {"poll": lambda self: None})(),
                   type("H", (), {"is_set": lambda self: False})())
            return "reachable", "x"

        saved = dict(os.environ)
        os.environ["ADMIN_TOKEN"] = "admin-secret-value"
        real_run = subprocess.run
        probe["subprocess"].run = fake_run
        probe["_run_capture_probe"] = fake_capture
        try:
            probe["probe_udp"]("node", "198.51.100.7", 9110, inject_from_node=True)
        finally:
            probe["subprocess"].run = real_run
            os.environ.clear()
            os.environ.update(saved)
        self.assertIsNotNone(seen.get("env"))
        self.assertNotIn("ADMIN_TOKEN", seen["env"])


def iso(dt):
    return dt.replace(tzinfo=None).isoformat()


class GreenStreakTests(unittest.TestCase):
    """probe_error pauses the green streak; real failures still reset it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dpprobe-green-")
        self.db = os.path.join(self.tmp, "vpn_users.db")
        self.probe = load_prober()
        self.probe["DB_PATH"] = self.db
        conn = self.connect()
        conn.execute("CREATE TABLE nodes (slug TEXT PRIMARY KEY, operator_enabled INTEGER,"
                     " status TEXT, last_heartbeat TEXT, endpoint TEXT, wg_port INTEGER,"
                     " ssh_host TEXT)")
        conn.execute("CREATE TABLE double_vpn_assignments (exit_slug TEXT, status TEXT,"
                     " applied_revision TEXT, runtime_validated_at TEXT, updated_at TEXT)")
        self.probe["ensure_columns"](conn)
        conn.execute("INSERT INTO nodes (slug, operator_enabled, status, last_heartbeat)"
                     " VALUES ('lab-alpha', 1, 'online', ?)", (iso(datetime.now(timezone.utc)),))
        conn.commit()
        conn.close()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self):
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        return conn

    def row(self):
        with self.connect() as conn:
            return dict(conn.execute("SELECT * FROM nodes WHERE slug='lab-alpha'").fetchone())

    def set(self, **cols):
        with self.connect() as conn:
            for k, v in cols.items():
                conn.execute(f"UPDATE nodes SET {k}=? WHERE slug='lab-alpha'", (v,))

    def run_once(self, udp, stealth="unconfigured", tls="unconfigured"):
        conn = self.connect()
        try:
            return self.probe["apply_verdicts"](
                conn, "lab-alpha", (udp, "d"), (stealth, "d"), (tls, "d"))
        finally:
            conn.close()

    def green_run(self):
        return self.run_once("reachable", "reachable", "reachable")

    def test_consecutive_greens_still_count_up_from_the_first(self):
        self.green_run()
        first_since = self.row()["data_plane_green_since"]
        self.green_run()
        self.green_run()
        self.assertEqual(self.row()["data_plane_green_streak"], 3)
        self.assertEqual(self.row()["data_plane_green_since"], first_since)

    def test_the_chicago_case_a_tls_probe_error_pauses_the_streak(self):
        for _ in range(3):
            self.green_run()
        before = self.row()
        result = self.run_once("reachable", "reachable", "probe_error")
        after = self.row()
        self.assertEqual(result["green_streak"], 3)
        self.assertEqual(after["data_plane_green_streak"], 3)
        self.assertEqual(after["data_plane_green_since"], before["data_plane_green_since"])

    def test_an_all_probe_error_run_below_the_close_streak_pauses(self):
        for _ in range(2):
            self.green_run()
        result = self.run_once("probe_error", "probe_error", "probe_error")
        self.assertEqual(result["aggregate"], "probe_error")
        self.assertFalse(result["promotion_consumed"])
        self.assertEqual(self.row()["data_plane_green_streak"], 2)

    def test_a_paused_run_is_not_counted_and_the_streak_resumes(self):
        for verdicts in (("reachable",) * 3, ("reachable", "reachable", "probe_error"),
                         ("reachable",) * 3, ("reachable",) * 3, ("reachable",) * 3):
            self.run_once(*verdicts)
        self.assertEqual(self.row()["data_plane_green_streak"], 4)

    def test_five_greens_around_a_probe_error_reach_the_reopen_count(self):
        # NODE_AUTO_REOPEN_PROOFS = 5 on the hub. Before this change one
        # tooling failure anywhere in the window restarted the clock.
        first_since = None
        for index, verdicts in enumerate((("reachable",) * 3,) * 2
                                         + (("probe_error",) * 3,)
                                         + (("reachable",) * 3,) * 3):
            self.run_once(*verdicts)
            if index == 0:
                first_since = self.row()["data_plane_green_since"]
        self.assertEqual(self.row()["data_plane_green_streak"], 5)
        self.assertEqual(self.row()["data_plane_green_since"], first_since)

    def test_unreachable_still_resets(self):
        for _ in range(3):
            self.green_run()
        self.run_once("reachable", "reachable", "unreachable")
        self.assertEqual(self.row()["data_plane_green_streak"], 0)
        self.assertIsNone(self.row()["data_plane_green_since"])

    def test_an_unreachable_beside_a_probe_error_still_resets(self):
        # A probe_error must not shield a transport that WAS measured and failed.
        for _ in range(3):
            self.green_run()
        self.run_once("reachable", "unreachable", "probe_error")
        self.assertEqual(self.row()["data_plane_green_streak"], 0)
        self.assertIsNone(self.row()["data_plane_green_since"])

    def test_a_probe_error_with_a_stale_heartbeat_resets(self):
        for _ in range(3):
            self.green_run()
        self.set(last_heartbeat=iso(datetime.now(timezone.utc) - timedelta(hours=2)))
        self.run_once("reachable", "reachable", "probe_error")
        self.assertEqual(self.row()["data_plane_green_streak"], 0)
        self.assertIsNone(self.row()["data_plane_green_since"])

    def test_a_probe_error_with_an_offline_heartbeat_resets(self):
        for _ in range(3):
            self.green_run()
        self.set(status="offline")
        self.run_once("probe_error", "probe_error", "probe_error")
        self.assertEqual(self.row()["data_plane_green_streak"], 0)

    def test_a_probe_error_run_that_closes_the_node_resets(self):
        for _ in range(3):
            self.green_run()
        self.set(data_plane_status="probe_error",
                 data_plane_probe_error_streak=self.probe["PROBE_ERROR_CLOSE_STREAK"] - 1)
        result = self.run_once("probe_error", "probe_error", "probe_error")
        self.assertEqual(result["close_reason"], "probe_error_streak")
        self.assertTrue(result["promotion_consumed"])
        self.assertEqual(self.row()["data_plane_green_streak"], 0)
        self.assertIsNone(self.row()["data_plane_green_since"])

    def test_a_probe_error_with_no_streak_leaves_it_at_zero(self):
        self.run_once("reachable", "reachable", "probe_error")
        self.assertEqual(self.row()["data_plane_green_streak"], 0)
        self.assertIsNone(self.row()["data_plane_green_since"])

    def test_end_to_end_a_consumed_tls_capture_does_not_break_the_streak(self):
        # The whole L103 chain: the TLS capture is ended by a stale plaintext
        # datagram, the prober reports probe_error for TLS (not unreachable),
        # and the green streak survives the run.
        for _ in range(3):
            self.green_run()
        tls = run_capture(self.probe, [HDR, "E..@..@.JN4I" + OTHER, "1 packet captured"])
        self.assertEqual(tls[0], "probe_error")
        conn = self.connect()
        try:
            self.probe["apply_verdicts"](conn, "lab-alpha", ("reachable", "d"),
                                         ("reachable", "d"), tls)
        finally:
            conn.close()
        self.assertEqual(self.row()["data_plane_green_streak"], 3)
        self.assertEqual(self.row()["data_plane_stealth_tls_fail_streak"], 0)


class NodeCaptureToolTests(unittest.TestCase):
    """The capture runs ON THE NODE over ssh, and a fresh data plane has only
    what the data-plane installer's apt_install put there. Without tcpdump every
    probe is probe_error and the node can never go live (every fresh node,
    2026-10-19)."""

    @staticmethod
    def required_packages():
        with open(DP_INSTALLER, encoding="utf-8") as fh:
            text = fh.read()
        body = re.search(r"^apt_install\(\) \{\n.*?^\}\n", text, re.S | re.M).group(0)
        lines = body.splitlines()
        start = next(i for i, line in enumerate(lines)
                     if line.strip().startswith('apt_retry "${APT_GET[@]}" install -y'))
        joined = ""
        for line in lines[start:]:
            joined += line.rstrip("\\").strip() + " "
            if not line.rstrip().endswith("\\"):
                break
        return joined.split()[len('apt_retry "${APT_GET[@]}" install -y'.split()):]

    def test_the_prober_runs_tcpdump_on_the_node(self):
        remotes = []
        probe = load_prober()
        probe["node_ssh_command"] = lambda host, remote: (remotes.append(remote), fake_tcpdump([]))[1]
        probe["CAPTURE_READY_TIMEOUT"] = 1
        probe["SEND_START_DELAY"] = 0.01
        probe["_run_capture_probe"]("node", "udp", NONCE, lambda proc, hit: 1, interface="lo")
        self.assertEqual(len(remotes), 1, remotes)
        self.assertRegex(remotes[0], r"^timeout \d+ tcpdump ")

    def test_the_data_plane_installer_installs_tcpdump(self):
        packages = self.required_packages()
        self.assertIn("iperf3", packages, "the package list was not parsed")
        self.assertIn("tcpdump", packages)
        self.assertEqual(packages.count("tcpdump"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
