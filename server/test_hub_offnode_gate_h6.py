#!/usr/bin/env python3
"""Slice H6 (design 2.9 evaluator rule, 3.16, ruling D.ii): the hub-run off-node gate.

Every test runs the REAL source extracted from the ONETOUCH control-plane
installer: the hub app (main.py heredoc) against temporary SQLite files, and the
node-side check (`testdata/wins_offnode_check_l46_v5_canary.sh`, the L46 v5
script with the one canary exemption, SHA-256 b8e22716...9c95) under bash with a
fake `docker`. Nothing contacts a node, a hub or the network. Every key here is
a throwaway drawn from os.urandom.

Covered:
  * the hub evaluator's one AWGSYSPEER rule (2.9): at most one line, and only
    when both digests equal the ones the hub computes from its own canary key
    and 10.8.255.1/32; every other AWGSYSPEER line is an "unexpected system
    peer"; a Core exit peer, any other key at .1 and a canary key with a broader
    or additional address stay AWGPEER and fail (5.5 "Off-node and AWG canary");
  * the node script and the evaluator end to end, with a fake `docker`;
  * the one remote command: it copies the installed check to a private
    directory, verifies the pinned digest on the copy and runs that copy, always
    with --canary-pubkey (3.16 step 1);
  * hub_offnode_check_run, hub_offnode_gate_record, hub_offnode_gate_attempt and
    installer_rerun_hub_offnode_gate: the record is source='hub', carries the
    canonical gate digest and snapshot digest exactly as POST
    /admin/nodes/offnode-gate computes them (3.16 steps 3 and 4), and is usable
    only for a node closed as installer_rerun or fresh_install, never by manual
    promotion or retirement;
  * the reopen sweep: the builder runs only when every other condition passes,
    no unused record exists and the window is open; a failed check holds the
    node with its reasons and raises the existing notice (5.1 step 8, 5.3 "the
    off-node gate is failed independently");
  * the node-side pin and the hub pin are one value.

Mutants (5.6 "Off-node exemption", plus the H6 ones) are applied to the
extracted source and each must be KILLED.

Run:  python3 server/test_hub_offnode_gate_h6.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import base64
import contextlib
import hashlib
import io
import json
import logging
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import closing, contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_data_plane_dark_start_latch as dark
import test_installer_sync_hub_fx2 as fx2

HERE = Path(__file__).resolve().parent
HUB_INSTALLER = HERE / "wins_control_plane_setup_ONETOUCH.sh"
DATA_INSTALLER = HERE / "wins_data_plane_setup_ONETOUCH.sh"
CHECK_SCRIPT = HERE / "testdata" / "wins_offnode_check_l46_v5_canary.sh"
BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash")
for _candidate in (os.path.expanduser("~/.homebrew/Homebrew/bin/bash"), "/opt/homebrew/bin/bash"):
    if os.path.exists(_candidate):
        BASH = _candidate
        break


def throwaway_key():
    return base64.b64encode(os.urandom(32)).decode()


CANARY = throwaway_key()
OTHER = throwaway_key()
CORE_KEY = throwaway_key()
EXACT = "10.8.255.1/32"
CORE_EXIT = "10.8.255.2/32"
GATE_NOTICE = "data-plane node waits on off-node gate"
CLEAN_GW = ("GW unit=inactive pid_known=0 forward=0 registry_flag_matches=0 gateway_can_read=unknown "
            "started_after_file=unknown reload_failed_since_file=unknown")


def d16(text):
    """The node script's d16(): the first 16 hex characters of the SHA-256."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def sys_peer_line(key=CANARY, ips=EXACT, hs="never", tag="canary"):
    return f"AWGSYSPEER {d16(key)} {tag} {d16(ips)} {hs}"


def awg_peer_line(key, ips, klass="core_exit", hs="never"):
    return f"AWGPEER {d16(key)} {klass} {d16(ips)} {hs}"


def report(peer_lines=(), winn3=False):
    """The report of a clean closed node, with the given AWG peer lines."""
    peers = list(peer_lines)
    lines = peers + [f"AWG_READ ok iface=awg0 peers={len(peers)}", "V3_FILE absent", CLEAN_GW]
    return "\n".join(lines) + "\n"


EMPTY_SNAPSHOT_SHA = hashlib.sha256(
    json.dumps({"version": 1, "peers": []}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# The bytes of a closed node's registry (the hub hashes exactly these into EMPTY_SNAPSHOT_SHA)
# and of one that carries a customer.
CLOSED_REGISTRY = json.dumps({"version": 1, "peers": []}, sort_keys=True, separators=(",", ":"))
CUSTOMER_REGISTRY = json.dumps({"version": 1, "peers": [{"key": "customer"}]}, sort_keys=True, separators=(",", ":"))


def canonical_gate_digest(slug, expected, confirmed_at, external, report_sha):
    """Computed here, independently of the hub (the bytes offnode_compare.py uses)."""
    return hashlib.sha256(("\n".join([
        "l46-offnode-gate-v3", f"slug={slug}", f"expected_v3_sha256={expected}",
        f"cleanup_confirmed_at={confirmed_at}", f"external_evidence_sha256={external}",
        f"node_report_sha256={report_sha}",
    ]) + "\n").encode()).hexdigest()


def quiet(mod):
    for handler in list(mod.logger.handlers):
        handler.close()
        mod.logger.removeHandler(handler)
    mod.logger.addHandler(logging.NullHandler())
    mod.logger.propagate = False


def hub_source():
    return HUB_INSTALLER.read_text(encoding="utf-8")


def load_hub(source=None):
    """The real hub, optionally from mutated source."""
    original = harness._extract_main_block
    if source is not None:
        def extract():
            lines = source.split("\n")
            for i, line in enumerate(lines):
                if re.search(r"<<'PYEOF'", line) and "main.py" in line:
                    j = i + 1
                    while lines[j] != "PYEOF":
                        j += 1
                    return "\n".join(lines[i + 1:j]) + "\n"
            raise RuntimeError("main.py heredoc not found")
        harness._extract_main_block = extract
    try:
        mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0")
    finally:
        harness._extract_main_block = original
    quiet(mod)
    mod.AWG_CANARY_PUBLIC_KEY = CANARY
    return mod


class HubCase(unittest.TestCase):
    """A fresh hub per test. SOURCE is set on a subclass to run a mutant."""
    SOURCE = None

    def setUp(self):
        self.mod = load_hub(self.SOURCE)
        self.addCleanup(shutil.rmtree, self.mod._TMPDIR, ignore_errors=True)
        # The database is first opened by the hub's own get_db, so it is in WAL
        # mode as on a hub. The snapshot digest reads the canary bindings (H3)
        # on a second get_db connection while the caller holds BEGIN IMMEDIATE;
        # on a rollback-journal file that read cannot take its lock.
        with self.mod.get_db():
            pass
        self.alerts = []
        self.mod.security_alert = lambda *a, **k: self.alerts.append((a[0], a[1], k.get("details")))

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.mod._DB)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def node(self, slug):
        with self.db() as conn:
            return conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()

    def gates(self, slug):
        with self.db() as conn:
            return conn.execute("SELECT * FROM node_offnode_gates WHERE slug = ?", (slug,)).fetchall()


_SEQ = [0]


class ClosedNodeCase(HubCase):
    def closed_node(self, reason="installer_rerun", cleanup="confirmed", **overrides):
        """A closed winn/1 node with a confirmed closure cleanup, straight in the
        database (the live fleet shape; the sweep scenarios use the real flows)."""
        _SEQ[0] += 1
        slug = f"lab-node-{_SEQ[0]}"
        now = self.mod.utcnow()
        row = {
            "slug": slug, "name": "Lab", "status": "online", "management_status": "ok",
            "operator_enabled": 0, "ssh_host": f"192.0.2.{10 + _SEQ[0]}",
            "endpoint": f"192.0.2.{10 + _SEQ[0]}:9110", "wg_port": 9110,
            "public_key": throwaway_key(), "direct_awg_enabled": 1,
            "health_closed_at": (now - timedelta(minutes=30)).isoformat(),
            "health_closed_reason": reason,
            "deployment_completed_at": (now - timedelta(minutes=20)).isoformat(),
        }
        row.update(overrides)
        with self.db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute(f"INSERT INTO nodes ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                         tuple(row.values()))
            if cleanup:
                conn.execute(
                    "INSERT INTO node_closure_cleanup (slug, state, awg_pending, v3_published, v3_required,"
                    " detail, updated_at, confirmed_at) VALUES (?, ?, 0, 0, 0, '', ?, ?)",
                    (slug, cleanup, now.isoformat(), (now - timedelta(minutes=10)).isoformat()))
        return slug

    def confirmed_at(self, slug):
        with self.db() as conn:
            return conn.execute("SELECT confirmed_at FROM node_closure_cleanup WHERE slug = ?",
                                (slug,)).fetchone()[0]

    def attempt(self, slug, check, now=None):
        """hub_offnode_gate_attempt the way the sweep calls it: inside the
        caller's BEGIN IMMEDIATE transaction on its own connection."""
        with patch.object(self.mod, "hub_offnode_check_run", side_effect=check):
            with self.mod.get_db() as conn:
                conn.commit()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()
                return self.mod.hub_offnode_gate_attempt(conn, row)

    def other_writer_can_write(self):
        """True when another connection can take the write lock right now."""
        other = sqlite3.connect(self.mod._DB, timeout=0.2)
        try:
            other.execute("BEGIN IMMEDIATE")
            other.rollback()
            return True
        except sqlite3.OperationalError:
            return False
        finally:
            other.close()


# ===================================================== the node script ======

def run_node_check(peers, arguments=(), script=CHECK_SCRIPT, exit_code=0):
    """The real node-side check under bash with a fake docker. peers is a list
    of (public key, allowed-ips string with spaces between addresses)."""
    root = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
    bin_dir = root / "bin"
    bin_dir.mkdir()
    (root / "peers").write_text("".join(f"{key}\n" for key, _ in peers))
    (root / "allowed").write_text("".join(f"{key}\t{ips}\n" for key, ips in peers))
    (root / "handshakes").write_text("".join(f"{key}\t0\n" for key, _ in peers))
    stubs = {
        "docker": ('#!/bin/bash\ncase "$1 $2" in\n"ps --format") echo awg ;;\n'
                   '"exec awg") case "$6" in peers) cat "$ROOT/peers" ;; allowed-ips) cat "$ROOT/allowed" ;; '
                   'latest-handshakes) cat "$ROOT/handshakes" ;; esac ;;\nesac\n'),
        "systemctl": "#!/bin/bash\nexit 0\n",
        "journalctl": "#!/bin/bash\nexit 0\n",
    }
    try:
        for name, body in stubs.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        copy = root / "wins-offnode-check"
        copy.write_text(Path(script).read_text())
        environment = dict(os.environ, ROOT=str(root), PATH=f"{bin_dir}:{os.environ['PATH']}")
        result = subprocess.run([BASH, str(copy), "--registry", str(root / "missing.json"), *arguments],
                                env=environment, capture_output=True, text=True, timeout=60)
        return result
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ============================================================ evaluator ====

def evaluator_checks(mod):
    """The AWGSYSPEER rule (design 2.9). Raises AssertionError on the first
    violated fact; the mutant tests run exactly this against mutated source."""
    fails = lambda text, protocol="winn/1": mod.offnode_node_report_failures(text, protocol, EMPTY_SNAPSHOT_SHA)
    good = report([sys_peer_line()])
    assert fails(good) == [], ("the exact canary system peer is exempt", fails(good))
    assert fails(report()) == [], "a node with no peer at all passes"
    # Anti-vacuity: the same fixture without the rule fails on any AWGPEER.
    assert fails(report([awg_peer_line(CANARY, EXACT, "core_exit")])) != [], "an AWGPEER line fails"

    def unexpected(text, what):
        got = fails(text)
        assert any(f.startswith("unexpected system peer") for f in got), (what, got)

    unexpected(report([sys_peer_line(key=OTHER)]), "another key's digest")
    unexpected(report([sys_peer_line(ips="10.8.255.0/24")]), "the whole /24")
    unexpected(report([sys_peer_line(ips="10.8.255.1/32,10.8.255.2/32")]), "an additional address")
    unexpected(report([sys_peer_line(ips=CORE_EXIT)]), "a Core exit address")
    unexpected(report([sys_peer_line(tag="core_exit")]), "a different tag")
    unexpected(report([sys_peer_line(hs="whenever")]), "an unknown handshake class")
    unexpected(report([f"AWGSYSPEER {d16(CANARY)} canary {d16(EXACT)}"]), "a short line")
    unexpected(report([sys_peer_line() + " extra"]), "a long line")
    unexpected(report([sys_peer_line(), sys_peer_line()]), "the same line twice")
    unexpected(report([sys_peer_line(), sys_peer_line(key=OTHER)]), "a second, different line")
    for hs in ("never", "lt3m", "lt1h", "lt1d", "older"):
        assert fails(report([sys_peer_line(hs=hs)])) == [], ("every handshake class is accepted", hs)
    # The exempt peer never hides a real one.
    core = fails(report([sys_peer_line(), awg_peer_line(CORE_KEY, CORE_EXIT)]))
    assert any("1 AWG peer(s) present" in f for f in core), core
    assert not any("unexpected system peer" in f for f in core), core
    other_at_one = fails(report([awg_peer_line(OTHER, EXACT, "core_exit")]))
    assert any("AWG peer(s) present" in f for f in other_at_one), other_at_one
    # The expectation comes from the hub's own canary key, never from the report.
    saved = mod.AWG_CANARY_PUBLIC_KEY
    try:
        mod.AWG_CANARY_PUBLIC_KEY = ""
        unexpected(good, "no canary key configured here")
        unexpected(report([sys_peer_line(key="")]), "the digest of an empty key when none is configured")
        mod.AWG_CANARY_PUBLIC_KEY = OTHER
        unexpected(good, "a different hub canary key")
    finally:
        mod.AWG_CANARY_PUBLIC_KEY = saved
    # The same rule gates a winn/3 report and the stored-record re-evaluation.
    assert fails(good, "winn/3") != [], "winn/3 still needs its registry facts"
    assert not any("system peer" in f for f in fails(good, "winn/3"))


class EvaluatorTests(HubCase):
    def test_the_awgsyspeer_rule(self):
        evaluator_checks(self.mod)

    def test_the_rule_is_the_only_exemption_in_the_evaluator(self):
        source = hub_source()
        body = source.split("def offnode_node_report_failures(", 1)[1].split("\ndef verify_offnode_gate_for_use", 1)[0]
        self.assertEqual(body.count("AWGSYSPEER"), 0, "the evaluator body only calls the rule function")
        self.assertIn("offnode_system_peer_failures(rows)", body)
        self.assertIn('peers = [r for r in rows if r[0] == "AWGPEER"]', body)
        rule = source.split("def offnode_system_peer_failures(", 1)[1].split("\ndef offnode_node_report_failures", 1)[0]
        self.assertIn("AWG_CANARY_ALLOWED_IPS", rule)
        self.assertNotIn("10.8.255.0", rule, "no /24 anywhere in the rule")

    def test_the_allowed_ips_the_rule_expects_is_exactly_the_canary_address(self):
        self.assertEqual(self.mod.AWG_CANARY_ALLOWED_IPS, EXACT)


class NodeScriptEndToEndTests(HubCase):
    """5.5 "Off-node and AWG canary", through the real node script."""

    def verdict(self, peers, arguments):
        result = run_node_check(peers, arguments)
        lines = [line for line in result.stdout.splitlines() if line.startswith("AWG")]
        return lines, result, self.mod.offnode_node_report_failures(result.stdout, "winn/1", EMPTY_SNAPSHOT_SHA)

    def test_the_exact_canary_is_exempt(self):
        lines, result, failures = self.verdict([(CANARY, EXACT)], ("--canary-pubkey", CANARY))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(lines[0].startswith("AWGSYSPEER ") and " canary " in lines[0], lines)
        self.assertEqual(failures, [])

    def test_a_leftover_core_exit_peer_is_reported_and_fails_the_gate(self):
        lines, _, failures = self.verdict([(CORE_KEY, CORE_EXIT)], ("--canary-pubkey", CANARY))
        self.assertTrue(lines[0].startswith("AWGPEER ") and " core_exit " in lines[0], lines)
        self.assertTrue(any("1 AWG peer(s) present" in f for f in failures), failures)

    def test_an_unexpected_key_at_dot_one_fails(self):
        lines, _, failures = self.verdict([(OTHER, EXACT)], ("--canary-pubkey", CANARY))
        self.assertTrue(lines[0].startswith("AWGPEER "), lines)
        self.assertTrue(any("AWG peer(s) present" in f for f in failures), failures)

    def test_the_canary_key_with_a_broader_or_additional_address_fails(self):
        for ips in ("10.8.255.1/32 10.8.255.2/32", "10.8.255.0/24", CORE_EXIT):
            with self.subTest(ips=ips):
                lines, _, failures = self.verdict([(CANARY, ips)], ("--canary-pubkey", CANARY))
                self.assertTrue(lines[0].startswith("AWGPEER "), lines)
                self.assertTrue(any("AWG peer(s) present" in f for f in failures), failures)

    def test_without_the_argument_the_canary_is_counted(self):
        lines, _, failures = self.verdict([(CANARY, EXACT)], ())
        self.assertTrue(lines[0].startswith("AWGPEER "), lines)
        self.assertTrue(any("1 AWG peer(s) present" in f for f in failures), failures)

    def test_the_exact_canary_beside_a_core_exit_peer_fails_for_the_core_exit_only(self):
        lines, _, failures = self.verdict([(CANARY, EXACT), (CORE_KEY, CORE_EXIT)], ("--canary-pubkey", CANARY))
        self.assertEqual(sorted(line.split()[0] for line in lines if not line.startswith("AWG_READ")),
                         ["AWGPEER", "AWGSYSPEER"])
        self.assertTrue(any("1 AWG peer(s) present" in f for f in failures), failures)
        self.assertFalse(any("unexpected system peer" in f for f in failures), failures)

    def test_the_hub_and_the_node_agree_on_the_digest_of_the_key(self):
        """The hub computes d16 over its own key; the script over the key it saw."""
        lines, _, _ = self.verdict([(CANARY, EXACT)], ("--canary-pubkey", CANARY))
        self.assertEqual(lines[0], sys_peer_line(hs=lines[0].split()[-1]))


# =================================================== the remote command =====

class RemoteCommandTests(HubCase):
    """3.16 step 1: wins-offnode-check --canary-pubkey <hub canary key> over node_ssh_command."""

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, body in {
            "docker": ('#!/bin/bash\ncase "$1 $2" in\n"ps --format") echo awg ;;\n'
                       '"exec awg") case "$6" in peers) cat "$ROOT/peers" ;; allowed-ips) cat "$ROOT/allowed" ;; '
                       'latest-handshakes) cat "$ROOT/handshakes" ;; esac ;;\nesac\n'),
            "systemctl": "#!/bin/bash\nexit 0\n", "journalctl": "#!/bin/bash\nexit 0\n",
        }.items():
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        (self.bin / "bash").symlink_to(BASH)
        (self.root / "peers").write_text(f"{CANARY}\n")
        (self.root / "allowed").write_text(f"{CANARY}\t{EXACT}\n")
        (self.root / "handshakes").write_text(f"{CANARY}\t0\n")
        self.workdir = self.root / "run"
        self.workdir.mkdir()
        self.installed = self.root / "installed-check"
        self.installed.write_text(CHECK_SCRIPT.read_text())
        self.marker = self.root / "marker"

    def execute(self, command=None, path=None, workdir=None, environment=None):
        with patch.object(self.mod, "HUB_OFFNODE_CHECK_PATH", str(path or self.installed)), \
                patch.object(self.mod, "HUB_OFFNODE_CHECK_WORKDIR", str(workdir or self.workdir)):
            text = command or self.mod.hub_offnode_check_remote_command(CANARY)
        env = dict(os.environ, ROOT=str(self.root), MARKER=str(self.marker),
                   PATH=f"{self.bin}:{os.environ['PATH']}")
        env.update(environment or {})
        return subprocess.run(["/bin/sh", "-c", text], env=env, capture_output=True, text=True, timeout=60)

    def test_the_pinned_script_runs_and_reports_the_exempt_canary(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(line.startswith("AWGSYSPEER ") for line in result.stdout.splitlines()), result.stdout)
        self.assertEqual(self.mod.offnode_node_report_failures(result.stdout, "winn/1", EMPTY_SNAPSHOT_SHA), [])

    def test_the_canary_key_is_always_passed(self):
        command = self.mod.hub_offnode_check_remote_command(CANARY)
        self.assertIn(f"--canary-pubkey {CANARY}", command)
        # And it is what the script acted on: without it the canary would be an AWGPEER.
        result = self.execute()
        self.assertFalse(any(line.startswith("AWGPEER ") for line in result.stdout.splitlines()), result.stdout)

    def test_only_a_32_byte_base64_key_reaches_the_remote_shell(self):
        for bad in ("", "x", "A" * 43, "A" * 44, CANARY + "; id", "$(id)" + CANARY[5:], CANARY[:-1] + "\n",
                    CANARY[:-1] + "'", "A" * 42 + "==", None, "A" * 43 + "= ", "A" * 43 + "=\n"):
            with self.subTest(key=bad), self.assertRaises(ValueError):
                self.mod.hub_offnode_check_remote_command(bad)

    def test_the_digest_is_checked_on_the_copy_and_a_changed_file_never_runs(self):
        self.installed.write_text(CHECK_SCRIPT.read_text().replace(
            "#!/usr/bin/env bash\n", '#!/usr/bin/env bash\ntouch "$MARKER"\n', 1))
        result = self.execute()
        self.assertEqual(result.returncode, self.mod.HUB_OFFNODE_CHECK_EXIT_DIGEST, result.stderr)
        self.assertFalse(self.marker.exists(), "a file that differs from the pin must not run")
        self.assertEqual(result.stdout, "")

    def test_the_bytes_that_were_verified_are_the_bytes_that_run(self):
        """The installed file is swapped right after the copy (a race the digest
        alone would not close): the verified copy still runs, the swap never does."""
        cp = self.bin / "cp"
        cp.write_text('#!/bin/bash\n/bin/cp "$@" || exit $?\n'
                      'printf \'#!/bin/bash\\ntouch "%s"\\nexit 0\\n\' "$MARKER" > "$SWAP"\n')
        cp.chmod(0o755)
        result = self.execute(environment={"SWAP": str(self.installed)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists(), "the swapped file was run")
        self.assertTrue(any(line.startswith("AWGSYSPEER ") for line in result.stdout.splitlines()), result.stdout)

    def test_a_missing_or_linked_check_is_not_installed(self):
        missing = self.execute(path=self.root / "nowhere")
        self.assertEqual(missing.returncode, self.mod.HUB_OFFNODE_CHECK_EXIT_MISSING)
        link = self.root / "link"
        link.symlink_to(self.installed)
        linked = self.execute(path=link)
        self.assertEqual(linked.returncode, self.mod.HUB_OFFNODE_CHECK_EXIT_MISSING, "a link is refused")
        self.assertFalse(self.marker.exists())

    def test_no_private_directory_is_its_own_exit(self):
        result = self.execute(workdir=self.root / "no-such-dir")
        self.assertEqual(result.returncode, self.mod.HUB_OFFNODE_CHECK_EXIT_WORKDIR, result.stderr)

    def test_the_private_directory_is_removed_after_the_run(self):
        self.execute()
        self.assertEqual(list(self.workdir.iterdir()), [], "the copy must not be left behind")
        self.execute(path=self.root / "nowhere")
        self.assertEqual(list(self.workdir.iterdir()), [])

    def test_the_script_exit_status_comes_back(self):
        """A check that read nothing exits 2 and the wrapper must say so."""
        (self.root / "peers").write_text("")
        broken = self.root / "bin" / "docker"
        broken.write_text("#!/bin/bash\ncase \"$1 $2\" in\n\"ps --format\") echo awg ;;\n*) exit 1 ;;\nesac\n")
        result = self.execute()
        self.assertEqual(result.returncode, 2, result.stdout)

    def test_the_pin_is_the_digest_of_the_certified_script(self):
        self.assertEqual(hashlib.sha256(CHECK_SCRIPT.read_bytes()).hexdigest(), self.mod.HUB_OFFNODE_CHECK_SHA256)
        self.assertRegex(self.mod.HUB_OFFNODE_CHECK_SHA256, r"^[0-9a-f]{64}$")
        self.assertIn(self.mod.HUB_OFFNODE_CHECK_SHA256, self.mod.hub_offnode_check_remote_command(CANARY))


# ================================================= hub_offnode_check_run =====

class CheckRunTests(HubCase):
    def run_check(self, completed=None, raises=None, host="192.0.2.50", canary=CANARY):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            if raises is not None:
                raise raises
            return completed

        def fake_ssh(node_host, remote_command, connect_timeout=5, multiplex=True):
            return ["ssh", f"root@{node_host}", remote_command]

        with patch.object(self.mod, "AWG_CANARY_PUBLIC_KEY", canary), \
                patch.object(self.mod, "node_ssh_command", side_effect=fake_ssh), \
                patch.object(self.mod.subprocess, "run", side_effect=fake_run):
            return self.mod.hub_offnode_check_run(host), calls

    def done(self, code=0, out="", err=""):
        return types.SimpleNamespace(returncode=code, stdout=out, stderr=err)

    def test_a_clean_run_returns_the_report_and_no_reason(self):
        text = report([sys_peer_line()])
        (got, reasons), calls = self.run_check(self.done(0, text))
        self.assertEqual((got, reasons), (text, []))
        command, kwargs = calls[0]
        self.assertIn(f"--canary-pubkey {CANARY}", command[-1])
        self.assertEqual(command[1], "root@192.0.2.50")
        self.assertEqual(kwargs["env"], self.mod.management_ssh_env(), "the narrowed management environment")
        self.assertEqual(kwargs["timeout"], self.mod.HUB_OFFNODE_CHECK_TIMEOUT_SECONDS)
        self.assertIs(kwargs["check"], False)
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL, "ssh never reads the hub's stdin")

    def test_every_failure_is_a_named_reason_and_no_report(self):
        cases = [
            (self.done(self.mod.HUB_OFFNODE_CHECK_EXIT_DIGEST), "pinned digest"),
            (self.done(self.mod.HUB_OFFNODE_CHECK_EXIT_MISSING), "not installed"),
            (self.done(self.mod.HUB_OFFNODE_CHECK_EXIT_WORKDIR), "private working directory"),
            (self.done(255), "management SSH"),
            (self.done(2, report()), "exited 2"),
            (self.done(1, report()), "exited 1"),
            (self.done(0, ""), "empty or too large"),
            (self.done(0, "   \n"), "empty or too large"),
            (self.done(0, "x" * (self.mod.OFFNODE_GATE_REPORT_MAX_BYTES + 1)), "empty or too large"),
        ]
        for completed, fragment in cases:
            with self.subTest(fragment=fragment, code=completed.returncode):
                (got, reasons), _ = self.run_check(completed)
                self.assertIsNone(got)
                self.assertEqual(len(reasons), 1)
                self.assertIn(fragment, reasons[0])

    def test_a_partial_report_with_a_nonzero_exit_is_never_a_pass(self):
        (got, reasons), _ = self.run_check(self.done(2, report([sys_peer_line()])))
        self.assertIsNone(got)
        self.assertTrue(reasons)

    def test_timeouts_and_errors_fail_closed(self):
        (got, reasons), _ = self.run_check(raises=subprocess.TimeoutExpired("ssh", 90))
        self.assertIsNone(got)
        self.assertIn("did not finish within 90 s", reasons[0])
        for error in (OSError("no ssh"), ValueError("unpinned"), RuntimeError("anything else")):
            with self.subTest(error=type(error).__name__):
                (got, reasons), _ = self.run_check(raises=error)
                self.assertIsNone(got)
                self.assertIn("could not be started", reasons[0])

    def test_no_canary_key_or_no_host_runs_nothing(self):
        (got, reasons), calls = self.run_check(self.done(0, report()), canary="")
        self.assertEqual((got, calls), (None, []))
        self.assertIn("AWG_CANARY_PUBLIC_KEY", reasons[0])
        (got, reasons), calls = self.run_check(self.done(0, report()), host="  ")
        self.assertEqual((got, calls), (None, []))
        self.assertIn("no management host", reasons[0])

    def test_the_hub_never_checks_itself(self):
        """H0 (D3): node_ssh_command refuses loopback and the hub's own address by name."""
        for host in ("127.0.0.1", "localhost", "::1"):
            with self.subTest(host=host), patch.object(self.mod.subprocess, "run") as run:
                got, reasons = self.mod.hub_offnode_check_run(host)
                self.assertIsNone(got)
                self.assertIn("Refusing to manage this hub", reasons[0])
                run.assert_not_called()

    def test_the_real_ssh_command_is_used_with_a_pinned_host(self):
        control = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, control, ignore_errors=True)
        seen = []

        def fake_run(command, **kwargs):
            seen.append(command)
            return self.done(0, report())

        with patch.object(self.mod, "AWG_CANARY_PUBLIC_KEY", CANARY), \
                patch.object(self.mod, "HUB_MANAGEMENT_SSH_CONTROL_DIR", control), \
                patch.object(self.mod, "management_known_hosts_has_hostname", return_value=True), \
                patch.object(self.mod.subprocess, "run", side_effect=fake_run):
            got, reasons = self.mod.hub_offnode_check_run("198.51.100.20")
        self.assertEqual(reasons, [])
        self.assertIn("StrictHostKeyChecking=yes", seen[0])
        self.assertEqual(seen[0][-2], "root@198.51.100.20")
        self.assertIn("--canary-pubkey " + CANARY, seen[0][-1])
        with patch.object(self.mod, "management_known_hosts_has_hostname", return_value=False), \
                patch.object(self.mod.subprocess, "run") as run:
            got, reasons = self.mod.hub_offnode_check_run("198.51.100.20")
        self.assertIsNone(got)
        self.assertIn("could not be started", reasons[0])
        run.assert_not_called()


class GatewayRestartTests(ClosedNodeCase):
    """R25: the hub restarts a closed node's gateway, once, when timing is all
    that stops its gate (the registry was published after the gateway started)."""

    def restart(self, completed=None, raises=None, host="192.0.2.50"):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            if raises is not None:
                raise raises
            return completed

        def fake_ssh(node_host, remote_command, connect_timeout=5, multiplex=True):
            return ["ssh", f"root@{node_host}", remote_command]

        with patch.object(self.mod, "node_ssh_command", side_effect=fake_ssh), \
                patch.object(self.mod.subprocess, "run", side_effect=fake_run):
            return self.mod.hub_offnode_gateway_restart(host, EMPTY_SNAPSHOT_SHA), calls

    def done(self, code=0, out="", err=""):
        return types.SimpleNamespace(returncode=code, stdout=out, stderr=err)

    def test_the_restart_goes_through_the_serving_activator_with_the_narrowed_environment(self):
        problem, calls = self.restart(self.done(0))
        self.assertEqual(problem, "")
        command, kwargs = calls[0]
        self.assertEqual(command[1], "root@192.0.2.50")
        self.assertEqual(command[-1], self.mod.HUB_OFFNODE_GATEWAY_RESTART_COMMAND + EMPTY_SNAPSHOT_SHA)
        self.assertIn("/usr/local/libexec/winsvpn/wins-serving-activate systemctl restart winn3-gateway.service",
                      command[-1])
        self.assertEqual(kwargs["env"], self.mod.management_ssh_env())
        self.assertEqual(kwargs["timeout"], self.mod.HUB_OFFNODE_GATEWAY_RESTART_TIMEOUT_SECONDS)
        self.assertIs(kwargs["check"], False)
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)

    def test_every_failure_is_a_named_reason(self):
        cases = [(self.done(3), "late failure"), (self.done(75), "activation lock"),
                 (self.done(76), "registry changed after the check"),
                 (self.done(255), "exited 255"), (self.done(1), "exited 1"), (self.done(127), "exited 127")]
        for completed, fragment in cases:
            with self.subTest(code=completed.returncode):
                problem, _ = self.restart(completed)
                self.assertIn(fragment, problem)
        problem, _ = self.restart(raises=subprocess.TimeoutExpired("ssh", 110))
        self.assertIn("did not finish", problem)
        for error in (OSError("no ssh"), ValueError("unpinned")):
            with self.subTest(error=type(error).__name__):
                problem, _ = self.restart(raises=error)
                self.assertIn("could not be started", problem)

    def run_restart_command(self, lock_ok=True, activator_exit=0, registry=CLOSED_REGISTRY,
                            registry_lock_ok=True, digest=EMPTY_SNAPSHOT_SHA):
        """The remote restart command under bash on this machine: the node's
        lock directory, registry directory and activator move into a sandbox, and
        every other tool it calls is a shim that records the call. registry is the
        node's winn3-peers.json ("symlink" makes it a link, None leaves it out)."""
        root = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        log = root / "calls.log"
        log.write_text("")
        shims = {
            "install": 'for last; do :; done; mkdir -p "$last"\n',
            "flock": ('echo "FLOCK $*" >> "$LOG"\n'
                      'if [ "${!#}" = 9 ]; then [ "$REGISTRY_LOCK_OK" = 1 ]; else [ "$LOCK_OK" = 1 ]; fi\n'),
            "timeout": 'echo "TIMEOUT $1 $2 $3" >> "$LOG"\nshift 3\nexec "$@"\n',
            "systemd-run": ('echo "SYSTEMD_RUN $*" >> "$LOG"\n'
                            'while [ $# -gt 0 ]; do case "$1" in --*) shift ;; *) break ;; esac; done\nexec "$@"\n'),
            "systemctl": 'echo "SYSTEMCTL $*" >> "$LOG"\n',
        }
        for name, body in shims.items():
            (bin_dir / name).write_text("#!/bin/bash\n" + body)
            (bin_dir / name).chmod(0o755)
        (bin_dir / "sha256sum").write_text(
            f'#!/bin/bash\nexec {shlex.quote(sys.executable)} -c \'import hashlib,sys; '
            f'print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()+"  "+sys.argv[1])\' "$1"\n')
        (bin_dir / "sha256sum").chmod(0o755)
        registry_dir = root / "winn"
        registry_dir.mkdir()
        if registry == "symlink":
            (registry_dir / "elsewhere.json").write_text(CLOSED_REGISTRY)
            (registry_dir / "winn3-peers.json").symlink_to(registry_dir / "elsewhere.json")
        elif registry is not None:
            (registry_dir / "winn3-peers.json").write_text(registry)
        activator = root / "wins-serving-activate"
        # fd 9 is the registry publication lock: it is still open inside the activator.
        activator.write_text('#!/bin/bash\necho "ACTIVATE $*" >> "$LOG"\n'
                             'if { : >&9; } 2>/dev/null; then echo "REGISTRY_LOCK_HELD" >> "$LOG"; fi\n'
                             'exit "$ACTIVATOR_EXIT"\n')
        activator.chmod(0o755)
        command = (self.mod.HUB_OFFNODE_GATEWAY_RESTART_COMMAND
                   .replace("/run/lock", str(root / "lock"))
                   .replace("/etc/winn", str(registry_dir))
                   .replace("/usr/local/libexec/winsvpn/wins-serving-activate", str(activator))
                   + digest)
        environment = {"PATH": f"{bin_dir}:/usr/bin:/bin", "LOG": str(log),
                       "LOCK_OK": "1" if lock_ok else "0", "REGISTRY_LOCK_OK": "1" if registry_lock_ok else "0",
                       "ACTIVATOR_EXIT": str(activator_exit)}
        result = subprocess.run([BASH, "-c", command], env=environment, capture_output=True, text=True, timeout=30)
        return result, log.read_text().splitlines()

    def test_the_restart_takes_the_activation_lock_and_runs_in_an_activation_scope(self):
        # R25-F5: node-local callers start serving through wins_serving_start, which
        # holds /run/lock/wins-serving-activation.lock and runs the activator in a
        # wins-serving-activation-*.scope; the late-failure handlers synchronize on both.
        result, calls = self.run_restart_command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c.split()[0] for c in calls],
                         ["FLOCK", "TIMEOUT", "SYSTEMD_RUN", "FLOCK", "ACTIVATE", "REGISTRY_LOCK_HELD"], calls)
        self.assertRegex(calls[0], r"^FLOCK -w \d+ 6$")
        self.assertEqual(calls[1], "TIMEOUT -k 5 100")
        self.assertIn("--scope", calls[2])
        self.assertRegex(calls[2], r"--unit=wins-serving-activation-hub-offnode-\d+ ")
        self.assertIn("--property=RuntimeMaxSec=100", calls[2])
        self.assertRegex(calls[3], r"^FLOCK -w \d+ 9$")
        self.assertEqual(calls[4], "ACTIVATE systemctl restart winn3-gateway.service")
        self.assertEqual(calls[5], "REGISTRY_LOCK_HELD", "the registry lock is held through the activator")

    def test_a_busy_activation_lock_restarts_nothing_and_a_late_failure_hold_comes_back_as_3(self):
        result, calls = self.run_restart_command(lock_ok=False)
        self.assertEqual(result.returncode, self.mod.HUB_OFFNODE_GATEWAY_RESTART_LOCK_EXIT)
        self.assertEqual([c.split()[0] for c in calls], ["FLOCK"], calls)
        result, calls = self.run_restart_command(activator_exit=3)
        self.assertEqual(result.returncode, self.mod.HUB_OFFNODE_GATEWAY_RESTART_LATE_HOLD_EXIT)
        self.assertNotIn("SYSTEMCTL", " ".join(calls))

    def test_a_registry_that_is_not_the_checked_snapshot_restarts_nothing(self):
        # R25 R2-G2: a changed, missing or linked registry file, a different digest and
        # a busy publication lock each refuse before the activator runs.
        cases = {
            "customers were published": (dict(registry=CUSTOMER_REGISTRY), 76),
            "the registry is gone": (dict(registry=None), 76),
            "the registry is a symlink": (dict(registry="symlink"), 76),
            "the hub checked another snapshot": (dict(digest="0" * 64), 76),
            "a publisher holds the registry lock": (dict(registry_lock_ok=False), 75),
        }
        for label, (arguments, code) in cases.items():
            with self.subTest(label):
                result, calls = self.run_restart_command(**arguments)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse([c for c in calls if c.startswith("ACTIVATE")], calls)
                self.assertNotIn("SYSTEMCTL", " ".join(calls))

    def test_a_digest_that_is_not_a_sha256_is_never_sent(self):
        for digest in ("", "abc", "G" * 64, "0" * 63, "0" * 65, EMPTY_SNAPSHOT_SHA.upper(), None):
            with self.subTest(digest=digest), patch.object(self.mod, "node_ssh_command") as ssh, \
                    patch.object(self.mod.subprocess, "run") as run:
                problem = self.mod.hub_offnode_gateway_restart("192.0.2.50", digest)
                self.assertIn("checked registry digest is unavailable", problem)
                ssh.assert_not_called()
                run.assert_not_called()

    LATE_GW = ("GW unit=active pid_known=1 forward=1 registry_flag_matches=1 gateway_can_read=1 "
               "started_after_file=0 reload_failed_since_file=0")
    def late_report(self, peer_lines=()):
        return report(peer_lines).replace(CLEAN_GW, self.LATE_GW)

    def sandbox_node(self, registry=CLOSED_REGISTRY):
        """A node under bash on this machine, for the whole restart round trip: the
        remote command runs in a sandbox whose /etc/winn, /run/lock and activator are
        local files, and every tool it calls records the call."""
        root = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (root / "winn").mkdir()
        log = root / "calls.log"
        log.write_text("")
        shims = {
            "install": 'for last; do :; done; mkdir -p "$last"\n',
            "flock": 'echo "FLOCK $*" >> "$LOG"\n',
            "timeout": 'shift 3\nexec "$@"\n',
            "systemd-run": ('while [ $# -gt 0 ]; do case "$1" in --*) shift ;; *) break ;; esac; done\nexec "$@"\n'),
            "sha256sum": f'exec {shlex.quote(sys.executable)} -c \'import hashlib,sys; '
                         f'print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()+"  "+sys.argv[1])\' "$1"\n',
        }
        for name, body in shims.items():
            (bin_dir / name).write_text("#!/bin/bash\n" + body)
            (bin_dir / name).chmod(0o755)
        activator = root / "wins-serving-activate"
        activator.write_text('#!/bin/bash\necho "ACTIVATE $*" >> "$LOG"\n')
        activator.chmod(0o755)
        registry_file = root / "winn" / "winn3-peers.json"
        registry_file.write_text(registry)
        environment = {"PATH": f"{bin_dir}:/usr/bin:/bin", "LOG": str(log)}
        real_run = subprocess.run

        def localize(remote_command):
            return (remote_command.replace("/run/lock", str(root / "lock"))
                    .replace("/etc/winn", str(root / "winn"))
                    .replace("/usr/local/libexec/winsvpn/wins-serving-activate", str(activator)))

        def fake_run(command, **kwargs):
            return real_run([BASH, "-c", localize(command[-1])], env=environment, stdin=subprocess.DEVNULL,
                            stdout=kwargs["stdout"], stderr=kwargs["stderr"], timeout=30)

        return types.SimpleNamespace(
            registry_file=registry_file, fake_run=fake_run,
            calls=lambda: log.read_text().splitlines())

    def test_a_node_that_reopened_and_published_after_the_check_is_never_restarted(self):
        # R25 R2-G2: the check and the restart are two SSH round trips with the
        # hub's write lock released in between. In that window the node was
        # reopened and its customers published; the restart used to be sent anyway.
        slug = self.closed_node()
        box = self.sandbox_node()

        def check(host):
            return self.late_report([sys_peer_line()]), []

        def ssh(node_host, remote_command, connect_timeout=5, multiplex=True):
            with self.db() as conn:
                conn.execute("UPDATE nodes SET operator_enabled=1 WHERE slug=?", (slug,))
            box.registry_file.write_text(CUSTOMER_REGISTRY)
            return ["ssh", f"root@{node_host}", remote_command]

        with patch.object(self.mod, "node_ssh_command", side_effect=ssh), \
                patch.object(self.mod.subprocess, "run", side_effect=box.fake_run):
            gate, reasons = self.attempt(slug, check)
        self.assertEqual(gate, "")
        self.assertEqual([c for c in box.calls() if c.startswith("ACTIVATE")], [],
                         "the gateway of a node that reopened is not restarted")
        self.assertIn("registry changed after the check", reasons[0])

    def test_the_same_round_trip_restarts_a_node_whose_registry_is_still_the_checked_snapshot(self):
        slug = self.closed_node()
        box = self.sandbox_node()

        def ssh(node_host, remote_command, connect_timeout=5, multiplex=True):
            return ["ssh", f"root@{node_host}", remote_command]

        with patch.object(self.mod, "node_ssh_command", side_effect=ssh), \
                patch.object(self.mod.subprocess, "run", side_effect=box.fake_run):
            gate, reasons = self.attempt(slug, lambda host: (self.late_report([sys_peer_line()]), []))
        self.assertEqual(gate, "")
        self.assertEqual([c for c in box.calls() if c.startswith("ACTIVATE")],
                         ["ACTIVATE systemctl restart winn3-gateway.service"])
        self.assertIn("the hub restarted the gateway", reasons[0])

    def test_no_host_runs_nothing_and_the_hub_never_restarts_itself(self):
        problem, calls = self.restart(self.done(0), host="  ")
        self.assertEqual(calls, [])
        self.assertIn("no management host", problem)
        for host in ("127.0.0.1", "localhost", "::1"):
            with self.subTest(host=host), patch.object(self.mod.subprocess, "run") as run:
                self.assertIn("could not be started", self.mod.hub_offnode_gateway_restart(host, EMPTY_SNAPSHOT_SHA))
                run.assert_not_called()


# ===================================== record, verify and the use rules =====

def record_checks(case):
    """hub_offnode_gate_record and verify_offnode_gate_for_use (3.16 steps 2 to 4)."""
    mod = case.mod
    slug = case.closed_node()
    text = report([sys_peer_line()])
    with case.db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        gate, reasons = mod.hub_offnode_gate_record(conn, slug, text)
    case.assertEqual(reasons, [])
    expected = canonical_gate_digest(slug, EMPTY_SNAPSHOT_SHA, case.confirmed_at(slug), "",
                                     hashlib.sha256(text.encode()).hexdigest())
    case.assertEqual(gate, expected, "the canonical gate digest, computed independently")
    rows = case.gates(slug)
    case.assertEqual(len(rows), 1)
    row = rows[0]
    case.assertEqual(row["source"], "hub")
    case.assertEqual(row["expected_v3_sha256"], EMPTY_SNAPSHOT_SHA)
    case.assertEqual(row["external_evidence_sha256"], "")
    case.assertEqual(row["node_report"], text)
    case.assertEqual(row["node_report_sha256"], hashlib.sha256(text.encode()).hexdigest())
    case.assertEqual(row["cleanup_confirmed_at"], case.confirmed_at(slug))
    case.assertIsNone(row["used_at"])
    with case.db() as conn:
        case.assertEqual(mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True), [])
        refused = mod.verify_offnode_gate_for_use(conn, slug, gate)
        case.assertTrue(any("accepted only for an installer rerun or fresh install reopen" in r for r in refused),
                        refused)
    return slug, gate


class RecordAndVerifyTests(ClosedNodeCase):
    def test_record_and_verify(self):
        record_checks(self)

    def test_the_record_goes_to_both_closure_classes_and_no_other(self):
        for reason, accepted in (("installer_rerun", True), ("fresh_install", True), ("heartbeat_stale", False),
                                 ("operator", False), (None, False)):
            with self.subTest(reason=reason):
                slug = self.closed_node(reason=reason)
                with self.db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    gate, reasons = self.mod.hub_offnode_gate_record(conn, slug, report([sys_peer_line()]))
                self.assertEqual(bool(gate), accepted, reasons)
                if not accepted:
                    self.assertEqual(self.gates(slug), [], "nothing stays recorded on a refusal")
                    self.assertTrue(any("not closed as an installer rerun or a fresh install" in r
                                        for r in reasons), reasons)

    def test_a_hub_record_is_usable_only_by_an_automatic_reopen(self):
        for reason in ("installer_rerun", "fresh_install"):
            with self.subTest(reason=reason):
                slug = self.closed_node(reason=reason)
                with self.db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    gate, _ = self.mod.hub_offnode_gate_record(conn, slug, report())
                self.assertTrue(gate)
                with self.db() as conn:
                    # An operator-source record is accepted everywhere.
                    conn.execute("UPDATE node_offnode_gates SET source='operator' WHERE gate_sha256=?", (gate,))
                    self.assertEqual(self.mod.verify_offnode_gate_for_use(conn, slug, gate), [])
                    conn.execute("UPDATE node_offnode_gates SET source='hub' WHERE gate_sha256=?", (gate,))
                    self.assertTrue(self.mod.verify_offnode_gate_for_use(conn, slug, gate))
                    self.assertEqual(self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True), [])
                    conn.execute("UPDATE nodes SET health_closed_reason='heartbeat_stale' WHERE slug=?", (slug,))
                    self.assertTrue(self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True))
                    conn.execute("UPDATE node_offnode_gates SET source='lab' WHERE gate_sha256=?", (gate,))
                    conn.execute("UPDATE nodes SET health_closed_reason=? WHERE slug=?", (reason, slug))
                    self.assertTrue(self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True),
                                    "an unknown source is never accepted")

    def test_manual_promotion_and_retirement_refuse_a_hub_record(self):
        for reason in ("installer_rerun", "fresh_install"):
            with self.subTest(reason=reason):
                slug = self.closed_node(reason=reason)
                with self.db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    gate, _ = self.mod.hub_offnode_gate_record(conn, slug, report())
                request = harness.FakeRequest(headers={"x-admin-token": dark.ADMIN_TOKEN}, path="/admin/nodes/tier")
                with self.assertRaises(harness.HTTPException) as caught:
                    self.mod.admin_set_node_tier(request, slug=slug, tier="premium", evidence_sha256=gate,
                                                 confirm_slug=slug, x_admin_token=dark.ADMIN_TOKEN)
                self.assertIn("accepted only for an installer rerun or fresh install reopen",
                              str(caught.exception.detail))
                with self.assertRaises(harness.HTTPException) as caught:
                    self.mod.admin_retire_node(request, slug=slug, reason="test", confirm_last_servable_node=slug,
                                               offnode_gate_sha256=gate, x_admin_token=dark.ADMIN_TOKEN)
                self.assertIn("accepted only for an installer rerun or fresh install reopen",
                              str(caught.exception.detail))
                self.assertEqual(self.node(slug)["operator_enabled"], 0)
                self.assertIsNone(self.node(slug)["retired_at"])
                self.assertIsNone(self.gates(slug)[0]["used_at"], "a refused use does not consume the record")

    def test_a_report_that_fails_the_rules_records_nothing(self):
        slug = self.closed_node()
        for name, text in (
            ("core exit peer", report([awg_peer_line(CORE_KEY, CORE_EXIT)])),
            ("unexpected key", report([sys_peer_line(key=OTHER)])),
            ("two canary lines", report([sys_peer_line(), sys_peer_line()])),
            ("no AWG read", "V3_FILE absent\n" + CLEAN_GW + "\n"),
        ):
            with self.subTest(name=name), self.db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                gate, reasons = self.mod.hub_offnode_gate_record(conn, slug, text)
                self.assertEqual(gate, "")
                self.assertTrue(reasons)
        self.assertEqual(self.gates(slug), [])

    def test_the_preconditions_are_the_gate_routes_preconditions(self):
        cases = [
            ("retired", dict(retired_at="2026-01-01T00:00:00"), "retired"),
            ("latch open", dict(operator_enabled=1), "latch is open"),
            ("withdrawal active", dict(deployment_withdrawal_id="w-1"), "withdrawal is active"),
        ]
        for name, overrides, fragment in cases:
            with self.subTest(name=name):
                slug = self.closed_node(**overrides)
                with self.db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    gate, reasons = self.mod.hub_offnode_gate_record(conn, slug, report())
                self.assertEqual(gate, "")
                self.assertTrue(any(fragment in r for r in reasons), reasons)
        for name, cleanup in (("pending", "pending"), ("never recorded", None)):
            with self.subTest(name=name):
                slug = self.closed_node(cleanup=cleanup)
                with self.db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    gate, reasons = self.mod.hub_offnode_gate_record(conn, slug, report())
                self.assertEqual(gate, "")
                self.assertTrue(any("closure cleanup is not confirmed" in r for r in reasons), reasons)
        with self.db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self.assertEqual(self.mod.hub_offnode_gate_record(conn, "no-such-node", report()),
                             ("", ["node not found"]))

    def test_no_record_and_another_nodes_record_open_nothing(self):
        slug, other = self.closed_node(), self.closed_node()
        with self.db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            gate, _ = self.mod.hub_offnode_gate_record(conn, other, report())
        with self.db() as conn:
            for digest in ("", "f" * 64, gate):
                refused = self.mod.verify_offnode_gate_for_use(conn, slug, digest, allow_hub_source=True)
                self.assertEqual(refused, ["no verified node-side gate record with this digest for this node"])

    def test_a_record_that_fails_its_own_verification_is_removed(self):
        slug = self.closed_node()
        with patch.object(self.mod, "verify_offnode_gate_for_use", return_value=["boom"]), self.db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            gate, reasons = self.mod.hub_offnode_gate_record(conn, slug, report([sys_peer_line()]))
        self.assertEqual((gate, reasons), ("", ["boom"]))
        self.assertEqual(self.gates(slug), [], "nothing stays recorded when the verification refuses it")

    def test_a_used_record_never_becomes_usable_again(self):
        slug = self.closed_node()
        text = report([sys_peer_line()])
        with self.db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            gate, _ = self.mod.hub_offnode_gate_record(conn, slug, text)
            conn.execute("UPDATE node_offnode_gates SET used_at=?, used_for='auto_reopened' WHERE gate_sha256=?",
                         (self.mod.utcnow().isoformat(), gate))
        with self.db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            again, reasons = self.mod.hub_offnode_gate_record(conn, slug, text)
        self.assertEqual(again, "")
        self.assertIn("an identical gate record exists and is not an unused hub record", reasons)
        row = self.gates(slug)[0]
        self.assertEqual(row["used_for"], "auto_reopened")
        self.assertTrue(row["used_at"])

    def test_an_identical_operator_record_is_not_taken_over_as_a_hub_record(self):
        slug = self.closed_node()
        text = report()
        digest = canonical_gate_digest(slug, EMPTY_SNAPSHOT_SHA, self.confirmed_at(slug), "",
                                       hashlib.sha256(text.encode()).hexdigest())
        with self.db() as conn:
            conn.execute(
                "INSERT INTO node_offnode_gates (gate_sha256, slug, recorded_at, cleanup_confirmed_at,"
                " expected_v3_sha256, external_evidence_sha256, node_report, node_report_sha256, used_at,"
                " used_for, source) VALUES (?, ?, ?, ?, ?, '', ?, ?, NULL, NULL, 'operator')",
                (digest, slug, self.mod.utcnow().isoformat(), self.confirmed_at(slug), EMPTY_SNAPSHOT_SHA, text,
                 hashlib.sha256(text.encode()).hexdigest()))
        with self.db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            gate, reasons = self.mod.hub_offnode_gate_record(conn, slug, text)
        self.assertEqual(gate, "")
        self.assertEqual(self.gates(slug)[0]["source"], "operator")

    def test_a_stored_hub_record_is_re_evaluated_at_use(self):
        """verify_offnode_gate_for_use re-reads the report with the same rules."""
        slug, gate = record_checks(self)
        with self.db() as conn:
            forged = report([awg_peer_line(CORE_KEY, CORE_EXIT)])
            conn.execute("UPDATE node_offnode_gates SET node_report=?, node_report_sha256=? WHERE gate_sha256=?",
                         (forged, hashlib.sha256(forged.encode()).hexdigest(), gate))
            failures = self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True)
        self.assertTrue(any("digest does not recompute" in f for f in failures), failures)
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET node_report=?, node_report_sha256=? WHERE gate_sha256=?",
                         (report([sys_peer_line()]), hashlib.sha256(report([sys_peer_line()]).encode()).hexdigest(),
                          gate))
        # The hub's canary key changes after the record: the exempt line is now unexpected.
        with self.db() as conn, patch.object(self.mod, "AWG_CANARY_PUBLIC_KEY", OTHER):
            failures = self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True)
        self.assertTrue(any(f.startswith("unexpected system peer") for f in failures), failures)

    def test_the_record_ages_out_after_two_hours(self):
        slug, gate = record_checks(self)
        old = (self.mod.utcnow() - timedelta(hours=3)).isoformat()
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET recorded_at=? WHERE gate_sha256=?", (old, gate))
            failures = self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True)
            self.assertIn("gate record older than 2 h", failures)
            self.assertEqual(self.mod.node_auto_reopen_gate_record(conn, slug), "")

    def test_the_reopen_failures_accept_a_hub_record_for_both_classes(self):
        for reason in ("installer_rerun", "fresh_install", "heartbeat_stale"):
            with self.subTest(reason=reason):
                slug = self.closed_node(reason="installer_rerun")
                with self.db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    gate, _ = self.mod.hub_offnode_gate_record(conn, slug, report([sys_peer_line()]))
                    conn.execute("UPDATE nodes SET health_closed_reason=? WHERE slug=?", (reason, slug))
                    row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
                    failures = self.mod.node_auto_reopen_failures(conn, row, self.mod.utcnow().isoformat())
                gate_failures = [f for f in failures if f.startswith("offnode gate: ")]
                if reason == "heartbeat_stale":
                    self.assertTrue(gate_failures, "a plain health closure never takes a hub record")
                else:
                    self.assertEqual(gate_failures, [], failures)


# ================================================ hub_offnode_gate_attempt ====

class AttemptTests(ClosedNodeCase):
    def clean_check(self, text=None, log=None):
        def check(host):
            if log is not None:
                log.append(host)
            return (text if text is not None else report([sys_peer_line()])), []
        return check

    def test_a_clean_check_records_a_hub_gate_and_returns_its_digest(self):
        for reason in ("installer_rerun", "fresh_install"):
            with self.subTest(reason=reason):
                slug = self.closed_node(reason=reason)
                log = []
                gate, reasons = self.attempt(slug, self.clean_check(log=log))
                self.assertEqual(reasons, [])
                self.assertEqual(log, [self.node(slug)["ssh_host"]], "the node's management host")
                self.assertEqual(self.gates(slug)[0]["gate_sha256"], gate)
                self.assertEqual(self.gates(slug)[0]["source"], "hub")

    def test_the_named_interface_returns_the_digest_or_the_empty_string(self):
        slug = self.closed_node()
        with patch.object(self.mod, "hub_offnode_check_run", side_effect=self.clean_check()):
            with self.mod.get_db() as conn:
                conn.commit()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
                gate = self.mod.installer_rerun_hub_offnode_gate(conn, row)
        self.assertRegex(gate, r"^[0-9a-f]{64}$")
        self.assertEqual(self.gates(slug)[0]["gate_sha256"], gate)
        other = self.closed_node()
        with patch.object(self.mod, "hub_offnode_check_run", return_value=(None, ["management SSH to the node failed"])):
            with self.mod.get_db() as conn:
                conn.commit()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM nodes WHERE slug=?", (other,)).fetchone()
                self.assertEqual(self.mod.installer_rerun_hub_offnode_gate(conn, row), "")

    def test_the_host_falls_back_to_the_endpoint(self):
        slug = self.closed_node(ssh_host="", endpoint="198.51.100.77:9110")
        log = []
        gate, _ = self.attempt(slug, self.clean_check(log=log))
        self.assertTrue(gate)
        self.assertEqual(log, ["198.51.100.77"])
        slug = self.closed_node(ssh_host="203.0.113.5", endpoint="198.51.100.78:9110")
        log = []
        self.attempt(slug, self.clean_check(log=log))
        self.assertEqual(log, ["203.0.113.5"], "the management host wins over the endpoint")

    def test_the_check_runs_without_the_database_write_lock(self):
        slug = self.closed_node()
        seen = []

        def check(host):
            seen.append(self.other_writer_can_write())
            return report([sys_peer_line()]), []

        gate, _ = self.attempt(slug, check)
        self.assertTrue(gate)
        self.assertEqual(seen, [True], "a 90 s SSH check must not hold the hub's write lock")

    def test_the_transaction_is_open_again_when_the_attempt_returns(self):
        slug = self.closed_node()
        with patch.object(self.mod, "hub_offnode_check_run", return_value=(None, ["management SSH to the node failed"])):
            with self.mod.get_db() as conn:
                conn.commit()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
                self.mod.hub_offnode_gate_attempt(conn, row)
                self.assertTrue(conn.in_transaction)
                self.assertFalse(self.other_writer_can_write(), "the caller's write transaction is back")

    def test_a_failed_check_is_held_with_its_reasons_and_records_nothing(self):
        slug = self.closed_node()
        gate, reasons = self.attempt(slug, lambda host: (None, ["management SSH to the node failed"]))
        self.assertEqual(gate, "")
        self.assertEqual(reasons, ["hub-run check: management SSH to the node failed"])
        self.assertEqual(self.gates(slug), [])
        gate, reasons = self.attempt(self.closed_node(), lambda host: (report([awg_peer_line(CORE_KEY, CORE_EXIT)]), []))
        self.assertEqual(gate, "")
        self.assertTrue(any("1 AWG peer(s) present" in r for r in reasons), reasons)
        self.assertTrue(all(r.startswith("hub-run check: ") for r in reasons), reasons)

    def test_preconditions_refuse_before_any_ssh(self):
        cases = [
            self.closed_node(reason="heartbeat_stale"), self.closed_node(reason=None),
            self.closed_node(retired_at="2026-01-01T00:00:00"), self.closed_node(operator_enabled=1),
            self.closed_node(deployment_withdrawal_id="w-1"),
            self.closed_node(cleanup="pending"), self.closed_node(cleanup=None),
        ]
        for slug in cases:
            with self.subTest(slug=slug):
                log = []
                gate, reasons = self.attempt(slug, self.clean_check(log=log))
                self.assertEqual((gate, log), ("", []), reasons)
                self.assertTrue(reasons)
                self.assertEqual(self.gates(slug), [])

    def test_a_failed_check_is_not_repeated_within_the_retry_window(self):
        slug = self.closed_node()
        calls = []

        def failing(host):
            calls.append(host)
            return None, ["management SSH to the node failed"]

        clock = [1000.0]
        fake_time = types.SimpleNamespace(monotonic=lambda: clock[0], time=time.time, sleep=time.sleep)
        with patch.object(self.mod, "time", fake_time):
            first = self.attempt(slug, failing)
            clock[0] += self.mod.HUB_OFFNODE_GATE_RETRY_SECONDS - 1
            second = self.attempt(slug, failing)
            self.assertEqual(second, first, "the same reasons, without another SSH")
            self.assertEqual(len(calls), 1)
            clock[0] += 2
            self.attempt(slug, failing)
            self.assertEqual(len(calls), 2, "after the window the check runs again")
            # A pass clears the memory.
            clock[0] += self.mod.HUB_OFFNODE_GATE_RETRY_SECONDS + 1
            gate, _ = self.attempt(slug, self.clean_check())
            self.assertTrue(gate)
        self.assertNotIn(slug, self.mod._HUB_OFFNODE_GATE_LAST)

    def test_the_retry_memory_is_per_node(self):
        first, second = self.closed_node(), self.closed_node()
        self.attempt(first, lambda host: (None, ["management SSH to the node failed"]))
        log = []
        gate, _ = self.attempt(second, self.clean_check(log=log))
        self.assertTrue(gate)
        self.assertEqual(len(log), 1)

    def test_a_node_that_changed_while_the_check_ran_gets_no_record(self):
        for column, value in (("operator_enabled", 1), ("retired_at", "2026-01-01T00:00:00"),
                              ("deployment_withdrawal_id", "w-9"), ("health_closed_reason", "heartbeat_stale"),
                              ("deployment_completed_at", "2030-01-01T00:00:00"), ("ssh_host", "192.0.2.250"),
                              ("protocol_version", "winn/3"), ("health_closed_at", "2030-01-01T00:00:00")):
            with self.subTest(column=column):
                slug = self.closed_node()

                def check(host, slug=slug, column=column, value=value):
                    with self.db() as conn:
                        conn.execute(f"UPDATE nodes SET {column}=? WHERE slug=?", (value, slug))
                    return report([sys_peer_line()]), []

                gate, reasons = self.attempt(slug, check)
                self.assertEqual(gate, "", reasons)
                self.assertTrue(any("the node changed while the check ran" in r and column in r for r in reasons)
                                or column == "health_closed_at", reasons)
                self.assertEqual(self.gates(slug), [])

    def test_a_node_removed_while_the_check_ran_gets_no_record(self):
        slug = self.closed_node()

        def check(host):
            with self.db() as conn:
                conn.execute("DELETE FROM nodes WHERE slug=?", (slug,))
            return report(), []

        gate, reasons = self.attempt(slug, check)
        self.assertEqual((gate, reasons), ("", ["node not found"]))

    def test_the_hub_check_is_not_run_on_a_stale_throttle_after_a_pass_elsewhere(self):
        slug = self.closed_node()
        self.mod._HUB_OFFNODE_GATE_LAST[slug] = (time.monotonic() - 10_000, ["old"])
        gate, _ = self.attempt(slug, self.clean_check())
        self.assertTrue(gate, "an old failure never blocks a later run")


    LATE_GW = ("GW unit=active pid_known=1 forward=1 registry_flag_matches=1 gateway_can_read=1 "
               "started_after_file=0 reload_failed_since_file=0")

    def late_report(self, peer_lines=()):
        return report(peer_lines).replace(CLEAN_GW, self.LATE_GW)

    def attempt_restarting(self, slug, check, problem=""):
        restarts = []

        def restart(host, registry_sha256):
            self.assertEqual(registry_sha256, EMPTY_SNAPSHOT_SHA, "the restart carries the snapshot the check matched")
            restarts.append((host, self.other_writer_can_write()))
            return problem

        with patch.object(self.mod, "hub_offnode_gateway_restart", side_effect=restart):
            result = self.attempt(slug, check)
        return result, restarts

    def test_a_gateway_that_started_before_the_file_is_restarted_once_and_rechecked_later(self):
        # A fresh install: the hub's first registry publication came after the
        # gateway started, so timing is the only thing that fails the gate.
        slug = self.closed_node(reason="fresh_install")
        calls = []

        def late(host):
            calls.append(host)
            return self.late_report([sys_peer_line()]), []

        clock = [1000.0]
        fake_time = types.SimpleNamespace(monotonic=lambda: clock[0], time=time.time, sleep=time.sleep)
        with patch.object(self.mod, "time", fake_time):
            (gate, reasons), restarts = self.attempt_restarting(slug, late)
            self.assertEqual(gate, "")
            self.assertEqual(restarts, [(self.node(slug)["ssh_host"], True)],
                             "one restart of that node, outside the write lock")
            self.assertEqual(reasons, ["hub-run check: gateway started after the file's last change: no; "
                                       "the hub restarted the gateway, the next check follows in 60 s"])
            self.assertEqual(self.gates(slug), [])
            # Inside the retry window nothing runs again: no check, no restart.
            clock[0] += self.mod.HUB_OFFNODE_GATE_RETRY_SECONDS - 1
            (_, again), restarts = self.attempt_restarting(slug, late)
            self.assertEqual((again, restarts, len(calls)), (reasons, [], 1))
            # After the window the gateway has started after the file: the gate records.
            clock[0] += 2
            (gate, reasons), restarts = self.attempt_restarting(slug, self.clean_check())
            self.assertTrue(gate, reasons)
            self.assertEqual(restarts, [], "a passing check restarts nothing")
        self.assertEqual(self.gates(slug)[0]["source"], "hub")

    def test_the_restart_is_only_for_a_report_whose_sole_failure_is_the_timing(self):
        slug = self.closed_node()
        # Another failure beside the timing: nothing is restarted.
        (gate, reasons), restarts = self.attempt_restarting(
            slug, lambda host: (self.late_report([awg_peer_line(CORE_KEY, CORE_EXIT)]), []))
        self.assertEqual((gate, restarts), ("", []))
        self.assertTrue(any("AWG peer(s) present" in r for r in reasons) and
                        any("started after the file" in r for r in reasons), reasons)
        # The check did not run, or the report is not one: nothing is restarted.
        for outcome in ((None, ["management SSH to the node failed"]), (None, ["the node-side check is not installed"])):
            with self.subTest(outcome=outcome):
                other = self.closed_node()
                (gate, reasons), restarts = self.attempt_restarting(other, lambda host, outcome=outcome: outcome)
                self.assertEqual((gate, restarts), ("", []))
        # Every other gate rule failing alone is not a timing problem either.
        other = self.closed_node()
        bad = self.LATE_GW.replace("started_after_file=0", "started_after_file=1").replace(
            "forward=1", "forward=0")
        (gate, reasons), restarts = self.attempt_restarting(
            other, lambda host: (report([sys_peer_line()]).replace(CLEAN_GW, bad), []))
        self.assertEqual((gate, restarts), ("", []))
        self.assertTrue(any("gateway in forward mode: no" in r for r in reasons), reasons)

    def test_a_node_that_changed_while_the_check_ran_is_not_restarted(self):
        slug = self.closed_node()

        def check(host):
            with self.db() as conn:
                conn.execute("UPDATE nodes SET operator_enabled=1 WHERE slug=?", (slug,))
            return self.late_report([sys_peer_line()]), []

        (gate, reasons), restarts = self.attempt_restarting(slug, check)
        self.assertEqual((gate, restarts), ("", []))
        self.assertTrue(any("the node changed while the check ran" in r for r in reasons), reasons)

    def test_a_refused_restart_is_reported_and_the_transaction_is_back(self):
        slug = self.closed_node()
        problem = "the node holds serving back after a late failure, so the gateway was not restarted"
        with patch.object(self.mod, "hub_offnode_check_run",
                          return_value=(self.late_report([sys_peer_line()]), [])), \
                patch.object(self.mod, "hub_offnode_gateway_restart", return_value=problem):
            with self.mod.get_db() as conn:
                conn.commit()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
                gate, reasons = self.mod.hub_offnode_gate_attempt(conn, row)
                self.assertTrue(conn.in_transaction)
                self.assertFalse(self.other_writer_can_write(), "the caller's write transaction is back")
        self.assertEqual(gate, "")
        self.assertEqual(reasons, ["hub-run check: gateway started after the file's last change: no; " + problem])
        self.assertEqual(self.gates(slug), [])

    def test_perf_a_budget_counts_only_the_ssh_checks_that_really_ran(self):
        budget = self.mod._HUB_OFFNODE_SWEEP_BUDGET
        budget.update(checks=0, seconds=0.0)

        def slow(host):
            time.sleep(0.03)
            return None, ["management SSH to the node failed"]

        refused = self.closed_node(reason="heartbeat_stale")
        self.attempt(refused, self.clean_check())
        self.assertEqual(budget, {"checks": 0, "seconds": 0.0}, "a precondition refusal runs no SSH")
        slug = self.closed_node()
        self.attempt(slug, slow)
        self.assertEqual(budget["checks"], 1)
        self.assertGreaterEqual(budget["seconds"], 0.03)
        spent = budget["seconds"]
        self.attempt(slug, slow)  # throttled: answered from memory
        self.assertEqual(budget["checks"], 1)
        self.assertEqual(budget["seconds"], spent)
        self.attempt(self.closed_node(), self.clean_check())
        self.assertEqual(budget["checks"], 2)

    def test_perf_the_sweep_starts_with_an_empty_budget(self):
        self.mod._HUB_OFFNODE_SWEEP_BUDGET.update(checks=99, seconds=999.0)
        with patch.object(self.mod, "NODE_AUTO_REOPEN_ENABLED", False), \
                patch.object(self.mod, "NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED", True):
            self.mod.auto_reopen_health_closed_nodes()
        self.assertEqual(self.mod._HUB_OFFNODE_SWEEP_BUDGET, {"checks": 0, "seconds": 0.0})


# ===================================================== the reopen sweep =====

class SweepCase(dark.DataPlaneDarkStartTests):
    """The real rerun flow on the real hub (as test_installer_sync_hub_fx2), with
    the hub-run SSH check replaced by a recorder."""
    SOURCE = None

    def setUp(self):
        original = harness._extract_main_block
        if self.SOURCE is not None:
            source = self.SOURCE

            def extract():
                lines = source.split("\n")
                for i, line in enumerate(lines):
                    if re.search(r"<<'PYEOF'", line) and "main.py" in line:
                        j = i + 1
                        while lines[j] != "PYEOF":
                            j += 1
                        return "\n".join(lines[i + 1:j]) + "\n"
                raise RuntimeError("main.py heredoc not found")
            harness._extract_main_block = extract
        try:
            super().setUp()
        finally:
            harness._extract_main_block = original
        self.mod.AWG_CANARY_PUBLIC_KEY = CANARY
        self.alerts = []
        self.mod.security_alert = lambda *a, **k: self.alerts.append((a[0], a[1], k.get("details")))
        self.checks = []
        self.next_check = lambda host: (report([sys_peer_line()]), [])
        patcher = patch.object(self.mod, "hub_offnode_check_run", side_effect=self.fake_check)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_check(self, host):
        self.checks.append(host)
        return self.next_check(host)

    def register_rev(self, slug, revision=fx2.REV_A, **overrides):
        return self.mod.register_node(fx2.reg_payload(slug, revision, **overrides),
                                      harness.FakeRequest(path="/api/v1/nodes/register"))

    def live_node(self, slug, revision=fx2.REV_A):
        self.seed_placeholder(slug)
        self.register_rev(slug, revision)
        now = self.mod.utcnow().isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET management_status='ok', data_plane_status='ok', data_plane_ok_at=?,"
                " data_plane_udp_status='ok', data_plane_udp_ok_at=? WHERE slug=?", (now, now, slug))
        self.promote(slug)

    def rerun(self, slug):
        withdrawn = self.mod.withdraw_node_for_deployment(
            slug, harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/withdraw"), x_node_token=dark.NODE_TOKEN)
        time.sleep(0.002)
        self.register_rev(slug)
        return self.mod.complete_node_deployment(
            slug, self.mod.DeploymentWithdrawalCompletion(withdrawal_id=withdrawn["withdrawal_id"]),
            harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/complete"), x_node_token=dark.NODE_TOKEN)

    def confirm_cleanup(self, slug):
        """The closure resync (node I/O stubbed) confirms the cleanup after the closure."""
        health = ("management_status", "management_checked_at", "management_error")
        before = tuple(self.node(slug)[column] for column in health)
        with patch.object(self.mod, "sync_peer_to_node", return_value=True), \
                patch.object(self.mod, "sync_winn3_registry_to_node", return_value=True), \
                patch.object(self.mod, "remove_peer_from_node", return_value=True), \
                patch.object(self.mod, "verify_node_management_access", return_value=True):
            self.mod.resync_active_peers_to_node(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET management_status = ?, management_checked_at = ?, management_error = ?"
                         " WHERE slug = ?", (*before, slug))

    def ready_rerun(self, slug):
        """A completed rerun for which every reopen condition except the gate holds."""
        self.live_node(slug)
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        self.confirm_cleanup(slug)
        now = self.mod.utcnow()
        later = (now + timedelta(seconds=5)).isoformat()
        with self.db() as conn:
            closed_at = conn.execute("SELECT health_closed_at FROM nodes WHERE slug=?", (slug,)).fetchone()[0]
            conn.execute(
                "UPDATE nodes SET last_heartbeat=?, status='online', data_plane_green_streak=?,"
                " data_plane_green_since=?, data_plane_udp_carry_status='ok', data_plane_udp_carry_ok_at=?"
                " WHERE slug=?", (now.isoformat(), self.mod.NODE_AUTO_REOPEN_PROOFS + 5,
                                  (self.mod.parse_iso_datetime(closed_at) + timedelta(seconds=1)).isoformat(),
                                  later, slug))
            conn.execute("UPDATE node_closure_cleanup SET confirmed_at=? WHERE slug=?", (later, slug))
        self.mod._NODE_AUTO_REOPEN_BASELINE[slug] = ("baseline", 0)

    def reopen(self):
        with patch.object(self.mod, "node_auto_reopen_arm", return_value=self.mod.utcnow().isoformat()):
            return self.mod.auto_reopen_health_closed_nodes()

    def gate_rows(self, slug, source="hub"):
        """The gate records of one source (promote() in live_node leaves an operator one)."""
        with self.db() as conn:
            return conn.execute("SELECT * FROM node_offnode_gates WHERE slug=? AND source=? ORDER BY recorded_at",
                                (slug, source)).fetchall()


class SweepTests(SweepCase):
    def test_hl_f3_the_rerun_closure_ends_a_streak_that_began_before_it(self):
        """hub-lite FINDINGS HL-F3, the installer_rerun closure: the L84 gate
        counts only a streak that began after the closure, so the completion
        ends an earlier one and the REAL prober's next green run starts it."""
        slug = "streak"
        self.live_node(slug)
        probe = dark.load_real_dataplane_probe()

        def green():
            time.sleep(0.002)
            with self.db() as conn:
                probe["apply_verdicts"](conn, slug, ("reachable", "recorded"), ("unconfigured", "not configured"),
                                        ("unconfigured", "not configured"))
        for _ in range(3):
            green()
        self.assertEqual(self.node(slug)["data_plane_green_streak"], 3)
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        row = self.node(slug)
        self.assertEqual(row["health_closed_reason"], "installer_rerun")
        self.assertEqual((row["data_plane_green_streak"], row["data_plane_green_since"]), (0, None))
        reason = "no healthy-proof streak that began after the closure"

        def held():
            with self.db() as conn:
                current = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
                return reason in self.mod.node_auto_reopen_failures(conn, current, self.mod.utcnow().isoformat())
        self.assertTrue(held())
        green()
        row = self.node(slug)
        self.assertGreater(row["data_plane_green_since"], row["health_closed_at"])
        self.assertFalse(held())

    def test_all_else_green_the_hub_runs_the_check_and_reopens_the_node(self):
        slug = "go"
        self.ready_rerun(slug)
        out = self.reopen()
        self.assertEqual(self.checks, [self.node(slug)["ssh_host"]], "one SSH check")
        self.assertIn(slug, out["reopened"], out)
        row = self.node(slug)
        self.assertEqual(row["operator_enabled"], 1)
        self.assertEqual(row["latch_cause"], "auto_reopen_installer_rerun")
        rows = self.gate_rows(slug)
        self.assertEqual([r["source"] for r in rows], ["hub"])
        self.assertEqual(rows[0]["used_for"], "auto_reopened", "consumed by the reopen")
        with self.db() as conn:
            event = conn.execute("SELECT * FROM node_promotion_events WHERE slug=? AND "
                                 "operator_source_hash='auto_reopen_installer_rerun'", (slug,)).fetchone()
        self.assertEqual(event["evidence_sha256"], rows[0]["gate_sha256"], "the hub gate is the evidence")

    def test_a_used_hub_record_cannot_open_the_next_closure(self):
        slug = "once"
        self.ready_rerun(slug)
        self.assertIn(slug, self.reopen()["reopened"])
        gate = self.gate_rows(slug)[0]["gate_sha256"]
        with self.db() as conn:
            self.assertIn("gate record already used",
                          self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True))

    def test_a_failing_check_holds_the_node_with_its_reasons_and_raises_the_notice(self):
        slug = "held"
        self.ready_rerun(slug)
        self.next_check = lambda host: (report([awg_peer_line(CORE_KEY, CORE_EXIT)]), [])
        out = self.reopen()
        self.assertIn(slug, out["held"], out)
        gate_lines = [f for f in out["held"][slug] if f.startswith("offnode gate: ")]
        self.assertTrue(any("hub-run check: 1 AWG peer(s) present" in f for f in gate_lines), out["held"][slug])
        self.assertEqual(len(gate_lines), len(out["held"][slug]), "the gate is the only thing holding it")
        self.assertEqual(out["gate_notices"], [slug])
        notice = [a for a in self.alerts if a[1] == GATE_NOTICE]
        self.assertEqual(len(notice), 1)
        self.assertTrue(any("hub-run check" in f for f in notice[0][2]["offnode_gate"]), notice)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        self.assertEqual(self.gate_rows(slug), [])

    def test_an_ssh_failure_holds_the_node_and_an_operator_record_still_opens_it(self):
        slug = "ssh-down"
        self.ready_rerun(slug)
        self.next_check = lambda host: (None, ["management SSH to the node failed"])
        out = self.reopen()
        self.assertIn("offnode gate: hub-run check: management SSH to the node failed", out["held"][slug])
        gate = self.offnode_gate(slug)  # the operator path: a record the operator posted
        self.mod._HUB_OFFNODE_GATE_LAST.clear()
        out = self.reopen()
        self.assertIn(slug, out["reopened"], out)
        self.assertEqual(len(self.checks), 1, "the operator record satisfied the gate; no second SSH")
        with self.db() as conn:
            used = conn.execute("SELECT used_for FROM node_offnode_gates WHERE gate_sha256=?", (gate,)).fetchone()
        self.assertEqual(used[0], "auto_reopened")
        self.assertEqual(self.gate_rows(slug), [], "no hub record was needed")

    def test_the_builder_runs_only_when_every_other_condition_passes(self):
        slug = "other-fails"
        self.ready_rerun(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET last_heartbeat=? WHERE slug=?",
                         ((self.mod.utcnow() - timedelta(days=2)).isoformat(), slug))
        out = self.reopen()
        self.assertIn("heartbeat is absent or stale", out["held"][slug])
        self.assertEqual(self.checks, [], "no SSH while anything else fails")
        # Each other condition on its own keeps it from running.
        for name, sql in (
            ("carry proof", "UPDATE nodes SET data_plane_udp_carry_status='failed' WHERE slug=?"),
            ("management", "UPDATE nodes SET management_status='failed' WHERE slug=?"),
            ("streak", "UPDATE nodes SET data_plane_green_streak=0 WHERE slug=?"),
        ):
            with self.subTest(name=name):
                other = f"other-{name.split()[0]}"
                self.ready_rerun(other)
                with self.db() as conn:
                    conn.execute(sql, (other,))
                self.reopen()
                self.assertNotIn(self.node(other)["ssh_host"], self.checks)

    def test_the_builder_does_not_run_while_an_unused_record_exists(self):
        slug = "has-record"
        self.ready_rerun(slug)
        self.offnode_gate(slug)
        out = self.reopen()
        self.assertEqual(self.checks, [])
        self.assertIn(slug, out["reopened"], out)

    def test_the_builder_does_not_run_for_an_expired_window(self):
        slug = "expired"
        self.ready_rerun(slug)
        old = (self.mod.utcnow() - timedelta(seconds=self.mod.NODE_INSTALLER_RERUN_REOPEN_WINDOW_SECONDS + 60))
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_completed_at=? WHERE slug=?", (old.isoformat(), slug))
        out = self.reopen()
        self.assertEqual(self.checks, [], "no SSH for a closure that is about to expire")
        self.assertIn(slug, out["installer_rerun_expired"])
        self.assertIsNone(self.node(slug)["health_closed_at"])

    def test_the_builder_does_not_run_for_a_plain_health_closure(self):
        slug = "plain"
        self.live_node(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=0, health_closed_at=?, health_closed_reason='heartbeat_stale'"
                         " WHERE slug=?", (self.mod.utcnow().isoformat(), slug))
        self.reopen()
        self.assertEqual(self.checks, [])
        self.assertEqual(self.gate_rows(slug), [])

    def test_a_failed_check_is_not_repeated_on_the_next_sweep(self):
        slug = "throttled"
        self.ready_rerun(slug)
        self.next_check = lambda host: (None, ["management SSH to the node failed"])
        self.reopen()
        self.reopen()
        self.assertEqual(len(self.checks), 1)

    def test_a_gate_that_appears_makes_the_next_sweep_open_the_node(self):
        slug = "recovers"
        self.ready_rerun(slug)
        self.next_check = lambda host: (None, ["management SSH to the node failed"])
        self.assertIn(slug, self.reopen()["held"])
        self.mod._HUB_OFFNODE_GATE_LAST.clear()
        self.next_check = lambda host: (report([sys_peer_line()]), [])
        self.assertIn(slug, self.reopen()["reopened"])

    def test_a_node_that_changes_during_the_check_is_not_reopened_on_that_check(self):
        slug = "moves"
        self.ready_rerun(slug)

        def check(host):
            with self.db() as conn:
                conn.execute("UPDATE nodes SET deployment_withdrawal_id='w-77' WHERE slug=?", (slug,))
            return report([sys_peer_line()]), []

        self.next_check = check
        out = self.reopen()
        self.assertNotIn(slug, out["reopened"])
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        self.assertEqual(self.gate_rows(slug), [])

    # ---- round 2 (Turn 1 votes): one liveness fix, the write-lock fixes, H6-PERF ----

    def hub_attempt(self, slug):
        """One hub-run attempt the way the sweep makes it; leaves an unused hub record."""
        with self.mod.get_db() as conn:
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()
            gate, reasons = self.mod.hub_offnode_gate_attempt(conn, row)
            conn.commit()
        self.assertEqual(reasons, [])
        return gate

    def bump_cleanup(self, slug, seconds=30):
        """A closure resync re-confirms the cleanup: every record taken before it stops verifying."""
        later = (self.mod.utcnow() + timedelta(seconds=seconds)).isoformat()
        with self.db() as conn:
            conn.execute("UPDATE node_closure_cleanup SET confirmed_at=? WHERE slug=?", (later, slug))

    def test_a_stale_unused_hub_record_does_not_stop_the_builder(self):
        slug = "stale"
        self.ready_rerun(slug)
        first = self.hub_attempt(slug)
        self.bump_cleanup(slug)
        with self.db() as conn:
            self.assertIn("closure cleanup changed after the gate was recorded",
                          self.mod.verify_offnode_gate_for_use(conn, slug, first, allow_hub_source=True))
        out = self.reopen()
        self.assertEqual(len(self.checks), 2, "the stale record is not a reason to skip the check")
        self.assertIn(slug, out["reopened"], out)
        rows = self.gate_rows(slug)
        self.assertEqual(len(rows), 2)
        self.assertIsNone(rows[0]["used_at"], "the stale record stays unused")
        self.assertEqual(rows[1]["used_for"], "auto_reopened", "the new record opened the node")
        self.assertNotEqual(rows[0]["gate_sha256"], rows[1]["gate_sha256"])

    def test_a_valid_unused_hub_record_is_used_without_a_second_check(self):
        slug = "fresh-record"
        self.ready_rerun(slug)
        gate = self.hub_attempt(slug)
        out = self.reopen()
        self.assertEqual(len(self.checks), 1, "the record in hand is enough")
        self.assertIn(slug, out["reopened"], out)
        self.assertEqual(self.gate_rows(slug)[0]["gate_sha256"], gate)
        self.assertEqual(self.gate_rows(slug)[0]["used_for"], "auto_reopened")

    def test_a_stale_operator_record_is_never_replaced_by_a_hub_record(self):
        slug = "op-stale"
        self.ready_rerun(slug)
        self.offnode_gate(slug)
        self.bump_cleanup(slug)
        out = self.reopen()
        self.assertEqual(self.checks, [], "an operator record is never replaced by the hub")
        self.assertIn(slug, out["held"], out)
        self.assertEqual(self.gate_rows(slug), [])
        self.assertEqual(self.node(slug)["operator_enabled"], 0)

    def test_state_that_worsens_during_the_check_holds_the_node(self):
        slug = "drift"
        self.ready_rerun(slug)

        def check(host):
            with self.db() as conn:
                conn.execute("UPDATE nodes SET data_plane_udp_carry_status='failed', status='offline' WHERE slug=?",
                             (slug,))
            return report([sys_peer_line()]), []

        self.next_check = check
        out = self.reopen()
        self.assertNotIn(slug, out["reopened"])
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        self.assertEqual(len(self.gate_rows(slug)), 1, "the record was written; the row is judged again with it")

    def test_recovery_that_regresses_during_the_check_holds_the_node(self):
        slug = "regress"
        self.ready_rerun(slug)
        state = {"ok": True}
        self.mod._NODE_AUTO_REOPEN_ARMED_AT = self.mod.utcnow().isoformat()
        self.addCleanup(setattr, self.mod, "_NODE_AUTO_REOPEN_ARMED_AT", None)

        def view(conn):
            return {"paired": state["ok"], "complete": state["ok"], "budget_trusted": state["ok"]}

        def check(host):
            state["ok"] = False
            return report([sys_peer_line()]), []

        self.next_check = check
        with patch.object(self.mod, "winn3_recovery_state", side_effect=view):
            out = self.mod.auto_reopen_health_closed_nodes()
        self.assertNotIn(slug, out["reopened"], out)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        self.assertIn("authority recovery is not complete in this hub process", out["held"][slug])

    def test_a_superseding_closure_is_not_expired_by_a_failed_check_on_the_old_row(self):
        slug = "superseded"
        self.ready_rerun(slug)
        window = self.mod.NODE_INSTALLER_RERUN_REOPEN_WINDOW_SECONDS
        real_now = self.mod.utcnow
        offset = {"s": 0}
        nearly = real_now() - timedelta(seconds=window - 10)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_completed_at=? WHERE slug=?", (nearly.isoformat(), slug))
        successor = {}

        def check(host):
            offset["s"] = 20  # the SSH run took 20 s; the old row's window is now over
            now = real_now() + timedelta(seconds=20)
            successor["completed"] = now.isoformat()
            with self.db() as conn:
                conn.execute("UPDATE nodes SET deployment_completed_at=?, health_closed_at=? WHERE slug=?",
                             (now.isoformat(), now.isoformat(), slug))
            return None, ["management SSH to the node failed"]

        self.next_check = check
        with patch.object(self.mod, "utcnow", side_effect=lambda: real_now() + timedelta(seconds=offset["s"])):
            out = self.reopen()
        self.assertNotIn(slug, out["installer_rerun_expired"], out)
        row = self.node(slug)
        self.assertEqual(row["health_closed_reason"], "installer_rerun", "the newer closure survives")
        self.assertEqual(row["health_closed_at"], successor["completed"])
        self.assertNotEqual(row["latch_cause"], "installer_rerun_expired")
        self.assertTrue(any("node changed while the hub-run check ran" in f for f in out["held"][slug]), out["held"])
        self.assertFalse([a for a in self.alerts if "reopen window expired" in a[1]], self.alerts)

    def test_a_node_removed_during_the_check_is_held_not_crashed(self):
        slug = "vanishes"
        self.ready_rerun(slug)

        def check(host):
            with self.db() as conn:
                conn.execute("DELETE FROM nodes WHERE slug=?", (slug,))
            return None, ["management SSH to the node failed"]

        self.next_check = check
        out = self.reopen()
        self.assertEqual(out["held"][slug], ["offnode gate: node disappeared while the hub-run check ran"])
        self.assertEqual(out["reopened"], [])

    # ---- H6-PERF ----

    def ready_reruns(self, count):
        slugs = [f"wave-{index}" for index in range(count)]
        for slug in slugs:
            self.ready_rerun(slug)
        return slugs

    def test_perf_a_sweep_runs_at_most_the_capped_number_of_hub_checks(self):
        slugs = self.ready_reruns(self.mod.HUB_OFFNODE_SWEEP_MAX_CHECKS + 1)
        out = self.reopen()
        cap = self.mod.HUB_OFFNODE_SWEEP_MAX_CHECKS
        self.assertEqual(len(self.checks), cap)
        self.assertEqual(out["reopened"], slugs[:cap])
        late = slugs[cap]
        self.assertIn("hub-run off-node check deferred to the next sweep (per-sweep check limit)", out["held"][late])
        self.assertEqual(out["gate_notices"], [], "a deferral is not a gate failure and raises no notice")
        self.assertEqual(self.node(late)["operator_enabled"], 0)
        # The next sweep picks the deferred node up.
        out = self.reopen()
        self.assertEqual(out["reopened"], [late], out)
        self.assertEqual(len(self.checks), cap + 1)

    def test_perf_a_one_slug_pass_beside_the_sweep_keeps_the_sweep_cap(self):
        # P-13's proof watch runs the one-slug pass in its own thread while the
        # fleet sweep is inside a hub-run check. That pass must spend the
        # sweep's budget, never reset it.
        cap = self.mod.HUB_OFFNODE_SWEEP_MAX_CHECKS
        slugs = self.ready_reruns(cap + 3)
        watched = slugs[-1]
        # The watched node failed its check moments ago, so its own pass is
        # answered from the throttle with no SSH.
        self.mod._HUB_OFFNODE_GATE_LAST[watched] = (time.monotonic(), ["management SSH to the node failed"])
        watch_passes = []

        def check(host):
            watch_passes.append(self.mod.evaluate_reopen_on_last_proof(watched))
            return None, ["management SSH to the node failed"]

        self.next_check = check
        self.reopen()
        self.assertTrue(watch_passes and all(p is not None for p in watch_passes),
                        "anti-vacuity: the watch ran the one-slug pass")
        self.assertNotIn(self.node(watched)["ssh_host"], self.checks, "the watched node took no SSH")
        self.assertEqual(len(self.checks), cap, "the sweep starts at most the capped number of hub checks")

    def test_perf_a_sweep_stops_starting_checks_once_its_time_is_spent(self):
        slugs = self.ready_reruns(3)

        def slow(host):
            time.sleep(0.06)
            return report([sys_peer_line()]), []

        self.next_check = slow
        with patch.object(self.mod, "HUB_OFFNODE_SWEEP_MAX_CHECKS", 99), \
                patch.object(self.mod, "HUB_OFFNODE_SWEEP_MAX_SECONDS", 0.05):
            out = self.reopen()
        self.assertEqual(len(self.checks), 1, "one slow check used up the sweep's time")
        self.assertEqual(out["reopened"], slugs[:1])
        self.assertEqual(sorted(out["held"]), slugs[1:])

    def test_perf_throttled_nodes_do_not_spend_the_sweep_budget(self):
        slugs = self.ready_reruns(3)
        cap = self.mod.HUB_OFFNODE_SWEEP_MAX_CHECKS
        # The first nodes fail their check and are throttled; the budget only counts real SSH.
        self.next_check = lambda host: (None, ["management SSH to the node failed"])
        self.reopen()
        self.assertEqual(len(self.checks), cap)
        self.next_check = lambda host: (report([sys_peer_line()]), [])
        out = self.reopen()
        # Throttled nodes answer from memory (no SSH); the third one gets the check.
        self.assertEqual(len(self.checks), cap + 1)
        self.assertEqual(out["reopened"], [slugs[cap]], out)

    def test_perf_nodes_whose_check_keeps_failing_do_not_starve_a_later_node(self):
        bad = self.ready_reruns(self.mod.HUB_OFFNODE_SWEEP_MAX_CHECKS)
        good = "zz-good"
        self.ready_rerun(good)
        bad_hosts = {self.node(slug)["ssh_host"] for slug in bad}
        self.next_check = lambda host: ((None, ["management SSH to the node failed"]) if host in bad_hosts
                                        else (report([sys_peer_line()]), []))
        reopened = []
        for _sweep in range(3):
            reopened += self.reopen()["reopened"]
            # A real sweep sleeps FLEET_AVAILABILITY_AUDIT_SECONDS (>= 30, default 120) between passes,
            # so the 60 s retry throttle of the failing nodes has expired by the next one.
            for slug, (at, reasons) in list(self.mod._HUB_OFFNODE_GATE_LAST.items()):
                self.mod._HUB_OFFNODE_GATE_LAST[slug] = (at - self.mod.HUB_OFFNODE_GATE_RETRY_SECONDS - 1, reasons)
        self.assertEqual(reopened, [good])

    def test_perf_persistent_failures_do_not_starve_a_deferred_node(self):
        slugs = self.ready_reruns(3)
        self.next_check = lambda host: (
            None, ["management SSH to the node failed"]
        )
        clock = [1000.0]
        fake_time = types.SimpleNamespace(
            monotonic=lambda: clock[0],
            time=time.time,
            sleep=time.sleep,
        )
        with patch.object(self.mod, "time", fake_time):
            self.reopen()
            self.assertNotIn(slugs[2], self.mod._HUB_OFFNODE_GATE_LAST)
            clock[0] += 120
            self.reopen()
            self.assertIn(slugs[2], self.mod._HUB_OFFNODE_GATE_LAST)

    def test_perf_the_alert_drain_runs_before_and_after_the_reopen_pass(self):
        import asyncio
        order = []

        async def stop(_seconds):
            raise asyncio.CancelledError()

        steps = {name: (lambda name=name: order.append(name)) for name in (
            "audit_fleet_availability_once", "audit_winn3_contract_once", "auto_reopen_health_closed_nodes",
            "drain_node_latch_events", "sync_awg_canary_peers_once")}
        with contextlib.ExitStack() as stack:
            for name, fn in steps.items():
                stack.enter_context(patch.object(self.mod, name, side_effect=lambda *a, fn=fn, **k: fn()))
            stack.enter_context(patch.object(self.mod.asyncio, "sleep", stop))
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(self.mod.fleet_availability_sweep_loop())
        # The canary peer push is its own task (H5 Turn 2, awg_canary_sync_loop),
        # so it stays patched here and must not appear in the sweep's order.
        self.assertEqual(order, [
            "audit_fleet_availability_once", "audit_winn3_contract_once", "drain_node_latch_events",
            "auto_reopen_health_closed_nodes", "drain_node_latch_events"])


PROBE_HEADER = "cat > /usr/local/lib/wins_node_dataplane_probe.py <<'DPPROBEEOF'"


def load_probe(source=None):
    """The REAL prober (the wins_node_dataplane_probe.py heredoc), from the
    installer on disk or from mutated installer text (the mutant table's S)."""
    if source is None:
        return dark.load_real_dataplane_probe()
    block = source.split(PROBE_HEADER, 1)[1].split("\nDPPROBEEOF", 1)[0]
    namespace = {"__name__": "wins_node_dataplane_promotion_lifecycle_test"}
    exec(compile(block, "wins_node_dataplane_probe.py", "exec"), namespace)
    return namespace


class ClosureStreakTests(SweepCase):
    """FINAL4 F4-HL: the L84 reopen gate (node_auto_reopen_failures) counts only
    a healthy-proof streak that began after the closure. The stale sweep
    (mark_stale_nodes_offline: the data closure and the heartbeat_stale flip)
    and a prober run that itself closes the node record automatic closures
    that gate judges, so each ends the streak in the same write. The REAL
    prober (apply_verdicts, from the same source as the hub) writes every
    streak here."""

    REASON = "no healthy-proof streak that began after the closure"
    GREEN = (("reachable", "recorded"), ("unconfigured", "not configured"), ("unconfigured", "not configured"))
    PAUSED = (("probe_error", "capture consumed"), ("unconfigured", "not configured"),
              ("unconfigured", "not configured"))

    def run_probe(self, slug, verdicts, runs=1):
        probe = load_probe(self.SOURCE)
        out = None
        for _ in range(runs):
            time.sleep(0.002)
            with self.db() as conn:
                out = probe["apply_verdicts"](conn, slug, *verdicts)
        return out

    def streak(self, slug):
        row = self.node(slug)
        return row["data_plane_green_streak"], row["data_plane_green_since"]

    def held(self, slug):
        with self.db() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            return self.REASON in self.mod.node_auto_reopen_failures(conn, row, self.mod.utcnow().isoformat())

    def sweep(self):
        with self.db() as conn:
            self.mod.mark_stale_nodes_offline(conn)

    def age_proof(self, slug):
        """The proof outlived DATA_PLANE_HARD_STALE_MINUTES while paused runs
        carried the streak (time passing, written directly)."""
        stale = (self.mod.utcnow() - timedelta(minutes=self.mod.DATA_PLANE_HARD_STALE_MINUTES + 1)).isoformat()
        with self.db() as conn:
            conn.execute("UPDATE nodes SET data_plane_ok_at=? WHERE slug=?", (stale, slug))

    def healthy_streak(self, slug, runs=3):
        self.live_node(slug)
        self.run_probe(slug, self.GREEN, runs)
        self.assertEqual(self.node(slug)["operator_enabled"], 1)
        self.assertEqual(self.streak(slug)[0], runs)

    def assert_new_streak_counts(self, slug):
        self.assertEqual(self.streak(slug), (0, None), "the closure ended the earlier streak")
        self.assertTrue(self.held(slug), "nothing is proven after the closure yet")
        self.run_probe(slug, self.GREEN)
        row = self.node(slug)
        self.assertEqual(row["data_plane_green_streak"], 1)
        self.assertGreater(row["data_plane_green_since"], row["health_closed_at"])
        self.assertFalse(self.held(slug))

    def test_f4_hl_the_sweeps_data_closure_ends_the_streak(self):
        slug = "sweep-data"
        self.healthy_streak(slug)
        self.run_probe(slug, self.PAUSED)          # a test not conducted pauses the streak
        self.assertEqual(self.streak(slug)[0], 3)
        self.age_proof(slug)
        self.sweep()
        row = self.node(slug)
        self.assertEqual((row["operator_enabled"], row["health_closed_reason"], row["latch_cause"]),
                         (0, "proof_stale", "health_proof_stale"))
        self.assert_new_streak_counts(slug)

    def test_f4_hl_the_sweeps_heartbeat_stale_closure_ends_the_streak(self):
        slug = "sweep-heartbeat"
        self.healthy_streak(slug)
        old = (self.mod.utcnow() - timedelta(seconds=self.mod.NODE_HEARTBEAT_STALE_SECONDS + 60)).isoformat()
        with self.db() as conn:
            conn.execute("UPDATE nodes SET last_heartbeat=? WHERE slug=?", (old, slug))
        self.sweep()
        row = self.node(slug)
        self.assertEqual((row["operator_enabled"], row["status"], row["health_closed_reason"]),
                         (0, "offline", "heartbeat_stale"))
        closed_at = row["health_closed_at"]
        self.assertEqual(self.streak(slug), (0, None), "the closure ended the earlier streak")
        self.assertTrue(self.held(slug))
        time.sleep(0.002)
        self.register_rev(slug)                    # the node heartbeats again (the real route)
        self.assertEqual(self.node(slug)["status"], "online")
        self.run_probe(slug, self.GREEN)
        row = self.node(slug)
        self.assertEqual(row["data_plane_green_streak"], 1)
        self.assertGreater(row["data_plane_green_since"], closed_at)
        self.assertFalse(self.held(slug))
        # A row that is already closed keeps its closure and a streak that
        # began after it: only the 1->0 flip is a new closure.
        since = row["data_plane_green_since"]
        with self.db() as conn:
            conn.execute("UPDATE nodes SET last_heartbeat=? WHERE slug=?", (old, slug))
        self.sweep()
        row = self.node(slug)
        self.assertEqual((row["status"], row["health_closed_at"]), ("offline", closed_at))
        self.assertEqual(self.streak(slug), (1, since))

    def test_f4_hl_a_green_prober_run_that_closes_ends_the_streak(self):
        slug = "probe-close"
        self.healthy_streak(slug)
        self.run_probe(slug, self.PAUSED)
        self.age_proof(slug)
        out = self.run_probe(slug, self.GREEN)     # healthy now, but the proof had aged: it closes
        self.assertTrue(out["promotion_consumed"], out)
        self.assertEqual(out["close_reason"], "proof_stale")
        row = self.node(slug)
        self.assertEqual((row["operator_enabled"], row["health_closed_reason"]), (0, "proof_stale"))
        self.assertEqual(out["green_streak"], 0)
        self.assert_new_streak_counts(slug)

    def test_f4_hl_a_streak_that_starts_on_the_closing_run_does_not_hold_the_node(self):
        # The gate needs since strictly after the closure; a streak stored by
        # the closing run itself would begin at the closure and never count.
        slug = "probe-equal"
        self.live_node(slug)
        self.age_proof(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET data_plane_green_streak=0, data_plane_green_since=NULL WHERE slug=?",
                         (slug,))
        out = self.run_probe(slug, self.GREEN)
        self.assertTrue(out["promotion_consumed"], out)
        self.assertEqual(self.streak(slug), (0, None))
        self.run_probe(slug, self.GREEN, 2)
        row = self.node(slug)
        self.assertEqual(row["data_plane_green_streak"], 2)
        self.assertGreater(row["data_plane_green_since"], row["health_closed_at"])
        self.assertFalse(self.held(slug))


class FreshInstallClassTests(SweepCase):
    """3.16 / 3.17: the same builder and the same acceptance rule serve a node
    closed as fresh_install. The sweep branch that opens it is H7's."""

    def test_the_readiness_gate_accepts_a_hub_record_for_a_fresh_install_closure(self):
        slug = "fresh"
        self.live_node(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=0, health_closed_at=?, health_closed_reason='fresh_install',"
                         " deployment_completed_at=? WHERE slug=?",
                         (self.mod.utcnow().isoformat(), self.mod.utcnow().isoformat(), slug))
        self.confirm_cleanup(slug)
        with self.mod.get_db() as conn:
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            gate, reasons = self.mod.hub_offnode_gate_attempt(conn, row)
            self.assertEqual(reasons, [])
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            readiness = self.mod.node_promotion_readiness_failures(
                conn, row, gate, allow_hub_gate=str(row["health_closed_reason"]) in
                self.mod.HUB_OFFNODE_GATE_CLOSURE_REASONS)
            self.assertFalse([f for f in readiness if f.startswith("offnode gate: ")], readiness)
            failures = self.mod.node_auto_reopen_failures(conn, row, self.mod.utcnow().isoformat())
            self.assertFalse([f for f in failures if f.startswith("offnode gate: ")], failures)
        # Manual promotion of the same node still refuses the hub record.
        with self.assertRaises(harness.HTTPException) as caught:
            self.mod.admin_set_node_tier(self.request, slug=slug, tier="premium", evidence_sha256=gate,
                                         confirm_slug=slug, x_admin_token=dark.ADMIN_TOKEN)
        self.assertIn("accepted only for an installer rerun or fresh install reopen", str(caught.exception.detail))


# ================================================================ static ====

class StaticTests(unittest.TestCase):
    def test_the_stub_text_is_gone(self):
        text = hub_source()
        self.assertNotIn("the hub-run off-node gate is not built yet", text)
        self.assertNotIn("Ruling D.ii, NOT BUILT", text)

    def test_the_hub_pin_equals_the_node_pin_when_the_data_plane_carries_one(self):
        """DP holds WINN3_OFFNODE_CHECK_SHA256 once S4 lands; the two change together."""
        pin = re.search(r'^HUB_OFFNODE_CHECK_SHA256 = "([0-9a-f]{64})"', hub_source(), re.M).group(1)
        self.assertEqual(hashlib.sha256(CHECK_SCRIPT.read_bytes()).hexdigest(), pin)
        data = DATA_INSTALLER.read_text(encoding="utf-8")
        node = re.search(r"^WINN3_OFFNODE_CHECK_SHA256=([0-9a-f]{64})$", data, re.M)
        if node is None:
            self.skipTest("this tree's data-plane installer has no off-node check yet (S4)")
        self.assertEqual(node.group(1), pin)
        self.assertIn("WINN3_OFFNODE_CHECK_PATH=/usr/local/libexec/winsvpn/wins-offnode-check", data)

    def test_the_hub_path_is_the_one_the_design_names(self):
        self.assertIn('HUB_OFFNODE_CHECK_PATH = "/usr/local/libexec/winsvpn/wins-offnode-check"', hub_source())

    def test_the_testdata_script_is_the_l46_v5_script_with_the_one_exemption(self):
        text = CHECK_SCRIPT.read_text()
        self.assertEqual(text.count("AWGSYSPEER"), 1)
        self.assertEqual(text.count("--canary-pubkey"), 4)
        exemption = ('if [[ -n $CANARY_PUBKEY && $key == "$CANARY_PUBKEY" && $ips_norm == "10.8.255.1/32" ]]; then')
        self.assertIn(exemption, text)
        self.assertEqual(text.count("10.8.255.1"), 2, "the exact address appears only in the rule and its comment")

    def test_the_gate_code_writes_nothing_but_the_gate_row(self):
        body = hub_source().split("def hub_offnode_gate_precondition_failures(", 1)[1].split(
            "def installer_rerun_hub_offnode_gate(", 1)[0]
        self.assertEqual(body.count('"INSERT OR IGNORE INTO node_offnode_gates'), 1)
        self.assertNotIn("UPDATE nodes", body, "the builder never writes the node row")
        self.assertNotIn("operator_enabled = 1", body, "the builder never opens a latch")
        self.assertNotIn("consume_offnode_gate", body, "the builder never consumes a record")


# ============================================================== mutants =====

def mutate(source, old, new, count=1):
    found = source.count(old)
    if found != count:
        raise AssertionError(f"mutant anchor found {found} times, wanted {count}: {old[:70]!r}")
    return source.replace(old, new)


def run_cases(source, cases):
    """Run the given (class, test name) pairs against mutated source. Returns
    the names of those that FAILED."""
    suite = unittest.TestSuite()
    for cls, name in cases:
        mutant = type(f"Mutant_{cls.__name__}", (cls,), {"SOURCE": source})
        suite.addTest(mutant(name))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    return [str(t) for t, _ in result.failures + result.errors]


def _mutant_table():
    S = hub_source()
    rule = "def offnode_system_peer_failures("
    ev = (EvaluatorTests, "test_the_awgsyspeer_rule")
    e2e = (NodeScriptEndToEndTests, "test_the_canary_key_with_a_broader_or_additional_address_fails")
    e2e_core = (NodeScriptEndToEndTests, "test_the_exact_canary_beside_a_core_exit_peer_fails_for_the_core_exit_only")
    rec = (RecordAndVerifyTests, "test_record_and_verify")
    reasons = (RecordAndVerifyTests, "test_the_record_goes_to_both_closure_classes_and_no_other")
    manual = (RecordAndVerifyTests, "test_manual_promotion_and_retirement_refuse_a_hub_record")
    use = (RecordAndVerifyTests, "test_a_hub_record_is_usable_only_by_an_automatic_reopen")
    pre = (RecordAndVerifyTests, "test_the_preconditions_are_the_gate_routes_preconditions")
    used = (RecordAndVerifyTests, "test_a_used_record_never_becomes_usable_again")
    nogate = (RecordAndVerifyTests, "test_no_record_and_another_nodes_record_open_nothing")
    removed = (RecordAndVerifyTests, "test_a_record_that_fails_its_own_verification_is_removed")
    operator_rec = (RecordAndVerifyTests, "test_an_identical_operator_record_is_not_taken_over_as_a_hub_record")
    refail = (RecordAndVerifyTests, "test_a_report_that_fails_the_rules_records_nothing")
    reeval = (RecordAndVerifyTests, "test_a_stored_hub_record_is_re_evaluated_at_use")
    reopen_acc = (RecordAndVerifyTests, "test_the_reopen_failures_accept_a_hub_record_for_both_classes")
    att_ok = (AttemptTests, "test_a_clean_check_records_a_hub_gate_and_returns_its_digest")
    att_lock = (AttemptTests, "test_the_check_runs_without_the_database_write_lock")
    att_back = (AttemptTests, "test_the_transaction_is_open_again_when_the_attempt_returns")
    att_pre = (AttemptTests, "test_preconditions_refuse_before_any_ssh")
    att_retry = (AttemptTests, "test_a_failed_check_is_not_repeated_within_the_retry_window")
    att_move = (AttemptTests, "test_a_node_that_changed_while_the_check_ran_gets_no_record")
    att_fail = (AttemptTests, "test_a_failed_check_is_held_with_its_reasons_and_records_nothing")
    att_name = (AttemptTests, "test_the_named_interface_returns_the_digest_or_the_empty_string")
    att_host = (AttemptTests, "test_the_host_falls_back_to_the_endpoint")
    att_gone = (AttemptTests, "test_a_node_removed_while_the_check_ran_gets_no_record")
    cmd_key = (RemoteCommandTests, "test_the_canary_key_is_always_passed")
    cmd_digest = (RemoteCommandTests, "test_the_digest_is_checked_on_the_copy_and_a_changed_file_never_runs")
    cmd_copy = (RemoteCommandTests, "test_the_bytes_that_were_verified_are_the_bytes_that_run")
    cmd_link = (RemoteCommandTests, "test_a_missing_or_linked_check_is_not_installed")
    cmd_clean = (RemoteCommandTests, "test_the_private_directory_is_removed_after_the_run")
    cmd_status = (RemoteCommandTests, "test_the_script_exit_status_comes_back")
    cmd_alpha = (RemoteCommandTests, "test_only_a_32_byte_base64_key_reaches_the_remote_shell")
    run_codes = (CheckRunTests, "test_every_failure_is_a_named_reason_and_no_report")
    run_partial = (CheckRunTests, "test_a_partial_report_with_a_nonzero_exit_is_never_a_pass")
    run_err = (CheckRunTests, "test_timeouts_and_errors_fail_closed")
    run_clean = (CheckRunTests, "test_a_clean_run_returns_the_report_and_no_reason")
    run_none = (CheckRunTests, "test_no_canary_key_or_no_host_runs_nothing")
    sw_go = (SweepTests, "test_all_else_green_the_hub_runs_the_check_and_reopens_the_node")
    sw_fail = (SweepTests, "test_a_failing_check_holds_the_node_with_its_reasons_and_raises_the_notice")
    sw_order = (SweepTests, "test_the_builder_runs_only_when_every_other_condition_passes")
    sw_rec = (SweepTests, "test_the_builder_does_not_run_while_an_unused_record_exists")
    sw_exp = (SweepTests, "test_the_builder_does_not_run_for_an_expired_window")
    sw_plain = (SweepTests, "test_the_builder_does_not_run_for_a_plain_health_closure")
    sw_throttle = (SweepTests, "test_a_failed_check_is_not_repeated_on_the_next_sweep")
    sw_move = (SweepTests, "test_a_node_that_changes_during_the_check_is_not_reopened_on_that_check")
    fresh = (FreshInstallClassTests, "test_the_readiness_gate_accepts_a_hub_record_for_a_fresh_install_closure")
    sw_op = (SweepTests, "test_an_ssh_failure_holds_the_node_and_an_operator_record_still_opens_it")
    sw_worse = (SweepTests, "test_state_that_worsens_during_the_check_holds_the_node")
    sw_stale = (SweepTests, "test_a_stale_unused_hub_record_does_not_stop_the_builder")
    sw_opstale = (SweepTests, "test_a_stale_operator_record_is_never_replaced_by_a_hub_record")
    sw_validrec = (SweepTests, "test_a_valid_unused_hub_record_is_used_without_a_second_check")
    sw_recovery = (SweepTests, "test_recovery_that_regresses_during_the_check_holds_the_node")
    sw_super = (SweepTests, "test_a_superseding_closure_is_not_expired_by_a_failed_check_on_the_old_row")
    sw_gone = (SweepTests, "test_a_node_removed_during_the_check_is_held_not_crashed")
    perf_cap = (SweepTests, "test_perf_a_sweep_runs_at_most_the_capped_number_of_hub_checks")
    perf_time = (SweepTests, "test_perf_a_sweep_stops_starting_checks_once_its_time_is_spent")
    perf_throttle = (SweepTests, "test_perf_throttled_nodes_do_not_spend_the_sweep_budget")
    perf_loop = (SweepTests, "test_perf_the_alert_drain_runs_before_and_after_the_reopen_pass")
    perf_reset = (AttemptTests, "test_perf_the_sweep_starts_with_an_empty_budget")
    perf_watch = (SweepTests, "test_perf_a_one_slug_pass_beside_the_sweep_keeps_the_sweep_cap")
    perf_budget = (AttemptTests, "test_perf_a_budget_counts_only_the_ssh_checks_that_really_ran")
    perf_starve = (SweepTests, "test_perf_nodes_whose_check_keeps_failing_do_not_starve_a_later_node")
    perf_rotate = (SweepTests, "test_perf_persistent_failures_do_not_starve_a_deferred_node")

    key_digest = "hashlib.sha256(AWG_CANARY_PUBLIC_KEY.encode()).hexdigest()[:16] if AWG_CANARY_PUBLIC_KEY else \"\""
    exact = ("exact = bool(want_key) and len(r) == 5 and r[1] == want_key and r[2] == \"canary\" \\\n"
             "            and r[3] == want_ips and r[4] in OFFNODE_HANDSHAKE_CLASSES")
    return [
        # ---- the exemption (5.6 "Off-node exemption") ----
        ("evaluator exempts every AWGSYSPEER line (no digest check)", S,
         exact, "exact = True", [ev, e2e]),
        ("evaluator ignores the key digest", S,
         "r[1] == want_key and ", "", [ev]),
        ("evaluator ignores the allowed-ips digest (the /24 is exempt)", S,
         " and r[3] == want_ips", "", [ev]),
        ("evaluator expects the digest of the whole /24", S,
         "want_ips = hashlib.sha256(AWG_CANARY_ALLOWED_IPS.encode()).hexdigest()[:16]",
         "want_ips = hashlib.sha256(b\"10.8.255.0/24\").hexdigest()[:16]", [ev]),
        ("evaluator accepts any number of system peer lines", S,
         "if exact and accepted == 0:\n            accepted = 1", "if exact:\n            accepted = 1", [ev]),
        ("evaluator accepts the digest of an empty key when no hub canary key is configured", S,
         'hashlib.sha256(AWG_CANARY_PUBLIC_KEY.encode()).hexdigest()[:16] if AWG_CANARY_PUBLIC_KEY else ""',
         'hashlib.sha256(AWG_CANARY_PUBLIC_KEY.encode()).hexdigest()[:16]', [ev]),
        ("evaluator takes the expected key from the report, not the hub", S,
         key_digest, "(lines[0][1] if lines else \"\")", [ev]),
        ("evaluator never calls the system peer rule", S,
         "    failures += offnode_system_peer_failures(rows)\n", "", [ev]),
        ("evaluator drops the AWGPEER failure (the Core exit peers are exempt)", S,
         'if peers:\n        failures.append(f"{len(peers)} AWG peer(s) present',
         'if False:\n        failures.append(f"{len(peers)} AWG peer(s) present', [ev, e2e, e2e_core]),
        ("evaluator ignores the tag and the handshake class", S,
         ' and r[2] == "canary"', "", [ev]),
        ("evaluator accepts a line with extra fields", S,
         "len(r) == 5 and r[1]", "len(r) >= 5 and r[1]", [ev]),
        # ---- who may use a hub record ----
        ("a hub record is accepted for any closure reason", S,
         '        if not (allow_hub_source and source == "hub" and closed_as is not None\n'
         '                and closed_as["health_closed_reason"] in HUB_OFFNODE_GATE_CLOSURE_REASONS):',
         '        if not (allow_hub_source and source == "hub" and closed_as is not None):', [use, reasons]),
        ("a hub record is accepted without allow_hub_source (manual promotion takes it)", S,
         '        if not (allow_hub_source and source == "hub" and closed_as is not None\n'
         '                and closed_as["health_closed_reason"] in HUB_OFFNODE_GATE_CLOSURE_REASONS):',
         '        if not (source == "hub" and closed_as is not None\n'
         '                and closed_as["health_closed_reason"] in HUB_OFFNODE_GATE_CLOSURE_REASONS):', [manual, use]),
        ("a hub record is accepted for installer_rerun only (fresh_install refused)", S,
         'HUB_OFFNODE_GATE_CLOSURE_REASONS = ("installer_rerun", "fresh_install")',
         'HUB_OFFNODE_GATE_CLOSURE_REASONS = ("installer_rerun",)', [use, fresh, att_ok, reopen_acc]),
        ("any source other than operator is accepted", S,
         'and source == "hub" and closed_as', 'and closed_as', [use]),
        ("the reopen readiness gate takes a hub record for no class", S,
         'allow_hub_gate=str(data.get("health_closed_reason") or "") in HUB_OFFNODE_GATE_CLOSURE_REASONS)',
         'allow_hub_gate=False)', [reopen_acc, sw_go, fresh]),
        ("the reopen readiness gate takes a hub record for installer_rerun only", S,
         'allow_hub_gate=str(data.get("health_closed_reason") or "") in HUB_OFFNODE_GATE_CLOSURE_REASONS)',
         'allow_hub_gate=str(data.get("health_closed_reason") or "") == "installer_rerun")', [reopen_acc, fresh]),
        ("the hub row is written as an operator row", S,
         "NULL, NULL, 'hub')", "NULL, NULL, 'operator')", [rec, manual]),
        ("INSERT OR REPLACE lets a used record be reset", S,
         '"INSERT OR IGNORE INTO node_offnode_gates (gate_sha256, slug, recorded_at, cleanup_confirmed_at,"',
         '"INSERT OR REPLACE INTO node_offnode_gates (gate_sha256, slug, recorded_at, cleanup_confirmed_at,"',
         [used, operator_rec]),
        ("the used or foreign-source check after the insert is dropped", S,
         'if stored is None or stored["source"] != "hub" or stored["used_at"]:',
         'if stored is None:', [used, operator_rec]),
        ("the gate digest ignores the report", S,
         "digest = offnode_gate_digest(slug, expected, confirmed_at, \"\", report_sha)",
         "digest = offnode_gate_digest(slug, expected, confirmed_at, \"\", \"\")", [rec]),
        ("the gate digest names another cleanup time", S,
         "digest = offnode_gate_digest(slug, expected, confirmed_at, \"\", report_sha)",
         "digest = offnode_gate_digest(slug, expected, \"\", \"\", report_sha)", [rec]),
        ("the v3 snapshot digest is not recomputed", S,
         "        expected = offnode_expected_v3_sha256(conn, slug)\n    except Exception:\n"
         "        expected = \"\"\n        failures.append(\"the node's v3 snapshot cannot be computed\")",
         "        expected = \"\"\n    except Exception:\n        expected = \"\"", [rec]),
        ("a refused record stays in the table", S,
         '        conn.execute(\n            "DELETE FROM node_offnode_gates WHERE gate_sha256 = ? AND slug = ? "\n'
         '            "AND source = \'hub\' AND used_at IS NULL", (digest, slug))\n        return "", verify',
         '        return "", verify', [removed]),
        ("the cleanup precondition is dropped", S,
         "    if cleanup is None or cleanup[\"state\"] != \"confirmed\":\n"
         "        failures.append(\"closure cleanup is not confirmed (resync the node first)\")\n    return failures",
         "    return failures", [pre, att_pre]),
        ("the closure class precondition is dropped", S,
         '    if str(data.get("health_closed_reason") or "") not in HUB_OFFNODE_GATE_CLOSURE_REASONS:\n'
         '        failures.append("the node is not closed as an installer rerun or a fresh install")\n',
         "", [reasons, att_pre]),
        ("the latch and retirement precondition is dropped", S,
         '    if node_admits_peer(data) or str(data.get("retired_at") or "").strip():\n'
         '        failures.append("node latch is open or the node is retired")\n', "", [pre, att_pre]),
        ("the withdrawal precondition is dropped", S,
         '        failures.append("node latch is open or the node is retired")\n'
         '    if str(data.get("deployment_withdrawal_id") or "").strip():\n'
         '        failures.append("installer deployment withdrawal is active")\n',
         '        failures.append("node latch is open or the node is retired")\n', [pre, att_pre]),
        # ---- the run ----
        ("the canary key is not passed to the node check", S,
         "bash \"$d/check\" --canary-pubkey {canary_public_key}", "bash \"$d/check\"", [cmd_key, ev]),
        ("the pinned digest is not checked on the node", S,
         "f'[ \"$(sha256sum \"$d/check\" | cut -d\" \" -f1)\" = {HUB_OFFNODE_CHECK_SHA256} ] '\n"
         "        f\"|| exit {HUB_OFFNODE_CHECK_EXIT_DIGEST}; \"\n", "", [cmd_digest]),
        ("the digest is checked but the installed file is what runs", S,
         'bash "$d/check" --canary-pubkey', 'bash "$f" --canary-pubkey', [cmd_copy]),
        ("a linked check is accepted", S,
         '[ -f "$f" ] && [ ! -L "$f" ] || exit', '[ -f "$f" ] || exit', [cmd_link]),
        ("the private directory is left behind", S,
         "trap 'rm -rf -- \\\"$d\\\"' EXIT; ", "", [cmd_clean]),
        ("the canary key alphabet is not checked", S,
         'if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", str(canary_public_key or "")):',
         'if False:', [cmd_alpha]),
        ("the script status is lost behind a trailing command", S,
         "f'bash \"$d/check\" --canary-pubkey {canary_public_key}'",
         "f'bash \"$d/check\" --canary-pubkey {canary_public_key}; true'", [cmd_status]),
        ("a nonzero exit with a report is accepted", S,
         '    if result.returncode != 0:\n        return None, [f"the node-side check exited',
         '    if False:\n        return None, [f"the node-side check exited', [run_partial, run_codes]),
        ("an SSH failure is accepted as an empty pass", S,
         '    if result.returncode == 255:\n        return None, ["management SSH to the node failed"]\n', "", [run_codes]),
        ("a timeout propagates out of the sweep", S,
         '    except subprocess.TimeoutExpired:\n        return None, [f"the node-side check did not finish within '
         '{HUB_OFFNODE_CHECK_TIMEOUT_SECONDS} s"]\n', '    except ZeroDivisionError:\n        return None, ["x"]\n', [run_err]),
        ("an unexpected exception propagates out of the sweep", S,
         "    except Exception as exc:  # fail closed: the sweep must survive any single node",
         "    except (OSError, ValueError) as exc:", [run_err]),
        ("the check runs without a timeout", S,
         "command, timeout=HUB_OFFNODE_CHECK_TIMEOUT_SECONDS, check=False, stdin=subprocess.DEVNULL,",
         "command, check=False, stdin=subprocess.DEVNULL,", [run_clean]),
        ("the check inherits the hub's stdin", S,
         "check=False, stdin=subprocess.DEVNULL,", "check=False,", [run_clean]),
        ("the check runs with the full hub environment", S,
         "capture_output=True, text=True, errors=\"replace\", env=management_ssh_env())\n    except subprocess.TimeoutExpired:",
         "capture_output=True, text=True, errors=\"replace\")\n    except subprocess.TimeoutExpired:", [run_clean]),
        ("an empty report is accepted", S,
         'if not raw.strip() or len(raw) > OFFNODE_GATE_REPORT_MAX_BYTES:', 'if False:', [run_codes]),
        ("a missing canary key still runs the check", S,
         "    if not AWG_CANARY_PUBLIC_KEY:\n        return None, [\"no hub AWG canary public key is configured (AWG_CANARY_PUBLIC_KEY)\"]\n",
         "", [run_none]),
        # ---- the attempt ----
        ("the check holds the database write lock", S,
         "    conn.commit()\n    started = time.monotonic()\n",
         "    started = time.monotonic()\n", [att_lock]),
        ("the write transaction is not begun again", S,
         "        conn.execute(\"BEGIN IMMEDIATE\")\n    fresh = ", "        pass\n    fresh = ", [att_back, att_ok]),
        ("a node that changed during the check is recorded anyway", S,
         "    if report is not None and moved:", "    if False:", [att_move, sw_move]),
        ("the stable fields are not compared", S,
         "if str(dict(fresh).get(k) or \"\") != str(data.get(k) or \"\")]", "if False]", [att_move, sw_move]),
        ("a node that vanished is recorded against", S,
         '    if fresh is None:\n        return "", ["node not found"]\n', "    fresh = fresh or node\n", [att_gone]),
        ("a failed check is repeated on every sweep", S,
         "    if last is not None and time.monotonic() - last[0] < HUB_OFFNODE_GATE_RETRY_SECONDS:\n"
         "        return \"\", list(last[1])\n", "", [att_retry, sw_throttle]),
        ("a failed check is never retried", S,
         "time.monotonic() - last[0] < HUB_OFFNODE_GATE_RETRY_SECONDS:", "True:", [att_retry]),
        ("a pass does not clear the retry memory", S,
         "        _HUB_OFFNODE_GATE_LAST.pop(slug, None)\n", "", [att_retry]),
        ("a failed check records no reasons", S,
         '    reasons = ["hub-run check: " + reason for reason in reasons]', "    reasons = []", [att_fail, sw_fail]),
        ("the host is taken from the endpoint only", S,
         "host = str(data.get(\"ssh_host\") or \"\").strip() or extract_node_host(str(data.get(\"endpoint\") or \"\"))",
         "host = extract_node_host(str(data.get(\"endpoint\") or \"\"))", [att_host, att_ok]),
        ("the named interface returns the reasons, not the digest", S,
         "    return hub_offnode_gate_attempt(conn, node)[0]", "    return hub_offnode_gate_attempt(conn, node)[1]", [att_name]),
        # ---- the sweep ----
        ("the builder runs before the other conditions pass", S,
         '                builder_due = not [f for f in failures if not f.startswith("offnode gate: ")] and \\\n'
         '                        not existing_gate and \\\n',
         '                builder_due = not existing_gate and \\\n', [sw_order]),
        ("the builder runs although an unused record exists", S,
         '                        not existing_gate and \\\n'
         '                        not installer_rerun_window_expired(row)\n',
         '                        not installer_rerun_window_expired(row)\n', [sw_rec]),
        ("the builder runs for an expired window", S,
         '                        not existing_gate and \\\n'
         '                        not installer_rerun_window_expired(row)\n',
         '                        not existing_gate\n', [sw_exp]),
        ("the gate failures lose their prefix and the notice", S,
         '                        failures += [\n'
         '                            "offnode gate: " + reason for reason in gate_reasons\n'
         '                        ]',
         '                        failures += list(gate_reasons)', [sw_fail]),
        ("a recorded gate is not judged again (the node stays held)", S,
         "                    failures = node_auto_reopen_failures(conn, row, armed_at)\n"
         "                    failures += installer_rerun_reopen_failures(conn, row)\n"
         "                    if not gate:",
         "                    failures = []\n                    if not gate:", [sw_go, sw_worse]),
        # ---- round 2: the liveness fix (Claude), the write-lock fixes (Sol) ----
        ("a stale hub record still counts as a record (the builder never runs again)", S,
         '                        existing_gate = ""   # a stale hub record counts as absent',
         '                        pass   # a stale hub record counts as absent', [sw_stale]),
        ("an operator record is replaced too when it is stale", S,
         'if held is not None and held["source"] == "hub" and verify_offnode_gate_for_use(',
         'if held is not None and verify_offnode_gate_for_use(', [sw_opstale]),
        ("every hub record counts as stale, even one that still verifies", S,
         'verify_offnode_gate_for_use(conn, slug, existing_gate, allow_hub_source=True):\n',
         'True:\n', [sw_validrec]),
        ("the recovery authorization is not read again after the check", S,
         "                    armed_at = node_auto_reopen_arm(conn)\n                    failures = node_auto_reopen_failures(conn, row, armed_at)\n"
         "                    failures += installer_rerun_reopen_failures(conn, row)\n                    if not gate:",
         "                    failures = node_auto_reopen_failures(conn, row, armed_at)\n"
         "                    failures += installer_rerun_reopen_failures(conn, row)\n                    if not gate:", [sw_recovery]),
        ("the row is not read again after the check (the old row decides expiry)", S,
         '                    row = conn.execute(\n'
         '                        "SELECT * FROM nodes WHERE slug = ?", (slug,)\n'
         '                    ).fetchone()\n'
         '                    if row is None:\n'
         '                        result["held"][slug] = [\n'
         '                            "offnode gate: node disappeared',
         '                    if row is None:\n'
         '                        result["held"][slug] = [\n'
         '                            "offnode gate: node disappeared', [sw_super]),
        ("a node that moved during a failed check is judged anyway", S,
         '                    if moved:\n                        result["held"][slug] = [\n                            "offnode gate: node changed while',
         '                    if False:\n                        result["held"][slug] = [\n                            "offnode gate: node changed while', [sw_super]),
        ("a node that vanished during the check is not noticed", S,
         '                    if row is None:\n                        result["held"][slug] = [\n                            "offnode gate: node disappeared',
         '                    if False:\n                        result["held"][slug] = [\n                            "offnode gate: node disappeared', [sw_gone]),
        # ---- H6-PERF ----
        ("PERF: no cap on the number of hub checks per sweep", S,
         'if builder_due and (_HUB_OFFNODE_SWEEP_BUDGET["checks"] >= HUB_OFFNODE_SWEEP_MAX_CHECKS or\n',
         'if builder_due and (False or\n', [perf_cap, perf_time]),
        ("PERF: no cap on the time of the hub checks per sweep", S,
         ' or\n                                    _HUB_OFFNODE_SWEEP_BUDGET["seconds"] >= HUB_OFFNODE_SWEEP_MAX_SECONDS):',
         '):', [perf_time]),
        ("PERF: the attempt does not count its checks", S,
         '        _HUB_OFFNODE_SWEEP_BUDGET["checks"] += 1\n',
         '        pass\n', [perf_cap, perf_budget]),
        ("PERF: the attempt does not count its time", S,
         '        _HUB_OFFNODE_SWEEP_BUDGET["seconds"] += time.monotonic() - started\n',
         '        pass\n', [perf_time, perf_budget]),
        ("PERF: the attempt counts a check that never ran SSH", S,
         "    last = _HUB_OFFNODE_GATE_LAST.get(slug)\n",
         "    last = _HUB_OFFNODE_GATE_LAST.get(slug)\n    _HUB_OFFNODE_SWEEP_BUDGET[\"checks\"] += 1\n", [perf_budget, perf_throttle]),
        ("PERF: a one-slug pass (the P-13 watch) resets the sweep's budget", S,
         "    if only_slug is None:\n        # H6-PERF: the check budget",
         "    if True:\n        # H6-PERF: the check budget", [perf_watch]),
        ("PERF: the sweep does not start with an empty budget", S,
         "    _HUB_OFFNODE_SWEEP_BUDGET.update(checks=0, seconds=0.0)\n", "    pass\n", [perf_reset, perf_cap]),
        ("PERF: the sweep keeps plain slug order (failing nodes starve later ones)", S,
         "    slugs.sort(\n"
         "        key=lambda slug: (\n"
         "            _HUB_OFFNODE_GATE_LAST.get(slug, (float(\"-inf\"), []))[0],\n"
         "            slug,\n"
         "        )\n"
         "    )\n", "", [perf_starve, perf_rotate]),
        ("PERF: never-attempted nodes sort last (a deferred node waits behind the failing ones)", S,
         '_HUB_OFFNODE_GATE_LAST.get(slug, (float("-inf"), []))[0],',
         '_HUB_OFFNODE_GATE_LAST.get(slug, (float("inf"), []))[0],', [perf_starve, perf_rotate]),
        ("PERF: the most recently attempted node goes first", S,
         "            slug,\n        )\n    )\n    for slug in slugs:\n",
         "            slug,\n        ),\n        reverse=True,\n    )\n    for slug in slugs:\n", [perf_starve, perf_rotate]),
        ("PERF: a deferred node is reported as a gate failure (and raises the notice)", S,
         'failures.append("hub-run off-node check deferred',
         'failures.append("offnode gate: hub-run off-node check deferred', [perf_cap]),
        ("PERF: the alert drain does not run before the reopen pass", S,
         "        # drain after the pass stays, so a reopen it records is alerted at once.\n"
         "        try:\n            await asyncio.to_thread(drain_node_latch_events)\n",
         "        # drain after the pass stays, so a reopen it records is alerted at once.\n"
         "        try:\n            await asyncio.to_thread(lambda: 0)\n", [perf_loop]),
        ("PERF: the alert drain after the reopen pass is gone", S,
         '            logger.error("node auto-reopen pass failed: %s", type(exc).__name__)\n'
         "        try:\n            await asyncio.to_thread(drain_node_latch_events)\n",
         '            logger.error("node auto-reopen pass failed: %s", type(exc).__name__)\n'
         "        try:\n            await asyncio.to_thread(lambda: 0)\n", [perf_loop]),
        ("the stub is back: the hub-run builder produces nothing", S,
         "    return hub_offnode_gate_attempt(conn, node)[0]", "    return \"\"", [att_name]),
        ("a node reopens although no gate record exists", S,
         '    if gate is None or gate["slug"] != slug:\n        return ["no verified node-side gate record with this digest for this node"]',
         '    if gate is None or gate["slug"] != slug:\n        return []', [nogate]),
        ("HL-F3: the installer_rerun closure keeps a streak that began before it", S,
         '"latch_cause=\'installer_rerun_pending\', deployment_completed_at=?, "\n'
         '                "data_plane_green_streak=0, data_plane_green_since=NULL "',
         '"latch_cause=\'installer_rerun_pending\', deployment_completed_at=? "',
         [(SweepTests, "test_hl_f3_the_rerun_closure_ends_a_streak_that_began_before_it")]),
        ("F4-HL: the sweep's data closure keeps a streak that began before it", S,
         "            latch_cause='health_' || {health_reason_sql},\n"
         "            data_plane_green_streak=0,\n"
         "            data_plane_green_since=NULL\n",
         "            latch_cause='health_' || {health_reason_sql}\n",
         [(ClosureStreakTests, "test_f4_hl_the_sweeps_data_closure_ends_the_streak")]),
        ("F4-HL: the sweep's heartbeat_stale closure keeps a streak that began before it", S,
         "            data_plane_green_streak=CASE WHEN COALESCE(operator_enabled, 0) = 1\n"
         "                                         THEN 0 ELSE data_plane_green_streak END,\n"
         "            data_plane_green_since=CASE WHEN COALESCE(operator_enabled, 0) = 1\n"
         "                                        THEN NULL ELSE data_plane_green_since END,\n",
         "",
         [(ClosureStreakTests, "test_f4_hl_the_sweeps_heartbeat_stale_closure_ends_the_streak")]),
        ("F4-HL: the heartbeat_stale sweep also ends the streak of a row that is already closed", S,
         "            data_plane_green_streak=CASE WHEN COALESCE(operator_enabled, 0) = 1\n"
         "                                         THEN 0 ELSE data_plane_green_streak END,\n"
         "            data_plane_green_since=CASE WHEN COALESCE(operator_enabled, 0) = 1\n"
         "                                        THEN NULL ELSE data_plane_green_since END,\n",
         "            data_plane_green_streak=0,\n"
         "            data_plane_green_since=NULL,\n",
         [(ClosureStreakTests, "test_f4_hl_the_sweeps_heartbeat_stale_closure_ends_the_streak")]),
        ("F4-HL: a prober run that closes keeps the streak", S,
         "        # after the closure.\n"
         "        green_streak = 0\n"
         "        green_since = None\n",
         "        # after the closure.\n",
         [(ClosureStreakTests, "test_f4_hl_a_green_prober_run_that_closes_ends_the_streak"),
          (ClosureStreakTests, "test_f4_hl_a_streak_that_starts_on_the_closing_run_does_not_hold_the_node")]),
        # R25 R2-G2: the restart is bound to the snapshot the check found.
        ("R2-G2: the restart ignores the checked registry digest", S,
         "'[ \"$actual\" = \"$1\" ] || exit 76; '", "''",
         [(GatewayRestartTests, "test_a_registry_that_is_not_the_checked_snapshot_restarts_nothing"),
          (GatewayRestartTests, "test_a_node_that_reopened_and_published_after_the_check_is_never_restarted")]),
        ("R2-G2: the restart does not take the registry publication lock", S,
         "\"exec 9>>/etc/winn/.winn3-peers.lock; flock -w 10 9 || exit 75; \"", "\"\"",
         [(GatewayRestartTests, "test_the_restart_takes_the_activation_lock_and_runs_in_an_activation_scope"),
          (GatewayRestartTests, "test_a_registry_that_is_not_the_checked_snapshot_restarts_nothing")]),
        ("R2-G2: a symlinked registry file passes the digest check", S,
         "[ -f /etc/winn/winn3-peers.json ] && [ ! -L /etc/winn/winn3-peers.json ] || exit 76; ",
         "[ -f /etc/winn/winn3-peers.json ] || exit 76; ",
         [(GatewayRestartTests, "test_a_registry_that_is_not_the_checked_snapshot_restarts_nothing")]),
        ("R2-G2: the hub sends a digest that is not the checked snapshot", S,
         "            registry_sha256 = offnode_expected_v3_sha256(conn, slug)\n",
         "            registry_sha256 = \"0\" * 64\n",
         [(AttemptTests, "test_a_gateway_that_started_before_the_file_is_restarted_once_and_rechecked_later"),
          (GatewayRestartTests, "test_the_same_round_trip_restarts_a_node_whose_registry_is_still_the_checked_snapshot")]),
    ]


class MutantTests(unittest.TestCase):
    """5.6: every mutant is applied to the extracted hub source and a named
    test of this file must FAIL on it. The unmutated run passes the same tests
    (anti-vacuity), proven once at the start."""

    @classmethod
    def setUpClass(cls):
        cls.table = _mutant_table()

    def test_the_unmutated_source_passes_every_mutant_target(self):
        targets = sorted({(c.__name__, n) for row in self.table for (c, n) in row[4]})
        cases = [(next(c for c in _all_classes() if c.__name__ == cn), n) for cn, n in targets]
        self.assertEqual(run_cases(hub_source(), cases), [])

    def test_every_mutant_is_killed(self):
        survivors = []
        for name, source, old, new, targets in self.table:
            mutated = mutate(source, old, new)
            self.assertNotEqual(mutated, source, name)
            failed = run_cases(mutated, targets)
            if not failed:
                survivors.append(name)
        self.assertEqual(survivors, [], "mutants that no test killed")

    def test_the_mutant_count(self):
        self.assertGreaterEqual(len(self.table), 55)


def _all_classes():
    return [EvaluatorTests, NodeScriptEndToEndTests, RemoteCommandTests, CheckRunTests, RecordAndVerifyTests,
            AttemptTests, SweepTests, ClosureStreakTests, FreshInstallClassTests, GatewayRestartTests]


# The shared fixtures inherit the dark-start and rerun tests; this file runs only its own.
for _cls in (SweepCase, SweepTests, ClosureStreakTests, FreshInstallClassTests):
    for _name in dir(dark.DataPlaneDarkStartTests):
        if _name.startswith("test_") and _name not in _cls.__dict__:
            setattr(_cls, _name, None)
# SweepTests inherits from SweepCase, whose own tests it must keep.


if __name__ == "__main__":
    unittest.main()
