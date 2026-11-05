#!/usr/bin/env python3
"""REGISTRY-PUSH: the v3 registry publication carries its size-growing payloads
on the ssh session's stdin, not in the command.

The release form put the node's whole authorization map (base64) and the
charge-journal lines inside ONE ssh remote-command argv string. Linux caps a
single argv string at MAX_ARG_STRLEN (131072 bytes), on the hub's execve of
ssh and again on the node's login shell, so a node past roughly 840 devices
could no longer be published to. The hub now sends a fixed script of about
1.5 KB and puts the registry and the journal lines on stdin. The node reads
the stream to end of file, checks its exact length and the SHA-256 of the whole
stream, and refuses anything else (exit 5) before the lock or any write.

These tests run the REAL hub source (extracted from the ONETOUCH heredoc by the
shared harness). The REAL remote command it builds is executed by bash, dash
and sh against a scratch directory standing in for /etc/winn, with only
getent, install, chown, flock, timeout and sync shimmed, and with stdin
delivered exactly as ssh delivers it. The fake transport also enforces the
Linux per-argument limit, so the release form fails here on any host.

No test contacts a node, a live hub or the network.

Run:  python3 server/test_registry_push_stdin.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import base64
import errno
import hashlib
import ipaddress
import json
import logging
import os
import re
import shlex
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import test_account_deletion_hub as harness

REAL_RUN = subprocess.run
# include/uapi/linux/binfmts.h: MAX_ARG_STRLEN = PAGE_SIZE * 32 (4 KiB pages).
# execve returns E2BIG for any single argument string whose length including
# its NUL exceeds it.
LINUX_MAX_ARG_STRLEN = 131072
GATEWAY_GO = Path(__file__).resolve().parents[1] / "winn_protocol_experimental" / "cmd" / "winn3-gateway" / "peer_registry.go"
INSTALLER = Path(__file__).resolve().parent / "wins_control_plane_setup_ONETOUCH.sh"
TOOLS = Path(__file__).resolve().parents[1] / "tools"

SEQ_FILE = ".winn3-peers.seq"
LOCK_FILE = ".winn3-peers.lock"
JOURNAL = ".winn3-charges.log"
REGISTRY = "winn3-peers.json"
KEY_ID = "a1b2c3d4e5f60718"
KEY_HEX = "11" * 32


def node_shells():
    shells = []
    for candidate in (shutil.which("bash"), "/bin/dash", "/bin/sh"):
        if candidate and os.path.exists(candidate) and candidate not in shells:
            shells.append(candidate)
    return shells


def synthetic_snapshot(count, not_after=4102444800):
    """Compact hub JSON for `count` devices, exactly as the hub serializes it
    for a node that reports peer-registry-tier (every entry names its tier)."""
    peers = []
    for index in range(1, count + 1):
        peers.append({
            "static_public": base64.b64encode(hashlib.sha256(b"key-%d" % index).digest()).decode(),
            "inner_v4": "10.%d.%d.%d" % ((index >> 16) & 255, (index >> 8) & 255, index & 255),
            "not_after": not_after,
            "tier": "free" if index % 4 == 0 else "premium",
        })
    document = {"version": 1, "peers": peers}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return document, raw


def journal_for(grants, charged_at=1_900_000_000):
    lines = ""
    for grant_id, account in grants:
        token = hmac_token(account, grant_id)
        lines += "%s %d %s %s\n" % (grant_id, charged_at, KEY_ID, token)
    return lines


def hmac_token(account, grant_id):
    import hmac
    return hmac.new(bytes.fromhex(KEY_HEX), f"{KEY_ID}:{account}:{grant_id}".encode(),
                    hashlib.sha256).hexdigest()[:32]


def release_command_length(raw, journal_lines):
    """Length of the release form's remote command for this data: 1,005 bytes of
    fixed text (measured on db5cc7b, including a 16 digit sequence and a 10
    digit journal floor) plus the two shell-quoted payloads."""
    payload = base64.b64encode(raw).decode("ascii")
    return 1005 + len(shlex.quote(payload)) + len(shlex.quote(journal_lines))


class NodeShell:
    """A scratch /etc/winn and the shell that plays the node's login shell."""

    def __init__(self, root, shell):
        self.root = root
        self.shell = shell
        self.dir = os.path.join(root, "etc_winn")
        self.shims = os.path.join(root, "shims")
        self.sync_log = os.path.join(root, "sync.log")
        os.makedirs(self.dir)
        os.makedirs(self.shims)
        bodies = {
            "getent": "exit 0",
            "chown": '[ -z "$REGPUSH_CHOWN_FAIL" ] || { echo chown-refused >&2; exit 1; }; exit 0',
            "flock": "exit 0",
            "install": 'for last; do :; done; mkdir -p "$last"',
            # A working timeout(1) (macOS has none): the child keeps the
            # shell's stdin, stdout and stderr and is terminated, exit 124,
            # when the time is up. Nothing is left holding the pipes.
            "timeout": "exec %s -c 'import subprocess, sys\n"
                       "p = subprocess.Popen(sys.argv[2:])\n"
                       "try:\n"
                       "    sys.exit(p.wait(timeout=float(sys.argv[1])))\n"
                       "except subprocess.TimeoutExpired:\n"
                       "    p.terminate(); p.wait(); sys.exit(124)' \"$@\"" % shlex.quote(sys.executable),
            # Records what was synced and what the node held at that moment
            # (registry size, sequence file, journal size), so the order of
            # every sync against every rename is observable. REGPUSH_SYNC_FAIL=k
            # makes the k-th call fail, as a disk that cannot flush would.
            "sync": 'n=$(( $(cat "$REGPUSH_SYNC_LOG" 2>/dev/null | wc -l) + 1 )); '
                    'size() { if [ -f "$1" ]; then wc -c < "$1" | tr -d " "; else echo -1; fi; }; '
                    'seq=-; [ ! -f "$REGPUSH_SEQ" ] || seq=$(cat "$REGPUSH_SEQ"); '
                    'printf "%s %s %s %s\\n" "$1" "$(size "$REGPUSH_REGISTRY")" "$seq" '
                    '"$(size "$REGPUSH_JOURNAL")" >> "$REGPUSH_SYNC_LOG"; '
                    '[ "$n" != "${REGPUSH_SYNC_FAIL:-0}" ] || { echo "sync: error syncing $1" >&2; exit 1; }',
        }
        if shutil.which("sha256sum") is None:
            bodies["sha256sum"] = "shasum -a 256"
        for name, body in bodies.items():
            path = os.path.join(self.shims, name)
            with open(path, "w") as handle:
                handle.write("#!/bin/bash\n" + body + "\n")
            os.chmod(path, stat.S_IRWXU)

    def path(self, name):
        return os.path.join(self.dir, name)

    def read(self, name):
        try:
            with open(self.path(name), "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def write(self, name, data):
        with open(self.path(name), "wb") as handle:
            handle.write(data)

    def tree(self):
        return {name: self.read(name) for name in sorted(os.listdir(self.dir))}

    def argv(self, command):
        command = command.replace("/etc/winn", self.dir)
        if os.path.basename(self.shell) == "bash":
            return [self.shell, "--noprofile", "--norc", "-c", command]
        return [self.shell, "-c", command]

    def env(self, **extra):
        env = dict(os.environ, PATH=self.shims + os.pathsep + os.environ.get("PATH", ""),
                   REGPUSH_SYNC_LOG=self.sync_log, REGPUSH_REGISTRY=self.path(REGISTRY),
                   REGPUSH_SEQ=self.path(SEQ_FILE), REGPUSH_JOURNAL=self.path(JOURNAL))
        env.update(extra)
        return env

    def run(self, command, stdin, timeout=60, **env):
        return REAL_RUN(self.argv(command), input=stdin, capture_output=True, text=True,
                        env=self.env(**env), timeout=timeout, check=False)

    def sync_calls(self):
        try:
            with open(self.sync_log) as handle:
                return [line.split() for line in handle.read().splitlines()]
        except FileNotFoundError:
            return []


class HubCase(unittest.TestCase):
    def setUp(self):
        self.mod = harness.load_hub()
        self.mod.logger.propagate = False
        self.addCleanup(shutil.rmtree, self.mod._TMPDIR, True)
        self.work = tempfile.mkdtemp(prefix="regpush-")
        self.addCleanup(shutil.rmtree, self.work, True)
        self.node_count = 0

    def node(self, shell=None):
        self.node_count += 1
        root = os.path.join(self.work, "n%d" % self.node_count)
        os.makedirs(root)
        return NodeShell(root, shell or node_shells()[0])


class StdinTransportTests(HubCase):
    """Item 2: the command is fixed and the payload is stdin."""

    def test_command_is_fixed_size_whatever_the_node_holds(self):
        sizes = []
        for count in (0, 10, 1000, 7000):
            _, raw = synthetic_snapshot(count)
            grants = [("%032x" % index, "1111-2222-3333") for index in range(1, min(count, 200) + 1)]
            journal = journal_for(grants)
            command, stdin_text = self.mod.winn3_registry_publish_command(7, raw, journal, 123)
            sizes.append(len(command))
            self.assertLess(len(command), 2048, count)
            self.assertEqual(stdin_text, raw.decode("ascii") + journal)
            self.assertNotIn(raw[:60].decode("ascii"), command)
            for grant_id, account in grants[:3]:
                self.assertNotIn(hmac_token(account, grant_id), command)
                self.assertNotIn(grant_id, command)
            if count >= 1000:
                self.assertGreater(release_command_length(raw, journal), LINUX_MAX_ARG_STRLEN, count)
        # Only the digits of total and reg_len differ.
        self.assertLess(max(sizes) - min(sizes), 16)

    def test_stream_is_the_registry_then_the_journal_and_nothing_else(self):
        _, raw = synthetic_snapshot(40)
        journal = journal_for([("%032x" % 9, "1111-2222-3333")])
        command, stdin_text = self.mod.winn3_registry_publish_command(7, raw, journal, 0)
        self.assertTrue(stdin_text.startswith('{"peers":['))
        self.assertTrue(stdin_text.endswith("\n"))
        self.assertEqual(len(stdin_text), len(raw) + len(journal))
        self.assertIn("total=%d;" % len(stdin_text), command)
        self.assertIn("reg_len=%d;" % len(raw), command)
        self.assertIn("stream_sha=%s;" % hashlib.sha256(stdin_text.encode("ascii")).hexdigest(), command)
        self.assertNotIn("reg_sha=", command)

    def test_substrings_other_suites_pin_are_unchanged(self):
        _, raw = synthetic_snapshot(3)
        command, _ = self.mod.winn3_registry_publish_command(7, raw, "", 0)
        for needle in ("mktemp /etc/winn/.winn3-peers.", "chown root:winn3-gateway", "chmod 0640",
                       'mv -f "$tmp" /etc/winn/winn3-peers.json', "getent group winn3-gateway",
                       "winn3-gateway-group-absent", "winn3-registry-stale-sequence",
                       "flock -w 10 9"):
            self.assertIn(needle, command)

    def test_installs_registry_and_journal_exactly_under_every_shell(self):
        _, raw = synthetic_snapshot(300)
        grants = [("%032x" % index, "1111-2222-3333") for index in range(1, 6)]
        journal = journal_for(grants)
        for shell in node_shells():
            with self.subTest(shell=shell):
                node = self.node(shell)
                old_line = "%032x %d %s %s\n" % (77, 1_800_000_000, KEY_ID, "e" * 32)
                stale_line = "%032x %d %s %s\n" % (78, 1_000, KEY_ID, "f" * 32)
                node.write(JOURNAL, (stale_line + old_line).encode())
                command, stdin_text = self.mod.winn3_registry_publish_command(41, raw, journal, 1_700_000_000)
                done = node.run(command, stdin_text)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(node.read(REGISTRY), raw)
                self.assertEqual(node.read(SEQ_FILE), b"41")
                # The journal is the old window plus the new lines; the line
                # older than the floor is gone.
                self.assertEqual(node.read(JOURNAL).decode(), old_line + journal)
                self.assertEqual(sorted(node.tree()), sorted([REGISTRY, SEQ_FILE, JOURNAL, LOCK_FILE]))

    def test_an_empty_journal_leaves_the_journal_window_alone(self):
        _, raw = synthetic_snapshot(5)
        node = self.node()
        line = "%032x %d %s %s\n" % (5, 1_900_000_000, KEY_ID, "d" * 32)
        node.write(JOURNAL, line.encode())
        command, stdin_text = self.mod.winn3_registry_publish_command(3, raw, "", 0)
        done = node.run(command, stdin_text)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(node.read(JOURNAL).decode(), line)
        self.assertEqual(node.read(REGISTRY), raw)


class SequenceGuardTests(HubCase):
    """The remote sequence guard still refuses a stale write under stdin delivery."""

    def test_a_stale_or_equal_sequence_is_refused_and_nothing_changes(self):
        _, raw_new = synthetic_snapshot(12)
        _, raw_old = synthetic_snapshot(6)
        for shell in node_shells():
            with self.subTest(shell=shell):
                node = self.node(shell)
                first, stdin_first = self.mod.winn3_registry_publish_command(100, raw_new, "", 0)
                self.assertEqual(node.run(first, stdin_first).returncode, 0)
                before = node.tree()
                for seq in (100, 99, 1):
                    command, stdin_text = self.mod.winn3_registry_publish_command(seq, raw_old, "", 0)
                    done = node.run(command, stdin_text)
                    self.assertEqual(done.returncode, 3, (seq, done.stderr))
                    self.assertIn("winn3-registry-stale-sequence 100", done.stderr)
                    self.assertEqual(node.tree(), before, seq)
                command, stdin_text = self.mod.winn3_registry_publish_command(101, raw_old, "", 0)
                self.assertEqual(node.run(command, stdin_text).returncode, 0)
                self.assertEqual(node.read(REGISTRY), raw_old)
                self.assertEqual(node.read(SEQ_FILE), b"101")
                self.assertFalse([name for name in node.tree() if name.startswith(".winn3-stage.")])

    def test_a_node_without_the_group_is_refused_before_stdin_is_read(self):
        _, raw = synthetic_snapshot(4)
        node = self.node()
        with open(os.path.join(node.shims, "getent"), "w") as handle:
            handle.write("#!/bin/bash\nexit 2\n")
        command, stdin_text = self.mod.winn3_registry_publish_command(5, raw, "", 0)
        done = node.run(command, stdin_text)
        self.assertEqual(done.returncode, 4)
        self.assertIn("winn3-gateway-group-absent", done.stderr)
        self.assertEqual(node.tree(), {})


class AtomicInstallTests(HubCase):
    def test_every_file_is_synced_before_its_rename_and_the_directory_after(self):
        _, raw_old = synthetic_snapshot(8)
        _, raw_new = synthetic_snapshot(9)
        journal_old = b"%032x %d %s %s\n" % (3, 1_900_000_000, KEY_ID.encode(), b"c" * 32)
        grants = [("%032x" % 9, "1111-2222-3333")]
        journal_new = journal_for(grants)
        node = self.node()
        node.write(REGISTRY, raw_old)
        node.write(SEQ_FILE, b"4")
        node.write(JOURNAL, journal_old)
        inode_before = os.stat(node.path(REGISTRY)).st_ino
        command, stdin_text = self.mod.winn3_registry_publish_command(5, raw_new, journal_new, 0)
        done = node.run(command, stdin_text)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(node.read(REGISTRY), raw_new)
        self.assertNotEqual(os.stat(node.path(REGISTRY)).st_ino, inode_before)
        calls = node.sync_calls()
        self.assertEqual(len(calls), 5, calls)
        names = [os.path.basename(call[0]) for call in calls]
        self.assertRegex(names[0], r"^\.winn3-peers\.[A-Za-z0-9]{6}$")
        self.assertEqual(names[1:3], [".winn3-peers.seq.new", ".winn3-charges.log.new"])
        self.assertEqual(calls[3][0], node.dir)
        self.assertEqual(calls[4][0], node.dir)
        # What the node held at each call: (registry bytes, sequence, journal bytes).
        state = [tuple(call[1:]) for call in calls]
        old_state = (str(len(raw_old)), "4", str(len(journal_old)))
        self.assertEqual(state[0], old_state)                        # registry temp synced, nothing renamed
        self.assertEqual(state[1], old_state)                        # seq.new synced before its rename
        self.assertEqual(state[2], (str(len(raw_old)), "5", str(len(journal_old))))   # journal.new synced
        self.assertEqual(state[3][:2], (str(len(raw_old)), "5"))      # journal renamed, registry still old
        self.assertNotEqual(state[3][2], str(len(journal_old)))
        self.assertEqual(state[4][:2], (str(len(raw_new)), "5"))      # registry renamed
        self.assertEqual(state[4][2], state[3][2])
        self.assertEqual(node.read(JOURNAL), journal_old + journal_new.encode())
        # The command text says the same: each sync is written before its rename
        # and the registry rename is last.
        order = ['sync "$tmp"', "sync /etc/winn/.winn3-peers.seq.new",
                 "mv -f /etc/winn/.winn3-peers.seq.new", "sync /etc/winn/.winn3-charges.log.new",
                 "mv -f /etc/winn/.winn3-charges.log.new", 'mv -f "$tmp" /etc/winn/winn3-peers.json']
        positions = [command.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))

    def test_a_failing_sync_aborts_before_the_next_rename_and_leaves_nothing_half_applied(self):
        _, raw_old = synthetic_snapshot(8)
        _, raw_new = synthetic_snapshot(9)
        journal_old = b"%032x %d %s %s\n" % (3, 1_900_000_000, KEY_ID.encode(), b"c" * 32)
        journal_add = journal_for([("%032x" % 9, "1111-2222-3333")])
        # k-th sync fails -> (registry installed?, sequence, journal replaced?)
        expected = {
            1: (False, b"4", False),   # registry temp: nothing was renamed
            2: (False, b"4", False),   # seq.new: the old sequence still stands
            3: (False, b"5", False),   # journal.new: sequence advanced, registry and journal untouched
            4: (False, b"5", True),    # directory after the journal rename: registry still old
            5: (True, b"5", True),     # directory after the registry rename: installed, durability unknown
        }
        for shell in node_shells():
            for k, (registry_new, seq, journal_new) in expected.items():
                with self.subTest(shell=shell, failing_sync=k):
                    node = self.node(shell)
                    node.write(REGISTRY, raw_old)
                    node.write(SEQ_FILE, b"4")
                    node.write(JOURNAL, journal_old)
                    command, stdin_text = self.mod.winn3_registry_publish_command(5, raw_new, journal_add, 0)
                    done = node.run(command, stdin_text, REGPUSH_SYNC_FAIL=str(k))
                    self.assertEqual(done.returncode, 1, done.stderr)
                    self.assertIn("sync: error syncing", done.stderr)
                    self.assertEqual(node.read(REGISTRY), raw_new if registry_new else raw_old)
                    self.assertEqual(node.read(SEQ_FILE), seq)
                    self.assertEqual(node.read(JOURNAL) != journal_old, journal_new)
                    # The registry only ever holds a complete document, and the
                    # stage and temp files are gone.
                    json.loads(node.read(REGISTRY))
                    leftovers = [name for name in node.tree()
                                 if name.startswith(".winn3-stage.")
                                 or re.fullmatch(r"\.winn3-peers\.[A-Za-z0-9]{6}", name)]
                    self.assertEqual(leftovers, [])

    def test_a_reader_holding_the_old_file_keeps_the_complete_old_snapshot(self):
        _, raw_old = synthetic_snapshot(8)
        _, raw_new = synthetic_snapshot(300)
        node = self.node()
        node.write(REGISTRY, raw_old)
        command, stdin_text = self.mod.winn3_registry_publish_command(5, raw_new, "", 0)
        with open(node.path(REGISTRY), "rb") as held:
            done = node.run(command, stdin_text)
            self.assertEqual(done.returncode, 0, done.stderr)
            # The gateway reading mid-publication sees one whole document or
            # the other, never a mixture: the old inode is untouched.
            self.assertEqual(held.read(), raw_old)
        self.assertEqual(node.read(REGISTRY), raw_new)

    def test_a_failure_before_the_rename_leaves_the_old_file_and_no_temp_files(self):
        _, raw_old = synthetic_snapshot(8)
        _, raw_new = synthetic_snapshot(9)
        for shell in node_shells():
            with self.subTest(shell=shell):
                node = self.node(shell)
                node.write(REGISTRY, raw_old)
                node.write(SEQ_FILE, b"4")
                node.write(JOURNAL, b"")
                command, stdin_text = self.mod.winn3_registry_publish_command(5, raw_new, "", 0)
                done = node.run(command, stdin_text, REGPUSH_CHOWN_FAIL="1")
                self.assertNotEqual(done.returncode, 0)
                self.assertEqual(node.read(REGISTRY), raw_old)
                self.assertEqual(node.read(SEQ_FILE), b"4")
                leftovers = [name for name in node.tree() if name.startswith((".winn3-stage.", ".winn3-peers.X"))
                             or re.fullmatch(r"\.winn3-peers\.[A-Za-z0-9]{6}", name)]
                self.assertEqual(leftovers, [])

    def test_the_stage_file_is_not_world_readable(self):
        _, raw = synthetic_snapshot(3)
        node = self.node()
        with open(os.path.join(node.shims, "sync"), "w") as handle:
            handle.write("#!/bin/bash\nfor f in \"$REGPUSH_DIR\"/.winn3-stage.*; do "
                         "stat -c %a \"$f\" 2>/dev/null || stat -f %Lp \"$f\"; done >> \"$REGPUSH_SYNC_LOG\"\n")
        command, stdin_text = self.mod.winn3_registry_publish_command(5, raw, "", 0)
        done = node.run(command, stdin_text, REGPUSH_DIR=node.dir)
        self.assertEqual(done.returncode, 0, done.stderr)
        modes = [call[0] for call in node.sync_calls()]
        self.assertTrue(modes)
        self.assertEqual(set(modes), {"600"})


class DamagedStreamTests(HubCase):
    """A truncated, empty, altered or stalled stdin is refused, never half applied."""

    def seeded(self, shell):
        node = self.node(shell)
        _, raw_old = synthetic_snapshot(8)
        node.write(REGISTRY, raw_old)
        node.write(SEQ_FILE, b"4")
        node.write(JOURNAL, b"%032x %d %s %s\n" % (3, 1_900_000_000, KEY_ID.encode(), b"c" * 32))
        return node

    def test_every_truncation_point_is_refused_with_nothing_written(self):
        _, raw = synthetic_snapshot(60)
        journal = journal_for([("%032x" % index, "1111-2222-3333") for index in range(1, 4)])
        command, stream = self.mod.winn3_registry_publish_command(9, raw, journal, 0)
        cuts = sorted({0, 1, 20, len(raw) // 2, len(raw) - 1, len(raw), len(raw) + 1,
                       len(stream) - len(journal) // 2, len(stream) - 1})
        for shell in node_shells():
            for cut in cuts:
                with self.subTest(shell=shell, cut=cut):
                    node = self.seeded(shell)
                    before = node.tree()
                    done = node.run(command, stream[:cut])
                    self.assertEqual(done.returncode, 5, done.stderr)
                    self.assertIn("winn3-registry-bad-payload", done.stderr)
                    # Not even the lock file: refused before the lock.
                    self.assertEqual(node.tree(), before)

    def test_an_altered_registry_of_the_right_length_is_refused(self):
        _, raw = synthetic_snapshot(20)
        command, stream = self.mod.winn3_registry_publish_command(9, raw, "", 0)
        flipped = stream[:50] + ("A" if stream[50] != "A" else "B") + stream[51:]
        self.assertEqual(len(flipped), len(stream))
        for shell in node_shells():
            with self.subTest(shell=shell):
                node = self.seeded(shell)
                before = node.tree()
                done = node.run(command, flipped)
                self.assertEqual(done.returncode, 5, done.stderr)
                self.assertEqual(node.tree(), before)

    def test_a_stalled_stream_is_refused_when_the_node_stops_waiting(self):
        _, raw = synthetic_snapshot(20)
        command, stream = self.mod.winn3_registry_publish_command(9, raw, "", 0)
        bound = "timeout %d head -c" % self.mod.WINN3_PUBLISH_STDIN_SECONDS
        self.assertIn(bound, command)
        quick = command.replace(bound, "timeout 1 head -c")
        node = self.seeded(node_shells()[0])
        before = node.tree()
        proc = subprocess.Popen(node.argv(quick), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=node.env())
        try:
            # Half the stream, then silence with stdin still open: the hub is
            # stuck or the path is partitioned.
            proc.stdin.write(stream[: len(stream) // 2])
            proc.stdin.flush()
            code = proc.wait(timeout=30)
            err_text = proc.stderr.read()
        finally:
            if proc.poll() is None:
                proc.kill()
            for handle in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    handle.close()
                except BrokenPipeError:
                    pass
        self.assertEqual(code, 5, err_text)
        self.assertIn("winn3-registry-bad-payload", err_text)
        self.assertEqual(node.tree(), before)

    def test_a_terminated_shell_removes_its_stage_file(self):
        _, raw = synthetic_snapshot(20)
        command, stream = self.mod.winn3_registry_publish_command(9, raw, "", 0)
        node = self.seeded(node_shells()[0])
        before = node.tree()
        proc = subprocess.Popen(node.argv(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=node.env())
        try:
            proc.stdin.write(stream[:100])
            proc.stdin.flush()
            for _ in range(200):
                if [name for name in os.listdir(node.dir) if name.startswith(".winn3-stage.")]:
                    break
                subprocess.run(["sleep", "0.05"], check=False)
            proc.send_signal(signal.SIGTERM)
            proc.stdin.close()
            proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(node.tree(), before)


    def test_a_stream_longer_than_the_node_bound_is_refused_before_any_read(self):
        _, raw = synthetic_snapshot(20)
        command, stream = self.mod.winn3_registry_publish_command(9, raw, "", 0)
        cap = self.mod.WINN3_PUBLISH_STREAM_MAX_BYTES
        self.assertEqual(cap, 4 * self.mod.WINN3_REGISTRY_MAX_BYTES)
        stated = command.replace("total=%d;" % len(stream), "total=%d;" % (cap + 1))
        self.assertNotEqual(stated, command)
        for shell in node_shells():
            with self.subTest(shell=shell):
                node = self.seeded(shell)
                before = node.tree()
                done = node.run(stated, stream)
                self.assertEqual(done.returncode, 5, done.stderr)
                self.assertIn("winn3-registry-bad-payload", done.stderr)
                # Refused before the stage file exists: the directory is untouched.
                self.assertEqual(node.tree(), before)

    def test_a_node_missing_a_required_tool_is_not_called_a_damaged_stream(self):
        # Without timeout(1) or sha256sum the stream check would see an empty or
        # unverifiable stage and answer exit 5, which the hub settles as a proven
        # refusal. The command names the missing tool first (exit 1: uncertain).
        _, raw = synthetic_snapshot(20)
        command, stream = self.mod.winn3_registry_publish_command(9, raw, "", 0)
        for tool in ("timeout", "sha256sum"):
            lying = command.replace("command -v %s " % tool, "command -v no-such-tool-for-the-test ")
            self.assertNotEqual(lying, command)
            for shell in node_shells():
                with self.subTest(tool=tool, shell=shell):
                    node = self.seeded(shell)
                    before = node.tree()
                    done = node.run(lying, stream)
                    self.assertEqual(done.returncode, 1, done.stderr)
                    self.assertIn("winn3-registry-missing-tool", done.stderr)
                    self.assertNotIn("bad-payload", done.stderr)
                    self.assertEqual(node.tree(), before)

    def test_bytes_beyond_the_stated_length_are_refused_with_nothing_written(self):
        # The node reads one byte more than stated and requires end of file
        # there: a stream with anything after it is not the stream the hub
        # digested, so it is refused like any other damaged delivery.
        _, raw = synthetic_snapshot(20)
        journal = journal_for([("%032x" % 9, "1111-2222-3333")])
        command, stream = self.mod.winn3_registry_publish_command(9, raw, journal, 0)
        for extra in ("X", "X" * 500, journal):
            for shell in node_shells():
                with self.subTest(shell=shell, extra=len(extra)):
                    node = self.seeded(shell)
                    before = node.tree()
                    done = node.run(command, stream + extra)
                    self.assertEqual(done.returncode, 5, done.stderr)
                    self.assertIn("winn3-registry-bad-payload", done.stderr)
                    self.assertEqual(node.tree(), before)

    def test_an_altered_journal_tail_of_the_right_length_is_refused(self):
        # The digest covers the WHOLE stream: one changed byte in the journal
        # lines (a token the gateway would later match a charge against) is
        # refused exactly like a changed registry byte.
        _, raw = synthetic_snapshot(20)
        journal = journal_for([("%032x" % index, "1111-2222-3333") for index in range(1, 4)])
        command, stream = self.mod.winn3_registry_publish_command(9, raw, journal, 0)
        position = len(stream) - 5
        flipped = stream[:position] + ("0" if stream[position] != "0" else "1") + stream[position + 1:]
        self.assertEqual(len(flipped), len(stream))
        self.assertEqual(flipped[:len(raw)], stream[:len(raw)])
        for shell in node_shells():
            with self.subTest(shell=shell):
                node = self.seeded(shell)
                before = node.tree()
                done = node.run(command, flipped)
                self.assertEqual(done.returncode, 5, done.stderr)
                self.assertIn("winn3-registry-bad-payload", done.stderr)
                self.assertEqual(node.tree(), before)

    def test_a_complete_stream_left_open_is_refused_when_the_node_stops_waiting(self):
        # Every byte arrives but end of file never does: the node cannot know
        # the stream is complete, so it refuses at its own bound.
        _, raw = synthetic_snapshot(20)
        command, stream = self.mod.winn3_registry_publish_command(9, raw, "", 0)
        bound = "timeout %d head -c" % self.mod.WINN3_PUBLISH_STDIN_SECONDS
        self.assertIn(bound, command)
        quick = command.replace(bound, "timeout 1 head -c")
        node = self.seeded(node_shells()[0])
        before = node.tree()
        proc = subprocess.Popen(node.argv(quick), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=node.env())
        try:
            proc.stdin.write(stream)
            proc.stdin.flush()
            code = proc.wait(timeout=30)
            err_text = proc.stderr.read()
        finally:
            if proc.poll() is None:
                proc.kill()
            for handle in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    handle.close()
                except BrokenPipeError:
                    pass
        self.assertEqual(code, 5, err_text)
        self.assertIn("winn3-registry-bad-payload", err_text)
        self.assertEqual(node.tree(), before)

    def test_the_stream_gates_run_before_the_sequence_guard(self):
        # A damaged stream is answered 5 even when its sequence is also stale:
        # the stream check precedes the lock and the guard.
        _, raw = synthetic_snapshot(20)
        command, stream = self.mod.winn3_registry_publish_command(9, raw, "", 0)
        for shell in node_shells():
            with self.subTest(shell=shell):
                node = self.seeded(shell)
                node.write(SEQ_FILE, str(10 ** 18).encode())
                before = node.tree()
                done = node.run(command, stream[: len(stream) // 2])
                self.assertEqual(done.returncode, 5, done.stderr)
                self.assertNotIn("stale-sequence", done.stderr)
                self.assertEqual(node.tree(), before)

    def test_a_stated_registry_part_above_the_gateway_limit_is_refused_before_any_read(self):
        # The node holds its own copy of the gateway's file limit (and of the
        # obvious reg_len <= total), so even a hub that skipped its guard
        # cannot make it install a file the gateway would refuse.
        _, raw = synthetic_snapshot(20)
        command, stream = self.mod.winn3_registry_publish_command(9, raw, "", 0)
        limit = self.mod.WINN3_REGISTRY_MAX_BYTES
        for stated in (limit + 1, len(stream) + 1):
            lying = command.replace("reg_len=%d;" % len(raw), "reg_len=%d;" % stated)
            self.assertNotEqual(lying, command)
            for shell in node_shells():
                with self.subTest(shell=shell, reg_len=stated):
                    node = self.seeded(shell)
                    before = node.tree()
                    done = node.run(lying, stream)
                    self.assertEqual(done.returncode, 5, done.stderr)
                    self.assertIn("winn3-registry-bad-payload", done.stderr)
                    self.assertEqual(node.tree(), before)


class RealPublicationTests(HubCase):
    """The real sync_winn3_registry_to_node, over a fake ssh that enforces the
    Linux argument limit and plays the node with the real remote command."""

    def setUp(self):
        super().setUp()
        harness.seed_account(self.mod, devices=0)
        self.node_shell = self.node()
        self.calls = []
        self.logs = []

        class Collect(logging.Handler):
            def emit(handler, record):  # noqa: N805
                self.logs.append(record.getMessage())

        handler = Collect(level=logging.DEBUG)
        self.mod.logger.addHandler(handler)
        self.mod.logger.setLevel(logging.DEBUG)
        self.addCleanup(self.mod.logger.removeHandler, handler)

    def publish(self, document, meta, *, keyring=None, runner=None, builder=None):
        mod = self.mod

        def ssh(host, remote_command, **kwargs):
            return ["l57-node", str(host), remote_command]

        def fake_run(args, **kwargs):
            for item in args:
                if len(str(item).encode("utf-8")) + 1 > LINUX_MAX_ARG_STRLEN:
                    raise OSError(errno.E2BIG, "Argument list too long", args[0])
            self.calls.append((list(args), dict(kwargs)))
            if runner is not None:
                return runner(args, kwargs)
            done = self.node_shell.run(args[2], kwargs.get("input"))
            return subprocess.CompletedProcess(args, done.returncode, done.stdout, done.stderr)

        patches = [
            patch.object(mod, "winn3_peer_registry_publication",
                         side_effect=builder or (lambda conn, slug, provisional=None: (document, meta))),
            patch.object(mod, "node_ssh_command", side_effect=ssh),
            patch.object(mod.subprocess, "run", side_effect=fake_run),
        ]
        if keyring is not None:
            patches.append(patch.object(mod, "winn3_charge_keyring", return_value=keyring))
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        with closing(sqlite3.connect(mod._DB)) as conn, conn:
            conn.row_factory = sqlite3.Row
            mod.ensure_schema(conn)
            return mod.sync_winn3_registry_to_node(conn, "127.0.0.1", "lab-alpha")

    def publications(self):
        with self.mod.winn3_authority_ledger() as ledger:
            return [dict(row) for row in ledger.execute(
                "SELECT seq, node_slug, outcome, refusal FROM winn3_publications ORDER BY seq")]

    def entries(self, seq):
        with self.mod.winn3_authority_ledger() as ledger:
            return ledger.execute(
                "SELECT COUNT(*) FROM winn3_publication_entries WHERE seq=?", (seq,)).fetchone()[0]

    def test_a_registry_whose_release_command_exceeds_the_argv_limit_publishes(self):
        for count in (1200, 7000):
            with self.subTest(devices=count):
                self.calls.clear()
                document, raw = synthetic_snapshot(count)
                self.assertGreater(release_command_length(raw, ""), LINUX_MAX_ARG_STRLEN)
                ok = self.publish(document, [{"kind": "live"}] * count)
                self.assertTrue(ok, self.logs[-3:])
                self.assertEqual(self.node_shell.read(REGISTRY), raw)
                argv, kwargs = self.calls[-1]
                self.assertLess(max(len(item) for item in argv), 4096)
                self.assertEqual(kwargs["input"], raw.decode("ascii"))
                self.assertEqual(kwargs["timeout"], 15)
                last = self.publications()[-1]
                self.assertEqual(last["outcome"], "confirmed")
                self.assertEqual(self.entries(last["seq"]), count)
                self.assertEqual(int(self.node_shell.read(SEQ_FILE)), last["seq"])

    def test_the_ledger_records_before_the_write_and_settles_after(self):
        document, raw = synthetic_snapshot(50)
        seen = {}

        def runner(args, kwargs):
            seen["during"] = self.publications()
            seen["entries"] = self.entries(seen["during"][-1]["seq"])
            done = self.node_shell.run(args[2], kwargs.get("input"))
            return subprocess.CompletedProcess(args, done.returncode, done.stdout, done.stderr)

        self.assertTrue(self.publish(document, [{"kind": "live"}] * 50, runner=runner))
        self.assertEqual([row["outcome"] for row in seen["during"]], ["uncertain"])
        self.assertEqual(seen["entries"], 50)
        self.assertEqual([row["outcome"] for row in self.publications()], ["confirmed"])

    def test_exit_codes_the_caller_interprets(self):
        document, raw = synthetic_snapshot(5)
        meta = [{"kind": "live"}] * 5
        cases = (
            (3, "winn3-registry-stale-sequence 99999999999999999", "refused", ""),
            (3, "no marker", "uncertain", ""),
            (4, "winn3-gateway-group-absent", "refused", "group_absent"),
            (4, "no marker", "uncertain", ""),
            (5, "winn3-registry-bad-payload", "refused", ""),
            (5, "no marker", "uncertain", ""),
            (255, "ssh: connect to host: Connection timed out", "uncertain", ""),
            (1, "mktemp: failed", "uncertain", ""),
        )
        for code, stderr, outcome, refusal in cases:
            with self.subTest(code=code, stderr=stderr):
                before = len(self.publications())

                def runner(args, kwargs, code=code, stderr=stderr):
                    return subprocess.CompletedProcess(args, code, "", stderr)

                self.assertFalse(self.publish(document, meta, runner=runner))
                rows = self.publications()
                self.assertEqual(len(rows), before + 1)
                self.assertEqual((rows[-1]["outcome"], rows[-1]["refusal"]), (outcome, refusal))
                if "stale-sequence" in stderr:
                    # A refused stale write teaches the hub the node's own
                    # sequence: later publications start above it.
                    with self.mod.winn3_authority_ledger() as ledger:
                        floor = ledger.execute(
                            "SELECT value FROM winn3_ledger_meta WHERE key='seq_floor'").fetchone()
                    self.assertEqual(int(floor[0]), 99999999999999999)

    def test_a_damaged_stream_is_refused_but_never_drops_a_v3_node_from_recovery(self):
        # Exit 5 settles as refused (the node proved it wrote nothing), so its
        # entries stop counting as possibly live. Only the exact pair
        # (refused, group_absent) lets winn3_proven_unwritten_slugs prune a node
        # from recovery; a damaged stream must never be one.
        document, raw = synthetic_snapshot(5)
        meta = [{"kind": "live"}] * 5

        def damaged(args, kwargs):
            return subprocess.CompletedProcess(args, 5, "", "winn3-registry-bad-payload")

        def absent(args, kwargs):
            return subprocess.CompletedProcess(args, 4, "", "winn3-gateway-group-absent")

        def proven():
            with closing(sqlite3.connect(self.mod._DB)) as conn, self.mod.winn3_authority_ledger() as ledger:
                conn.row_factory = sqlite3.Row
                return self.mod.winn3_proven_unwritten_slugs(conn, ledger)

        # A node row that is not winn/3 and holds no descriptor is the only kind
        # recovery may prune.
        with closing(sqlite3.connect(self.mod._DB)) as conn, conn:
            conn.execute("INSERT OR IGNORE INTO nodes (slug, name, flag, endpoint, public_key, status, "
                         "ssh_host, operator_enabled) VALUES ('lab-alpha','lab-alpha','XX',"
                         "'203.0.113.5:51820','k','online','203.0.113.5', 1)")
            conn.execute("UPDATE nodes SET protocol_version='', winn3_descriptor_json='' "
                         "WHERE slug='lab-alpha'")
        self.assertFalse(self.publish(document, meta, runner=damaged))
        self.assertEqual(self.publications()[-1]["outcome"], "refused")
        self.assertEqual(self.publications()[-1]["refusal"], "")
        self.assertNotIn("lab-alpha", proven())
        # The contrast: a node that says it has no gateway group is provably
        # unwritten, and only then is it pruned.
        self.assertFalse(self.publish(document, meta, runner=absent))
        self.assertEqual(self.publications()[-1]["refusal"], "group_absent")
        self.assertIn("lab-alpha", proven())

    def test_every_damaged_delivery_settles_refused_and_a_good_one_lands_after(self):
        # The real caller, the real node command and a transport that damages
        # stdin on the way: each class is refused by the node (exit 5), settled
        # refused on the ledger, and leaves the node byte for byte as it was.
        count = 30
        document, raw = synthetic_snapshot(count)
        grants = [("%032x" % (0xbad000 + index), "1111-2222-3333") for index in range(2)]
        meta = [{"kind": "live"}] * (count - 2) + [
            {"kind": "departure", "grant_id": grant_id, "account_number": account}
            for grant_id, account in grants]
        ring = {"active": KEY_ID, "keys": {KEY_ID: {"key": KEY_HEX, "created_at": 0, "retired_at": None}}}
        self.assertTrue(self.publish(document, meta, keyring=ring))
        good = self.node_shell.tree()

        def flip(text, at):
            return text[:at] + ("0" if text[at] != "0" else "1") + text[at + 1:]

        damages = {
            "empty": lambda text: "",
            "cut in the registry": lambda text: text[: len(raw) // 2],
            "cut at the registry end": lambda text: text[: len(raw)],
            "one byte short": lambda text: text[:-1],
            "registry byte altered": lambda text: flip(text, 40),
            "journal byte altered": lambda text: flip(text, len(text) - 3),
            "extra bytes": lambda text: text + "END\n",
        }
        for label, damage in damages.items():
            with self.subTest(damage=label):

                def runner(args, kwargs, damage=damage):
                    done = self.node_shell.run(args[2], damage(kwargs["input"]))
                    return subprocess.CompletedProcess(args, done.returncode, done.stdout, done.stderr)

                self.assertFalse(self.publish(document, meta, keyring=ring, runner=runner))
                last = self.publications()[-1]
                self.assertEqual((last["outcome"], last["refusal"]), ("refused", ""), label)
                self.assertEqual(self.node_shell.tree(), good, label)
        self.assertTrue(self.publish(document, meta, keyring=ring))
        self.assertEqual(self.publications()[-1]["outcome"], "confirmed")

    def test_a_lifted_pool_over_the_release_ceiling_publishes_through_the_real_builder(self):
        # The hub's own builder and device rows, the /24 pin lifted to a /20 for
        # this test only: 1,200 entries, a release command well past 131072
        # bytes, published through stdin with a fixed-size command.
        mod = self.mod
        wide = ipaddress.IPv4Network("10.10.0.0/20")
        hosts = [str(host) for host in wide.hosts()][1:1201]
        now = mod.utcnow().isoformat()
        rows = [("dev-%d" % index, "1111-2222-3333", "m", "10.8.%d.%d" % (index >> 8, index & 255),
                 "pk%d" % index, "cp%d" % index, now, "lab-alpha", now, "h",
                 base64.b64encode(hashlib.sha256(b"w%d" % index).digest()).decode(), inner)
                for index, inner in enumerate(hosts, 1)]
        with mod.get_db() as conn:
            conn.executemany(
                "INSERT INTO devices (device_id, account_number, device_model, vpn_internal_ip, "
                "client_private_key, client_public_key, last_seen, location_slug, updated_at, "
                "device_auth_token_hash, winn3_static_public, winn3_inner_v4) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            conn.execute("INSERT OR IGNORE INTO nodes (slug, name, flag, endpoint, public_key, status, "
                         "ssh_host, operator_enabled) VALUES ('lab-alpha','lab-alpha','XX',"
                         "'203.0.113.5:51820','k','online','203.0.113.5', 1)")
            conn.execute("UPDATE nodes SET winn3_gateway_report_json=? WHERE slug='lab-alpha'",
                         (json.dumps({"peer_tier": True}),))
        real = mod.winn3_peer_registry_publication
        with patch.object(mod, "winn3_inner_pool", return_value=wide):
            done = self.publish(None, None, builder=lambda conn, slug, provisional=None: real(conn, slug, provisional))
        self.assertTrue(done, self.logs[-3:])
        landed = self.node_shell.read(REGISTRY)
        self.assertEqual(len(json.loads(landed)["peers"]), 1200)
        self.assertGreater(release_command_length(landed, ""), LINUX_MAX_ARG_STRLEN)
        argv, kwargs = self.calls[-1]
        self.assertLess(max(len(item) for item in argv), 4096)
        self.assertEqual(kwargs["input"], landed.decode("ascii"))

    def test_a_snapshot_above_the_gateway_limit_is_refused_before_anything_is_recorded_or_sent(self):
        limit = self.mod.WINN3_REGISTRY_MAX_BYTES
        low, high = 1, 20000
        while low < high:
            middle = (low + high + 1) // 2
            if len(synthetic_snapshot(middle)[1]) <= limit:
                low = middle
            else:
                high = middle - 1
        fits, too_big = low, low + 1
        self.assertLessEqual(len(synthetic_snapshot(fits)[1]), limit)
        self.assertGreater(len(synthetic_snapshot(too_big)[1]), limit)
        document, raw = synthetic_snapshot(too_big)
        self.assertFalse(self.publish(document, [{"kind": "live"}] * too_big))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.publications(), [])
        self.assertTrue([line for line in self.logs if "above the gateway limit" in line], self.logs)
        # One device fewer fits and publishes.
        document, raw = synthetic_snapshot(fits)
        self.assertTrue(self.publish(document, [{"kind": "live"}] * fits), self.logs[-3:])
        self.assertEqual(self.node_shell.read(REGISTRY), raw)

    def test_a_full_inner_pool_publishes_through_the_real_builder(self):
        # The hub pins the inner pool to exactly one /24 (_winn3_inner_pool_or_reason),
        # so no node can hold more entries than the pool has hosts. Fill it and
        # publish with the hub's own document builder, nothing patched but the
        # transport.
        mod = self.mod
        pool = mod.winn3_inner_pool()
        hosts = [str(host) for host in pool.hosts()][1:]  # .1 is the gateway
        now = mod.utcnow().isoformat()
        rows = [("dev-%d" % index, "1111-2222-3333", "m", "10.8.%d.%d" % (index >> 8, index & 255),
                 "pk%d" % index, "cp%d" % index, now, "lab-alpha", now, "h",
                 base64.b64encode(hashlib.sha256(b"k%d" % index).digest()).decode(), inner)
                for index, inner in enumerate(hosts, 1)]
        with mod.get_db() as conn:
            conn.executemany(
                "INSERT INTO devices (device_id, account_number, device_model, vpn_internal_ip, "
                "client_private_key, client_public_key, last_seen, location_slug, updated_at, "
                "device_auth_token_hash, winn3_static_public, winn3_inner_v4) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            conn.execute("INSERT OR IGNORE INTO nodes (slug, name, flag, endpoint, public_key, status, "
                         "ssh_host, operator_enabled) VALUES ('lab-alpha','lab-alpha','XX',"
                         "'203.0.113.5:51820','k','online','203.0.113.5', 1)")
            # A node whose gateway reports peer-registry-tier gets the tier word
            # on every entry (FREE-CAP): the larger document is the one to test.
            conn.execute("UPDATE nodes SET winn3_gateway_report_json=? WHERE slug='lab-alpha'",
                         (json.dumps({"peer_tier": True}),))
        mod_publication = mod.winn3_peer_registry_publication
        document = {}

        def real_builder(conn, slug, provisional=None):
            document["value"], meta = mod_publication(conn, slug, provisional)
            return document["value"], meta

        done = self.publish(None, None, builder=real_builder)
        self.assertTrue(done, self.logs[-3:])
        landed = json.loads(self.node_shell.read(REGISTRY))
        self.assertEqual(len(landed["peers"]), len(hosts))
        self.assertEqual(len(hosts), 253)
        self.assertEqual({entry.get("tier") for entry in landed["peers"]} - {None}, {"premium"})
        self.assertTrue(all("tier" in entry for entry in landed["peers"]))
        argv, kwargs = self.calls[-1]
        self.assertEqual(self.node_shell.read(REGISTRY).decode("ascii"), kwargs["input"])
        # Latent today, not live: even the release form fits below the argv limit
        # at a full /24 (about 40 KB of 131072), which is why nothing failed yet.
        self.assertLess(release_command_length(self.node_shell.read(REGISTRY), ""), LINUX_MAX_ARG_STRLEN // 2)

    def test_every_address_of_the_pool_fits_under_the_registry_limit(self):
        # The invariant that makes the file limit safe: a fully populated pool
        # is always publishable. Widening the pool past this is the moment to
        # raise the gateway's maximumRegistryBytes and WINN3_REGISTRY_MAX_BYTES
        # together (and to make the gateway reload only a changed file).
        pool = self.mod.winn3_inner_pool()
        # The widest entry the builder emits: the longest address text, a ten
        # digit expiry and the longer FREE-CAP tier word, which a node that
        # reports peer-registry-tier carries on every entry.
        worst = len(json.dumps({"inner_v4": "255.255.255.255", "not_after": 9999999999,
                                "static_public": "A" * 44, "tier": "premium"},
                               sort_keys=True, separators=(",", ":")))
        self.assertLessEqual(24 + pool.num_addresses * (worst + 1), self.mod.WINN3_REGISTRY_MAX_BYTES)

    def test_the_hub_limit_equals_the_gateways(self):
        source = GATEWAY_GO.read_text(encoding="utf-8")
        match = re.search(r"const maximumRegistryBytes = ([0-9 *]+)\n", source)
        self.assertIsNotNone(match)
        self.assertEqual(eval(match.group(1), {"__builtins__": {}}), self.mod.WINN3_REGISTRY_MAX_BYTES)

    def test_journal_tokens_stay_out_of_argv_and_logs_and_reach_the_node_journal(self):
        count = 30
        document, raw = synthetic_snapshot(count)
        grants = [("%032x" % (0xabc000 + index), "1111-2222-3333") for index in range(3)]
        meta = [{"kind": "live"}] * (count - 3) + [
            {"kind": "departure", "grant_id": grant_id, "account_number": account}
            for grant_id, account in grants]
        ring = {"active": KEY_ID, "keys": {KEY_ID: {"key": KEY_HEX, "created_at": 0, "retired_at": None}}}
        tokens = [hmac_token(account, grant_id) for grant_id, account in grants]

        def failing(args, kwargs):
            return subprocess.CompletedProcess(args, 1, "", "boom")

        self.assertFalse(self.publish(document, meta, keyring=ring, runner=failing))
        self.assertTrue(self.publish(document, meta, keyring=ring))
        for argv, kwargs in self.calls:
            for token in tokens:
                self.assertNotIn(token, " ".join(argv))
                self.assertIn(token, kwargs["input"])
            for grant_id, _ in grants:
                self.assertNotIn(grant_id, " ".join(argv))
        for line in self.logs:
            for token in tokens:
                self.assertNotIn(token, line)
        journal = self.node_shell.read(JOURNAL).decode().splitlines()
        self.assertEqual(sorted(line.split()[0] for line in journal), sorted(g for g, _ in grants))
        self.assertEqual(sorted(line.split()[3] for line in journal), sorted(tokens))

    def test_a_ssh_timeout_logs_no_token_and_no_registry(self):
        # subprocess.TimeoutExpired renders the whole argv into its message, and
        # the hub logs that message ("Winn3 registry sync warning"). The release
        # command carried the registry and the journal tokens, so a 15 s timeout
        # wrote them to the hub log; the command now carries neither.
        count = 40
        document, raw = synthetic_snapshot(count)
        grants = [("%032x" % (0xfed000 + index), "1111-2222-3333") for index in range(3)]
        meta = [{"kind": "live"}] * (count - 3) + [
            {"kind": "departure", "grant_id": grant_id, "account_number": account}
            for grant_id, account in grants]
        ring = {"active": KEY_ID, "keys": {KEY_ID: {"key": KEY_HEX, "created_at": 0, "retired_at": None}}}
        tokens = [hmac_token(account, grant_id) for grant_id, account in grants]

        def hung(args, kwargs):
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])

        self.assertFalse(self.publish(document, meta, keyring=ring, runner=hung))
        lines = [line for line in self.logs if "registry sync warning" in line]
        self.assertEqual(len(lines), 1, self.logs)
        self.assertIn("timed out", lines[0])
        self.assertLess(len(lines[0]), 4096)
        for token in tokens:
            self.assertNotIn(token, lines[0])
        self.assertNotIn(raw[:80].decode("ascii"), lines[0])
        # The attempt stays on the ledger as uncertain: the write may have landed.
        self.assertEqual([row["outcome"] for row in self.publications()], ["uncertain"])

    def test_the_read_back_parses_what_the_new_publication_wrote(self):
        count = 25
        document, raw = synthetic_snapshot(count)
        grants = [("%032x" % (0xdef000 + index), "1111-2222-3333") for index in range(2)]
        meta = [{"kind": "live"}] * (count - 2) + [
            {"kind": "departure", "grant_id": grant_id, "account_number": account}
            for grant_id, account in grants]
        ring = {"active": KEY_ID, "keys": {KEY_ID: {"key": KEY_HEX, "created_at": 0, "retired_at": None}}}
        self.assertTrue(self.publish(document, meta, keyring=ring))
        mod = self.mod

        def runner(args, kwargs):
            done = self.node_shell.run(args[2], kwargs.get("input"))
            return subprocess.CompletedProcess(args, done.returncode, done.stdout, done.stderr)

        with patch.object(mod, "node_ssh_command", side_effect=lambda host, cmd, **kw: ["l57-node", host, cmd]), \
                patch.object(mod.subprocess, "run", side_effect=lambda args, **kw: runner(args, kw)):
            self.assertTrue(mod.observe_winn3_node("127.0.0.1", "lab-alpha", gateway="127.0.0.1"))
        with mod.winn3_authority_ledger() as ledger:
            observed = ledger.execute(
                "SELECT COUNT(*) FROM winn3_publication_entries WHERE kind='observed'").fetchone()[0]
            charges = ledger.execute("SELECT COUNT(*) FROM winn3_observed_charges").fetchone()[0]
        self.assertEqual(observed, count)
        self.assertEqual(charges, 2)


class CallerCoverageTests(HubCase):
    """Item 3: every node_ssh_command and core_ssh_command caller, and why none of
    the others can grow with the number of users, devices, peers or rules."""

    # function -> (kind, why)
    CALLERS = {
        "sync_winn3_registry_to_node": ("stdin", "registry and journal travel on stdin"),
        "observe_winn3_node": ("fixed", "fixed script; the registry comes back on stdout"),
        "sync_peer_to_node": ("per-peer", "one peer per call: a 44 character key, a /32, one preshared key"),
        "remove_peer_from_node": ("per-peer", "one 44 character key per call"),
        "verify_node_management_access": ("fixed", "constant probe"),
        "winn3_pull_identity": ("fixed", "constant python program, fixed paths"),
        "hub_offnode_check_run": ("fixed", "constants plus one 44 character canary key"),
        "hub_offnode_gateway_restart": ("fixed", "one constant systemctl restart command plus one 64 character digest"),
        "verify_core_management_tunnel": ("fixed", "constant systemctl probe"),
    }

    def callers(self):
        tree = ast.parse(harness._extract_main_block())
        found = {}

        class Visitor(ast.NodeVisitor):
            def __init__(visitor):  # noqa: N805
                visitor.stack = []

            def visit_FunctionDef(visitor, node):  # noqa: N805
                visitor.stack.append(node.name)
                visitor.generic_visit(node)
                visitor.stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(visitor, node):  # noqa: N805
                name = getattr(node.func, "id", "")
                if name in ("node_ssh_command", "core_ssh_command") and visitor.stack \
                        and visitor.stack[-1] not in ("node_ssh_command", "core_ssh_command"):
                    found.setdefault(visitor.stack[-1], []).append(node.lineno)
                visitor.generic_visit(node)

        Visitor().visit(tree)
        return found

    def test_every_call_site_is_classified(self):
        found = self.callers()
        self.assertEqual(set(found), set(self.CALLERS),
                         "a new node_ssh_command or core_ssh_command caller must be classified here")

    def capture(self, function, *args, **kwargs):
        mod = self.mod
        calls = []

        def ssh(host, remote_command, **kw):
            return ["l57-node", str(host), remote_command]

        def fake_run(argv, **kw):
            calls.append((list(argv), dict(kw)))
            return subprocess.CompletedProcess(argv, 1, "", "stub")

        with patch.object(mod, "node_ssh_command", side_effect=ssh), \
                patch.object(mod, "core_ssh_command", side_effect=lambda h, u, c, **kw: ["l57-core", h, c]), \
                patch.object(mod.subprocess, "run", side_effect=fake_run):
            try:
                function(*args, **kwargs)
            except Exception:
                pass
        return calls

    def test_the_other_callers_build_a_bounded_command_that_does_not_depend_on_the_fleet(self):
        mod = self.mod
        key = base64.b64encode(b"\x07" * 32).decode()
        cfg = {"client_public_key": key, "vpn_internal_ip": "255.255.255.255", "preshared_key": key,
               "node_max_peers": 65535}
        node = {"slug": "lab-alpha", "ssh_host": "203.0.113.9", "endpoint": "203.0.113.9:51820"}
        mod.AWG_CANARY_PUBLIC_KEY = key
        probes = {
            "sync_peer_to_node": lambda: mod.sync_peer_to_node("203.0.113.9", cfg),
            "remove_peer_from_node": lambda: mod.remove_peer_from_node("203.0.113.9", key),
            "verify_node_management_access": lambda: mod.verify_node_management_access("203.0.113.9"),
            "winn3_pull_identity": lambda: mod.winn3_pull_identity(node),
            "hub_offnode_check_run": lambda: mod.hub_offnode_check_run("203.0.113.9"),
            "hub_offnode_gateway_restart": lambda: mod.hub_offnode_gateway_restart("203.0.113.9", "0" * 64),
            "observe_winn3_node": lambda: mod.observe_winn3_node("203.0.113.9", "lab-alpha", gateway="203.0.113.9"),
        }
        with closing(sqlite3.connect(mod._DB)) as conn, conn:
            conn.row_factory = sqlite3.Row
            mod.ensure_schema(conn)
        sizes = {}
        for name, probe in probes.items():
            calls = self.capture(probe)
            self.assertEqual(len(calls), 1, name)
            sizes[name] = max(len(item) for item in calls[0][0])
            self.assertLess(sizes[name], 8192, name)
        # A fleet of 2,000 devices changes none of them.
        harness.seed_account(mod, devices=2000)
        for name, probe in probes.items():
            calls = self.capture(probe)
            self.assertEqual(len(calls), 1, name)
            self.assertEqual(max(len(item) for item in calls[0][0]), sizes[name], name)

    def test_a_ssh_timeout_logs_no_preshared_key(self):
        # The v1 peer sync still carries the peer's preshared key inside its
        # command (one 44 character key per call, it does not grow). What it
        # must not do is write that command to the hub log: the text of
        # subprocess.TimeoutExpired renders the whole argv, and the release hub
        # logged it ("Peer sync warning") on every 15 s timeout.
        mod = self.mod
        logs = []

        class Collect(logging.Handler):
            def emit(handler, record):  # noqa: N805
                logs.append(record.getMessage())

        handler = Collect(level=logging.DEBUG)
        mod.logger.addHandler(handler)
        mod.logger.setLevel(logging.DEBUG)
        self.addCleanup(mod.logger.removeHandler, handler)
        psk = base64.b64encode(bytes(range(32))).decode()
        key = base64.b64encode(b"p" * 32).decode()
        cfg = {"client_public_key": key, "vpn_internal_ip": "10.10.0.2", "preshared_key": psk,
               "traffic_tier": "premium"}
        seen = []

        def hung(argv, **kwargs):
            seen.append(" ".join(argv))
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        with patch.object(mod, "node_ssh_command", side_effect=lambda host, cmd, **kw: ["l57-node", host, cmd]), \
                patch.object(mod.subprocess, "run", side_effect=hung):
            self.assertFalse(mod.sync_peer_to_node("203.0.113.9", cfg))
        self.assertEqual(len(seen), 1)
        self.assertIn(psk, seen[0])  # unchanged: the key still travels in the command
        lines = [line for line in logs if "Peer sync" in line]
        self.assertEqual(len(lines), 1, logs)
        self.assertIn("timed out", lines[0])
        self.assertNotIn(psk, lines[0])
        self.assertLess(len(lines[0]), 512)

    def test_the_core_probe_command_is_a_literal(self):
        tree = ast.parse(harness._extract_main_block())
        literal = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "verify_core_management_tunnel":
                for item in ast.walk(node):
                    if isinstance(item, ast.Assign) and any(
                            getattr(target, "id", "") == "command" for target in item.targets):
                        literal = isinstance(item.value, ast.Constant) and isinstance(item.value.value, str)
        self.assertTrue(literal)

    def test_the_probe_module_callers_are_classified(self):
        # The embedded data-plane probe has its own node_ssh_command: one
        # interface and filter per capture, one datagram per send.
        sys.path.insert(0, str(TOOLS))
        from validate_deployment_scripts import parse_heredocs
        body = next(block.body for block in parse_heredocs(INSTALLER)
                    if block.header.strip() == "cat > /usr/local/lib/wins_node_dataplane_probe.py <<'DPPROBEEOF'")
        found = []
        for function in ast.parse(body).body:
            if isinstance(function, ast.FunctionDef):
                for call in ast.walk(function):
                    if isinstance(call, ast.Call) and getattr(call.func, "id", "") == "node_ssh_command":
                        found.append(function.name)
        self.assertCountEqual(found, ["_run_capture_probe", "probe_udp"])

    def test_no_size_growing_payload_is_quoted_into_a_remote_command(self):
        source = harness._extract_main_block()
        self.assertNotIn("shlex.quote(payload)", source)
        self.assertNotIn("shlex.quote(journal_lines)", source)
        self.assertNotIn('| base64 -d > \\"$tmp\\"', source)
        body = source[source.index("def sync_winn3_registry_to_node"):source.index("def observe_winn3_node")]
        # The bounded management runner takes subprocess.run's arguments.
        run_at = body.index("result = run_management_ssh_bounded(")
        self.assertIn("input=stdin_text", body[run_at:body.index("env=management_ssh_env()", run_at)])

    def test_resync_makes_one_bounded_call_per_peer(self):
        # resync_active_peers_to_node loops over peers and calls sync_peer_to_node
        # once for each, so the number of ssh sessions grows with the fleet and
        # the size of every one of them does not.
        source = harness._extract_main_block()
        body = source[source.index("def resync_active_peers_to_node"):]
        body = body[:body.index("\ndef remove_peer_from_node")]
        self.assertIn("sync_peer_to_node(node_ip, {", body)
        self.assertNotIn("node_ssh_command", body)


class HubLiteEmulatorTests(HubCase):
    """The hub-lite node emulator answers the new command with the node's own
    gates, in the node's order."""

    def test_the_emulator_applies_the_same_stream_and_sequence_gates(self):
        sys.path.insert(0, str(TOOLS / "onetouch_tiers"))
        import hub_lite
        root = Path(self.work) / "emulated"
        root.mkdir()
        hub = type("Hub", (), {"node_plan": staticmethod(lambda slug: {}),
                               "node_dir": staticmethod(lambda slug: root)})()
        emulator = hub_lite.NodeEmulator(hub)
        _, raw = synthetic_snapshot(12)
        journal = journal_for([("%032x" % 5, "1111-2222-3333")])
        command, stream = self.mod.winn3_registry_publish_command(7, raw, journal, 0)
        for damaged in ("", stream[:-1], stream + "X", stream[:-3] + "0" + stream[-2:]
                        if stream[-3] != "0" else stream[:-3] + "1" + stream[-2:]):
            self.assertEqual(emulator._answer("lab", command, damaged)[1], 5)
            self.assertFalse((root / "emulated_node.json").exists())
        kind, rc, _, err = emulator._answer("lab", command, stream)
        self.assertEqual((kind, rc), ("registry-publish", 0), err)
        state = json.loads((root / "emulated_node.json").read_text())
        self.assertEqual(base64.b64decode(state["registry_b64"]), raw)
        self.assertEqual(emulator._answer("lab", command, stream)[1:3], (3, ""))


if __name__ == "__main__":
    unittest.main()
