"""Managed SSH output must be bounded before it enters hub memory.

The runner is extracted from the control installer's main.py heredoc and run
against local child processes standing in for ssh; nothing contacts a host.
"""

import ast
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "server/wins_control_plane_setup_ONETOUCH.sh"
NAMES = {"_drain_management_pipe", "run_management_ssh_bounded", "winn3_pull_identity"}


def load(extra=None):
    source = INSTALLER.read_text()
    start = source.index('  cat > "${APP_DIR}/main.py" <<\'PYEOF\'')
    end = source.index("\nPYEOF", start)
    module = ast.parse(source[source.index("\n", start) + 1:end])
    selected = [
        node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name in NAMES
    ]
    assert {node.name for node in selected} == NAMES, "runner or caller missing from main.py"
    namespace = {
        "Any": object,
        "MANAGEMENT_SSH_MAX_STDOUT_BYTES": 64 * 1024,
        "MANAGEMENT_SSH_STDERR_TAIL_BYTES": 16 * 1024,
        "management_ssh_env": lambda: {"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        "json": json,
        "os": os,
        "shlex": shlex,
        "subprocess": subprocess,
        "threading": threading,
        "time": time,
    }
    namespace.update(extra or {})
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(INSTALLER), "exec"), namespace)
    return namespace


def child(script):
    return [sys.executable, "-I", "-c", script]


class ManagementOutputBoundTest(unittest.TestCase):
    def test_stdout_flood_is_refused(self):
        run = load()["run_management_ssh_bounded"]
        with self.assertRaisesRegex(ValueError, "management-ssh-output-oversize"):
            run(child("import sys; sys.stdout.write('x' * (8 * 1048576))"), timeout=20, text=True)

    def test_reply_at_the_limit_is_accepted(self):
        run = load()["run_management_ssh_bounded"]
        done = run(child("import sys; sys.stdout.write('y' * 4096)"), timeout=20, text=True, max_stdout=4096)
        self.assertEqual((done.returncode, done.stdout), (0, "y" * 4096))

    def test_stderr_flood_keeps_only_its_tail(self):
        run = load()["run_management_ssh_bounded"]
        done = run(child("import sys; sys.stderr.write('e' * 1048576 + 'TAIL'); sys.exit(3)"), timeout=20, text=True)
        self.assertEqual(done.returncode, 3)
        self.assertEqual(len(done.stderr), 16 * 1024)
        self.assertTrue(done.stderr.endswith("TAIL"))

    def test_stdin_round_trip_text_and_exit_status(self):
        run = load()["run_management_ssh_bounded"]
        script = "import sys; data = sys.stdin.read(); print(len(data)); print('ok\\r'); sys.exit(4)"
        done = run(child(script), timeout=20, text=True, input="z" * 262144)
        self.assertEqual(done.returncode, 4)
        # "ok\r\n" arrives as "ok\n", as subprocess.run(text=True) gives it.
        self.assertEqual(done.stdout, "262144\nok\n")

    def test_bytes_mode(self):
        run = load()["run_management_ssh_bounded"]
        done = run(child("import sys; sys.stdout.buffer.write(b'\\xff\\x00')"), timeout=20)
        self.assertEqual(done.stdout, b"\xff\x00")

    def test_timeout_still_kills_a_flooding_child(self):
        run = load()["run_management_ssh_bounded"]
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run(child("import time, sys; sys.stdout.write('x' * 1048576); sys.stdout.flush(); time.sleep(30)"),
                timeout=1, text=True, max_stdout=64)
        self.assertLess(time.monotonic() - started, 10)

    def test_a_grandchild_holding_the_pipe_times_out(self):
        run = load()["run_management_ssh_bounded"]
        script = ("import subprocess, sys; subprocess.Popen([sys.executable, '-I', '-c', "
                  "'import time; time.sleep(6)']); sys.stdout.write('done')")
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            run(child(script), timeout=1, text=True)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(raised.exception.cmd, ["ssh"])

    def test_substituted_runner_output_is_passed_through(self):
        fake = subprocess.CompletedProcess(["ssh"], 0, "from the node simulation", "")
        calls = []

        class FakeSubprocess:
            TimeoutExpired = subprocess.TimeoutExpired
            CompletedProcess = subprocess.CompletedProcess
            DEVNULL = subprocess.DEVNULL

            @staticmethod
            def run(command, **kwargs):
                calls.append(kwargs)
                return fake

        run = load({"subprocess": FakeSubprocess})["run_management_ssh_bounded"]
        self.assertIs(run(["ssh", "node", "true"], timeout=15, check=False, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, env={"PATH": "/bin"}), fake)
        self.assertIs(calls[0]["check"], False)
        self.assertEqual(calls[0]["timeout"], 15)
        self.assertIs(calls[0]["stdin"], subprocess.DEVNULL)
        self.assertEqual(calls[0]["env"], {"PATH": "/bin"})
        self.assertNotIn("capture_output", calls[0])

    def test_identity_pull_refuses_an_oversize_node_reply(self):
        script = "import sys; sys.stdout.write('x' * 1048576)"
        namespace = load({
            "_node_field": lambda node, field: node.get(field),
            "extract_node_host": lambda endpoint: "node",
            "node_ssh_command": lambda host, command, multiplex: child(script),
        })
        with self.assertRaisesRegex(ValueError, "management-ssh-output-oversize"):
            namespace["winn3_pull_identity"]({"ssh_host": "node", "endpoint": "node:9111"})


if __name__ == "__main__":
    unittest.main()
