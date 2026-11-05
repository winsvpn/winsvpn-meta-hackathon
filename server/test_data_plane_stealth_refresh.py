"""Observe every firewall mutation, including the middle of a refresh."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tools/fake_netfilter.py"
INSTALLER = ROOT / "server/wins_data_plane_setup_ONETOUCH.sh"
BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash")

BACKEND = r'''
import importlib.util, json, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("netfilter", os.environ["FAKE_MODULE"])
fake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fake)
if sys.argv[1] == "restore":
    if os.environ.get("FAIL_RESTORE") == "1":
        sys.stdin.read()
        rc = 1
    else:
        rc = fake.run_restore(sys.argv[2:])
else:
    rc = fake.run_iptables(sys.argv[2:])
state = fake.load()
chain = state["filter"].get("WINVPN-STEALTH-CF", {}).get("rules", [])
# A new non-loopback connection from outside the allowed range reaches DROP.
# No matching DROP means RETURN to WINVPN-INPUT's default public accepts.
closed = "-j DROP" in chain
with open(os.environ["OBSERVATIONS"], "a") as handle:
    handle.write(json.dumps({"closed": closed, "args": sys.argv[1:]}) + "\n")
sys.exit(rc)
'''


class StealthRefreshTests(unittest.TestCase):
    def exercise(self, fail_restore=False):
        source = INSTALLER.read_text().split("write_runtime_vpn_firewall_unit() {", 1)[1]
        def function(name):
            return re.search(r"^" + name + r"\(\) \{\n.*?^\}\n",
                             source, re.M | re.S).group()
        spec = importlib.util.spec_from_file_location("netfilter", FAKE)
        fake = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fake)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            backend = work / "backend.py"
            backend.write_text(BACKEND)
            restore = work / "restore"
            import shlex
            restore.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable)
                               + " " + shlex.quote(str(backend)) + ' restore "$@"\n')
            restore.chmod(0o700)
            state = fake.empty_state()
            old = ["-s 192.0.2.0/24 -j RETURN", "-j DROP"]
            state["filter"]["WINVPN-STEALTH-CF"] = {"policy": "-", "rules": old}
            state["filter"]["INPUT"]["rules"] = [
                "-p tcp -m multiport --dports 80,443 -j WINVPN-STEALTH-CF"]
            state_path = work / "state.json"
            state_path.write_text(json.dumps(state))
            observations = work / "observations.jsonl"
            env = dict(os.environ, FAKE_MODULE=str(FAKE), FAKE_IPT_STATE=str(state_path),
                       OBSERVATIONS=str(observations), IPT_RESTORE_BIN=str(restore),
                       BACKEND=str(backend), PYTHON=sys.executable,
                       FAIL_RESTORE="1" if fail_restore else "0")
            script = (
                "set -u\n"
                'ipt() { "$PYTHON" "$BACKEND" iptables "$@"; }\n'
                'fail() { printf "%s\\n" "$*" >&2; }\n'
                + function("ensure_jump") + function("winvpn_fw_build_stealth_chain")
                + "winvpn_fw_build_stealth_chain 203.0.113.0/24\n"
            )
            proc = subprocess.run([BASH, "-c", script], env=env, text=True,
                                  capture_output=True, timeout=20)
            observed = [json.loads(line) for line in observations.read_text().splitlines()]
            result = json.loads(state_path.read_text())["filter"]["WINVPN-STEALTH-CF"]["rules"]
            return proc, observed, result, old

    def test_refresh_has_no_intermediate_open_chain(self):
        proc, observed, result, _ = self.exercise()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(observed)
        self.assertTrue(all(item["closed"] for item in observed),
                        "Refresh exposed a referenced empty chain: " + str(observed))
        self.assertIn("-s 203.0.113.0/24 -j RETURN", result)
        self.assertNotIn("-s 192.0.2.0/24 -j RETURN", result)
        self.assertEqual(result[-1], "-j DROP")

    def test_rejected_transaction_preserves_previous_chain(self):
        proc, observed, result, old = self.exercise(fail_restore=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(all(item["closed"] for item in observed))
        self.assertEqual(result, old)


if __name__ == "__main__":
    unittest.main()
