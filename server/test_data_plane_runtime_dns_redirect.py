"""The periodic egress refresh must preserve the edge DNS redirect policy."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server/wins_data_plane_setup_ONETOUCH.sh"
FAKE = ROOT / "tools/fake_netfilter.py"
BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash")


class RuntimeDNSRedirectTests(unittest.TestCase):
    def test_refresh_preserves_both_dns_redirects_on_each_vpn_interface(self):
        source = INSTALLER.read_text()
        start = source.index("write_runtime_vpn_firewall_unit() {\n")
        end = source.index('  install -m 600 -o root -g root "${transaction_tmp}"', start)
        renderer = source[start:end] + '  cat "${transaction_tmp}"\n}\n'
        script = (
            "set -Eeuo pipefail\n"
            "ip() { printf 'default via 192.0.2.1 dev eth0\\n'; }\n"
            "warn() { printf '%s\\n' \"$*\" >&2; }\n"
            "WAN_IF=eth0; VPN_INTERFACES='awg0 amn0'; VPN_CIDR=10.8.0.0/16\n"
            "VPN_TCP_SYN_RATE_LIMIT=100/sec; VPN_TCP_SYN_RATE_BURST=200\n"
            + renderer + "write_runtime_vpn_firewall_unit\n"
        )
        spec = importlib.util.spec_from_file_location("fake_netfilter", FAKE)
        fake = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fake)
        with tempfile.TemporaryDirectory() as temporary:
            env = dict(os.environ, TMPDIR=temporary,
                       FAKE_IPT_STATE=str(Path(temporary) / "iptables.json"))
            rendered = subprocess.run([BASH, "-c", script], text=True,
                                      capture_output=True, env=env, timeout=10)
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            state = fake.empty_state()
            redirects = [
                f"-i {interface} -p {protocol} --dport 53 -j REDIRECT --to-ports 53"
                for interface in ("awg0", "amn0") for protocol in ("udp", "tcp")
            ]
            state["nat"]["WINVPN-NAT-PREROUTING"] = {"policy": "-", "rules": redirects}
            jumps = [f"-i {interface} -j WINVPN-NAT-PREROUTING"
                     for interface in ("awg0", "amn0")]
            state["nat"]["PREROUTING"]["rules"] = jumps
            import json
            Path(env["FAKE_IPT_STATE"]).write_text(json.dumps(state))
            for refresh in range(2):
                applied = subprocess.run(
                    [sys.executable, str(FAKE), "iptables-restore", "--wait", "10", "--noflush"],
                    input=rendered.stdout, text=True, capture_output=True, env=env, timeout=10)
                self.assertEqual(applied.returncode, 0, applied.stderr)
                state = json.loads(Path(env["FAKE_IPT_STATE"]).read_text())
                self.assertEqual(state["nat"]["WINVPN-NAT-PREROUTING"]["rules"],
                                 redirects, f"DNS redirects lost on refresh {refresh + 1}")
                self.assertEqual(state["nat"]["PREROUTING"]["rules"], jumps)
                self.assertIn("-s 10.8.0.0/16 -o eth0 -j MASQUERADE",
                              state["nat"]["WINVPN-NAT-POSTROUTING"]["rules"])


if __name__ == "__main__":
    unittest.main()
