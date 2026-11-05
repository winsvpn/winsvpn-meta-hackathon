"""Inspect real generated firewall argv with shell command mocks."""
import pathlib
import shlex
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "linux/runner/linux_tunnel_backend.cc"


def function(source, name):
    start = source.index(name + "() {\n")
    return source[start:source.index("\n}\n", start) + 3]


class IPv6LinkControlTests(unittest.TestCase):
    def rules(self, family):
        source = SOURCE.read_text()
        script = "set -eu\n"
        if "append_ipv6_link_control() {" in source:
            script += function(source, "append_ipv6_link_control")
        script += function(source, "build_winn3_ks_chain")
        script += r'''
iptables() { printf '%s\n' "$*"; }
ip6tables() { printf '%s\n' "$*"; }
WINN_IPT=ip6tables
WINN_HOST=2001:db8::10
WINN_PORT=51820
build_winn3_ks_chain "$1"
'''
        result = subprocess.run(["/bin/sh", "-c", script, "fixture", family],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [shlex.split(line) for line in result.stdout.splitlines()]

    def test_v3_keeps_neighbor_discovery_before_reject(self):
        rules = self.rules("ip6tables")
        reject = next(i for i, row in enumerate(rules) if row[-1] == "REJECT")
        nd_rows = [row for row in rules if "--icmpv6-type" in row]
        self.assertEqual(len(nd_rows), 3)
        for kind in ("133", "135", "136"):
            row = next(row for row in nd_rows
                       if row[row.index("--icmpv6-type") + 1] == kind)
            self.assertLess(rules.index(row), reject)
            self.assertEqual(row[row.index("--hl-eq") + 1], "255")
            self.assertEqual(row[row.index("-p") + 1], "ipv6-icmp")
            self.assertEqual(row[row.index("--comment") + 1],
                             "winsvpn-killswitch3")
            self.assertEqual(row[-1], "RETURN")

    def test_ipv4_policy_does_not_gain_icmp_bypass(self):
        self.assertFalse(any("--icmpv6-type" in row
                             for row in self.rules("iptables")))

    def test_awg_and_transition_guard_use_same_helper(self):
        source = SOURCE.read_text()
        awg = function(source, "configure_kill_switch")
        guard = function(source, "begin_reconnect_guard")
        self.assertLess(awg.index('append_ipv6_link_control "$IPT" WINSVPN_KS'),
                        awg.index('KS_BATCH="$CIDR_FILE.rules"'))
        self.assertLess(guard.index('append_ipv6_link_control "$IPT"'),
                        guard.index('--comment winsvpn-reconnect-guard -j REJECT'))


if __name__ == "__main__":
    unittest.main()
