#!/usr/bin/env python3
"""Config contract for the Xray-core v26.9.30 pin (owner decision 2026-10-06).

Xray-core v26.4.15 and newer block Freedom outbound traffic that came in over
a VLESS/VMess/Trojan/Shadowsocks/Hysteria/WireGuard inbound when the final
destination is a private or loopback address, unless a `finalRules` entry
allows it (infra/conf/freedom.go and proxy/freedom/freedom.go, the default
safe policy). Both generated server configs forward to a loopback AmneziaWG
port through `"redirect": "127.0.0.1:<port>"`, so without an explicit allow
rule every tunnel would be silently black-holed for 30 to 90 seconds per
connection while `xray -test` still passes.

Xray-core v26.7.11 and newer also refuse a VLESS outbound without TLS (or
VLESS encryption) to a public address (validateOutboundTransportSecurity).
The Core exit probe must therefore not select a plaintext candidate for such
a host.

These are source-level checks. They do not run the Xray binary.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "server/wins_data_plane_setup_ONETOUCH.sh"
CORE = ROOT / "server/wins_core_server_setup_ONETOUCH.sh"
SELFTEST = ROOT / "tools/xray_udp_tunnel_selftest.sh"

PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def render_heredoc_config(source: str, marker: str, values: dict[str, str]) -> dict:
    start = source.index(marker)
    body_start = source.index("\n", start) + 1
    body = source[body_start : source.index("\nEOF\n", body_start)]
    rendered = PLACEHOLDER.sub(lambda m: values.get(m.group(1), "1"), body)
    return json.loads(rendered)


def freedom_outbound(config: dict, tag: str) -> dict:
    for outbound in config["outbounds"]:
        if outbound.get("tag") == tag:
            assert outbound["protocol"] == "freedom"
            return outbound
    raise AssertionError(f"outbound {tag} missing")


def assert_loopback_allow(test: unittest.TestCase, outbound: dict, port: str) -> None:
    settings = outbound["settings"]
    test.assertEqual(settings["redirect"], f"127.0.0.1:{port}")
    rules = settings.get("finalRules")
    test.assertTrue(rules, "freedom redirect to loopback needs a finalRules allow")
    first = rules[0]
    test.assertEqual(first["action"], "allow")
    test.assertEqual(first["network"], "udp")
    test.assertEqual(first["ip"], ["127.0.0.1"])
    test.assertEqual(str(first["port"]), port)
    # Never widen the allow beyond the exact redirect target.
    for rule in rules:
        if rule["action"] == "allow":
            test.assertEqual(rule["ip"], ["127.0.0.1"])
            test.assertEqual(str(rule["port"]), port)


class XrayV2690ConfigContract(unittest.TestCase):
    def test_data_plane_loopback_redirect_is_explicitly_allowed(self) -> None:
        config = render_heredoc_config(
            DATA.read_text(encoding="utf-8"),
            "cat > /usr/local/etc/xray/config.json <<EOF",
            {"WG_PORT": "9110"},
        )
        assert_loopback_allow(self, freedom_outbound(config, "forward-to-amneziawg"), "9110")

    def test_core_loopback_redirect_is_explicitly_allowed(self) -> None:
        config = render_heredoc_config(
            CORE.read_text(encoding="utf-8"),
            "cat > /usr/local/etc/xray/config.json <<EOF",
            {"CORE_INGRESS_PORT": "9210"},
        )
        assert_loopback_allow(self, freedom_outbound(config, "forward-to-core-awg"), "9210")

    def test_selftest_rig_allows_its_loopback_redirect(self) -> None:
        text = SELFTEST.read_text(encoding="utf-8")
        start = text.index('cat >"${work_dir}/server.json" <<EOF')
        body = text[text.index("\n", start) + 1 :]
        body = body[: body.index("\nEOF\n")]
        config = json.loads(PLACEHOLDER.sub("1", body))
        assert_loopback_allow(self, freedom_outbound(config, "selftest-forward"), "12111")

    def test_core_exit_probe_skips_plaintext_candidates_for_public_hosts(self) -> None:
        source = CORE.read_text(encoding="utf-8")
        begin = source.index("XRAY_PRIVATE_NETS = [")
        end = source.index("for candidate in transports:", begin)
        namespace: dict = {"ipaddress": ipaddress}
        exec(compile(source[begin:end], "core-exit-probe", "exec"), namespace)  # noqa: S102
        refused = namespace["plaintext_vless_refused"]
        for public in ("8.8.8.8", "172.32.0.1", "exit.example.com", "2606:4700::1"):
            self.assertTrue(refused(public), public)
        for private in ("10.1.2.3", "127.0.0.1", "172.20.0.5", "100.64.1.1", "fd00::1", "node.lan", "a.internal"):
            self.assertFalse(refused(private), private)
        # The skip must precede the reachability preflight so a later TLS
        # candidate is still tried.
        candidate_loop = source[end : end + 1600]
        self.assertLess(
            candidate_loop.index("plaintext_vless_refused(host)"),
            candidate_loop.index("socket.create_connection"),
        )


if __name__ == "__main__":
    unittest.main()
