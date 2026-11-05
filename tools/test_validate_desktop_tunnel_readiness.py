#!/usr/bin/env python3
"""Exact Linux route-probe interface contract for desktop tunnel readiness."""

from __future__ import annotations

import subprocess
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
VALIDATOR = TOOLS / "validate_desktop_tunnel_readiness.py"
LINUX_BACKEND = ROOT / "linux/runner/linux_tunnel_backend.cc"
LINUX_WINN3_HEADER = ROOT / "linux/runner/linux_winn3_host.h"
WINDOWS_BACKEND = ROOT / "windows/runner/windows_tunnel_backend.cpp"
HELPER_SENTINEL = "# Helpers end. Remaining statements are the source contract.\n"


def _load_readiness() -> types.ModuleType:
    source = VALIDATOR.read_text(encoding="utf-8")
    head, sentinel, _tail = source.partition(HELPER_SENTINEL)
    if not sentinel:
        raise AssertionError("validator helper sentinel is missing")
    module = types.ModuleType("validate_desktop_tunnel_readiness")
    module.__file__ = str(VALIDATOR)
    exec(compile(head + sentinel, str(VALIDATOR), "exec"), module.__dict__)
    return module


readiness = _load_readiness()

V1_POSITIVE_ROUTES = (
    "1.1.1.1 via 192.0.2.1 dev winsvpn src 10.8.0.2 uid 1000\n    cache",
    "1.1.1.1 dev winsvpn src 10.8.0.2 uid 1000",
    "1.1.1.1 dev winsvpn",
)
V3_POSITIVE_ROUTES = (
    "1.1.1.1 via 10.64.0.1 dev winsvpn3 src 10.64.0.2 uid 1000\n    cache",
    "1.1.1.1 dev winsvpn3 src 10.64.0.2 uid 1000",
    "1.1.1.1 dev winsvpn3",
)
HOSTILE_INTERFACE_ROUTES = (
    "1.1.1.1 via 192.0.2.1 dev winsvpn-attacker src 192.0.2.8 uid 1000",
    "1.1.1.1 dev winsvpn0 src 10.8.0.2 uid 1000",
    "1.1.1.1 dev winsvpn_test src 10.8.0.2 uid 1000",
    "1.1.1.1 dev winsvpnx src 10.8.0.2 uid 1000",
    "1.1.1.1 dev winsvpn3a src 10.64.0.2 uid 1000",
    "1.1.1.1 dev winsvpn30 src 10.64.0.2 uid 1000",
    "1.1.1.1 dev winsvpn3-attacker src 10.64.0.2 uid 1000",
    "1.1.1.1 dev awinsvpn src 10.8.0.2 uid 1000",
    "1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.8 uid 1000",
    "1.1.1.1 dev tun0 src 10.0.0.2 uid 1000",
    "1.1.1.1 dev wg0 src 10.0.0.2 uid 1000",
    "1.1.1.1 via winsvpn dev eth0 src 192.0.2.8 uid 1000",
    "1.1.1.1 via winsvpn3 dev eth0 src 192.0.2.8 uid 1000",
)

GOOD_PROBE = """
FlValue* ProbeInternetValue() {
  const bool v3 =
      winsvpn::winn3host::LinuxWinn3StandaloneSessionWasStarted();
  const char* tun =
      v3 ? winsvpn::winn3host::kLinuxWinn3InterfaceName : kTunnelName;
  const std::string route_pattern =
      v3 ? " dev winsvpn3( |$)" : " dev winsvpn( |$)";
  const bool route_uses_tunnel =
      active &&
      ProcSucceeded(RunShScript("ip route get 1.1.1.1 2>/dev/null | grep -Eq \\"$1\\"",
                                "winsvpn-route-check", {route_pattern},
                                ProcOutput::kSuppress));
  const bool ok = route_uses_tunnel &&
                  ProcSucceeded(RunShScript(
                      "curl -fsS --max-time 4 --interface \\"$1\\" "
                      "https://example.test/generate_204",
                      "winsvpn-net-check", {tun}, ProcOutput::kSuppress));
}
"""


def _contract_message(source: str) -> str:
    try:
        readiness.validate_linux_route_probe_contract(source)
    except SystemExit as exc:
        return str(exc)
    raise AssertionError("route-probe contract unexpectedly accepted the source")


class LinuxRouteProbeInterfaceTests(unittest.TestCase):
    def test_protocol_selects_exact_v1_and_v3_interface_names(self) -> None:
        self.assertEqual(
            readiness.linux_tunnel_interface_for_protocol("v1"), "winsvpn"
        )
        self.assertEqual(
            readiness.linux_tunnel_interface_for_protocol("v3"), "winsvpn3"
        )
        with self.assertRaises(ValueError):
            readiness.linux_tunnel_interface_for_protocol("v2")
        with self.assertRaises(ValueError):
            readiness.linux_route_probe_ere("winsvpn-attacker")

    def test_v1_positive_routes_use_winsvpn(self) -> None:
        for route in V1_POSITIVE_ROUTES:
            with self.subTest(route=route):
                self.assertTrue(
                    readiness.linux_route_uses_intended_interface(route, "v1")
                )
                self.assertFalse(
                    readiness.linux_route_uses_intended_interface(route, "v3")
                )

    def test_v3_positive_routes_use_winsvpn3(self) -> None:
        for route in V3_POSITIVE_ROUTES:
            with self.subTest(route=route):
                self.assertTrue(
                    readiness.linux_route_uses_intended_interface(route, "v3")
                )
                self.assertFalse(
                    readiness.linux_route_uses_intended_interface(route, "v1")
                )

    def test_hostile_wrong_interfaces_are_rejected(self) -> None:
        for route in HOSTILE_INTERFACE_ROUTES:
            for protocol in ("v1", "v3"):
                with self.subTest(protocol=protocol, route=route):
                    self.assertFalse(
                        readiness.linux_route_uses_intended_interface(
                            route, protocol
                        )
                    )

    def test_sibling_protocol_interface_is_rejected(self) -> None:
        leftover_v1 = "1.1.1.1 dev winsvpn src 10.8.0.2 uid 1000"
        leftover_v3 = "1.1.1.1 dev winsvpn3 src 10.64.0.2 uid 1000"
        self.assertFalse(
            readiness.linux_route_uses_intended_interface(leftover_v1, "v3")
        )
        self.assertFalse(
            readiness.linux_route_uses_intended_interface(leftover_v3, "v1")
        )

    def test_loose_prefix_regex_would_accept_attacker_names(self) -> None:
        loose = r"dev winsvpn"
        hostile = "1.1.1.1 dev winsvpn-attacker src 192.0.2.8 uid 1000"
        self.assertRegex(hostile, loose)
        self.assertFalse(
            readiness.linux_route_uses_intended_interface(hostile, "v1")
        )
        self.assertFalse(
            readiness.linux_route_uses_intended_interface(hostile, "v3")
        )
        self.assertRegex("1.1.1.1 dev winsvpn3 src 10.64.0.2", loose)
        self.assertFalse(
            readiness.linux_route_uses_intended_interface(
                "1.1.1.1 dev winsvpn3 src 10.64.0.2", "v1"
            )
        )

    def test_grep_ere_rejects_prefixed_names(self) -> None:
        v1_pattern = readiness.linux_route_probe_ere_for_protocol("v1")
        v3_pattern = readiness.linux_route_probe_ere_for_protocol("v3")
        cases = (
            (v1_pattern, "1.1.1.1 dev winsvpn src 10.8.0.2", 0),
            (v3_pattern, "1.1.1.1 dev winsvpn3 src 10.64.0.2", 0),
            (v1_pattern, "1.1.1.1 dev winsvpn3 src 10.64.0.2", 1),
            (v3_pattern, "1.1.1.1 dev winsvpn src 10.8.0.2", 1),
            (v1_pattern, "1.1.1.1 dev winsvpn-attacker src 192.0.2.8", 1),
            (v3_pattern, "1.1.1.1 dev winsvpn30 src 10.64.0.2", 1),
        )
        for pattern, route, expected in cases:
            with self.subTest(pattern=pattern, route=route):
                completed = subprocess.run(
                    ["grep", "-Eq", pattern],
                    input=route + "\n",
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, expected)


class LinuxRouteProbeSourceContractTests(unittest.TestCase):
    def test_good_probe_source_is_accepted(self) -> None:
        readiness.validate_linux_route_probe_contract(GOOD_PROBE)

    def test_current_tree_binds_probe_to_protocol_evidence(self) -> None:
        readiness.validate_linux_tunnel_interface_evidence(
            LINUX_BACKEND.read_text(encoding="utf-8"),
            LINUX_WINN3_HEADER.read_text(encoding="utf-8"),
        )

    def test_reintroduced_shell_composition_is_rejected(self) -> None:
        """B-APP-004 regression pin: ShellQuote must not come back."""
        linux = LINUX_BACKEND.read_text(encoding="utf-8") + (
            '\nstd::string ShellQuote(const std::string& value) { return value; }\n'
        )
        header = LINUX_WINN3_HEADER.read_text(encoding="utf-8")
        with self.assertRaises(SystemExit) as raised:
            readiness.validate_linux_tunnel_interface_evidence(linux, header)
        self.assertIn("must not reintroduce ShellQuote", str(raised.exception))

    def test_missing_argv_helpers_are_rejected(self) -> None:
        linux = LINUX_BACKEND.read_text(encoding="utf-8").replace(
            "ProcResult RunArgv(", "ProcResult RemovedArgv(", 1
        )
        header = LINUX_WINN3_HEADER.read_text(encoding="utf-8")
        with self.assertRaises(SystemExit) as raised:
            readiness.validate_linux_tunnel_interface_evidence(linux, header)
        self.assertIn("must define the argv-form process helper", str(raised.exception))

    def test_hardcoded_v1_route_grep_is_rejected(self) -> None:
        hostile = (
            GOOD_PROBE
            + "\n  // ip route get 1.1.1.1 | grep -Eq ' dev winsvpn( |$)';\n"
        )
        message = _contract_message(hostile)
        self.assertIn("must not hardcode only the v1 interface", message)

    def test_loose_prefix_regex_source_is_rejected(self) -> None:
        hostile = GOOD_PROBE + '\n  const char* loose = "dev winsvpn.*";\n'
        message = _contract_message(hostile)
        self.assertIn("must not use a prefix regex", message)

    def test_optional_digit_regex_source_is_rejected(self) -> None:
        hostile = GOOD_PROBE + '\n  const char* both = "winsvpn(3)?";\n'
        message = _contract_message(hostile)
        self.assertIn("optional-digit regex that accepts both names", message)

    def test_missing_protocol_evidence_is_rejected(self) -> None:
        hostile = GOOD_PROBE.replace(
            "LinuxWinn3StandaloneSessionWasStarted()",
            "IsTunnelRunning()",
        )
        message = _contract_message(hostile)
        self.assertIn(
            "must select the interface from Winn v3 session evidence", message
        )

    def test_wrong_interface_constant_is_rejected(self) -> None:
        message = _contract_message(
            GOOD_PROBE.replace(
                "v3 ? winsvpn::winn3host::kLinuxWinn3InterfaceName : kTunnelName",
                "v3 ? winsvpn::winn3host::kLinuxWinn3InterfaceName : kOtherName",
            )
        )
        self.assertIn(
            "must bind the selected interface to protocol evidence", message
        )

    def test_wrong_v1_interface_constant_value_is_rejected(self) -> None:
        linux = LINUX_BACKEND.read_text(encoding="utf-8").replace(
            'constexpr char kTunnelName[] = "winsvpn";',
            'constexpr char kTunnelName[] = "winsvpn-attacker";',
        )
        header = LINUX_WINN3_HEADER.read_text(encoding="utf-8")
        with self.assertRaises(SystemExit) as raised:
            readiness.validate_linux_tunnel_interface_evidence(linux, header)
        self.assertIn(
            "v1 tunnel interface evidence must be exactly winsvpn",
            str(raised.exception),
        )

    def test_wrong_v3_interface_constant_value_is_rejected(self) -> None:
        linux = LINUX_BACKEND.read_text(encoding="utf-8")
        header = LINUX_WINN3_HEADER.read_text(encoding="utf-8").replace(
            'inline constexpr char kLinuxWinn3InterfaceName[] = "winsvpn3";',
            'inline constexpr char kLinuxWinn3InterfaceName[] = "winsvpn";',
        )
        with self.assertRaises(SystemExit) as raised:
            readiness.validate_linux_tunnel_interface_evidence(linux, header)
        self.assertIn(
            "v3 tunnel interface evidence must be exactly winsvpn3",
            str(raised.exception),
        )


class WindowsDynamicTunnelProbeSourceContractTests(unittest.TestCase):
    def _current_probe(self) -> str:
        return readiness.windows_tunnel_interface_probe_source(
            WINDOWS_BACKEND.read_text(encoding="utf-8")
        )

    def _assert_rejected(self, source: str, message: str) -> None:
        with self.assertRaises(SystemExit) as raised:
            readiness.validate_windows_tunnel_interface_probe_contract(source)
        self.assertIn(message, str(raised.exception))

    def test_current_probe_selects_v3_or_v1_alias_from_runtime_proof(self) -> None:
        readiness.validate_windows_tunnel_interface_probe_contract(
            self._current_probe()
        )

    def test_hardcoded_v1_alias_is_rejected(self) -> None:
        hostile = self._current_probe().replace(
            "ConvertInterfaceAliasToLuid(alias_wide.c_str(), &tunnel_luid)",
            "ConvertInterfaceAliasToLuid(kTunnelName, &tunnel_luid)",
            1,
        )
        self._assert_rejected(hostile, "classified adapter alias")

    def test_missing_fail_closed_alias_classification_is_rejected(self) -> None:
        hostile = self._current_probe().replace(
            "WindowsTunnelProbeAlias::kRefuse",
            "WindowsTunnelProbeAlias::kV1",
            1,
        )
        self._assert_rejected(hostile, "fail closed on ambiguous adapter proof")

    def test_missing_v3_manager_evidence_is_rejected(self) -> None:
        hostile = self._current_probe().replace(
            'ParseTunnelManagerUnsigned(manager_status, "winn3_promoted",',
            'ParseTunnelManagerUnsigned(manager_status, "ignored",',
            1,
        )
        self._assert_rejected(hostile, "manager status key winn3_promoted")

    def test_uncommitted_v1_manager_status_is_rejected(self) -> None:
        hostile = self._current_probe().replace(
            "IsExpectedCommittedManagerStatus(manager_status)",
            "true",
            1,
        )
        self._assert_rejected(hostile, "require committed manager status")


if __name__ == "__main__":
    unittest.main()
