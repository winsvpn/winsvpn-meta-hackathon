#!/usr/bin/env python3
"""Regression tests for the address-free data-plane DNS diagnostic."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("data_plane_dns_readonly_diagnostic.py")
SPEC = importlib.util.spec_from_file_location("wins_dns_diagnostic", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RequiredTargetsTests(unittest.TestCase):
    def test_only_loopback_and_awg_addresses_are_required(self) -> None:
        payload = [
            {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}]},
            {"ifname": "eth0", "addr_info": [{"local": "192.0.2.10"}]},
            {"ifname": "docker0", "addr_info": [{"local": "172.17.0.1"}]},
            {"ifname": "awg0", "addr_info": [{"local": "10.8.1.1"}]},
        ]
        with mock.patch.object(MODULE, "run", return_value=(0, json.dumps(payload))):
            targets = MODULE.required_targets()

        self.assertEqual(
            targets,
            [
                ("127.0.0.1", "loopback", "lo"),
                ("10.8.1.1", "private", "awg0"),
            ],
        )

    def test_yaml_lists_are_section_bounded(self) -> None:
        text = """dns:
  upstream_dns:
    - 'https://dns.quad9.net/dns-query'
  fallback_dns:
    - 'https://dns.opendns.com/dns-query'
    - 'https://private.example.invalid/token'
  bootstrap_dns:
    - 9.9.9.9
"""
        self.assertEqual(
            MODULE._yaml_list(text, "upstream_dns"),
            ["https://dns.quad9.net/dns-query"],
        )
        self.assertEqual(
            MODULE._yaml_list(text, "fallback_dns"),
            [
                "https://dns.opendns.com/dns-query",
                "https://private.example.invalid/token",
            ],
        )

    def test_awg_interface_name_is_bounded(self) -> None:
        payload = [
            {"ifname": "awg2", "addr_info": [{"local": "10.8.2.1"}]},
            {"ifname": "awg999", "addr_info": [{"local": "10.8.3.1"}]},
            {"ifname": "awg0;touch", "addr_info": [{"local": "10.8.4.1"}]},
        ]
        with mock.patch.object(MODULE, "run", return_value=(0, json.dumps(payload))):
            targets = MODULE.required_targets()

        self.assertEqual(
            targets,
            [
                ("127.0.0.1", "loopback", "lo"),
                ("10.8.2.1", "private", "awg2"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
