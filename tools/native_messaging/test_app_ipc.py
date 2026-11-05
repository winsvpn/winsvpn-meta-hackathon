#!/usr/bin/env python3
# Source contracts for the desktop-app IPC channel used by the native host.
# Live behaviour is proven by test/browser_bridge_app_ipc_test.dart; this file
# pins the shipping host's fail-closed wiring so a later edit cannot put a
# state-file override, a token print, or UnobservedStateSource back on the
# production path without turning this red.

from __future__ import annotations

import os
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
HOST = HERE / "host" / "bin" / "wins_bridge_host.dart"
HARNESS = HERE / "host" / "bin" / "wins_bridge_host_harness.dart"
IPC_LIB = REPO / "lib" / "browser_bridge_app_ipc.dart"
HOST_IPC_LINK = HERE / "host" / "lib" / "browser_bridge_app_ipc.dart"
MAIN = REPO / "lib" / "main.dart"


class AppIpcHostContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.host = HOST.read_text(encoding="utf-8")
        cls.harness = HARNESS.read_text(encoding="utf-8")
        cls.ipc = IPC_LIB.read_text(encoding="utf-8")
        cls.main = MAIN.read_text(encoding="utf-8")

    def test_host_ipc_library_is_a_relative_symlink_to_the_app_copy(self) -> None:
        self.assertTrue(HOST_IPC_LINK.is_symlink(), HOST_IPC_LINK)
        target = os.path.normpath(HOST_IPC_LINK.parent / os.readlink(HOST_IPC_LINK))
        self.assertEqual(Path(target).resolve(), IPC_LIB.resolve())

    def test_host_shared_libraries_are_relative_symlinks_into_app_lib(self) -> None:
        host_lib = HERE / "host" / "lib"
        expected = {
            "browser_bridge_app_ipc.dart",
            "browser_bridge_framing.dart",
            "browser_bridge_protocol.dart",
            "browser_bridge_proxy.dart",
            "vpn_config_validation.dart",
            "windows_system_executable.dart",
            "winn_carrier_profile_keys.dart",
            "winn_protocol_dispatch.dart",
        }
        names = {path.name for path in host_lib.glob("*.dart")}
        self.assertEqual(names, expected)
        for name in sorted(names):
            path = host_lib / name
            self.assertTrue(path.is_symlink(), path)
            link = os.readlink(path)
            self.assertFalse(os.path.isabs(link), link)
            resolved = Path(os.path.normpath(path.parent / link)).resolve()
            self.assertEqual(resolved, (REPO / "lib" / name).resolve())

    def test_production_host_is_app_ipc_and_fail_closed(self) -> None:
        self.assertIn("class AppIpcStateSource", self.host)
        self.assertIn("AppIpcStateSource(winn: winn)", self.host)
        self.assertIn("invokeFailClosed", self.host)
        self.assertIn("stateSource.requestConnect()", self.host)
        self.assertIn("stateSource.requestDisconnect()", self.host)
        self.assertNotIn("stateSource: UnobservedStateSource(winn)", self.host)
        self.assertNotIn("FileStateSource", self.host)
        self.assertIn("production host has no state-file override", self.host)
        self.assertIn("stateSource=app-ipc failClosed=true", self.host)

    def test_host_never_prints_the_ipc_token(self) -> None:
        self.assertNotIn("endpoint.token", self.host)
        self.assertNotIn("tokenForTest", self.host)
        self.assertNotIn("${token}", self.host)
        self.assertNotIn("$token", self.host)
        self.assertNotIn("stderr.writeln(token", self.host)
        self.assertIn("never carries a token", self.host.split("STDOUT IS THE WIRE", 1)[1][:400])

    def test_ipc_library_is_loopback_only_with_posix_gate(self) -> None:
        self.assertIn("InternetAddress.loopbackIPv4", self.ipc)
        self.assertIn("kBrowserBridgeAppIpcLoopbackHost = '127.0.0.1'", self.ipc)
        self.assertIn("Connect ONLY to the IPv4 loopback object", self.ipc)
        self.assertIn("browserBridgeAppIpcConstantTimeEquals", self.ipc)
        self.assertIn("Windows: FileStat.mode is not a POSIX", self.ipc)
        self.assertIn("Windows process liveness is not `kill -0`", self.ipc)
        self.assertIn("kBrowserBridgeAppIpcTokenBytes = 32", self.ipc)
        self.assertNotIn("0.0.0.0", self.ipc)

    def test_app_wires_ipc_through_existing_tunnel_controls(self) -> None:
        self.assertIn("import 'browser_bridge_app_ipc.dart';", self.main)
        self.assertIn("_startBrowserBridgeAppIpc()", self.main)
        self.assertIn("_handleWatchCommand(WatchCommand.connect, '')", self.main)
        self.assertIn("_handleWatchCommand(WatchCommand.disconnect, '')", self.main)
        self.assertIn("unawaited(ipc.stop())", self.main)
        self.assertIn("browserBridgeAppIpcSupportedOn(Platform.operatingSystem)", self.main)

    def test_harness_remains_the_only_state_file_override(self) -> None:
        self.assertIn("class FileStateSource", self.harness)
        self.assertIn("--state-file", self.harness)
        self.assertIn("AppIpcStateSource(winn: winn)", self.harness)
        self.assertIn("THIS IS NOT A SHIPPING PATH", self.harness)


if __name__ == "__main__":
    unittest.main()
