#!/usr/bin/env python3
"""Direct unit/static/link-symbol tests for Apple Xray runtime hardening.

No network, cloud, GitHub, sudo, password, product build, sign, deploy, or
upload. Compiles a local in-process harness with stub LibXray symbols.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "apple" / "EngineWrappers" / "WinsXrayVlessWsTransport.m"
HARNESS = ROOT / "apple" / "EngineWrappers" / "wins_xray_sock_protect_harness.c"
BRIDGE = ROOT / "tools" / "build_apple_wg_go_bridge.sh"
WRAPPERS = ROOT / "tools" / "build_apple_engine_wrappers.sh"
STAGING = ROOT / "tools" / "stage_apple_engine_artifacts.sh"
README = ROOT / "apple" / "EngineArtifacts" / "README.md"
NOTICES = ROOT / "docs" / "THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md"
AWG_PROVENANCE = ROOT / "docs" / "AMNEZIAWG_ENGINE_PROVENANCE.md"
ENGINE_PROVENANCE = ROOT / "apple" / "EngineArtifacts" / "apple_awg_31_engine_provenance.json"
DART = ROOT / "lib" / "main.dart"

APPLE_XRAY_VERSION = "v1.260924.0"
APPLE_XRAY_COMMIT = "77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3"
APPLE_XRAY_ZIP = "7df5ebc400da6cc4ab13f5578e2fd19b855f98807f1ef1d86a30afc2cd213c40"
LIBXRAY_MIXED = "v1.0.3"
NON_APPLE_XTLS = "v26.9.30"
MAX_MEMORY = "16 * 1024 * 1024"


def clang_bin() -> str:
    xcrun = shutil.which("xcrun")
    if xcrun:
        return xcrun
    clang = shutil.which("clang")
    if clang:
        return clang
    raise unittest.SkipTest("clang/xcrun is required for Apple wrapper harness tests")


class AppleXrayRuntimeHardeningTests(unittest.TestCase):
    def source(self, path: pathlib.Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_wrapper_wires_sock_callback_and_bounded_memory(self) -> None:
        text = self.source(WRAPPER)
        self.assertIn("LibXraySetSockCallback", text)
        self.assertIn("wins_xray_sock_callback", text)
        self.assertIn("IP_BOUND_IF", text)
        self.assertIn("IPV6_BOUND_IF", text)
        self.assertIn("WINS_XRAY_LIBXRAY_MAX_MEMORY_BYTES", text)
        self.assertIn(MAX_MEMORY, text)
        self.assertIn("LibXrayRunXray(", text)
        self.assertIn("WINS_XRAY_LIBXRAY_MAX_MEMORY_BYTES)", text)
        self.assertNotIn("LibXrayRunXray(g_xray_dat_dir, g_xray_config_path, 0)", text)
        self.assertIn("wins_xray_register_sock_callback_locked", text)
        self.assertIn("wins_xray_protect_arm_locked", text)
        self.assertIn("wins_xray_protect_disarm_locked", text)
        self.assertIn("wins_xray_fail_closed_fd", text)
        self.assertIn("Happy Eyeballs", text)
        self.assertIn("TLS/ECH DNS", text)
        self.assertIn("reconnect", text)
        self.assertNotIn("LibXraySetSockCallback(NULL", text)
        self.assertNotIn("LibXraySetSockCallback(0", text)
        register = text.split("wins_xray_register_sock_callback_locked(void) {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn("g_xray_sock_callback_registered", register)
        self.assertIn("LibXraySetSockCallback(wins_xray_sock_callback, NULL)", register)
        start = text.split("wins_xray_vless_ws_transport_start(void) {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertLess(
            start.index("wins_xray_register_sock_callback_locked"),
            start.index("LibXrayRunXray"),
        )
        self.assertLess(
            start.index("wins_xray_protect_arm_locked"),
            start.index("LibXrayRunXray"),
        )
        stop = text.split("wins_xray_stop_locked(void) {", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(
            stop.index("wins_xray_protect_disarm_locked"),
            stop.index("LibXrayStopXray"),
        )
        callback = text.split("wins_xray_sock_callback(", 1)[1].split(
            "static bool wins_xray_result_ok", 1
        )[0]
        self.assertNotIn("close(fd)", callback)
        fail_closed = text.split("static void wins_xray_fail_closed_fd", 1)[1].split(
            "static bool wins_xray_prepare_fail_closed_poison_locked", 1
        )[0]
        self.assertIn("dup2(", fail_closed)
        self.assertIn("_exit(70)", fail_closed)
        self.assertNotIn("pipe(", fail_closed)
        self.assertNotIn("listen(fd, 0)", fail_closed)
        self.assertNotIn("UINT32_MAX", fail_closed)
        self.assertNotIn("shutdown(", fail_closed)
        self.assertNotIn("close(fd)", fail_closed)
        self.assertNotIn("IP_BOUND_IF", fail_closed)
        self.assertNotIn("wins_xray_bind_loopback", fail_closed)
        self.assertIn("wins_xray_prepare_fail_closed_poison_locked", text)
        self.assertIn("g_xray_fail_closed_poison_fd", text)
        self.assertIn("RLIMIT_NOFILE", HARNESS.read_text(encoding="utf-8"))
        self.assertIn("EMFILE", HARNESS.read_text(encoding="utf-8"))
        self.assertIn("wins_xray_test_libxray_max_memory_bytes", text)
        self.assertIn("wins_xray_test_config_file_present", text)
        self.assertIn("#if defined(WINS_XRAY_TRANSPORT_TESTING)", text)

    def test_wrapper_build_stays_on_the_single_xray_source_file(self) -> None:
        wrappers = self.source(WRAPPERS)
        self.assertIn('"${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsXrayVlessWsTransport.m"', wrappers)
        self.assertIn("LibXraySetSockCallback", wrappers)
        self.assertIn("require_undefined_symbols", wrappers)
        self.assertIn("write_xray_provenance", wrappers)
        self.assertIn("apple_xray_vless_ws_engine_provenance.json", wrappers)
        self.assertNotIn("WINS_XRAY_TRANSPORT_TESTING", wrappers)
        self.assertIn("apple_xray_vless_ws_engine_provenance.json", wrappers)
        self.assertIn("verify_and_stage_xray_provenance", self.source(STAGING))

    def test_owner_pins_are_not_bumped_or_rolled_back(self) -> None:
        bridge = self.source(BRIDGE)
        readme = self.source(README)
        notices = self.source(NOTICES)
        dart = self.source(DART)
        awg = self.source(AWG_PROVENANCE)
        for text in (readme, notices, dart, awg):
            self.assertIn(APPLE_XRAY_VERSION, text)
        if ENGINE_PROVENANCE.is_file():
            self.assertIn(APPLE_XRAY_VERSION, self.source(ENGINE_PROVENANCE))
        self.assertIn('AMNEZIA_XRAY_VERSION="v1.260924.0"', bridge)
        self.assertNotIn('AMNEZIA_XRAY_VERSION="v1.260206.0"', bridge)
        self.assertNotIn("amnezia-libxray@", bridge)
        self.assertNotIn("amnezia-libxray v1.0.2", bridge)
        self.assertNotIn("amnezia-libxray v1.1", bridge)
        self.assertIn(f"amnezia-libxray {LIBXRAY_MIXED}", readme)
        self.assertIn("owner-blocked", readme)
        self.assertIn("not an upstream-equivalent", readme)
        self.assertIn(NON_APPLE_XTLS, dart)
        self.assertIn(NON_APPLE_XTLS, notices)
        self.assertNotIn("v1.260206.0", dart)

    def test_notices_keep_apple_core_and_xtls_separate(self) -> None:
        dart = self.source(DART)
        notices = self.source(NOTICES)
        readme = self.source(README)
        awg = self.source(AWG_PROVENANCE)
        self.assertIn("amnezia-xray-core v1.260924.0", dart)
        self.assertIn("hostname-safe", dart)
        self.assertIn("transport/internet/tls/ech.go", dart)
        self.assertIn("dns.quad9.net/dns-query", dart)
        self.assertIn("Xray-core v26.9.30", dart)
        self.assertIn("amnezia-xray-core (Apple)", dart)
        self.assertIn("['Xray-core']", dart)
        # The notice must not print the v1.260728.0 module ZIP hash next to
        # the newer version; the value is a BUILD-LANE input.
        self.assertNotIn(APPLE_XRAY_ZIP, dart)
        self.assertIn("mixed pairing", dart.lower())
        self.assertIn("owner-blocked", dart)
        self.assertIn("Windows/Android/Linux", notices)
        self.assertIn("Apple PacketTunnel", notices)
        self.assertIn("amnezia-libxray v1.0.3", notices)
        self.assertIn("owner-blocked", notices)
        self.assertIn("v26.9.30", notices)
        self.assertIn("LibXraySetSockCallback", readme)
        self.assertIn("16 MiB", readme)
        self.assertIn("dup2(2)", readme)
        self.assertIn("ENOTSOCK", readme)
        self.assertIn("RLIMIT_NOFILE/EMFILE", readme)
        self.assertNotIn("Darwin listen(2)", readme)
        self.assertIn("amnezia-libxray v1.0.3", awg)
        self.assertIn(APPLE_XRAY_VERSION, awg)

    def test_production_object_link_symbols(self) -> None:
        compiler = clang_bin()
        with tempfile.TemporaryDirectory(prefix="wins-apple-xray-symbols-") as raw:
            obj = pathlib.Path(raw) / "WinsXrayVlessWsTransport.o"
            cmd = self._clang_prefix(compiler) + [
                "-c",
                "-fobjc-arc",
                "-fvisibility=hidden",
                "-o",
                str(obj),
                str(WRAPPER),
            ]
            completed = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            nm = subprocess.run(
                ["nm", "-m", str(obj)],
                capture_output=True,
                text=True,
                check=True,
            )
            symbols = nm.stdout
            for exported in (
                "_wins_xray_vless_ws_transport_contract_version",
                "_wins_xray_vless_ws_transport_configure",
                "_wins_xray_vless_ws_transport_start",
                "_wins_xray_vless_ws_transport_stop",
            ):
                self.assertIn(exported, symbols)
                self.assertRegex(symbols, rf"external.*{exported}")
            for undefined in (
                "_LibXraySetSockCallback",
                "_LibXrayRunXray",
                "_LibXrayStopXray",
            ):
                self.assertIn(undefined, symbols)
                self.assertRegex(symbols, rf"undefined.*{undefined}")
            self.assertNotIn("_wins_xray_test_", symbols)

    def test_in_process_socket_protection_harness(self) -> None:
        harness = self.source(HARNESS)
        self.assertIn("ENOTSOCK", harness)
        self.assertIn("ECONNREFUSED", harness)
        self.assertIn("127.0.0.1", harness)
        self.assertIn("localhost", harness)
        self.assertIn("::1", harness)
        self.assertIn("192.0.2.1", harness)
        self.assertIn("2001:db8::1", harness)
        self.assertIn("connect(", harness)
        self.assertIn("SOCK_DGRAM", harness)
        self.assertIn("wins_xray_test_config_file_present", harness)
        self.assertNotIn("ipv4_bound_loopback", harness)
        compiler = clang_bin()
        with tempfile.TemporaryDirectory(prefix="wins-apple-xray-harness-") as raw:
            binary = pathlib.Path(raw) / "wins_xray_sock_protect_harness"
            cmd = self._clang_prefix(compiler) + [
                "-fobjc-arc",
                "-framework",
                "Foundation",
                "-DWINS_XRAY_TRANSPORT_TESTING=1",
                "-o",
                str(binary),
                str(WRAPPER),
                str(HARNESS),
            ]
            completed = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            nm = subprocess.run(
                ["nm", "-m", str(binary)],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("_LibXraySetSockCallback", nm.stdout)
            self.assertIn("_wins_xray_vless_ws_transport_start", nm.stdout)
            self.assertIn("_wins_xray_test_libxray_max_memory_bytes", nm.stdout)
            ran = subprocess.run(
                [str(binary)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                env=dict(os.environ),
            )
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn("APPLE XRAY SOCK PROTECT HARNESS: PASS", ran.stdout)

    @staticmethod
    def _clang_prefix(compiler: str) -> list[str]:
        if compiler.endswith("xcrun") or pathlib.Path(compiler).name == "xcrun":
            return [compiler, "clang"]
        return [compiler]


if __name__ == "__main__":
    unittest.main()
