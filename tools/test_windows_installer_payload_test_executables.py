#!/usr/bin/env python3
"""No unit-test program ships in the Windows installer.

windows/runner/CMakeLists.txt builds its unit-test programs (windows_winn_gate_test.exe,
winn_frame_selftest_test.exe, winn3_supervisor_test.exe, winsvpn-carrierhost-test.exe,
winsvpn-carrierpin-test.exe, winsvpn-split-routeplan-test.exe and
winsvpn-tunnel-service-client-test.exe) into the same Release directory as the
application, and winsvpn.iss packs that directory recursively. Three layers now keep them
out: build_installer.ps1 removes them from the payload and asserts none is left, the
[Files] entry excludes the two name patterns, and the Windows cross-store gate refuses
an installer inventory that still carries one.

Run: python3 -B tools/test_windows_installer_payload_test_executables.py
"""

from __future__ import annotations

import fnmatch
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import windows_cross_store_artifact_gate as gate  # noqa: E402

PRODUCER = (ROOT / "installer/windows/build_installer.ps1").read_text(encoding="utf-8")
INNO = (ROOT / "installer/windows/winsvpn.iss").read_text(encoding="utf-8")

SHIPPED_TEST_PROGRAMS = (
    "windows_winn_gate_test.exe",
    "winn_frame_selftest_test.exe",
    "winn3_supervisor_test.exe",
    "winsvpn-carrierhost-test.exe",
    "winsvpn-carrierpin-test.exe",
    "winsvpn-split-routeplan-test.exe",
    "winsvpn-tunnel-service-client-test.exe",
)
PRODUCT_PROGRAMS = (
    "wins_vpn.exe",
    "wins_vpn_tunnel_service.exe",
    "winsvpn_awg_engine.exe",
    "winn-datapath.exe",
    "wins_bridge_host.exe",
    "latest.exe",
    "contest.exe",
    "test.exe",
    "attestation.exe",
    "vc_redist.x64.exe",
)


class WindowsInstallerTestExecutableTests(unittest.TestCase):
    def test_cmake_really_builds_the_seven_test_programs_next_to_the_application(self) -> None:
        cmake = (ROOT / "windows/runner/CMakeLists.txt").read_text(encoding="utf-8")
        built = set(re.findall(r"add_executable\(([A-Za-z0-9_-]+)", cmake))
        for program in SHIPPED_TEST_PROGRAMS:
            self.assertIn(program[: -len(".exe")], built, program)

    def test_producer_removes_then_asserts_before_the_payload_is_staged_and_compiled(self) -> None:
        first = PRODUCER.index("Remove-WindowsPayloadTestExecutables -PayloadRoot $ReleaseDir")
        asserts = [m.start() for m in re.finditer(r"Assert-WindowsPayloadContainsNoTestExecutables", PRODUCER)]
        self.assertGreaterEqual(len(asserts), 5, "definition plus four call sites")
        self.assertLess(first, PRODUCER.index("\nAssert-StagedReleasePeMachines\n"))
        iscc = PRODUCER.index("& $iscc @innoArguments")
        before_iscc = [position for position in asserts if position < iscc]
        self.assertGreaterEqual(len(before_iscc), 5)
        self.assertIn(
            "Assert-WindowsPayloadContainsNoTestExecutables -PayloadRoot $StagedDependenciesDir "
            "-Label 'Windows staged dependencies'",
            PRODUCER,
        )

    def test_producer_pattern_matches_exactly_the_test_programs(self) -> None:
        match = re.search(r"-match '\(\?i\)(\[-_\]test\\\.exe\$)'", PRODUCER)
        self.assertIsNotNone(match)
        pattern = re.compile(match.group(1), re.IGNORECASE)
        for name in SHIPPED_TEST_PROGRAMS:
            self.assertRegex(name, pattern)
            self.assertRegex(name.upper(), pattern)
        for name in PRODUCT_PROGRAMS:
            self.assertNotRegex(name, pattern, name)

    def test_inno_files_entry_excludes_the_same_names(self) -> None:
        entry = next(
            line for line in INNO.splitlines() if line.startswith('Source: "{#SourceDir}\\*"')
        )
        excludes = re.search(r'Excludes: "([^"]+)"', entry).group(1).split(",")
        for pattern in ("*-test.exe", "*_test.exe"):
            self.assertIn(pattern, excludes)
        for name in SHIPPED_TEST_PROGRAMS:
            self.assertTrue(any(fnmatch.fnmatch(name, pattern) for pattern in excludes), name)
        for name in PRODUCT_PROGRAMS:
            self.assertFalse(any(fnmatch.fnmatch(name, pattern) for pattern in excludes), name)

    def _inventory(self, *extra: str) -> list[gate.InnerPayloadRecord]:
        names = set(gate._required_payload_basenames(False, "x64")) | set(extra)
        return [gate.InnerPayloadRecord(name, "", "0" * 64, 1) for name in sorted(names)]

    def test_the_gate_refuses_an_installer_inventory_that_packs_a_test_program(self) -> None:
        gate._require_complete_inner_inventory(self._inventory(), False, "x64")
        for name in SHIPPED_TEST_PROGRAMS + ("sub/dir/Custom_TEST.EXE",):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    gate.WindowsArtifactGateError, r"Windows package ships test executables: "
                ) as raised:
                    gate._require_complete_inner_inventory(self._inventory(name), False, "x64")
                self.assertIn(name.casefold(), str(raised.exception))
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "ships test executables"):
            gate._require_complete_inner_inventory(self._inventory(SHIPPED_TEST_PROGRAMS[0]), False, "x64")

    def test_the_gate_check_runs_before_the_generic_extra_executable_refusal(self) -> None:
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "ships test executables"):
            gate._require_complete_inner_inventory(
                self._inventory("winsvpn-carrierhost-test.exe", "other.exe"), False, "x64"
            )
        with self.assertRaisesRegex(gate.WindowsArtifactGateError, "extra executables: other.exe"):
            gate._require_complete_inner_inventory(self._inventory("other.exe"), False, "x64")


if __name__ == "__main__":
    unittest.main()
