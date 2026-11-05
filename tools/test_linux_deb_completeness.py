#!/usr/bin/env python3
"""Fail-closed completeness contract for the Linux Debian package."""

from __future__ import annotations

import pathlib
import struct
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tools/build_linux_deb.sh").read_text(encoding="utf-8")
PRODUCER = ROOT / "tools/build_linux_deb.sh"


def synthetic_elf64(machine: int, *, elf_type: int = 2) -> bytes:
    data = bytearray(64)
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        elf_type,
        machine,
        1,
        0,
        0,
        0,
        0,
        64,
        56,
        0,
        0,
        0,
        0,
    )
    return bytes(data)


def write_executable(path: pathlib.Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o755)


def fixture_bundle(root: pathlib.Path, machine: int) -> None:
    for relative in (
        "wins_vpn",
        "winsvpn-bypass-bpf",
        "winn-datapath",
        "xray",
        "awg",
        "amneziawg-go",
        "tools/native_messaging/host/wins_bridge_host",
    ):
        write_executable(root / relative, synthetic_elf64(machine))
    write_executable(root / "awg-quick", b"#!/bin/sh\nexit 0\n")
    write_executable(root / "lib/libapp.so", synthetic_elf64(machine, elf_type=3))
    write_executable(root / "lib/libflutter_linux_gtk.so", synthetic_elf64(machine, elf_type=3))
    (root / "lib/libapp.so").chmod(0o644)
    (root / "lib/libflutter_linux_gtk.so").chmod(0o644)


class LinuxDebCompletenessTests(unittest.TestCase):
    def test_every_primary_and_fallback_runtime_is_mandatory(self) -> None:
        self.assertIn(
            "tools/native_messaging/host/wins_bridge_host; do",
            SOURCE,
        )

    def test_incomplete_runtime_cannot_produce_a_ui_only_package(self) -> None:
        self.assertNotIn("WINS_DEB_ALLOW_INCOMPLETE", SOURCE)
        self.assertNotIn("+ui-only", SOURCE)
        self.assertIn(
            "Refusing to produce a package without the complete v3-primary",
            SOURCE,
        )

    def test_package_architecture_is_derived_and_every_elf_is_checked(self) -> None:
        self.assertIn("elf_identity()", SOURCE)
        self.assertIn('[[ "$elf_class" == 2 && "$elf_data" == 1 ]]', SOURCE)
        self.assertIn('find "$root" -type f -print0', SOURCE)
        self.assertIn("refusing mixed-architecture bundle", SOURCE)
        self.assertIn("tools/native_messaging/host/wins_bridge_host", SOURCE)
        self.assertIn("lib/libapp.so", SOURCE)
        self.assertIn("lib/libflutter_linux_gtk.so", SOURCE)
        self.assertIn("winn3-descriptor-ring-attestation.json", SOURCE)

    def test_debian_identity_is_canonical_1_0_15_plus_30(self) -> None:
        self.assertIn('DEB_VERSION="${APP_VERSION}-${BUILD_NUMBER}"', SOURCE)
        self.assertIn('wins-vpn_${DEB_VERSION}_${arch}.deb', SOURCE)
        self.assertIn("Package: wins-vpn", SOURCE)
        self.assertIn("winn-datapath", SOURCE)
        self.assertIn("tools/native_messaging/host/wins_bridge_host", SOURCE)

    def test_architecture_self_test_accepts_each_exact_architecture(self) -> None:
        for arch, machine in (("amd64", 62), ("arm64", 183)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as name:
                bundle = pathlib.Path(name)
                fixture_bundle(bundle, machine)
                completed = subprocess.run(
                    ["bash", str(PRODUCER), "--self-test-bundle-architecture", str(bundle), arch],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn(f"PASS ({arch})", completed.stdout)

    def test_architecture_self_test_rejects_mixed_nested_elf(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle = pathlib.Path(name)
            fixture_bundle(bundle, 62)
            write_executable(bundle / "lib/foreign.so", synthetic_elf64(183, elf_type=3))
            completed = subprocess.run(
                ["bash", str(PRODUCER), "--self-test-bundle-architecture", str(bundle), "amd64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn("refusing mixed-architecture bundle", completed.stderr)
        self.assertIn("foreign.so", completed.stderr)

    def test_architecture_self_test_rejects_wrong_class_and_missing_native_host(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle = pathlib.Path(name)
            fixture_bundle(bundle, 62)
            malformed = bytearray(synthetic_elf64(62))
            malformed[4] = 1
            write_executable(bundle / "xray", bytes(malformed))
            wrong_class = subprocess.run(
                ["bash", str(PRODUCER), "--self-test-bundle-architecture", str(bundle), "amd64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(wrong_class.returncode, 3, wrong_class.stderr)
            self.assertIn("not a supported little-endian ELF64", wrong_class.stderr)

            write_executable(bundle / "xray", synthetic_elf64(62))
            (bundle / "tools/native_messaging/host/wins_bridge_host").unlink()
            missing = subprocess.run(
                ["bash", str(PRODUCER), "--self-test-bundle-architecture", str(bundle), "amd64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(missing.returncode, 3, missing.stderr)
        self.assertIn("wins_bridge_host", missing.stderr)

    def test_architecture_self_test_rejects_missing_flutter_library(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle = pathlib.Path(name)
            fixture_bundle(bundle, 62)
            (bundle / "lib/libapp.so").unlink()
            completed = subprocess.run(
                ["bash", str(PRODUCER), "--self-test-bundle-architecture", str(bundle), "amd64"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn("libapp.so", completed.stderr)


if __name__ == "__main__":
    unittest.main()
