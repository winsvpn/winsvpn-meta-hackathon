#!/usr/bin/env python3
"""Adversarial contracts for the installed Linux transport runtime."""

from __future__ import annotations

import pathlib
import platform
import re
import struct
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKEND_PATH = ROOT / "linux/runner/linux_tunnel_backend.cc"
INSTALLER_PATH = ROOT / "linux/packaging/install.sh"
PRODUCER_PATH = ROOT / "tools/build_linux_release.sh"
BACKEND = BACKEND_PATH.read_text(encoding="utf-8")


def synthetic_elf64(machine: int, *, elf_type: int = 2) -> bytes:
    """Return a structurally valid ELF64 fixture with a loadable code segment."""

    data = bytearray(4096)
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    load_vaddr = 0x400000
    is_shared = elf_type == 3
    entry = 0 if is_shared else load_vaddr + 0x200
    phnum = 2 if is_shared else 1
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        elf_type,
        machine,
        1,
        entry,
        64,
        0,
        0,
        64,
        56,
        phnum,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        1,
        5,
        0,
        load_vaddr,
        load_vaddr,
        len(data),
        len(data),
        4096,
    )
    if is_shared:
        dynamic_offset = 0x300
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            64 + 56,
            2,
            6,
            dynamic_offset,
            load_vaddr + dynamic_offset,
            load_vaddr + dynamic_offset,
            16,
            16,
            8,
        )
        struct.pack_into("<QQ", data, dynamic_offset, 0, 0)
    if machine == 62:
        code = b"\x31\xff\xb8\x3c\x00\x00\x00\x0f\x05"
    elif machine == 183:
        code = b"\x00\x00\x80\xd2\xa8\x0b\x80\xd2\x01\x00\x00\xd4"
    else:
        code = b"\x00\x00\x00\x00"
    data[0x200 : 0x200 + len(code)] = code
    return bytes(data)


def privileged_script() -> str:
    match = re.search(
        r'return R"WINS\((.*?)\)WINS";', BACKEND, flags=re.DOTALL
    )
    if not match:
        raise AssertionError("PrivilegedTunnelScript raw string was not found")
    return match.group(1)


def run_privileged_script(bundle: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "/bin/sh",
            "-c",
            privileged_script(),
            "winsvpn-runtime-test",
            "up",
            "ignored-config",
            "ignored-public-key",
            str(bundle),
            "",
            "",
            "",
            "",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def host_elf_machine() -> int:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return 62
    if machine in {"aarch64", "arm64"}:
        return 183
    raise unittest.SkipTest(f"unsupported test host architecture: {machine}")


def write_executable(path: pathlib.Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o755)


class LinuxInstalledRuntimeSecurityTests(unittest.TestCase):
    def test_supplied_empty_bundle_fails_closed_before_system_awg_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            completed = run_privileged_script(pathlib.Path(name))
        self.assertEqual(completed.returncode, 65, completed.stderr)
        self.assertIn("requires all bundled AmneziaWG components", completed.stderr)
        self.assertNotIn('[ "$present" -ne 0 ] || return 0', privileged_script())

    def test_supplied_partial_bundle_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle = pathlib.Path(name)
            write_executable(bundle / "awg", b"#!/bin/sh\nexit 99\n")
            completed = run_privileged_script(bundle)
        self.assertEqual(completed.returncode, 65, completed.stderr)
        self.assertIn("(1 of 3 present)", completed.stderr)

    def test_installer_self_test_rejects_wrong_arch_winn_datapath(self) -> None:
        expected = host_elf_machine()
        wrong = 183 if expected == 62 else 62
        with tempfile.TemporaryDirectory() as name:
            bundle = pathlib.Path(name)
            write_executable(bundle / "wins_vpn", synthetic_elf64(expected))
            write_executable(bundle / "winn-datapath", synthetic_elf64(wrong))
            for filename in (
                "winsvpn-bypass-bpf",
                "awg",
                "amneziawg-go",
                "xray",
            ):
                write_executable(bundle / filename, synthetic_elf64(expected))
            write_executable(bundle / "awg-quick", b"#!/bin/sh\nexit 0\n")
            native_host = bundle / "tools/native_messaging/host/wins_bridge_host"
            native_host.parent.mkdir(parents=True)
            write_executable(native_host, synthetic_elf64(expected))
            completed = subprocess.run(
                ["bash", str(INSTALLER_PATH), "--self-test", str(bundle)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 65, completed.stderr)
            self.assertIn("winn-datapath", completed.stderr)
            self.assertIn("expected", completed.stderr)

            write_executable(bundle / "winn-datapath", synthetic_elf64(expected))
            accepted = subprocess.run(
                ["bash", str(INSTALLER_PATH), "--self-test", str(bundle)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn("winn-datapath          ELF architecture OK", accepted.stdout)

    def test_installer_self_test_rejects_foreign_nested_library(self) -> None:
        expected = host_elf_machine()
        wrong = 183 if expected == 62 else 62
        with tempfile.TemporaryDirectory() as name:
            bundle = pathlib.Path(name)
            for filename in (
                "wins_vpn",
                "winsvpn-bypass-bpf",
                "winn-datapath",
                "awg",
                "amneziawg-go",
                "xray",
            ):
                write_executable(bundle / filename, synthetic_elf64(expected))
            write_executable(bundle / "awg-quick", b"#!/bin/sh\nexit 0\n")
            native_host = bundle / "tools/native_messaging/host/wins_bridge_host"
            native_host.parent.mkdir(parents=True)
            write_executable(native_host, synthetic_elf64(expected))
            (bundle / "lib").mkdir()
            write_executable(bundle / "lib/foreign.so", synthetic_elf64(wrong, elf_type=3))
            completed = subprocess.run(
                ["bash", str(INSTALLER_PATH), "--self-test", str(bundle)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 65, completed.stderr)
            self.assertIn("foreign.so", completed.stderr)
            self.assertIn("expected", completed.stderr)

    def test_installer_self_test_rejects_foreign_fallback_or_native_host(self) -> None:
        expected = host_elf_machine()
        wrong = 183 if expected == 62 else 62
        with tempfile.TemporaryDirectory() as name:
            bundle = pathlib.Path(name)
            for filename in (
                "wins_vpn",
                "winsvpn-bypass-bpf",
                "winn-datapath",
                "awg",
                "amneziawg-go",
                "xray",
            ):
                write_executable(bundle / filename, synthetic_elf64(expected))
            write_executable(bundle / "awg-quick", b"#!/bin/sh\nexit 0\n")
            native_host = bundle / "tools/native_messaging/host/wins_bridge_host"
            native_host.parent.mkdir(parents=True)
            write_executable(native_host, synthetic_elf64(expected))

            for relative in ("xray", "tools/native_messaging/host/wins_bridge_host"):
                with self.subTest(relative=relative):
                    candidate = bundle / relative
                    write_executable(candidate, synthetic_elf64(wrong))
                    completed = subprocess.run(
                        ["bash", str(INSTALLER_PATH), "--self-test", str(bundle)],
                        cwd=ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 65, completed.stderr)
                    self.assertIn(relative, completed.stderr)
                    write_executable(candidate, synthetic_elf64(expected))

    def test_installer_requires_flutter_payloads_and_walks_every_elf(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn("lib/libapp.so", installer)
        self.assertIn("lib/libflutter_linux_gtk.so", installer)
        self.assertIn("winn3-descriptor-ring-attestation.json", installer)
        self.assertIn("assert_every_extracted_elf_matches_this_machine", installer)
        self.assertIn("mixed-architecture ELF", installer)
        self.assertIn(
            "refusing to install an unpinned runtime",
            installer,
        )
        self.assertNotIn("A release that does not carry it installs normally", installer)

    def test_producer_gate_accepts_target_and_rejects_foreign_datapath(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = pathlib.Path(name)
            target = directory / "target-winn-datapath"
            foreign = directory / "foreign-winn-datapath"
            write_executable(target, synthetic_elf64(183))
            write_executable(foreign, synthetic_elf64(62))
            accepted = subprocess.run(
                [
                    "bash",
                    str(PRODUCER_PATH),
                    "--self-test-elf-machine",
                    str(target),
                    "183",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            rejected = subprocess.run(
                [
                    "bash",
                    str(PRODUCER_PATH),
                    "--self-test-elf-machine",
                    str(foreign),
                    "183",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("LINUX ELF ARCHITECTURE SELF-TEST: PASS", accepted.stdout)
        self.assertEqual(rejected.returncode, 65, rejected.stderr)
        self.assertIn("targets ELF machine 62", rejected.stderr)

    def test_producer_checks_datapath_before_staging(self) -> None:
        producer = PRODUCER_PATH.read_text(encoding="utf-8")
        build_at = producer.index(
            'PATH=/usr/bin:/bin:/usr/sbin:/sbin bash "$ROOT/tools/build_winn_protocol_engine.sh"'
        )
        check_at = producer.index("  assert_release_elf_machine \\\n", build_at)
        install_at = producer.index(
            'winsvpn_install_bound_engine "$tmp_dir/winn/winn-datapath"', build_at
        )
        self.assertLess(check_at, install_at)


if __name__ == "__main__":
    unittest.main()
