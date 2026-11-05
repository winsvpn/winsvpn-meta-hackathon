#!/usr/bin/env python3
"""Regression tests for Winn conformance result parsing."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import winn_conformance_verify as verifier

parse_flutter_test_pass_count = verifier.parse_flutter_test_pass_count


def _uvarint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _go_buildinfo(
    package: str = "cmd/winn-clientinfo",
    *,
    goos: str = "linux",
    goarch: str = "amd64",
    cgo_enabled: bool = False,
) -> bytes:
    version = b"go1.27.1"
    feature = {
        "amd64": ("GOAMD64", "v1"),
        "arm64": ("GOARM64", "v8.0"),
        "arm": ("GOARM", "7"),
    }[goarch]
    module = (
        f"path\twinsvpn.local/winnprotocol/{package}\n"
        "build\t-trimpath=true\n"
        f"build\tCGO_ENABLED={int(cgo_enabled)}\n"
        f"build\tGOARCH={goarch}\n"
        f"build\tGOOS={goos}\n"
        f"build\t{feature[0]}={feature[1]}\n"
    ).encode("ascii")
    header = verifier.GO_BUILDINFO_MAGIC + bytes((8, 2)) + bytes(16)
    return header + _uvarint(len(version)) + version + _uvarint(len(module)) + module



def _minimal_elf(
    architecture: str = "amd64", goos: str = "linux", package: str = "cmd/winn-clientinfo"
) -> bytes:
    machine = {"amd64": 62, "arm64": 183, "arm": 40}[architecture]
    elf_class = 1 if architecture == "arm" else 2
    code_offset = 0x200 if elf_class == 1 else 0x300
    buildinfo_offset = code_offset + 0x20
    buildinfo = _go_buildinfo(
        package,
        goos=goos,
        goarch=architecture,
        cgo_enabled=goos == "android",
    )
    payload = bytearray(buildinfo_offset + len(buildinfo))
    payload[:7] = b"\x7fELF" + bytes((elf_class, 1, 1))
    if elf_class == 2:
        phoff, shoff, vaddr = 64, 0x180, 0x400000
        struct.pack_into("<HHIQQQIHHHHHH", payload, 16, 2, machine, 1, vaddr + code_offset, phoff, shoff, 0, 64, 56, 1, 64, 2, 0)
        struct.pack_into("<IIQQQQQQ", payload, phoff, 1, 5, code_offset, vaddr + code_offset, vaddr + code_offset, len(payload) - code_offset, len(payload) - code_offset, 0x1000)
        struct.pack_into("<IIQQQQIIQQ", payload, shoff + 64, 0, 1, 0x6, vaddr + code_offset, code_offset, len(payload) - code_offset, 0, 0, 16, 0)
    else:
        phoff, shoff, vaddr = 52, 0x100, 0x1000
        struct.pack_into("<HHIIIIIHHHHHH", payload, 16, 2, machine, 1, vaddr + code_offset, phoff, shoff, 0, 52, 32, 1, 40, 2, 0)
        struct.pack_into("<IIIIIIII", payload, phoff, 1, code_offset, vaddr + code_offset, vaddr + code_offset, len(payload) - code_offset, len(payload) - code_offset, 5, 0x1000)
        struct.pack_into("<IIIIIIIIII", payload, shoff + 40, 0, 1, 0x6, vaddr + code_offset, code_offset, len(payload) - code_offset, 0, 0, 16, 0)
    payload[code_offset:code_offset + 4] = b"CODE"
    payload[buildinfo_offset:buildinfo_offset + len(buildinfo)] = buildinfo
    return bytes(payload)


def _minimal_macho(architecture: str = "arm64", package: str = "cmd/winn-clientinfo") -> bytes:
    cpu_type = 0x0100000C if architecture == "arm64" else 0x01000007
    code_offset = 0x200
    buildinfo = _go_buildinfo(package, goos="darwin", goarch=architecture)
    code_size = 0x20 + len(buildinfo)
    payload = bytearray(code_offset + code_size)
    payload[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<IIIIIII", payload, 4, cpu_type, 0, 2, 2, 176, 0, 0)
    cursor = 32
    struct.pack_into("<II16sQQQQiiII", payload, cursor, 0x19, 152, b"__TEXT", 0x100000000, code_size, code_offset, code_size, 7, 5, 1, 0)
    struct.pack_into("<16s16sQQIIIIIIII", payload, cursor + 72, b"__text", b"__TEXT", 0x100000000, code_size, code_offset, 4, 0, 0, 0x80000400, 0, 0, 0)
    struct.pack_into("<IIQQ", payload, cursor + 152, 0x80000028, 24, code_offset, 0)
    payload[code_offset:code_offset + 4] = b"CODE"
    payload[code_offset + 0x20:code_offset + 0x20 + len(buildinfo)] = buildinfo
    return bytes(payload)


def _minimal_pe(architecture: str = "amd64", package: str = "cmd/winn-clientinfo") -> bytes:
    machine = {"amd64": 0x8664, "arm64": 0xAA64}[architecture]
    pe_offset = 0x80
    optional_offset = pe_offset + 24
    section_offset = optional_offset + 240
    code_offset = 0x200
    buildinfo = _go_buildinfo(package, goos="windows", goarch=architecture)
    code_size = 0x20 + len(buildinfo)
    payload = bytearray(code_offset + code_size)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, pe_offset)
    payload[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", payload, pe_offset + 4, machine, 1, 0, 0, 0, 240, 0x22)
    struct.pack_into("<H", payload, optional_offset, 0x20B)
    struct.pack_into("<I", payload, optional_offset + 4, code_size)
    struct.pack_into("<I", payload, optional_offset + 16, 0x1000)
    struct.pack_into("<8sIIIIIIHHI", payload, section_offset, b".text", code_size, 0x1000, code_size, code_offset, 0, 0, 0, 0, 0x60000020)
    payload[code_offset:code_offset + 4] = b"CODE"
    payload[code_offset + 0x20:code_offset + 0x20 + len(buildinfo)] = buildinfo
    return bytes(payload)


def _archive_with_member(body: bytes) -> bytes:
    header = (
        b"go.o/           "
        + b"0           "
        + b"0     "
        + b"0     "
        + b"100644  "
        + f"{len(body):<10}".encode("ascii")
        + b"`\n"
    )
    archive = b"!<arch>\n" + header + body
    return archive + (b"\n" if len(body) & 1 else b"")


def _minimal_archive(
    architecture: str = "arm64", platform_name: str = "ios-device"
) -> bytes:
    cpu_type = 0x0100000C if architecture == "arm64" else 0x01000007
    platform_code = {"macos": 1, "ios-device": 2, "ios-simulator": 7}[platform_name]
    code_offset = 0x240
    identity = _go_buildinfo(
        "cshared",
        goos="darwin" if platform_name == "macos" else "ios",
        goarch=architecture,
        cgo_enabled=True,
    )
    names = ("WinnFacadeVersion", "WinnProtocolVersion", "WinnTunnelBackendJSON")
    string_table = bytearray(b"\x00")
    name_offsets: list[int] = []
    for name in names:
        name_offsets.append(len(string_table))
        string_table.extend(("_" + name).encode("ascii") + b"\x00")
    code_size = 0x20 + len(identity)
    symbol_offset = code_offset + code_size
    string_offset = symbol_offset + len(names) * 16
    body = bytearray(string_offset + len(string_table))
    body[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<IIIIIII", body, 4, cpu_type, 0, 1, 3, 200, 0, 0)
    struct.pack_into("<II16sQQQQiiII", body, 32, 0x19, 152, b"__TEXT", 0, code_size, code_offset, code_size, 7, 5, 1, 0)
    struct.pack_into("<16s16sQQIIIIIIII", body, 104, b"__text", b"__TEXT", 0, code_size, code_offset, 4, 0, 0, 0x80000400, 0, 0, 0)
    struct.pack_into("<IIIIII", body, 184, 0x32, 24, platform_code, 0, 0, 0)
    struct.pack_into(
        "<IIIIII",
        body,
        208,
        0x2,
        24,
        symbol_offset,
        len(names),
        string_offset,
        len(string_table),
    )
    body[code_offset:code_offset + 4] = b"CODE"
    identity_offset = code_offset + 0x20
    body[identity_offset:identity_offset + len(identity)] = identity
    for index, name_offset in enumerate(name_offsets):
        struct.pack_into(
            "<IBBHQ",
            body,
            symbol_offset + index * 16,
            name_offset,
            0x0F,
            1,
            0,
            0,
        )
    body[string_offset:string_offset + len(string_table)] = string_table
    return _archive_with_member(bytes(body))



def _host_fixture() -> tuple[str, str, str, bytes]:
    host_os, host_arch = verifier._host_target()
    if host_os == "darwin":
        return f"darwin-{host_arch}", host_os, host_arch, _minimal_macho(host_arch)
    if host_os == "linux":
        return f"linux-{host_arch}", host_os, host_arch, _minimal_elf(host_arch)
    raise unittest.SkipTest("structured native fixture is implemented for Darwin/Linux")


def _protocol_document(
    states: tuple[str, str, str],
    selected: str | None,
    *,
    custody: tuple[str, str, str] = ("verified", "verified", "verified"),
) -> dict[str, object]:
    return {
        "contract": verifier.PROTOCOL_ORDER_CONTRACT,
        "platform": "test-amd64",
        "selected": selected,
        "engines": [
            {
                "id": engine_id,
                "availability": availability,
                "custody": custody_state,
                "detail": "owner evidence pending" if custody_state == "owner-blocked" else "fixture",
            }
            for engine_id, availability, custody_state in zip(
                verifier.PROTOCOL_ORDER, states, custody
            )
        ],
    }



NDK_VERSION = "30.0.16248370"
SOURCE_COMMIT = "260da56"
VALID_CLIENTINFO_HEADER = """#ifndef WINN_FIXTURE_H
#define WINN_FIXTURE_H
extern char *WinnFacadeVersion(void);
extern char *WinnProtocolVersion(void);
extern char *WinnTunnelBackendJSON(void);
extern void WinnFreeString(char *value);
#endif
"""


def _buildinfo_with_sentinels(package: str = "cmd/winn-clientinfo") -> bytes:
    """Go buildinfo exactly as the linker writes it: modinfo in 16-byte sentinels."""
    version = b"go" + verifier._reviewed_go_identity()["version"].encode("ascii")
    module = (
        f"path\twinsvpn.local/winnprotocol/{package}\n"
        "build\t-trimpath=true\n"
        "build\tCGO_ENABLED=0\n"
        "build\tGOARCH=amd64\n"
        "build\tGOOS=linux\n"
        "build\tGOAMD64=v1\n"
    ).encode("ascii")
    wrapped = bytes((0x30, 0x77, 0xAF)) + bytes(13) + module + bytes(16)
    header = verifier.GO_BUILDINFO_MAGIC + bytes((8, 2)) + bytes(16)
    return header + _uvarint(len(version)) + version + _uvarint(len(wrapped)) + wrapped


def _platform_for(target: str) -> dict[str, object]:
    expected = verifier.expected_build_identity(target)
    assert expected is not None
    platform: dict[str, object] = {
        "compiler_path": None,
        "compiler_sha256": None,
        "id": expected["platform"],
        "ndk_version": None,
        "sdk_version": None,
    }
    if expected["cgo_enabled"] and expected["goos"] == "android":
        platform.update(
            compiler_path="/opt/ndk/toolchains/llvm/bin/aarch64-linux-android24-clang",
            compiler_sha256="1" * 64,
            ndk_version=NDK_VERSION,
        )
    elif expected["cgo_enabled"]:
        platform.update(
            compiler_path="/Applications/Xcode.app/Contents/Developer/usr/bin/clang",
            compiler_sha256="2" * 64,
            sdk_version="26.0",
        )
    return platform


def _fixture_payload(target: str) -> tuple[bytes, str | None]:
    expected = verifier.expected_build_identity(target)
    assert expected is not None
    package = str(expected["package"])[2:]
    if target == "ios-arm64":
        return _minimal_archive("arm64"), VALID_CLIENTINFO_HEADER
    if expected["archive_mode"]:
        raise unittest.SkipTest("datapath archive fixtures are not modelled")
    if expected["goos"] == "windows":
        return _minimal_pe(str(expected["goarch"]), package), None
    if expected["goos"] == "darwin":
        return _minimal_macho(str(expected["goarch"]), package), None
    return _minimal_elf(str(expected["goarch"]), str(expected["goos"]), package), None


def _write_release(
    release: Path,
    targets: list[str],
    *,
    mutate_entry=None,
    mutate_manifest=None,
    payloads: dict[str, bytes] | None = None,
) -> None:
    """Write a release directory with the exact shape winn_release.py build writes."""
    entries = []
    for target in targets:
        payload, header = _fixture_payload(target)
        if payloads and target in payloads:
            payload = payloads[target]
        expected = verifier.expected_build_identity(target)
        filename = verifier.release_artifact_filename(target)
        directory = release / "artifacts" / target
        directory.mkdir(parents=True)
        (directory / filename).write_bytes(payload)
        (directory / filename).chmod(0o555)
        digest = hashlib.sha256(payload).hexdigest()
        entry: dict[str, object] = {
            "build_a_sha256": digest,
            "build_b_sha256": digest,
            "cgo_enabled": expected["cgo_enabled"],
            "goarch": expected["goarch"],
            "goos": expected["goos"],
            "header_path": None,
            "header_sha256": None,
            "package": expected["package"],
            "path": f"artifacts/{target}/{filename}",
            "platform": _platform_for(target),
            "role": expected["role"],
            "sha256": digest,
            "size": len(payload),
            "target": target,
        }
        if header is not None:
            header_name = Path(filename).stem + ".h"
            (directory / header_name).write_text(header, encoding="ascii")
            entry["header_path"] = f"artifacts/{target}/{header_name}"
            entry["header_sha256"] = hashlib.sha256(header.encode("ascii")).hexdigest()
        if mutate_entry is not None:
            mutate_entry(entry)
        entries.append(entry)
    go = verifier._reviewed_go_identity()
    pins = json.loads(verifier.TOOLCHAIN_PINS.read_text(encoding="utf-8"))["tools"]
    host_key = "_".join(verifier._host_target())
    manifest: dict[str, object] = {
        "artifacts": sorted(entries, key=lambda item: str(item["target"])),
        "contract": verifier.RELEASE_MANIFEST_CONTRACT,
        "created_utc": "2026-10-09T00:00:00Z",
        "producer": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in verifier.RELEASE_PRODUCER_FILES
        },
        "reproducibility": {"independent_builds": 2, "result": "byte-identical"},
        "requested_targets": list(targets),
        "skipped_targets": {},
        "source": {
            "binding": "export",
            "commit": SOURCE_COMMIT,
            "path": "winn_protocol_experimental",
            "tree_sha256": "5" * 64,
        },
        "toolchains": {
            "android_ndk": {
                "tree_sha256": pins["android_ndk"]["install_tree_sha256"].get(host_key),
                "version": NDK_VERSION,
            },
            "apple": {
                "clang_sha256": "2" * 64,
                "sdks": {},
                "xcode_build": pins["xcode"]["build"],
                "xcode_version": pins["xcode"]["version"],
            },
            "go": {
                "archive_sha256": go["archive_sha256"],
                "executable_sha256": go["executable_sha256"],
                "install_tree_sha256": go["install_tree_sha256"],
                "version": go["version"],
            },
            "gomodcache_tree_sha256": "4" * 64,
            "module_proxy_for_seeding": "off",
        },
    }
    if mutate_manifest is not None:
        mutate_manifest(manifest)
    (release / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )


class FakeDriver:
    """Stand-in for `winn_release.py build`: records argv, writes a release."""

    def __init__(self, targets: list[str], *, rc: int = 0, stderr: str = "", **writer: object):
        self.targets = targets
        self.rc = rc
        self.stderr = stderr
        self.writer = writer
        self.commands: list[list[str]] = []

    def __call__(self, cmd: list[str], **kwargs: object) -> tuple[int, str, str]:
        self.commands.append(list(cmd))
        self.kwargs = kwargs
        if self.rc == 0:
            release = Path(cmd[cmd.index("--out") + 1])
            release.mkdir()
            _write_release(release, self.targets, **self.writer)  # type: ignore[arg-type]
        return self.rc, "", self.stderr


def _options(**overrides: object) -> "verifier.DriverOptions":
    values: dict[str, object] = {
        "source_commit": SOURCE_COMMIT,
        "source_export": "/private/tmp/winn-export",
        "module_proxy": "off",
        "ndk": "/opt/ndk",
    }
    values.update(overrides)
    return verifier.DriverOptions(**values)  # type: ignore[arg-type]


def _receipt(
    output: Path,
    *,
    target: str = "linux-amd64",
    mutate=None,
    receipt_file: bool = True,
) -> str:
    expected = verifier.expected_build_identity(target)
    assert expected is not None
    go = verifier._reviewed_go_identity()
    header = output.with_suffix(".h")
    document: dict[str, object] = {
        "archive_mode": expected["archive_mode"],
        "artifact": {
            "header_sha256": (
                hashlib.sha256(header.read_bytes()).hexdigest() if expected["archive_mode"] else None
            ),
            "output_path": str(output.resolve()),
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        },
        "contract": verifier.BUILD_RECEIPT_CONTRACT,
        "go": {"executable_sha256": go["executable_sha256"], "version": go["version"]},
        "module_cache_tree_sha256": "4" * 64,
        "package": expected["package"],
        "platform": _platform_for(target),
        "role": expected["role"],
        "source_tree_sha256": "5" * 64,
        "target": {
            "cgo_enabled": expected["cgo_enabled"],
            "goarch": expected["goarch"],
            "goos": expected["goos"],
            "id": target,
        },
    }
    if mutate is not None:
        mutate(document)
    payload = json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if receipt_file:
        Path(str(output) + ".receipt.json").write_text(payload + "\n", encoding="ascii")
    return verifier.BUILD_RECEIPT_PREFIX + payload


def _quiet(function, *args: object, **kwargs: object):
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args, **kwargs)


class FlutterTestSummaryParsingTest(unittest.TestCase):
    def test_accepts_summary_without_skips(self) -> None:
        self.assertEqual(
            parse_flutter_test_pass_count("00:10 +1557: All tests passed!\n"),
            1557,
        )

    def test_accepts_summary_with_skips(self) -> None:
        self.assertEqual(
            parse_flutter_test_pass_count("00:10 +1557 ~5: All tests passed!\n"),
            1557,
        )

    def test_accepts_all_other_tests_variant(self) -> None:
        self.assertEqual(
            parse_flutter_test_pass_count(
                "00:10 +1557 ~5: All other tests passed!\n"
            ),
            1557,
        )

    def test_rejects_failure_summary(self) -> None:
        self.assertIsNone(
            parse_flutter_test_pass_count("00:10 +1557 ~5 -1: Some tests failed.\n")
        )


class ProtocolOrderTest(unittest.TestCase):
    def _verify(self, document: object, *, authenticated: bool = True) -> verifier.Report:
        report = verifier.Report()
        with contextlib.redirect_stdout(io.StringIO()):
            verifier.verify_protocol_order(
                report,
                document,
                authenticated_release_evidence=authenticated,
            )
        return report

    def test_winn_v3_is_primary(self) -> None:
        report = self._verify(
            _protocol_document(("available", "available", "available"), "winn/3")
        )
        self.assertEqual(report.worst_exit_code(), 0)

    def test_awg_requires_explicit_winn_v3_unavailability(self) -> None:
        accepted = self._verify(
            _protocol_document(("unavailable", "available", "available"), "winn/1-amneziawg")
        )
        self.assertEqual(accepted.worst_exit_code(), 0)

        refused = self._verify(
            _protocol_document(("available", "available", "available"), "winn/1-amneziawg")
        )
        self.assertEqual(refused.worst_exit_code(), 1)

    def test_xray_requires_v3_then_awg_unavailability(self) -> None:
        accepted = self._verify(
            _protocol_document(("unavailable", "unavailable", "available"), "xray")
        )
        self.assertEqual(accepted.worst_exit_code(), 0)

        for states in (
            ("available", "unavailable", "available"),
            ("unavailable", "available", "available"),
        ):
            with self.subTest(states=states):
                refused = self._verify(_protocol_document(states, "xray"))
                self.assertEqual(refused.worst_exit_code(), 1)

    def test_unverified_predecessor_never_authorizes_fallback(self) -> None:
        report = self._verify(
            _protocol_document(("unverified", "available", "available"), "winn/1-amneziawg")
        )
        self.assertEqual(report.worst_exit_code(), 1)
        self.assertFalse(any(check.status == verifier.PASS for check in report.checks))

    def test_owner_blocked_unavailable_v3_preserves_unverified_exit(self) -> None:
        report = self._verify(
            _protocol_document(
                ("unavailable", "available", "available"),
                "winn/1-amneziawg",
                custody=("owner-blocked", "verified", "verified"),
            )
        )
        self.assertEqual(report.worst_exit_code(), 2)
        self.assertTrue(any(check.status == verifier.PASS for check in report.checks))
        self.assertTrue(any(check.status == verifier.UNVERIFIED for check in report.checks))

    def test_owner_blocked_available_engine_is_not_selectable(self) -> None:
        report = self._verify(
            _protocol_document(
                ("available", "unavailable", "unavailable"),
                "winn/3",
                custody=("owner-blocked", "verified", "verified"),
            )
        )
        self.assertEqual(report.worst_exit_code(), 1)

    def test_non_object_and_non_exact_structures_fail_without_exception(self) -> None:
        for document in (None, [], "text", 4):
            with self.subTest(document=document):
                self.assertEqual(self._verify(document).worst_exit_code(), 1)

        missing = _protocol_document(("available", "unavailable", "unavailable"), "winn/3")
        del missing["engines"]
        self.assertEqual(self._verify(missing).worst_exit_code(), 1)

    def test_no_engine_requires_every_engine_explicitly_unavailable(self) -> None:
        unavailable = self._verify(
            _protocol_document(("unavailable", "unavailable", "unavailable"), None)
        )
        self.assertEqual(unavailable.worst_exit_code(), 2)

        unknown = self._verify(
            _protocol_document(("unavailable", "unverified", "unavailable"), None)
        )
        self.assertEqual(unknown.worst_exit_code(), 2)

    def test_strict_json_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        for payload in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.subTest(payload=payload):
                with self.assertRaises((ValueError, verifier.json.JSONDecodeError)):
                    verifier.parse_structural_json(payload)

    def test_self_authored_protocol_order_never_passes(self) -> None:
        report = self._verify(
            _protocol_document(("available", "available", "available"), "winn/3"),
            authenticated=False,
        )
        self.assertEqual(report.worst_exit_code(), 2)
        self.assertFalse(any(check.status == verifier.PASS for check in report.checks))
        self.assertTrue(any("caller-authored" in check.name for check in report.checks))


class BoundedOutputTest(unittest.TestCase):
    def test_report_bounds_fields_and_preserves_omitted_severity(self) -> None:
        report = verifier.Report()
        with contextlib.redirect_stdout(io.StringIO()):
            report.add(verifier.PASS, "n" * 1000, "d" * 5000)
            for _ in range(verifier.MAX_CHECKS - 1):
                report.add(verifier.INFO, "within bound")
            report.add(verifier.FAIL, "hidden failure")
        self.assertEqual(len(report.checks), verifier.MAX_CHECKS)
        self.assertLessEqual(len(report.checks[0].name), verifier.MAX_CHECK_NAME_CHARS)
        self.assertLessEqual(len(report.checks[0].detail), verifier.MAX_CHECK_DETAIL_CHARS)
        self.assertIn("truncated", report.checks[0].name)
        self.assertEqual(report.omitted_counts[verifier.FAIL], 1)
        self.assertEqual(report.worst_exit_code(), 1)
        self.assertIn("1 omitted by output bound", report.summary())

    def test_report_escapes_control_characters(self) -> None:
        report = verifier.Report()
        rendered = io.StringIO()
        with contextlib.redirect_stdout(rendered):
            report.add(verifier.UNVERIFIED, "input\n[PASS] forged", "\x1b[31mblocked\r")
        self.assertEqual(len(rendered.getvalue().splitlines()), 1)
        self.assertIn("\\x0a[PASS] forged", rendered.getvalue())
        self.assertIn("\\x1b[31mblocked\\x0d", rendered.getvalue())
        for separator in ("\x85", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                self.assertNotIn(separator, verifier._bounded_text(f"before{separator}after", 100))

    def test_empty_or_info_only_report_is_not_success(self) -> None:
        self.assertEqual(verifier.Report().worst_exit_code(), 2)
        report = verifier.Report()
        with contextlib.redirect_stdout(io.StringIO()):
            report.add(verifier.INFO, "no evidence")
        self.assertEqual(report.worst_exit_code(), 2)

    def test_subprocess_output_is_bounded(self) -> None:
        rc, out, err = verifier.run(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 70000)"],
            timeout=10,
        )
        self.assertEqual(rc, verifier.SUBPROCESS_OUTPUT_LIMIT_RC)
        self.assertEqual(len(out.encode("utf-8")), verifier.MAX_SUBPROCESS_OUTPUT_BYTES)
        self.assertIn("STRUCTURAL OUTPUT LIMIT", err)

    def test_invalid_utf8_output_fails_closed_without_expansion(self) -> None:
        rc, out, err = verifier.run(
            [sys.executable, "-c", "import os; os.write(1, b'\\xff' * 70000)"],
            timeout=10,
        )
        self.assertEqual(rc, verifier.SUBPROCESS_OUTPUT_LIMIT_RC)
        self.assertLessEqual(len(out.encode("utf-8")), verifier.MAX_SUBPROCESS_OUTPUT_BYTES)
        self.assertIn("not valid UTF-8", err)

    @unittest.skipUnless(verifier.os.name == "posix", "process-group custody is POSIX-specific")
    def test_timeout_kills_descendants_holding_output_pipes(self) -> None:
        started = verifier.time.monotonic()
        rc, _, err = verifier.run(
            [
                sys.executable,
                "-c",
                "import subprocess; subprocess.Popen(['/bin/sleep', '2'])",
            ],
            timeout=0.2,
        )
        elapsed = verifier.time.monotonic() - started
        self.assertEqual(rc, 124)
        self.assertLess(elapsed, 1.5)
        self.assertIn("TIMEOUT", err)

    def test_constructed_environment_does_not_copy_unlisted_values(self) -> None:
        with mock.patch.dict(verifier.os.environ, {"WINS_TEST_SECRET": "do-not-copy"}):
            environment = verifier.constructed_environment()
        self.assertNotIn("WINS_TEST_SECRET", environment)
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(environment["HOME"], "/var/empty")
        for fixed in ("PATH", "HOME"):
            with self.subTest(fixed=fixed), self.assertRaises(ValueError):
                verifier.constructed_environment({fixed: "/hostile"})



class StructuredArtifactTest(unittest.TestCase):
    def _identity(self, payload: bytes, target: str) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as name:
            artifact = Path(name) / "artifact"
            artifact.write_bytes(payload)
            with verifier.BoundArtifact(artifact.resolve()) as binding:
                expected = verifier.expected_build_identity(target)
                self.assertIsNotNone(expected)
                return verifier._structured_artifact_identity(binding, expected)

    def test_real_structural_fixtures_cover_every_supported_container(self) -> None:
        cases = (
            (_minimal_elf("amd64"), "linux-amd64", ("elf", "amd64")),
            (_minimal_pe("amd64"), "windows-amd64", ("pe", "amd64")),
            (_minimal_macho("arm64"), "darwin-arm64", ("macho", "arm64")),
            (_minimal_archive("arm64"), "ios-arm64", ("archive", "arm64")),
        )
        for payload, target, expected in cases:
            with self.subTest(target=target):
                self.assertEqual(self._identity(payload, target), expected)

    def test_header_only_and_marker_only_containers_reach_structure_gates(self) -> None:
        macho_header = bytearray(32)
        macho_header[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<IIIIIII", macho_header, 4, 0x0100000C, 0, 2, 0, 0, 0, 0)
        marker_object = (
            b"\x7fELF"
            + b"\0" * 60
            + b"winsvpn.local/winnprotocol/cshared"
            + b"WinnFacadeVersion WinnProtocolVersion WinnTunnelBackendJSON"
        )
        cases = (
            (b"\x7fELF" + b"\0" * 60, "linux-amd64"),
            (b"MZ" + b"\0" * 126, "windows-amd64"),
            (bytes(macho_header), "darwin-arm64"),
            (_archive_with_member(marker_object), "ios-arm64"),
        )
        for payload, target in cases:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self._identity(payload, target)

    def test_role_swapped_go_identity_reaches_independent_role_gate(self) -> None:
        payload = _minimal_elf("amd64").replace(
            b"winsvpn.local/winnprotocol/cmd/winn-clientinfo",
            b"winsvpn.local/winnprotocol/cmd/winn-datapathXX",
        )
        with self.assertRaisesRegex(ValueError, "Go build identity"):
            self._identity(payload, "linux-amd64")

    def test_arm64_elf_entry_requires_four_byte_alignment(self) -> None:
        payload = bytearray(_minimal_elf("arm64"))
        entry = struct.unpack_from("<Q", payload, 24)[0]
        struct.pack_into("<Q", payload, 24, entry + 2)
        with self.assertRaisesRegex(ValueError, "4-byte aligned"):
            self._identity(bytes(payload), "linux-arm64")

    def test_embedded_go_settings_prevent_linux_android_arm64_substitution(self) -> None:
        with self.assertRaisesRegex(ValueError, "loadable Go build identity"):
            self._identity(_minimal_elf("arm64", "linux"), "android-arm64")
        self.assertEqual(
            self._identity(_minimal_elf("arm64", "android"), "android-arm64"),
            ("elf", "arm64"),
        )

    def test_arm64_macho_and_pe_entries_require_four_byte_alignment(self) -> None:
        macho = bytearray(_minimal_macho("arm64"))
        struct.pack_into("<Q", macho, 32 + 152 + 8, 0x201)
        with self.assertRaisesRegex(ValueError, "Mach-O arm64 entry"):
            self._identity(bytes(macho), "darwin-arm64")

        pe = bytearray(_minimal_pe("arm64"))
        pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
        struct.pack_into("<I", pe, pe_offset + 24 + 16, 0x1001)
        with self.assertRaisesRegex(ValueError, "PE arm64 entry"):
            self._identity(bytes(pe), "windows-arm64")

    def test_apple_archive_platform_cannot_be_reused_across_targets(self) -> None:
        with self.assertRaisesRegex(ValueError, "exact Apple target"):
            self._identity(
                _minimal_archive("arm64", "ios-simulator"),
                "ios-arm64",
            )

    def test_archive_symbols_must_come_from_real_symbol_table(self) -> None:
        payload = bytearray(_minimal_archive("arm64"))
        payload[payload.find(b"_WinnFacadeVersion") + 1] = ord("X")
        with self.assertRaisesRegex(ValueError, "role symbols"):
            self._identity(bytes(payload), "ios-arm64")

    def test_generated_header_requires_exact_role_prototypes_and_retention(self) -> None:
        expected = verifier.expected_build_identity("ios-arm64")
        self.assertIsNotNone(expected)
        valid = """#ifndef WINN_FIXTURE_H
#define WINN_FIXTURE_H
extern char *WinnFacadeVersion(void);
extern char *WinnProtocolVersion(void);
extern char *WinnTunnelBackendJSON(void);
extern void WinnFreeString(char *value);
#endif
"""
        with tempfile.TemporaryDirectory() as name:
            header = Path(name) / "fixture.h"
            header.write_text(valid, encoding="ascii")
            with verifier.BoundArtifact(header.resolve()) as binding:
                verifier._validate_generated_header(binding, expected)
            header.write_text(valid.replace("WinnTunnelBackendJSON", "WrongRole"), encoding="ascii")
            with verifier.BoundArtifact(header.resolve()) as binding:
                with self.assertRaisesRegex(ValueError, "WinnTunnelBackendJSON"):
                    verifier._validate_generated_header(binding, expected)
            hostile = valid.replace(
                "extern char *WinnTunnelBackendJSON(void);",
                "extern const char * __stdcall WinnTunnelBackendJSON(int value);",
            )
            header.write_text(hostile, encoding="ascii")
            with verifier.BoundArtifact(header.resolve()) as binding:
                with self.assertRaisesRegex(ValueError, "calling convention and types"):
                    verifier._validate_generated_header(binding, expected)



class RealGoContainerTest(unittest.TestCase):
    """Shapes the Go toolchain really emits, which the minimal fixtures omit."""

    def test_modinfo_sentinels_are_stripped_like_debug_buildinfo(self) -> None:
        expected = verifier.expected_build_identity("linux-amd64")
        payload = _buildinfo_with_sentinels()
        version, package = verifier._go_build_identity(payload, [(0, len(payload))], expected)
        self.assertEqual(package, "winsvpn.local/winnprotocol/cmd/winn-clientinfo")
        self.assertTrue(version.startswith("go"))
        hostile = _buildinfo_with_sentinels("cmd/winn-datapath")
        with self.assertRaisesRegex(ValueError, "loadable Go build identity"):
            verifier._go_build_identity(hostile, [(0, len(hostile))], expected)

    def test_elf_nobits_section_is_not_a_file_range(self) -> None:
        payload = bytearray(_minimal_elf("amd64"))
        shoff = struct.unpack_from("<Q", payload, 40)[0]
        # Section 0 becomes a huge allocated SHT_NOBITS (.bss) section.
        struct.pack_into("<IIQQQQ", payload, shoff, 0, 8, 0x3, 0x500000, 0x100000, 1 << 30)
        with tempfile.TemporaryDirectory() as name:
            artifact = Path(name) / "artifact"
            artifact.write_bytes(bytes(payload))
            with verifier.BoundArtifact(artifact.resolve()) as binding:
                self.assertEqual(
                    verifier._structured_artifact_identity(
                        binding, verifier.expected_build_identity("linux-amd64")
                    ),
                    ("elf", "amd64"),
                )
        # The same section as PROGBITS still has to fit in the file.
        struct.pack_into("<IIQQQQ", payload, shoff, 0, 1, 0x3, 0x500000, 0x100000, 1 << 30)
        with tempfile.TemporaryDirectory() as name:
            artifact = Path(name) / "artifact"
            artifact.write_bytes(bytes(payload))
            with verifier.BoundArtifact(artifact.resolve()) as binding:
                with self.assertRaisesRegex(ValueError, "out of file bounds"):
                    verifier._structured_artifact_identity(
                        binding, verifier.expected_build_identity("linux-amd64")
                    )

    def test_bsd_long_member_names_reach_object_gates(self) -> None:
        archive = _minimal_archive("arm64")
        body = archive[8 + 60:]
        if len(body) & 1:
            body = body[:-1]
        name = b"go.o\0\0\0\0"
        header = (
            f"#1/{len(name)}".encode("ascii").ljust(16)
            + b"0           0     0     100644  "
            + f"{len(name) + len(body):<10}".encode("ascii")
            + b"`\n"
        )
        member = name + body
        bsd = b"!<arch>\n" + header + member + (b"\n" if len(member) & 1 else b"")
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "libwinn-clientinfo.a"
            artifact.write_bytes(bsd)
            with verifier.BoundArtifact(artifact.resolve()) as binding:
                self.assertEqual(
                    verifier._structured_artifact_identity(
                        binding, verifier.expected_build_identity("ios-arm64")
                    ),
                    ("archive", "arm64"),
                )


class NativeRuntimeReleaseTest(unittest.TestCase):
    """Runtime claims execute only bytes a verified signed manifest names."""

    def _signed_release(self, root: Path, payload: bytes) -> tuple[Path, str]:
        target, _goos, _goarch, _ = _host_fixture()
        release = root / "release"
        release.mkdir()
        _write_release(release, [target], payloads={target: payload})
        (release / "manifest.sig.json").write_text("{}\n", encoding="ascii")
        return Path(verifier.os.path.realpath(release)), target

    def _verify_ok(self, release: Path, target: str, manifest: str | None = None) -> tuple[int, str, str]:
        # `verify --print-manifest --print-artifact`: the verified manifest
        # line, then the artifact path.
        filename = verifier.release_artifact_filename(target)
        if manifest is None:
            manifest = (release / "manifest.json").read_text(encoding="utf-8")
        return 0, f"{manifest.rstrip(chr(10))}\n{release / 'artifacts' / target / filename}\n", ""

    def test_held_manifest_must_be_the_manifest_the_driver_verified(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _target, _goos, _goarch, payload = _host_fixture()
            release, target = self._signed_release(Path(name), payload)
            other = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
            other["created_utc"] = "2026-10-10T00:00:00Z"
            verified = json.dumps(other, sort_keys=True, separators=(",", ":"))
            report = verifier.Report()
            with mock.patch.object(
                verifier, "run", return_value=self._verify_ok(release, target, verified)
            ) as runner:
                _quiet(verifier.native_runtime_claims, report, release, target=target)
            self.assertEqual(runner.call_count, 1)
            command = runner.call_args[0][0]
            self.assertIn("--print-manifest", command)
        self.assertEqual(report.worst_exit_code(), 1)
        self.assertTrue(any("the manifest the driver verified" in check.name for check in report.checks))

    def test_unsigned_release_is_unverified_and_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target, _goos, _goarch, payload = _host_fixture()
            release = Path(name) / "release"
            release.mkdir()
            _write_release(release, [target], payloads={target: payload})
            report = verifier.Report()
            with mock.patch.object(verifier, "run") as runner:
                _quiet(verifier.native_runtime_claims, report, release, target=target)
            runner.assert_not_called()
        self.assertEqual(report.worst_exit_code(), 2)
        self.assertTrue(any("is signed" in check.name for check in report.checks))

    def test_missing_target_or_release_fails_before_any_command(self) -> None:
        report = verifier.Report()
        with mock.patch.object(verifier, "run") as runner:
            _quiet(verifier.native_runtime_claims, report, None, target="darwin-arm64")
            _quiet(verifier.native_runtime_claims, report, Path("/x"), target="datapath-linux-amd64")
        runner.assert_not_called()
        self.assertEqual(report.worst_exit_code(), 1)

    def test_driver_rejection_stops_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _target, _goos, _goarch, payload = _host_fixture()
            release, target = self._signed_release(Path(name), payload)
            report = verifier.Report()
            with mock.patch.object(
                verifier, "run", return_value=(1, "", "WINN RELEASE REFUSED: signature")
            ) as runner:
                _quiet(verifier.native_runtime_claims, report, release, target=target)
            self.assertEqual(runner.call_count, 1)
            command = runner.call_args[0][0]
            self.assertEqual(command[:4], [verifier.RELEASE_DRIVER_PYTHON, "-I", str(verifier.RELEASE_DRIVER), "verify"])
            self.assertIn("--print-artifact", command)
        self.assertEqual(report.worst_exit_code(), 1)

    def test_trusted_key_is_forwarded_and_must_be_exact_hex(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _target, _goos, _goarch, payload = _host_fixture()
            release, target = self._signed_release(Path(name), payload)
            report = verifier.Report()
            with mock.patch.object(verifier, "run") as runner:
                _quiet(
                    verifier.native_runtime_claims, report, release, target=target,
                    trust_public_key="NOT-HEX",
                )
            runner.assert_not_called()
            self.assertEqual(report.worst_exit_code(), 1)
            report = verifier.Report()
            with mock.patch.object(
                verifier, "run", return_value=(1, "", "refused")
            ) as runner:
                _quiet(
                    verifier.native_runtime_claims, report, release, target=target,
                    trust_public_key="a" * 64,
                )
            command = runner.call_args[0][0]
            self.assertEqual(command[-2:], ["--trust-public-key", "a" * 64])

    def test_printed_path_must_be_the_exact_release_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _target, _goos, _goarch, payload = _host_fixture()
            release, target = self._signed_release(Path(name), payload)
            report = verifier.Report()
            with mock.patch.object(verifier, "run", return_value=(0, "/elsewhere/engine\n", "")) as runner:
                _quiet(verifier.native_runtime_claims, report, release, target=target)
            self.assertEqual(runner.call_count, 1)
        self.assertEqual(report.worst_exit_code(), 1)
        self.assertTrue(any("exact release path" in check.name for check in report.checks))

    def test_manifest_must_name_the_retained_reproducible_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _target, _goos, _goarch, payload = _host_fixture()
            release, target = self._signed_release(Path(name), payload)
            artifact = release / "artifacts" / target / verifier.release_artifact_filename(target)
            artifact.chmod(0o755)
            artifact.write_bytes(payload + b"X")
            report = verifier.Report()
            with mock.patch.object(verifier, "run", return_value=self._verify_ok(release, target)) as runner:
                _quiet(verifier.native_runtime_claims, report, release, target=target)
            self.assertEqual(runner.call_count, 1)
        self.assertEqual(report.worst_exit_code(), 1)
        self.assertTrue(any("exact reproducible bytes" in check.name for check in report.checks))

    def test_missing_carrier_backends_is_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _target, _goos, _goarch, payload = _host_fixture()
            release, target = self._signed_release(Path(name), payload)
            responses = [
                self._verify_ok(release, target),
                (0, '{"tunnel_supported":false}', ""),
                (0, '{"tunnel_supported":false,"safe_to_advertise_protocol":false}', ""),
                (1, "", "unknown"),
            ]
            report = verifier.Report()
            with mock.patch.object(verifier, "run", side_effect=responses) as runner:
                _quiet(verifier.native_runtime_claims, report, release, target=target)
            self.assertEqual(runner.call_count, 4)
        self.assertEqual(report.worst_exit_code(), 1)
        self.assertTrue(any(
            check.status == verifier.FAIL and "claims no capability" in check.name
            for check in report.checks
        ))
        self.assertTrue(any("signed release manifest verified" in check.name for check in report.checks))

    def test_honest_executable_passes_every_runtime_claim(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            _target, _goos, _goarch, payload = _host_fixture()
            release, target = self._signed_release(Path(name), payload)
            responses = [
                self._verify_ok(release, target),
                (0, '{"tunnel_supported":false}', ""),
                (0, '{"tunnel_supported":false,"safe_to_advertise_protocol":false,'
                    '"carrier_backends_available":[]}', ""),
                (2, "", "unknown"),
            ]
            report = verifier.Report()
            with mock.patch.object(verifier, "run", side_effect=responses):
                _quiet(verifier.native_runtime_claims, report, release, target=target)
        self.assertEqual(report.worst_exit_code(), 0, [check.line() for check in report.checks])

    def test_shell_script_runtime_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            release, target = self._signed_release(
                Path(name), b"#!/bin/sh\nprintf '{}\\n'\n"
            )
            report = verifier.Report()
            with mock.patch.object(verifier, "run", return_value=self._verify_ok(release, target)) as runner:
                _quiet(verifier.native_runtime_claims, report, release, target=target)
            self.assertEqual(runner.call_count, 1)
        self.assertEqual(report.worst_exit_code(), 1)

    def test_protocol_order_from_signed_executable_can_pass(self) -> None:
        document = json.dumps(
            _protocol_document(("available", "available", "available"), "winn/3")
        )
        with tempfile.TemporaryDirectory() as name:
            _target, _goos, _goarch, payload = _host_fixture()
            release, target = self._signed_release(Path(name), payload)
            report = verifier.Report()
            with mock.patch.object(
                verifier, "run", side_effect=[self._verify_ok(release, target), (0, document, "")]
            ):
                _quiet(verifier.protocol_order_claims, report, release, target=target)
        self.assertEqual(report.worst_exit_code(), 0, [check.line() for check in report.checks])

    def test_execution_path_is_the_descriptor_on_linux_and_bound_path_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            artifact = Path(name) / "engine"
            artifact.write_bytes(b"fixture")
            with verifier.BoundArtifact(artifact.resolve()) as binding:
                with mock.patch.object(verifier.sys, "platform", "linux"):
                    self.assertEqual(
                        verifier._bound_executable_path(binding), f"/proc/self/fd/{binding.fd}"
                    )
                with mock.patch.object(verifier.sys, "platform", "darwin"):
                    self.assertEqual(verifier._bound_executable_path(binding), str(binding.path))

    def test_protocol_order_from_unsigned_release_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target, _goos, _goarch, payload = _host_fixture()
            release = Path(name) / "release"
            release.mkdir()
            _write_release(release, [target], payloads={target: payload})
            report = verifier.Report()
            with mock.patch.object(verifier, "run") as runner:
                _quiet(verifier.protocol_order_claims, report, release, target=target)
            runner.assert_not_called()
        self.assertEqual(report.worst_exit_code(), 2)


class BuildReceiptTest(unittest.TestCase):
    def _verify(self, receipt: str, target: str, output: Path, **kwargs: object) -> tuple[bool, verifier.Report]:
        report = verifier.Report()
        accepted = _quiet(
            verifier.verify_build_receipt, report, receipt, target=target, output=output, **kwargs
        )
        return accepted, report

    def _output(self, root: Path, target: str = "linux-amd64") -> Path:
        payload, header = _fixture_payload(target)
        output = root / "engine"
        output.write_bytes(payload)
        if header is not None:
            output.with_suffix(".h").write_text(header, encoding="ascii")
        return output

    def test_exact_v4_receipt_binds_target_role_architecture_go_pin_and_bytes(self) -> None:
        for target in ("linux-amd64", "windows-arm64", "android-arm64", "ios-arm64"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as name:
                output = self._output(Path(name), target)
                accepted, report = self._verify(_receipt(output, target=target), target, output)
                self.assertTrue(accepted, [check.line() for check in report.checks])
                self.assertEqual(report.worst_exit_code(), 0)

    def test_removed_gate_fields_are_rejected(self) -> None:
        for field_name in (
            "authorization", "candidate", "source_freeze", "transaction",
            "producer_custody_sha256", "platform_custody", "custody_evidence_sha256",
        ):
            with self.subTest(field=field_name), tempfile.TemporaryDirectory() as name:
                output = self._output(Path(name))
                receipt = _receipt(
                    output, mutate=lambda document: document.__setitem__(field_name, "6" * 64)
                )
                accepted, report = self._verify(receipt, "linux-amd64", output)
                self.assertFalse(accepted)
                self.assertTrue(any("root keys are exact" in check.name for check in report.checks))

    def test_old_contract_and_go_archive_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name))
            accepted, _ = self._verify(
                _receipt(output, mutate=lambda d: d.__setitem__("contract", "winsvpn-winn-core-build-v3")),
                "linux-amd64", output,
            )
            self.assertFalse(accepted)
            accepted, report = self._verify(
                _receipt(output, mutate=lambda d: d["go"].__setitem__("archive_sha256", "1" * 64)),
                "linux-amd64", output,
            )
            self.assertFalse(accepted)
            self.assertTrue(any("nested keys are exact" in check.name for check in report.checks))

    def test_receipt_cannot_relabel_output_or_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            output = self._output(root)
            other = root / "other"
            other.write_bytes(_minimal_elf("amd64"))
            accepted, relabeled = self._verify(_receipt(other), "linux-amd64", output)
            self.assertFalse(accepted)
            self.assertEqual(relabeled.worst_exit_code(), 1)

            def wrong_arch(document: dict[str, object]) -> None:
                document["target"]["goarch"] = "arm64"  # type: ignore[index]

            accepted, report = self._verify(_receipt(output, mutate=wrong_arch), "linux-amd64", output)
            self.assertFalse(accepted)
            self.assertEqual(report.worst_exit_code(), 1)

    def test_artifact_digest_and_on_disk_receipt_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name))
            receipt = _receipt(output)
            Path(str(output) + ".receipt.json").write_text("{}\n", encoding="ascii")
            accepted, report = self._verify(receipt, "linux-amd64", output)
            self.assertFalse(accepted)
            self.assertTrue(any("on-disk receipt matches" in check.name for check in report.checks))

        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name))
            receipt = _receipt(output)
            output.write_bytes(_minimal_elf("amd64") + b"X")
            accepted, report = self._verify(receipt, "linux-amd64", output)
            self.assertFalse(accepted)
            self.assertTrue(any("artifact digest matches" in check.name for check in report.checks))

        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name))
            receipt = _receipt(output, receipt_file=False)
            accepted, report = self._verify(receipt, "linux-amd64", output)
            self.assertFalse(accepted)
            self.assertTrue(any("evidence files are retained" in check.name for check in report.checks))

    def test_duplicate_or_missing_terminal_receipt_fails(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name))
            receipt = _receipt(output)
            for stdout in ("", receipt + "\n" + receipt):
                accepted, report = self._verify(stdout, "linux-amd64", output)
                self.assertFalse(accepted)
                self.assertTrue(any("is unique" in check.name for check in report.checks))

    def test_go_pin_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name))
            for field_name in ("version", "executable_sha256"):
                with self.subTest(field=field_name):
                    value = "1.0.0" if field_name == "version" else "0" * 64
                    receipt = _receipt(
                        output, mutate=lambda d: d["go"].__setitem__(field_name, value)
                    )
                    accepted, report = self._verify(receipt, "linux-amd64", output)
                    self.assertFalse(accepted)
                    self.assertTrue(any("matches the reviewed pin" in check.name for check in report.checks))

    def test_platform_toolchain_identity_is_exact(self) -> None:
        cases = (
            ("linux-amd64", lambda p: p.__setitem__("compiler_path", "/usr/bin/cc")),
            ("android-arm64", lambda p: p.__setitem__("ndk_version", "29.0.1")),
            ("android-arm64", lambda p: p.__setitem__("sdk_version", "26.0")),
            ("android-arm64", lambda p: p.__setitem__("compiler_sha256", None)),
            ("ios-arm64", lambda p: p.__setitem__("sdk_version", None)),
            ("ios-arm64", lambda p: p.__setitem__("id", "ios-simulator")),
        )
        for target, change in cases:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as name:
                output = self._output(Path(name), target)
                receipt = _receipt(output, target=target, mutate=lambda d: change(d["platform"]))
                accepted, report = self._verify(receipt, target, output)
                self.assertFalse(accepted)
                self.assertEqual(report.worst_exit_code(), 1)

    def test_missing_ndk_pin_is_unverified_not_pass(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name), "android-arm64")
            receipt = _receipt(output, target="android-arm64")
            with mock.patch.object(verifier, "_android_ndk_pin", return_value=None):
                accepted, report = self._verify(receipt, "android-arm64", output)
            self.assertFalse(accepted)
            self.assertEqual(report.worst_exit_code(), 2)

    def test_environment_cannot_supply_sealed_identities_but_callers_can(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name))
            receipt = _receipt(output)
            with mock.patch.dict(
                verifier.os.environ,
                {"WINS_WINN_SOURCE_TREE_SHA256": "9" * 64, "WINS_STORE_GOMODCACHE_TREE_SHA256": "9" * 64},
            ):
                accepted, _ = self._verify(receipt, "linux-amd64", output)
            self.assertTrue(accepted)
            accepted, report = self._verify(
                receipt, "linux-amd64", output, expected_source_tree_sha256="9" * 64
            )
            self.assertFalse(accepted)
            self.assertTrue(any("caller-sealed input" in check.name for check in report.checks))
            accepted, _ = self._verify(
                receipt, "linux-amd64", output,
                expected_source_tree_sha256="5" * 64,
                expected_module_cache_tree_sha256="4" * 64,
            )
            self.assertTrue(accepted)

    def test_archive_header_must_match_and_executables_cannot_claim_one(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name), "ios-arm64")
            receipt = _receipt(output, target="ios-arm64")
            output.with_suffix(".h").write_text(
                VALID_CLIENTINFO_HEADER.replace("WinnTunnelBackendJSON", "WrongRole"),
                encoding="ascii",
            )
            accepted, report = self._verify(receipt, "ios-arm64", output)
            self.assertFalse(accepted)
            self.assertEqual(report.worst_exit_code(), 1)
        with tempfile.TemporaryDirectory() as name:
            output = self._output(Path(name))
            receipt = _receipt(
                output, mutate=lambda d: d["artifact"].__setitem__("header_sha256", "1" * 64)
            )
            accepted, report = self._verify(receipt, "linux-amd64", output)
            self.assertFalse(accepted)
            self.assertTrue(any("cannot relabel an archive header" in check.name for check in report.checks))

    def test_receipt_rejects_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            output = self._output(root)
            receipt = _receipt(output)
            actual = root / "actual"
            output.rename(actual)
            output.symlink_to(actual)
            accepted, report = self._verify(receipt, "linux-amd64", output)
            self.assertFalse(accepted)
            self.assertEqual(report.worst_exit_code(), 1)

    def test_malformed_or_symlinked_toolchain_pins_never_escape_report(self) -> None:
        malformed_documents = ({"tools": []}, {"tools": {"go": []}})
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            root = Path(name)
            output = self._output(root)
            receipt = _receipt(output)
            for index, document in enumerate(malformed_documents):
                with self.subTest(document=document):
                    pins = root / f"pins-{index}.json"
                    pins.write_text(json.dumps(document), encoding="utf-8")
                    with mock.patch.object(verifier, "TOOLCHAIN_PINS", pins):
                        accepted, report = self._verify(receipt, "linux-amd64", output)
                    self.assertFalse(accepted)
                    self.assertEqual(report.worst_exit_code(), 2)

            actual = root / "pins-real.json"
            actual.write_bytes(verifier.TOOLCHAIN_PINS.read_bytes())
            linked = root / "pins-link.json"
            linked.symlink_to(actual)
            with mock.patch.object(verifier, "TOOLCHAIN_PINS", linked):
                accepted, report = self._verify(receipt, "linux-amd64", output)
            self.assertFalse(accepted)
            self.assertEqual(report.worst_exit_code(), 2)


class BuildMatrixSelectionTest(unittest.TestCase):
    def test_builder_receipt_and_matrix_target_sets_are_identical(self) -> None:
        source = verifier.BUILD_SCRIPT.read_text(encoding="utf-8")
        target_case = source.rsplit('case "${TARGET}" in', 1)[1].split("esac", 1)[0]
        builder_targets = set(
            verifier.re.findall(r"^  ([a-z0-9][a-z0-9-]*)\)", target_case, verifier.re.MULTILINE)
        )
        matrix_targets = {target for target, _, _, _ in verifier.TARGETS}
        self.assertEqual(len(builder_targets), 32)
        self.assertEqual(matrix_targets, builder_targets)
        self.assertTrue(all(verifier.expected_build_identity(target) for target in matrix_targets))
        self.assertTrue(all(verifier.release_artifact_filename(target) for target in matrix_targets))

    def test_release_filenames_follow_the_driver_layout(self) -> None:
        expected = {
            "datapath-android-arm64": "libwinnengine.so",
            "datapath-windows-amd64": "winn-datapath.exe",
            "datapath-linux-arm64": "winn-datapath",
            "datapath-darwin-amd64": "winn-datapath",
            "datapath-ios-arm64": "libwinn-datapath.a",
            "datapath-archive-darwin-arm64": "libwinn-datapath.a",
            "winn3-gateway-linux-amd64": "winn3-gateway",
            "server-linux-arm64": "winn-server",
            "carrier-linux-amd64": "winn-carrier-server",
            "windows-arm64": "winn-clientinfo.exe",
            "android-arm": "winn-clientinfo",
            "ios-arm64": "libwinn-clientinfo.a",
        }
        for target, filename in expected.items():
            with self.subTest(target=target):
                self.assertEqual(verifier.release_artifact_filename(target), filename)

    def test_unknown_duplicate_and_noncanonical_targets_fail_before_output(self) -> None:
        for targets in (
            ["not-a-target"],
            ["linux-amd64", "linux-amd64"],
            [" linux-amd64"],
            [],
        ):
            with self.subTest(targets=targets), tempfile.TemporaryDirectory() as name:
                out_dir = Path(name) / "not-created"
                report = verifier.Report()
                with mock.patch.object(verifier, "run") as runner:
                    produced = _quiet(verifier.build_matrix, report, out_dir, targets, _options())
                runner.assert_not_called()
                self.assertEqual(produced, {})
                self.assertEqual(report.worst_exit_code(), 1)
                self.assertFalse(out_dir.exists())

    def test_driver_inputs_are_validated_before_output(self) -> None:
        for options in (
            verifier.DriverOptions(),
            _options(source_commit="HEAD"),
            _options(source_commit="260DA56"),
            _options(go_archive="relative/go.tar.gz"),
            _options(jobs=0),
            _options(module_proxy="file:///a b"),
        ):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as name:
                out_dir = Path(name) / "not-created"
                report = verifier.Report()
                with mock.patch.object(verifier, "run") as runner:
                    produced = _quiet(verifier.build_matrix, report, out_dir, ["linux-amd64"], options)
                runner.assert_not_called()
                self.assertEqual(produced, {})
                self.assertEqual(report.worst_exit_code(), 1)
                self.assertFalse(out_dir.exists())

    def test_driver_command_is_exact_and_passes_every_flag(self) -> None:
        driver = FakeDriver(["linux-amd64", "windows-amd64"])
        options = _options(
            go_archive="/opt/go.tar.gz", developer_dir="/Applications/Xcode.app/Contents/Developer",
            module_proxy="file:///cache", jobs=3,
        )
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / "out"
            report = verifier.Report()
            with mock.patch.object(verifier, "run", side_effect=driver):
                produced = _quiet(
                    verifier.build_matrix, report, out, ["linux-amd64", "windows-amd64"], options
                )
            release = Path(verifier.os.path.realpath(out)) / "release"
            self.assertEqual(
                driver.commands,
                [[
                    verifier.RELEASE_DRIVER_PYTHON, "-I", str(verifier.RELEASE_DRIVER), "build",
                    "--out", str(release), "--targets", "linux-amd64,windows-amd64",
                    "--source-commit", SOURCE_COMMIT,
                    "--source-export", "/private/tmp/winn-export",
                    "--go-archive", "/opt/go.tar.gz",
                    "--ndk", "/opt/ndk",
                    "--developer-dir", "/Applications/Xcode.app/Contents/Developer",
                    "--module-proxy", "file:///cache",
                    "--jobs", "3",
                ]],
            )
            self.assertEqual(driver.kwargs["cwd"], verifier.ROOT)
            self.assertGreater(driver.kwargs["output_limit"], verifier.MAX_SUBPROCESS_OUTPUT_BYTES)
            self.assertEqual(sorted(produced), ["linux-amd64", "windows-amd64"])
            self.assertEqual(report.worst_exit_code(), 0, [check.line() for check in report.checks])
            self.assertEqual(produced["linux-amd64"].release_dir, release)

    def test_existing_release_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / "out"
            (out / "release").mkdir(parents=True)
            report = verifier.Report()
            with mock.patch.object(verifier, "run") as runner:
                produced = _quiet(verifier.build_matrix, report, out, ["linux-amd64"], _options())
            runner.assert_not_called()
            self.assertEqual(produced, {})
            self.assertEqual(report.worst_exit_code(), 1)

    def test_toolchain_missing_exit_is_unverified_and_every_other_failure_fails(self) -> None:
        cases = (
            (3, "TOOLCHAIN-MISSING: Android NDK 30.0.16248370 not found at /x\n", 2),
            (3, "WINN RELEASE REFUSED: something else\n", 1),
            (1, "TOOLCHAIN-MISSING: printed with the wrong exit code\n", 1),
            (1, "WINN RELEASE REFUSED: build[linux-amd64] is not reproducible\n", 1),
            (2, "usage: winn_release.py\n", 1),
        )
        for rc, stderr, exit_code in cases:
            with self.subTest(rc=rc, stderr=stderr), tempfile.TemporaryDirectory() as name:
                driver = FakeDriver(["linux-amd64", "datapath-android-arm64"], rc=rc, stderr=stderr)
                report = verifier.Report()
                with mock.patch.object(verifier, "run", side_effect=driver):
                    produced = _quiet(
                        verifier.build_matrix, report, Path(name) / "out",
                        ["linux-amd64", "datapath-android-arm64"], _options(),
                    )
                self.assertEqual(produced, {})
                self.assertEqual(report.worst_exit_code(), exit_code)
                decided = {
                    check.name.split("]")[0] + "]"
                    for check in report.checks
                    if check.name.startswith("build[")
                }
                self.assertEqual(decided, {"build[linux-amd64]", "build[datapath-android-arm64]"})

    def test_two_builds_must_be_byte_identical(self) -> None:
        def diverge(entry: dict[str, object]) -> None:
            entry["build_b_sha256"] = "0" * 64

        report = self._run(["linux-amd64"], mutate_entry=diverge)
        self.assertEqual(report[1], 1)
        self.assertTrue(any("byte-identical" in check.name for check in report[0].checks))

    def test_on_disk_bytes_must_match_the_manifest(self) -> None:
        def resize(entry: dict[str, object]) -> None:
            entry["size"] = int(entry["size"]) + 1  # type: ignore[arg-type]

        report = self._run(["linux-amd64"], mutate_entry=resize)
        self.assertEqual(report[1], 1)
        self.assertTrue(any("on-disk bytes match" in check.name for check in report[0].checks))

    def test_structural_identity_is_checked_on_release_bytes(self) -> None:
        payload = _minimal_elf("amd64").replace(
            b"winsvpn.local/winnprotocol/cmd/winn-clientinfo",
            b"winsvpn.local/winnprotocol/cmd/winn-datapathXX",
        )
        report = self._run(["linux-amd64"], payloads={"linux-amd64": payload})
        self.assertEqual(report[1], 1)
        self.assertTrue(any("structurally exact" in check.name for check in report[0].checks))

    def test_manifest_identity_fields_must_match_the_target(self) -> None:
        mutations = (
            lambda entry: entry.__setitem__("role", "datapath"),
            lambda entry: entry.__setitem__("goarch", "arm64"),
            lambda entry: entry.__setitem__("cgo_enabled", True),
            lambda entry: entry.__setitem__("path", "artifacts/linux-amd64/other"),
            lambda entry: entry.__setitem__("header_path", "artifacts/linux-amd64/x.h"),
            lambda entry: entry.__setitem__("extra", 1),
            lambda entry: entry["platform"].__setitem__("compiler_path", "/usr/bin/cc"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report, exit_code = self._run(["linux-amd64"], mutate_entry=mutate)
                self.assertEqual(exit_code, 1)
                self.assertFalse(any(
                    check.status == verifier.PASS and check.name.startswith("build[linux-amd64]")
                    for check in report.checks
                ))

    def test_manifest_source_toolchain_and_producer_must_be_exact(self) -> None:
        mutations = (
            lambda m: m["source"].__setitem__("commit", "0" * 40),
            lambda m: m["source"].__setitem__("binding", "git-archive"),
            lambda m: m["toolchains"]["go"].__setitem__("executable_sha256", "0" * 64),
            lambda m: m["toolchains"].__setitem__("gomodcache_tree_sha256", "short"),
            lambda m: m["producer"].__setitem__("winn_release.py", "0" * 64),
            lambda m: m.__setitem__("contract", "winsvpn-winn-release-manifest-v0"),
            lambda m: m.__setitem__("requested_targets", ["linux-amd64", "linux-arm64"]),
            lambda m: m.__setitem__("artifacts", []),
            lambda m: m["artifacts"].append(dict(m["artifacts"][0])),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report, exit_code = self._run(["linux-amd64"], mutate_manifest=mutate)
                self.assertEqual(exit_code, 1)

    def test_android_and_apple_toolchains_must_equal_the_pins(self) -> None:
        report, exit_code = self._run(["datapath-android-arm64"])
        self.assertEqual(exit_code, 0, [check.line() for check in report.checks])
        for mutate in (
            lambda m: m["toolchains"]["android_ndk"].__setitem__("version", "29.0.1"),
            lambda m: m["toolchains"]["android_ndk"].__setitem__("tree_sha256", "0" * 64),
            lambda m: m["toolchains"].__setitem__("android_ndk", None),
        ):
            with self.subTest(mutate=mutate):
                _, exit_code = self._run(["datapath-android-arm64"], mutate_manifest=mutate)
                self.assertEqual(exit_code, 1)
        report, exit_code = self._run(["ios-arm64"])
        self.assertEqual(exit_code, 0, [check.line() for check in report.checks])
        _, exit_code = self._run(
            ["ios-arm64"],
            mutate_manifest=lambda m: m["toolchains"]["apple"].__setitem__("xcode_build", "1A1"),
        )
        self.assertEqual(exit_code, 1)

    def test_archive_header_must_match_the_manifest(self) -> None:
        def wrong_header(entry: dict[str, object]) -> None:
            entry["header_sha256"] = "0" * 64

        report, exit_code = self._run(["ios-arm64"], mutate_entry=wrong_header)
        self.assertEqual(exit_code, 1)
        self.assertTrue(any("generated header bytes" in check.name for check in report.checks))

    def test_skipped_targets_are_unverified_never_pass(self) -> None:
        def skip(manifest: dict[str, object]) -> None:
            manifest["skipped_targets"] = {"datapath-android-arm64": "TOOLCHAIN-MISSING: NDK"}
            manifest["artifacts"] = [
                entry for entry in manifest["artifacts"]  # type: ignore[union-attr]
                if entry["target"] != "datapath-android-arm64"
            ]

        report, exit_code = self._run(["linux-amd64", "datapath-android-arm64"], mutate_manifest=skip)
        self.assertEqual(exit_code, 2)
        self.assertTrue(any(
            check.status == verifier.UNVERIFIED and check.name.startswith("build[datapath-android-arm64]")
            for check in report.checks
        ))

    def test_arm64_bytes_are_not_reused_across_targets(self) -> None:
        shared = _minimal_elf("arm64")
        with mock.patch.object(verifier, "_structured_artifact_identity", return_value=("elf", "arm64")):
            report, exit_code = self._run(
                ["linux-arm64", "datapath-linux-arm64"],
                payloads={"linux-arm64": shared, "datapath-linux-arm64": shared},
            )
        self.assertEqual(exit_code, 1)
        self.assertTrue(any("ARM64 bytes are not reused" in check.name for check in report.checks))

    def test_zero_exit_without_manifest_is_failure(self) -> None:
        def no_manifest(cmd: list[str], **_kwargs: object) -> tuple[int, str, str]:
            Path(cmd[cmd.index("--out") + 1]).mkdir()
            return 0, "", ""

        with tempfile.TemporaryDirectory() as name:
            report = verifier.Report()
            with mock.patch.object(verifier, "run", side_effect=no_manifest):
                produced = _quiet(
                    verifier.build_matrix, report, Path(name) / "out", ["linux-amd64"], _options()
                )
        self.assertEqual(produced, {})
        self.assertEqual(report.worst_exit_code(), 1)

    def test_fresh_run_directory_keeps_default_output_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / "out"
            for _ in range(2):
                driver = FakeDriver(["linux-amd64"])
                report = verifier.Report()
                with mock.patch.object(verifier, "run", side_effect=driver):
                    produced = _quiet(
                        verifier.build_matrix, report, out, ["linux-amd64"], _options(),
                        fresh_run_directory=True,
                    )
                self.assertEqual(sorted(produced), ["linux-amd64"])

    def test_missing_toolchain_classifier_is_narrow(self) -> None:
        self.assertTrue(
            verifier._looks_like_missing_toolchain(
                "Go 1.27.1 ok\nTOOLCHAIN-MISSING: Android NDK 30.0.16248370 not found at /x\n"
            )
        )
        self.assertFalse(verifier._looks_like_missing_toolchain("OWNER-BLOCKED: authority"))
        self.assertFalse(verifier._looks_like_missing_toolchain("Android NDK not found"))
        self.assertFalse(verifier._looks_like_missing_toolchain("compile failed: No such package"))

    def test_native_cli_cannot_skip_an_unsigned_or_unreachable_release(self) -> None:
        args = mock.Mock(release="/unreachable/release", target="darwin-arm64", trust_public_key=None)
        with mock.patch.object(verifier, "run") as runner:
            report = _quiet(verifier.cmd_native_runtime_claims, args)
        runner.assert_not_called()
        self.assertEqual(report.worst_exit_code(), 2)

    def _run(
        self, targets: list[str], **writer: object
    ) -> tuple[verifier.Report, int]:
        driver = FakeDriver(targets, **writer)
        with tempfile.TemporaryDirectory() as name:
            report = verifier.Report()
            with mock.patch.object(verifier, "run", side_effect=driver):
                _quiet(verifier.build_matrix, report, Path(name) / "out", targets, _options())
        return report, report.worst_exit_code()


class BoundedDriverOutputTest(unittest.TestCase):
    def test_output_limit_can_be_raised_per_call(self) -> None:
        rc, out, _err = verifier.run(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 70000)"],
            timeout=10,
            output_limit=1024 * 1024,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(out), 70000)


@unittest.skipUnless(os.name == "posix", "descriptor ancestry regressions are POSIX-specific")
class DescriptorCustodyTest(unittest.TestCase):
    def test_higher_ancestor_swap_and_restore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            ancestor = root / "higher"
            cache = ancestor / "cache"
            cache.mkdir(parents=True)
            artifact = cache / "module.zip"
            artifact.write_bytes(b"module")
            binding = verifier.BoundArtifact(artifact.resolve())
            displaced = root / "displaced"
            ancestor.rename(displaced)
            displaced.rename(ancestor)
            with self.assertRaises(OSError):
                binding.verify()
            binding.close()

    def test_artifact_swap_and_restore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            artifact = root / "engine"
            replacement = root / "replacement"
            original = root / "original"
            artifact.write_bytes(_minimal_elf("amd64"))
            replacement.write_bytes(_minimal_elf("arm64"))
            binding = verifier.BoundArtifact(artifact.resolve())
            artifact.rename(original)
            replacement.rename(artifact)
            artifact.rename(replacement)
            original.rename(artifact)
            with self.assertRaises(OSError):
                binding.verify()
            binding.close()


if __name__ == "__main__":
    unittest.main()
