#!/usr/bin/env python3
"""Hostile tests for bounded producer-authenticated Winn v3 PE identity."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import tracemalloc
import unittest


TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import winn3_pe_identity as peid  # noqa: E402


PACKAGE = "github.com/winsvpn/winn/cmd/winn-datapath"
MODULE = "github.com/winsvpn/winn"
MODULE_IDENTITY = MODULE + "\t(devel)"
VERSION = "go1.27.1"


def uvarint(value: int) -> bytes:
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def buildinfo(
    *,
    version: str = VERSION,
    package: str = PACKAGE,
    module: str = MODULE,
    module_identity: str = MODULE_IDENTITY,
) -> bytes:
    module_text = f"path\t{package}\nmod\t{module_identity}\n".encode("utf-8")
    framed = peid.BUILDINFO_START + module_text + peid.BUILDINFO_END
    header = peid.BUILDINFO_MAGIC + bytes((8, 2)) + bytes(16)
    return (
        header
        + uvarint(len(version.encode("ascii")))
        + version.encode("ascii")
        + uvarint(len(framed))
        + framed
    )


def pe(
    machine: int,
    *,
    include_buildinfo: bool = True,
    second_buildinfo: bool = False,
    marker: bool = False,
) -> bytes:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", data, 0x84, machine, 2, 0, 0, 0, 240, 0x0022
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    struct.pack_into("<I", data, optional + 108, 0)

    text = optional + 240
    data[text : text + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, text + 8, 0x180, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, text + 36, 0x60000020)

    writable = text + 40
    data[writable : writable + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, writable + 8, 0x180, 0x2000, 0x200, 0x400)
    struct.pack_into("<I", data, writable + 36, 0xC0000040)
    if include_buildinfo:
        blob = buildinfo()
        data[0x400 : 0x400 + len(blob)] = blob
    if second_buildinfo:
        blob = buildinfo(package="github.com/winsvpn/winn/cmd/duplicate")
        data[0x4B0 : 0x4B0 + len(blob)] = blob
    if marker:
        data[0x250 : 0x250 + len(b"winsvpn.local/winnprotocol/winn3")] = (
            b"winsvpn.local/winnprotocol/winn3"
        )
    return bytes(data)


class PeIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def write(self, role: str, payload: bytes) -> Path:
        path = self.root / peid.ROLE_FILENAMES[role]
        path.write_bytes(payload)
        return path

    def expected(
        self,
        role: str,
        payload: bytes,
        *,
        architecture: str = "x64",
        digest: str | None = None,
        size: int | None = None,
        version: str = VERSION,
        package: str = PACKAGE,
        module: str = MODULE,
        module_identity: str = MODULE_IDENTITY,
    ) -> peid.AuthenticatedArtifact:
        return peid.AuthenticatedArtifact(
            contract=peid.CONTRACT,
            role=role,
            architecture=architecture,
            filename=peid.ROLE_FILENAMES[role],
            sha256=digest or hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload) if size is None else size,
            go_version=version,
            go_package_path=package,
            go_module_path=module,
            go_module_identity=module_identity,
        )

    def verify(
        self, path: Path, expected: peid.AuthenticatedArtifact
    ) -> peid.PeIdentity:
        with peid.verify_authenticated_pe(path, expected) as verified:
            return verified.identity

    def test_exact_x64_and_arm64_authenticated_outputs_pass(self) -> None:
        for architecture in ("x64", "arm64"):
            with self.subTest(architecture=architecture):
                payload = pe(peid.ARCH_MACHINES[architecture])
                path = self.write("core", payload)
                identity = self.verify(
                    path, self.expected("core", payload, architecture=architecture)
                )
                self.assertEqual(identity.architecture, architecture)
                self.assertEqual(identity.go_module_path, MODULE)
                self.assertEqual(identity.sha256, hashlib.sha256(payload).hexdigest())

    def test_role_is_from_authenticated_digest_not_marker_strings(self) -> None:
        core_payload = pe(peid.ARCH_MACHINES["x64"], marker=False)
        core = self.write("core", core_payload)
        self.assertEqual(
            self.verify(core, self.expected("core", core_payload)).role,
            "core",
        )

        relay_payload = pe(peid.ARCH_MACHINES["x64"], marker=True)
        relay = self.write("relay", relay_payload)
        self.assertEqual(
            self.verify(
                relay, self.expected("relay", relay_payload)
            ).role,
            "relay",
        )

    def test_digest_size_filename_and_machine_mismatches_are_refused(self) -> None:
        payload = pe(peid.ARCH_MACHINES["x64"])
        path = self.write("core", payload)
        with self.assertRaisesRegex(peid.PeIdentityError, "artifact-digest-mismatch"):
            self.verify(
                path, self.expected("core", payload, digest="0" * 64)
            )
        with self.assertRaisesRegex(peid.PeIdentityError, "artifact-size-mismatch"):
            self.verify(
                path, self.expected("core", payload, size=len(payload) - 1)
            )
        with self.assertRaisesRegex(peid.PeIdentityError, "pe-machine-mismatch"):
            self.verify(
                path, self.expected("core", payload, architecture="arm64")
            )
        wrong_name = self.root / "renamed.exe"
        wrong_name.write_bytes(payload)
        with self.assertRaisesRegex(peid.PeIdentityError, "role-filename-mismatch"):
            self.verify(wrong_name, self.expected("core", payload))

    def test_geometry_only_synthetic_pe_without_go_buildinfo_is_refused(self) -> None:
        payload = pe(peid.ARCH_MACHINES["x64"], include_buildinfo=False)
        path = self.write("core", payload)
        with self.assertRaisesRegex(peid.PeIdentityError, "go-buildinfo-not-unique"):
            self.verify(path, self.expected("core", payload))

    def test_duplicate_buildinfo_is_refused(self) -> None:
        payload = pe(peid.ARCH_MACHINES["x64"], second_buildinfo=True)
        path = self.write("core", payload)
        with self.assertRaisesRegex(peid.PeIdentityError, "go-buildinfo-not-unique"):
            self.verify(path, self.expected("core", payload))

    def test_overlapping_sections_and_invalid_entrypoint_are_refused(self) -> None:
        original = pe(peid.ARCH_MACHINES["x64"])
        optional = 0x98
        data_section = optional + 240 + 40
        cases = {
            "raw overlap": (data_section + 20, struct.pack("<I", 0x200), "raw-sections-overlap"),
            "bad entry": (optional + 16, struct.pack("<I", 0x5000), "entrypoint-invalid"),
        }
        for name, (offset, replacement, refusal) in cases.items():
            with self.subTest(name=name):
                changed = bytearray(original)
                changed[offset : offset + len(replacement)] = replacement
                payload = bytes(changed)
                path = self.write("core", payload)
                with self.assertRaisesRegex(peid.PeIdentityError, refusal):
                    self.verify(path, self.expected("core", payload))

    def test_malformed_pe32plus_geometry_is_refused(self) -> None:
        original = pe(peid.ARCH_MACHINES["x64"])
        optional = 0x98
        data_section = optional + 240 + 40
        cases = {
            "misaligned image base": (
                optional + 24,
                struct.pack("<Q", 1),
                "image-geometry-invalid",
            ),
            "subpage alignment mismatch": (
                optional + 32,
                struct.pack("<II", 0x800, 0x200),
                "alignment-invalid",
            ),
            "nonadjacent section rva": (
                data_section + 12,
                struct.pack("<I", 0x3000),
                "section-mapping-invalid",
            ),
            "descending section rva": (
                data_section + 12,
                struct.pack("<I", 0x1000),
                "section-mapping-invalid",
            ),
            "oversized image": (
                optional + 56,
                struct.pack("<I", peid.MAX_IMAGE_BYTES + 0x1000),
                "image-geometry-invalid",
            ),
            "image does not end after final section": (
                optional + 56,
                struct.pack("<I", 0x4000),
                "image-geometry-invalid",
            ),
        }
        for name, (offset, replacement, refusal) in cases.items():
            with self.subTest(name=name):
                changed = bytearray(original)
                changed[offset : offset + len(replacement)] = replacement
                payload = bytes(changed)
                path = self.write("core", payload)
                with self.assertRaisesRegex(peid.PeIdentityError, refusal):
                    self.verify(path, self.expected("core", payload))

    def test_hostile_path_replacement_cannot_change_consumed_bytes(self) -> None:
        payload = pe(peid.ARCH_MACHINES["x64"])
        path = self.write("core", payload)
        replacement = pe(peid.ARCH_MACHINES["x64"], marker=True)
        staged = self.root / "hostile-replacement.exe"
        staged.write_bytes(replacement)
        with self.assertRaisesRegex(peid.PeIdentityError, "custody-changed"):
            with peid.verify_authenticated_pe(
                path, self.expected("core", payload)
            ) as verified:
                os.replace(staged, path)
                self.assertEqual(verified.read_at(0, len(payload)), payload)
                self.assertEqual(
                    verified.identity.sha256, hashlib.sha256(payload).hexdigest()
                )

    def test_invalid_data_directory_is_refused(self) -> None:
        changed = bytearray(pe(peid.ARCH_MACHINES["x64"]))
        optional = 0x98
        struct.pack_into("<I", changed, optional + 108, 1)
        struct.pack_into("<II", changed, optional + 112, 0x9000, 0x40)
        payload = bytes(changed)
        path = self.write("core", payload)
        with self.assertRaisesRegex(peid.PeIdentityError, "data-directory-invalid"):
            self.verify(path, self.expected("core", payload))

    def test_go_version_package_and_module_mismatches_are_refused(self) -> None:
        payload = pe(peid.ARCH_MACHINES["x64"])
        path = self.write("core", payload)
        cases = (
            ({"version": "go1.26.0"}, "go-version-mismatch"),
            ({"package": "github.com/winsvpn/winn/cmd/other"}, "go-package-mismatch"),
            ({"module": "github.com/winsvpn/other"}, "go-module-mismatch"),
            ({"module_identity": MODULE + "\tv1.0.0"}, "go-module-mismatch"),
        )
        for changes, refusal in cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(peid.PeIdentityError, refusal):
                    self.verify(
                        path, self.expected("core", payload, **changes)
                    )

    def test_authenticated_record_requires_exact_fields(self) -> None:
        payload = pe(peid.ARCH_MACHINES["x64"])
        record = self.expected("core", payload).__dict__.copy()
        self.assertEqual(
            peid.AuthenticatedArtifact.from_record(record).sha256,
            hashlib.sha256(payload).hexdigest(),
        )
        record["extra"] = True
        with self.assertRaisesRegex(peid.PeIdentityError, "fields-not-exact"):
            peid.AuthenticatedArtifact.from_record(record)

    def test_streaming_peak_is_bounded_for_large_authenticated_output(self) -> None:
        payload = pe(peid.ARCH_MACHINES["x64"]) + bytes(8 * 1024 * 1024)
        path = self.write("core", payload)
        expected = self.expected("core", payload)
        tracemalloc.start()
        try:
            identity = self.verify(path, expected)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(identity.size_bytes, len(payload))
        self.assertLess(peak, 4 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
