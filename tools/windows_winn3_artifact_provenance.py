#!/usr/bin/env python3
"""Check the compiled role of a staged Windows Winn v3 executable.

Release provenance for winn-datapath.exe is the signed Winn release manifest
(tools/winn_release.py verify). This tool adds the Windows-specific checks
that a manifest digest cannot express: the bytes are a well-formed PE32+
executable for the requested architecture, and the Go build information
compiled into them names the expected main package and module. That second
check is what keeps the relay (winsvpn_winn3_engine.exe, raw inner packets, no
cryptography) and the datapath (winn-datapath.exe, the winn/3 cryptography)
from being staged under each other's names, which would put cleartext on the
wire.

Usage:
  windows_winn3_artifact_provenance.py check-role --role {core,relay}
      --architecture {x64,arm64} [--expect-sha256 HEX] [--signed-entry JSON] PATH

Website builds garble these engines (owner ruling 2026-10-27), which leaves
the build-info header with version "unknown" and no module record. For such
bytes the role comes only from --signed-entry: the caller's copy of the
verified, signed Winn release manifest row for these exact bytes plus that
manifest's obfuscation record. A plain build never takes that path, and a
garbled build without a signed entry is refused.

Exit 0 and one line "PASS: ..." only when every check holds; exit 1 with a
"FAIL: ..." line on stderr otherwise; exit 2 on usage errors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
from typing import Any


MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
ARCH_MACHINES = {"x64": 0x8664, "arm64": 0xAA64}
MACHINE_NAMES = {value: key for key, value in ARCH_MACHINES.items()}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACT_SPECS = {
    "core": ("winn-datapath.exe", "winn3-core"),
    "relay": ("winsvpn_winn3_engine.exe", "winn3-relay"),
}
GO_ROLE_IDENTITIES = {
    "core": (
        "winsvpn.local/winnprotocol/cmd/winn-datapath",
        "winsvpn.local/winnprotocol",
    ),
    "relay": (
        "winsvpn.local/winsvpnwinn3engine",
        "winsvpn.local/winsvpnwinn3engine",
    ),
}


# The signed manifest row that names each role's garbled bytes.
OBFUSCATED_ROLE_TARGETS = {
    "core": ("datapath-windows-{goarch}", "./cmd/winn-datapath", "datapath"),
    "relay": ("winn3-relay-windows-{goarch}", ".", "winn3-relay"),
}
ARCH_GOARCH = {"x64": "amd64", "arm64": "arm64"}
GARBLE_TOOL = "mvdan.cc/garble"


class ProvenanceError(RuntimeError):
    """The supplied bytes do not prove the expected compiled role."""


def _read_regular_file(path: Path, maximum: int, label: str) -> bytes:
    """Read one regular, non-symlink, single-link file that does not change."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ProvenanceError(f"{label} is unavailable: {exc}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ProvenanceError(f"{label} must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > maximum:
        raise ProvenanceError(f"{label} size is outside the accepted bounds")
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProvenanceError(f"{label} could not be opened: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise ProvenanceError(f"{label} changed before it was opened")
        if opened.st_nlink != 1:
            raise ProvenanceError(f"{label} must have exactly one link")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(fd, min(1 << 20, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        if len(data) != before.st_size or after.st_size != before.st_size:
            raise ProvenanceError(f"{label} changed while it was read")
        return data
    finally:
        os.close(fd)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_pe_machine(data: bytes, label: str) -> int:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ProvenanceError(f"{label} is not a DOS/PE image")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset < 0x40 or offset > len(data) - 24 or data[offset : offset + 4] != b"PE\0\0":
        raise ProvenanceError(f"{label} has an invalid PE header")
    machine, sections = struct.unpack_from("<HH", data, offset + 4)
    if machine not in MACHINE_NAMES:
        raise ProvenanceError(f"{label} has unsupported PE machine 0x{machine:04x}")
    if sections < 1 or sections > 96:
        raise ProvenanceError(f"{label} has an invalid PE section count")
    optional_size, characteristics = struct.unpack_from("<HH", data, offset + 20)
    if characteristics & 0x0002 == 0 or characteristics & 0x2000:
        raise ProvenanceError(f"{label} is not an executable PE image")
    if optional_size < 112 or optional_size > 4096:
        raise ProvenanceError(f"{label} has an invalid PE32+ optional-header size")
    optional = offset + 24
    section_table = optional + optional_size
    if section_table > len(data) or sections * 40 > len(data) - section_table:
        raise ProvenanceError(f"{label} has a truncated PE section table")
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ProvenanceError(f"{label} is not a PE32+ image")
    entrypoint = struct.unpack_from("<I", data, optional + 16)[0]
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    section_alignment, file_alignment = struct.unpack_from("<II", data, optional + 32)
    win32_version_value = struct.unpack_from("<I", data, optional + 52)[0]
    size_image, size_headers = struct.unpack_from("<II", data, optional + 56)
    loader_flags = struct.unpack_from("<I", data, optional + 104)[0]
    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    if (
        entrypoint == 0
        or image_base % 0x10000
        or win32_version_value != 0
        or loader_flags != 0
        or file_alignment < 512
        or file_alignment > 65536
        or section_alignment < file_alignment
        or file_alignment & (file_alignment - 1)
        or section_alignment & (section_alignment - 1)
        or size_image < section_alignment
        or size_image % section_alignment
        or size_headers < section_table + sections * 40
        or size_headers > len(data)
        or size_headers % file_alignment
        or directory_count > 16
        or 112 + directory_count * 8 > optional_size
    ):
        raise ProvenanceError(f"{label} has invalid PE32+ image geometry")
    entry_in_executable_section = False
    expected_virtual_address = (
        (size_headers + section_alignment - 1) // section_alignment
    ) * section_alignment
    raw_ranges: list[tuple[int, int]] = []
    final_image_end = 0
    for index in range(sections):
        section = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, section + 8
        )
        section_characteristics = struct.unpack_from("<I", data, section + 36)[0]
        if (
            virtual_address % section_alignment
            or raw_size % file_alignment
            or (raw_size and raw_pointer % file_alignment)
            or (not raw_size and raw_pointer)
        ):
            raise ProvenanceError(f"{label} has an unaligned PE section")
        if virtual_address < size_headers:
            raise ProvenanceError(f"{label} PE section overlaps mapped PE headers")
        if virtual_address != expected_virtual_address:
            raise ProvenanceError(f"{label} PE sections are not adjacent and ordered")
        if raw_size and (raw_pointer < size_headers or raw_pointer > len(data) - raw_size):
            raise ProvenanceError(f"{label} has a section outside the PE file")
        if raw_size:
            raw_range = (raw_pointer, raw_pointer + raw_size)
            if any(raw_range[0] < end and start < raw_range[1] for start, end in raw_ranges):
                raise ProvenanceError(f"{label} has overlapping raw PE sections")
            raw_ranges.append(raw_range)
        executable = bool(
            section_characteristics & 0x00000020
            and section_characteristics & 0x20000000
        )
        span = max(virtual_size, raw_size)
        if span == 0:
            raise ProvenanceError(f"{label} has an empty PE section")
        final_image_end = virtual_address + span
        expected_virtual_address = (
            (final_image_end + section_alignment - 1) // section_alignment
        ) * section_alignment
        if executable and span and virtual_address <= entrypoint < virtual_address + span:
            entry_in_executable_section = True
    if expected_virtual_address != size_image:
        raise ProvenanceError(f"{label} SizeOfImage does not cover aligned sections")
    if not entry_in_executable_section:
        raise ProvenanceError(f"{label} entrypoint is not in an executable code section")
    return machine


def _decode_uvarint_string(
    data: bytes, cursor: int, limit: int, label: str
) -> tuple[str, int]:
    value = 0
    shift = 0
    while cursor < limit and shift < 64:
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            end = cursor + value
            if end > limit:
                raise ProvenanceError(
                    f"{label} Go build-info string exceeds its PE section"
                )
            return data[cursor:end].decode("latin1"), end
        shift += 7
    raise ProvenanceError(f"{label} Go build-info string length is malformed")


def _go_runtime_table_identity(
    data: bytes, section_table: int, section_count: int, label: str
) -> dict[str, Any]:
    """Require at most one valid Go build ID and exactly one runtime pclntab.

    Release executables are linked with -ldflags=-buildid= (see
    tools/build_winn_protocol_engine.sh), which omits the build-ID header, so
    its absence is accepted; a malformed or duplicated header is not.
    """

    build_id_prefix = b'\xff Go build ID: "'
    build_ids: list[bytes] = []
    pclntabs: list[tuple[int, int, int, bytes]] = []
    magics = {0xFFFFFFF1, 0xFFFFFFF0, 0xFFFFFFFA, 0xFFFFFFFB}
    for index in range(section_count):
        row = section_table + index * 40
        raw_size, raw_offset = struct.unpack_from("<II", data, row + 16)
        flags = struct.unpack_from("<I", data, row + 36)[0]
        if not raw_size:
            continue
        payload = data[raw_offset : raw_offset + raw_size]
        if flags & 0x20000000:
            if payload.startswith(build_id_prefix):
                end = payload.find(b'"\n', len(build_id_prefix), 256)
                if end < 0:
                    raise ProvenanceError(f"{label} Go build ID header is malformed")
                value = payload[len(build_id_prefix) : end]
                if re.fullmatch(rb"[A-Za-z0-9_./+-]{32,200}", value) is None:
                    raise ProvenanceError(f"{label} Go build ID is invalid")
                build_ids.append(value)
            continue
        cursor = 0
        while cursor + 72 <= len(payload):
            magic = struct.unpack_from("<I", payload, cursor)[0]
            if magic not in magics:
                cursor += 4
                continue
            pad1, pad2, min_lc, pointer_size = payload[cursor + 4 : cursor + 8]
            if pad1 or pad2 or min_lc not in {1, 2, 4} or pointer_size != 8:
                cursor += 4
                continue
            fields = struct.unpack_from("<8Q", payload, cursor + 8)
            (
                function_count,
                file_count,
                _text_start,
                function_names,
                compile_units,
                files,
                pc_table,
                function_table,
            ) = fields
            if (
                function_count < 100
                or function_count > 10_000_000
                or file_count < 10
                or file_count > 10_000_000
                or not (
                    72
                    <= function_names
                    < compile_units
                    < files
                    < pc_table
                    < function_table
                )
                or function_table > len(payload) - cursor
                or (function_count + 1) * 8
                > len(payload) - cursor - function_table
            ):
                cursor += 4
                continue
            previous_pc = -1
            valid = True
            for item_index in range(function_count + 1):
                pc, function_offset = struct.unpack_from(
                    "<II", payload, cursor + function_table + item_index * 8
                )
                if (
                    pc <= previous_pc
                    or (
                        item_index < function_count
                        and not (72 <= function_offset < len(payload) - cursor)
                    )
                    or (item_index == function_count and function_offset != 0)
                ):
                    valid = False
                    break
                previous_pc = pc
            if valid:
                table_end = function_table + (function_count + 1) * 8
                pclntabs.append(
                    (
                        int(function_count),
                        int(file_count),
                        magic,
                        payload[cursor : cursor + table_end],
                    )
                )
            cursor += 4
    if len(build_ids) > 1:
        raise ProvenanceError(f"{label} has more than one Go linker build ID")
    if len(pclntabs) != 1:
        raise ProvenanceError(f"{label} lacks one exact Go runtime pclntab")
    function_count, file_count, magic, table = pclntabs[0]
    return {
        "go_build_id_sha256": (
            hashlib.sha256(build_ids[0]).hexdigest() if build_ids else None
        ),
        "go_pclntab_sha256": hashlib.sha256(table).hexdigest(),
        "go_pclntab_magic": f"0x{magic:08x}",
        "go_function_count": function_count,
        "go_file_count": file_count,
    }


def _obfuscated_role_facts(
    data: bytes, *, role: str, architecture: str, signed_entry: dict[str, Any] | None
) -> dict[str, Any]:
    """Role facts for garbled bytes, taken only from their signed manifest row."""

    label = f"{role}-{architecture}"
    if signed_entry is None:
        raise ProvenanceError(f"{label} is garbled; its role needs --signed-entry")
    row = signed_entry.get("artifact")
    obfuscation = signed_entry.get("manifest_obfuscation")
    if not isinstance(row, dict) or not isinstance(obfuscation, dict):
        raise ProvenanceError(f"{label} signed entry is malformed")
    target, package, signed_role = OBFUSCATED_ROLE_TARGETS[role]
    target = target.format(goarch=ARCH_GOARCH[architecture])
    if (
        row.get("target") != target
        or row.get("package") != package
        or row.get("role") != signed_role
        or row.get("goos") != "windows"
        or row.get("goarch") != ARCH_GOARCH[architecture]
        or row.get("sha256") != _sha256(data)
        or row.get("size") != len(data)
        or row.get("obfuscation") != obfuscation
        or obfuscation.get("tool") != GARBLE_TOOL
        or not isinstance(obfuscation.get("version"), str)
        or SHA256_RE.fullmatch(str(obfuscation.get("seed_sha256"))) is None
    ):
        raise ProvenanceError(f"{label} signed entry does not name these garbled bytes as {target}")
    for module_path in {path for pair in GO_ROLE_IDENTITIES.values() for path in pair}:
        if module_path.encode("ascii") in data:
            raise ProvenanceError(f"{label} garbled bytes still name {module_path}")
    return {
        "go_module": f"{GARBLE_TOOL}@{obfuscation['version']}",
        "go_path": f"{target}:{package}",
        "go_version": "unknown",
        "obfuscation_seed_sha256": obfuscation["seed_sha256"],
    }


def _compiled_go_identity(
    data: bytes, *, role: str, architecture: str,
    signed_entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive role identity from authenticated PE and Go build-info bytes."""

    label = f"{role}-{architecture}"
    machine = _parse_pe_machine(data, label)
    if machine != ARCH_MACHINES[architecture]:
        raise ProvenanceError(f"{label} PE machine does not match its role")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_size
    magic = b"\xff Go buildinf:"
    candidates: list[tuple[int, int]] = []
    executable_code = bytearray()
    for index in range(section_count):
        section = section_table + index * 40
        raw_size, raw_offset = struct.unpack_from("<II", data, section + 16)
        flags = struct.unpack_from("<I", data, section + 36)[0]
        if raw_size and flags & 0x00000020 and flags & 0x20000000 and flags & 0x40000000:
            executable_code.extend(data[raw_offset : raw_offset + raw_size])
        substantive = flags & ~0x00F00000
        if not raw_size or substantive != 0xC0000040:
            continue
        section_end = raw_offset + raw_size
        cursor = (raw_offset + 15) & ~15
        while cursor + 32 <= section_end:
            if data[cursor : cursor + len(magic)] == magic:
                candidates.append((cursor, section_end))
            cursor += 16
    if (
        len(executable_code) < 32
        or sum(byte != 0 for byte in executable_code) < 16
        or len(set(executable_code)) < 8
    ):
        raise ProvenanceError(f"{label} has no substantive compiled executable code")
    if len(candidates) != 1:
        raise ProvenanceError(
            f"{label} has no unique Go build-info header in authenticated PE data"
        )
    cursor, section_end = candidates[0]
    header = data[cursor : cursor + 32]
    if header[14] not in (4, 8) or header[15] & 0x2 == 0:
        raise ProvenanceError(f"{label} Go build-info is not inline format")
    version, cursor = _decode_uvarint_string(data, cursor + 32, section_end, label)
    module_info, _cursor = _decode_uvarint_string(data, cursor, section_end, label)
    if version == "unknown" and module_info == "":
        facts = {
            "architecture": architecture,
            "pe_machine": architecture,
            "role": ARTIFACT_SPECS[role][1],
            # garble's patched linker randomizes the pclntab magic, so the
            # runtime-table identity cannot apply; the signed digest binds
            # these bytes instead.
            **_obfuscated_role_facts(
                data, role=role, architecture=architecture, signed_entry=signed_entry
            ),
        }
        return {
            **facts,
            "build_identity": hashlib.sha256(
                b"WINSVPN-WINDOWS-WINN3-COMPILED-ROLE-V2\0"
                + json.dumps(facts, sort_keys=True, separators=(",", ":")).encode("ascii")
                + hashlib.sha256(data).digest()
            ).hexdigest(),
        }
    if re.fullmatch(r"go[0-9]+\.[0-9]+(?:\.[0-9]+)?", version) is None:
        raise ProvenanceError(f"{label} Go build version is invalid")
    start = bytes.fromhex("3077af0c9274080241e1c107e6d618e6").decode("latin1")
    end = bytes.fromhex("f932433186182072008242104116d8f2").decode("latin1")
    if not module_info.startswith(start) or not module_info.endswith(end):
        raise ProvenanceError(f"{label} Go module-info framing is invalid")
    fields: dict[str, list[str]] = {}
    for line in module_info[16:-16].splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            fields.setdefault(parts[0], []).append(parts[1])
    paths = fields.get("path", [])
    modules = fields.get("mod", [])
    if len(paths) != 1 or len(modules) != 1:
        raise ProvenanceError(f"{label} Go role identity is missing or ambiguous")
    expected_path, expected_module = GO_ROLE_IDENTITIES[role]
    if (paths[0], modules[0]) != (expected_path, expected_module):
        raise ProvenanceError(f"{label} compiled Go role identity is invalid")
    runtime_identity = _go_runtime_table_identity(
        data, section_table, section_count, label
    )
    facts = {
        "architecture": architecture,
        "go_module": modules[0],
        "go_path": paths[0],
        "go_version": version,
        "pe_machine": architecture,
        "role": ARTIFACT_SPECS[role][1],
        **runtime_identity,
    }
    return {
        **facts,
        "build_identity": hashlib.sha256(
            b"WINSVPN-WINDOWS-WINN3-COMPILED-ROLE-V2\0"
            + json.dumps(facts, sort_keys=True, separators=(",", ":")).encode("ascii")
            + hashlib.sha256(data).digest()
        ).hexdigest(),
    }




def check_role(
    path: Path,
    *,
    role: str,
    architecture: str,
    expect_sha256: str | None = None,
    signed_entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the compiled identity of PATH or raise ProvenanceError."""

    if role not in ARTIFACT_SPECS:
        raise ProvenanceError(f"unknown role: {role}")
    if architecture not in ARCH_MACHINES:
        raise ProvenanceError(f"unknown architecture: {architecture}")
    if expect_sha256 is not None and SHA256_RE.fullmatch(expect_sha256) is None:
        raise ProvenanceError("--expect-sha256 must be 64 lowercase hex characters")
    filename = ARTIFACT_SPECS[role][0]
    if path.name != filename:
        raise ProvenanceError(f"{role} artifact must be named {filename}, not {path.name}")
    data = _read_regular_file(path, MAX_ARTIFACT_BYTES, f"{role}-{architecture}")
    digest = _sha256(data)
    if expect_sha256 is not None and digest != expect_sha256:
        raise ProvenanceError(
            f"{role}-{architecture} sha256 {digest} does not match the expected {expect_sha256}"
        )
    identity = _compiled_go_identity(
        data, role=role, architecture=architecture, signed_entry=signed_entry
    )
    return {"sha256": digest, "size_bytes": len(data), **identity}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check-role")
    check.add_argument("--role", choices=sorted(ARTIFACT_SPECS), required=True)
    check.add_argument("--architecture", choices=sorted(ARCH_MACHINES), required=True)
    check.add_argument("--expect-sha256")
    check.add_argument("--json", action="store_true")
    check.add_argument("--signed-entry", type=Path,
                       help="verified signed manifest row for garbled bytes (JSON)")
    check.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        signed_entry = None
        if args.signed_entry is not None:
            raw = _read_regular_file(args.signed_entry, 64 * 1024, "signed entry")
            signed_entry = json.loads(raw.decode("utf-8"))
            if not isinstance(signed_entry, dict):
                raise ProvenanceError("signed entry must be a JSON object")
        identity = check_role(
            args.path,
            role=args.role,
            architecture=args.architecture,
            expect_sha256=args.expect_sha256,
            signed_entry=signed_entry,
        )
    except ProvenanceError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(identity, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"PASS: windows winn3 {args.role} {args.architecture} "
            f"sha256={identity['sha256']} build_identity={identity['build_identity']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
