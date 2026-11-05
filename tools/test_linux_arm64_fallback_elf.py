#!/usr/bin/env python3
"""Fail-closed ELF / script inspector for Linux arm64 Winn-v1 fallback binaries.

Used by tools/build_linux_arm64_awg.sh, tools/build_linux_release.sh, and
tools/test_linux_arm64_fallback.py. This is the shape gate: wrong architecture,
wrong hash, dynamic Go binary, static C awg, non-executable mode, missing
embedded version, or a partial AmneziaWG triple are all refusals.

Canonical SHA-256 values below were produced by two clean byte-identical
builds on 2026-08-23 and independently re-hashed on the host.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import os
import pathlib
import platform
import re
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62
EM_AARCH64 = 183
PT_LOAD = 1
PT_INTERP = 3
PT_DYNAMIC = 2
PF_X = 1
PF_R = 4
ELF_MAGIC = b"\x7fELF"
# The Xray build embeds its release tag through -X core.build (tools/build_xray_engine.sh,
# XRAY_TAG), so the marker follows XRAY_VERSION in tools/build_linux_release.sh.
XRAY_VERSION_MARKER = b"v26.9.30"
XRAY_LINUX_ARM64_SHA256 = (
    "868fcabbf9a08d1e453bc6dc82dd8ca27cfcf8cdb2b3a8ff31b824361966964b"
)
AWG_GO_LINUX_ARM64_SHA256 = (
    "9083c92dbd16422cd590df8fcf2ebae2c604b43539bdd58dddaede74efd0642a"
)
AWG_GO_LINUX_AMD64_SHA256 = (
    "5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f"
)
AWG_LINUX_ARM64_SHA256 = (
    "bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d"
)
AWG_QUICK_SOURCE_SHA256 = (
    "f4bb0f5d63665ade87f0cb9f2185c43515cff09868637eb311f98f65a318722c"
)
AWG_QUICK_SHA256 = (
    "89dca7788242e542cec249af5d062764fbcb3a6a3ef66999c400d5bbe2f446db"
)

TRIPLE = ("awg", "awg-quick", "amneziawg-go")
REQUIRED_FALLBACK = TRIPLE + ("xray",)


class FallbackElfError(ValueError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_regular_executable(path: pathlib.Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FallbackElfError(f"{path}: expected a regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o111 == 0:
        raise FallbackElfError(f"{path}: not executable (mode {mode:04o})")
    return path.read_bytes()


def _entry_bytes_are_defined(machine: int, code: bytes) -> bool:
    if not code or code.startswith(b"\x00" * min(4, len(code))):
        return False
    if machine == EM_X86_64:
        return not (
            code.startswith(b"\xcc")
            or code.startswith(b"\xf4")
            or code.startswith(b"\x0f\x0b")
        )
    if machine == EM_AARCH64 and len(code) >= 4:
        instruction = int.from_bytes(code[:4], "little")
        return instruction != 0 and instruction & 0xFFE0001F not in {
            0xD4200000,  # BRK
            0xD4400000,  # HLT
        }
    return False


def _program_headers(data: bytes) -> tuple[int, int, int, list[tuple[int, ...]]]:
    if len(data) < 64 or data[:4] != ELF_MAGIC or data[5] != 1:
        raise FallbackElfError("expected a little-endian ELF image")
    if data[4] != 2:
        raise FallbackElfError(f"unsupported ELF class {data[4]}; expected ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    elf_type = header[1]
    machine = header[2]
    elf_version = header[3]
    entry = header[4]
    program_offset = header[5]
    elf_header_size = header[8]
    program_entry_size = header[9]
    program_count = header[10]
    if machine == EM_AARCH64 and entry % 4:
        raise FallbackElfError("AArch64 ELF entry point is not 4-byte aligned")
    if elf_version != 1 or data[6] != 1:
        raise FallbackElfError("invalid ELF version")
    if elf_header_size != 64:
        raise FallbackElfError("invalid ELF64 header size")
    if program_entry_size != 56:
        raise FallbackElfError("invalid ELF64 program-header size")
    if program_count == 0 or program_count > 4096:
        raise FallbackElfError("invalid ELF64 program-header count")
    if program_offset < elf_header_size:
        raise FallbackElfError("ELF program-header table overlaps the ELF header")
    table_end = program_offset + program_entry_size * program_count
    if table_end > len(data):
        raise FallbackElfError("truncated ELF program-header table")
    headers = [
        struct.unpack_from("<IIQQQQQQ", data, program_offset + index * 56)
        for index in range(program_count)
    ]
    executable_loads = 0
    entry_is_executable = False
    entry_file_offset: int | None = None
    dynamic_count = 0
    interpreter_count = 0
    for kind, flags, offset, vaddr, _paddr, filesz, memsz, alignment in headers:
        if filesz > memsz:
            raise FallbackElfError("ELF segment file size exceeds memory size")
        if offset > len(data) or filesz > len(data) - offset:
            raise FallbackElfError("ELF segment extends beyond the image")
        if alignment not in {0, 1} and alignment & (alignment - 1):
            raise FallbackElfError("ELF segment alignment is not a power of two")
        if kind == PT_LOAD and alignment not in {0, 1} and (vaddr - offset) % alignment:
            raise FallbackElfError("ELF PT_LOAD p_vaddr/p_offset alignment is incongruent")
        if kind == PT_LOAD and flags & PF_X:
            if filesz == 0:
                raise FallbackElfError("ELF executable PT_LOAD has no mapped file bytes")
            executable_loads += 1
            if vaddr <= entry < vaddr + memsz and entry - vaddr < filesz:
                entry_is_executable = True
                entry_file_offset = offset + (entry - vaddr)
        elif kind == PT_DYNAMIC:
            dynamic_count += 1
        elif kind == PT_INTERP:
            interpreter_count += 1
    if executable_loads == 0:
        raise FallbackElfError("ELF image has no executable PT_LOAD segment")
    if elf_type in {ET_EXEC, ET_DYN} and not entry_is_executable:
        raise FallbackElfError("ELF entry point is outside executable PT_LOAD segments")
    if entry_file_offset is None or not _entry_bytes_are_defined(
        machine, data[entry_file_offset : entry_file_offset + 16]
    ):
        raise FallbackElfError("ELF entry point is undefined or trap-only")
    if dynamic_count > 1:
        raise FallbackElfError("ELF has multiple PT_DYNAMIC segments")
    if interpreter_count > 1:
        raise FallbackElfError("ELF has multiple PT_INTERP segments")
    if interpreter_count and dynamic_count != 1:
        raise FallbackElfError("ELF PT_INTERP requires exactly one PT_DYNAMIC segment")
    if elf_type == ET_DYN and dynamic_count != 1:
        raise FallbackElfError("ET_DYN executable requires exactly one PT_DYNAMIC segment")
    return elf_type, machine, program_count, headers


def _needed_libraries(data: bytes, headers: list[tuple[int, ...]]) -> list[bytes]:
    dynamic_segments: list[tuple[int, int]] = []
    loads: list[tuple[int, int, int]] = []
    for kind, _flags, offset, vaddr, _paddr, filesz, _memsz, _align in headers:
        if kind == PT_LOAD:
            loads.append((vaddr, offset, filesz))
        if kind == PT_DYNAMIC:
            dynamic_segments.append((offset, filesz))
    if not dynamic_segments:
        return []
    if len(dynamic_segments) != 1:
        raise FallbackElfError("ELF must contain at most one PT_DYNAMIC segment")
    dynoff, dynsz = dynamic_segments[0]
    if dynsz == 0 or dynsz % 16:
        raise FallbackElfError("ELF PT_DYNAMIC size is invalid")

    def vaddr_to_off(virt: int) -> int | None:
        for vaddr, offset, filesz in loads:
            if vaddr <= virt < vaddr + filesz:
                return offset + (virt - vaddr)
        return None

    strtab = None
    strsz = None
    needed_vals: list[int] = []
    terminated = False
    cursor = dynoff
    end = dynoff + dynsz
    while cursor + 16 <= end:
        tag, val = struct.unpack_from("<QQ", data, cursor)
        cursor += 16
        if tag == 0:
            terminated = True
            break
        if tag == 5:  # DT_STRTAB
            strtab = val
        if tag == 1:  # DT_NEEDED
            needed_vals.append(val)
        if tag == 10:  # DT_STRSZ
            strsz = val
    if not terminated:
        raise FallbackElfError("ELF PT_DYNAMIC lacks DT_NULL termination")
    if needed_vals and (strtab is None or strsz is None or strsz <= 1):
        raise FallbackElfError("ELF DT_NEEDED entries lack a bounded string table")
    if not needed_vals:
        return []
    str_off = vaddr_to_off(strtab)
    if str_off is None:
        raise FallbackElfError("ELF DT_STRTAB is not backed by loadable file bytes")
    needed: list[bytes] = []
    for rel in needed_vals:
        start = str_off + rel
        if rel >= strsz or start >= len(data):
            raise FallbackElfError("DT_NEEDED string is outside the image")
        zero = data.find(b"\x00", start, str_off + strsz)
        if zero < 0:
            raise FallbackElfError("unterminated DT_NEEDED string")
        needed.append(data[start:zero])
    return needed


def inspect_elf(path: pathlib.Path) -> dict[str, object]:
    data = _require_regular_executable(path)
    elf_type, machine, _count, headers = _program_headers(data)
    interp: bytes | None = None
    dynamic_count = 0
    for kind, _flags, offset, _vaddr, _paddr, filesz, _memsz, _align in headers:
        if kind == PT_DYNAMIC:
            dynamic_count += 1
        if kind == PT_INTERP:
            raw_interp = data[offset : offset + filesz]
            if not raw_interp or not raw_interp.endswith(b"\x00"):
                raise FallbackElfError("ELF PT_INTERP is empty or unterminated")
            if b"\x00" in raw_interp[:-1]:
                raise FallbackElfError("ELF PT_INTERP contains an embedded NUL")
            interp = raw_interp[:-1]
    needed = _needed_libraries(data, headers)
    return {
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "mode": stat.S_IMODE(path.stat().st_mode),
        "elf_type": elf_type,
        "machine": machine,
        "interpreter": interp,
        "needed": needed,
        "static": interp is None and dynamic_count == 0 and not needed,
        "data": data,
    }


def _pinned_sha256(kind: str) -> str:
    return {
        "xray": XRAY_LINUX_ARM64_SHA256,
        "amneziawg-go": AWG_GO_LINUX_ARM64_SHA256,
        "awg": AWG_LINUX_ARM64_SHA256,
        "awg-quick": AWG_QUICK_SHA256,
    }[kind]


def _expect_sha256(info: dict[str, object], expected: str | None) -> None:
    if expected is None:
        return
    want = expected.lower()
    if info["sha256"] != want:
        raise FallbackElfError(
            f"{info['path']}: SHA-256 drift: expected {want}, got {info['sha256']}"
        )


def verify_xray_linux_arm64(
    path: pathlib.Path, *, expected_sha256: str | None = XRAY_LINUX_ARM64_SHA256
) -> dict[str, object]:
    info = inspect_elf(path)
    if info["machine"] != EM_AARCH64:
        raise FallbackElfError(
            f"{path}: ELF e_machine {info['machine']} is not ARM aarch64 (183)"
        )
    if info["elf_type"] not in {ET_EXEC, ET_DYN}:
        raise FallbackElfError(f"{path}: expected an executable ELF, got type {info['elf_type']}")
    if not info["static"]:
        raise FallbackElfError(
            f"{path}: Xray must be a CGO_ENABLED=0 static binary; "
            f"interpreter={info['interpreter']!r} needed={info['needed']!r}"
        )
    if info["size"] < 1_000_000:
        raise FallbackElfError(f"{path}: implausibly small Xray ({info['size']} bytes)")
    data = info["data"]
    assert isinstance(data, bytes)
    for marker in (b"go1.27.1", b"github.com/xtls/xray-core", XRAY_VERSION_MARKER):
        if marker not in data:
            raise FallbackElfError(
                f"{path}: missing embedded marker {marker!r}"
            )
    _expect_sha256(info, expected_sha256)
    return info


def verify_amneziawg_go_linux_arm64(
    path: pathlib.Path, *, expected_sha256: str | None = AWG_GO_LINUX_ARM64_SHA256
) -> dict[str, object]:
    info = inspect_elf(path)
    if info["machine"] != EM_AARCH64:
        raise FallbackElfError(
            f"{path}: ELF e_machine {info['machine']} is not ARM aarch64 (183)"
        )
    if info["elf_type"] not in {ET_EXEC, ET_DYN}:
        raise FallbackElfError(f"{path}: expected an executable ELF, got type {info['elf_type']}")
    if not info["static"]:
        raise FallbackElfError(
            f"{path}: amneziawg-go must be a CGO_ENABLED=0 static binary; "
            f"interpreter={info['interpreter']!r} needed={info['needed']!r}"
        )
    if info["size"] < 1_000_000:
        raise FallbackElfError(
            f"{path}: implausibly small amneziawg-go ({info['size']} bytes)"
        )
    data = info["data"]
    assert isinstance(data, bytes)
    for marker in (b"go1.27.1", b"github.com/amnezia-vpn/amneziawg-go/v3"):
        if marker not in data:
            raise FallbackElfError(f"{path}: missing embedded marker {marker!r}")
    _expect_sha256(info, expected_sha256)
    return info


def verify_awg_linux_arm64(
    path: pathlib.Path, *, expected_sha256: str | None = AWG_LINUX_ARM64_SHA256
) -> dict[str, object]:
    info = inspect_elf(path)
    if info["machine"] != EM_AARCH64:
        raise FallbackElfError(
            f"{path}: ELF e_machine {info['machine']} is not ARM aarch64 (183)"
        )
    if info["elf_type"] != ET_DYN:
        raise FallbackElfError(
            f"{path}: awg must be a PIE (ET_DYN) like the amd64 zip; got type {info['elf_type']}"
        )
    if info["static"] or info["interpreter"] is None:
        raise FallbackElfError(f"{path}: awg must be dynamically linked")
    if info["needed"] != [b"libc.so.6"]:
        raise FallbackElfError(f"{path}: unexpected DT_NEEDED {info['needed']!r}")
    if info["interpreter"] != b"/lib/ld-linux-aarch64.so.1":
        raise FallbackElfError(
            f"{path}: unexpected interpreter {info['interpreter']!r}"
        )
    data = info["data"]
    assert isinstance(data, bytes)
    if b"3.1.20260812" not in data:
        raise FallbackElfError(f"{path}: missing amneziawg-tools version string")
    _expect_sha256(info, expected_sha256)
    return info


def verify_awg_quick(
    path: pathlib.Path, *, expected_sha256: str | None = AWG_QUICK_SHA256
) -> dict[str, object]:
    data = _require_regular_executable(path)
    if not data.startswith(b"#!/bin/bash\n"):
        raise FallbackElfError(f"{path}: awg-quick must be a bash script")
    if data[:4] == ELF_MAGIC:
        raise FallbackElfError(f"{path}: awg-quick must not be an ELF")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256.lower():
        raise FallbackElfError(
            f"{path}: SHA-256 drift: expected {expected_sha256.lower()}, got {digest}"
        )
    for marker in (
        b"HeaderProtectionKey requires the exact reviewed userspace AmneziaWG engine",
        b'local implementation="${SELF%/*}/amneziawg-go"',
        AWG_GO_LINUX_AMD64_SHA256.encode("ascii"),
        AWG_GO_LINUX_ARM64_SHA256.encode("ascii"),
        b'/usr/bin/sha256sum -- "$implementation"',
        b'cmd "$implementation" "$INTERFACE"',
    ):
        if marker not in data:
            raise FallbackElfError(f"{path}: missing userspace-only marker {marker!r}")
    # The pinned upstream script defines add_if() itself, with the
    # WG_QUICK_USERSPACE_IMPLEMENTATION variable, near its top. The release
    # transform inserts the reviewed add_if() override after it, at the
    # "function override insertion point", and bash keeps the last definition of
    # a function. So the override must be present once, must not mention the
    # variable, and must be the last add_if() definition in the script.
    if data.count(AWG_QUICK_OVERRIDE_MARKER) != 1:
        raise FallbackElfError(f"{path}: missing userspace-only marker {AWG_QUICK_OVERRIDE_MARKER!r}")
    override_start = data.index(AWG_QUICK_OVERRIDE_MARKER)
    override_end = data.find(b"\n}\n", override_start)
    if override_end < 0:
        raise FallbackElfError("awg-quick userspace add_if override is missing")
    if b"WG_QUICK_USERSPACE_IMPLEMENTATION" in data[override_start:]:
        raise FallbackElfError(f"{path}: arbitrary userspace implementation override remains enabled")
    if re.search(rb"(?m)^[ \t]*(?:function[ \t]+)?add_if[ \t]*\([ \t]*\)", data[override_end + 3 :]):
        raise FallbackElfError(f"{path}: a later add_if() could replace the reviewed userspace override")
    if expected_sha256 is not None:
        _prove_hpk_userspace_route(path, data)
    return {"path": str(path), "sha256": digest, "size": len(data), "script": True}


AWG_QUICK_OVERRIDE_MARKER = (
    b"# Wins VPN release override: HPK requires the exact in-bundle reviewed userspace engine.\n"
)


def _prove_hpk_userspace_route(path: pathlib.Path, data: bytes) -> None:
    marker = data.find(AWG_QUICK_OVERRIDE_MARKER)
    start = data.find(b"add_if() {\n", marker) if marker >= 0 else -1
    end = data.find(b"\n}\n", start) if start >= 0 else -1
    if start < 0 or end < 0:
        raise FallbackElfError("awg-quick userspace add_if override is missing")
    override = data[start : end + 3]
    if data.count(override) != 1:
        raise FallbackElfError("awg-quick userspace add_if override is not exact")
    engine = path.parent / "amneziawg-go"
    if engine.is_symlink() or not engine.is_file() or not os.access(engine, os.X_OK):
        raise FallbackElfError("awg-quick reviewed sibling amneziawg-go is missing or unsafe")
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        expected_engine = AWG_GO_LINUX_AMD64_SHA256
    elif machine in {"aarch64", "arm64"}:
        expected_engine = AWG_GO_LINUX_ARM64_SHA256
    else:
        raise FallbackElfError(f"unsupported HPK userspace proof architecture: {machine}")
    if sha256_file(engine) != expected_engine:
        raise FallbackElfError("awg-quick sibling engine is not the reviewed architecture payload")
    with tempfile.TemporaryDirectory(prefix="winsvpn-awg-hpk-route-") as raw:
        root = pathlib.Path(raw)
        harness = root / "prove.sh"
        harness.write_bytes(
            b"#!/bin/bash\nset -Eeuo pipefail\n"
            b"die() { printf 'DIE:%s\\n' \"$*\"; exit 97; }\n"
            b"cmd() { printf 'CMD:%s\\n' \"$*\"; }\n"
            + override
            + f"SELF={shlex.quote(str(path))}\n".encode("ascii")
            + b"INTERFACE=wg-hpk-proof\n"
            + b"HeaderProtectionKey=00112233445566778899aabbccddeeff\n"
            + b"export HeaderProtectionKey\n"
            + b"add_if\n"
        )
        harness.chmod(0o700)
        environment = {
            "HOME": raw,
            "PATH": "/usr/bin:/bin",
            "WG_QUICK_USERSPACE_IMPLEMENTATION": "/tmp/attacker-awg",
        }
        completed = subprocess.run(
            ["/bin/bash", str(harness)],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise FallbackElfError(
                f"HPK userspace route proof failed with exit {completed.returncode}"
            )
        expected_stdout = f"CMD:{engine} wg-hpk-proof\n".encode("ascii")
        if completed.stdout != expected_stdout:
            raise FallbackElfError("HPK did not force the reviewed userspace implementation")
        if b"kernel fast path is disabled" not in completed.stderr or b"ip link" in completed.stdout:
            raise FallbackElfError("HPK userspace route proof did not exclude the kernel path")


def require_complete_fallback_triple(directory: pathlib.Path) -> None:
    present = [name for name in TRIPLE if (directory / name).exists()]
    if len(present) != 3:
        raise FallbackElfError(
            f"{directory}: incomplete AmneziaWG triple "
            f"({len(present)} of {', '.join(TRIPLE)}); refusing a partial set"
        )
    missing = [name for name in REQUIRED_FALLBACK if not (directory / name).is_file()]
    if missing:
        raise FallbackElfError(
            f"{directory}: missing required fallback components: {', '.join(missing)}"
        )


def verify_linux_arm64_fallback_dir(
    directory: pathlib.Path, *, check_hashes: bool = True
) -> dict[str, dict[str, object]]:
    require_complete_fallback_triple(directory)
    xray_hash = XRAY_LINUX_ARM64_SHA256 if check_hashes else None
    awg_hash = AWG_LINUX_ARM64_SHA256 if check_hashes else None
    awg_go_hash = AWG_GO_LINUX_ARM64_SHA256 if check_hashes else None
    quick_hash = AWG_QUICK_SHA256 if check_hashes else None
    return {
        "xray": verify_xray_linux_arm64(
            directory / "xray", expected_sha256=xray_hash
        ),
        "awg": verify_awg_linux_arm64(
            directory / "awg", expected_sha256=awg_hash
        ),
        "awg-quick": verify_awg_quick(
            directory / "awg-quick", expected_sha256=quick_hash
        ),
        "amneziawg-go": verify_amneziawg_go_linux_arm64(
            directory / "amneziawg-go", expected_sha256=awg_go_hash
        ),
    }


def _structural_elf64_fixture(
    *, machine: int, elf_type: int = ET_EXEC, interp: bytes | None = None,
    trap_entry: bool = False,
) -> bytes:
    """Build a structurally valid ELF64 fixture, not a magic/header-only positive."""

    data = bytearray(4096)
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    dynamic = interp is not None or elf_type == ET_DYN
    phnum = 1 + (1 if interp else 0) + (1 if dynamic else 0)
    load_vaddr = 0x400000
    entry = load_vaddr + 0x200
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
    # PT_LOAD
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        PT_LOAD,
        5,
        0,
        load_vaddr,
        load_vaddr,
        len(data),
        len(data),
        4096,
    )
    if trap_entry and machine == EM_X86_64:
        code = b"\x0f\x0b"
    elif trap_entry and machine == EM_AARCH64:
        code = b"\x00\x00\x20\xd4"
    elif machine == EM_X86_64:
        code = b"\x31\xff\xb8\x3c\x00\x00\x00\x0f\x05"
    elif machine == EM_AARCH64:
        code = b"\x00\x00\x80\xd2\xa8\x0b\x80\xd2\x01\x00\x00\xd4"
    else:
        code = b"\x00\x00\x00\x00"
    data[0x200 : 0x200 + len(code)] = code
    next_header = 120
    if interp:
        interp_blob = interp + b"\x00"
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            next_header,
            PT_INTERP,
            4,
            512,
            load_vaddr + 512,
            load_vaddr + 512,
            len(interp_blob),
            len(interp_blob),
            1,
        )
        data[512 : 512 + len(interp_blob)] = interp_blob
        next_header += 56
    if dynamic:
        dynamic_offset = 0x300
        string_offset = 0x380
        string_table = b"\x00libc.so.6\x00" if interp else b"\x00"
        dynamic_entries = [
            (5, load_vaddr + string_offset),
            (10, len(string_table)),
        ]
        if interp:
            dynamic_entries.append((1, 1))
        dynamic_entries.append((0, 0))
        dynamic_size = len(dynamic_entries) * 16
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            next_header,
            PT_DYNAMIC,
            6,
            dynamic_offset,
            load_vaddr + dynamic_offset,
            load_vaddr + dynamic_offset,
            dynamic_size,
            dynamic_size,
            8,
        )
        for index, entry_value in enumerate(dynamic_entries):
            struct.pack_into("<QQ", data, dynamic_offset + index * 16, *entry_value)
        data[string_offset : string_offset + len(string_table)] = string_table
    return bytes(data)


class LinuxArm64FallbackElfTests(unittest.TestCase):
    def test_rejects_wrong_machine(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "xray"
            path.write_bytes(_structural_elf64_fixture(machine=EM_X86_64))
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "e_machine 62"):
                verify_xray_linux_arm64(path, expected_sha256=None)

    def test_rejects_dynamic_xray(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "xray"
            path.write_bytes(
                _structural_elf64_fixture(
                    machine=EM_AARCH64,
                    elf_type=ET_DYN,
                    interp=b"/lib/ld-linux-aarch64.so.1",
                )
            )
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "static binary"):
                verify_xray_linux_arm64(path, expected_sha256=None)

    def test_rejects_header_only_fake_elf(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "fake"
            data = bytearray(64)
            ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
            struct.pack_into(
                "<16sHHIQQQIHHHHHH",
                data,
                0,
                ident,
                ET_EXEC,
                EM_AARCH64,
                1,
                0,
                64,
                0,
                0,
                64,
                56,
                0,
                0,
                0,
                0,
            )
            path.write_bytes(data)
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "program-header count"):
                inspect_elf(path)

    def test_rejects_entry_outside_executable_segment(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "bad-entry"
            data = bytearray(_structural_elf64_fixture(machine=EM_AARCH64))
            struct.pack_into("<Q", data, 24, 0x900000)
            path.write_bytes(data)
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "entry point"):
                inspect_elf(path)

    def test_rejects_misaligned_aarch64_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "misaligned-entry"
            data = bytearray(_structural_elf64_fixture(machine=EM_AARCH64))
            struct.pack_into("<Q", data, 24, 0x400201)
            path.write_bytes(data)
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "not 4-byte aligned"):
                inspect_elf(path)

    def test_rejects_et_dyn_executable_with_zero_entry(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "marker-only-pie"
            data = bytearray(
                _structural_elf64_fixture(machine=EM_AARCH64, elf_type=ET_DYN)
            )
            struct.pack_into("<Q", data, 24, 0)
            data.extend(b"go1.27.1 github.com/amnezia-vpn/amneziawg-go/v3")
            path.write_bytes(data)
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "entry point"):
                inspect_elf(path)

    def test_rejects_incongruent_load_segment(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "bad-congruence"
            data = bytearray(_structural_elf64_fixture(machine=EM_AARCH64))
            struct.pack_into("<Q", data, 64 + 16, 0x400001)
            path.write_bytes(data)
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "p_vaddr/p_offset"):
                inspect_elf(path)

    def test_rejects_trap_only_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "trap-entry"
            path.write_bytes(
                _structural_elf64_fixture(
                    machine=EM_AARCH64,
                    trap_entry=True,
                )
            )
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "trap-only"):
                inspect_elf(path)

    def test_rejects_dynamic_executable_without_dynamic_segment(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "missing-dynamic"
            data = bytearray(_structural_elf64_fixture(machine=EM_AARCH64))
            struct.pack_into("<H", data, 16, ET_DYN)
            path.write_bytes(data)
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "PT_DYNAMIC"):
                inspect_elf(path)

    def test_rejects_needed_library_with_unmapped_string_table(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "unmapped-strtab"
            data = bytearray(
                _structural_elf64_fixture(
                    machine=EM_AARCH64,
                    elf_type=ET_DYN,
                    interp=b"/lib/ld-linux-aarch64.so.1",
                )
            )
            struct.pack_into("<Q", data, 0x300 + 8, 0x900000)
            path.write_bytes(data)
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "DT_STRTAB"):
                inspect_elf(path)

    def test_native_fixture_is_really_runnable_on_linux(self) -> None:
        machine = platform.machine().lower()
        expected = EM_X86_64 if machine in {"x86_64", "amd64"} else EM_AARCH64
        if sys.platform != "linux" or machine not in {"x86_64", "amd64", "aarch64", "arm64"}:
            with tempfile.TemporaryDirectory() as name:
                path = pathlib.Path(name) / "structural"
                path.write_bytes(_structural_elf64_fixture(machine=expected))
                path.chmod(0o755)
                self.assertEqual(inspect_elf(path)["machine"], expected)
            self.skipTest("executing the native fixture requires Linux x86_64 or arm64")
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "runnable"
            path.write_bytes(_structural_elf64_fixture(machine=expected))
            path.chmod(0o755)
            completed = subprocess.run([str(path)], stdin=subprocess.DEVNULL, check=False)
            self.assertEqual(completed.returncode, 0)

    def test_real_host_elf_structure_and_corrupted_entry_fail_closed(self) -> None:
        if sys.platform != "linux":
            self.skipTest("real host ELF evidence requires Linux")
        source = pathlib.Path("/bin/true")
        if not source.is_file() or source.read_bytes()[:4] != ELF_MAGIC:
            self.skipTest("host /bin/true is not an ELF executable")
        authentic = inspect_elf(source)
        self.assertIn(authentic["machine"], {EM_X86_64, EM_AARCH64})
        with tempfile.TemporaryDirectory() as name:
            corrupted = pathlib.Path(name) / "true-corrupted-entry"
            payload = bytearray(source.read_bytes())
            struct.pack_into("<Q", payload, 24, 0xFFFFFFFFFFFFF000)
            corrupted.write_bytes(payload)
            corrupted.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "entry point"):
                inspect_elf(corrupted)

    def test_rejects_wrong_hash(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "awg-quick"
            path.write_bytes(
                b"#!/bin/bash\n"
                b"# HeaderProtectionKey requires the verified userspace AmneziaWG engine\n"
                b"cmd \"$implementation\" \"$INTERFACE\"\n"
                b"echo no\n"
            )
            path.chmod(0o755)
            with self.assertRaisesRegex(FallbackElfError, "SHA-256 drift"):
                verify_awg_quick(path)

    def test_hpk_rejects_arbitrary_userspace_environment_override(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "awg-quick"
            payload = (
                b"#!/bin/bash\n"
                b"add_if() {\n"
                b'\tlocal implementation="${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}"\n'
                b'\tcommand -v "$implementation" >/dev/null 2>&1 || die "verified AmneziaWG userspace implementation is unavailable"\n'
                b'\techo "[!] HeaderProtectionKey requires the verified userspace AmneziaWG engine; kernel fast path is disabled until exact kernel proof is pinned." >&2\n'
                b'\tcmd "$implementation" "$INTERFACE"\n'
                b"}\n"
            )
            path.write_bytes(payload)
            path.chmod(0o755)
            with self.assertRaisesRegex(
                FallbackElfError,
                "userspace|arbitrary|marker",
            ):
                verify_awg_quick(
                    path, expected_sha256=hashlib.sha256(payload).hexdigest()
                )

    def _transformed_awg_quick(self, *, extra_in_override: bytes = b"", after: bytes = b"") -> bytes:
        # Shape of the real release script: the pinned upstream add_if() (with the
        # environment variable) first, the reviewed override inserted after it.
        return (
            b"#!/bin/bash\n"
            b"add_if() {\n"
            b'\tcmd "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" "$INTERFACE"\n'
            b"}\n"
            b"cmd_up() {\n\tadd_if\n}\n"
            + AWG_QUICK_OVERRIDE_MARKER
            + b"add_if() {\n"
            b'\tlocal implementation="${SELF%/*}/amneziawg-go"\n'
            + AWG_GO_LINUX_AMD64_SHA256.encode("ascii")
            + b"\n"
            + AWG_GO_LINUX_ARM64_SHA256.encode("ascii")
            + b"\n"
            b'\tactual="$(/usr/bin/sha256sum -- "$implementation")"\n'
            b'\techo "[!] HeaderProtectionKey requires the exact reviewed userspace AmneziaWG engine; kernel fast path is disabled." >&2\n'
            b'\tcmd "$implementation" "$INTERFACE"\n'
            + extra_in_override
            + b"}\n"
            + after
            + b"cmd_up\n"
        )

    def test_hpk_accepts_the_release_transform_of_the_upstream_script(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "awg-quick"
            path.write_bytes(self._transformed_awg_quick())
            path.chmod(0o755)
            self.assertTrue(verify_awg_quick(path, expected_sha256=None)["script"])

    def test_hpk_refuses_the_override_variable_or_a_later_add_if_after_the_marker(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "awg-quick"
            for label, payload, pattern in (
                ("variable", self._transformed_awg_quick(extra_in_override=b'\t: "${WG_QUICK_USERSPACE_IMPLEMENTATION:-x}"\n'), "override remains enabled"),
                ("redefinition", self._transformed_awg_quick(after=b"add_if() {\n\ttrue\n}\n"), "later add_if"),
            ):
                with self.subTest(label):
                    path.unlink(missing_ok=True)
                    path.write_bytes(payload)
                    path.chmod(0o755)
                    with self.assertRaisesRegex(FallbackElfError, pattern):
                        verify_awg_quick(path, expected_sha256=None)

    def test_xray_version_marker_follows_the_pinned_release(self) -> None:
        producer = (pathlib.Path(__file__).resolve().parent / "build_linux_release.sh").read_text(encoding="utf-8")
        version = re.search(r'^XRAY_VERSION="([0-9.]+)"$', producer, re.MULTILINE).group(1)
        self.assertEqual(XRAY_VERSION_MARKER, b"v" + version.encode("ascii"))
        builder = (pathlib.Path(__file__).resolve().parent / "build_xray_engine.sh").read_text(encoding="utf-8")
        self.assertIn(f'XRAY_TAG="v{version}"', builder)

    def test_rejects_partial_triple(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = pathlib.Path(name)
            (directory / "awg").write_bytes(b"partial")
            (directory / "xray").write_bytes(b"x")
            with self.assertRaisesRegex(FallbackElfError, "incomplete AmneziaWG triple"):
                require_complete_fallback_triple(directory)

    def test_rejects_non_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "awg-quick"
            path.write_bytes(b"#!/bin/bash\n")
            path.chmod(0o644)
            with self.assertRaisesRegex(FallbackElfError, "not executable"):
                verify_awg_quick(path, expected_sha256=None)

    def test_canonical_pins_are_64_hex(self) -> None:
        for digest in (
            XRAY_LINUX_ARM64_SHA256,
            AWG_GO_LINUX_ARM64_SHA256,
            AWG_LINUX_ARM64_SHA256,
            AWG_QUICK_SOURCE_SHA256,
            AWG_QUICK_SHA256,
        ):
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    @staticmethod
    def _awg_fixture(directory: pathlib.Path) -> tuple[pathlib.Path, str]:
        path = directory / "awg"
        data = _structural_elf64_fixture(
            machine=EM_AARCH64,
            elf_type=ET_DYN,
            interp=b"/lib/ld-linux-aarch64.so.1",
        ) + b"3.1.20260812"
        path.write_bytes(data)
        path.chmod(0o755)
        return path, hashlib.sha256(data).hexdigest()

    @staticmethod
    def _run_cli(argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = _cli(argv)
        return code, out.getvalue(), err.getvalue()

    def test_cli_final_pass_is_structure_plus_pinned_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path, digest = self._awg_fixture(pathlib.Path(name))
            with mock.patch.dict(globals(), {"AWG_LINUX_ARM64_SHA256": digest}):
                code, out, err = self._run_cli(["verify", "awg", str(path)])
                self.assertEqual(code, 0, err)
                self.assertIn(f"LINUX ARM64 FALLBACK awg: PASS sha256={digest}", out)
                code, out, err = self._run_cli(
                    ["verify", "awg", str(path), "--sha256", digest.upper()]
                )
                self.assertEqual(code, 0, err)
                self.assertIn("PASS", out)

    def test_cli_final_pass_refuses_unpinned_sha_and_bad_structure(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path, digest = self._awg_fixture(pathlib.Path(name))
            code, out, err = self._run_cli(["verify", "awg", str(path)])
            self.assertEqual(code, 65)
            self.assertIn("SHA-256 drift", err)
            self.assertNotIn("PASS", out)
            code, out, err = self._run_cli(["verify", "awg", str(path), "--sha256", digest])
            self.assertEqual(code, 65)
            self.assertIn("is not the reviewed pin", err)
            self.assertNotIn("PASS", out)
            wrong = pathlib.Path(name) / "wrong-machine"
            wrong_bytes = _structural_elf64_fixture(
                machine=EM_X86_64, elf_type=ET_DYN, interp=b"/lib/ld-linux-aarch64.so.1"
            ) + b"3.1.20260812"
            wrong.write_bytes(wrong_bytes)
            wrong.chmod(0o755)
            wrong_digest = hashlib.sha256(wrong_bytes).hexdigest()
            with mock.patch.dict(globals(), {"AWG_LINUX_ARM64_SHA256": wrong_digest}):
                code, out, err = self._run_cli(["verify", "awg", str(wrong)])
            self.assertEqual(code, 65)
            self.assertIn("is not ARM aarch64", err)
            code, out, err = self._run_cli(["verify", "awg", str(path), "--shape-only"])
            self.assertEqual(code, 0, err)
            self.assertIn("STRUCTURE-ONLY", out)

    def test_cli_has_no_execution_receipt_options(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path, _digest = self._awg_fixture(pathlib.Path(name))
            for argv in (
                ["verify", "awg", str(path), "--linux-execution-receipt", "r"],
                ["verify", "awg", str(path), "--linux-execution-bundle", "b"],
                ["verify", "awg", str(path), "--release-index-sha256", "0" * 64],
                ["verify-dir", name, "--linux-execution-receipts-dir", name],
            ):
                with self.subTest(argv=argv[3:]):
                    with self.assertRaises(SystemExit) as caught:
                        self._run_cli(argv)
                    self.assertEqual(caught.exception.code, 2)

    def test_cli_verify_dir_pass_checks_pinned_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            with mock.patch.dict(
                globals(),
                {"verify_linux_arm64_fallback_dir": mock.Mock(return_value={})},
            ):
                code, out, err = self._run_cli(["verify-dir", name])
                self.assertEqual(code, 0, err)
                self.assertIn("LINUX ARM64 FALLBACK DIR: PASS", out)
                globals()["verify_linux_arm64_fallback_dir"].assert_called_once_with(
                    pathlib.Path(name), check_hashes=True
                )
            with mock.patch.dict(
                globals(),
                {"verify_linux_arm64_fallback_dir": mock.Mock(return_value={})},
            ):
                code, out, err = self._run_cli(["verify-dir", name, "--shape-only"])
                self.assertEqual(code, 0, err)
                self.assertIn("STRUCTURE-ONLY", out)
                globals()["verify_linux_arm64_fallback_dir"].assert_called_once_with(
                    pathlib.Path(name), check_hashes=False
                )
            refused = mock.Mock(side_effect=FallbackElfError("SHA-256 drift: fixture"))
            with mock.patch.dict(globals(), {"verify_linux_arm64_fallback_dir": refused}):
                code, out, err = self._run_cli(["verify-dir", name])
            self.assertEqual(code, 65)
            self.assertNotIn("PASS", out)


def _cli(argv: list[str] | None = None) -> int:
    """Final PASS is the ELF/script structure checks plus the reviewed SHA-256 pin."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    verify = sub.add_parser("verify", help="verify one binary")
    verify.add_argument("kind", choices=("xray", "amneziawg-go", "awg", "awg-quick"))
    verify.add_argument("path")
    verify.add_argument("--sha256", default=None)
    verify.add_argument("--shape-only", action="store_true")
    directory = sub.add_parser("verify-dir", help="verify a complete fallback directory")
    directory.add_argument("path")
    directory.add_argument("--shape-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "verify":
            path = pathlib.Path(args.path)
            pinned = _pinned_sha256(args.kind)
            if args.shape_only:
                expected = None
            else:
                expected = pinned
                if args.sha256 is not None and args.sha256.lower() != pinned:
                    raise FallbackElfError(
                        f"--sha256 {args.sha256} for {args.kind} is not the reviewed pin {pinned}"
                    )
            if args.kind == "xray":
                info = verify_xray_linux_arm64(path, expected_sha256=expected)
            elif args.kind == "amneziawg-go":
                info = verify_amneziawg_go_linux_arm64(path, expected_sha256=expected)
            elif args.kind == "awg":
                info = verify_awg_linux_arm64(path, expected_sha256=expected)
            else:
                info = verify_awg_quick(path, expected_sha256=expected)
            verdict = "STRUCTURE-ONLY" if args.shape_only else "PASS"
            print(
                f"LINUX ARM64 FALLBACK {args.kind}: {verdict} "
                f"sha256={info['sha256']} size={info['size']}"
            )
            return 0
        verify_linux_arm64_fallback_dir(
            pathlib.Path(args.path), check_hashes=not args.shape_only
        )
        verdict = "STRUCTURE-ONLY" if args.shape_only else "PASS"
        print(f"LINUX ARM64 FALLBACK DIR: {verdict}")
        return 0
    except FallbackElfError as exc:
        print(f"LINUX ARM64 FALLBACK: FAIL: {exc}", file=sys.stderr)
        return 65


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        loader = unittest.defaultTestLoader
        suite = loader.loadTestsFromTestCase(LinuxArm64FallbackElfTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    raise SystemExit(_cli())
