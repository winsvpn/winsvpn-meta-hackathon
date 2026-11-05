#!/usr/bin/env python3
"""Focused hostile tests for shipped native artifact freshness custody."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping, Optional
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "verify_shipped_native_artifact_freshness.py"
SPEC = importlib.util.spec_from_file_location("shipped_freshness", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


REAL_ELF = {
    "arm64": ROOT / "android/app/src/release/jniLibs/arm64-v8a/libwinnengine.so",
    "arm": ROOT / "android/app/src/release/jniLibs/armeabi-v7a/libwinnengine.so",
    "amd64": ROOT / "android/app/src/release/jniLibs/x86_64/libwinnengine.so",
}
REAL_ARCHIVE = (
    ROOT / "tools/winn_conformance_build_out/libwinn-datapath-ios-arm64.a"
)
REAL_SIM_WRAPPER = (
    ROOT / "apple/EngineArtifacts/ios/iphonesimulator/libWinsWinnPacketEngine.dylib"
)


def real_elf(arch: str) -> bytes:
    return REAL_ELF[arch].read_bytes()


@dataclass(frozen=True)
class FixtureProducerReceipt:
    """Parser fixture only. Production role validation must refuse this type."""

    target: str
    artifact_sha256: str
    authority_path: str = "TEST-FIXTURE-NOT-A-PRODUCTION-AUTHORITY"


def authenticated_fixture_receipt(blob: bytes, artifact: object) -> object:
    return FixtureProducerReceipt(
        artifact.target,
        hashlib.sha256(blob).hexdigest(),
    )


def retained_reference(path: Path, target: str) -> object:
    private = Path(tempfile.mkdtemp(prefix=".retained-reference.", dir=path.parent))
    retained = private / path.name
    shutil.copyfile(path, retained)
    retained.chmod(0o400)
    custody = MODULE.DescriptorCustody(
        "test retained producer reference", MODULE.CustodyUnavailable
    )
    node = custody.bind_file(str(retained))
    payload = retained.read_bytes()
    handoff = MODULE.AuthenticatedPublicationHandoff(
        target,
        str(retained),
        node.identity,
        hashlib.sha256(payload).hexdigest(),
    )
    return MODULE.RetainedReference(str(retained), custody, handoff)


def atomic_publish(path: Path, payload: bytes) -> None:
    """Publish from an unwatched sibling transaction, like the real producer."""
    staging = Path(tempfile.mkdtemp(prefix=".producer-stage.", dir=path.parent.parent))
    candidate = staging / path.name
    candidate.write_bytes(payload)
    os.replace(candidate, path)


def authenticated_publication_handoff(
    path: Path,
    target: str = "test-publication",
) -> object:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        current = os.lstat(path)
        identity = MODULE._file_identity(info)
        if identity != MODULE._file_identity(current):
            raise AssertionError("fixture publication path changed during handoff")
        digest = hashlib.sha256()
        offset = 0
        while offset < info.st_size:
            block = os.pread(fd, info.st_size - offset, offset)
            if not block:
                raise AssertionError("fixture publication descriptor ended early")
            digest.update(block)
            offset += len(block)
        return MODULE.AuthenticatedPublicationHandoff(
            target,
            str(path),
            identity,
            digest.hexdigest(),
        )
    finally:
        os.close(fd)


FIXED_RECEIPT_HASH = "a" * 64


def pinned_go() -> dict[str, str]:
    """The v4 receipt names Go by the reviewed pin, not by any authority."""
    tools = json.loads(Path(MODULE.PIN_MANIFEST).read_text(encoding="utf-8"))["tools"]
    return {
        "executable_sha256": tools["go"]["executable_sha256"],
        "version": tools["go"]["version"],
    }


@contextlib.contextmanager
def simulated_linux_host() -> Iterator[None]:
    """Run as a Linux host whose own bin/go pin is the receipt's Go digest.

    bin/go is pinned per host platform, so a simulated Linux host needs its
    own tools.go.executable_sha256_by_platform entry; this fixture copy of the
    reviewed pins carries one equal to the darwin measurement the fixture
    receipts name. The repository pin file is never changed.
    """
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}[platform.machine().lower()]
    document = json.loads(Path(MODULE.PIN_MANIFEST).read_text(encoding="utf-8"))
    go = document["tools"]["go"]
    go["executable_sha256_by_platform"] = {f"linux_{arch}": go["executable_sha256"]}
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / "toolchain-pins.json"
        manifest.write_text(json.dumps(document), encoding="utf-8")
        with mock.patch.object(MODULE.sys, "platform", "linux"), mock.patch.object(
            MODULE, "PIN_MANIFEST", str(manifest)
        ):
            yield


def write_claimed_output(kwargs: Mapping[str, object], payload: bytes) -> None:
    environment = kwargs.get("env", kwargs.get("environment"))
    if not isinstance(environment, dict):
        raise AssertionError("producer environment is absent")
    if (
        environment.get("WINS_FRESHNESS_OUTPUT_CONTRACT")
        != "winsvpn-exclusive-generation-path-v1"
    ):
        raise AssertionError("exclusive generation path contract is absent")
    if "WINS_FRESHNESS_OUTPUT_FD" in environment:
        raise AssertionError("incompatible precreated output descriptor was supplied")
    path = Path(str(environment["WINS_FRESHNESS_OUTPUT_PATH"]))
    if not path.is_absolute() or path.exists():
        raise AssertionError("producer destination is not a fresh absent absolute path")
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def descriptor_run_adapter(
    callback: Callable[..., object],
) -> Callable[..., object]:
    def run(
        executable: str,
        arguments: list[str],
        **kwargs: object,
    ) -> object:
        adapted = dict(kwargs)
        adapted["env"] = adapted.get("environment")
        return callback([executable, *arguments], **adapted)

    return run


def producer_receipt_stdout(
    path: Path,
    target: str,
    mutate: Optional[Callable[[dict[str, object]], None]] = None,
    post_mutate: Optional[Callable[[dict[str, object]], None]] = None,
) -> str:
    """Write the exact winsvpn-winn-core-build-v4 receipt the builder writes."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    goos = target.split("-")[1]
    goarch = target.rsplit("-", 1)[-1]
    archive_mode = target.startswith("datapath-ios") or target.startswith(
        "datapath-archive-darwin-"
    )
    package = "./cdatapath" if archive_mode else "./cmd/winn-datapath"
    record: dict[str, object] = {
        "archive_mode": archive_mode,
        "artifact": {
            "header_sha256": None,
            "output_path": str(path),
            "sha256": digest,
        },
        "contract": "winsvpn-winn-core-build-v4",
        "go": pinned_go(),
        "module_cache_tree_sha256": FIXED_RECEIPT_HASH,
        "package": package,
        "platform": {
            "compiler_path": None,
            "compiler_sha256": None,
            "id": goos,
            "ndk_version": None,
            "sdk_version": None,
        },
        "role": "datapath",
        "source_tree_sha256": FIXED_RECEIPT_HASH,
        "target": {
            "cgo_enabled": target.startswith("datapath-android-"),
            "goarch": goarch,
            "goos": goos,
            "id": target,
        },
    }
    if mutate is not None:
        mutate(record)
    if post_mutate is not None:
        post_mutate(record)
    payload = json.dumps(
        record, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    (Path(str(path) + ".receipt.json")).write_bytes((payload + "\n").encode("ascii"))
    return "WINN_BUILD_RECEIPT " + payload + "\n"


def go_uvarint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def synthetic_elf(arch: str, marker: bool = True, suffix: bytes = b"") -> bytes:
    classes = {"arm": 1, "arm64": 2, "amd64": 2}
    machines = {"arm": 40, "arm64": 183, "amd64": 62}
    elf_class = classes[arch]
    data_offset = 0x100
    payload = (MODULE.WINN_MARKER if marker else b"no-core-marker") + suffix
    body = bytearray(data_offset + len(payload))
    identity = bytearray(16)
    identity[:4] = b"\x7fELF"
    identity[4] = elf_class
    identity[5] = 1
    identity[6] = 1
    if elf_class == 1:
        header_size, program_size = 52, 32
        virtual_address = 0x10000
        struct.pack_into(
            "<16sHHIIIIIHHHHHH",
            body,
            0,
            bytes(identity),
            2,
            machines[arch],
            1,
            virtual_address + data_offset,
            header_size,
            0,
            0,
            header_size,
            program_size,
            1,
            40,
            0,
            0,
        )
        struct.pack_into(
            "<IIIIIIII",
            body,
            header_size,
            1,
            0,
            virtual_address,
            virtual_address,
            len(body),
            len(body),
            5,
            0x1000,
        )
    else:
        header_size, program_size = 64, 56
        virtual_address = 0x400000
        struct.pack_into(
            "<16sHHIQQQIHHHHHH",
            body,
            0,
            bytes(identity),
            2,
            machines[arch],
            1,
            virtual_address + data_offset,
            header_size,
            0,
            0,
            header_size,
            program_size,
            1,
            64,
            0,
            0,
        )
        struct.pack_into(
            "<IIQQQQQQ",
            body,
            header_size,
            1,
            5,
            0,
            virtual_address,
            virtual_address,
            len(body),
            len(body),
            0x1000,
        )
    body[data_offset:] = payload
    return bytes(body)


def elf_with_pt_note(identifier: bytes, note_offset: int = 0x180) -> bytes:
    description = identifier
    note = (
        struct.pack("<III", 4, len(description), 4)
        + b"Go\x00\x00"
        + description
        + b"\x00" * ((-len(description)) & 3)
    )
    body = bytearray(max(0x180, note_offset) + len(note))
    identity = bytearray(16)
    identity[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into(
        "<16sHHIQQQIHHHHHH", body, 0, bytes(identity), 2, 183, 1,
        0x400100, 64, 0, 0, 64, 56, 2, 64, 0, 0,
    )
    struct.pack_into(
        "<IIQQQQQQ", body, 64, 1, 5, 0, 0x400000, 0x400000,
        0x180, 0x180, 0x1000,
    )
    struct.pack_into(
        "<IIQQQQQQ", body, 120, 4, 4, note_offset, 0x500000, 0,
        len(note), len(note), 4,
    )
    body[0x100:0x100 + len(MODULE.WINN_MARKER)] = MODULE.WINN_MARKER
    body[note_offset:note_offset + len(note)] = note
    return bytes(body)


def elf_with_authenticated_build_id(
    identifier: bytes, *, overlapping_rodata: bool = False
) -> bytes:
    body = bytearray(elf_with_pt_note(identifier))
    note_offset = 0x180
    note_size = len(body) - note_offset
    names = b"\0.note.go.buildid\0.shstrtab\0.rodata\0"
    names_offset = len(body)
    body.extend(names)
    section_offset = (len(body) + 7) & ~7
    body.extend(b"\0" * (section_offset - len(body)))
    section_count = 4 if overlapping_rodata else 3
    body.extend(b"\0" * (section_count * 64))
    struct.pack_into("<Q", body, 40, section_offset)
    struct.pack_into("<HHH", body, 58, 64, section_count, 2)
    struct.pack_into(
        "<IIQQQQIIQQ",
        body,
        section_offset + 64,
        1,
        7,
        2,
        0x500000,
        note_offset,
        note_size,
        0,
        0,
        4,
        0,
    )
    struct.pack_into(
        "<IIQQQQIIQQ",
        body,
        section_offset + 128,
        18,
        3,
        0,
        0,
        names_offset,
        len(names),
        0,
        0,
        1,
        0,
    )
    if overlapping_rodata:
        struct.pack_into(
            "<IIQQQQIIQQ",
            body,
            section_offset + 192,
            28,
            1,
            2,
            0x500000,
            note_offset,
            note_size,
            0,
            0,
            4,
            0,
        )
    return bytes(body)


def synthetic_pe(arch: str, marker: str = "core", suffix: bytes = b"") -> bytes:
    body = bytearray(0x600)
    body[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", body, 0x3C, pe_offset)
    body[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        body,
        pe_offset + 4,
        MODULE.PE_MACHINES[arch],
        2,
        0,
        0,
        0,
        240,
        0x0022,
    )
    optional = pe_offset + 24
    struct.pack_into("<H", body, optional, 0x20B)
    struct.pack_into("<I", body, optional + 4, 0x200)
    struct.pack_into("<II", body, optional + 16, 0x1000, 0x1000)
    struct.pack_into("<Q", body, optional + 24, 0x140000000)
    struct.pack_into("<II", body, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", body, optional + 56, 0x3000)
    struct.pack_into("<I", body, optional + 60, 0x200)
    struct.pack_into("<H", body, optional + 68, 3)
    struct.pack_into("<I", body, optional + 108, 16)
    section = optional + 240
    body[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", body, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", body, section + 36, 0x60000020)
    data_section = section + 40
    body[data_section:data_section + 8] = b".data\x00\x00\x00"
    struct.pack_into("<IIII", body, data_section + 8, 0x200, 0x2000, 0x200, 0x400)
    struct.pack_into("<I", body, data_section + 36, 0xC0000040)
    role_code = {
        "core": bytes(range(1, 65)),
        "relay": bytes(range(65, 129)),
    }[marker]
    body[0x200:0x200 + len(role_code)] = role_code
    roles = {
        "core": (
            "winsvpn.local/winnprotocol/cmd/winn-datapath",
            "winsvpn.local/winnprotocol",
        ),
        "relay": (
            "winsvpn.local/winsvpnwinn3engine",
            "winsvpn.local/winsvpnwinn3engine",
        ),
    }
    path, module = roles[marker]
    module_text = (
        bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
        + f"path\t{path}\nmod\t{module}\tv0.0.0\t\n".encode("ascii")
        + bytes.fromhex("f932433186182072008242104116d8f2")
    )
    version = b"go1.27.1"
    build_info = (
        b"\xff Go buildinf:" + bytes((8, 2)) + b"\x00" * 16
        + bytes((len(version),)) + version
        + go_uvarint(len(module_text)) + module_text
    )
    body[0x400:0x400 + len(build_info)] = build_info
    body[0x400 + len(build_info):0x400 + len(build_info) + len(suffix)] = suffix
    return bytes(body)


def synthetic_macho(
    arch: str,
    platform_name: str,
    filetype: int = 6,
    symbols: bool = True,
    suffix: bytes = b"",
) -> bytes:
    exported = list(MODULE.APPLE_REQUIRED_SYMBOLS) if symbols else [b"WinnTunnelCreateWinn3"]
    if arch == "arm64":
        function = bytes.fromhex("1f2003d5c0035fd6")
    else:
        function = bytes.fromhex("554889e531c05dc3")
    role_code = b"".join(
        function + bytes((index + 1, 0, 0, 0, 0, 0, 0, 0))
        for index in range(len(exported))
    )
    payload = role_code
    if symbols:
        payload += MODULE.WINN_MARKER
    payload += suffix or bytes(range(1, 129))
    strings = bytearray(b"\x00")
    records = bytearray()
    for symbol in exported:
        string_at = len(strings)
        strings.extend(b"_" + symbol + b"\x00")
        records.extend(struct.pack("<IBBHQ", string_at, 0x0F, 1, 0, 0))
    dylib_command = b""
    if filetype == 6:
        dylib_name = b"fixture.dylib\x00"
        dylib_size = (24 + len(dylib_name) + 7) & ~7
        dylib_command = (
            struct.pack("<6I", 0xD, dylib_size, 24, 0, 0, 0)
            + dylib_name
            + b"\x00" * (dylib_size - 24 - len(dylib_name))
        )
    segment_size = 72 + 80
    command_size = segment_size + 24 + 24 + len(dylib_command)
    content_offset = 32 + command_size
    symbol_offset = content_offset + len(payload)
    strings_offset = symbol_offset + len(records)
    total_size = strings_offset + len(strings)
    segment_name = b"__TEXT" if filetype == 6 else b""
    segment_name = segment_name.ljust(16, b"\x00")
    section_segment = b"__TEXT".ljust(16, b"\x00")
    if filetype == 6:
        virtual_address, virtual_size = 0x100000000, total_size
        file_offset, file_size, initial_protection = 0, total_size, 5
        section_address = virtual_address + content_offset
    else:
        virtual_address, virtual_size = 0, len(payload)
        file_offset, file_size, initial_protection = content_offset, len(payload), 7
        section_address = 0
    symbol_stride = 16
    for index in range(len(exported)):
        struct.pack_into(
            "<Q", records, index * 16 + 8,
            (section_address or symbol_stride) + index * symbol_stride,
        )
    segment = struct.pack(
        "<2I16s4Q4I",
        0x19,
        segment_size,
        segment_name,
        virtual_address,
        virtual_size,
        file_offset,
        file_size,
        7,
        initial_protection,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text".ljust(16, b"\x00"),
        section_segment,
        section_address,
        len(payload),
        content_offset,
        0,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    build_version = struct.pack(
        "<6I", 0x32, 24, MODULE.MACHO_PLATFORMS[platform_name], 0, 0, 0
    )
    symbol_command = struct.pack(
        "<6I", 0x2, 24, symbol_offset, len(exported), strings_offset, len(strings)
    )
    header = struct.pack(
        "<8I",
        0xFEEDFACF,
        MODULE.MACHO_CPUS[arch],
        0,
        filetype,
        4 if filetype == 6 else 3,
        command_size,
        0,
        0,
    )
    return (
        header + segment + section + build_version + symbol_command
        + dylib_command + payload + bytes(records) + bytes(strings)
    )


def synthetic_fat_macho(
    arches: tuple[str, ...], platform_name: str, filetype: int = 6
) -> bytes:
    slices = [synthetic_macho(arch, platform_name, filetype=filetype) for arch in arches]
    offset = 8 + 20 * len(slices)
    records = []
    for arch, payload in zip(arches, slices):
        records.append(struct.pack(">5I", MODULE.MACHO_CPUS[arch], 0, offset, len(payload), 0))
        offset += len(payload)
    return struct.pack(">2I", 0xCAFEBABE, len(slices)) + b"".join(records) + b"".join(slices)


def ar_member(name: str, payload: bytes) -> bytes:
    name_bytes = name.encode("ascii") + b"\x00"
    stored = name_bytes + payload
    header = bytearray(b" " * 60)
    header[:16] = ("#1/" + str(len(name_bytes))).ljust(16).encode("ascii")
    header[16:28] = b"0".ljust(12)
    header[28:34] = b"0".ljust(6)
    header[34:40] = b"0".ljust(6)
    header[40:48] = b"100644".ljust(8)
    header[48:58] = str(len(stored)).ljust(10).encode("ascii")
    header[58:60] = bytes((0x60, 0x0A))
    return bytes(header) + stored + (b"\n" if len(stored) & 1 else b"")


def synthetic_archive(arch: str, platform_name: str) -> bytes:
    build_id = b'\xff Go build ID: "action/contenthash"\n \xff'
    object_payload = synthetic_macho(
        arch,
        platform_name,
        filetype=1,
        symbols=False,
        suffix=build_id + MODULE.WINN_MARKER + b"WinnTunnelCreateWinn3",
    )
    symbol_strings = b"_WinnTunnelCreateWinn3\x00"
    placeholder = struct.pack("<I", 8) + struct.pack("<II", 0, 8) + struct.pack(
        "<I", len(symbol_strings)
    ) + symbol_strings
    symbol_bytes = ar_member("__.SYMDEF SORTED", placeholder)
    go_header_offset = len(MODULE.AR_MAGIC) + len(symbol_bytes)
    symbol_payload = struct.pack("<I", 8) + struct.pack(
        "<II", 0, go_header_offset
    ) + struct.pack("<I", len(symbol_strings)) + symbol_strings
    symbol_bytes = ar_member("__.SYMDEF SORTED", symbol_payload)
    return MODULE.AR_MAGIC + symbol_bytes + ar_member("go.o", object_payload)


def protobuf_varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def protobuf_bytes(number: int, payload: bytes) -> bytes:
    return protobuf_varint(number << 3 | 2) + protobuf_varint(len(payload)) + payload


def protobuf_integer(number: int, value: int) -> bytes:
    return protobuf_varint(number << 3) + protobuf_varint(value)


def android_string_pool(strings: tuple[str, ...]) -> bytes:
    offsets: list[int] = []
    encoded = bytearray()
    for value in strings:
        payload = value.encode("utf-8")
        if len(value) >= 0x80 or len(payload) >= 0x80:
            raise AssertionError("fixture string is too long")
        offsets.append(len(encoded))
        encoded.extend((len(value), len(payload)))
        encoded.extend(payload)
        encoded.append(0)
    while len(encoded) & 3:
        encoded.append(0)
    header_size = 28
    strings_start = header_size + 4 * len(offsets)
    chunk_size = strings_start + len(encoded)
    header = struct.pack(
        "<HHI5I",
        0x0001,
        header_size,
        chunk_size,
        len(offsets),
        0,
        0x00000100,
        strings_start,
        0,
    )
    return header + b"".join(struct.pack("<I", offset) for offset in offsets) + bytes(encoded)


def binary_android_manifest(
    package: str = "org.winsvpn.app",
    application: str = "android.app.Application",
) -> bytes:
    android_namespace = "http://schemas.android.com/apk/res/android"
    values = (
        "manifest", "package", package, "application",
        android_namespace, "name", application,
    )
    strings = android_string_pool(values)

    def start_element(name: int, attributes: tuple[tuple[int, int, int], ...]) -> bytes:
        records = b"".join(
            struct.pack("<IIIHBBI", namespace, key, value, 8, 0, 0x03, value)
            for namespace, key, value in attributes
        )
        size = 36 + len(records)
        return (
            struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF)
            + struct.pack(
                "<II6H", 0xFFFFFFFF, name, 20, 20, len(attributes), 0, 0, 0
            )
            + records
        )

    def end_element(name: int) -> bytes:
        return (
            struct.pack("<HHIII", 0x0103, 16, 24, 1, 0xFFFFFFFF)
            + struct.pack("<II", 0xFFFFFFFF, name)
        )

    chunks = (
        start_element(0, ((0xFFFFFFFF, 1, 2),)),
        start_element(3, ((4, 5, 6),)),
        end_element(3),
        end_element(0),
    )
    size = 8 + len(strings) + sum(len(chunk) for chunk in chunks)
    return struct.pack("<HHI", 0x0003, 8, size) + strings + b"".join(chunks)


def binary_android_resources() -> bytes:
    global_strings = android_string_pool(())
    type_strings = android_string_pool(())
    key_strings = android_string_pool(())
    package_header_size = 288
    package_size = package_header_size + len(type_strings) + len(key_strings)
    package = bytearray(package_header_size)
    struct.pack_into("<HHI", package, 0, 0x0200, package_header_size, package_size)
    struct.pack_into("<I", package, 8, 0x7F)
    package_name = "com.example.fixture".encode("utf-16le")
    package[12:12 + len(package_name)] = package_name
    struct.pack_into("<I", package, 268, package_header_size)
    struct.pack_into("<I", package, 276, package_header_size + len(type_strings))
    body = global_strings + bytes(package) + type_strings + key_strings
    return struct.pack("<HHII", 0x0002, 12, 12 + len(body), 1) + body


def bundle_config_proto() -> bytes:
    return protobuf_bytes(1, protobuf_bytes(2, b"1.18.2"))


def aab_manifest_proto(
    package: str = "org.winsvpn.app",
    application: str = "android.app.Application",
) -> bytes:
    package_attribute = protobuf_bytes(2, b"package") + protobuf_bytes(
        3, package.encode("ascii")
    )
    application_attribute = (
        protobuf_bytes(1, b"http://schemas.android.com/apk/res/android")
        + protobuf_bytes(2, b"name")
        + protobuf_bytes(3, application.encode("ascii"))
    )
    application_element = (
        protobuf_bytes(3, b"application")
        + protobuf_bytes(4, application_attribute)
    )
    child = protobuf_bytes(1, application_element)
    element = (
        protobuf_bytes(3, b"manifest")
        + protobuf_bytes(4, package_attribute)
        + protobuf_bytes(5, child)
    )
    return protobuf_bytes(1, element)


def aab_resources_proto() -> bytes:
    package_id = protobuf_integer(1, 0x7F)
    package = protobuf_bytes(1, package_id) + protobuf_bytes(
        2, b"com.example.fixture"
    )
    return protobuf_bytes(2, package)


def minimal_dex() -> bytes:
    payload = bytearray(0x8C)
    payload[:8] = b"dex\n035\x00"
    struct.pack_into("<III", payload, 32, len(payload), 0x70, 0x12345678)
    struct.pack_into("<III", payload, 44, 0, 0, 0x70)
    struct.pack_into("<II", payload, 104, 0x1C, 0x70)
    struct.pack_into("<I", payload, 0x70, 2)
    struct.pack_into("<HHII", payload, 0x74, 0x0000, 0, 1, 0)
    struct.pack_into("<HHII", payload, 0x80, 0x1000, 0, 1, 0x70)
    payload[12:32] = hashlib.sha1(payload[32:]).digest()
    struct.pack_into("<I", payload, 8, zlib.adler32(payload[12:]) & 0xFFFFFFFF)
    return bytes(payload)


def write_android_package(path: Path, payloads: dict[str, bytes], prefix: str = "") -> None:
    package_name = (
        "org.winsvpn.devicecheck"
        if "android/devicecheck/" in path.as_posix()
        else "org.winsvpn.app"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as package:
        if prefix == "base/" or path.suffix == ".aab":
            package.writestr("BundleConfig.pb", bundle_config_proto())
            package.writestr(
                "base/manifest/AndroidManifest.xml",
                aab_manifest_proto(package_name),
            )
            package.writestr("base/resources.pb", aab_resources_proto())
            package.writestr("base/dex/classes.dex", minimal_dex())
        else:
            package.writestr(
                "AndroidManifest.xml", binary_android_manifest(package_name)
            )
            package.writestr("resources.arsc", binary_android_resources())
            package.writestr("classes.dex", minimal_dex())
        for abi, payload in payloads.items():
            package.writestr(f"{prefix}lib/{abi}/libwinnengine.so", payload)
        package.writestr("assets/ordinary-file", b"ordinary")


def write_linux_tar(path: Path, payload: bytes, name: str = "winn-datapath") -> None:
    with tarfile.open(path, "w:gz") as package:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        info.mode = 0o755
        package.addfile(info, io.BytesIO(payload))


RETIRED_RELEASE_GO_ENV = (
    "WINS_GO_CUSTODY_ISSUANCE",
    "WINS_RELEASE_GO_SHA256",
    "WINS_RELEASE_GO_TREE_SHA256",
    "WINS_RELEASE_GO_RUNTIME",
    "WINS_RELEASE_GO_RUNTIME_ID",
    "WINS_RELEASE_GO_ROOT",
)


class ReviewedGoFixture:
    """A pinned Go root, its pins and a sealed module cache, all caller-owned.

    Nothing here is root-owned, immutable or under /Library: the pins and the
    sealed digests are the whole authority.
    """

    def __init__(self, root: Path, reported_version: str = "1.27.1") -> None:
        self.root = root
        self.go_root = root / "go1.27.1"
        self.binary = self.go_root / "bin" / "go"
        self.manifest = root / "toolchain-pins.json"
        self.module_cache = root / "gomodcache"
        self.go_root.mkdir(mode=0o700)
        self.binary.parent.mkdir(mode=0o700)
        module = self.module_cache / "example.com" / "dep@v1.0.0"
        module.mkdir(parents=True, mode=0o700)
        (module / "go.mod").write_text("module example.com/dep\n", encoding="ascii")
        (module / "go.mod").chmod(0o400)
        for directory in (module, module.parent, self.module_cache):
            directory.chmod(0o500)
        host_os = {"darwin": "darwin", "linux": "linux"}[sys.platform]
        host_arch = {
            "arm64": "arm64",
            "aarch64": "arm64",
            "x86_64": "amd64",
        }[platform.machine().lower()]
        self.host_key = f"{host_os}_{host_arch}"
        self.identity = f"go version go1.27.1 {host_os}/{host_arch}"
        reported = f"go version go{reported_version} {host_os}/{host_arch}"
        self.binary.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = version ]; then\n"
            f"  printf '%s\\n' '{reported}'\n"
            "  exit 0\n"
            "fi\n"
            "exit 17\n",
            encoding="ascii",
        )
        self.binary.chmod(0o700)
        tree_sha = MODULE._reviewed_tree_hash(str(self.go_root))
        self.manifest.write_text(
            json.dumps(
                {
                    "tools": {
                        "go": {
                            "version": "1.27.1",
                            "executable": "bin/go",
                            "executable_sha256": sha256(self.binary),
                            "install_tree_sha256": {self.host_key: tree_sha},
                            "archive_sha256": {self.host_key: "a" * 64},
                        }
                    }
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )

    def cache_digest(self) -> str:
        driver = Path(MODULE.REPO_ROOT) / "tools" / "winn_release.py"
        completed = subprocess.run(
            ["/usr/bin/python3", "-I", str(driver), "digest", "--kind", "sealed",
             str(self.module_cache)],
            capture_output=True, text=True, timeout=60, check=True,
        )
        return completed.stdout.strip()

    def environment(self, **overrides: str) -> dict[str, str]:
        environment = {
            "WINS_FRESHNESS_GO_ROOT": str(self.go_root),
            "WINS_STORE_GOMODCACHE": str(self.module_cache),
            "PATH": str(self.root / "hostile-path"),
        }
        environment.update(overrides)
        if "WINS_STORE_GOMODCACHE_TREE_SHA256" not in environment:
            environment["WINS_STORE_GOMODCACHE_TREE_SHA256"] = self.cache_digest()
        return environment

    def authenticate(self, **overrides: str) -> object:
        with mock.patch.object(MODULE, "PIN_MANIFEST", str(self.manifest)), mock.patch.dict(
            os.environ, self.environment(**overrides), clear=False,
        ):
            # The retired ReleaseGo custody inputs must not be needed; drop
            # any the person running the suite happens to have exported.
            for retired in RETIRED_RELEASE_GO_ENV:
                os.environ.pop(retired, None)
            return MODULE.authenticate_reviewed_go()

    def unseal(self) -> None:
        for directory, _dirs, _files in os.walk(self.module_cache):
            os.chmod(directory, 0o700)


class ShippedFreshnessCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        # Fixture snapshots are not sealed trees; the builder would measure
        # them itself, so a fixed digest stands in for that measurement.
        sealed = mock.patch.object(
            MODULE, "_sealed_tree_digest", return_value=FIXED_RECEIPT_HASH
        )
        sealed.start()
        self.addCleanup(sealed.stop)

    def test_global_inventory_has_all_platform_surfaces(self) -> None:
        inventory = MODULE.SHIPPED
        self.assertEqual(
            len([item for item in inventory if item.group == "android" and item.kind == "raw"]),
            10,
        )
        self.assertEqual(
            len([item for item in inventory if item.group == "android" and item.kind == "android-package"]),
            20,
        )
        self.assertEqual(
            len([item for item in inventory if item.group == "android" and item.kind == "elf"]),
            6,
        )
        self.assertEqual(
            {item.path for item in inventory if item.group == "apple"},
            {
                "tools/winn_conformance_build_out/libwinn-datapath-darwin-arm64.a",
                "tools/winn_conformance_build_out/libwinn-datapath-darwin-amd64.a",
                "tools/winn_conformance_build_out/libwinn-datapath-ios-arm64.a",
                "tools/winn_conformance_build_out/libwinn-datapath-iossimulator-arm64.a",
                "tools/winn_conformance_build_out/libwinn-datapath-iossimulator-amd64.a",
                "apple/EngineArtifacts/ios/iphoneos/libWinsWinnPacketEngine.dylib",
                "apple/EngineArtifacts/ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
                "apple/EngineArtifacts/macos/libWinsWinnPacketEngine.dylib",
            },
        )
        windows = [item for item in inventory if item.group == "windows"]
        self.assertEqual(len(windows), 4)
        self.assertEqual(
            {item.path for item in windows},
            {
                "build/windows/winn3/x64/winn-datapath.exe",
                "build/windows/winn3/x64/winsvpn_winn3_engine.exe",
                "build/windows/winn3/arm64/winn-datapath.exe",
                "build/windows/winn3/arm64/winsvpn_winn3_engine.exe",
            },
        )
        self.assertEqual(
            {(item.role, item.arch) for item in windows},
            {("core", "amd64"), ("core", "arm64"), ("relay", "amd64"), ("relay", "arm64")},
        )
        self.assertEqual(
            {item.path for item in inventory if item.group == "linux"},
            {
                "build/linux/x64/release/bundle/winn-datapath",
                "build/linux/arm64/release/bundle/winn-datapath",
                "web/downloads/wins-vpn-linux-x64.tar.gz",
                "web/downloads/wins-vpn-linux-arm64.tar.gz",
            },
        )
        self.assertEqual(
            {(item.arch, item.member) for item in inventory if item.group == "linux"},
            {
                ("amd64", ""),
                ("arm64", ""),
                ("amd64", "winn-datapath"),
                ("arm64", "winn-datapath"),
            },
        )
        packaging_consumer = (
            ROOT / "tools/validate_release_artifact_privacy.py"
        ).read_text(encoding="ascii")
        consumer_packages = {
            path
            for role, path in re.findall(
                r'"(linux-(?:x64|arm64)-package)": "([^"]+)"',
                packaging_consumer,
            )
            if role in {"linux-x64-package", "linux-arm64-package"}
        }
        self.assertEqual(
            {item.path for item in inventory if item.kind == "linux-package"},
            consumer_packages,
        )
        consumer_android = {
            path
            for role, path in re.findall(
                r'"(android-(?:phone-tablet|tv)-(?:apk|aab))": "([^"]+)"',
                packaging_consumer,
            )
        }
        self.assertTrue(
            consumer_android.issubset(
                {
                    item.path
                    for item in inventory
                    if item.group == "android" and item.kind == "android-package"
                }
            )
        )

    def test_android_inventory_carries_staged_qa_and_package_roles(self) -> None:
        packages = MODULE._android_package_artifacts()
        self.assertEqual(len(packages), 18)
        self.assertEqual(
            {item.path for item in packages},
            {
                "build/app/outputs/flutter-apk/app-phone-release.apk",
                "build/app/outputs/bundle/phoneRelease/app-phone-release.aab",
                "build/app/outputs/flutter-apk/app-tv-release.apk",
                "build/app/outputs/bundle/tvRelease/app-tv-release.aab",
                "build/app/outputs/flutter-apk/app-release.apk",
                "build/app/outputs/bundle/release/app-release.aab",
            },
        )
        self.assertEqual(
            {
                item.path
                for item in MODULE.SHIPPED
                if item.group == "android" and item.kind == "android-package"
            }
            - {item.path for item in packages},
            {
                "android/devicecheck/app/build/outputs/apk/debug/app-debug.apk",
                "android/devicecheck/app/build/outputs/apk/release/app-release.apk",
            },
        )
        with mock.patch.object(MODULE, "_validate_consumer_authority_manifests"):
            self.assertEqual(
                set(MODULE._independent_consumer_inventory_paths()),
                {item.path for item in MODULE.SHIPPED}
                - {path for path, _ in MODULE.ANDROID_QA_NATIVE_PATHS},
            )
            self.assertIs(MODULE.inventory(), MODULE.SHIPPED)

    def test_inventory_rejects_independent_consumer_or_declaration_drift(self) -> None:
        declared = {item.path for item in MODULE.SHIPPED}
        consumers = declared - {path for path, _ in MODULE.ANDROID_QA_NATIVE_PATHS}
        with mock.patch.object(
            MODULE,
            "_independent_consumer_inventory_paths",
            return_value=frozenset(consumers | {"build/hostile/new-consumer.bin"}),
        ):
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "undeclared consumers.*new-consumer"
            ):
                MODULE.inventory()
        omitted = next(iter(consumers))
        with mock.patch.object(
            MODULE,
            "_independent_consumer_inventory_paths",
            return_value=frozenset(consumers - {omitted}),
        ):
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "declarations absent from consumers"
            ):
                MODULE.inventory()

    def test_self_check_declares_every_host_required_target_explicitly(self) -> None:
        declared = {target for target, _, _ in MODULE._self_check_pairs()}
        if sys.platform == "darwin":
            expected = {
                "datapath-linux-amd64", "datapath-linux-arm64",
                "datapath-windows-amd64", "datapath-windows-arm64",
                "relay-windows-amd64", "relay-windows-arm64",
                "datapath-android-arm64", "datapath-android-arm",
                "datapath-android-amd64",
                "datapath-archive-darwin-arm64",
                "datapath-archive-darwin-amd64", "datapath-ios-arm64",
                "datapath-iossimulator-arm64",
                "datapath-iossimulator-amd64",
                "apple-wrapper-iphoneos",
                "apple-wrapper-iphonesimulator", "apple-wrapper-macosx",
            }
        elif sys.platform.startswith("linux"):
            expected = {
                "datapath-linux-amd64", "datapath-linux-arm64",
                "datapath-windows-amd64", "datapath-windows-arm64",
                "relay-windows-amd64", "relay-windows-arm64",
                "datapath-android-arm64", "datapath-android-arm",
                "datapath-android-amd64",
            }
        else:
            expected = set()
        self.assertEqual(declared, expected)
        self.assertEqual(len(declared), len(MODULE._self_check_pairs()))

    def test_inventory_rejects_metadata_drift_with_the_same_path(self) -> None:
        with mock.patch.object(MODULE, "_validate_consumer_authority_manifests"):
            independent = list(MODULE._independent_consumer_inventory())
        changed = list(independent)
        first = changed[0]
        changed[0] = MODULE.Artifact(
            first.path,
            first.target,
            first.group,
            first.why,
            kind=first.kind,
            role=first.role,
            arch="hostile-arch",
            member=first.member,
            platform=first.platform,
            closure=first.closure,
        )
        with mock.patch.object(
            MODULE, "_independent_consumer_inventory", return_value=tuple(changed)
        ):
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "metadata mismatch.*hostile-arch"
            ):
                MODULE.inventory()

    def test_inventory_cannot_self_authorize_a_shared_omission(self) -> None:
        with mock.patch.object(MODULE, "_validate_consumer_authority_manifests"):
            independent = list(MODULE._independent_consumer_inventory())
        omitted_path = independent[0].path
        declared = tuple(item for item in MODULE.SHIPPED if item.path != omitted_path)
        consumers = tuple(item for item in independent if item.path != omitted_path)
        with mock.patch.object(MODULE, "SHIPPED", declared), mock.patch.object(
            MODULE, "_independent_consumer_inventory", return_value=consumers
        ):
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "fixed consumer authority.*missing="
            ):
                MODULE.inventory()

    def test_manifest_discovery_rejects_hidden_stale_windows_consumer(self) -> None:
        canonical = "\n".join(
            f"build/windows/winn3/{arch}/{name}.exe"
            for arch in ("x64", "arm64")
            for name in ("winn-datapath", "winsvpn_winn3_engine")
        )
        linux_candidate = json.dumps(
            {
                "required_upload_targets": [
                    "linux-x64-package", "linux-arm64-package"
                ],
                "deb": MODULE.LINUX_DEB_NON_UPLOAD,
            }
        )
        sources = {
            "tools/producer.sh": canonical,
            MODULE.LINUX_RELEASE_CANDIDATE: linux_candidate,
            "installer/windows/hidden-staging.json": (
                canonical
                + "\nbuild/windows/x64/runner/Release/winn-datapath.exe\n"
            ),
        }
        with mock.patch.object(
            MODULE, "_consumer_authority_files", return_value=tuple(sources)
        ), mock.patch.object(
            MODULE, "_consumer_source", side_effect=lambda relative: sources[relative]
        ):
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "stale Windows native consumer"
            ):
                MODULE._validate_consumer_authority_manifests()

        sources = {
            "tools/producer.sh": canonical,
            MODULE.LINUX_RELEASE_CANDIDATE: linux_candidate,
        }
        with mock.patch.object(
            MODULE, "_consumer_authority_files", return_value=tuple(sources)
        ), mock.patch.object(
            MODULE, "_consumer_source", side_effect=lambda relative: sources[relative]
        ):
            MODULE._validate_consumer_authority_manifests()

    def test_current_inventory_reconciles_windows_consumers(
        self,
    ) -> None:
        items = MODULE.inventory()
        self.assertEqual(len(items), 52)
        windows_items = [item for item in items if item.group == "windows"]
        self.assertEqual(len(windows_items), 4)

    def test_linux_debian_inventory_is_exact_and_explicitly_not_uploaded(self) -> None:
        candidate = json.loads(
            (ROOT / MODULE.LINUX_RELEASE_CANDIDATE).read_text(encoding="utf-8")
        )
        self.assertEqual(candidate["deb"], MODULE.LINUX_DEB_NON_UPLOAD)
        self.assertFalse(candidate["deb"]["upload_target"])
        self.assertFalse(candidate["deb"]["produced"])
        self.assertFalse(candidate["deb"]["upload_performed"])
        self.assertFalse(candidate["deb"]["publication_authorized"])
        self.assertNotIn("deb", " ".join(candidate["required_upload_targets"]).lower())

    def test_retired_windows_owner_gate_is_absent(self) -> None:
        for retired in (
            "tools/build_macos_windows_winn3_ledger_bootstrap.sh",
            "tools/build_windows_winn3_fixed_loader.sh",
            "tools/macos_windows_winn3_ledger_bootstrap.c",
            "tools/produce_windows_winn3_artifacts.sh",
            "tools/test_macos_windows_winn3_ledger_bootstrap.py",
            "tools/test_produce_windows_winn3_artifacts.py",
            "tools/test_windows_winn3_artifact_custody.py",
            "tools/test_windows_winn3_fixed_loader.py",
            "tools/test_windows_winn3_owner_authorization.py",
            "tools/test_windows_winn3_producer_witness.py",
            "tools/test_windows_winn3_release_python_custody.py",
            "tools/test_winn3_authorization_ledger.py",
            "tools/windows_winn3_fixed_loader.c",
            "tools/windows_winn3_owner_authorization.py",
            "tools/windows_winn3_owner_authorization.trust.json",
            "tools/windows_winn3_producer_witness.py",
            "tools/windows_winn3_release_python_custody.py",
            "tools/winn3_authorization_ledger.py",
        ):
            self.assertFalse((ROOT / retired).exists(), retired)
        for name in (
            "WINDOWS_TRUST",
            "WINDOWS_AUTHORITY",
            "WINDOWS_OWNER_AUTHORIZATIONS",
            "WINDOWS_PRODUCER_RECEIPTS",
            "WINDOWS_SOURCE_BINDINGS",
            "WINDOWS_CONSUMPTION_LEDGER_CONTRACT",
            "AuthenticatedProducerReceipt",
            "_verify_windows_owner_authorization",
            "_consume_windows_owner_authorization_once",
        ):
            self.assertFalse(hasattr(MODULE, name), name)
        source = (ROOT / "tools/verify_shipped_native_artifact_freshness.py").read_text(
            encoding="utf-8"
        )
        for dropped in (
            "ReleaseWindowsWinn3Authority",
            "windows_winn3_owner_authorization",
            "produce_windows_winn3_artifacts",
            "winn3_authorization_ledger",
        ):
            self.assertNotIn(dropped, source)

    def test_exact_go_list_closure_excludes_unrelated_tests_and_binds_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "module"
            dependency = root / "gomodcache" / "example.com" / "dep@v1.0.0"
            source.mkdir()
            dependency.mkdir(parents=True)
            (source / "go.mod").write_text("module example.com/main\n", encoding="ascii")
            (source / "go.sum").write_text("example.com/dep v1.0.0 h1:x\n", encoding="ascii")
            (source / "main.go").write_text("package main\n", encoding="ascii")
            (source / "helper.go").write_text("package main\n", encoding="ascii")
            (source / "unrelated_test.go").write_text("package main\n", encoding="ascii")
            (source / "spike.go").write_text("package spike\n", encoding="ascii")
            (dependency / "go.mod").write_text("module example.com/dep\n", encoding="ascii")
            (dependency / "dep.go").write_text("package dep\n", encoding="ascii")
            reviewed = mock.Mock(gomodcache=str(root / "gomodcache"))
            packages = [
                {
                    "ImportPath": "example.com/main",
                    "Dir": str(source),
                    "GoFiles": ["main.go"],
                    "Module": {
                        "Path": "example.com/main",
                        "Main": True,
                        "GoMod": str(source / "go.mod"),
                    },
                },
                {
                    "ImportPath": "example.com/dep",
                    "Dir": str(dependency),
                    "GoFiles": ["dep.go"],
                    "Module": {
                        "Path": "example.com/dep",
                        "Version": "v1.0.0",
                        "GoMod": str(dependency / "go.mod"),
                    },
                },
            ]
            with mock.patch.object(MODULE, "MODULE_DIR", str(source)), mock.patch.object(
                MODULE, "RELAY_MODULE_DIR", str(root / "relay")
            ):
                sources, dependencies, modules = MODULE._go_list_paths(packages, reviewed)
                packages[0]["GoFiles"] = ["main.go", "helper.go"]
                drifted_sources, _, _ = MODULE._go_list_paths(packages, reviewed)
            self.assertEqual(
                sources,
                {str(source / "main.go"), str(source / "go.mod"), str(source / "go.sum")},
            )
            self.assertNotIn(str(source / "unrelated_test.go"), sources)
            self.assertNotIn(str(source / "spike.go"), sources)
            self.assertEqual(
                dependencies,
                {str(dependency / "dep.go"), str(dependency / "go.mod")},
            )
            self.assertEqual(modules, {"example.com/main", "example.com/dep@v1.0.0"})
            self.assertEqual(drifted_sources - sources, {str(source / "helper.go")})

    def test_retained_created_file_detects_path_swap_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            retained = root / "retained-go"
            parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            fd = os.open(
                retained.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            custody = MODULE.DescriptorCustody(
                "retained creation test", MODULE.CustodyUnavailable
            )
            try:
                node = custody.adopt_created_file(str(retained), fd)
                fd = -1
                os.write(node.fd, b"reviewed bytes")
                os.fchmod(node.fd, 0o400)
                custody.seal_created_file(str(retained))
                saved = root / "retained-go.saved"
                retained.rename(saved)
                retained.write_bytes(b"substitute")
                retained.unlink()
                saved.rename(retained)
                self.assertEqual(os.pread(node.fd, 1024, 0), b"reviewed bytes")
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable, "descriptor (?:identity changed|mutation event)"
                ):
                    custody.verify()
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(parent_fd)
                custody.close()

    @unittest.skipUnless(sys.platform == "darwin", "Darwin vnode seal baseline")
    def test_darwin_seal_does_not_report_the_producer_write_as_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "producer-output"
            parent_fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            fd = os.open(
                path.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            custody = MODULE.DescriptorCustody(
                "Darwin producer self-event test", MODULE.CustodyUnavailable
            )
            try:
                node = custody.adopt_created_file(str(path), fd)
                fd = -1
                os.write(node.fd, b"producer bytes")
                os.fsync(node.fd)
                os.fchmod(node.fd, 0o400)
                custody.verify_created_file_path(str(path))
                custody.seal_created_file(str(path))
                custody.verify()
                os.chmod(path, 0o600)
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable, "descriptor (?:identity changed|mutation event)"
                ):
                    custody.verify()
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(parent_fd)
                custody.close()

    def test_seal_preserves_an_existing_active_output_watch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "producer-output"
            path.write_bytes(b"published bytes")
            custody = MODULE.DescriptorCustody(
                "existing output watch test", MODULE.CustodyUnavailable
            )
            try:
                node = custody.bind_file(str(path))
                with mock.patch.object(custody, "_watch_node") as watch, mock.patch.object(
                    custody, "_enable_node_watch"
                ) as enable:
                    custody.seal_created_file(str(path))
                watch.assert_not_called()
                enable.assert_not_called()
                self.assertEqual(
                    custody._nodes[custody._canonical(str(path))].fd, node.fd
                )
            finally:
                custody.close()

    def test_seal_revalidates_after_installing_a_new_file_watch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "producer-output"
            parent_fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            fd = os.open(
                path.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            custody = MODULE.DescriptorCustody(
                "pre-watch mutation test", MODULE.CustodyUnavailable
            )
            try:
                if custody._event_queue is not None:
                    custody._event_queue.close()
                    custody._event_queue = None
                if custody._inotify_fd >= 0:
                    os.close(custody._inotify_fd)
                    custody._inotify_fd = -1
                node = custody.adopt_created_file(str(path), fd)
                fd = -1
                os.write(node.fd, b"producer bytes")
                original_watch = custody._watch_node

                def mutate_during_watch(*args: object, **kwargs: object) -> None:
                    with path.open("r+b") as handle:
                        handle.seek(0)
                        handle.write(b"hostile bytes")
                        handle.flush()
                        os.fsync(handle.fileno())
                    original_watch(*args, **kwargs)

                with mock.patch.object(custody, "_watch_node", side_effect=mutate_during_watch):
                    with self.assertRaisesRegex(
                        MODULE.CustodyUnavailable, "changed while sealing"
                    ):
                        custody.seal_created_file(str(path))
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(parent_fd)
                custody.close()

    def test_go_output_uses_fresh_exclusive_path_and_rejects_substitution(self) -> None:
        for mode in ("exclusive", "replace-after-receipt", "stale-hardlink"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                output_dir = Path(tmp) / "output"
                reviewed = mock.Mock()
                reviewed.build_environment.return_value = {}
                reviewed.pass_fds.return_value = ()
                closure = mock.Mock(snapshot_root=tmp)
                closure.path.side_effect = lambda path: path
                closure.retained_fd.return_value = 123
                closure.retained_root_fd.return_value = 124
                closure.retained_root_fd.return_value = 124

                def substitute(command: list[str], **kwargs: object) -> object:
                    output = Path(command[-1])
                    self.assertFalse(output.exists())
                    if mode == "exclusive":
                        write_claimed_output(kwargs, b"exclusive Go -o bytes")
                        receipt = producer_receipt_stdout(output, command[-2])
                    elif mode == "replace-after-receipt":
                        write_claimed_output(kwargs, b"receipt-bound bytes")
                        receipt = producer_receipt_stdout(output, command[-2])
                        output.unlink()
                        output.write_bytes(b"hostile replacement bytes")
                    else:
                        stale = Path(tmp) / "stale-artifact"
                        stale.write_bytes(b"stale relabel candidate")
                        os.link(stale, output)
                        receipt = producer_receipt_stdout(output, command[-2])
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        receipt,
                        "",
                    )

                with simulated_linux_host(), mock.patch.object(
                    MODULE,
                    "_run_system_descriptor",
                    side_effect=descriptor_run_adapter(substitute),
                ):
                    ok, output, log = MODULE.build_reference(
                        "datapath-linux-arm64",
                        "libwinnengine.so",
                        str(output_dir),
                        reviewed,
                        closure,
                    )
                if mode == "exclusive":
                    self.assertTrue(ok, log)
                    self.assertIsNotNone(output)
                    assert output is not None
                    output.close()
                else:
                    self.assertFalse(ok)
                    self.assertIsNone(output)
                    self.assertRegex(
                        log,
                        r"exclusive producer publication|unsafe|differs from its fresh",
                    )

    def test_publication_replaced_after_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "output"
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            reviewed.pass_fds.return_value = ()
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            closure.retained_fd.return_value = 123
            closure.retained_root_fd.return_value = 124

            def publish_then_replace(command: list[str], **kwargs: object) -> object:
                output = Path(command[-1])
                write_claimed_output(kwargs, b"receipt publication")
                receipt = producer_receipt_stdout(output, command[-2])
                output.unlink()
                output.write_bytes(b"second unreceipted publication")
                return subprocess.CompletedProcess(
                    command, 0, receipt, ""
                )

            with simulated_linux_host(), mock.patch.object(
                MODULE,
                "_run_system_descriptor",
                side_effect=descriptor_run_adapter(publish_then_replace),
            ):
                ok, output, log = MODULE.build_reference(
                    "datapath-linux-arm64", "engine", str(output_dir), reviewed, closure
                )
            self.assertFalse(ok)
            self.assertIsNone(output)
            self.assertRegex(
                log, r"exclusive producer publication|differs from its fresh"
            )

    def test_receipt_material_substitution_is_rejected(self) -> None:
        cases: tuple[
            tuple[str, Callable[[dict[str, object]], None], bool], ...
        ] = (
            (
                "retired-authorization-field",
                lambda record: record.__setitem__("authorization", {"forged": True}),
                False,
            ),
            (
                "retired-transaction-field",
                lambda record: record.__setitem__(
                    "transaction",
                    {"producer_execution_sha256": "b" * 64, "semantic_sha256": "c" * 64},
                ),
                True,
            ),
            (
                "v3-contract",
                lambda record: record.__setitem__("contract", "winsvpn-winn-core-build-v3"),
                False,
            ),
            (
                "cross-go-executable",
                lambda record: record.__setitem__(
                    "go", {**dict(record["go"]), "executable_sha256": "b" * 64}
                ),
                False,
            ),
            (
                "cross-go-version",
                lambda record: record.__setitem__(
                    "go", {**dict(record["go"]), "version": "1.0.0"}
                ),
                False,
            ),
            (
                "go-archive-relabel",
                lambda record: record.__setitem__(
                    "go", {**dict(record["go"]), "archive_sha256": "b" * 64}
                ),
                False,
            ),
            (
                "cross-source-tree",
                lambda record: record.__setitem__("source_tree_sha256", "b" * 64),
                False,
            ),
            (
                "cross-role",
                lambda record: record.__setitem__("role", "winn3-gateway"),
                False,
            ),
            (
                "pure-go-compiler-claim",
                lambda record: record["platform"].__setitem__("compiler_path", "/usr/bin/cc"),
                False,
            ),
        )
        for label, mutate, after_transaction in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                output_dir = Path(tmp) / "output"
                reviewed = mock.Mock()
                reviewed.build_environment.return_value = {}
                reviewed.pass_fds.return_value = ()
                closure = mock.Mock(snapshot_root=tmp)
                closure.path.side_effect = lambda path: path
                closure.retained_fd.return_value = 123
                closure.retained_root_fd.return_value = 124

                def produce(command: list[str], **kwargs: object) -> object:
                    output = Path(command[-1])
                    write_claimed_output(kwargs, b"receipt substitution fixture")
                    receipt = producer_receipt_stdout(
                        output,
                        command[-2],
                        None if after_transaction else mutate,
                        mutate if after_transaction else None,
                    )
                    return subprocess.CompletedProcess(command, 0, receipt, "")

                with simulated_linux_host(), mock.patch.object(
                    MODULE,
                    "_run_system_descriptor",
                    side_effect=descriptor_run_adapter(produce),
                ):
                    ok, output, log = MODULE.build_reference(
                        "datapath-linux-arm64", "engine", str(output_dir), reviewed, closure
                    )
                self.assertFalse(ok, label)
                self.assertIsNone(output)
                self.assertIn("OWNER-BLOCKED", log)

    def test_cross_attempt_receipt_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replayed = root / "old" / "engine"
            replayed.parent.mkdir()
            replayed.write_bytes(b"replayed producer bytes")
            old_stdout = producer_receipt_stdout(
                replayed, "datapath-linux-arm64"
            )
            old_sidecars = {
                suffix: Path(str(replayed) + suffix).read_bytes()
                for suffix in (".receipt.json",)
            }
            output_dir = root / "new"
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            reviewed.pass_fds.return_value = ()
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            closure.retained_fd.return_value = 123
            closure.retained_root_fd.return_value = 124

            def replay(command: list[str], **kwargs: object) -> object:
                output = Path(command[-1])
                write_claimed_output(kwargs, b"replayed producer bytes")
                for suffix, payload in old_sidecars.items():
                    Path(str(output) + suffix).write_bytes(payload)
                return subprocess.CompletedProcess(command, 0, old_stdout, "")

            with simulated_linux_host(), mock.patch.object(
                MODULE,
                "_run_system_descriptor",
                side_effect=descriptor_run_adapter(replay),
            ):
                ok, output, log = MODULE.build_reference(
                    "datapath-linux-arm64", "engine", str(output_dir), reviewed, closure
                )
            self.assertFalse(ok)
            self.assertIsNone(output)
            self.assertIn("OWNER-BLOCKED", log)

    def test_exclusive_publication_handoff_binds_exact_fresh_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "published"
            custody = MODULE.DescriptorCustody(
                "exact publication test", MODULE.CustodyUnavailable
            )
            try:
                custody.bind_directory(str(root))
                custody._publication_started[str(output.resolve())] = time.time()
                output.write_bytes(b"exact producer bytes")
                handoff = authenticated_publication_handoff(output)
                node = custody.bind_atomic_publication(str(output), handoff)
                self.assertEqual(node.identity, handoff.descriptor_identity)
                self.assertEqual(custody.read_file(str(output)), b"exact producer bytes")
            finally:
                custody.close()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "published"
            unrelated = root / "unrelated"
            custody = MODULE.DescriptorCustody(
                "unrelated publication test", MODULE.CustodyUnavailable
            )
            try:
                custody.bind_directory(str(root))
                custody._publication_started[str(output.resolve())] = time.time()
                output.write_bytes(b"real producer bytes")
                handoff = authenticated_publication_handoff(output)
                unrelated.write_bytes(b"hostile second publication")
                os.replace(unrelated, output)
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable,
                    "differs from its fresh retained generation receipt",
                ):
                    custody.bind_atomic_publication(str(output), handoff)
            finally:
                custody.close()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "published"
            custody = MODULE.DescriptorCustody(
                "swap restore publication test", MODULE.CustodyUnavailable
            )
            try:
                custody.bind_directory(str(root))
                custody._publication_started[str(output.resolve())] = time.time()
                output.write_bytes(b"substitute")
                handoff = authenticated_publication_handoff(output)
                saved = root / "saved-substitute"
                output.rename(saved)
                output.write_bytes(b"hostile temporary generation")
                output.unlink()
                saved.rename(output)
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable,
                    "descriptor mutation event|changed during custody|differs from its fresh",
                ):
                    custody.bind_atomic_publication(str(output), handoff)
            finally:
                custody.close()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux pre-seal parent custody")
    def test_linux_preseal_output_parent_swap_restore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "output"
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            reviewed.pass_fds.return_value = ()
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            closure.retained_fd.return_value = 123
            closure.retained_root_fd.return_value = 124

            def swap_parent(command: list[str], **kwargs: object) -> object:
                output = Path(command[-1])
                parent = output.parent
                saved = parent.with_name(parent.name + ".saved")
                parent.rename(saved)
                parent.mkdir()
                output.write_bytes(b"hostile parent output")
                shutil.rmtree(parent)
                saved.rename(parent)
                return subprocess.CompletedProcess(command, 0, "", "")

            with simulated_linux_host(), mock.patch.object(
                MODULE,
                "_run_system_descriptor",
                side_effect=descriptor_run_adapter(swap_parent),
            ):
                ok, output, log = MODULE.build_reference(
                    "datapath-linux-arm64",
                    "engine",
                    str(output_dir),
                    reviewed,
                    closure,
                )
            self.assertFalse(ok)
            self.assertIsNone(output)
            self.assertRegex(log, r"identity changed|mutation event|pre-seal custody")

    def test_reference_output_is_returned_as_retained_descriptor_custody(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "output"
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            reviewed.pass_fds.return_value = ()
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            closure.retained_fd.return_value = 123
            closure.retained_root_fd.return_value = 124

            def produce(command: list[str], **kwargs: object) -> object:
                Path(command[-1]).parent.mkdir(parents=True, exist_ok=True)
                write_claimed_output(kwargs, b"retained producer bytes")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    producer_receipt_stdout(Path(command[-1]), command[-2]),
                    "",
                )

            with simulated_linux_host(), mock.patch.object(
                MODULE,
                "_run_system_descriptor",
                side_effect=descriptor_run_adapter(produce),
            ):
                ok, output, log = MODULE.build_reference(
                    "datapath-linux-arm64",
                    "libwinnengine.so",
                    str(output_dir),
                    reviewed,
                    closure,
                )
            self.assertTrue(ok, log)
            self.assertIsInstance(output, MODULE.RetainedReference)
            assert output is not None
            saved = output_dir / "saved.so"
            node = next(
                item
                for item in output.custody._nodes.values()
                if not item.is_directory and item.path.endswith("/libwinnengine.so")
            )
            Path(output.path).rename(saved)
            Path(output.path).write_bytes(b"pathname substitute")
            try:
                self.assertEqual(os.pread(node.fd, 1024, 0), b"retained producer bytes")
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable,
                    r"descriptor (?:mutation event|identity changed)",
                ):
                    output.verify()
            finally:
                output.close()

    def test_relay_reference_without_authenticated_handoff_is_owner_blocked(self) -> None:
        # Darwin no longer refuses the relay producer for want of immutable
        # ReleaseGo descriptor execution: it runs with the retained pinned Go
        # copy, and the absent v4 receipt is what blocks it.
        with tempfile.TemporaryDirectory() as tmp:
            reviewed = mock.Mock(retained_binary="/private/retained-go/bin/go")
            reviewed.build_environment.return_value = {}
            output_dir = Path(tmp) / "relay-output"
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            closure.retained_root_fd.return_value = 124
            seen: list[tuple[list[str], dict[str, str]]] = []

            def produce(command: list[str], **kwargs: object) -> object:
                environment = kwargs["env"]
                assert isinstance(environment, dict)
                seen.append((command, environment))
                write_claimed_output(kwargs, b"relay bytes without a receipt")
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(MODULE.sys, "platform", "darwin"), mock.patch.object(
                MODULE, "_run_system_descriptor", side_effect=descriptor_run_adapter(produce)
            ):
                ok, output, log = MODULE.build_reference(
                    "relay-windows-amd64", "winsvpn_winn3_engine.exe",
                    str(output_dir), reviewed, closure,
                )
            self.assertFalse(ok)
            self.assertIsNone(output)
            self.assertEqual(len(seen), 1, log)
            command, environment = seen[0]
            self.assertEqual(command[:2], ["/bin/bash", MODULE.RELAY_BUILD_SCRIPT])
            self.assertNotIn("-p", command)
            self.assertEqual(environment["WINS_RELEASE_GO"], "/private/retained-go/bin/go")
            self.assertIn("OWNER-BLOCKED", log)
            self.assertIn("publication handoff is absent", log)
            self.assertNotIn("Darwin pathname launchers are refused", log)

    def test_apple_wrapper_reference_is_unbuildable_off_darwin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            with mock.patch.object(MODULE, "sys", mock.Mock(platform="linux")):
                ok, _, log = MODULE.build_reference(
                    "apple-wrapper-iphoneos",
                    "libWinsWinnPacketEngine.dylib",
                    tmp,
                    reviewed,
                    closure,
                )
            self.assertFalse(ok)
            self.assertIn("Darwin", log)

    def test_provisioned_apple_target_reaches_authenticated_producer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            custody = mock.Mock()
            toolchain = MODULE.PlatformToolchainCustody(
                custody,
                {
                    "DEVELOPER_DIR": "/Library/Developer/CommandLineTools",
                    "SDKROOT": "/Library/SDKs/iPhoneOS.sdk",
                    "CC": "/Library/Developer/usr/bin/clang",
                },
            )
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            reviewed.pass_fds.return_value = ()
            closure.retained_fd.return_value = 123

            def run(command: list[str], **kwargs: object) -> object:
                self.assertEqual(
                    kwargs["env"]["DEVELOPER_DIR"],
                    "/Library/Developer/CommandLineTools",
                )
                return subprocess.CompletedProcess(
                    command, 73, "", "OWNER-BLOCKED: external Xcode producer authority\n"
                )

            with mock.patch.object(MODULE.sys, "platform", "darwin"), mock.patch.object(
                MODULE, "_bind_apple_toolchain_custody", return_value=toolchain
            ), mock.patch.object(MODULE.subprocess, "run", side_effect=run):
                ok, output, log = MODULE.build_reference(
                    "apple-wrapper-iphoneos",
                    "libWinsWinnPacketEngine.dylib",
                    str(Path(tmp) / "output"),
                    reviewed,
                    closure,
                )
            self.assertFalse(ok)
            self.assertIsNone(output)
            self.assertIn("OWNER-BLOCKED", log)
            custody.verify.assert_called()
            custody.close.assert_called_once_with()

    def test_wrong_elf_arch_is_invalid_before_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "wrong.so"
            path.write_bytes(real_elf("amd64"))
            artifact = MODULE.Artifact(
                "wrong.so", "datapath-android-arm64", "android", "test",
                kind="elf", arch="arm64",
            )
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE, "build_reference", side_effect=AssertionError("must not build")
            ):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "INVALID")
            self.assertIn("architecture mismatch", result.detail)

    def test_symlink_artifact_is_invalid_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.so"
            target.write_bytes(synthetic_elf("arm64"))
            os.symlink(target, root / "link.so")
            artifact = MODULE.Artifact(
                "link.so", "datapath-android-arm64", "android", "test",
                kind="elf", arch="arm64",
            )
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE, "build_reference", side_effect=AssertionError("must not build")
            ):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "INVALID")

    def test_symlinked_artifact_parent_is_invalid_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "artifact.so").write_bytes(synthetic_elf("arm64"))
            os.symlink(outside, root / "build")
            artifact = MODULE.Artifact(
                "build/artifact.so", "datapath-android-arm64", "android", "test",
                kind="elf", arch="arm64",
            )
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE, "build_reference", side_effect=AssertionError("must not build")
            ):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "INVALID")

    def test_path_escape_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = MODULE.Artifact(
                "../outside", "datapath-android-arm64", "android", "test",
                kind="elf", arch="arm64",
            )
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "INVALID")

    def test_absent_artifact_is_owner_blocked_and_not_rebuilt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = MODULE.Artifact(
                "absent.so", "datapath-android-arm64", "android", "test",
                kind="elf", arch="arm64",
            )
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE, "build_reference", side_effect=AssertionError("must not build")
            ):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "OWNER-BLOCKED", result.detail)
            self.assertIn("artifact authority is absent", result.detail)

    def test_pe_role_and_architecture_are_both_enforced(self) -> None:
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "architecture mismatch"):
            MODULE._validate_binary(
                synthetic_pe("amd64"), MODULE.Artifact(
                    "relay.exe", "relay-windows-arm64", "windows", "test",
                    kind="pe", role="relay", arch="arm64",
                )
            )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "embedded Go role identity"):
            MODULE._validate_binary(
                synthetic_pe("amd64", marker="core"), MODULE.Artifact(
                    "relay.exe", "relay-windows-amd64", "windows", "test",
                    kind="pe", role="relay", arch="amd64",
                )
            )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "embedded Go role identity"):
            MODULE._validate_binary(
                synthetic_pe("amd64", marker="relay"), MODULE.Artifact(
                    "core.exe", "datapath-windows-amd64", "windows", "test",
                    kind="pe", role="core", arch="amd64",
                )
            )

        spoofed = synthetic_pe("amd64", marker="relay", suffix=MODULE.WINN_MARKER)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "OWNER-BLOCKED role identity"):
            MODULE._validate_binary(
                spoofed,
                MODULE.Artifact(
                    "relay.exe", "relay-windows-amd64", "windows", "test",
                    kind="pe", role="relay", arch="amd64",
                ),
            )

    def test_pe_writable_buildinfo_never_authorizes_role(self) -> None:
        body = bytearray(synthetic_pe("amd64", marker="core"))
        build_info = body.find(b"\xff Go buildinf:")
        self.assertGreaterEqual(build_info, 0)
        body[build_info:build_info + 14] = b"marker spoof!!\x00"
        body[-len(MODULE.WINN_MARKER):] = MODULE.WINN_MARKER
        artifact = MODULE.Artifact(
            "core.exe", "datapath-windows-amd64", "windows", "test",
            kind="pe", role="core", arch="amd64",
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "Go build-info"):
            MODULE._validate_binary(
                bytes(body),
                artifact,
            )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "Go build-info"):
            MODULE._validate_binary(
                bytes(body),
                artifact,
                require_authenticated_role=False,
            )

    def test_pe_role_requires_substantive_executable_code(self) -> None:
        body = bytearray(synthetic_pe("amd64", marker="core"))
        body[0x200:0x400] = b"\0" * 0x200
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "executable code"):
            artifact = MODULE.Artifact(
                "core.exe", "datapath-windows-amd64", "windows", "test",
                kind="pe", role="core", arch="amd64",
            )
            MODULE._validate_binary(
                bytes(body),
                artifact,
                require_authenticated_role=False,
            )

    def test_pe_self_check_role_comes_from_embedded_go_identity(self) -> None:
        core = synthetic_pe("amd64", marker="core")
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "embedded Go role"):
            MODULE._validate_binary(
                core,
                MODULE.Artifact(
                    "relay.exe", "relay-windows-amd64", "windows", "test",
                    kind="pe", role="relay", arch="amd64",
                ),
                require_authenticated_role=False,
            )

    def test_aarch64_elf_entry_point_requires_four_byte_alignment(self) -> None:
        body = bytearray(synthetic_elf("arm64"))
        entry = struct.unpack_from("<Q", body, 24)[0]
        struct.pack_into("<Q", body, 24, entry + 2)
        with self.assertRaisesRegex(
            MODULE.ArtifactInvalid, "AArch64 ELF entry point is not 4-byte aligned"
        ):
            MODULE._parse_elf(bytes(body), "misaligned-arm64")

        aligned = MODULE._parse_elf(synthetic_elf("arm64"), "aligned-arm64")
        self.assertEqual(aligned.entry & 0x3, 0)

    def test_pe_entry_point_must_be_file_backed_executable_code(self) -> None:
        body = bytearray(synthetic_pe("amd64"))
        pe_offset = struct.unpack_from("<I", body, 0x3C)[0]
        optional = pe_offset + 24
        section = optional + 240
        struct.pack_into("<I", body, section + 8, 0x400)
        struct.pack_into("<I", body, section + 16, 0x200)
        struct.pack_into("<I", body, optional + 16, 0x1200)
        with self.assertRaisesRegex(
            MODULE.ArtifactInvalid, "entry point is outside executable code"
        ):
            MODULE._parse_pe(bytes(body), "zero-fill-entry.exe")

        backed = MODULE._parse_pe(synthetic_pe("amd64"), "file-backed-entry.exe")
        self.assertEqual(backed.entry_rva, 0x1000)

    def test_fixture_receipt_is_test_only_and_production_refuses_it(self) -> None:
        blob = synthetic_pe("amd64", marker="core")
        artifact = MODULE.Artifact(
            "core.exe", "datapath-windows-amd64", "windows", "test",
            kind="pe", role="core", arch="amd64",
        )
        with self.assertRaisesRegex(
            MODULE.ArtifactInvalid, "not externally authenticated"
        ):
            MODULE._validate_binary(
                blob,
                artifact,
                role_receipt=authenticated_fixture_receipt(blob, artifact),
            )

    def test_windows_producer_receipt_objects_are_never_production_authority(
        self,
    ) -> None:
        blob = synthetic_pe("amd64", marker="core")
        artifact = MODULE.Artifact(
            "core.exe", "datapath-windows-amd64", "windows", "test",
            kind="pe", role="core", arch="amd64",
        )
        source_closure = MODULE.SourceClosure("windows", "a" * 64, ())
        for caller_minted in (
            authenticated_fixture_receipt(blob, artifact),
            object(),
        ):
            with self.assertRaisesRegex(
                MODULE.ArtifactInvalid, "Windows producer receipts are retired"
            ):
                MODULE._validate_binary(
                    blob,
                    artifact,
                    role_receipt=caller_minted,
                    authoritative_source_closure=source_closure,
                )

    def test_windows_pe_machine_matching_its_declaration_is_accepted(self) -> None:
        for arch in ("amd64", "arm64"):
            artifact = MODULE.Artifact(
                f"build/windows/winn3/{'x64' if arch == 'amd64' else arch}/winn-datapath.exe",
                f"datapath-windows-{arch}",
                "windows",
                "test",
                kind="pe",
                arch=arch,
            )
            self.assertIsNone(
                MODULE._require_pe_machine_architecture(synthetic_pe(arch), artifact)
            )

    def test_windows_pe_equal_to_authenticated_rebuild_is_fresh(self) -> None:
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                body = synthetic_pe("amd64", marker="core")
                (root / "core.exe").write_bytes(body)
                reference = root / "reference" / "core.exe"
                reference.parent.mkdir()
                rebuilt = bytearray(body)
                if changed:
                    rebuilt[0x200 + 40] ^= 0x01
                reference.write_bytes(bytes(rebuilt))
                artifact = MODULE.Artifact(
                    "core.exe", "datapath-windows-amd64", "windows", "test",
                    kind="pe", role="core", arch="amd64",
                )
                closure = mock.Mock(
                    closure=MODULE.SourceClosure(artifact.target, "a" * 64, ())
                )
                with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                    MODULE,
                    "build_reference",
                    return_value=(
                        True, retained_reference(reference, artifact.target), ""
                    ),
                ):
                    result = MODULE.check(
                        artifact, str(root), mock.Mock(), source_custody=closure
                    )
                if changed:
                    self.assertEqual(result.verdict, "STALE", result.detail)
                else:
                    self.assertEqual(result.verdict, "FRESH", result.detail)
                    self.assertEqual(
                        result.shipped_digest, hashlib.sha256(body).hexdigest()
                    )

    def test_windows_receipt_architecture_is_pe_derived(self) -> None:
        arm64_blob = synthetic_pe("arm64")
        caller_claims_x64 = MODULE.Artifact(
            "build/windows/winn3/x64/winn-datapath.exe",
            "datapath-windows-amd64",
            "windows",
            "hostile caller metadata",
            kind="pe",
            arch="amd64",
        )
        with self.assertRaisesRegex(
            MODULE.ArtifactInvalid, "derive from the PE machine"
        ):
            MODULE._require_pe_machine_architecture(arm64_blob, caller_claims_x64)

    def test_android_package_requires_all_main_abis_and_rejects_duplicate_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.apk"
            payloads = {
                "arm64-v8a": real_elf("arm64"),
                "armeabi-v7a": real_elf("arm"),
                "x86_64": real_elf("amd64"),
            }
            write_android_package(path, payloads)
            artifact = MODULE.Artifact(
                "app.apk", "datapath-android-arm64", "android", "test",
                kind="android-package", arch="arm64",
                member="lib/arm64-v8a/libwinnengine.so",
            )
            self.assertEqual(
                MODULE._artifact_payload(str(path), artifact), payloads["arm64-v8a"]
            )

            duplicate = Path(tmp) / "duplicate.apk"
            with zipfile.ZipFile(duplicate, "w", compression=zipfile.ZIP_STORED) as package:
                for abi, payload in payloads.items():
                    package.writestr(f"lib/{abi}/libwinnengine.so", payload)
                package.writestr("./lib/arm64-v8a/libwinnengine.so", payloads["arm64-v8a"])
            with self.assertRaisesRegex(MODULE.ArtifactInvalid, "duplicate"):
                MODULE._read_zip_member(str(duplicate), artifact)

    def test_android_package_rejects_symlink_and_wrong_member_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = MODULE.Artifact(
                "android/devicecheck/app-debug.apk", "datapath-android-arm64",
                "android", "test", kind="android-package", arch="arm64",
                member="lib/arm64-v8a/libwinnengine.so",
            )
            symlink_zip = root / "symlink.apk"
            with zipfile.ZipFile(symlink_zip, "w", compression=zipfile.ZIP_STORED) as package:
                info = zipfile.ZipInfo("lib/arm64-v8a/libwinnengine.so")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                package.writestr(info, b"not-followed")
            with self.assertRaisesRegex(MODULE.ArtifactInvalid, "symbolic"):
                MODULE._read_zip_member(str(symlink_zip), artifact)

            missing = root / "missing.apk"
            write_android_package(
                missing,
                {"arm64-v8a": real_elf("arm64")},
            )
            with self.assertRaisesRegex(MODULE.ArtifactInvalid, "members differ"):
                MODULE._read_zip_member(str(missing), MODULE.Artifact(
                    "app.apk", "datapath-android-arm64", "android", "test",
                    kind="android-package", arch="arm64",
                    member="lib/arm64-v8a/libwinnengine.so",
                ))

            traversal = root / "traversal.apk"
            with zipfile.ZipFile(traversal, "w", compression=zipfile.ZIP_STORED) as package:
                for abi, payload in {
                    "arm64-v8a": real_elf("arm64"),
                    "armeabi-v7a": real_elf("arm"),
                    "x86_64": real_elf("amd64"),
                }.items():
                    package.writestr(f"lib/{abi}/libwinnengine.so", payload)
                package.writestr("../outside", b"bad")
            with self.assertRaisesRegex(MODULE.ArtifactInvalid, "traverses"):
                MODULE._read_zip_member(str(traversal), MODULE.Artifact(
                    "app.apk", "datapath-android-arm64", "android", "test",
                    kind="android-package", arch="arm64",
                    member="lib/arm64-v8a/libwinnengine.so",
                ))

    def test_android_manifests_require_exact_production_package(self) -> None:
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "package"):
            MODULE._validate_binary_android_manifest(
                binary_android_manifest("org.hostile.relabel"),
                "hostile.apk:AndroidManifest.xml",
                "org.winsvpn.app",
            )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "package"):
            MODULE._validate_aab_manifest(
                aab_manifest_proto("org.hostile.relabel"),
                "hostile.aab:AndroidManifest.xml",
                "org.winsvpn.app",
            )

    def test_android_manifests_require_exact_application_identity(self) -> None:
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "application"):
            MODULE._validate_binary_android_manifest(
                binary_android_manifest(
                    "org.winsvpn.app", "org.hostile.SubstituteApplication"
                ),
                "hostile.apk:AndroidManifest.xml",
                "org.winsvpn.app",
            )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "application"):
            MODULE._validate_aab_manifest(
                aab_manifest_proto(
                    "org.winsvpn.app", "org.hostile.SubstituteApplication"
                ),
                "hostile.aab:AndroidManifest.xml",
                "org.winsvpn.app",
            )

    def test_check_compares_package_member_content_and_reports_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "app.apk"
            shipped = real_elf("arm64") + b"shipped"
            rebuilt = real_elf("arm64") + b"rebuilt"
            write_android_package(
                package,
                {
                    "arm64-v8a": shipped,
                    "armeabi-v7a": real_elf("arm"),
                    "x86_64": real_elf("amd64"),
                },
            )
            reference = root / "reference" / "reference.so"
            reference.parent.mkdir()
            reference.write_bytes(rebuilt)
            artifact = MODULE.Artifact(
                "app.apk", "datapath-android-arm64", "android", "test",
                kind="android-package", arch="arm64",
                member="lib/arm64-v8a/libwinnengine.so",
            )
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE,
                "build_reference",
                return_value=(
                    True,
                    retained_reference(reference, artifact.target),
                    "",
                ),
            ):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "STALE")

    def test_missing_receipt_or_authority_stays_owner_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            windows = root / "core.exe"
            windows.write_bytes(synthetic_pe("amd64", marker="core"))
            artifact = MODULE.Artifact(
                "core.exe", "datapath-windows-amd64", "windows", "test",
                kind="pe", role="core", arch="amd64",
            )
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE, "build_reference", side_effect=AssertionError("must not build")
            ):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "OWNER-BLOCKED")
            self.assertIn("authoritative source closure", result.detail)

            linux = root / "engine"
            linux.write_bytes(real_elf("arm64"))
            linux_artifact = MODULE.Artifact(
                "engine", "datapath-linux-arm64", "linux", "test",
                kind="elf", arch="arm64",
            )
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE,
                "build_reference",
                return_value=(False, None, "OWNER-BLOCKED: platform authority absent\n"),
            ):
                result = MODULE.check(
                    linux_artifact, str(root), mock.Mock(), source_custody=mock.Mock()
                )
            self.assertEqual(result.verdict, "OWNER-BLOCKED")

    def test_apple_wrapper_and_archive_platform_arch_checks(self) -> None:
        wrapper = MODULE.Artifact(
            "wrapper.dylib", "apple-wrapper-iphonesimulator", "apple", "test",
            kind="apple-wrapper", role="core+relay", arch="arm64,x86_64",
            platform="iphonesimulator",
        )
        valid = REAL_SIM_WRAPPER.read_bytes()
        MODULE._validate_binary(
            valid,
            wrapper,
            require_authenticated_role=False,
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "architectures differ"):
            MODULE._validate_binary(
                synthetic_macho("arm64", "iphoneos"), wrapper
            )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "platform mismatch"):
            MODULE._validate_binary(
                synthetic_fat_macho(("arm64", "x86_64"), "macosx"), wrapper
            )

        archive = MODULE.Artifact(
            "engine.a", "datapath-ios-arm64", "apple", "test",
            kind="apple-archive", arch="arm64", platform="iphoneos",
        )
        archive_blob = REAL_ARCHIVE.read_bytes()
        MODULE._validate_binary(
            archive_blob,
            archive,
            require_authenticated_role=False,
        )

        raw_spoof = synthetic_macho(
            "arm64", "iphoneos", symbols=False,
            suffix=MODULE.WINN_MARKER + b"\x00".join(MODULE.APPLE_REQUIRED_SYMBOLS),
        )
        single_wrapper = MODULE.Artifact(
            "wrapper.dylib", "apple-wrapper-iphoneos", "apple", "test",
            kind="apple-wrapper", role="core+relay", arch="arm64",
            platform="iphoneos",
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "missing exported"):
            MODULE._validate_binary(raw_spoof, single_wrapper)

    def test_linux_tar_rejects_traversal_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = MODULE.Artifact(
                "bundle.tar.gz", "datapath-linux-amd64", "linux", "test",
                kind="linux-package", arch="amd64", member="winn-datapath",
            )
            valid = root / "valid.tar.gz"
            payload = real_elf("amd64")
            write_linux_tar(valid, payload)
            self.assertEqual(MODULE._artifact_payload(str(valid), artifact), payload)

            traversal = root / "traversal.tar.gz"
            with tarfile.open(traversal, "w:gz") as package:
                info = tarfile.TarInfo("../winn-datapath")
                info.size = len(payload)
                package.addfile(info, io.BytesIO(payload))
            with self.assertRaisesRegex(MODULE.ArtifactInvalid, "traverses"):
                MODULE._read_tar_member(str(traversal), artifact)

            symlink = root / "symlink.tar.gz"
            with tarfile.open(symlink, "w:gz") as package:
                info = tarfile.TarInfo("winn-datapath")
                info.type = tarfile.SYMTYPE
                info.linkname = "elsewhere"
                package.addfile(info)
            with self.assertRaisesRegex(MODULE.ArtifactInvalid, "unsafe"):
                MODULE._read_tar_member(str(symlink), artifact)

    def test_source_closure_digest_changes_when_current_source_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "module"
            source.mkdir()
            (source / "go.mod").write_text("module test\n", encoding="ascii")
            main = source / "main.go"
            main.write_text("package main\n", encoding="ascii")
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)):
                first = MODULE._current_closure("test", (str(source),))
                main.write_text("package main\nvar changed = true\n", encoding="ascii")
                second = MODULE._current_closure("test", (str(source),))
            self.assertNotEqual(first.digest, second.digest)

    def test_shipped_byte_mutation_remains_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shipped = root / "staged" / "libwinnengine.so"
            reference = root / "reference" / "libwinnengine.so"
            shipped.parent.mkdir()
            reference.parent.mkdir()
            body = real_elf("arm64")
            shipped.write_bytes(body)
            reference.write_bytes(body)
            artifact = MODULE.Artifact(
                "staged/libwinnengine.so",
                "datapath-android-arm64",
                "android",
                "test",
                kind="elf",
                arch="arm64",
            )
            reviewed = mock.Mock()
            def rebuilt_reference(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                return True, retained_reference(reference, artifact.target), ""

            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE,
                "build_reference",
                side_effect=rebuilt_reference,
            ):
                fresh = MODULE.check(artifact, str(root), reviewed)
                self.assertEqual(fresh.verdict, "FRESH", fresh.detail)
                self.assertEqual(fresh.shipped_digest, MODULE.fingerprint_bytes(body))
                self.assertEqual(fresh.rebuilt_digest, fresh.shipped_digest)
                consumed: list[str] = []

                def consume(retained: object) -> None:
                    payload = retained.read_archive()
                    consumed.append(hashlib.sha256(payload).hexdigest())

                consumed_but_unpublished = MODULE.check(
                    artifact,
                    str(root),
                    reviewed,
                    consumer=consume,
                )
                self.assertEqual(consumed_but_unpublished.verdict, "FRESH")
                self.assertEqual(consumed, [])
                body = bytearray(shipped.read_bytes())
                body[len(body) // 2] ^= 0xFF
                shipped.write_bytes(body)
                self.assertEqual(MODULE.check(artifact, str(root), reviewed).verdict, "STALE")

    def test_forged_consumer_is_never_invoked_and_cannot_change_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            shipped = root / "winn-datapath"
            reference = root / "reference"
            payload = real_elf("arm64")
            shipped.write_bytes(payload)
            reference.write_bytes(payload)
            artifact = MODULE.Artifact(
                "winn-datapath", "datapath-linux-arm64", "linux", "test",
                kind="elf", arch="arm64",
            )
            retained = retained_reference(reference, artifact.target)
            invoked = False

            def rebuilt_reference(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                return True, retained, ""

            def forged_consumer(_retained: object) -> object:
                nonlocal invoked
                invoked = True
                return authenticated_publication_handoff(shipped, artifact.target)

            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE, "build_reference", side_effect=rebuilt_reference
            ):
                result = MODULE.check(
                    artifact, str(root), mock.Mock(), consumer=forged_consumer
                )
            self.assertFalse(invoked)
            self.assertEqual(result.verdict, "FRESH", result.detail)
            self.assertEqual(result.shipped_digest, MODULE.fingerprint_bytes(payload))
            self.assertFalse(hasattr(MODULE, "_linux_downstream_consumer"))
            self.assertFalse(hasattr(MODULE, "_PUBLICATION_HANDOFF_AUTHENTICATION"))

    def test_linux_downstream_forgery_and_mutable_output_fail_closed(self) -> None:
        for mode in ("wrong-input", "writable-output"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                repo = root / "repo"
                shipped = repo / "winn-datapath"
                repo.mkdir()
                body = real_elf("arm64")
                shipped.write_bytes(body)
                reference = root / "reference"
                reference.write_bytes(body)
                output = root / "published"
                artifact = MODULE.Artifact(
                    "winn-datapath", "datapath-linux-arm64", "linux", "test",
                    kind="elf", arch="arm64",
                )

                def rebuilt_reference(
                    *args: object, **kwargs: object
                ) -> tuple[bool, object, str]:
                    return True, retained_reference(reference, artifact.target), ""

                def hostile(retained: object) -> object:
                    payload = retained.read_archive()
                    output.write_bytes(payload)
                    if mode != "writable-output":
                        output.chmod(0o400)
                    identity = MODULE._file_identity(os.lstat(output))
                    digest = hashlib.sha256(payload).hexdigest()
                    claimed_input = "0" * 64 if mode == "wrong-input" else digest
                    receipt_path = Path(str(output) + ".freshness.json")
                    receipt = {
                        "schema_version": 1,
                        "contract": "winsvpn-native-freshness-downstream-v1",
                        "target": artifact.target,
                        "artifact_path": artifact.path,
                        "architecture": artifact.arch,
                        "input": {
                            "sha256": claimed_input,
                            "size_bytes": len(payload),
                        },
                        "output": {
                            "path": str(output),
                            "sha256": digest,
                            "size_bytes": len(payload),
                            "descriptor_identity": list(identity),
                        },
                    }
                    receipt_path.write_text(
                        json.dumps(
                            receipt, sort_keys=True, separators=(",", ":")
                        )
                        + "\n",
                        encoding="ascii",
                    )
                    receipt_path.chmod(0o400)
                    return MODULE.AuthenticatedPublicationHandoff(
                        artifact.target,
                        str(output),
                        identity,
                        digest,
                        claimed_input,
                        len(payload),
                        str(receipt_path),
                        hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                        True,
                    )

                with mock.patch.object(
                    MODULE, "REPO_ROOT", str(repo)
                ), mock.patch.object(
                    MODULE, "build_reference", side_effect=rebuilt_reference
                ):
                    result = MODULE.check(
                        artifact, str(root), mock.Mock(), consumer=hostile
                    )
                # The hostile consumer never runs: nothing is published and
                # the verdict rests only on the bytes compared under custody.
                self.assertEqual(result.verdict, "FRESH", result.detail)
                self.assertFalse(output.exists())
                self.assertEqual(result.shipped_digest, MODULE.fingerprint_bytes(body))

    def test_fresh_verdict_binds_the_bytes_read_not_a_later_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repo = root / "repo"
            shipped = repo / "nested" / "libwinnengine.so"
            shipped.parent.mkdir(parents=True)
            body = real_elf("arm64")
            shipped.write_bytes(body)
            reference = root / "reference.so"
            reference.write_bytes(body)
            artifact = MODULE.Artifact(
                "nested/libwinnengine.so",
                "datapath-android-arm64",
                "android",
                "test",
                kind="elf",
                arch="arm64",
            )

            def rebuilt_reference(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                return True, retained_reference(reference, artifact.target), ""

            with mock.patch.object(MODULE, "REPO_ROOT", str(repo)), mock.patch.object(
                MODULE, "build_reference", side_effect=rebuilt_reference
            ):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "FRESH", result.detail)
            self.assertEqual(result.shipped_digest, MODULE.fingerprint_bytes(body))
            saved = repo / "nested.saved"
            shipped.parent.rename(saved)
            shipped.parent.mkdir()
            shipped.write_bytes(body + b"post-check substitute")
            try:
                self.assertNotEqual(
                    MODULE.fingerprint_bytes(shipped.read_bytes()), result.shipped_digest
                )
            finally:
                shutil.rmtree(shipped.parent)
                saved.rename(shipped.parent)

    def test_parent_replace_and_swap_restore_at_consumer_return_are_rejected(self) -> None:
        for level in ("immediate", "higher"):
            for restore in (False, True):
                with self.subTest(level=level, restore=restore), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp).resolve()
                    repo = root / "repo"
                    shipped = repo / "nested" / "libwinnengine.so"
                    shipped.parent.mkdir(parents=True)
                    body = real_elf("arm64")
                    shipped.write_bytes(body)
                    reference = root / "reference.so"
                    reference.write_bytes(body)
                    artifact = MODULE.Artifact(
                        "nested/libwinnengine.so",
                        "datapath-android-arm64",
                        "android",
                        "test",
                        kind="elf",
                        arch="arm64",
                    )
                    attacked = shipped.parent if level == "immediate" else repo
                    saved = attacked.with_name(attacked.name + ".saved")
                    invoked = False

                    def rebuilt_reference(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                        return True, retained_reference(reference, artifact.target), ""

                    def consume(retained: object) -> None:
                        nonlocal invoked
                        invoked = True
                        self.assertEqual(retained.read_archive(), body)
                        attacked.rename(saved)
                        shipped.parent.mkdir(parents=True)
                        shipped.write_bytes(body + b"consumer-return substitute")
                        if restore:
                            shutil.rmtree(attacked)
                            saved.rename(attacked)

                    try:
                        with mock.patch.object(
                            MODULE, "REPO_ROOT", str(repo)
                        ), mock.patch.object(
                            MODULE, "build_reference", side_effect=rebuilt_reference
                        ):
                            result = MODULE.check(
                                artifact,
                                str(root),
                                mock.Mock(),
                                consumer=consume,
                            )
                        self.assertFalse(invoked)
                        self.assertEqual(result.verdict, "FRESH", result.detail)
                        self.assertEqual(
                            result.shipped_digest, MODULE.fingerprint_bytes(body)
                        )
                    finally:
                        if saved.exists():
                            if attacked.exists():
                                shutil.rmtree(attacked)
                            saved.rename(attacked)

    def test_parent_replace_and_swap_restore_after_check_before_consume_are_rejected(
        self,
    ) -> None:
        for level in ("immediate", "higher"):
            for restore in (False, True):
                with self.subTest(level=level, restore=restore), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp).resolve()
                    repo = root / "repo"
                    shipped = repo / "nested" / "libwinnengine.so"
                    shipped.parent.mkdir(parents=True)
                    body = real_elf("arm64")
                    shipped.write_bytes(body)
                    reference = root / "reference.so"
                    reference.write_bytes(body)
                    artifact = MODULE.Artifact(
                        "nested/libwinnengine.so",
                        "datapath-android-arm64",
                        "android",
                        "test",
                        kind="elf",
                        arch="arm64",
                    )
                    attacked = shipped.parent if level == "immediate" else repo
                    saved = attacked.with_name(attacked.name + ".saved")
                    invoked = False

                    def rebuilt_reference(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                        return True, retained_reference(reference, artifact.target), ""

                    def consume(retained: object) -> None:
                        nonlocal invoked
                        invoked = True
                        attacked.rename(saved)
                        shipped.parent.mkdir(parents=True)
                        shipped.write_bytes(body + b"pre-consume substitute")
                        if restore:
                            shutil.rmtree(attacked)
                            saved.rename(attacked)
                        retained.read_archive()

                    try:
                        with mock.patch.object(
                            MODULE, "REPO_ROOT", str(repo)
                        ), mock.patch.object(
                            MODULE, "build_reference", side_effect=rebuilt_reference
                        ):
                            result = MODULE.check(
                                artifact,
                                str(root),
                                mock.Mock(),
                                consumer=consume,
                            )
                        self.assertFalse(invoked)
                        self.assertEqual(result.verdict, "FRESH", result.detail)
                        self.assertEqual(
                            result.shipped_digest, MODULE.fingerprint_bytes(body)
                        )
                    finally:
                        if saved.exists():
                            if attacked.exists():
                                shutil.rmtree(attacked)
                            saved.rename(attacked)

    def test_close_drains_parent_attack_queued_in_finally(self) -> None:
        for level in ("immediate", "higher"):
            for restore in (False, True):
                with self.subTest(level=level, restore=restore), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp).resolve()
                    repo = root / "repo"
                    shipped = repo / "nested" / "libwinnengine.so"
                    shipped.parent.mkdir(parents=True)
                    body = real_elf("arm64")
                    shipped.write_bytes(body)
                    reference = root / "reference.so"
                    reference.write_bytes(body)
                    artifact = MODULE.Artifact(
                        "nested/libwinnengine.so",
                        "datapath-android-arm64",
                        "android",
                        "test",
                        kind="elf",
                        arch="arm64",
                    )
                    attacked = shipped.parent if level == "immediate" else repo
                    saved = attacked.with_name(attacked.name + ".saved")
                    original_close = MODULE.DescriptorCustody.close
                    attack_once = False

                    def rebuilt_reference(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                        return True, retained_reference(reference, artifact.target), ""

                    def close_with_attack(custody: object) -> None:
                        nonlocal attack_once
                        if not attack_once and custody.label.startswith("shipped artifact"):
                            attack_once = True
                            attacked.rename(saved)
                            shipped.parent.mkdir(parents=True)
                            shipped.write_bytes(body + b"finally substitute")
                            if restore:
                                shutil.rmtree(attacked)
                                saved.rename(attacked)
                        original_close(custody)

                    try:
                        with mock.patch.object(
                            MODULE, "REPO_ROOT", str(repo)
                        ), mock.patch.object(
                            MODULE, "build_reference", side_effect=rebuilt_reference
                        ), mock.patch.object(
                            MODULE.DescriptorCustody, "close", new=close_with_attack
                        ):
                            result = MODULE.check(
                                artifact,
                                str(root),
                                mock.Mock(),
                                consumer=lambda retained: retained.read_archive(),
                            )
                        self.assertTrue(attack_once)
                        self.assertEqual(result.verdict, "INVALID")
                        self.assertIn("final release", result.detail)
                    finally:
                        if saved.exists():
                            if attacked.exists():
                                shutil.rmtree(attacked)
                            saved.rename(attacked)

    def test_close_queue_boundary_cannot_turn_a_read_into_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repo = root / "repo"
            shipped = repo / "nested" / "libwinnengine.so"
            shipped.parent.mkdir(parents=True)
            body = real_elf("arm64")
            shipped.write_bytes(body)
            reference = root / "reference.so"
            reference.write_bytes(body)
            artifact = MODULE.Artifact(
                "nested/libwinnengine.so",
                "datapath-android-arm64",
                "android",
                "test",
                kind="elf",
                arch="arm64",
            )
            saved = repo.with_name("repo.saved")
            original_close = MODULE.DescriptorCustody.close
            attacked = False

            def rebuilt_reference(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                return True, retained_reference(reference, artifact.target), ""

            def close_at_queue_boundary(custody: object) -> None:
                nonlocal attacked
                queue = custody._event_queue
                if (
                    not attacked
                    and queue is not None
                    and custody.label.startswith("shipped artifact")
                ):
                    class QueueBoundaryAttack:
                        def control(self, *args: object, **kwargs: object) -> object:
                            return queue.control(*args, **kwargs)

                        def close(self) -> None:
                            nonlocal attacked
                            repo.rename(saved)
                            (repo / "nested").mkdir(parents=True)
                            shipped.write_bytes(body + b"close-boundary substitute")
                            shutil.rmtree(repo)
                            saved.rename(repo)
                            attacked = True
                            queue.close()

                    custody._event_queue = QueueBoundaryAttack()
                original_close(custody)

            with mock.patch.object(
                MODULE, "REPO_ROOT", str(repo)
            ), mock.patch.object(
                MODULE, "build_reference", side_effect=rebuilt_reference
            ), mock.patch.object(
                MODULE.DescriptorCustody, "close", new=close_at_queue_boundary
            ):
                result = MODULE.check(
                    artifact,
                    str(root),
                    mock.Mock(),
                    consumer=lambda retained: retained.read_archive(),
                )
            self.assertTrue(attacked)
            # The swap happens after custody ended and is restored; the verdict
            # is about the bytes held under custody, which were authentic.
            self.assertEqual(result.verdict, "FRESH", result.detail)
            self.assertEqual(result.shipped_digest, MODULE.fingerprint_bytes(body))

    def test_cli_passes_only_when_every_checked_artifact_is_fresh(
        self,
    ) -> None:
        artifact = MODULE.Artifact(
            "staged/libwinnengine.so",
            "datapath-android-arm64",
            "android",
            "test",
            kind="elf",
            arch="arm64",
        )
        reviewed_go = mock.Mock()
        closure = mock.Mock()
        closure.closure = MODULE.SourceClosure(
            artifact.target,
            "11" * 32,
            ("winn_protocol_experimental/go.mod",),
            "22" * 32,
            ("winsvpn.local/winnprotocol",),
        )
        closure.verify.return_value = None
        closure.close.return_value = None
        all_match = MODULE.Result(
            artifact,
            "FRESH",
            shipped_mtime=1.0,
            shipped_digest="33" * 32,
            rebuilt_digest="33" * 32,
        )
        args = mock.Mock(self_check=False, only="android")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE.argparse.ArgumentParser, "parse_args", return_value=args
        ), mock.patch.object(
            MODULE, "authenticate_reviewed_go", return_value=reviewed_go
        ), mock.patch.object(
            MODULE, "inventory", return_value=(artifact,)
        ), mock.patch.object(
            MODULE,
            "bind_source_closures",
            return_value={artifact.target: closure},
        ), mock.patch.object(
            MODULE, "newest_source_mtime", return_value=(1.0, "source.go")
        ), mock.patch.object(
            MODULE, "check", return_value=all_match
        ), mock.patch.object(
            MODULE.tempfile, "mkdtemp", return_value="/private/tmp/freshness-fixture"
        ), mock.patch.object(
            MODULE.shutil, "rmtree"
        ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            status = MODULE.main()
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertIn("PASS: all 1 checked shipped native artifact(s)", stdout.getvalue())
        reviewed_go.verify_unchanged.assert_called_once_with()
        reviewed_go.close.assert_called_once_with()

        for verdict, expected_status in (
            ("OWNER-BLOCKED", 1),
            ("STALE", 1),
            ("INVALID", 1),
            ("UNBUILDABLE", 1),
        ):
            reviewed_go = mock.Mock()
            not_fresh = MODULE.Result(
                artifact,
                verdict,
                "fixture",
                shipped_mtime=1.0,
                shipped_digest="33" * 32,
                rebuilt_digest="44" * 32,
            )
            stdout = io.StringIO()
            with self.subTest(verdict=verdict), mock.patch.object(
                MODULE.argparse.ArgumentParser, "parse_args", return_value=args
            ), mock.patch.object(
                MODULE, "authenticate_reviewed_go", return_value=reviewed_go
            ), mock.patch.object(
                MODULE, "inventory", return_value=(artifact,)
            ), mock.patch.object(
                MODULE,
                "bind_source_closures",
                return_value={artifact.target: closure},
            ), mock.patch.object(
                MODULE, "newest_source_mtime", return_value=(1.0, "source.go")
            ), mock.patch.object(
                MODULE, "check", return_value=not_fresh
            ), mock.patch.object(
                MODULE.tempfile, "mkdtemp", return_value="/private/tmp/freshness-fixture"
            ), mock.patch.object(
                MODULE.shutil, "rmtree"
            ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", io.StringIO()):
                self.assertEqual(MODULE.main(), expected_status)
            self.assertNotIn("PASS", stdout.getvalue())

    def test_cli_discards_read_only_reference_trees_in_its_workdir(self) -> None:
        artifact = MODULE.Artifact(
            "one/libwinnengine.so", "datapath-android-arm64", "android", "test",
            kind="elf", arch="arm64",
        )
        closure = mock.Mock()
        closure.closure = MODULE.SourceClosure(artifact.target, "11" * 32, (), "22" * 32, ())
        with tempfile.TemporaryDirectory() as raw:
            workdir = Path(raw) / "winn-freshness.fixture"
            sealed = workdir / ".reference-fixture" / ".gomodcache"
            sealed.mkdir(parents=True)
            (sealed / "module.zip").write_bytes(b"sealed")
            (sealed / "module.zip").chmod(0o400)
            sealed.chmod(0o500)
            args = mock.Mock(self_check=False, only="android", artifact=None)
            with mock.patch.object(
                MODULE.argparse.ArgumentParser, "parse_args", return_value=args
            ), mock.patch.object(
                MODULE, "authenticate_reviewed_go", return_value=mock.Mock()
            ), mock.patch.object(
                MODULE, "inventory", return_value=(artifact,)
            ), mock.patch.object(
                MODULE, "bind_source_closures", return_value={artifact.target: closure}
            ), mock.patch.object(
                MODULE, "newest_source_mtime", return_value=(1.0, "source.go")
            ), mock.patch.object(
                MODULE,
                "check",
                return_value=MODULE.Result(
                    artifact, "FRESH", shipped_mtime=1.0,
                    shipped_digest="33" * 32, rebuilt_digest="33" * 32,
                ),
            ), mock.patch.object(
                MODULE.tempfile, "mkdtemp", return_value=str(workdir)
            ), mock.patch("sys.stdout", io.StringIO()), mock.patch(
                "sys.stderr", io.StringIO()
            ):
                self.assertEqual(MODULE.main(), 0)
            self.assertFalse(workdir.exists())

    def test_cli_artifact_filter_checks_only_named_declared_artifacts(self) -> None:
        first = MODULE.Artifact(
            "one/libwinnengine.so", "datapath-android-arm64", "android", "test",
            kind="elf", arch="arm64",
        )
        second = MODULE.Artifact(
            "two/libwinnengine.so", "datapath-android-arm", "android", "test",
            kind="elf", arch="arm",
        )
        closure = mock.Mock()
        closure.closure = MODULE.SourceClosure(
            first.target, "11" * 32, (), "22" * 32, ()
        )

        def fresh(artifact: object, *args: object, **kwargs: object) -> object:
            return MODULE.Result(
                artifact, "FRESH", shipped_mtime=1.0,
                shipped_digest="33" * 32, rebuilt_digest="33" * 32,
            )

        for selection, expected_status, expected_checked in (
            (["one/libwinnengine.so"], 0, ["one/libwinnengine.so"]),
            (["not/declared.so"], 2, []),
        ):
            args = mock.Mock(self_check=False, only="android", artifact=selection)
            reviewed_go = mock.Mock()
            stderr = io.StringIO()
            with self.subTest(selection=selection), mock.patch.object(
                MODULE.argparse.ArgumentParser, "parse_args", return_value=args
            ), mock.patch.object(
                MODULE, "authenticate_reviewed_go", return_value=reviewed_go
            ), mock.patch.object(
                MODULE, "inventory", return_value=(first, second)
            ), mock.patch.object(
                MODULE, "bind_source_closures", return_value={first.target: closure}
            ) as bind, mock.patch.object(
                MODULE, "newest_source_mtime", return_value=(1.0, "source.go")
            ), mock.patch.object(
                MODULE, "check", side_effect=fresh
            ) as checked, mock.patch.object(
                MODULE.tempfile, "mkdtemp", return_value="/private/tmp/freshness-fixture"
            ), mock.patch.object(
                MODULE.shutil, "rmtree"
            ), mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", stderr):
                status = MODULE.main()
            self.assertEqual(status, expected_status, stderr.getvalue())
            self.assertEqual(
                [call.args[0].path for call in checked.call_args_list], expected_checked
            )
            if expected_status == 2:
                self.assertIn("--artifact names no declared artifact", stderr.getvalue())
                bind.assert_not_called()
            else:
                self.assertEqual(list(bind.call_args.args[0]), [first.target])

    def test_linux_cli_checks_every_declared_linux_artifact(self) -> None:
        artifacts = tuple(
            MODULE.Artifact(
                f"build/linux/{arch}/release/bundle/winn-datapath",
                f"datapath-linux-{arch}",
                "linux",
                "test",
                kind="elf",
                arch=arch,
            )
            for arch in ("amd64", "arm64")
        )
        reviewed_go = mock.Mock()
        closures = {}
        for artifact in artifacts:
            closure = mock.Mock()
            closure.closure = MODULE.SourceClosure(
                artifact.target,
                hashlib.sha256(artifact.target.encode("ascii")).hexdigest(),
                ("winn_protocol_experimental/go.mod",),
                "22" * 32,
                ("winsvpn.local/winnprotocol",),
            )
            closure.verify.return_value = None
            closure.close.return_value = None
            closures[artifact.target] = closure

        args = mock.Mock(self_check=False, only="linux")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE.argparse.ArgumentParser, "parse_args", return_value=args
        ), mock.patch.object(
            MODULE, "authenticate_reviewed_go", return_value=reviewed_go
        ), mock.patch.object(
            MODULE, "_linux_artifacts", return_value=artifacts
        ), mock.patch.object(
            MODULE, "bind_source_closures", return_value=closures
        ), mock.patch.object(
            MODULE, "newest_source_mtime", return_value=(1.0, "source.go")
        ), mock.patch.object(
            MODULE,
            "check",
            side_effect=lambda artifact, *a, **k: MODULE.Result(
                artifact, "FRESH", shipped_mtime=1.0,
                shipped_digest="33" * 32, rebuilt_digest="33" * 32,
            ),
        ) as checked, mock.patch.object(
            MODULE.tempfile, "mkdtemp", return_value="/private/tmp/freshness-fixture"
        ), mock.patch.object(
            MODULE.shutil, "rmtree"
        ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            status = MODULE.main()
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertIn("PASS: all 2 checked shipped native artifact(s)", stdout.getvalue())
        self.assertEqual(
            [call.args[0].target for call in checked.call_args_list],
            ["datapath-linux-amd64", "datapath-linux-arm64"],
        )
        for call in checked.call_args_list:
            self.assertNotIn("consumer", call.kwargs)
        reviewed_go.verify_unchanged.assert_called_once_with()
        reviewed_go.close.assert_called_once_with()

    def test_linux_cli_checks_raw_and_tar_artifacts_of_one_target_separately(self) -> None:
        artifacts = (
            MODULE.Artifact(
                "build/linux/x64/release/bundle/winn-datapath",
                "datapath-linux-amd64",
                "linux",
                "raw",
                kind="elf",
                arch="amd64",
            ),
            MODULE.Artifact(
                "web/downloads/wins-vpn-linux-x64.tar.gz",
                "datapath-linux-amd64",
                "linux",
                "package",
                kind="linux-package",
                arch="amd64",
                member="winn-datapath",
            ),
        )
        args = mock.Mock(self_check=False, only="linux")
        reviewed_go = mock.Mock()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE.argparse.ArgumentParser, "parse_args", return_value=args
        ), mock.patch.object(
            MODULE, "authenticate_reviewed_go", return_value=reviewed_go
        ), mock.patch.object(
            MODULE, "_linux_artifacts", return_value=artifacts
        ), mock.patch.object(
            MODULE, "bind_source_closures"
        ) as bind, mock.patch.object(
            MODULE.tempfile, "mkdtemp", return_value="/private/tmp/freshness-fixture"
        ), mock.patch.object(
            MODULE.shutil, "rmtree"
        ), mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", stderr):
            status = MODULE.main()
        # One target, two artifacts: the old single-use transaction collision
        # refusal is gone. The pair is still refused here, but only because
        # the arm64 Linux target is not declared.
        self.assertEqual(status, 2)
        self.assertNotIn("collide", stderr.getvalue())
        self.assertIn("every declared Linux x64/arm64 target", stderr.getvalue())
        bind.assert_not_called()
        reviewed_go.close.assert_not_called()

    def test_real_linux_cli_requires_reviewed_go_custody(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(ROOT / "tools/verify_shipped_native_artifact_freshness.py"),
                "--only",
                "linux",
            ],
            cwd=ROOT,
            env={"PATH": MODULE.SYSTEM_PATH},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("collide", completed.stderr)
        self.assertIn("exact reviewed Go custody is unavailable", completed.stderr)
        self.assertIn(MODULE.REVIEWED_GO_ROOT_ENV, completed.stderr)
        self.assertNotIn("descendant-containment supervisor", completed.stderr)

    def test_linux_cli_refuses_incomplete_declared_host_pair(self) -> None:
        artifact = MODULE.Artifact(
            "build/linux/arm64/release/bundle/winn-datapath",
            "datapath-linux-arm64",
            "linux",
            "test",
            kind="elf",
            arch="arm64",
        )
        reviewed_go = mock.Mock()
        closure = mock.Mock()
        closure.closure = MODULE.SourceClosure(
            artifact.target,
            "11" * 32,
            ("winn_protocol_experimental/go.mod",),
            "22" * 32,
            ("winsvpn.local/winnprotocol",),
        )
        closure.verify.return_value = None
        closure.close.return_value = None
        result = MODULE.Result(
            artifact,
            "FRESH",
            shipped_mtime=1.0,
            shipped_digest="33" * 32,
            rebuilt_digest="33" * 32,
        )
        args = mock.Mock(self_check=False, only="linux")
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE.argparse.ArgumentParser, "parse_args", return_value=args
        ), mock.patch.object(
            MODULE, "authenticate_reviewed_go", return_value=reviewed_go
        ), mock.patch.object(
            MODULE, "_linux_artifacts", return_value=(artifact,)
        ), mock.patch.object(
            MODULE,
            "bind_source_closures",
            return_value={artifact.target: closure},
        ), mock.patch.object(
            MODULE, "newest_source_mtime", return_value=(1.0, "source.go")
        ), mock.patch.object(
            MODULE, "check", return_value=result
        ), mock.patch.object(
            MODULE.tempfile, "mkdtemp", return_value="/private/tmp/freshness-fixture"
        ), mock.patch.object(
            MODULE.shutil, "rmtree"
        ), mock.patch("sys.stdout", io.StringIO()), mock.patch(
            "sys.stderr", stderr
        ):
            status = MODULE.main()
        self.assertEqual(status, 2)
        self.assertIn("every declared Linux x64/arm64 target", stderr.getvalue())

    def test_cli_self_check_success_is_explicitly_non_release(self) -> None:
        artifact = MODULE.Artifact(
            "selfcheck-arm64",
            "datapath-linux-arm64",
            "linux",
            "self-check",
            kind="elf",
            arch="arm64",
        )
        reviewed_go = mock.Mock()
        closure = mock.Mock()
        closure.verify.return_value = None
        closure.close.return_value = None
        args = mock.Mock(self_check=True, only=None)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE.argparse.ArgumentParser, "parse_args", return_value=args
        ), mock.patch.object(
            MODULE, "authenticate_reviewed_go", return_value=reviewed_go
        ), mock.patch.object(
            MODULE, "_self_check_pairs", return_value=((artifact.target, "out", artifact),)
        ), mock.patch.object(
            MODULE,
            "bind_source_closures",
            return_value={artifact.target: closure},
        ), mock.patch.object(
            MODULE, "self_check", return_value=0
        ) as diagnostic, mock.patch.object(
            MODULE.tempfile, "mkdtemp", return_value="/private/tmp/freshness-self-check"
        ), mock.patch.object(
            MODULE.shutil, "rmtree"
        ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            status = MODULE.main()
        self.assertEqual(status, MODULE.SELF_CHECK_DIAGNOSTIC_EXIT)
        self.assertNotEqual(status, 0)
        self.assertIn("SELF-CHECK DIAGNOSTIC PASS", stderr.getvalue())
        self.assertIn("not a release PASS", stderr.getvalue())
        self.assertNotIn("Every shipped native artifact", stdout.getvalue())
        diagnostic.assert_called_once_with(
            "/private/tmp/freshness-self-check",
            reviewed_go,
            {artifact.target: closure},
        )
        closure.verify.assert_called_once_with()
        closure.close.assert_called_once_with()
        reviewed_go.verify_unchanged.assert_called_once_with()
        reviewed_go.close.assert_called_once_with()

    def test_higher_artifact_parent_swap_restore_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repo = root / "repo"
            artifact_path = repo / "nested" / "libwinnengine.so"
            artifact_path.parent.mkdir(parents=True)
            current = real_elf("arm64")
            artifact_path.write_bytes(current)
            reference = root / "reference.so"
            reference.write_bytes(current)
            artifact = MODULE.Artifact(
                "nested/libwinnengine.so",
                "datapath-android-arm64",
                "android",
                "test",
                kind="elf",
                arch="arm64",
            )

            def swap_restore(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                saved = root / "repo.saved"
                repo.rename(saved)
                substitute = repo / "nested"
                substitute.mkdir(parents=True)
                (substitute / "libwinnengine.so").write_bytes(
                    real_elf("arm64") + b"substitute"
                )
                shutil.rmtree(repo)
                saved.rename(repo)
                return True, retained_reference(reference, artifact.target), ""

            with mock.patch.object(MODULE, "REPO_ROOT", str(repo)), mock.patch.object(
                MODULE, "build_reference", side_effect=swap_restore
            ):
                result = MODULE.check(artifact, str(root), mock.Mock())
            self.assertEqual(result.verdict, "INVALID")
            self.assertRegex(result.detail, r"descriptor (?:mutation event|identity changed)")

    def _assert_late_reference_parent_attack(self, restore: bool) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repo = root / "repo"
            repo.mkdir()
            body = real_elf("arm64")
            (repo / "engine.so").write_bytes(body)
            source_reference = root / "reference" / "engine.so"
            source_reference.parent.mkdir()
            source_reference.write_bytes(body)
            artifact = MODULE.Artifact(
                "engine.so", "datapath-android-arm64", "android", "test",
                kind="elf", arch="arm64",
            )
            ready = threading.Event()
            attacked = threading.Event()
            retained: dict[str, object] = {}
            errors: list[BaseException] = []

            def rebuilt_reference(
                target: str, *args: object, **kwargs: object
            ) -> tuple[bool, object, str]:
                reference = retained_reference(source_reference, target)
                retained["value"] = reference
                return True, reference, ""

            def attacker() -> None:
                if not ready.wait(5):
                    errors.append(AssertionError("late reference attack was not released"))
                    attacked.set()
                    return
                try:
                    reference = retained["value"]
                    parent = Path(reference.path).parent
                    saved = parent.with_name(parent.name + ".saved")
                    parent.rename(saved)
                    parent.mkdir()
                    (parent / Path(reference.path).name).write_bytes(body + b"stale")
                    if restore:
                        shutil.rmtree(parent)
                        saved.rename(parent)
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    attacked.set()

            calls = 0
            original_fingerprint = MODULE.fingerprint_bytes

            def synchronized_fingerprint(blob: bytes) -> str:
                nonlocal calls
                calls += 1
                if calls == 2:
                    ready.set()
                    if not attacked.wait(5):
                        raise AssertionError("late reference attack did not finish")
                return original_fingerprint(blob)

            worker = threading.Thread(target=attacker, daemon=True)
            worker.start()
            try:
                with mock.patch.object(MODULE, "REPO_ROOT", str(repo)), mock.patch.object(
                    MODULE, "build_reference", side_effect=rebuilt_reference
                ), mock.patch.object(
                    MODULE, "fingerprint_bytes", side_effect=synchronized_fingerprint
                ):
                    with self.assertRaisesRegex(
                        MODULE.CustodyUnavailable,
                        r"descriptor (?:mutation event|identity changed)|"
                        r"descriptor-relative name changed",
                    ):
                        MODULE.check(artifact, str(root), mock.Mock())
            finally:
                worker.join(5)
                reference = retained.get("value")
                if reference is not None:
                    parent = Path(reference.path).parent
                    saved = parent.with_name(parent.name + ".saved")
                    if saved.exists():
                        if parent.exists():
                            shutil.rmtree(parent)
                        saved.rename(parent)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])

    def test_late_reference_parent_replacement_during_fingerprint_is_rejected(
        self,
    ) -> None:
        self._assert_late_reference_parent_attack(False)

    def test_late_reference_parent_swap_restore_during_fingerprint_is_rejected(
        self,
    ) -> None:
        self._assert_late_reference_parent_attack(True)

    def test_source_descriptor_custody_detects_transient_swap_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repo = root / "repo"
            source = root / "source"
            repo.mkdir()
            source.mkdir()
            artifact_path = repo / "engine.so"
            reference = root / "reference.so"
            payload = real_elf("arm64")
            artifact_path.write_bytes(payload)
            reference.write_bytes(payload)
            source_file = source / "main.go"
            source_file.write_text("package main\n", encoding="ascii")
            custody = MODULE.DescriptorCustody(
                "test source closure", MODULE.CustodyUnavailable
            )
            custody.bind_file(str(source_file))
            bound = MODULE.BoundSourceClosure(
                MODULE.SourceClosure("test", "0" * 64, ("source/main.go",)),
                custody,
                str(root / "snapshot"),
            )
            (root / "snapshot").mkdir()
            artifact = MODULE.Artifact(
                "engine.so", "datapath-android-arm64", "android", "test",
                kind="elf", arch="arm64",
            )

            def swap_restore(*args: object, **kwargs: object) -> tuple[bool, object, str]:
                saved = root / "source.saved"
                source.rename(saved)
                source.mkdir()
                (source / "main.go").write_text("package hostile\n", encoding="ascii")
                shutil.rmtree(source)
                saved.rename(source)
                return True, retained_reference(reference, artifact.target), ""

            try:
                with mock.patch.object(MODULE, "REPO_ROOT", str(repo)), mock.patch.object(
                    MODULE, "build_reference", side_effect=swap_restore
                ):
                    with self.assertRaisesRegex(
                        MODULE.CustodyUnavailable,
                        r"descriptor (?:mutation event|identity changed)",
                    ):
                        MODULE.check(artifact, str(root), mock.Mock(), bound)
            finally:
                bound.close()

    def _run_shell(
        self,
        script: str,
        environment: Optional[dict[str, str]] = None,
        timeout: float = 10,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as cwd:
            return MODULE._run_system_descriptor(
                "/bin/sh",
                ["-c", script],
                cwd=cwd,
                environment=environment or {"PATH": MODULE.SYSTEM_PATH},
                timeout=timeout,
            )

    def test_bounded_producer_really_runs_with_exact_environment(self) -> None:
        with mock.patch.dict(os.environ, {"WINS_OUTER_SECRET_NAME": "outer"}):
            completed = self._run_shell(
                'env; printf "stdin=[%s]\\n" "$(cat)"; echo diagnostic >&2; exit 3',
                {"PATH": MODULE.SYSTEM_PATH, "WINS_ONLY": "inner"},
            )
        self.assertEqual(completed.returncode, 3)
        self.assertIn("WINS_ONLY=inner", completed.stdout)
        self.assertNotIn("WINS_OUTER_SECRET_NAME", completed.stdout)
        self.assertNotIn("HOME=", completed.stdout)
        self.assertIn("stdin=[]", completed.stdout)
        self.assertEqual(completed.stderr, "diagnostic\n")
        self.assertEqual(self._run_shell("exit 0").returncode, 0)

    def _assert_in_group_straggler_is_killed(self, outcome: str, leader: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / f"straggler-{outcome}-marker"
            environment = {"PATH": MODULE.SYSTEM_PATH, "MARKER": str(marker)}
            script = (
                '(sleep 0.5; printf straggler > "$MARKER") >/dev/null 2>&1 & '
                + leader
            )
            if outcome in ("timeout", "overflow"):
                expected = "deadline exceeded" if outcome == "timeout" else "exceeded"
                with self.assertRaisesRegex(MODULE.CustodyUnavailable, expected):
                    self._run_shell(
                        script, environment, timeout=0.3 if outcome == "timeout" else 10
                    )
            else:
                completed = self._run_shell(script, environment)
                self.assertEqual(completed.returncode, 0 if outcome == "success" else 7)
            time.sleep(0.8)
            self.assertFalse(marker.exists())

    def test_in_group_straggler_is_killed_after_success(self) -> None:
        self._assert_in_group_straggler_is_killed("success", "exit 0")

    def test_in_group_straggler_is_killed_after_failure(self) -> None:
        self._assert_in_group_straggler_is_killed("failure", "exit 7")

    def test_in_group_straggler_is_killed_on_timeout(self) -> None:
        self._assert_in_group_straggler_is_killed("timeout", "sleep 10")

    def test_in_group_straggler_is_killed_on_overflow(self) -> None:
        self._assert_in_group_straggler_is_killed("overflow", "/usr/bin/yes overflow")

    def test_timeout_and_overflow_kill_the_group_with_sigkill_first(self) -> None:
        for leader, timeout in (("trap '' TERM; sleep 10", 0.3), ("/usr/bin/yes x", 10)):
            sent: list[tuple[int, int]] = []
            real_killpg = os.killpg

            def recording_killpg(pgid: int, signum: int) -> None:
                if signum:
                    sent.append((pgid, signum))
                real_killpg(pgid, signum)

            started = time.monotonic()
            with self.subTest(leader=leader), mock.patch.object(
                MODULE.os, "killpg", side_effect=recording_killpg
            ):
                with self.assertRaises(MODULE.CustodyUnavailable):
                    self._run_shell(leader, timeout=timeout)
            self.assertTrue(sent)
            self.assertEqual(sent[0][1], signal.SIGKILL)
            self.assertLess(time.monotonic() - started, 5)

    def test_normal_exit_still_kills_the_process_group(self) -> None:
        sent: list[int] = []
        real_killpg = os.killpg

        def recording_killpg(pgid: int, signum: int) -> None:
            if signum:
                sent.append(signum)
            real_killpg(pgid, signum)

        with mock.patch.object(MODULE.os, "killpg", side_effect=recording_killpg):
            completed = self._run_shell(
                "(sleep 5) >/dev/null 2>&1 & exit 0"
            )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(sent[:1], [signal.SIGTERM])

    def test_bounded_run_rechecks_the_executable_identity_afterwards(self) -> None:
        with mock.patch.object(
            MODULE,
            "_require_unchanged_executable",
            side_effect=MODULE.CustodyUnavailable("executable changed fixture"),
        ) as recheck:
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "executable changed fixture"
            ):
                self._run_shell("exit 0")
        recheck.assert_called_once()
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "tool"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            fd = os.open(executable, os.O_RDONLY)
            try:
                before = os.fstat(fd)
                MODULE._require_unchanged_executable(fd, before, None)
                MODULE._require_unchanged_executable(fd, before, str(executable))
                time.sleep(0.01)
                with executable.open("ab") as handle:
                    handle.write(b"# changed\n")
                with self.assertRaisesRegex(MODULE.CustodyUnavailable, "changed"):
                    MODULE._require_unchanged_executable(fd, before, None)
            finally:
                os.close(fd)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin immutable execution")
    def test_darwin_mutable_executable_is_refused_before_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "mutable-executable-marker"
            executable = root / "hostile-executable"
            executable.write_text(
                "#!/bin/sh\nprintf executed > \"$MARKER\"\n",
                encoding="ascii",
            )
            executable.chmod(0o500)
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "root-owned immutable executable"
            ):
                MODULE._run_system_descriptor(
                    str(executable),
                    [],
                    cwd=tmp,
                    environment={
                        "PATH": MODULE.SYSTEM_PATH,
                        "MARKER": str(marker),
                    },
                    timeout=5,
                )
            self.assertFalse(marker.exists())

    def test_normalisation_only_masks_authenticated_archive_locations(self) -> None:
        first = REAL_ARCHIVE.read_bytes()
        second = bytearray(first)
        members = MODULE._archive_members(first)
        symbol = next(item for item in members if item.name == "__.SYMDEF SORTED")
        go_object = next(item for item in members if item.name == "go.o")
        second[symbol.header_offset + 16:symbol.header_offset + 28] = b"12345678901 "
        build_id = re.search(
            rb'\xff Go build ID: "([A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)+)"\n \xff',
            go_object.payload,
        )
        self.assertIsNotNone(build_id)
        assert build_id is not None
        identifier = build_id.group(1)
        final_at = (
            go_object.payload_offset + build_id.start(1) + identifier.rfind(b"/") + 1
        )
        final_size = len(identifier) - identifier.rfind(b"/") - 1
        second[final_at:final_at + final_size] = b"Z" * final_size
        timestamp_only = bytearray(first)
        timestamp_only[symbol.header_offset + 16:symbol.header_offset + 28] = (
            b"12345678901 "
        )
        self.assertEqual(
            MODULE.fingerprint_bytes(first),
            MODULE.fingerprint_bytes(bytes(timestamp_only)),
        )
        self.assertNotEqual(
            MODULE.fingerprint_bytes(first), MODULE.fingerprint_bytes(bytes(second))
        )

        changed_action = bytearray(first)
        action_at = go_object.payload_offset + build_id.start(1)
        changed_action[action_at] ^= 1
        self.assertNotEqual(
            MODULE.fingerprint_bytes(first), MODULE.fingerprint_bytes(bytes(changed_action))
        )
        lookalike_a = synthetic_elf("arm64", suffix=b'Go build ID: "alpha"')
        lookalike_b = synthetic_elf("arm64", suffix=b'Go build ID: "bravo"')
        self.assertNotEqual(
            MODULE.fingerprint_bytes(lookalike_a),
            MODULE.fingerprint_bytes(lookalike_b),
        )

    def test_elf_build_id_mask_requires_nonexecuting_pt_note(self) -> None:
        existing = real_elf("arm64")
        self.assertEqual(MODULE.normalise(existing), existing)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "authenticated section"):
            MODULE.fingerprint_bytes(elf_with_pt_note(b"action/contenthash"))
        overlapping = elf_with_pt_note(b"action/contenthash", note_offset=0x100)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "writable or executable"):
            MODULE.fingerprint_bytes(overlapping)
        writable = bytearray(overlapping)
        struct.pack_into("<I", writable, 68, 7)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "writable or executable"):
            MODULE.fingerprint_bytes(bytes(writable))
        trailing = bytearray(elf_with_pt_note(b"action/contenthash"))
        trailing.extend(b"\0" * 12)
        struct.pack_into("<Q", trailing, 152, 44)
        struct.pack_into("<Q", trailing, 160, 44)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "layout is not exact"):
            MODULE.fingerprint_bytes(bytes(trailing))

        duplicate = bytearray(elf_with_pt_note(b"action/contenthash"))
        struct.pack_into("<H", duplicate, 56, 3)
        duplicate[176:232] = duplicate[120:176]
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "PT_NOTE.*overlap"):
            MODULE.fingerprint_bytes(bytes(duplicate))

    def test_elf_build_id_mask_refuses_overlapping_authenticated_sections(self) -> None:
        valid = elf_with_authenticated_build_id(b"action/contenthash")
        masked = MODULE.normalise(valid)
        self.assertNotEqual(masked, valid)
        hostile = elf_with_authenticated_build_id(
            b"action/contenthash", overlapping_rodata=True
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "overlap"):
            MODULE.normalise(hostile)

    def test_elf_section_zero_must_be_exact_sht_null(self) -> None:
        hostile = bytearray(real_elf("arm64"))
        section_offset = struct.unpack_from("<Q", hostile, 40)[0]
        self.assertGreater(section_offset, 0)
        struct.pack_into("<I", hostile, section_offset + 4, 1)
        artifact = MODULE.Artifact(
            "engine.so", "datapath-android-arm64", "android", "test",
            kind="elf", arch="arm64",
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "section header 0.*SHT_NULL"):
            MODULE._validate_binary(
                bytes(hostile), artifact, require_authenticated_role=False
            )

    def test_pe_requires_complete_aligned_headers_and_file_alignment(self) -> None:
        artifact = MODULE.Artifact(
            "engine.exe", "datapath-windows-amd64", "windows", "test",
            kind="pe", arch="amd64",
        )
        pe_offset = 0x80
        optional = pe_offset + 24
        cases = {
            "optional header": (pe_offset + 20, "<H", 224),
            "SizeOfHeaders": (optional + 60, "<I", 0x300),
            "section bytes are outside": (optional + 60, "<I", 0x400),
            "file/section alignment": (optional + 36, "<I", 0x100),
        }
        for expected, (offset, encoding, value) in cases.items():
            with self.subTest(expected=expected):
                hostile = bytearray(synthetic_pe("amd64"))
                struct.pack_into(encoding, hostile, offset, value)
                with self.assertRaisesRegex(MODULE.ArtifactInvalid, expected):
                    MODULE._validate_binary(
                        bytes(hostile), artifact, require_authenticated_role=False
                    )

    def test_pe_accepts_go_linker_header_padding(self) -> None:
        # The Go linker sets SizeOfHeaders above the rounded minimum. Shift
        # both sections of the synthetic image by one FileAlignment and
        # declare the larger header area, as a real Go PE does.
        artifact = MODULE.Artifact(
            "engine.exe", "datapath-windows-amd64", "windows", "test",
            kind="pe", arch="amd64",
        )
        original = synthetic_pe("amd64")
        padded = bytearray(original[:0x200] + bytes(0x200) + original[0x200:])
        optional = 0x80 + 24
        struct.pack_into("<I", padded, optional + 60, 0x400)
        section_table = optional + struct.unpack_from("<H", padded, 0x80 + 20)[0]
        for index in range(struct.unpack_from("<H", padded, 0x80 + 6)[0]):
            raw_at = section_table + index * 40 + 20
            raw = struct.unpack_from("<I", padded, raw_at)[0]
            if raw:
                struct.pack_into("<I", padded, raw_at, raw + 0x200)
        MODULE._validate_binary(bytes(padded), artifact, require_authenticated_role=False)

        # Headers that end past 0x200 round up to 0x400; an aligned but
        # smaller SizeOfHeaders must still be refused.
        relocated = bytearray(len(original) + 0x200)
        relocated[:0x40] = original[:0x40]
        struct.pack_into("<I", relocated, 0x3C, 0x180)
        relocated[0x180:0x2E0] = original[0x80:0x1E0]
        relocated[0x400:] = original[0x200:]
        optional = 0x180 + 24
        struct.pack_into("<I", relocated, optional + 60, 0x400)
        section_table = optional + struct.unpack_from("<H", relocated, 0x180 + 20)[0]
        for index in range(struct.unpack_from("<H", relocated, 0x180 + 6)[0]):
            raw_at = section_table + index * 40 + 20
            raw = struct.unpack_from("<I", relocated, raw_at)[0]
            if raw:
                struct.pack_into("<I", relocated, raw_at, raw + 0x200)
        MODULE._validate_binary(bytes(relocated), artifact, require_authenticated_role=False)
        struct.pack_into("<I", relocated, optional + 60, 0x200)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "SizeOfHeaders"):
            MODULE._validate_binary(
                bytes(relocated), artifact, require_authenticated_role=False
            )

    def test_elf_core_role_requires_authenticated_main_symbol(self) -> None:
        body = real_elf("arm64")
        self.assertIn(b"main.main\0", body)
        hostile = body.replace(b"main.main\0", b"xxxx.xxxx\0")
        artifact = MODULE.Artifact(
            "engine.so", "datapath-android-arm64", "android", "test",
            kind="elf", arch="arm64",
        )
        with self.assertRaisesRegex(
            MODULE.ArtifactInvalid, "authenticated Go symbols"
        ):
            MODULE._validate_binary(
                hostile, artifact, require_authenticated_role=False
            )

    def test_elf_role_evidence_must_be_executable_marker_and_real_code(self) -> None:
        nonexecuting_marker = synthetic_elf("arm64", marker=False) + MODULE.WINN_MARKER
        artifact = MODULE.Artifact(
            "engine.so", "datapath-android-arm64", "android", "test",
            kind="elf", arch="arm64",
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "substantive.*executable"):
            MODULE._validate_binary(nonexecuting_marker, artifact)

        no_export = bytearray(synthetic_elf("arm64"))
        struct.pack_into("<H", no_export, 16, 3)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "substantive.*executable"):
            MODULE._validate_binary(bytes(no_export), artifact)

    def test_markers_and_symbol_names_are_not_authenticated_role_identity(self) -> None:
        elf_artifact = MODULE.Artifact(
            "engine.so", "datapath-android-arm64", "android", "test",
            kind="elf", arch="arm64",
        )
        marker_only_elf = synthetic_elf("arm64")
        self.assertEqual(len(marker_only_elf), 288)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "substantive.*executable"):
            MODULE._validate_binary(
                marker_only_elf,
                elf_artifact,
                require_authenticated_role=False,
            )
        real_elf_blob = real_elf("arm64")
        MODULE._validate_binary(
            real_elf_blob,
            elf_artifact,
            require_authenticated_role=False,
        )

        wrapper_artifact = MODULE.Artifact(
            "wrapper.dylib", "apple-wrapper-iphoneos", "apple", "test",
            kind="apple-wrapper", role="core+relay", arch="arm64",
            platform="iphoneos",
        )
        arbitrary_words_and_symbols = synthetic_macho("arm64", "iphoneos")
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "OWNER-BLOCKED role identity"):
            MODULE._validate_binary(arbitrary_words_and_symbols, wrapper_artifact)

        archive_artifact = MODULE.Artifact(
            "engine.a", "datapath-ios-arm64", "apple", "test",
            kind="apple-archive", arch="arm64", platform="iphoneos",
        )
        substantive_archive = REAL_ARCHIVE.read_bytes()
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "OWNER-BLOCKED role identity"):
            MODULE._validate_binary(substantive_archive, archive_artifact)
        zero_code_archive = bytearray(substantive_archive)
        go_object = next(
            member
            for member in MODULE._archive_members(substantive_archive)
            if member.name == "go.o"
        )
        for layout in MODULE._macho_slices(go_object.payload):
            for section in layout.sections:
                if section.segment == "__TEXT" and section.name == "__text":
                    start = go_object.payload_offset + section.offset
                    zero_code_archive[start:start + section.size] = b"\0" * section.size
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "substantive.*executable"):
            MODULE._validate_binary(
                bytes(zero_code_archive),
                archive_artifact,
            )

        marker_only_macho = bytearray(synthetic_macho("arm64", "iphoneos"))
        macho_layout = MODULE._macho_slices(bytes(marker_only_macho))[0]
        text_section = next(
            section
            for section in macho_layout.sections
            if section.segment == "__TEXT" and section.name == "__text"
        )
        marker_payload = (
            MODULE.WINN_MARKER
            * ((text_section.size // len(MODULE.WINN_MARKER)) + 1)
        )[:text_section.size]
        marker_only_macho[
            text_section.offset:text_section.offset + text_section.size
        ] = marker_payload
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "implementations"):
            MODULE._validate_binary(
                bytes(marker_only_macho),
                wrapper_artifact,
                require_authenticated_role=False,
            )

    def test_macho_executable_text_is_never_normalised(self) -> None:
        archive = bytearray(REAL_ARCHIVE.read_bytes())
        go_object = next(
            item for item in MODULE._archive_members(bytes(archive)) if item.name == "go.o"
        )
        build_id = re.search(
            rb'\xff Go build ID: "([A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)+)"\n \xff',
            go_object.payload,
        )
        self.assertIsNotNone(build_id)
        assert build_id is not None
        changed = bytearray(archive)
        changed[go_object.payload_offset + build_id.start(1)] ^= 1
        self.assertNotEqual(
            MODULE.fingerprint_bytes(bytes(archive)),
            MODULE.fingerprint_bytes(bytes(changed)),
        )

    def test_macho_initprot_must_be_subset_of_maxprot(self) -> None:
        hostile = bytearray(synthetic_macho("arm64", "iphoneos"))
        struct.pack_into("<I", hostile, 32 + 56, 1)
        struct.pack_into("<I", hostile, 32 + 60, 5)
        artifact = MODULE.Artifact(
            "wrapper.dylib", "apple-wrapper-iphoneos", "apple", "test",
            kind="apple-wrapper", role="core+relay", arch="arm64",
            platform="iphoneos",
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "initprot.*subset.*maxprot"):
            MODULE._validate_binary(
                bytes(hostile), artifact, require_authenticated_role=False
            )

    def test_macho_section_export_requires_nonzero_in_range_value(self) -> None:
        hostile = bytearray(synthetic_macho("arm64", "iphoneos"))
        command_cursor = 32
        symbol_offset = 0
        for _ in range(struct.unpack_from("<I", hostile, 16)[0]):
            command, command_size = struct.unpack_from("<2I", hostile, command_cursor)
            if command == 0x2:
                symbol_offset = struct.unpack_from("<I", hostile, command_cursor + 8)[0]
                break
            command_cursor += command_size
        self.assertGreater(symbol_offset, 0)
        struct.pack_into("<Q", hostile, symbol_offset + 8, 0)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "outside its section"):
            MODULE._validate_binary(
                bytes(hostile),
                MODULE.Artifact(
                    "wrapper.dylib", "apple-wrapper-iphoneos", "apple", "test",
                    kind="apple-wrapper", role="core+relay", arch="arm64",
                    platform="iphoneos",
                ),
            )

    def test_macho_required_roles_cannot_alias_one_text_byte(self) -> None:
        hostile = bytearray(synthetic_macho("arm64", "iphoneos"))
        command_cursor = 32
        symbol_offset = 0
        for _ in range(struct.unpack_from("<I", hostile, 16)[0]):
            command, command_size = struct.unpack_from("<2I", hostile, command_cursor)
            if command == 0x2:
                symbol_offset = struct.unpack_from("<I", hostile, command_cursor + 8)[0]
                break
            command_cursor += command_size
        self.assertGreater(symbol_offset, 0)
        first_value = struct.unpack_from("<Q", hostile, symbol_offset + 8)[0]
        for index in range(len(MODULE.APPLE_REQUIRED_SYMBOLS)):
            struct.pack_into("<Q", hostile, symbol_offset + index * 16 + 8, first_value)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "distinct.*__TEXT,__text"):
            MODULE._validate_binary(
                bytes(hostile),
                MODULE.Artifact(
                    "wrapper.dylib", "apple-wrapper-iphoneos", "apple", "test",
                    kind="apple-wrapper", role="core+relay", arch="arm64",
                    platform="iphoneos",
                ),
            )

    def test_macho_arm64_role_implementation_must_be_aligned_code(self) -> None:
        hostile = bytearray(synthetic_macho("arm64", "iphoneos"))
        command_cursor = 32
        symbol_offset = 0
        for _ in range(struct.unpack_from("<I", hostile, 16)[0]):
            command, command_size = struct.unpack_from("<2I", hostile, command_cursor)
            if command == 0x2:
                symbol_offset = struct.unpack_from("<I", hostile, command_cursor + 8)[0]
                break
            command_cursor += command_size
        first = struct.unpack_from("<Q", hostile, symbol_offset + 8)[0]
        struct.pack_into("<Q", hostile, symbol_offset + 8, first + 1)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "aligned non-overlapping"):
            MODULE._validate_binary(
                bytes(hostile),
                MODULE.Artifact(
                    "wrapper.dylib", "apple-wrapper-iphoneos", "apple", "test",
                    kind="apple-wrapper", role="core+relay", arch="arm64",
                    platform="iphoneos",
                ),
            )

    def test_bsd_ranlib_offset_must_name_real_member_header(self) -> None:
        archive = bytearray(REAL_ARCHIVE.read_bytes())
        members = MODULE._archive_members(bytes(archive))
        symbol = next(item for item in members if item.name == "__.SYMDEF SORTED")
        wrong_member = next(
            item for item in members
            if item.name not in ("__.SYMDEF", "__.SYMDEF SORTED", "go.o")
        )
        table_bytes = struct.unpack_from("<I", archive, symbol.payload_offset)[0]
        strings_at = symbol.payload_offset + 4 + table_bytes
        string_bytes = struct.unpack_from("<I", archive, strings_at)[0]
        strings = bytes(archive[strings_at + 4:strings_at + 4 + string_bytes])
        for record in range(0, table_bytes, 8):
            string_at = struct.unpack_from("<I", archive, symbol.payload_offset + 4 + record)[0]
            string_end = strings.find(b"\0", string_at)
            name = strings[string_at:string_end]
            if name.startswith(b"__cgoexp_") and name.endswith(b"_WinnTunnelCreateWinn3"):
                struct.pack_into(
                    "<I",
                    archive,
                    symbol.payload_offset + 8 + record,
                    wrong_member.header_offset,
                )
                break
        else:
            self.fail("real archive has no WinnTunnelCreateWinn3 cgo export receipt")
        artifact = MODULE.Artifact(
            "engine.a", "datapath-ios-arm64", "apple", "test",
            kind="apple-archive", arch="arm64", platform="iphoneos",
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "symbol table"):
            MODULE._validate_binary(bytes(archive), artifact)

    def test_bsd_ranlib_role_symbol_must_resolve_to_member_executable_text(self) -> None:
        raw = b"__cgoexp_deadbeef_WinnTunnelCreateWinn3"
        strings = raw + b"\0"
        payload = (
            struct.pack("<I", 8)
            + struct.pack("<II", 0, 8)
            + struct.pack("<I", len(strings))
            + strings
        )
        name = raw.decode("ascii").removeprefix("_")
        hostile = MODULE.MachoSliceLayout(
            "arm64", 1, MODULE.MACHO_PLATFORMS["iphoneos"], 0, 64,
            (), frozenset(), (), frozenset({name}),
            ((name, 4, "__DATA", "__data"),),
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "symbol table"):
            MODULE._validate_bsd_symbol_table(payload, {8: (hostile,)}, 8)

    def test_bsd_ranlib_string_offset_must_start_at_a_symbol_boundary(self) -> None:
        raw = b"junk\0__cgoexp_deadbeef_WinnTunnelCreateWinn3\0"
        interior = raw.index(b"__cgoexp") + 1
        payload = (
            struct.pack("<I", 8)
            + struct.pack("<II", interior, 8)
            + struct.pack("<I", len(raw))
            + raw
        )
        name = raw[interior:].split(b"\0", 1)[0].decode("ascii").removeprefix("_")
        layout = MODULE.MachoSliceLayout(
            "arm64", 1, MODULE.MACHO_PLATFORMS["iphoneos"], 0, 64,
            (), frozenset(), (), frozenset({name}),
            ((name, 4, "__TEXT", "__text"),),
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "symbol table"):
            MODULE._validate_bsd_symbol_table(payload, {8: (layout,)}, 8)

    def test_bsd_ranlib_rejects_duplicate_symbol_member_records(self) -> None:
        raw = b"_WinnTunnelCreateWinn3\0"
        payload = (
            struct.pack("<I", 16)
            + struct.pack("<II", 0, 8)
            + struct.pack("<II", 0, 8)
            + struct.pack("<I", len(raw))
            + raw
        )
        layout = MODULE.MachoSliceLayout(
            "arm64", 1, MODULE.MACHO_PLATFORMS["iphoneos"], 0, 64,
            (), frozenset(), (), frozenset({"WinnTunnelCreateWinn3"}),
            (("WinnTunnelCreateWinn3", 4, "__TEXT", "__text"),),
        )
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "symbol table"):
            MODULE._validate_bsd_symbol_table(payload, {8: (layout,)}, 8)

    def test_android_build_refuses_ambient_ndk_without_custody_pin(self) -> None:
        # The ambient ANDROID_NDK_HOME is never consulted: only the NDK root
        # named by WINS_FRESHNESS_NDK_ROOT (or the pinned default under HOME)
        # whose revision and tree digest match tools/toolchain-pins.json.
        reviewed = mock.Mock()
        closure = mock.Mock(snapshot_root="/private/source")
        with tempfile.TemporaryDirectory() as tmp:
            unpinned = Path(tmp) / "ndk"
            unpinned.mkdir()
            (unpinned / "source.properties").write_text(
                "Pkg.Revision = 30.0.16248370\n", encoding="ascii"
            )
            for overrides in (
                {"WINS_FRESHNESS_NDK_ROOT": str(unpinned)},
                {"WINS_FRESHNESS_NDK_ROOT": "", "HOME": str(Path(tmp) / "empty-home")},
            ):
                with self.subTest(overrides=overrides), mock.patch.dict(
                    os.environ,
                    {
                        "ANDROID_NDK_HOME": "/hostile/ndk",
                        "ANDROID_HOME": "/hostile/sdk",
                        **overrides,
                    },
                ), mock.patch.object(
                    MODULE.subprocess, "run", side_effect=AssertionError("must not execute")
                ), mock.patch.object(
                    MODULE,
                    "_run_system_descriptor",
                    side_effect=AssertionError("must not execute"),
                ):
                    if not os.environ.get("WINS_FRESHNESS_NDK_ROOT"):
                        os.environ.pop("WINS_FRESHNESS_NDK_ROOT", None)
                    ok, _, log = MODULE.build_reference(
                        "datapath-android-arm64", "engine.so", tempfile.gettempdir(),
                        reviewed, closure,
                    )
                self.assertFalse(ok)
                self.assertIn("OWNER-BLOCKED", log)
                self.assertIn("Android toolchain", log)
                self.assertNotIn("/hostile/ndk", log)

    def test_every_mobile_and_apple_target_routes_to_external_authority(self) -> None:
        targets = {
            "datapath-android-arm64": "Android toolchain",
            "datapath-android-arm": "Android toolchain",
            "datapath-android-amd64": "Android toolchain",
            "datapath-ios-arm64": "Apple authority",
            "datapath-iossimulator-arm64": "Apple authority",
            "datapath-iossimulator-amd64": "Apple authority",
            "datapath-archive-darwin-arm64": "Apple authority",
            "datapath-archive-darwin-amd64": "Apple authority",
            "apple-wrapper-iphoneos": "Apple authority",
            "apple-wrapper-iphonesimulator": "Apple authority",
            "apple-wrapper-macosx": "Apple authority",
        }
        with tempfile.TemporaryDirectory() as tmp:
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            for target, expected in targets.items():
                with self.subTest(target=target), mock.patch.object(
                    MODULE,
                    "_bind_android_toolchain_custody",
                    side_effect=MODULE.CustodyUnavailable("Android authority absent"),
                ) as android, mock.patch.object(
                    MODULE,
                    "_bind_apple_toolchain_custody",
                    side_effect=MODULE.CustodyUnavailable("Apple authority absent"),
                ) as apple, mock.patch.object(
                    MODULE.subprocess,
                    "run",
                    side_effect=AssertionError("producer must not run without authority"),
                ):
                    ok, output, log = MODULE.build_reference(
                        target, "output.bin", tmp, mock.Mock(), closure
                    )
                self.assertFalse(ok)
                self.assertIsNone(output)
                self.assertIn("OWNER-BLOCKED", log)
                self.assertIn(expected, log)
                if target.startswith("datapath-android-"):
                    android.assert_called_once_with(target)
                    apple.assert_not_called()
                else:
                    apple.assert_called_once()
                    android.assert_not_called()

    def test_provisioned_android_target_reaches_authenticated_ndk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            custody = mock.Mock()
            toolchain = MODULE.PlatformToolchainCustody(
                custody,
                {
                    "ANDROID_NDK_HOME": "/Users/release/.local/android-sdk/ndk/30.0.16248370",
                    "ANDROID_NDK_ROOT": "/Users/release/.local/android-sdk/ndk/30.0.16248370",
                    "WINS_ANDROID_NDK_ROOT": "/Users/release/.local/android-sdk/ndk/30.0.16248370",
                },
            )
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {
                "ANDROID_HOME": "/hostile/sdk",
                "ANDROID_SDK_ROOT": "/hostile/sdk",
                "ANDROID_NDK_HOME": "/hostile/ndk",
                "ANDROID_NDK_ROOT": "/hostile/ndk",
            }
            reviewed.pass_fds.return_value = ()
            closure.retained_fd.return_value = 123

            def run(command: list[str], **kwargs: object) -> object:
                self.assertEqual(
                    kwargs["env"]["ANDROID_NDK_HOME"],
                    "/Users/release/.local/android-sdk/ndk/30.0.16248370",
                )
                self.assertEqual(
                    kwargs["env"]["ANDROID_NDK_ROOT"],
                    "/Users/release/.local/android-sdk/ndk/30.0.16248370",
                )
                self.assertEqual(
                    kwargs["env"]["WINS_ANDROID_NDK_ROOT"],
                    "/Users/release/.local/android-sdk/ndk/30.0.16248370",
                )
                self.assertNotIn("ANDROID_HOME", kwargs["env"])
                self.assertNotIn("ANDROID_SDK_ROOT", kwargs["env"])
                return subprocess.CompletedProcess(
                    command, 73, "", "OWNER-BLOCKED: external Android producer authority\n"
                )

            with mock.patch.object(
                MODULE, "_bind_android_toolchain_custody", return_value=toolchain
            ), mock.patch.object(
                MODULE, "_run_system_descriptor", side_effect=descriptor_run_adapter(run)
            ):
                ok, output, log = MODULE.build_reference(
                    "datapath-android-arm64",
                    "engine.so",
                    str(Path(tmp) / "output"),
                    reviewed,
                    closure,
                )
            self.assertFalse(ok)
            self.assertIsNone(output)
            self.assertIn("OWNER-BLOCKED", log)
            custody.verify.assert_called()
            custody.close.assert_called_once_with()

    def test_producer_executes_only_private_snapshot_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = Path(tmp) / "snapshot"
            script = snapshot / "tools" / "build_winn_protocol_engine.sh"
            script.parent.mkdir(parents=True)
            script.write_text("#!/bin/bash\n", encoding="ascii")
            output_dir = Path(tmp) / "out"
            closure = mock.Mock(snapshot_root=str(snapshot))
            closure.path.side_effect = lambda path: str(
                snapshot / Path(path).relative_to(MODULE.REPO_ROOT)
            )
            builder_fd = os.open(script, os.O_RDONLY)
            closure.retained_fd.return_value = builder_fd
            closure.retained_root_fd.return_value = builder_fd
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            reviewed.pass_fds.return_value = ()

            def run(command: list[str], **kwargs: object) -> object:
                self.assertEqual(kwargs["cwd"], str(snapshot))
                # Plain bash on the sealed snapshot copy: no retained custody
                # descriptor handoff and no -p /dev/fd launch.
                self.assertEqual(command[:2], ["/bin/bash", str(script)])
                self.assertNotIn("-p", command)
                environment = kwargs["env"]
                self.assertFalse(
                    any(name.startswith("WINS_RETAINED_") for name in environment)
                )
                self.assertEqual(
                    environment["WINS_WINN_SOURCE_ROOT"],
                    os.path.realpath(
                        snapshot / Path(MODULE.MODULE_DIR).relative_to(MODULE.REPO_ROOT)
                    ),
                )
                self.assertEqual(
                    environment["WINS_WINN_SOURCE_TREE_SHA256"], FIXED_RECEIPT_HASH
                )
                self.assertIn("WINS_RELEASE_GO_ROOT", environment)
                self.assertNotIn(MODULE.BUILD_SCRIPT, command)
                Path(command[-1]).parent.mkdir(parents=True, exist_ok=True)
                write_claimed_output(kwargs, real_elf("arm64"))
                return subprocess.CompletedProcess(
                    command,
                    0,
                    producer_receipt_stdout(Path(command[-1]), command[-2]),
                    "",
                )

            try:
                with simulated_linux_host(), mock.patch.object(
                    MODULE,
                    "_run_system_descriptor",
                    side_effect=descriptor_run_adapter(run),
                ):
                    ok, _, log = MODULE.build_reference(
                        "datapath-linux-arm64", "engine", str(output_dir), reviewed, closure
                    )
            finally:
                os.close(builder_fd)
            self.assertTrue(ok, log)

    def test_core_producer_closure_binds_exact_release_authority_materials(self) -> None:
        expected = {
            MODULE.BUILD_SCRIPT,
            MODULE.PIN_MANIFEST,
            *MODULE.PRODUCTION_BUILDER_MATERIALS,
        }
        for target in (
            "datapath-linux-amd64",
            "datapath-linux-arm64",
            "datapath-windows-amd64",
            "datapath-windows-arm64",
            "datapath-android-arm64",
            "datapath-android-arm",
            "datapath-android-amd64",
        ):
            with self.subTest(target=target):
                specs = MODULE._target_specs(target)
                self.assertEqual(len(specs), 1)
                self.assertTrue(expected.issubset(set(specs[0].producer_files)))
                self.assertTrue(all(os.path.isfile(path) for path in expected))

    def test_header_only_pseudo_binaries_and_packages_fail_closed(self) -> None:
        elf_header = bytearray(64)
        elf_header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", elf_header, 16, 2, 183)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "ELF|program-header"):
            MODULE._validate_binary(
                bytes(elf_header) + MODULE.WINN_MARKER,
                MODULE.Artifact("bad.so", "x", "android", "test", kind="elf", arch="arm64"),
            )

        pe_header = bytearray(160)
        pe_header[:2] = b"MZ"
        struct.pack_into("<I", pe_header, 0x3C, 64)
        pe_header[64:68] = b"PE\x00\x00"
        struct.pack_into("<H", pe_header, 68, MODULE.PE_MACHINES["amd64"])
        struct.pack_into("<H", pe_header, 88, 0x20B)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "section count|optional header"):
            MODULE._validate_binary(
                bytes(pe_header) + MODULE.WINN_MARKER,
                MODULE.Artifact("bad.exe", "x", "windows", "test", kind="pe", arch="amd64"),
            )

        macho_header = struct.pack(
            "<8I", 0xFEEDFACF, MODULE.MACHO_CPUS["arm64"], 0, 6, 1, 24, 0, 0
        ) + struct.pack("<6I", 0x32, 24, MODULE.MACHO_PLATFORMS["iphoneos"], 0, 0, 0)
        with self.assertRaisesRegex(MODULE.ArtifactInvalid, "no structurally loadable"):
            MODULE._validate_binary(
                macho_header + MODULE.WINN_MARKER + b"\0".join(MODULE.APPLE_REQUIRED_SYMBOLS),
                MODULE.Artifact(
                    "bad.dylib", "x", "apple", "test", kind="apple-wrapper",
                    role="core+relay", arch="arm64", platform="iphoneos",
                ),
            )

        with tempfile.TemporaryDirectory() as tmp:
            package_path = Path(tmp) / "bad.apk"
            with zipfile.ZipFile(package_path, "w") as package:
                package.writestr(
                    "lib/arm64-v8a/libwinnengine.so", synthetic_elf("arm64")
                )
            with self.assertRaisesRegex(MODULE.ArtifactInvalid, "APK is missing"):
                MODULE._read_zip_member(
                    str(package_path),
                    MODULE.Artifact(
                        "bad.apk", "x", "android", "test", kind="android-package",
                        arch="arm64", member="lib/arm64-v8a/libwinnengine.so",
                    ),
                )

            stub_path = Path(tmp) / "header-only.apk"
            with zipfile.ZipFile(stub_path, "w") as package:
                package.writestr("AndroidManifest.xml", struct.pack("<HHI", 3, 8, 8))
                package.writestr("resources.arsc", struct.pack("<HHI", 2, 8, 8))
                package.writestr("classes.dex", minimal_dex())
                package.writestr(
                    "lib/arm64-v8a/libwinnengine.so", synthetic_elf("arm64")
                )
            with self.assertRaisesRegex(MODULE.ArtifactInvalid, "manifest root|string pool"):
                MODULE._read_zip_member(
                    str(stub_path),
                    MODULE.Artifact(
                        "android/devicecheck/header-only.apk", "x", "android", "test",
                        kind="android-package", arch="arm64",
                        member="lib/arm64-v8a/libwinnengine.so",
                    ),
                )

    def test_real_minimal_aab_structure_is_loadable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package_path = Path(tmp) / "app.aab"
            payloads = {
                "arm64-v8a": real_elf("arm64"),
                "armeabi-v7a": real_elf("arm"),
                "x86_64": real_elf("amd64"),
            }
            write_android_package(package_path, payloads, prefix="base/")
            artifact = MODULE.Artifact(
                "app.aab", "datapath-android-arm64", "android", "test",
                kind="android-package", arch="arm64",
                member="base/lib/arm64-v8a/libwinnengine.so",
            )
            extracted = MODULE._read_zip_member(str(package_path), artifact)
            MODULE._validate_binary(
                extracted,
                artifact,
                require_authenticated_role=False,
            )

    def test_self_check_fails_when_zero_reference_pairs_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            MODULE,
            "build_reference",
            return_value=(False, None, "unavailable"),
        ):
            self.assertEqual(
                MODULE.self_check(tmp, mock.Mock()), len(MODULE._self_check_pairs())
            )

    def test_self_check_rejects_one_byte_outputs_and_partial_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            counter = 0

            def one_byte(
                target: str, *args: object, **kwargs: object
            ) -> tuple[bool, object, str]:
                nonlocal counter
                counter += 1
                path = Path(tmp) / f"bad-{counter}"
                path.write_bytes(b"x")
                return True, retained_reference(path, target), ""

            with mock.patch.object(MODULE, "build_reference", side_effect=one_byte):
                self.assertEqual(
                    MODULE.self_check(tmp, mock.Mock()), len(MODULE._self_check_pairs())
                )

            first_target = MODULE._self_check_pairs()[0][0]
            counter = 0

            def one_pair(target: str, *args: object, **kwargs: object) -> tuple[bool, object, str]:
                nonlocal counter
                counter += 1
                path = Path(tmp) / f"pair-{counter}"
                if target != first_target:
                    return False, None, "unavailable"
                arch = "arm64" if target.endswith("arm64") else "amd64"
                path.write_bytes(real_elf(arch))
                return True, retained_reference(path, target), ""

            with mock.patch.object(MODULE, "build_reference", side_effect=one_pair):
                self.assertEqual(
                    MODULE.self_check(tmp, mock.Mock()),
                    len(MODULE._self_check_pairs()) - 1,
                )

    def test_self_check_rejects_authenticated_marker_only_pseudo_builds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = MODULE.Artifact(
                "selfcheck-arm64", "datapath-linux-arm64", "linux", "test",
                kind="elf", arch="arm64",
            )
            counter = 0

            def marker_only(
                target: str, *args: object, **kwargs: object
            ) -> tuple[bool, object, str]:
                nonlocal counter
                counter += 1
                path = Path(tmp) / f"marker-only-{counter}"
                payload = synthetic_elf("arm64")
                self.assertEqual(len(payload), 288)
                path.write_bytes(payload)
                return True, retained_reference(path, target), ""

            with mock.patch.object(
                MODULE,
                "_self_check_pairs",
                return_value=((artifact.target, artifact.path, artifact),),
            ), mock.patch.object(MODULE, "build_reference", side_effect=marker_only):
                self.assertEqual(MODULE.self_check(tmp, mock.Mock()), 1)

    def test_self_check_requires_authenticated_role_for_every_valid_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = MODULE.Artifact(
                "selfcheck-arm64", "datapath-linux-arm64", "linux", "test",
                kind="elf", arch="arm64",
            )
            counter = 0

            def unauthenticated(
                target: str, *args: object, **kwargs: object
            ) -> tuple[bool, object, str]:
                nonlocal counter
                counter += 1
                source = Path(tmp) / f"source-{counter}"
                source.write_bytes(real_elf("arm64"))
                private = Path(tempfile.mkdtemp(dir=tmp))
                retained = private / "output"
                shutil.copyfile(source, retained)
                retained.chmod(0o400)
                custody = MODULE.DescriptorCustody(
                    "unauthenticated self-check fixture", MODULE.CustodyUnavailable
                )
                custody.bind_file(str(retained))
                return True, MODULE.RetainedReference(str(retained), custody), ""

            with mock.patch.object(
                MODULE,
                "_self_check_pairs",
                return_value=((artifact.target, artifact.path, artifact),),
            ), mock.patch.object(
                MODULE, "build_reference", side_effect=unauthenticated
            ):
                self.assertEqual(MODULE.self_check(tmp, mock.Mock()), 1)

    def test_self_check_executes_two_distinct_deterministic_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = MODULE.Artifact(
                "selfcheck-arm64", "datapath-linux-arm64", "linux", "test",
                kind="elf", arch="arm64",
            )
            calls: list[tuple[str, str]] = []

            def build(target: str, base: str, *args: object) -> tuple[bool, object, str]:
                calls.append((target, base))
                path = Path(tmp) / base
                path.write_bytes(real_elf("arm64"))
                return True, retained_reference(path, target), ""

            with mock.patch.object(
                MODULE,
                "_self_check_pairs",
                return_value=(("datapath-linux-arm64", "selfcheck-arm64", artifact),),
            ), mock.patch.object(MODULE, "build_reference", side_effect=build):
                self.assertEqual(MODULE.self_check(tmp, mock.Mock()), 0)
            self.assertEqual(
                calls,
                [
                    ("datapath-linux-arm64", "1-selfcheck-arm64"),
                    ("datapath-linux-arm64", "2-selfcheck-arm64"),
                ],
            )

    def test_self_check_rejects_identical_outputs_across_required_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_one = MODULE.Artifact(
                "one", "datapath-linux-arm64", "linux", "test",
                kind="elf", arch="arm64",
            )
            artifact_two = MODULE.Artifact(
                "two", "second-linux-arm64", "linux", "test",
                kind="elf", arch="arm64",
            )
            counter = 0

            def same_output(
                target: str, base: str, *args: object
            ) -> tuple[bool, object, str]:
                nonlocal counter
                counter += 1
                path = Path(tmp) / f"same-{counter}"
                path.write_bytes(real_elf("arm64"))
                return True, retained_reference(path, target), ""

            pairs = (
                (artifact_one.target, artifact_one.path, artifact_one),
                (artifact_two.target, artifact_two.path, artifact_two),
            )
            with mock.patch.object(
                MODULE, "_self_check_pairs", return_value=pairs
            ), mock.patch.object(MODULE, "build_reference", side_effect=same_output):
                self.assertGreater(MODULE.self_check(tmp, mock.Mock()), 0)

    def test_self_check_mutation_offset_comes_from_real_format_parser(self) -> None:
        executable = synthetic_elf("arm64")
        hostile_tail = b"non-code-tail" * 1024
        blob = executable + hostile_tail
        artifact = MODULE.Artifact(
            "engine", "datapath-linux-arm64", "linux", "test",
            kind="elf", arch="arm64",
        )
        offset = MODULE._authenticated_executable_code_offset(blob, artifact)
        self.assertLess(offset, len(executable))
        self.assertNotEqual(offset, len(blob) // 2)

    def test_independent_go_list_projection_and_repeat_detect_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = MODULE.GoTargetSpec(tmp, ".", "linux", "arm64", False, ())
            stable_json = '{"ImportPath":"example.com/main"}\n'
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            reviewed.run.side_effect = [
                subprocess.CompletedProcess([], 0, stable_json, ""),
                subprocess.CompletedProcess([], 0, stable_json, ""),
                subprocess.CompletedProcess([], 0, "example.com/main\n", ""),
            ]
            packages = MODULE._run_exact_go_list(reviewed, spec, tmp)
            self.assertEqual(packages[0]["ImportPath"], "example.com/main")

            reviewed.run.reset_mock()
            reviewed.run.side_effect = [
                subprocess.CompletedProcess([], 0, stable_json, ""),
                subprocess.CompletedProcess(
                    [], 0, '{"ImportPath":"example.com/changed"}\n', ""
                ),
            ]
            with self.assertRaisesRegex(MODULE.CustodyUnavailable, "listing drifted"):
                MODULE._run_exact_go_list(reviewed, spec, tmp)

    def test_module_verification_is_mandatory_for_sealed_dependencies(self) -> None:
        reviewed = mock.Mock()
        reviewed.build_environment.return_value = {}
        reviewed.run.return_value = subprocess.CompletedProcess(
            [], 1, "", "modified module cache"
        )
        spec = MODULE.GoTargetSpec("/module", ".", "linux", "arm64", False, ())
        with self.assertRaisesRegex(MODULE.CustodyUnavailable, "module verification"):
            MODULE._verify_module_dependencies(reviewed, spec, "/work")

        reviewed.run.return_value = subprocess.CompletedProcess(
            [], 0, "all modules verified\n", ""
        )
        MODULE._verify_module_dependencies(reviewed, spec, "/work")
        self.assertEqual(reviewed.run.call_args.args[0], ["mod", "verify"])
        reviewed.tree_custody.verify.assert_called_once()
        reviewed.module_custody.verify.assert_called_once()

    def test_multi_output_producers_bind_every_built_variant(self) -> None:
        relay = MODULE._target_specs("relay-windows-amd64")
        self.assertEqual({spec.goarch for spec in relay}, {"amd64", "arm64"})
        wrappers = MODULE._target_specs("apple-wrapper-iphoneos")
        self.assertEqual(
            {(spec.goos, spec.goarch) for spec in wrappers},
            {
                ("darwin", "arm64"),
                ("darwin", "amd64"),
                ("ios", "arm64"),
                ("ios", "amd64"),
            },
        )

    def test_post_binding_go_list_omission_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            source = root / "main.go"
            source.write_text("package main\n", encoding="ascii")
            cache = Path(tmp) / "gomodcache"
            cache.mkdir(mode=0o500)
            spec = MODULE.GoTargetSpec(
                str(root), ".", "linux", "arm64", False, (str(source),)
            )
            reviewed = mock.Mock()
            reviewed.gomodcache = str(cache)
            reviewed.module_custody = mock.Mock()
            listed = ({str(source)}, set(), {"example.com/main"})
            omitted = (set(), set(), {"example.com/main"})
            with mock.patch.object(MODULE, "REPO_ROOT", str(root)), mock.patch.object(
                MODULE, "_target_specs", return_value=(spec,)
            ), mock.patch.object(
                MODULE, "_verify_module_dependencies"
            ), mock.patch.object(
                MODULE, "_run_exact_go_list", side_effect=([], [])
            ), mock.patch.object(
                MODULE, "_go_list_paths", side_effect=(listed, omitted)
            ):
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable, "drifted after descriptor binding"
                ):
                    MODULE._bind_source_closure("datapath-linux-arm64", reviewed, tmp)

class SourceSnapshotCustodyTests(unittest.TestCase):
    """The bound source snapshot must not trip its own mutation custody."""

    def _fixture(self, tmp: Path) -> tuple[Path, object, mock.Mock]:
        repo = tmp / "repo"
        module = repo / "mod"
        tools = repo / "tools"
        module.mkdir(parents=True)
        tools.mkdir()
        (module / "go.mod").write_text("module example.com/m\n", encoding="ascii")
        (module / "main.go").write_text("package main\n", encoding="ascii")
        script = tools / "build.sh"
        script.write_text("#!/bin/bash\nexit 0\n", encoding="ascii")
        script.chmod(0o755)
        spec = MODULE.GoTargetSpec(
            str(module), ".", "linux", "arm64", False, (str(script),)
        )
        reviewed = mock.Mock()
        reviewed.gomodcache = str(tmp / "gomodcache")
        reviewed.module_custody = mock.Mock()
        return repo, spec, reviewed

    def _bind(self, tmp: Path, repo: Path, spec: object, reviewed: object) -> object:
        def listing(_reviewed: object, target_spec: object, _workdir: str) -> str:
            return target_spec.module_dir

        def paths(module_dir: str, _reviewed: object) -> tuple[set[str], set[str], set[str]]:
            return (
                {os.path.join(module_dir, "go.mod"), os.path.join(module_dir, "main.go")},
                set(),
                {"example.com/m"},
            )

        work = tmp / "work"
        work.mkdir(mode=0o700)
        with mock.patch.object(MODULE, "REPO_ROOT", str(repo)), mock.patch.object(
            MODULE, "_target_specs", return_value=(spec,)
        ), mock.patch.object(
            MODULE, "_verify_module_dependencies"
        ), mock.patch.object(
            MODULE, "_run_exact_go_list", side_effect=listing
        ), mock.patch.object(
            MODULE, "_go_list_paths", side_effect=paths
        ):
            return MODULE._bind_source_closure("datapath-linux-arm64", reviewed, str(work))

    def test_real_snapshot_binds_without_self_inflicted_mutation_events(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw).resolve()
            repo, spec, reviewed = self._fixture(tmp)
            bound = self._bind(tmp, repo, spec, reviewed)
            try:
                self.assertEqual(
                    bound.closure.files,
                    ("mod/go.mod", "mod/main.go", "tools/build.sh"),
                )
                snapshot = Path(bound.snapshot_root)
                self.assertEqual(
                    (snapshot / "mod" / "main.go").read_bytes(), b"package main\n"
                )
                self.assertEqual(stat.S_IMODE((snapshot / "mod" / "main.go").stat().st_mode), 0o400)
                self.assertEqual(stat.S_IMODE((snapshot / "tools" / "build.sh").stat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o500)
                bound.verify()
                # A later private directory request in the same workdir must
                # not disturb the retained snapshot ancestors.
                MODULE._private_directory(str(tmp / "work"))
                bound.verify()
                with mock.patch.object(MODULE, "REPO_ROOT", str(repo)):
                    fd = bound.retained_fd(str(repo / "tools" / "build.sh"))
                self.assertEqual(os.pread(fd, 64, 0), b"#!/bin/bash\nexit 0\n")
            finally:
                bound.close()
            self.assertFalse(Path(bound.snapshot_root).exists())

    def test_snapshot_tampered_before_binding_is_refused(self) -> None:
        for mode in ("content", "extra-file", "foreign-owner"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as raw:
                tmp = Path(raw).resolve()
                repo, spec, reviewed = self._fixture(tmp)
                original_bind_tree = MODULE.DescriptorCustody.bind_tree
                # A non-root test cannot chown, so the snapshot files are made
                # to look foreign by changing the uid the check compares with.
                foreign_uid = mock.patch.object(
                    MODULE.os, "getuid", return_value=os.getuid() + 1
                )

                def tamper_then_bind(custody: object, root: str, *args: object) -> None:
                    if mode == "foreign-owner":
                        original_bind_tree(custody, root, *args)
                        foreign_uid.start()
                        return
                    target_dir = Path(root) / "mod"
                    target_dir.chmod(0o700)
                    if mode == "content":
                        victim = target_dir / "main.go"
                        victim.chmod(0o600)
                        victim.write_bytes(b"package evil\n")
                        victim.chmod(0o400)
                    else:
                        extra = target_dir / "extra.go"
                        extra.write_bytes(b"package main\n")
                        extra.chmod(0o400)
                    target_dir.chmod(0o500)
                    original_bind_tree(custody, root, *args)

                with mock.patch.object(
                    MODULE.DescriptorCustody, "bind_tree", new=tamper_then_bind
                ):
                    expected = (
                        "outside the bound closure" if mode == "extra-file"
                        else "differs from the bound source"
                    )
                    try:
                        with self.assertRaisesRegex(MODULE.CustodyUnavailable, expected):
                            self._bind(tmp, repo, spec, reviewed)
                    finally:
                        if mode == "foreign-owner":
                            foreign_uid.stop()

    def test_private_directory_leaves_an_already_private_directory_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw).resolve()
            private = tmp / "private"
            private.mkdir(mode=0o700)
            (private / "held").write_bytes(b"x")
            with MODULE.DescriptorCustody("fixture", MODULE.CustodyUnavailable) as custody:
                custody.bind_file(str(private / "held"))
                custody.bind_directory(str(private))
                MODULE._private_directory(str(private))
                custody.verify()
            loose = tmp / "loose"
            loose.mkdir(mode=0o755)
            loose.chmod(0o755)
            MODULE._private_directory(str(loose))
            self.assertEqual(stat.S_IMODE(loose.stat().st_mode), 0o700)
            link = tmp / "link"
            link.symlink_to(private)
            with self.assertRaisesRegex(MODULE.CustodyUnavailable, "unsafe"):
                MODULE._private_directory(str(link))


class ArchiveHeaderPublicationTests(unittest.TestCase):
    """An Apple archive receipt binds the header published beside it."""

    def setUp(self) -> None:
        # Fixture snapshots are not sealed trees, as in the custody tests.
        sealed = mock.patch.object(
            MODULE, "_sealed_tree_digest", return_value=FIXED_RECEIPT_HASH
        )
        sealed.start()
        self.addCleanup(sealed.stop)

    def _build(
        self,
        target: str,
        basename: str,
        mode: str,
    ) -> tuple[bool, object, str]:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "output"
            output_dir.mkdir()
            reference_root = output_dir / ".reference-fixture"
            reference_root.mkdir(mode=0o700)
            if mode == "stale-header":
                (reference_root / (basename[: -len(".a")] + ".h")).write_bytes(
                    b"/* stale header from an earlier generation */\n"
                )
            reviewed = mock.Mock()
            reviewed.build_environment.return_value = {}
            reviewed.pass_fds.return_value = ()
            closure = mock.Mock(snapshot_root=tmp)
            closure.path.side_effect = lambda path: path
            closure.retained_fd.return_value = 123
            closure.retained_root_fd.return_value = 124
            header_text = b"/* generated cgo header */\nvoid WinnStart(void);\n"

            def produce(command: list[str], **kwargs: object) -> object:
                output = Path(command[-1])
                write_claimed_output(kwargs, b"!<arch>\narchive fixture bytes")
                header = Path(str(output)[: -len(".a")] + ".h") if str(output).endswith(".a") else None
                if header is not None and mode != "no-header-file":
                    with header.open("xb") as handle:
                        handle.write(header_text)

                def set_header(record: dict[str, object]) -> None:
                    identity, _, _, package = MODULE._receipt_target_identity(target)
                    record["target"] = identity
                    record["package"] = package
                    artifact = record["artifact"]
                    assert isinstance(artifact, dict)
                    if mode in ("ok", "stale-header", "no-header-file"):
                        artifact["header_sha256"] = hashlib.sha256(header_text).hexdigest()
                    elif mode == "header-mismatch":
                        artifact["header_sha256"] = hashlib.sha256(b"other").hexdigest()
                    elif mode == "header-on-executable":
                        artifact["header_sha256"] = hashlib.sha256(header_text).hexdigest()
                    elif mode == "archive-without-header":
                        artifact["header_sha256"] = None

                return subprocess.CompletedProcess(
                    command, 0, producer_receipt_stdout(output, command[-2], set_header), ""
                )

            with simulated_linux_host(), mock.patch.object(
                MODULE, "_bind_apple_toolchain_custody", return_value=None
            ), mock.patch.object(
                MODULE, "_receipt_platform_identity", return_value={}
            ), mock.patch.object(
                MODULE.tempfile, "mkdtemp", return_value=str(reference_root)
            ), mock.patch.object(
                MODULE,
                "_run_system_descriptor",
                side_effect=descriptor_run_adapter(produce),
            ):
                ok, output, log = MODULE.build_reference(
                    target, basename, str(output_dir), reviewed, closure
                )
            if output is not None:
                output.close()
            return ok, output, log

    def test_archive_receipt_with_its_published_header_is_accepted(self) -> None:
        ok, output, log = self._build(
            "datapath-ios-arm64", "libwinn-datapath.a", "ok"
        )
        self.assertTrue(ok, log)
        self.assertIsNotNone(output)
        self.assertNotIn("not integrated", log)

    def test_archive_header_must_match_the_receipt_and_the_archive_contract(self) -> None:
        cases = (
            ("datapath-ios-arm64", "libwinn-datapath.a", "header-mismatch",
             "archive header bytes differ from the producer receipt"),
            ("datapath-ios-arm64", "libwinn-datapath.a", "archive-without-header",
             "header does not match the archive contract"),
            ("datapath-linux-arm64", "engine", "header-on-executable",
             "header does not match the archive contract"),
        )
        for target, basename, mode, expected in cases:
            with self.subTest(mode=mode):
                ok, output, log = self._build(target, basename, mode)
                self.assertFalse(ok, log)
                self.assertIsNone(output)
                self.assertIn(expected, log)
        ok, output, log = self._build(
            "datapath-ios-arm64", "libwinn-datapath.a", "no-header-file"
        )
        self.assertFalse(ok, log)
        self.assertIsNone(output)
        # A header left by an earlier generation is refused before the build.
        with self.assertRaisesRegex(
            MODULE.CustodyUnavailable, "fresh exclusive generation destination"
        ):
            self._build("datapath-ios-arm64", "libwinn-datapath.a", "stale-header")


class PinnedGoAuthenticationTests(unittest.TestCase):
    """Go and its module cache are accepted by the pins and digests alone.

    The owner retired the ReleaseGo custody (2026-10-09): no /Library
    authority, no issuance file, no root-owned or immutable Go and no
    root-owned module cache. What stays is tools/toolchain-pins.json (bin/go
    sha256, install-tree sha256 for the host, exact `go version`) and the
    sealed module-cache digest, each re-measured after use.
    """

    def _sealed_cache(self, root: Path) -> tuple[Path, Path]:
        cache = root / "sealed-gomodcache"
        module = cache / "example.com" / "dependency@v1.0.0"
        module.mkdir(parents=True, mode=0o700)
        source = module / "go.mod"
        source.write_bytes(b"module example.com/dependency\n")
        source.chmod(0o400)
        module.chmod(0o500)
        module.parent.chmod(0o500)
        cache.chmod(0o500)
        return cache, source

    def _reviewed(self, root: Path, cache: Path) -> object:
        return MODULE.ReviewedGo(
            root=str(root / "go"),
            binary=str(root / "go" / "bin" / "go"),
            retained_root=str(root / "retained-go"),
            retained_binary=str(root / "retained-go" / "bin" / "go"),
            custody_root=str(root / "retained-custody"),
            version="1.27.1",
            binary_sha256="a" * 64,
            tree_sha256="b" * 64,
            archive_sha256="c" * 64,
            identity="go version go1.27.1 darwin/arm64",
            gomodcache=str(cache),
            tree_custody=mock.Mock(),
            module_custody=mock.Mock(),
            gomodcache_tree_sha256=MODULE._sealed_tree_digest(str(cache)),
        )

    def test_pinned_go_root_is_accepted_without_release_go_custody(self) -> None:
        # Every path the verifier opens or lists while authenticating, via
        # the interpreter's audit events (they cannot be unhooked, so the
        # hook records only while this test is inside authenticate()).
        opened: list[str] = []
        recording = [False]

        def audit(event: str, arguments: tuple[object, ...]) -> None:
            if recording[0] and event in ("open", "os.scandir", "os.listdir"):
                if arguments and isinstance(arguments[0], str):
                    opened.append(arguments[0])

        sys.addaudithook(audit)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp))
            recording[0] = True
            try:
                reviewed = fixture.authenticate()
            finally:
                recording[0] = False
            # Anti-vacuity: the hook did see the Go root being read.
            self.assertIn(str(fixture.binary), opened)
            try:
                self.assertEqual(reviewed.identity, fixture.identity)
                self.assertEqual(reviewed.root, str(fixture.go_root))
                self.assertNotEqual(reviewed.retained_root, reviewed.root)
                self.assertEqual(reviewed.gomodcache, os.path.realpath(fixture.module_cache))
                self.assertEqual(reviewed.gomodcache_tree_sha256, fixture.cache_digest())
                attempt = Path(tmp) / "attempt"
                attempt.mkdir(mode=0o700)
                environment = reviewed.build_environment(str(attempt))
                self.assertEqual(environment["GOROOT"], reviewed.retained_root)
                self.assertEqual(environment["GOPROXY"], "off")
                self.assertEqual(environment["GOFLAGS"], "-mod=readonly")
                self.assertEqual(
                    environment["WINS_STORE_GOMODCACHE_TREE_SHA256"],
                    reviewed.gomodcache_tree_sha256,
                )
                self.assertFalse(
                    any(name.startswith("WINS_RELEASE_GO") for name in environment)
                )
                reviewed.verify_unchanged()
                reviewed.verify_module_cache_unchanged()
            finally:
                reviewed.close()
        self.assertEqual([path for path in opened if path.startswith("/Library")], [])

    def test_release_go_custody_is_not_required_anywhere(self) -> None:
        for retired in (
            "RELEASE_GO_AUTHORITY",
            "RELEASE_GO_ISSUANCE_ENV",
            "RELEASE_GO_ROOT_ENV",
            "RELEASE_GO_MATERIALS",
            "RELEASE_GOMODCACHE_AUTHORITY",
            "REVIEWED_GO_SHELL",
            "RetainedGoLauncher",
            "_authenticate_external_release_go",
            "_retained_go_launcher",
            "_require_owner_dependency_digest",
        ):
            self.assertFalse(hasattr(MODULE, retired), retired)
        fields = {item.name for item in dataclasses.fields(MODULE.ReviewedGo)}
        self.assertFalse({"retained_binary_fd", "dependency_digests"} & fields)
        for method in ("execution_path", "pass_fds"):
            self.assertFalse(hasattr(MODULE.ReviewedGo, method), method)
        source = Path(MODULE.__file__).read_text(encoding="utf-8")
        for dropped in (
            "/Library/WinsVPN/ReleaseGo",
            "ReleaseGoModuleCacheAuthority",
            "WINS_GO_CUSTODY_ISSUANCE",
            "WINS_RELEASE_GO_SHA256",
            "WINS_RELEASE_GO_TREE_SHA256",
            "WINS_RELEASE_GO_RUNTIME",
            "wins_release_go_",
        ):
            self.assertNotIn(dropped, source)
        self.assertFalse(
            any(
                os.path.basename(path).startswith(("release_go_archive_custody.sh",
                                                   "provision_macos_release_go"))
                for path in MODULE.PRODUCTION_BUILDER_MATERIALS
            )
        )

    def test_go_root_whose_bin_go_differs_from_the_pin_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp))
            fixture.binary.write_bytes(fixture.binary.read_bytes() + b"# one more byte\n")
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                "reviewed Go executable does not match tools/toolchain-pins.json",
            ):
                fixture.authenticate()

    def test_go_executable_pin_is_selected_for_the_build_host(self) -> None:
        darwin, linux, explicit = "1" * 64, "2" * 64, "3" * 64

        def pin(host: str, by_platform: object = None) -> str:
            go: dict[str, object] = {"executable_sha256": darwin}
            if by_platform is not None:
                go["executable_sha256_by_platform"] = by_platform
            with mock.patch.object(MODULE, "_toolchain_host_key", return_value=host):
                return MODULE._go_executable_pin(go)

        # A Linux host uses its own bin/go pin even though the darwin pin exists.
        self.assertEqual(pin("linux_amd64", {"linux_amd64": linux}), linux)
        # A Linux host without its own pin refuses; the darwin pin is never borrowed.
        for by_platform in (None, {"darwin_arm64": explicit}):
            with self.subTest(by_platform=by_platform), self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "missing or invalid for linux_amd64"
            ):
                pin("linux_amd64", by_platform)
        # A malformed host entry or table refuses.
        for host, by_platform, message in (
            ("linux_amd64", {"linux_amd64": "A" * 64}, "missing or invalid for linux_amd64"),
            ("linux_amd64", {"linux_amd64": None}, "missing or invalid for linux_amd64"),
            ("darwin_arm64", {"darwin_arm64": "not-a-digest"}, "missing or invalid for darwin_arm64"),
            ("linux_amd64", ["linux_amd64", linux], "must be an object"),
        ):
            with self.subTest(host=host, by_platform=by_platform), self.assertRaisesRegex(
                MODULE.CustodyUnavailable, message
            ):
                pin(host, by_platform)
        # darwin_arm64 without its own entry keeps the darwin pin; an explicit entry wins.
        self.assertEqual(pin("darwin_arm64"), darwin)
        self.assertEqual(pin("darwin_arm64", {"linux_amd64": linux}), darwin)
        self.assertEqual(pin("darwin_arm64", {"darwin_arm64": explicit}), explicit)

    def test_receipt_toolchain_names_the_host_go_executable_pin(self) -> None:
        darwin, linux = "1" * 64, "2" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "toolchain-pins.json"

            def pinned(host: str, by_platform: object = None) -> dict[str, str]:
                go: dict[str, object] = {"version": "1.27.1", "executable_sha256": darwin}
                if by_platform is not None:
                    go["executable_sha256_by_platform"] = by_platform
                manifest.write_text(
                    json.dumps({"tools": {"go": go, "android_ndk": {"version": "r30"}}}),
                    encoding="ascii",
                )
                with mock.patch.object(MODULE, "PIN_MANIFEST", str(manifest)), mock.patch.object(
                    MODULE, "_toolchain_host_key", return_value=host
                ):
                    return MODULE._pinned_winn_toolchain()

            self.assertEqual(pinned("linux_amd64", {"linux_amd64": linux})["go_executable_sha256"], linux)
            self.assertEqual(pinned("darwin_arm64")["go_executable_sha256"], darwin)
            with self.assertRaisesRegex(MODULE.CustodyUnavailable, "missing or invalid for linux_amd64"):
                pinned("linux_amd64")

    def test_host_platform_go_pin_authenticates_bin_go_instead_of_the_darwin_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp))
            document = json.loads(fixture.manifest.read_text(encoding="ascii"))
            go = document["tools"]["go"]
            measured = go["executable_sha256"]

            def write(executable: str, host_pin: str) -> None:
                go["executable_sha256"] = executable
                go["executable_sha256_by_platform"] = {fixture.host_key: host_pin}
                fixture.manifest.write_text(
                    json.dumps(document, sort_keys=True) + "\n", encoding="ascii"
                )

            # The host's own entry wins over a different global darwin digest.
            write("f" * 64, measured)
            reviewed = fixture.authenticate()
            try:
                self.assertEqual(reviewed.binary_sha256, measured)
            finally:
                reviewed.close()
            # A host entry that does not match bin/go refuses even if the darwin pin does.
            write(measured, "e" * 64)
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                "reviewed Go executable does not match tools/toolchain-pins.json",
            ):
                fixture.authenticate()

    def test_go_root_whose_install_tree_differs_from_the_pin_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp))
            (fixture.go_root / "VERSION").write_text("go1.27.1\n", encoding="ascii")
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                "reviewed Go install tree does not match tools/toolchain-pins.json",
            ):
                fixture.authenticate()

    def test_go_whose_version_line_differs_from_the_pin_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp), reported_version="1.27.0")
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "reviewed Go identity mismatch"
            ):
                fixture.authenticate()

    def test_go_root_must_be_named_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp))
            for value in ("", "relative/go"):
                with self.subTest(value=value), self.assertRaisesRegex(
                    MODULE.CustodyUnavailable, "WINS_FRESHNESS_GO_ROOT must name"
                ):
                    fixture.authenticate(WINS_FRESHNESS_GO_ROOT=value)

    def test_writable_module_cache_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp))
            digest = fixture.cache_digest()
            member = fixture.module_cache / "example.com" / "dep@v1.0.0" / "go.mod"
            member.chmod(0o600)
            with self.assertRaisesRegex(MODULE.CustodyUnavailable, "writable"):
                fixture.authenticate(WINS_STORE_GOMODCACHE_TREE_SHA256=digest)
            member.chmod(0o400)
            (fixture.module_cache / "example.com").chmod(0o700)
            with self.assertRaisesRegex(MODULE.CustodyUnavailable, "writable"):
                fixture.authenticate(WINS_STORE_GOMODCACHE_TREE_SHA256=digest)

    def test_module_cache_digest_mismatch_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp))
            for value, pattern in (
                ("0" * 64, "does not match WINS_STORE_GOMODCACHE_TREE_SHA256"),
                ("not-a-digest", "64-hex sealed digest"),
                ("", "64-hex sealed digest"),
            ):
                with self.subTest(value=value), self.assertRaisesRegex(
                    MODULE.CustodyUnavailable, pattern
                ):
                    fixture.authenticate(WINS_STORE_GOMODCACHE_TREE_SHA256=value)
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable, "WINS_STORE_GOMODCACHE must name"
            ):
                fixture.authenticate(WINS_STORE_GOMODCACHE="")

    def test_module_cache_change_after_binding_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReviewedGoFixture(Path(tmp))
            reviewed = fixture.authenticate()
            try:
                member = fixture.module_cache / "example.com" / "dep@v1.0.0" / "go.mod"
                member.chmod(0o600)
                member.write_bytes(b"module hostile.example/substitute\n")
                member.chmod(0o400)
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable,
                    "sealed Go module cache changed during freshness verification",
                ):
                    reviewed.verify_module_cache_unchanged()
            finally:
                reviewed.close()

    def test_reviewed_go_runs_only_the_retained_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, _ = self._sealed_cache(root)
            payload = b"retained pinned go"
            reviewed = MODULE.ReviewedGo(
                root="/external/go",
                binary="/external/go/bin/go",
                retained_root="/private/go",
                retained_binary="/private/go/bin/go",
                custody_root="/private",
                version="1.27.1",
                binary_sha256=hashlib.sha256(payload).hexdigest(),
                tree_sha256="b" * 64,
                archive_sha256="c" * 64,
                identity="go version go1.27.1 darwin/arm64",
                gomodcache=str(cache),
                tree_custody=mock.Mock(),
                module_custody=mock.Mock(),
                gomodcache_tree_sha256=MODULE._sealed_tree_digest(str(cache)),
            )
            reviewed.tree_custody.read_file.return_value = payload
            completed = subprocess.CompletedProcess([], 0, "ok\n", "")
            with mock.patch.object(
                MODULE, "_run_pinned_go", return_value=completed
            ) as run, mock.patch.object(MODULE.ReviewedGo, "verify_unchanged") as after:
                self.assertIs(
                    reviewed.run(["version"], cwd=tmp, environment={}), completed
                )
                self.assertEqual(run.call_args.args[0], "/private/go/bin/go")
                after.assert_called_once_with()
                reviewed.tree_custody.read_file.return_value = payload + b"!"
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable, "changed before it ran"
                ):
                    reviewed.run(["version"], cwd=tmp, environment={})
                self.assertEqual(run.call_count, 1)

    def test_each_build_attempt_gets_a_hash_bound_isolated_module_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, source = self._sealed_cache(root)
            reviewed = self._reviewed(root, cache)
            attempt = root / "attempt"
            attempt.mkdir(mode=0o700)
            environment = reviewed.build_environment(str(attempt))
            self.assertEqual(environment["GOPATH"], str(attempt / ".freshness-gopath"))
            self.assertEqual(environment["GOMODCACHE"], str(cache))
            self.assertEqual(
                environment["WINS_STORE_GOMODCACHE_TREE_SHA256"],
                reviewed.gomodcache_tree_sha256,
            )
            custody = MODULE.DescriptorCustody(
                "isolated module-cache test", MODULE.CustodyUnavailable
            )
            try:
                isolated = MODULE._isolate_attempt_module_cache(
                    reviewed, str(attempt), custody
                )
                self.assertEqual(isolated, str(attempt / ".gomodcache"))
                self.assertNotEqual(os.path.realpath(isolated), os.path.realpath(cache))
                self.assertEqual(
                    MODULE._sealed_tree_digest(isolated),
                    reviewed.gomodcache_tree_sha256,
                )
                self.assertEqual(
                    stat.S_IMODE(
                        os.lstat(
                            Path(isolated)
                            / "example.com"
                            / "dependency@v1.0.0"
                            / "go.mod"
                        ).st_mode
                    ),
                    0o400,
                )
                custody.verify()
                source.chmod(0o600)
                source.write_bytes(b"module hostile.example/substitute\n")
                self.assertEqual(
                    (
                        Path(isolated)
                        / "example.com"
                        / "dependency@v1.0.0"
                        / "go.mod"
                    ).read_bytes(),
                    b"module example.com/dependency\n",
                )
                custody.verify()
            finally:
                custody.close()

    def test_isolated_cache_substitution_between_prehash_and_bind_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, _ = self._sealed_cache(root)
            reviewed = self._reviewed(root, cache)
            attempt = root / "attempt"
            attempt.mkdir()
            custody = MODULE.DescriptorCustody(
                "hostile isolated cache", MODULE.CustodyUnavailable
            )
            original_digest = MODULE._sealed_tree_digest
            attacked = False

            def prehash_then_substitute(path: str) -> str:
                nonlocal attacked
                digest = original_digest(path)
                if not attacked and path.endswith(".gomodcache"):
                    target = (
                        Path(path)
                        / "example.com"
                        / "dependency@v1.0.0"
                        / "go.mod"
                    )
                    target.chmod(0o600)
                    target.write_bytes(b"module hostile.example/substitute\n")
                    target.chmod(0o400)
                    attacked = True
                return digest

            try:
                with mock.patch.object(
                    MODULE, "_sealed_tree_digest", side_effect=prehash_then_substitute
                ):
                    with self.assertRaisesRegex(
                        MODULE.CustodyUnavailable,
                        "retained isolated Go module cache changed",
                    ):
                        MODULE._isolate_attempt_module_cache(
                            reviewed, str(attempt), custody
                        )
                self.assertTrue(attacked)
            finally:
                custody.close()


PINNED_NDK_VERSION = "30.0.16248370"
PINNED_XCODE = ("27.0", "27A266a")
NDK_TRIPLES = (
    "aarch64-linux-android",
    "armv7a-linux-androideabi",
    "x86_64-linux-android",
)


def ndk_host_tag() -> Optional[str]:
    return {
        ("darwin", "arm64"): "darwin-x86_64",
        ("darwin", "x86_64"): "darwin-x86_64",
        ("linux", "x86_64"): "linux-x86_64",
    }.get((sys.platform, platform.machine().lower()))


def toolchain_host_key() -> str:
    host_os = {"darwin": "darwin", "linux": "linux"}[sys.platform]
    host_arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}[
        platform.machine().lower()
    ]
    return f"{host_os}_{host_arch}"


def winn_release_platform_digest(root: Path) -> str:
    """The pin value, measured by the real `winn_release.py digest --kind platform`."""
    driver = Path(MODULE.REPO_ROOT) / "tools" / "winn_release.py"
    completed = subprocess.run(
        ["/usr/bin/python3", "-I", str(driver), "digest", "--kind", "platform", str(root)],
        capture_output=True, text=True, timeout=120, check=True,
    )
    return completed.stdout.strip()


class PinnedNdkFixture:
    """A caller-owned NDK tree plus a pins file naming it, nothing under /Library."""

    def __init__(self, root: Path, revision: str = PINNED_NDK_VERSION) -> None:
        host_tag = ndk_host_tag()
        if host_tag is None:
            raise unittest.SkipTest("no Android NDK host tag for this host")
        self.root = root
        self.ndk = root / "ndk" / PINNED_NDK_VERSION
        self.bin = self.ndk / "toolchains" / "llvm" / "prebuilt" / host_tag / "bin"
        self.bin.mkdir(parents=True)
        (self.ndk / "meta").mkdir()
        (self.ndk / "source.properties").write_text(
            f"Pkg.Desc = Android NDK\nPkg.Revision = {revision}\n", encoding="ascii"
        )
        (self.ndk / "NOTICE").write_text("fixture notice\n", encoding="ascii")
        (self.ndk / "meta" / "empty.json").write_bytes(b"")
        (self.bin / "clang-21").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        os.symlink("clang-21", self.bin / "clang")
        os.symlink("bin", self.bin.parent / "bin-link")
        for triple in NDK_TRIPLES:
            compiler = self.bin / f"{triple}24-clang"
            compiler.write_text(
                f'#!/bin/sh\nexec "$(dirname "$0")/clang" --target={triple}24 "$@"\n',
                encoding="ascii",
            )
        for directory, dirs, files in os.walk(self.ndk):
            os.chmod(directory, 0o755)
            for name in files:
                path = os.path.join(directory, name)
                if not os.path.islink(path):
                    executable = name.endswith("clang") or name.startswith("clang")
                    os.chmod(path, 0o755 if executable else 0o644)
        self.compilers = {
            triple: self.bin / f"{triple}24-clang" for triple in NDK_TRIPLES
        }
        self.tree_sha256 = winn_release_platform_digest(self.ndk)
        self.manifest = root / "toolchain-pins.json"
        self.write_pins(self.tree_sha256)

    def write_pins(self, tree_sha256: str) -> None:
        self.manifest.write_text(
            json.dumps(
                {
                    "tools": {
                        "android_ndk": {
                            "version": PINNED_NDK_VERSION,
                            "install_tree_sha256": {toolchain_host_key(): tree_sha256},
                        },
                        "xcode": {"version": PINNED_XCODE[0], "build": PINNED_XCODE[1]},
                    }
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )

    def bind(self, target: str = "datapath-android-arm64", **environment: str) -> object:
        overrides = {"WINS_FRESHNESS_NDK_ROOT": str(self.ndk)}
        overrides.update(environment)
        with mock.patch.object(MODULE, "PIN_MANIFEST", str(self.manifest)), mock.patch.dict(
            os.environ, overrides, clear=False,
        ):
            if not os.environ.get("WINS_FRESHNESS_NDK_ROOT"):
                os.environ.pop("WINS_FRESHNESS_NDK_ROOT", None)
            return MODULE._bind_android_toolchain_custody(target)


class PinnedXcodeFixture:
    """A caller-owned developer directory and a stub for the one Apple tool seam."""

    def __init__(self, root: Path, reported: tuple[str, str] = PINNED_XCODE) -> None:
        self.root = root
        self.developer = root / "Xcode.app" / "Contents" / "Developer"
        self.xcodebuild = self.developer / "usr" / "bin" / "xcodebuild"
        self.clang = (
            self.developer / "Toolchains" / "XcodeDefault.xctoolchain" / "usr" / "bin" / "clang"
        )
        self.sdk = (
            self.developer / "Platforms" / "iPhoneOS.platform" / "Developer" / "SDKs"
            / "iPhoneOS.sdk"
        )
        for path in (self.xcodebuild, self.clang, self.sdk / "SDKSettings.json"):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.xcodebuild.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        self.clang.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        (self.sdk / "SDKSettings.json").write_text('{"Version":"27.0"}\n', encoding="ascii")
        self.reported = reported
        self.clang_answer = str(self.clang)
        self.sdk_answer = str(self.sdk)
        self.calls: list[tuple[list[str], Optional[str]]] = []
        self.manifest = root / "toolchain-pins.json"
        self.manifest.write_text(
            json.dumps(
                {"tools": {"xcode": {"version": PINNED_XCODE[0], "build": PINNED_XCODE[1]}}}
            )
            + "\n",
            encoding="ascii",
        )

    def tool(self, argv: list[str], developer_dir: Optional[str]) -> str:
        self.calls.append((list(argv), developer_dir))
        if argv == ["/usr/bin/xcode-select", "-p"]:
            return str(self.developer) + "\n"
        if argv[1:] == ["-version"]:
            return f"Xcode {self.reported[0]}\nBuild version {self.reported[1]}\n"
        if argv[:2] == ["/usr/bin/xcrun", "--sdk"] and argv[3:] == ["--show-sdk-path"]:
            return self.sdk_answer + "\n"
        if argv == ["/usr/bin/xcrun", "-f", "clang"]:
            return self.clang_answer + "\n"
        raise AssertionError(f"unexpected Apple tool call {argv}")

    def bind(self, platform_name: str = "iphoneos", **environment: str) -> object:
        overrides = {"WINS_FRESHNESS_DEVELOPER_DIR": str(self.developer)}
        overrides.update(environment)
        with mock.patch.object(MODULE, "PIN_MANIFEST", str(self.manifest)), mock.patch.object(
            MODULE.sys, "platform", "darwin"
        ), mock.patch.object(
            MODULE, "_apple_tool_output", side_effect=self.tool
        ), mock.patch.object(
            MODULE.subprocess, "run", side_effect=AssertionError("only the tool seam may run")
        ), mock.patch.dict(os.environ, overrides, clear=False):
            if not os.environ.get("WINS_FRESHNESS_DEVELOPER_DIR"):
                os.environ.pop("WINS_FRESHNESS_DEVELOPER_DIR", None)
            return MODULE._bind_apple_toolchain_custody(platform_name)


def record_opens() -> tuple[list[str], list[bool]]:
    """Record every path opened or listed while the returned flag is set."""
    opened: list[str] = []
    recording = [False]

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if recording[0] and event in ("open", "os.scandir", "os.listdir"):
            if arguments and isinstance(arguments[0], str):
                opened.append(arguments[0])

    sys.addaudithook(audit)
    return opened, recording


def library_reads(opened: list[str]) -> list[str]:
    """/Library paths, including a descriptor-relative open of / then Library."""
    return [path for path in opened if path == "Library" or path.startswith("/Library")]


class PinnedPlatformToolchainTests(unittest.TestCase):
    """The Android NDK and Xcode are accepted by tools/toolchain-pins.json alone.

    The owner removed every AI-made gate (2026-10-09): the /Library Apple and
    Android NDK custody authorities, their root-owned and immutable
    requirements and the /Library/WinsVPN/ReleaseAndroidNDK/ root are gone.
    What stays is the pinned NDK revision and install-tree digest (the
    `winn_release.py digest --kind platform` encoding) and the pinned Xcode
    version and build, the same checks `winn_release.py prepare_ndk` and
    `prepare_xcode` make.
    """

    def test_library_toolchain_authorities_are_gone(self) -> None:
        for retired in ("APPLE_TOOLCHAIN_AUTHORITY", "ANDROID_TOOLCHAIN_AUTHORITY"):
            self.assertFalse(hasattr(MODULE, retired), retired)
        self.assertEqual(MODULE.ANDROID_NDK_ROOT_ENV, "WINS_FRESHNESS_NDK_ROOT")
        self.assertEqual(MODULE.APPLE_DEVELOPER_DIR_ENV, "WINS_FRESHNESS_DEVELOPER_DIR")
        source = Path(MODULE.__file__).read_text(encoding="utf-8")
        for dropped in (
            "/Library/WinsVPN/AppleToolchainAuthority",
            "/Library/WinsVPN/ReleaseAndroidNDK",
            "toolchain-custody.json",
            "winsvpn.apple-toolchain-custody.v1",
            "winsvpn.android-ndk-freshness-custody.v1",
        ):
            self.assertNotIn(dropped, source)

    def test_platform_tree_digest_is_the_winn_release_platform_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedNdkFixture(Path(tmp))
            # Anti-vacuity: the fixture has the member kinds the encoding names.
            self.assertTrue((fixture.bin / "clang").is_symlink())
            self.assertTrue((fixture.bin.parent / "bin-link").is_symlink())
            self.assertEqual((fixture.ndk / "meta" / "empty.json").stat().st_size, 0)
            self.assertRegex(fixture.tree_sha256, r"^[0-9a-f]{64}$")
            self.assertEqual(MODULE._platform_tree_digest(str(fixture.ndk)), fixture.tree_sha256)
            (fixture.ndk / "NOTICE").chmod(0o666)
            with self.assertRaisesRegex(MODULE.CustodyUnavailable, "writable by others"):
                MODULE._platform_tree_digest(str(fixture.ndk))

    def test_pinned_ndk_is_accepted_without_library_authority(self) -> None:
        opened, recording = record_opens()
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedNdkFixture(Path(tmp))
            for target, triple in (
                ("datapath-android-arm64", "aarch64-linux-android"),
                ("datapath-android-arm", "armv7a-linux-androideabi"),
                ("datapath-android-amd64", "x86_64-linux-android"),
            ):
                with self.subTest(target=target):
                    del opened[:]
                    recording[0] = True
                    try:
                        toolchain = fixture.bind(target)
                    finally:
                        recording[0] = False
                    try:
                        root = os.path.realpath(fixture.ndk)
                        self.assertEqual(
                            toolchain.environment,
                            {
                                "ANDROID_NDK_HOME": root,
                                "ANDROID_NDK_ROOT": root,
                                "WINS_ANDROID_NDK_ROOT": root,
                            },
                        )
                        compiler = os.path.realpath(fixture.compilers[triple])
                        self.assertIn(
                            MODULE.DescriptorCustody._canonical(compiler),
                            toolchain.custody._nodes,
                        )
                        toolchain.custody.verify()
                    finally:
                        toolchain.custody.close()
                    # Anti-vacuity: the hook saw the fixture being read
                    # (descriptor-relative opens record the bare name).
                    self.assertIn(
                        os.path.join(os.path.realpath(fixture.ndk), "NOTICE"), opened
                    )
                    self.assertIn("source.properties", opened)
                    self.assertEqual(library_reads(opened), [])

    def test_ndk_with_wrong_revision_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedNdkFixture(Path(tmp), revision="29.0.14206865")
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                r"is 29\.0\.14206865, not the pinned 30\.0\.16248370",
            ):
                fixture.bind()

    def test_one_byte_ndk_tree_change_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedNdkFixture(Path(tmp))
            notice = fixture.ndk / "NOTICE"
            payload = bytearray(notice.read_bytes())
            payload[0] ^= 0x01
            notice.write_bytes(bytes(payload))
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                f"tree digest [0-9a-f]{{64}} is not the pinned {fixture.tree_sha256}",
            ):
                fixture.bind()

    def test_ndk_compiler_must_exist_in_the_pinned_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedNdkFixture(Path(tmp))
            fixture.compilers["x86_64-linux-android"].unlink()
            fixture.write_pins(winn_release_platform_digest(fixture.ndk))
            with self.assertRaisesRegex(MODULE.CustodyUnavailable, "x86_64-linux-android24-clang"):
                fixture.bind("datapath-android-amd64")
            # The other ABIs in the same pinned tree still bind.
            fixture.bind("datapath-android-arm64").custody.close()

    def test_ndk_root_env_relative_is_refused_and_unset_uses_the_pinned_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            fixture = PinnedNdkFixture(Path(tmp) / "fixture")
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                "WINS_FRESHNESS_NDK_ROOT must name the absolute root",
            ):
                fixture.bind(WINS_FRESHNESS_NDK_ROOT="relative/ndk")
            # Unset: ~/.local/android-sdk/ndk/<pin>, as winn_release.py prepare_ndk.
            home.mkdir()
            with self.assertRaises(MODULE.CustodyUnavailable):
                fixture.bind(WINS_FRESHNESS_NDK_ROOT="", HOME=str(home))
            default_root = home / ".local" / "android-sdk" / "ndk" / PINNED_NDK_VERSION
            default_root.parent.mkdir(parents=True)
            fixture.ndk.rename(default_root)
            toolchain = fixture.bind(WINS_FRESHNESS_NDK_ROOT="", HOME=str(home))
            try:
                self.assertEqual(
                    toolchain.environment["WINS_ANDROID_NDK_ROOT"],
                    os.path.realpath(default_root),
                )
            finally:
                toolchain.custody.close()

    def test_ndk_receipt_compiler_is_checked_against_the_pinned_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedNdkFixture(Path(tmp))
            toolchain = fixture.bind()
            try:
                compiler = os.path.realpath(fixture.compilers["aarch64-linux-android"])
                pinned = {"android_ndk_version": PINNED_NDK_VERSION}
                receipt = {
                    "compiler_path": compiler,
                    "compiler_sha256": sha256(Path(compiler)),
                    "id": "android-api-24",
                    "ndk_version": PINNED_NDK_VERSION,
                    "sdk_version": None,
                }
                self.assertEqual(
                    MODULE._receipt_platform_identity(
                        "datapath-android-arm64", dict(receipt), pinned, toolchain
                    ),
                    receipt,
                )
                outside = Path(tmp) / "outside-clang"
                outside.write_bytes(Path(compiler).read_bytes())
                with self.assertRaisesRegex(MODULE.CustodyUnavailable, "outside the retained"):
                    MODULE._receipt_platform_identity(
                        "datapath-android-arm64",
                        dict(receipt, compiler_path=str(outside)),
                        pinned,
                        toolchain,
                    )
                with self.assertRaisesRegex(MODULE.CustodyUnavailable, "bytes differ"):
                    MODULE._receipt_platform_identity(
                        "datapath-android-arm64",
                        dict(receipt, compiler_sha256="0" * 64),
                        pinned,
                        toolchain,
                    )
            finally:
                toolchain.custody.close()

    def test_pinned_xcode_is_accepted_without_library_authority(self) -> None:
        opened, recording = record_opens()
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedXcodeFixture(Path(tmp))
            recording[0] = True
            try:
                toolchain = fixture.bind("iphoneos")
            finally:
                recording[0] = False
            try:
                developer = os.path.realpath(fixture.developer)
                clang = os.path.realpath(fixture.clang)
                self.assertEqual(
                    toolchain.environment,
                    {
                        "DEVELOPER_DIR": developer,
                        "SDKROOT": os.path.realpath(fixture.sdk),
                        "CC": clang,
                        "CXX": clang + "++",
                        "WINS_APPLE_DEVELOPER_DIR": developer,
                    },
                )
                self.assertIn(
                    ([os.path.join(developer, "usr", "bin", "xcodebuild"), "-version"],
                     developer),
                    fixture.calls,
                )
                self.assertIn(
                    (["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"], developer),
                    fixture.calls,
                )
                self.assertNotIn((["/usr/bin/xcode-select", "-p"], None), fixture.calls)
                for retained in (clang, os.path.join(fixture.sdk, "SDKSettings.json")):
                    self.assertIn(
                        MODULE.DescriptorCustody._canonical(os.path.realpath(retained)),
                        toolchain.custody._nodes,
                    )
                toolchain.custody.verify()
            finally:
                toolchain.custody.close()
            self.assertIn("toolchain-pins.json", opened)
            self.assertIn("SDKSettings.json", opened)
            self.assertEqual(library_reads(opened), [])

    def test_xcode_developer_dir_defaults_to_xcode_select(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedXcodeFixture(Path(tmp))
            toolchain = fixture.bind("iphoneos", WINS_FRESHNESS_DEVELOPER_DIR="")
            try:
                self.assertEqual(fixture.calls[0], (["/usr/bin/xcode-select", "-p"], None))
                self.assertEqual(
                    toolchain.environment["DEVELOPER_DIR"],
                    os.path.realpath(fixture.developer),
                )
            finally:
                toolchain.custody.close()
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                "WINS_FRESHNESS_DEVELOPER_DIR must name an absolute",
            ):
                fixture.bind("iphoneos", WINS_FRESHNESS_DEVELOPER_DIR="Xcode.app/Contents")

    def test_xcode_with_mismatched_build_or_version_is_refused(self) -> None:
        for reported in (("27.0", "27A999z"), ("26.4", "27A266a")):
            with self.subTest(reported=reported), tempfile.TemporaryDirectory() as tmp:
                fixture = PinnedXcodeFixture(Path(tmp), reported=reported)
                with self.assertRaisesRegex(
                    MODULE.CustodyUnavailable,
                    re.escape(
                        f"Xcode {reported[0]} ({reported[1]})"
                    ) + r" at .* is not the pinned 27\.0 \(27A266a\)",
                ):
                    fixture.bind("iphoneos")

    def test_clang_or_sdk_outside_the_developer_dir_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = PinnedXcodeFixture(Path(tmp))
            elsewhere = Path(tmp) / "elsewhere"
            elsewhere.mkdir()
            foreign_clang = elsewhere / "clang"
            foreign_clang.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            fixture.clang_answer = str(foreign_clang)
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                "Apple clang resolves outside the pinned developer directory",
            ):
                fixture.bind("iphoneos")
            # A path inside the developer dir that resolves outside it.
            fixture.clang.unlink()
            os.symlink(foreign_clang, fixture.clang)
            fixture.clang_answer = str(fixture.clang)
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                "Apple clang resolves outside the pinned developer directory",
            ):
                fixture.bind("iphoneos")
            fixture.clang.unlink()
            fixture.clang.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            fixture.sdk_answer = str(elsewhere)
            with self.assertRaisesRegex(
                MODULE.CustodyUnavailable,
                "Apple SDK resolves outside the pinned developer directory",
            ):
                fixture.bind("iphoneos")

    def test_apple_tool_seam_runs_with_a_clean_environment(self) -> None:
        seen: list[tuple[list[str], dict[str, str]]] = []

        def run(argv: list[str], **kwargs: object) -> object:
            seen.append((list(argv), dict(kwargs["env"])))  # type: ignore[arg-type]
            return subprocess.CompletedProcess(argv, 0, "Xcode 27.0\n", "")

        with mock.patch.dict(
            os.environ, {"DEVELOPER_DIR": "/hostile", "SDKROOT": "/hostile"}
        ), mock.patch.object(MODULE.subprocess, "run", side_effect=run):
            self.assertEqual(
                MODULE._apple_tool_output(["/usr/bin/xcodebuild", "-version"], "/Dev"),
                "Xcode 27.0\n",
            )
            MODULE._apple_tool_output(["/usr/bin/xcode-select", "-p"], None)
        self.assertEqual(
            seen,
            [
                (["/usr/bin/xcodebuild", "-version"],
                 {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "DEVELOPER_DIR": "/Dev"}),
                (["/usr/bin/xcode-select", "-p"], {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}),
            ],
        )
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, "", "no developer tools"),
        ), self.assertRaisesRegex(MODULE.CustodyUnavailable, "no developer tools"):
            MODULE._apple_tool_output(["/usr/bin/xcrun", "-f", "clang"], "/Dev")


class SealedProducerInputDigestTests(unittest.TestCase):
    """The digest passed to the sealed builder must be the driver's digest."""

    def _sealed_tree(self, root: Path) -> Path:
        tree = root / "module"
        (tree / "cmd").mkdir(parents=True)
        (tree / "go.mod").write_text("module example\n", encoding="ascii")
        (tree / "go.sum").write_text("", encoding="ascii")
        (tree / "cmd" / "main.go").write_text("package main\n", encoding="ascii")
        for directory, _dirs, files in os.walk(tree, topdown=False):
            for name in files:
                os.chmod(os.path.join(directory, name), 0o400)
            os.chmod(directory, 0o500)
        return tree

    def _unseal(self, tree: Path) -> None:
        for directory, _dirs, _files in os.walk(tree):
            os.chmod(directory, 0o700)

    def test_digest_equals_release_driver_digest(self) -> None:
        driver = Path(MODULE.REPO_ROOT) / "tools" / "winn_release.py"
        with tempfile.TemporaryDirectory() as tmp:
            tree = self._sealed_tree(Path(tmp))
            try:
                completed = subprocess.run(
                    ["/usr/bin/python3", "-I", str(driver), "digest", "--kind", "sealed", str(tree)],
                    capture_output=True, text=True, timeout=60, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(
                    MODULE._sealed_tree_digest(str(tree)), completed.stdout.strip()
                )
            finally:
                self._unseal(tree)

    def test_writable_or_linked_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = self._sealed_tree(Path(tmp))
            try:
                os.chmod(tree / "cmd", 0o700)
                with self.assertRaisesRegex(MODULE.CustodyUnavailable, "writable"):
                    MODULE._sealed_tree_digest(str(tree))
                os.link(tree / "go.mod", tree / "cmd" / "hardlink")
                os.chmod(tree / "cmd", 0o500)
                with self.assertRaisesRegex(MODULE.CustodyUnavailable, "hard-linked"):
                    MODULE._sealed_tree_digest(str(tree))
            finally:
                self._unseal(tree)


if __name__ == "__main__":
    unittest.main()
