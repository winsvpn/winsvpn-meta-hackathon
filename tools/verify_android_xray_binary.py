#!/usr/bin/env python3
"""Fail-closed verifier for a produced Android Xray executable."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import struct
import sys


MINIMUM_XRAY_BYTES = 1_000_000
PT_LOAD = 1
PT_INTERP = 3
ET_DYN = 3
ANDROID_TARGETS = {
    "arm": (1, 40, b"/system/bin/linker"),
    "arm64": (2, 183, b"/system/bin/linker64"),
    "amd64": (2, 62, b"/system/bin/linker64"),
}


def _program_headers(
    data: bytes,
) -> tuple[int, int, int, int, list[tuple[int, ...]]]:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        raise ValueError("expected a little-endian ELF image")
    elf_class = data[4]
    if elf_class == 1:
        header_format = "<16sHHIIIIIHHHHHH"
        program_format = "<IIIIIIII"
    elif elf_class == 2:
        header_format = "<16sHHIQQQIHHHHHH"
        program_format = "<IIQQQQQQ"
    else:
        raise ValueError(f"unsupported ELF class {elf_class}")

    header_size = struct.calcsize(header_format)
    if len(data) < header_size:
        raise ValueError("truncated ELF header")
    header = struct.unpack_from(header_format, data, 0)
    elf_type = header[1]
    machine = header[2]
    entry = header[4]
    program_offset = header[5]
    program_entry_size = header[9]
    program_count = header[10]
    expected_entry_size = struct.calcsize(program_format)
    table_end = program_offset + program_entry_size * program_count
    if program_entry_size != expected_entry_size or table_end > len(data):
        raise ValueError("invalid ELF program-header table")
    headers = [
        struct.unpack_from(
            program_format,
            data,
            program_offset + index * program_entry_size,
        )
        for index in range(program_count)
    ]
    return elf_class, elf_type, machine, entry, headers


def verify_android_xray_binary(
    path: pathlib.Path,
    *,
    goarch: str,
    go_version: str,
    build_marker: str,
    page_size: int = 16_384,
    expected_sha256: str | None = None,
) -> dict[str, int | str]:
    if goarch not in ANDROID_TARGETS:
        raise ValueError(f"unsupported Android GOARCH {goarch!r}")
    if page_size <= 0 or page_size & (page_size - 1):
        raise ValueError("page size must be a positive power of two")
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{path}: expected a regular, non-symlink binary")

    data = path.read_bytes()
    if len(data) < MINIMUM_XRAY_BYTES:
        raise ValueError(f"{path}: implausibly small Xray output ({len(data)} bytes)")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256.lower():
        raise ValueError(
            f"{path}: SHA-256 drift: expected {expected_sha256.lower()}, got {digest}"
        )

    elf_class, elf_type, machine, entry, headers = _program_headers(data)
    expected_class, expected_machine, expected_interpreter = ANDROID_TARGETS[goarch]
    if elf_class != expected_class:
        raise ValueError(f"{path}: ELF class {elf_class} does not match android/{goarch}")
    if machine != expected_machine:
        raise ValueError(
            f"{path}: ELF e_machine {machine} does not match android/{goarch}"
        )
    if elf_type != ET_DYN or entry == 0:
        raise ValueError(
            f"{path}: expected an Android PIE executable (ET_DYN with entry point)"
        )

    load_count = 0
    interpreter: bytes | None = None
    for index, header in enumerate(headers):
        if elf_class == 1:
            kind, offset, vaddr, _, file_size, _, _, alignment = header
        else:
            kind, _, offset, vaddr, _, file_size, _, alignment = header
        if kind == PT_INTERP:
            end = offset + file_size
            if end > len(data):
                raise ValueError(f"{path}: PT_INTERP extends past end of file")
            interpreter = data[offset:end].rstrip(b"\x00")
        if kind != PT_LOAD:
            continue
        load_count += 1
        if alignment < page_size or alignment % page_size:
            raise ValueError(
                f"{path}: PT_LOAD {index} alignment {alignment} is not "
                f"{page_size}-byte compatible"
            )
        if offset % page_size != vaddr % page_size:
            raise ValueError(
                f"{path}: PT_LOAD {index} offset/vaddr congruence is invalid"
            )

    if interpreter != expected_interpreter:
        raise ValueError(
            f"{path}: interpreter {interpreter!r} does not match "
            f"{expected_interpreter!r}"
        )
    if load_count < 2:
        raise ValueError(f"{path}: expected at least two loadable segments")

    markers = (
        b"github.com/xtls/xray-core/main",
        b"github.com/xtls/xray-core/core",
        ("go" + go_version).encode("ascii"),
        build_marker.encode("ascii"),
    )
    for marker in markers:
        if marker not in data:
            raise ValueError(f"{path}: missing provenance/content marker {marker!r}")

    return {
        "path": str(path),
        "goarch": goarch,
        "elf_class": elf_class,
        "e_machine": machine,
        "load_segments": load_count,
        "page_size": page_size,
        "size": len(data),
        "sha256": digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--goarch", required=True, choices=sorted(ANDROID_TARGETS))
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--build-marker", required=True)
    parser.add_argument("--page-size", type=int, default=16_384)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()

    try:
        result = verify_android_xray_binary(
            args.binary,
            goarch=args.goarch,
            go_version=args.go_version,
            build_marker=args.build_marker,
            page_size=args.page_size,
            expected_sha256=args.expected_sha256,
        )
    except (OSError, ValueError) as error:
        print(f"VERIFY ANDROID XRAY ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "Verified Android Xray: "
        f"{result['path']} android/{result['goarch']} "
        f"e_machine={result['e_machine']} PT_LOAD={result['load_segments']} "
        f"alignment={result['page_size']} size={result['size']} "
        f"sha256={result['sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
