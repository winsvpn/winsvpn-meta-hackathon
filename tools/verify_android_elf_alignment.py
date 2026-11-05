#!/usr/bin/env python3
"""Verify Android ELF architecture and 16 KiB PT_LOAD compatibility."""

from __future__ import annotations

import argparse
import pathlib
import struct
import sys


PT_LOAD = 1
ANDROID_ABIS = {
    "arm64-v8a": (2, 183),
    "armeabi-v7a": (1, 40),
    "x86_64": (2, 62),
}


def verify_android_elf_alignment(
    path: pathlib.Path,
    *,
    abi: str,
    page_size: int = 16_384,
) -> dict[str, int | str]:
    if abi not in ANDROID_ABIS:
        raise ValueError(f"unsupported Android ABI {abi!r}")
    if page_size <= 0 or page_size & (page_size - 1):
        raise ValueError("page size must be a positive power of two")
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{path}: expected a regular, non-symlink binary")

    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        raise ValueError(f"{path}: expected a little-endian ELF image")
    elf_class = data[4]
    if elf_class == 1:
        header_format = "<16sHHIIIIIHHHHHH"
        program_format = "<IIIIIIII"
    elif elf_class == 2:
        header_format = "<16sHHIQQQIHHHHHH"
        program_format = "<IIQQQQQQ"
    else:
        raise ValueError(f"{path}: unsupported ELF class {elf_class}")

    header_size = struct.calcsize(header_format)
    if len(data) < header_size:
        raise ValueError(f"{path}: truncated ELF header")
    header = struct.unpack_from(header_format, data, 0)
    machine = header[2]
    program_offset = header[5]
    program_entry_size = header[9]
    program_count = header[10]
    expected_entry_size = struct.calcsize(program_format)
    table_end = program_offset + program_entry_size * program_count
    if program_entry_size != expected_entry_size or table_end > len(data):
        raise ValueError(f"{path}: invalid ELF program-header table")

    expected_class, expected_machine = ANDROID_ABIS[abi]
    if elf_class != expected_class or machine != expected_machine:
        raise ValueError(
            f"{path}: ELF class/machine {elf_class}/{machine} does not match "
            f"Android ABI {abi} ({expected_class}/{expected_machine})"
        )

    load_count = 0
    for index in range(program_count):
        fields = struct.unpack_from(
            program_format,
            data,
            program_offset + index * program_entry_size,
        )
        if elf_class == 1:
            kind, offset, vaddr, _, _, _, _, alignment = fields
        else:
            kind, _, offset, vaddr, _, _, _, alignment = fields
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
    if load_count < 1:
        raise ValueError(f"{path}: expected at least one loadable segment")

    return {
        "path": str(path),
        "abi": abi,
        "elf_class": elf_class,
        "e_machine": machine,
        "load_segments": load_count,
        "page_size": page_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--abi", required=True, choices=sorted(ANDROID_ABIS))
    parser.add_argument("--page-size", type=int, default=16_384)
    args = parser.parse_args()
    try:
        result = verify_android_elf_alignment(
            args.binary,
            abi=args.abi,
            page_size=args.page_size,
        )
    except (OSError, ValueError) as error:
        print(f"VERIFY ANDROID ELF ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "Verified Android ELF: "
        f"{result['path']} abi={result['abi']} "
        f"e_machine={result['e_machine']} PT_LOAD={result['load_segments']} "
        f"alignment={result['page_size']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
