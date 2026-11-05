#!/usr/bin/env python3
"""Verify 16 KiB-safe AAB packaging: aligned uncompressed or compressed natives."""

from __future__ import annotations

import argparse
import pathlib
import tempfile
import zipfile


class AlignmentError(RuntimeError):
    pass


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise AlignmentError("invalid protobuf varint")


def _fields(data: bytes) -> list[tuple[int, int, int | bytes]]:
    result: list[tuple[int, int, int | bytes]] = []
    offset = 0
    while offset < len(data):
        tag, offset = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise AlignmentError("invalid protobuf field number")
        if wire == 0:
            value, offset = _varint(data, offset)
        elif wire == 1:
            if offset + 8 > len(data):
                raise AlignmentError("truncated fixed64 field")
            value, offset = data[offset : offset + 8], offset + 8
        elif wire == 2:
            size, offset = _varint(data, offset)
            if size > len(data) - offset:
                raise AlignmentError("truncated length-delimited field")
            value, offset = data[offset : offset + size], offset + size
        elif wire == 5:
            if offset + 4 > len(data):
                raise AlignmentError("truncated fixed32 field")
            value, offset = data[offset : offset + 4], offset + 4
        else:
            raise AlignmentError(f"unsupported protobuf wire type {wire}")
        result.append((number, wire, value))
    return result


def _single_message(data: bytes, number: int, context: str) -> bytes:
    values = [value for field, wire, value in _fields(data) if field == number and wire == 2]
    if len(values) != 1 or not isinstance(values[0], bytes):
        raise AlignmentError(f"{context} must contain exactly one message field {number}")
    return values[0]


def verify_bundle_config(data: bytes, *, all_native_libraries_compressed: bool) -> None:
    optimizations = _single_message(data, 2, "BundleConfig")
    native = _single_message(optimizations, 2, "Optimizations")
    fields = _fields(native)
    enabled = [value for number, wire, value in fields if number == 1 and wire == 0]
    alignment = [value for number, wire, value in fields if number == 2 and wire == 0]
    if len(enabled) > 1 or len(alignment) > 1:
        raise AlignmentError("AAB contains duplicate native packaging settings")
    uncompressed = enabled == [1]
    if uncompressed:
        if alignment != [2]:
            raise AlignmentError("uncompressed AAB libraries do not request PAGE_ALIGNMENT_16K")
    elif not all_native_libraries_compressed:
        raise AlignmentError(
            "AAB neither requests 16 KiB alignment nor compresses every native library"
        )


def verify_aab(path: pathlib.Path) -> None:
    resolved = path.expanduser().resolve(strict=True)
    if resolved.suffix.lower() != ".aab":
        raise AlignmentError(f"expected an exact .aab artifact: {resolved}")
    try:
        with zipfile.ZipFile(resolved) as archive:
            names = archive.namelist()
            if names.count("BundleConfig.pb") != 1:
                raise AlignmentError("AAB must contain exactly one BundleConfig.pb")
            native = [
                info
                for info in archive.infolist()
                if "/lib/" in f"/{info.filename}" and info.filename.endswith(".so")
            ]
            if not native:
                raise AlignmentError("AAB contains no native libraries")
            verify_bundle_config(
                archive.read("BundleConfig.pb"),
                all_native_libraries_compressed=all(
                    info.compress_type != zipfile.ZIP_STORED for info in native
                ),
            )
    except zipfile.BadZipFile as exc:
        raise AlignmentError(f"invalid AAB ZIP archive: {resolved}") from exc


def _encode_varint(value: int) -> bytes:
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _message(number: int, payload: bytes) -> bytes:
    return _encode_varint((number << 3) | 2) + _encode_varint(len(payload)) + payload


def _scalar(number: int, value: int) -> bytes:
    return _encode_varint(number << 3) + _encode_varint(value)


def self_test() -> None:
    native = _scalar(1, 1) + _scalar(2, 2)
    valid = _message(2, _message(2, native))
    verify_bundle_config(valid, all_native_libraries_compressed=False)
    compressed = _message(2, _message(2, _scalar(2, 2)))
    verify_bundle_config(compressed, all_native_libraries_compressed=True)
    for invalid in (
        _message(2, _message(2, _scalar(1, 1) + _scalar(2, 1))),
        _message(2, _message(2, _scalar(1, 0) + _scalar(2, 2))),
        valid + _message(2, b""),
    ):
        try:
            verify_bundle_config(invalid, all_native_libraries_compressed=False)
        except AlignmentError:
            pass
        else:
            raise AlignmentError("self-test accepted an invalid BundleConfig")
    with tempfile.TemporaryDirectory() as name:
        aab = pathlib.Path(name) / "fixture.aab"
        with zipfile.ZipFile(aab, "w") as archive:
            archive.writestr("BundleConfig.pb", valid)
            archive.writestr("base/lib/arm64-v8a/libapp.so", b"native", compress_type=zipfile.ZIP_STORED)
        verify_aab(aab)
    print("ANDROID AAB 16 KIB PACKAGING SELF-TEST: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("aab", nargs="?", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.aab:
        verify_aab(args.aab)
        print(f"ANDROID AAB 16 KIB PACKAGING: PASS {args.aab}")
    else:
        parser.error("provide an AAB or --self-test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
