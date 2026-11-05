"""Generate extension icons from the checked-in red panda Guardian app icon.

Owner ruling 2026-10-25: the eagle "Win Empire" artwork is retired and the
current brand is the red panda Guardian shield. The source is the reviewed iOS
1024x1024 app icon (cream background, the same art as the apps), and its bytes
are pinned below so a changed or swapped logo fails the build instead of
shipping silently.

The source logo is decoded and resized here rather than through an image
library for one reason: this is a censorship-circumvention tool and every
third-party dependency in its build is a way to compromise every user of it at
once. PNG's zlib stream, five scanline filters, area averaging, CRC32, and the
output encoder are small enough to implement with the Python standard library.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SOURCE_LOGO = (
    Path(__file__).resolve().parents[2]
    / "ios"
    / "Runner"
    / "Assets.xcassets"
    / "AppIcon.appiconset"
    / "Icon-App-1024x1024@1x.png"
)
# The same digest tools/verify_apple_readiness.sh pins for this file. Changing
# the app icon means refreshing both pins in the same reviewed change.
SOURCE_LOGO_SHA256 = (
    "0b8e4f2a0f9c75ba120bba8d7a034477199a7c6ce757f8368a26bcf3dca51e77"
)


def _paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    if above_distance <= upper_left_distance:
        return above
    return upper_left


def _decode_png(path: Path) -> tuple[int, int, bytes]:
    """Decode a non-interlaced, 8-bit RGB or RGBA PNG into RGBA bytes."""
    encoded = path.read_bytes()
    if not encoded.startswith(PNG_SIGNATURE):
        raise ValueError(f"{path}: invalid PNG signature")

    offset = len(PNG_SIGNATURE)
    header = None
    compressed = bytearray()
    ended = False
    while offset < len(encoded):
        if offset + 12 > len(encoded):
            raise ValueError(f"{path}: truncated PNG chunk")
        length = struct.unpack(">I", encoded[offset : offset + 4])[0]
        chunk_end = offset + 12 + length
        if chunk_end > len(encoded):
            raise ValueError(f"{path}: truncated PNG chunk payload")
        tag = encoded[offset + 4 : offset + 8]
        payload = encoded[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(
            ">I", encoded[offset + 8 + length : chunk_end]
        )[0]
        actual_crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError(f"{path}: invalid {tag.decode('ascii', 'replace')} CRC")

        if tag == b"IHDR":
            if header is not None or length != 13 or offset != len(PNG_SIGNATURE):
                raise ValueError(f"{path}: invalid IHDR")
            header = struct.unpack(">IIBBBBB", payload)
        elif tag == b"IDAT":
            if header is None or ended:
                raise ValueError(f"{path}: invalid IDAT placement")
            compressed.extend(payload)
        elif tag == b"IEND":
            if length != 0 or header is None or not compressed:
                raise ValueError(f"{path}: invalid IEND")
            ended = True
            offset = chunk_end
            break
        elif tag == b"PLTE":
            pass
        elif tag[0] & 0x20 == 0:
            raise ValueError(f"{path}: unsupported critical chunk {tag!r}")
        offset = chunk_end

    if not ended or offset != len(encoded) or header is None:
        raise ValueError(f"{path}: incomplete PNG datastream")

    width, height, bit_depth, color_type, compression, filtering, interlace = header
    if width == 0 or height == 0:
        raise ValueError(f"{path}: empty PNG")
    if bit_depth != 8 or color_type not in (2, 6):
        raise ValueError(f"{path}: only 8-bit RGB and RGBA PNGs are supported")
    if compression != 0 or filtering != 0 or interlace != 0:
        raise ValueError(f"{path}: unsupported PNG encoding")

    channels = 3 if color_type == 2 else 4
    stride = width * channels
    filtered = zlib.decompress(bytes(compressed))
    expected_length = height * (stride + 1)
    if len(filtered) != expected_length:
        raise ValueError(
            f"{path}: decoded {len(filtered)} bytes, expected {expected_length}"
        )

    decoded = bytearray()
    previous = bytearray(stride)
    offset = 0
    for _ in range(height):
        filter_type = filtered[offset]
        offset += 1
        row = bytearray(filtered[offset : offset + stride])
        offset += stride
        if filter_type not in range(5):
            raise ValueError(f"{path}: unsupported PNG filter {filter_type}")
        for index, value in enumerate(row):
            left = row[index - channels] if index >= channels else 0
            above = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            elif filter_type == 4:
                predictor = _paeth(left, above, upper_left)
            else:
                predictor = 0
            row[index] = (value + predictor) & 0xFF
        decoded.extend(row)
        previous = row

    if channels == 4:
        return width, height, bytes(decoded)

    rgba = bytearray(width * height * 4)
    for source_index in range(0, len(decoded), 3):
        target_index = (source_index // 3) * 4
        rgba[target_index : target_index + 3] = decoded[
            source_index : source_index + 3
        ]
        rgba[target_index + 3] = 255
    return width, height, bytes(rgba)


def _axis_weights(
    source_size: int, target_size: int
) -> list[list[tuple[int, int]]]:
    weights = []
    for target_index in range(target_size):
        target_start = target_index * source_size
        target_end = (target_index + 1) * source_size
        source_start = target_start // target_size
        source_end = (target_end + target_size - 1) // target_size
        weights.append(
            [
                (
                    source_index,
                    min(target_end, (source_index + 1) * target_size)
                    - max(target_start, source_index * target_size),
                )
                for source_index in range(source_start, source_end)
            ]
        )
    return weights


def _area_average(
    source_width: int,
    source_height: int,
    source: bytes,
    target_width: int,
    target_height: int,
) -> bytes:
    """Resize RGBA pixels with an exact box filter using integer weights."""
    if target_width <= 0 or target_height <= 0:
        raise ValueError("target dimensions must be positive")
    if target_width > source_width or target_height > source_height:
        raise ValueError("area averaging only supports downsampling")

    x_weights = _axis_weights(source_width, target_width)
    y_weights = _axis_weights(source_height, target_height)
    denominator = source_width * source_height
    target = bytearray(target_width * target_height * 4)
    for target_y, source_rows in enumerate(y_weights):
        for target_x, source_columns in enumerate(x_weights):
            sums = [0, 0, 0, 0]
            for source_y, y_weight in source_rows:
                for source_x, x_weight in source_columns:
                    weight = x_weight * y_weight
                    source_index = (source_y * source_width + source_x) * 4
                    for channel in range(4):
                        sums[channel] += source[source_index + channel] * weight
            target_index = (target_y * target_width + target_x) * 4
            for channel in range(4):
                target[target_index + channel] = (
                    sums[channel] + denominator // 2
                ) // denominator
    return bytes(target)


def _chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def _png(width: int, height: int, pixels: bytes) -> bytes:
    stride = width * 4
    raw = b"".join(
        b"\x00" + pixels[offset : offset + stride]
        for offset in range(0, len(pixels), stride)
    )
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        PNG_SIGNATURE
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(raw, 9))
        + _chunk(b"IEND", b"")
    )


def write_icons(target_dir: Path, sizes=(16, 32, 48, 128)) -> list[Path]:
    logo_digest = hashlib.sha256(SOURCE_LOGO.read_bytes()).hexdigest()
    if logo_digest != SOURCE_LOGO_SHA256:
        raise ValueError(
            f"{SOURCE_LOGO}: expected reviewed brand logo sha256 "
            f"{SOURCE_LOGO_SHA256}, got {logo_digest}"
        )
    source_width, source_height, source = _decode_png(SOURCE_LOGO)
    target_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for size in sizes:
        path = target_dir / f"icon{size}.png"
        pixels = _area_average(source_width, source_height, source, size, size)
        path.write_bytes(_png(size, size, pixels))
        written.append(path)
    return written


if __name__ == "__main__":
    import sys

    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    for p in write_icons(out):
        print(p)
