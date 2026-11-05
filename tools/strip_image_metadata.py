#!/usr/bin/env python3
"""Strip metadata from project image assets without touching source references."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageOps


IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp"}
METADATA_KEYS = {
    "exif",
    "icc_profile",
    "xmp",
    "XML:com.adobe.xmp",
    "photoshop",
    "comment",
    "description",
    "author",
    "copyright",
    "software",
    "dpi",
}
TECHNICAL_INFO_KEYS = {"transparency", "loop", "background", "duration"}


def has_metadata(path: Path) -> bool:
    with Image.open(path) as source:
        if getattr(source, "is_animated", False):
            return False
        suffix = path.suffix.lower()
        for key, value in source.info.items():
            key_name = str(key).lower()
            if key_name in TECHNICAL_INFO_KEYS:
                continue
            if key_name in METADATA_KEYS or key_name.startswith(("exif", "xmp", "xml", "icc")):
                return bool(value)
            if suffix == ".png" and isinstance(value, str) and value.strip():
                return True
        return False


def strip_image(path: Path, force: bool = False) -> bool:
    if not force and not has_metadata(path):
        return False
    before = path.read_bytes()
    with Image.open(path) as source:
        if getattr(source, "is_animated", False):
            return False
        image = ImageOps.exif_transpose(source)
        if image.mode not in {"RGB", "RGBA", "L", "LA"}:
            image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
        save_kwargs = {"optimize": True}
        suffix = path.suffix.lower()
        if suffix in {".jpg", ".jpeg"}:
            if image.mode != "RGB":
                image = image.convert("RGB")
            save_kwargs.update({"quality": 90, "progressive": True})
        elif suffix == ".webp":
            save_kwargs.update({"quality": 88, "method": 6})
        image.save(path, **save_kwargs)
    return path.read_bytes() != before


def main() -> int:
    parser = argparse.ArgumentParser(description="Strip EXIF/text metadata from app and website images.")
    parser.add_argument("paths", nargs="+", help="Image files or directories to process.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--force", action="store_true", help="Rewrite even when metadata is not detected.")
    mode.add_argument(
        "--check",
        action="store_true",
        help="Fail when removable metadata is present without modifying any file.",
    )
    args = parser.parse_args()

    changed = 0
    checked = 0
    metadata_present = 0
    for raw in args.paths:
        root = Path(raw)
        candidates = [root] if root.is_file() else sorted(
            p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES
        )
        for path in candidates:
            if path.suffix.lower() not in IMAGE_SUFFIXES:
                continue
            checked += 1
            if args.check:
                if has_metadata(path):
                    metadata_present += 1
                    print(f"metadata-present {path}")
                continue
            if strip_image(path, force=args.force):
                changed += 1
                print(f"stripped {path}")
    if args.check:
        print(f"checked={checked} metadata_present={metadata_present}")
        return 1 if metadata_present else 0
    print(f"checked={checked} changed={changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
