#!/usr/bin/env python3
"""Owner ruling 2026-10-25: the eagle "Win Empire" artwork is retired and the
extension toolbar and store icons come from the red panda Guardian app icon.

The icons are generated at stage time by icons.py, so there are no checked-in
icon PNGs to pin. This test pins the two things that decide what ships: the
exact bytes of the source logo, and the decoded pixels of every generated size.
Decoded pixels are compared instead of PNG bytes because the pixel resize is
integer arithmetic and identical everywhere, while the zlib stream is not."""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sys
import tempfile
import unittest

TOOLS_DIR = pathlib.Path(__file__).resolve().parent

_spec = importlib.util.spec_from_file_location("extension_icons", TOOLS_DIR / "icons.py")
icons = importlib.util.module_from_spec(_spec)
sys.modules["extension_icons"] = icons
_spec.loader.exec_module(icons)

# Decoded RGBA pixel digests of the generated icons, per size.
EXPECTED_PIXEL_SHA256 = {
    16: "aeb0b8646227b4db53959c748b111a0b1fd189ad1a6b9aad95896390da7acd5f",
    32: "e3fff049cdcef309a0bd71cf79599e537bc535afceff7738df02a1da1fc8af86",
    48: "ca37070e491b86eca6a6c2a8ef5b08affa2cc758bb4a29a83aa7b6a2ee7a5b0d",
    128: "6850350e0023afdbb322650dda55fd23eadfa0a040e3af6269e87392f993594a",
}
# Cream background of the red panda Guardian icon; a flat area survives the
# box filter unchanged, so every size keeps this exact corner pixel.
CREAM_CORNER_RGBA = (255, 242, 214, 255)


class ExtensionIconBrandTest(unittest.TestCase):
    def test_source_logo_is_the_pinned_ios_app_icon(self) -> None:
        self.assertEqual(
            icons.SOURCE_LOGO.parts[-5:],
            (
                "ios",
                "Runner",
                "Assets.xcassets",
                "AppIcon.appiconset",
                "Icon-App-1024x1024@1x.png",
            ),
        )
        payload = icons.SOURCE_LOGO.read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), icons.SOURCE_LOGO_SHA256)
        width, height, _ = icons._decode_png(icons.SOURCE_LOGO)
        self.assertEqual((width, height), (1024, 1024))

    def test_generated_icons_are_the_red_panda_at_every_manifest_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            written = icons.write_icons(pathlib.Path(tmp))
            self.assertEqual(
                [path.name for path in written],
                ["icon16.png", "icon32.png", "icon48.png", "icon128.png"],
            )
            for size, path in zip((16, 32, 48, 128), written):
                with self.subTest(size=size):
                    encoded = path.read_bytes()
                    self.assertTrue(encoded.startswith(icons.PNG_SIGNATURE))
                    # IHDR: 8-bit RGBA, non-interlaced, as before the brand change.
                    self.assertEqual(encoded[24:29], b"\x08\x06\x00\x00\x00")
                    width, height, pixels = icons._decode_png(path)
                    self.assertEqual((width, height), (size, size))
                    self.assertEqual(set(pixels[3::4]), {255})
                    self.assertEqual(tuple(pixels[:4]), CREAM_CORNER_RGBA)
                    self.assertEqual(
                        hashlib.sha256(pixels).hexdigest(), EXPECTED_PIXEL_SHA256[size]
                    )

    def test_changed_source_logo_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            swapped = pathlib.Path(tmp) / "logo.png"
            swapped.write_bytes(icons.SOURCE_LOGO.read_bytes() + b"\x00")
            original = icons.SOURCE_LOGO
            icons.SOURCE_LOGO = swapped
            try:
                with self.assertRaisesRegex(ValueError, "expected reviewed brand logo"):
                    icons.write_icons(pathlib.Path(tmp) / "out")
            finally:
                icons.SOURCE_LOGO = original
            self.assertFalse((pathlib.Path(tmp) / "out").exists())


if __name__ == "__main__":
    unittest.main()
