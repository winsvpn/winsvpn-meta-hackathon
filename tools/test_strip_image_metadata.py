#!/usr/bin/env python3
"""Regression tests for non-mutating release image metadata checks."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest

from PIL import Image, PngImagePlugin


SCRIPT = pathlib.Path(__file__).with_name("strip_image_metadata.py")


class StripImageMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _png(self, name: str, *, with_metadata: bool) -> pathlib.Path:
        path = self.root / name
        metadata = None
        if with_metadata:
            metadata = PngImagePlugin.PngInfo()
            metadata.add_text("comment", "must not ship")
        Image.new("RGB", (4, 4), (23, 45, 67)).save(path, pnginfo=metadata)
        return path

    def _run(self, *args: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *(str(arg) for arg in args)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_check_accepts_clean_image_without_rewriting(self) -> None:
        path = self._png("clean.png", with_metadata=False)
        before = path.read_bytes()
        result = self._run("--check", path)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(path.read_bytes(), before)
        self.assertIn("metadata_present=0", result.stdout)

    def test_check_rejects_metadata_without_rewriting(self) -> None:
        path = self._png("tagged.png", with_metadata=True)
        before = path.read_bytes()
        result = self._run("--check", path)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(path.read_bytes(), before)
        self.assertIn("metadata-present", result.stdout)
        self.assertIn("metadata_present=1", result.stdout)


if __name__ == "__main__":
    unittest.main()
