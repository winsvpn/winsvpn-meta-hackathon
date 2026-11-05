#!/usr/bin/env python3
"""OI-42 (Round 36 treaty) drift test: every generated extension manifest
carries the app's pubspec version (build metadata stripped), so the extension
can never silently drift back to a hard-coded placeholder."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
import unittest

EXTENSION_DIR = pathlib.Path(__file__).resolve().parents[1]
ROOT = EXTENSION_DIR.parent

_spec = importlib.util.spec_from_file_location("extension_build", EXTENSION_DIR / "build.py")
extension_build = importlib.util.module_from_spec(_spec)
sys.modules["extension_build"] = extension_build
_spec.loader.exec_module(extension_build)


class ExtensionVersionTracksAppTest(unittest.TestCase):
    def test_pubspec_version_line_exists(self) -> None:
        pubspec = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
        match = re.search(r'^version:\s*([0-9]+\.[0-9]+\.[0-9]+)\+', pubspec, re.M)
        self.assertIsNotNone(match, "pubspec.yaml must carry version: x.y.z+build")

    def test_app_version_strips_build_metadata(self) -> None:
        version = extension_build.app_version()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertNotIn("+", version)

    def test_app_version_components_are_store_legal(self) -> None:
        # Round 37 convergence (solpro): each component must be 0..65535, not
        # merely dot-separated digits; 65536 passes a naive shape check and
        # fails Chrome's manifest grammar at install time.
        version = extension_build.app_version()
        for part in version.split("."):
            self.assertTrue(part.isdigit())
            self.assertLessEqual(int(part), 65535)

    def test_every_target_manifest_carries_the_app_version(self) -> None:
        expected = extension_build.app_version()
        for target in ("chrome", "edge", "firefox", "safari"):
            manifest_path = EXTENSION_DIR / "manifest" / f"{target}.jsonc"
            if not manifest_path.exists():
                continue
            manifest = extension_build.build_manifest(target)
            self.assertEqual(
                manifest.get("version"),
                expected,
                f"{target} manifest version must equal the pubspec app version",
            )


if __name__ == "__main__":
    unittest.main()
