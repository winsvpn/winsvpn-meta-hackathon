#!/usr/bin/env python3
"""Adversarial tests for private release-symbol filesystem custody."""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import private_release_symbol_custody as custody


class PrivateReleaseSymbolCustodyTests(unittest.TestCase):
    def fixture(
        self, root: pathlib.Path
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
        repo = root / "repo"
        private = repo / ".artifacts" / "private-release-symbols"
        symbols = private / "android" / "1.0.15+30"
        symbols.mkdir(parents=True)
        (repo / "pubspec.yaml").write_text("version: 1.0.15+30\n", encoding="utf-8")
        symbol = symbols / "app.android-arm64.symbols"
        symbol.write_bytes(b"private-symbol-fixture")
        artifact = root / "app-release.apk"
        artifact.write_bytes(b"release-artifact-fixture")
        return repo, private, symbols, artifact

    def test_record_rejects_symbol_with_external_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            repo, private, symbols, artifact = self.fixture(root)
            symbol = symbols / "app.android-arm64.symbols"
            os.link(symbol, root / "outside-symbol-link")
            self.assertEqual(symbol.stat().st_nlink, 2)
            with self.assertRaisesRegex(SystemExit, "exactly one filesystem link"):
                custody.record(
                    "android",
                    symbols,
                    [artifact],
                    private_root=private,
                    repo_root=repo,
                )

    def test_verify_rejects_symbol_hardlinked_after_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            repo, private, symbols, artifact = self.fixture(root)
            custody.record(
                "android",
                symbols,
                [artifact],
                private_root=private,
                repo_root=repo,
            )
            os.link(symbols / "app.android-arm64.symbols", root / "late-symbol-link")
            with self.assertRaisesRegex(SystemExit, "exactly one filesystem link"):
                custody.verify("android", symbols, [artifact], private_root=private)

    @unittest.skipIf(os.name == "nt", "POSIX ownership and mode contract")
    def test_record_rejects_group_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            repo, private, symbols, artifact = self.fixture(root)
            unsafe_parent = symbols.parent
            unsafe_parent.chmod(0o770)
            with self.assertRaisesRegex(SystemExit, "group/other writable"):
                custody.record(
                    "android",
                    symbols,
                    [artifact],
                    private_root=private,
                    repo_root=repo,
                )

    @unittest.skipIf(os.name == "nt", "POSIX ownership and mode contract")
    def test_verify_rejects_parent_made_writable_after_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            repo, private, symbols, artifact = self.fixture(root)
            custody.record(
                "android",
                symbols,
                [artifact],
                private_root=private,
                repo_root=repo,
            )
            symbols.parent.chmod(0o777)
            with self.assertRaisesRegex(SystemExit, "group/other writable"):
                custody.verify("android", symbols, [artifact], private_root=private)

    @unittest.skipIf(os.name == "nt", "POSIX ownership and mode contract")
    def test_record_rejects_writable_parent_above_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            repo, private, symbols, artifact = self.fixture(root)
            private.parent.chmod(0o777)
            with self.assertRaisesRegex(SystemExit, "group/other writable"):
                custody.record(
                    "android",
                    symbols,
                    [artifact],
                    private_root=private,
                    repo_root=repo,
                )

    def test_record_rejects_symlinked_parent_component(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            repo = root / "repo"
            private = repo / ".artifacts" / "private-release-symbols"
            private.mkdir(parents=True)
            real_parent = private / "real-android"
            symbols = real_parent / "1.0.15+30"
            symbols.mkdir(parents=True)
            (private / "android").symlink_to(real_parent, target_is_directory=True)
            (repo / "pubspec.yaml").write_text("version: 1.0.15+30\n", encoding="utf-8")
            (symbols / "app.symbols").write_bytes(b"private")
            artifact = root / "app-release.apk"
            artifact.write_bytes(b"release")
            linked_symbols = private / "android" / "1.0.15+30"
            with self.assertRaisesRegex(SystemExit, "real directory"):
                custody.record(
                    "android",
                    linked_symbols,
                    [artifact],
                    private_root=private,
                    repo_root=repo,
                )


if __name__ == "__main__":
    unittest.main()
