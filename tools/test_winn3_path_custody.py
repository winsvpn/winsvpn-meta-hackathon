#!/usr/bin/env python3
"""Hostile tests for retained Windows Winn v3 filesystem custody."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import winn3_path_custody as custody  # noqa: E402


class PathCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / "inputs"
        self.directory.mkdir(mode=0o700)
        self.payload = self.directory / "artifact.bin"
        self.payload.write_bytes((b"0123456789abcdef" * 1024) + b"tail")

    def test_exact_file_is_read_from_retained_descriptor(self) -> None:
        expected = self.payload.read_bytes()
        with custody.open_custodied_file(
            self.payload,
            maximum_bytes=len(expected),
            label="fixture",
        ) as held:
            self.assertEqual(held.size, len(expected))
            self.assertEqual(held.read_at(7, 19), expected[7:26])
            self.assertEqual(
                b"".join(chunk for _offset, chunk in held.iter_chunks(4096)),
                expected,
            )
            held.assert_unchanged()

    def test_relative_and_non_normalized_paths_are_refused(self) -> None:
        with self.assertRaisesRegex(custody.CustodyError, "path-not-absolute"):
            custody.open_custodied_file(
                Path("artifact.bin"), maximum_bytes=100, label="relative"
            )
        non_normalized = self.directory / "nested" / ".." / self.payload.name
        with self.assertRaisesRegex(custody.CustodyError, "path-not-normalized"):
            custody.open_custodied_file(
                non_normalized, maximum_bytes=100000, label="dotdot"
            )

    def test_empty_oversized_and_directory_inputs_are_refused(self) -> None:
        empty = self.directory / "empty.bin"
        empty.write_bytes(b"")
        with self.assertRaisesRegex(custody.CustodyError, "size-out-of-range"):
            custody.open_custodied_file(empty, maximum_bytes=100, label="empty")
        with self.assertRaisesRegex(custody.CustodyError, "size-out-of-range"):
            custody.open_custodied_file(
                self.payload, maximum_bytes=16, label="oversized"
            )
        with self.assertRaises(custody.CustodyError):
            custody.open_custodied_file(
                self.directory, maximum_bytes=100000, label="directory"
            )

    def test_final_symlink_and_hardlink_are_refused(self) -> None:
        symlink = self.directory / "artifact-link.bin"
        symlink.symlink_to(self.payload)
        with self.assertRaises(custody.CustodyError):
            custody.open_custodied_file(
                symlink, maximum_bytes=100000, label="symlink"
            )

        hardlink = self.directory / "artifact-hardlink.bin"
        os.link(self.payload, hardlink)
        with self.assertRaisesRegex(custody.CustodyError, "multiple-links"):
            custody.open_custodied_file(
                self.payload, maximum_bytes=100000, label="hardlink"
            )

    def test_symlinked_ancestor_is_refused(self) -> None:
        real = self.root / "real"
        real.mkdir()
        target = real / "inside.bin"
        target.write_bytes(b"inside")
        linked = self.root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaises(custody.CustodyError):
            custody.open_custodied_file(
                linked / "inside.bin", maximum_bytes=100, label="linked ancestor"
            )

    def test_pathname_replacement_after_open_is_refused(self) -> None:
        with custody.open_custodied_file(
            self.payload, maximum_bytes=100000, label="replacement"
        ) as held:
            replacement = self.directory / "replacement.bin"
            replacement.write_bytes(b"different bytes")
            os.replace(replacement, self.payload)
            with self.assertRaises(custody.CustodyError):
                held.assert_unchanged()

    def test_in_place_mutation_after_open_is_refused(self) -> None:
        with custody.open_custodied_file(
            self.payload, maximum_bytes=100000, label="mutation"
        ) as held:
            with self.payload.open("ab") as stream:
                stream.write(b"changed")
                stream.flush()
                os.fsync(stream.fileno())
            with self.assertRaisesRegex(custody.CustodyError, "custody-changed"):
                held.assert_unchanged()

    def test_ancestor_rename_after_open_is_refused(self) -> None:
        nested = self.directory / "nested"
        nested.mkdir()
        artifact = nested / "held.bin"
        artifact.write_bytes(b"held")
        with custody.open_custodied_file(
            artifact, maximum_bytes=100, label="ancestor rename"
        ) as held:
            moved = self.directory / "moved"
            nested.rename(moved)
            nested.mkdir()
            (nested / "held.bin").write_bytes(b"replacement")
            with self.assertRaises(custody.CustodyError):
                held.assert_unchanged()

    def test_directory_allows_content_changes_but_not_identity_replacement(self) -> None:
        with custody.open_custodied_directory(
            self.directory, label="mutable ledger"
        ) as held:
            (self.directory / "new-entry").write_bytes(b"entry")
            held.assert_unchanged(allow_content_changes=True)
            moved = self.root / "moved-inputs"
            self.directory.rename(moved)
            self.directory.mkdir()
            with self.assertRaises(custody.CustodyError):
                held.assert_unchanged(allow_content_changes=True)

    def test_windows_seal_proof_is_not_emulated_on_posix(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX refusal contract is not applicable on Windows")
        with custody.open_custodied_file(
            self.payload, maximum_bytes=100000, label="seal proof"
        ) as held:
            with self.assertRaisesRegex(
                custody.CustodyError, "windows-seal-proof-requires-windows"
            ):
                held.assert_windows_sealed()

    def test_windows_write_mask_includes_generic_all(self) -> None:
        self.assertEqual(custody.WINDOWS_WRITE_MASK & 0x10000000, 0x10000000)

    @unittest.skipUnless(os.name == "nt", "Windows reparse test requires Windows")
    def test_windows_physical_junction_reparse_point_is_refused(self) -> None:
        target = self.root / "junction-target"
        target.mkdir()
        link = self.root / "junction"
        completed = subprocess.run(
            ["cmd.exe", "/d", "/s", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            self.skipTest(
                "owner-blocked physical junction creation: "
                + (completed.stderr.strip() or completed.stdout.strip())
            )
        with self.assertRaisesRegex(custody.CustodyError, "reparse-point"):
            custody.open_custodied_directory(link, label="reparse")

    @unittest.skipUnless(os.name == "nt", "Windows ACL test requires Windows")
    def test_windows_user_writable_generation_is_not_sealed(self) -> None:
        with custody.open_custodied_file(
            self.payload, maximum_bytes=100000, label="unsealed generation"
        ) as held:
            with self.assertRaisesRegex(custody.CustodyError, "windows-(?:owner|dacl)"):
                held.assert_windows_sealed()


if __name__ == "__main__":
    unittest.main()
