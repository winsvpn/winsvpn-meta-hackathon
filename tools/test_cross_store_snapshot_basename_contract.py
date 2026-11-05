#!/usr/bin/env python3
"""Focused tests for private exact-basename artifact snapshots."""

from __future__ import annotations

import hashlib
import os
import pathlib
import stat
import sys
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import cross_store_gate_runner as gate_runner


class CrossStoreSnapshotBasenameContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _sha(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _artifact(
        self,
        relative: str,
        payload: bytes = b"authenticated-release-artifact\n",
    ) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def _boundary(self, path: pathlib.Path) -> gate_runner.ExactArtifactSnapshot:
        return gate_runner.ExactArtifactSnapshot(
            source_path=path,
            cwd=self.repo,
            expected_sha256=self._sha(path),
        )

    def _transaction_directories(self) -> list[pathlib.Path]:
        return sorted(
            path
            for path in self.repo.rglob(".winsvpn-art-*")
            if path.is_dir()
        )

    def test_exact_windows_and_linux_basenames_are_preserved(self) -> None:
        names = (
            "WinsVPN-Setup.exe",
            "WinsVPN-Setup-arm64.exe",
            "wins-vpn-linux-x64.tar.gz",
            "wins-vpn-linux-arm64.tar.gz",
        )
        for index, name in enumerate(names):
            with self.subTest(name=name):
                artifact = self._artifact(f"artifacts/{index}/{name}")
                boundary = self._boundary(artifact)
                with boundary as exact:
                    self.assertEqual(exact.snapshot_path.name, name)
                    self.assertEqual(
                        pathlib.Path(exact.executed_artifact_arg(str(artifact))).name,
                        name,
                    )
                    relative = artifact.relative_to(self.repo).as_posix()
                    self.assertEqual(
                        pathlib.Path(exact.executed_artifact_arg(relative)).name,
                        name,
                    )
                    self.assertTrue(exact.snapshot_path.is_file())
                    self.assertIn(".winsvpn-art-", exact.snapshot_path.as_posix())
                    if os.name != "nt":
                        self.assertEqual(
                            stat.S_IMODE(exact.snapshot_directory.lstat().st_mode),
                            0o700,
                        )
                self.assertTrue(boundary.cleanup_complete)
                self.assertFalse(boundary.snapshot_directory.exists())
        self.assertEqual(self._transaction_directories(), [])

    def test_duplicate_basenames_in_distinct_inputs_do_not_collide(self) -> None:
        first_path = self._artifact("first/WinsVPN-Setup.exe")
        second_path = self._artifact("second/WinsVPN-Setup.exe")
        first = self._boundary(first_path)
        second = self._boundary(second_path)
        with first as first_exact, second as second_exact:
            self.assertNotEqual(first_exact.snapshot_path, second_exact.snapshot_path)
            self.assertEqual(first_exact.snapshot_path.name, "WinsVPN-Setup.exe")
            self.assertEqual(second_exact.snapshot_path.name, "WinsVPN-Setup.exe")
            self.assertEqual(
                first_exact.snapshot_path.read_bytes(),
                second_exact.snapshot_path.read_bytes(),
            )
        self.assertTrue(first.cleanup_complete)
        self.assertTrue(second.cleanup_complete)
        self.assertEqual(self._transaction_directories(), [])

    def test_same_input_concurrent_snapshot_collision_fails_closed(self) -> None:
        artifact = self._artifact("build/WinsVPN-Setup.exe")
        first = self._boundary(artifact)
        with first:
            with self.assertRaisesRegex(
                gate_runner.ExactSnapshotError,
                "collision or concurrent execution",
            ):
                with self._boundary(artifact):
                    self.fail("colliding artifact snapshot unexpectedly entered")
        self.assertTrue(first.cleanup_complete)
        self.assertEqual(self._transaction_directories(), [])

    def test_symlink_source_is_rejected_without_snapshot(self) -> None:
        artifact = self._artifact("build/real/WinsVPN-Setup.exe")
        link = self.repo / "build" / "linked-WinsVPN-Setup.exe"
        try:
            link.symlink_to(artifact.relative_to(link.parent))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(gate_runner.ExactSnapshotError, "symlink"):
            with gate_runner.ExactArtifactSnapshot(
                source_path=link,
                cwd=self.repo,
                expected_sha256=self._sha(artifact),
            ):
                self.fail("symlink artifact unexpectedly entered")
        self.assertEqual(self._transaction_directories(), [])

    def test_hardlink_source_is_rejected_without_snapshot(self) -> None:
        artifact = self._artifact("build/WinsVPN-Setup.exe")
        alias = self.repo / "build" / "WinsVPN-Setup-alias.exe"
        try:
            os.link(artifact, alias)
        except (OSError, NotImplementedError):
            self.skipTest("hardlinks unavailable")
        self.assertGreater(artifact.lstat().st_nlink, 1)
        with self.assertRaisesRegex(gate_runner.ExactSnapshotError, "hardlinked"):
            with self._boundary(artifact):
                self.fail("hardlinked artifact unexpectedly entered")
        self.assertEqual(self._transaction_directories(), [])

    def test_source_path_traversal_is_rejected(self) -> None:
        outside = self.repo.parent / f"{self.repo.name}-outside-WinsVPN-Setup.exe"
        outside.write_bytes(b"outside\n")
        try:
            with self.assertRaisesRegex(
                gate_runner.ExactSnapshotError,
                "escapes the repository",
            ):
                with gate_runner.ExactArtifactSnapshot(
                    source_path=pathlib.Path("..") / outside.name,
                    cwd=self.repo,
                    expected_sha256=self._sha(outside),
                ):
                    self.fail("traversal artifact unexpectedly entered")
        finally:
            outside.unlink()
        self.assertEqual(self._transaction_directories(), [])

    def test_snapshot_hash_traversal_is_rejected(self) -> None:
        artifact = self._artifact("build/WinsVPN-Setup.exe")
        with self.assertRaisesRegex(
            gate_runner.ExactSnapshotError,
            "canonical SHA-256",
        ):
            gate_runner.artifact_snapshot_path_for(
                artifact,
                "../" + "a" * 61,
            )
        self.assertEqual(self._transaction_directories(), [])

    def test_preexisting_transaction_symlink_collision_is_rejected(self) -> None:
        artifact = self._artifact("build/WinsVPN-Setup.exe")
        snapshot = gate_runner.artifact_snapshot_path_for(artifact, self._sha(artifact))
        target = self.repo / "collision-target"
        target.mkdir()
        try:
            snapshot.parent.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks unavailable")
        with self.assertRaisesRegex(
            gate_runner.ExactSnapshotError,
            "collision or concurrent execution",
        ):
            with self._boundary(artifact):
                self.fail("symlink collision unexpectedly entered")
        self.assertFalse(snapshot.exists())

    def test_snapshot_path_swap_and_restore_is_detected_and_cleaned(self) -> None:
        artifact = self._artifact("build/WinsVPN-Setup.exe")
        boundary = self._boundary(artifact)
        with self.assertRaisesRegex(
            gate_runner.ExactSnapshotError,
            "changed during exact-byte execution",
        ):
            with boundary as exact:
                saved = exact.snapshot_path.with_name("saved-snapshot")
                exact.snapshot_path.rename(saved)
                exact.snapshot_path.write_bytes(artifact.read_bytes())
                exact.snapshot_path.unlink()
                saved.rename(exact.snapshot_path)
        self.assertTrue(boundary.cleanup_complete)
        self.assertEqual(self._transaction_directories(), [])

    def test_snapshot_directory_swap_and_restore_is_detected_and_cleaned(
        self,
    ) -> None:
        artifact = self._artifact("build/WinsVPN-Setup.exe")
        boundary = self._boundary(artifact)
        with self.assertRaisesRegex(
            gate_runner.ExactSnapshotError,
            "changed during exact-byte execution",
        ):
            with boundary as exact:
                saved = exact.snapshot_directory.with_name(
                    exact.snapshot_directory.name + "-saved"
                )
                exact.snapshot_directory.rename(saved)
                exact.snapshot_directory.mkdir(mode=0o700)
                exact.snapshot_path.write_bytes(artifact.read_bytes())
                exact.snapshot_path.unlink()
                exact.snapshot_directory.rmdir()
                saved.rename(exact.snapshot_directory)
        self.assertTrue(boundary.cleanup_complete)
        self.assertEqual(self._transaction_directories(), [])

    def test_snapshot_tamper_is_detected_and_cleaned(self) -> None:
        artifact = self._artifact("build/wins-vpn-linux-x64.tar.gz")
        boundary = self._boundary(artifact)
        with self.assertRaisesRegex(
            gate_runner.ExactSnapshotError,
            "changed during exact-byte execution",
        ):
            with boundary as exact:
                exact.snapshot_path.write_bytes(b"tampered\n")
        self.assertTrue(boundary.cleanup_complete)
        self.assertEqual(self._transaction_directories(), [])


if __name__ == "__main__":
    unittest.main()
