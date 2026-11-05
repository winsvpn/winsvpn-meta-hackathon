#!/usr/bin/env python3

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import create_gcloud_custody_receipt as producer
import gcloud_custody as custody


class SimulatedCrash(BaseException):
    pass


class GcloudCustodyReceiptPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "google-cloud-sdk"
        self.root.mkdir()
        (self.root / "payload.txt").write_bytes(b"reviewed-runtime\n")
        self.archive_data = b"reviewed-official-archive-v1\n"
        self.receipt_data = b'{"contract":"test-receipt","schema_version":1}\n'
        self.expected_clean_tree = custody.install_tree_sha256(self.root)
        archive = self.root / custody.CUSTODY_ARCHIVE_NAME
        archive.write_bytes(self.archive_data)
        archive.chmod(custody.SEALED_PUBLIC_DATA_MODE)
        self.expected_tree = custody.install_tree_sha256(self.root)
        archive.chmod(0o600)
        archive.unlink()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self) -> tuple[Path, Path]:
        return producer._publish_pair(
            self.root,
            self.archive_data,
            self.receipt_data,
            expected_clean_tree=self.expected_clean_tree,
            expected_tree=self.expected_tree,
        )

    def assert_complete_publication(self) -> None:
        receipt = self.root / custody.RECEIPT_NAME
        archive = self.root / custody.CUSTODY_ARCHIVE_NAME
        self.assertEqual(receipt.read_bytes(), self.receipt_data)
        self.assertEqual(archive.read_bytes(), self.archive_data)
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o444)
        self.assertEqual(receipt.stat().st_nlink, 1)
        self.assertEqual(archive.stat().st_nlink, 1)
        self.assertFalse((self.root / producer.RECEIPT_STAGE_NAME).exists())
        self.assertFalse((self.root / producer.ARCHIVE_STAGE_NAME).exists())
        self.assertEqual(custody.install_tree_sha256(self.root), self.expected_tree)

    def test_exact_retry_is_idempotent_and_reestablishes_durability(self) -> None:
        receipt, archive = self.publish()
        identities = (receipt.stat().st_ino, archive.stat().st_ino)
        retried_receipt, retried_archive = self.publish()
        self.assertEqual(
            (retried_receipt.stat().st_ino, retried_archive.stat().st_ino),
            identities,
        )
        self.assert_complete_publication()

    def test_crash_after_archive_link_is_exactly_recoverable(self) -> None:
        real_unlink = producer._unlink_stage
        crashed = False

        def crash_after_archive_link(
            directory: int,
            name: str,
            expected_inode: tuple[int, int],
            *,
            label: str,
        ) -> None:
            nonlocal crashed
            if name == producer.ARCHIVE_STAGE_NAME and not crashed:
                crashed = True
                raise SimulatedCrash("power loss after archive publication")
            real_unlink(directory, name, expected_inode, label=label)

        with mock.patch.object(
            producer, "_unlink_stage", side_effect=crash_after_archive_link
        ):
            with self.assertRaises(SimulatedCrash):
                self.publish()
        archive = self.root / custody.CUSTODY_ARCHIVE_NAME
        stage = self.root / producer.ARCHIVE_STAGE_NAME
        self.assertTrue(archive.is_file())
        self.assertTrue(stage.is_file())
        self.assertEqual(
            (archive.stat().st_dev, archive.stat().st_ino),
            (stage.stat().st_dev, stage.stat().st_ino),
        )
        self.assertEqual(archive.stat().st_nlink, 2)
        self.assertFalse((self.root / custody.RECEIPT_NAME).exists())

        self.publish()
        self.assert_complete_publication()

    def test_crash_after_receipt_link_is_exactly_recoverable(self) -> None:
        real_unlink = producer._unlink_stage
        crashed = False

        def crash_after_receipt_link(
            directory: int,
            name: str,
            expected_inode: tuple[int, int],
            *,
            label: str,
        ) -> None:
            nonlocal crashed
            if name == producer.RECEIPT_STAGE_NAME and not crashed:
                crashed = True
                raise SimulatedCrash("power loss after receipt publication")
            real_unlink(directory, name, expected_inode, label=label)

        with mock.patch.object(
            producer, "_unlink_stage", side_effect=crash_after_receipt_link
        ):
            with self.assertRaises(SimulatedCrash):
                self.publish()
        receipt = self.root / custody.RECEIPT_NAME
        stage = self.root / producer.RECEIPT_STAGE_NAME
        archive = self.root / custody.CUSTODY_ARCHIVE_NAME
        self.assertTrue(receipt.is_file())
        self.assertTrue(stage.is_file())
        self.assertTrue(archive.is_file())
        self.assertEqual(
            (receipt.stat().st_dev, receipt.stat().st_ino),
            (stage.stat().st_dev, stage.stat().st_ino),
        )
        self.assertEqual(receipt.stat().st_nlink, 2)
        self.assertEqual(archive.stat().st_nlink, 1)

        self.publish()
        self.assert_complete_publication()

    def test_crash_during_stage_cleanup_is_exactly_recoverable(self) -> None:
        real_unlink = producer.os.unlink
        crashed = False
        cleanup_name = producer._cleanup_name(producer.ARCHIVE_STAGE_NAME)

        def crash_after_cleanup_rename(name: str, **kwargs: object) -> None:
            nonlocal crashed
            if name == cleanup_name and not crashed:
                crashed = True
                raise SimulatedCrash("power loss during stage cleanup")
            real_unlink(name, **kwargs)

        with mock.patch.object(
            producer.os, "unlink", side_effect=crash_after_cleanup_rename
        ):
            with self.assertRaises(SimulatedCrash):
                self.publish()
        archive = self.root / custody.CUSTODY_ARCHIVE_NAME
        stage = self.root / producer.ARCHIVE_STAGE_NAME
        cleanup = self.root / cleanup_name
        self.assertTrue(archive.is_file())
        self.assertFalse(stage.exists())
        self.assertTrue(cleanup.is_file())
        self.assertEqual(
            (archive.stat().st_dev, archive.stat().st_ino),
            (cleanup.stat().st_dev, cleanup.stat().st_ino),
        )
        self.assertEqual(archive.stat().st_nlink, 2)

        self.publish()
        self.assert_complete_publication()

    def test_partial_private_stage_is_cleaned_before_retry(self) -> None:
        stage = self.root / producer.RECEIPT_STAGE_NAME
        stage.write_bytes(b"partial-crash")
        stage.chmod(producer.STAGE_WRITING_MODE)
        self.publish()
        self.assert_complete_publication()

    def test_unsafe_preexisting_targets_are_preserved(self) -> None:
        cases = (custody.CUSTODY_ARCHIVE_NAME, custody.RECEIPT_NAME)
        for index, name in enumerate(cases):
            with self.subTest(name=name):
                root = Path(self.temporary.name) / f"unsafe-{index}"
                root.mkdir()
                (root / "payload.txt").write_bytes(b"reviewed-runtime\n")
                target = root / name
                target.write_bytes(b"foreign-sentinel\n")
                target.chmod(custody.SEALED_PUBLIC_DATA_MODE)
                identity = (target.stat().st_dev, target.stat().st_ino)
                with self.assertRaisesRegex(
                    custody.GcloudCustodyError, "unsafe preexisting"
                ):
                    producer._publish_pair(
                        root,
                        self.archive_data,
                        self.receipt_data,
                        expected_clean_tree=custody.install_tree_sha256(root),
                        expected_tree=self.expected_tree,
                    )
                self.assertEqual(target.read_bytes(), b"foreign-sentinel\n")
                self.assertEqual((target.stat().st_dev, target.stat().st_ino), identity)

        symlink_root = Path(self.temporary.name) / "unsafe-symlink"
        symlink_root.mkdir()
        (symlink_root / "payload.txt").write_bytes(b"reviewed-runtime\n")
        victim = Path(self.temporary.name) / "victim"
        victim.write_bytes(b"victim-sentinel\n")
        target = symlink_root / custody.RECEIPT_NAME
        target.symlink_to(victim)
        with self.assertRaisesRegex(custody.GcloudCustodyError, "unsafe preexisting"):
            producer._publish_pair(
                symlink_root,
                self.archive_data,
                self.receipt_data,
                expected_clean_tree=custody.install_tree_sha256(symlink_root),
                expected_tree=self.expected_tree,
            )
        self.assertTrue(target.is_symlink())
        self.assertEqual(victim.read_bytes(), b"victim-sentinel\n")

    def test_cleanup_name_race_preserves_foreign_file_and_stage(self) -> None:
        stage_name = producer.ARCHIVE_STAGE_NAME
        cleanup_name = producer._cleanup_name(stage_name)
        directory = os.open(self.root, producer._DIRECTORY_FLAGS)
        try:
            producer._write_exclusive(
                directory,
                stage_name,
                self.archive_data,
                custody.SEALED_PUBLIC_DATA_MODE,
                label="archive stage",
            )
            stage = self.root / stage_name
            stage_identity = (stage.stat().st_dev, stage.stat().st_ino)
            real_rename = producer._rename_exclusive

            def race_cleanup(
                directory_fd: int, source: str, target: str
            ) -> None:
                self.assertEqual(source, stage_name)
                self.assertEqual(target, cleanup_name)
                hostile = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
                try:
                    os.write(hostile, b"foreign-cleanup-sentinel\n")
                    os.fsync(hostile)
                finally:
                    os.close(hostile)
                real_rename(directory_fd, source, target)

            with mock.patch.object(
                producer, "_rename_exclusive", side_effect=race_cleanup
            ), self.assertRaisesRegex(
                custody.GcloudCustodyError, "preserved both names"
            ):
                producer._unlink_stage(
                    directory,
                    stage_name,
                    stage_identity,
                    label="archive stage",
                )
            cleanup = self.root / cleanup_name
            self.assertEqual(stage.read_bytes(), self.archive_data)
            self.assertEqual(
                (stage.stat().st_dev, stage.stat().st_ino), stage_identity
            )
            self.assertEqual(cleanup.read_bytes(), b"foreign-cleanup-sentinel\n")
        finally:
            os.close(directory)

    def test_publication_root_gid_and_special_mode_are_exact(self) -> None:
        with mock.patch.object(
            producer, "_effective_gid", return_value=os.getegid() ^ 1
        ), self.assertRaisesRegex(
            custody.GcloudCustodyError, "install root is not a directory"
        ):
            self.publish()

        original_mode = stat.S_IMODE(self.root.stat().st_mode)
        self.root.chmod(original_mode | stat.S_ISVTX)
        try:
            with self.assertRaisesRegex(
                custody.GcloudCustodyError, "install root is not a directory"
            ):
                self.publish()
        finally:
            self.root.chmod(original_mode)

    def test_metadata_file_and_parent_durability_ordering(self) -> None:
        events: list[tuple[str, object]] = []
        real_write = producer.os.write
        real_fchmod = producer.os.fchmod
        real_fsync = producer.os.fsync
        real_link = producer.os.link
        real_rename = producer._rename_exclusive
        real_unlink = producer.os.unlink

        def recording_write(descriptor: int, data: object) -> int:
            events.append(("write", descriptor))
            return real_write(descriptor, data)

        def recording_fchmod(descriptor: int, mode: int) -> None:
            events.append(("fchmod", mode))
            real_fchmod(descriptor, mode)

        def recording_fsync(descriptor: int) -> None:
            kind = "fsync-directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "fsync-file"
            events.append((kind, descriptor))
            real_fsync(descriptor)

        def recording_link(source: str, target: str, **kwargs: object) -> None:
            events.append(("link", target))
            real_link(source, target, **kwargs)

        def recording_unlink(name: str, **kwargs: object) -> None:
            events.append(("unlink", name))
            real_unlink(name, **kwargs)

        def recording_rename(directory: int, source: str, target: str) -> None:
            events.append(("rename", source))
            real_rename(directory, source, target)

        with mock.patch.object(
            producer.os, "write", side_effect=recording_write
        ), mock.patch.object(
            producer.os, "fchmod", side_effect=recording_fchmod
        ), mock.patch.object(
            producer.os, "fsync", side_effect=recording_fsync
        ), mock.patch.object(
            producer.os, "link", side_effect=recording_link
        ), mock.patch.object(
            producer, "_rename_exclusive", side_effect=recording_rename
        ), mock.patch.object(
            producer.os, "unlink", side_effect=recording_unlink
        ):
            self.publish()

        link_indexes = {
            value: index
            for index, (kind, value) in enumerate(events)
            if kind == "link"
        }
        archive_link = link_indexes[custody.CUSTODY_ARCHIVE_NAME]
        receipt_link = link_indexes[custody.RECEIPT_NAME]
        self.assertLess(archive_link, receipt_link)
        fchmod_indexes = [
            index for index, (kind, _value) in enumerate(events) if kind == "fchmod"
        ]
        self.assertEqual(len(fchmod_indexes), 2)
        for metadata_index, link_index in zip(
            fchmod_indexes, (archive_link, receipt_link)
        ):
            file_sync = next(
                index
                for index in range(metadata_index + 1, link_index)
                if events[index][0] == "fsync-file"
            )
            stage_parent_sync = next(
                index
                for index in range(file_sync + 1, link_index)
                if events[index][0] == "fsync-directory"
            )
            publication_parent_sync = next(
                index
                for index in range(link_index + 1, len(events))
                if events[index][0] == "fsync-directory"
            )
            self.assertLess(metadata_index, file_sync)
            self.assertLess(file_sync, stage_parent_sync)
            self.assertLess(stage_parent_sync, link_index)
            self.assertLess(link_index, publication_parent_sync)
        archive_cleanup = events.index(("rename", producer.ARCHIVE_STAGE_NAME))
        receipt_cleanup = events.index(("rename", producer.RECEIPT_STAGE_NAME))
        self.assertGreater(archive_cleanup, archive_link)
        self.assertGreater(receipt_cleanup, receipt_link)
        self.assertTrue(
            any(
                kind == "fsync-directory"
                for kind, _value in events[archive_cleanup + 1 :]
            )
        )
        self.assertTrue(
            any(
                kind == "fsync-directory"
                for kind, _value in events[receipt_cleanup + 1 :]
            )
        )
        self.assert_complete_publication()


if __name__ == "__main__":
    unittest.main()
