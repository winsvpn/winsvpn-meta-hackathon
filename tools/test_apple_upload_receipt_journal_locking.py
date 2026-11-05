#!/usr/bin/env python3
"""Journal lock ordering, replay, custody, and interruption regressions."""
import errno
import fcntl
import json
import os
import pathlib
import secrets
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_cross_store_artifact_gate as gate


class JournalReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        identity = self.root / gate.RELEASE_IDENTITY_RELATIVE_PATH
        identity.parent.mkdir(parents=True)
        identity.write_bytes((ROOT / gate.RELEASE_IDENTITY_RELATIVE_PATH).read_bytes())
        self.patch = mock.patch.object(gate, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.path = self.root / gate.UPLOAD_RECEIPT_JOURNAL_RELATIVE
        gate._with_upload_receipt_journal(None)

    def auth(self):
        return gate.issue_upload_receipt_challenge(
            "ios-app-store-ipa",
            artifact_sha256=secrets.token_hex(32),
            artifact_bytes=11,
            architectures=tuple(gate.REQUIRED_IOS_ARCHITECTURES),
            release=gate.CANONICAL_RELEASE,
        )

    def concurrent(self, auths):
        barrier = threading.Barrier(2)
        real_flock = gate.fcntl.flock
        errors, committed, unexpected = [], [], []
        def locked(fd, operation):
            if operation == fcntl.LOCK_EX:
                barrier.wait(timeout=5)
            return real_flock(fd, operation)
        def worker(auth):
            try:
                gate._consume_upload_receipt_challenge(auth)
                committed.append(auth['nonce'])
            except gate.AppleArtifactGateError as exc:
                errors.append(str(exc))
            except BaseException as exc:
                unexpected.append(repr(exc))
        with mock.patch.object(gate.fcntl, 'flock', locked):
            threads = [threading.Thread(target=worker, args=(auth,), daemon=True) for auth in auths]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(unexpected, [])
        records = gate._parse_upload_receipt_journal(self.path.read_bytes())
        return committed, errors, records

    def test_duplicate_commit_is_replay_after_wait(self):
        auth = self.auth()
        committed, errors, records = self.concurrent((auth, auth))
        self.assertEqual(len(committed), 1)
        self.assertEqual(errors, [gate.RECEIPT_REPLAY_ERROR])
        self.assertEqual(sum(x['kind'] == 'consumed-set' for x in records), 1)

    def test_distinct_valid_concurrent_commits_both_succeed(self):
        committed, errors, records = self.concurrent((self.auth(), self.auth()))
        self.assertEqual(errors, [])
        self.assertEqual(len(committed), 2)
        self.assertEqual(sum(x['kind'] == 'consumed-set' for x in records), 2)

    def test_lock_retained_between_operations_until_close(self):
        held = gate._HeldUploadReceiptJournal()
        fd = os.open(self.path, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            token = gate._UPLOAD_RECEIPT_JOURNAL_CUSTODY.set(held)
            try:
                gate._with_upload_receipt_journal(None)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                gate._UPLOAD_RECEIPT_JOURNAL_CUSTODY.reset(token)
            held.close(verify=True)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
            held.close(verify=False)

    def test_competing_append_cannot_race_final_close(self):
        first, second = self.auth(), self.auth()
        real_close = gate._HeldUploadReceiptJournal.close
        attacked = False
        appended = False
        def closing(held, *, verify):
            nonlocal attacked, appended
            if verify and not attacked:
                attacked = True
                fd = os.open(self.path, os.O_RDWR | os.O_APPEND)
                try:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass
                    else:
                        record = dict(schema=gate.UPLOAD_RECEIPT_JOURNAL_SCHEMA,
                            kind='consumed-set', transaction_id=secrets.token_hex(32),
                            committed=True, authentications=[second])
                        os.write(fd, (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii'))
                        os.fsync(fd)
                        appended = True
                finally:
                    os.close(fd)
            return real_close(held, verify=verify)
        with mock.patch.object(gate._HeldUploadReceiptJournal, 'close', closing):
            gate._consume_upload_receipt_challenge(first)
        self.assertTrue(attacked)
        self.assertFalse(appended)
        gate._consume_upload_receipt_challenge(second)
        records = gate._parse_upload_receipt_journal(self.path.read_bytes())
        self.assertEqual(sum(x['kind'] == 'consumed-set' for x in records), 2)

    def test_post_write_fsync_failure_rolls_back_and_retry_succeeds(self):
        auth = self.auth()
        before = self.path.read_bytes()
        real_write, real_fsync = os.write, os.fsync
        written_fd = None
        failed = False
        def written(fd, payload):
            nonlocal written_fd
            result = real_write(fd, payload)
            if b'"kind":"consumed-set"' in payload:
                written_fd = fd
            return result
        def synced(fd):
            nonlocal failed
            if fd == written_fd and not failed:
                failed = True
                raise OSError('post-write fsync fault')
            return real_fsync(fd)
        with mock.patch.object(gate.os, 'write', written):
            with mock.patch.object(gate.os, 'fsync', synced):
                with self.assertRaisesRegex(OSError, 'post-write fsync fault'):
                    gate._consume_upload_receipt_challenge(auth)
        self.assertTrue(failed)
        self.assertEqual(self.path.read_bytes(), before)
        gate._consume_upload_receipt_challenge(auth)
        records = gate._parse_upload_receipt_journal(self.path.read_bytes())
        self.assertEqual(sum(x['kind'] == 'consumed-set' for x in records), 1)

    def tamper_before_lock(self, tamper):
        real_flock = gate.fcntl.flock
        def locked(fd, operation):
            if operation == fcntl.LOCK_EX:
                tamper()
            return real_flock(fd, operation)
        with mock.patch.object(gate.fcntl, 'flock', locked):
            with self.assertRaisesRegex(gate.AppleArtifactGateError, 'ancestor was replaced'):
                gate._with_upload_receipt_journal(None)

    def test_leaf_replacement_while_waiting_rejected(self):
        def tamper():
            self.path.rename(self.path.with_suffix('.old'))
            self.path.write_bytes(b'')
        self.tamper_before_lock(tamper)

    def test_ancestor_swap_restore_while_waiting_rejected(self):
        def tamper():
            parent = self.path.parent
            renamed = parent.with_name('renamed')
            parent.rename(renamed)
            renamed.rename(parent)
        self.tamper_before_lock(tamper)

    def test_leaf_mode_change_while_waiting_rejected(self):
        self.tamper_before_lock(lambda: self.path.chmod(0o644))

    def test_leaf_hardlink_while_waiting_rejected(self):
        self.tamper_before_lock(lambda: os.link(self.path, self.path.with_suffix('.link')))

    def test_content_mutation_after_lock_rejected(self):
        held = gate._HeldUploadReceiptJournal()
        try:
            self.path.write_bytes(b'corruption\n')
            with self.assertRaisesRegex(gate.AppleArtifactGateError, 'ancestor was replaced'):
                held.read_payload()
        finally:
            held.close(verify=False)

    def test_interrupted_lock_acquisition_closes_descriptors(self):
        real_open = gate.os.open
        descriptors = []
        def opened(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            descriptors.append(fd)
            return fd
        with mock.patch.object(gate.os, 'open', opened):
            with mock.patch.object(gate.fcntl, 'flock', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    gate._with_upload_receipt_journal(None)
        for fd in set(descriptors):
            try:
                os.fstat(fd)
            except OSError as exc:
                self.assertEqual(exc.errno, errno.EBADF)
            else:
                os.close(fd)
                self.fail('descriptor leaked on interrupted lock acquisition')

if __name__ == '__main__':
    unittest.main(verbosity=2)
