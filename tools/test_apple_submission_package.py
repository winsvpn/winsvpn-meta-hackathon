#!/usr/bin/env python3
"""Frozen Apple en-US marketing copy must match the current three metadata files."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import apple_watch_companion_smoke_testkit as watch_kit
import validate_apple_submission_package as submission


FROZEN_FILES = (
    "description.txt",
    "promotional_text.txt",
    "release_notes.txt",
)
STALE_MARKETING_COPY_SHA256 = {
    "description.txt": "0d908f927bb1459410b8880526090a1a1ee252fe2f7c2c1095ecc7c0f48e7a1c",
    "promotional_text.txt": "0f9d9556e03ddd6ab5b5a722378c5e98bf03d9b9e04232b95a2b96d2a0d10e24",
    "release_notes.txt": "f80070ecfdd20bc70c9ed491495dfeec0e2299c8e25ce655a3fe098aa96a97c0",
}
STALE_MARKETING_COPY_LENGTH = {
    "description.txt": 1573,
    "promotional_text.txt": 71,
    "release_notes.txt": 316,
}
APPLE_TEXT_LIMITS = {
    "promotional_text.txt": 170,
    "description.txt": 4000,
    "release_notes.txt": 4000,
}


class AppleSubmissionWatchSmokeTests(unittest.TestCase):
    def test_runtime_evidence_reverifies_the_watch_smoke_receipt(self) -> None:
        # R22 Y3 D2: outside the not-started state the runtime validator
        # re-hashes a passed smoke receipt and requires one when complete.
        candidate_relative = "app_store/apple/artifacts/release_candidate.json"
        runtime_relative = "app_store/apple/artifacts/runtime_evidence.json"
        commit = "e" * 40
        with tempfile.TemporaryDirectory(prefix="wins-submission-watch-smoke-") as temporary:
            root = Path(temporary).resolve()
            for relative in ("pubspec.yaml", candidate_relative, runtime_relative):
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, root / relative)
            candidate = json.loads((root / candidate_relative).read_text(encoding="utf-8"))
            candidate["candidate_set_status"] = "complete_local_candidates"
            candidate["source_commit"] = commit
            (root / candidate_relative).write_text(json.dumps(candidate, indent=2) + "\n", encoding="ascii")
            path, digest = watch_kit.write_receipt(
                root, watch_kit.receipt_document(release="1.0.17+34", source_commit=commit)
            )
            runtime = json.loads((root / runtime_relative).read_text(encoding="utf-8"))

            def run(status: str, smoke: dict[str, str]) -> None:
                changed = dict(runtime, candidate_set_status=status, watch_companion_smoke=smoke)
                (root / runtime_relative).write_text(json.dumps(changed, indent=2) + "\n", encoding="ascii")
                submission.validate_runtime_evidence_manifest()

            passed = {"status": "passed", "receipt_path": path, "receipt_sha256": digest}
            pending = {"status": "pending", "receipt_path": "", "receipt_sha256": ""}
            with mock.patch.multiple(
                submission,
                ROOT=root,
                ARTIFACT_MANIFEST=root / candidate_relative,
                RUNTIME_EVIDENCE_MANIFEST=root / runtime_relative,
            ):
                # An honest receipt passes the smoke check; the validator then
                # stops at the live-tunnel log this fixture does not supply.
                for status, smoke in (
                    ("complete_current_candidates", passed),
                    ("partial_pending_universal_macos_rebuild", passed),
                    ("partial_pending_universal_macos_rebuild", pending),
                ):
                    with self.subTest(status=status, smoke=smoke["status"]):
                        with self.assertRaisesRegex(AssertionError, "runtime_log must be a /tmp/wins_"):
                            run(status, smoke)
                for smoke, message in (
                    (pending, "requires a passed watch companion smoke"),
                    ({**passed, "receipt_sha256": "7" * 64}, "does not match the receipt bytes"),
                    ({**passed, "receipt_path": "/opt/release/" + path}, "repository-relative"),
                    ({**passed, "status": "current"}, "pending or passed"),
                ):
                    with self.subTest(message=message):
                        with self.assertRaisesRegex(AssertionError, message):
                            run("complete_current_candidates", smoke)
                with self.assertRaisesRegex(AssertionError, "must stay unbound"):
                    run("pending_current_runtime_evidence", passed)


class AppleSubmissionVerificationMarkerTests(unittest.TestCase):
    def test_bundle_markers_match_what_the_producer_prints(self) -> None:
        # Rehearsal r48: the freeze refused a real iOS verification log because
        # the marker predated the " plus watch companion" summary the smoke
        # prints for the iOS layout.
        smoke = (TOOLS / "apple_runtime_smoke.sh").read_text(encoding="utf-8")
        self.assertIn(
            'watch_summary = " plus watch companion" if bundle_layout == "ios" else ""',
            smoke,
        )
        self.assertIn(
            'host app and embedded PacketTunnel{watch_summary} verified (', smoke
        )
        markers = submission.VERIFICATION_LOG_MARKERS
        ios = markers[("ios", "app_store_local", "ipa")]
        macos = markers[("macos", "app_store_local", "pkg")]
        self.assertIn(
            "Exported existing iOS App Store local app: host app and embedded "
            "PacketTunnel plus watch companion verified",
            ios,
        )
        self.assertNotIn(
            "Exported existing iOS App Store local app: host app and embedded "
            "PacketTunnel verified",
            ios,
        )
        self.assertIn(
            "Exported existing macOS App Store local app: host app and embedded "
            "PacketTunnel verified",
            macos,
        )


class AppleSubmissionFrozenMarketingCopyTests(unittest.TestCase):
    def test_scoped_files_are_ascii(self) -> None:
        for relative in (
            "tools/validate_apple_submission_package.py",
            "tools/test_apple_submission_package.py",
        ):
            with self.subTest(path=relative):
                (ROOT / relative).read_text(encoding="ascii")

    def test_frozen_maps_cover_exactly_the_three_en_us_files(self) -> None:
        self.assertEqual(submission.FROZEN_MARKETING_COPY_FILES, FROZEN_FILES)
        self.assertEqual(set(submission.FROZEN_MARKETING_COPY_SHA256), set(FROZEN_FILES))
        self.assertEqual(set(submission.FROZEN_MARKETING_COPY_LENGTH), set(FROZEN_FILES))
        self.assertEqual(len(submission.FROZEN_MARKETING_COPY_SHA256), 3)
        self.assertEqual(len(submission.FROZEN_MARKETING_COPY_LENGTH), 3)

    def test_apple_text_limits_are_not_relaxed(self) -> None:
        for filename, limit in APPLE_TEXT_LIMITS.items():
            with self.subTest(filename=filename):
                self.assertEqual(submission.TEXT_LIMITS[filename], limit)
                self.assertLessEqual(
                    submission.FROZEN_MARKETING_COPY_LENGTH[filename],
                    limit,
                )
                self.assertGreater(
                    submission.FROZEN_MARKETING_COPY_LENGTH[filename],
                    STALE_MARKETING_COPY_LENGTH[filename],
                )

    def test_frozen_hashes_and_lengths_match_current_files(self) -> None:
        messages = submission.validate_frozen_marketing_copy()
        self.assertEqual(len(messages), 3)
        for filename in FROZEN_FILES:
            path = submission.METADATA / filename
            payload = path.read_bytes()
            payload.decode("ascii")
            actual_hash = submission.sha256_file(path)
            actual_length = len(path.read_text(encoding="ascii").strip())
            self.assertEqual(
                actual_hash,
                submission.FROZEN_MARKETING_COPY_SHA256[filename],
                filename,
            )
            self.assertEqual(
                actual_length,
                submission.FROZEN_MARKETING_COPY_LENGTH[filename],
                filename,
            )
            self.assertNotEqual(actual_hash, STALE_MARKETING_COPY_SHA256[filename], filename)
            self.assertNotEqual(
                actual_length,
                STALE_MARKETING_COPY_LENGTH[filename],
                filename,
            )
            self.assertTrue(
                any(
                    message.startswith(f"PASS: {filename} preserved exactly ({actual_hash},")
                    for message in messages
                ),
                messages,
            )

    def test_stale_copy_bytes_fail_current_pins(self) -> None:
        original = {
            name: (submission.METADATA / name).read_bytes() for name in FROZEN_FILES
        }
        with tempfile.TemporaryDirectory(prefix="wins-apple-stale-copy-") as tmp_dir:
            meta = Path(tmp_dir)
            stale_name = "promotional_text.txt"
            for name, payload in original.items():
                if name == stale_name:
                    payload = payload.replace(b"Winn v3", b"Winn v0", 1)
                    self.assertNotEqual(
                        hashlib.sha256(payload).hexdigest(),
                        submission.FROZEN_MARKETING_COPY_SHA256[name],
                    )
                (meta / name).write_bytes(payload)
            with mock.patch.object(submission, "METADATA", meta):
                with self.assertRaisesRegex(
                    AssertionError,
                    r"promotional_text\.txt changed but must be preserved exactly; "
                    r"sha256 is [0-9a-f]{64}, expected "
                    + submission.FROZEN_MARKETING_COPY_SHA256[stale_name],
                ):
                    submission.validate_frozen_marketing_copy()

    def test_stale_committed_pins_reject_current_copy(self) -> None:
        with mock.patch.object(
            submission,
            "FROZEN_MARKETING_COPY_SHA256",
            STALE_MARKETING_COPY_SHA256,
        ), mock.patch.object(
            submission,
            "FROZEN_MARKETING_COPY_LENGTH",
            STALE_MARKETING_COPY_LENGTH,
        ):
            with self.assertRaisesRegex(AssertionError, "must be preserved exactly"):
                submission.validate_frozen_marketing_copy()

    def test_stale_length_pin_fails_when_hash_still_matches(self) -> None:
        stale_lengths = dict(submission.FROZEN_MARKETING_COPY_LENGTH)
        stale_lengths["release_notes.txt"] = STALE_MARKETING_COPY_LENGTH["release_notes.txt"]
        with mock.patch.object(submission, "FROZEN_MARKETING_COPY_LENGTH", stale_lengths):
            with self.assertRaisesRegex(
                AssertionError,
                r"release_notes\.txt changed but must be preserved exactly; "
                r"length is 750, expected 316",
            ):
                submission.validate_frozen_marketing_copy()

    def test_dropping_a_frozen_file_fails_closed(self) -> None:
        incomplete = dict(submission.FROZEN_MARKETING_COPY_SHA256)
        incomplete.pop("release_notes.txt")
        with mock.patch.object(submission, "FROZEN_MARKETING_COPY_SHA256", incomplete):
            with self.assertRaisesRegex(
                AssertionError,
                "frozen marketing copy hash map must pin description.txt, "
                "promotional_text.txt, and release_notes.txt",
            ):
                submission.validate_frozen_marketing_copy()

    def test_selftest_rejects_stale_copy(self) -> None:
        self.assertEqual(
            submission.selftest_frozen_marketing_copy(),
            "PASS: frozen marketing copy self-test rejects stale copy",
        )
        self.assertEqual(submission.METADATA, ROOT / "app_store" / "apple" / "metadata" / "en-US")



class AppleSubmissionOwnerPacketRowTests(unittest.TestCase):
    def test_a_hash_moved_to_another_row_fails_the_cross_reference(self) -> None:
        # R24 X-02: each metadata path and its hash only had to appear somewhere in
        # the packet, so two hashes swapped between rows still passed.
        packet = (ROOT / "app_store/apple/review/owner_review_packet.md").read_text(
            encoding="utf-8"
        )
        required = submission.owner_review_packet_required_values()
        submission.assert_owner_review_packet_has_values(packet, required)
        first, second = submission.OWNER_PACKET_METADATA_HASH_FILES[:2]
        first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
        second_hash = hashlib.sha256(second.read_bytes()).hexdigest()
        self.assertNotEqual(first_hash, second_hash)
        swapped = packet.replace(first_hash, "@@").replace(second_hash, first_hash).replace(
            "@@", second_hash
        )
        self.assertNotEqual(swapped, packet)
        with self.assertRaisesRegex(AssertionError, "missing current release cross-reference"):
            submission.assert_owner_review_packet_has_values(swapped, required)


if __name__ == "__main__":
    unittest.main()
