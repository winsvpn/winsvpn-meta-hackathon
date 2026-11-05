#!/usr/bin/env python3
"""Fail-closed tests for the Watch companion smoke receipt (R22 Y3 D2, part 2)."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import apple_watch_companion_smoke as smoke
import apple_watch_companion_smoke_testkit as kit


RELEASE = "1.0.17+34"
COMMIT = "a" * 40
CANDIDATE = "app_store/apple/artifacts/release_candidate.json"
RUNTIME = "app_store/apple/artifacts/runtime_evidence.json"
WATCH_SOURCES = ROOT / "ios" / "WinsWatch Watch App"
WATCH_APP_SWIFT = WATCH_SOURCES / "WinsWatchApp.swift"
PROJECT = ROOT / "ios" / "Runner.xcodeproj" / "project.pbxproj"
HOOK_TOKENS = ("WatchCompanionSmoke", "wins_watch_companion_smoke", "wins-watch-companion-smoke")


def _complete_candidate(commit: str = COMMIT) -> dict[str, object]:
    candidate = json.loads((ROOT / CANDIDATE).read_text(encoding="utf-8"))
    candidate["candidate_set_status"] = smoke.COMPLETE_LOCAL_CANDIDATES
    candidate["source_commit"] = commit
    return candidate


def _runtime(status: str = "pending", path: str = "", digest: str = "") -> dict[str, object]:
    runtime = json.loads((ROOT / RUNTIME).read_text(encoding="utf-8"))
    runtime["watch_companion_smoke"] = {
        "status": status,
        "receipt_path": path,
        "receipt_sha256": digest,
    }
    return runtime


class ReceiptVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-watch-smoke-")
        self.root = pathlib.Path(self.temp.name).resolve()
        self.document = kit.receipt_document(release=RELEASE, source_commit=COMMIT)
        self.path, self.digest = kit.write_receipt(self.root, self.document)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def verify(self, path: object = None, digest: object = None, **kwargs: str) -> dict[str, object]:
        return smoke.verify_receipt(
            self.root,
            self.path if path is None else path,
            self.digest if digest is None else digest,
            release=kwargs.get("release", RELEASE),
            source_commit=kwargs.get("source_commit", COMMIT),
        )

    def rewrite(self, document: dict[str, object]) -> None:
        self.path, self.digest = kit.write_receipt(self.root, document)

    def test_honest_receipt_passes(self) -> None:
        receipt = self.verify()
        self.assertEqual(receipt["verdict"], "PASS")
        self.assertEqual(receipt["source"]["git_commit"], COMMIT)

    def test_wrong_hash_is_refused(self) -> None:
        for digest, message in (
            ("0" * 64, "does not match the receipt bytes"),
            ("", "must be lowercase hex"),
            (self.digest.upper(), "must be lowercase hex"),
        ):
            with self.subTest(digest=digest):
                with self.assertRaisesRegex(smoke.WatchSmokeError, message):
                    self.verify(digest=digest)

    def test_missing_file_is_refused(self) -> None:
        missing = self.path.replace("20261018T000000Z", "20261018T000001Z")
        with self.assertRaisesRegex(smoke.WatchSmokeError, "does not exist"):
            self.verify(path=missing)

    def test_absolute_and_non_canonical_paths_are_refused(self) -> None:
        for path, message in (
            (str(self.root / self.path), "repository-relative"),
            ("/tmp/WATCH_COMPANION_SMOKE.json", "repository-relative"),
            (".artifacts/apple-watch-companion-smoke/../x/WATCH_COMPANION_SMOKE.json", "repository-relative"),
            ("", "repository-relative"),
            (".artifacts/other/20261018T000000Z/WATCH_COMPANION_SMOKE.json", "must be"),
            (".artifacts/apple-watch-companion-smoke/latest/WATCH_COMPANION_SMOKE.json", "must be"),
            (".artifacts/apple-watch-companion-smoke/20261018T000000Z/receipt.json", "must be"),
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(smoke.WatchSmokeError, message):
                    self.verify(path=path)

    def test_fail_verdict_is_refused(self) -> None:
        document = copy.deepcopy(self.document)
        document["verdict"] = "FAIL"
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "verdict is not PASS"):
            self.verify()

    def test_wrong_release_is_refused(self) -> None:
        with self.assertRaisesRegex(smoke.WatchSmokeError, "release"):
            self.verify(release="1.0.15+30")
        document = copy.deepcopy(self.document)
        document["release"] = "1.0.15+30"
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "release"):
            self.verify()
        document = copy.deepcopy(self.document)
        document["build_number"] = "32"
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "version and build"):
            self.verify()

    def test_source_commit_must_match_the_candidate_set(self) -> None:
        with self.assertRaisesRegex(smoke.WatchSmokeError, "source commit does not match"):
            self.verify(source_commit="b" * 40)
        for commit in ("", "a" * 39, "A" * 40):
            with self.subTest(commit=commit):
                with self.assertRaisesRegex(smoke.WatchSmokeError, "40-hex source commit"):
                    self.verify(source_commit=commit)

    def test_dirty_tree_receipt_is_refused(self) -> None:
        self.rewrite(kit.receipt_document(release=RELEASE, source_commit=COMMIT, tree_clean=False))
        with self.assertRaisesRegex(smoke.WatchSmokeError, "dirty tree"):
            self.verify()

    def test_simulator_statement_and_identities_are_required(self) -> None:
        cases = (
            (("statement",), "This is the App Store IPA.", "simulator build"),
            (("artifacts", "watch_app", "platform"), "watchos", "WinsWatch.app identity"),
            (("artifacts", "watch_app", "build_platforms"), ["WATCHOS"], "WinsWatch.app identity"),
            (("artifacts", "watch_app", "bundle_id"), "org.winsvpn.app.watchkitapp", "WinsWatch.app identity"),
            (("artifacts", "runner_app", "platform"), "iphoneos", "Runner.app identity"),
            (("contract",), "winsvpn-apple-watch-companion-smoke-v0", "contract is invalid"),
        )
        for keys, value, message in cases:
            with self.subTest(keys=keys):
                document = copy.deepcopy(self.document)
                target = document
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                self.rewrite(document)
                with self.assertRaisesRegex(smoke.WatchSmokeError, message):
                    self.verify()

    def test_producer_record_and_measured_build_are_required(self) -> None:
        # R24 V1 F1: observations alone re-derive the verdict. A document with no
        # record of the run (tool, host, simulator pair, cleanup), made by other
        # bytes than this producer, or whose measured apps are not the release
        # build or lack the debug hook, is not a producer receipt.
        def mutated(keys: tuple[str, ...], value: object = None, *, drop: bool = False) -> dict:
            document = copy.deepcopy(self.document)
            target = document
            for key in keys[:-1]:
                target = target[key]
            if drop:
                del target[keys[-1]]
            else:
                target[keys[-1]] = value
            return document

        cases = (
            (mutated(("tool",), drop=True), "tool must be an object"),
            (mutated(("tool", "sha256"), "0" * 64), "not made by this producer"),
            (mutated(("tool", "path"), "tools/other.py"), "not made by this producer"),
            (mutated(("host",), drop=True), "host must be an object"),
            (mutated(("host", "xcode"), ""), "host record"),
            (mutated(("simulators",), drop=True), "simulators must be an object"),
            (mutated(("simulators", "watch"), drop=True), "simulators watch must be an object"),
            (mutated(("simulators", "phone", "udid"), ""), "simulator record"),
            (mutated(("simulators", "pair"), ""), "simulator pair"),
            (mutated(("cleanup",), drop=True), "cleanup record"),
            (mutated(("cleanup",), []), "cleanup record"),
            (mutated(("cleanup",), [{"udid": "OTHER", "delete_exit": 0}] * 2), "cleanup record"),
            (mutated(("artifacts", "runner_app", "version"), "1.0.15"), "not the measured release build"),
            (mutated(("artifacts", "runner_app", "build"), "30"), "not the measured release build"),
            (mutated(("artifacts", "watch_app", "version"), "1.0"), "not the measured release build"),
            (mutated(("artifacts", "watch_app", "build"), "1"), "not the measured release build"),
            (mutated(("artifacts", "watch_app", "smoke_hook_present"), False), "not the measured release build"),
            (mutated(("artifacts", "watch_app", "smoke_hook_present"), drop=True), "not the measured release build"),
        )
        for document, message in cases:
            with self.subTest(message=message):
                self.rewrite(document)
                with self.assertRaisesRegex(smoke.WatchSmokeError, message):
                    self.verify()
        # A kept-simulators run (no delete) is a legitimate producer record.
        document = copy.deepcopy(self.document)
        document["cleanup"] = [{"udid": "FIXTURE-WATCH", "kept": True}, {"udid": "FIXTURE-PHONE", "kept": True}]
        self.rewrite(document)
        self.verify()

    def test_positive_verdict_is_re_derived_from_the_observation(self) -> None:
        document = copy.deepcopy(self.document)
        document["positive"]["observation"]["probe"]["reply_received"] = False
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "checks do not match"):
            self.verify()
        document["positive"]["checks"] = smoke.evaluate_observation(
            document["positive"]["observation"], kit.POSITIVE_NONCE
        )
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "does not prove the link"):
            self.verify()
        stale = copy.deepcopy(self.document)
        stale["positive"]["observation"]["nonce"] = "f" * 32
        stale["positive"]["checks"] = smoke.evaluate_observation(
            stale["positive"]["observation"], kit.POSITIVE_NONCE
        )
        self.rewrite(stale)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "does not prove the link"):
            self.verify()

    def test_every_negative_control_must_fail_on_the_link(self) -> None:
        # Not running: a reply from a phone app WatchConnectivity had to wake
        # (bridge default, status unknown) must fail; one from a running phone
        # app must not be accepted as a negative.
        document = copy.deepcopy(self.document)
        woken = document["negative_cases"][0]
        woken["observation"] = kit.observation(woken["nonce"], linked=True)
        woken["checks"] = smoke.evaluate_observation(woken["observation"], woken["nonce"])
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "did not fail on the link"):
            self.verify()
        # A not-running control that never ran on the Watch proves nothing.
        document = copy.deepcopy(self.document)
        silent = document["negative_cases"][1]
        silent["observation"] = {}
        silent["checks"] = smoke.evaluate_observation({}, silent["nonce"])
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "did not fail on the link"):
            self.verify()
        # Not installed: the Watch app must not have reported for the nonce,
        # and the removal or the failed launch must be recorded.
        document = copy.deepcopy(self.document)
        removed = document["negative_cases"][2]
        removed["observation"] = kit.observation(removed["nonce"], linked=False)
        removed["checks"] = smoke.evaluate_observation(removed["observation"], removed["nonce"])
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "did not fail on the link"):
            self.verify()
        document = copy.deepcopy(self.document)
        document["negative_cases"][2].update(
            watch_launch_exit=0, watch_app_installed_after_phone_uninstall=True
        )
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "did not fail on the link"):
            self.verify()
        for mutate, message in (
            (lambda d: d["negative_cases"].pop(), "not-running and not-installed controls"),
            (lambda d: d["negative_cases"].reverse(), "not-running and not-installed controls"),
            (lambda d: d.pop("negative_cases"), "not-running and not-installed controls"),
            (lambda d: d["negative_cases"][0].update(control_held=False), "did not fail on the link"),
            (lambda d: d["negative_cases"][1].update(observed_verdict="PASS"), "did not fail on the link"),
        ):
            with self.subTest(message=message):
                document = copy.deepcopy(self.document)
                mutate(document)
                self.rewrite(document)
                with self.assertRaisesRegex(smoke.WatchSmokeError, message):
                    self.verify()

    def test_only_launches_that_never_activated_may_be_retried(self) -> None:
        def attempt(nonce: str, *, activated: bool, linked: bool = False) -> dict[str, object]:
            observation = kit.observation(nonce, linked=linked)
            if not activated:
                observation.update(
                    activation_state="notActivated", activation_states_seen=["notActivated"]
                )
            return {
                "nonce": nonce,
                "observation": observation,
                "checks": smoke.evaluate_observation(observation, nonce),
            }

        document = copy.deepcopy(self.document)
        document["positive"]["activation_retries"] = [attempt("5" * 32, activated=False)]
        document["negative_cases"][0]["activation_retries"] = [
            attempt("6" * 32, activated=False),
            attempt("7" * 32, activated=False),
        ]
        self.rewrite(document)
        self.verify()
        for label, mutate, message in (
            ("activated", lambda d: d["positive"]["activation_retries"].append(attempt("8" * 32, activated=True)), "retried a launch that activated"),
            ("linked", lambda d: d["negative_cases"][1].update(activation_retries=[attempt("8" * 32, activated=True, linked=True)]), "retried a launch that activated"),
            ("too many", lambda d: d["negative_cases"][0]["activation_retries"].append(attempt("8" * 32, activated=False)), "retries are invalid"),
            ("reused nonce", lambda d: d["negative_cases"][1].update(activation_retries=[attempt("5" * 32, activated=False)]), "reuses one launch nonce"),
            ("tampered", lambda d: d["positive"]["activation_retries"][0]["checks"].update(activation_activated=True), "checks do not match"),
        ):
            with self.subTest(case=label):
                changed = copy.deepcopy(document)
                mutate(changed)
                self.rewrite(changed)
                with self.assertRaisesRegex(smoke.WatchSmokeError, message):
                    self.verify()

    def test_one_nonce_per_launch(self) -> None:
        document = copy.deepcopy(self.document)
        reused = document["negative_cases"][0]
        reused["nonce"] = kit.POSITIVE_NONCE
        reused["observation"] = kit.observation(kit.POSITIVE_NONCE, linked=False, woken=True)
        reused["checks"] = smoke.evaluate_observation(reused["observation"], kit.POSITIVE_NONCE)
        self.rewrite(document)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "reuses one launch nonce"):
            self.verify()

    def test_duplicate_keys_and_non_finite_numbers_are_refused(self) -> None:
        text = json.dumps(self.document, indent=2, sort_keys=True)
        duplicated = text.replace('"verdict": "PASS"', '"verdict": "FAIL", "verdict": "PASS"', 1)
        self.path, self.digest = kit.write_receipt(self.root, duplicated.encode("ascii"))
        with self.assertRaisesRegex(smoke.WatchSmokeError, "duplicate JSON key"):
            self.verify()
        non_finite = text.replace('"elapsed_ms": 5000.0', '"elapsed_ms": NaN', 1)
        self.path, self.digest = kit.write_receipt(self.root, non_finite.encode("ascii"))
        with self.assertRaisesRegex(smoke.WatchSmokeError, "non-finite"):
            self.verify()

    def test_symlinks_hard_links_and_open_modes_are_refused(self) -> None:
        receipt = self.root / self.path
        stamp = receipt.parent
        os.chmod(receipt, 0o644)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "mode 0600"):
            self.verify()
        os.chmod(receipt, 0o600)
        os.chmod(stamp, 0o755)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "owner-only"):
            self.verify()
        os.chmod(stamp, 0o700)
        link = self.root / "hard-link.json"
        os.link(receipt, link)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "hard-linked"):
            self.verify()
        link.unlink()
        moved = stamp.with_name("20261018T000009Z")
        stamp.rename(moved)
        stamp.symlink_to(moved.name)
        with self.assertRaisesRegex(smoke.WatchSmokeError, "symbolic link"):
            self.verify()
        stamp.unlink()
        moved.rename(stamp)
        self.verify()

    def test_a_short_os_write_does_not_leave_a_truncated_receipt(self) -> None:
        # R24 V1 F6: write_receipt returns the digest of the payload, so the
        # writer must put every byte on disk even when os.write accepts few.
        real_write = os.write
        calls = []

        def short_write(descriptor: int, data: object) -> int:
            calls.append(len(data))
            return real_write(descriptor, bytes(data)[:7])

        payload = b"x" * 100
        target = self.root / "short-write.bin"
        with mock.patch.object(smoke.os, "write", side_effect=short_write):
            smoke._write_private_file(target, payload)
        self.assertEqual(target.read_bytes(), payload)
        self.assertGreater(len(calls), 1)


class RuntimeBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-watch-smoke-runtime-")
        self.root = pathlib.Path(self.temp.name).resolve()
        self.path, self.digest = kit.write_receipt(
            self.root, kit.receipt_document(release=RELEASE, source_commit=COMMIT)
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def check(self, runtime: dict[str, object], candidate: dict[str, object], **kwargs: bool) -> str:
        return smoke.runtime_watch_smoke_sha256(
            self.root, runtime, candidate, release=RELEASE, **kwargs
        )

    def test_committed_state_is_pending_and_unbound(self) -> None:
        runtime = json.loads((ROOT / RUNTIME).read_text(encoding="utf-8"))
        candidate = json.loads((ROOT / CANDIDATE).read_text(encoding="utf-8"))
        self.assertEqual(
            runtime["watch_companion_smoke"],
            {"status": "pending", "receipt_path": "", "receipt_sha256": ""},
        )
        self.assertEqual(candidate["candidate_set_status"], "no_current_candidate")
        self.assertEqual(smoke.runtime_watch_smoke_sha256(ROOT, runtime, candidate, release=RELEASE), "")
        with self.assertRaisesRegex(smoke.WatchSmokeError, "requires a passed"):
            smoke.runtime_watch_smoke_sha256(
                ROOT, runtime, candidate, release=RELEASE, require_passed=True
            )

    def test_passed_receipt_binds_its_digest(self) -> None:
        runtime = _runtime("passed", self.path, self.digest)
        self.assertEqual(self.check(runtime, _complete_candidate()), self.digest)
        self.assertEqual(
            self.check(runtime, _complete_candidate(), require_passed=True), self.digest
        )

    def test_invalid_bindings_are_refused(self) -> None:
        cases = (
            ("pending with a path", _runtime("pending", self.path, ""), _complete_candidate(), "must not bind"),
            ("pending with a digest", _runtime("pending", "", self.digest), _complete_candidate(), "must not bind"),
            ("claim without receipt", _runtime("passed", "", self.digest), _complete_candidate(), "repository-relative"),
            ("unknown status", _runtime("current", self.path, self.digest), _complete_candidate(), "pending or passed"),
            ("wrong digest", _runtime("passed", self.path, "7" * 64), _complete_candidate(), "does not match"),
            ("no candidate", _runtime("passed", self.path, self.digest), json.loads((ROOT / CANDIDATE).read_text()), "complete release candidate"),
            ("candidate without commit", _runtime("passed", self.path, self.digest), _complete_candidate(""), "40-hex"),
            ("other commit", _runtime("passed", self.path, self.digest), _complete_candidate("b" * 40), "source commit"),
        )
        for label, runtime, candidate, message in cases:
            with self.subTest(case=label):
                with self.assertRaisesRegex(smoke.WatchSmokeError, message):
                    self.check(runtime, candidate)
        bare = _runtime()
        bare["watch_companion_smoke_sha256"] = self.digest
        with self.assertRaisesRegex(smoke.WatchSmokeError, "bare digest"):
            self.check(bare, _complete_candidate())
        extra = _runtime("passed", self.path, self.digest)
        extra["watch_companion_smoke"]["verdict"] = "PASS"
        with self.assertRaisesRegex(smoke.WatchSmokeError, "schema is invalid"):
            self.check(extra, _complete_candidate())
        candidate = _complete_candidate()
        candidate["build_number"] = "32"
        with self.assertRaisesRegex(smoke.WatchSmokeError, "expected release"):
            self.check(_runtime("passed", self.path, self.digest), candidate)


class RecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-watch-smoke-record-")
        self.root = pathlib.Path(self.temp.name).resolve()
        for relative in (CANDIDATE, RUNTIME, "pubspec.yaml"):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        self.path, self.digest = kit.write_receipt(
            self.root, kit.receipt_document(release=RELEASE, source_commit=COMMIT)
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, record: dict[str, object]) -> None:
        (self.root / relative).write_text(json.dumps(record, indent=2) + "\n", encoding="ascii")

    def test_committed_pending_state_refuses_recording_and_stays_unchanged(self) -> None:
        before = (self.root / RUNTIME).read_bytes()
        with self.assertRaisesRegex(smoke.WatchSmokeError, "not a complete candidate set"):
            smoke.record(self.root, self.path)
        self.assertEqual((self.root / RUNTIME).read_bytes(), before)
        self.assertEqual(before, (ROOT / RUNTIME).read_bytes())

    def test_runtime_evidence_must_have_left_the_not_started_state(self) -> None:
        self.write(CANDIDATE, _complete_candidate())
        before = (self.root / RUNTIME).read_bytes()
        with self.assertRaisesRegex(smoke.WatchSmokeError, "not-started"):
            smoke.record(self.root, self.path)
        self.assertEqual((self.root / RUNTIME).read_bytes(), before)

    def test_partial_runtime_state_records_a_verified_receipt(self) -> None:
        self.write(CANDIDATE, _complete_candidate())
        runtime = json.loads((self.root / RUNTIME).read_text(encoding="utf-8"))
        runtime["candidate_set_status"] = "partial_pending_universal_macos_rebuild"
        self.write(RUNTIME, runtime)
        self.assertEqual(smoke.record(self.root, self.path), self.digest)
        recorded = json.loads((self.root / RUNTIME).read_text(encoding="utf-8"))
        self.assertEqual(recorded["watch_companion_smoke"]["status"], "passed")

    def test_complete_state_records_a_verified_receipt(self) -> None:
        self.write(CANDIDATE, _complete_candidate())
        runtime = json.loads((self.root / RUNTIME).read_text(encoding="utf-8"))
        runtime["candidate_set_status"] = smoke.RUNTIME_COMPLETE_STATUS
        self.write(RUNTIME, runtime)
        self.assertEqual(smoke.record(self.root, self.path), self.digest)
        recorded = json.loads((self.root / RUNTIME).read_text(encoding="utf-8"))
        self.assertEqual(
            recorded["watch_companion_smoke"],
            {"status": "passed", "receipt_path": self.path, "receipt_sha256": self.digest},
        )
        self.assertEqual(list(recorded), list(runtime))
        for key in runtime:
            if key != "watch_companion_smoke":
                self.assertEqual(recorded[key], runtime[key])
        self.assertEqual(
            smoke.runtime_watch_smoke_sha256(
                self.root, recorded, _complete_candidate(), release=RELEASE, require_passed=True
            ),
            self.digest,
        )

    def test_unverifiable_receipts_are_never_recorded(self) -> None:
        self.write(CANDIDATE, _complete_candidate("b" * 40))
        runtime = json.loads((self.root / RUNTIME).read_text(encoding="utf-8"))
        runtime["candidate_set_status"] = smoke.RUNTIME_COMPLETE_STATUS
        self.write(RUNTIME, runtime)
        before = (self.root / RUNTIME).read_bytes()
        with self.assertRaisesRegex(smoke.WatchSmokeError, "source commit"):
            smoke.record(self.root, self.path)
        self.write(CANDIDATE, _complete_candidate())
        failed = kit.receipt_document(release=RELEASE, source_commit=COMMIT)
        failed["verdict"] = "FAIL"
        path, _ = kit.write_receipt(self.root, failed, stamp="20261018T000002Z")
        with self.assertRaisesRegex(smoke.WatchSmokeError, "not PASS"):
            smoke.record(self.root, path)
        self.assertEqual((self.root / RUNTIME).read_bytes(), before)


class ObservationTests(unittest.TestCase):
    def test_linked_observation_passes_and_unlinked_fails_on_the_link(self) -> None:
        linked = smoke.evaluate_observation(kit.observation(kit.POSITIVE_NONCE, linked=True), kit.POSITIVE_NONCE)
        self.assertEqual(tuple(linked), smoke.OBSERVATION_CHECKS)
        self.assertEqual(smoke.observation_verdict(linked), "PASS")
        unlinked = smoke.evaluate_observation(kit.observation(kit.NEGATIVE_NONCE, linked=False), kit.NEGATIVE_NONCE)
        self.assertEqual(smoke.observation_verdict(unlinked), "FAIL")
        self.assertTrue(smoke.negative_control_held(unlinked))
        self.assertFalse(smoke.negative_control_held(linked))

    def test_a_woken_phone_app_reply_is_not_a_pass(self) -> None:
        # Measured on the simulators: WatchConnectivity wakes a phone app that
        # is installed but not running, and its bridge answers "unknown"
        # before Dart has published. That is a link, but not a running app.
        woken = smoke.evaluate_observation(
            kit.observation(kit.NEGATIVE_NONCE, linked=False, woken=True), kit.NEGATIVE_NONCE
        )
        self.assertTrue(woken["reply_received"])
        self.assertFalse(woken["reply_from_running_app"])
        self.assertEqual(smoke.observation_verdict(woken), "FAIL")
        self.assertTrue(smoke.negative_control_held(woken))
        self.assertNotIn("unknown", smoke.PHONE_PUBLISHED_STATUSES)
        dart = (ROOT / "lib" / "watch_bridge.dart").read_text(encoding="utf-8")
        published = set(re.findall(r"^\s+(\w+)\('(\w+)'\)[,;]", dart, re.MULTILINE))
        self.assertEqual(
            {wire for _name, wire in published} - {"unknown"}, set(smoke.PHONE_PUBLISHED_STATUSES)
        )
        bridge = (ROOT / "ios" / "Runner" / "WatchSessionBridge.swift").read_text(encoding="utf-8")
        self.assertIn('"status": "unknown",', bridge)

    def test_phone_link_end_state_is_recorded_not_judged(self) -> None:
        # Final run 2: PhoneLink's own 4 s timeout left the link
        # "unreachable" although it had applied the reply's phone state.
        observation = kit.observation(kit.POSITIVE_NONCE, linked=True)
        observation["phone_link"]["link"] = "unreachable"
        checks = smoke.evaluate_observation(observation, kit.POSITIVE_NONCE)
        self.assertTrue(checks["phone_link_current"])
        self.assertEqual(smoke.observation_verdict(checks), "PASS")
        observation["phone_link"]["snapshot_updated_at_ms"] = 1792281599999.0
        checks = smoke.evaluate_observation(observation, kit.POSITIVE_NONCE)
        self.assertFalse(checks["phone_link_current"])

    def test_each_link_check_alone_fails_the_verdict(self) -> None:
        mutations = {
            "reply_from_running_app": lambda o: o["probe"]["reply"].update(status="unknown"),
            "reply_received": lambda o: o["probe"].update(reply_received=False),
            "reply_protocol_version": lambda o: o["probe"]["reply"].update(protocol_version=2),
            "reply_timestamped": lambda o: o["probe"]["reply"].update(updated_at_ms=0),
            "phone_link_current": lambda o: o["phone_link"].update(snapshot_updated_at_ms=1.0),
            "companion_app_installed": lambda o: o.update(is_companion_app_installed=False),
            "reachable": lambda o: o.update(reachable_ever=False),
            "activation_activated": lambda o: o.update(activation_state="inactive"),
            "complete": lambda o: o.update(complete=False),
            "watch_bundle_id": lambda o: o.update(watch_bundle_id="org.winsvpn.app.watchkitapp"),
        }
        for name, mutate in mutations.items():
            with self.subTest(check=name):
                observation = kit.observation(kit.POSITIVE_NONCE, linked=True)
                mutate(observation)
                checks = smoke.evaluate_observation(observation, kit.POSITIVE_NONCE)
                self.assertFalse(checks[name])
                self.assertEqual(smoke.observation_verdict(checks), "FAIL")
        checks = smoke.evaluate_observation(
            kit.observation(kit.POSITIVE_NONCE, linked=True), kit.NEGATIVE_NONCE
        )
        self.assertFalse(checks["nonce"])
        self.assertEqual(smoke.evaluate_observation({}, kit.POSITIVE_NONCE)["contract"], False)
        self.assertEqual(smoke.observation_verdict({}), "FAIL")


class SimulatorEngineInputTests(unittest.TestCase):
    def test_every_simulator_engine_input_is_pinned_by_committed_provenance(self) -> None:
        inputs = smoke.simulator_engine_inputs(ROOT)
        self.assertEqual(len(inputs), 13)
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/apple/EngineArtifacts/**", ignore)
        self.assertIn("/tools/winn_conformance_build_out/", ignore)
        for item in inputs:
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(
                item["path"].startswith("apple/EngineArtifacts/ios/iphonesimulator/")
                or item["path"].startswith("tools/winn_conformance_build_out/libwinn-datapath-"),
                item["path"],
            )

    def test_staging_refuses_bytes_that_do_not_match_the_pin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-watch-smoke-engines-") as temporary:
            base = pathlib.Path(temporary)
            root = base / "repo"
            source = base / "source"
            for relative in (
                "apple/EngineArtifacts/apple_awg_31_engine_provenance.json",
                "apple/EngineArtifacts/apple_xray_vless_ws_engine_provenance.json",
                "apple/EngineArtifacts/apple_winn_v3_engine_provenance.json",
            ):
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, root / relative)
            first = smoke.simulator_engine_inputs(root)[0]
            (source / first["path"]).parent.mkdir(parents=True)
            (source / first["path"]).write_bytes(b"not the pinned engine")
            transcript = base / "log"
            runner = smoke.Runner(transcript)
            with mock.patch("sys.stdout"):
                with self.assertRaisesRegex(smoke.WatchSmokeError, "does not match its provenance pin"):
                    smoke.stage_simulator_engines(root, source, runner)
                self.assertFalse((root / first["path"]).exists())
                with self.assertRaisesRegex(smoke.WatchSmokeError, "is missing"):
                    smoke.stage_simulator_engines(root, None, runner)
                (root / first["path"]).parent.mkdir(parents=True)
                (root / first["path"]).write_bytes(b"stale engine already present")
                with self.assertRaisesRegex(smoke.WatchSmokeError, "committed provenance pin"):
                    smoke.stage_simulator_engines(root, source, runner)


def _debug_regions(source: str) -> list[tuple[int, int]]:
    """Line ranges of every top-level ``#if DEBUG`` ... ``#endif`` block."""

    regions: list[tuple[int, int]] = []
    stack: list[tuple[str, int]] = []
    for number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#if "):
            stack.append((stripped, number))
        elif stripped.startswith("#elseif") or stripped == "#else":
            if stack and stack[-1][0] == "#if DEBUG":
                raise AssertionError("a DEBUG block must not have an #else branch")
        elif stripped == "#endif":
            condition, start = stack.pop()
            if condition == "#if DEBUG" and not any(c == "#if DEBUG" for c, _ in stack):
                regions.append((start, number))
    if stack:
        raise AssertionError("unbalanced #if in Watch source")
    return regions


class DebugHookReleaseTests(unittest.TestCase):
    def test_hook_source_lives_only_inside_debug_blocks(self) -> None:
        for path in sorted(WATCH_SOURCES.glob("*.swift")):
            source = path.read_text(encoding="utf-8")
            regions = _debug_regions(source)
            for number, line in enumerate(source.splitlines(), start=1):
                if any(token in line for token in HOOK_TOKENS):
                    with self.subTest(path=path.name, line=number):
                        self.assertTrue(
                            any(start < number < end for start, end in regions),
                            f"{path.name}:{number} is outside #if DEBUG",
                        )
        source = WATCH_APP_SWIFT.read_text(encoding="utf-8")
        self.assertIn("enum WatchCompanionSmoke {", source)
        self.assertIn(f'static let argument = "{smoke.WATCH_SMOKE_ARGUMENT}"', source)
        self.assertIn(
            f'static let contract = "{smoke.OBSERVATION_CONTRACT}"', source
        )
        self.assertIn(
            f'static let fileName = "{pathlib.PurePosixPath(smoke.WATCH_OBSERVATION_RELATIVE).name}"',
            source,
        )
        self.assertIn(smoke.WATCH_SMOKE_BINARY_MARKER.decode("ascii"), source)

    def test_only_the_watch_debug_configuration_defines_debug(self) -> None:
        project = PROJECT.read_text(encoding="utf-8")
        # One XCBuildConfiguration object at a time, so a setting from another
        # target can never satisfy or mask a Watch assertion.
        configs = re.findall(
            r"\n\t\t([0-9A-F]{24}) /\* (\w+) \*/ = \{\n\t\t\tisa = XCBuildConfiguration;\n(.*?)\n\t\t\};",
            project,
            re.DOTALL,
        )
        watch = {
            name: body
            for _identifier, name, body in configs
            if 'INFOPLIST_FILE = "WinsWatch Watch App/Info.plist";' in body
        }
        self.assertEqual(sorted(watch), ["Debug", "Profile", "Release"])
        self.assertIn("PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.debug.watchkitapp;", watch["Debug"])
        self.assertIn("SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;", watch["Debug"])
        for name in ("Release", "Profile"):
            self.assertIn("PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.watchkitapp;", watch[name])
            self.assertNotIn("SWIFT_ACTIVE_COMPILATION_CONDITIONS", watch[name])
            self.assertNotIn("OTHER_SWIFT_FLAGS", watch[name])
        # The project-level Release and Profile configurations the Watch
        # target inherits from must not define DEBUG either.
        project_level = [
            body
            for _identifier, name, body in configs
            if name in {"Release", "Profile"} and "INFOPLIST_FILE" not in body and "SDKROOT = iphoneos;" in body
        ]
        self.assertTrue(project_level)
        for body in project_level:
            self.assertNotIn("SWIFT_ACTIVE_COMPILATION_CONDITIONS", body)
        for xcconfig in ("Release.xcconfig", "Profile.xcconfig", "Winn3DescriptorRing.xcconfig"):
            text = (ROOT / "ios" / "Flutter" / xcconfig).read_text(encoding="utf-8")
            self.assertNotIn("SWIFT_ACTIVE_COMPILATION_CONDITIONS", text)
            self.assertNotIn("OTHER_SWIFT_FLAGS", text)

    def test_release_compilation_drops_the_hook_and_debug_keeps_it(self) -> None:
        # Compile the exact Watch sources for the watch simulator the way the
        # Release configuration does (no DEBUG) and the way Debug does. The
        # release object must carry neither the marker nor the hook type; the
        # debug object is the negative control proving the scan can see them.
        sources = [str(path) for path in sorted(WATCH_SOURCES.glob("*.swift"))]
        with tempfile.TemporaryDirectory(prefix="wins-watch-hook-") as temporary:
            objects: dict[str, bytes] = {}
            for label, flags in (("release", ["-O"]), ("debug", ["-Onone", "-D", "DEBUG"])):
                output = pathlib.Path(temporary) / f"{label}.o"
                completed = subprocess.run(
                    [
                        "/usr/bin/xcrun",
                        "-sdk",
                        "watchsimulator",
                        "swiftc",
                        "-swift-version",
                        "5",
                        "-target",
                        "arm64-apple-watchos9.0-simulator",
                        "-module-name",
                        "WinsWatch",
                        "-parse-as-library",
                        "-wmo",
                        "-c",
                        *flags,
                        *sources,
                        "-o",
                        str(output),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=600,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
                objects[label] = output.read_bytes()
        for token in (smoke.WATCH_SMOKE_BINARY_MARKER, b"WatchCompanionSmoke", b"--wins-watch-companion-smoke"):
            with self.subTest(token=token):
                self.assertNotIn(token, objects["release"])
                self.assertIn(token, objects["debug"])


class FreezeSourceCommitTests(unittest.TestCase):
    def setUp(self) -> None:
        import freeze_apple_release_candidates as freeze

        self.freeze = freeze

    def test_freeze_records_the_source_commit(self) -> None:
        text = (TOOLS / "freeze_apple_release_candidates.py").read_text(encoding="utf-8")
        self.assertIn('"source_commit": commit,', text)
        self.assertIn("commit = source_commit()", text)

    def test_source_commit_fails_closed(self) -> None:
        def result(code: int, out: str) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(["git"], code, out, "")

        with mock.patch.object(self.freeze.subprocess, "run", return_value=result(0, COMMIT + "\n")):
            self.assertEqual(self.freeze.source_commit(), COMMIT)
        for label, effect in (
            ("non-zero", result(128, "")),
            ("malformed", result(0, "HEAD\n")),
            ("short", result(0, "abc123\n")),
        ):
            with self.subTest(case=label):
                with mock.patch.object(self.freeze.subprocess, "run", return_value=effect):
                    with self.assertRaises(self.freeze.FreezeError):
                        self.freeze.source_commit()
        for exc in (OSError("no git"), subprocess.TimeoutExpired(["git"], 60)):
            with self.subTest(case=type(exc).__name__):
                with mock.patch.object(self.freeze.subprocess, "run", side_effect=exc):
                    with self.assertRaises(self.freeze.FreezeError):
                        self.freeze.source_commit()


if __name__ == "__main__":
    unittest.main()
