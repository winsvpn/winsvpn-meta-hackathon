#!/usr/bin/env python3
"""Fail-closed tests for the Apple owner-authorization schema."""

from __future__ import annotations

import json
import plistlib
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import apple_final_evidence_collector as collector
import apple_watch_companion_smoke_testkit as watch_kit
import validate_apple_owner_signoff as owner_signoff


PRIVACY = "app_store/apple/review/privacy_label_manifest.json"
CANDIDATE = "app_store/apple/artifacts/release_candidate.json"
RUNTIME = "app_store/apple/artifacts/runtime_evidence.json"
SIGNOFF = "app_store/apple/review/owner_signoff.json"
IOS_NOTES = "app_store/apple/review/ios_review_notes.txt"
PRIVACY_ANSWERS = "app_store/apple/review/privacy_answers.md"


def _read(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return value


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def _complete_evidence(snapshot: str) -> dict[str, object]:
    digest = "a" * 64
    return collector.canonical_owner_evidence_set(
        {
            "contract": collector.OWNER_AUTHORIZATION_CONTRACT,
            "release": collector.CANONICAL_RELEASE,
            "app_version": collector.CANONICAL_APP_VERSION,
            "build_number": collector.CANONICAL_BUILD_NUMBER,
            "required_surfaces": list(collector.REQUIRED_OWNER_SURFACES),
            "release_input_index_sha256": "1" * 64,
            "ios_artifact_sha256": "2" * 64,
            "ios_artifact_size_bytes": 11,
            "ios_bundle_id": collector.HOST_BUNDLE_ID,
            "ios_packet_tunnel_bundle_id": collector.PACKET_TUNNEL_BUNDLE_ID,
            "watch_bundle_id": collector.WATCH_BUNDLE_ID,
            "watch_companion_bundle_id": collector.HOST_BUNDLE_ID,
            "watch_version": collector.CANONICAL_APP_VERSION,
            "watch_build": collector.CANONICAL_BUILD_NUMBER,
            "watch_executable": collector.WATCH_EXECUTABLE,
            "watch_executable_sha256": "3" * 64,
            "watch_privacy_info_sha256": "4" * 64,
            "macos_artifact_sha256": "5" * 64,
            "macos_artifact_size_bytes": 13,
            "macos_bundle_id": collector.HOST_BUNDLE_ID,
            "macos_packet_tunnel_bundle_id": collector.PACKET_TUNNEL_BUNDLE_ID,
            "macos_architecture_inventory": {
                "required_architectures": ["arm64", "x86_64"],
                "shipped": [
                    {
                        "path": "WinsVPN.app/Contents/MacOS/WinsVPN",
                        "sha256": "6" * 64,
                        "size_bytes": 9,
                        "architectures": ["arm64", "x86_64"],
                    }
                ],
            },
            "runtime_evidence_sha256": "7" * 64,
            "watch_companion_smoke_sha256": "8" * 64,
            "archive_privacy_inventory_sha256": "9" * 64,
            "app_store_privacy_snapshot_sha256": snapshot,
            "final_receipt_sha256": {"IOS_BUILD_RECEIPT.json": digest},
        }
    )


def _write_freeze_output(root: Path) -> dict[str, object]:
    """Write fixture candidates and the release_candidate.json shape the freeze writes."""
    base = root / ".artifacts" / "apple-freeze-fixture"
    base.mkdir(parents=True)
    watch_prefix = "Payload/Calculator.app/Watch/WinsWatch.app"
    ipa = base / "Calculator.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr(
            "Payload/Calculator.app/Info.plist",
            plistlib.dumps({"CFBundleIdentifier": collector.HOST_BUNDLE_ID}),
        )
        archive.writestr(
            f"{watch_prefix}/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": collector.WATCH_BUNDLE_ID,
                    "WKCompanionAppBundleIdentifier": collector.HOST_BUNDLE_ID,
                    "CFBundleShortVersionString": collector.CANONICAL_APP_VERSION,
                    "CFBundleVersion": collector.CANONICAL_BUILD_NUMBER,
                    "CFBundleExecutable": collector.WATCH_EXECUTABLE,
                }
            ),
        )
        archive.writestr(f"{watch_prefix}/WinsWatch", b"fixture watch executable")
        archive.writestr(f"{watch_prefix}/PrivacyInfo.xcprivacy", b"fixture privacy")
    pkg = base / "WinsVPN.pkg"
    pkg.write_bytes(b"fixture macOS package bytes")
    index = base / "RELEASE_INPUT_INDEX.json"
    index.write_bytes(b'{"fixture": "release input index"}\n')
    inventory = base / "APPLE_ARCHIVE_PRIVACY_INVENTORY.json"
    inventory.write_bytes(b'{"report_type": "local_archive_privacy_manifest_inventory"}\n')
    index_sha = collector.sha256_file(index)

    def entry(platform: str, path: Path, artifact_type: str, tag: str) -> dict[str, object]:
        return {
            "platform": platform,
            "lane": "app_store_local",
            "type": artifact_type,
            "path": path.relative_to(root).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": collector.sha256_file(path),
            "bundle_id": collector.HOST_BUNDLE_ID,
            "packet_tunnel_bundle_id": collector.PACKET_TUNNEL_BUNDLE_ID,
            "artifact_status": "current_candidate",
            "release_input_index": index.relative_to(root).as_posix(),
            "release_input_index_sha256": index_sha,
            "build_receipt_sha256": tag * 64,
            "build_receipt_anchor_sha256": str(int(tag) + 2) * 64,
            "signing": {
                "status": "current_candidate",
                "contract": "apple-distribution",
                "authority": "Authority=Apple Distribution:",
                "team_id": "5YT8H4U72M",
            },
        }

    ios = entry("ios", ipa, "ipa", "1")
    ios["embedded_watchos_companion"] = {
        "status": "current_candidate",
        **collector.embedded_watch_identity_from_ipa(ipa),
    }
    macos = entry("macos", pkg, "pkg", "2")
    macos["shipped_architecture_inventory"] = {
        "required_architectures": ["arm64", "x86_64"],
        "shipped": [
            {
                "path": "WinsVPN.app/Contents/MacOS/WinsVPN",
                "sha256": "6" * 64,
                "size_bytes": 9,
                "architectures": ["arm64", "x86_64"],
            }
        ],
    }
    candidate = _read(root / CANDIDATE)
    candidate.update(
        {
            "candidate_set_status": collector.COMPLETE_LOCAL_CANDIDATES,
            "release_input_index": index.relative_to(root).as_posix(),
            "release_input_index_sha256": index_sha,
            "archive_privacy_inventory": inventory.relative_to(root).as_posix(),
            "archive_privacy_inventory_sha256": collector.sha256_file(inventory),
            "source_commit": "e" * 40,
            "artifacts": [ios, macos],
        }
    )
    candidate.pop("final_receipt_sha256", None)
    _write(root / CANDIDATE, candidate)
    return candidate


class AppleOwnerAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="wins-apple-owner-auth-")
        self.stage = Path(self.temp.name)
        for relative in (PRIVACY, CANDIDATE, RUNTIME, SIGNOFF):
            source = ROOT / relative
            dest = self.stage / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _stage_review_copy(self) -> None:
        for relative in owner_signoff.REVIEW_COPY_RELATIVE_PATHS:
            source = ROOT / relative
            dest = self.stage / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)

    def test_current_tree_is_fail_closed_pending(self) -> None:
        messages = owner_signoff.validate_owner_signoff(ROOT)
        self.assertTrue(any("no_current_candidate" in message for message in messages))
        self.assertTrue(any("watchOS" in message or "watchos" in message.lower() for message in messages))
        self.assertTrue(
            any("Product Interaction" in message for message in messages)
        )
        signoff = _read(ROOT / SIGNOFF)
        self.assertIs(signoff["submission_approved"], False)
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        self.assertIs(authorization["upload_authorized"], False)
        self.assertIs(authorization["credentials_authorized"], False)
        decisions = signoff["required_decisions"]
        assert isinstance(decisions, dict)
        export_decision = decisions["export_compliance_answers"]
        assert isinstance(export_decision, dict)
        self.assertEqual(export_decision["status"], "approved")
        privacy_decision = decisions["app_privacy_answers"]
        assert isinstance(privacy_decision, dict)
        self.assertIn("Product Interaction", str(privacy_decision["approved_value"]))
        ios_decision = decisions["ios_review_notes"]
        assert isinstance(ios_decision, dict)
        self.assertNotIn("four-digit", str(ios_decision["approved_value"]))
        self.assertNotIn("000000", str(ios_decision["approved_value"]))
        with self.assertRaisesRegex(AssertionError, "complete current 1.0.17\\+34 evidence set"):
            owner_signoff.validate_owner_signoff(ROOT, require_approved=True)

    def test_stale_build_29_current_hashes_are_rejected(self) -> None:
        candidate = _read(self.stage / CANDIDATE)
        artifacts = candidate["artifacts"]
        assert isinstance(artifacts, list)
        ios = artifacts[0]
        assert isinstance(ios, dict)
        ios["sha256"] = next(iter(collector.STALE_BUILD_29_SHA256))
        ios["path"] = (
            ".artifacts/apple-final-sr-securestate-xray-20260720-final-apple2/"
            "artifacts/ios/WinsVPN-1.0.14+29-ios-app-store.ipa"
        )
        _write(self.stage / CANDIDATE, candidate)
        with self.assertRaisesRegex(AssertionError, "stale build 29"):
            owner_signoff.evidence_from_repo(self.stage)

    def test_omitted_watch_is_rejected(self) -> None:
        candidate = _read(self.stage / CANDIDATE)
        artifacts = candidate["artifacts"]
        assert isinstance(artifacts, list)
        ios = artifacts[0]
        assert isinstance(ios, dict)
        ios.pop("embedded_watchos_companion")
        _write(self.stage / CANDIDATE, candidate)
        with self.assertRaisesRegex(AssertionError, "omitted the embedded watchOS companion"):
            owner_signoff.evidence_from_repo(self.stage)

    def test_complete_evidence_measures_watch_and_release_index_bytes(self) -> None:
        # R22 Y3-02: like the IPA and PKG hashes, the embedded watch hashes and
        # the release input index hash are re-derived from bytes, never taken
        # from the candidate manifest on shape alone.
        root = self.stage.resolve()
        base = root / ".artifacts" / "apple-test"
        base.mkdir(parents=True)
        watch_prefix = "Payload/Calculator.app/Watch/WinsWatch.app"
        ipa = base / "Calculator.ipa"
        with zipfile.ZipFile(ipa, "w") as archive:
            archive.writestr(
                "Payload/Calculator.app/Info.plist",
                plistlib.dumps({"CFBundleIdentifier": collector.HOST_BUNDLE_ID}),
            )
            archive.writestr(
                f"{watch_prefix}/Info.plist",
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": collector.WATCH_BUNDLE_ID,
                        "WKCompanionAppBundleIdentifier": collector.HOST_BUNDLE_ID,
                        "CFBundleShortVersionString": collector.CANONICAL_APP_VERSION,
                        "CFBundleVersion": collector.CANONICAL_BUILD_NUMBER,
                        "CFBundleExecutable": collector.WATCH_EXECUTABLE,
                    }
                ),
            )
            archive.writestr(f"{watch_prefix}/WinsWatch", b"fixture watch executable")
            archive.writestr(f"{watch_prefix}/PrivacyInfo.xcprivacy", b"fixture privacy")
        pkg = base / "WinsVPN.pkg"
        pkg.write_bytes(b"fixture macOS package bytes")
        index = base / "RELEASE_INPUT_INDEX.json"
        index.write_bytes(b'{"fixture": "release input index"}\n')
        privacy_inventory = base / "APPLE_ARCHIVE_PRIVACY_INVENTORY.json"
        privacy_inventory.write_bytes(b'{"report_type": "local_archive_privacy_manifest_inventory"}\n')
        watch = {"status": "current_candidate", **collector.embedded_watch_identity_from_ipa(ipa)}
        signing = {
            "status": "current_candidate",
            "contract": "apple-distribution",
            "authority": "Authority=Apple Distribution:",
            "team_id": "5YT8H4U72M",
        }

        def entry(platform: str, path: Path, artifact_type: str) -> dict[str, object]:
            return {
                "platform": platform,
                "lane": "app_store_local",
                "type": artifact_type,
                "path": path.relative_to(root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": collector.sha256_file(path),
                "bundle_id": collector.HOST_BUNDLE_ID,
                "packet_tunnel_bundle_id": collector.PACKET_TUNNEL_BUNDLE_ID,
                "artifact_status": "current_candidate",
                "signing": dict(signing),
            }

        ios = entry("ios", ipa, "ipa")
        ios["embedded_watchos_companion"] = watch
        macos = entry("macos", pkg, "pkg")
        macos["shipped_architecture_inventory"] = {
            "required_architectures": ["arm64", "x86_64"],
            "shipped": [
                {
                    "path": "WinsVPN.app/Contents/MacOS/WinsVPN",
                    "sha256": "6" * 64,
                    "size_bytes": 9,
                    "architectures": ["arm64", "x86_64"],
                }
            ],
        }
        # The freeze writes the archive privacy inventory and the source
        # commit, and tools/apple_watch_companion_smoke.py writes the watch
        # smoke receipt, which the owner evidence re-hashes (R22 Y3 D2).
        commit = "e" * 40
        smoke_path, smoke_sha = watch_kit.write_receipt(
            root,
            watch_kit.receipt_document(
                release=collector.CANONICAL_RELEASE, source_commit=commit
            ),
        )
        runtime = _read(root / RUNTIME)
        runtime["watch_companion_smoke"] = {
            "status": "passed",
            "receipt_path": smoke_path,
            "receipt_sha256": smoke_sha,
        }
        _write(root / RUNTIME, runtime)
        candidate = _read(root / CANDIDATE)
        candidate.update(
            {
                "candidate_set_status": collector.COMPLETE_LOCAL_CANDIDATES,
                "release_input_index": index.relative_to(root).as_posix(),
                "release_input_index_sha256": collector.sha256_file(index),
                "archive_privacy_inventory": privacy_inventory.relative_to(root).as_posix(),
                "archive_privacy_inventory_sha256": collector.sha256_file(privacy_inventory),
                "source_commit": commit,
                "final_receipt_sha256": {"IOS_BUILD_RECEIPT.json": "a" * 64},
                "artifacts": [ios, macos],
            }
        )
        _write(root / CANDIDATE, candidate)
        evidence = owner_signoff.evidence_from_repo(root)
        self.assertEqual(evidence["watch_companion_smoke_sha256"], smoke_sha)
        self.assertEqual(evidence["watch_executable_sha256"], watch["executable_sha256"])
        self.assertEqual(evidence["watch_privacy_info_sha256"], watch["privacy_info_sha256"])
        self.assertEqual(
            evidence["release_input_index_sha256"], collector.sha256_file(index)
        )
        self.assertEqual(
            evidence["archive_privacy_inventory_sha256"],
            collector.sha256_file(privacy_inventory),
        )

        for field in ("executable_sha256", "privacy_info_sha256"):
            with self.subTest(watch_field=field):
                changed = json.loads(json.dumps(candidate))
                changed["artifacts"][0]["embedded_watchos_companion"][field] = "9" * 64
                _write(root / CANDIDATE, changed)
                with self.assertRaisesRegex(
                    AssertionError, f"{field} does not match the iOS artifact bytes"
                ):
                    owner_signoff.evidence_from_repo(root)
        for label, key, value, message in (
            ("index hash", "release_input_index_sha256", "9" * 64, "index sha256 does not match"),
            ("index path", "release_input_index", ".artifacts/apple-test/absent.json", "does not exist"),
            ("absolute index", "release_input_index", "/opt/release/RELEASE_INPUT_INDEX.json", "must be repository-relative"),
            ("no index", "release_input_index", "", "must be repository-relative"),
            ("inventory hash", "archive_privacy_inventory_sha256", "8" * 64, "inventory sha256 does not match"),
            ("inventory path", "archive_privacy_inventory", ".artifacts/apple-test/absent.json", "does not exist"),
            ("absolute inventory", "archive_privacy_inventory", "/opt/release/inventory.json", "must be repository-relative"),
            ("no inventory", "archive_privacy_inventory", "", "must be repository-relative"),
        ):
            with self.subTest(case=label):
                changed = dict(candidate)
                changed[key] = value
                _write(root / CANDIDATE, changed)
                with self.assertRaisesRegex(AssertionError, message):
                    owner_signoff.evidence_from_repo(root)

        # R22 Y3 D2: the watch smoke receipt is re-hashed and re-derived like
        # the inventory; a bare claim, a changed byte or a FAIL never binds.
        _write(root / CANDIDATE, candidate)
        failed = watch_kit.receipt_document(
            release=collector.CANONICAL_RELEASE, source_commit=commit
        )
        failed["verdict"] = "FAIL"
        failed_path, failed_sha = watch_kit.write_receipt(
            root, failed, stamp="20261018T000001Z"
        )
        stale = watch_kit.receipt_document(release="1.0.15+30", source_commit=commit)
        stale_path, stale_sha = watch_kit.write_receipt(
            root, stale, stamp="20261018T000002Z"
        )
        for label, smoke, message in (
            ("smoke hash", ("passed", smoke_path, "7" * 64), "does not match the receipt bytes"),
            ("smoke path", ("passed", smoke_path.replace("000000Z", "000009Z"), smoke_sha), "does not exist"),
            ("absolute smoke", ("passed", "/opt/release/" + smoke_path, smoke_sha), "repository-relative"),
            ("claim only", ("pending", "", smoke_sha), "must not bind"),
            ("FAIL verdict", ("passed", failed_path, failed_sha), "verdict is not PASS"),
            ("wrong release", ("passed", stale_path, stale_sha), "release"),
        ):
            with self.subTest(case=label):
                changed_runtime = _read(root / RUNTIME)
                changed_runtime["watch_companion_smoke"] = dict(
                    zip(("status", "receipt_path", "receipt_sha256"), smoke)
                )
                _write(root / RUNTIME, changed_runtime)
                with self.assertRaisesRegex(AssertionError, message):
                    owner_signoff.evidence_from_repo(root)
        _write(root / CANDIDATE, {**candidate, "source_commit": "f" * 40})
        runtime = _read(root / RUNTIME)
        runtime["watch_companion_smoke"] = {
            "status": "passed",
            "receipt_path": smoke_path,
            "receipt_sha256": smoke_sha,
        }
        _write(root / RUNTIME, runtime)
        with self.assertRaisesRegex(AssertionError, "source commit does not match"):
            owner_signoff.evidence_from_repo(root)
        _write(root / CANDIDATE, candidate)
        runtime["watch_companion_smoke"] = {
            "status": "pending",
            "receipt_path": "",
            "receipt_sha256": "",
        }
        _write(root / RUNTIME, runtime)
        # A complete candidate set with the smoke still pending has no
        # complete owner evidence set to approve: it derives the pending set
        # (R24 F-R24-03; it used to crash on the shipped macOS inventory).
        self.assertEqual(
            owner_signoff.evidence_from_repo(root),
            collector.pending_owner_evidence_set(
                app_store_privacy_snapshot_sha256=owner_signoff.privacy_snapshot_sha256(root)
            ),
        )

    def test_freeze_output_with_pending_watch_smoke_validates_as_pending(self) -> None:
        # R24 F-R24-03: the freeze writes a complete candidate set before the
        # Watch companion smoke can be recorded against it, and leaves
        # runtime_evidence.json and owner_signoff.json as they were. That honest
        # intermediate state validates as pending; nothing can approve it.
        self._stage_review_copy()
        signoff = _read(self.stage / SIGNOFF)
        for relative in {
            *(str(item["source_file"]) for item in signoff["required_decisions"].values()),
            *owner_signoff.SCREENSHOT_CANDIDATES,
            "pubspec.yaml",
        }:
            dest = self.stage / relative
            if not dest.exists():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, dest)
        root = self.stage.resolve()
        candidate = _write_freeze_output(root)
        snapshot = owner_signoff.privacy_snapshot_sha256(root)
        pending = collector.pending_owner_evidence_set(
            app_store_privacy_snapshot_sha256=snapshot
        )
        self.assertEqual(owner_signoff.evidence_from_repo(root), pending)
        messages = owner_signoff.validate_owner_signoff(root)
        self.assertIn(
            "PASS: owner authorization stays pending while the complete candidate set "
            "awaits its watch companion smoke receipt",
            messages,
        )
        with self.assertRaisesRegex(AssertionError, "requires a passed watch companion smoke"):
            owner_signoff.validate_owner_signoff(root, require_approved=True)
        authorization = signoff["owner_authorization"]
        for label, change, message in (
            ("approved status", {"status": "approved"}, "must stay pending until the watch"),
            ("upload flag", {"upload_authorized": True}, "stay false until real evidence"),
            ("credential flag", {"credentials_authorized": True}, "stay false until real evidence"),
            ("approval hash", {"approved_evidence_set_sha256": "e" * 64}, "false-positive pending"),
        ):
            with self.subTest(case=label):
                changed = json.loads(json.dumps(signoff))
                changed["owner_authorization"] = {**authorization, **change}
                with self.assertRaisesRegex(AssertionError, message):
                    owner_signoff.validate_owner_authorization_schema(root, signoff=changed)
        approved = json.loads(json.dumps(signoff))
        approved["submission_approved"] = True
        with self.assertRaisesRegex(AssertionError, "watch companion smoke is pending"):
            owner_signoff.validate_owner_authorization_schema(root, signoff=approved)
        # The pending answer does not skip a single candidate byte.
        tampered = json.loads(json.dumps(candidate))
        tampered["archive_privacy_inventory_sha256"] = "8" * 64
        _write(root / CANDIDATE, tampered)
        with self.assertRaisesRegex(AssertionError, "inventory sha256 does not match"):
            owner_signoff.evidence_from_repo(root)
        _write(root / CANDIDATE, candidate)

        # Once the smoke receipt binds, the same freeze output derives the
        # complete set; the freeze records no final_receipt_sha256 map.
        smoke_path, smoke_sha = watch_kit.write_receipt(
            root,
            watch_kit.receipt_document(
                release=collector.CANONICAL_RELEASE,
                source_commit=str(candidate["source_commit"]),
            ),
        )
        runtime = _read(root / RUNTIME)
        runtime["watch_companion_smoke"] = {
            "status": "passed",
            "receipt_path": smoke_path,
            "receipt_sha256": smoke_sha,
        }
        _write(root / RUNTIME, runtime)
        complete = owner_signoff.evidence_from_repo(root)
        self.assertTrue(collector.evidence_set_is_complete(complete))
        self.assertEqual(complete["watch_companion_smoke_sha256"], smoke_sha)
        self.assertEqual(
            complete["final_receipt_sha256"],
            {
                "build_receipt_anchor_sha256": "3" * 64,
                "build_receipt_sha256": "1" * 64,
                "release_input_index_sha256": candidate["release_input_index_sha256"],
            },
        )

    def test_missing_architecture_is_rejected(self) -> None:
        with self.assertRaisesRegex(collector.CollectorError, "missing shipped macOS architecture"):
            collector.validate_macos_architecture_inventory(
                {
                    "required_architectures": ["arm64", "x86_64"],
                    "shipped": [
                        {
                            "path": "WinsVPN.app/Contents/MacOS/WinsVPN",
                            "sha256": "b" * 64,
                            "size_bytes": 8,
                            "architectures": ["arm64"],
                        }
                    ],
                },
                require_complete=True,
            )

    def test_changed_evidence_invalidates_owner_approval_hash(self) -> None:
        snapshot = "c" * 64
        baseline = _complete_evidence(snapshot)
        digest = collector.owner_evidence_set_sha256(baseline)
        changed = dict(baseline)
        changed["watch_privacy_info_sha256"] = "d" * 64
        changed = collector.canonical_owner_evidence_set(changed)
        self.assertNotEqual(digest, collector.owner_evidence_set_sha256(changed))

        signoff = _read(self.stage / SIGNOFF)
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["approved_evidence_set_sha256"] = digest
        authorization["status"] = "pending"
        with self.assertRaisesRegex(AssertionError, "false-positive pending"):
            owner_signoff.validate_owner_authorization_schema(
                self.stage, signoff=signoff
            )

    def test_false_positive_pending_state_is_rejected(self) -> None:
        signoff = _read(ROOT / SIGNOFF)
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["approved_evidence_set_sha256"] = "e" * 64
        with self.assertRaisesRegex(AssertionError, "false-positive pending"):
            owner_signoff.validate_owner_authorization_schema(ROOT, signoff=signoff)

        authorization["approved_evidence_set_sha256"] = ""
        authorization["upload_authorized"] = True
        with self.assertRaisesRegex(AssertionError, "stay false until real evidence exists"):
            owner_signoff.validate_owner_authorization_schema(ROOT, signoff=signoff)

        authorization["upload_authorized"] = False
        authorization["credentials_authorized"] = True
        with self.assertRaisesRegex(AssertionError, "stay false until real evidence exists"):
            owner_signoff.validate_owner_authorization_schema(ROOT, signoff=signoff)

        authorization["credentials_authorized"] = False
        signoff["submission_approved"] = True
        with self.assertRaisesRegex(AssertionError, "submission_approved cannot be true"):
            owner_signoff.validate_owner_authorization_schema(ROOT, signoff=signoff)

    def test_tmp_log_is_not_runtime_authority(self) -> None:
        runtime = _read(self.stage / RUNTIME)
        runtime["runtime_log"] = "/tmp/wins_apple_current_both_live_runtime_019f58ea.log"
        _write(self.stage / RUNTIME, runtime)
        with self.assertRaisesRegex(AssertionError, "mutable /tmp logs"):
            owner_signoff.evidence_from_repo(self.stage)

    def test_selftest_and_dry_run_keep_eighteen_decisions(self) -> None:
        messages = owner_signoff.run_selftest(ROOT)
        self.assertIn(
            "PASS: owner sign-off approved-value marker self-test rejected 18 vague approvals",
            messages,
        )
        dry_run = owner_signoff.run_owner_packet_approval_dry_run(ROOT)
        self.assertIn(
            "PASS: owner approval dry-run validated 18 packet values against the current owner gate",
            dry_run,
        )
        self.assertTrue(any("left the real owner_signoff.json" in item for item in dry_run))

    def test_review_prose_does_not_contradict_the_signoff_statuses(self) -> None:
        # R24 V2 F-11: the owner packet and the README kept saying the four
        # re-approved store texts were pending, and that the screenshot set was
        # owner-approved while it is pending. The JSON status fields are the
        # authority; the prose that restates them must not disagree.
        decisions = _read(ROOT / SIGNOFF)["required_decisions"]
        packet = (ROOT / owner_signoff.OWNER_REVIEW_PACKET).read_text(encoding="utf-8")
        readme = (ROOT / "app_store/apple/README.md").read_text(encoding="utf-8")
        reapproved = (
            "storefront_description",
            "storefront_release_notes",
            "ios_review_notes",
            "macos_review_notes",
        )
        if all(decisions[name]["status"] == "approved" for name in reapproved):
            collapsed = " ".join(packet.split())
            for stale in (
                "await owner re-approval",
                "Owner re-approval pending",
                "are pending in `owner_signoff.json`",
            ):
                self.assertFalse(stale in collapsed, f"owner packet still says {stale!r}")
        if decisions["screenshot_set"]["status"] != "approved":
            self.assertFalse(
                "Screenshot inventory is owner-approved" in " ".join(readme.split()),
                "README says the screenshot set is owner-approved while it is pending",
            )

    def test_owner_approved_review_notes_are_pinned_to_their_bytes(self) -> None:
        # R24 V2 F-12: an unapproved sentence appended to an approved review note
        # passed every check, and the notes reach App Review as typed.
        self._stage_review_copy()
        owner_signoff.validate_review_copy(self.stage)
        for relative in owner_signoff.REVIEW_NOTES_SHA256:
            path = self.stage / relative
            original = path.read_bytes()
            with self.subTest(path=relative):
                path.write_bytes(original + b"\nAn unapproved extra sentence.\n")
                with self.assertRaisesRegex(AssertionError, "differs from the owner-approved"):
                    owner_signoff.validate_review_copy(self.stage)
                path.write_bytes(original)
                owner_signoff.validate_review_copy(self.stage)
        for relative, pinned in owner_signoff.REVIEW_NOTES_SHA256.items():
            self.assertEqual(owner_signoff._sha256_file(ROOT / relative), pinned, relative)

    def test_product_interaction_omission_is_rejected(self) -> None:
        self._stage_review_copy()
        path = self.stage / PRIVACY_ANSWERS
        mutated = path.read_text(encoding="ascii").replace(
            "Product Interaction", "Usage Choice"
        )
        self.assertNotIn("Product Interaction", mutated)
        path.write_text(mutated, encoding="ascii")
        with self.assertRaisesRegex(AssertionError, "Product Interaction"):
            owner_signoff.validate_review_copy(self.stage)

    def test_stale_four_digit_and_all_zero_pin_copy_is_rejected(self) -> None:
        self._stage_review_copy()
        path = self.stage / IOS_NOTES
        original = path.read_text(encoding="ascii")
        path.write_text(original + "\nfour-digit PIN reviewer instructions\n", encoding="ascii")
        with self.assertRaisesRegex(AssertionError, "stale four-digit/000000 PIN copy"):
            owner_signoff.validate_review_copy(self.stage)
        path.write_text(original + "\nconfigured PIN of 000000\n", encoding="ascii")
        with self.assertRaisesRegex(AssertionError, "stale four-digit/000000 PIN copy"):
            owner_signoff.validate_review_copy(self.stage)
        path.write_text(original, encoding="ascii")
        owner_signoff.validate_review_copy(self.stage)


    def test_review_copy_device_label_and_release_follow_canonical_constants(self) -> None:
        # The one reviewed display-name constant is the shipped app name.
        for relative in ("ios/Runner/Info.plist", "ios/WinsWatch Watch App/Info.plist"):
            with (ROOT / relative).open("rb") as handle:
                plist = plistlib.load(handle)
            self.assertEqual(
                plist["CFBundleDisplayName"], owner_signoff.IOS_DISPLAY_NAME, relative
            )
        markers = [
            marker
            for values in owner_signoff.REVIEW_COPY_REQUIRED_MARKERS.values()
            for marker in values
        ]
        self.assertIn(f"no current {collector.CANONICAL_RELEASE}", markers)
        self.assertIn(f"no current `{collector.CANONICAL_RELEASE}` candidate set", markers)
        self._stage_review_copy()
        owner_signoff.validate_review_copy(self.stage)
        name = owner_signoff.IOS_DISPLAY_NAME
        whole_name = re.compile(rf"\b{re.escape(name)}\b")
        for relative in owner_signoff.REVIEW_COPY_RELATIVE_PATHS:
            path = self.stage / relative
            original = path.read_text(encoding="ascii")
            self.assertRegex(original, whole_name)
            # The old cover names ("Calculator" until the 2026-10-25 ruling,
            # "Basic Calc" before that) and a lower-case variant must not count
            # as the device-label disclosure.
            for replacement in ("Calculator", "Basic Calc", name.lower()):
                with self.subTest(path=relative, label=replacement):
                    path.write_text(whole_name.sub(replacement, original), encoding="ascii")
                    with self.assertRaisesRegex(
                        AssertionError,
                        f"must disclose the {re.escape(repr(name))} device label",
                    ):
                        owner_signoff.validate_review_copy(self.stage)
            path.write_text(original, encoding="ascii")
        for relative, values in owner_signoff.REVIEW_COPY_REQUIRED_MARKERS.items():
            if not any(collector.CANONICAL_RELEASE in marker for marker in values):
                continue
            path = self.stage / relative
            original = path.read_text(encoding="ascii")
            with self.subTest(path=relative, release="1.0.15+30"):
                path.write_text(
                    original.replace(collector.CANONICAL_RELEASE, "1.0.15+30"),
                    encoding="ascii",
                )
                with self.assertRaisesRegex(AssertionError, "must disclose 'no current"):
                    owner_signoff.validate_review_copy(self.stage)
            path.write_text(original, encoding="ascii")
        owner_signoff.validate_review_copy(self.stage)

    def test_owner_approval_markers_follow_the_display_name_constant(self) -> None:
        name = owner_signoff.IOS_DISPLAY_NAME
        packet = owner_signoff.owner_packet_approval_values(ROOT)
        previous_values = {
            "storefront_description": (
                "App Store description for iPhone, iPad, Mac, and embedded non-VPN "
                "Apple Watch companion, including always-on post-activation Calculator "
                "camouflage and four linked privacy types, approved"
            ),
            "storefront_release_notes": (
                "App Store What's New copy for 1.0.17+34, including always-on "
                "post-activation Calculator camouflage and no in-app purchases, approved"
            ),
            "ios_review_notes": (
                "iOS review notes and iPhone test flow, including Calculator device "
                "label, six-digit nontrivial PIN, embedded non-VPN watchOS companion, "
                "and Product Interaction disclosure, approved"
            ),
        }
        # Swapping the old cover name back into the new value must fail too.
        swapped_values = {
            key: re.sub(rf"\b{re.escape(name)}\b", "Calculator", packet[key])
            for key in previous_values
        }
        for key, previous in previous_values.items():
            with self.subTest(decision=key):
                owner_signoff._assert_approved_value_is_specific(ROOT, key, packet[key])
                for stale in (previous, swapped_values[key]):
                    with self.assertRaisesRegex(
                        AssertionError,
                        "missing required marker ("
                        + re.escape(repr(f"installed name {name}"))
                        + "|"
                        + re.escape(repr(f"device label {name}"))
                        + ")",
                    ):
                        owner_signoff._assert_approved_value_is_specific(ROOT, key, stale)


if __name__ == "__main__":
    unittest.main()
