#!/usr/bin/env python3
"""Focused mutation tests for Apple owner authorization schema v2."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from collections.abc import Callable
from typing import Any


TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import apple_final_evidence_collector as collector
import apple_watch_companion_smoke_testkit as watch_kit
import cross_store_upload_readiness as readiness


SIGNOFF = readiness.OWNER_SIGNOFF
CANDIDATE = readiness.APPLE_RELEASE_CANDIDATE
RUNTIME = readiness.APPLE_RUNTIME_EVIDENCE
PRIVACY = readiness.APPLE_PRIVACY_SNAPSHOT
RELEASE_IDENTITY = readiness.RELEASE_IDENTITY_RELATIVE
PLATFORM_OWNER_SIGNOFFS = tuple(spec.path for spec in readiness.PLATFORM_OWNER_EVIDENCE)
SOURCE_COMMIT = "e" * 40


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


def _write_json(path: pathlib.Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="ascii",
    )


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return value


def _file_sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _complete_inventory() -> dict[str, object]:
    return {
        "required_architectures": ["arm64", "x86_64"],
        "shipped": [
            {
                "path": "WinsVPN.app/Contents/MacOS/WinsVPN",
                "sha256": _sha("macos-binary"),
                "size_bytes": 9,
                "architectures": ["arm64", "x86_64"],
            }
        ],
    }


def _utc_stamp(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _complete_candidate() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-08-24T00:00:00Z",
        "app_version": collector.CANONICAL_APP_VERSION,
        "build_number": collector.CANONICAL_BUILD_NUMBER,
        "candidate_set_status": collector.COMPLETE_LOCAL_CANDIDATES,
        "release_input_index_sha256": _sha("release-index"),
        "archive_privacy_inventory_sha256": _sha("archive-privacy"),
        "source_commit": SOURCE_COMMIT,
        "final_receipt_sha256": {"IOS_BUILD_RECEIPT.json": _sha("ios-receipt")},
        "artifacts": [
            {
                "platform": "ios",
                "lane": "app_store_local",
                "type": "ipa",
                "path": ".artifacts/apple-test/WinsVPN-ios.ipa",
                "size_bytes": 11,
                "sha256": _sha("ios-artifact"),
                "bundle_id": collector.HOST_BUNDLE_ID,
                "packet_tunnel_bundle_id": collector.PACKET_TUNNEL_BUNDLE_ID,
                "artifact_status": "current_candidate",
                "embedded_watchos_companion": {
                    "status": "current_candidate",
                    "bundle_id": collector.WATCH_BUNDLE_ID,
                    "companion_bundle_id": collector.HOST_BUNDLE_ID,
                    "version": collector.CANONICAL_APP_VERSION,
                    "build": collector.CANONICAL_BUILD_NUMBER,
                    "executable": collector.WATCH_EXECUTABLE,
                    "executable_sha256": _sha("watch-executable"),
                    "privacy_info_sha256": _sha("watch-privacy"),
                },
            },
            {
                "platform": "macos",
                "lane": "app_store_local",
                "type": "pkg",
                "path": ".artifacts/apple-test/WinsVPN-macos.pkg",
                "size_bytes": 13,
                "sha256": _sha("macos-artifact"),
                "bundle_id": collector.HOST_BUNDLE_ID,
                "packet_tunnel_bundle_id": collector.PACKET_TUNNEL_BUNDLE_ID,
                "artifact_status": "current_candidate",
                "shipped_architecture_inventory": _complete_inventory(),
            },
        ],
    }


def _complete_runtime(receipt_path: str, receipt_sha256: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "app_version": collector.CANONICAL_APP_VERSION,
        "build_number": collector.CANONICAL_BUILD_NUMBER,
        "candidate_set_status": collector.COMPLETE_LOCAL_CANDIDATES,
        "watch_companion_smoke": {
            "status": "passed",
            "receipt_path": receipt_path,
            "receipt_sha256": receipt_sha256,
        },
        "platform_results": [{"platform": "ios", "status": "pass"}],
    }


def _evidence_from_files(
    candidate: dict[str, object],
    runtime_sha256: str,
    privacy_sha256: str,
    watch_smoke_sha256: str,
) -> dict[str, object]:
    artifacts = candidate["artifacts"]
    assert isinstance(artifacts, list)
    ios = artifacts[0]
    macos = artifacts[1]
    assert isinstance(ios, dict)
    assert isinstance(macos, dict)
    watch = ios["embedded_watchos_companion"]
    assert isinstance(watch, dict)
    return collector.canonical_owner_evidence_set(
        {
            "contract": collector.OWNER_AUTHORIZATION_CONTRACT,
            "release": collector.CANONICAL_RELEASE,
            "app_version": collector.CANONICAL_APP_VERSION,
            "build_number": collector.CANONICAL_BUILD_NUMBER,
            "required_surfaces": list(collector.REQUIRED_OWNER_SURFACES),
            "release_input_index_sha256": candidate["release_input_index_sha256"],
            "ios_artifact_sha256": ios["sha256"],
            "ios_artifact_size_bytes": ios["size_bytes"],
            "ios_bundle_id": ios["bundle_id"],
            "ios_packet_tunnel_bundle_id": ios["packet_tunnel_bundle_id"],
            "watch_bundle_id": watch["bundle_id"],
            "watch_companion_bundle_id": watch["companion_bundle_id"],
            "watch_version": watch["version"],
            "watch_build": watch["build"],
            "watch_executable": watch["executable"],
            "watch_executable_sha256": watch["executable_sha256"],
            "watch_privacy_info_sha256": watch["privacy_info_sha256"],
            "macos_artifact_sha256": macos["sha256"],
            "macos_artifact_size_bytes": macos["size_bytes"],
            "macos_bundle_id": macos["bundle_id"],
            "macos_packet_tunnel_bundle_id": macos["packet_tunnel_bundle_id"],
            "macos_architecture_inventory": macos["shipped_architecture_inventory"],
            "runtime_evidence_sha256": runtime_sha256,
            "watch_companion_smoke_sha256": watch_smoke_sha256,
            "archive_privacy_inventory_sha256": candidate[
                "archive_privacy_inventory_sha256"
            ],
            "app_store_privacy_snapshot_sha256": privacy_sha256,
            "final_receipt_sha256": candidate["final_receipt_sha256"],
        }
    )


def _approved_signoff(evidence: dict[str, object]) -> dict[str, object]:
    digest = collector.owner_evidence_set_sha256(evidence)
    return {
        "schema_version": readiness.OWNER_SIGNOFF_DOCUMENT_SCHEMA_VERSION,
        "authorization_schema_version": readiness.OWNER_AUTHORIZATION_SCHEMA_VERSION,
        "submission_approved": True,
        "approved_by": "Win's VPN Release Owner",
        "approved_at_utc": _utc_stamp(dt.datetime.now(tz=dt.timezone.utc)),
        "approved_scope": list(readiness.OWNER_FINAL_SCOPE),
        "owner_authorization": {
            "contract": collector.OWNER_AUTHORIZATION_CONTRACT,
            "status": "approved",
            "credentials_authorized": True,
            "upload_authorized": True,
            "approved_evidence_set_sha256": digest,
            "evidence": evidence,
        },
    }


class CrossStoreAppleOwnerAuthorizationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wins-cross-store-apple-owner-v2-"
        )
        self.repo = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _pubspec(self) -> None:
        _write(self.repo / "pubspec.yaml", "name: wins_vpn\nversion: 1.0.17+34\n")

    def _copy_real_pending(self) -> None:
        self._pubspec()
        for relative in (SIGNOFF, CANDIDATE, RUNTIME, PRIVACY):
            source = ROOT / relative
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)

    def _install_platform_owner_dependencies(self) -> None:
        for relative in (RELEASE_IDENTITY, *PLATFORM_OWNER_SIGNOFFS):
            source = ROOT / relative
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)

    def _install_approved(self) -> dict[str, object]:
        self._pubspec()
        self._install_platform_owner_dependencies()
        _write_json(
            self.repo / PRIVACY,
            {
                "schema_version": 1,
                "app_version": collector.CANONICAL_APP_VERSION,
                "build_number": collector.CANONICAL_BUILD_NUMBER,
            },
        )
        # R22 Y3 D2: a real durable smoke receipt, re-hashed by the gate.
        receipt_path, receipt_sha256 = watch_kit.write_receipt(
            self.repo,
            watch_kit.receipt_document(
                release=collector.CANONICAL_RELEASE, source_commit=SOURCE_COMMIT
            ),
        )
        runtime = _complete_runtime(receipt_path, receipt_sha256)
        _write_json(self.repo / RUNTIME, runtime)
        candidate = _complete_candidate()
        _write_json(self.repo / CANDIDATE, candidate)
        evidence = _evidence_from_files(
            candidate,
            _file_sha(self.repo / RUNTIME),
            _file_sha(self.repo / PRIVACY),
            receipt_sha256,
        )
        signoff = _approved_signoff(evidence)
        _write_json(self.repo / SIGNOFF, signoff)
        return signoff

    def _rewrite_signoff(self, record: dict[str, object]) -> None:
        _write_json(self.repo / SIGNOFF, record)

    def test_freeze_output_derives_the_owner_validator_evidence(self) -> None:
        # R24: the freeze writes no final_receipt_sha256 map, and the Watch
        # companion smoke records only after it (F-R24-03), so cross-store must
        # derive what validate_apple_owner_signoff derives from the same bytes:
        # the pending set while the smoke is pending, the complete set after.
        import validate_apple_owner_signoff as owner_signoff
        from test_apple_owner_authorization import _write_freeze_output

        self._copy_real_pending()
        repo = self.repo.resolve()
        candidate = _write_freeze_output(repo)
        self.assertNotIn("final_receipt_sha256", candidate)
        pending = owner_signoff.evidence_from_repo(repo)
        self.assertFalse(collector.evidence_set_is_complete(pending))
        self.assertEqual(readiness._owner_evidence_from_repo(repo, collector), pending)
        self.assertFalse(readiness._owner_signoff_submission_approved(repo))
        approved = _read_json(repo / SIGNOFF)
        approved["submission_approved"] = True
        approved["owner_authorization"] = {
            **approved["owner_authorization"],
            "status": "approved",
            "credentials_authorized": True,
            "upload_authorized": True,
            "approved_evidence_set_sha256": "e" * 64,
        }
        self._rewrite_signoff(approved)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "requires a complete current evidence set"
        ):
            readiness._owner_signoff_submission_approved(repo)

        receipt_path, receipt_sha256 = watch_kit.write_receipt(
            repo,
            watch_kit.receipt_document(
                release=collector.CANONICAL_RELEASE,
                source_commit=str(candidate["source_commit"]),
            ),
        )
        runtime = _read_json(repo / RUNTIME)
        runtime["watch_companion_smoke"] = {
            "status": "passed",
            "receipt_path": receipt_path,
            "receipt_sha256": receipt_sha256,
        }
        _write_json(repo / RUNTIME, runtime)
        complete = owner_signoff.evidence_from_repo(repo)
        self.assertTrue(collector.evidence_set_is_complete(complete))
        self.assertEqual(readiness._owner_evidence_from_repo(repo, collector), complete)

    def test_real_tree_pending_stays_fail_closed(self) -> None:
        self.assertFalse(readiness._owner_signoff_submission_approved(ROOT))
        result = readiness.evaluate_source_gates(ROOT)
        blocker_ids = [item["id"] for item in result["owner_blockers"]]
        self.assertIn("apple-owner-signoff", blocker_ids)
        self.assertFalse(result["store_upload_authorized"])
        self.assertFalse(result["publication_authorized"])

    def test_copied_pending_tree_is_not_converted_to_approved(self) -> None:
        self._copy_real_pending()
        before = (self.repo / SIGNOFF).read_bytes()
        self.assertFalse(readiness._owner_signoff_submission_approved(self.repo))
        self.assertEqual((self.repo / SIGNOFF).read_bytes(), before)
        real = _read_json(ROOT / SIGNOFF)
        self.assertIs(real.get("submission_approved"), False)
        authorization = real["owner_authorization"]
        assert isinstance(authorization, dict)
        self.assertEqual(authorization.get("status"), "pending")

    def test_schema_1_pending_does_not_raise(self) -> None:
        self._pubspec()
        _write_json(
            self.repo / SIGNOFF,
            {"schema_version": 1, "submission_approved": False},
        )
        self.assertFalse(readiness._owner_signoff_submission_approved(self.repo))

    def test_schema_1_cannot_approve_unbound_artifacts(self) -> None:
        self._pubspec()
        _write_json(
            self.repo / SIGNOFF,
            {"schema_version": 1, "submission_approved": True},
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "not bound to exact release artifacts"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_boolean_schema_version_cannot_alias_integer_one(self) -> None:
        self._pubspec()
        _write_json(
            self.repo / SIGNOFF,
            {"schema_version": True, "submission_approved": False},
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "schema_version is invalid"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_approved_v2_clears_apple_blocker_when_fully_bound(self) -> None:
        self._install_approved()
        self.assertTrue(readiness._owner_signoff_submission_approved(self.repo))
        _write(
            self.repo / readiness.PLAY_DECLARATIONS,
            "Approval status: `APPROVED` - owner Play Console gate.\n",
        )
        _write(self.repo / readiness.CHECKLIST, "Cross-store checklist without live gate.\n")
        blockers = readiness._owner_blockers(self.repo)
        blocker_ids = {str(item["id"]) for item in blockers}
        self.assertNotIn("apple-owner-signoff", blocker_ids)
        self.assertEqual(
            blocker_ids,
            {spec.blocker_id for spec in readiness.PLATFORM_OWNER_EVIDENCE},
        )

    def test_missing_canonical_android_phone_signoff_remains_blocked(self) -> None:
        self._install_approved()
        _write(
            self.repo / readiness.PLAY_DECLARATIONS,
            "Approval status: `APPROVED` - owner Play Console gate.\n",
        )
        _write(self.repo / readiness.CHECKLIST, "Cross-store checklist without live gate.\n")
        phone = next(
            spec
            for spec in readiness.PLATFORM_OWNER_EVIDENCE
            if spec.blocker_id == "android-phone-owner-signoff"
        )
        (self.repo / phone.path).unlink()

        blockers = readiness._owner_blockers(self.repo)
        record = next(item for item in blockers if item["id"] == phone.blocker_id)
        self.assertIn(readiness.OWNER_BLOCKED_ABSENT, str(record["detail"]))
        self.assertEqual(record["target_ids"], list(phone.target_ids))

    def test_complete_unapproved_evidence_stays_fail_closed(self) -> None:
        signoff = self._install_approved()
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["status"] = "pending"
        authorization["credentials_authorized"] = False
        authorization["upload_authorized"] = False
        authorization["approved_evidence_set_sha256"] = ""
        signoff["submission_approved"] = False
        signoff["approved_by"] = ""
        signoff["approved_at_utc"] = ""
        self._rewrite_signoff(signoff)
        self.assertFalse(readiness._owner_signoff_submission_approved(self.repo))

    def test_pending_submission_approved_flip_is_self_contradictory(self) -> None:
        self._copy_real_pending()
        signoff = _read_json(self.repo / SIGNOFF)
        signoff["submission_approved"] = True
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "self-contradictory"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_mutations_reject_stale_mixed_partial_authorization(self) -> None:
        mutations: tuple[tuple[str, Callable[[dict[str, object]], None], str], ...] = (
            (
                "stale-approval-hash",
                lambda record: record["owner_authorization"].__setitem__(
                    "approved_evidence_set_sha256", "0" * 64
                ),
                "stale",
            ),
            (
                "stale-ios-hash",
                lambda record: record["owner_authorization"]["evidence"].__setitem__(
                    "ios_artifact_sha256", _sha("stale-ios")
                ),
                "stale",
            ),
            (
                "stale-release",
                lambda record: record["owner_authorization"]["evidence"].__setitem__(
                    "release", "1.0.14+29"
                ),
                "invalid|stale",
            ),
            (
                "stale-build-29",
                lambda record: record["owner_authorization"]["evidence"].__setitem__(
                    "ios_artifact_sha256", next(iter(collector.STALE_BUILD_29_SHA256))
                ),
                "stale|invalid",
            ),
            (
                "mixed-schema-version",
                lambda record: record.__setitem__("authorization_schema_version", 1),
                "mixed",
            ),
            (
                "mixed-pending-status",
                lambda record: record["owner_authorization"].__setitem__(
                    "status", "pending"
                ),
                "self-contradictory",
            ),
            (
                "mixed-submission-flag",
                lambda record: record.__setitem__("submission_approved", False),
                "self-contradictory",
            ),
            (
                "self-contradictory-upload-flag",
                lambda record: record["owner_authorization"].__setitem__(
                    "upload_authorized", False
                ),
                "self-contradictory",
            ),
            (
                "partial-missing-watch-surface",
                lambda record: record["owner_authorization"]["evidence"].__setitem__(
                    "required_surfaces", ["ios", "macos"]
                ),
                "partial|invalid",
            ),
            (
                "partial-placeholder-signer",
                lambda record: record.__setitem__("approved_by", "owner"),
                "partial",
            ),
            (
                "partial-empty-timestamp",
                lambda record: record.__setitem__("approved_at_utc", ""),
                "partial",
            ),
            (
                "invalid-timestamp",
                lambda record: record.__setitem__(
                    "approved_at_utc", "2026-08-24 12:00:00"
                ),
                "invalid",
            ),
            (
                "partial-draft-scope",
                lambda record: record.__setitem__("approved_scope", ["ios", "macos"]),
                "partial",
            ),
            (
                "partial-authorization-keys",
                lambda record: record["owner_authorization"].__setitem__(
                    "unexpected", True
                ),
                "partial",
            ),
            (
                "boolean-authorization-schema",
                lambda record: record.__setitem__(
                    "authorization_schema_version", True
                ),
                "mixed",
            ),
        )
        for name, mutate, pattern in mutations:
            with self.subTest(name=name):
                signoff = self._install_approved()
                mutate(signoff)
                self._rewrite_signoff(signoff)
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError, pattern
                ):
                    readiness._owner_signoff_submission_approved(self.repo)

    def test_candidate_hash_change_invalidates_approval(self) -> None:
        self._install_approved()
        candidate = _read_json(self.repo / CANDIDATE)
        artifacts = candidate["artifacts"]
        assert isinstance(artifacts, list)
        ios = artifacts[0]
        assert isinstance(ios, dict)
        ios["sha256"] = _sha("mutated-ios-artifact")
        _write_json(self.repo / CANDIDATE, candidate)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "stale"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_watch_smoke_receipt_is_rehashed_and_rederived(self) -> None:
        # R22 Y3 D2: the approved digest names receipt bytes that must still
        # exist, hash to it, re-derive PASS and match the candidate commit.
        signoff = self._install_approved()
        self.assertTrue(readiness._owner_signoff_submission_approved(self.repo))
        runtime = _read_json(self.repo / RUNTIME)
        smoke = runtime["watch_companion_smoke"]
        receipt = self.repo / smoke["receipt_path"]
        original = receipt.read_bytes()
        receipt.write_bytes(original.replace(b'"verdict": "PASS"', b'"verdict": "FAIL"'))
        with self.assertRaisesRegex(readiness.UploadReadinessError, "does not match the receipt bytes"):
            readiness._owner_signoff_submission_approved(self.repo)
        receipt.unlink()
        with self.assertRaisesRegex(readiness.UploadReadinessError, "does not exist"):
            readiness._owner_signoff_submission_approved(self.repo)
        receipt.write_bytes(original)
        receipt.chmod(0o600)
        self.assertTrue(readiness._owner_signoff_submission_approved(self.repo))
        candidate = _read_json(self.repo / CANDIDATE)
        candidate["source_commit"] = "f" * 40
        _write_json(self.repo / CANDIDATE, candidate)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "source commit does not match"):
            readiness._owner_signoff_submission_approved(self.repo)
        candidate["source_commit"] = SOURCE_COMMIT
        _write_json(self.repo / CANDIDATE, candidate)
        for label, replacement, pattern in (
            ("bare claim", {"status": "current", "receipt_path": smoke["receipt_path"], "receipt_sha256": smoke["receipt_sha256"]}, "pending or passed"),
            ("pending with digest", {"status": "pending", "receipt_path": "", "receipt_sha256": smoke["receipt_sha256"]}, "must not bind"),
            ("absolute path", {**smoke, "receipt_path": "/opt/release/" + smoke["receipt_path"]}, "repository-relative"),
        ):
            with self.subTest(case=label):
                runtime["watch_companion_smoke"] = replacement
                _write_json(self.repo / RUNTIME, runtime)
                with self.assertRaisesRegex(readiness.UploadReadinessError, pattern):
                    readiness._owner_signoff_submission_approved(self.repo)
        self.assertEqual(signoff["submission_approved"], True)

    def test_privacy_snapshot_change_invalidates_approval(self) -> None:
        self._install_approved()
        privacy = _read_json(self.repo / PRIVACY)
        privacy["mutated"] = True
        _write_json(self.repo / PRIVACY, privacy)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "stale"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_runtime_evidence_change_invalidates_approval(self) -> None:
        self._install_approved()
        runtime = _read_json(self.repo / RUNTIME)
        runtime["notes"] = "mutated runtime identity"
        _write_json(self.repo / RUNTIME, runtime)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "stale"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_omitted_watch_companion_is_partial(self) -> None:
        self._install_approved()
        candidate = _read_json(self.repo / CANDIDATE)
        artifacts = candidate["artifacts"]
        assert isinstance(artifacts, list)
        ios = artifacts[0]
        assert isinstance(ios, dict)
        ios.pop("embedded_watchos_companion")
        _write_json(self.repo / CANDIDATE, candidate)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "partial|omitted the embedded watchOS"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_missing_macos_architecture_is_rejected(self) -> None:
        self._install_approved()
        candidate = _read_json(self.repo / CANDIDATE)
        artifacts = candidate["artifacts"]
        assert isinstance(artifacts, list)
        macos = artifacts[1]
        assert isinstance(macos, dict)
        macos["shipped_architecture_inventory"] = {
            "required_architectures": ["arm64", "x86_64"],
            "shipped": [
                {
                    "path": "WinsVPN.app/Contents/MacOS/WinsVPN",
                    "sha256": _sha("macos-binary"),
                    "size_bytes": 9,
                    "architectures": ["arm64"],
                }
            ],
        }
        _write_json(self.repo / CANDIDATE, candidate)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "invalid|architecture"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_required_apple_targets_are_the_app_store_pair(self) -> None:
        self.assertEqual(
            readiness.APPLE_REQUIRED_UPLOAD_TARGET_IDS,
            ("ios-app-store-ipa", "macos-app-store-pkg"),
        )

    def test_mixed_owner_authorization_without_schema_version(self) -> None:
        self._copy_real_pending()
        signoff = _read_json(self.repo / SIGNOFF)
        signoff.pop("authorization_schema_version")
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "mixed"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_v2_schema_without_authorization_body_is_partial(self) -> None:
        self._copy_real_pending()
        signoff = _read_json(self.repo / SIGNOFF)
        signoff.pop("owner_authorization")
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "partial"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_pubspec_mismatch_is_stale_release_identity(self) -> None:
        self._install_approved()
        _write(self.repo / "pubspec.yaml", "name: wins_vpn\nversion: 1.0.16+31\n")
        with self.assertRaisesRegex(readiness.UploadReadinessError, "stale"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_pending_candidate_leftover_hash_is_mixed(self) -> None:
        self._copy_real_pending()
        candidate = _read_json(self.repo / CANDIDATE)
        artifacts = candidate["artifacts"]
        assert isinstance(artifacts, list)
        ios = artifacts[0]
        assert isinstance(ios, dict)
        ios["sha256"] = _sha("leftover-ios")
        _write_json(self.repo / CANDIDATE, candidate)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "mixed"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_valid_fixture_binds_ios_watchos_macos_and_release(self) -> None:
        signoff = self._install_approved()
        self.assertTrue(readiness._owner_signoff_submission_approved(self.repo))
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        evidence = authorization["evidence"]
        assert isinstance(evidence, dict)
        self.assertEqual(evidence["release"], collector.CANONICAL_RELEASE)
        self.assertEqual(
            list(evidence["required_surfaces"]),
            list(collector.REQUIRED_OWNER_SURFACES),
        )
        self.assertEqual(signoff["approved_scope"], list(readiness.OWNER_FINAL_SCOPE))
        self.assertEqual(
            readiness.APPLE_REQUIRED_UPLOAD_TARGET_IDS,
            ("ios-app-store-ipa", "macos-app-store-pkg"),
        )

    def test_forged_boolean_submission_approved_is_rejected(self) -> None:
        self._install_approved()
        signoff = _read_json(self.repo / SIGNOFF)
        signoff["submission_approved"] = 1
        raw = json.dumps(signoff, indent=2, sort_keys=True, ensure_ascii=True)
        raw = raw.replace('"submission_approved": 1', '"submission_approved": 1')
        _write(self.repo / SIGNOFF, raw + "\n")
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "submission_approved is invalid"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_forged_boolean_nested_authorization_flags_are_rejected(self) -> None:
        self._install_approved()
        signoff = _read_json(self.repo / SIGNOFF)
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["credentials_authorized"] = 1
        authorization["upload_authorized"] = "true"
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "must be a JSON boolean"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_stale_authorization_timestamp_is_expired(self) -> None:
        signoff = self._install_approved()
        stale = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(hours=73)
        signoff["approved_at_utc"] = _utc_stamp(stale)
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "stale or future-dated"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_wrong_release_is_rejected(self) -> None:
        signoff = self._install_approved()
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["evidence"]["release"] = "1.0.14+29"
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "invalid|stale"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_wrong_target_omits_watchos(self) -> None:
        signoff = self._install_approved()
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["evidence"]["required_surfaces"] = ["ios", "macos"]
        signoff["approved_scope"] = ["ios", "macos"]
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "partial|invalid"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_wrong_source_and_candidate_hashes_are_stale(self) -> None:
        signoff = self._install_approved()
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["evidence"]["release_input_index_sha256"] = _sha("wrong-source")
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "stale"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_wrong_owner_identity_is_rejected(self) -> None:
        signoff = self._install_approved()
        signoff["approved_by"] = "candidate producer"
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "signer/team identity"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        self._install_approved()
        path = self.repo / SIGNOFF
        text = path.read_text(encoding="ascii")
        injected = text.replace(
            '"schema_version": 1,',
            '"schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        self.assertNotEqual(injected, text)
        path.write_text(injected, encoding="ascii")
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "duplicate JSON key"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_extra_evidence_and_authorization_keys_are_rejected(self) -> None:
        signoff = self._install_approved()
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["unexpected"] = True
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "schema fields are invalid"
        ):
            readiness._owner_signoff_submission_approved(self.repo)
        signoff = self._install_approved()
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        authorization["evidence"]["unexpected"] = True
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "invalid"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_receipt_reuse_is_rejected(self) -> None:
        signoff = self._install_approved()
        candidate = _read_json(self.repo / CANDIDATE)
        receipts = candidate["final_receipt_sha256"]
        assert isinstance(receipts, dict)
        reused = receipts["IOS_BUILD_RECEIPT.json"]
        receipts["MACOS_BUILD_RECEIPT.json"] = reused
        _write_json(self.repo / CANDIDATE, candidate)
        authorization = signoff["owner_authorization"]
        assert isinstance(authorization, dict)
        evidence = authorization["evidence"]
        assert isinstance(evidence, dict)
        evidence["final_receipt_sha256"] = dict(receipts)
        authorization["approved_evidence_set_sha256"] = (
            collector.owner_evidence_set_sha256(evidence)
        )
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "receipt reuse"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_candidate_minted_authorization_is_rejected(self) -> None:
        self._install_approved()
        candidate = _read_json(self.repo / CANDIDATE)
        candidate["owner_authorization"] = {
            "status": "approved",
            "upload_authorized": True,
        }
        _write_json(self.repo / CANDIDATE, candidate)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "candidate-minted"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_candidate_minted_timestamp_copy_is_rejected(self) -> None:
        signoff = self._install_approved()
        candidate = _read_json(self.repo / CANDIDATE)
        minted = _utc_stamp(dt.datetime.now(tz=dt.timezone.utc))
        candidate["generated_at_utc"] = minted
        _write_json(self.repo / CANDIDATE, candidate)
        signoff["approved_at_utc"] = minted
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "candidate-minted"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_top_level_schema_2_confused_with_nested_v2(self) -> None:
        signoff = self._install_approved()
        signoff["schema_version"] = 2
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "mixed"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_nested_schema_1_confused_with_document_schema(self) -> None:
        signoff = self._install_approved()
        signoff["authorization_schema_version"] = 1
        self._rewrite_signoff(signoff)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "mixed"):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_schema_v1_approval_still_fails(self) -> None:
        self._pubspec()
        _write_json(
            self.repo / SIGNOFF,
            {
                "schema_version": 1,
                "submission_approved": True,
                "approved_by": "Win's VPN Release Owner",
                "approved_at_utc": _utc_stamp(dt.datetime.now(tz=dt.timezone.utc)),
            },
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "not bound to exact release artifacts"
        ):
            readiness._owner_signoff_submission_approved(self.repo)

    def test_current_signoff_remains_pending(self) -> None:
        real = _read_json(ROOT / SIGNOFF)
        self.assertIs(real.get("submission_approved"), False)
        self.assertEqual(real.get("schema_version"), 1)
        self.assertEqual(real.get("authorization_schema_version"), 2)
        authorization = real["owner_authorization"]
        assert isinstance(authorization, dict)
        self.assertEqual(authorization.get("status"), "pending")
        self.assertFalse(authorization.get("credentials_authorized"))
        self.assertFalse(authorization.get("upload_authorized"))
        self.assertFalse(readiness._owner_signoff_submission_approved(ROOT))


if __name__ == "__main__":
    unittest.main()
