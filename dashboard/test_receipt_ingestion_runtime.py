#!/usr/bin/env python3
"""Runtime ingestion tests for independently produced schema-4 receipts."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from dashboard import server


CONFIG = Path(__file__).with_name("state.json")
NOW = datetime(2026, 8, 25, 16, 0, tzinfo=timezone.utc)


class ReceiptIngestionRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.evidence_root = self.root / "evidence"
        self.evidence_root.mkdir(mode=0o700)
        self.repo_root = self.root / "repo"
        self.repo_root.mkdir(mode=0o700)
        self.cache_path = self.root / "absent-cross-store-cache.json"
        self.artifacts: dict[str, Path] = {}
        self.payloads: dict[str, bytes] = {}

    def _write_artifact(
        self,
        target_id: str,
        evidence_id: str,
        observed_at: datetime,
    ) -> dict[str, str]:
        directory = self.evidence_root / target_id
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        path = directory / f"{evidence_id}.proof"
        payload = (
            f"independent schema-4 evidence:{target_id}:{evidence_id}\n"
        ).encode("ascii")
        path.write_bytes(payload)
        path.chmod(0o600)
        os.utime(path, (observed_at.timestamp(), observed_at.timestamp()))
        self.artifacts[evidence_id] = path
        self.payloads[evidence_id] = payload
        return {
            "root": "evidence",
            "path": path.relative_to(self.evidence_root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def _check(
        self,
        target_id: str,
        evidence_id: str,
        contract: tuple[str, str],
        observed_at: datetime,
    ) -> dict[str, object]:
        return {
            "status": "pass",
            "observed_at": server.iso_utc(observed_at),
            "producer": contract[1],
            "evidence_type": contract[0],
            "summary_code": f"{evidence_id}_runtime_evidence",
            "artifacts": [
                self._write_artifact(target_id, evidence_id, observed_at)
            ],
        }

    def _produce_receipt(
        self,
        target_id: str = "control-hub",
        *,
        observed_at: dict[str, datetime] | None = None,
    ) -> tuple[Path, dict[str, object]]:
        observation_times = observed_at or {}
        dimensions = {
            dimension["id"]: self._check(
                target_id,
                dimension["id"],
                server.DIMENSION_EVIDENCE_CONTRACT[dimension["id"]],
                observation_times.get(dimension["id"], NOW),
            )
            for dimension in server.load_config(CONFIG)["dimensions"]
        }
        receipt: dict[str, object] = {
            "schema_version": 4,
            "release": server.RELEASE_IDENTITY,
            "target": target_id,
            "generated_at": server.iso_utc(NOW),
            "dimensions": dimensions,
            "blocker_audit": self._check(
                target_id,
                "blocker_audit",
                server.BLOCKER_AUDIT_CONTRACT,
                observation_times.get("blocker_audit", NOW),
            ),
            "blockers": [],
        }
        path = self.evidence_root / f"{target_id}.json"
        self._write_receipt(path, receipt)
        return path, receipt

    @staticmethod
    def _write_receipt(path: Path, receipt: dict[str, object]) -> None:
        path.write_text(
            json.dumps(
                receipt,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="ascii",
        )
        path.chmod(0o600)
        os.utime(path, (NOW.timestamp(), NOW.timestamp()))

    def _snapshot(self) -> dict[str, object]:
        snapshot = server.build_snapshot(
            CONFIG,
            self.evidence_root,
            NOW,
            repo_root=self.repo_root,
            cache_path=self.cache_path,
        )
        self.assertIs(
            snapshot["current_posture"]["store_upload_authorized"], False
        )
        return snapshot

    @staticmethod
    def _target(snapshot: dict[str, object], target_id: str) -> dict[str, object]:
        return next(
            target
            for target in snapshot["targets"]
            if target["id"] == target_id
        )

    @staticmethod
    def _dimension(target: dict[str, object], dimension_id: str) -> dict[str, object]:
        return next(
            dimension
            for dimension in target["dimensions"]
            if dimension["id"] == dimension_id
        )

    def test_valid_independent_receipt_and_referenced_bytes_are_consumed(self) -> None:
        receipt_path, receipt = self._produce_receipt()

        snapshot = self._snapshot()
        target = self._target(snapshot, "control-hub")

        self.assertEqual(target["status"], "ready")
        self.assertEqual(target["readiness"], 100)
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["receipt_generated_at"], server.iso_utc(NOW))
        self.assertEqual(receipt_path.stat().st_uid, os.geteuid())
        self.assertEqual(receipt_path.stat().st_mode & 0o022, 0)
        self.assertEqual(receipt_path.stat().st_nlink, 1)

        raw_dimensions = receipt["dimensions"]
        for dimension_id, contract in server.DIMENSION_EVIDENCE_CONTRACT.items():
            with self.subTest(dimension=dimension_id):
                result = self._dimension(target, dimension_id)
                raw = raw_dimensions[dimension_id]
                artifact = result["artifacts"][0]
                self.assertEqual(result["status"], "verified")
                self.assertEqual(result["observed_at"], server.iso_utc(NOW))
                self.assertEqual(result["evidence_type"], contract[0])
                self.assertEqual(result["producer"], contract[1])
                self.assertEqual(artifact["bytes"], len(self.payloads[dimension_id]))
                self.assertEqual(artifact["sha256"], raw["artifacts"][0]["sha256"])
                self.assertEqual(artifact["modified_at"], server.iso_utc(NOW))

        self.assertEqual(target["blocker_audit"]["status"], "verified")
        self.assertIs(snapshot["current_posture"]["store_upload_authorized"], False)

    def test_changed_referenced_bytes_fail_hash_validation(self) -> None:
        self._produce_receipt()
        path = self.artifacts["engineering"]
        changed = b"changed referenced artifact bytes after receipt production\n"
        path.write_bytes(changed)
        path.chmod(0o600)
        os.utime(path, (NOW.timestamp(), NOW.timestamp()))

        target = self._target(self._snapshot(), "control-hub")
        engineering = self._dimension(target, "engineering")

        self.assertEqual(engineering["status"], "invalid")
        self.assertIn("SHA-256 mismatch", engineering["reason"])
        self.assertLess(target["readiness"], 100)
        self.assertNotEqual(target["status"], "ready")

    def test_stale_observation_and_artifact_remain_unready(self) -> None:
        stale_at = NOW - timedelta(days=2)
        self._produce_receipt(observed_at={"runtime_proof": stale_at})

        target = self._target(self._snapshot(), "control-hub")
        runtime = self._dimension(target, "runtime_proof")

        self.assertEqual(runtime["status"], "stale")
        self.assertLess(target["readiness"], 100)
        self.assertEqual(target["status"], "stale")

    def test_receipt_and_artifact_timestamp_mismatches_remain_unready(self) -> None:
        receipt_path, _ = self._produce_receipt()
        mismatched = NOW - timedelta(minutes=10)
        os.utime(receipt_path, (mismatched.timestamp(), mismatched.timestamp()))

        target = self._target(self._snapshot(), "control-hub")
        self.assertEqual(target["status"], "invalid")
        self.assertLess(target["readiness"], 100)
        self.assertNotEqual(target["status"], "ready")
        self.assertIn("file time does not match", target["blocker_audit"]["reason"])

        self._produce_receipt(
            observed_at={"engineering": NOW - timedelta(minutes=10)}
        )
        changed_after_observation = self.artifacts["engineering"]
        os.utime(
            changed_after_observation,
            (NOW.timestamp(), NOW.timestamp()),
        )
        target = self._target(self._snapshot(), "control-hub")
        engineering = self._dimension(target, "engineering")
        self.assertEqual(engineering["status"], "invalid")
        self.assertIn("changed after evidence observation", engineering["reason"])
        self.assertLess(target["readiness"], 100)
        self.assertNotEqual(target["status"], "ready")

    def test_receipt_and_artifact_write_modes_remain_unready(self) -> None:
        receipt_path, _ = self._produce_receipt()
        receipt_path.chmod(0o620)

        target = self._target(self._snapshot(), "control-hub")
        self.assertEqual(target["status"], "invalid")
        self.assertLess(target["readiness"], 100)
        self.assertNotEqual(target["status"], "ready")
        self.assertIn("group- or other-writable", target["blocker_audit"]["reason"])

        receipt_path.chmod(0o600)
        self.artifacts["signing"].chmod(0o602)
        target = self._target(self._snapshot(), "control-hub")
        signing = self._dimension(target, "signing")
        self.assertEqual(signing["status"], "invalid")
        self.assertIn("group- or other-writable", signing["reason"])
        self.assertEqual(target["readiness"], 0)

    def test_owner_mismatch_remains_unready(self) -> None:
        self._produce_receipt()
        foreign_effective_uid = os.geteuid() + 1

        with mock.patch.object(
            server.os, "geteuid", return_value=foreign_effective_uid
        ):
            target = self._target(self._snapshot(), "control-hub")

        self.assertEqual(target["status"], "invalid")
        self.assertEqual(target["readiness"], 0)
        self.assertIn("owned by the dashboard user", target["blocker_audit"]["reason"])

    def test_target_release_evidence_type_and_producer_must_match(self) -> None:
        receipt_path, original = self._produce_receipt()
        cases = (
            ("target", lambda value: value.__setitem__("target", "android")),
            ("release", lambda value: value.__setitem__("release", "1.0.14+29")),
            (
                "evidence_type",
                lambda value: value["dimensions"]["signing"].__setitem__(
                    "evidence_type", "engineering_verification"
                ),
            ),
            (
                "producer",
                lambda value: value["dimensions"]["signing"].__setitem__(
                    "producer", "engineering_gate"
                ),
            ),
        )

        for case, mutate in cases:
            with self.subTest(case=case):
                candidate = json.loads(json.dumps(original))
                mutate(candidate)
                self._write_receipt(receipt_path, candidate)
                target = self._target(self._snapshot(), "control-hub")
                self.assertLess(target["readiness"], 100)
                self.assertNotEqual(target["status"], "ready")
                if case in {"evidence_type", "producer"}:
                    self.assertEqual(
                        self._dimension(target, "signing")["status"], "invalid"
                    )
                else:
                    self.assertEqual(target["status"], "invalid")

    def test_absent_signing_evidence_remains_unready(self) -> None:
        receipt_path, receipt = self._produce_receipt()
        receipt["dimensions"]["signing"] = None
        self._write_receipt(receipt_path, receipt)

        target = self._target(self._snapshot(), "control-hub")
        signing = self._dimension(target, "signing")

        self.assertEqual(signing["status"], "missing")
        self.assertEqual(target["technical_readiness"], 80)
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")

    def test_absent_upload_receipts_withhold_mapped_target_readiness(self) -> None:
        self._produce_receipt("android")

        snapshot = self._snapshot()
        target = self._target(snapshot, "android")

        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["cross_store_status"], "missing")
        self.assertTrue(target["cross_store_receipts"])
        self.assertTrue(
            all(
                receipt["status"] == "missing"
                for receipt in target["cross_store_receipts"]
            )
        )
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")
        self.assertEqual(snapshot["coverage"]["store_upload"]["verified"], 0)
        self.assertIs(snapshot["current_posture"]["store_upload_authorized"], False)

    def test_receipt_and_artifact_symlinks_remain_unready(self) -> None:
        receipt_path, _ = self._produce_receipt()
        outside_receipt = self.root / "outside-receipt.json"
        receipt_path.replace(outside_receipt)
        receipt_path.symlink_to(outside_receipt)

        target = self._target(self._snapshot(), "control-hub")
        self.assertEqual(target["status"], "invalid")
        self.assertEqual(target["readiness"], 0)
        self.assertIn("symbolic link", target["blocker_audit"]["reason"])

        receipt_path.unlink()
        outside_receipt.replace(receipt_path)
        artifact_path = self.artifacts["engineering"]
        outside_artifact = self.root / "outside-artifact.proof"
        artifact_path.replace(outside_artifact)
        artifact_path.symlink_to(outside_artifact)
        target = self._target(self._snapshot(), "control-hub")
        engineering = self._dimension(target, "engineering")
        self.assertEqual(engineering["status"], "invalid")
        self.assertIn("symbolic link", engineering["reason"])
        self.assertLess(target["readiness"], 100)
        self.assertNotEqual(target["status"], "ready")

    def test_receipt_and_artifact_hardlinks_remain_unready(self) -> None:
        receipt_path, _ = self._produce_receipt()
        receipt_alias = self.root / "receipt-hardlink-alias.json"
        os.link(receipt_path, receipt_alias)

        target = self._target(self._snapshot(), "control-hub")
        self.assertEqual(target["status"], "invalid")
        self.assertEqual(target["readiness"], 0)
        self.assertIn("hard-linked", target["blocker_audit"]["reason"])

        receipt_alias.unlink()
        artifact_path = self.artifacts["engineering"]
        artifact_alias = self.root / "artifact-hardlink-alias.proof"
        os.link(artifact_path, artifact_alias)
        target = self._target(self._snapshot(), "control-hub")
        engineering = self._dimension(target, "engineering")
        self.assertEqual(engineering["status"], "invalid")
        self.assertIn("hard-linked", engineering["reason"])
        self.assertLess(target["readiness"], 100)
        self.assertNotEqual(target["status"], "ready")

    def test_relative_and_absolute_path_escapes_remain_unready(self) -> None:
        receipt_path, original = self._produce_receipt()
        outside = self.root / "outside-path-escape.proof"
        outside.write_bytes(self.payloads["engineering"])
        cases = ("../outside-path-escape.proof", str(outside))

        for hostile_path in cases:
            with self.subTest(path=hostile_path):
                candidate = json.loads(json.dumps(original))
                candidate["dimensions"]["engineering"]["artifacts"][0][
                    "path"
                ] = hostile_path
                self._write_receipt(receipt_path, candidate)
                target = self._target(self._snapshot(), "control-hub")
                engineering = self._dimension(target, "engineering")
                self.assertEqual(engineering["status"], "invalid")
                self.assertIn("absolute artifact paths", engineering["reason"])
                self.assertLess(target["readiness"], 100)
                self.assertNotEqual(target["status"], "ready")


if __name__ == "__main__":
    unittest.main()
