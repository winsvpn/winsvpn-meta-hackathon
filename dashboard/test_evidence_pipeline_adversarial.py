#!/usr/bin/env python3
"""Adversarial tests for the local dashboard evidence pipeline.

These tests call production dashboard functions with temporary local fixtures.
They do not sign, upload, deploy, use GitHub, access secrets, or write
repository upload receipts.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from unittest import mock


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dashboard import server


CONFIG = Path(__file__).with_name("state.json")
SYNC = _REPO_ROOT / "tools" / "sync_progress.sh"


class EvidencePipelineAdversarialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.cache_path = self.root / "cross-store-cache.json"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.max_age = timedelta(
            seconds=server.load_config(CONFIG)["max_evidence_age_seconds"]
        )
        with server._hash_cache_lock:
            server._hash_cache.clear()

    def artifact(
        self,
        target: str,
        name: str,
        *,
        payload: bytes | None = None,
        modified_at: datetime | None = None,
    ) -> dict[str, str]:
        when = modified_at or self.now
        relative = Path(target) / name
        path = self.evidence / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        body = payload if payload is not None else (
            b"verified " + target.encode("ascii") + b":" + name.encode("ascii") + b"\n"
        )
        path.write_bytes(body)
        os.utime(path, (when.timestamp(), when.timestamp()))
        return {
            "root": "evidence",
            "path": relative.as_posix(),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    def check(
        self,
        target: str,
        dimension: str,
        *,
        status: str = "pass",
        observed_at: datetime | None = None,
        artifact: dict[str, str] | None = None,
        modified_at: datetime | None = None,
    ) -> dict[str, object]:
        when = observed_at or self.now
        contract = server.DIMENSION_EVIDENCE_CONTRACT.get(
            dimension,
            server.BLOCKER_AUDIT_CONTRACT
            if dimension == "blocker_audit"
            else server.OPEN_BLOCKER_CONTRACT,
        )
        return {
            "status": status,
            "observed_at": server.iso_utc(when),
            "producer": contract[1],
            "evidence_type": contract[0],
            "summary_code": dimension + "_evidence",
            "artifacts": [
                artifact
                or self.artifact(
                    target, dimension + ".proof", modified_at=modified_at or when
                )
            ],
        }

    def receipt(
        self,
        target: str,
        dimensions: dict[str, object],
        *,
        generated_at: datetime | None = None,
        blocker_audit: object | None = None,
    ) -> None:
        when = generated_at or self.now
        value = {
            "schema_version": 4,
            "release": server.RELEASE_IDENTITY,
            "target": target,
            "generated_at": server.iso_utc(when),
            "dimensions": dimensions,
            "blocker_audit": blocker_audit or self.check(target, "blocker_audit"),
            "blockers": [],
        }
        path = self.evidence / (target + ".json")
        path.write_text(json.dumps(value), encoding="ascii")
        os.utime(path, (when.timestamp(), when.timestamp()))

    def all_dimensions(
        self,
        target: str,
        *,
        signing_status: str = "pass",
        observed_at: datetime | None = None,
    ) -> dict[str, object]:
        when = observed_at or self.now
        return {
            dimension["id"]: self.check(
                target,
                dimension["id"],
                status=signing_status if dimension["id"] == "signing" else "pass",
                observed_at=when,
            )
            for dimension in server.load_config(CONFIG)["dimensions"]
        }

    def snapshot(self, now: datetime | None = None) -> dict[str, object]:
        return server.build_snapshot(
            CONFIG,
            self.evidence,
            now or self.now,
            repo_root=self.repo,
            cache_path=self.cache_path,
        )

    def target(self, target_id: str, now: datetime | None = None) -> dict[str, object]:
        return next(
            item
            for item in self.snapshot(now)["targets"]
            if item["id"] == target_id
        )

    def evaluate(self, target_id: str, now: datetime | None = None) -> dict[str, object]:
        config = server.load_config(CONFIG)
        target_cfg = next(item for item in config["targets"] if item["id"] == target_id)
        return server.evaluate_target(
            target_cfg,
            config["dimensions"],
            self.evidence,
            now or self.now,
            self.max_age,
            config["cross_store"],
            self.repo,
            {},
            {},
            None,
        )

    def live_handler_snapshot(self) -> dict[str, object]:
        original = (
            server.DashboardHandler.config_path,
            server.DashboardHandler.evidence_root,
            server.DashboardHandler.repo_root,
            server.DashboardHandler.cache_path,
            server.DashboardHandler.snapshot_path,
        )
        server.DashboardHandler.config_path = CONFIG
        server.DashboardHandler.evidence_root = self.evidence
        server.DashboardHandler.repo_root = self.repo
        server.DashboardHandler.cache_path = self.cache_path
        server.DashboardHandler.snapshot_path = self.root / "planted.snapshot.json"
        try:
            probe = object.__new__(server.DashboardHandler)
            return probe._read_only_snapshot()
        finally:
            (
                server.DashboardHandler.config_path,
                server.DashboardHandler.evidence_root,
                server.DashboardHandler.repo_root,
                server.DashboardHandler.cache_path,
                server.DashboardHandler.snapshot_path,
            ) = original

    def write_stale_cross_store_cache(self) -> None:
        generated = self.now - self.max_age - timedelta(hours=1)
        payload = {
            "schema_version": server.CROSS_STORE_CACHE_SCHEMA_VERSION,
            "release": server.RELEASE_IDENTITY,
            "generated_at": server.iso_utc(generated),
            "receipt_directory": server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY,
            "release_input_index": server.DEFAULT_RELEASE_INPUT_INDEX,
            "receipts": {
                target_id: {
                    "target_id": target_id,
                    "receipt": (
                        server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY
                        + "/"
                        + target_id
                        + ".json"
                    ),
                    "receipt_schema_version": 2,
                    "release": server.RELEASE_IDENTITY,
                    "status": "missing",
                    "verified_at": None,
                    "receipt_sha256": None,
                    "artifact_sha256": None,
                    "reason": "stale cache must not preserve readiness",
                }
                for target_id in server.KNOWN_CROSS_STORE_TARGET_IDS
            },
        }
        self.cache_path.write_text(json.dumps(payload), encoding="ascii")
        os.chmod(self.cache_path, 0o600)

    def start_http_server(
        self, snapshot_path: Path | None = None
    ) -> server.ThreadingHTTPServer:
        original = (
            server.DashboardHandler.config_path,
            server.DashboardHandler.evidence_root,
            server.DashboardHandler.repo_root,
            server.DashboardHandler.cache_path,
            server.DashboardHandler.snapshot_path,
        )
        server.DashboardHandler.config_path = CONFIG
        server.DashboardHandler.evidence_root = self.evidence
        server.DashboardHandler.repo_root = self.repo
        server.DashboardHandler.cache_path = self.cache_path
        server.DashboardHandler.snapshot_path = snapshot_path or (
            self.root / "unused.snapshot.json"
        )
        try:
            httpd = server.ThreadingHTTPServer(
                (server.LOCAL_BIND, 0), server.DashboardHandler
            )
        except PermissionError as exc:
            (
                server.DashboardHandler.config_path,
                server.DashboardHandler.evidence_root,
                server.DashboardHandler.repo_root,
                server.DashboardHandler.cache_path,
                server.DashboardHandler.snapshot_path,
            ) = original
            self.skipTest("sandbox disallows local loopback binds: " + str(exc))
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()

        def cleanup() -> None:
            httpd.shutdown()
            httpd.server_close()
            worker.join(timeout=2)
            (
                server.DashboardHandler.config_path,
                server.DashboardHandler.evidence_root,
                server.DashboardHandler.repo_root,
                server.DashboardHandler.cache_path,
                server.DashboardHandler.snapshot_path,
            ) = original

        self.addCleanup(cleanup)
        return httpd

    def http_get(
        self, httpd: server.ThreadingHTTPServer, target: str
    ) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection("127.0.0.1", httpd.server_port, timeout=5)
        try:
            connection.request("GET", target, headers={"Host": "127.0.0.1"})
            response = connection.getresponse()
            body = response.read()
            headers = {name.lower(): value for name, value in response.getheaders()}
            return response.status, headers, body
        finally:
            connection.close()

    def test_changed_referenced_bytes_invalidate_cached_and_current_evidence(
        self,
    ) -> None:
        original = b"original-engineering-bytes\n"
        artifact = self.artifact(
            "windows-x86", "engineering.proof", payload=original
        )
        validated = server.validate_artifact(artifact, self.evidence)
        self.assertEqual(validated["sha256"], hashlib.sha256(original).hexdigest())
        first_stat = (self.evidence / artifact["path"]).stat()
        cached = server.sha256_file(self.evidence / artifact["path"], first_stat)
        self.assertEqual(cached, validated["sha256"])

        changed = b"tampered-engineering-bytes-after-observation\n"
        path = self.evidence / artifact["path"]
        path.write_bytes(changed)
        os.utime(path, (self.now.timestamp(), self.now.timestamp()))
        with self.assertRaisesRegex(server.DashboardError, "SHA-256 mismatch"):
            server.validate_artifact(artifact, self.evidence)
        second_stat = path.stat()
        recomputed = server.sha256_file(path, second_stat)
        self.assertEqual(recomputed, hashlib.sha256(changed).hexdigest())
        self.assertNotEqual(recomputed, cached)

        dimensions = self.all_dimensions("windows-x86")
        dimensions["engineering"] = self.check(
            "windows-x86", "engineering", artifact=artifact
        )
        self.receipt("windows-x86", dimensions)
        path.write_bytes(changed)
        os.utime(path, (self.now.timestamp(), self.now.timestamp()))
        evaluated = self.evaluate("windows-x86")
        engineering = next(
            item for item in evaluated["dimensions"] if item["id"] == "engineering"
        )
        self.assertEqual(engineering["status"], "invalid")
        self.assertIn("SHA-256 mismatch", engineering["reason"])
        self.assertNotEqual(evaluated["status"], "ready")
        self.assertEqual(evaluated["readiness"], 0)

        first = self.live_handler_snapshot()
        first_target = next(
            item for item in first["targets"] if item["id"] == "windows-x86"
        )
        first_engineering = next(
            item
            for item in first_target["dimensions"]
            if item["id"] == "engineering"
        )
        self.assertEqual(first_engineering["status"], "invalid")
        self.assertIs(first["current_posture"]["store_upload_authorized"], False)

    def test_stale_timestamps_expire_engineering_evidence(self) -> None:
        stale_at = self.now - self.max_age - timedelta(minutes=1)
        config = server.load_config(CONFIG)
        dimension = next(
            item for item in config["dimensions"] if item["id"] == "engineering"
        )
        stale_check = self.check(
            "windows-x86",
            "engineering",
            observed_at=stale_at,
            modified_at=stale_at,
        )
        stale_result = server._dimension_result(
            dimension,
            stale_check,
            server.DIMENSION_EVIDENCE_CONTRACT["engineering"],
            self.evidence,
            self.now,
            self.max_age,
            self.now,
            "windows-x86",
            {},
        )
        self.assertEqual(stale_result["status"], "stale")
        self.assertIn("freshness window", stale_result["reason"])

        fresh_check_old_file = self.check(
            "windows-x86",
            "engineering",
            observed_at=self.now,
            artifact=self.artifact(
                "windows-x86",
                "old-engineering.proof",
                modified_at=stale_at,
            ),
        )
        old_file_result = server._dimension_result(
            dimension,
            fresh_check_old_file,
            server.DIMENSION_EVIDENCE_CONTRACT["engineering"],
            self.evidence,
            self.now,
            self.max_age,
            self.now,
            "windows-x86",
            {},
        )
        self.assertEqual(old_file_result["status"], "stale")

        dimensions = self.all_dimensions("windows-x86", observed_at=stale_at)
        self.receipt("windows-x86", dimensions, generated_at=stale_at)
        target = self.evaluate("windows-x86")
        engineering = next(
            item for item in target["dimensions"] if item["id"] == "engineering"
        )
        self.assertEqual(engineering["status"], "stale")
        self.assertEqual(target["engineering_readiness"], 0)
        self.assertNotEqual(target["status"], "ready")
        self.assertEqual(target["readiness"], 0)

        later = self.now + timedelta(days=2)
        current_dimensions = self.all_dimensions("windows-x86")
        self.receipt("windows-x86", current_dimensions)
        later_target = self.evaluate("windows-x86", now=later)
        later_engineering = next(
            item
            for item in later_target["dimensions"]
            if item["id"] == "engineering"
        )
        self.assertEqual(later_engineering["status"], "stale")
        self.assertNotEqual(later_target["status"], "ready")

        verified_looking = {
            "target_id": "android-tv-aab",
            "receipt": (
                server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY
                + "/android-tv-aab.json"
            ),
            "receipt_schema_version": 2,
            "release": server.RELEASE_IDENTITY,
            "status": "verified",
            "verified_at": server.iso_utc(stale_at),
            "receipt_sha256": "a" * 64,
            "artifact_sha256": "b" * 64,
            "reason": "stale cached verification must expire",
        }
        expired = server._apply_cross_store_freshness(
            verified_looking,
            "android-tv-aab",
            verified_looking["receipt"],
            self.now,
            self.max_age,
        )
        self.assertEqual(expired["status"], "stale")
        self.assertNotEqual(expired["status"], "verified")

    def test_missing_signing_or_upload_receipts_never_become_ready(self) -> None:
        missing_signing_readiness, missing_signing_status = (
            server._derive_status_and_readiness(
                80,
                {"verified", "failed"},
                "verified",
                [],
                "not_applicable",
                False,
            )
        )
        self.assertEqual(missing_signing_readiness, 0)
        self.assertNotEqual(missing_signing_status, "ready")

        missing_upload_readiness, missing_upload_status = (
            server._derive_status_and_readiness(
                100,
                {"verified"},
                "verified",
                [],
                "missing",
                True,
            )
        )
        self.assertEqual(missing_upload_readiness, 0)
        self.assertNotEqual(missing_upload_status, "ready")

        self.receipt(
            "control-hub",
            self.all_dimensions("control-hub", signing_status="fail"),
        )
        hub = self.evaluate("control-hub")
        signing = next(item for item in hub["dimensions"] if item["id"] == "signing")
        self.assertEqual(signing["status"], "failed")
        self.assertEqual(hub["store_evidence_readiness"], 40)
        self.assertNotEqual(hub["status"], "ready")
        self.assertEqual(hub["readiness"], 0)

        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        windows = self.evaluate("windows-x86")
        self.assertEqual(windows["technical_readiness"], 100)
        self.assertEqual(windows["cross_store_status"], "missing")
        self.assertNotEqual(windows["status"], "ready")
        self.assertEqual(windows["readiness"], 0)
        self.assertTrue(
            all(
                receipt["status"] == "missing"
                for receipt in windows["cross_store_receipts"]
            )
        )

        missing_path = (
            self.repo
            / server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY
            / "android-tv-aab.json"
        )
        with self.assertRaises(server.CrossStoreReceiptMissing):
            server.verify_cross_store_upload_receipt(
                self.repo,
                self.repo / server.DEFAULT_RELEASE_INPUT_INDEX,
                "android-tv-aab",
                missing_path,
                self.now,
            )
        self.assertFalse(server._upload_receipt_present(missing_path))
        self.assertFalse(missing_path.exists())
        upload_dir = self.repo / server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY
        self.assertFalse(upload_dir.exists())

        snapshot = self.snapshot()
        self.assertEqual(snapshot["ready_targets"], 0)
        self.assertEqual(snapshot["coverage"]["store_upload"]["verified"], 0)
        self.assertEqual(snapshot["coverage"]["store_upload"]["pending"], 16)
        mapped = next(
            item for item in snapshot["targets"] if item["id"] == "windows-x86"
        )
        self.assertNotEqual(mapped["status"], "ready")
        self.assertIs(snapshot["current_posture"]["store_upload_authorized"], False)

    def test_symlinks_hardlinks_and_path_escape_are_refused(self) -> None:
        payload = b"escape-probe\n"
        real = self.artifact("windows-x86", "real.proof", payload=payload)

        link = self.evidence / "windows-x86" / "linked.proof"
        link.symlink_to(self.evidence / real["path"])
        with self.assertRaisesRegex(server.DashboardError, "symbolic link"):
            server.validate_artifact(
                {**real, "path": "windows-x86/linked.proof"}, self.evidence
            )

        outside = self.root / "outside.proof"
        outside.write_bytes(payload)
        outside_link = self.evidence / "windows-x86" / "outside-link.proof"
        outside_link.symlink_to(outside)
        with self.assertRaisesRegex(server.DashboardError, "symbolic link"):
            server.validate_artifact(
                {
                    "root": "evidence",
                    "path": "windows-x86/outside-link.proof",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                self.evidence,
            )

        nested = self.evidence / "windows-x86" / "nested"
        nested.mkdir()
        (nested / "proof.bin").write_bytes(payload)
        alias = self.evidence / "windows-x86" / "alias-dir"
        alias.symlink_to(nested, target_is_directory=True)
        with self.assertRaisesRegex(server.DashboardError, "symbolic link"):
            server.validate_artifact(
                {
                    "root": "evidence",
                    "path": "windows-x86/alias-dir/proof.bin",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                self.evidence,
            )

        root_link = self.root / "evidence-link"
        root_link.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaisesRegex(server.DashboardError, "symbolic link"):
            server.validate_artifact(real, root_link)

        hard = self.evidence / "windows-x86" / "hard.proof"
        os.link(self.evidence / real["path"], hard)
        with self.assertRaisesRegex(server.DashboardError, "hard-linked"):
            server.validate_artifact(
                {**real, "path": "windows-x86/hard.proof"}, self.evidence
            )
        with self.assertRaisesRegex(server.DashboardError, "hard-linked"):
            server.validate_artifact(real, self.evidence)

        escaped = self.root / "escaped.proof"
        escaped.write_bytes(payload)
        with self.assertRaisesRegex(server.DashboardError, "escapes its root"):
            server._resolve_contained_without_symlinks(
                self.evidence, Path("..") / "escaped.proof", "artifact evidence"
            )

        for raw_path in (
            "../escaped.proof",
            "/tmp/escaped.proof",
            "windows-x86\\escaped.proof",
            "windows-x86/../escaped.proof",
            "",
        ):
            with self.subTest(path=raw_path):
                with self.assertRaises(server.DashboardError):
                    server._artifact_path(
                        {
                            "root": "evidence",
                            "path": raw_path,
                            "sha256": hashlib.sha256(payload).hexdigest(),
                        },
                        self.evidence,
                    )

        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        receipt_path = self.evidence / "windows-x86.json"
        linked_receipt = self.evidence / "windows-x86.linked.json"
        os.link(receipt_path, linked_receipt)
        hard_receipt = self.evaluate("windows-x86")
        self.assertEqual(hard_receipt["status"], "invalid")
        self.assertIn("hard-linked", hard_receipt["dimensions"][0]["reason"])
        self.assertNotEqual(hard_receipt["status"], "ready")
        linked_receipt.unlink()

        outside_receipt = self.root / "outside.json"
        outside_receipt.write_text("{}", encoding="ascii")
        receipt_path.unlink()
        receipt_path.symlink_to(outside_receipt)
        linked_eval = self.evaluate("windows-x86")
        self.assertEqual(linked_eval["status"], "invalid")
        self.assertIn("symbolic link", linked_eval["dimensions"][0]["reason"])
        self.assertNotEqual(linked_eval["status"], "ready")

    def test_stale_snapshot_and_http_cache_cannot_preserve_readiness(self) -> None:
        planted = self.root / "planted.snapshot.json"
        planted.write_text(
            json.dumps(
                {
                    "overall_readiness": 100,
                    "ready_targets": 20,
                    "source": "planted-stale-snapshot",
                    "current_posture": {"store_upload_authorized": True},
                }
            ),
            encoding="ascii",
        )
        server.DashboardHandler.snapshot_path = planted
        live = self.live_handler_snapshot()
        self.assertNotEqual(live.get("source"), "planted-stale-snapshot")
        self.assertEqual(live["overall_readiness"], 0)
        self.assertEqual(live["ready_targets"], 0)
        self.assertIs(live["current_posture"]["store_upload_authorized"], False)
        self.assertEqual(json.loads(planted.read_text(encoding="ascii"))["overall_readiness"], 100)

        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        before = self.live_handler_snapshot()
        before_target = next(
            item for item in before["targets"] if item["id"] == "windows-x86"
        )
        self.assertEqual(before_target["technical_readiness"], 100)
        self.assertNotEqual(before_target["status"], "ready")
        engineering_path = self.evidence / "windows-x86" / "engineering.proof"
        engineering_path.write_bytes(b"changed-after-http-snapshot\n")
        os.utime(engineering_path, (self.now.timestamp(), self.now.timestamp()))
        after = self.live_handler_snapshot()
        after_target = next(
            item for item in after["targets"] if item["id"] == "windows-x86"
        )
        after_engineering = next(
            item
            for item in after_target["dimensions"]
            if item["id"] == "engineering"
        )
        self.assertEqual(after_engineering["status"], "invalid")
        self.assertLess(after_target["technical_readiness"], before_target["technical_readiness"])
        self.assertNotEqual(after_target["status"], "ready")
        self.assertIs(after["current_posture"]["store_upload_authorized"], False)

        self.write_stale_cross_store_cache()
        config = server.load_config(CONFIG)
        with self.assertRaisesRegex(server.DashboardError, "stale"):
            server._read_cross_store_cache(
                self.cache_path,
                self.now,
                self.max_age,
                config["cross_store"]["receipt_directory"],
                config["cross_store"]["release_input_index"],
                self.repo,
            )
        failed = self.live_handler_snapshot()
        self.assertEqual(failed["source"], "invalid-local-evidence")
        self.assertEqual(failed["overall_readiness"], 0)
        self.assertEqual(failed["ready_targets"], 0)
        self.assertIs(failed["current_posture"]["store_upload_authorized"], False)
        self.cache_path.unlink()

        stdout = io.StringIO()
        with mock.patch("sys.stdout", stdout):
            code = server.main(["--failure-snapshot", str(planted)])
        self.assertEqual(code, 0)
        replaced = json.loads(planted.read_text(encoding="ascii"))
        self.assertEqual(replaced["source"], "invalid-local-evidence")
        self.assertEqual(replaced["overall_readiness"], 0)
        self.assertIs(replaced["current_posture"]["store_upload_authorized"], False)

        httpd = self.start_http_server(snapshot_path=planted)
        status, headers, body = self.http_get(httpd, "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store, max-age=0")
        payload = json.loads(body.decode("ascii"))
        self.assertEqual(payload["overall_readiness"], 0)
        self.assertIs(payload["current_posture"]["store_upload_authorized"], False)
        self.assertNotEqual(payload.get("source"), "planted-stale-snapshot")

        snapshot_file = self.root / "output" / "state.json"
        snapshot_file.parent.mkdir()
        snapshot_file.write_text(
            json.dumps({"overall_readiness": 100, "ready_targets": 20}),
            encoding="ascii",
        )
        environment = os.environ.copy()
        environment.update(
            {
                "WINSVPN_DASHBOARD_PYTHON": sys.executable,
                "WINSVPN_DASHBOARD_EVIDENCE_DIR": str(self.evidence),
                "WINSVPN_DASHBOARD_SNAPSHOT": str(snapshot_file),
                "WINSVPN_DASHBOARD_REPO_ROOT": str(self.repo),
                "WINSVPN_DASHBOARD_CROSS_STORE_CACHE": str(self.cache_path),
            }
        )
        synced = subprocess.run(
            ["bash", str(SYNC)],
            cwd=str(_REPO_ROOT),
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(synced.returncode, 0, synced.stderr)
        synced_snapshot = json.loads(snapshot_file.read_text(encoding="ascii"))
        self.assertEqual(synced_snapshot["overall_readiness"], 0)
        self.assertIs(
            synced_snapshot["current_posture"]["store_upload_authorized"], False
        )
        self.assertFalse(Path(str(snapshot_file) + ".expired-do-not-use").exists())

    def test_store_upload_authorized_remains_false_under_every_input(self) -> None:
        postures = []

        empty = self.snapshot()
        postures.append(empty["current_posture"])

        self.receipt(
            "windows-x86",
            {
                "engineering": self.check("windows-x86", "engineering"),
                "artifact": self.check("windows-x86", "artifact", status="fail"),
                "signing": self.check("windows-x86", "signing", status="fail"),
                "store_metadata": self.check(
                    "windows-x86", "store_metadata", status="fail"
                ),
                "runtime_proof": self.check("windows-x86", "runtime_proof"),
            },
        )
        engineering_only = self.snapshot()
        postures.append(engineering_only["current_posture"])

        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        complete_local = self.snapshot()
        postures.append(complete_local["current_posture"])

        self.receipt(
            "control-hub",
            self.all_dimensions("control-hub", signing_status="fail"),
        )
        missing_signing = self.snapshot()
        postures.append(missing_signing["current_posture"])

        failure = server.build_failure_snapshot(self.now)
        postures.append(failure["current_posture"])

        claimed_complete = dict(complete_local["coverage"])
        claimed_store = dict(claimed_complete["store_upload"])
        claimed_store["verified"] = 16
        claimed_store["pending"] = 0
        claimed_store["failed"] = 0
        claimed_store["stale"] = 0
        claimed_store["unavailable"] = 0
        claimed_complete["store_upload"] = claimed_store
        forced = server._current_posture(
            complete_local["targets"],
            claimed_complete,
            complete_local["blocker_summary"],
            repo_root=self.repo,
            release_input_index=server.DEFAULT_RELEASE_INPUT_INDEX,
            now=self.now,
            evidence_root=self.evidence,
        )
        postures.append(forced)
        self.assertEqual(forced["upload_receipts"]["status"], "complete")

        http_payload = self.live_handler_snapshot()
        postures.append(http_payload["current_posture"])

        for index, posture in enumerate(postures):
            with self.subTest(index=index):
                self.assertIs(posture["store_upload_authorized"], False)
                self.assertEqual(posture["publication_hold"], "DO-NOT-UPLOAD")

        self.assertTrue(
            all(item["store_upload_authorized"] is False for item in postures)
        )


if __name__ == "__main__":
    unittest.main()
