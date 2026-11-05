#!/usr/bin/env python3
"""Executable tests for the local, evidence-derived release dashboard."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from unittest import mock

from dashboard import server


CONFIG = Path(__file__).with_name("state.json")
INDEX = Path(__file__).with_name("index.html")
STATIC_INDEX = Path(__file__).with_name("static") / "index.html"
APP_JS = Path(__file__).with_name("static") / "app.js"
DENOMINATOR_CRITICAL_SHELL_COPY = (
    "Chrome and Edge stay distinct. "
    "Android TV AAB remains one of the 16 required upload targets."
)
SYNC = Path(__file__).parents[1] / "tools" / "sync_progress.sh"
NOW = datetime(2026, 8, 23, 13, 30, tzinfo=timezone.utc)
FORBIDDEN_SYNC_COMMAND_RE = re.compile(
    r"(^|[;&|()\s])/?(?:[A-Za-z0-9._-]+/)*(git|curl|wget|ssh|scp)(?=\s|$)",
    flags=re.MULTILINE,
)
REAL_LIVE_CROSS_STORE = server.run_live_cross_store_verification


def _shell_subtitle(html: str) -> str:
    marker = '<div class="subtitle">'
    start = html.index(marker) + len(marker)
    return html[start : html.index("</div>", start)]


class DashboardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.cache_path = self.root / "cross-store-cache.json"
        self.cross_store_verifier = mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=self.verified_cross_store_receipt,
        )
        self.cross_store_verifier.start()
        self.addCleanup(self.cross_store_verifier.stop)

    @staticmethod
    def verified_cross_store_receipt(
        repo_root: Path,
        release_input_index: Path,
        target_id: str,
        receipt_path: Path,
        now: datetime,
    ) -> dict[str, object]:
        del release_input_index
        return {
            "target_id": target_id,
            "receipt": receipt_path.relative_to(repo_root).as_posix(),
            "receipt_schema_version": server.CROSS_STORE_RECEIPT_SCHEMA_VERSION,
            "release": server.RELEASE_IDENTITY,
            "status": "verified",
            "verified_at": server.iso_utc(now),
            "receipt_sha256": hashlib.sha256(
                (target_id + ":receipt").encode("ascii")
            ).hexdigest(),
            "artifact_sha256": hashlib.sha256(
                (target_id + ":artifact").encode("ascii")
            ).hexdigest(),
            "reason": "authoritative schema-v2 receipt verified",
        }

    def artifact(
        self, target: str, name: str, *, modified_at: datetime = NOW
    ) -> dict[str, str]:
        relative = Path(target) / name
        path = self.evidence / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = ("verified " + target + ":" + name + "\n").encode()
        path.write_bytes(payload)
        os.utime(path, (modified_at.timestamp(), modified_at.timestamp()))
        return {
            "root": "evidence",
            "path": relative.as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def check(
        self,
        target: str,
        dimension: str,
        *,
        status: str = "pass",
        observed_at: datetime = NOW,
        artifact: dict[str, str] | None = None,
        producer: str | None = None,
        evidence_type: str | None = None,
    ) -> dict[str, object]:
        contract = server.DIMENSION_EVIDENCE_CONTRACT.get(
            dimension,
            server.BLOCKER_AUDIT_CONTRACT
            if dimension == "blocker_audit"
            else server.OPEN_BLOCKER_CONTRACT,
        )
        return {
            "status": status,
            "observed_at": server.iso_utc(observed_at),
            "producer": producer or contract[1],
            "evidence_type": evidence_type or contract[0],
            "summary_code": dimension + "_evidence",
            "artifacts": [
                artifact
                or self.artifact(
                    target, dimension + ".proof", modified_at=observed_at
                )
            ],
        }

    def receipt(
        self,
        target: str,
        dimensions: dict[str, object],
        *,
        blockers: list[object] | None = None,
        blocker_audit: object | None = None,
        generated_at: datetime = NOW,
        declared_target: str | None = None,
    ) -> None:
        value = {
            "schema_version": 4,
            "release": server.RELEASE_IDENTITY,
            "target": declared_target or target,
            "generated_at": server.iso_utc(generated_at),
            "dimensions": dimensions,
            "blocker_audit": blocker_audit or self.check(target, "blocker_audit"),
            "blockers": [] if blockers is None else blockers,
        }
        path = self.evidence / (target + ".json")
        path.write_text(json.dumps(value), encoding="utf-8")
        os.utime(path, (generated_at.timestamp(), generated_at.timestamp()))

    def all_dimensions(self, target: str, **overrides: object) -> dict[str, object]:
        return {
            dimension["id"]: overrides.get(
                dimension["id"], self.check(target, dimension["id"])
            )
            for dimension in server.load_config(CONFIG)["dimensions"]
        }

    def snapshot(self, now: datetime = NOW) -> dict[str, object]:
        return server.build_snapshot(
            CONFIG,
            self.evidence,
            now,
            repo_root=self.repo,
            cache_path=self.cache_path,
        )

    def target(self, target_id: str) -> dict[str, object]:
        return next(item for item in self.snapshot()["targets"] if item["id"] == target_id)

    def start_http_server(self) -> server.ThreadingHTTPServer:
        original_config = server.DashboardHandler.config_path
        original_evidence = server.DashboardHandler.evidence_root
        original_repo = server.DashboardHandler.repo_root
        original_cache = server.DashboardHandler.cache_path
        server.DashboardHandler.config_path = CONFIG
        server.DashboardHandler.evidence_root = self.evidence
        server.DashboardHandler.repo_root = self.repo
        server.DashboardHandler.cache_path = self.cache_path
        try:
            httpd = server.ThreadingHTTPServer(
                (server.LOCAL_BIND, 0), server.DashboardHandler
            )
        except PermissionError as exc:
            server.DashboardHandler.config_path = original_config
            server.DashboardHandler.evidence_root = original_evidence
            server.DashboardHandler.repo_root = original_repo
            server.DashboardHandler.cache_path = original_cache
            self.skipTest("sandbox disallows local loopback binds: " + str(exc))
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()

        def cleanup() -> None:
            httpd.shutdown()
            httpd.server_close()
            worker.join(timeout=2)
            server.DashboardHandler.config_path = original_config
            server.DashboardHandler.evidence_root = original_evidence
            server.DashboardHandler.repo_root = original_repo
            server.DashboardHandler.cache_path = original_cache

        self.addCleanup(cleanup)
        return httpd

    def http_request(
        self,
        httpd: server.ThreadingHTTPServer,
        method: str,
        target: str,
        *,
        host: str | None = None,
        duplicate_hosts: tuple[str, ...] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection("127.0.0.1", httpd.server_port, timeout=5)
        try:
            if duplicate_hosts is not None:
                connection.putrequest(method, target, skip_host=True)
                for value in duplicate_hosts:
                    connection.putheader("Host", value)
                connection.endheaders()
            else:
                headers = {} if host is None else {"Host": host}
                connection.request(method, target, headers=headers)
            response = connection.getresponse()
            body = response.read()
            headers = {name.lower(): value for name, value in response.getheaders()}
            return response.status, headers, body
        finally:
            connection.close()

    def test_configuration_has_exact_targets_and_five_explicit_dimensions(self) -> None:
        config = server.load_config(CONFIG)
        self.assertEqual(config["schema_version"], 8)
        self.assertEqual(
            {target["id"]: target["label"] for target in config["targets"]},
            server.REQUIRED_TARGETS,
        )
        self.assertEqual(
            {dimension["id"]: dimension["label"] for dimension in config["dimensions"]},
            server.REQUIRED_DIMENSIONS,
        )
        self.assertEqual(sum(item["weight"] for item in config["dimensions"]), 100)
        self.assertEqual(
            config["cross_store"]["receipt_schema_version"],
            server.CROSS_STORE_RECEIPT_SCHEMA_VERSION,
        )
        self.assertEqual(
            config["cross_store"]["required_upload_targets"],
            list(server.REQUIRED_UPLOAD_TARGET_IDS),
        )
        mapped = {
            upload_target
            for target in config["targets"]
            for upload_target in target["upload_targets"]
        }
        self.assertEqual(mapped, set(server.REQUIRED_UPLOAD_TARGET_IDS))
        self.assertEqual(len(mapped), 16)
        self.assertFalse(any("tvos" in target for target in mapped))
        self.assertEqual(
            server.DASHBOARD_UPLOAD_TARGET_MAP["ios"],
            ("ios-app-store-ipa",),
        )
        self.assertEqual(
            server.DASHBOARD_UPLOAD_TARGET_MAP["apple-watch-watchos"],
            ("ios-app-store-ipa",),
        )
        self.assertEqual(
            server.DASHBOARD_UPLOAD_TARGET_MAP["macos-x86"],
            ("macos-app-store-pkg",),
        )
        self.assertEqual(
            server.DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP["macos-x86"],
            ("macos-developer-id-app",),
        )
        self.assertNotIn(
            "macos-developer-id-app",
            server.DASHBOARD_UPLOAD_TARGET_MAP["macos-arm64"],
        )

    def test_snapshot_binds_the_validated_target_contract(self) -> None:
        config = server.load_config(CONFIG)
        snapshot = self.snapshot()
        self.assertEqual(snapshot["schema_version"], 8)
        self.assertEqual(snapshot["receipt_schema_version"], 4)
        self.assertEqual(snapshot["cross_store_receipt_schema_version"], 2)
        self.assertEqual(snapshot["release"], server.RELEASE_IDENTITY)
        self.assertGreater(
            server.parse_utc(snapshot["snapshot_expires_at"], "snapshot_expires_at"),
            server.parse_utc(snapshot["generated_at"], "generated_at"),
        )
        self.assertEqual(
            snapshot["contract_sha256"], server.config_contract_sha256(config)
        )
        self.assertEqual(snapshot["target_count"], len(server.REQUIRED_TARGETS))
        self.assertEqual(
            snapshot["cross_store"]["required_upload_targets"],
            list(server.REQUIRED_UPLOAD_TARGET_IDS),
        )
        self.assertEqual(snapshot["cross_store"]["required_upload_target_count"], 16)
        self.assertEqual(snapshot["cross_store"]["status_counts"]["verified"], 16)
        self.assertEqual(snapshot["cross_store"]["status_counts"]["unavailable"], 0)
        self.assertEqual(len(snapshot["cross_store"]["receipts"]), 16)
        self.assertEqual(snapshot["cross_store"]["optional_upload_target_count"], 1)
        self.assertEqual(snapshot["cross_store"]["optional_upload_targets"], ["macos-developer-id-app"])
        self.assertEqual(snapshot["cross_store"]["optional_status_counts"]["verified"], 1)
        self.assertEqual(snapshot["cross_store"]["optional_status_counts"]["unavailable"], 0)
        for target in snapshot["targets"]:
            self.assertEqual(
                [receipt["target_id"] for receipt in target["cross_store_receipts"]],
                target["upload_targets"],
            )
            self.assertEqual(
                [
                    receipt["target_id"]
                    for receipt in target["optional_cross_store_receipts"]
                ],
                target["optional_upload_targets"],
            )

    def test_failure_snapshot_withholds_all_evidence_and_readiness(self) -> None:
        snapshot = server.build_failure_snapshot(NOW)
        self.assertEqual(snapshot["source"], "invalid-local-evidence")
        self.assertIsNone(snapshot["contract_sha256"])
        self.assertEqual(snapshot["overall_readiness"], 0)
        self.assertEqual(snapshot["overall_technical_readiness"], 0)
        self.assertEqual(snapshot["overall_engineering_readiness"], 0)
        self.assertEqual(snapshot["overall_store_evidence_readiness"], 0)
        self.assertEqual(snapshot["ready_targets"], 0)
        self.assertEqual(snapshot["target_count"], len(server.REQUIRED_TARGETS))
        coverage = snapshot["coverage"]
        self.assertEqual(coverage["scored_targets"]["required"], 20)
        self.assertEqual(coverage["scored_targets"]["unavailable"], 20)
        self.assertEqual(coverage["scored_targets"]["pending"], 0)
        self.assertEqual(coverage["scored_targets"]["ready"], 0)
        self.assertEqual(coverage["engineering"]["percent"], 0)
        self.assertEqual(coverage["store_upload"]["required_receipts"], 16)
        self.assertEqual(coverage["store_upload"]["verified"], 0)
        self.assertEqual(coverage["store_upload"]["unavailable"], 16)
        self.assertEqual(coverage["store_upload"]["percent"], 0)
        self.assertEqual(snapshot["freshness"]["max_age_seconds"], 0)
        self.assertEqual(snapshot["freshness"]["stale_upload_receipts"], 0)
        posture = snapshot["current_posture"]
        self.assertEqual(posture["publication_hold"], "DO-NOT-UPLOAD")
        self.assertFalse(posture["store_upload_authorized"])
        self.assertEqual(posture["upload_receipts"]["verified"], 0)
        self.assertEqual(posture["upload_receipts"]["required"], 16)
        self.assertEqual(posture["upload_receipts"]["status"], "unavailable")
        self.assertFalse(posture["gcp_proof"]["fresh"])
        self.assertEqual(posture["gcp_proof"]["status"], "unavailable")
        self.assertIn("no valid fresh GCP proof", posture["gcp_proof"]["reason"])
        self.assertEqual(posture["agp_migration"]["status"], "in_progress")
        self.assertEqual(
            posture["macos_release_python"]["status"], "owner_prompt_pending"
        )
        category_ids = [item["id"] for item in posture["active_blocker_categories"]]
        self.assertEqual(category_ids[0], "publication_hold")
        self.assertIn("missing_upload_receipts", category_ids)
        self.assertIn("gcp_proof", category_ids)
        self.assertIn("agp_migration", category_ids)
        self.assertIn("macos_release_python", category_ids)
        self.assertTrue(
            all(
                item["status"] == "unavailable"
                and item["last_evidence_at"] is None
                and item["dimensions"] == []
                and item["blocker_audit"]["status"] == "unavailable"
                and item["blockers"] == []
                for item in snapshot["targets"]
            )
        )
        self.assertEqual(snapshot["cross_store"]["required_upload_target_count"], 16)
        self.assertEqual(
            snapshot["cross_store"]["status_counts"],
            {
                "verified": 0,
                "missing": 0,
                "invalid": 0,
                "stale": 0,
                "unavailable": 16,
            },
        )
        self.assertEqual(
            snapshot["cross_store"]["optional_status_counts"],
            {
                "verified": 0,
                "missing": 0,
                "invalid": 0,
                "stale": 0,
                "unavailable": 1,
            },
        )
        self.assertTrue(
            all(
                receipt["status"] == "unavailable"
                for receipt in snapshot["cross_store"]["receipts"]
            )
        )
        self.assertEqual(
            sum(snapshot["cross_store"]["status_counts"].values()),
            len(snapshot["cross_store"]["receipts"]),
        )
        self.assertEqual(snapshot["cross_store"]["optional_upload_targets"], ["macos-developer-id-app"])
        macos = next(item for item in snapshot["targets"] if item["id"] == "macos-x86")
        self.assertEqual(macos["upload_targets"], ["macos-app-store-pkg"])
        self.assertEqual(macos["optional_upload_targets"], ["macos-developer-id-app"])
        self.assertEqual(macos["optional_cross_store_status"], "unavailable")
        self.assertEqual(
            macos["optional_cross_store_receipts"][0]["status"], "unavailable"
        )

    def test_missing_receipts_withhold_all_store_and_technical_progress(self) -> None:
        snapshot = self.snapshot()
        self.assertEqual(snapshot["overall_readiness"], 0)
        self.assertEqual(snapshot["overall_technical_readiness"], 0)
        self.assertEqual(snapshot["overall_engineering_readiness"], 0)
        self.assertEqual(snapshot["overall_store_evidence_readiness"], 0)
        self.assertEqual(snapshot["ready_targets"], 0)
        self.assertTrue(all(item["status"] == "unverified" for item in snapshot["targets"]))
        coverage = snapshot["coverage"]
        self.assertEqual(coverage["scored_targets"]["required"], 20)
        self.assertEqual(coverage["scored_targets"]["pending"], 20)
        self.assertEqual(coverage["scored_targets"]["failed"], 0)
        self.assertEqual(coverage["scored_targets"]["ready"], 0)
        self.assertEqual(coverage["engineering"]["pending_targets"], 20)
        self.assertEqual(coverage["engineering"]["failed_targets"], 0)
        self.assertEqual(coverage["engineering"]["verified_dimensions"], 0)
        self.assertEqual(coverage["engineering"]["percent"], 0)
        self.assertEqual(coverage["store_upload"]["required_receipts"], 16)
        self.assertNotEqual(coverage["engineering"]["percent"], 100)
        self.assertNotEqual(snapshot["overall_readiness"], 100)
        posture = snapshot["current_posture"]
        self.assertEqual(posture["publication_hold"], "DO-NOT-UPLOAD")
        self.assertFalse(posture["store_upload_authorized"])
        self.assertEqual(posture["upload_receipts"]["required"], 16)
        self.assertEqual(posture["gcp_proof"]["status"], "missing")
        self.assertEqual(posture["agp_migration"]["status"], "in_progress")
        self.assertEqual(
            posture["macos_release_python"]["status"], "owner_prompt_pending"
        )

    def test_synthetic_chrome_dashboard_receipt_cannot_hide_missing_upload_receipts(
        self,
    ) -> None:
        self.receipt(
            "chrome-extension",
            self.all_dimensions("chrome-extension"),
        )

        def missing_mapped_receipts(
            repo_root: Path,
            release_input_index: Path,
            target_id: str,
            receipt_path: Path,
            now: datetime,
        ) -> dict[str, object]:
            if target_id in {"chrome-extension-package", "edge-extension-package"}:
                raise server.CrossStoreReceiptMissing(
                    f"required {target_id} schema-v2 receipt is missing"
                )
            return self.verified_cross_store_receipt(
                repo_root, release_input_index, target_id, receipt_path, now
            )

        with mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=missing_mapped_receipts,
        ):
            snapshot = self.snapshot()
        target = next(
            item for item in snapshot["targets"] if item["id"] == "chrome-extension"
        )
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")
        self.assertEqual(target["cross_store_status"], "missing")
        self.assertEqual(
            [receipt["status"] for receipt in target["cross_store_receipts"]],
            ["missing", "missing"],
        )
        self.assertEqual(snapshot["cross_store"]["status_counts"]["missing"], 2)
        self.assertEqual(snapshot["ready_targets"], 0)

    def test_partial_cross_store_mapping_cannot_produce_ready_or_store_credit(
        self,
    ) -> None:
        self.receipt(
            "chrome-extension",
            self.all_dimensions("chrome-extension"),
        )

        def missing_edge_only(
            repo_root: Path,
            release_input_index: Path,
            target_id: str,
            receipt_path: Path,
            now: datetime,
        ) -> dict[str, object]:
            if target_id == "edge-extension-package":
                raise server.CrossStoreReceiptMissing(
                    "required edge-extension-package schema-v2 receipt is missing"
                )
            return self.verified_cross_store_receipt(
                repo_root, release_input_index, target_id, receipt_path, now
            )

        with mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=missing_edge_only,
        ):
            target = self.target("chrome-extension")
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["status"], "partial")
        self.assertEqual(target["cross_store_status"], "partial")
        self.assertEqual(
            [receipt["status"] for receipt in target["cross_store_receipts"]],
            ["verified", "missing"],
        )

    def test_optional_macos_developer_id_never_gates_app_store_readiness(self) -> None:
        for dashboard_target in ("macos-x86", "macos-arm64"):
            self.receipt(
                dashboard_target,
                self.all_dimensions(dashboard_target),
            )
        optional_cases = ("missing", "invalid", "stale")
        for optional_status in optional_cases:
            with self.subTest(optional_status=optional_status):
                def optional_developer_id_result(
                    repo_root: Path,
                    release_input_index: Path,
                    target_id: str,
                    receipt_path: Path,
                    now: datetime,
                ) -> dict[str, object]:
                    if target_id == "macos-developer-id-app":
                        if optional_status == "missing":
                            raise server.CrossStoreReceiptMissing(
                                "optional macos-developer-id-app receipt is missing"
                            )
                        if optional_status == "invalid":
                            raise server.DashboardError(
                                "optional macos-developer-id-app receipt is invalid"
                            )
                        result = self.verified_cross_store_receipt(
                            repo_root,
                            release_input_index,
                            target_id,
                            receipt_path,
                            now,
                        )
                        result["verified_at"] = server.iso_utc(
                            NOW - timedelta(days=2)
                        )
                        return result
                    return self.verified_cross_store_receipt(
                        repo_root,
                        release_input_index,
                        target_id,
                        receipt_path,
                        now,
                    )

                with mock.patch.object(
                    server,
                    "verify_cross_store_upload_receipt",
                    side_effect=optional_developer_id_result,
                ):
                    snapshot = self.snapshot()
                for dashboard_target in ("macos-x86", "macos-arm64"):
                    target = next(
                        item
                        for item in snapshot["targets"]
                        if item["id"] == dashboard_target
                    )
                    self.assertEqual(target["upload_targets"], ["macos-app-store-pkg"])
                    self.assertEqual(
                        target["optional_upload_targets"],
                        ["macos-developer-id-app"],
                    )
                    self.assertEqual(target["cross_store_status"], "verified")
                    self.assertEqual(
                        target["optional_cross_store_status"], optional_status
                    )
                    self.assertEqual(target["technical_readiness"], 100)
                    self.assertEqual(target["readiness"], 100)
                    self.assertEqual(target["status"], "ready")
                self.assertEqual(
                    snapshot["cross_store"]["status_counts"],
                    {
                        "verified": 16,
                        "missing": 0,
                        "invalid": 0,
                        "stale": 0,
                        "unavailable": 0,
                    },
                )
                self.assertEqual(
                    snapshot["cross_store"]["optional_status_counts"][
                        optional_status
                    ],
                    1,
                )

    def test_required_macos_app_store_pkg_still_gates_ready(self) -> None:
        self.receipt("macos-x86", self.all_dimensions("macos-x86"))

        def missing_required_pkg(
            repo_root: Path,
            release_input_index: Path,
            target_id: str,
            receipt_path: Path,
            now: datetime,
        ) -> dict[str, object]:
            if target_id == "macos-app-store-pkg":
                raise server.CrossStoreReceiptMissing(
                    "required macos-app-store-pkg schema-v2 receipt is missing"
                )
            return self.verified_cross_store_receipt(
                repo_root, release_input_index, target_id, receipt_path, now
            )

        with mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=missing_required_pkg,
        ):
            target = self.target("macos-x86")
        self.assertEqual(target["optional_cross_store_status"], "verified")
        self.assertEqual(target["cross_store_status"], "missing")
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")

    def test_cross_store_receipt_older_than_dashboard_window_is_stale(self) -> None:
        self.receipt(
            "chrome-extension",
            self.all_dimensions("chrome-extension"),
        )

        def old_chrome_receipt(
            repo_root: Path,
            release_input_index: Path,
            target_id: str,
            receipt_path: Path,
            now: datetime,
        ) -> dict[str, object]:
            result = self.verified_cross_store_receipt(
                repo_root, release_input_index, target_id, receipt_path, now
            )
            if target_id == "chrome-extension-package":
                result["verified_at"] = server.iso_utc(NOW - timedelta(days=2))
            return result

        with mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=old_chrome_receipt,
        ):
            target = self.target("chrome-extension")
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["status"], "stale")
        self.assertEqual(target["cross_store_status"], "stale")
        self.assertEqual(target["cross_store_receipts"][0]["status"], "stale")
        self.assertIn(
            "dashboard freshness window",
            target["cross_store_receipts"][0]["reason"],
        )

    def test_stale_or_substituted_cross_store_receipt_fails_closed(self) -> None:
        self.receipt(
            "chrome-extension",
            self.all_dimensions("chrome-extension"),
        )
        failures = {
            "stale": "chrome-extension-package receipt is stale or future-dated",
            "target-substitution": "target_id binding is invalid",
            "release-substitution": "receipt release 1.0.14+29 does not match 1.0.17+34",
        }
        for case, reason in failures.items():
            with self.subTest(case=case):
                def reject_chrome(
                    repo_root: Path,
                    release_input_index: Path,
                    target_id: str,
                    receipt_path: Path,
                    now: datetime,
                ) -> dict[str, object]:
                    if target_id == "chrome-extension-package":
                        raise server.DashboardError(reason)
                    return self.verified_cross_store_receipt(
                        repo_root,
                        release_input_index,
                        target_id,
                        receipt_path,
                        now,
                    )

                with mock.patch.object(
                    server,
                    "verify_cross_store_upload_receipt",
                    side_effect=reject_chrome,
                ):
                    target = self.target("chrome-extension")
                self.assertEqual(target["technical_readiness"], 100)
                self.assertEqual(target["readiness"], 0)
                self.assertEqual(target["status"], "invalid")
                self.assertEqual(target["cross_store_status"], "invalid")
                self.assertEqual(target["cross_store_receipts"][0]["status"], "invalid")
                self.assertIn(reason, target["cross_store_receipts"][0]["reason"])

    def test_config_rejects_upload_mapping_matrix_or_path_substitution(self) -> None:
        original = json.loads(CONFIG.read_text(encoding="utf-8"))
        mutations = []
        missing_edge = json.loads(json.dumps(original))
        chrome = next(
            target
            for target in missing_edge["targets"]
            if target["id"] == "chrome-extension"
        )
        chrome["upload_targets"] = ["chrome-extension-package"]
        mutations.append(missing_edge)
        developer_id_required = json.loads(json.dumps(original))
        macos = next(
            target
            for target in developer_id_required["targets"]
            if target["id"] == "macos-x86"
        )
        macos["upload_targets"].append("macos-developer-id-app")
        mutations.append(developer_id_required)
        tvos = json.loads(json.dumps(original))
        tvos["cross_store"]["required_upload_targets"][-1] = "tvos-app-store-ipa"
        mutations.append(tvos)
        stale_release = json.loads(json.dumps(original))
        stale_release["release"] = "1.0.14+29"
        mutations.append(stale_release)
        escaped_index = json.loads(json.dumps(original))
        escaped_index["cross_store"]["release_input_index"] = "../RELEASE_INPUT_INDEX.json"
        mutations.append(escaped_index)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(server.DashboardError):
                    server.validate_config(mutation)

    def test_cross_store_wrapper_binds_authoritative_result_to_release_and_path(
        self,
    ) -> None:
        repo = self.root / "repo"
        receipt = repo / ".artifacts/upload-receipts/chrome-extension-package.json"
        receipt.parent.mkdir(parents=True)
        receipt.write_text("{}\n", encoding="utf-8")
        index = repo / ".artifacts/release-inputs/RELEASE_INPUT_INDEX.json"
        evidence_dir = repo / ".artifacts/dashboard/cross-store-gate-tmp/chrome-extension-package"
        expected = {
            "receipt_path": receipt.relative_to(repo).as_posix(),
            "receipt_sha256": "a" * 64,
            "release": server.RELEASE_IDENTITY,
            "artifact": {"sha256": "b" * 64},
            "verified_utc": server.iso_utc(NOW),
        }
        verifier = mock.Mock()
        verifier.verify_target_receipt_current.return_value = expected
        with mock.patch.object(
            server, "_load_cross_store_module", return_value=verifier
        ):
            result = REAL_LIVE_CROSS_STORE(
                repo,
                index,
                "chrome-extension-package",
                receipt,
                NOW,
                evidence_dir,
            )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["release"], server.RELEASE_IDENTITY)
        self.assertEqual(result["receipt"], expected["receipt_path"])
        verifier.verify_target_receipt_current.assert_called_once_with(
            repo,
            index,
            "chrome-extension-package",
            receipt,
            now=NOW,
            evidence_dir=evidence_dir,
        )

        substitutions = {
            "release": {**expected, "release": "1.0.14+29"},
            "target-path": {
                **expected,
                "receipt_path": ".artifacts/upload-receipts/edge-extension-package.json",
            },
            "receipt-hash": {**expected, "receipt_sha256": "not-a-hash"},
            "artifact-hash": {**expected, "artifact": {"sha256": "not-a-hash"}},
        }
        for case, substituted in substitutions.items():
            with self.subTest(case=case):
                verifier = mock.Mock()
                verifier.verify_target_receipt_current.return_value = substituted
                with mock.patch.object(
                    server, "_load_cross_store_module", return_value=verifier
                ):
                    with self.assertRaisesRegex(
                        server.DashboardError, "canonical release"
                    ):
                        REAL_LIVE_CROSS_STORE(
                            repo,
                            index,
                            "chrome-extension-package",
                            receipt,
                            NOW,
                            evidence_dir,
                        )

    def test_dashboard_rejects_forged_stored_gate_evidence_for_non_zip_aab(
        self,
    ) -> None:
        repo = self.root / "repo"
        receipt = (
            repo
            / ".artifacts/upload-receipts/android-phone-tablet-aab.json"
        )
        receipt.parent.mkdir(parents=True)
        receipt.write_text(
            '{"stored_gate_status":"passed","artifact":"not-a-zip"}\n',
            encoding="utf-8",
        )
        index = repo / ".artifacts/release-inputs/RELEASE_INPUT_INDEX.json"
        evidence_dir = (
            repo / ".artifacts/dashboard/cross-store-gate-tmp/android-phone-tablet-aab"
        )
        verifier = mock.Mock()
        verifier.verify_target_receipt_current.side_effect = RuntimeError(
            "ANDROID AAB SIGNER: FAIL: invalid AAB ZIP archive"
        )
        with mock.patch.object(
            server, "_load_cross_store_module", return_value=verifier
        ):
            with self.assertRaisesRegex(server.DashboardError, "invalid AAB ZIP"):
                REAL_LIVE_CROSS_STORE(
                    repo,
                    index,
                    "android-phone-tablet-aab",
                    receipt,
                    NOW,
                    evidence_dir,
                )
        verifier.verify_target_receipt_current.assert_called_once_with(
            repo,
            index,
            "android-phone-tablet-aab",
            receipt,
            now=NOW,
            evidence_dir=evidence_dir,
        )

    def test_stale_release_receipt_fails_closed(self) -> None:
        self.receipt("android", self.all_dimensions("android"))
        path = self.evidence / "android.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["release"] = "1.0.14+29"
        path.write_text(json.dumps(value), encoding="utf-8")
        os.utime(path, (NOW.timestamp(), NOW.timestamp()))
        target = self.target("android")
        self.assertEqual(target["status"], "invalid")
        self.assertIn("receipt release does not match", target["dimensions"][0]["reason"])

    def test_each_receipt_must_cover_every_dimension_and_blocker_disclosure(self) -> None:
        self.receipt("windows-x86", {"engineering": self.check("windows-x86", "engineering")})
        target = self.target("windows-x86")
        self.assertEqual(target["status"], "invalid")
        self.assertTrue(all(item["status"] == "invalid" for item in target["dimensions"]))
        self.assertIn("dimension set mismatch", target["dimensions"][0]["reason"])

    def test_all_fresh_categories_with_verified_upload_receipts_is_store_ready(self) -> None:
        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        target = self.target("windows-x86")
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["engineering_readiness"], 40)
        self.assertEqual(target["store_evidence_readiness"], 60)
        self.assertEqual(target["readiness"], 100)
        self.assertEqual(target["status"], "ready")
        self.assertEqual(target["cross_store_status"], "verified")
        self.assertEqual(target["blockers"], [])

    def test_partial_categories_show_technical_progress_but_not_ready(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        dimensions["signing"] = self.check("windows-x86", "signing", status="fail")
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertEqual(target["technical_readiness"], 80)
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["status"], "blocked")
        self.assertEqual(target["engineering_readiness"], 40)
        self.assertEqual(target["store_evidence_readiness"], 40)

    def test_open_owner_blocker_zeroes_store_readiness_not_technical_evidence(self) -> None:
        blocker = self.check("windows-x86", "owner_signing", artifact=self.artifact("windows-x86", "owner.proof"))
        blocker.update({"id": "authenticode_identity", "kind": "owner"})
        self.receipt("windows-x86", self.all_dimensions("windows-x86"), blockers=[blocker])
        target = self.target("windows-x86")
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["status"], "blocked")
        self.assertEqual(target["blockers"][0]["status"], "open")
        self.assertEqual(target["blockers"][0]["kind"], "owner")

    def test_untrusted_owner_blocker_states_zero_store_not_technical_readiness(self) -> None:
        cases = (
            ("stale", "pass", NOW - timedelta(days=8)),
            ("failed", "fail", NOW),
            ("invalid", "unknown", NOW),
        )
        for expected_status, check_status, observed_at in cases:
            with self.subTest(expected_status=expected_status):
                blocker = self.check(
                    "windows-x86",
                    "owner_signing",
                    status=check_status,
                    observed_at=observed_at,
                    artifact=self.artifact(
                        "windows-x86",
                        "owner-" + expected_status + ".proof",
                        modified_at=observed_at,
                    ),
                )
                blocker.update(
                    {"id": "authenticode_" + expected_status, "kind": "owner"}
                )
                self.receipt(
                    "windows-x86",
                    self.all_dimensions("windows-x86"),
                    blockers=[blocker],
                )
                target = self.target("windows-x86")
                self.assertEqual(target["technical_readiness"], 100)
                self.assertEqual(target["readiness"], 0)
                self.assertEqual(target["status"], "blocked")
                self.assertEqual(target["blockers"][0]["status"], expected_status)

    def test_external_blocker_is_distinct_from_owner_blocker(self) -> None:
        blocker = self.check("android", "store_review", artifact=self.artifact("android", "review.proof"))
        blocker.update({"id": "play_review_pending", "kind": "external"})
        self.receipt("android", self.all_dimensions("android"), blockers=[blocker])
        target = self.target("android")
        self.assertEqual(target["blockers"][0]["kind"], "external")
        self.assertEqual(target["blockers"][0]["status"], "open")

    def test_hash_mismatch_and_stale_evidence_fail_closed(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        artifact = self.artifact("windows-x86", "bad.proof")
        artifact["sha256"] = "0" * 64
        dimensions["artifact"] = self.check("windows-x86", "artifact", artifact=artifact)
        dimensions["runtime_proof"] = self.check(
            "windows-x86", "runtime_proof", observed_at=NOW - timedelta(days=8)
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        by_id = {item["id"]: item for item in target["dimensions"]}
        self.assertEqual(by_id["artifact"]["status"], "invalid")
        self.assertEqual(by_id["runtime_proof"]["status"], "stale")
        self.assertEqual(target["technical_readiness"], 60)
        self.assertEqual(target["status"], "invalid")

    def test_fresh_receipt_cannot_retimestamp_stale_or_changed_artifacts(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        stale_artifact = self.artifact(
            "windows-x86",
            "old-package.proof",
            modified_at=NOW - timedelta(days=2),
        )
        dimensions["artifact"] = self.check(
            "windows-x86", "artifact", artifact=stale_artifact
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        by_id = {item["id"]: item for item in target["dimensions"]}
        self.assertEqual(by_id["artifact"]["status"], "stale")
        self.assertEqual(target["technical_readiness"], 80)

        dimensions = self.all_dimensions("windows-x86")
        changed_after_observation = self.artifact(
            "windows-x86",
            "changed-after-check.proof",
            modified_at=NOW,
        )
        dimensions["artifact"] = self.check(
            "windows-x86",
            "artifact",
            observed_at=NOW - timedelta(minutes=10),
            artifact=changed_after_observation,
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        by_id = {item["id"]: item for item in target["dimensions"]}
        self.assertEqual(by_id["artifact"]["status"], "invalid")
        self.assertIn("changed after", by_id["artifact"]["reason"])
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["store_evidence_readiness"], 40)

    def test_fresh_blocker_audit_is_required_for_any_store_readiness(self) -> None:
        self.receipt(
            "windows-x86",
            self.all_dimensions("windows-x86"),
            blocker_audit=self.check(
                "windows-x86", "blocker_audit", status="fail"
            ),
        )
        target = self.target("windows-x86")
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["status"], "blocked")

        self.receipt(
            "windows-x86",
            self.all_dimensions("windows-x86"),
            blocker_audit=self.check(
                "windows-x86",
                "blocker_audit",
                observed_at=NOW - timedelta(days=2),
            ),
        )
        target = self.target("windows-x86")
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["status"], "stale")

        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        receipt_path = self.evidence / "windows-x86.json"
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
        del value["blocker_audit"]
        receipt_path.write_text(json.dumps(value), encoding="utf-8")
        os.utime(receipt_path, (NOW.timestamp(), NOW.timestamp()))
        target = self.target("windows-x86")
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["status"], "invalid")
        self.assertIn("missing blocker_audit", target["blocker_audit"]["reason"])

    def test_dimension_type_and_dedicated_producer_contract_prevent_generic_credit(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        dimensions["signing"] = self.check(
            "windows-x86",
            "signing",
            producer="engineering_gate",
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        signing = next(item for item in target["dimensions"] if item["id"] == "signing")
        self.assertEqual(signing["status"], "invalid")
        self.assertIn("producer must be signature_gate", signing["reason"])

        dimensions = self.all_dimensions("windows-x86")
        dimensions["store_metadata"] = self.check(
            "windows-x86",
            "store_metadata",
            evidence_type="engineering_verification",
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        metadata = next(
            item for item in target["dimensions"] if item["id"] == "store_metadata"
        )
        self.assertEqual(metadata["status"], "invalid")
        self.assertIn("evidence_type must be store_metadata_verification", metadata["reason"])

    def test_receipt_file_time_and_local_write_trust_fail_closed(self) -> None:
        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        receipt_path = self.evidence / "windows-x86.json"
        mismatched = NOW - timedelta(minutes=10)
        os.utime(receipt_path, (mismatched.timestamp(), mismatched.timestamp()))
        target = self.target("windows-x86")
        self.assertEqual(target["status"], "invalid")
        self.assertIn("file time does not match", target["blocker_audit"]["reason"])

        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        artifact_path = self.evidence / "windows-x86" / "engineering.proof"
        artifact_path.chmod(0o666)
        target = self.target("windows-x86")
        engineering = next(
            item for item in target["dimensions"] if item["id"] == "engineering"
        )
        self.assertEqual(engineering["status"], "invalid")
        self.assertIn("group- or other-writable", engineering["reason"])

    def test_handoff_and_sensitive_artifact_paths_are_not_evidence(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        handoff = self.artifact("handoff", "claimed.proof")
        dimensions["engineering"] = self.check("windows-x86", "engineering", artifact=handoff)
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertEqual(target["dimensions"][0]["status"], "invalid")
        self.assertIn("not release evidence", target["dimensions"][0]["reason"])
        secret = self.artifact("windows-x86", "secret-token.proof")
        dimensions = self.all_dimensions("windows-x86")
        dimensions["artifact"] = self.check("windows-x86", "artifact", artifact=secret)
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertIn("sensitive", target["dimensions"][1]["reason"])

    def test_artifacts_reject_final_intermediate_and_root_symlinks(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        handoff = self.artifact("handoff", "symlink-claimed.proof")
        final_link = self.evidence / "windows-x86" / "safe-evidence.proof"
        final_link.symlink_to(self.evidence / handoff["path"])
        dimensions["engineering"] = self.check(
            "windows-x86",
            "engineering",
            artifact={**handoff, "path": "windows-x86/safe-evidence.proof"},
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertEqual(target["dimensions"][0]["status"], "invalid")
        self.assertIn("symbolic link", target["dimensions"][0]["reason"])
        self.assertNotEqual(target["status"], "ready")

        real_directory = self.evidence / "verified-storage"
        real_directory.mkdir()
        payload = b"intermediate symlink evidence\n"
        (real_directory / "proof.txt").write_bytes(payload)
        directory_link = self.evidence / "windows-x86" / "linked-directory"
        directory_link.symlink_to(real_directory, target_is_directory=True)
        dimensions = self.all_dimensions("windows-x86")
        dimensions["engineering"] = self.check(
            "windows-x86",
            "engineering",
            artifact={
                "root": "evidence",
                "path": "windows-x86/linked-directory/proof.txt",
                "sha256": hashlib.sha256(payload).hexdigest(),
            },
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertEqual(target["dimensions"][0]["status"], "invalid")
        self.assertIn("symbolic link", target["dimensions"][0]["reason"])

        root_link = self.root / "evidence-root-link"
        root_link.symlink_to(self.evidence, target_is_directory=True)
        regular_artifact = self.artifact("windows-x86", "root-link.proof")
        with self.assertRaisesRegex(server.DashboardError, "root must not be a symbolic link"):
            server.validate_artifact(regular_artifact, root_link)

    def test_receipt_symlink_and_target_mismatch_are_rejected(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        (self.evidence / "windows-x86.json").symlink_to(outside)
        target = self.target("windows-x86")
        self.assertEqual(target["status"], "invalid")
        self.assertIn("symbolic link", target["dimensions"][0]["reason"])
        (self.evidence / "windows-x86.json").unlink()
        self.receipt("windows-x86", self.all_dimensions("windows-x86"), declared_target="android")
        target = self.target("windows-x86")
        self.assertEqual(target["status"], "invalid")
        self.assertIn("does not match", target["dimensions"][0]["reason"])

    def test_unknown_receipt_fields_are_rejected_before_they_can_be_rendered(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        dimensions["engineering"]["secret"] = "not-renderable"
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertEqual(target["status"], "invalid")
        self.assertIn("check fields are invalid", target["dimensions"][0]["reason"])

    def test_producer_is_a_small_non_secret_identifier_and_invalid_values_do_not_render(self) -> None:
        invalid_producers = (
            "/Users/alice/release gate",
            "release gate",
            "release.gate",
            "release-gate",
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
            "AICORE",
            "a" * 33,
            "syntactically_valid_but_wrong",
        )
        for producer in invalid_producers:
            with self.subTest(producer=producer):
                dimensions = self.all_dimensions("windows-x86")
                dimensions["engineering"] = self.check(
                    "windows-x86", "engineering", producer=producer
                )
                self.receipt("windows-x86", dimensions)
                target = self.target("windows-x86")
                self.assertEqual(target["dimensions"][0]["status"], "invalid")
                self.assertIsNone(target["dimensions"][0]["producer"])
                self.assertNotIn(producer, json.dumps(target))

        dimensions = self.all_dimensions("windows-x86")
        dimensions["engineering"] = self.check(
            "windows-x86", "engineering", producer="engineering_gate"
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertEqual(target["dimensions"][0]["status"], "verified")
        self.assertEqual(target["dimensions"][0]["producer"], "engineering_gate")

    def test_snapshot_is_private_atomic_and_does_not_disclose_absolute_evidence_path(self) -> None:
        output = self.root / "output" / "state.json"
        snapshot = self.snapshot()
        server.write_json_atomic(output, snapshot)
        value = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(value["evidence_directory"], "local hash-verified evidence")
        self.assertNotIn(str(self.evidence), output.read_text(encoding="utf-8"))
        self.assertFalse(list(output.parent.glob(".*.tmp")))

    def test_snapshot_remains_atomic_and_private_under_concurrent_writers(self) -> None:
        output = self.root / "concurrent" / "state.json"
        errors: list[Exception] = []

        def writer(writer_id: int) -> None:
            try:
                for sequence in range(5):
                    server.write_json_atomic(
                        output, {"writer": writer_id, "sequence": sequence}
                    )
            except Exception as exc:
                errors.append(exc)

        workers = [threading.Thread(target=writer, args=(index,)) for index in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        self.assertEqual(errors, [])
        self.assertEqual(set(json.loads(output.read_text(encoding="utf-8"))), {"writer", "sequence"})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(output.parent.glob(".*.tmp")))

    def test_server_is_loopback_only_and_disallows_bind_override(self) -> None:
        self.assertEqual(server.LOCAL_BIND, "127.0.0.1")
        self.assertNotIn("bind", vars(server.parse_args([])))
        self.assertNotIn("0.0.0.0", Path(server.__file__).read_text(encoding="utf-8"))

    def test_live_loopback_api_has_no_store_and_security_headers(self) -> None:
        httpd = self.start_http_server()
        status, headers, body = self.http_request(httpd, "GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store, max-age=0")
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertIn("default-src 'self'", headers["content-security-policy"])
        payload = json.loads(body)
        self.assertTrue(payload["local_only"])
        self.assertEqual(payload["source"], "verified-local-evidence")
        self.assertEqual(payload["overall_readiness"], 0)
        self.assertEqual(payload["current_posture"]["publication_hold"], "DO-NOT-UPLOAD")
        self.assertEqual(payload["current_posture"]["upload_receipts"]["required"], 16)
        self.assertFalse(payload["current_posture"]["gcp_proof"]["fresh"])

    def test_host_allowlist_and_origin_form_are_enforced(self) -> None:
        httpd = self.start_http_server()
        port = httpd.server_port
        for host in (
            "localhost",
            "127.0.0.1",
            "LOCALHOST",
            f"localhost:{port}",
            f"127.0.0.1:{port}",
        ):
            with self.subTest(allowed_host=host):
                status, _, _ = self.http_request(
                    httpd, "GET", "/api/state", host=host
                )
                self.assertEqual(status, 200)

        wrong_port = port + 1 if port < 65535 else port - 1
        for host in (
            "attacker.example",
            "localhost.",
            f"localhost:{wrong_port}",
            "127.0.0.1:4210" if port != 4210 else "127.0.0.1:4211",
        ):
            with self.subTest(rejected_host=host):
                status, headers, body = self.http_request(
                    httpd, "GET", "/api/state", host=host
                )
                self.assertEqual(status, 400)
                self.assertEqual(body, b"invalid host\n")
                self.assertEqual(headers["cache-control"], "no-store, max-age=0")
                self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
                self.assertEqual(headers["x-content-type-options"], "nosniff")

        status, _, _ = self.http_request(
            httpd,
            "GET",
            "/api/state",
            duplicate_hosts=("localhost", f"127.0.0.1:{port}"),
        )
        self.assertEqual(status, 400)
        status, _, _ = self.http_request(
            httpd, "GET", "/api/state", duplicate_hosts=()
        )
        self.assertEqual(status, 400)

        status, headers, body = self.http_request(
            httpd,
            "GET",
            f"http://127.0.0.1:{port}/api/state",
            host=f"127.0.0.1:{port}",
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, b"invalid request target\n")
        self.assertEqual(headers["cache-control"], "no-store, max-age=0")

    def test_non_get_methods_fail_closed_through_security_header_path(self) -> None:
        httpd = self.start_http_server()
        for method in ("HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, body = self.http_request(httpd, method, "/")
                self.assertEqual(status, 405)
                self.assertEqual(headers["allow"], "GET")
                self.assertEqual(headers["cache-control"], "no-store, max-age=0")
                self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
                self.assertEqual(headers["x-content-type-options"], "nosniff")
                if method == "HEAD":
                    self.assertEqual(body, b"")
                else:
                    self.assertEqual(body, b"method not allowed\n")

    def test_html_renders_every_target_and_separate_dimensions_and_blockers(self) -> None:
        html = INDEX.read_text(encoding="utf-8")
        script = APP_JS.read_text(encoding="utf-8")
        contract = html + script
        for target_id, label in server.REQUIRED_TARGETS.items():
            self.assertIn(target_id, script)
            self.assertIn(label, script)
        for group in server.load_config(CONFIG)["targets"]:
            self.assertIn(group["group"], script)
        for label in server.REQUIRED_DIMENSIONS.values():
            self.assertIn(label, CONFIG.read_text(encoding="utf-8"))
        self.assertIn("Owner and external blockers", script)
        self.assertIn("Fresh blocker audit declares no owner or external blocker", script)
        self.assertIn("currentSnapshot", script)
        self.assertIn("validDerivedScores", script)
        self.assertIn("validCrossStoreState", script)
        self.assertIn("validCrossStoreReceipt", script)
        self.assertIn("requiredUploadTargets", script)
        self.assertIn("optionalUploadTargets", script)
        required_line = next(
            line
            for line in script.splitlines()
            if line.replace(" ", "").startswith("constrequiredUploadTargets")
            or line.startswith("const requiredUploadTargets")
        )
        optional_line = next(
            line
            for line in script.splitlines()
            if line.replace(" ", "").startswith("constoptionalUploadTargets")
            or line.startswith("const optionalUploadTargets")
        )
        self.assertNotIn("macos-developer-id-app", required_line)
        self.assertIn("macos-developer-id-app", optional_line)
        self.assertIn("target.cross_store_receipts", script)
        self.assertIn("target.optional_cross_store_receipts", script)
        self.assertIn("target.cross_store_status !== expectedCrossStoreStatus", script)
        self.assertIn(
            "target.optional_cross_store_status !== expectedOptionalStatus", script
        )
        self.assertIn("state.cross_store.receipts", script)
        self.assertIn("state.cross_store_receipt_schema_version !== 2", script)
        self.assertIn("target.group === contract[2]", script)
        self.assertIn("technical_readiness", script)
        self.assertIn("engineering_readiness", script)
        self.assertIn("store_evidence_readiness", script)
        self.assertIn("engineering/test", contract)
        self.assertIn("signed-artifact/store-upload", contract)
        self.assertIn("Store-upload coverage", html)
        self.assertIn("Engineering/operator targets (20)", html)
        self.assertIn("0 / 16", html)
        self.assertIn("0 / 20", html)
        self.assertNotIn("0 / 21", html)
        self.assertIn("strict store denominator", html)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, html)
        self.assertIn("Pending", html)
        self.assertIn("Failed", html)
        self.assertIn("Freshness", html)
        self.assertIn("validCoverage", script)
        self.assertIn("coverage.engineering.percent", script)
        self.assertIn("coverage.store_upload.percent", script)
        self.assertIn("Pending missing receipts are not PASS", script)
        self.assertIn("DO-NOT-UPLOAD", contract)
        self.assertIn("validCurrentPosture", script)
        self.assertIn("state.current_posture", script)
        self.assertIn("publication_hold", script)
        self.assertIn("agp_migration", script)
        self.assertIn("macos_release_python", script)
        self.assertIn("no valid fresh GCP proof", script)
        self.assertIn("owner prompt pending", contract)
        self.assertIn("source presence", contract)
        self.assertIn("publication-hold", html)
        self.assertIn("blocker-category-list", html)
        self.assertIn("Active blocker categories", html)
        self.assertIn("edge-extension", script)
        self.assertIn("android-tv-aab", contract)
        self.assertIn("validOperatorTargets", script)
        self.assertIn("state.operator_targets", script)
        self.assertIn("claimsReadinessFromMissingReceipts", script)
        self.assertIn('src="/app.js"', html)
        self.assertNotIn("<script>", html.replace('<script src="/app.js"></script>', ""))
        self.assertNotIn("innerHTML", contract)
        self.assertNotIn("insertAdjacentHTML", script)
        self.assertNotIn("document.write", script)
        self.assertTrue(all(ord(character) < 128 for character in contract))

    def test_dashboard_lane_sources_are_ascii(self) -> None:
        sources = (
            INDEX,
            CONFIG,
            Path(server.__file__),
            Path(__file__),
            Path(__file__).with_name("test_operator_coverage.py"),
            Path(__file__).with_name("README.md"),
            STATIC_INDEX,
            Path(__file__).with_name("static") / "app.js",
        )
        for path in sources:
            payload = path.read_bytes()
            self.assertTrue(payload, path.name)
            self.assertTrue(
                all(byte < 128 for byte in payload),
                path.name + " contains non-ASCII bytes",
            )

    def test_served_and_static_shells_share_denominator_critical_copy(self) -> None:
        live_path = server.DASHBOARD_INDEX
        static_path = server.INDEX
        live = live_path.read_text(encoding="ascii")
        static_html = static_path.read_text(encoding="ascii")
        self.assertEqual(live_path.resolve(), INDEX.resolve())
        self.assertEqual(static_path.resolve(), STATIC_INDEX.resolve())
        self.assertNotEqual(live_path.resolve(), static_path.resolve())
        self.assertEqual(live_path.read_bytes(), static_path.read_bytes())
        self.assertEqual(live, static_html)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, live)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, static_html)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, _shell_subtitle(live))
        self.assertEqual(_shell_subtitle(live), _shell_subtitle(static_html))
        self.assertIn("strict store denominator", live)
        self.assertIn("not a store denominator", live)
        self.assertTrue(all(ord(character) < 128 for character in live))
        self.assertTrue(all(ord(character) < 128 for character in static_html))

    def test_live_html_loads_the_validated_script_contract(self) -> None:
        httpd = self.start_http_server()
        status, headers, body = self.http_request(httpd, "GET", "/")
        html = body.decode("ascii")
        self.assertEqual(status, 200)
        self.assertEqual(body, server.DASHBOARD_INDEX.read_bytes())
        self.assertEqual(body, server.INDEX.read_bytes())
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, html)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, _shell_subtitle(html))
        self.assertIn('src="/app.js"', html)
        self.assertNotIn("const requiredTargets", html)
        csp = headers["content-security-policy"]
        self.assertIn("script-src 'self';", csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)
        script_status, _, script_body = self.http_request(httpd, "GET", "/app.js")
        self.assertEqual(script_status, 200)
        self.assertEqual(script_body, server.APP_JS.read_bytes())
        self.assertIn("const scoredTargets", script_body.decode("ascii"))
        self.assertIn("engineering/test", script_body.decode("ascii"))

    def test_coverage_distinguishes_pending_from_failed_and_stale(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        dimensions["signing"] = self.check("windows-x86", "signing", status="fail")
        self.receipt("windows-x86", dimensions)
        self.receipt("android", self.all_dimensions("android"))
        stale_at = NOW - timedelta(days=2)
        stale_dimensions = self.all_dimensions("linux-x86")
        stale_dimensions["runtime_proof"] = self.check(
            "linux-x86",
            "runtime_proof",
            observed_at=stale_at,
            artifact=self.artifact(
                "linux-x86", "runtime.proof", modified_at=stale_at
            ),
        )
        self.receipt("linux-x86", stale_dimensions)

        def mixed_upload_receipts(
            repo_root: Path,
            release_input_index: Path,
            target_id: str,
            receipt_path: Path,
            now: datetime,
        ) -> dict[str, object]:
            if target_id in {"android-tv-aab", "edge-extension-package"}:
                raise server.CrossStoreReceiptMissing(
                    f"required {target_id} schema-v2 receipt is missing"
                )
            if target_id == "firefox-extension-package":
                raise server.DashboardError("firefox-extension-package receipt is invalid")
            result = self.verified_cross_store_receipt(
                repo_root, release_input_index, target_id, receipt_path, now
            )
            if target_id == "chrome-extension-package":
                result["verified_at"] = server.iso_utc(NOW - timedelta(days=2))
            return result

        with mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=mixed_upload_receipts,
        ):
            snapshot = self.snapshot()
        coverage = snapshot["coverage"]
        freshness = snapshot["freshness"]
        self.assertEqual(coverage["scored_targets"]["required"], 20)
        self.assertEqual(coverage["scored_targets"]["ready"], 0)
        self.assertEqual(coverage["scored_targets"]["failed"], 2)
        self.assertEqual(coverage["scored_targets"]["stale"], 2)
        self.assertEqual(coverage["scored_targets"]["pending"], 15)
        self.assertEqual(coverage["scored_targets"]["partial"], 1)
        self.assertEqual(coverage["store_upload"]["required_receipts"], 16)
        self.assertEqual(coverage["store_upload"]["pending"], 2)
        self.assertEqual(coverage["store_upload"]["failed"], 1)
        self.assertEqual(coverage["store_upload"]["stale"], 1)
        self.assertEqual(coverage["store_upload"]["verified"], 12)
        self.assertEqual(coverage["store_upload"]["percent"], 75)
        self.assertNotEqual(coverage["store_upload"]["percent"], 100)
        self.assertEqual(snapshot["ready_targets"], 0)
        self.assertEqual(coverage["scored_targets"]["ready"], 0)
        self.assertNotEqual(snapshot["overall_readiness"], 100)
        self.assertEqual(coverage["engineering"]["failed_targets"], 0)
        self.assertEqual(coverage["engineering"]["verified_targets"], 2)
        self.assertEqual(coverage["engineering"]["stale_targets"], 1)
        self.assertEqual(coverage["engineering"]["pending_targets"], 17)
        self.assertLess(coverage["engineering"]["percent"], 100)
        self.assertEqual(freshness["max_age_seconds"], 86400)
        self.assertEqual(freshness["stale_targets"], 2)
        self.assertEqual(freshness["stale_upload_receipts"], 1)
        self.assertGreaterEqual(freshness["stale_dimensions"], 1)
        windows = next(item for item in snapshot["targets"] if item["id"] == "windows-x86")
        android = next(item for item in snapshot["targets"] if item["id"] == "android")
        linux = next(item for item in snapshot["targets"] if item["id"] == "linux-x86")
        self.assertEqual(windows["status"], "blocked")
        self.assertEqual(android["status"], "partial")
        self.assertEqual(linux["status"], "stale")
        firefox = next(item for item in snapshot["targets"] if item["id"] == "firefox-extension")
        chrome = next(item for item in snapshot["targets"] if item["id"] == "chrome-extension")
        self.assertEqual(firefox["status"], "invalid")
        self.assertEqual(chrome["status"], "stale")
        self.assertNotEqual(windows["status"], "unverified")
        self.assertNotEqual(android["status"], "blocked")

    def test_plans_and_missing_receipts_cannot_count_as_pass(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        planted = self.artifact("plans", "rollout.md")
        dimensions["engineering"] = self.check(
            "windows-x86", "engineering", artifact=planted
        )
        self.receipt("windows-x86", dimensions)
        snapshot = self.snapshot()
        coverage = snapshot["coverage"]
        windows = next(item for item in snapshot["targets"] if item["id"] == "windows-x86")
        self.assertEqual(windows["dimensions"][0]["status"], "invalid")
        self.assertEqual(coverage["engineering"]["failed_targets"], 1)
        self.assertEqual(coverage["engineering"]["verified_targets"], 0)
        self.assertLess(coverage["engineering"]["percent"], 100)
        self.assertEqual(windows["readiness"], 80)
        self.assertNotEqual(windows["status"], "ready")
        self.assertEqual(snapshot["ready_targets"], 0)
        self.assertNotEqual(snapshot["overall_readiness"], 100)
        self.assertEqual(coverage["scored_targets"]["ready"], 0)

    def test_html_serves_pending_failed_coverage_and_freshness_fields(self) -> None:
        html = INDEX.read_text(encoding="ascii")
        script = APP_JS.read_text(encoding="ascii")
        self.assertIn('id="upload-coverage"', html)
        self.assertIn('id="pending-count"', html)
        self.assertIn('id="failed-count"', html)
        self.assertIn('id="freshness"', html)
        self.assertIn("validCoverage", script)
        self.assertIn("scoredOutcome", script)
        self.assertIn("receiptOutcome", script)
        self.assertIn("Pending missing receipts are not PASS", script)
        self.assertIn("validCurrentPosture", script)
        self.assertIn("DO-NOT-UPLOAD", html)
        self.assertIn('id="publication-hold"', html)
        self.assertIn('id="gcp-proof"', html)
        self.assertIn('id="agp-migration"', html)
        self.assertIn('id="macos-python"', html)
        self.assertIn('id="blocker-category-list"', html)

    def test_engineering_only_evidence_cannot_make_store_ready(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        for dimension_id in ("artifact", "signing", "store_metadata", "runtime_proof"):
            dimensions[dimension_id] = self.check(
                "windows-x86", dimension_id, status="fail"
            )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertEqual(target["engineering_readiness"], 20)
        self.assertEqual(target["store_evidence_readiness"], 0)
        self.assertEqual(target["technical_readiness"], 20)
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")

    def test_unit_test_plan_and_handoff_paths_cannot_report_store_ready(self) -> None:
        cases = (
            ("tests", "test_release.py", "unit-test output"),
            ("plans", "rollout.md", "plan documents"),
            ("handoff", "claimed.proof", "not release evidence"),
        )
        for folder, name, reason in cases:
            with self.subTest(path=folder + "/" + name):
                dimensions = self.all_dimensions("windows-x86")
                planted = self.artifact(folder, name)
                dimensions["engineering"] = self.check(
                    "windows-x86", "engineering", artifact=planted
                )
                self.receipt("windows-x86", dimensions)
                target = self.target("windows-x86")
                self.assertEqual(target["dimensions"][0]["status"], "invalid")
                self.assertIn(reason, target["dimensions"][0]["reason"])
                self.assertEqual(target["engineering_readiness"], 20)
                self.assertEqual(target["store_evidence_readiness"], 60)
                self.assertEqual(target["readiness"], 80)
                self.assertNotEqual(target["status"], "ready")
                self.assertLess(target["technical_readiness"], 100)

    def test_repo_unit_test_file_cannot_be_release_evidence(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        test_file = Path(server.__file__).with_name("test_dashboard.py")
        dimensions["engineering"] = self.check(
            "windows-x86",
            "engineering",
            artifact={
                "root": "repo",
                "path": "dashboard/test_dashboard.py",
                "sha256": hashlib.sha256(test_file.read_bytes()).hexdigest(),
            },
        )
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        self.assertEqual(target["dimensions"][0]["status"], "invalid")
        self.assertIn("unit-test output", target["dimensions"][0]["reason"])
        self.assertEqual(target["readiness"], 80)
        self.assertNotEqual(target["status"], "ready")

    def test_unit_test_files_cannot_produce_one_hundred_percent(self) -> None:
        dimensions = {
            dimension["id"]: self.check(
                "windows-x86",
                dimension["id"],
                artifact=self.artifact("tests", dimension["id"] + "_unit.py"),
            )
            for dimension in server.load_config(CONFIG)["dimensions"]
        }
        self.receipt(
            "windows-x86",
            dimensions,
            blocker_audit=self.check(
                "windows-x86",
                "blocker_audit",
                artifact=self.artifact("tests", "blocker_unit.py"),
            ),
        )
        target = self.target("windows-x86")
        self.assertTrue(
            all(item["status"] == "invalid" for item in target["dimensions"])
        )
        self.assertEqual(target["engineering_readiness"], 0)
        self.assertEqual(target["store_evidence_readiness"], 0)
        self.assertEqual(target["technical_readiness"], 0)
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")
        snapshot = self.snapshot()
        self.assertNotEqual(snapshot["overall_readiness"], 100)
        self.assertEqual(snapshot["ready_targets"], 0)

    def test_reused_artifact_hash_cannot_credit_two_dimensions(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        shared = self.artifact("windows-x86", "shared.proof")
        dimensions["engineering"] = self.check(
            "windows-x86", "engineering", artifact=shared
        )
        dimensions["signing"] = self.check("windows-x86", "signing", artifact=shared)
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        by_id = {item["id"]: item for item in target["dimensions"]}
        self.assertEqual(by_id["engineering"]["status"], "verified")
        self.assertEqual(by_id["signing"]["status"], "invalid")
        self.assertIn("reused", by_id["signing"]["reason"])
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")

    def test_reused_artifact_hash_cannot_credit_two_targets(self) -> None:
        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        shared = {
            "root": "evidence",
            "path": "windows-x86/engineering.proof",
            "sha256": hashlib.sha256(
                b"verified windows-x86:engineering.proof\n"
            ).hexdigest(),
        }
        dimensions = self.all_dimensions("android")
        dimensions["engineering"] = self.check(
            "android", "engineering", artifact=shared
        )
        self.receipt("android", dimensions)
        android = self.target("android")
        self.assertEqual(android["dimensions"][0]["status"], "invalid")
        self.assertIn("reused", android["dimensions"][0]["reason"])
        self.assertEqual(android["readiness"], 80)
        self.assertNotEqual(android["status"], "ready")

    def test_reused_cross_store_receipt_hash_fails_closed(self) -> None:
        self.receipt(
            "chrome-extension",
            self.all_dimensions("chrome-extension"),
        )
        shared = "a" * 64

        def reused_hashes(
            repo_root: Path,
            release_input_index: Path,
            target_id: str,
            receipt_path: Path,
            now: datetime,
        ) -> dict[str, object]:
            result = self.verified_cross_store_receipt(
                repo_root, release_input_index, target_id, receipt_path, now
            )
            if target_id in {"chrome-extension-package", "edge-extension-package"}:
                result["receipt_sha256"] = shared
            return result

        with mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=reused_hashes,
        ):
            target = self.target("chrome-extension")
        self.assertEqual(target["cross_store_status"], "invalid")
        self.assertEqual(
            [receipt["status"] for receipt in target["cross_store_receipts"]],
            ["invalid", "invalid"],
        )
        self.assertEqual(target["technical_readiness"], 100)
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")

    def test_hostile_freshness_future_cross_store_receipt_is_invalid(self) -> None:
        self.receipt(
            "chrome-extension",
            self.all_dimensions("chrome-extension"),
        )

        def future_chrome(
            repo_root: Path,
            release_input_index: Path,
            target_id: str,
            receipt_path: Path,
            now: datetime,
        ) -> dict[str, object]:
            result = self.verified_cross_store_receipt(
                repo_root, release_input_index, target_id, receipt_path, now
            )
            if target_id == "chrome-extension-package":
                result["verified_at"] = server.iso_utc(NOW + timedelta(hours=2))
            return result

        with mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=future_chrome,
        ):
            target = self.target("chrome-extension")
        self.assertEqual(target["cross_store_receipts"][0]["status"], "invalid")
        self.assertIn("future-dated", target["cross_store_receipts"][0]["reason"])
        self.assertEqual(target["readiness"], 0)
        self.assertEqual(target["status"], "invalid")

    def test_hostile_freshness_new_receipt_cannot_revive_stale_observation(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        stale_at = NOW - timedelta(days=2)
        dimensions["signing"] = self.check(
            "windows-x86",
            "signing",
            observed_at=stale_at,
            artifact=self.artifact(
                "windows-x86", "stale-signature.proof", modified_at=stale_at
            ),
        )
        self.receipt("windows-x86", dimensions, generated_at=NOW)
        target = self.target("windows-x86")
        signing = next(
            item for item in target["dimensions"] if item["id"] == "signing"
        )
        self.assertEqual(signing["status"], "stale")
        self.assertEqual(target["readiness"], 0)
        self.assertNotEqual(target["status"], "ready")

    def test_hostile_path_swap_of_artifact_bytes_fails_closed(self) -> None:
        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        original = self.evidence / "windows-x86" / "engineering.proof"
        replacement = self.evidence / "windows-x86" / "swapped.proof"
        replacement.write_bytes(b"swapped-bytes-not-in-receipt\n")
        os.replace(replacement, original)
        os.utime(original, (NOW.timestamp(), NOW.timestamp()))
        target = self.target("windows-x86")
        engineering = next(
            item for item in target["dimensions"] if item["id"] == "engineering"
        )
        self.assertEqual(engineering["status"], "invalid")
        self.assertIn("SHA-256 mismatch", engineering["reason"])
        self.assertEqual(target["readiness"], 80)
        self.assertNotEqual(target["status"], "ready")

    def test_hostile_path_swap_directory_to_symlink_fails_closed(self) -> None:
        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        real = self.evidence / "windows-x86"
        moved = self.evidence / "windows-x86-real"
        real.rename(moved)
        real.symlink_to(moved, target_is_directory=True)
        target = self.target("windows-x86")
        self.assertEqual(target["status"], "invalid")
        self.assertIn("symbolic link", target["dimensions"][0]["reason"])
        self.assertEqual(target["readiness"], 0)

    def test_hostile_receipt_path_swap_to_other_target_fails_closed(self) -> None:
        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        self.receipt("android", self.all_dimensions("android"))
        windows = self.evidence / "windows-x86.json"
        android = self.evidence / "android.json"
        os.replace(android, windows)
        os.utime(windows, (NOW.timestamp(), NOW.timestamp()))
        target = self.target("windows-x86")
        self.assertEqual(target["status"], "invalid")
        self.assertIn("does not match", target["dimensions"][0]["reason"])
        self.assertEqual(target["readiness"], 0)

    def test_hostile_schema_mutations_fail_closed(self) -> None:
        self.receipt("windows-x86", self.all_dimensions("windows-x86"))
        path = self.evidence / "windows-x86.json"
        original = json.loads(path.read_text(encoding="ascii"))
        mutations = {
            "manual-percent": {**original, "readiness": 100},
            "schema-upgrade": {**original, "schema_version": 5},
            "missing-target": {k: v for k, v in original.items() if k != "target"},
        }
        for case, mutated in mutations.items():
            with self.subTest(case=case):
                path.write_text(json.dumps(mutated), encoding="ascii")
                os.utime(path, (NOW.timestamp(), NOW.timestamp()))
                target = self.target("windows-x86")
                self.assertEqual(target["status"], "invalid")
                self.assertEqual(target["readiness"], 0)
                self.assertNotEqual(target["status"], "ready")
        duplicate = json.dumps(original).replace(
            '"schema_version": 4',
            '"schema_version": 4, "schema_version": 3',
            1,
        )
        path.write_text(duplicate, encoding="ascii")
        os.utime(path, (NOW.timestamp(), NOW.timestamp()))
        target = self.target("windows-x86")
        self.assertEqual(target["status"], "invalid")
        self.assertIn("duplicate JSON key", target["dimensions"][0]["reason"])
        self.assertEqual(target["readiness"], 0)

    def test_hardlinked_artifact_is_rejected(self) -> None:
        dimensions = self.all_dimensions("windows-x86")
        source = self.evidence / "windows-x86" / "engineering.proof"
        linked = self.evidence / "windows-x86" / "hardlinked.proof"
        os.link(source, linked)
        self.receipt("windows-x86", dimensions)
        target = self.target("windows-x86")
        engineering = next(
            item for item in target["dimensions"] if item["id"] == "engineering"
        )
        self.assertEqual(engineering["status"], "invalid")
        self.assertIn("hard-linked", engineering["reason"])
        self.assertEqual(target["readiness"], 80)
        self.assertNotEqual(target["status"], "ready")

    def test_sync_script_is_local_serialized_and_writes_fail_closed_snapshot(self) -> None:
        script = SYNC.read_text(encoding="utf-8")
        executable_lines = [
            line.strip()
            for line in script.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        commands = "\n".join(executable_lines)
        self.assertTrue(os.access(SYNC, os.X_OK))
        self.assertIn("mkdir --", script)
        self.assertIn("--refresh-cross-store-cache", script)
        self.assertIn("exit 75", script)
        self.assertNotRegex(commands, FORBIDDEN_SYNC_COMMAND_RE)
        for forbidden_command in (
            "git push origin main",
            "curl https://example.invalid",
            "/usr/bin/git status",
            "env wget https://example.invalid/file",
            "ssh release-host",
            "scp artifact release-host:/tmp/",
        ):
            with self.subTest(forbidden_command=forbidden_command):
                self.assertRegex(forbidden_command, FORBIDDEN_SYNC_COMMAND_RE)
        snapshot = self.root / "output" / "state.json"
        environment = os.environ.copy()
        environment.update(
            {
                "WINSVPN_DASHBOARD_PYTHON": sys.executable,
                "WINSVPN_DASHBOARD_EVIDENCE_DIR": str(self.evidence),
                "WINSVPN_DASHBOARD_SNAPSHOT": str(snapshot),
                "WINSVPN_DASHBOARD_REPO_ROOT": str(self.repo),
                "WINSVPN_DASHBOARD_CROSS_STORE_CACHE": str(self.cache_path),
            }
        )
        result = subprocess.run(
            ["bash", str(SYNC)],
            cwd=Path(__file__).parents[1],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(snapshot.read_text())["overall_readiness"], 0)
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
        self.assertFalse(Path(str(snapshot) + ".lock").exists())
        lock = Path(str(snapshot) + ".lock")
        lock.mkdir()
        locked = subprocess.run(
            ["bash", str(SYNC)],
            cwd=Path(__file__).parents[1],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(locked.returncode, 75)
        self.assertIn("another sync owns", locked.stderr)
        lock.rmdir()

        invalid_config = self.root / "invalid-state.json"
        invalid_config.write_text("{\"schema_version\":3}", encoding="utf-8")
        invalid_environment = environment.copy()
        invalid_environment["WINSVPN_DASHBOARD_CONFIG"] = str(invalid_config)
        invalid = subprocess.run(
            ["bash", str(SYNC)],
            cwd=Path(__file__).parents[1],
            env=invalid_environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(invalid.returncode, 0)
        failure = json.loads(snapshot.read_text())
        self.assertEqual(failure["source"], "invalid-local-evidence")
        self.assertEqual(failure["overall_readiness"], 0)
        self.assertEqual(failure["target_count"], len(server.REQUIRED_TARGETS))
        self.assertTrue(
            all(item["status"] == "unavailable" for item in failure["targets"])
        )

        invalid_watch = subprocess.run(
            ["bash", str(SYNC), "--watch", "1"],
            cwd=Path(__file__).parents[1],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(invalid_watch.returncode, 64)
        self.assertIn("watch interval", invalid_watch.stderr)

        snapshot.write_text('{"overall_readiness":100}\n', encoding="utf-8")
        unavailable_python = environment.copy()
        unavailable_python["WINSVPN_DASHBOARD_PYTHON"] = "/usr/bin/false"
        failed_writer = subprocess.run(
            ["bash", str(SYNC)],
            cwd=Path(__file__).parents[1],
            env=unavailable_python,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(failed_writer.returncode, 0)
        self.assertFalse(snapshot.exists())
        self.assertFalse(Path(str(snapshot) + ".expired-do-not-use").exists())
        self.assertFalse(Path(str(snapshot) + ".lock").exists())

    def test_unmocked_missing_receipts_are_zero_sixteen_zero_forty_and_zero_percent(
        self,
    ) -> None:
        self.cross_store_verifier.stop()
        try:
            before = {
                path: path.stat().st_mtime_ns
                for path in self.root.rglob("*")
                if path.is_file()
            }
            dirs_before = {path for path in self.root.rglob("*") if path.is_dir()}
            snapshot = self.snapshot()
            coverage = snapshot["coverage"]
            self.assertEqual(coverage["store_upload"]["verified"], 0)
            self.assertEqual(coverage["store_upload"]["pending"], 16)
            self.assertEqual(coverage["store_upload"]["required_receipts"], 16)
            self.assertEqual(coverage["store_upload"]["percent"], 0)
            self.assertEqual(coverage["engineering"]["required_dimensions"], 40)
            self.assertEqual(coverage["engineering"]["verified_dimensions"], 0)
            self.assertEqual(coverage["engineering"]["pending_dimensions"], 40)
            self.assertEqual(coverage["engineering"]["percent"], 0)
            self.assertEqual(snapshot["overall_readiness"], 0)
            self.assertEqual(snapshot["overall_engineering_readiness"], 0)
            self.assertEqual(snapshot["cross_store"]["status_counts"]["verified"], 0)
            self.assertEqual(snapshot["cross_store"]["status_counts"]["missing"], 16)
            posture = snapshot["current_posture"]
            self.assertEqual(posture["publication_hold"], "DO-NOT-UPLOAD")
            self.assertFalse(posture["store_upload_authorized"])
            self.assertEqual(posture["upload_receipts"]["verified"], 0)
            self.assertEqual(posture["upload_receipts"]["required"], 16)
            self.assertEqual(posture["upload_receipts"]["status"], "pending")
            self.assertEqual(posture["gcp_proof"]["status"], "missing")
            self.assertFalse(posture["gcp_proof"]["fresh"])
            self.assertEqual(posture["agp_migration"]["status"], "in_progress")
            self.assertEqual(
                posture["macos_release_python"]["status"], "owner_prompt_pending"
            )
            self.assertEqual(
                sum(snapshot["cross_store"]["status_counts"].values()),
                16,
            )
            after_files = {
                path: path.stat().st_mtime_ns
                for path in self.root.rglob("*")
                if path.is_file()
            }
            after_dirs = {path for path in self.root.rglob("*") if path.is_dir()}
            self.assertEqual(after_files, before)
            self.assertEqual(after_dirs, dirs_before)
            self.assertFalse(
                list(self.repo.rglob("cross-store-current-verification"))
            )
            self.assertFalse(list(self.repo.rglob("cross-store-gate-tmp")))
        finally:
            self.cross_store_verifier.start()

    def test_snapshot_and_get_never_execute_live_gates(self) -> None:
        self.cross_store_verifier.stop()
        try:
            live = mock.Mock(side_effect=AssertionError("live gates must not run"))
            with mock.patch.object(server, "run_live_cross_store_verification", live):
                snapshot = self.snapshot()
                httpd = self.start_http_server()
                status, _, body = self.http_request(httpd, "GET", "/api/state")
            self.assertEqual(snapshot["coverage"]["store_upload"]["verified"], 0)
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertEqual(payload["coverage"]["store_upload"]["percent"], 0)
            live.assert_not_called()
        finally:
            self.cross_store_verifier.start()

    def test_stale_or_invalid_cache_fails_closed_without_filesystem_mutation(
        self,
    ) -> None:
        self.cross_store_verifier.stop()
        stale = {
            "schema_version": server.CROSS_STORE_CACHE_SCHEMA_VERSION,
            "release": server.RELEASE_IDENTITY,
            "generated_at": server.iso_utc(NOW - timedelta(days=2)),
            "receipt_directory": server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY,
            "release_input_index": server.DEFAULT_RELEASE_INPUT_INDEX,
            "receipts": {
                target_id: {
                    "target_id": target_id,
                    "receipt": f"{server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY}/{target_id}.json",
                    "receipt_schema_version": 2,
                    "release": server.RELEASE_IDENTITY,
                    "status": "verified",
                    "verified_at": server.iso_utc(NOW - timedelta(days=2)),
                    "receipt_sha256": "a" * 64,
                    "artifact_sha256": "b" * 64,
                    "reason": "stale cache must not count",
                }
                for target_id in server.KNOWN_CROSS_STORE_TARGET_IDS
            },
        }
        self.cache_path.write_text(json.dumps(stale), encoding="ascii")
        os.chmod(self.cache_path, 0o600)
        os.utime(self.cache_path, (NOW.timestamp(), NOW.timestamp()))
        with self.assertRaisesRegex(server.DashboardError, "stale"):
            self.snapshot()
        invalid = dict(stale)
        invalid["generated_at"] = server.iso_utc(NOW)
        invalid["release"] = "1.0.14+29"
        self.cache_path.write_text(json.dumps(invalid), encoding="ascii")
        os.chmod(self.cache_path, 0o600)
        os.utime(self.cache_path, (NOW.timestamp(), NOW.timestamp()))
        with self.assertRaisesRegex(server.DashboardError, "invalid"):
            self.snapshot()
        self.assertFalse(list(self.repo.rglob("cross-store-gate-tmp")))

    def test_hostile_forged_fresh_cache_cannot_claim_sixteen_without_rehash(
        self,
    ) -> None:
        self.cross_store_verifier.stop()
        try:
            receipt_directory = Path(server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY)
            receipts_dir = self.repo / receipt_directory
            receipts_dir.mkdir(parents=True)
            artifacts_dir = self.repo / ".artifacts" / "forged-artifacts"
            artifacts_dir.mkdir(parents=True)
            cache_receipts: dict[str, dict[str, object]] = {}
            for target_id in server.KNOWN_CROSS_STORE_TARGET_IDS:
                artifact_bytes = (target_id + ":forged-artifact\n").encode("ascii")
                artifact_path = artifacts_dir / (target_id + ".bin")
                artifact_path.write_bytes(artifact_bytes)
                receipt_payload = {
                    "artifact": {
                        "path": artifact_path.relative_to(self.repo).as_posix(),
                        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                        "bytes": len(artifact_bytes),
                    }
                }
                encoded = json.dumps(
                    receipt_payload, separators=(",", ":")
                ).encode("ascii")
                receipt_path = receipts_dir / (target_id + ".json")
                receipt_path.write_bytes(encoded)
                cache_receipts[target_id] = {
                    "target_id": target_id,
                    "receipt": (receipt_directory / (target_id + ".json")).as_posix(),
                    "receipt_schema_version": 2,
                    "release": server.RELEASE_IDENTITY,
                    "status": "verified",
                    "verified_at": server.iso_utc(NOW),
                    "receipt_sha256": hashlib.sha256(encoded).hexdigest(),
                    "artifact_sha256": "b" * 64,
                    "reason": "forged cache must not count",
                }
            forged = {
                "schema_version": server.CROSS_STORE_CACHE_SCHEMA_VERSION,
                "release": server.RELEASE_IDENTITY,
                "generated_at": server.iso_utc(NOW),
                "receipt_directory": server.DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY,
                "release_input_index": server.DEFAULT_RELEASE_INPUT_INDEX,
                "receipts": cache_receipts,
            }
            self.cache_path.write_text(json.dumps(forged), encoding="ascii")
            os.chmod(self.cache_path, 0o400)
            os.utime(self.cache_path, (NOW.timestamp(), NOW.timestamp()))
            live = mock.Mock(side_effect=AssertionError("live gates must not run"))
            with mock.patch.object(
                server, "run_live_cross_store_verification", live
            ):
                snapshot = self.snapshot()
            live.assert_not_called()
            self.assertEqual(snapshot["cross_store"]["status_counts"]["verified"], 0)
            self.assertEqual(snapshot["coverage"]["store_upload"]["verified"], 0)
            self.assertNotEqual(snapshot["coverage"]["store_upload"]["percent"], 100)
            posture = snapshot["current_posture"]
            self.assertEqual(posture["publication_hold"], "DO-NOT-UPLOAD")
            self.assertIs(posture["store_upload_authorized"], False)
            self.assertNotEqual(posture["upload_receipts"]["verified"], 16)
            self.assertTrue(
                all(
                    receipt["status"] == "invalid"
                    for receipt in snapshot["cross_store"]["receipts"]
                )
            )
            self.assertTrue(
                all(
                    "hash" in str(receipt["reason"])
                    for receipt in snapshot["cross_store"]["receipts"]
                )
            )
            self.assertFalse(list(self.repo.rglob("cross-store-gate-tmp")))
        finally:
            self.cross_store_verifier.start()

    def test_exact_host_path_and_method_handling(self) -> None:
        httpd = self.start_http_server()
        port = httpd.server_port
        status, _, _ = self.http_request(httpd, "GET", "/api/state?x=1")
        self.assertEqual(status, 400)
        status, _, _ = self.http_request(httpd, "GET", "/api/state/")
        self.assertEqual(status, 404)
        status, _, _ = self.http_request(httpd, "GET", "/API/STATE")
        self.assertEqual(status, 404)
        status, _, body = self.http_request(httpd, "GET", "/app.js")
        self.assertEqual(status, 200)
        self.assertEqual(body, server.APP_JS.read_bytes())
        status, headers, body = self.http_request(httpd, "TRACE", "/")
        self.assertEqual(status, 405)
        self.assertEqual(headers["allow"], "GET")
        self.assertEqual(body, b"method not allowed\n")
        status, _, body = self.http_request(
            httpd, "GET", "/api/state", host=f"[::1]:{port}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, b"invalid host\n")

    def test_cross_site_browser_requests_are_refused_before_any_snapshot(self) -> None:
        # A page on another origin can make the operator's browser send a
        # no-cors GET to the loopback dashboard with the right Host. The body
        # is unreadable to it, but every such request used to run a full
        # evidence snapshot (file reads and artifact hashing).
        httpd = self.start_http_server()
        port = httpd.server_port

        def request(headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
            connection = HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.putrequest("GET", "/api/state", skip_host=True)
                connection.putheader("Host", f"127.0.0.1:{port}")
                for name, value in headers.items():
                    connection.putheader(name, value)
                connection.endheaders()
                response = connection.getresponse()
                body = response.read()
                return (
                    response.status,
                    {name.lower(): value for name, value in response.getheaders()},
                    body,
                )
            finally:
                connection.close()

        real_build = server.build_snapshot
        calls: list[int] = []

        def counting_build(*args: object, **kwargs: object) -> dict[str, object]:
            calls.append(1)
            return real_build(*args, **kwargs)

        with mock.patch.object(server, "build_snapshot", side_effect=counting_build):
            for headers in (
                {"Sec-Fetch-Site": "cross-site"},
                {"Sec-Fetch-Site": "same-site"},
                {"Origin": "https://evil.example"},
                {"Origin": "null"},
                {"Origin": f"http://localhost:{port + 1 if port < 65535 else port - 1}"},
                {"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example"},
            ):
                with self.subTest(refused=headers):
                    status, response_headers, body = request(headers)
                    self.assertEqual(status, 403)
                    self.assertEqual(body, b"cross-origin request rejected\n")
                    self.assertEqual(response_headers["cache-control"], "no-store, max-age=0")
                    self.assertIn(
                        "frame-ancestors 'none'",
                        response_headers["content-security-policy"],
                    )
            self.assertEqual(calls, [])
            for headers in (
                {},
                {"Sec-Fetch-Site": "same-origin"},
                {"Sec-Fetch-Site": "none"},
                {"Origin": f"http://127.0.0.1:{port}"},
                {"Sec-Fetch-Site": "same-origin", "Origin": f"http://localhost:{port}"},
            ):
                with self.subTest(allowed=headers):
                    status, _, _ = request(headers)
                    self.assertEqual(status, 200)
            self.assertEqual(len(calls), 5)

        connection = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.putrequest("GET", "/api/state", skip_host=True)
            connection.putheader("Host", f"127.0.0.1:{port}")
            connection.putheader("Sec-Fetch-Site", "same-origin")
            connection.putheader("Sec-Fetch-Site", "cross-site")
            connection.endheaders()
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 403)
        finally:
            connection.close()

    def test_xss_payloads_stay_in_text_nodes_and_json(self) -> None:
        script = APP_JS.read_text(encoding="ascii")
        html = INDEX.read_text(encoding="ascii")
        for sink in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "Function(",
        ):
            self.assertNotIn(sink, script)
            self.assertNotIn(sink, html)
        payload = "<script>alert(1)</script><img src=x onerror=alert(1)>"
        snapshot = server.build_failure_snapshot(NOW)
        snapshot["cross_store"]["receipts"][0]["reason"] = payload
        encoded = json.dumps(snapshot)
        self.assertIn(payload, encoded)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("createTextNode", script)

    def assert_named_current_holds(
        self,
        snapshot: dict[str, object],
        *,
        upload_verified: int = 0,
        gcp_fresh: bool = False,
        agp_complete: bool = False,
        python_authenticated: bool = False,
    ) -> None:
        posture = snapshot["current_posture"]
        self.assertEqual(posture["publication_hold"], "DO-NOT-UPLOAD")
        self.assertIs(posture["store_upload_authorized"], False)
        self.assertEqual(posture["upload_receipts"]["required"], 16)
        self.assertEqual(posture["upload_receipts"]["verified"], upload_verified)
        self.assertEqual(posture["gcp_proof"]["fresh"], gcp_fresh)
        if gcp_fresh:
            self.assertEqual(posture["gcp_proof"]["status"], "verified")
        else:
            self.assertNotEqual(posture["gcp_proof"]["status"], "verified")
            self.assertIn("no valid fresh GCP proof", posture["gcp_proof"]["reason"])
        self.assertEqual(
            posture["agp_migration"]["status"],
            "complete" if agp_complete else "in_progress",
        )
        self.assertEqual(
            posture["macos_release_python"]["status"],
            "authenticated" if python_authenticated else "owner_prompt_pending",
        )
        category_ids = [
            item["id"] for item in posture["active_blocker_categories"]
        ]
        self.assertEqual(category_ids[0], "publication_hold")
        self.assertEqual(
            posture["active_blocker_categories"][0]["detail"], "DO-NOT-UPLOAD"
        )
        if upload_verified != 16:
            self.assertIn("missing_upload_receipts", category_ids)
        else:
            self.assertNotIn("missing_upload_receipts", category_ids)
        if not gcp_fresh:
            self.assertIn("gcp_proof", category_ids)
        else:
            self.assertNotIn("gcp_proof", category_ids)
        if not agp_complete:
            self.assertIn("agp_migration", category_ids)
        else:
            self.assertNotIn("agp_migration", category_ids)
        if not python_authenticated:
            self.assertIn("macos_release_python", category_ids)
        else:
            self.assertNotIn("macos_release_python", category_ids)

    def test_source_presence_and_workers_cannot_mint_named_passes(self) -> None:
        (self.repo / "LANE_REPORT.md").write_text("COMPLETED\n", encoding="ascii")
        (self.repo / "PROGRESS.json").write_text(
            '{"percent":100,"status":"pass"}\n', encoding="ascii"
        )
        (self.repo / "CONTINUE.md").write_text("refill\n", encoding="ascii")
        (self.repo / "android.pid").write_text("12345\n", encoding="ascii")
        logs = self.repo / "logs"
        logs.mkdir()
        (logs / "android.pid").write_text("99999\n", encoding="ascii")
        gradle = self.repo / "android" / "settings.gradle.kts"
        gradle.parent.mkdir()
        gradle.write_text(
            'id("com.android.application") version "9.4.1" apply false\n',
            encoding="ascii",
        )
        python_src = self.repo / "tools" / "macos_release_python_runtime_receipt.py"
        python_src.parent.mkdir()
        python_src.write_text("authenticated = True\n", encoding="ascii")
        gcp_bin = self.repo / ".artifacts" / "gcp-proof" / "winn3-gateway-linux-amd64"
        gcp_bin.parent.mkdir(parents=True)
        gcp_bin.write_bytes(b"not-an-acceptance-receipt")
        self.cross_store_verifier.stop()
        try:
            snapshot = self.snapshot()
        finally:
            self.cross_store_verifier.start()
        self.assert_named_current_holds(snapshot, upload_verified=0)
        self.assertEqual(snapshot["overall_readiness"], 0)
        self.assertEqual(snapshot["ready_targets"], 0)
        self.assertEqual(snapshot["coverage"]["store_upload"]["verified"], 0)

    def test_generic_gcp_card_receipt_is_not_a_fresh_gcp_proof(self) -> None:
        self.receipt(
            "gcp-three-server-proof",
            self.all_dimensions("gcp-three-server-proof"),
        )
        target = self.target("gcp-three-server-proof")
        self.assertEqual(target["technical_readiness"], 100)
        snapshot = self.snapshot()
        self.assert_named_current_holds(snapshot, upload_verified=16)
        self.assertEqual(snapshot["current_posture"]["gcp_proof"]["status"], "missing")

    def test_dedicated_gcp_summary_is_not_fresh_without_canonical_receipt(
        self,
    ) -> None:
        dimensions = self.all_dimensions("gcp-three-server-proof")
        runtime = self.check("gcp-three-server-proof", "runtime_proof")
        runtime["summary_code"] = "gcp_proof_acceptance"
        dimensions["runtime_proof"] = runtime
        self.receipt("gcp-three-server-proof", dimensions)
        snapshot = self.snapshot()
        self.assert_named_current_holds(
            snapshot, upload_verified=16, gcp_fresh=False
        )
        self.assertNotEqual(
            snapshot["current_posture"]["gcp_proof"]["status"], "verified"
        )
        gcp_target = next(
            item
            for item in snapshot["targets"]
            if item["id"] == "gcp-three-server-proof"
        )
        runtime_status = next(
            item["status"]
            for item in gcp_target["dimensions"]
            if item["id"] == "runtime_proof"
        )
        self.assertNotEqual(runtime_status, "verified")
        self.assertEqual(
            snapshot["current_posture"]["publication_hold"], "DO-NOT-UPLOAD"
        )
        self.assertIs(
            snapshot["current_posture"]["store_upload_authorized"], False
        )

    def test_agp_source_pin_is_not_completion_and_needs_both_surfaces(self) -> None:
        gradle = self.repo / "android" / "settings.gradle.kts"
        gradle.parent.mkdir()
        gradle.write_text(
            'id("com.android.application") version "9.4.1" apply false\n',
            encoding="ascii",
        )
        dimensions = self.all_dimensions("android")
        artifact = self.check("android", "artifact")
        artifact["summary_code"] = "agp_migration_complete"
        dimensions["artifact"] = artifact
        self.receipt("android", dimensions)
        snapshot = self.snapshot()
        self.assertEqual(
            snapshot["current_posture"]["agp_migration"]["status"], "in_progress"
        )
        wear = self.all_dimensions("watch-wear-os")
        wear_artifact = self.check("watch-wear-os", "artifact")
        wear_artifact["summary_code"] = "agp_migration_complete"
        wear["artifact"] = wear_artifact
        self.receipt("watch-wear-os", wear)
        snapshot = self.snapshot()
        self.assert_named_current_holds(
            snapshot, upload_verified=16, agp_complete=True
        )
        self.assertEqual(
            snapshot["current_posture"]["publication_hold"], "DO-NOT-UPLOAD"
        )

    def test_macos_python_schema_source_is_not_authenticated(self) -> None:
        python_src = self.repo / "tools" / "macos_release_python_runtime_receipt.py"
        python_src.parent.mkdir()
        python_src.write_text("# owner provisioned\n", encoding="ascii")
        snapshot = self.snapshot()
        self.assertEqual(
            snapshot["current_posture"]["macos_release_python"]["status"],
            "owner_prompt_pending",
        )
        dimensions = self.all_dimensions("macos-arm64")
        engineering = self.check("macos-arm64", "engineering")
        engineering["summary_code"] = "macos_release_python_runtime"
        dimensions["engineering"] = engineering
        self.receipt("macos-arm64", dimensions)
        snapshot = self.snapshot()
        self.assert_named_current_holds(
            snapshot, upload_verified=16, python_authenticated=True
        )
        self.assertIs(
            snapshot["current_posture"]["store_upload_authorized"], False
        )

    def test_ready_cards_and_sixteen_receipts_still_do_not_upload(self) -> None:
        for target_id in server.REQUIRED_TARGETS:
            self.receipt(target_id, self.all_dimensions(target_id))
        snapshot = self.snapshot()
        self.assertGreater(snapshot["ready_targets"], 0)
        self.assertEqual(snapshot["coverage"]["store_upload"]["verified"], 16)
        self.assert_named_current_holds(snapshot, upload_verified=16)
        category_ids = [
            item["id"]
            for item in snapshot["current_posture"]["active_blocker_categories"]
        ]
        self.assertNotIn("missing_upload_receipts", category_ids)
        self.assertEqual(
            snapshot["current_posture"]["upload_receipts"]["status"], "complete"
        )

    def _write_freeze_index(self) -> dict[str, str]:
        relative = Path(server.DEFAULT_RELEASE_INPUT_INDEX)
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = b'{"release":"1.0.17+34","platforms":[]}\n'
        path.write_bytes(payload)
        return {
            "path": str(path.absolute()),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": str(len(payload)),
        }

    def _gcp_acceptance_dimensions(self) -> dict[str, object]:
        artifact = self.artifact(
            "gcp-three-server-proof", "acceptance-receipt.json"
        )
        dimensions = self.all_dimensions("gcp-three-server-proof")
        runtime = self.check(
            "gcp-three-server-proof",
            "runtime_proof",
            artifact=artifact,
        )
        runtime["summary_code"] = "gcp_proof_acceptance"
        dimensions["runtime_proof"] = runtime
        return dimensions

    def test_canonical_gcp_receipt_verifies_with_six_hour_freeze_binding(
        self,
    ) -> None:
        freeze = self._write_freeze_index()
        self.receipt("gcp-three-server-proof", self._gcp_acceptance_dimensions())
        calls: list[tuple[str, str]] = []

        def fake_verify(
            receipt_path: Path,
            *,
            repo_root: Path,
            release_input_index: Path,
        ) -> dict[str, object]:
            calls.append((receipt_path.name, Path(release_input_index).name))
            self.assertEqual(receipt_path.name, "acceptance-receipt.json")
            self.assertEqual(repo_root, self.repo)
            return {
                "verified": True,
                "receipt_created_utc": server.iso_utc(NOW),
                "release": server.RELEASE_IDENTITY,
                "publication_authorized": False,
                "release_input_index": {
                    "path": freeze["path"],
                    "sha256": freeze["sha256"],
                },
            }

        with mock.patch.object(
            server,
            "verify_gcp_proof_acceptance_receipt_for_release",
            fake_verify,
        ):
            snapshot = self.snapshot()
        self.assertGreaterEqual(len(calls), 1)
        self.assert_named_current_holds(
            snapshot, upload_verified=16, gcp_fresh=True
        )
        self.assertEqual(
            snapshot["current_posture"]["publication_hold"], "DO-NOT-UPLOAD"
        )
        self.assertIs(
            snapshot["current_posture"]["store_upload_authorized"], False
        )

    def test_hostile_gcp_receipt_without_verifier_is_not_fresh(self) -> None:
        self._write_freeze_index()
        self.receipt("gcp-three-server-proof", self._gcp_acceptance_dimensions())

        def fake_verify(*args: object, **kwargs: object) -> dict[str, object]:
            raise server.DashboardError("canonical verifier refused the receipt")

        with mock.patch.object(
            server,
            "verify_gcp_proof_acceptance_receipt_for_release",
            fake_verify,
        ):
            snapshot = self.snapshot()
        self.assert_named_current_holds(
            snapshot, upload_verified=16, gcp_fresh=False
        )
        self.assertEqual(
            snapshot["current_posture"]["gcp_proof"]["status"], "invalid"
        )

    def test_hostile_gcp_freeze_digest_mismatch_is_not_fresh(self) -> None:
        freeze = self._write_freeze_index()
        self.receipt("gcp-three-server-proof", self._gcp_acceptance_dimensions())

        def fake_verify(*args: object, **kwargs: object) -> dict[str, object]:
            return {
                "verified": True,
                "receipt_created_utc": server.iso_utc(NOW),
                "release": server.RELEASE_IDENTITY,
                "publication_authorized": False,
                "release_input_index": {
                    "path": freeze["path"],
                    "sha256": "0" * 64,
                },
            }

        with mock.patch.object(
            server,
            "verify_gcp_proof_acceptance_receipt_for_release",
            fake_verify,
        ):
            snapshot = self.snapshot()
        self.assert_named_current_holds(
            snapshot, upload_verified=16, gcp_fresh=False
        )
        self.assertEqual(
            snapshot["current_posture"]["gcp_proof"]["status"], "invalid"
        )

    def test_hostile_gcp_receipt_older_than_six_hours_is_stale(self) -> None:
        freeze = self._write_freeze_index()
        self.receipt("gcp-three-server-proof", self._gcp_acceptance_dimensions())
        stale_at = NOW - timedelta(hours=6, minutes=1)

        def fake_verify(*args: object, **kwargs: object) -> dict[str, object]:
            return {
                "verified": True,
                "receipt_created_utc": server.iso_utc(stale_at),
                "release": server.RELEASE_IDENTITY,
                "publication_authorized": False,
                "release_input_index": {
                    "path": freeze["path"],
                    "sha256": freeze["sha256"],
                },
            }

        with mock.patch.object(
            server,
            "verify_gcp_proof_acceptance_receipt_for_release",
            fake_verify,
        ):
            snapshot = self.snapshot()
        self.assert_named_current_holds(
            snapshot, upload_verified=16, gcp_fresh=False
        )
        self.assertEqual(
            snapshot["current_posture"]["gcp_proof"]["status"], "stale"
        )
        self.assertEqual(server.GCP_PROOF_FRESHNESS, timedelta(hours=6))

    def test_hostile_gcp_wrapper_uses_canonical_fleet_verifier(self) -> None:
        self._write_freeze_index()
        self.receipt("gcp-three-server-proof", self._gcp_acceptance_dimensions())
        calls: list[str] = []

        class FakeFleet:
            MAX_EVIDENCE_AGE = timedelta(hours=6)
            RECEIPT_NAME = "acceptance-receipt.json"

            def verify_acceptance_receipt_for_release(
                self,
                receipt_path: Path,
                *,
                repo_root: Path,
                release_input_index: Path,
            ) -> dict[str, object]:
                del repo_root, release_input_index
                calls.append(receipt_path.name)
                raise RuntimeError("canonical verifier refused")

        with mock.patch.object(
            server, "_load_gcp_proof_module", return_value=FakeFleet()
        ):
            snapshot = self.snapshot()
        self.assertEqual(calls, ["acceptance-receipt.json", "acceptance-receipt.json"])
        self.assert_named_current_holds(
            snapshot, upload_verified=16, gcp_fresh=False
        )


if __name__ == "__main__":
    unittest.main()
