#!/usr/bin/env python3
"""Focused tests for operator Chrome/Edge visibility and Android TV AAB coverage."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from dashboard import server


CONFIG = Path(__file__).with_name("state.json")
STATIC_INDEX = Path(__file__).with_name("static") / "index.html"
STATIC_APP = Path(__file__).with_name("static") / "app.js"
LIVE_INDEX = Path(__file__).with_name("index.html")
DENOMINATOR_CRITICAL_SHELL_COPY = (
    "Chrome and Edge stay distinct. "
    "Android TV AAB remains one of the 16 required upload targets."
)
NOW = datetime(2026, 8, 23, 13, 30, tzinfo=timezone.utc)


def _shell_subtitle(html: str) -> str:
    marker = '<div class="subtitle">'
    start = html.index(marker) + len(marker)
    return html[start : html.index("</div>", start)]


class OperatorCoverageTest(unittest.TestCase):
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

    def artifact(self, target: str, name: str) -> dict[str, str]:
        relative = Path(target) / name
        path = self.evidence / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = ("verified " + target + ":" + name + "\n").encode("ascii")
        path.write_bytes(payload)
        os.utime(path, (NOW.timestamp(), NOW.timestamp()))
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
        artifact: dict[str, str] | None = None,
    ) -> dict[str, object]:
        contract = server.DIMENSION_EVIDENCE_CONTRACT.get(
            dimension,
            server.BLOCKER_AUDIT_CONTRACT
            if dimension == "blocker_audit"
            else server.OPEN_BLOCKER_CONTRACT,
        )
        return {
            "status": "pass",
            "observed_at": server.iso_utc(NOW),
            "producer": contract[1],
            "evidence_type": contract[0],
            "summary_code": dimension + "_evidence",
            "artifacts": [artifact or self.artifact(target, dimension + ".proof")],
        }

    def receipt(
        self,
        target: str,
        dimensions: dict[str, object],
        *,
        blockers: list[object] | None = None,
    ) -> None:
        value = {
            "schema_version": 4,
            "release": server.RELEASE_IDENTITY,
            "target": target,
            "generated_at": server.iso_utc(NOW),
            "dimensions": dimensions,
            "blocker_audit": self.check(target, "blocker_audit"),
            "blockers": [] if blockers is None else blockers,
        }
        path = self.evidence / (target + ".json")
        path.write_text(json.dumps(value), encoding="ascii")
        os.utime(path, (NOW.timestamp(), NOW.timestamp()))

    def all_dimensions(self, target: str) -> dict[str, object]:
        return {
            dimension["id"]: self.check(target, dimension["id"])
            for dimension in server.load_config(CONFIG)["dimensions"]
        }

    def test_android_tv_aab_is_in_dashboard_contract(self) -> None:
        config = json.loads(CONFIG.read_text(encoding="ascii"))
        html = Path(__file__).with_name("index.html").read_text(encoding="ascii")
        app = Path(__file__).with_name("static").joinpath("app.js").read_text(encoding="ascii")
        required = config["cross_store"]["required_upload_targets"]
        self.assertEqual(len(required), 16)
        self.assertIn("android-tv-aab", required)
        self.assertIn("android-phone-tablet-aab", required)
        self.assertIn("edge-extension-package", required)
        self.assertIn("android-tv-aab", app)
        self.assertIn("16 required", html)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, html)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, _shell_subtitle(html))
        self.assertIn("edge-extension", app)

    def test_chrome_and_edge_operator_mappings_are_distinct(self) -> None:
        self.assertEqual(
            server.DASHBOARD_UPLOAD_TARGET_MAP["chrome-extension"],
            ("chrome-extension-package", "edge-extension-package"),
        )
        self.assertNotIn(
            server.OPERATOR_EDGE_TARGET_ID,
            server.DASHBOARD_UPLOAD_TARGET_MAP,
        )
        self.assertEqual(
            server.OPERATOR_UPLOAD_TARGET_MAP["chrome-extension"],
            ("chrome-extension-package",),
        )
        self.assertEqual(
            server.OPERATOR_UPLOAD_TARGET_MAP[server.OPERATOR_EDGE_TARGET_ID],
            ("edge-extension-package",),
        )
        self.assertNotEqual(
            server.OPERATOR_UPLOAD_TARGET_MAP["chrome-extension"],
            server.OPERATOR_UPLOAD_TARGET_MAP[server.OPERATOR_EDGE_TARGET_ID],
        )
        represented = {
            upload_target
            for upload_targets in server.OPERATOR_UPLOAD_TARGET_MAP.values()
            for upload_target in upload_targets
        }
        self.assertEqual(represented, set(server.REQUIRED_UPLOAD_TARGET_IDS))
        self.assertEqual(len(represented), 16)
        self.assertIn("android-tv-aab", represented)
        self.assertIn("edge-extension-package", represented)
        self.assertIn(
            "android-tv-aab",
            server.DASHBOARD_UPLOAD_TARGET_MAP["android"],
        )

    def test_operator_view_shows_distinct_chrome_and_edge_cards(self) -> None:
        self.receipt("chrome-extension", self.all_dimensions("chrome-extension"))

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
            snapshot = server.build_snapshot(
                CONFIG,
                self.evidence,
                NOW,
                repo_root=self.repo,
                cache_path=self.cache_path,
            )
        scored = next(
            item for item in snapshot["targets"] if item["id"] == "chrome-extension"
        )
        chrome = next(
            item
            for item in snapshot["operator_targets"]
            if item["id"] == "chrome-extension"
        )
        edge = next(
            item
            for item in snapshot["operator_targets"]
            if item["id"] == "edge-extension"
        )
        self.assertEqual(snapshot["target_count"], len(server.REQUIRED_TARGETS))
        self.assertEqual(
            len(snapshot["operator_targets"]),
            len(server.REQUIRED_TARGETS) + 1,
        )
        self.assertEqual(
            scored["upload_targets"],
            ["chrome-extension-package", "edge-extension-package"],
        )
        self.assertEqual(scored["status"], "partial")
        self.assertEqual(scored["readiness"], 0)
        self.assertEqual(chrome["upload_targets"], ["chrome-extension-package"])
        self.assertEqual(edge["upload_targets"], ["edge-extension-package"])
        self.assertEqual(chrome["cross_store_status"], "verified")
        self.assertEqual(edge["cross_store_status"], "missing")
        self.assertEqual(chrome["status"], "ready")
        self.assertEqual(chrome["readiness"], 100)
        self.assertNotEqual(edge["status"], "ready")
        self.assertEqual(edge["readiness"], 0)
        self.assertEqual(snapshot["overall_readiness"], 0)
        self.assertEqual(snapshot["ready_targets"], 0)
        represented = {
            upload_target
            for target in snapshot["operator_targets"]
            for upload_target in target["upload_targets"]
        }
        self.assertEqual(represented, set(server.REQUIRED_UPLOAD_TARGET_IDS))
        self.assertEqual(len(snapshot["cross_store"]["receipts"]), 16)
        self.assertEqual(snapshot["current_posture"]["publication_hold"], "DO-NOT-UPLOAD")
        self.assertFalse(snapshot["current_posture"]["store_upload_authorized"])
        self.assertIn(
            "android-tv-aab",
            snapshot["cross_store"]["required_upload_targets"],
        )

    def test_missing_receipts_cannot_claim_upload_readiness(self) -> None:
        self.receipt("chrome-extension", self.all_dimensions("chrome-extension"))
        self.receipt("android", self.all_dimensions("android"))

        def missing_required_packages(
            repo_root: Path,
            release_input_index: Path,
            target_id: str,
            receipt_path: Path,
            now: datetime,
        ) -> dict[str, object]:
            if target_id in {
                "chrome-extension-package",
                "edge-extension-package",
                "android-tv-aab",
            }:
                raise server.CrossStoreReceiptMissing(
                    f"required {target_id} schema-v2 receipt is missing"
                )
            return self.verified_cross_store_receipt(
                repo_root, release_input_index, target_id, receipt_path, now
            )

        with mock.patch.object(
            server,
            "verify_cross_store_upload_receipt",
            side_effect=missing_required_packages,
        ):
            snapshot = server.build_snapshot(
                CONFIG,
                self.evidence,
                NOW,
                repo_root=self.repo,
                cache_path=self.cache_path,
            )
        self.assertEqual(snapshot["overall_readiness"], 0)
        self.assertNotEqual(snapshot["overall_readiness"], 100)
        by_id = {item["id"]: item for item in snapshot["operator_targets"]}
        self.assertEqual(by_id["chrome-extension"]["readiness"], 0)
        self.assertNotEqual(by_id["chrome-extension"]["status"], "ready")
        self.assertEqual(by_id["edge-extension"]["readiness"], 0)
        self.assertNotEqual(by_id["edge-extension"]["status"], "ready")
        android = by_id["android"]
        self.assertEqual(android["readiness"], 0)
        self.assertNotEqual(android["status"], "ready")
        self.assertEqual(android["cross_store_status"], "partial")
        self.assertEqual(
            [receipt["target_id"] for receipt in android["cross_store_receipts"]],
            ["android-phone-tablet-aab", "android-tv-aab"],
        )
        self.assertEqual(
            [receipt["status"] for receipt in android["cross_store_receipts"]],
            ["verified", "missing"],
        )

    def test_blocker_summary_counts_chrome_and_edge_surfaces(self) -> None:
        owner = self.check(
            "chrome-extension",
            "owner_signing",
            artifact=self.artifact("chrome-extension", "owner.proof"),
        )
        owner.update({"id": "edge_listing_assets", "kind": "owner"})
        external = self.check(
            "chrome-extension",
            "store_review",
            artifact=self.artifact("chrome-extension", "review.proof"),
        )
        external.update({"id": "edge_store_review", "kind": "external"})
        self.receipt(
            "chrome-extension",
            self.all_dimensions("chrome-extension"),
            blockers=[owner, external],
        )
        snapshot = server.build_snapshot(
            CONFIG,
            self.evidence,
            NOW,
            repo_root=self.repo,
            cache_path=self.cache_path,
        )
        summary = snapshot["blocker_summary"]
        self.assertGreaterEqual(summary["owner"], 2)
        self.assertGreaterEqual(summary["external"], 2)
        owner_surfaces = {
            item["target_id"]
            for item in summary["items"]
            if item["kind"] == "owner"
        }
        external_surfaces = {
            item["target_id"]
            for item in summary["items"]
            if item["kind"] == "external"
        }
        self.assertIn("chrome-extension", owner_surfaces)
        self.assertIn("edge-extension", owner_surfaces)
        self.assertIn("chrome-extension", external_surfaces)
        self.assertIn("edge-extension", external_surfaces)
        self.assertEqual(
            summary["count"],
            summary["owner"] + summary["external"] + summary["undisclosed_audits"],
        )

    def test_missing_audits_are_not_shown_as_zero_blockers(self) -> None:
        snapshot = server.build_snapshot(
            CONFIG,
            self.evidence,
            NOW,
            repo_root=self.repo,
            cache_path=self.cache_path,
        )
        summary = snapshot["blocker_summary"]
        self.assertGreaterEqual(summary["undisclosed_audits"], 21)
        self.assertEqual(snapshot["cross_store"]["required_upload_target_count"], 16)
        self.assertEqual(snapshot["target_count"], 20)
        self.assertNotEqual(
            snapshot["cross_store"]["required_upload_target_count"],
            summary["undisclosed_audits"],
        )
        self.assertNotEqual(snapshot["target_count"], summary["undisclosed_audits"])
        self.assertGreater(summary["count"], 0)
        edge_undisclosed = [
            item
            for item in summary["items"]
            if item["target_id"] == "edge-extension" and item["kind"] == "undisclosed"
        ]
        self.assertTrue(edge_undisclosed)
        failure = server.build_failure_snapshot(NOW)
        self.assertGreaterEqual(failure["blocker_summary"]["undisclosed_audits"], 21)
        failure_ids = {item["id"] for item in failure["operator_targets"]}
        self.assertIn("chrome-extension", failure_ids)
        self.assertIn("edge-extension", failure_ids)

    def test_static_operator_ui_keeps_chrome_edge_and_tv_aab_visible(self) -> None:
        html = STATIC_INDEX.read_text(encoding="ascii")
        app = STATIC_APP.read_text(encoding="ascii")
        self.assertIn('src="/app.js"', html)
        self.assertIn("Owner blockers", html)
        self.assertIn("External blockers", html)
        self.assertIn("Required upload targets", html)
        self.assertIn("Pending", html)
        self.assertIn("Failed", html)
        self.assertIn("Freshness", html)
        self.assertIn("Store-upload coverage", html)
        self.assertIn("Engineering/operator targets (20)", html)
        self.assertIn("0 / 16", html)
        self.assertIn("0 / 20", html)
        self.assertNotIn("0 / 21", html)
        self.assertIn("not a store denominator", html)
        self.assertIn("not 21 Chrome/Edge blocker-audit entries", app)
        self.assertIn("DO-NOT-UPLOAD", html)
        self.assertIn("Active blocker categories", html)
        self.assertIn("android-tv-aab", app)
        self.assertIn("edge-extension-package", app)
        self.assertIn('["chrome-extension-package"]', app)
        self.assertIn('["edge-extension-package"]', app)
        self.assertIn("edge-extension", app)
        self.assertIn("validOperatorTargets", app)
        self.assertIn("validBlockerSummary", app)
        self.assertIn("validCoverage", app)
        self.assertIn("validCurrentPosture", app)
        self.assertIn("claimsReadinessFromMissingReceipts", app)
        self.assertIn("state.operator_targets", app)
        self.assertIn("state.current_posture", app)
        live = LIVE_INDEX.read_text(encoding="ascii")
        self.assertIn("validCoverage", app)
        self.assertIn("android-tv-aab", app)
        self.assertIn("edge-extension", app)
        self.assertIn("DO-NOT-UPLOAD", live)
        self.assertIn("validCurrentPosture", app)
        self.assertIn('src="/app.js"', live)
        self.assertNotIn("innerHTML", app)
        self.assertEqual(server.DASHBOARD_INDEX.resolve(), LIVE_INDEX.resolve())
        self.assertEqual(server.INDEX, STATIC_INDEX.resolve())
        self.assertEqual(server.APP_JS, STATIC_APP.resolve())
        self.assertEqual(server.DASHBOARD_INDEX.read_bytes(), server.INDEX.read_bytes())
        self.assertEqual(live, html)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, live)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, html)
        self.assertIn(DENOMINATOR_CRITICAL_SHELL_COPY, _shell_subtitle(live))
        self.assertEqual(_shell_subtitle(live), _shell_subtitle(html))
        self.assertTrue(all(ord(character) < 128 for character in html))
        self.assertTrue(all(ord(character) < 128 for character in app))
        self.assertTrue(all(ord(character) < 128 for character in live))


if __name__ == "__main__":
    unittest.main()
