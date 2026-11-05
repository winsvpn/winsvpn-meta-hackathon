#!/usr/bin/env python3
"""Focused regressions for the Double VPN Core dark-start promotion latch."""

from __future__ import annotations

import asyncio
import logging
import shutil
import sqlite3
import unittest
from contextlib import contextmanager
from pathlib import Path

import test_account_deletion_hub as harness


ADMIN_TOKEN = "test-admin-token"
CORE_TOKEN = "test-core-token-with-enough-entropy"
EVIDENCE_SHA256 = "a" * 64
CORE_INSTALLER = Path(__file__).resolve().parent / "wins_core_server_setup_ONETOUCH.sh"


def core_registration(mod, *, runtime_ready: bool) -> object:
    return mod.CoreRegistration(
        core_id=mod.DOUBLE_VPN_CORE_ID,
        name="Test Double VPN Core",
        region="test-region",
        management_host="core-management.test",
        management_user="ubuntu",
        ingress_endpoint="core.test:9210",
        tunnel_gateway_ipv4="10.255.0.1",
        ingress_public_key="test-ingress-public-key",
        exit_public_key="test-exit-public-key",
        stealth_endpoint="core.test:80",
        xray_uuid="test-xray-uuid",
        xray_path="/wins-core-tunnel",
        xray_security="none",
        stealth_transports=[],
        regional_aliases=["core.test"],
        direct_awg_enabled=True,
        status="online",
        runtime_ready=runtime_ready,
        applied_assignment_revisions=[],
    )


class CoreDarkStartLatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0", DOUBLE_VPN_ENABLED="1")
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.logger.propagate = False
        self.request = harness.FakeRequest(
            headers={"x-admin-token": ADMIN_TOKEN},
            path="/admin/core/promote",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.mod._TMPDIR, ignore_errors=True)

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.mod._DB)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def seed_core_token(self) -> None:
        with self.db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute(
                "INSERT INTO core_servers (core_id, core_token_hash) VALUES (?, ?)",
                (self.mod.DOUBLE_VPN_CORE_ID, self.mod.token_digest(CORE_TOKEN)),
            )

    def register(self, *, runtime_ready: bool, core_token: str = CORE_TOKEN) -> dict:
        return self.mod.register_core(
            core_registration(self.mod, runtime_ready=runtime_ready),
            harness.FakeRequest(path="/api/v1/core/register"),
            x_core_token=core_token,
        )

    def make_promotable(self) -> None:
        now = self.mod.utcnow().isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE core_servers SET status='online', runtime_ready=1,"
                " management_status='ok', management_checked_at=?,"
                " last_heartbeat=?, runtime_checked_at=? WHERE core_id=?",
                (now, now, now, self.mod.DOUBLE_VPN_CORE_ID),
            )

    def request_promotion(
        self,
        *,
        evidence_sha256: str = EVIDENCE_SHA256,
        confirm_core_id: str | None = None,
    ) -> dict:
        core_id = self.mod.DOUBLE_VPN_CORE_ID
        return self.mod.admin_promote_core(
            self.request,
            core_id=core_id,
            confirm_core_id=core_id if confirm_core_id is None else confirm_core_id,
            evidence_sha256=evidence_sha256,
            x_admin_token=ADMIN_TOKEN,
        )

    def acknowledge_promotion(self, promotion_id: str) -> dict:
        return self.mod.acknowledge_core_promotion(
            self.mod.CorePromotionAcknowledgement(
                core_id=self.mod.DOUBLE_VPN_CORE_ID,
                promotion_id=promotion_id,
            ),
            harness.FakeRequest(path="/api/v1/core/promotion/ack"),
            x_core_token=CORE_TOKEN,
        )

    def promote(
        self,
        *,
        evidence_sha256: str = EVIDENCE_SHA256,
        confirm_core_id: str | None = None,
    ) -> dict:
        pending = self.request_promotion(
            evidence_sha256=evidence_sha256,
            confirm_core_id=confirm_core_id,
        )
        return self.acknowledge_promotion(pending["promotion_id"])

    def withdraw(self) -> dict:
        return self.mod.admin_withdraw_core(
            self.request,
            core_id=self.mod.DOUBLE_VPN_CORE_ID,
            x_admin_token=ADMIN_TOKEN,
        )

    def core(self) -> sqlite3.Row:
        with self.db() as conn:
            row = conn.execute(
                "SELECT * FROM core_servers WHERE core_id=?",
                (self.mod.DOUBLE_VPN_CORE_ID,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row

    def promotion_count(self) -> int:
        with self.db() as conn:
            return conn.execute("SELECT COUNT(*) FROM core_promotion_events").fetchone()[0]

    def seed_selectable_exit(self) -> None:
        now = self.mod.utcnow().isoformat()
        with self.db() as conn:
            conn.execute(
                "INSERT INTO nodes (slug, name, status, management_status, management_checked_at,"
                " operator_enabled, data_plane_status, data_plane_checked_at, data_plane_ok_at,"
                " endpoint, public_key, last_heartbeat) VALUES "
                "('test-exit', 'Test Exit', 'online', 'ok', ?, 1, 'ok', ?, ?,"
                " 'exit.test:9110', 'test-exit-public-key', ?)",
                (now, now, now, now),
            )

    def test_fresh_and_legacy_schemas_default_every_core_dark(self) -> None:
        with self.db() as conn:
            self.mod.ensure_schema(conn)
            columns = {
                row["name"]: row for row in conn.execute("PRAGMA table_info(core_servers)")
            }
            self.assertEqual(columns["promoted"]["notnull"], 1)
            self.assertEqual(columns["promoted"]["dflt_value"], "0")
            for field in (
                "pending_promotion_id",
                "pending_promotion_evidence_sha256",
                "pending_promotion_operator_source_hash",
                "pending_promotion_requested_at",
                "active_promotion_id",
            ):
                self.assertIn(field, columns)
            conn.execute("INSERT INTO core_servers (core_id) VALUES ('fresh-dark')")
            self.assertEqual(
                conn.execute(
                    "SELECT promoted FROM core_servers WHERE core_id='fresh-dark'"
                ).fetchone()[0],
                0,
            )

        legacy_path = self.mod._TMPDIR + "/legacy-core.db"
        legacy = sqlite3.connect(legacy_path)
        legacy.row_factory = sqlite3.Row
        legacy.execute(
            "CREATE TABLE core_servers (core_id TEXT PRIMARY KEY, status TEXT, runtime_ready INTEGER)"
        )
        legacy.execute("INSERT INTO core_servers VALUES ('legacy-core', 'online', 1)")
        self.mod.ensure_schema(legacy)
        row = legacy.execute(
            "SELECT status, runtime_ready, promoted FROM core_servers WHERE core_id='legacy-core'"
        ).fetchone()
        self.assertEqual(tuple(row), ("online", 1, 0))
        legacy.close()

    def test_bootstrap_placeholder_and_registration_are_dark_with_boolean_response(self) -> None:
        grant_request = harness.FakeRequest(path="/admin/bootstrap-grant")
        grant = self.mod.mint_bootstrap_grant(
            self.mod.BootstrapGrantRequest(
                role="core", subject_id=self.mod.DOUBLE_VPN_CORE_ID
            ),
            grant_request,
            x_admin_token=ADMIN_TOKEN,
        )["bootstrap_token"]
        bootstrap = self.mod.bootstrap_core(
            self.mod.CoreBootstrapRequest(
                core_id=self.mod.DOUBLE_VPN_CORE_ID,
                bootstrap_token=grant,
            ),
            harness.FakeRequest(path="/api/v1/core/bootstrap"),
        )
        response = self.register(
            runtime_ready=False,
            core_token=bootstrap["core_token"],
        )
        self.assertIs(type(response["promoted"]), bool)
        self.assertFalse(response["promoted"])
        self.assertEqual(response["pending_promotion_id"], "")
        self.assertEqual(response["active_promotion_id"], "")
        self.assertEqual(self.core()["promoted"], 0)

    def test_promotion_is_pending_until_exact_core_ack_and_retry_is_idempotent(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        self.seed_selectable_exit()

        pending = self.request_promotion()
        promotion_id = pending["promotion_id"]
        self.assertFalse(pending["promoted"])
        self.assertTrue(pending["promotion_pending"])
        self.assertEqual(self.promotion_count(), 0)
        self.assertEqual(self.core()["pending_promotion_id"], promotion_id)
        with self.db() as conn:
            self.assertIsNone(self.mod.select_double_vpn_core(conn))

        registered = self.register(runtime_ready=True)
        self.assertFalse(registered["promoted"])
        self.assertEqual(registered["pending_promotion_id"], promotion_id)
        with self.assertRaises(harness.HTTPException) as refused:
            self.acknowledge_promotion("b" * 32)
        self.assertEqual(refused.exception.status_code, 409)
        self.assertEqual(self.promotion_count(), 0)

        acknowledged = self.acknowledge_promotion(promotion_id)
        self.assertTrue(acknowledged["promoted"])
        self.assertFalse(acknowledged["idempotent"])
        self.assertEqual(acknowledged["active_promotion_id"], promotion_id)
        self.assertEqual(self.promotion_count(), 1)
        with self.db() as conn:
            self.assertIsNotNone(self.mod.select_double_vpn_core(conn))

        retry = self.acknowledge_promotion(promotion_id)
        self.assertTrue(retry["idempotent"])
        self.assertEqual(self.promotion_count(), 1)

    def test_ready_registration_preserves_manual_promotion(self) -> None:
        self.seed_core_token()
        dark = self.register(runtime_ready=True)
        self.assertIs(type(dark["promoted"]), bool)
        self.assertFalse(dark["promoted"])
        self.make_promotable()
        promoted = self.promote()
        self.assertTrue(promoted["promoted"])
        ready = self.register(runtime_ready=True)
        self.assertIs(type(ready["promoted"]), bool)
        self.assertTrue(ready["promoted"])
        self.assertEqual(self.core()["promoted"], 1)

    def test_stale_ready_registration_demotes_and_never_repromotes(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        self.promote()
        stale = (
            self.mod.utcnow()
            - self.mod.timedelta(seconds=self.mod.DOUBLE_VPN_CORE_STALE_SECONDS + 1)
        ).isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE core_servers SET last_heartbeat=?, runtime_checked_at=?, "
                "management_checked_at=? WHERE core_id=?",
                (stale, stale, stale, self.mod.DOUBLE_VPN_CORE_ID),
            )
            conn.execute(
                "INSERT INTO double_vpn_assignments "
                "(device_id, core_id, status, applied_revision, runtime_validated_at) "
                "VALUES ('stale-core-device', ?, 'active', ?, ?)",
                (self.mod.DOUBLE_VPN_CORE_ID, "b" * 64, self.mod.utcnow().isoformat()),
            )

        recovered = self.register(runtime_ready=True)
        self.assertFalse(recovered["promoted"])
        core = self.core()
        self.assertEqual(core["status"], "online")
        self.assertEqual(core["runtime_ready"], 1)
        self.assertEqual(core["promoted"], 0)
        self.assertEqual(self.promotion_count(), 1)
        with self.db() as conn:
            assignment = conn.execute(
                "SELECT status, applied_revision, runtime_validated_at "
                "FROM double_vpn_assignments WHERE device_id='stale-core-device'"
            ).fetchone()
        self.assertEqual(tuple(assignment), ("inactive", None, None))

        again = self.register(runtime_ready=True)
        self.assertFalse(again["promoted"])
        self.make_promotable()
        self.promote()
        self.assertEqual(self.promotion_count(), 2)

    def test_stale_pending_promotion_is_cancelled_before_heartbeat_refresh(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        pending = self.request_promotion()
        stale = (
            self.mod.utcnow()
            - self.mod.timedelta(seconds=self.mod.DOUBLE_VPN_CORE_STALE_SECONDS + 1)
        ).isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE core_servers SET last_heartbeat=?, runtime_checked_at=?, "
                "management_checked_at=? WHERE core_id=?",
                (stale, stale, stale, self.mod.DOUBLE_VPN_CORE_ID),
            )

        recovered = self.register(runtime_ready=True)
        self.assertFalse(recovered["promoted"])
        self.assertEqual(recovered["pending_promotion_id"], "")
        self.assertIsNone(self.core()["pending_promotion_id"])
        with self.assertRaises(harness.HTTPException) as refused:
            self.acknowledge_promotion(pending["promotion_id"])
        self.assertEqual(refused.exception.status_code, 409)
        self.assertEqual(self.promotion_count(), 0)

    def test_selection_requires_promotion_and_every_existing_readiness_gate(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        self.seed_selectable_exit()
        with self.db() as conn:
            self.assertIsNone(self.mod.select_double_vpn_core(conn))
        self.promote()
        with self.db() as conn:
            selected = self.mod.select_double_vpn_core(conn)
            self.assertIsNotNone(selected)
            self.assertEqual(selected["core_id"], self.mod.DOUBLE_VPN_CORE_ID)
            conn.execute(
                "UPDATE core_servers SET runtime_ready=0 WHERE core_id=?",
                (self.mod.DOUBLE_VPN_CORE_ID,),
            )
            self.assertIsNone(self.mod.select_double_vpn_core(conn))

    def test_public_hoppy_snapshot_never_bypasses_canonical_core_selection(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=False)
        snapshot = self.mod.site_public_snapshot()
        self.assertIn("Double VPN public availability: not available yet", snapshot)

        source = harness._extract_main_block()
        for function_name, next_name in (
            ("site_gemini_answer", "site_vertex_access_token"),
            ("site_vertex_answer", "site_local_llm_answer"),
            ("site_local_llm_answer", "run_site_ai"),
        ):
            with self.subTest(backend=function_name):
                body = source.split(f"def {function_name}(", 1)[1].split(
                    f"\ndef {next_name}(", 1
                )[0]
                self.assertIn("site_public_snapshot()", body)

        self.register(runtime_ready=True)
        self.make_promotable()
        self.seed_selectable_exit()
        self.promote()
        self.assertIn("Double VPN public availability: available", self.mod.site_public_snapshot())

    def test_operator_dark_or_retired_only_exit_is_never_advertised(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        self.seed_selectable_exit()
        self.promote()

        advertised = asyncio.run(self.mod.list_public_nodes())
        self.assertTrue(advertised["double_vpn_available"])
        self.assertTrue(advertised["double_vpn"]["available"])

        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET operator_enabled=0 WHERE slug='test-exit'"
            )
            self.assertIsNone(self.mod.select_double_vpn_core(conn))
        operator_dark = asyncio.run(self.mod.list_public_nodes())
        self.assertFalse(operator_dark["double_vpn_available"])
        self.assertFalse(operator_dark["doublevpnavailable"])
        self.assertFalse(operator_dark["double_vpn"]["available"])

        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET operator_enabled=1, retired_at=? "
                "WHERE slug='test-exit'",
                (self.mod.utcnow().isoformat(),),
            )
            self.assertIsNone(self.mod.select_double_vpn_core(conn))
        retired = asyncio.run(self.mod.list_public_nodes())
        self.assertFalse(retired["double_vpn_available"])
        self.assertFalse(retired["double_vpn"]["available"])

        with self.db() as conn:
            conn.execute("UPDATE nodes SET retired_at=NULL WHERE slug='test-exit'")
            self.assertIsNotNone(self.mod.select_double_vpn_core(conn))
        restored = asyncio.run(self.mod.list_public_nodes())
        self.assertTrue(restored["double_vpn_available"])

    def test_promotion_refuses_missing_evidence_confirmation_and_stale_health(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        cases = (
            ({"evidence_sha256": ""}, 400),
            ({"confirm_core_id": "wrong-core"}, 400),
        )
        for kwargs, status in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(harness.HTTPException) as refused:
                    self.promote(**kwargs)
                self.assertEqual(refused.exception.status_code, status)
                self.assertEqual(self.core()["promoted"], 0)
                self.assertEqual(self.promotion_count(), 0)

        stale = (
            self.mod.utcnow()
            - self.mod.timedelta(seconds=self.mod.DOUBLE_VPN_CORE_STALE_SECONDS + 1)
        ).isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE core_servers SET management_checked_at=? WHERE core_id=?",
                (stale, self.mod.DOUBLE_VPN_CORE_ID),
            )
        with self.assertRaises(harness.HTTPException) as refused:
            self.promote()
        self.assertEqual(refused.exception.status_code, 409)
        self.assertEqual(self.core()["promoted"], 0)
        self.assertEqual(self.promotion_count(), 0)

    def test_promotion_evidence_is_immutable_and_rolls_back_with_the_latch(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        result = self.promote()
        self.assertRegex(result["promotion_id"], r"^[0-9a-f]{32}$")
        with self.db() as conn:
            event = conn.execute(
                "SELECT * FROM core_promotion_events WHERE promotion_id=?",
                (result["promotion_id"],),
            ).fetchone()
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(core_promotion_events)")
            }
            self.assertNotIn("reason", columns)
            self.assertNotIn("source_ip", columns)
            self.assertEqual(event["evidence_sha256"], EVIDENCE_SHA256)
            self.assertNotEqual(event["operator_source_hash"], self.request.client.host)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "UPDATE core_promotion_events SET core_status='offline' WHERE promotion_id=?",
                    (result["promotion_id"],),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "DELETE FROM core_promotion_events WHERE promotion_id=?",
                    (result["promotion_id"],),
                )

        self.withdraw()
        self.make_promotable()
        with self.db() as conn:
            conn.execute(
                "CREATE TRIGGER test_reject_core_promotion BEFORE INSERT ON core_promotion_events "
                "BEGIN SELECT RAISE(ABORT, 'forced evidence failure'); END"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.promote()
        self.assertEqual(self.core()["promoted"], 0)
        self.assertEqual(self.promotion_count(), 1)

    def test_withdrawal_needs_no_health_and_invalidates_live_assignments(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        self.promote()
        with self.db() as conn:
            conn.execute(
                "INSERT INTO double_vpn_assignments "
                "(device_id, core_id, status, applied_revision, runtime_validated_at) "
                "VALUES ('device-one', ?, 'active', ?, ?)",
                (self.mod.DOUBLE_VPN_CORE_ID, "b" * 64, self.mod.utcnow().isoformat()),
            )
            conn.execute(
                "UPDATE core_servers SET status='offline', management_status='failed' WHERE core_id=?",
                (self.mod.DOUBLE_VPN_CORE_ID,),
            )
        result = self.withdraw()
        self.assertFalse(result["promoted"])
        self.assertEqual(result["invalidated_assignment_count"], 1)
        core = self.core()
        self.assertEqual(core["promoted"], 0)
        self.assertEqual(core["runtime_ready"], 0)
        with self.db() as conn:
            assignment = conn.execute(
                "SELECT status, applied_revision, runtime_validated_at "
                "FROM double_vpn_assignments WHERE device_id='device-one'"
            ).fetchone()
        self.assertEqual(tuple(assignment), ("inactive", None, None))
        again = self.withdraw()
        self.assertFalse(again["was_promoted"])
        self.assertEqual(again["invalidated_assignment_count"], 0)

    def test_installer_withdrawal_generation_cannot_restore_promotion(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        self.seed_selectable_exit()
        self.promote()
        with self.db() as conn:
            conn.execute(
                "INSERT INTO double_vpn_assignments "
                "(device_id, core_id, exit_slug, status, applied_revision, runtime_validated_at) "
                "VALUES ('installer-core-device', ?, 'test-exit', 'active', ?, ?)",
                (self.mod.DOUBLE_VPN_CORE_ID, "d" * 64, self.mod.utcnow().isoformat()),
            )
            conn.execute(
                "CREATE TRIGGER reject_core_installer_assignment_invalidation "
                "BEFORE UPDATE OF status ON double_vpn_assignments "
                "BEGIN SELECT RAISE(ABORT, 'forced Core invalidation failure'); END"
            )

        with self.assertRaises(harness.HTTPException) as forged:
            self.mod.withdraw_core_for_deployment(
                self.mod.DOUBLE_VPN_CORE_ID,
                harness.FakeRequest(path="/api/v1/core/deployment/withdraw"),
                x_core_token="wrong-core-token-with-enough-entropy",
            )
        self.assertEqual(forged.exception.status_code, 401)
        self.assertEqual(self.core()["promoted"], 1)

        with self.assertRaises(sqlite3.IntegrityError):
            self.mod.withdraw_core_for_deployment(
                self.mod.DOUBLE_VPN_CORE_ID,
                harness.FakeRequest(path="/api/v1/core/deployment/withdraw"),
                x_core_token=CORE_TOKEN,
            )
        core = self.core()
        self.assertEqual(core["promoted"], 1)
        self.assertIsNone(core["deployment_withdrawal_id"])
        with self.db() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM double_vpn_assignments "
                    "WHERE device_id='installer-core-device'"
                ).fetchone()[0],
                "active",
            )
            conn.execute("DROP TRIGGER reject_core_installer_assignment_invalidation")

        withdrawn = self.mod.withdraw_core_for_deployment(
            self.mod.DOUBLE_VPN_CORE_ID,
            harness.FakeRequest(path="/api/v1/core/deployment/withdraw"),
            x_core_token=CORE_TOKEN,
        )
        self.assertFalse(withdrawn["promoted"])
        self.assertFalse(withdrawn["runtime_ready"])
        self.assertEqual(withdrawn["invalidated_assignment_count"], 1)
        self.assertRegex(withdrawn["withdrawal_id"], r"^[0-9a-f]{32}$")
        core = self.core()
        self.assertEqual(core["status"], "maintenance")
        self.assertEqual(core["promoted"], 0)
        self.assertEqual(core["active_promotion_id"], None)
        self.assertEqual(core["deployment_withdrawal_id"], withdrawn["withdrawal_id"])

        registered = self.register(runtime_ready=True)
        self.assertFalse(registered["promoted"])
        self.make_promotable()
        with self.assertRaises(harness.HTTPException) as blocked:
            self.request_promotion(evidence_sha256="e" * 64)
        self.assertEqual(blocked.exception.status_code, 409)

        with self.assertRaises(harness.HTTPException) as wrong_generation:
            self.mod.complete_core_deployment(
                self.mod.DOUBLE_VPN_CORE_ID,
                self.mod.DeploymentWithdrawalCompletion(withdrawal_id="0" * 32),
                harness.FakeRequest(path="/api/v1/core/deployment/complete"),
                x_core_token=CORE_TOKEN,
            )
        self.assertEqual(wrong_generation.exception.status_code, 409)
        self.assertEqual(
            self.core()["deployment_withdrawal_id"], withdrawn["withdrawal_id"]
        )

        completed = self.mod.complete_core_deployment(
            self.mod.DOUBLE_VPN_CORE_ID,
            self.mod.DeploymentWithdrawalCompletion(
                withdrawal_id=withdrawn["withdrawal_id"]
            ),
            harness.FakeRequest(path="/api/v1/core/deployment/complete"),
            x_core_token=CORE_TOKEN,
        )
        self.assertFalse(completed["promoted"])
        self.assertEqual(self.core()["promoted"], 0)
        self.promote(evidence_sha256="e" * 64)
        self.assertEqual(self.promotion_count(), 2)

    def test_admin_auth_and_contract_are_not_bypassable_from_registration(self) -> None:
        self.seed_core_token()
        self.register(runtime_ready=True)
        self.make_promotable()
        with self.assertRaises(harness.HTTPException) as refused:
            self.mod.admin_promote_core(
                self.request,
                core_id=self.mod.DOUBLE_VPN_CORE_ID,
                confirm_core_id=self.mod.DOUBLE_VPN_CORE_ID,
                evidence_sha256=EVIDENCE_SHA256,
                x_admin_token="wrong-admin-token",
            )
        self.assertEqual(refused.exception.status_code, 401)
        self.assertNotIn("promoted", self.mod.CoreRegistration.__annotations__)
        source = harness._extract_main_block()
        register_source = source.split('def register_core(', 1)[1].split(
            '\n@app.post("/admin/core/promote")', 1
        )[0]
        self.assertIn('"promoted": promoted', register_source)
        self.assertNotIn("excluded.promoted", register_source)
        selector = source.split("def select_double_vpn_core(", 1)[1].split(
            "\ndef mark_stale_nodes_offline", 1
        )[0]
        self.assertIn("AND promoted = 1", selector)
        self.assertIn("AND COALESCE(n.operator_enabled, 0) = 1", selector)
        self.assertIn("AND n.retired_at IS NULL", selector)


class CoreInstallerPromotionLifecycleTests(unittest.TestCase):
    def test_rerun_withdrawal_and_local_hold_precede_mutation(self) -> None:
        source = CORE_INSTALLER.read_text(encoding="utf-8")
        main = source.rsplit("\nmain() {", 1)[1].split(
            "\n}\n\nif [[ \"${BASH_SOURCE[0]}\" == \"$0\" ]]", 1
        )[0]
        self.assertLess(
            main.index("begin_core_deployment_withdrawal_before_mutation"),
            main.index("mark_core_role"),
        )
        self.assertLess(main.index("postflight_core"), main.index("complete_core_deployment_after_postflight"))

        withdrawal = source.split(
            "\nbegin_core_deployment_withdrawal_before_mutation() {", 1
        )[1].split("\n}\n\nrelease_core_deployment_hold_after_postflight()", 1)[0]
        self.assertLess(withdrawal.index("/deployment/withdraw"), withdrawal.index("persist_core_installer_withdrawal_state"))
        self.assertLess(withdrawal.index("persist_core_installer_withdrawal_state"), withdrawal.index("install_core_failure_hold_firewall"))
        # The hold drops FORWARD first and so cuts the AmneziaWG image build's
        # DNS: the pinned image is ensured after the latch and before the hold.
        self.assertLess(withdrawal.index("persist_core_installer_withdrawal_state"), withdrawal.index("select_awg_image"))
        self.assertLess(withdrawal.index("select_awg_image"), withdrawal.index("install_core_failure_hold_firewall"))
        self.assertIn('installer-rerun-${withdrawal_id}', withdrawal)

        firewall = source.split("\nwrite_firewall() {", 1)[1].split(
            "\n}\n\napply_bootstrap_firewall()", 1
        )[0]
        self.assertEqual(firewall.count('CORE_INSTALLER_RERUN_ACTIVE}" != "1'), 2)

        release = source.split(
            "\nrelease_core_deployment_hold_after_postflight() {", 1
        )[1].split("\n}\n\ncomplete_core_deployment_after_postflight()", 1)[0]
        self.assertIn("reason=installer-rerun-${CORE_DEPLOYMENT_WITHDRAWAL_ID}", release)
        self.assertIn("iptables-restore --wait 10 --test --noflush", release)
        self.assertIn('if ! iptables-save > "${active}"', release)
        self.assertGreaterEqual(release.count('iptables-restore --wait 10 < "${snapshot}"'), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
