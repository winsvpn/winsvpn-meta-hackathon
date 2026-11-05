#!/usr/bin/env python3
"""Focused regressions for the data-plane dark-start promotion latch.

The hub application is extracted from the production control-plane installer
and executed against a real temporary SQLite database. No test contacts a live
hub, node, or network.

Run: python3 server/test_data_plane_dark_start_latch.py
"""

import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import hashlib
import json
import logging
import re
import shutil
import sqlite3
import tempfile
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import test_account_deletion_hub as harness


HERE = Path(__file__).resolve().parent
CONTROL_INSTALLER = HERE / "wins_control_plane_setup_ONETOUCH.sh"
DATA_INSTALLER = HERE / "wins_data_plane_setup_ONETOUCH.sh"
ADMIN_TOKEN = "test-admin-token"
NODE_TOKEN = "test-node-token"
EVIDENCE_SHA256 = "a" * 64


def load_real_dataplane_probe() -> dict:
    source = CONTROL_INSTALLER.read_text(encoding="utf-8").split(
        "cat > /usr/local/lib/wins_node_dataplane_probe.py <<'DPPROBEEOF'", 1
    )[1].split("\nDPPROBEEOF", 1)[0]
    namespace = {"__name__": "wins_node_dataplane_promotion_lifecycle_test"}
    exec(compile(source, "wins_node_dataplane_probe.py", "exec"), namespace)
    return namespace


def registration_payload(slug: str, *, status: str = "online") -> types.SimpleNamespace:
    return types.SimpleNamespace(
        slug=slug,
        name="Dark Start Test",
        flag="X",
        data_plane_code_revision="unprovable",
        endpoint="198.51.100.7:9110",
        tunnel_gateway_ipv4="10.8.1.1",
        stealth_endpoint="",
        public_key="A" * 43 + "=",
        preshared_key=None,
        secret_token=NODE_TOKEN,
        status=status,
        obfuscation_json=None,
        ssh_host="198.51.100.7",
        wg_port=9110,
        xray_uuid="",
        xray_path="/wins-stealth-tunnel",
        xray_security="none",
        xray_sni="",
        stealth_public_port=80,
        xray_inbound_port=10085,
        regional_aliases=[],
        stealth_transports=[],
        awg_rx_bytes=0,
        awg_tx_bytes=0,
        wan_rx_bytes=0,
        wan_tx_bytes=0,
        peer_count=0,
        max_peers=100,
        direct_awg_enabled=None,
    )


class DataPlaneDarkStartTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0")
        # The shared extraction harness installs a process-global rotating file
        # handler. Each test deletes its isolated tempdir, so replace that
        # handler before a later module tries to log into the prior test's path.
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.logger.propagate = False
        self.request = harness.FakeRequest(
            headers={"x-admin-token": ADMIN_TOKEN},
            path="/admin/nodes/tier",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.mod._TMPDIR, ignore_errors=True)

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.mod._DB)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def node(self, slug: str) -> sqlite3.Row:
        with self.db() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()
        self.assertIsNotNone(row)
        return row

    def seed_placeholder(self, slug: str, *, operator_enabled: int = 0) -> None:
        with self.db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute(
                "INSERT INTO nodes (slug, node_token_hash, operator_enabled) VALUES (?, ?, ?)",
                (slug, self.mod.token_digest(NODE_TOKEN), operator_enabled),
            )

    def register(self, slug: str, *, status: str = "online") -> dict:
        return self.mod.register_node(
            registration_payload(slug, status=status),
            harness.FakeRequest(path="/api/v1/nodes/register"),
        )

    def make_promotable(self, slug: str) -> None:
        self.seed_placeholder(slug)
        self.register(slug)
        # L77: promotion proves every configured transport, not the aggregate
        # alone. This fixture's node configures direct UDP only (no stealth
        # endpoint or Xray identity), so fresh UDP proof is what it needs.
        now = self.mod.utcnow().isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET management_status = 'ok', data_plane_status = 'ok',"
                " data_plane_ok_at = ?, data_plane_udp_status = 'ok',"
                " data_plane_udp_ok_at = ? WHERE slug = ?",
                (now, now, slug),
            )

    def offnode_gate(self, slug: str) -> str:
        """Round HV ruling D3 (F2, repo port by lane L57): promotion and
        retirement consume a node-side gate record the hub verified itself; an
        arbitrary 64-hex digest is refused. This produces one for real: the
        closure resync (node I/O replaced by stubs) confirms the cleanup, then
        the node report of a clean winn/1 node (no AWG peer, no registry, no
        gateway) is recorded through the hub's own verifying endpoint. The
        canonical digest is computed here, independently of the hub. The
        resync's management-status bookkeeping is undone, so the node health a
        test set up is what the promotion sees."""
        health = ("management_status", "management_checked_at", "management_error")
        before = tuple(self.node(slug)[column] for column in health)
        with patch.object(self.mod, "sync_peer_to_node", return_value=True), \
                patch.object(self.mod, "sync_winn3_registry_to_node", return_value=True), \
                patch.object(self.mod, "remove_peer_from_node", return_value=True), \
                patch.object(self.mod, "verify_node_management_access", return_value=True):
            self.mod.resync_active_peers_to_node(slug)
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET management_status = ?, management_checked_at = ?,"
                " management_error = ? WHERE slug = ?", (*before, slug),
            )
            confirmed_at = conn.execute(
                "SELECT confirmed_at FROM node_closure_cleanup WHERE slug = ?", (slug,)
            ).fetchone()[0]
        report = (
            "AWG_READ ok iface=awg0 peers=0\nV3_FILE absent\n"
            "GW unit=inactive pid_known=0 forward=0 registry_flag_matches=0 gateway_can_read=unknown "
            "started_after_file=unknown reload_failed_since_file=unknown\n"
        )
        snapshot = json.dumps({"version": 1, "peers": []}, sort_keys=True, separators=(",", ":"))
        canonical = "\n".join([
            "l46-offnode-gate-v3", f"slug={slug}",
            f"expected_v3_sha256={hashlib.sha256(snapshot.encode()).hexdigest()}",
            f"cleanup_confirmed_at={confirmed_at}", "external_evidence_sha256=",
            f"node_report_sha256={hashlib.sha256(report.encode()).hexdigest()}",
        ]) + "\n"
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        self.mod.admin_record_offnode_gate(
            self.request, slug=slug, gate_sha256=digest, node_report=report,
            external_evidence_sha256="", x_admin_token=ADMIN_TOKEN,
        )
        return digest

    def promote(
        self,
        slug: str,
        evidence_sha256: str = EVIDENCE_SHA256,
        *,
        confirm_slug: str | None = None,
    ) -> dict:
        # A well-formed digest for a closed, unretired node stands for "valid
        # gate evidence": on a hub with the off-node gate it is replaced by a
        # real, hub-verified gate record. Malformed or empty evidence is passed
        # through unchanged so the hub's own refusal is what the test observes.
        row = self.node(slug)
        if (hasattr(self.mod, "admin_record_offnode_gate")
                and re.fullmatch(r"[0-9a-f]{64}", evidence_sha256 or "")
                and not self.mod.node_admits_peer(row) and not row["retired_at"]):
            evidence_sha256 = self.offnode_gate(slug)
        self.evidence_used = evidence_sha256
        return self.mod.admin_set_node_tier(
            self.request,
            slug=slug,
            tier="premium",
            evidence_sha256=evidence_sha256,
            confirm_slug=slug if confirm_slug is None else confirm_slug,
            x_admin_token=ADMIN_TOKEN,
        )

    def test_fresh_schema_and_bootstrap_placeholder_default_dark(self) -> None:
        with self.db() as conn:
            self.mod.ensure_schema(conn)
            columns = {
                row["name"]: row for row in conn.execute("PRAGMA table_info(nodes)")
            }
            self.assertEqual(columns["operator_enabled"]["notnull"], 1)
            self.assertEqual(columns["operator_enabled"]["dflt_value"], "0")

            conn.execute(
                "INSERT INTO nodes (slug, node_token_hash) VALUES (?, ?)",
                ("schema-dark", self.mod.token_digest(NODE_TOKEN)),
            )
            value = conn.execute(
                "SELECT operator_enabled FROM nodes WHERE slug = 'schema-dark'"
            ).fetchone()[0]
            self.assertEqual(value, 0)
        self.assertFalse(self.mod.node_is_operator_enabled({"operator_enabled": None}))
        hub_source = harness._extract_main_block()
        self.assertNotIn("COALESCE(operator_enabled, 1)", hub_source)
        self.assertNotIn("COALESCE(n.operator_enabled, 1)", hub_source)

    def test_existing_default_one_schema_is_rebuilt_with_default_dark(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-dark-start-migration-") as tmpdir:
            database = Path(tmpdir) / "legacy.db"
            conn = sqlite3.connect(database)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            # Rehearse the real upgrade shape: the base table plus the columns
            # prior installers and the external data-plane prober add later.
            self.mod.create_nodes_table(conn)
            for column, declaration in (
                ("data_plane_status", "TEXT DEFAULT 'unknown'"),
                ("data_plane_checked_at", "TEXT"),
                ("data_plane_ok_at", "TEXT"),
                ("data_plane_fail_streak", "INTEGER DEFAULT 0"),
                ("data_plane_error", "TEXT DEFAULT ''"),
                ("data_plane_udp_status", "TEXT DEFAULT 'unknown'"),
                ("data_plane_udp_ok_at", "TEXT"),
                ("data_plane_udp_fail_streak", "INTEGER DEFAULT 0"),
                ("data_plane_stealth_status", "TEXT DEFAULT 'unknown'"),
                ("data_plane_stealth_ok_at", "TEXT"),
                ("data_plane_stealth_fail_streak", "INTEGER DEFAULT 0"),
                ("data_plane_stealth_tls_status", "TEXT DEFAULT 'unknown'"),
                ("data_plane_stealth_tls_ok_at", "TEXT"),
                ("data_plane_stealth_tls_fail_streak", "INTEGER DEFAULT 0"),
                ("winn3_descriptor_json", "TEXT"),
                ("winn3_admission_json", "TEXT"),
                ("path_mtu", "INTEGER"),
                ("carrier_classes", "TEXT"),
            ):
                conn.execute(f"ALTER TABLE nodes ADD COLUMN {column} {declaration}")
            create_sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'nodes'"
            ).fetchone()[0]
            historical_sql = create_sql.replace(
                "operator_enabled INTEGER NOT NULL DEFAULT 0",
                "operator_enabled INTEGER NOT NULL DEFAULT 1",
                1,
            )
            self.assertNotEqual(create_sql, historical_sql)
            conn.execute("DROP TABLE nodes")
            conn.execute(historical_sql)
            conn.execute(
                "CREATE INDEX legacy_nodes_data_status ON nodes(data_plane_status)"
            )
            conn.execute(
                "CREATE TRIGGER legacy_nodes_update AFTER UPDATE OF data_plane_status "
                "ON nodes BEGIN SELECT 1; END"
            )
            conn.execute(
                "INSERT INTO nodes (slug, public_key, operator_enabled, data_plane_status, "
                "data_plane_ok_at, winn3_descriptor_json, path_mtu, carrier_classes) "
                "VALUES (?, ?, 1, 'ok', ?, ?, 1450, 'udp,tcp,tls')",
                (
                    "existing-promoted",
                    "test-public-key",
                    "2026-09-02T00:00:00+00:00",
                    '{"payload":"test","sig":"test"}',
                ),
            )
            conn.execute(
                "CREATE TABLE node_refs (slug TEXT REFERENCES nodes(slug))"
            )
            conn.execute("INSERT INTO node_refs (slug) VALUES ('existing-promoted')")
            conn.commit()

            before_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(nodes)")
            }

            self.mod.ensure_schema(conn)
            columns = {
                row["name"]: row for row in conn.execute("PRAGMA table_info(nodes)")
            }
            self.assertTrue(before_columns.issubset(columns))
            self.assertEqual(columns["operator_enabled"]["dflt_value"], "0")
            preserved = conn.execute(
                "SELECT operator_enabled, data_plane_status, data_plane_ok_at, "
                "winn3_descriptor_json, path_mtu, carrier_classes FROM nodes "
                "WHERE slug = 'existing-promoted'"
            ).fetchone()
            self.assertEqual(
                tuple(preserved),
                (
                    1,
                    "ok",
                    "2026-09-02T00:00:00+00:00",
                    '{"payload":"test","sig":"test"}',
                    1450,
                    "udp,tcp,tls",
                ),
            )
            owned_objects = {
                row["name"] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE tbl_name = 'nodes'"
                )
            }
            self.assertIn("legacy_nodes_data_status", owned_objects)
            self.assertIn("legacy_nodes_update", owned_objects)
            self.assertEqual(
                conn.execute("PRAGMA foreign_key_list(node_refs)").fetchone()[2],
                "nodes",
            )
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            conn.execute("INSERT INTO nodes (slug) VALUES ('new-dark-row')")
            self.assertEqual(
                conn.execute(
                    "SELECT operator_enabled FROM nodes WHERE slug = 'new-dark-row'"
                ).fetchone()[0],
                0,
            )
            conn.close()

    def test_first_registration_darkens_old_default_placeholder(self) -> None:
        # Simulates a grant placeholder created just before an upgraded hub
        # changed the historical database default from 1 to 0.
        self.seed_placeholder("legacy-placeholder", operator_enabled=1)
        self.register("legacy-placeholder")
        row = self.node("legacy-placeholder")
        self.assertTrue(row["endpoint"])
        self.assertEqual(row["operator_enabled"], 0)

    def test_registration_preserves_an_existing_manual_promotion(self) -> None:
        self.make_promotable("preserve-promotion")
        self.promote("preserve-promotion")
        self.register("preserve-promotion", status="congested")
        row = self.node("preserve-promotion")
        self.assertEqual(row["operator_enabled"], 1)
        self.assertEqual(row["status"], "congested")

    def test_admin_direct_awg_override_survives_node_registration(self) -> None:
        slug = "direct-awg-override"
        self.seed_placeholder(slug)
        payload = registration_payload(slug)
        payload.direct_awg_enabled = True
        request = harness.FakeRequest(path="/api/v1/nodes/register")
        self.mod.register_node(payload, request)
        self.assertEqual(self.node(slug)["direct_awg_enabled"], 1)

        payload.direct_awg_enabled = False
        self.mod.register_node(payload, request)
        self.assertEqual(self.node(slug)["direct_awg_enabled"], 0)

        admin_request = harness.FakeRequest(path="/admin/nodes/direct-awg")
        self.mod.admin_set_node_direct_awg(
            admin_request, slug=slug, enabled=True, x_admin_token=ADMIN_TOKEN
        )
        self.mod.register_node(payload, request)
        self.assertEqual(self.node(slug)["direct_awg_enabled"], 0)

        payload.direct_awg_enabled = True
        self.mod.register_node(payload, request)
        self.assertEqual(self.node(slug)["direct_awg_enabled"], 1)

        self.mod.admin_set_node_direct_awg(
            admin_request, slug=slug, enabled=False, x_admin_token=ADMIN_TOKEN
        )
        payload.direct_awg_enabled = True
        self.mod.register_node(payload, request)
        self.assertEqual(self.node(slug)["direct_awg_enabled"], 0)

        self.mod.admin_set_node_direct_awg(
            admin_request, slug=slug, enabled=True, x_admin_token=ADMIN_TOKEN
        )
        self.assertEqual(self.node(slug)["direct_awg_enabled"], 1)

    def test_stale_registration_closes_latch_and_invalidates_assignment(self) -> None:
        slug = "stale-registration"
        self.make_promotable(slug)
        self.promote(slug)
        stale = (
            self.mod.utcnow()
            - self.mod.timedelta(seconds=self.mod.NODE_HEARTBEAT_STALE_SECONDS + 1)
        ).isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET last_heartbeat=? WHERE slug=?", (stale, slug)
            )
            conn.execute(
                "INSERT INTO double_vpn_assignments "
                "(device_id, exit_slug, status, applied_revision, runtime_validated_at) "
                "VALUES ('stale-node-device', ?, 'active', ?, ?)",
                (slug, "b" * 64, self.mod.utcnow().isoformat()),
            )

        self.register(slug)
        recovered = self.node(slug)
        self.assertEqual(recovered["status"], "online")
        self.assertEqual(recovered["operator_enabled"], 0)
        with self.db() as conn:
            assignment = conn.execute(
                "SELECT status, applied_revision, runtime_validated_at "
                "FROM double_vpn_assignments WHERE device_id='stale-node-device'"
            ).fetchone()
            self.assertEqual(tuple(assignment), ("inactive", None, None))
            self.assertIsNone(self.mod.select_online_node(conn, "auto"))
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM node_promotion_events").fetchone()[0],
                1,
            )

        self.register(slug)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        with self.assertRaises(harness.HTTPException) as missing_evidence:
            self.promote(slug, "")
        self.assertEqual(missing_evidence.exception.status_code, 400)
        self.promote(slug)
        with self.db() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM node_promotion_events").fetchone()[0],
                2,
            )

    def test_stale_heartbeat_cannot_refresh_an_old_promotion(self) -> None:
        slug = "stale-heartbeat"
        self.make_promotable(slug)
        self.promote(slug)
        stale = (
            self.mod.utcnow()
            - self.mod.timedelta(seconds=self.mod.NODE_HEARTBEAT_STALE_SECONDS + 1)
        ).isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET last_heartbeat=? WHERE slug=?", (stale, slug)
            )
        self.mod.heartbeat(
            self.mod.NodeHeartbeat(
                slug=slug, secret_token=NODE_TOKEN, status="online"
            ),
            harness.FakeRequest(path="/api/v1/nodes/heartbeat"),
        )
        recovered = self.node(slug)
        self.assertEqual(recovered["status"], "online")
        self.assertEqual(recovered["operator_enabled"], 0)

    def test_stale_external_health_consumes_promotion_until_new_evidence(self) -> None:
        slug = "stale-external-proof"
        self.make_promotable(slug)
        self.promote(slug)
        probe = load_real_dataplane_probe()
        stale = (
            self.mod.utcnow()
            - self.mod.timedelta(minutes=self.mod.DATA_PLANE_HARD_STALE_MINUTES + 1)
        ).isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET data_plane_ok_at=? WHERE slug=?", (stale, slug)
            )
            conn.execute(
                "INSERT INTO double_vpn_assignments "
                "(device_id, exit_slug, status, applied_revision, runtime_validated_at) "
                "VALUES ('stale-external-device', ?, 'active', ?, ?)",
                (slug, "c" * 64, self.mod.utcnow().isoformat()),
            )
            self.assertIsNone(self.mod.select_online_node(conn, "auto"))

        # Reproduce the dangerous ordering directly against the generated
        # external prober: the old proof is already stale, but this run obtains
        # a fresh green verdict before the hub's ordinary stale sweep runs.
        # The prober must consume the promotion before replacing data_plane_ok_at.
        with self.db() as conn:
            result = probe["apply_verdicts"](
                conn,
                slug,
                ("reachable", "fresh UDP proof"),
                ("unconfigured", "not configured"),
                ("unconfigured", "not configured"),
            )
        self.assertEqual(result["aggregate"], "ok")
        self.assertTrue(result["promotion_consumed"])

        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        with self.db() as conn:
            assignment = conn.execute(
                "SELECT status, applied_revision, runtime_validated_at "
                "FROM double_vpn_assignments WHERE device_id='stale-external-device'"
            ).fetchone()
            self.assertEqual(tuple(assignment), ("inactive", None, None))
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM node_promotion_events").fetchone()[0],
                1,
            )
            self.assertIsNone(self.mod.select_online_node(conn, "auto"))

        self.promote(slug, evidence_sha256="d" * 64)
        with self.db() as conn:
            self.assertEqual(self.mod.select_online_node(conn, "auto")["slug"], slug)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM node_promotion_events").fetchone()[0],
                2,
            )

    def test_unreachable_external_health_also_consumes_promotion(self) -> None:
        slug = "unreachable-external-proof"
        self.make_promotable(slug)
        self.promote(slug)
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET data_plane_status='unreachable' WHERE slug=?",
                (slug,),
            )
            self.mod.mark_stale_nodes_offline(conn)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)

    def test_stale_demotion_rolls_back_if_assignment_invalidation_fails(self) -> None:
        slug = "atomic-stale-demotion"
        self.make_promotable(slug)
        self.promote(slug)
        stale = (
            self.mod.utcnow()
            - self.mod.timedelta(minutes=self.mod.DATA_PLANE_HARD_STALE_MINUTES + 1)
        ).isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET data_plane_ok_at=? WHERE slug=?", (stale, slug)
            )
            conn.execute(
                "INSERT INTO double_vpn_assignments (device_id, exit_slug, status) "
                "VALUES ('atomic-device', ?, 'active')",
                (slug,),
            )
            conn.execute(
                "CREATE TRIGGER reject_stale_assignment_invalidation "
                "BEFORE UPDATE OF status ON double_vpn_assignments "
                "BEGIN SELECT RAISE(ABORT, 'forced invalidation failure'); END"
            )

        with self.assertRaises(sqlite3.IntegrityError):
            with self.db() as conn:
                self.mod.mark_stale_nodes_offline(conn)
        self.assertEqual(self.node(slug)["operator_enabled"], 1)
        with self.db() as conn:
            assignment_status = conn.execute(
                "SELECT status FROM double_vpn_assignments "
                "WHERE device_id='atomic-device'"
            ).fetchone()[0]
        self.assertEqual(assignment_status, "active")

    def test_probe_recovery_rolls_back_if_promotion_cannot_close(self) -> None:
        slug = "atomic-prober-recovery"
        self.make_promotable(slug)
        self.promote(slug)
        probe = load_real_dataplane_probe()
        stale = (
            self.mod.utcnow()
            - self.mod.timedelta(minutes=self.mod.DATA_PLANE_HARD_STALE_MINUTES + 1)
        ).isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET data_plane_ok_at=? WHERE slug=?", (stale, slug)
            )
            conn.execute(
                "INSERT INTO double_vpn_assignments (device_id, exit_slug, status) "
                "VALUES ('atomic-prober-device', ?, 'active')",
                (slug,),
            )
            conn.execute(
                "CREATE TRIGGER reject_prober_assignment_invalidation "
                "BEFORE UPDATE OF status ON double_vpn_assignments "
                "BEGIN SELECT RAISE(ABORT, 'forced prober invalidation failure'); END"
            )

        with self.assertRaises(sqlite3.IntegrityError):
            with self.db() as conn:
                probe["apply_verdicts"](
                    conn,
                    slug,
                    ("reachable", "fresh UDP proof"),
                    ("unconfigured", "not configured"),
                    ("unconfigured", "not configured"),
                )

        row = self.node(slug)
        self.assertEqual(row["operator_enabled"], 1)
        self.assertEqual(row["data_plane_ok_at"], stale)
        with self.db() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM double_vpn_assignments "
                    "WHERE device_id='atomic-prober-device'"
                ).fetchone()[0],
                "active",
            )

    def test_promotion_fails_closed_without_digest_or_positive_health(self) -> None:
        self.make_promotable("promotion-refusal")
        with self.assertRaises(harness.HTTPException) as confirmation:
            self.promote("promotion-refusal", confirm_slug="wrong-node")
        self.assertEqual(confirmation.exception.status_code, 400)

        with self.assertRaises(harness.HTTPException) as missing:
            self.promote("promotion-refusal", "")
        self.assertEqual(missing.exception.status_code, 400)

        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET management_status = 'unknown' WHERE slug = ?",
                ("promotion-refusal",),
            )
        with self.assertRaises(harness.HTTPException) as unhealthy:
            self.promote("promotion-refusal")
        self.assertEqual(unhealthy.exception.status_code, 409)

        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET management_status = 'ok', data_plane_ok_at = ? WHERE slug = ?",
                (
                    (
                        self.mod.utcnow()
                        - self.mod.timedelta(minutes=self.mod.DATA_PLANE_HARD_STALE_MINUTES + 1)
                    ).isoformat(),
                    "promotion-refusal",
                ),
            )
        with self.assertRaises(harness.HTTPException) as stale:
            self.promote("promotion-refusal")
        self.assertEqual(stale.exception.status_code, 409)
        self.assertEqual(self.node("promotion-refusal")["operator_enabled"], 0)
        with self.db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM node_promotion_events").fetchone()[0]
        self.assertEqual(count, 0)

    def test_manual_promotion_records_immutable_secret_free_evidence(self) -> None:
        slug = "promotion-evidence"
        self.make_promotable(slug)
        with self.db() as conn:
            self.assertIsNone(self.mod.select_online_node(conn, "auto"))
        result = self.promote(slug)
        self.assertTrue(result["operator_enabled"])
        self.assertRegex(result["promotion_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(result["evidence_sha256"], self.evidence_used)
        with self.db() as conn:
            self.assertEqual(self.mod.select_online_node(conn, "auto")["slug"], slug)

        with self.db() as conn:
            event = conn.execute(
                "SELECT * FROM node_promotion_events WHERE promotion_id = ?",
                (result["promotion_id"],),
            ).fetchone()
            columns = {row["name"] for row in conn.execute(
                "PRAGMA table_info(node_promotion_events)"
            )}
            self.assertNotIn("reason", columns)
            self.assertNotIn("source_ip", columns)
            self.assertEqual(event["slug"], slug)
            self.assertEqual(event["evidence_sha256"], self.evidence_used)
            self.assertNotEqual(event["operator_source_hash"], self.request.client.host)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "UPDATE node_promotion_events SET tier = 'free' WHERE promotion_id = ?",
                    (result["promotion_id"],),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "DELETE FROM node_promotion_events WHERE promotion_id = ?",
                    (result["promotion_id"],),
                )

        listing = self.mod.admin_list_node_promotions(self.request, x_admin_token=ADMIN_TOKEN)
        self.assertEqual(listing["promotions"][0]["promotion_id"], result["promotion_id"])

    def test_evidence_insert_failure_rolls_back_the_latch(self) -> None:
        slug = "promotion-rollback"
        self.make_promotable(slug)
        with self.db() as conn:
            conn.execute(
                "CREATE TRIGGER test_reject_promotion_evidence "
                "BEFORE INSERT ON node_promotion_events BEGIN "
                "SELECT RAISE(ABORT, 'forced evidence failure'); END"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.promote(slug)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        with self.db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM node_promotion_events").fetchone()[0]
        self.assertEqual(count, 0)

    def test_tier_endpoint_cannot_reenable_without_a_new_promotion_record(self) -> None:
        slug = "no-tier-bypass"
        self.make_promotable(slug)
        self.promote(slug)
        self.mod.admin_set_node_tier(
            self.request,
            slug=slug,
            tier="off",
            evidence_sha256="",
            x_admin_token=ADMIN_TOKEN,
        )
        with self.assertRaises(harness.HTTPException) as refused:
            self.promote(slug, "")
        self.assertEqual(refused.exception.status_code, 400)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)

    def test_installer_withdrawal_is_atomic_and_completion_stays_dark(self) -> None:
        slug = "installer-rerun"
        self.make_promotable(slug)
        self.promote(slug)
        with self.db() as conn:
            conn.execute(
                "INSERT INTO double_vpn_assignments "
                "(device_id, exit_slug, status, applied_revision, runtime_validated_at) "
                "VALUES ('installer-device', ?, 'active', ?, ?)",
                (slug, "e" * 64, self.mod.utcnow().isoformat()),
            )
            conn.execute(
                "CREATE TRIGGER reject_installer_assignment_invalidation "
                "BEFORE UPDATE OF status ON double_vpn_assignments "
                "BEGIN SELECT RAISE(ABORT, 'forced installer invalidation failure'); END"
            )

        with self.assertRaises(harness.HTTPException) as forged:
            self.mod.withdraw_node_for_deployment(
                slug,
                harness.FakeRequest(
                    path=f"/api/v1/nodes/{slug}/deployment/withdraw"
                ),
                x_node_token="wrong-node-token",
            )
        self.assertEqual(forged.exception.status_code, 401)
        self.assertEqual(self.node(slug)["operator_enabled"], 1)

        with self.assertRaises(sqlite3.IntegrityError):
            self.mod.withdraw_node_for_deployment(
                slug,
                harness.FakeRequest(
                    path=f"/api/v1/nodes/{slug}/deployment/withdraw"
                ),
                x_node_token=NODE_TOKEN,
            )
        row = self.node(slug)
        self.assertEqual(row["operator_enabled"], 1)
        self.assertIsNone(row["deployment_withdrawal_id"])
        with self.db() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM double_vpn_assignments "
                    "WHERE device_id='installer-device'"
                ).fetchone()[0],
                "active",
            )
            conn.execute("DROP TRIGGER reject_installer_assignment_invalidation")

        withdrawn = self.mod.withdraw_node_for_deployment(
            slug,
            harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/withdraw"),
            x_node_token=NODE_TOKEN,
        )
        self.assertFalse(withdrawn["operator_enabled"])
        self.assertEqual(withdrawn["invalidated_assignment_count"], 1)
        self.assertRegex(withdrawn["withdrawal_id"], r"^[0-9a-f]{32}$")
        row = self.node(slug)
        self.assertEqual(row["status"], "maintenance")
        self.assertEqual(row["operator_enabled"], 0)
        self.assertEqual(row["deployment_withdrawal_id"], withdrawn["withdrawal_id"])

        self.register(slug)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        with self.assertRaises(harness.HTTPException) as blocked:
            self.promote(slug, evidence_sha256="f" * 64)
        self.assertEqual(blocked.exception.status_code, 409)

        with self.assertRaises(harness.HTTPException) as wrong_generation:
            self.mod.complete_node_deployment(
                slug,
                self.mod.DeploymentWithdrawalCompletion(withdrawal_id="0" * 32),
                harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/complete"),
                x_node_token=NODE_TOKEN,
            )
        self.assertEqual(wrong_generation.exception.status_code, 409)
        self.assertEqual(self.node(slug)["deployment_withdrawal_id"], withdrawn["withdrawal_id"])

        completed = self.mod.complete_node_deployment(
            slug,
            self.mod.DeploymentWithdrawalCompletion(
                withdrawal_id=withdrawn["withdrawal_id"]
            ),
            harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/complete"),
            x_node_token=NODE_TOKEN,
        )
        self.assertFalse(completed["operator_enabled"])
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        self.promote(slug, evidence_sha256="f" * 64)
        with self.db() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM node_promotion_events").fetchone()[0],
                2,
            )

    def test_retirement_restore_returns_to_dark_state(self) -> None:
        slug = "restore-dark"
        self.make_promotable(slug)
        self.promote(slug)
        gate = {}
        if hasattr(self.mod, "admin_record_offnode_gate"):
            # Round HV F2: an open node cannot be retired. Close it, confirm
            # the cleanup and record a verified gate first; then make the
            # tombstone claim the node was enabled, so restore is still tested
            # against a record that would reopen the latch if it were trusted.
            self.mod.admin_set_node_tier(
                self.request, slug=slug, tier="off", evidence_sha256="",
                x_admin_token=ADMIN_TOKEN,
            )
            gate = {"offnode_gate_sha256": self.offnode_gate(slug)}
        retired = self.mod.admin_retire_node(
            self.request,
            slug=slug,
            reason="test retirement",
            confirm_last_servable_node=slug,
            x_admin_token=ADMIN_TOKEN,
            **gate,
        )
        self.assertTrue(retired["ok"])
        if gate:
            with self.db() as conn:
                tombstone = conn.execute(
                    "SELECT retirement_id, state_json FROM node_retirements WHERE slug = ?", (slug,)
                ).fetchone()
                recorded = json.loads(tombstone["state_json"])
                recorded["operator_enabled"] = 1
                conn.execute(
                    "UPDATE node_retirements SET state_json = ? WHERE retirement_id = ?",
                    (json.dumps(recorded), tombstone["retirement_id"]),
                )
        restored = self.mod.admin_restore_node(
            self.request,
            slug=slug,
            x_admin_token=ADMIN_TOKEN,
        )
        self.assertFalse(restored["operator_enabled"])
        self.assertEqual(self.node(slug)["operator_enabled"], 0)


class DataPlaneInstallerCompletionTests(unittest.TestCase):
    def test_automatic_completion_registers_readiness_but_never_promotes(self) -> None:
        source = DATA_INSTALLER.read_text(encoding="utf-8")
        completion = source.split("\nmark_data_deployment_ready() {", 1)[1].split(
            "\n}\n\nwrite_diagnose_script()", 1
        )[0]
        self.assertIn("/usr/local/bin/wins-node-register", completion)
        self.assertIn("final registration did not change the hub promotion latch", completion)
        # IA-SYNC SYNC-08 (Fable 5.1 ruling F): the wording changed deliberately.
        self.assertIn("The hub reopens a rerun of a live node automatically once identity, "
                      "lineage and carrying proofs pass", completion)
        # Design 3.17: a fresh node under a go_live=auto ticket goes live on the
        # hub's proofs after complete-fresh, so "dark until manual promotion" no
        # longer holds for every new node.
        self.assertIn("stays dark until the hub's fresh-install proofs pass under a go_live=auto ticket, "
                      "or until that manual evidenced promotion", completion)
        self.assertIn("POST /admin/nodes/tier", completion)
        self.assertNotIn("ADMIN_TOKEN", completion)
        self.assertNotIn("curl ", completion)

        main = source.rsplit("\nmain() {", 1)[1].split("\n}\n\nfor arg in", 1)[0]
        self.assertLess(
            main.index("begin_data_deployment_withdrawal_before_mutation"),
            main.index("mark_data_role"),
        )
        self.assertLess(main.index("postflight_data_plane"), main.index("mark_data_deployment_ready"))
        self.assertEqual(main.count("mark_data_deployment_ready"), 1)
        self.assertNotIn("/admin/nodes/tier", main)

        withdrawal = source.split(
            "\nbegin_data_deployment_withdrawal_before_mutation() {", 1
        )[1].split("\n}\n\ncomplete_data_deployment_after_postflight()", 1)[0]
        self.assertLess(
            withdrawal.index("/deployment/withdraw"),
            withdrawal.index("wins-node-local-serving disable"),
        )
        self.assertIn("operator_enabled == false", withdrawal)
        self.assertIn('installer-rerun:${installer_sha}', withdrawal)

        guard = source.split("<<'WINS_NODE_LOCAL_SERVING_GUARD'\n", 1)[1].split(
            "\nWINS_NODE_LOCAL_SERVING_GUARD", 1
        )[0]
        self.assertIn("only the exact current installer rerun may release this latch", guard)
        self.assertIn('reason}" == "installer-rerun:${installer_sha}', guard)
        release = guard.split("\nrelease_deployment() {", 1)[1].split(
            "\n}\n\nenforce_serving()", 1
        )[0]
        self.assertLess(
            release.index('rm -f -- "${LATCH_FILE}"'),
            release.index("apply_enabled_chain"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
