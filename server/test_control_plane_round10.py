#!/usr/bin/env python3
"""Round 10 regressions using production hub code and real SQLite files.

Remote peer operations are controlled doubles. Signing and identity generation
use the existing descriptor harness; no live account or gateway is changed.
"""
import _toolchain  # noqa: F401
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
import json
import logging
from pathlib import Path
import re
import shutil
import sqlite3
import threading
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_winn3_descriptor_hub as descriptor


class Round10Tests(unittest.TestCase):
    def setUp(self):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        with patch("logging.basicConfig", side_effect=close_handlers):
            self.mod = descriptor.load_hub_with_ring(
                DURABILITY_BARRIER_ENABLED=0, DURABILITY_BARRIER_REQUIRED=0,
                WINN3_INNER_POOL_CIDR="10.10.0.0/24", WINN3_CANARY_NODE_SLUG="",
                HIDE_CONTROL_ORIGIN=0, DEVICE_LIMIT=1,
            )
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.security_alert = lambda *args, **kwargs: None
        self.addCleanup(self.cleanup)
        harness.seed_account(self.mod, devices=0)
        for slug, host in (("lab-alpha", "192.0.2.10"), ("lab-beta", "192.0.2.11")):
            payload, signature = descriptor.envelope_for(descriptor.descriptor_payload(node=slug))
            descriptor.seed_node(
                self.mod, slug=slug, protocol_version="winn/3", protocol_params_json="{}",
                descriptor_json=json.dumps({"payload": payload, "sig": signature}),
            )
            with self.mod.get_db() as conn:
                conn.execute("UPDATE nodes SET ssh_host=? WHERE slug=?", (host, slug))

    def cleanup(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR)

    def verify(self, *, bearer=None, publish=None, sync_peer=None, **overrides):
        if bearer is None:
            descriptor.arm_activation(self.mod)
            headers = {"x-wins-activation": descriptor.ACTIVATION_SECRET}
        else:
            headers = {"authorization": "Bearer " + bearer}
        login = descriptor.build_login(
            self.mod, supports_winn3=True, supports_winn3_descriptor=True, **overrides)
        with patch.object(self.mod, "sync_peer_to_node", side_effect=sync_peer or (lambda *args: True)), patch.object(
            self.mod, "sync_winn3_registry_to_node", side_effect=publish or (lambda *args, **kwargs: True)
        ):
            result = asyncio.run(self.mod.verify_account(
                harness.FakeRequest(path="/verify", headers=headers), login, harness.BackgroundTasks()))
        return json.loads(result.body) if hasattr(result, "body") else result

    def device(self):
        with self.mod.get_db() as conn:
            return dict(conn.execute("SELECT * FROM devices").fetchone())

    def test_replacement_rotates_identity_and_revokes_old_registry_key(self):
        self.verify()
        before = self.device()
        published = []

        def publish(conn, host, slug, **_kwargs):
            published.extend(self.mod.winn3_peer_registry_document(conn, slug)["peers"])
            return True

        self.verify(device_id="replacement-device-12345678",
                    device_fingerprint="replacement-fingerprint-12345678",
                    client_public_key="D" * 43 + "=", publish=publish)
        after = self.device()
        self.assertNotEqual(before["device_id"], after["device_id"])
        for field in ("winn3_static_private", "winn3_static_public", "device_auth_token_hash"):
            self.assertTrue(after[field])
            self.assertNotEqual(before[field], after[field], field)
        self.assertNotIn(before["winn3_static_public"], json.dumps(published))
        self.assertIn(after["winn3_static_public"], json.dumps(published))

    def test_authenticated_reconnect_preserves_identity_but_new_enrollment_rotates(self):
        result = self.verify()
        before = self.device()
        self.verify(bearer=result["device_auth_token"])
        after = self.device()
        for field in ("winn3_inner_v4", "winn3_static_private", "winn3_static_public"):
            self.assertEqual(before[field], after[field], field)
        self.verify()
        self.assertNotEqual(before["winn3_static_public"], self.device()["winn3_static_public"])

    def test_awg_key_change_requires_enrollment_and_rotates_v3_identity(self):
        result = self.verify()
        before = self.device()
        with self.assertRaises(harness.HTTPException) as caught:
            self.verify(bearer=result["device_auth_token"], client_public_key="E" * 43 + "=")
        self.assertEqual(caught.exception.status_code, 401)
        self.assertEqual(self.device()["winn3_static_public"], before["winn3_static_public"])
        self.verify(client_public_key="E" * 43 + "=")
        self.assertNotEqual(before["winn3_static_public"], self.device()["winn3_static_public"])

    def test_failed_old_registry_sync_rolls_back_and_repairs_both_nodes(self):
        self.verify()
        before = self.device()
        publications = []
        remote_peers = {("192.0.2.10", before["client_public_key"])}

        def sync_peer(host, device):
            remote_peers.add((host, device["client_public_key"]))
            return True

        def publish(conn, host, slug, **_kwargs):
            self.assertTrue(conn.in_transaction)
            with self.mod.get_db() as reader:
                self.assertEqual(reader.execute("SELECT location_slug FROM devices").fetchone()[0],
                                 "lab-alpha")
            publications.append(slug)
            return slug != "lab-alpha"

        with self.assertRaises(harness.HTTPException) as caught:
            self.verify(location="lab-beta", publish=publish, sync_peer=sync_peer)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(publications, ["lab-beta", "lab-alpha"])
        self.assertEqual(self.device(), before)
        with self.mod.get_db() as conn:
            user = conn.execute("SELECT activation_secret_hash, activation_secret_used_at FROM users").fetchone()
            self.assertEqual(user[0], self.mod.token_digest(descriptor.ACTIVATION_SECRET))
            self.assertIsNone(user[1])
            self.assertEqual({row[0] for row in conn.execute(
                "SELECT node_slug FROM winn3_registry_refreshes WHERE next_attempt_at=0")},
                {"lab-alpha", "lab-beta"})
            self.assertEqual(conn.execute(
                "SELECT management_status FROM nodes WHERE slug='lab-alpha'").fetchone()[0], "failed")
            self.assertEqual([tuple(row) for row in conn.execute(
                "SELECT node_ip, client_public_key FROM peer_revocations")],
                [("192.0.2.11", before["client_public_key"])])
        self.assertIn(("192.0.2.11", before["client_public_key"]), remote_peers)

        def remove_peer(host, key):
            remote_peers.discard((host, key))
            return True

        with patch.object(self.mod, "remove_peer_from_node", side_effect=remove_peer):
            self.assertEqual(self.mod.drain_peer_revocation_outbox(), {"removed": 1, "retry": 0})
        self.assertEqual(remote_peers, {("192.0.2.10", before["client_public_key"])})
        # Reuse the same still-valid activation without rearming it.
        request = harness.FakeRequest(path="/verify", headers={
            "x-wins-activation": descriptor.ACTIVATION_SECRET})
        login = descriptor.build_login(self.mod, location="lab-beta", supports_winn3=True,
                                       supports_winn3_descriptor=True)
        with patch.object(self.mod, "sync_peer_to_node", return_value=True), patch.object(
                self.mod, "sync_winn3_registry_to_node", return_value=True):
            result = asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks()))
        result = json.loads(result.body) if hasattr(result, "body") else result
        self.assertTrue(result["device_auth_token"])
        self.assertEqual(self.device()["location_slug"], "lab-beta")

    def test_failed_selected_registry_sync_queues_remote_side_effect_repairs(self):
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM winn3_registry_refreshes")
        installed = []

        def sync_peer(host, device):
            installed.append((host, device["client_public_key"]))
            return True

        with self.assertRaises(harness.HTTPException) as caught:
            self.verify(publish=lambda *args, **kwargs: False, sync_peer=sync_peer)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(len(installed), 1)
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 0)
            self.assertEqual([row[0] for row in conn.execute(
                "SELECT node_slug FROM winn3_registry_refreshes WHERE next_attempt_at=0")], ["lab-alpha"])
            self.assertEqual([tuple(row) for row in conn.execute(
                "SELECT node_ip, client_public_key FROM peer_revocations")], installed)
        with patch.object(self.mod, "remove_peer_from_node", return_value=True) as remove:
            self.assertEqual(self.mod.drain_peer_revocation_outbox(), {"removed": 1, "retry": 0})
            remove.assert_called_once_with(*installed[0])

    def queue_current_peer(self):
        self.verify()
        key = self.device()["client_public_key"]
        with self.mod.get_db() as conn:
            self.mod.queue_peer_revocation(conn, "192.0.2.10", key)
        return key

    def test_delayed_revocation_cannot_remove_reauthorized_peer(self):
        key = self.queue_current_peer()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET location_slug='lab-beta'")
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET location_slug='lab-alpha'")
        with patch.object(self.mod, "remove_peer_from_node") as remove:
            self.assertEqual(self.mod.drain_peer_revocation_outbox(), {"removed": 0, "retry": 0})
            remove.assert_not_called()
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0], 0)
            self.assertTrue(self.mod.peer_has_current_authority(conn, "192.0.2.10", key))
            self.assertFalse(self.mod.peer_has_current_authority(conn, "192.0.2.11", key))

    def test_revocation_removal_leases_the_row_releases_the_writer_lock_and_retries_durably(self):
        # IA-CP-19: the shipped drain (claim, remote removal, settle) holds the
        # SQLite writer lock only for the short claim and settle transactions.
        # The SSH round trip runs with NO lock held, so verify, webhooks and
        # settlement are never stalled behind a slow node; a lease on the row,
        # not the writer lock, is what keeps a concurrent drain off it.
        self.queue_current_peer()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET location_slug='lab-beta'")
        during = {}

        def remove(host, key):
            with closing(sqlite3.connect(self.mod._DB, timeout=0.5)) as writer:
                writer.execute("BEGIN IMMEDIATE")
                writer.execute("ROLLBACK")
            with closing(sqlite3.connect(self.mod._DB)) as reader:
                during["lease_until"] = reader.execute(
                    "SELECT lease_until FROM peer_revocations").fetchone()[0]
            during["concurrent"] = self.mod.drain_peer_revocation_outbox()
            return False

        with patch.object(self.mod, "remove_peer_from_node", side_effect=remove) as removal:
            self.assertEqual(self.mod.drain_peer_revocation_outbox(), {"removed": 0, "retry": 1})
            self.assertEqual(removal.call_count, 1, "a concurrent drain claimed a leased row")
        self.assertIsNotNone(during["lease_until"], "the row was not leased during the removal")
        self.assertEqual(during["concurrent"], {"removed": 0, "retry": 0})
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT * FROM peer_revocations").fetchone()
            self.assertEqual(row["attempts"], 1)
            self.assertIsNone(row["lease_until"])
            self.assertEqual(row["last_failure_kind"], "remove_failed")
            conn.execute("UPDATE peer_revocations SET next_attempt_at=0")
        with patch.object(self.mod, "remove_peer_from_node", return_value=True) as remove:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: self.mod.drain_peer_revocation_outbox(), range(2)))
            self.assertEqual(sum(result["removed"] for result in results), 1)
            remove.assert_called_once()

    def test_authority_rejects_inactive_expired_missing_and_malformed_expiry(self):
        key = self.queue_current_peer()
        now = self.mod.utcnow()
        for status, expiry, expected in (
            ("active", (now + timedelta(days=1)).isoformat(), True),
            ("disabled", (now + timedelta(days=1)).isoformat(), False),
            ("active", now.isoformat(), False), ("active", None, False),
            ("active", "invalid", False),
        ):
            with self.subTest(status=status, expiry=expiry), self.mod.get_db() as conn:
                conn.execute("UPDATE users SET status=?, expiration_date=?", (status, expiry))
                with patch.object(self.mod, "utcnow", return_value=now):
                    self.assertEqual(self.mod.peer_has_current_authority(conn, "192.0.2.10", key), expected)

    def test_security_event_connections_apply_pragmas_and_concurrent_writes(self):
        configure = self.mod.configure_security_events_connection
        observed = []
        lock = threading.Lock()

        def checked(conn):
            configure(conn)
            actual = tuple(conn.execute("PRAGMA " + name).fetchone()[0]
                           for name in ("journal_mode", "synchronous", "busy_timeout", "foreign_keys"))
            with lock:
                observed.append(actual)

        def record(index):
            return self.mod.record_security_event(3, "round10", "192.0.2.20", "/probe",
                                                  {"index": index}, "pending")

        with patch.object(self.mod, "configure_security_events_connection", side_effect=checked):
            first = record(-1)
            with ThreadPoolExecutor(max_workers=16) as pool:
                ids = list(pool.map(record, range(100)))
            self.mod.update_security_event_email_status(first, "sent")
        self.assertEqual(len(set(ids)), 100)
        self.assertEqual(len(observed), 102)
        self.assertTrue(all(item == ("wal", 1, 10000, 1) for item in observed))
        with closing(sqlite3.connect(self.mod.SECURITY_EVENTS_DB)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0], 101)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM security_events WHERE source_ip IS NOT NULL").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT email_status FROM security_events WHERE event_id=?", (first,)).fetchone()[0], "sent")

    def test_every_embedded_security_db_connection_is_configured(self):
        source = Path(harness.HUB).read_text()
        pattern = r"(?m)^( +)with (?:closing\()?sqlite3\.connect\((?:SECURITY_EVENTS_DB|EVENTS_DB|db_path)[^\n]*\n([^\n]+)"
        matches = list(re.finditer(pattern, source))
        self.assertEqual(len(matches), 12)
        for match in matches:
            self.assertEqual(match.group(2), match.group(1) + "    configure_security_events_connection(conn)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
