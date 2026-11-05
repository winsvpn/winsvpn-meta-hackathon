#!/usr/bin/env python3
"""Round HV F2 on the repo lineage (lane L57): a closed node and the Round O
departure grants and authority ledger.

F2 (certified on the live hub, Round HV) says a node whose operator latch is
closed carries no customer authorization: no AWG peer and, for winn/3, a
canary-only registry. The repo lineage adds what the live hub lacks: Round O
departure grants (a switch leaves a bounded entry at the previous gateway) and
the authority ledger (every publication is recorded before its remote write
and counted until a confirmed replacement). These tests pin the two decisions
the port makes:

  (a) a closed node's publication contains no departure grant: /verify issues
      no allowance at a closed node, the closure resync retires the grants
      still live there, and an open node's grace is unchanged;
  (b) the closure unbinds devices as a departure WITHOUT an allowance, and
      the cleanup counts as confirmed only when the authority ledger shows the
      canary-only snapshot confirmed at the node's gateway. Until then the
      ledger keeps counting the closed node, and the durable refresh queue
      keeps the withdrawal pending, so an unreachable node is never assumed
      clean. A revocation queued for a peer still bound to a closed node is
      carried out, not dropped as "still authorized".

They reuse the Round O harness from test_winn3_departure_grace_hub.py
unchanged (the REAL hub source, the REAL sync_winn3_registry_to_node and its
remote command run by bash against a scratch directory per node). AWG pushes,
removals and the management probe are recorders. No test contacts a node, a
live hub, or the network.

Run:  python3 server/test_winn3_offnode_departure_hub.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import unittest
from unittest.mock import patch

import test_winn3_departure_grace_hub as roundo

ALPHA, BETA = "lab-alpha", "lab-beta"
REFRESH = roundo.REFRESH
GRACE = roundo.GRACE
entry_authorizes = roundo.entry_authorizes


class ClosedNodeDepartureTests(unittest.TestCase):
    # ------------------------------------------------------------ plumbing

    def setUp(self):
        roundo.DepartureGraceTests.setUp(self)
        self.removed = []

    def patched(self, mod):
        def remove(node_ip, key):
            self.removed.append((node_ip, key))
            return True

        return roundo.DepartureGraceTests.patched(self, mod) + [
            patch.object(mod, "remove_peer_from_node", side_effect=remove),
            patch.object(mod, "verify_node_management_access", return_value=True),
        ]

    def close(self, slug):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=0 WHERE slug=?", (slug,))

    def resync(self, slug):
        return self.run_patched(self.mod, self.mod.resync_active_peers_to_node, slug)

    def cleanup_state(self, slug):
        with self.mod.get_db() as conn:
            try:
                row = conn.execute(
                    "SELECT state FROM node_closure_cleanup WHERE slug=?", (slug,)).fetchone()
            except Exception:
                return "no-table"
        return row[0] if row else None

    def ledger_latest(self, slug):
        with self.mod.winn3_authority_ledger() as ledger:
            row = ledger.execute(
                "SELECT seq, outcome FROM winn3_publications WHERE node_slug=? AND gateway=?"
                " ORDER BY seq DESC LIMIT 1", (slug, "127.0.0.1")).fetchone()
            if row is None:
                return None, []
            entries = sorted(e[0] for e in ledger.execute(
                "SELECT static_public FROM winn3_publication_entries WHERE seq=?", (row["seq"],)))
        return row["outcome"], entries

    def grant_nodes(self):
        return sorted(g["node_slug"] for g in self.grants())

    # ------------------------------------------- decision (a): departure grants

    def test_switch_away_from_closed_node_earns_no_allowance(self):
        # L77 (Sol RF-1): the switch no longer takes the immediate-removal
        # branch, which republished the closed node without the device while
        # the reply could still be travelling through it. It is deferred
        # before any remote write; the closure resync unbinds the device and
        # the retry then switches without touching the closed node.
        key = self.connected_at(ALPHA)
        self.close(ALPHA)
        caught = self.assert_deferred_before_publication(
            BETA, "winn3_switch_deferred_departure_closed")
        self.assertEqual(caught.headers.get("Retry-After"), "60")
        self.assertNotIn(ALPHA, self.grant_nodes(), "a closed node was given a departure grant")
        self.assertEqual(self.charges(), 0, "leaving a closed node charged the departure budget")
        self.assertTrue(entry_authorizes(self.fleet.landed(ALPHA), key, self.clock.now),
                        "the reply path through the current gateway must stay authorized")
        self.resync(ALPHA)
        self.assertEqual(self.device()["location_slug"], "")
        self.verify(BETA)
        self.assertEqual(self.device()["location_slug"], BETA)
        self.assertNotIn(ALPHA, self.grant_nodes(), "a closed node was given a departure grant")
        self.assertEqual(self.charges(), 0, "leaving a closed node charged the departure budget")
        self.assertFalse(entry_authorizes(self.fleet.landed(ALPHA), key, self.clock.now),
                         "the closed node still authorizes the device that left it")
        self.assertTrue(entry_authorizes(self.fleet.landed(BETA), key, self.clock.now))
        self.assert_bounded(key)

    def test_open_node_keeps_its_departure_grace(self):
        key = self.connected_at(ALPHA)
        started = self.clock.now
        self.verify(BETA)
        self.assertEqual(self.grant_nodes(), [ALPHA])
        alpha = self.fleet.landed(ALPHA)
        self.assertTrue(entry_authorizes(alpha, key, started + 30))
        self.assertFalse(entry_authorizes(alpha, key, started + GRACE + 1))
        self.assertEqual(self.charges(), 1)
        self.assert_bounded(key)

    def test_closure_resync_retires_the_grant_held_at_the_closed_node(self):
        key = self.connected_at(ALPHA)
        self.verify(BETA)
        self.assertEqual(self.live_grant_nodes(), [ALPHA])
        self.assertTrue(entry_authorizes(self.fleet.landed(ALPHA), key, self.clock.now))
        self.close(ALPHA)
        out = self.resync(ALPHA)
        self.assertEqual(out.get("offnode_departure_grants_retired"), 1)
        self.assertEqual(self.live_grant_nodes(), [], "the grant outlived the closure")
        self.assertFalse(entry_authorizes(self.fleet.landed(ALPHA), key, self.clock.now),
                         "the closed node's file still carries the departure entry")
        self.assertEqual(self.charges(), 1, "the charge for the published allowance must survive")
        self.assertEqual(self.cleanup_state(ALPHA), "confirmed")
        self.assertNotIn(ALPHA, self.queued())
        self.assertEqual(self.device()["location_slug"], BETA, "the device that left is not touched")
        self.tick(REFRESH + 0.01)
        self.assertNotIn(ALPHA, self.hub_effective(key))
        self.assert_bounded(key)

    # ---------------------------------- decision (b): unbinding and the ledger

    def test_closure_unbinds_and_the_ledger_records_the_withdrawal(self):
        key = self.connected_at(ALPHA)
        self.close(ALPHA)
        out = self.resync(ALPHA)
        self.assertEqual(self.device()["location_slug"], "")
        self.assertEqual(out.get("offnode_devices_unbound"), 1)
        self.assertEqual(out.get("offnode_cleanup_confirmed"), [ALPHA])
        self.assertEqual(self.ledger_latest(ALPHA), ("confirmed", []))
        self.assertFalse(entry_authorizes(self.fleet.landed(ALPHA), key, self.clock.now))
        self.assertEqual(self.grants(), [], "an unbinding closure issues no departure grant")
        self.assertNotIn(ALPHA, self.queued(), "a confirmed withdrawal left a republish queued")
        self.assertIn(ALPHA, self.hub_effective(key), "released before the gateway refresh allowance")
        self.tick(REFRESH + 0.01)
        self.assertNotIn(ALPHA, self.hub_effective(key))
        self.assert_bounded(key)

    def test_unreachable_closed_node_stays_counted_and_pending(self):
        key = self.connected_at(ALPHA)
        self.close(ALPHA)
        self.fleet.mode[ALPHA] = "down"
        out = self.resync(ALPHA)
        self.assertEqual(self.device()["location_slug"], "", "the unbinding is durable without the node")
        self.assertFalse(out.get("ok"))
        self.assertEqual(self.cleanup_state(ALPHA), "pending")
        self.assertEqual(self.ledger_latest(ALPHA)[0], "uncertain")
        self.assertIn(ALPHA, self.queued(), "the withdrawal must stay on the durable refresh queue")
        self.tick(REFRESH + 1)
        self.assertIn(ALPHA, self.hub_effective(key), "an unconfirmed closed node stopped being counted")
        # The unbound device moves without waiting for the dead node.
        self.verify(BETA)
        self.assertEqual(self.device()["location_slug"], BETA)
        self.assertNotIn(ALPHA, self.grant_nodes())
        self.assert_bounded(key)
        self.fleet.mode[ALPHA] = "ok"
        self.drain()
        self.assertFalse(entry_authorizes(self.fleet.landed(ALPHA), key, self.clock.now))
        self.tick(REFRESH + 0.01)
        self.assertNotIn(ALPHA, self.hub_effective(key))
        self.resync(ALPHA)
        self.assertEqual(self.cleanup_state(ALPHA), "confirmed")

    def test_lost_ack_is_not_a_confirmed_cleanup(self):
        key = self.connected_at(ALPHA)
        self.close(ALPHA)
        self.fleet.mode[ALPHA] = "lost_ack"
        self.resync(ALPHA)
        self.assertFalse(entry_authorizes(self.fleet.landed(ALPHA), key, self.clock.now),
                         "the write did land")
        self.assertEqual(self.cleanup_state(ALPHA), "pending", "an unacknowledged write was trusted")
        self.fleet.mode[ALPHA] = "ok"
        self.resync(ALPHA)
        self.assertEqual(self.cleanup_state(ALPHA), "confirmed")
        self.assertEqual(self.ledger_latest(ALPHA), ("confirmed", []))

    def test_revocation_for_a_peer_bound_to_a_closed_node_is_carried_out(self):
        self.connected_at(ALPHA)
        awg_key = self.device()["client_public_key"]
        self.assertTrue(awg_key)
        self.close(ALPHA)
        with self.mod.get_db() as conn:
            self.mod.queue_peer_revocation(conn, "127.0.0.1", awg_key)
        result = self.run_patched(self.mod, self.mod.drain_peer_revocation_outbox)
        self.assertEqual(result.get("removed"), 1, "the revocation was dropped as still authorized")
        self.assertIn(("127.0.0.1", awg_key), self.removed)


for _name in ("load", "cleanup", "publish_now", "run_patched", "verify", "run_background",
              "deferred", "drain", "reconcile", "device", "document", "grants",
              "live_grant_nodes", "queued", "clear_queue", "hub_effective", "charges",
              "account_bound", "connected_at", "tick", "recover", "assert_fleet_bounded",
              "assert_bounded", "landings", "assert_deferred_before_publication"):
    setattr(ClosedNodeDepartureTests, _name, getattr(roundo.DepartureGraceTests, _name))


if __name__ == "__main__":
    unittest.main(verbosity=2)
