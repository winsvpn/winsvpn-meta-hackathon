#!/usr/bin/env python3
"""H7: automatic go-live, the fresh_install class (design v17 3.17, 3.1 step 5;
section 5.5 "Tickets", "Pipeline" and "Go-live and completion", section 5.6
"Pipeline and go-live" mutants).

Every test runs the REAL hub source extracted from the control-plane installer
heredoc against temporary SQLite files (the fx2 InstallerRerunTests harness).
Tickets are signed by REAL openssl(1) with a throwaway t1 key and stored through
the REAL POST /admin/nodes/winn3/signer-ticket route; stored descriptors are
signed with a throwaway g1 key. Nothing contacts a node, a signer, a host or the
network, and no real key is used or created.

WHAT IS UNDER TEST:

  * POST /api/v1/nodes/{slug}/deployment/complete-fresh: the refusals (open
    withdrawal, open latch, a promotion since the bootstrap, a reset without a
    valid unconsumed reset ticket, a digest that differs from the registered
    revision, a different completion already recorded) and its idempotence.
  * The rerun completion route classifies a never-live node the same way, sets
    deployment_released_at on every matching release, and leaves a live node on
    the installer_rerun path.
  * Ticket authority is read at use: go_live and tier come from the re-verified
    ticket bytes at completion and again at the flip, never from a column.
  * fresh_install_reopen_failures and the flip in auto_reopen_health_closed_nodes:
    every proof is failed independently to confirm darkness, the tier is the
    verified ticket's, and the promotion ledger and latch events record it.
  * winn3_identity_sha256 replaces the raw descriptor hash as the rerun identity
    field, the carrier flip's expected transition is accepted only as recorded,
    and only a 16 hex character promotion row evidences an installer revision.
  * The control-plane installer writes and validates WINN3_FRESH_INSTALL_AUTO_GOLIVE.
  * Every 5.6 mutant of this slice is applied to the extracted source and killed.

Run: python3 -m pytest server/test_hub_h7_fresh_install_golive.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import base64
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import timedelta
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_data_plane_dark_start_latch as dark
import test_hub_h1_descriptor_signer as h1
import test_hub_h4_signer_ticket_route as h4
import test_installer_sync_hub_fx2 as fx2
import test_winn3_descriptor_hub as desc

REV_A = fx2.REV_A
REV_B = fx2.REV_B
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
HEX64 = "c" * 64
KEYDIR = tempfile.mkdtemp(prefix="winshub-h7-keys-")


class H7Base(fx2.InstallerRerunTests):
    """The fx2 rerun harness plus tickets, fresh nodes and go-live proofs."""

    def setUp(self):
        super().setUp()
        _key, pub = h4.t1_keypair(KEYDIR)
        os.environ["WINN3_SIGNER_TICKET_PUBKEY_T1"] = base64.b64encode(pub).decode()
        os.environ["WINN3_DESCRIPTOR_PUBKEY_G1"] = desc.SLOT_PUBS["g1"]
        self.serial = 0
        with self.db() as conn:
            self.mod.ensure_schema(conn)
            existing = {row[1] for row in conn.execute("PRAGMA table_info(nodes)")}
            for column in ("data_plane_udp_carry_status", "data_plane_udp_carry_ok_at",
                           "data_plane_stealth_carry_status", "data_plane_stealth_carry_ok_at",
                           "data_plane_stealth_tls_carry_status", "data_plane_stealth_tls_carry_ok_at",
                           "winn3_carrier_flipped_at"):
                # H5's columns, so the real carry rule runs instead of a stub.
                # winn3_carrier_flipped_at is declared by the hub itself (H3's
                # writer; HubSourceGuardTests pins the declaration); adding it
                # here only when absent lets this file run, as evidence, against
                # a tree that predates the column.
                if column not in existing:
                    conn.execute(f"ALTER TABLE nodes ADD COLUMN {column} TEXT")

    # ------------------------------------------------------------ tickets --

    def next_nonce(self, slug, action):
        self.serial += 1
        return hashlib.sha256(f"{slug}:{action}:{self.serial}".encode()).hexdigest()

    def ticket(self, slug, action="new", go_live="auto", tier="free", not_after=None, key=None):
        body = h4.ticket_body(slug=slug, action=action, gateway_id=f"{slug}-gw1", go_live=go_live,
                              tier=tier, nonce=self.next_nonce(slug, action), not_after=not_after)
        return body, h4.envelope(self.mod, body, key=key)

    def post_ticket(self, slug, **kwargs):
        body, env = self.ticket(slug, **kwargs)
        h4.post(self.mod, slug, env)
        time.sleep(0.002)
        return body

    def insert_ticket(self, slug, body, env, posted_at=None):
        with self.db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO winn3_signer_tickets"
                " (slug, action, epoch, nonce, payload, sig, go_live, tier, not_after, posted_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (slug, body["action"], body["epoch"], body["nonce"], env["payload"], env["sig"],
                 body["go_live"], body["tier"], body["not_after"], posted_at or self.mod.utcnow().isoformat()))

    def alter_ticket(self, slug, nonce, field, value, column_only=False):
        """Alter a stored ticket after signing. column_only changes the
        denormalised column and leaves the signed bytes alone."""
        with self.db() as conn:
            row = conn.execute("SELECT * FROM winn3_signer_tickets WHERE slug=? AND nonce=?",
                               (slug, nonce)).fetchone()
            if column_only:
                conn.execute(f"UPDATE winn3_signer_tickets SET {field}=? WHERE slug=? AND nonce=?",
                             (value, slug, nonce))
                return
            fields = json.loads(base64.b64decode(row["payload"]))
            fields[field] = value
            payload = base64.b64encode(h4.canonical(fields)).decode()
            conn.execute("UPDATE winn3_signer_tickets SET payload=? WHERE slug=? AND nonce=?",
                         (payload, slug, nonce))

    # -------------------------------------------------------------- nodes --

    def fresh_node(self, slug, revision=REV_A):
        """A bootstrapped, registered, healthy node that was never promoted."""
        self.seed_placeholder(slug)
        self.register_rev(slug, revision)
        now = self.mod.utcnow().isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET management_status='ok', data_plane_status='ok', data_plane_ok_at=?,"
                " data_plane_udp_status='ok', data_plane_udp_ok_at=? WHERE slug=?", (now, now, slug))

    def complete_fresh(self, slug, digest=DIGEST_A, token=dark.NODE_TOKEN):
        return self.mod.complete_fresh_node_deployment(
            slug, self.mod.FreshDeploymentCompletion(installer_sha256=digest),
            harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/complete-fresh"),
            x_node_token=token)

    def refused(self, slug, status=409, **kwargs):
        with self.assertRaises(harness.HTTPException) as caught:
            self.complete_fresh(slug, **kwargs)
        self.assertEqual(caught.exception.status_code, status, caught.exception.detail)
        return str(caught.exception.detail)

    def rebootstrap(self, slug):
        """The database effect of a re-bootstrap of an existing slug (design
        3.17 "a re-bootstrap opens a fresh deployment epoch"); the route that
        writes it belongs to the job slice."""
        time.sleep(0.003)
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET node_bootstrapped_at=?, deployment_released_at=NULL,"
                " deployment_completed_at=NULL, deployment_withdrawal_id=NULL, deployment_withdrawn_at=NULL,"
                " deployment_prior_state_json=NULL, winn3_expected_transition_json=NULL,"
                " health_closed_at=NULL, health_closed_reason=NULL, operator_enabled=0,"
                " deployment_generation=deployment_generation+1 WHERE slug=?",
                (self.mod.utcnow().isoformat(), slug))
        time.sleep(0.003)

    def promote_before_epoch(self, slug):
        """Make `slug` a slug that was live before its latest bootstrap."""
        self.live_node(slug)
        self.mod.admin_set_node_tier(self.request, slug=slug, tier="off", evidence_sha256="",
                                     x_admin_token=dark.ADMIN_TOKEN)
        self.rebootstrap(slug)

    def promotions(self, slug):
        with self.db() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM node_promotion_events WHERE slug=? ORDER BY promoted_at", (slug,))]

    def completions(self, slug):
        with self.db() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM node_fresh_completions WHERE slug=? ORDER BY completed_at", (slug,))]

    def stored_descriptor(self, slug, *, seq=1, secret_bytes=64, static=b"S", node=None):
        payload = desc.descriptor_payload(node=node or slug, seq=seq, secret_bytes=secret_bytes,
                                          static_bytes=32)
        payload["static_pub"] = base64.b64encode(static * 32).decode()
        payload["admission_secret"] = base64.b64encode(("a" * 64).encode()).decode()
        p64, s64 = desc.envelope_for(payload)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET winn3_descriptor_json=? WHERE slug=?",
                         (json.dumps({"payload": p64, "sig": s64}), slug))
        return payload

    def prove(self, slug, *, identity=HEX64, canary_identity=None, canary_generation=None,
              canary_at=None, carry_at=None, protocol="winn/3", seq=1, canary_seq=None,
              flipped_at=None, **extra):
        """Every proof a go-live needs, newer than the completion: a stored,
        verified g1 descriptor at `seq`, the carrier flipped after the
        completion, and the v3 canary after the flip, bound to the identity,
        the generation and the descriptor's sequence (Sol T1 item 1).
        Individual tests then spoil exactly one."""
        flipped = flipped_at or (self.mod.utcnow() + timedelta(seconds=2)).isoformat()
        later = (self.mod.utcnow() + timedelta(seconds=5)).isoformat()
        self.stored_descriptor(slug, seq=seq)
        row = self.node(slug)
        values = {
            "protocol_version": protocol,
            "winn3_identity_sha256": identity,
            "winn3_carrier_flipped_at": flipped,
            "winn3_canary_status": "ok",
            "winn3_canary_ok_at": canary_at or later,
            "winn3_canary_identity_sha256": identity if canary_identity is None else canary_identity,
            "winn3_canary_generation": (row["deployment_generation"]
                                        if canary_generation is None else canary_generation),
            "winn3_canary_seq": seq if canary_seq is None else canary_seq,
            "data_plane_udp_carry_status": "ok",
            "data_plane_udp_carry_ok_at": carry_at or later,
        }
        values.update(extra)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET " + ", ".join(f"{k}=?" for k in values) + " WHERE slug=?",
                         (*values.values(), slug))

    def candidate(self, slug, *, ticket=None, digest=DIGEST_A, **ticket_kwargs):
        """A fresh node completed under an auto ticket and carrying an unused
        operator gate record, with every proof present."""
        self.fresh_node(slug, "sha256:" + digest)
        body = self.post_ticket(slug, **ticket_kwargs) if ticket is None else ticket
        out = self.complete_fresh(slug, digest)
        self.assertTrue(out["auto_golive_pending"], out)
        gate = self.offnode_gate(slug)
        self.prove(slug)
        return body, gate

    def offnode_gate_v3(self, slug):
        """A real, hub-verified gate record whose node report is a healthy v3
        gateway holding exactly the hub's snapshot, so it passes the winn/3
        rules at use: the same closure resync as dark.offnode_gate (node I/O
        stubbed), then POST /admin/nodes/offnode-gate, which re-verifies it."""
        health = ("management_status", "management_checked_at", "management_error")
        before = tuple(self.node(slug)[column] for column in health)
        with patch.object(self.mod, "sync_peer_to_node", return_value=True), \
                patch.object(self.mod, "sync_winn3_registry_to_node", return_value=True), \
                patch.object(self.mod, "remove_peer_from_node", return_value=True), \
                patch.object(self.mod, "verify_node_management_access", return_value=True):
            self.mod.resync_active_peers_to_node(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET management_status = ?, management_checked_at = ?,"
                         " management_error = ? WHERE slug = ?", (*before, slug))
            confirmed_at = conn.execute(
                "SELECT confirmed_at FROM node_closure_cleanup WHERE slug = ?", (slug,)).fetchone()[0]
            expected = self.mod.offnode_expected_v3_sha256(conn, slug)
        report = (
            "AWG_READ ok iface=awg0 peers=0\n"
            f"V3_FILE present regular=1 sha256={expected}\n"
            "V3_VALID gateway_rules=ok\n"
            "GW unit=active pid_known=1 forward=1 registry_flag_matches=1 gateway_can_read=1 "
            "started_after_file=1 reload_failed_since_file=0\n"
        )
        digest = self.mod.offnode_gate_digest(slug, expected, confirmed_at, "",
                                              hashlib.sha256(report.encode()).hexdigest())
        self.mod.admin_record_offnode_gate(
            self.request, slug=slug, gate_sha256=digest, node_report=report,
            external_evidence_sha256="", x_admin_token=dark.ADMIN_TOKEN)
        return digest

    def flip(self, **patches):
        """One reopen pass with the readiness gate stubbed (the existing suites
        own it) so each test isolates the fresh_install rules."""
        with patch.object(self.mod, "node_auto_reopen_failures", side_effect=lambda *a, **k: []):
            return self.reopen()


def quiet_inherited(cls):
    """The fx2 rerun tests live on the base class; only this file's tests run
    here (the same device fx2 itself uses)."""
    for name in dir(fx2.InstallerRerunTests):
        if name.startswith("test") and name not in cls.__dict__:
            setattr(cls, name, None)
    return cls


H7Base = quiet_inherited(H7Base)


# ===================================================== complete-fresh route ==

@quiet_inherited
class CompleteFreshTests(H7Base):

    def test_auto_ticket_records_the_fresh_install_closure_and_never_opens(self):
        slug = "sg-auto"
        self.fresh_node(slug, REV_A)
        body = self.post_ticket(slug, go_live="auto", tier="free")
        out = self.complete_fresh(slug)
        self.assertEqual(out, {"ok": True, "slug": slug, "operator_enabled": False,
                               "auto_golive_pending": True, "reasons": []})
        row = self.node(slug)
        self.assertEqual(row["operator_enabled"], 0, "completion never opens the latch")
        self.assertEqual(row["health_closed_reason"], "fresh_install")
        self.assertTrue(row["health_closed_at"])
        self.assertEqual(row["latch_cause"], "fresh_install_pending")
        self.assertTrue(row["deployment_released_at"] and row["deployment_completed_at"])
        self.assertEqual(self.completions(slug)[0]["installer_sha256"], DIGEST_A)
        self.assertEqual(self.completions(slug)[0]["ticket_nonce"], body["nonce"])
        self.assertIn((3, "node completed fresh install; automatic go-live pending proofs"),
                      [(a[0], a[1]) for a in self.alerts])

    def test_manual_ticket_is_a_plain_closure_that_is_still_released(self):
        slug = "sg-manual"
        self.fresh_node(slug)
        self.post_ticket(slug, go_live="manual", tier="premium")
        out = self.complete_fresh(slug)
        self.assertFalse(out["auto_golive_pending"], out)
        self.assertEqual(out["reasons"], ["the go-live ticket carries go_live=manual"])
        row = self.node(slug)
        self.assertIsNone(row["health_closed_at"])
        self.assertIsNone(row["health_closed_reason"])
        self.assertTrue(row["deployment_released_at"], "sign needs the release even for a manual node")
        self.assertTrue(row["deployment_completed_at"])
        self.assertEqual(row["operator_enabled"], 0)
        self.assertIn((2, "node completed fresh install; manual evidenced promotion required"),
                      [(a[0], a[1]) for a in self.alerts])

    def test_no_ticket_switch_off_and_unverifiable_tickets_leave_the_plain_closure(self):
        other_key = os.path.join(KEYDIR, "other.pem")
        if not os.path.exists(other_key):
            import subprocess
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", other_key],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cases = {}

        def none(slug):
            pass

        def wrong_key(slug):
            body, env = self.ticket(slug, key=other_key)
            self.insert_ticket(slug, body, env)

        def expired(slug):
            body, env = self.ticket(slug, not_after=int(time.time()) - 30)
            self.insert_ticket(slug, body, env)

        def altered_go_live(slug):
            body = self.post_ticket(slug, go_live="manual")
            self.alter_ticket(slug, body["nonce"], "go_live", "auto")

        def altered_tier(slug):
            body = self.post_ticket(slug, go_live="auto", tier="free")
            self.alter_ticket(slug, body["nonce"], "tier", "premium")

        def wrong_slug(slug):
            body = h4.ticket_body(slug="someone-else", gateway_id="x-gw1", nonce=self.next_nonce(slug, "new"))
            env = h4.envelope(self.mod, body)
            self.insert_ticket(slug, dict(body, slug=slug), env)

        def wrong_action(slug):
            self.post_ticket(slug, action="rekey")

        def set_up_none(slug):
            return none(slug)

        scenarios = [("none", none, "no verified go-live ticket (no-stored-ticket)"),
                     ("wrong-key", wrong_key, "signer-ticket-signature-invalid"),
                     ("expired", expired, "signer-ticket-lifetime"),
                     ("altered-go-live", altered_go_live, "signer-ticket-signature-invalid"),
                     ("altered-tier", altered_tier, "signer-ticket-signature-invalid"),
                     ("wrong-slug", wrong_slug, "signer-ticket-wrong-slug"),
                     ("rekey-only", wrong_action, "no-stored-ticket")]
        for name, setup, expected in scenarios:
            with self.subTest(name):
                slug = f"sg-{name}"
                self.fresh_node(slug)
                setup(slug)
                out = self.complete_fresh(slug)
                self.assertFalse(out["auto_golive_pending"], out)
                self.assertTrue(any(expected in reason for reason in out["reasons"]), out["reasons"])
                row = self.node(slug)
                self.assertIsNone(row["health_closed_reason"])
                self.assertTrue(row["deployment_released_at"])
        with self.subTest("switch-off"), patch.object(self.mod, "WINN3_FRESH_INSTALL_AUTO_GOLIVE", False):
            slug = "sg-off"
            self.fresh_node(slug)
            self.post_ticket(slug, go_live="auto")
            out = self.complete_fresh(slug)
            self.assertFalse(out["auto_golive_pending"])
            self.assertTrue(any("WINN3_FRESH_INSTALL_AUTO_GOLIVE=0" in r for r in out["reasons"]), out)
            self.assertIsNone(self.node(slug)["health_closed_reason"])

    def test_go_live_and_tier_come_only_from_the_verified_ticket_bytes(self):
        # A denormalised column that disagrees with the signed bytes changes
        # nothing: the column says auto, the signed ticket says manual.
        slug = "sg-column"
        self.fresh_node(slug)
        body = self.post_ticket(slug, go_live="manual", tier="free")
        self.alter_ticket(slug, body["nonce"], "go_live", "auto", column_only=True)
        out = self.complete_fresh(slug)
        self.assertFalse(out["auto_golive_pending"], out)
        # The converse: the signed ticket says auto, the column says manual.
        other = "sg-column2"
        self.fresh_node(other)
        body = self.post_ticket(other, go_live="auto", tier="free")
        self.alter_ticket(other, body["nonce"], "go_live", "manual", column_only=True)
        self.assertTrue(self.complete_fresh(other)["auto_golive_pending"])

    def test_refused_when_open_or_withdrawn_or_retired_or_unknown(self):
        slug = "sg-state"
        self.fresh_node(slug)
        self.post_ticket(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_withdrawal_id=? WHERE slug=?", ("f" * 32, slug))
        self.assertIn("open withdrawal", self.refused(slug))
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_withdrawal_id=NULL, operator_enabled=1 WHERE slug=?", (slug,))
        self.assertIn("open withdrawal or is open", self.refused(slug))
        with self.db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=0, retired_at=? WHERE slug=?",
                         (self.mod.utcnow().isoformat(), slug))
        self.assertIn("Retired", self.refused(slug))
        self.refused("no-such-node", status=401)  # the token check comes first
        self.assertEqual(self.completions(slug), [])
        # Anti-vacuity: the same node, restored, completes.
        with self.db() as conn:
            conn.execute("UPDATE nodes SET retired_at=NULL WHERE slug=?", (slug,))
        self.assertTrue(self.complete_fresh(slug)["ok"])

    def test_refused_for_a_bad_token_a_bad_digest_and_an_unknown_slug(self):
        slug = "sg-auth"
        self.fresh_node(slug)
        self.refused(slug, status=401, token="not-the-token")
        for bad in ("", "A" * 64, "a" * 63, "sha256:" + "a" * 64, "g" * 64):
            self.refused(slug, status=400, digest=bad)
        self.assertEqual(self.completions(slug), [])

    def test_a_promotion_since_the_bootstrap_refuses(self):
        slug = "sg-live"
        self.live_node(slug)
        self.mod.admin_set_node_tier(self.request, slug=slug, tier="off", evidence_sha256="",
                                     x_admin_token=dark.ADMIN_TOKEN)
        self.post_ticket(slug, action="reset")
        # promoted_at is at or after node_bootstrapped_at (the migration zero
        # epoch), so the slug is live since its bootstrap: the rerun route
        # handles such a node, not this one.
        self.assertIn("live since its bootstrap", self.refused(slug))
        self.assertEqual(self.completions(slug), [])

    def test_a_reset_of_a_previously_live_slug_needs_a_valid_unconsumed_reset_ticket(self):
        slug = "sg-reset"
        self.promote_before_epoch(slug)
        self.assertEqual(len(self.promotions(slug)), 1)
        # No ticket at all.
        self.assertIn("needs a verified, unexpired t1 reset ticket (no-stored-ticket)", self.refused(slug))
        # A new ticket is not a reset ticket.
        self.post_ticket(slug, action="new")
        self.assertIn("t1 reset ticket", self.refused(slug))
        # An expired reset ticket.
        body, env = self.ticket(slug, action="reset", not_after=int(time.time()) - 5)
        self.insert_ticket(slug, body, env)
        self.assertIn("signer-ticket-lifetime", self.refused(slug))
        # A reset ticket whose bytes were altered after signing.
        altered = self.post_ticket(slug, action="reset")
        self.alter_ticket(slug, altered["nonce"], "tier", "premium")
        self.assertIn("signer-ticket-signature-invalid", self.refused(slug))
        self.assertEqual(self.completions(slug), [])
        # A valid reset ticket (the newest) completes it, releases the
        # deployment (so the H2 job may ask the signer, which spends the
        # nonce), and records the use.
        good = self.post_ticket(slug, action="reset", go_live="auto", tier="premium")
        out = self.complete_fresh(slug)
        self.assertTrue(out["auto_golive_pending"], out)
        self.assertEqual(self.completions(slug)[0]["ticket_nonce"], good["nonce"])
        row = self.node(slug)
        self.assertEqual(row["health_closed_reason"], "fresh_install")
        self.assertTrue(row["deployment_released_at"])
        self.assertEqual(row["operator_enabled"], 0)

    def test_a_reset_that_passes_every_hub_side_check_completes_and_records_the_reset_nonce(self):
        # H7-TICKET: the signer consumes the reset nonce at sign, and sign is
        # refused until this completion has released the slug (design 3.17),
        # so the hub's share of "unconsumed" is "not used by an earlier
        # epoch's completion". A reset that passes every hub-side check
        # completes, is released and is recorded under the reset nonce.
        slug = "sg-reset-ok"
        self.promote_before_epoch(slug)
        good = self.post_ticket(slug, action="reset", go_live="auto", tier="free")
        out = self.complete_fresh(slug)
        self.assertTrue(out["ok"] and out["auto_golive_pending"], out)
        row = self.node(slug)
        self.assertTrue(row["deployment_released_at"] and row["deployment_completed_at"])
        self.assertEqual((row["health_closed_reason"], row["operator_enabled"]), ("fresh_install", 0))
        self.assertEqual([c["ticket_nonce"] for c in self.completions(slug)], [good["nonce"]])
        # Anti-vacuity: the same slug shape with only a new ticket is refused,
        # released nowhere and recorded nowhere.
        self.promote_before_epoch("sg-reset-newonly")
        self.post_ticket("sg-reset-newonly", action="new", go_live="auto")
        self.assertIn("t1 reset ticket", self.refused("sg-reset-newonly"))
        self.assertIsNone(self.node("sg-reset-newonly")["deployment_released_at"])
        self.assertEqual(self.completions("sg-reset-newonly"), [])

    def test_a_reset_ticket_used_by_an_earlier_epoch_is_consumed(self):
        slug = "sg-spent"
        self.promote_before_epoch(slug)
        good = self.post_ticket(slug, action="reset", go_live="manual")
        self.assertFalse(self.complete_fresh(slug)["auto_golive_pending"])
        self.assertEqual(self.completions(slug)[0]["ticket_nonce"], good["nonce"])
        # The same reset ticket in the SAME epoch is idempotent...
        self.assertTrue(self.complete_fresh(slug)["idempotent"])
        # ...but a second provider reset (a new epoch) cannot reuse it.
        self.rebootstrap(slug)
        self.assertIn("already used by an earlier completion", self.refused(slug))
        # A fresh reset ticket for the new epoch works.
        self.post_ticket(slug, action="reset", go_live="auto")
        self.assertTrue(self.complete_fresh(slug)["auto_golive_pending"])

    def test_a_reset_under_a_newer_new_ticket_records_the_reset_nonce(self):
        # The complete-fresh side of H7-NONCE (Claude T3): the hub-side reuse
        # check can find a spent reset nonce only if the completion recorded
        # it, so a reset completed under a newer go_live=auto new ticket is
        # recorded under the RESET nonce, and a later epoch cannot reuse it.
        slug = "sg-reset-newer-new"
        self.promote_before_epoch(slug)
        reset = self.post_ticket(slug, action="reset", go_live="auto")
        newer = self.post_ticket(slug, action="new", go_live="auto")
        with self.db() as conn:  # the case is not vacuous: the go-live ticket is the newer one
            self.assertEqual(self.mod.winn3_golive_ticket(conn, slug)[0]["nonce"], newer["nonce"])
        self.assertTrue(self.complete_fresh(slug)["auto_golive_pending"])
        self.assertEqual([c["ticket_nonce"] for c in self.completions(slug)], [reset["nonce"]])
        self.rebootstrap(slug)
        self.assertIn("already used by an earlier completion", self.refused(slug))

    def test_an_identical_reset_completion_stays_idempotent_after_its_ticket_is_spent(self):
        # Sol T1 item 2 ("an identical completion already committed in the
        # current epoch must remain idempotent after signing consumes its
        # ticket") and Claude's T1 note (a retry after the reset ticket expires
        # got 409): reset authority runs after the idempotence check.
        slug = "sg-retry"
        self.promote_before_epoch(slug)
        self.post_ticket(slug, action="reset", go_live="auto")
        self.assertTrue(self.complete_fresh(slug)["auto_golive_pending"])
        # The reset ticket is now unusable (here: a newer reset ticket that has
        # expired is the one the hub selects), as after the signer spent it.
        body, env = self.ticket(slug, action="reset", not_after=int(time.time()) - 5)
        self.insert_ticket(slug, body, env)
        try:  # a refusal here is the defect, so it fails by assertion, not by error
            again = self.complete_fresh(slug)
        except harness.HTTPException as exc:
            self.fail(f"the identical completion was refused after its reset ticket was spent: {exc.detail}")
        self.assertTrue(again["ok"] and again["idempotent"] and again["auto_golive_pending"], again)
        self.assertEqual(len(self.completions(slug)), 1)
        # A different completion is still refused, and a new epoch still needs
        # its own reset authority.
        self.register_rev(slug, REV_B)
        self.assertIn("a different completion is already recorded", self.refused(slug, digest=DIGEST_B))
        self.rebootstrap(slug)
        self.register_rev(slug, REV_A)
        self.assertIn("t1 reset ticket", self.refused(slug))

    def test_a_slug_with_no_earlier_promotion_needs_no_reset_ticket(self):
        slug = "sg-new"
        self.fresh_node(slug)
        out = self.complete_fresh(slug)  # no ticket at all: a plain closure, not a refusal
        self.assertTrue(out["ok"] and not out["auto_golive_pending"])
        self.assertTrue(self.node(slug)["deployment_released_at"])

    def test_the_installer_digest_must_equal_the_registered_revision(self):
        slug = "sg-digest"
        self.fresh_node(slug, REV_A)
        self.post_ticket(slug)
        self.assertIn("differs from the registered revision", self.refused(slug, digest=DIGEST_B))
        with self.db() as conn:
            conn.execute("UPDATE nodes SET data_plane_code_revision='unprovable' WHERE slug=?", (slug,))
        self.assertIn("differs from the registered revision", self.refused(slug))
        self.assertEqual(self.completions(slug), [])
        self.assertIsNone(self.node(slug)["deployment_completed_at"])

    def test_idempotent_for_the_same_digest_and_refused_for_a_different_completion(self):
        slug = "sg-idem"
        self.fresh_node(slug, REV_A)
        self.post_ticket(slug)
        first = self.complete_fresh(slug)
        recorded = self.node(slug)["deployment_completed_at"]
        again = self.complete_fresh(slug)
        self.assertEqual(again["idempotent"], True)
        self.assertEqual(again["auto_golive_pending"], first["auto_golive_pending"])
        self.assertEqual(self.node(slug)["deployment_completed_at"], recorded, "the first completion stands")
        self.assertEqual(len(self.completions(slug)), 1)
        # The node re-registers with other installer bytes: a different
        # completion is already recorded.
        self.register_rev(slug, REV_B)
        self.assertIn("a different completion is already recorded", self.refused(slug, digest=DIGEST_B))
        # A completion recorded by something else (no record for this epoch) is
        # a different completion too.
        other = "sg-idem2"
        self.fresh_node(other, REV_A)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_completed_at=? WHERE slug=?",
                         (self.mod.utcnow().isoformat(), other))
        self.assertIn("a different completion is already recorded", self.refused(other))

    def test_a_reset_after_a_rebootstrap_is_not_refused_by_the_old_completion(self):
        slug = "sg-again"
        self.fresh_node(slug, REV_A)
        self.post_ticket(slug, action="new", go_live="manual")
        self.complete_fresh(slug)
        old = self.node(slug)["node_bootstrapped_at"]
        self.rebootstrap(slug)
        self.assertNotEqual(self.node(slug)["node_bootstrapped_at"], old)
        self.assertIsNone(self.node(slug)["deployment_completed_at"])
        # The same installer digest, and then (after another re-bootstrap) a
        # different one: neither is refused by the completion before.
        self.assertTrue(self.complete_fresh(slug)["ok"])
        self.rebootstrap(slug)
        self.register_rev(slug, REV_B)
        self.assertTrue(self.complete_fresh(slug, DIGEST_B)["ok"])
        self.assertEqual(len(self.completions(slug)), 3)

    def test_migration_default_and_the_coalesce(self):
        # ensure_schema gives every row the zero epoch.
        slug = "sg-zero"
        self.fresh_node(slug)
        self.assertEqual(self.node(slug)["node_bootstrapped_at"], "0001-01-01T00:00:00")
        # A row with the column forced back to NULL reads the same way.
        with self.db() as conn:
            conn.execute("UPDATE nodes SET node_bootstrapped_at=NULL WHERE slug=?", (slug,))
        self.assertEqual(self.mod.node_bootstrap_epoch(self.node(slug)), "0001-01-01T00:00:00")
        # A pre-v7 live node (a manual promotion, the column NULL) is therefore
        # never "never live": complete-fresh refuses it, whichever way the
        # column reads.
        live = "sg-prev7"
        self.live_node(live)
        self.mod.admin_set_node_tier(self.request, slug=live, tier="off", evidence_sha256="",
                                     x_admin_token=dark.ADMIN_TOKEN)
        self.post_ticket(live, action="reset")
        for value in (None, "0001-01-01T00:00:00"):
            with self.db() as conn:
                conn.execute("UPDATE nodes SET node_bootstrapped_at=? WHERE slug=?", (value, live))
            self.assertIn("live since its bootstrap", self.refused(live))
        with self.db() as conn:
            self.mod.ensure_schema(conn)
            self.assertEqual(conn.execute("SELECT node_bootstrapped_at FROM nodes WHERE slug=?",
                                          (live,)).fetchone()[0], "0001-01-01T00:00:00")
            conn.execute("UPDATE nodes SET node_bootstrapped_at=NULL WHERE slug=?", (live,))
            self.mod.ensure_schema(conn)
            self.assertEqual(conn.execute("SELECT node_bootstrapped_at FROM nodes WHERE slug=?",
                                          (live,)).fetchone()[0], "0001-01-01T00:00:00")

    def test_the_route_never_calls_the_tier_route_or_carries_the_admin_token(self):
        source = HUB_SOURCE
        body = source.split("def complete_fresh_node_deployment(", 1)[1].split("\n@app.", 1)[0]
        self.assertNotIn("operator_enabled=1", body.replace(" ", ""))
        self.assertNotIn("admin_set_node_tier", body)
        self.assertNotIn("require_admin_token", body)
        self.assertIn("require_node_token", body)


HUB_SOURCE = harness._extract_main_block()


# ============================================== the rerun completion route ==

@quiet_inherited
class RerunCompletionTests(H7Base):

    def never_live_rerun(self, slug, *, ticket=True, go_live="auto", revision=REV_A, **kwargs):
        """A node that has an installer deployment withdrawal but was never
        live: the resume rerun of a late-failed fresh install."""
        self.fresh_node(slug, revision)
        if ticket:
            self.post_ticket(slug, go_live=go_live, **kwargs)
        return self.rerun(slug, revision)

    def test_a_never_live_rerun_under_an_auto_ticket_is_a_fresh_install_closure(self):
        slug = "re-auto"
        out = self.never_live_rerun(slug)
        self.assertTrue(out["auto_golive_pending"] and out["auto_reopen_pending"], out)
        self.assertEqual(out["reasons"], [])
        row = self.node(slug)
        self.assertEqual(row["health_closed_reason"], "fresh_install")
        self.assertEqual(row["latch_cause"], "fresh_install_pending")
        self.assertTrue(row["deployment_released_at"] and row["deployment_completed_at"])
        self.assertEqual(row["operator_enabled"], 0)
        self.assertEqual(self.completions(slug)[0]["epoch"], "0001-01-01T00:00:00")
        self.assertIn((3, "node completed fresh install rerun; automatic go-live pending proofs"),
                      [(a[0], a[1]) for a in self.alerts])

    def test_an_ineligible_rerun_is_still_released_and_stays_a_plain_closure(self):
        # The resume rerun of a late-failed go_live=manual install.
        slug = "re-manual"
        out = self.never_live_rerun(slug, go_live="manual")
        self.assertFalse(out["auto_golive_pending"] or out["auto_reopen_pending"], out)
        self.assertIn("prior operator_enabled != 1 (the node was not live when withdrawn)", out["reasons"])
        row = self.node(slug)
        self.assertTrue(row["deployment_released_at"])
        self.assertIsNone(row["health_closed_reason"])
        self.assertIsNone(row["deployment_completed_at"])
        # No ticket at all.
        out = self.never_live_rerun("re-none", ticket=False)
        self.assertFalse(out["auto_golive_pending"])
        self.assertTrue(self.node("re-none")["deployment_released_at"])
        # The first node of an installer revision nobody evidenced (a live node).
        self.live_node("re-newrev", REV_A)
        out = self.rerun("re-newrev", REV_B)
        self.assertFalse(out["auto_reopen_pending"])
        self.assertTrue(self.node("re-newrev")["deployment_released_at"])
        # A rerun while NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED=0.
        with patch.object(self.mod, "NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED", False):
            self.live_node("re-off", REV_A)
            out = self.rerun("re-off")
            self.assertFalse(out["auto_reopen_pending"])
            self.assertTrue(self.node("re-off")["deployment_released_at"])

    def test_a_live_node_keeps_the_installer_rerun_path_even_under_an_auto_ticket(self):
        slug = "re-live"
        self.live_node(slug)
        self.post_ticket(slug, go_live="auto")
        out = self.rerun(slug)
        self.assertTrue(out["auto_reopen_pending"] and not out["auto_golive_pending"], out)
        self.assertEqual(self.node(slug)["health_closed_reason"], "installer_rerun")
        self.assertEqual(self.completions(slug), [])

    def test_a_node_live_at_withdrawal_with_no_promotion_row_is_not_fresh(self):
        # A legacy node opened by direct SQL has no promotion event; its
        # withdrawal snapshot still says it was live, so it is no fresh install.
        slug = "re-legacy"
        self.fresh_node(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=1, latch_cause='legacy' WHERE slug=?", (slug,))
        self.post_ticket(slug, go_live="auto")
        out = self.rerun(slug)
        self.assertFalse(out["auto_golive_pending"], out)
        self.assertNotEqual(self.node(slug)["health_closed_reason"], "fresh_install")

    def test_a_pre_v7_live_node_is_never_classed_fresh_install(self):
        # A manual promotion exists and the column is the migration zero (or
        # NULL): the first v3 rerun under an auto "new" ticket is the
        # installer_rerun path or the plain closure, never fresh_install.
        for value in ("0001-01-01T00:00:00", None):
            slug = f"re-prev7-{'zero' if value else 'null'}"
            self.live_node(slug)
            self.post_ticket(slug, action="new", go_live="auto")
            with self.db() as conn:
                conn.execute("UPDATE nodes SET node_bootstrapped_at=? WHERE slug=?", (value, slug))
            out = self.rerun(slug)
            self.assertFalse(out["auto_golive_pending"], out)
            self.assertIn(self.node(slug)["health_closed_reason"], ("installer_rerun", None))
            self.assertNotEqual(self.node(slug)["health_closed_reason"], "fresh_install")

    def test_a_pre_v7_node_closed_at_withdrawal_is_never_classed_fresh_install(self):
        # A manual promotion exists (migration zero or NULL) and the node was
        # closed, not live, when the rerun withdrew it: the prior latch says
        # nothing, so only "never live since bootstrap" keeps it off the
        # fresh_install class (design 3.17, 5.5 "Migration default").
        for value in ("0001-01-01T00:00:00", None):
            slug = f"re-closed-{'zero' if value else 'null'}"
            self.live_node(slug)
            with self.db() as conn:
                conn.execute("UPDATE nodes SET operator_enabled=0, node_bootstrapped_at=? WHERE slug=?",
                             (value, slug))
            self.post_ticket(slug, action="new", go_live="auto")
            out = self.rerun(slug)
            self.assertFalse(out["auto_golive_pending"], out)
            self.assertNotEqual(self.node(slug)["health_closed_reason"], "fresh_install")
            self.assertEqual(self.completions(slug), [])

    def test_a_reset_slug_is_classed_fresh_install_on_the_rerun_route_only_under_the_reset_authority(self):
        # Sol T1 item 2 applied to both completion routes: a slug that was live
        # before its latest bootstrap goes live automatically only under the
        # same reset authority as complete-fresh (a verified, unexpired reset
        # ticket not used by an earlier epoch's completion). Without it the
        # resume rerun is still released (so it can be signed) and stays a
        # plain closure. A go_live=auto ticket that is not a reset ticket is
        # still a valid go-live ticket, so only the reset failures keep the
        # slug off the class (Claude T2: reading the nonce slot instead
        # survived).
        slug = "re-reset-newonly"
        self.promote_before_epoch(slug)
        self.post_ticket(slug, action="new", go_live="auto")
        out = self.rerun(slug)
        self.assertFalse(out["auto_golive_pending"], out)
        row = self.node(slug)
        self.assertNotEqual(row["health_closed_reason"], "fresh_install")
        self.assertTrue(row["deployment_released_at"])
        self.assertEqual(row["operator_enabled"], 0)
        self.assertEqual(self.completions(slug), [])
        # Anti-vacuity: a reset slug under a valid reset ticket is classed
        # fresh_install by the same route (the same authority as complete-fresh).
        self.promote_before_epoch("re-reset-ok")
        good = self.post_ticket("re-reset-ok", action="reset", go_live="auto")
        self.assertTrue(self.rerun("re-reset-ok")["auto_golive_pending"])
        self.assertEqual([c["ticket_nonce"] for c in self.completions("re-reset-ok")], [good["nonce"]])
        # The same slug shape under a valid reset ticket and a NEWER new ticket
        # is classed fresh_install too, and the completion is recorded under
        # the RESET nonce (the one a later epoch's reuse check must find), not
        # the newer new ticket's (Fable T2, the severable nonce hardening).
        self.promote_before_epoch("re-reset")
        reset = self.post_ticket("re-reset", action="reset", go_live="auto")
        newer = self.post_ticket("re-reset", action="new", go_live="auto")
        with self.db() as conn:  # the case is not vacuous: the go-live ticket is the newer one
            self.assertEqual(self.mod.winn3_golive_ticket(conn, "re-reset")[0]["nonce"], newer["nonce"])
        out = self.rerun("re-reset")
        self.assertTrue(out["auto_golive_pending"], out)
        self.assertEqual(self.node("re-reset")["health_closed_reason"], "fresh_install")
        self.assertEqual([c["ticket_nonce"] for c in self.completions("re-reset")], [reset["nonce"]])
        # A never-promoted slug under the same ticket shape is classed
        # fresh_install by the same route.
        self.assertTrue(self.never_live_rerun("re-reset-new")["auto_golive_pending"])

    def test_a_tampered_ticket_leaves_the_plain_closure_on_the_rerun_route(self):
        slug = "re-tamper"
        self.fresh_node(slug)
        body = self.post_ticket(slug, go_live="manual")
        self.alter_ticket(slug, body["nonce"], "go_live", "auto")
        out = self.rerun(slug)
        self.assertFalse(out["auto_golive_pending"], out)
        self.assertTrue(self.node(slug)["deployment_released_at"])

    def test_the_switch_off_leaves_the_plain_closure_on_the_rerun_route(self):
        with patch.object(self.mod, "WINN3_FRESH_INSTALL_AUTO_GOLIVE", False):
            out = self.never_live_rerun("re-switch")
        self.assertFalse(out["auto_golive_pending"], out)
        self.assertIsNone(self.node("re-switch")["health_closed_reason"])

    def test_the_existing_not_live_rerun_still_names_its_reason(self):
        slug = "re-plain"
        self.seed_placeholder(slug)
        self.register_rev(slug)
        out = self.rerun(slug)
        self.assertEqual(out["auto_reopen_pending"], False)
        self.assertEqual(out["auto_golive_pending"], False)
        self.assertIn("prior operator_enabled != 1 (the node was not live when withdrawn)", out["reasons"])


# ====================================================== the reopen and flip ==

@quiet_inherited
class FreshReopenTests(H7Base):

    def held(self, slug):
        out = self.flip()
        self.assertNotIn(slug, out["reopened"], out)
        return out["held"].get(slug, [])

    def assertHeld(self, slug, text):
        reasons = self.held(slug)
        self.assertTrue(any(text in reason for reason in reasons), (text, reasons))
        self.assertEqual(self.node(slug)["operator_enabled"], 0)

    def test_every_proof_present_flips_at_the_verified_tier_and_records_everything(self):
        for tier in ("free", "premium"):
            with self.subTest(tier=tier):
                slug = f"fl-{tier}"
                body, gate = self.candidate(slug, tier=tier)
                self.alerts.clear()
                out = self.flip()
                self.assertEqual(out["reopened"], [slug], out)
                row = self.node(slug)
                self.assertEqual(row["operator_enabled"], 1)
                self.assertEqual(row["free_access_enabled"], 1 if tier == "free" else 0)
                self.assertEqual(row["latch_cause"], "auto_golive_fresh_install")
                self.assertIsNone(row["health_closed_at"])
                self.assertIsNone(row["health_closed_reason"])
                event = self.promotions(slug)[-1]
                self.assertEqual(event["tier"], tier)
                self.assertEqual(event["operator_source_hash"], "auto_golive_fresh_install")
                self.assertEqual(event["evidence_sha256"], gate)
                with self.db() as conn:
                    latch = conn.execute("SELECT cause, detail_json FROM node_latch_events WHERE slug=? "
                                         "ORDER BY event_id DESC LIMIT 1", (slug,)).fetchone()
                    used = conn.execute("SELECT used_for FROM node_offnode_gates WHERE gate_sha256=?",
                                        (gate,)).fetchone()[0]
                self.assertEqual(latch["cause"], "auto_golive_fresh_install")
                detail = json.loads(latch["detail_json"])["fresh_install"]
                self.assertEqual(detail["ticket"]["nonce"], body["nonce"])
                self.assertEqual(detail["ticket"]["tier"], tier)
                self.assertEqual(detail["identity_sha256"], HEX64)
                self.assertNotIn("host_key_sha256", json.dumps(detail))
                self.assertEqual(used, "auto_reopened", "the gate record is consumed like a manual promotion")
                self.assertIn((3, "fresh install node went live automatically"),
                              [(a[0], a[1]) for a in self.alerts])
                # A second pass changes nothing.
                self.assertEqual(self.flip()["reopened"], [])

    def test_each_missing_proof_keeps_the_node_dark_by_name(self):
        def spoil(**values):
            def apply(slug):
                with self.db() as conn:
                    conn.execute("UPDATE nodes SET " + ", ".join(f"{k}=?" for k in values) + " WHERE slug=?",
                                 (*values.values(), slug))
            return apply

        stale = (self.mod.utcnow() - timedelta(days=1)).isoformat()
        cases = [
            ("carry-missing", spoil(data_plane_udp_carry_status="unknown", data_plane_udp_carry_ok_at=None),
             "udp: no carrying proof newer than the rerun completion"),
            ("carry-stale", spoil(data_plane_udp_carry_ok_at=stale),
             "udp: no carrying proof newer than the rerun completion"),
            ("carry-failed", spoil(data_plane_udp_carry_status="failed"),
             "udp: no carrying proof newer than the rerun completion"),
            ("canary-stale", spoil(winn3_canary_ok_at=stale),
             "winn/3: no per-slug v3 canary newer than the rerun completion"),
            ("canary-failed", spoil(winn3_canary_status="fail"),
             "winn/3: no per-slug v3 canary newer than the rerun completion"),
            ("canary-other-identity", spoil(winn3_canary_identity_sha256="d" * 64),
             "winn/3: the per-slug v3 canary result is bound to another identity"),
            ("canary-other-generation", spoil(winn3_canary_generation=99),
             "winn/3: the per-slug v3 canary result is bound to another deployment generation"),
            ("no-identity", spoil(winn3_identity_sha256=None, winn3_canary_identity_sha256=None),
             "winn/3: no recorded identity digest to bind the v3 canary to"),
            ("carrier-v1", spoil(protocol_version="winn/1"),
             "the carrier is not winn/3 (no v3 profile is served yet)"),
            ("hold", spoil(winn3_operator_hold=1), "winn3 operator hold is active"),
            ("unreleased", spoil(deployment_released_at=None), "the hub never released this deployment"),
        ]
        for name, apply, expected in cases:
            with self.subTest(name):
                slug = f"dk-{name}"
                self.candidate(slug)
                apply(slug)
                self.assertHeld(slug, expected)
        # A closure with no recorded completion has no window to be judged in:
        # it becomes an operator closure at once.
        slug = "dk-no-completion"
        self.candidate(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_completed_at=NULL WHERE slug=?", (slug,))
        out = self.flip()
        self.assertIn(slug, out["fresh_install_expired"], out)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        # Anti-vacuity: the unspoiled candidate in the same run does flip.
        self.candidate("dk-control")
        out = self.flip()
        self.assertIn("dk-control", out["reopened"], out)

    def test_the_go_live_canary_is_bound_to_the_current_descriptor_and_follows_the_carrier_flip(self):
        # Sol T1 item 1: identity and generation alone let a canary of an older
        # descriptor (sequence 1 while sequence 2 is stored) or a pre-flip
        # proof (pre-sign or prospective) satisfy the go-live gate.
        def spoil(**values):
            def apply(slug):
                with self.db() as conn:
                    conn.execute("UPDATE nodes SET " + ", ".join(f"{k}=?" for k in values) + " WHERE slug=?",
                                 (*values.values(), slug))
            return apply

        def renewed(slug):  # the descriptor moved on to sequence 2; the canary proved sequence 1
            self.stored_descriptor(slug, seq=2)

        def tampered(slug):  # a stored descriptor whose bytes no longer verify
            with self.db() as conn:
                envelope = json.loads(conn.execute("SELECT winn3_descriptor_json FROM nodes WHERE slug=?",
                                                   (slug,)).fetchone()[0])
                fields = json.loads(base64.b64decode(envelope["payload"]))
                fields["seq"] = 7
                envelope["payload"] = base64.b64encode(json.dumps(fields, sort_keys=True,
                                                                  separators=(",", ":")).encode()).decode()
                conn.execute("UPDATE nodes SET winn3_descriptor_json=?, winn3_canary_seq=7 WHERE slug=?",
                             (json.dumps(envelope), slug))

        def expired(slug):  # an authentic stored descriptor whose not_after has passed
            payload = desc.descriptor_payload(node=slug, seq=1, iat=int(time.time()) - 7200, ttl=3600,
                                              secret_bytes=64, static_bytes=32)
            payload["static_pub"] = base64.b64encode(b"S" * 32).decode()
            payload["admission_secret"] = base64.b64encode(("a" * 64).encode()).decode()
            p64, s64 = desc.envelope_for(payload)
            spoil(winn3_descriptor_json=json.dumps({"payload": p64, "sig": s64}))(slug)

        def before_flip(slug):  # canary after the completion but before the carrier flip
            flipped = (self.mod.utcnow() + timedelta(seconds=30)).isoformat()
            spoil(winn3_carrier_flipped_at=flipped)(slug)

        def hard_stale(slug):  # newer than completion and flip, older than the hard-stale limit
            base = self.mod.utcnow() - timedelta(minutes=self.mod.WINN3_CANARY_HARD_STALE_MINUTES + 30)
            spoil(deployment_completed_at=base.isoformat(),
                  winn3_carrier_flipped_at=(base + timedelta(seconds=10)).isoformat(),
                  winn3_canary_ok_at=(base + timedelta(seconds=20)).isoformat())(slug)

        cases = [
            ("seq-older", renewed,
             "winn/3: the per-slug v3 canary result is not bound to the current verified descriptor"),
            ("seq-missing", spoil(winn3_canary_seq=None),
             "winn/3: the per-slug v3 canary result is not bound to the current verified descriptor"),
            ("no-descriptor", spoil(winn3_descriptor_json=None),
             "winn/3: the per-slug v3 canary result is not bound to the current verified descriptor"),
            ("descriptor-unverified", tampered,
             "winn/3: the per-slug v3 canary result is not bound to the current verified descriptor"),
            ("descriptor-expired", expired,
             "winn/3: the per-slug v3 canary result is not bound to the current verified descriptor"),
            ("no-flip-time", spoil(winn3_carrier_flipped_at=None),
             "winn/3: no per-slug v3 canary newer than the carrier flip"),
            ("canary-before-flip", before_flip,
             "winn/3: no per-slug v3 canary newer than the carrier flip"),
            ("canary-hard-stale", hard_stale,
             "winn/3: the per-slug v3 canary is absent, stale or incorrectly bound"),
        ]
        for name, apply, expected in cases:
            with self.subTest(name):
                slug = f"cb-{name}"
                self.candidate(slug)
                apply(slug)
                self.assertHeld(slug, expected)
        # Each spoil holds by its own rule: the hard-stale case is newer than
        # the completion and the flip and bound in full, so only freshness
        # names it.
        self.assertEqual(
            [r for r in self.held("cb-canary-hard-stale") if r.startswith("winn/3")],
            ["winn/3: the per-slug v3 canary is absent, stale or incorrectly bound"])
        # Anti-vacuity: the unspoiled candidate, its canary after the flip and
        # bound to sequence 1 of the stored descriptor, flips.
        self.candidate("cb-control")
        self.assertIn("cb-control", self.flip()["reopened"])

    def test_the_whole_winn3_gate_without_stubs_opens_the_node_once_everything_is_true(self):
        # Sol T1 acceptance: the real readiness gate (a winn/3 node report and
        # a hub-verified gate record), the real fresh rules, a verified stored
        # descriptor and a canary bound to it after the carrier flip. Only node
        # I/O and the authority-recovery arm are stubbed (the fx2 harness).
        # The H6 hub-sourced gate is not in this tree; an operator-posted
        # record stands in for it. The record (a healthy v3 gateway report) is
        # taken before the flip, so the closure cleanup is the winn/1 resync's;
        # at use it is verified again under winn/3 rules.
        slug = "wg-whole"
        self.fresh_node(slug, "sha256:" + DIGEST_A)
        body = self.post_ticket(slug, tier="premium")
        self.assertTrue(self.complete_fresh(slug)["auto_golive_pending"])
        gate = self.offnode_gate_v3(slug)
        self.prove(slug)
        now = self.mod.utcnow()
        with self.db() as conn:
            conn.execute("UPDATE nodes SET status='online', last_heartbeat=?, data_plane_green_streak=1,"
                         " data_plane_green_since=? WHERE slug=?",
                         (now.isoformat(), (now + timedelta(seconds=2)).isoformat(), slug))
        out = self.reopen()
        self.assertIn(slug, out["held"], out)
        self.assertEqual([r for r in out["held"][slug] if "healthy proofs since authority recovery" not in r], [],
                         out["held"][slug])
        # A canary that predates the carrier flip holds it through the real gate.
        flipped = self.node(slug)["winn3_carrier_flipped_at"]
        with self.db() as conn:
            conn.execute("UPDATE nodes SET data_plane_green_streak=9, winn3_carrier_flipped_at=? WHERE slug=?",
                         ((now + timedelta(seconds=30)).isoformat(), slug))
        out = self.reopen()
        self.assertIn("winn/3: no per-slug v3 canary newer than the carrier flip", out["held"].get(slug, []), out)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET winn3_carrier_flipped_at=? WHERE slug=?", (flipped, slug))
        out = self.reopen()
        self.assertEqual(out["reopened"], [slug], out)
        row = self.node(slug)
        self.assertEqual((row["operator_enabled"], row["free_access_enabled"]), (1, 0))
        event = self.promotions(slug)[-1]
        self.assertEqual((event["tier"], event["operator_source_hash"], event["evidence_sha256"]),
                         ("premium", "auto_golive_fresh_install", gate))
        with self.db() as conn:
            detail = json.loads(conn.execute(
                "SELECT detail_json FROM node_latch_events WHERE slug=? ORDER BY event_id DESC LIMIT 1",
                (slug,)).fetchone()[0])["fresh_install"]
        self.assertEqual(detail["ticket"]["nonce"], body["nonce"])

    def test_a_transport_without_its_carry_proof_holds_every_advertised_transport(self):
        slug = "dk-transports"
        self.candidate(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET stealth_endpoint='s.example.test:80', xray_security='none',"
                         " xray_path='/p', xray_uuid='11111111-2222-4333-8444-555555555555',"
                         " stealth_public_port=80, stealth_transports='[]', direct_awg_enabled=0 WHERE slug=?",
                         (slug,))
        self.assertHeld(slug, "stealth: no carrying proof newer than the rerun completion (unknown)")
        later = (self.mod.utcnow() + timedelta(seconds=9)).isoformat()
        with self.db() as conn:
            conn.execute("UPDATE nodes SET data_plane_stealth_carry_status='ok',"
                         " data_plane_stealth_carry_ok_at=? WHERE slug=?", (later, slug))
        self.assertEqual(self.flip()["reopened"], [slug])

    def test_the_real_readiness_gate_still_holds_a_node_with_no_gate_record(self):
        slug = "dk-gate"
        self.fresh_node(slug, REV_A)
        self.post_ticket(slug)
        self.complete_fresh(slug)
        self.prove(slug)
        out = self.reopen()
        self.assertNotIn(slug, out["reopened"])
        reasons = out["held"][slug]
        self.assertTrue(any(r.startswith("offnode gate: ") for r in reasons), reasons)
        # The completion proofs alone do not open it: the streak and the
        # budget rules of node_auto_reopen_failures apply to this class too.
        self.assertEqual(self.node(slug)["operator_enabled"], 0)

    def test_the_full_readiness_gate_applies_to_this_class_item_by_item(self):
        # node_promotion_readiness_failures is the same function manual
        # promotion uses; the fresh_install class must be held by every item
        # of it, with the fresh rules stubbed so only the gate speaks.
        def spoil(sql):
            def apply(slug):
                with self.db() as conn:
                    conn.execute(sql.replace("{slug}", slug))
            return apply

        cases = [
            ("offline", spoil("UPDATE nodes SET status='offline' WHERE slug='{slug}'"),
             "node heartbeat is not online"),
            ("management", spoil("UPDATE nodes SET management_status='failed' WHERE slug='{slug}'"),
             "management verification is not ok"),
            ("transport", spoil("UPDATE nodes SET data_plane_udp_status='failed' WHERE slug='{slug}'"),
             "positive external data-plane proof is absent or stale"),
            ("cleanup", spoil("DELETE FROM node_closure_cleanup WHERE slug='{slug}'"),
             "closed-node runtime cleanup was never recorded"),
            ("gate", spoil("UPDATE node_offnode_gates SET used_at='2020-01-01T00:00:00' WHERE slug='{slug}'"),
             "offnode gate: "),
        ]
        for name, apply, expected in cases:
            with self.subTest(name):
                slug = f"rd-{name}"
                self.candidate(slug)
                apply(slug)
                with patch.object(self.mod, "fresh_install_reopen_failures", side_effect=lambda *a, **k: []):
                    out = self.reopen()
                self.assertNotIn(slug, out["reopened"], out)
                self.assertTrue(any(expected in reason for reason in out["held"].get(slug, [])),
                                (expected, out["held"].get(slug)))
                self.assertEqual(self.node(slug)["operator_enabled"], 0)

    def test_the_whole_gate_without_stubs_opens_the_node_once_everything_is_true(self):
        slug = "dk-whole"
        self.candidate(slug)
        now = self.mod.utcnow()
        closed_at = self.node(slug)["health_closed_at"]
        green_since = (now + timedelta(seconds=2)).isoformat()
        with self.db() as conn:
            conn.execute("UPDATE nodes SET status='online', last_heartbeat=?, data_plane_green_streak=1,"
                         " data_plane_green_since=? WHERE slug=?", (now.isoformat(), green_since, slug))
        # A winn/3 node needs a winn/3 node report, which the helper's gate
        # record is not: keep the carrier on winn/1 for the real readiness
        # gate and judge the fresh rules (stubbed here) in their own tests.
        with self.db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/1' WHERE slug=?", (slug,))
        with patch.object(self.mod, "fresh_install_reopen_failures", return_value=[]):
            out = self.reopen()
            self.assertIn(slug, out["held"], out)
            self.assertTrue(any("healthy proofs since authority recovery" in r for r in out["held"][slug]),
                            out["held"][slug])
            with self.db() as conn:
                conn.execute("UPDATE nodes SET data_plane_green_streak=9 WHERE slug=?", (slug,))
            self.assertIn(slug, self.reopen()["reopened"], closed_at)

    def test_the_gate_check_accepts_hub_sourced_gate_records_for_this_class(self):
        # The readiness gate must be told this closure may use a hub-run gate.
        slug = "dk-hubgate"
        self.candidate(slug)
        calls = []
        real = self.mod.node_promotion_readiness_failures

        def spy(conn, node, gate, allow_hub_gate=False):
            calls.append((dict(node)["health_closed_reason"], allow_hub_gate))
            return real(conn, node, gate, allow_hub_gate=allow_hub_gate)

        with patch.object(self.mod, "node_promotion_readiness_failures", side_effect=spy):
            self.reopen()
        self.assertEqual(calls[0], ("fresh_install", True))
        # And a health closure is still not allowed one.
        stale = "dk-health"
        self.live_node(stale)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=0, health_closed_at=?, "
                         "health_closed_reason='heartbeat_stale' WHERE slug=?",
                         (self.mod.utcnow().isoformat(), stale))
        calls.clear()
        with patch.object(self.mod, "NODE_AUTO_REOPEN_ENABLED", True), \
                patch.object(self.mod, "node_promotion_readiness_failures", side_effect=spy):
            self.reopen()
        self.assertIn(("heartbeat_stale", False), calls)

    def test_a_ticket_altered_after_completion_holds_the_flip_and_cannot_change_the_tier(self):
        for field, value in (("go_live", "manual"), ("tier", "premium")):
            with self.subTest(field):
                slug = "tk-" + field.replace("_", "-")
                body, _gate = self.candidate(slug, tier="free")
                self.alter_ticket(slug, body["nonce"], field, value)
                reasons = self.held(slug)
                self.assertTrue(any("go-live ticket: no verified go-live ticket (signer-ticket-signature-invalid)" in r
                                    for r in reasons), reasons)
                self.assertEqual(self.node(slug)["operator_enabled"], 0)
        # A column-only edit changes nothing: the verified bytes say free.
        slug = "tk-column"
        body, _gate = self.candidate(slug, tier="free")
        self.alter_ticket(slug, body["nonce"], "tier", "premium", column_only=True)
        self.assertEqual(self.flip()["reopened"], [slug])
        self.assertEqual(self.node(slug)["free_access_enabled"], 1)
        self.assertEqual(self.promotions(slug)[-1]["tier"], "free")

    def test_a_newer_manual_ticket_or_a_missing_ticket_holds_the_flip(self):
        slug = "tk-manual"
        self.candidate(slug)
        self.post_ticket(slug, action="reset", go_live="manual")
        self.assertHeld(slug, "go-live ticket: the go-live ticket carries go_live=manual")
        gone = "tk-gone"
        self.candidate(gone)
        with self.db() as conn:
            conn.execute("DELETE FROM winn3_signer_tickets WHERE slug=?", (gone,))
        self.assertHeld(gone, "go-live ticket: no verified go-live ticket (no-stored-ticket)")

    def test_an_expired_ticket_holds_the_flip(self):
        slug = "tk-expired"
        self.candidate(slug)
        body, env = self.ticket(slug, not_after=int(time.time()) - 5)
        self.insert_ticket(slug, body, env)  # the newest ticket has expired
        self.assertHeld(slug, "go-live ticket: no verified go-live ticket (signer-ticket-lifetime)")

    def test_the_operator_hold_is_checked_first_and_blocks_the_flip(self):
        slug = "hd"
        self.candidate(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET winn3_operator_hold=1 WHERE slug=?", (slug,))
        self.assertHeld(slug, "winn3 operator hold is active")
        with self.db() as conn:
            conn.execute("UPDATE nodes SET winn3_operator_hold=0 WHERE slug=?", (slug,))
        self.assertEqual(self.flip()["reopened"], [slug])

    def test_a_promotion_since_the_bootstrap_holds_a_fresh_install_closure(self):
        slug = "pr"
        self.candidate(slug)
        with self.db() as conn:
            conn.execute(
                "INSERT INTO node_promotion_events (promotion_id, slug, promoted_at, tier, evidence_sha256,"
                " operator_source_hash, node_status, management_status, data_plane_status, data_plane_ok_at)"
                " VALUES ('p-x', ?, ?, 'free', ?, 'abcdef0123456789', 'online', 'ok', 'ok', ?)",
                (slug, self.mod.utcnow().isoformat(), "e" * 64, self.mod.utcnow().isoformat()))
        self.assertHeld(slug, "the node has been live since its bootstrap; manual promotion required")

    def test_the_gate_builder_runs_last_and_only_when_nothing_else_fails(self):
        slug = "gb"
        self.candidate(slug)
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET used_at=?, used_for='x' WHERE slug=?",
                         (self.mod.utcnow().isoformat(), slug))
        ran = []
        # H6's hub_offnode_gate_attempt (H7-QUESTIONS (3)): ("", []) is a
        # check that recorded nothing and named no reason.
        with patch.object(self.mod, "hub_offnode_gate_attempt",
                          side_effect=lambda conn, node: ran.append(1) or ("", [])):
            reasons = self.held(slug)
            self.assertEqual(len(ran), 1)
            self.assertIn("offnode gate: the hub-run off-node gate produced no record; "
                          "an operator-posted gate record is required", reasons)
            # Anti-vacuity: any other failing condition keeps the builder from running.
            ran.clear()
            with self.db() as conn:
                conn.execute("UPDATE nodes SET winn3_operator_hold=1 WHERE slug=?", (slug,))
            self.held(slug)
            self.assertEqual(ran, [])

    def test_a_hub_recorded_gate_opens_the_node_and_a_moved_generation_does_not(self):
        slug = "gm"
        _body, gate = self.candidate(slug)
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET used_at=?, used_for='x' WHERE gate_sha256=?",
                         (self.mod.utcnow().isoformat(), gate))

        def builder_records(conn, node):
            conn.execute("UPDATE node_offnode_gates SET used_at=NULL, used_for=NULL WHERE gate_sha256=?", (gate,))
            return gate, []

        with patch.object(self.mod, "hub_offnode_gate_attempt", side_effect=builder_records):
            out = self.flip()
        self.assertEqual(out["reopened"], [slug], out)
        # The same again, but the generation moves while the gate builds.
        other = "gm2"
        _body, gate2 = self.candidate(other)
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET used_at=?, used_for='x' WHERE gate_sha256=?",
                         (self.mod.utcnow().isoformat(), gate2))

        def builder_moves(conn, node):
            conn.execute("UPDATE node_offnode_gates SET used_at=NULL, used_for=NULL WHERE gate_sha256=?", (gate2,))
            conn.execute("UPDATE nodes SET deployment_generation=deployment_generation+1 WHERE slug=?", (other,))
            return gate2, []

        with patch.object(self.mod, "hub_offnode_gate_attempt", side_effect=builder_moves):
            out = self.flip()
        self.assertNotIn(other, out["reopened"], out)
        self.assertEqual(out["held"][other], ["the deployment generation moved while the hub-run off-node gate ran"])
        self.assertEqual(self.node(other)["operator_enabled"], 0)

    def test_the_fresh_branch_carries_h6s_reasons_budget_and_stable_row_rule(self):
        # H7-QUESTIONS (3), wired at the H7 rebase: the fresh branch calls H6's
        # hub_offnode_gate_attempt under the same rules as the installer_rerun
        # branch. (a) A failed check holds the node with H6's own reasons.
        slug = "h6-reasons"
        _body, gate = self.candidate(slug)
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET used_at=?, used_for='x' WHERE gate_sha256=?",
                         (self.mod.utcnow().isoformat(), gate))
        with patch.object(self.mod, "hub_offnode_gate_attempt",
                          side_effect=lambda conn, node: ("", ["hub-run check: management SSH to the node failed"])):
            reasons = self.held(slug)
        self.assertIn("offnode gate: hub-run check: management SSH to the node failed", reasons)
        self.assertNotIn("offnode gate: the hub-run off-node gate produced no record; "
                         "an operator-posted gate record is required", reasons)
        # (b) The per-sweep check budget defers the check, with no SSH.
        ran = []
        with patch.object(self.mod, "HUB_OFFNODE_SWEEP_MAX_CHECKS", 0), \
                patch.object(self.mod, "hub_offnode_gate_attempt",
                             side_effect=lambda conn, node: ran.append(1) or (gate, [])):
            reasons = self.held(slug)
        self.assertEqual(ran, [])
        self.assertIn("hub-run off-node check deferred to the next sweep (per-sweep check limit)", reasons)
        # (c) A node whose stable fields moved while the check ran is held,
        # even with a recorded gate and the same generation.
        moved = "h6-moved"
        _body, gate2 = self.candidate(moved)
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET used_at=?, used_for='x' WHERE gate_sha256=?",
                         (self.mod.utcnow().isoformat(), gate2))

        def builder_moves_the_host(conn, node):
            conn.execute("UPDATE node_offnode_gates SET used_at=NULL, used_for=NULL WHERE gate_sha256=?", (gate2,))
            conn.execute("UPDATE nodes SET ssh_host='203.0.113.77' WHERE slug=?", (moved,))
            return gate2, []

        with patch.object(self.mod, "hub_offnode_gate_attempt", side_effect=builder_moves_the_host):
            out = self.flip()
        self.assertNotIn(moved, out["reopened"], out)
        self.assertEqual(out["held"][moved], ["offnode gate: node changed while the hub-run check ran (ssh_host)"])
        self.assertEqual(self.node(moved)["operator_enabled"], 0)

    def test_a_usable_hub_record_stops_the_fresh_branch_builder(self):
        # H6's record rule, the other half (design 3.16, "no unused gate
        # record exists"): an unused hub record that still verifies is a
        # usable record, so the fresh branch spends no new hub-run check on
        # the node and opens it on that record.
        slug = "h6-usable-hub"
        self.fresh_node(slug, "sha256:" + DIGEST_A)
        self.post_ticket(slug)
        self.assertTrue(self.complete_fresh(slug, DIGEST_A)["auto_golive_pending"])
        gate = self.offnode_gate_v3(slug)
        self.prove(slug)
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET source='hub' WHERE gate_sha256=?", (gate,))
            self.assertFalse(self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True))
        ran = []
        with patch.object(self.mod, "hub_offnode_gate_attempt",
                          side_effect=lambda conn, node: ran.append(dict(node)["slug"]) or ("", ["hub-run check: x"])):
            out = self.flip()
        self.assertEqual(ran, [], out)
        self.assertEqual(out["reopened"], [slug], out)

    def test_a_stale_hub_record_is_rebuilt_and_an_operator_record_is_never_replaced(self):
        # H6's rule on the fresh branch: an unused hub record that no longer
        # verifies counts as absent, so the hub builds again; an operator
        # record is never replaced by a hub-run check.
        for source, builds in (("hub", 1), ("operator", 0)):
            with self.subTest(source):
                slug = f"h6-stale-{source}"
                _body, gate = self.candidate(slug)
                with self.db() as conn:
                    conn.execute("UPDATE node_offnode_gates SET source=?, node_report_sha256=? WHERE gate_sha256=?",
                                 (source, "0" * 64, gate))
                    self.assertTrue(self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True))
                ran = []
                with patch.object(self.mod, "hub_offnode_gate_attempt",
                                  side_effect=lambda conn, node: ran.append(dict(node)["slug"]) or ("", ["hub-run check: x"])):
                    out = self.flip()
                # Counted per slug: the earlier subtest's slug is still held and
                # is checked again in the same sweep.
                self.assertEqual(ran.count(slug), builds, out)
                if builds:
                    self.assertIn("offnode gate: hub-run check: x", out["held"][slug])
                    self.assertEqual(self.node(slug)["operator_enabled"], 0)

    def test_the_window_expires_into_an_operator_closure_with_one_alert(self):
        slug = "wx"
        self.candidate(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_completed_at=? WHERE slug=?",
                         ((self.mod.utcnow() - timedelta(hours=7)).isoformat(), slug))
        self.alerts.clear()
        out = self.flip()
        self.assertEqual(out["fresh_install_expired"], [slug], out)
        row = self.node(slug)
        self.assertIsNone(row["health_closed_at"])
        self.assertIsNone(row["health_closed_reason"])
        self.assertEqual(row["latch_cause"], "fresh_install_expired")
        self.assertEqual(row["operator_enabled"], 0)
        expired = [a for a in self.alerts if a[1].startswith("fresh install go-live window expired")]
        self.assertEqual([a[0] for a in expired], [2])
        self.flip()
        self.assertEqual(len([a for a in self.alerts if a[1].startswith("fresh install go-live window")]), 1)
        # A node HELD by a failing proof expires the same way: the first
        # window check runs before any proof decides (the check right before
        # the flip covers only nodes that pass).
        held = "wx-held"
        self.candidate(held)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_completed_at=?, winn3_operator_hold=1 WHERE slug=?",
                         ((self.mod.utcnow() - timedelta(hours=7)).isoformat(), held))
        out = self.flip()
        self.assertEqual(out["fresh_install_expired"], [held], out)
        self.assertEqual(self.node(held)["latch_cause"], "fresh_install_expired")

    def test_the_window_is_checked_again_right_before_the_flip(self):
        # Sol T1 item 3: the window can run out while the hub-run gate builds
        # (H6 runs it outside the write lock). Here the deadline passes during
        # the builder; every proof still passes afterwards, and the node must
        # become an operator closure with one level-2 alert, never go live.
        slug = "wx-builder"
        _body, gate = self.candidate(slug)
        with self.db() as conn:
            conn.execute("UPDATE node_offnode_gates SET used_at=?, used_for='x' WHERE gate_sha256=?",
                         (self.mod.utcnow().isoformat(), gate))
        real_expired = self.mod.installer_rerun_window_expired
        crossed = []

        def builder_crosses_the_deadline(conn, node):
            conn.execute("UPDATE node_offnode_gates SET used_at=NULL, used_for=NULL WHERE gate_sha256=?", (gate,))
            # The clock crossed the deadline while the check ran. H6 holds a
            # node whose deployment_completed_at moved during the check
            # (HUB_OFFNODE_GATE_STABLE_FIELDS), so the crossing is the window
            # rule's answer, not a moved row; the proofs stay fresh.
            crossed.append(1)
            return gate, []

        self.alerts.clear()
        with patch.object(self.mod, "hub_offnode_gate_attempt", side_effect=builder_crosses_the_deadline), \
                patch.object(self.mod, "installer_rerun_window_expired",
                             side_effect=lambda node: bool(crossed) or real_expired(node)):
            out = self.flip()
        self.assertNotIn(slug, out["reopened"], out)
        self.assertEqual(out["fresh_install_expired"], [slug], out)
        row = self.node(slug)
        self.assertEqual((row["operator_enabled"], row["health_closed_at"], row["health_closed_reason"],
                          row["latch_cause"]), (0, None, None, "fresh_install_expired"))
        self.assertEqual([p["operator_source_hash"] for p in self.promotions(slug)], [])
        expired = [a for a in self.alerts if a[1].startswith("fresh install go-live window expired")]
        self.assertEqual([(a[0], a[2]["last_failures"]) for a in expired],
                         [(2, ["the go-live window expired before the flip"])])
        with self.db() as conn:
            self.assertIsNone(conn.execute("SELECT used_at FROM node_offnode_gates WHERE gate_sha256=?",
                                           (gate,)).fetchone()[0], "the gate is not consumed")

    def test_the_switch_is_per_class_and_a_fresh_closure_is_never_a_health_closure(self):
        slug = "sw"
        self.candidate(slug)
        with patch.object(self.mod, "WINN3_FRESH_INSTALL_AUTO_GOLIVE", False):
            out = self.flip()
        self.assertEqual(out["reopened"], [], out)
        self.assertNotIn(slug, out["held"])
        self.assertEqual(self.node(slug)["health_closed_reason"], "fresh_install", "left exactly as it is")
        # With the health switch ON and the fresh switch OFF, the health path
        # must not judge (and open) it as a health closure.
        with patch.object(self.mod, "WINN3_FRESH_INSTALL_AUTO_GOLIVE", False), \
                patch.object(self.mod, "NODE_AUTO_REOPEN_ENABLED", True):
            out = self.flip()
        self.assertEqual(out["reopened"], [], out)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        # The health switch alone (fresh ON) does not alter the fresh rules.
        with patch.object(self.mod, "NODE_AUTO_REOPEN_ENABLED", True):
            self.assertEqual(self.flip()["reopened"], [slug])

    def test_the_daily_budget_is_shared_with_the_other_automatic_reopens(self):
        slug = "bd"
        self.candidate(slug)
        with self.db() as conn:
            for _ in range(self.mod.NODE_AUTO_REOPEN_MAX_PER_DAY):
                conn.execute("INSERT INTO node_latch_events (slug, changed_at, from_value, to_value, cause) "
                             "VALUES (?, ?, 0, 1, 'auto_golive_fresh_install')",
                             (slug, self.mod.utcnow().isoformat()))
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            failures = self.mod.node_auto_reopen_failures(conn, row, self.mod.utcnow().isoformat())
        self.assertTrue(any("automatic reopen used" in f for f in failures), failures)
        self.assertIn("auto_golive_fresh_install", self.mod.NODE_AUTO_REOPEN_CAUSES)
        self.assertIn("auto_reopen_installer_rerun", self.mod.NODE_AUTO_REOPEN_CAUSES)
        # Anti-vacuity: operator promotions do not count.
        with self.db() as conn:
            conn.execute("UPDATE node_latch_events SET cause='operator_promotion' WHERE slug=?", (slug,))
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            failures = self.mod.node_auto_reopen_failures(conn, row, self.mod.utcnow().isoformat())
        self.assertFalse(any("automatic reopen used" in f for f in failures), failures)

    def test_the_flip_is_open_node_evidence_for_the_audit(self):
        slug = "ev"
        self.candidate(slug)
        self.assertEqual(self.flip()["reopened"], [slug])
        with self.db() as conn:
            report = self.mod.open_nodes_without_promotion_evidence(conn)
        self.assertNotIn(slug, [item["slug"] for item in report])

    def test_installer_never_calls_the_tier_route(self):
        source = HUB_SOURCE
        # P2 (P-13) adds the only_slug parameter, so the split names the
        # function without its argument list.
        flip = source.split("def auto_reopen_health_closed_nodes(", 1)[1].split("\ndef drain_node_latch_events", 1)[0]
        self.assertNotIn("admin_set_node_tier", flip)


# ======================================== identity field and the transition ==

@quiet_inherited
class IdentityTransitionTests(H7Base):

    def test_the_rerun_identity_field_is_the_identity_digest_not_the_descriptor_hash(self):
        self.assertIn("winn3_identity_sha256", self.mod.NODE_RERUN_IDENTITY_FIELDS)
        self.assertNotIn("winn3_descriptor_sha256", self.mod.NODE_RERUN_IDENTITY_FIELDS)
        slug = "id-field"
        self.live_node(slug)
        self.stored_descriptor(slug, seq=1)
        row = self.node(slug)
        before = self.mod.node_deployment_prior_state(row, "t")["winn3_identity_sha256"]
        self.assertRegex(before, r"^[0-9a-f]{64}$")
        # A renewal re-signs only seq, iat and not_after: the identity digest is
        # unchanged although the stored bytes differ.
        self.stored_descriptor(slug, seq=2)
        after = self.mod.node_deployment_prior_state(self.node(slug), "t")["winn3_identity_sha256"]
        self.assertEqual(before, after)
        # A changed static key is an identity change.
        self.stored_descriptor(slug, seq=3, static=b"T")
        changed = self.mod.node_deployment_prior_state(self.node(slug), "t")["winn3_identity_sha256"]
        self.assertNotEqual(before, changed)
        # No stored descriptor: "".
        with self.db() as conn:
            conn.execute("UPDATE nodes SET winn3_descriptor_json=NULL WHERE slug=?", (slug,))
        self.assertEqual(self.mod.node_deployment_prior_state(self.node(slug), "t")["winn3_identity_sha256"], "")

    def test_the_digest_matches_the_signers_own_definition(self):
        # The hub's digest and the signer program's identity_sha256 are two
        # copies of one definition (design 3.17); a drift between them would
        # make every adoption read as a change.
        import pathlib
        signer = h1.load_signer(pathlib.Path(tempfile.mkdtemp(prefix="winshub-h7-signer-")))
        for secret in ("a" * 64, "b" * 64):
            payload = desc.descriptor_payload(node="id-sig", seq=4)
            payload["admission_secret"] = base64.b64encode(secret.encode()).decode()
            payload["auth_ed25519"] = base64.b64encode(b"E" * 32).decode()
            payload["auth_mldsa65"] = base64.b64encode(b"M" * 1952).decode()
            hub = self.mod.winn3_identity_digest(payload)
            self.assertRegex(hub, r"^[0-9a-f]{64}$")
            self.assertEqual(hub, signer.identity_sha256(payload))
        # The secret changes the digest only through its fingerprint, and a
        # renewal's seq, iat and not_after change nothing.
        base = desc.descriptor_payload(node="id-sig", seq=4)
        renewed = dict(base, seq=9, iat=base["iat"] + 100, not_after=base["not_after"] + 100)
        self.assertEqual(self.mod.winn3_identity_digest(base), self.mod.winn3_identity_digest(renewed))
        self.assertNotEqual(self.mod.winn3_identity_digest(base),
                            self.mod.winn3_identity_digest(dict(base, endpoint="203.0.113.99:9111")))

    def test_an_adoption_that_keeps_its_identity_compares_equal_and_reopens(self):
        slug = "id-adopt"
        self.live_node(slug)
        self.stored_descriptor(slug, seq=1)
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        # The pulled identity and the g1 descriptor carry the same fields; the
        # renewal that follows has a higher seq and the identity still matches.
        self.stored_descriptor(slug, seq=2)
        self.offnode_gate(slug)
        with patch.object(self.mod, "node_auto_reopen_failures", return_value=[]), \
                patch.object(self.mod, "installer_rerun_carry_failures", return_value=[]):
            out = self.reopen()
        self.assertEqual(out["reopened"], [slug], out)

    def test_the_first_v3_transition_is_accepted_only_as_recorded(self):
        slug = "id-first"
        self.live_node(slug)
        self.post_ticket(slug, action="new", go_live="auto")
        out = self.rerun(slug)
        self.assertTrue(out["auto_reopen_pending"], out)
        # The job flips the carrier after the completion: a stored g1
        # descriptor, winn/3, and the recorded transition at this generation.
        self.stored_descriptor(slug, seq=1)
        digest = self.mod.node_winn3_identity_sha256(self.node(slug))
        generation = self.node(slug)["deployment_generation"]
        flipped = {"protocol_version": "winn/3", "carrier_classes": "udp", "path_mtu": 1450}
        with self.db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/3', carrier_classes='udp', path_mtu=1450 "
                         "WHERE slug=?", (slug,))

        def record(**overrides):
            transition = dict(flipped, generation=generation, winn3_identity_sha256=digest)
            transition.update(overrides)
            with self.db() as conn:
                conn.execute("UPDATE nodes SET winn3_expected_transition_json=? WHERE slug=?",
                             (json.dumps(transition, sort_keys=True), slug))

        def reasons():
            with self.db() as conn:
                row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
                return self.mod.installer_rerun_reopen_eligibility(
                    conn, row, self.mod.node_deployment_prior(row))[0]

        # No transition recorded: every changed field is named.
        names = sorted(r.removeprefix("identity changed: ") for r in reasons() if r.startswith("identity changed"))
        self.assertEqual(names, ["carrier_classes", "path_mtu", "protocol_version", "winn3_identity_sha256"])
        record()
        self.assertEqual(reasons(), [])
        # Recorded under another generation.
        record(generation=generation + 1)
        self.assertEqual(len([r for r in reasons() if r.startswith("identity changed")]), 4)
        # A recorded value that is not the current one.
        record(path_mtu=1400)
        self.assertEqual(len([r for r in reasons() if r.startswith("identity changed")]), 4)
        record(winn3_identity_sha256="e" * 64)
        self.assertEqual(len([r for r in reasons() if r.startswith("identity changed")]), 4)
        record()
        self.assertEqual(reasons(), [])
        # A difference in any other field still holds the node with its name.
        original_endpoint = self.node(slug)["endpoint"]
        with self.db() as conn:
            conn.execute("UPDATE nodes SET endpoint='198.51.100.250:9110' WHERE slug=?", (slug,))
        self.assertEqual(reasons(), ["identity changed: endpoint"])
        with self.db() as conn:
            conn.execute("UPDATE nodes SET endpoint=? WHERE slug=?", (original_endpoint, slug))
        # A malformed or extended record is no record.
        with self.db() as conn:
            conn.execute("UPDATE nodes SET winn3_expected_transition_json=? WHERE slug=?",
                         (json.dumps({"generation": generation, "surprise": 1}), slug))
        self.assertEqual(len([r for r in reasons() if r.startswith("identity changed")]), 4)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET winn3_expected_transition_json='not json' WHERE slug=?", (slug,))
        self.assertEqual(len([r for r in reasons() if r.startswith("identity changed")]), 4)

    def test_a_first_identity_needs_a_verified_new_or_reset_ticket(self):
        slug = "id-ticket"
        self.live_node(slug)
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        self.stored_descriptor(slug, seq=1)
        digest = self.mod.node_winn3_identity_sha256(self.node(slug))
        generation = self.node(slug)["deployment_generation"]
        transition = {"protocol_version": "winn/3", "carrier_classes": "udp", "path_mtu": 1450,
                      "generation": generation, "winn3_identity_sha256": digest}
        with self.db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/3', carrier_classes='udp', path_mtu=1450,"
                         " winn3_expected_transition_json=? WHERE slug=?",
                         (json.dumps(transition, sort_keys=True), slug))

        def named():
            with self.db() as conn:
                row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
                return [r for r in self.mod.installer_rerun_reopen_eligibility(
                    conn, row, self.mod.node_deployment_prior(row))[0] if r.startswith("identity changed")]

        # No ticket: the carrier fields are accepted, the first identity is not.
        self.assertEqual(named(), ["identity changed: winn3_identity_sha256"])
        # A rekey ticket is not the first identity's authority.
        self.post_ticket(slug, action="rekey")
        self.assertEqual(named(), ["identity changed: winn3_identity_sha256"])
        # A new ticket is.
        self.post_ticket(slug, action="new")
        self.assertEqual(named(), [])

    def test_a_change_of_an_existing_identity_is_never_accepted_as_the_first_transition(self):
        slug = "id-rekey"
        self.live_node(slug)
        self.stored_descriptor(slug, seq=1)
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        self.post_ticket(slug, action="new")
        self.stored_descriptor(slug, seq=2, static=b"T")
        digest = self.mod.node_winn3_identity_sha256(self.node(slug))
        generation = self.node(slug)["deployment_generation"]
        with self.db() as conn:
            conn.execute("UPDATE nodes SET winn3_expected_transition_json=? WHERE slug=?",
                         (json.dumps({"protocol_version": self.node(slug)["protocol_version"],
                                      "carrier_classes": self.node(slug)["carrier_classes"],
                                      "path_mtu": self.node(slug)["path_mtu"],
                                      "generation": generation, "winn3_identity_sha256": digest},
                                     sort_keys=True), slug))
        with self.db() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            reasons = self.mod.installer_rerun_reopen_eligibility(conn, row, self.mod.node_deployment_prior(row))[0]
        self.assertIn("identity changed: winn3_identity_sha256", reasons)


# ============================================== manual revision evidence ==

@quiet_inherited
class ManualEvidenceTests(H7Base):

    def evidence_row(self, slug, source, revision, tier="premium"):
        with self.db() as conn:
            conn.execute(
                "INSERT INTO node_promotion_events (promotion_id, slug, promoted_at, tier, evidence_sha256,"
                " operator_source_hash, node_status, management_status, data_plane_status, data_plane_ok_at,"
                " data_plane_code_revision) VALUES (?, ?, ?, ?, ?, ?, 'online', 'ok', 'ok', ?, ?)",
                (self.next_nonce(slug, source)[:32], slug, self.mod.utcnow().isoformat(), tier, "d" * 64,
                 source, self.mod.utcnow().isoformat(), revision))

    def eligible_for(self, revision):
        slug = f"ev-{revision[-4:]}-{self.serial}"
        self.serial += 1
        self.live_node(slug, REV_A)
        with self.db() as conn:  # the revision under test is the one the rerun lands
            conn.execute("DELETE FROM nodes WHERE slug='none'")
        out = self.rerun(slug, revision)
        return out["auto_reopen_pending"]

    def test_only_a_sixteen_hex_row_evidences_a_revision(self):
        rev = "sha256:" + "9" * 64
        self.live_node("ev-holder", REV_A)
        cases = [
            ("auto_reopen_installer_rerun", False),
            ("auto_golive_fresh_install", False),
            ("abcdef0123456789", True),
            ("ABCDEF0123456789", False),
            ("abcdef012345678", False),
            ("abcdef01234567890", False),
            ("abcdef012345678g", False),
            ("", False),
        ]
        for source, evidences in cases:
            with self.subTest(source=source):
                revision = "sha256:" + hashlib.sha256(source.encode()).hexdigest()
                self.evidence_row("ev-holder", source, revision)
                self.assertEqual(self.eligible_for(revision), evidences)

    def test_the_automatic_markers_never_match_the_manual_pattern(self):
        pattern = re.compile(r"[0-9a-f]{16}")
        for name in self.mod.AUTOMATIC_PROMOTION_SOURCES:
            self.assertIsNone(pattern.fullmatch(name), name)
        self.assertEqual(set(self.mod.AUTOMATIC_PROMOTION_SOURCES),
                         {"auto_reopen_installer_rerun", "auto_golive_fresh_install"})
        # A real manual promotion writes security_event_hash, which matches.
        self.assertRegex(self.mod.security_event_hash("203.0.113.5"), r"^[0-9a-f]{16}$")
        # The automatic writer uses the constant, so the two cannot drift.
        self.assertEqual(self.mod.MANUAL_PROMOTION_SOURCE_GLOB, "[0-9a-f]" * 16)


# ============================================================ installer ==

class InstallerWiringTests(unittest.TestCase):
    SOURCE = fx2.HUB_INSTALLER.read_text(encoding="utf-8")

    def test_the_installer_writes_defaults_and_validates_the_switch(self):
        self.assertIn('WINN3_FRESH_INSTALL_AUTO_GOLIVE_DEFAULT="${WINN3_FRESH_INSTALL_AUTO_GOLIVE:-1}"', self.SOURCE)
        body = self.SOURCE.split("\nwrite_env() {", 1)[1]
        self.assertIn('write_env_kv WINN3_FRESH_INSTALL_AUTO_GOLIVE "${fresh_golive}"', body)
        self.assertIn('[[ "${fresh_golive}" =~ ^[01]$ ]] || { err "WINN3_FRESH_INSTALL_AUTO_GOLIVE must be 0 or 1."; exit 1; }', body)
        # The hub app reads exactly that name, defaulting to on like the
        # installer, and per-node authority still comes from the ticket.
        self.assertIn('os.getenv("WINN3_FRESH_INSTALL_AUTO_GOLIVE", "1")', self.SOURCE)

    def test_the_validation_line_really_refuses_other_values(self):
        import subprocess
        line = next(l for l in self.SOURCE.splitlines() if 'WINN3_FRESH_INSTALL_AUTO_GOLIVE must be 0 or 1' in l).strip()
        bash = os.path.expanduser("~/.homebrew/Homebrew/bin/bash")
        for value, expected in (("0", 0), ("1", 0), ("2", 7), ("", 7), ("yes", 7), ("11", 7)):
            script = ('err() { echo "$*" >&2; }\nfresh_golive="$1"\n(' + line + ') ; echo $?')
            run = subprocess.run([bash, "-c", script, "x", value], capture_output=True, text=True)
            code = int(run.stdout.strip().splitlines()[-1])
            self.assertEqual(code == 0, expected == 0, (value, run.stdout, run.stderr))

    def test_no_dashes_in_the_new_text(self):
        for path in (fx2.HERE / "test_hub_h7_fresh_install_golive.py",):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(chr(0x2014), text)
            self.assertNotIn(chr(0x2013), text)


class HubSourceGuardTests(unittest.TestCase):
    """H7-QUESTIONS (1), unanimous in Turn 1: H4's winn3_signer_tickets is the
    single ticket store. H7 reads it as is, and the provisional column
    nodes.winn3_signer_ticket_json (no writer anywhere) must not survive
    integration: H2 moves its reads to the same table. This guard turns red
    if that column is declared or written in the integrated hub."""

    # The property, not the name (Claude T2): no nodes column of that name is
    # declared or written. The name itself may stay as a SELECT alias over
    # winn3_signer_tickets (Claude's T1 Q1 patch, WINN3_JOB_ROW_SQL), which H2's
    # request builder and identity check keep reading from the row.
    TICKET_COLUMN_DECLARED = re.compile(
        r'"nodes",\s*"winn3_signer_ticket_json"|\bwinn3_signer_ticket_json\s+TEXT\b')
    TICKET_COLUMN_WRITTEN = re.compile(
        r'\bwinn3_signer_ticket_json\s*=\s*\?'
        r'|INSERT\s+(?:OR\s+\w+\s+)?INTO\s+nodes\s*\([^)]*\bwinn3_signer_ticket_json\b')

    def test_the_go_live_authority_reads_only_the_single_ticket_store(self):
        self.assertEqual(self.TICKET_COLUMN_DECLARED.findall(HUB_SOURCE), [])
        self.assertEqual(self.TICKET_COLUMN_WRITTEN.findall(HUB_SOURCE), [])
        # Anti-vacuity: each pattern sees the form it forbids, and neither
        # sees the alias or a read of it.
        self.assertTrue(self.TICKET_COLUMN_DECLARED.search(
            'add_column_if_missing(conn, "nodes", "winn3_signer_ticket_json", "TEXT")'))
        self.assertTrue(self.TICKET_COLUMN_WRITTEN.search(
            '"UPDATE nodes SET winn3_signer_ticket_json=? WHERE slug=?"'))
        for allowed in ('"ORDER BY t.posted_at DESC, t.nonce DESC LIMIT 1) AS winn3_signer_ticket_json "',
                        'ticket = json.loads(_node_field(node, "winn3_signer_ticket_json") or "")'):
            self.assertIsNone(self.TICKET_COLUMN_DECLARED.search(allowed))
            self.assertIsNone(self.TICKET_COLUMN_WRITTEN.search(allowed))
        body = HUB_SOURCE.split("def winn3_golive_ticket(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("FROM winn3_signer_tickets WHERE slug = ?", body)

    def test_the_hub_declares_the_carrier_flip_time_it_reads(self):
        # Sol T1 item 1: the boundary column is the hub's own (setUp adds it
        # only to run this file against an older tree).
        self.assertIn('add_column_if_missing(conn, "nodes", "winn3_carrier_flipped_at", "TEXT")', HUB_SOURCE)


# ============== hub-lite FINDINGS HL-F2 and HL-F3 (705bedd), design 3.17 ==

def quiet_every_inherited(cls):
    """Only this file's tests run on a class built on another suite's harness."""
    for base in cls.__mro__[1:]:
        for name in vars(base):
            if name.startswith("test") and name not in cls.__dict__:
                setattr(cls, name, None)
    return cls


@quiet_every_inherited
class RecoveryHostTests(fx2.RegistryGroupAbsentTests):
    """HL-F2: a recovery node that is not winn/3 (a released node before its
    flip, whose registry the hub has published) is read back at its registered
    host like every other recovery node, and that read counts. The Round O
    fleet runs the hub's real publication and read-back commands; every node of
    the fixture is registered at 127.0.0.1, and V1 is winn/1."""

    unattempted = frozenset()

    def patched(self, mod):
        """The fleet hands observe_winn3_node 127.0.0.1 for every simulated
        machine. For a winn/3 slug the real function records its read at the
        registered host anyway (winn3_node_hosts); for a slug that is not
        winn/3 it records it at the host addressed, which the fleet would turn
        into 127.0.0.1. Name that host as the gateway, as the real call does.
        Every node registered at 127.0.0.1 behaves exactly as before."""
        patches = super().patched(mod)
        index = next(i for i, item in enumerate(patches)
                     if getattr(item, "attribute", "") == "observe_winn3_node")
        fleet_observe = patches[index].kwargs["side_effect"]

        def observe(node_ip, slug, gateway=None):
            if (slug, gateway) in self.unattempted:
                return False   # never reached, as a pair past the per-pass limit
            if gateway is None:
                with mod.get_db() as conn:
                    gateway = mod.winn3_node_hosts(conn).get(str(slug).strip().lower()) or node_ip
            return fleet_observe(node_ip, slug, gateway=gateway)

        patches[index] = patch.object(mod, "observe_winn3_node", side_effect=observe)
        return patches

    def view(self):
        with self.mod.get_db() as conn:
            return self.mod.winn3_recovery_state(conn, self.clock.now)

    def settle(self):
        self.reconcile()
        self.tick(fx2.roundo.REFRESH + 0.01)
        self.reconcile()
        return self.view()

    def test_hl_f2_a_released_node_not_yet_winn3_is_read_back_and_trusts_the_budget(self):
        self.resync(self.V1)               # the hub published V1's registry before its flip
        self.assertEqual(self.ledger_rows(self.V1)[-1], ("confirmed", ""))
        self.assertEqual(self.node_protocol(self.V1), "winn/1")
        view = self.settle()               # recovery entered, every recovery node read back
        self.assertIn(self.V1, self.recovery_set())
        self.assertTrue(view["paired"] and view["complete"], view)
        self.assertTrue(view["budget_trusted"], "the journal read of a winn/1 recovery node must count, "
                        "not hold budget trust for the whole departure window")
        with self.mod.get_db() as conn:
            self.assertEqual(self.mod.winn3_recovery_hosts(conn).get(self.V1), "127.0.0.1")
            self.assertNotIn(self.V1, self.mod.winn3_node_hosts(conn), "retired gateways keep the winn/3 map")
        # Anti-vacuity: without the read-back the same node keeps trust down.
        with self.mod.winn3_authority_ledger() as ledger:
            ledger.execute("DELETE FROM winn3_journal_reads WHERE node_slug=?", (self.V1,))
            ledger.commit()
        self.assertFalse(self.view()["budget_trusted"])

    def test_hl_f2_a_node_first_published_after_the_entry_is_recovered_without_a_flip(self):
        view = self.settle()
        self.assertTrue(view["complete"] and view["budget_trusted"], view)
        self.assertNotIn(self.V1, self.recovery_set())
        self.resync(self.V1)               # first named by the ledger after this process's entry
        self.assertIn(self.V1, self.recovery_set())
        view = self.settle()
        self.assertEqual(self.node_protocol(self.V1), "winn/1")
        self.assertTrue(view["complete"], view)
        self.assertTrue(view["budget_trusted"], view)

    def test_f4_hl_a_moved_slug_that_is_not_winn3_keeps_its_old_machine_a_charge_source(self):
        """FINAL4 F4-HL (Astra, Turn 2; the Claude seat's Turn 1 note): Round
        O's moved-slug charge test (test_moved_slug_old_gateway_stays_a_charge_
        history_source) with the moved slug no longer winn/3. Gamma's old
        machine journaled three charges, then gamma was rolled back to winn/1,
        moved to another host, and an earlier ledger was restored. Reading the
        new machine's empty journal must not trust the budget: the old
        machine's own read does, or the departure window. On FINAL4 tree.t2
        the budget was trusted once the new host alone was read, and the
        switch to delta was admitted with a seventh departure allowance in the
        hour (the budget is 6)."""
        old = "127.0.0.1"
        self.connected_at("lab-beta")
        earlier = self.snapshot_ledger()
        for slug in ["lab-gamma", "lab-beta"] * 3:
            self.verify(slug)
            self.tick(10)
        self.assertEqual(self.charges(), 6)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/1', winn3_descriptor_json=NULL "
                         "WHERE slug='lab-gamma'")
        self.move_slug("lab-gamma")
        self.restore_ledger(earlier)
        self.fleet.mode["lab-gamma"] = "down"   # the old machine; the new one answers
        self.reconcile()
        self.tick(fx2.roundo.REFRESH + 0.01)
        self.reconcile()
        self.tick(fx2.roundo.REFRESH + 0.01)
        with self.mod.winn3_authority_ledger() as ledger:
            since = float(self.mod.winn3_ledger_meta(ledger)["recovery_since"])
            reads = {tuple(row) for row in ledger.execute(
                "SELECT node_slug, gateway FROM winn3_journal_reads WHERE recovery_since=?", (since,))}
        self.assertIn(("lab-gamma", self.MOVED_HOST), reads, "the new machine was read back")
        self.assertNotIn(("lab-gamma", old), reads)
        self.assertEqual(self.node_protocol("lab-gamma"), "winn/1")
        self.assertIn("lab-gamma", self.recovery_set())
        self.assertEqual(self.charges(), 3, "only beta's journal has been read")
        view = self.view()
        self.assertFalse(view["budget_trusted"], "the old machine's journal is unread")
        self.assertEqual(view["budget_trusted_after"], since + self.mod.WINN3_DEPARTURE_LEDGER_SECONDS)
        self.assertIn(("lab-gamma", old), view["retired_pending"])
        caught = self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_budget")
        self.assertLessEqual(int(caught.headers["Retry-After"]), 60, "untrusted, not exhausted")
        # The old machine, read back at its own host, restores trust at once.
        self.fleet.mode.clear()
        self.reconcile()
        self.tick(fx2.roundo.REFRESH + 0.01)
        self.assertEqual(self.charges(), 6, "the old machine's journal was not read")
        view = self.view()
        self.assertTrue(view["budget_trusted"], view)
        self.assertNotIn(("lab-gamma", old), view["retired_pending"])
        caught = self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_budget")
        self.assertGreater(int(caught.headers["Retry-After"]), 60, "exhausted, not merely untrusted")

    def roll_back_and_move_gamma(self):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/1', winn3_descriptor_json=NULL "
                         "WHERE slug='lab-gamma'")
        self.move_slug("lab-gamma")
        self.fleet.mode["lab-gamma"] = "down"   # the old machine; the new one answers

    def restart_and_read_back(self):
        self.mod = self.load(DATABASE_PATH=self.mod._DB)
        states = [self.reconcile()["recovery"]]
        self.tick(fx2.roundo.REFRESH + 0.01)
        states += [self.reconcile()["recovery"], self.reconcile()["recovery"]]
        self.assertEqual(states[0], "entered")
        self.assertEqual(states[-1], "normal", "authority recovery completes without the old machine")
        with self.mod.winn3_authority_ledger() as ledger:
            return float(self.mod.winn3_ledger_meta(ledger)["recovery_since"])

    def old_rows(self):
        with self.mod.winn3_authority_ledger() as ledger:
            return ledger.execute("SELECT COUNT(*) FROM winn3_publications WHERE node_slug='lab-gamma' "
                                  "AND gateway='127.0.0.1'").fetchone()[0]

    def test_f4_hl_a_hub_start_after_a_move_inside_the_window_reads_the_old_machine(self):
        """FINAL4 F4-HL, the Claude seat's case (Turn 1 HL-F2 note, Turn 2 note
        1): a slug that is not winn/3 moved gateways inside the departure
        window, then the hub restarted. The budget is trusted once the old
        machine's journal is read back at its own host; while it cannot be
        read, only after the window since the entry. On FINAL4 tree.t2 the new
        host's read alone trusted it."""
        self.connected_at("lab-beta")
        for slug in ["lab-gamma", "lab-beta"] * 2:
            self.verify(slug)
            self.tick(10)
        self.roll_back_and_move_gamma()
        since = self.restart_and_read_back()
        view = self.view()
        self.assertFalse(view["budget_trusted"], view)
        self.assertEqual(view["budget_trusted_after"], since + self.mod.WINN3_DEPARTURE_LEDGER_SECONDS)
        self.assertEqual(view["retired_pending"], {("lab-gamma", "127.0.0.1")})
        caught = self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_budget")
        self.assertLessEqual(int(caught.headers["Retry-After"]), 60)
        self.fleet.mode.clear()
        self.reconcile()
        self.tick(fx2.roundo.REFRESH + 0.01)
        view = self.view()
        self.assertTrue(view["budget_trusted"], view)
        self.assertEqual(view["retired_pending"], set())
        self.verify("lab-delta")               # four of six charges in the hour: admitted
        self.assertEqual(self.device()["location_slug"], "lab-delta")

    def test_f4_hl_an_unreachable_old_machine_stops_holding_the_budget_once_settled_and_aged_out(self):
        """The bound on that wait (the Claude seat's Turn 2 note 1), kept
        restore-safe. Gamma's old machine never answers again. The first hub
        start waits the window since its entry. Once that window has passed and
        the old machine's record (failed read-backs included) is older than
        the window plus retention, authorizing nothing, it is forgotten like a
        winn/3 slug's retired gateway, and the next hub start trusts the budget
        as soon as the other journals are read."""
        self.connected_at("lab-beta")
        self.roll_back_and_move_gamma()
        since = self.restart_and_read_back()
        view = self.view()
        self.assertFalse(view["budget_trusted"], view)
        self.assertEqual(view["budget_trusted_after"], since + self.mod.WINN3_DEPARTURE_LEDGER_SECONDS)
        self.tick(self.mod.WINN3_DEPARTURE_LEDGER_SECONDS + fx2.roundo.RETENTION + 10)
        self.assertTrue(self.view()["budget_trusted"], "the window since the entry has passed")
        self.assertEqual(self.reconcile()["recovery"], "normal")
        self.assertEqual(self.old_rows(), 0, "settled by the window and aged out: forgotten")
        self.restart_and_read_back()
        view = self.view()
        self.assertTrue(view["budget_trusted"], "a forgotten old machine held the budget again")
        self.assertEqual(view["retired_pending"], set())

    def test_f4_hl_a_record_that_only_looks_old_is_not_forgotten_before_its_charges_are_settled(self):
        """The bound must not trust the record's age alone: after a restore the
        record may understate the old machine's last use. Gamma's old machine
        is never even attempted (as a pair past the per-pass limit), so no
        failed read-back refreshes its record, which is older than the window
        plus retention. It is kept, and keeps the budget untrusted, until a
        read or the window since this recovery's entry settles it."""
        self.connected_at("lab-beta")
        self.roll_back_and_move_gamma()
        self.unattempted = {("lab-gamma", "127.0.0.1")}
        self.tick(self.mod.WINN3_DEPARTURE_LEDGER_SECONDS + fx2.roundo.RETENTION + 10)
        since = self.restart_and_read_back()
        self.assertGreater(self.old_rows(), 0, "forgotten before its charges were settled")
        view = self.view()
        self.assertFalse(view["budget_trusted"], view)
        self.assertEqual(view["budget_trusted_after"], since + self.mod.WINN3_DEPARTURE_LEDGER_SECONDS)
        self.tick(self.mod.WINN3_DEPARTURE_LEDGER_SECONDS - 60)
        self.assertEqual(self.reconcile()["recovery"], "normal")
        self.assertGreater(self.old_rows(), 0)
        self.tick(61)
        self.assertEqual(self.reconcile()["recovery"], "normal")
        self.assertEqual(self.old_rows(), 0, "settled by the window: forgotten")

    def node_protocol(self, slug):
        with self.mod.get_db() as conn:
            return conn.execute("SELECT protocol_version FROM nodes WHERE slug=?", (slug,)).fetchone()[0]


@quiet_inherited
class StreakAfterClosureTests(H7Base):
    """HL-F3: the reopen gate counts only a healthy-proof streak that began
    after the closure (node_auto_reopen_failures). Every write that records a
    fresh_install closure, and a re-bootstrap, ends the streak in the same
    UPDATE; the REAL prober (wins_node_dataplane_probe.py apply_verdicts) then
    starts a new one on its next green run."""

    REASON = "no healthy-proof streak that began after the closure"

    def green(self, slug, runs=1):
        probe = dark.load_real_dataplane_probe()
        for _ in range(runs):
            time.sleep(0.002)
            with self.db() as conn:
                probe["apply_verdicts"](conn, slug, ("reachable", "recorded"), ("unconfigured", "not configured"),
                                        ("unconfigured", "not configured"))

    def streak(self, slug):
        row = self.node(slug)
        return row["data_plane_green_streak"], row["data_plane_green_since"]

    def held_by_the_streak(self, slug):
        with self.db() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            return self.REASON in self.mod.node_auto_reopen_failures(conn, row, self.mod.utcnow().isoformat())

    def assert_new_streak_counts(self, slug):
        self.assertEqual(self.streak(slug), (0, None), "the closure ended the earlier streak")
        self.assertTrue(self.held_by_the_streak(slug), "nothing is proven after the closure yet")
        self.green(slug)
        row = self.node(slug)
        self.assertEqual(row["data_plane_green_streak"], 1)
        self.assertGreater(row["data_plane_green_since"], row["health_closed_at"])
        self.assertFalse(self.held_by_the_streak(slug))

    def test_hl_f3_complete_fresh_ends_a_streak_that_began_before_the_closure(self):
        slug = "st-fresh"
        self.fresh_node(slug, "sha256:" + DIGEST_A)
        self.green(slug, 3)                # the prober saw the node healthy before completion
        self.assertEqual(self.streak(slug)[0], 3)
        self.post_ticket(slug)
        self.assertTrue(self.complete_fresh(slug)["auto_golive_pending"])
        self.assert_new_streak_counts(slug)

    def test_hl_f3_a_manual_fresh_completion_leaves_the_streak(self):
        # Only the automatic closure is judged by the reopen gate.
        slug = "st-manual"
        self.fresh_node(slug, "sha256:" + DIGEST_A)
        self.green(slug, 2)
        self.post_ticket(slug, go_live="manual")
        self.assertFalse(self.complete_fresh(slug)["auto_golive_pending"])
        self.assertEqual(self.streak(slug)[0], 2)

    def test_hl_f3_a_never_live_rerun_closure_ends_the_streak(self):
        slug = "st-rerun"
        self.fresh_node(slug, REV_A)
        self.post_ticket(slug)
        self.green(slug, 3)
        out = self.rerun(slug, REV_A)
        self.assertTrue(out["auto_golive_pending"], out)
        self.assertEqual(self.node(slug)["health_closed_reason"], "fresh_install")
        self.assert_new_streak_counts(slug)

    def test_hl_f3_a_rebootstrap_through_the_real_route_ends_the_old_machines_streak(self):
        slug = "st-boot"
        self.fresh_node(slug, "sha256:" + DIGEST_A)
        self.green(slug, 4)
        self.assertEqual(self.streak(slug)[0], 4)
        with self.db() as conn:
            conn.execute("INSERT INTO bootstrap_grants (token_hash, role, subject_id, expires_at) VALUES (?, ?, ?, ?)",
                         (self.mod.token_digest("h7-throwaway-grant"), "node", slug,
                          (self.mod.utcnow() + timedelta(minutes=5)).isoformat()))
        out = self.mod.bootstrap_node(self.mod.NodeBootstrapRequest(slug=slug, bootstrap_token="h7-throwaway-grant"),
                                      harness.FakeRequest(path="/api/v1/nodes/bootstrap"))
        self.assertTrue(out["ok"])
        self.assertEqual(self.streak(slug), (0, None))


# ================================================================ mutants ==

def apply_and_run(mutations, test_cases):
    """Load the hub from a mutated copy of the extracted source and run the
    named tests against it. Returns the unittest result."""
    original = harness._extract_main_block
    source = original()
    mutated = source
    for old, new in mutations:
        assert mutated.count(old) == 1, (mutated.count(old), old)
        mutated = mutated.replace(old, new)
    assert mutated != source
    compile(mutated, "h7-mutant", "exec")  # a mutant that does not even compile proves nothing
    harness._extract_main_block = lambda: mutated
    try:
        suite = unittest.TestSuite(test_cases)
        return unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    finally:
        harness._extract_main_block = original


class MutantTests(unittest.TestCase):
    """Design 5.6, "Pipeline and go-live": each mutant must be killed by the
    named test, and the same test must pass on the unmutated source."""

    MUTANTS = [
        ("complete-fresh counts promotions from before node_bootstrapped_at",
         [('"SELECT 1 FROM node_promotion_events WHERE slug = ? AND promoted_at >= ? LIMIT 1",\n        (slug, epoch),',
           '"SELECT 1 FROM node_promotion_events WHERE slug = ? AND ? IS NOT NULL LIMIT 1",\n        (slug, epoch),')],
         [(CompleteFreshTests, "test_a_reset_after_a_rebootstrap_is_not_refused_by_the_old_completion"),
          (CompleteFreshTests, "test_a_reset_of_a_previously_live_slug_needs_a_valid_unconsumed_reset_ticket")]),
        ("complete-fresh accepts a reset of a previously live slug without a ticket",
         [("    ).fetchone() is None:\n        return [], None\n    ticket, reason = winn3_golive_ticket(conn, slug, actions=(\"reset\",))",
           "    ).fetchone() is None or True:\n        return [], None\n    ticket, reason = winn3_golive_ticket(conn, slug, actions=(\"reset\",))")],
         [(CompleteFreshTests, "test_a_reset_of_a_previously_live_slug_needs_a_valid_unconsumed_reset_ticket"),
          (CompleteFreshTests,
           "test_a_reset_that_passes_every_hub_side_check_completes_and_records_the_reset_nonce")]),
        ("complete-fresh accepts a consumed reset ticket",
         [('"SELECT 1 FROM node_fresh_completions WHERE slug = ? AND ticket_nonce = ? AND epoch != ? LIMIT 1",',
           '"SELECT 1 FROM node_fresh_completions WHERE slug = ? AND ticket_nonce = ? AND epoch != ? AND 0 LIMIT 1",')],
         [(CompleteFreshTests, "test_a_reset_ticket_used_by_an_earlier_epoch_is_consumed")]),
        ("node_bootstrapped_at NULL is read as never bootstrapped (no COALESCE)",
         [('return str(dict(node).get("node_bootstrapped_at") or "").strip() or NODE_BOOTSTRAP_EPOCH_ZERO',
           'return str(dict(node).get("node_bootstrapped_at") or "").strip() or "9999-12-31T00:00:00"')],
         [(CompleteFreshTests, "test_migration_default_and_the_coalesce")]),
        ("the migration default is removed",
         [("        conn.execute(\"UPDATE nodes SET node_bootstrapped_at='0001-01-01T00:00:00' \"\n                     \"WHERE node_bootstrapped_at IS NULL\")\n",
           "        pass\n")],
         [(CompleteFreshTests, "test_migration_default_and_the_coalesce")]),
        ("complete-fresh accepts a digest that differs from the registered revision",
         [('if str(row["data_plane_code_revision"] or "").strip().lower() != "sha256:" + digest:',
           "if False:")],
         [(CompleteFreshTests, "test_the_installer_digest_must_equal_the_registered_revision")]),
        ("complete-fresh accepts a different completion",
         [('            raise HTTPException(\n                status_code=409,\n                detail="Fresh completion refused: a different completion is already recorded.",\n            )',
           '            pass')],
         [(CompleteFreshTests, "test_idempotent_for_the_same_digest_and_refused_for_a_different_completion")]),
        ("complete-fresh opens the latch",
         [("\"UPDATE nodes SET health_closed_at=?, health_closed_reason='fresh_install', \"\n                \"latch_cause='fresh_install_pending', \"",
           "\"UPDATE nodes SET operator_enabled=1, health_closed_at=?, health_closed_reason='fresh_install', \"\n                \"latch_cause='fresh_install_pending', \"")],
         [(CompleteFreshTests, "test_auto_ticket_records_the_fresh_install_closure_and_never_opens")]),
        ("the ticket signature is not verified",
         [("        winn3_verify_signer_ticket_signature(payload, signature)\n        ticket = winn3_decode_signer_ticket(payload, slug=slug)\n    except Winn3ContractError as exc:\n        return None, exc.reason",
           "        ticket = winn3_decode_signer_ticket(payload, slug=slug)\n    except Winn3ContractError as exc:\n        return None, exc.reason")],
         [(CompleteFreshTests, "test_no_ticket_switch_off_and_unverifiable_tickets_leave_the_plain_closure"),
          (FreshReopenTests, "test_a_ticket_altered_after_completion_holds_the_flip_and_cannot_change_the_tier")]),
        ("go_live is read from the stored column instead of the verified bytes",
         [('    if ticket["go_live"] != "auto":\n        return None, ["the go-live ticket carries go_live=manual"]',
           '    if conn.execute("SELECT go_live FROM winn3_signer_tickets WHERE slug = ? ORDER BY posted_at DESC LIMIT 1", (slug,)).fetchone()[0] != "auto":\n        return None, ["the go-live ticket carries go_live=manual"]')],
         [(CompleteFreshTests, "test_go_live_and_tier_come_only_from_the_verified_ticket_bytes")]),
        ("tier is read from the stored column instead of the verified bytes",
         [('                fresh_tier = ticket["tier"]',
           '                fresh_tier = conn.execute("SELECT tier FROM winn3_signer_tickets WHERE slug = ? ORDER BY posted_at DESC LIMIT 1", (slug,)).fetchone()[0]')],
         [(FreshReopenTests, "test_a_ticket_altered_after_completion_holds_the_flip_and_cannot_change_the_tier")]),
        ("a fresh_install closure is judged as a health closure",
         [('            fresh = str(row["health_closed_reason"] or "") == "fresh_install"',
           "            fresh = False")],
         [(FreshReopenTests, "test_the_switch_is_per_class_and_a_fresh_closure_is_never_a_health_closure")]),
        ("go-live flipped with a missing transport carry proof",
         [("    failures += installer_rerun_carry_failures(data)\n    if str(data.get(\"winn3_canary_status\")",
           "    if str(data.get(\"winn3_canary_status\")")],
         [(FreshReopenTests, "test_each_missing_proof_keeps_the_node_dark_by_name")]),
        ("go-live flipped with a v3 canary bound to another identity or generation",
         [("        failures += fresh_install_carry_binding_failures(data)",
           "        pass")],
         [(FreshReopenTests, "test_each_missing_proof_keeps_the_node_dark_by_name")]),
        ("go-live flipped with the carrier still winn/1",
         [('    if str(data.get("protocol_version") or "").strip().lower() != "winn/3":\n        failures.append("the carrier is not winn/3 (no v3 profile is served yet)")',
           "    pass")],
         [(FreshReopenTests, "test_each_missing_proof_keeps_the_node_dark_by_name")]),
        ("go-live flipped with an active operator hold",
         [('    if int(data.get("winn3_operator_hold") or 0):\n        failures.append("winn3 operator hold is active")',
           "    pass")],
         [(FreshReopenTests, "test_each_missing_proof_keeps_the_node_dark_by_name"),
          (FreshReopenTests, "test_the_operator_hold_is_checked_first_and_blocks_the_flip")]),
        ("go-live flipped without consuming the off-node gate",
         [("            if not consume_offnode_gate(conn, slug, gate, \"auto_reopened\"):\n                conn.rollback()",
           "            if False:\n                conn.rollback()")],
         [(FreshReopenTests, "test_every_proof_present_flips_at_the_verified_tier_and_records_everything")]),
        ("go-live flipped with a missing off-node gate (the builder result ignored)",
         [('                    if not gate:\n                        failures += ["offnode gate: " + reason for reason in (gate_reasons or [',
           '                    if False:\n                        failures += ["offnode gate: " + reason for reason in (gate_reasons or [')],
         [(FreshReopenTests, "test_the_gate_builder_runs_last_and_only_when_nothing_else_fails")]),
        ("a generation move is ignored by the flip",
         [('                    if row is None or row["deployment_generation"] != generation:\n                        result["held"][slug] = ["the deployment generation moved while the hub-run off-node gate ran"]',
           '                    if row is None:\n                        result["held"][slug] = ["the deployment generation moved while the hub-run off-node gate ran"]'),
          ('                    "AND deployment_generation = ? AND health_closed_at = ? "\n                    "AND health_closed_reason = \'fresh_install\'",',
           '                    "AND ? IS NOT NULL AND health_closed_at = ? "\n                    "AND health_closed_reason = \'fresh_install\'",')],
         [(FreshReopenTests, "test_a_hub_recorded_gate_opens_the_node_and_a_moved_generation_does_not")]),
        ("the window never expires a fresh_install closure",
         [("                if installer_rerun_window_expired(row):\n                    # Eligibility never lingers (the same window as a rerun):",
           "                if False:\n                    # Eligibility never lingers (the same window as a rerun):")],
         [(FreshReopenTests, "test_the_window_expires_into_an_operator_closure_with_one_alert")]),
        ("the shared daily budget leaves out the fresh go-live",
         [('    "auto_reopen", "auto_reopen_installer_rerun", "auto_golive_fresh_install")',
           '    "auto_reopen", "auto_reopen_installer_rerun", "auto_reopen_installer_rerun")')],
         [(FreshReopenTests, "test_the_daily_budget_is_shared_with_the_other_automatic_reopens")]),
        ("the readiness gate is not told a fresh_install closure may use a hub gate",
         [('allow_hub_gate=str(data.get("health_closed_reason") or "") in HUB_OFFNODE_GATE_CLOSURE_REASONS)',
           'allow_hub_gate=str(data.get("health_closed_reason") or "") == "installer_rerun")')],
         [(FreshReopenTests, "test_the_gate_check_accepts_hub_sourced_gate_records_for_this_class")]),
        ("the lineage query accepts an auto_golive_fresh_install row as manual evidence",
         [('"AND tier IN (\'free\', \'premium\') AND operator_source_hash GLOB ? "\n        "AND operator_source_hash NOT IN (" + ", ".join("?" for _ in AUTOMATIC_PROMOTION_SOURCES) + ") "',
           '"AND tier IN (\'free\', \'premium\') AND operator_source_hash != \'auto_reopen_installer_rerun\' AND ? IS NOT NULL "\n        "AND ? IS NOT NULL AND ? IS NOT NULL "')],
         [(ManualEvidenceTests, "test_only_a_sixteen_hex_row_evidences_a_revision")]),
        ("the expected transition is accepted under another generation",
         [("    if type(recorded[\"generation\"]) is not int or type(generation) is not int \\\n            or recorded[\"generation\"] != generation:\n        return set()",
           "    if type(recorded[\"generation\"]) is not int:\n        return set()")],
         [(IdentityTransitionTests, "test_the_first_v3_transition_is_accepted_only_as_recorded")]),
        ("the expected transition accepts a change in a field outside the four",
         [("    moved = [field for field in changed if field in NODE_RERUN_TRANSITION_FIELDS]",
           "    moved = list(changed)")],
         [(IdentityTransitionTests, "test_the_first_v3_transition_is_accepted_only_as_recorded")]),
        ("the first identity is accepted without a ticket",
         [("        if str(prior.get(\"winn3_identity_sha256\") or \"\") != \"\" or ticket is None:\n            accepted.discard(\"winn3_identity_sha256\")",
           "        pass")],
         [(IdentityTransitionTests, "test_a_first_identity_needs_a_verified_new_or_reset_ticket")]),
        ("the rerun identity field is the raw descriptor hash again",
         [('        return winn3_identity_digest(descriptor) if descriptor else ""',
           '        return hashlib.sha256(str(dict(node).get("winn3_descriptor_json") or "").encode()).hexdigest() if descriptor else ""')],
         [(IdentityTransitionTests, "test_the_rerun_identity_field_is_the_identity_digest_not_the_descriptor_hash")]),
        ("a node live at withdrawal is treated as a fresh install",
         [("        if int(prior.get(\"operator_enabled\") or 0) != 1 and node_never_live_since_bootstrap(conn, row):",
           "        if node_never_live_since_bootstrap(conn, row):")],
         [(RerunCompletionTests, "test_a_node_live_at_withdrawal_with_no_promotion_row_is_not_fresh")]),
        ("a manual ticket is classed fresh_install on the rerun route",
         [('    if ticket["go_live"] != "auto":\n        return None, ["the go-live ticket carries go_live=manual"]',
           '    if False:\n        return None, ["the go-live ticket carries go_live=manual"]')],
         [(RerunCompletionTests, "test_an_ineligible_rerun_is_still_released_and_stays_a_plain_closure"),
          (CompleteFreshTests, "test_manual_ticket_is_a_plain_closure_that_is_still_released")]),
        ("the rerun route does not release the deployment",
         [('"UPDATE nodes SET deployment_withdrawal_id=NULL, deployment_withdrawn_at=NULL, deployment_released_at=? "\n            "WHERE slug=? AND deployment_withdrawal_id=? AND COALESCE(operator_enabled, 0)=0",\n            (utcnow().isoformat(), node_slug, withdrawal_id),',
           '"UPDATE nodes SET deployment_withdrawal_id=NULL, deployment_withdrawn_at=NULL "\n            "WHERE slug=? AND deployment_withdrawal_id=? AND COALESCE(operator_enabled, 0)=0",\n            (node_slug, withdrawal_id),')],
         [(RerunCompletionTests, "test_an_ineligible_rerun_is_still_released_and_stays_a_plain_closure")]),
        ("complete-fresh never records the release",
         [('"UPDATE nodes SET deployment_released_at=?, deployment_completed_at=? "\n            "WHERE slug=? AND deployment_withdrawal_id IS NULL',
           '"UPDATE nodes SET deployment_completed_at=?, deployment_completed_at=? "\n            "WHERE slug=? AND deployment_withdrawal_id IS NULL')],
         [(CompleteFreshTests, "test_manual_ticket_is_a_plain_closure_that_is_still_released")]),
        ("the fresh_install closure ignores the hub switch at completion",
         [('    if not WINN3_FRESH_INSTALL_AUTO_GOLIVE:\n        return None, ["fresh install automatic go-live is off (WINN3_FRESH_INSTALL_AUTO_GOLIVE=0)"]',
           "    pass")],
         [(CompleteFreshTests, "test_no_ticket_switch_off_and_unverifiable_tickets_leave_the_plain_closure")]),
        # ---- Turn 1 fix round (Claude and Sol votes) ----
        ("a node closed at withdrawal but promoted since its bootstrap is treated as a fresh install",
         [("        if int(prior.get(\"operator_enabled\") or 0) != 1 and node_never_live_since_bootstrap(conn, row):",
           "        if int(prior.get(\"operator_enabled\") or 0) != 1:")],
         [(RerunCompletionTests, "test_a_pre_v7_node_closed_at_withdrawal_is_never_classed_fresh_install")]),
        ("the go-live canary is not bound to the current descriptor sequence",
         [('    if not descriptor or type(canary_seq) is not int \\\n            or canary_seq != descriptor.get("seq"):',
           "    if False:")],
         [(FreshReopenTests,
           "test_the_go_live_canary_is_bound_to_the_current_descriptor_and_follows_the_carrier_flip")]),
        ("the go-live canary binding accepts an expired descriptor",
         [("        descriptor = winn3_stored_descriptor(data)\n    except Exception:\n        descriptor = {}",
           "        descriptor = winn3_stored_descriptor(data, clock_tolerant=True)\n    except Exception:\n        descriptor = {}")],
         [(FreshReopenTests,
           "test_the_go_live_canary_is_bound_to_the_current_descriptor_and_follows_the_carrier_flip")]),
        ("the go-live canary may predate the carrier flip",
         [('    if not _iso_after(\n            data.get("winn3_canary_ok_at"), data.get("winn3_carrier_flipped_at")):',
           "    if False:")],
         [(FreshReopenTests,
           "test_the_go_live_canary_is_bound_to_the_current_descriptor_and_follows_the_carrier_flip"),
          (FreshReopenTests, "test_the_whole_winn3_gate_without_stubs_opens_the_node_once_everything_is_true")]),
        ("the go-live canary freshness rule is skipped",
         [('    if not winn3_canary_is_fresh(data):\n'
           '        failures.append("winn/3: the per-slug v3 canary is absent, stale or incorrectly bound")',
           "    pass")],
         [(FreshReopenTests,
           "test_the_go_live_canary_is_bound_to_the_current_descriptor_and_follows_the_carrier_flip")]),
        ("the rerun route classes a reset slug fresh_install without the reset authority",
         [("                reset_refusals, reset_nonce = fresh_completion_reset_failures(conn, row)\n"
           "                if reset_refusals:\n"
           "                    fresh_ticket = None",
           "                pass")],
         [(RerunCompletionTests,
           "test_a_reset_slug_is_classed_fresh_install_on_the_rerun_route_only_under_the_reset_authority")]),
        # ---- Turn 2 fix round (Claude and Fable votes) ----
        ("the rerun route reads the reset nonce instead of the reset failures",
         [("                if reset_refusals:\n                    fresh_ticket = None",
           "                if reset_nonce:\n                    fresh_ticket = None")],
         [(RerunCompletionTests,
           "test_a_reset_slug_is_classed_fresh_install_on_the_rerun_route_only_under_the_reset_authority")]),
        ("the rerun route records the newer new ticket's nonce instead of the reset nonce",
         [("                     reset_nonce or fresh_ticket[\"nonce\"], completed_at),",
           "                     fresh_ticket[\"nonce\"], completed_at),")],
         [(RerunCompletionTests,
           "test_a_reset_slug_is_classed_fresh_install_on_the_rerun_route_only_under_the_reset_authority")]),
        ("complete-fresh records the newer new ticket's nonce instead of the reset nonce",
         [('(slug, epoch, installer_sha256, ticket_nonce, completed_at) VALUES (?, ?, ?, ?, ?)",\n'
           '            (node_slug, epoch, digest, reset_nonce or (ticket["nonce"] if ticket is not None else None), now_iso),',
           '(slug, epoch, installer_sha256, ticket_nonce, completed_at) VALUES (?, ?, ?, ?, ?)",\n'
           '            (node_slug, epoch, digest, (ticket["nonce"] if ticket is not None else None) or reset_nonce, now_iso),')],
         [(CompleteFreshTests, "test_a_reset_under_a_newer_new_ticket_records_the_reset_nonce")]),
        ("reset authority runs before the idempotence check again",
         [('        if str(row["data_plane_code_revision"] or "").strip().lower() != "sha256:" + digest:',
           '        refusals, reset_nonce = fresh_completion_reset_failures(conn, row)\n'
           '        if refusals:\n'
           '            raise HTTPException(status_code=409, detail="Fresh completion refused: " + "; ".join(refusals))\n'
           '        if str(row["data_plane_code_revision"] or "").strip().lower() != "sha256:" + digest:')],
         [(CompleteFreshTests, "test_an_identical_reset_completion_stays_idempotent_after_its_ticket_is_spent")]),
        ("the window is not checked again right before the flip",
         [("                if installer_rerun_window_expired(row):\n                    conn.execute(\n",
           "                if False:\n                    conn.execute(\n")],
         [(FreshReopenTests, "test_the_window_is_checked_again_right_before_the_flip")]),
        # ---- H7 rebase onto H4/rebase_s13: H6's gate attempt on the fresh branch (Q3) ----
        ("the fresh branch drops H6's hub-run check reasons",
         [('failures += ["offnode gate: " + reason for reason in (gate_reasons or [',
           'failures += ["offnode gate: " + reason for reason in ([] or [')],
         [(FreshReopenTests, "test_the_fresh_branch_carries_h6s_reasons_budget_and_stable_row_rule")]),
        ("the fresh branch ignores H6's per-sweep check budget",
         [('                if fresh_builder_due and fresh_install_check_budget_spent():',
           '                if fresh_builder_due and False:')],
         [(FreshReopenTests, "test_the_fresh_branch_carries_h6s_reasons_budget_and_stable_row_rule")]),
        ("the fresh branch skips H6's stable-field re-check after the hub-run check",
         [('                    if changed_fields:\n',
           '                    if False:\n')],
         [(FreshReopenTests, "test_the_fresh_branch_carries_h6s_reasons_budget_and_stable_row_rule")]),
        ("a stale hub record stops the fresh-branch builder",
         [('                and verify_offnode_gate_for_use(conn, slug, record, allow_hub_source=True):\n            return ""\n',
           '                and verify_offnode_gate_for_use(conn, slug, record, allow_hub_source=True):\n            pass\n')],
         [(FreshReopenTests, "test_a_stale_hub_record_is_rebuilt_and_an_operator_record_is_never_replaced")]),
        ("the fresh-branch builder replaces a stale operator record",
         [('        if stored is not None and stored["source"] == "hub" \\\n',
           '        if stored is not None \\\n')],
         [(FreshReopenTests, "test_a_stale_hub_record_is_rebuilt_and_an_operator_record_is_never_replaced")]),
        ("a usable hub record does not stop the fresh-branch builder",
         [('                and verify_offnode_gate_for_use(conn, slug, record, allow_hub_source=True):\n            return ""\n',
           '                and (verify_offnode_gate_for_use(conn, slug, record, allow_hub_source=True) or True):\n            return ""\n')],
         [(FreshReopenTests, "test_a_usable_hub_record_stops_the_fresh_branch_builder")]),
        # ---- hub-lite FINDINGS HL-F2 and HL-F3 (705bedd) ----
        ("HL-F2: a recovery node's own evidence is matched through the winn/3-only map again",
         [('        for row in conn.execute("SELECT slug, ssh_host, endpoint FROM nodes WHERE slug != \'\'")\n',
           '        for row in conn.execute("SELECT slug, ssh_host, endpoint FROM nodes '
           'WHERE protocol_version=\'winn/3\' AND slug != \'\'")\n')],
         [(RecoveryHostTests, "test_hl_f2_a_released_node_not_yet_winn3_is_read_back_and_trusts_the_budget"),
          (RecoveryHostTests, "test_hl_f2_a_node_first_published_after_the_entry_is_recovered_without_a_flip")]),
        ("HL-F2: the needed journal read is keyed through the winn/3-only map again",
         [('journals_needed = {(slug, own_hosts.get(slug, "")) for slug in budget_nodes}',
           'journals_needed = {(slug, hosts.get(slug, "")) for slug in budget_nodes}')],
         [(RecoveryHostTests, "test_hl_f2_a_released_node_not_yet_winn3_is_read_back_and_trusts_the_budget")]),
        ("HL-F2: the new-node barrier looks a node up through the winn/3-only map again",
         [("            ledger, nodes, own_hosts, since, now)", "            ledger, nodes, hosts, since, now)"),
          ("                ledger, current, own_hosts, float(", "                ledger, current, hosts, float(")],
         [(RecoveryHostTests, "test_hl_f2_a_node_first_published_after_the_entry_is_recovered_without_a_flip")]),
        ("HL-F3: complete-fresh keeps a streak that began before its closure",
         [('"latch_cause=\'fresh_install_pending\', "\n                "data_plane_green_streak=0, data_plane_green_since=NULL "',
           '"latch_cause=\'fresh_install_pending\' "')],
         [(StreakAfterClosureTests, "test_hl_f3_complete_fresh_ends_a_streak_that_began_before_the_closure")]),
        ("HL-F3: the rerun route's fresh_install closure keeps the earlier streak",
         [('"latch_cause=\'fresh_install_pending\', deployment_completed_at=?, "\n'
           '                "data_plane_green_streak=0, data_plane_green_since=NULL "',
           '"latch_cause=\'fresh_install_pending\', deployment_completed_at=? "')],
         [(StreakAfterClosureTests, "test_hl_f3_a_never_live_rerun_closure_ends_the_streak")]),
        ("HL-F3: a re-bootstrap keeps the old machine's streak",
         [('"protocol_params_json=NULL, path_mtu=NULL, carrier_classes=NULL, "\n'
           '                     "data_plane_green_streak=0, data_plane_green_since=NULL WHERE slug=?",',
           '"protocol_params_json=NULL, path_mtu=NULL, carrier_classes=NULL WHERE slug=?",')],
         [(StreakAfterClosureTests, "test_hl_f3_a_rebootstrap_through_the_real_route_ends_the_old_machines_streak")]),
        # ---- FINAL4 F4-HL: a moved slug that is not winn/3 (Astra T2, Claude seat) ----
        ("F4-HL: budget journals come from the winn/3-only retired set again (tree.t2)",
         [("            pair for pair in budget_retired if pair[0] in budget_nodes\n",
           "            pair for pair in retired if pair[0] in budget_nodes\n")],
         [(RecoveryHostTests, "test_f4_hl_a_moved_slug_that_is_not_winn3_keeps_its_old_machine_a_charge_source"),
          (RecoveryHostTests, "test_f4_hl_a_hub_start_after_a_move_inside_the_window_reads_the_old_machine")]),
        ("F4-HL: the budget's retired machines are found through the winn/3-only map",
         [("        budget_retired = winn3_retired_gateways(ledger, own_hosts, now)\n",
           "        budget_retired = winn3_retired_gateways(ledger, hosts, now)\n")],
         [(RecoveryHostTests, "test_f4_hl_a_moved_slug_that_is_not_winn3_keeps_its_old_machine_a_charge_source"),
          (RecoveryHostTests, "test_f4_hl_a_hub_start_after_a_move_inside_the_window_reads_the_old_machine")]),
        ("F4-HL: the old machine is needed but never read back",
         [("        retired_pending |= {pair for pair in budget_retired if pair in journals_needed and pair not in read}\n",
           "        pass\n")],
         [(RecoveryHostTests, "test_f4_hl_a_moved_slug_that_is_not_winn3_keeps_its_old_machine_a_charge_source"),
          (RecoveryHostTests, "test_f4_hl_a_hub_start_after_a_move_inside_the_window_reads_the_old_machine")]),
        ("F4-HL: an old machine of a slug that is not winn/3 is never forgotten (the wait recurs at every start)",
         [("                if pair[0] not in node_hosts and (window_passed or pair in settled):\n",
           "                if False:\n")],
         [(RecoveryHostTests,
           "test_f4_hl_an_unreachable_old_machine_stops_holding_the_budget_once_settled_and_aged_out")]),
        ("F4-HL: an old machine is forgotten on its record's age alone, before its charges are settled",
         [("                if pair[0] not in node_hosts and (window_passed or pair in settled):\n",
           "                if pair[0] not in node_hosts:\n")],
         [(RecoveryHostTests,
           "test_f4_hl_a_record_that_only_looks_old_is_not_forgotten_before_its_charges_are_settled")]),
    ]

    def test_every_mutant_is_killed_and_the_tests_pass_unmutated(self):
        survivors = []
        for name, mutations, tests in self.MUTANTS:
            cases = [cls(method) for cls, method in tests]
            result = apply_and_run(mutations, cases)
            if result.wasSuccessful():
                survivors.append(name)
        self.assertEqual(survivors, [], "mutants that survived")

    def test_the_named_tests_pass_on_the_unmutated_source(self):
        failures = []
        seen = set()
        for name, _mutations, tests in self.MUTANTS:
            for cls, method in tests:
                if (cls, method) in seen:
                    continue
                seen.add((cls, method))
                result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(
                    unittest.TestSuite([cls(method)]))
                if not result.wasSuccessful():
                    failures.append((cls.__name__, method))
        self.assertEqual(failures, [])



# ====================== node side end to end (whole-tree fix, design 3.17) ==

E2E_BRIDGE_CURL = r"""#!/bin/bash
cat > "$AREA/config"
prev=""
for arg in "$@"; do
  [[ "$prev" == --data-binary ]] && cp "${arg#@}" "$AREA/body"
  prev="$arg"
done
: > "$AREA/request.ready"
for _ in $(seq 1 600); do
  [[ -f "$AREA/response.ready" ]] && break
  sleep 0.05
done
[[ -f "$AREA/response.ready" ]] || exit 28
cat "$AREA/response"
exit "$(cat "$AREA/curl_rc")"
"""


def dp_shell_function(name):
    sys.path.insert(0, str(fx2.HERE.parent / "tools"))
    from winn3_gateway_block import segment
    lines = fx2.DATA_INSTALLER.read_text(encoding="utf-8").split("\n")
    for item in segment(lines):
        if item["kind"] == "func" and item["name"] == name:
            return "\n".join(lines[item["start"]:item["end"] + 1])
    raise AssertionError("missing data plane function: " + name)


@quiet_inherited
class FreshNodeCompletionEndToEndTests(H7Base):
    """The REAL data plane complete_fresh_deployment_after_postflight runs under
    bash. Its curl is a bridge: the request it would send (curl config on stdin
    and the body file) is handed to the REAL complete-fresh route in this
    process, and the route's answer comes back the way curl -f would return it
    (the JSON body and exit 0, or no body and exit 22 for an HTTP error). The
    installer digest is the real data plane installer's own sha256."""

    PULLED = {"identity": "i", "identity_sig": "s", "admission_secret": "a"}

    def setUp(self):
        super().setUp()
        self.area = tempfile.mkdtemp(prefix="h7-e2e-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, self.area, True)
        os.makedirs(os.path.join(self.area, "bin"))
        curl = os.path.join(self.area, "bin", "curl")
        with open(curl, "w", encoding="utf-8") as handle:
            handle.write(E2E_BRIDGE_CURL)
        os.chmod(curl, 0o755)
        self.digest = hashlib.sha256(fx2.DATA_INSTALLER.read_bytes()).hexdigest()

    def signer_request(self, slug):
        with self.db() as conn:
            row = conn.execute(self.mod.WINN3_JOB_ROW_SQL, (slug,)).fetchone()
            return self.mod.winn3_build_signer_request(row, "sign", row["deployment_generation"], self.PULLED)

    def run_node(self, slug):
        for name in ("config", "body", "request.ready", "response", "curl_rc", "response.ready"):
            path = os.path.join(self.area, name)
            if os.path.exists(path):
                os.unlink(path)
        script = ("set -Eeuo pipefail\n"
                  "log() { printf 'LOG %s\\n' \"$*\"; }\n"
                  "warn() { printf 'WARN %s\\n' \"$*\"; }\n"
                  "err() { printf 'ERR %s\\n' \"$*\"; }\n"
                  + dp_shell_function("data_plane_installer_path") + "\n"
                  + dp_shell_function("data_plane_installer_sha256") + "\n"
                  + dp_shell_function("complete_fresh_deployment_after_postflight") + "\n"
                  "complete_fresh_deployment_after_postflight\n")
        env = dict(os.environ, AREA=self.area, PATH=os.path.join(self.area, "bin") + ":" + os.environ["PATH"],
                   NODE_SLUG=slug, NODE_TOKEN=dark.NODE_TOKEN, HUB_API_BASE="https://hub.example",
                   WINS_DATA_PLANE_INSTALLER_PATH=str(fx2.DATA_INSTALLER))
        bash = os.environ.get("WINS_TEST_BASH", "/bin/bash")
        proc = subprocess.Popen([bash, "-c", script], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            ready = os.path.join(self.area, "request.ready")
            deadline = time.time() + 30
            while not os.path.exists(ready) and proc.poll() is None and time.time() < deadline:
                time.sleep(0.02)
            self.assertTrue(os.path.exists(ready), "the node never sent the request")
            config = open(os.path.join(self.area, "config"), encoding="utf-8").read().splitlines()
            headers = [re.fullmatch(r'header = "([^"]*)"', line).group(1) for line in config if line.startswith("header")]
            url = next(re.fullmatch(r'url = "([^"]*)"', line).group(1) for line in config if line.startswith("url"))
            self.assertIn('request = "POST"', config)
            token = next(h.split(": ", 1)[1] for h in headers if h.lower().startswith("x-node-token: "))
            path = re.fullmatch(r"https://hub\.example(/api/v1/nodes/([a-z0-9-]+)/deployment/complete-fresh)", url)
            self.assertIsNotNone(path, url)
            body = json.loads(open(os.path.join(self.area, "body"), encoding="utf-8").read())
            # The route's request model forbids extra fields (extra="forbid" in
            # FreshDeploymentCompletion); the harness model takes the fields as is.
            self.assertEqual(sorted(body), ["installer_sha256"])
            payload = self.mod.FreshDeploymentCompletion(**body)
            try:
                answer = self.mod.complete_fresh_node_deployment(
                    path.group(2), payload, harness.FakeRequest(path=path.group(1)), x_node_token=token)
                response, curl_rc = json.dumps(answer), 0
            except harness.HTTPException as refused:
                self.http_status = refused.status_code
                response, curl_rc = "", 22
            for name, value in (("response", response), ("curl_rc", str(curl_rc)), ("response.ready", "")):
                with open(os.path.join(self.area, name), "w", encoding="utf-8") as handle:
                    handle.write(value)
            out, err = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        return proc.returncode, out + err, body

    def test_a_passing_fresh_install_is_released_and_the_signer_request_is_then_accepted(self):
        slug = "sg-e2e-auto"
        self.fresh_node(slug, "sha256:" + self.digest)
        ticket = self.post_ticket(slug, go_live="auto", tier="free")
        with self.assertRaisesRegex(ValueError, "deployment-not-released"):
            self.signer_request(slug)
        rc, output, body = self.run_node(slug)
        self.assertEqual(rc, 0, output)
        self.assertEqual(body, {"installer_sha256": self.digest})
        self.assertIn("LOG Released the fresh Data deployment after postflight; the hub recorded it for automatic go-live",
                      output)
        row = self.node(slug)
        self.assertTrue(row["deployment_released_at"])
        self.assertTrue(row["deployment_completed_at"])
        self.assertEqual(row["health_closed_reason"], "fresh_install")
        self.assertEqual(row["operator_enabled"], 0, "completion never opens the latch")
        self.assertEqual(self.completions(slug)[0]["installer_sha256"], self.digest)
        request = self.signer_request(slug)
        self.assertEqual(request["verb"], "sign")
        self.assertEqual(json.loads(base64.b64decode(request["ticket"]["payload"]))["nonce"], ticket["nonce"])
        # A replay of the same completion (an interrupted install run again) stays idempotent.
        rc, output, _ = self.run_node(slug)
        self.assertEqual(rc, 0, output)

    def test_a_manual_ticket_is_released_for_signing_and_the_node_says_promotion_is_manual(self):
        slug = "sg-e2e-manual"
        self.fresh_node(slug, "sha256:" + self.digest)
        self.post_ticket(slug, go_live="manual", tier="premium")
        rc, output, _ = self.run_node(slug)
        self.assertEqual(rc, 0, output)
        self.assertIn("a manual evidenced promotion is still required", output)
        self.assertIn("WARN Hub: automatic go-live not recorded: the go-live ticket carries go_live=manual", output)
        self.assertTrue(self.node(slug)["deployment_released_at"])
        self.assertIsNone(self.node(slug)["health_closed_reason"])
        self.assertEqual(self.signer_request(slug)["verb"], "sign")

    def test_a_hub_refusal_fails_the_install_closed_and_signing_stays_refused(self):
        slug = "sg-e2e-other-revision"
        self.fresh_node(slug, REV_A)
        self.post_ticket(slug, go_live="auto")
        rc, output, body = self.run_node(slug)
        self.assertEqual(rc, 1, output)
        self.assertEqual(self.http_status, 409)
        self.assertEqual(body, {"installer_sha256": self.digest})
        self.assertIn("ERR Fresh postflight passed, but the hub refused or did not answer the fresh completion", output)
        self.assertIsNone(self.node(slug)["deployment_released_at"])
        self.assertEqual(self.completions(slug), [])
        with self.assertRaisesRegex(ValueError, "deployment-not-released"):
            self.signer_request(slug)

    def test_a_wrong_node_token_is_refused_and_nothing_is_released(self):
        slug = "sg-e2e-token"
        self.fresh_node(slug, "sha256:" + self.digest)
        original = dark.NODE_TOKEN
        try:
            dark.NODE_TOKEN = "not-the-node-token"
            rc, output, _ = self.run_node(slug)
        finally:
            dark.NODE_TOKEN = original
        self.assertEqual(rc, 1, output)
        self.assertEqual(self.http_status, 401)
        self.assertIsNone(self.node(slug)["deployment_released_at"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
