#!/usr/bin/env python3
"""Installer fix wave 2, lane sync_hub (IA-SYNC 2026-09-29).

Covers the hub side of SYNC-01, SYNC-04, SYNC-07, SYNC-08, SYNC-23, SYNC-24
and SYNC-25. Every hub test runs the REAL hub source extracted from the
ONETOUCH heredoc against temporary SQLite files; the keepalive tests run the
REAL installer functions under bash on a synthetic root. No test contacts a
node, a hub, or the network. Addresses are RFC 5737 documentation literals.

Every guard has an anti-vacuity arm that flips one condition and asserts the
refusal.

Run: python3 server/test_installer_sync_hub_fx2.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import types
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_data_plane_dark_start_latch as dark
import test_winn3_departure_grace_hub as roundo
import test_winn3_descriptor_hub as descriptor

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
HUB_INSTALLER = HERE / "wins_control_plane_setup_ONETOUCH.sh"
DATA_INSTALLER = HERE / "wins_data_plane_setup_ONETOUCH.sh"
REV_A = "sha256:" + "a" * 64
REV_B = "sha256:" + "b" * 64


def quiet(mod):
    for handler in list(mod.logger.handlers):
        handler.close()
        mod.logger.removeHandler(handler)
    mod.logger.addHandler(logging.NullHandler())
    mod.logger.propagate = False


# ============================================================ SYNC-01 ======

class RegistryGroupAbsentTests(roundo.DepartureGraceTests):
    """A node without the winn3-gateway group, published through the REAL
    sync_winn3_registry_to_node and its REAL remote command (Round O harness,
    with getent failing for the named nodes)."""

    V1, V3 = "lab-alpha", "lab-beta"

    def setUp(self):
        super().setUp()
        self.nogroup = set()
        self.probe = True
        self.probe_calls = []
        nogroup_shims = os.path.join(self.fleet.root, "shims-nogroup")
        shutil.copytree(self.fleet.shims, nogroup_shims)
        with open(os.path.join(nogroup_shims, "getent"), "w") as handle:
            handle.write("#!/bin/bash\nexit 2\n")
        os.chmod(os.path.join(nogroup_shims, "getent"), stat.S_IRWXU)
        real_execute = self.fleet.execute
        fleet = self.fleet

        def execute(slug, command, stdin=None):
            if slug not in self.nogroup:
                return real_execute(slug, command, stdin)
            target = fleet.directory(slug)
            os.makedirs(target, exist_ok=True)
            env = dict(os.environ, PATH=nogroup_shims + os.pathsep + os.environ.get("PATH", ""))
            result = roundo.REAL_RUN(
                ["bash", "--noprofile", "--norc", "-c", command.replace("/etc/winn", target)],
                input=stdin, capture_output=True, text=True, env=env, check=False,
            )
            self.last_nogroup = result
            return result

        self.fleet.execute = execute
        with self.mod.get_db() as conn:
            conn.execute(
                "UPDATE nodes SET protocol_version='winn/1', winn3_descriptor_json=NULL, "
                "management_status='unknown' WHERE slug=?", (self.V1,))

    def patched(self, mod):
        def probe(node_ip):
            self.probe_calls.append(node_ip)
            return self.probe
        return super().patched(mod) + [
            patch.object(mod, "remove_peer_from_node", return_value=True),
            patch.object(mod, "verify_node_management_access", side_effect=probe),
        ]

    def resync(self, slug=""):
        return self.run_patched(self.mod, self.mod.resync_active_peers_to_node, slug)

    def management(self, slug):
        with self.mod.get_db() as conn:
            return conn.execute(
                "SELECT management_status FROM nodes WHERE slug=?", (slug,)).fetchone()[0]

    def test_remote_command_names_the_missing_group(self):
        self.nogroup.add(self.V1)
        self.resync(self.V1)
        self.assertEqual(self.last_nogroup.returncode, 4)
        self.assertIn("winn3-gateway-group-absent", self.last_nogroup.stderr)
        self.assertIsNone(self.fleet.landed(self.V1), "nothing may land without the group")

    def test_self_resync_of_a_v1_node_without_the_group_passes_on_the_probe(self):
        self.nogroup.add(self.V1)
        out = self.resync(self.V1)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["winn3_registry_skipped"], 1)
        self.assertEqual(out["winn3_registry_failed"], 0)
        self.assertEqual(self.management(self.V1), "ok")
        self.assertEqual(self.probe_calls, ["127.0.0.1"], "the hub management probe must decide")

    def test_self_resync_still_fails_when_management_ssh_fails(self):
        self.nogroup.add(self.V1)
        self.probe = False
        out = self.resync(self.V1)
        self.assertFalse(out["ok"], out)
        self.assertEqual(self.management(self.V1), "failed")

    def test_fleet_resync_skips_a_reachable_v1_node_and_fails_an_unreachable_one(self):
        self.nogroup.add(self.V1)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET management_status='ok' WHERE slug=?", (self.V1,))
        out = self.resync("")
        self.assertEqual(out["winn3_registry_failed"], 0, out)
        self.assertEqual(out["winn3_registry_skipped"], 1)
        self.assertEqual(self.management(self.V1), "ok")
        self.probe = False
        out = self.resync("")
        self.assertEqual(out["winn3_registry_failed"], 1, out)
        self.assertEqual(self.management(self.V1), "failed")

    def test_a_winn3_node_without_the_group_is_still_a_failure(self):
        self.nogroup.add(self.V3)
        out = self.resync(self.V3)
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["winn3_registry_failed"], 1)
        self.assertEqual(self.management(self.V3), "failed")

    def closed_status(self, slug, status):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET status=?, operator_enabled=0 WHERE slug=?", (status, slug))

    def test_round2_installing_node_is_probed_in_every_status(self):
        # The data-plane installer registers every node as maintenance while
        # it runs verify_hub_node_management (D:11313-11314): the skip must
        # still prove management.
        for status in ("maintenance", "offline", "online"):
            for probe in (False, True):
                with self.subTest(status=status, probe=probe):
                    self.nogroup = {self.V1}
                    self.probe, self.probe_calls = probe, []
                    self.closed_status(self.V1, status)
                    with self.mod.get_db() as conn:
                        conn.execute("UPDATE nodes SET management_status='unknown' WHERE slug=?", (self.V1,))
                    out = self.resync(self.V1)
                    self.assertEqual(out["ok"], probe, out)
                    self.assertEqual(self.management(self.V1), "ok" if probe else "failed")
                    self.assertGreaterEqual(len(self.probe_calls), 1, "no management probe ran")

    def test_round2_ssh_failure_on_a_maintenance_node_fails_with_the_group_present(self):
        self.closed_status(self.V1, "maintenance")
        self.fleet.mode[self.V1] = "down"
        self.probe = False
        out = self.resync(self.V1)
        self.assertFalse(out["ok"], out)
        self.assertEqual(self.management(self.V1), "failed")
        self.assertEqual(self.probe_calls, ["127.0.0.1"])

    def ledger_rows(self, slug):
        with self.mod.winn3_authority_ledger() as ledger:
            return [tuple(r) for r in ledger.execute(
                "SELECT outcome, refusal FROM winn3_publications WHERE node_slug=? ORDER BY seq", (slug,))]

    def recovery_set(self):
        with self.mod.get_db() as conn, self.mod.winn3_authority_ledger() as ledger:
            return self.mod.winn3_recovery_node_set(conn, ledger)

    def test_round2_group_absent_is_a_recorded_refusal_and_leaves_the_recovery_set(self):
        self.nogroup.add(self.V1)
        self.resync(self.V1)
        self.resync(self.V1)
        self.assertEqual(self.ledger_rows(self.V1), [("refused", "group_absent")] * 2)
        nodes = self.recovery_set()
        self.assertNotIn(self.V1, nodes, "a never-written v1 node must not block recovery")
        self.assertIn(self.V3, nodes)

    def test_round2_any_other_outcome_keeps_the_v1_node_in_the_recovery_set(self):
        self.nogroup.add(self.V1)
        self.resync(self.V1)
        self.assertNotIn(self.V1, self.recovery_set())
        # An ack lost after a real write is uncertain: authority may exist.
        self.nogroup.discard(self.V1)
        self.fleet.mode[self.V1] = "lost_ack"
        self.resync(self.V1)
        self.assertIn(("uncertain", ""), self.ledger_rows(self.V1))
        self.assertIn(self.V1, self.recovery_set())

    def test_round2_stale_refusal_and_winn3_nodes_stay_in_the_recovery_set(self):
        with self.mod.winn3_authority_ledger() as ledger:
            ledger.execute("INSERT INTO winn3_publications (seq, node_slug, started_at, outcome, finished_at, "
                           "gateway, refusal) VALUES (1, ?, 1, 'refused', 2, '127.0.0.1', '')", (self.V1,))
        self.assertIn(self.V1, self.recovery_set(), "a stale-sequence refusal proves the node holds a file")
        with self.mod.winn3_authority_ledger() as ledger:
            ledger.execute("UPDATE winn3_publications SET refusal='group_absent' WHERE seq=1")
        self.assertNotIn(self.V1, self.recovery_set())
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/3' WHERE slug=?", (self.V1,))
        self.assertIn(self.V1, self.recovery_set(), "a winn/3 node is always counted")

    # ---- round 3 (OI-SYNC_HUB-6 / N-8): the latest definite outcome decides
    def test_round3_one_transient_failure_does_not_keep_a_v1_node_forever(self):
        self.nogroup.add(self.V1)
        self.resync(self.V1)
        self.assertNotIn(self.V1, self.recovery_set())
        self.fleet.mode[self.V1] = "down"          # one ssh timeout: uncertain
        self.resync(self.V1)
        self.assertIn(self.V1, self.recovery_set(), "an uncertain latest row is conservative")
        self.fleet.mode.pop(self.V1)
        self.resync(self.V1)                        # the next group-absent contact
        self.assertEqual(self.ledger_rows(self.V1)[-1], ("refused", "group_absent"))
        self.assertNotIn(self.V1, self.recovery_set())

    def test_round3_a_recovery_read_back_of_a_groupless_node_is_a_refusal(self):
        self.nogroup.add(self.V1)
        # Resolved inside the patches, so the harness's routing wrapper runs.
        ok = self.run_patched(self.mod, lambda: self.mod.observe_winn3_node("127.0.0.1", self.V1))
        self.assertFalse(ok)
        self.assertEqual(self.last_nogroup.returncode, 4)
        self.assertEqual(self.ledger_rows(self.V1), [("refused", "group_absent")])
        self.assertNotIn(self.V1, self.recovery_set())

    def test_round3_any_confirmed_row_keeps_the_slug_whatever_its_case(self):
        with self.mod.winn3_authority_ledger() as ledger:
            ledger.execute("INSERT INTO winn3_publications (seq, node_slug, started_at, outcome, finished_at, "
                           "gateway, refusal) VALUES (1, 'LAB-ALPHA ', 1, 'confirmed', 2, '127.0.0.1', '')")
            ledger.execute("INSERT INTO winn3_publications (seq, node_slug, started_at, outcome, finished_at, "
                           "gateway, refusal) VALUES (2, 'lab-alpha', 3, 'refused', 4, '127.0.0.1', 'group_absent')")
        self.assertIn(self.V1, self.recovery_set())

    def test_round3_a_v1_node_with_a_stored_descriptor_stays_in_the_recovery_set(self):
        self.nogroup.add(self.V1)
        self.resync(self.V1)
        self.assertNotIn(self.V1, self.recovery_set())
        payload, signature = descriptor.envelope_for(descriptor.descriptor_payload(node=self.V1))
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET winn3_descriptor_json=? WHERE slug=?",
                         (json.dumps({"payload": payload, "sig": signature}), self.V1))
        self.assertIn(self.V1, self.recovery_set(), "a stored descriptor is v3 authority the hub issued")
        with self.mod.get_db() as conn, self.mod.winn3_authority_ledger() as ledger:
            self.assertNotIn(self.V1, self.mod.winn3_proven_unwritten_slugs(conn, ledger))

    def _recovering(self, saved):
        with self.mod.winn3_authority_ledger() as ledger:
            for key, value in (("recovery_since", repr(time.time() - 3600)), ("recovery_nodes", json.dumps(saved))):
                ledger.execute("INSERT OR REPLACE INTO winn3_ledger_meta (key, value) VALUES (?, ?)", (key, value))
            ledger.execute("DELETE FROM winn3_ledger_meta WHERE key='recovery_complete'")
        return patch.object(self.mod, "_winn3_trust_broken", return_value=False)

    def test_round3_saved_recovery_membership_loses_a_proven_unwritten_slug(self):
        self.nogroup.add(self.V1)
        self.resync(self.V1)
        with self._recovering([self.V1]):
            with self.mod.get_db() as conn:
                view = self.mod.winn3_recovery_state(conn, time.time())
        self.assertNotIn(self.V1, view["unrecovered"])
        # Anti-vacuity: once the latest row is uncertain, saved membership holds again.
        self.nogroup.discard(self.V1)
        self.fleet.mode[self.V1] = "lost_ack"
        self.resync(self.V1)
        with self._recovering([self.V1]):
            with self.mod.get_db() as conn:
                view = self.mod.winn3_recovery_state(conn, time.time())
        self.assertIn(self.V1, view["unrecovered"])

    def _confirm_all(self, slugs, since):
        with self.mod.get_db() as conn:
            hosts = self.mod.winn3_node_hosts(conn)
        with self.mod.winn3_authority_ledger() as ledger:
            for slug in sorted(slugs):
                seq = ledger.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM winn3_publications").fetchone()[0]
                ledger.execute(
                    "INSERT INTO winn3_publications (seq, node_slug, started_at, outcome, finished_at, "
                    "gateway, refusal) VALUES (?, ?, ?, 'confirmed', ?, ?, '')",
                    (seq, slug, since + 1, since + 2, hosts.get(slug, "")))

    def _maintain(self, saved, confirmed):
        """One epoch-maintenance pass over a recovery that began an hour ago, with `confirmed`
        read back after it began. Returns the ledger meta afterwards."""
        with self._recovering(saved):
            with self.mod.winn3_authority_ledger() as ledger:
                since = float(self.mod.winn3_ledger_meta(ledger)["recovery_since"])
            self._confirm_all(confirmed, since)
            with self.mod.get_db() as conn:
                self.mod.maintain_winn3_authority_epoch(conn)
            with self.mod.winn3_authority_ledger() as ledger:
                return self.mod.winn3_ledger_meta(ledger)

    def test_round3_epoch_maintenance_completes_recovery_without_an_excluded_saved_slug(self):
        self.nogroup.add(self.V1)
        self.resync(self.V1)
        others = self.recovery_set()
        self.assertNotIn(self.V1, others)
        meta = self._maintain(sorted(others | {self.V1}), others)
        self.assertEqual(meta.get("recovery_complete"), "1",
                         "saved membership must not hold recovery open for a proven-unwritten slug")
        # Anti-vacuity: once its latest row is uncertain the same pass cannot complete.
        self.nogroup.discard(self.V1)
        self.fleet.mode[self.V1] = "lost_ack"
        self.resync(self.V1)
        self.assertIn(self.V1, self.recovery_set())
        meta = self._maintain(sorted(others | {self.V1}), others)
        self.assertNotEqual(meta.get("recovery_complete"), "1")

    def test_round3_the_observe_pass_does_not_read_back_an_excluded_saved_slug(self):
        self.nogroup.add(self.V1)
        self.resync(self.V1)
        observed = []

        def fake(ip, slug, *args, **kwargs):
            observed.append(slug)
            return False

        def one_pass():
            with self._recovering([self.V1]), patch.object(self.mod, "observe_winn3_node", side_effect=fake):
                self.run_patched(self.mod, self.mod.reconcile_winn3_authority_ledger)

        one_pass()
        self.assertNotIn(self.V1, observed, "a proven-unwritten slug is not read back again")
        self.assertTrue(observed, "anti-vacuity: the pass does read back the nodes that still count")
        # Anti-vacuity: with an uncertain latest row the same saved slug is read back.
        self.nogroup.discard(self.V1)
        self.fleet.mode[self.V1] = "lost_ack"
        self.resync(self.V1)
        observed.clear()
        one_pass()
        self.assertIn(self.V1, observed)

    def test_a_v1_node_with_a_stored_descriptor_is_still_a_failure(self):
        payload, signature = descriptor.envelope_for(descriptor.descriptor_payload(node=self.V1))
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET winn3_descriptor_json=? WHERE slug=?",
                         (json.dumps({"payload": payload, "sig": signature}), self.V1))
        self.nogroup.add(self.V1)
        out = self.resync(self.V1)
        self.assertFalse(out["ok"], out)
        self.assertEqual(self.management(self.V1), "failed")


# ============================================================ SYNC-07 ======

class DescriptorExpiryTests(unittest.TestCase):
    def setUp(self):
        self.mod = descriptor.load_hub_with_ring()
        quiet(self.mod)
        self.addCleanup(shutil.rmtree, self.mod._TMPDIR, True)
        self.alerts = []
        self.mod.security_alert = lambda *a, **k: self.alerts.append((a, k))
        self.mod._WINN3_DESCRIPTOR_EXPIRY_ALERTED.clear()

    def seed_ttl(self, slug, *, not_after_in, ttl, protocol="winn/3"):
        iat = int(time.time()) + not_after_in - ttl
        payload, signature = descriptor.envelope_for(
            descriptor.descriptor_payload(node=slug, iat=iat, ttl=ttl))
        descriptor.seed_node(
            self.mod, slug=slug, protocol_version=protocol, protocol_params_json="{}",
            descriptor_json=json.dumps({"payload": payload, "sig": signature}))

    def test_expiring_and_expired_descriptors_alert_once_at_priority_two(self):
        self.seed_ttl("lab-alpha", not_after_in=3 * 86400, ttl=20 * 86400)
        self.seed_ttl("lab-beta", not_after_in=-600, ttl=86400)
        self.seed_ttl("lab-gamma", not_after_in=20 * 86400, ttl=25 * 86400)
        self.seed_ttl("lab-delta", not_after_in=3600, ttl=86400, protocol="winn/1")
        out = self.mod.audit_fleet_availability_once()
        states = {item["slug"]: item["state"] for item in out["winn3_descriptor_expiry"]}
        self.assertEqual(states, {"lab-alpha": "expiring", "lab-beta": "expired"})
        events = sorted((a[1], k["details"]["slug"], a[0]) for a, k in self.alerts
                        if a[0] == 2 and a[1].startswith("winn3 descriptor"))
        self.assertEqual(events, [
            ("winn3 descriptor expired", "lab-beta", 2),
            ("winn3 descriptor expires soon", "lab-alpha", 2),
        ])
        before = len([a for a, _ in self.alerts if a[1].startswith("winn3 descriptor")])
        self.mod.audit_fleet_availability_once()
        self.assertEqual(len([a for a, _ in self.alerts if a[1].startswith("winn3 descriptor")]), before,
                         "one alert per descriptor per day")

    def test_a_closed_node_never_mails_about_its_descriptor(self):
        self.seed_ttl("lab-alpha", not_after_in=-600, ttl=86400)
        self.seed_ttl("lab-beta", not_after_in=3 * 86400, ttl=20 * 86400)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=0")
        out = self.mod.audit_fleet_availability_once()
        self.assertNotIn("winn3_descriptor_expiry", out)
        self.assertEqual([a for a, _ in self.alerts if a[1].startswith("winn3 descriptor")], [])

    def test_no_warning_while_auto_renewal_still_has_its_first_day(self):
        # winn3_auto_provision() renews under 7 days left; the warning waits a day.
        self.seed_ttl("lab-alpha", not_after_in=6 * 86400 + 3600, ttl=14 * 86400)
        self.seed_ttl("lab-beta", not_after_in=6 * 86400 - 3600, ttl=14 * 86400)
        out = self.mod.audit_fleet_availability_once()
        states = {item["slug"]: item["state"] for item in out["winn3_descriptor_expiry"]}
        self.assertEqual(states, {"lab-beta": "expiring"})

    def test_a_forged_descriptor_reports_nothing(self):
        self.seed_ttl("lab-alpha", not_after_in=3600, ttl=86400)
        with self.mod.get_db() as conn:
            raw = json.loads(conn.execute(
                "SELECT winn3_descriptor_json FROM nodes WHERE slug='lab-alpha'").fetchone()[0])
            payload = json.loads(base64.b64decode(raw["payload"]))
            payload["not_after"] += 1
            raw["payload"] = base64.b64encode(json.dumps(
                payload, sort_keys=True, separators=(",", ":")).encode()).decode()
            conn.execute("UPDATE nodes SET winn3_descriptor_json=? WHERE slug='lab-alpha'",
                         (json.dumps(raw),))
        out = self.mod.audit_fleet_availability_once()
        self.assertNotIn("winn3_descriptor_expiry", out)
        self.assertEqual(self.mod.winn3_descriptor_expiry(
            descriptor.node_row(self.mod, "lab-alpha"))["state"], "none")

    def test_result_shape_is_unchanged_when_nothing_expires(self):
        self.seed_ttl("lab-alpha", not_after_in=20 * 86400, ttl=25 * 86400)
        out = self.mod.audit_fleet_availability_once()
        self.assertEqual(set(out) - {"open_without_promotion_evidence"}, {"registered", "servable"})

    def test_listing_shows_not_after_even_for_an_expired_descriptor(self):
        self.seed_ttl("lab-alpha", not_after_in=-600, ttl=86400)
        self.seed_ttl("lab-beta", not_after_in=20 * 86400, ttl=25 * 86400)
        listing = {e["slug"]: e for e in descriptor.admin_list_descriptors(self.mod)["nodes"]}
        self.assertEqual(listing["lab-alpha"]["descriptor_expiry_state"], "expired")
        self.assertFalse(listing["lab-alpha"]["descriptor_valid"])
        self.assertIsInstance(listing["lab-alpha"]["descriptor_not_after"], int)
        self.assertLess(listing["lab-alpha"]["descriptor_seconds_left"], 0)
        self.assertEqual(listing["lab-beta"]["descriptor_expiry_state"], "ok")


# ============================================================ SYNC-24 ======

class ManagementNameKeyTests(unittest.TestCase):
    def load(self, **env):
        os.environ.pop("MANAGEMENT_NAME_HMAC_KEY", None)
        mod = harness.load_hub(**env)
        quiet(mod)
        self.addCleanup(shutil.rmtree, mod._TMPDIR, True)
        os.environ.pop("MANAGEMENT_NAME_HMAC_KEY", None)
        return mod

    def names(self, mod):
        return (mod.node_management_hostname("lab-alpha"),
                mod.core_management_hostname("north-america-core"),
                mod.core_assignment_revision({"device_id": "d1", "core_id": "c"}))

    def test_rotating_the_rate_limit_secret_keeps_every_management_name(self):
        old = self.names(self.load(RATE_LIMIT_SECRET="r" * 64))
        kept = self.names(self.load(RATE_LIMIT_SECRET="s" * 64, MANAGEMENT_NAME_HMAC_KEY="r" * 64))
        self.assertEqual(old, kept)
        # Anti-vacuity: the key really drives the names.
        moved = self.names(self.load(RATE_LIMIT_SECRET="r" * 64, MANAGEMENT_NAME_HMAC_KEY="s" * 64))
        self.assertNotEqual(old[0], moved[0])
        self.assertNotEqual(old[1], moved[1])
        self.assertNotEqual(old[2], moved[2])

    def installer_seed(self, env):
        source = HUB_INSTALLER.read_text(encoding="utf-8")
        body = source.split("\nwrite_env() {", 1)[1]
        start = body.index('  rate_limit_secret="${RATE_LIMIT_SECRET:-}"')
        end = body.index('[[ -n "${management_name_hmac_key}" ]] || management_name_hmac_key="${rate_limit_secret}"')
        snippet = body[start:end] + '[[ -n "${management_name_hmac_key}" ]] || management_name_hmac_key="${rate_limit_secret}"\n'
        snippet = snippet.replace("  local management_name_hmac_key\n", "")
        self.assertIn('write_env_kv MANAGEMENT_NAME_HMAC_KEY "${management_name_hmac_key}"', body)
        script = snippet + 'printf "%s\\n" "${management_name_hmac_key}"\n'
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("RATE_LIMIT_SECRET", "MANAGEMENT_NAME_HMAC_KEY")}
        clean.update(env)
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              env=clean, check=True).stdout.strip()

    def test_installer_seeds_once_from_the_rate_limit_secret_then_keeps_it(self):
        self.assertEqual(self.installer_seed({"RATE_LIMIT_SECRET": "r" * 64}), "r" * 64)
        self.assertEqual(self.installer_seed(
            {"RATE_LIMIT_SECRET": "s" * 64, "MANAGEMENT_NAME_HMAC_KEY": "r" * 64}), "r" * 64)


# ============================================================ SYNC-25 ======

class ServedCoreIdTests(unittest.TestCase):
    def setUp(self):
        self.mod = harness.load_hub(DOUBLE_VPN_CORE_ID="north-america-core")
        quiet(self.mod)
        self.addCleanup(shutil.rmtree, self.mod._TMPDIR, True)
        self.mod.security_alert = lambda *a, **k: None

    def mint(self, role, subject):
        payload = types.SimpleNamespace(role=role, subject_id=subject, ttl_seconds=600)
        return self.mod.mint_bootstrap_grant(
            payload, harness.FakeRequest(path="/admin/bootstrap-grant"),
            x_admin_token="test-admin-token")

    def test_grant_for_another_core_id_is_refused_naming_both(self):
        with self.assertRaises(harness.HTTPException) as caught:
            self.mint("core", "aicore-core0")
        self.assertEqual(caught.exception.status_code, 409)
        self.assertIn("north-america-core", caught.exception.detail)
        self.assertIn("aicore-core0", caught.exception.detail)
        self.assertTrue(self.mint("core", "north-america-core")["ok"])
        self.assertTrue(self.mint("node", "aicore-core0")["ok"], "node grants are unaffected")

    def test_operator_tool_prints_the_hub_detail(self):
        tool = (REPO / "tools" / "wins_operator_prepare_subject.sh").read_text(encoding="utf-8")
        line = next(l for l in tool.splitlines() if "refused to mint a bootstrap grant" in l)
        self.assertIn(".detail", line)


# ============================================================ SYNC-04 ======

def keepalive_functions() -> str:
    source = HUB_INSTALLER.read_text(encoding="utf-8")
    start = source.index("# IA-SYNC SYNC-04: the health-forging keepalive.")
    end = source.index("\n# Owned-paths manifest (lane L51 C4)", start)
    return source[start:end]


def installer_function(source: str, name: str) -> str:
    head = f"\n{name}() {{\n"
    assert source.count(head) == 1, name
    start = source.index(head) + 1
    return source[start:source.index("\n}\n", start) + 3]


def deploy_env_functions() -> str:
    """FU-SYNCHUB: write_env's own environment steps, which the coverage gate now runs
    (the operator-intent capture done at start-up, then the functions write_env calls)."""
    source = HUB_INSTALLER.read_text(encoding="utf-8")
    begin = source.index("# --- begin IA-CP-01 operator intent capture ---")
    parts = [source[begin:source.index("# --- end IA-CP-01 operator intent capture ---", begin)]]
    parts += [installer_function(source, name) for name in (
        "wins_require_trusted_env_file", "overlay_wins_secrets_file", "load_existing_envs",
        "load_env_file_as_data", "wins_runtime_owned_key", "snapshot_operator_intent",
        "reapply_operator_intent")]
    parts.append("declare -A WINS_OPERATOR_INTENT_PENDING=()\ndeclare -A WINS_OPERATOR_INTENT_OWNED=()\n")
    return "\n".join(parts)


# The real trust check needs GNU stat and root ownership (it runs as root on the hub); on a
# developer machine the file is the tester's. This stand-in keeps its first rule only.
TRUST_STUB = ('wins_require_trusted_env_file() { [[ -f "$1" && ! -L "$1" ]] || '
              '{ echo "[ERR] $2 must be a real regular file: $1" >&2; exit 1; }; }\n')


def bash5() -> str:
    for candidate in (shutil.which("bash"), "/bin/bash", "/usr/bin/bash"):
        if not candidate:
            continue
        out = subprocess.run([candidate, "-c", "echo ${BASH_VERSINFO[0]}"],
                             capture_output=True, text=True).stdout.strip()
        if out.isdigit() and int(out) >= 4:
            return candidate
    raise RuntimeError("bash 4 or newer is required (the installer targets bash 5)")


CRONTAB_SHIM = r"""#!/usr/bin/env bash
spool="${WINS_KEEPALIVE_ROOT}/var/spool/cron/crontabs"
echo "crontab $*" >> "${WINS_KEEPALIVE_ROOT}/crontab.calls"
[[ "$1" == "-u" ]] || exit 2
user="$2"; shift 2
if [[ "$1" == "-l" ]]; then
  [[ -f "${spool}/${user}" ]] || exit 1
  grep -v '^# DO NOT EDIT' "${spool}/${user}"
  exit 0
fi
cat "$1" > "${spool}/${user}"
"""

KEEPALIVE_LINE = "* * * * * root /usr/bin/python3 /root/vpn_auth/keepalive_nodes.py >/dev/null 2>&1"

# Turn 4: a small model of systemd, so a stop, its verification and a failure of either
# can be told apart. State lives under $WINS_KEEPALIVE_ROOT/systemd/:
#   active/<unit>      the unit is active          stuck/<unit>       stop returns 0, unit stays active
#   stopfail/<unit>    stop (and disable --now) fail  triggers/<unit>  what a timer triggers
#   reactivate/<unit>  a daemon-reload makes it active again   fail/<verb>  that verb fails
# disable removes a linked unit's link under /etc/systemd/system, as systemd does.
# FU-SYNCHUB adds identity: alias/<name> holds the unit's Id (default: the name),
# mainpid/<id> its MainPID (default 0), dropins/<id> its DropInPaths, and
# onreload/<pid>/ a fake /proc entry that appears at the next daemon-reload, and
# transient/<pid> (seconds) one that then disappears that long after the reload.
# Turn 7: names/<id> holds the unit's Names (its Id and aliases; default: the Id), and
# failprop/<A,B> makes `show -p A,B` fail (systemd stops answering that one query).
# `show` answers every property asked for (-p A,B), as Name=value or, with --value, bare.
SYSTEMCTL_SHIM = r"""#!/usr/bin/env bash
echo "systemctl $*" >> "${WINS_KEEPALIVE_ROOT}/systemctl.calls"
echo "systemctl $*" >> "${WINS_KEEPALIVE_ROOT}/events"
st="${WINS_KEEPALIVE_ROOT}/systemd"
[[ -e "${st}/fail/$1" ]] && exit 1
[[ "$1" == show && -e "${st}/failprop/$3" ]] && exit 1
stop_unit() { [[ -e "${st}/stopfail/$1" ]] && exit 1; [[ -e "${st}/stuck/$1" ]] || rm -f "${st}/active/$1"; }
case "$1" in
  stop) stop_unit "$2" ;;
  disable)
    u="${!#}"
    [[ -L "${WINS_KEEPALIVE_ROOT}/etc/systemd/system/${u}" ]] && rm -f "${WINS_KEEPALIVE_ROOT}/etc/systemd/system/${u}"
    [[ "$2" == --now ]] && stop_unit "$3" ;;
  daemon-reload)
    for f in "${st}"/reactivate/*; do [[ -e "${f}" ]] && touch "${st}/active/${f##*/}"; done
    for f in "${st}"/onreload/*; do [[ -d "${f}" ]] && cp -R "${f}" "${WINS_KEEPALIVE_ROOT}/proc/${f##*/}"; done
    for f in "${st}"/transient/*; do
      [[ -e "${f}" ]] && { sleep "$(cat "${f}")"; rm -rf "${WINS_KEEPALIVE_ROOT}/proc/${f##*/}"; } >/dev/null 2>&1 &
    done ;;
  show)
    u="${!#}"
    id="$(cat "${st}/alias/${u}" 2>/dev/null || printf '%s' "${u}")"
    IFS=, read -r -a props <<<"$3"
    for p in "${props[@]}"; do
      case "${p}" in
        ActiveState) if [[ -e "${st}/active/${u}" ]]; then v=active; else v=inactive; fi ;;
        Triggers) v="$(cat "${st}/triggers/${u}" 2>/dev/null)" ;;
        Id) v="${id}" ;;
        MainPID) v="$(cat "${st}/mainpid/${id}" 2>/dev/null || echo 0)" ;;
        DropInPaths) v="$(cat "${st}/dropins/${id}" 2>/dev/null)" ;;
        Names) v="$(cat "${st}/names/${id}" 2>/dev/null || printf '%s' "${id}")" ;;
        *) v="" ;;
      esac
      if [[ " $* " == *" --value "* ]]; then printf '%s\n' "${v}"; else printf '%s=%s\n' "${p}" "${v}"; fi
    done ;;
esac
exit 0
"""

# A stand-in for the kill builtin (a shell function wins over a builtin): a signalled fake
# process disappears from the fake /proc unless it is listed in immortal/ (or becomes a zombie,
# zombify/; respawn/<pid> holds the PID of a copy that appears in its place). Fake PIDs are above the largest Linux pid_max (2^22), so a real kill could
# never reach a real process.
KILL_SHIM = r"""kill() {
  echo "kill $*" >> "${WINS_KEEPALIVE_ROOT}/kill.calls"
  echo "kill $*" >> "${WINS_KEEPALIVE_ROOT}/events"
  [[ "$1" == -s ]] && shift 2
  local pid
  for pid in "$@"; do
    if [[ -s "${WINS_KEEPALIVE_ROOT}/respawn/${pid}" ]]; then
      cp -R "${WINS_KEEPALIVE_ROOT}/proc/${pid}" "${WINS_KEEPALIVE_ROOT}/proc/$(cat "${WINS_KEEPALIVE_ROOT}/respawn/${pid}")"
    fi
    if [[ -e "${WINS_KEEPALIVE_ROOT}/zombify/${pid}" ]]; then
      printf 'State:\tZ (zombie)\nPPid:\t1\n' > "${WINS_KEEPALIVE_ROOT}/proc/${pid}/status"
    elif [[ ! -e "${WINS_KEEPALIVE_ROOT}/immortal/${pid}" ]]; then
      rm -rf "${WINS_KEEPALIVE_ROOT}/proc/${pid}"
    fi
  done
  return 0
}
"""


class HealthKeepaliveTests(unittest.TestCase):
    def setUp(self):
        self.bash = bash5()
        self.root = tempfile.mkdtemp(prefix="wins-keepalive-")
        self.addCleanup(shutil.rmtree, self.root, True)
        for d in ("etc/cron.d", "var/spool/cron/crontabs", "root/vpn_auth", "etc/systemd/system",
                  "shims", "opt/wins"):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        shim = os.path.join(self.root, "shims", "crontab")
        Path(shim).write_text(CRONTAB_SHIM)
        os.chmod(shim, stat.S_IRWXU)
        systemctl = os.path.join(self.root, "shims", "systemctl")
        Path(systemctl).write_text(SYSTEMCTL_SHIM)
        os.chmod(systemctl, stat.S_IRWXU)

    def write(self, rel, text, mode=0o644):
        os.makedirs(os.path.dirname(os.path.join(self.root, rel)), exist_ok=True)
        path = os.path.join(self.root, rel)
        Path(path).write_text(text)
        os.chmod(path, mode)
        return path

    def run_fn(self, fn, **env):
        script = (
            "set -Eeuo pipefail\n"
            "log() { echo \"LOG $*\"; }\nwarn() { echo \"WARN $*\"; }\nerr() { echo \"ERR $*\"; }\n"
            + deploy_env_functions() + "\n" + keepalive_functions() + f"\n{fn}\n"
        )
        full = dict(os.environ, WINS_KEEPALIVE_ROOT=self.root,
                    PATH=os.path.join(self.root, "shims") + os.pathsep + os.environ.get("PATH", ""))
        full.update(env)
        return subprocess.run([self.bash, "-c", script], capture_output=True, text=True, env=full)

    def seed_everything(self):
        self.write("root/vpn_auth/keepalive_nodes.py", "print('forge')\n", 0o755)
        self.write("opt/wins/keepalive_nodes.py", "print('forge copy')\n", 0o755)
        self.write("etc/cron.d/wins-keepalive", "SHELL=/bin/bash\n" + KEEPALIVE_LINE + "\n")
        self.write("etc/crontab", "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
                   + "*/2 * * * * root /usr/bin/python3 /opt/wins/keepalive_nodes.py\n")
        self.write("var/spool/cron/crontabs/root",
                   "# DO NOT EDIT THIS FILE\n0 3 * * * /usr/local/bin/wins-backup\n"
                   "* * * * * python3 /root/vpn_auth/keepalive_nodes.py\n", 0o600)
        self.write("etc/systemd/system/keepalive.service",
                   "[Service]\nExecStart=/usr/bin/python3 /root/vpn_auth/keepalive_nodes.py\n")

    def quarantine(self):
        base = os.path.join(self.root, "var/backups/winsvpn-retired")
        dirs = [d for d in os.listdir(base) if d.startswith("keepalive-")]
        self.assertEqual(len(dirs), 1)
        return os.path.join(base, dirs[0])

    def test_deploy_quarantines_every_runner_and_script_and_keeps_other_lines(self):
        self.seed_everything()
        out = self.run_fn("retire_health_forging_keepalive")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        root = self.root
        self.assertFalse(os.path.exists(f"{root}/root/vpn_auth/keepalive_nodes.py"))
        self.assertFalse(os.path.exists(f"{root}/opt/wins/keepalive_nodes.py"))
        self.assertFalse(os.path.exists(f"{root}/etc/cron.d/wins-keepalive"))
        crontab = Path(f"{root}/etc/crontab").read_text()
        self.assertNotIn("keepalive_nodes", crontab)
        self.assertIn("run-parts --report /etc/cron.hourly", crontab)
        spool = Path(f"{root}/var/spool/cron/crontabs/root").read_text()
        self.assertNotIn("keepalive_nodes", spool)
        self.assertIn("/usr/local/bin/wins-backup", spool)
        self.assertIn("crontab -u root -l", Path(f"{root}/crontab.calls").read_text(),
                      "a user crontab is changed through crontab(1)")
        q = self.quarantine()
        self.assertEqual(stat.S_IMODE(os.stat(q).st_mode), 0o700)
        kept = os.listdir(q)
        self.assertIn("_root_vpn_auth_keepalive_nodes.py", kept)
        self.assertIn("_etc_cron.d_wins-keepalive.removed", kept)
        self.assertIn("crontab-root", kept)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(q, "_root_vpn_auth_keepalive_nodes.py")).st_mode), 0o600)
        # Round 3: a forging unit is stopped, disabled and quarantined.
        self.assertFalse(os.path.exists(f"{root}/etc/systemd/system/keepalive.service"))
        calls = Path(f"{root}/systemctl.calls").read_text()
        self.assertIn("systemctl disable --now keepalive.service", calls)
        self.assertIn("systemctl daemon-reload", calls)
        self.assertIn("a rescan finds nothing that forges", out.stdout)
        # A second run finds nothing left to do.
        again = self.run_fn("retire_health_forging_keepalive")
        self.assertIn("no keepalive_nodes script or runner found", again.stdout)

    def test_report_only_changes_nothing(self):
        self.seed_everything()
        before = sorted(str(p.relative_to(self.root)) for p in Path(self.root).rglob("*"))
        for fn, env in (("report_health_forging_keepalive", {}),):
            out = self.run_fn(fn, **env)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("SECURITY: health-forging keepalive script at /root/vpn_auth/keepalive_nodes.py",
                          out.stdout)
            self.assertIn("cron at /etc/cron.d/wins-keepalive", out.stdout)
            after = sorted(str(p.relative_to(self.root)) for p in Path(self.root).rglob("*"))
            self.assertEqual(before, after, fn)
            self.assertIn("keepalive_nodes", Path(self.root, "etc/crontab").read_text())

    def main_like(self, **env):
        return self.run_fn("deploy() { retire_health_forging_keepalive || return 1; echo DEPLOY-CONTINUED; }\n"
                           "deploy", **env)

    def shim(self, name, body):
        path = os.path.join(self.root, "shims", name)
        Path(path).write_text("#!/usr/bin/env bash\n" + body + "\n")
        os.chmod(path, stat.S_IRWXU)

    def test_round2_a_failed_move_stops_the_deploy_in_the_production_call_shape(self):
        self.seed_everything()
        self.shim("mv", 'for a; do case "$a" in *keepalive_nodes*) echo "mv: Permission denied" >&2; exit 1;; esac; done\n'
                  'exec /bin/mv "$@"')
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("cannot move", out.stdout)
        self.assertNotIn("quarantined the health-forging keepalive script", out.stdout)

    def test_round2_a_failed_rewrite_stops_the_deploy(self):
        self.seed_everything()
        self.shim("mktemp", 'case "$*" in *wins-keepalive*) echo "mktemp: mkstemp failed" >&2; exit 1;; esac\n'
                  'exec /usr/bin/mktemp "$@"')
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertNotIn("removed the health-forging keepalive line(s)", out.stdout)
        self.assertIn("cannot stage a rewrite of /etc/cron.d/wins-keepalive", out.stdout,
                      "the failing step is named")
        self.assertIn("keepalive_nodes", Path(self.root, "etc/crontab").read_text())

    def test_round2_a_move_that_silently_does_nothing_is_caught_by_the_rescan(self):
        self.write("root/vpn_auth/keepalive_nodes.py", "print('forge')\n", 0o755)
        self.shim("mv", "exit 0")
        self.shim("chmod", "exit 0")
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("still in place after retirement", out.stdout)

    def test_round2_scripts_named_only_by_a_unit_or_periodic_job_are_quarantined(self):
        self.write("opt/keepalive_nodes.py", "print('forge')\n", 0o755)
        self.write("opt/wins/keepalive_nodes_daily.sh", "echo forge\n", 0o755)
        self.write("etc/systemd/system/forge.service",
                   "[Service]\nExecStart=/usr/bin/python3 /opt/keepalive_nodes.py\n")
        self.write("etc/cron.daily/forge", "#!/bin/sh\n/opt/wins/keepalive_nodes_daily.sh\n", 0o755)
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        for gone in ("opt/keepalive_nodes.py", "opt/wins/keepalive_nodes_daily.sh",
                     "etc/systemd/system/forge.service", "etc/cron.daily/forge"):
            self.assertFalse(os.path.exists(os.path.join(self.root, gone)), gone)

    def test_round2_a_symlinked_script_is_moved_and_its_target_kept(self):
        self.write("opt/real_forger.py", "print('forge')\n", 0o755)
        os.symlink(os.path.join(self.root, "opt/real_forger.py"),
                   os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py"))
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(os.path.lexists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")))
        self.assertTrue(os.path.exists(os.path.join(self.root, "opt/real_forger.py")), "never follow the link")
        self.assertTrue(os.path.islink(os.path.join(self.quarantine(), "_root_vpn_auth_keepalive_nodes.py")))

    # ---- round 3: the release gate (OI-SYNC_HUB-1)
    PROBE = "#!/usr/bin/env bash\nexit 0\n"

    def seed_hub_db(self, rows, canary_nodes="", canary_slug="", probe=True, keys=("alpha",),
                    stale_minutes=None, probe_mode=0o755):
        """rows: (slug, operator_enabled, canary_status, checked_minutes_ago[, ok_minutes_ago]).
        ok_minutes_ago defaults to checked_minutes_ago."""
        db = os.path.join(self.root, "root/vpn_auth/vpn_users.db")
        now = datetime.now(timezone.utc)
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE nodes (slug TEXT, protocol_version TEXT, retired_at TEXT,"
                         " operator_enabled INTEGER, winn3_canary_status TEXT, winn3_canary_checked_at TEXT,"
                         " winn3_canary_ok_at TEXT, winn3_descriptor_json TEXT, winn3_identity_sha256 TEXT,"
                         " deployment_generation INTEGER, winn3_canary_identity_sha256 TEXT,"
                         " winn3_canary_seq INTEGER, winn3_canary_generation INTEGER, deployment_completed_at TEXT,"
                         " deployment_released_at TEXT, winn3_carrier_flipped_at TEXT)")
            # H3: coverage needs a result bound to the row's identity, sequence and generation.
            payload = base64.b64encode(json.dumps({"seq": 7}).encode()).decode()
            envelope = json.dumps({"payload": payload, "sig": ""})
            for slug, enabled, status, ago, *rest in rows:
                at = (now - timedelta(minutes=ago)).isoformat() if ago is not None else None
                ok_ago = rest[0] if rest else ago
                ok_at = (now - timedelta(minutes=ok_ago)).isoformat() if ok_ago is not None else None
                # The proof must also follow the release, the flip and the completion.
                before = (now - timedelta(minutes=ok_ago + 5)).isoformat() if ok_ago is not None else None
                conn.execute("INSERT INTO nodes VALUES (?, 'winn/3', NULL, ?, ?, ?, ?, ?, ?, 3, ?, 7, 3, ?, ?, ?)",
                             (slug, enabled, status, at, ok_at, envelope, "a" * 64, "a" * 64,
                              before, before, before))
            conn.execute("INSERT INTO nodes VALUES ('v1-node', 'winn/1', NULL, 1, 'unknown', NULL, NULL,"
                         " NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL)")
        env = []
        if canary_nodes:
            env.append(f"WINN3_CANARY_NODES='{canary_nodes}'")
        if canary_slug:
            env += [f"WINN3_CANARY_NODE_SLUG='{canary_slug}'", f"WINN3_CANARY_KEY_DIR='/etc/winn/canary/{canary_slug}'",
                    "WINN3_CANARY_GATEWAY_ENDPOINT='198.51.100.7:51820'", "WINN3_CANARY_GATEWAY_ID='gid'",
                    "WINN3_CANARY_INNER_V4='10.10.0.9'"]
        if stale_minutes is not None:
            env.append(f"WINN3_CANARY_HARD_STALE_MINUTES='{stale_minutes}'")
        Path(self.root, "root/vpn_auth.env").write_text("\n".join(env) + "\n")
        if probe:
            self.write("usr/local/bin/winn3-probe", self.PROBE, probe_mode)
        for slug in keys:
            for name in ("client.key", "static.pub", "admission.key"):
                self.write(f"etc/winn/canary/{slug}/{name}", "k\n", 0o600)

    def entry(self, slug):
        return f"{slug}|cGs=|10.10.0.9|/etc/winn/canary/{slug}|198.51.100.7:51820|gid"

    def tree_digest(self):
        out = []
        for p in sorted(Path(self.root).rglob("*")):
            rel = str(p.relative_to(self.root))
            if rel.startswith(("shims", "crontab.calls", "systemctl.calls", "events")):  # events: the model's call log
                continue
            out.append((rel, p.read_bytes() if p.is_file() and not p.is_symlink() else b""))
        return out

    def test_round3_gate_refuses_before_any_write_and_names_each_slug(self):
        cases = {
            "no canary binding": dict(rows=[("alpha", 1, "ok", 1)]),
            "probe /usr/local/bin/winn3-probe is missing": dict(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha", probe=False),
            "probe /usr/local/bin/winn3-probe is missing or not executable": dict(
                rows=[("alpha", 1, "ok", 1)], canary_slug="alpha", probe_mode=0o644),
            "key_dir /etc/winn/canary/alpha lacks": dict(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha", keys=()),
            "no fresh canary verdict (status ok)": dict(rows=[("alpha", 1, "ok", 45)], canary_slug="alpha"),
            "no fresh canary verdict (status failed)": dict(rows=[("alpha", 1, "failed", 1)], canary_slug="alpha"),
        }
        for reason, kw in cases.items():
            with self.subTest(reason=reason):
                self.setUp()
                self.seed_everything()
                self.seed_hub_db(**kw)
                before = self.tree_digest()
                out = self.main_like()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("UNCOVERED alpha", out.stdout)
                self.assertIn(reason, out.stdout)
                self.assertIn("refusing to retire the keepalive", out.stdout)
                self.assertEqual(self.tree_digest(), before, "the gate writes nothing")

    def test_round3_a_probe_that_does_not_run_is_not_coverage(self):
        self.seed_everything()
        self.PROBE = "#!/no/such/interpreter\n"
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha")
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("does not run", out.stdout)

    def test_round3_what_counts_as_a_probe_that_runs(self):
        # -h exiting 0 or 2 (Go's flag package) runs; 126 and 127 (the shell could not exec it) and a
        # death by signal do not.
        cases = (("exit 0", True), ("exit 2", True), ("exit 126", False), ("exit 127", False), ("kill -9 $$", False))
        for body, runs in cases:
            with self.subTest(body=body):
                self.setUp()
                self.seed_everything()
                self.PROBE = f"#!/usr/bin/env bash\n{body}\n"
                self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha")
                out = self.main_like()
                if runs:
                    self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                else:
                    self.assertNotEqual(out.returncode, 0, out.stdout)
                    self.assertIn("does not run (rc ", out.stdout)

    def test_round3_full_coverage_retires_and_closed_slugs_are_not_counted(self):
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1), ("beta", 0, "unknown", None), ("gone", 1, "unknown", None)],
                         canary_nodes=self.entry("alpha"))
        with sqlite3.connect(os.path.join(self.root, "root/vpn_auth/vpn_users.db")) as conn:
            conn.execute("UPDATE nodes SET retired_at='2026-01-01T00:00:00+00:00' WHERE slug='gone'")
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("every open winn/3 slug has a real external canary", out.stdout)
        self.assertIn("SUMMARY open=1 covered=1 uncovered=none", out.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")))

    def test_round3_one_uncovered_slug_among_covered_ones_stops_the_deploy(self):
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1), ("gamma", 1, "ok", 1)],
                         canary_nodes=self.entry("alpha"))
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("UNCOVERED gamma no canary binding", out.stdout)
        self.assertIn("uncovered=gamma", out.stdout)

    def test_round3_force_retires_anyway_and_says_so(self):
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], probe=False, keys=())
        for value in ("0", "yes", "true"):
            with self.subTest(value=value):
                out = self.main_like(HUB_RETIRE_HEALTH_KEEPALIVE_FORCE=value)
                self.assertNotEqual(out.returncode, 0, "only the exact value 1 forces")
        out = self.main_like(HUB_RETIRE_HEALTH_KEEPALIVE_FORCE="1")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("HUB_RETIRE_HEALTH_KEEPALIVE_FORCE=1: retiring the keepalive anyway", out.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")))

    def test_round3_an_unreadable_database_stops_the_deploy(self):
        self.seed_everything()
        self.write("root/vpn_auth/vpn_users.db", "this is not sqlite\n")
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("ERROR database unreadable", out.stdout)

    def test_round3_preflight_previews_the_gate(self):
        # Turn 4b (Seat C N-12): the preview of a refusing gate is now a non-zero status.
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], probe=False)
        out = self.run_fn("report_health_forging_keepalive")
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("Health keepalive gate (preview): UNCOVERED alpha", out.stdout)

    # ---- Turn 4b: the gate reads the binding the deploy will write (Seat C N-10)
    def env_file(self, *lines):
        Path(self.root, "root/vpn_auth.env").write_text("".join(line + "\n" for line in lines))

    def test_turn4b_a_binding_given_to_the_installer_is_coverage(self):
        # Seat C's probe p_gate_env.py: the first rollout supplies the binding in the
        # installer's environment; nothing is in the env file yet.
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
        self.env_file()
        out = self.main_like(WINN3_CANARY_NODES=self.entry("alpha"), WINN3_CANARY_BIN="/usr/local/bin/winn3-probe")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("SUMMARY open=1 covered=1 uncovered=none", out.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")))

    def test_turn4b_no_binding_anywhere_still_refuses(self):
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
        self.env_file()
        out = self.main_like(WINN3_CANARY_NODES="")
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("UNCOVERED alpha no canary binding", out.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")))

    def test_turn4b_a_given_value_wins_over_the_file_and_an_empty_one_does_not(self):
        bad = "alpha|cGs=|10.10.0.9|/etc/winn/canary/none|198.51.100.7:51820|gid"
        for given, covered in ((self.entry("alpha"), True), ("", False)):
            with self.subTest(given=given):
                self.setUp()
                self.seed_everything()
                self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
                self.env_file(f"WINN3_CANARY_NODES='{bad}'")
                out = self.run_fn("health_keepalive_canary_coverage", WINN3_CANARY_NODES=given)
                if covered:
                    self.assertIn("COVERED alpha", out.stdout.splitlines(), out.stdout)
                else:
                    self.assertIn("key_dir /etc/winn/canary/none lacks", out.stdout, "the file's binding is read")

    def test_turn4b_the_env_file_is_read_with_the_installers_own_quoting(self):
        # Seat C's probe p_envquote.py: the installer reads this file with bash source.
        entry = self.entry("alpha")
        cases = {
            "single quotes (the installer's writer)": f"WINN3_CANARY_NODES='{entry}'",
            "double quotes (a hand edit)": f'WINN3_CANARY_NODES="{entry}"',
            "export and double quotes": f'export WINN3_CANARY_NODES="{entry}"',
            "set twice, the last wins": f"WINN3_CANARY_NODES='nobody|x|y|z|w|v'\nWINN3_CANARY_NODES=\"{entry}\"",
        }
        for label, line in cases.items():
            with self.subTest(label=label):
                self.setUp()
                self.seed_everything()
                self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
                self.env_file(line)
                out = self.run_fn("health_keepalive_canary_coverage")
                self.assertIn("COVERED alpha", out.stdout.splitlines(), out.stdout)
        self.setUp()
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
        self.env_file(f"# WINN3_CANARY_NODES='{entry}'")
        out = self.run_fn("health_keepalive_canary_coverage")
        self.assertIn("UNCOVERED alpha no canary binding", out.stdout, "anti-vacuity: a comment binds nothing")
        # Unquoted, the '|' separators are pipes to bash, so the installer itself binds nothing;
        # the gate must agree with it (the old line parser called this covered).
        self.setUp()
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
        self.env_file(f"WINN3_CANARY_NODES={entry}")
        out = self.run_fn("health_keepalive_canary_coverage")
        self.assertIn("UNCOVERED alpha no canary binding", out.stdout)

    # ---- Turn 4b: --preflight fails when the deploy would refuse (Seat C N-12)
    def test_turn4b_the_preview_passes_only_when_the_deploy_would_retire(self):
        cases = (
            ("uncovered", dict(rows=[("alpha", 1, "ok", 1), ("beta", 1, "ok", 1)], probe=False), {}, 1),
            ("covered", dict(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha"), {}, 0),
            ("forced", dict(rows=[("alpha", 1, "ok", 1)], probe=False), {"HUB_RETIRE_HEALTH_KEEPALIVE_FORCE": "1"}, 0),
            ("no database", None, {}, 0),
        )
        for label, db, env, rc in cases:
            with self.subTest(case=label):
                self.setUp()
                self.seed_everything()
                if db is not None:
                    self.seed_hub_db(**db)
                out = self.run_fn("report_health_forging_keepalive", **env)
                self.assertEqual(out.returncode, rc, out.stdout)
                if rc:
                    self.assertIn("a deploy would refuse to retire the health-forging keepalive", out.stdout)
                    self.assertIn("a deploy will refuse to retire it", out.stdout)
                    self.assertNotIn("a deploy quarantines it", out.stdout)
                else:
                    self.assertIn("a deploy quarantines it", out.stdout)
                self.assertTrue(os.path.exists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")),
                                "the preview changes nothing")

    def preflight_main(self, **env):
        source = HUB_INSTALLER.read_text(encoding="utf-8")
        main = "main() {" + source.rsplit("\nmain() {", 1)[1].rsplit('\nmain "$@"', 1)[0]
        stubs = ("refuse_retired_winn_protocol_v3_enable() { :; }\nrequire_root() { :; }\npreflight_control() { :; }\n"
                 "verify_disk_encryption_posture() { echo POSTURE-CHECKED; }\ncontrol_print_disk_encryption_guarantee() { :; }\n"
                 "CONTROL_DISK_ENCRYPTION_EFFECTIVE=test\n")
        return self.run_fn(stubs + main + "\nmain --preflight\necho MAIN-RETURNED-0", **env)

    def test_turn4b_preflight_exits_non_zero_when_the_deploy_would_refuse(self):
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], probe=False)
        out = self.preflight_main()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("MAIN-RETURNED-0", out.stdout)
        self.assertIn("Control-plane preflight failed: a deploy would refuse", out.stdout)
        self.assertNotIn("preflight and disk-encryption posture checks passed", out.stdout)
        self.assertIn("POSTURE-CHECKED", out.stdout, "the other preflight checks still run")
        self.setUp()
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha")
        out = self.preflight_main()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("preflight and disk-encryption posture checks passed", out.stdout, "anti-vacuity")

    def test_round2_the_deferral_switch_is_gone(self):
        self.seed_everything()
        out = self.main_like(HUB_RETIRE_HEALTH_KEEPALIVE="0")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")))
        self.assertNotIn("HUB_RETIRE_HEALTH_KEEPALIVE:-", keepalive_functions())
        self.assertNotIn("HUB_RETIRE_HEALTH_KEEPALIVE}", keepalive_functions())

    # ---- round 3: content scan (Sol N-7, Seat C N-9)
    INLINE_FORGER = ("#!/usr/bin/env python3\nimport sqlite3\nc = sqlite3.connect('/root/vpn_auth/vpn_users.db')\n"
                     "c.execute(\"\"\"\n    UPDATE nodes SET status='online', operator_enabled=1,\n"
                     "        management_status='ok', last_heartbeat=datetime('now')\n\"\"\")\nc.commit()\n")

    def test_round3_inline_periodic_forgers_are_quarantined(self):
        self.write("etc/cron.daily/keepalive_nodes", self.INLINE_FORGER, 0o755)
        self.write("etc/cron.hourly/health", self.INLINE_FORGER, 0o755)
        self.write("etc/cron.weekly/apt-update", "#!/bin/sh\napt-get update\n", 0o755)
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/cron.daily/keepalive_nodes")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/cron.hourly/health")))
        self.assertTrue(os.path.exists(os.path.join(self.root, "etc/cron.weekly/apt-update")), "anti-vacuity")

    def test_round3_units_outside_etc_and_drop_ins_are_found(self):
        self.write("lib/systemd/system/forge.timer", "[Timer]\nOnCalendar=minutely\n# keepalive_nodes\n")
        self.write("lib/systemd/system/forge.service", "[Service]\nExecStart=/usr/bin/python3 /opt/forge/keepalive_nodes.py\n")
        self.write("opt/forge/keepalive_nodes.py", "print('forge')\n", 0o755)
        self.write("etc/systemd/system/wins-hub.service", "[Service]\nExecStart=/usr/local/bin/wins-hub\n")
        self.write("etc/systemd/system/wins-hub.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/forge2/keepalive_nodes.py\n")
        self.write("opt/forge2/keepalive_nodes.py", "print('forge')\n", 0o755)
        self.write("usr/lib/systemd/system/inline.service",
                   "[Service]\nExecStart=/usr/bin/sqlite3 /root/vpn_auth/vpn_users.db \"UPDATE nodes SET operator_enabled=1\"\n")
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        for gone in ("lib/systemd/system/forge.timer", "lib/systemd/system/forge.service", "opt/forge/keepalive_nodes.py",
                     "etc/systemd/system/wins-hub.service.d/zz.conf", "opt/forge2/keepalive_nodes.py",
                     "usr/lib/systemd/system/inline.service"):
            self.assertFalse(os.path.exists(os.path.join(self.root, gone)), gone)
        self.assertTrue(os.path.exists(os.path.join(self.root, "etc/systemd/system/wins-hub.service")),
                        "only the drop-in goes, never its parent unit")
        calls = Path(self.root, "systemctl.calls").read_text()
        self.assertIn("disable --now forge.service", calls)
        self.assertNoUnitAction(calls, "wins-hub")
        self.assertIn("daemon-reload", calls)

    def test_round3_a_lib_symlink_finds_each_unit_once(self):
        self.write("usr/lib/systemd/system/forge.service", "[Service]\nExecStart=/usr/bin/python3 /opt/f/keepalive_nodes.py\n")
        os.symlink("usr/lib", os.path.join(self.root, "lib"))
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(out.stdout.count("quarantined the health-forging systemd"), 1)

    def test_round3_forging_cron_lines_without_the_name_are_removed(self):
        self.write("etc/cron.d/inline",
                   "* * * * * root sqlite3 /root/vpn_auth/vpn_users.db \"UPDATE nodes SET operator_enabled=1\"\n"
                   "*/5 * * * * root curl -fsS -X POST https://hub.example.test/api/v1/nodes/heartbeat -d @/x\n"
                   "0 4 * * * root /usr/local/bin/wins-backup\n")
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        kept = Path(self.root, "etc/cron.d/inline").read_text()
        self.assertNotIn("UPDATE nodes", kept)
        self.assertNotIn("/heartbeat", kept)
        self.assertIn("wins-backup", kept, "anti-vacuity: the unrelated line stays")

    # ---- round 3: the gate, each component alone (OI-SYNC_HUB-1)
    def test_round3_each_missing_key_file_alone_leaves_the_slug_uncovered(self):
        files = ("client.key", "static.pub", "admission.key")
        for missing in files:
            with self.subTest(missing=missing):
                self.setUp()
                self.seed_everything()
                self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha", keys=())
                for name in files:
                    if name != missing:
                        self.write(f"etc/winn/canary/alpha/{name}", "k\n", 0o600)
                out = self.main_like()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertEqual(re.findall(r"lacks (\S+)", out.stdout), [missing], out.stdout)

    def test_round3_an_incomplete_binding_is_not_coverage(self):
        self.seed_everything()
        incomplete = "alpha|cGs=|10.10.0.9|/etc/winn/canary/alpha|198.51.100.7:51820|"
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_nodes=incomplete)
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("canary binding incomplete", out.stdout)

    def test_round3_freshness_follows_the_hub_rule_ok_at_not_checked_at(self):
        # winn3_canary_is_fresh reads winn3_canary_ok_at. A canary that keeps failing
        # keeps checked_at current and ok_at old: the hub serves such a row to nobody.
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1, 120)], canary_slug="alpha")
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("no fresh canary verdict (status ok)", out.stdout)

    def test_round3_the_stale_window_is_the_hubs_setting(self):
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 45, 45)], canary_slug="alpha")
        self.assertNotEqual(self.main_like().returncode, 0, "45 minutes is stale at the default 30")
        self.setUp()
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 45, 45)], canary_slug="alpha", stale_minutes=60)
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_round3_the_legacy_single_binding_counts_when_complete(self):
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha")
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("SUMMARY open=1 covered=1 uncovered=none", out.stdout)

    def test_round3_a_refusal_that_returns_zero_is_caught(self):
        # The refusal must reach the caller as a non-zero status in the production call shape.
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
        out = self.main_like()
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")))

    # ---- round 3: the content scan, completed (SYNC-04, Sol N-7, Seat C N-9)
    def test_round3_every_periodic_directory_is_scanned(self):
        for kind in ("hourly", "daily", "weekly", "monthly"):
            self.write(f"etc/cron.{kind}/job-{kind}", self.INLINE_FORGER, 0o755)
        self.write("etc/cron.daily/loadavg", "#!/bin/sh\ncat /proc/loadavg\n", 0o755)
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        for kind in ("hourly", "daily", "weekly", "monthly"):
            self.assertFalse(os.path.exists(os.path.join(self.root, f"etc/cron.{kind}/job-{kind}")), kind)
        self.assertTrue(os.path.exists(os.path.join(self.root, "etc/cron.daily/loadavg")), "anti-vacuity")

    def test_round3_every_unit_directory_is_scanned(self):
        dirs = ("etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system",
                "usr/local/lib/systemd/system", "run/systemd/system")
        for i, d in enumerate(dirs):
            self.write(f"{d}/forge{i}.service",
                       "[Service]\nExecStart=/usr/bin/sqlite3 /root/vpn_auth/vpn_users.db "
                       "\"UPDATE nodes SET management_status='ok'\"\n")
        self.write("usr/lib/systemd/system/harmless.service", "[Service]\nExecStart=/usr/bin/true\n")
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        calls = Path(self.root, "systemctl.calls").read_text()
        for i, d in enumerate(dirs):
            self.assertFalse(os.path.exists(os.path.join(self.root, f"{d}/forge{i}.service")), d)
            self.assertIn(f"disable --now forge{i}.service", calls)
        self.assertTrue(os.path.exists(os.path.join(self.root, "usr/lib/systemd/system/harmless.service")))

    def test_round3_service_and_timer_drop_ins_go_and_their_parent_units_stay(self):
        for kind in ("service", "timer"):
            self.write(f"etc/systemd/system/wins-hub.{kind}", "[Unit]\nDescription=legit\n")
            self.write(f"etc/systemd/system/wins-hub.{kind}.d/zz.conf",
                       "[Service]\nExecStartPost=/usr/bin/python3 /opt/forge/keepalive_nodes.py\n")
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        for kind in ("service", "timer"):
            self.assertFalse(os.path.exists(os.path.join(self.root, f"etc/systemd/system/wins-hub.{kind}.d/zz.conf")), kind)
            self.assertTrue(os.path.exists(os.path.join(self.root, f"etc/systemd/system/wins-hub.{kind}")), kind)
        calls = Path(self.root, "systemctl.calls").read_text()
        self.assertNotIn("zz.conf", calls, "a drop-in is not a unit to disable")
        self.assertIn("daemon-reload", calls)

    def test_round3_each_forged_column_is_enough_on_one_line_and_across_lines(self):
        columns = ("management_status", "operator_enabled", "last_heartbeat", "winn3_canary_status", "data_plane_status")
        for column in columns:
            with self.subTest(column=column):
                self.setUp()
                self.write("etc/cron.d/one", f"* * * * * root sqlite3 /d.db \"UPDATE nodes SET {column}='x'\"\n"
                                             "0 4 * * * root /usr/local/bin/wins-backup\n")
                self.write("etc/cron.daily/many", f"#!/bin/sh\nsqlite3 /d.db <<'EOF'\nUPDATE nodes\n  SET {column} = 'x';\nEOF\n", 0o755)
                out = self.main_like()
                self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                self.assertNotIn("UPDATE nodes", Path(self.root, "etc/cron.d/one").read_text())
                self.assertIn("wins-backup", Path(self.root, "etc/cron.d/one").read_text())
                self.assertFalse(os.path.exists(os.path.join(self.root, "etc/cron.daily/many")))

    def test_round3_other_tables_and_plain_selects_are_not_forgers(self):
        self.write("etc/cron.d/users", "* * * * * root sqlite3 /d.db \"UPDATE users SET operator_enabled=1\"\n")
        self.write("etc/cron.daily/report", "#!/bin/sh\nsqlite3 /d.db 'SELECT management_status FROM nodes'\n", 0o755)
        self.write("etc/systemd/system/watch.service", "[Unit]\nDescription=node heartbeat watcher\n")
        out = self.run_fn("retire_health_forging_keepalive")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("no keepalive_nodes script or runner found", out.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "var/backups")))

    def test_round3_heartbeat_posts_are_found_in_every_kind_of_runner(self):
        route = "curl -fsS -X POST https://hub.example.test/api/v1/nodes/{}heartbeat -d @/x"
        self.write("etc/crontab", "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
                   f"* * * * * root {route.format('')}\n")
        self.write("var/spool/cron/crontabs/root", f"0 3 * * * /usr/local/bin/wins-backup\n* * * * * {route.format('lab-alpha/')}\n", 0o600)
        self.write("etc/cron.hourly/beat", f"#!/bin/sh\n{route.format('lab-beta/')}\n", 0o755)
        self.write("etc/systemd/system/beat.service", f"[Service]\nExecStart=/bin/sh -c '{route.format('')}'\n")
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotIn("heartbeat", Path(self.root, "etc/crontab").read_text())
        self.assertIn("run-parts", Path(self.root, "etc/crontab").read_text())
        self.assertNotIn("heartbeat", Path(self.root, "var/spool/cron/crontabs/root").read_text())
        self.assertIn("wins-backup", Path(self.root, "var/spool/cron/crontabs/root").read_text())
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/cron.hourly/beat")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/systemd/system/beat.service")))

    def test_round3_a_periodic_or_unit_move_that_did_nothing_is_caught_by_the_rescan(self):
        self.shim("mv", "exit 0")
        self.shim("chmod", "exit 0")
        for rel in ("etc/cron.daily/forge", "etc/systemd/system/forge.service"):
            with self.subTest(rel=rel):
                self.setUp()
                self.shim("mv", "exit 0")
                self.shim("chmod", "exit 0")
                self.write(rel, self.INLINE_FORGER, 0o755)
                out = self.main_like()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("still in place after retirement", out.stdout)

    def test_round3_a_failed_move_of_a_periodic_job_or_a_unit_stops_the_deploy(self):
        # Turn 4 adds the drop-in, which now has its own move.
        for rel in ("etc/cron.daily/forge", "etc/systemd/system/forge.service",
                    "etc/systemd/system/wins-hub.service.d/forge.conf"):
            with self.subTest(rel=rel):
                self.setUp()
                self.shim("mv", 'for a; do case "$a" in */forge*) echo "mv: Permission denied" >&2; exit 1;; esac; done\n'
                          'exec /bin/mv "$@"')
                self.write(rel, self.INLINE_FORGER, 0o755)
                out = self.main_like()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("cannot move", out.stdout)

    def test_round3_a_failed_daemon_reload_stops_the_deploy(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.sd("fail", "daemon-reload")
        out = self.main_like()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("daemon-reload failed", out.stdout)

    def test_round3_a_failed_disable_still_quarantines_the_unit_and_says_so(self):
        # Turn 4: only once a separate stop worked and the unit is verified stopped.
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.sd("active", "forge.service")
        self.sd("fail", "disable")
        out = self.main_like()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("systemctl disable --now forge.service failed, but it stopped", out.stdout)
        self.assertIn("systemctl stop forge.service", Path(self.root, "systemctl.calls").read_text())
        self.assertFalse(os.path.exists(os.path.join(self.root, "systemd/active/forge.service")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/systemd/system/forge.service")))

    # ---- Turn 4: a running forger must stop, and be proven stopped (Sol N-10)
    def sd(self, kind, unit, text=""):
        """Set one piece of the systemd model's state (see SYSTEMCTL_SHIM)."""
        self.write(f"systemd/{kind}/{unit}", text)

    def proc(self, pid, cgroup, argv, ppid=1, state="S (sleeping)", immortal=False):
        """A fake /proc entry. cgroup is a path (v2) or the full text of a cgroup file."""
        text = cgroup if "\n" in cgroup else f"0::{cgroup}\n"
        self.write(f"proc/{pid}/cgroup", text)
        Path(self.root, f"proc/{pid}/cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        self.write(f"proc/{pid}/status", f"Name:\t{os.path.basename(argv[0])}\nState:\t{state}\nPPid:\t{ppid}\n")
        if immortal:
            self.write(f"immortal/{pid}", "")

    def alive(self, pid):
        return os.path.exists(os.path.join(self.root, f"proc/{pid}"))

    def deploy_k(self, **env):
        env.setdefault("WINS_KEEPALIVE_STOP_TICKS", "1")
        return self.run_fn(KILL_SHIM + "deploy() { retire_health_forging_keepalive || return 1; echo DEPLOY-CONTINUED; }\n"
                           "deploy", **env)

    def kills(self):
        path = Path(self.root, "kill.calls")
        return path.read_text() if path.exists() else ""

    UNIT_ACTIONS = re.compile(r"^systemctl (stop|start|restart|try-restart|reload|reload-or-restart|disable|enable|"
                              r"kill|mask|reset-failed)\b.*$", re.M)

    def assertNoUnitAction(self, calls, needle, msg=None):
        """FU-SYNCHUB: systemctl may be asked (show) which units a drop-in reaches; no unit
        whose name contains needle may be stopped, started, restarted, disabled or signalled."""
        acted = [m.group(0) for m in self.UNIT_ACTIONS.finditer(calls) if needle in m.group(0)]
        self.assertEqual(acted, [], msg)

    def test_turn4_a_failed_stop_refuses_and_leaves_the_unit_in_place(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.sd("active", "forge.service")
        self.sd("stopfail", "forge.service")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("cannot stop forge.service", out.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.root, "etc/systemd/system/forge.service")),
                        "the unit file stays where an operator finds it")

    def test_turn4_a_unit_that_stays_active_after_its_stop_refuses(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.sd("active", "forge.service")
        self.sd("stuck", "forge.service")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("forge.service is not verified stopped", out.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.root, "etc/systemd/system/forge.service")))

    def test_turn4_an_unanswered_state_query_is_not_a_stop(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.sd("fail", "show")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("not verified stopped", out.stdout)

    def test_turn4_a_process_left_in_the_units_cgroup_is_ended(self):
        # KillMode=process leaves a forking child behind after a successful stop.
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.sd("active", "forge.service")
        self.proc(5000001, "/system.slice/forge.service", ["/usr/bin/python3", "/opt/forge/loop.py"])
        self.proc(5000002, "/system.slice/other.service", ["/usr/bin/python3", "/opt/forge/loop.py"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertFalse(self.alive(5000001))
        self.assertIn("kill -s TERM 5000001", self.kills())
        self.assertTrue(self.alive(5000002), "anti-vacuity: another unit's process is left alone")
        self.assertNotIn("5000002", self.kills())

    def test_turn4_a_process_that_survives_sigkill_refuses(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.proc(5000001, "/system.slice/forge.service", ["/bin/sh", "-c", "while :; do sleep 60; done"], immortal=True)
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("survived SIGKILL", out.stdout)
        self.assertIn("kill -s TERM 5000001", self.kills())
        self.assertIn("kill -s KILL 5000001", self.kills())
        self.assertTrue(os.path.exists(os.path.join(self.root, "etc/systemd/system/forge.service")))

    def test_turn4_a_zombie_is_not_a_running_process(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.proc(5000001, "/system.slice/forge.service", ["python3"], state="Z (zombie)", immortal=True)
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_turn4_a_process_that_dies_into_a_zombie_is_gone(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.proc(5000001, "/system.slice/forge.service", ["python3", "/opt/forge/loop.py"])
        self.write("zombify/5000001", "")
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("kill -s TERM 5000001", self.kills())
        self.assertNotIn("kill -s KILL", self.kills(), "a zombie is not signalled again")

    def test_turn4_the_v1_systemd_hierarchy_counts_and_other_hierarchies_do_not(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.proc(5000001, "12:cpu,cpuacct:/\n1:name=systemd:/system.slice/forge.service\n", ["python3", "/x"])
        self.proc(5000002, "12:cpu,cpuacct:/system.slice/forge.service\n1:name=systemd:/system.slice/cron.service\n",
                  ["python3", "/y"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(self.alive(5000001))
        self.assertTrue(self.alive(5000002), "only the systemd hierarchy places a process in a unit")

    def test_turn4_a_running_drop_in_command_is_ended_and_its_parent_kept(self):
        self.write("etc/systemd/system/wins-hub.service", "[Service]\nExecStart=/usr/local/bin/wins-hub\n")
        self.write("etc/systemd/system/wins-hub.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/forge/keepalive_nodes.py\n")
        self.proc(5000001, "/system.slice/wins-hub.service", ["/usr/local/bin/wins-hub"])
        self.sd("mainpid", "wins-hub.service", "5000001")
        # Not the drop-in's exact command (an extra argument): matched because it forges.
        self.proc(5000002, "/system.slice/wins-hub.service", ["/usr/bin/python3", "/opt/forge/keepalive_nodes.py", "--loop"])
        self.proc(5000003, "/system.slice/wins-hub.service", ["sleep", "60"], ppid=5000002)
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertFalse(self.alive(5000002), "the forging command")
        self.assertFalse(self.alive(5000003), "its child")
        self.assertTrue(self.alive(5000001), "the parent service's own process stays")
        self.assertNotIn("5000001", self.kills())
        self.assertIn("ended the health-forging process(es)", out.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/systemd/system/wins-hub.service.d/zz.conf")))
        calls = Path(self.root, "systemctl.calls").read_text()
        self.assertNoUnitAction(calls, "wins-hub", "the parent unit is never stopped or disabled")
        events = Path(self.root, "events").read_text()
        self.assertLess(events.index("systemctl daemon-reload"), events.index("kill -s TERM"),
                        "ended after the reload, so a restart cannot run the drop-in again")

    def test_turn4_a_drop_in_command_is_matched_by_its_exact_exec_line(self):
        # The drop-in is found by its description; the command it runs names nothing that forges.
        self.write("etc/systemd/system/wins-hub.service", "[Service]\nExecStart=/usr/local/bin/wins-hub\n")
        self.write("etc/systemd/system/wins-hub.service.d/zz.conf",
                   "[Unit]\nDescription=keepalive_nodes helper\n[Service]\n"
                   "ExecStartPost=-/bin/sh -c 'while true; do /opt/h/run; sleep 60; done'\n")
        self.proc(5000001, "/system.slice/wins-hub.service", ["/usr/local/bin/wins-hub"])
        self.sd("mainpid", "wins-hub.service", "5000001")
        self.proc(5000002, "/system.slice/wins-hub.service", ["/bin/sh", "-c", "while true; do /opt/h/run; sleep 60; done"])
        # FU-SYNCHUB: a child of the unit's own main process (an orphan would now refuse).
        self.proc(5000003, "/system.slice/wins-hub.service", ["/bin/sh", "-c", "while true; do /opt/h/other; done"],
                  ppid=5000001)
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(self.alive(5000002))
        self.assertTrue(self.alive(5000001))
        self.assertTrue(self.alive(5000003), "anti-vacuity: a different command is not the drop-in's")

    # ---- Turn 5: drop-ins that reach more than one unit (Seat C N-15)
    def test_turn5_a_dash_prefix_drop_in_reaches_every_unit_it_applies_to(self):
        # Seat C's model case probes.py::test_zz_prefix_dropin_dir, widened: systemd applies
        # foo-.service.d to foo-bar.service and to foo-bar-baz.service.
        self.write("etc/systemd/system/foo-.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
        forger = ["/usr/bin/python3", "/opt/keepalive_nodes.py"]
        self.proc(5000020, "/system.slice/foo-bar.service", forger)
        self.proc(5000021, "/system.slice/foo-bar-baz.service", forger)
        self.proc(5000022, "/system.slice/foo-bar.service", ["/usr/local/bin/foo-bar"])
        self.sd("mainpid", "foo-bar.service", "5000022")
        self.proc(5000023, "/system.slice/other.service", forger)
        self.proc(5000024, "/system.slice/foo-a.slice/x.service", forger)
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertFalse(self.alive(5000020), "forger left running in foo-bar.service")
        self.assertFalse(self.alive(5000021), "forger left running in foo-bar-baz.service")
        self.assertTrue(self.alive(5000022), "the unit's own process stays")
        self.assertTrue(self.alive(5000023), "anti-vacuity: a unit outside the prefix is not touched")
        self.assertTrue(self.alive(5000024), "matched by path component: a foo-a.slice is not a foo-*.service")
        self.assertIn("it applies to every foo-*.service unit", out.stdout)
        self.assertNoUnitAction(Path(self.root, "systemctl.calls").read_text(), "foo-", "no unit is stopped or disabled")

    def test_turn5_a_real_systemd_shaped_prefix_drop_in(self):
        # Seat C's vm_probe.sh section A on systemd 255: kaprobe-.service.d resets ExecStart of
        # kaprobe-xyz.service to a forging loop; the process runs as the unit's main process.
        self.write("etc/systemd/system/kaprobe-xyz.service", "[Service]\nExecStart=/bin/sleep infinity\n")
        self.write("etc/systemd/system/kaprobe-.service.d/zz.conf",
                   "[Service]\nExecStart=\nExecStart=/bin/bash -c \"while :; do echo 'UPDATE nodes SET last_heartbeat=1' "
                   ">/dev/null; sleep 1; done\"\n")
        self.proc(5000030, "/system.slice/kaprobe-xyz.service",
                  ["/bin/bash", "-c", "while :; do echo 'UPDATE nodes SET last_heartbeat=1' >/dev/null; sleep 1; done"])
        self.proc(5000031, "/system.slice/kaprobe-xyz.service", ["sleep", "1"], ppid=5000030)
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(self.alive(5000030))
        self.assertFalse(self.alive(5000031), "its child")
        self.assertTrue(os.path.exists(os.path.join(self.root, "etc/systemd/system/kaprobe-xyz.service")))

    def test_turn5_a_prefix_drop_in_process_that_survives_refuses(self):
        self.write("etc/systemd/system/foo-.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
        self.proc(5000020, "/system.slice/foo-bar.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"], immortal=True)
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("survived SIGKILL", out.stdout)

    def test_turn5_a_bare_dash_drop_in_reaches_every_service(self):
        self.write("etc/systemd/system/-.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
        self.proc(5000040, "/system.slice/anything.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
        self.proc(5000041, "/system.slice/anything.service", ["/usr/sbin/anything"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(self.alive(5000040))
        self.assertTrue(self.alive(5000041))

    def test_turn5_a_top_level_type_drop_in_refuses_before_any_write(self):
        for kind in ("service", "timer"):
            with self.subTest(kind=kind):
                self.setUp()
                self.seed_everything()
                self.write(f"etc/systemd/system/{kind}.d/zz.conf",
                           "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
                self.proc(5000050, "/system.slice/anything.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
                before = self.tree_digest()
                out = self.deploy_k()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("a top-level systemd type drop-in forges health", out.stdout)
                self.assertIn(f"/etc/systemd/system/{kind}.d/zz.conf", out.stdout)
                self.assertEqual(self.tree_digest(), before, "nothing is written, nothing is ended")
                self.assertEqual(self.kills(), "")
                preview = self.run_fn("report_health_forging_keepalive")
                self.assertEqual(preview.returncode, 1, preview.stdout)
                self.assertIn("a deploy would refuse: a top-level systemd type drop-in", preview.stdout)
        self.setUp()
        self.write("etc/systemd/system/service.d/limits.conf", "[Service]\nLimitNOFILE=65536\n")
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("no keepalive_nodes script or runner found", out.stdout, "anti-vacuity: a benign type drop-in")

    def test_turn5_h0_the_gate_takes_no_binding_from_the_app_writable_legacy_file(self):
        # H0 (D7): load_existing_envs parses the app-writable legacy copy as
        # data and takes only generated secrets from it, so a canary binding
        # (a key directory, an endpoint) found only there is not the binding
        # the deploy writes, and the gate does not count it.
        bad = "alpha|cGs=|10.10.0.9|/etc/winn/canary/none|198.51.100.7:51820|gid"
        cases = (("legacy only", f"WINN3_CANARY_NODES='{self.entry('alpha')}'", None, False),
                 ("the env file wins over the legacy file", f"WINN3_CANARY_NODES='{self.entry('alpha')}'",
                  f"WINN3_CANARY_NODES='{bad}'", False))
        for label, legacy, current, covered in cases:
            with self.subTest(case=label):
                self.setUp()
                self.seed_everything()
                self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
                self.env_file(*([current] if current else []))
                self.write("root/vpn_auth/.env", legacy + "\n", 0o600)
                out = self.run_fn("health_keepalive_canary_coverage")
                if covered:
                    self.assertIn("COVERED alpha", out.stdout.splitlines(), out.stdout)
                elif current is None:
                    self.assertNotIn("COVERED alpha", out.stdout.splitlines(), out.stdout)
                    self.assertIn("SUMMARY open=1 covered=0 uncovered=alpha", out.stdout.splitlines(), out.stdout)
                else:
                    self.assertIn("key_dir /etc/winn/canary/none lacks", out.stdout)

    def test_turn4_a_template_drop_in_reaches_every_instance(self):
        self.write("etc/systemd/system/getty@.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/forge/keepalive_nodes.py\n")
        self.proc(5000001, "/system.slice/system-getty.slice/getty@tty1.service",
                  ["/usr/bin/python3", "/opt/forge/keepalive_nodes.py"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(self.alive(5000001))

    def test_turn4_a_drop_in_command_that_survives_refuses(self):
        self.write("etc/systemd/system/wins-hub.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/forge/keepalive_nodes.py\n")
        self.proc(5000002, "/system.slice/wins-hub.service", ["/usr/bin/python3", "/opt/forge/keepalive_nodes.py"],
                  immortal=True)
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("survived SIGKILL", out.stdout)

    def test_turn4_a_linked_unit_is_stopped_verified_and_only_its_link_moves(self):
        self.write("opt/forge/forge.service", self.INLINE_FORGER)
        link = os.path.join(self.root, "etc/systemd/system/forge.service")
        os.symlink(os.path.join(self.root, "opt/forge/forge.service"), link)
        self.sd("active", "forge.service")
        self.proc(5000001, "/system.slice/forge.service", ["python3", "/opt/forge/loop.py"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        calls = Path(self.root, "systemctl.calls").read_text()
        self.assertIn("systemctl disable --now forge.service", calls)
        self.assertIn("daemon-reload", calls, "a linked unit counts as a unit")
        self.assertFalse(os.path.exists(os.path.join(self.root, "systemd/active/forge.service")))
        self.assertFalse(self.alive(5000001))
        self.assertFalse(os.path.lexists(link))
        self.assertTrue(os.path.exists(os.path.join(self.root, "opt/forge/forge.service")), "never follow the link")
        self.assertTrue(os.path.islink(os.path.join(self.quarantine(), "_etc_systemd_system_forge.service")),
                        "the link is kept in quarantine although disable removed it")

    def test_turn4_a_linked_unit_that_cannot_stop_refuses(self):
        self.write("opt/forge/forge.service", self.INLINE_FORGER)
        os.symlink(os.path.join(self.root, "opt/forge/forge.service"),
                   os.path.join(self.root, "etc/systemd/system/forge.service"))
        self.sd("active", "forge.service")
        self.sd("stopfail", "forge.service")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("cannot stop forge.service", out.stdout)

    def test_turn4_a_forging_timer_stops_the_unit_it_triggers(self):
        self.write("etc/systemd/system/forge.timer", "[Timer]\nOnCalendar=minutely\nUnit=run.service\n# keepalive_nodes\n")
        self.write("etc/systemd/system/run.service", "[Service]\nExecStart=/opt/h/run\n")
        self.sd("active", "forge.timer")
        self.sd("active", "run.service")
        self.sd("triggers", "forge.timer", "run.service\n")
        self.proc(5000001, "/system.slice/run.service", ["/opt/h/run"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("systemctl stop run.service", Path(self.root, "systemctl.calls").read_text())
        self.assertFalse(os.path.exists(os.path.join(self.root, "systemd/active/run.service")))
        self.assertFalse(self.alive(5000001))
        self.assertTrue(os.path.exists(os.path.join(self.root, "etc/systemd/system/run.service")),
                        "a triggered unit that does not forge by content is stopped, not quarantined")
        self.setUp()
        self.write("etc/systemd/system/forge.timer", "[Timer]\nOnCalendar=minutely\n# keepalive_nodes\n")
        self.sd("triggers", "forge.timer", "run.service\n")
        self.sd("stopfail", "run.service")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("cannot stop run.service, which the health-forging forge.timer triggers", out.stdout)

    def test_turn4_a_forger_that_respawns_when_killed_refuses(self):
        for kind in ("unit", "drop-in"):
            with self.subTest(kind=kind):
                self.setUp()
                if kind == "unit":
                    self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
                    cgroup, message = "/system.slice/forge.service", "forge.service is not verified stopped"
                else:
                    self.write("etc/systemd/system/wins-hub.service.d/zz.conf",
                               "[Service]\nExecStartPost=/usr/bin/python3 /opt/forge/keepalive_nodes.py\n")
                    cgroup, message = "/system.slice/wins-hub.service", "is still running in wins-hub.service"
                self.proc(5000001, cgroup, ["/usr/bin/python3", "/opt/forge/keepalive_nodes.py"])
                self.write("respawn/5000001", "5000009")
                out = self.deploy_k()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn(message, out.stdout)
                self.assertTrue(self.alive(5000009))

    def test_turn4_a_unit_running_again_after_the_reload_refuses(self):
        self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
        self.sd("active", "forge.service")
        self.sd("reactivate", "forge.service")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("forge.service is running again after the daemon-reload", out.stdout)

    # ---- FU-SYNCHUB (2026-10-01): Sol's Turn 5 fixtures (N-16, N-17, N-18 = CLAUDE-N-10; SOL-N-10)
    ALIAS_DROPIN = "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n"

    def alias_fixture(self, how):
        """Sol N-16: alias.service is a symlink to the benign canonical.service; the forging
        drop-in sits in alias.service.d, its process in canonical.service's cgroup."""
        self.write("etc/systemd/system/canonical.service", "[Service]\nExecStart=/usr/local/bin/canonical\n")
        os.symlink("canonical.service", os.path.join(self.root, "etc/systemd/system/alias.service"))
        self.write("etc/systemd/system/alias.service.d/zz.conf", self.ALIAS_DROPIN)
        if how in ("alias", "both"):
            self.sd("alias", "alias.service", "canonical.service")
        if how in ("dropinpaths", "both"):
            self.sd("dropins", "canonical.service", "/etc/systemd/system/alias.service.d/zz.conf")
        self.sd("mainpid", "canonical.service", "5000079")
        self.proc(5000079, "/system.slice/canonical.service", ["/usr/local/bin/canonical"])
        self.proc(5000080, "/system.slice/canonical.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"])

    def test_fu_n16_an_alias_drop_in_reaches_the_unit_systemd_runs(self):
        # systemd resolves alias.service to its Id canonical.service (and lists the drop-in in
        # canonical.service's DropInPaths): each answer alone is enough to find the forger.
        for how in ("alias", "dropinpaths", "both"):
            with self.subTest(how=how):
                self.setUp()
                self.alias_fixture(how)
                out = self.deploy_k()
                self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                self.assertIn("DEPLOY-CONTINUED", out.stdout)
                self.assertFalse(self.alive(5000080), "the forger in canonical.service's cgroup is ended")
                self.assertIn("kill -s TERM 5000080", self.kills())
                self.assertIn("ended the health-forging process(es) 5000080", out.stdout)
                self.assertIn("(canonical.service", out.stdout, "the unit is named by its systemd Id")
                self.assertTrue(self.alive(5000079), "anti-vacuity: the unit's own main process stays")
                self.assertNotIn("5000079", self.kills())
                self.assertNoUnitAction(Path(self.root, "systemctl.calls").read_text(), "canonical")
                self.assertFalse(os.path.exists(os.path.join(self.root, "etc/systemd/system/alias.service.d/zz.conf")))
                self.assertTrue(os.path.islink(os.path.join(self.root, "etc/systemd/system/alias.service")))

    def test_fu_n16_an_alias_drop_in_forger_that_survives_refuses_and_is_named(self):
        self.alias_fixture("alias")
        self.write("immortal/5000080", "")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertRegex(out.stdout, r"survived SIGKILL: 5000080")

    def test_fu_n16_a_systemd_that_does_not_answer_refuses_before_any_write(self):
        for broken in ("fail", "empty"):
            with self.subTest(broken=broken):
                self.setUp()
                self.alias_fixture("alias")
                if broken == "fail":
                    self.sd("fail", "show")
                else:
                    self.shim("systemctl", 'echo "systemctl $*" >> "${WINS_KEEPALIVE_ROOT}/systemctl.calls"\nexit 0')
                before = self.tree_digest()
                out = self.deploy_k()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("systemd did not say which units the drop-in /etc/systemd/system/alias.service.d/zz.conf applies to",
                              out.stdout)
                self.assertEqual(self.tree_digest(), before, "nothing is written")
                self.assertEqual(self.kills(), "")

    N17_DROPIN = ("[Unit]\nDescription=keepalive_nodes helper\n[Service]\nEnvironment=WORKER=/opt/h/run\n"
                  "ExecStartPost=/usr/bin/python3 ${WORKER}\n")

    def test_fu_n17_an_expanded_command_refuses_and_names_the_process(self):
        # Sol N-17: foo-.service.d forges by its description; systemd ran ExecStartPost with ${WORKER}
        # expanded, so neither the Exec*= text nor the forging pattern matches /usr/bin/python3 /opt/h/run.
        cases = {
            "Environment= in the drop-in (Sol's fixture)": self.N17_DROPIN,
            "the command alone (WORKER set by the unit)": "[Unit]\nDescription=keepalive_nodes helper\n[Service]\n"
                                                         "ExecStartPost=/usr/bin/python3 ${WORKER}\n",
        }
        for label, dropin in cases.items():
            with self.subTest(case=label):
                self.setUp()
                self.write("etc/systemd/system/foo-.service.d/zz.conf", dropin)
                self.sd("mainpid", "foo-bar.service", "5000082")
                self.proc(5000082, "/system.slice/foo-bar.service", ["/usr/local/bin/foo-bar"])
                self.proc(5000081, "/system.slice/foo-bar.service", ["/usr/bin/python3", "/opt/h/run"])
                before = self.tree_digest()
                out = self.deploy_k()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("5000081 (/usr/bin/python3 /opt/h/run) in foo-bar.service", out.stdout, "the survivor is named")
                self.assertIn("Nothing was changed", out.stdout)
                self.assertEqual(self.tree_digest(), before, "refused before the quarantine exists")
                self.assertEqual(self.kills(), "")
                preview = self.run_fn("report_health_forging_keepalive")
                self.assertEqual(preview.returncode, 1, preview.stdout)
                self.assertIn("a deploy would refuse: see the drop-in check above", preview.stdout)
                pre = self.preflight_main()
                self.assertNotEqual(pre.returncode, 0, pre.stdout)
                self.assertNotIn("MAIN-RETURNED-0", pre.stdout)

    def test_fu_n17_a_template_drop_in_is_checked_in_every_instance(self):
        # systemd applies getty@.service.d to getty@tty1.service by name: a process there that the
        # drop-in may have started and that does not forge refuses, as in a plain parent.
        self.write("etc/systemd/system/getty@.service.d/zz.conf", self.N17_DROPIN)
        self.sd("mainpid", "getty@tty1.service", "5000090")
        self.proc(5000090, "/system.slice/system-getty.slice/getty@tty1.service", ["/sbin/agetty", "tty1"])
        self.proc(5000091, "/system.slice/system-getty.slice/getty@tty1.service", ["/usr/bin/python3", "/opt/h/run"])
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("5000091 (/usr/bin/python3 /opt/h/run) in getty@tty1.service", out.stdout)

    def test_fu_n17_only_the_units_own_main_process_line_is_explained(self):
        # Anti-vacuity for the refusal above: the same process as a child of the unit's MainPID,
        # with a drop-in that only adds a side command, is the unit's own and stays.
        self.write("etc/systemd/system/foo-.service.d/zz.conf",
                   "[Unit]\nDescription=keepalive_nodes helper\n[Service]\nExecStartPost=/usr/bin/python3 ${WORKER}\n")
        self.sd("mainpid", "foo-bar.service", "5000082")
        self.proc(5000082, "/system.slice/foo-bar.service", ["/usr/local/bin/foo-bar"])
        self.proc(5000081, "/system.slice/foo-bar.service", ["/usr/bin/python3", "/opt/h/run"], ppid=5000082)
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertTrue(self.alive(5000081))
        self.assertEqual(self.kills(), "")

    def test_fu_n17_a_drop_in_that_replaces_the_main_command_owns_the_main_process(self):
        # ExecStart= reset to an expanded command: the unit's MainPID is the drop-in's process,
        # so it is not explained by being the main process.
        self.write("etc/systemd/system/foo-.service.d/zz.conf",
                   "[Unit]\nDescription=keepalive_nodes helper\n[Service]\nExecStart=\nExecStart=/usr/bin/python3 ${WORKER}\n")
        self.sd("mainpid", "foo-bar.service", "5000083")
        self.proc(5000083, "/system.slice/foo-bar.service", ["/usr/bin/python3", "/opt/h/run"])
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("5000083 (/usr/bin/python3 /opt/h/run) in foo-bar.service", out.stdout)

    def test_fu_n17_a_process_that_appears_after_the_reload_refuses(self):
        # The final check after the daemon-reload uses the same cgroup rule, not the Exec*= text.
        self.write("etc/systemd/system/foo-.service.d/zz.conf", self.N17_DROPIN)
        self.proc(5000084, "/system.slice/foo-bar.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
        self.write("systemd/onreload/5000085/cgroup", "0::/system.slice/foo-bar.service\n")
        Path(self.root, "systemd/onreload/5000085/cmdline").write_bytes(b"/usr/bin/python3\0/opt/h/run\0")
        self.write("systemd/onreload/5000085/status", "Name:\tpython3\nState:\tS (sleeping)\nPPid:\t1\n")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertFalse(self.alive(5000084), "the recognisable forger was ended")
        self.assertIn("after the drop-in of foo-.service was retired, process(es) it may have started still run: "
                      "5000085 (/usr/bin/python3 /opt/h/run) in foo-bar.service", out.stdout)

    def test_fu_n16_a_child_the_ended_forger_orphaned_gets_the_stop_window(self):
        # Real systemd 255 (logs/vm_probe_fix.log): the forger's `sleep 1` outlived it, reparented,
        # for under a second. The post-check waits the stop window before it refuses.
        self.alias_fixture("alias")
        self.write("systemd/onreload/5000087/cgroup", "0::/system.slice/canonical.service\n")
        Path(self.root, "systemd/onreload/5000087/cmdline").write_bytes(b"sleep\x001\x00")
        self.write("systemd/onreload/5000087/status", "Name:\tsleep\nState:\tS (sleeping)\nPPid:\t1\n")
        self.sd("transient", "5000087", "0.6")
        out = self.deploy_k(WINS_KEEPALIVE_STOP_TICKS="15")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertFalse(self.alive(5000080))
        self.assertNotIn("5000087", self.kills(), "the orphan is waited for, never signalled")

    # N-18 / CLAUDE-N-10: coverage is judged on the binding write_env leaves after every overlay.
    def secrets_file(self, text, mode=0o600):
        return self.write("root/winsvpn-secrets.env", text, mode)

    def test_fu_n18_an_unexported_secrets_overlay_is_judged_by_the_binding_it_leaves(self):
        # Sol's fixture: a complete, valid legacy binding in the runtime file (keys under
        # /etc/winn/canary/alpha, an executable probe, a fresh verdict); the secrets file sets only
        # WINN3_CANARY_KEY_DIR, which write_env overlays last. FORCE unset.
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha")
        self.secrets_file("WINN3_CANARY_KEY_DIR='/etc/winn/canary/none'\n")
        before = self.tree_digest()
        out = self.run_fn(TRUST_STUB + "deploy() { retire_health_forging_keepalive || return 1; echo DEPLOY-CONTINUED; }\ndeploy")
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("UNCOVERED alpha key_dir /etc/winn/canary/none lacks client.key,static.pub,admission.key", out.stdout)
        self.assertIn("refusing to retire the keepalive", out.stdout)
        self.assertEqual(self.tree_digest(), before)
        preview = self.run_fn(TRUST_STUB + "report_health_forging_keepalive")
        self.assertEqual(preview.returncode, 1, preview.stdout)
        self.assertIn("UNCOVERED alpha key_dir /etc/winn/canary/none", preview.stdout)
        # The order is write_env's: the secrets file wins over a value the installer was given, too.
        out = self.run_fn(TRUST_STUB + "health_keepalive_canary_coverage", WINN3_CANARY_KEY_DIR="/etc/winn/canary/alpha")
        self.assertIn("UNCOVERED alpha key_dir /etc/winn/canary/none", out.stdout, out.stdout + out.stderr)
        # Anti-vacuity: the same overlay naming the directory that holds the keys retires.
        self.setUp()
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha")
        self.secrets_file("WINN3_CANARY_KEY_DIR='/etc/winn/canary/alpha'\n")
        out = self.run_fn(TRUST_STUB + "deploy() { retire_health_forging_keepalive || return 1; echo DEPLOY-CONTINUED; }\ndeploy")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("SUMMARY open=1 covered=1 uncovered=none", out.stdout)

    def test_fu_n18_a_binding_only_in_the_secrets_file_is_the_one_written(self):
        # Turn 5 left this fail-closed; the deploy writes it, so it is coverage now.
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)])
        self.env_file()
        self.secrets_file(f"WINN3_CANARY_NODES='{self.entry('alpha')}'\n")
        out = self.run_fn(TRUST_STUB + "health_keepalive_canary_coverage")
        self.assertIn("COVERED alpha", out.stdout.splitlines(), out.stdout + out.stderr)

    def test_fu_n18_a_secrets_file_the_deploy_would_refuse_is_an_error(self):
        # write_env exits on an untrusted secrets file; the gate must not judge the binding without it.
        self.seed_everything()
        self.seed_hub_db(rows=[("alpha", 1, "ok", 1)], canary_slug="alpha")
        self.write("opt/secrets.env", "WINN3_CANARY_KEY_DIR='/etc/winn/canary/none'\n", 0o600)
        os.symlink(os.path.join(self.root, "opt/secrets.env"), os.path.join(self.root, "root/winsvpn-secrets.env"))
        out = self.run_fn(TRUST_STUB + "deploy() { retire_health_forging_keepalive || return 1; echo DEPLOY-CONTINUED; }\ndeploy")
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("ERROR the runtime environment this deploy would write cannot be read", out.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.root, "root/vpn_auth/keepalive_nodes.py")))

    # ---- FU-SYNCHUB Turn 7 (2026-10-01): Sol's Turn 6 fixtures (N-19, N-20, T93; SOL-N-10)
    def proc_on(self, when, pid, cgroup, argv, ppid=1):
        """A fake /proc entry that appears later: when="onreload" at the next daemon-reload,
        when="onsleep" at the first sleep the installer runs after it (see sleep_shim)."""
        os.makedirs(os.path.join(self.root, "proc"), exist_ok=True)
        self.write(f"systemd/{when}/{pid}/cgroup", f"0::{cgroup}\n")
        Path(self.root, f"systemd/{when}/{pid}/cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        self.write(f"systemd/{when}/{pid}/status", f"Name:\t{os.path.basename(argv[0])}\nState:\tS (sleeping)\nPPid:\t{ppid}\n")

    def sleep_shim(self):
        """The first sleep after the reload (the installer's wait) ends every onsleepgone/<pid> and
        starts every onsleep/<pid>; a process change then lands inside the wait, never before it.
        Turn 8: it also makes every onsleepactive/<unit> active again (systemd started it)."""
        self.shim("sleep", 'r="${WINS_KEEPALIVE_ROOT}"; st="${r}/systemd"\n'
                  'if [[ -e "${r}/events" ]] && grep -q "daemon-reload" "${r}/events" && [[ ! -e "${st}/slept" ]]; then\n'
                  '  touch "${st}/slept"\n'
                  '  for f in "${st}"/onsleepgone/*; do [[ -e "${f}" ]] && rm -rf "${r}/proc/${f##*/}"; done\n'
                  '  for f in "${st}"/onsleep/*; do [[ -d "${f}" ]] && cp -R "${f}" "${r}/proc/${f##*/}"; done\n'
                  '  for f in "${st}"/onsleepactive/*; do [[ -e "${f}" ]] && touch "${st}/active/${f##*/}"; done\n'
                  'fi\nexec /bin/sleep "$@"')

    def test_t7_n19_a_unit_that_starts_after_the_precheck_is_checked(self):
        # Sol's Turn 6 fixture: no unit the drop-in reaches holds a process at the precheck;
        # across the retirement (modelled at the daemon-reload) a new dash-prefix unit or a new
        # template instance runs the drop-in's expanded command, PID 5000191.
        for parent, cgroup, unit in (
                ("foo-.service", "/system.slice/foo-new.service", "foo-new.service"),
                ("getty@.service", "/system.slice/system-getty.slice/getty@tty2.service", "getty@tty2.service")):
            with self.subTest(unit=unit):
                self.setUp()
                self.write(f"etc/systemd/system/{parent}.d/zz.conf", self.N17_DROPIN)
                self.proc_on("onreload", 5000191, cgroup, ["/usr/bin/python3", "/opt/h/run"])
                pre = self.run_fn("report_health_forging_keepalive")
                self.assertEqual(pre.returncode, 0, "the precheck sees nothing yet: " + pre.stdout)
                out = self.deploy_k()
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn(f"after the drop-in of {parent} was retired, process(es) it may have started still "
                              f"run: 5000191 (/usr/bin/python3 /opt/h/run) in {unit}", out.stdout)
                self.assertTrue(self.alive(5000191), "not recognisable as a forger: named, never signalled")
                self.assertEqual(self.kills(), "")

    def test_t7_t93_a_recognisable_forger_in_a_late_template_instance_is_ended(self):
        # Sol's T93 fixture: the same late getty@tty2.service, its worker recognisable as a forger.
        # The template pattern of _keepalive_cgroup_members finds the instance (T93 removes it).
        self.write("etc/systemd/system/getty@.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
        self.proc_on("onreload", 5000191, "/system.slice/system-getty.slice/getty@tty2.service",
                     ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("kill -s TERM 5000191", self.kills())
        self.assertFalse(self.alive(5000191), "the late instance's forger is ended")
        self.assertIn("ended the health-forging process(es) 5000191", out.stdout)

    def test_t7_n19_an_alias_the_drop_in_reaches_is_checked_when_its_unit_starts_late(self):
        # systemd applies kaprobe-.service.d to canonical.service through its alias
        # kaprobe-alias.service; canonical.service starts after the precheck.
        for alias, refused in ((True, True), (False, False)):
            with self.subTest(alias=alias):
                self.setUp()
                self.write("etc/systemd/system/kaprobe-.service.d/zz.conf", self.N17_DROPIN)
                if alias:
                    self.sd("names", "canonical.service", "canonical.service kaprobe-alias.service")
                self.proc_on("onreload", 5000193, "/system.slice/canonical.service", ["/usr/bin/python3", "/opt/h/run"])
                out = self.deploy_k()
                if refused:
                    self.assertNotEqual(out.returncode, 0, out.stdout)
                    self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                    self.assertIn("5000193 (/usr/bin/python3 /opt/h/run) in canonical.service", out.stdout)
                else:
                    # Anti-vacuity: without the alias the drop-in does not reach canonical.service.
                    self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                    self.assertIn("DEPLOY-CONTINUED", out.stdout)
                self.assertTrue(self.alive(5000193))

    def test_t7_n19_what_starts_while_the_check_waits_is_checked(self):
        # The wait after the reload (an orphan, 5000195, holds it open) finds the units again on
        # every pass: a forger that starts meanwhile, in the same or in a new unit, or a new
        # unit's unexplained process, refuses; it is never left out as "already ended".
        cases = (
            ("forger, same unit", "/system.slice/foo-bar.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"],
             "5000196 (/usr/bin/python3 /opt/keepalive_nodes.py), a health forger, in foo-.service"),
            ("forger, new unit", "/system.slice/foo-late.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"],
             "5000196 (/usr/bin/python3 /opt/keepalive_nodes.py), a health forger, in foo-.service"),
            ("unexplained, new unit", "/system.slice/foo-late.service", ["/usr/bin/python3", "/opt/h/run"],
             "5000196 (/usr/bin/python3 /opt/h/run) in foo-late.service"),
        )
        for label, cgroup, argv, named in cases:
            with self.subTest(case=label):
                self.setUp()
                self.sleep_shim()
                self.write("etc/systemd/system/foo-.service.d/zz.conf",
                           "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
                self.proc_on("onreload", 5000195, "/system.slice/foo-bar.service", ["sleep", "1"])
                self.write("systemd/onsleepgone/5000195", "")
                self.proc_on("onsleep", 5000196, cgroup, argv)
                out = self.deploy_k(WINS_KEEPALIVE_STOP_TICKS="3")
                self.assertTrue(os.path.exists(os.path.join(self.root, "systemd/slept")), "the wait ran")
                self.assertFalse(self.alive(5000195), "the orphan went")
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                # Turn 8: the wait itself refuses (the last pass after every wait is a second net).
                self.assertIn("after the drop-in of foo-.service was retired, process(es) it may have started "
                              "still run: " + named, out.stdout)
        # Anti-vacuity: nothing starts during the wait, the orphan goes, the deploy continues.
        self.setUp()
        self.sleep_shim()
        self.write("etc/systemd/system/foo-.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
        self.proc_on("onreload", 5000195, "/system.slice/foo-bar.service", ["sleep", "1"])
        self.write("systemd/onsleepgone/5000195", "")
        out = self.deploy_k(WINS_KEEPALIVE_STOP_TICKS="3")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)

    def test_t7_n19_a_systemd_that_stops_answering_after_the_reload_refuses(self):
        # The units are found again after the reload; when systemd does not say which names a
        # running unit has, the drop-in's reach is unknown and the deploy refuses.
        self.write("etc/systemd/system/foo-.service.d/zz.conf", self.N17_DROPIN)
        self.proc(5000197, "/system.slice/other.service", ["/usr/sbin/other"])
        self.sd("mainpid", "other.service", "5000197")
        self.sd("failprop", "Id,Names")
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("systemd did not say which units the retired drop-in of foo-.service reaches now", out.stdout)
        self.assertTrue(self.alive(5000197))

    def test_t7_n20_a_unit_whose_cgroup_name_systemd_escapes(self):
        # Sol's Turn 6 fixture: systemd (cg_escape) runs _foo.service in the cgroup __foo.service.
        self.write("etc/systemd/system/_foo.service", "[Service]\nExecStart=/usr/local/bin/foo\n")
        self.write("etc/systemd/system/_foo.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
        self.sd("dropins", "_foo.service", "/etc/systemd/system/_foo.service.d/zz.conf")
        self.sd("mainpid", "_foo.service", "5000200")
        self.proc(5000200, "/system.slice/__foo.service", ["/usr/local/bin/foo"])
        self.proc(5000201, "/system.slice/__foo.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
        self.proc(5000204, "/system.slice/__foobar.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertFalse(self.alive(5000201), "the forger in __foo.service is ended")
        self.assertIn("kill -s TERM 5000201", self.kills())
        self.assertTrue(self.alive(5000200), "the unit's own main process stays")
        self.assertTrue(self.alive(5000204), "anti-vacuity: _foobar.service is another unit")
        self.assertNotIn("5000204", self.kills())

    def test_t7_n20_an_escaped_unit_is_found_by_the_precheck_and_by_the_unit_stop(self):
        with self.subTest(case="dash prefix, precheck"):
            # A dash prefix whose units are escaped: the precheck names _foo-bar.service (found from
            # its cgroup __foo-bar.service) and refuses before any write.
            self.setUp()
            self.write("etc/systemd/system/_foo-.service.d/zz.conf", self.N17_DROPIN)
            self.sd("mainpid", "_foo-bar.service", "5000202")
            self.proc(5000202, "/system.slice/__foo-bar.service", ["/usr/local/bin/foo-bar"])
            self.proc(5000203, "/system.slice/__foo-bar.service", ["/usr/bin/python3", "/opt/h/run"])
            before = self.tree_digest()
            out = self.deploy_k()
            self.assertNotEqual(out.returncode, 0, out.stdout)
            self.assertIn("5000203 (/usr/bin/python3 /opt/h/run) in _foo-bar.service", out.stdout)
            self.assertIn("Nothing was changed", out.stdout)
            self.assertEqual(self.tree_digest(), before, "refused before the quarantine exists")
        with self.subTest(case="kernel-name clash, unit stop"):
            # A forging unit file whose name clashes with a kernel controller file: systemd runs
            # cpu.service in _cpu.service; what KillMode=process left there after the stop is ended.
            self.setUp()
            self.write("etc/systemd/system/cpu.service", self.INLINE_FORGER)
            self.sd("active", "cpu.service")
            self.proc(5000205, "/system.slice/_cpu.service", ["/usr/bin/python3", "/opt/forge/loop.py"])
            out = self.deploy_k()
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertFalse(self.alive(5000205))
            self.assertIn("kill -s TERM 5000205", self.kills())

    # ---- FU-SYNCHUB Turn 8 (2026-10-01): Sol's Turn 7 fixtures (N-21; SOL-N-10)
    def n21_fixture(self, parent, first_cgroup):
        """Sol N-21: a recognisable forger, PID 5000210, runs in a unit the drop-in reaches and
        survives SIGTERM until the first sleep of the wait that ends it (immortal to the kill
        model, gone at that sleep: see sleep_shim)."""
        self.sleep_shim()
        self.write(f"etc/systemd/system/{parent}.d/zz.conf", self.N17_DROPIN)
        self.proc(5000210, first_cgroup, ["/usr/bin/python3", "/opt/keepalive_nodes.py"], immortal=True)
        self.write("systemd/onsleepgone/5000210", "")

    def test_t8_n21_a_unit_that_starts_while_a_forger_is_ended_is_checked(self):
        # Sol's Turn 7 fixtures: while _keepalive_end_pids waits for 5000210, a new unit the drop-in
        # reaches (dash prefix, template instance, alias) starts the drop-in's expanded command
        # 5000211, or (the stronger alias variant) a recognisable forger 5000212. Each refuses.
        expanded = ["/usr/bin/python3", "/opt/h/run"]
        forger = ["/usr/bin/python3", "/opt/keepalive_nodes.py"]
        cases = (
            ("prefix", "foo-.service", "/system.slice/foo-bar.service", None,
             5000211, "/system.slice/foo-new.service", expanded,
             "after the drop-in of foo-.service was retired, process(es) it may have started still run: "
             "5000211 (/usr/bin/python3 /opt/h/run) in foo-new.service"),
            ("template", "getty@.service", "/system.slice/system-getty.slice/getty@tty1.service", None,
             5000211, "/system.slice/system-getty.slice/getty@tty2.service", expanded,
             "after the drop-in of getty@.service was retired, process(es) it may have started still run: "
             "5000211 (/usr/bin/python3 /opt/h/run) in getty@tty2.service"),
            ("alias", "foo-.service", "/system.slice/foo-bar.service", "canonical.service foo-alias.service",
             5000211, "/system.slice/canonical.service", expanded,
             "after the drop-in of foo-.service was retired, process(es) it may have started still run: "
             "5000211 (/usr/bin/python3 /opt/h/run) in canonical.service"),
            ("alias, recognisable forger", "foo-.service", "/system.slice/foo-bar.service",
             "canonical.service foo-alias.service", 5000212, "/system.slice/canonical.service", forger,
             "a health-forging process the drop-in started is still running in foo-.service: 5000212"),
        )
        for label, parent, first, names, pid, cgroup, argv, named in cases:
            with self.subTest(case=label):
                self.setUp()
                self.n21_fixture(parent, first)
                if names:
                    self.sd("names", "canonical.service", names)
                self.proc_on("onsleep", pid, cgroup, argv)
                out = self.deploy_k()
                self.assertTrue(os.path.exists(os.path.join(self.root, "systemd/slept")), "the SIGTERM wait ran")
                self.assertIn("kill -s TERM 5000210", self.kills())
                self.assertFalse(self.alive(5000210))
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn(named, out.stdout)
                self.assertTrue(self.alive(pid), "a process that appeared during the wait is named, never signalled")
                self.assertNotIn(str(pid), self.kills())

    def test_t8_n21_controls_for_the_sigterm_wait(self):
        # Anti-vacuity for the refusals above, Sol's controls: the expanded worker appearing during
        # the SIGTERM wait in the unit already recorded refuses; nothing appearing retires cleanly.
        with self.subTest(case="same unit"):
            self.setUp()
            self.n21_fixture("foo-.service", "/system.slice/foo-bar.service")
            self.proc_on("onsleep", 5000211, "/system.slice/foo-bar.service", ["/usr/bin/python3", "/opt/h/run"])
            out = self.deploy_k()
            self.assertNotEqual(out.returncode, 0, out.stdout)
            self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
            self.assertIn("5000211 (/usr/bin/python3 /opt/h/run) in foo-bar.service", out.stdout)
        with self.subTest(case="nothing appears"):
            self.setUp()
            self.n21_fixture("foo-.service", "/system.slice/foo-bar.service")
            out = self.deploy_k()
            self.assertTrue(os.path.exists(os.path.join(self.root, "systemd/slept")), "the SIGTERM wait ran")
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("DEPLOY-CONTINUED", out.stdout)
            self.assertFalse(self.alive(5000210))
            self.assertIn("ended the health-forging process(es) 5000210", out.stdout)

    def test_t8_n21_a_unit_another_drop_ins_wait_lets_start_is_checked(self):
        # The same boundary across drop-ins: alpha-.service.d is checked first and passes; the wait
        # that ends beta-.service.d's forger 5000220 lets a new alpha- unit start. The last check
        # after every wait finds it (an unexplained process, or a recognisable forger) and refuses.
        cases = (
            ("unexplained", ["/usr/bin/python3", "/opt/h/run"],
             "5000221 (/usr/bin/python3 /opt/h/run) in alpha-new.service"),
            ("forger", ["/usr/bin/python3", "/opt/keepalive_nodes.py"],
             "5000221 (/usr/bin/python3 /opt/keepalive_nodes.py), a health forger, in alpha-.service"),
            ("nothing appears", None, None),
        )
        for label, argv, named in cases:
            with self.subTest(case=label):
                self.setUp()
                self.sleep_shim()
                self.write("etc/systemd/system/alpha-.service.d/zz.conf", self.N17_DROPIN)
                self.write("etc/systemd/system/beta-.service.d/zz.conf",
                           "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
                self.proc(5000220, "/system.slice/beta-x.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"],
                          immortal=True)
                self.write("systemd/onsleepgone/5000220", "")
                if argv:
                    self.proc_on("onsleep", 5000221, "/system.slice/alpha-new.service", argv)
                out = self.deploy_k()
                self.assertTrue(os.path.exists(os.path.join(self.root, "systemd/slept")), "the SIGTERM wait ran")
                self.assertFalse(self.alive(5000220))
                if argv is None:
                    self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                    self.assertIn("DEPLOY-CONTINUED", out.stdout)
                    continue
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("while the retirement waited, the drop-in of alpha-.service came to reach process(es) "
                              "it may have started: " + named, out.stdout)
                self.assertTrue(self.alive(5000221))
                self.assertNotIn("5000221", self.kills())

    def test_t8_a_recognisable_forger_in_a_late_alias_unit_is_ended_after_the_reload(self):
        # The discovery right after the reload (before any wait) reaches a unit that started after
        # the precheck through its alias: its recognisable forger is ended, not merely refused
        # later, as T93's late template instance is (G01 replaces that discovery with the stored list).
        self.write("etc/systemd/system/foo-.service.d/zz.conf",
                   "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
        self.sd("names", "canonical.service", "canonical.service foo-alias.service")
        self.proc_on("onreload", 5000213, "/system.slice/canonical.service",
                     ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertIn("kill -s TERM 5000213", self.kills())
        self.assertFalse(self.alive(5000213))
        self.assertIn("ended the health-forging process(es) 5000213 that a drop-in started in foo-.service "
                      "(canonical.service)", out.stdout)

    def test_t8_n21_a_stopped_unit_that_starts_during_a_drop_in_wait_refuses(self):
        # forge.service was stopped and verified quiet after the reload; it starts again while the
        # wait ends a drop-in's forger. The last check after every wait refuses.
        for again in (True, False):
            with self.subTest(again=again):
                self.setUp()
                self.sleep_shim()
                self.write("etc/systemd/system/forge.service", self.INLINE_FORGER)
                self.sd("active", "forge.service")
                self.write("etc/systemd/system/beta-.service.d/zz.conf",
                           "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n")
                self.proc(5000220, "/system.slice/beta-x.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"],
                          immortal=True)
                self.write("systemd/onsleepgone/5000220", "")
                if again:
                    self.sd("onsleepactive", "forge.service")
                out = self.deploy_k()
                self.assertTrue(os.path.exists(os.path.join(self.root, "systemd/slept")), "the SIGTERM wait ran")
                if again:
                    self.assertNotEqual(out.returncode, 0, out.stdout)
                    self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                    self.assertIn("forge.service is running again (it started while the retirement waited)", out.stdout)
                else:
                    # Anti-vacuity: it stays stopped, the deploy continues.
                    self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                    self.assertIn("DEPLOY-CONTINUED", out.stdout)

    # ---- FU-SYNCHUB Turn 9 (2026-10-02): N-23 (the Claude seat's test_c1) and N-22
    # A hook in the systemctl model: at the first `show -p MainPID` of alpha-new.service, every PID in
    # systemd/race_gone/ leaves the fake /proc and every PID in systemd/race_orphan/ is reparented to
    # PID 1 (a launcher that exited after starting its worker). It fires once, after the decision's
    # process listing, and records itself in race.log.
    RACE_HOOK = r'''r="${WINS_KEEPALIVE_ROOT}"; st="${r}/systemd"
if [[ "$1" == show && "$3" == MainPID && "${!#}" == alpha-new.service && -d "${st}/race_gone" && ! -e "${st}/race_fired" ]]; then
  touch "${st}/race_fired"; echo "RACE fired on: $*" >> "${r}/race.log"
  for f in "${st}"/race_gone/*; do [[ -e "${f}" ]] && rm -rf "${r}/proc/${f##*/}"; done
  for f in "${st}"/race_orphan/*; do
    [[ -e "${f}" ]] && printf 'Name:\tpython3\nState:\tS (sleeping)\nPPid:\t1\n' > "${r}/proc/${f##*/}/status"
  done
fi
'''
    TRUSTED_DROPIN = "[Service]\nExecStartPost=/usr/bin/python3 /opt/keepalive_nodes.py\n"

    def n23_fixture(self, alpha_dropin, gone=(), orphan=(), launcher=True):
        """The Claude seat's test_c1 shape (T:2141 across drop-ins): alpha-.service.d is checked first
        and passes; the wait that ends beta-.service.d's forger 5000220 starts, in alpha-new.service, a
        recognisable launcher 5000231 with its worker child 5000232 (or, launcher=False, a lone worker
        5000233). The last pass then decides about alpha-new.service."""
        self.sleep_shim()
        body = Path(self.root, "shims", "systemctl").read_text()
        Path(self.root, "shims", "systemctl").write_text(
            body.replace("#!/usr/bin/env bash\n", "#!/usr/bin/env bash\n" + self.RACE_HOOK, 1))
        os.makedirs(os.path.join(self.root, "systemd/race_gone"), exist_ok=True)
        for pid in gone:
            self.write(f"systemd/race_gone/{pid}", "")
        for pid in orphan:
            self.write(f"systemd/race_orphan/{pid}", "")
        self.write("etc/systemd/system/alpha-.service.d/zz.conf", alpha_dropin)
        self.write("etc/systemd/system/beta-.service.d/zz.conf", self.TRUSTED_DROPIN)
        self.proc(5000220, "/system.slice/beta-x.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"],
                  immortal=True)
        self.write("systemd/onsleepgone/5000220", "")
        if launcher:
            self.proc_on("onsleep", 5000231, "/system.slice/alpha-new.service",
                         ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
            self.proc_on("onsleep", 5000232, "/system.slice/alpha-new.service", ["/usr/bin/python3", "/opt/h/run"],
                         ppid=5000231)
        else:
            self.proc_on("onsleep", 5000233, "/system.slice/alpha-new.service", ["/usr/bin/python3", "/opt/h/run"])
        return self.deploy_k()

    def test_t9_n23_a_launcher_that_exits_during_the_last_pass_cannot_hide_its_child(self):
        # The Claude seat's N-23: the last pass took "ended" and "unexplained" from different listings;
        # launcher 5000231 exiting between them left its reparented worker 5000232 in neither, and the
        # deploy returned 0 with it alive. One listing per decision: the worker is reported (it was the
        # launcher's when the listing was taken) and the deploy refuses, for both drop-in shapes.
        for shape, dropin in (("side command only", self.TRUSTED_DROPIN), ("Environment= (N-17)", self.N17_DROPIN)):
            with self.subTest(shape=shape, launcher="stays"):
                # Anti-vacuity: no race; both are named as forgers.
                self.setUp()
                out = self.n23_fixture(dropin)
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("5000231 (/usr/bin/python3 /opt/keepalive_nodes.py), a health forger, in alpha-.service",
                              out.stdout)
                self.assertIn("5000232 (/usr/bin/python3 /opt/h/run), a health forger, in alpha-.service", out.stdout)
            with self.subTest(shape=shape, launcher="exits"):
                self.setUp()
                out = self.n23_fixture(dropin, gone=(5000231,), orphan=(5000232,))
                race_log = Path(self.root, "race.log")
                self.assertTrue(race_log.exists(), "the race hook fired: " + out.stdout)
                self.assertIn("RACE fired on: show -p MainPID --value -- alpha-new.service", race_log.read_text())
                self.assertFalse(self.alive(5000231))
                self.assertTrue(self.alive(5000232))
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("while the retirement waited, the drop-in of alpha-.service came to reach process(es) it "
                              "may have started: 5000232 (/usr/bin/python3 /opt/h/run), a health forger, in alpha-.service",
                              out.stdout)
                self.assertNotIn("5000231 (", out.stdout.split("came to reach")[-1], "a process verified gone is not named")
                self.assertNotIn("5000232", self.kills())
            with self.subTest(shape=shape, launcher="both gone"):
                # Anti-vacuity: launcher and worker both gone by the time they would be reported; nothing
                # the drop-in reaches runs, so the deploy continues.
                self.setUp()
                out = self.n23_fixture(dropin, gone=(5000231, 5000232))
                self.assertTrue(Path(self.root, "race.log").exists(), "the race hook fired")
                self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                self.assertIn("DEPLOY-CONTINUED", out.stdout)
        with self.subTest(case="a lone unexplained worker that is gone when it would be reported"):
            self.setUp()
            out = self.n23_fixture(self.N17_DROPIN, gone=(5000233,), launcher=False)
            self.assertTrue(Path(self.root, "race.log").exists(), "the race hook fired")
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("DEPLOY-CONTINUED", out.stdout)
        with self.subTest(case="the same worker, still there"):
            self.setUp()
            out = self.n23_fixture(self.N17_DROPIN, launcher=False)
            self.assertNotEqual(out.returncode, 0, out.stdout)
            self.assertIn("5000233 (/usr/bin/python3 /opt/h/run) in alpha-new.service", out.stdout)

    def n22_fixture(self, when):
        """N-22: forger 5000250 (started by an exact-parent drop-in) forks a short child 5000251 while
        the precheck decides. when="before": the child is there from the start; when="decision": it
        appears when the installer reads the drop-in to decide whether it may change the main process
        (the grep in _keepalive_dropin_main_trusted), after the decision's process listing; with two
        listings that was between them."""
        self.write("etc/systemd/system/wins-hub.service.d/zz.conf", self.TRUSTED_DROPIN)
        self.sd("mainpid", "wins-hub.service", "5000249")
        self.proc(5000249, "/system.slice/wins-hub.service", ["/usr/local/bin/wins-hub"])
        self.proc(5000250, "/system.slice/wins-hub.service", ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
        child = ("/system.slice/wins-hub.service", ["sleep", "1"])
        if when == "before":
            self.proc(5000251, child[0], child[1], ppid=5000250)
        else:
            self.proc_on("forkon", 5000251, child[0], child[1], ppid=5000250)
            self.shim("grep", 'r="${WINS_KEEPALIVE_ROOT}"\n'
                      'if [[ "$*" == *"Documentation|ExecStartPre"* && -d "${r}/systemd/forkon/5000251" ]]; then\n'
                      '  cp -R "${r}/systemd/forkon/5000251" "${r}/proc/5000251"; rm -rf "${r}/systemd/forkon/5000251"\n'
                      '  echo forked >> "${r}/fork.log"\nfi\nexec /usr/bin/grep "$@"')
        return self.deploy_k()

    def test_t9_n22_a_forgers_child_forked_while_the_precheck_decides_is_the_forgers(self):
        for when in ("before", "decision"):
            with self.subTest(when=when):
                self.setUp()
                out = self.n22_fixture(when)
                if when == "decision":
                    self.assertTrue(Path(self.root, "fork.log").exists(), "the child was forked during the decision")
                self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                self.assertIn("DEPLOY-CONTINUED", out.stdout)
                self.assertNotIn("5000251 (sleep 1) in", out.stdout, "never reported as unexplained")
                self.assertFalse(self.alive(5000250))
                self.assertFalse(self.alive(5000251), "ended with the forger it descends from")
                self.assertTrue(self.alive(5000249), "the unit's main process stays")
        with self.subTest(case="anti-vacuity: the same child with its forger already gone is unexplained"):
            self.setUp()
            self.write("etc/systemd/system/wins-hub.service.d/zz.conf", self.TRUSTED_DROPIN)
            self.sd("mainpid", "wins-hub.service", "5000249")
            self.proc(5000249, "/system.slice/wins-hub.service", ["/usr/local/bin/wins-hub"])
            self.proc(5000251, "/system.slice/wins-hub.service", ["sleep", "1"], ppid=1)
            out = self.deploy_k()
            self.assertNotEqual(out.returncode, 0, out.stdout)
            self.assertIn("5000251 (sleep 1) in wins-hub.service", out.stdout)
            self.assertIn("Nothing was changed", out.stdout)

    def test_t9_an_unreadable_command_line_is_counted_and_never_leaks_to_stderr(self):
        # A /proc entry still there whose cmdline cannot be read: it cannot be shown to be a forger, so
        # it is unexplained (refused, named with an empty command), and the failed read stays off stderr.
        self.write("etc/systemd/system/wins-hub.service.d/zz.conf", self.TRUSTED_DROPIN)
        self.sd("mainpid", "wins-hub.service", "5000259")
        self.proc(5000259, "/system.slice/wins-hub.service", ["/usr/local/bin/wins-hub"])
        self.proc(5000260, "/system.slice/wins-hub.service", ["/usr/bin/python3", "/opt/h/run"])
        os.remove(os.path.join(self.root, "proc/5000260/cmdline"))
        out = self.deploy_k()
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("5000260 () in wins-hub.service", out.stdout)
        self.assertNotIn("No such file or directory", out.stderr)

    # ---- FU-SYNCHUB Turn 10 (2026-10-02): N-24, the Claude seat's Turn 9 probes test_c3 to test_c5
    # A legacy (v1) host with cgroup2 also mounted: systemd tracks the unit in the v1 name=systemd
    # hierarchy, and the kernel adds the empty unified line "0::/" last.
    V1_TRAIL = "1:name=systemd:/system.slice/wins-hub.service\n0::/\n"
    V1_PLAIN = "1:name=systemd:/system.slice/wins-hub.service\n"

    def n24_base(self):
        self.write("etc/systemd/system/wins-hub.service.d/zz.conf", self.TRUSTED_DROPIN)
        self.sd("mainpid", "wins-hub.service", "5000301")
        self.proc(5000301, "/system.slice/wins-hub.service", ["/usr/local/bin/wins-hub"])

    def test_t10_n24_a_v1_forger_with_a_trailing_unified_line_is_ended(self):
        # Turn 9 dropped the process: the cgroup loop's last command, [[ -n "" ]] for the empty
        # component of "0::/", made the read look failed. The forger then ran on and the deploy returned 0.
        for label, cg in (("plain v1 (control)", self.V1_PLAIN), ("v1 + trailing 0::/", self.V1_TRAIL)):
            with self.subTest(cg=label):
                self.setUp()
                self.n24_base()
                self.proc(5000302, cg, ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
                out = self.deploy_k()
                self.assertFalse(self.alive(5000302), label + ": the forger is ended. " + out.stdout)
                self.assertIn("kill -s TERM 5000302", self.kills())
                self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                self.assertIn("DEPLOY-CONTINUED", out.stdout)
                self.assertTrue(self.alive(5000301), "the unit's own main process stays")

    def test_t10_n24_a_v1_unexplained_process_with_a_trailing_unified_line_refuses(self):
        for label, cg in (("plain v1 (control)", self.V1_PLAIN), ("v1 + trailing 0::/", self.V1_TRAIL)):
            with self.subTest(cg=label):
                self.setUp()
                self.n24_base()
                self.proc(5000303, cg, ["/usr/bin/python3", "/opt/h/run"])
                out = self.deploy_k()
                self.assertNotEqual(out.returncode, 0, label + ": " + out.stdout)
                self.assertNotIn("DEPLOY-CONTINUED", out.stdout)
                self.assertIn("5000303 (/usr/bin/python3 /opt/h/run) in wins-hub.service", out.stdout)
                self.assertTrue(self.alive(5000303))

    def test_t10_drop_in_membership_uses_only_the_systemd_hierarchy(self):
        # T:1429 for the drop-in path: a cpu-controller line naming wins-hub.service does not place a
        # process there; the systemd hierarchy says cron.service, so the process is not the drop-in's.
        self.n24_base()
        self.proc(5000304, "12:cpu,cpuacct:/system.slice/wins-hub.service\n1:name=systemd:/system.slice/cron.service\n",
                  ["/usr/bin/python3", "/opt/keepalive_nodes.py"])
        out = self.deploy_k()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DEPLOY-CONTINUED", out.stdout)
        self.assertTrue(self.alive(5000304), "a process in cron.service is not the drop-in's")
        self.assertNotIn("5000304", self.kills())

    def test_a_clean_host_is_reported_clean(self):
        self.write("etc/cron.d/wins-backup", "0 3 * * * root /usr/local/bin/wins-backup\n")
        out = self.run_fn("retire_health_forging_keepalive")
        self.assertEqual(out.returncode, 0)
        self.assertIn("no keepalive_nodes script or runner found", out.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "var/backups")))

    def test_an_unreadable_user_crontab_is_never_written_back_empty(self):
        self.write("var/spool/cron/crontabs/root", "* * * * * python3 /root/vpn_auth/keepalive_nodes.py\n", 0o600)
        Path(self.root, "shims", "crontab").write_text("#!/usr/bin/env bash\n[[ \"$3\" == -l ]] && exit 1\n"
                                                       "echo WROTE >> \"$WINS_KEEPALIVE_ROOT/wrote\"\n")
        out = self.run_fn("retire_health_forging_keepalive")
        self.assertNotEqual(out.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.root, "wrote")))

    def test_main_runs_retire_on_deploy_and_report_on_preflight(self):
        source = HUB_INSTALLER.read_text(encoding="utf-8")
        main = source.rsplit("\nmain() {", 1)[1]
        preflight = main.split("--preflight|--validate)", 1)[1].split(";;", 1)[0]
        self.assertIn("report_health_forging_keepalive", preflight)
        self.assertNotIn("retire_health_forging_keepalive", preflight)
        deploy = main.split("esac", 1)[1]
        self.assertLess(deploy.index("preflight_control"), deploy.index("retire_health_forging_keepalive || return 1"))
        self.assertLess(deploy.index("retire_health_forging_keepalive"), deploy.index("write_env"))


FORGER_SAMPLE = """
conn.execute('''
    UPDATE nodes SET
        status = 'online', operator_enabled = 1, management_status = 'ok',
        last_heartbeat = ?
    WHERE slug IN (?)
''')
"""


def health_forgers(text: str) -> list[str]:
    return [m.group(0)[:60] for m in re.finditer(r"UPDATE\s+nodes\s+SET(.{0,2000}?)WHERE", text, re.S | re.I)
            if "management_status" in m.group(1) and "last_heartbeat" in m.group(1)]


class RepoStopsShippingTheForgerTests(unittest.TestCase):
    def test_no_shipped_tool_forges_node_health(self):
        self.assertTrue(health_forgers(FORGER_SAMPLE), "anti-vacuity: the scanner must see a forger")
        self.assertFalse((REPO / "tools" / "apply_kansas_winn3.py").exists())
        offenders = []
        for base in ("tools", "deploy", "installer"):
            for path in sorted((REPO / base).rglob("*")):
                if not path.is_file() or path.suffix not in {".py", ".sh", ".ps1"} \
                        or path.name.startswith("test_") or ".orig" in path.name:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                if "keepalive_nodes" in text or health_forgers(text):
                    offenders.append(str(path.relative_to(REPO)))
        self.assertEqual(offenders, [])


# ============================================================ SYNC-23 ======

class DeadContractNameTests(unittest.TestCase):
    def test_dead_names_are_gone_and_the_profile_path_is_persisted(self):
        data = DATA_INSTALLER.read_text(encoding="utf-8")
        for name in ("HUB_RESYNC_PEERS_URL", "HUB_MANAGEMENT_TUNNEL_BOOTSTRAP_URL",
                     "carry the admin token"):
            self.assertNotIn(name, data, name)
        writer = data.split("\nwrite_node_env() {", 1)[1].split("\n}\n", 1)[0] \
            if "\nwrite_node_env() {" in data else data
        self.assertIn('write_env_kv AWG_OBFUSCATION_PROFILE "${AWG_OBFUSCATION_PROFILE}"', writer)
        register = data.split("AWG_OBFUSCATION_PROFILE=\"${AWG_OBFUSCATION_PROFILE:-/etc/winsvpn/awg-obfuscation.env}\"")
        self.assertGreaterEqual(len(register), 3, "renderer and register script both read the variable")


# ============================================================ SYNC-08 ======

_IDENTITY_INDEX: dict[str, int] = {}


def reg_payload(slug, revision=REV_A, **overrides):
    """A registration whose identity (endpoint, key, host) is unique per slug,
    because the hub refuses a second node claiming another's identity."""
    index = _IDENTITY_INDEX.setdefault(slug, len(_IDENTITY_INDEX) + 10)
    payload = dark.registration_payload(slug)
    payload.data_plane_code_revision = revision
    payload.endpoint = f"198.51.100.{index}:9110"
    payload.ssh_host = f"198.51.100.{index}"
    payload.public_key = base64.b64encode(hashlib.sha256(slug.encode()).digest()).decode()
    for key, value in overrides.items():
        setattr(payload, key, value)
    return payload


class InstallerRerunTests(dark.DataPlaneDarkStartTests):
    """Fable 5.1 ruling 2026-09-29 Q1, on the real hub app."""

    def setUp(self):
        super().setUp()
        self.alerts = []
        self.mod.security_alert = lambda *a, **k: self.alerts.append((a[0], a[1], k.get("details")))
        # H6 built the hub-run gate. These tests are about the reopen sweep, not
        # the SSH check (test_hub_offnode_gate_h6.py), so the builder is a
        # recorder that never produces a record.
        self.builder_calls = []

        def builder(conn, node):
            self.builder_calls.append(dict(node)["slug"])
            return "", ["hub-run check: the builder ran"]

        patcher = patch.object(self.mod, "hub_offnode_gate_attempt", side_effect=builder)
        patcher.start()
        self.addCleanup(patcher.stop)

    def register_rev(self, slug, revision=REV_A, **overrides):
        return self.mod.register_node(reg_payload(slug, revision, **overrides),
                                      harness.FakeRequest(path="/api/v1/nodes/register"))

    def live_node(self, slug, revision=REV_A, tier="premium"):
        self.seed_placeholder(slug)
        self.register_rev(slug, revision)
        now = self.mod.utcnow().isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET management_status='ok', data_plane_status='ok', data_plane_ok_at=?,"
                " data_plane_udp_status='ok', data_plane_udp_ok_at=? WHERE slug=?", (now, now, slug))
        self.promote(slug)
        if tier == "free":
            self.mod.admin_set_node_tier(self.request, slug=slug, tier="free", evidence_sha256="",
                                         x_admin_token=dark.ADMIN_TOKEN)

    def withdraw(self, slug):
        return self.mod.withdraw_node_for_deployment(
            slug, harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/withdraw"),
            x_node_token=dark.NODE_TOKEN)

    def complete(self, slug, withdrawal_id):
        return self.mod.complete_node_deployment(
            slug, self.mod.DeploymentWithdrawalCompletion(withdrawal_id=withdrawal_id),
            harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/complete"),
            x_node_token=dark.NODE_TOKEN)

    def rerun(self, slug, revision=REV_A, between=None, **overrides):
        withdrawn = self.withdraw(slug)
        time.sleep(0.002)
        self.register_rev(slug, revision, **overrides)
        if between:
            between()
        return self.complete(slug, withdrawn["withdrawal_id"])

    def reopen(self, armed=True):
        with patch.object(self.mod, "node_auto_reopen_arm",
                          return_value=self.mod.utcnow().isoformat() if armed else None):
            return self.mod.auto_reopen_health_closed_nodes()

    # 1
    def test_rerun_of_a_node_that_was_not_live_stays_a_plain_closure(self):
        slug = "fresh"
        self.seed_placeholder(slug)
        self.register_rev(slug)
        out = self.rerun(slug)
        self.assertFalse(out["auto_reopen_pending"])
        self.assertIn("prior operator_enabled != 1 (the node was not live when withdrawn)", out["reasons"])
        self.assertIsNone(self.node(slug)["health_closed_at"])
        self.assertIn((2, "node completed installer rerun; manual evidenced promotion required"),
                      [(a[0], a[1]) for a in self.alerts])

    # 2
    def test_rerun_of_a_live_node_is_recorded_as_installer_rerun(self):
        slug = "live"
        self.live_node(slug)
        out = self.rerun(slug)
        self.assertTrue(out["auto_reopen_pending"], out)
        self.assertEqual(out["reasons"], [])
        row = self.node(slug)
        self.assertEqual(row["health_closed_reason"], "installer_rerun")
        self.assertEqual(row["latch_cause"], "installer_rerun_pending")
        self.assertTrue(row["deployment_completed_at"])
        self.assertEqual(row["operator_enabled"], 0, "recorded, never opened at completion")
        self.assertIn((3, "node completed installer rerun; automatic reopen pending proofs"),
                      [(a[0], a[1]) for a in self.alerts])

    # 3
    def test_rerun_identity_changes_are_named(self):
        changes = {
            "public_key": ("public_key", "C" * 43 + "="),
            "endpoint": ("endpoint", "198.51.100.8:9110"),
            "wg_port": ("wg_port", 9111),
            "ssh_host": ("ssh_host", "198.51.100.9"),
            "stealth_endpoint": ("stealth_endpoint", "x.example.test:80"),
            "stealth_public_port": ("stealth_public_port", 8080),
            "stealth_transports": ("stealth_transports", '[{"security":"tls"}]'),
            "xray_uuid": ("xray_uuid", "11111111-2222-4333-8444-555555555556"),
            "xray_path": ("xray_path", "/other"),
            "xray_security": ("xray_security", "tls"),
            "regional_aliases": ("regional_aliases", '["a.example.test"]'),
            "obfuscation_sha256": ("obfuscation_json", '{"jc": 9}'),
            "protocol_version": ("protocol_version", "winn/3"),
            "carrier_classes": ("carrier_classes", "udp"),
            "path_mtu": ("path_mtu", 1400),
            # H7 (design 3.17): the identity digest of the stored, verified
            # descriptor replaces the raw descriptor hash, so a stored g1
            # descriptor (signed here with the throwaway test key) is what
            # changes it; a renewal does not (H7's own suite).
            "winn3_identity_sha256": ("winn3_descriptor_json", lambda slug: json.dumps(dict(zip(
                ("payload", "sig"), descriptor.envelope_for(descriptor.descriptor_payload(node=slug)))))),
        }
        self.assertEqual(set(changes), set(self.mod.NODE_RERUN_IDENTITY_FIELDS))
        os.environ["WINN3_DESCRIPTOR_PUBKEY_G1"] = descriptor.SLOT_PUBS["g1"]
        for index, (field, (column, value)) in enumerate(sorted(changes.items())):
            with self.subTest(field=field):
                slug = f"ident-{index}"
                self.live_node(slug)

                def change(column=column, value=value, slug=slug):
                    with self.db() as conn:
                        conn.execute(f"UPDATE nodes SET {column} = ? WHERE slug = ?",
                                     (value(slug) if callable(value) else value, slug))
                out = self.rerun(slug, between=change)
                self.assertFalse(out["auto_reopen_pending"])
                self.assertIn(f"identity changed: {field}", out["reasons"])
                self.assertIsNone(self.node(slug)["health_closed_at"])

    # 4
    def test_rerun_after_a_rebootstrap_is_a_plain_closure(self):
        slug = "rebooted"
        self.live_node(slug)
        withdrawn = self.withdraw(slug)
        self.register_rev(slug)
        # The bootstrap exchange replaces node_token_hash; the node then holds
        # only the new token.
        fresh = dark.NODE_TOKEN + "-rebootstrapped"
        with self.db() as conn:
            conn.execute("UPDATE nodes SET node_token_hash = ? WHERE slug = ?",
                         (self.mod.token_digest(fresh), slug))
        out = self.mod.complete_node_deployment(
            slug, self.mod.DeploymentWithdrawalCompletion(withdrawal_id=withdrawn["withdrawal_id"]),
            harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/complete"), x_node_token=fresh)
        self.assertFalse(out["auto_reopen_pending"])
        self.assertIn("node token changed since the withdrawal (re-bootstrapped)", out["reasons"])

    def test_rerun_needs_an_online_registration_after_the_withdrawal(self):
        for slug, status in (("no-register", None), ("maint-register", "maintenance")):
            with self.subTest(slug=slug):
                self.live_node(slug)
                withdrawn = self.withdraw(slug)
                if status:
                    time.sleep(0.002)
                    self.register_rev(slug, status=status)
                out = self.complete(slug, withdrawn["withdrawal_id"])
                self.assertFalse(out["auto_reopen_pending"])
                self.assertIn("no online registration since the withdrawal", out["reasons"])

    # 5
    def test_rerun_lineage_rules(self):
        cases = [
            ("unprov", REV_A, "unprovable", None, False, "installer revision is not provable (unprovable)"),
            ("staged", REV_A, REV_B + "/staged", None, False, "installer revision is not provable"),
            ("newrev", REV_A, REV_B, None, False, "installer revision was never evidenced by a manual promotion"),
            ("same", REV_A, REV_A, None, True, ""),
            ("pinned", REV_A, REV_B, REV_B, True, ""),
            ("pinned-other", REV_A, REV_A, REV_B, False, "installer revision differs from WINS_EXPECTED_DATA_PLANE_REVISION"),
        ]
        for slug, before, after, pin, eligible, reason in cases:
            with self.subTest(slug=slug), patch.object(self.mod, "WINS_EXPECTED_DATA_PLANE_REVISION", pin or ""):
                self.live_node(slug, before)
                out = self.rerun(slug, after)
                self.assertEqual(out["auto_reopen_pending"], eligible, out)
                if reason:
                    self.assertTrue(any(r.startswith(reason) for r in out["reasons"]), out["reasons"])
        # (c): a revision an operator evidenced on another node is eligible.
        self.live_node("evidence-b", REV_B)
        self.live_node("moves-to-b", REV_A)
        out = self.rerun("moves-to-b", REV_B)
        self.assertTrue(out["auto_reopen_pending"], out)
        # Anti-vacuity: a hub reopen's ledger row never evidences a revision.
        rev_c = "sha256:" + "c" * 64
        with self.db() as conn:
            conn.execute(
                "INSERT INTO node_promotion_events (promotion_id, slug, promoted_at, tier, evidence_sha256,"
                " operator_source_hash, node_status, management_status, data_plane_status, data_plane_ok_at,"
                " data_plane_code_revision) VALUES ('p-hub', 'evidence-b', ?, 'premium', ?, "
                "'auto_reopen_installer_rerun', 'online', 'ok', 'ok', ?, ?)",
                (self.mod.utcnow().isoformat(), "d" * 64, self.mod.utcnow().isoformat(), rev_c))
        self.live_node("moves-to-c", REV_A)
        out = self.rerun("moves-to-c", rev_c)
        self.assertFalse(out["auto_reopen_pending"], out)

    # 6
    def test_rerun_reopen_is_held_while_the_carrying_canaries_do_not_exist(self):
        slug = "held"
        self.live_node(slug)
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        out = self.reopen()
        self.assertIn(slug, out["held"])
        # H5: the carry columns exist now, so a node with no carrying proof is
        # held by the proof rule, not by "not available" (an older row without
        # the columns still gets that message: see the dict-based test below).
        self.assertIn(
            "udp: no carrying proof newer than the rerun completion (unknown)", out["held"][slug])
        self.assertNotIn(self.BUILDER, out["held"][slug], "the builder runs only when all else passes")
        self.assertEqual(self.builder_calls, [])
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/3' WHERE slug=?", (slug,))
        out = self.reopen()
        self.assertTrue(any(r.startswith("winn/3: no per-slug v3 canary") for r in out["held"][slug]),
                        out["held"][slug])

    def test_rerun_carry_rule_reads_each_advertised_transport(self):
        completed = self.mod.utcnow()
        before = (completed - timedelta(minutes=5)).isoformat()
        after = (completed + timedelta(minutes=5)).isoformat()
        base = {"deployment_completed_at": completed.isoformat(), "direct_awg_enabled": 1,
                "endpoint": "198.51.100.7:9110", "public_key": "A" * 43 + "=", "ssh_host": "198.51.100.7",
                "stealth_endpoint": "", "protocol_version": "winn/1"}
        fn = self.mod.installer_rerun_carry_failures
        self.assertEqual(fn(base), ["udp: awg carrying canary not available"])
        self.assertEqual(fn({**base, "data_plane_udp_carry_status": "ok", "data_plane_udp_carry_ok_at": after}), [])
        self.assertEqual(len(fn({**base, "data_plane_udp_carry_status": "ok", "data_plane_udp_carry_ok_at": before})), 1)
        self.assertEqual(len(fn({**base, "data_plane_udp_carry_status": "failed", "data_plane_udp_carry_ok_at": after})), 1)
        self.assertEqual(fn({**base, "direct_awg_enabled": 0}), [], "an unadvertised transport is not required")
        stealth = {**base, "direct_awg_enabled": 0, "stealth_endpoint": "s.example.test:80",
                   "stealth_transports": "[]", "xray_security": "none", "xray_path": "/p",
                   "xray_uuid": "11111111-2222-4333-8444-555555555555", "stealth_public_port": 80}
        self.assertIn("stealth: awg carrying canary not available", fn(stealth))
        v3 = {**base, "direct_awg_enabled": 0, "protocol_version": "winn/3",
              "winn3_canary_status": "ok", "winn3_canary_ok_at": after}
        self.assertEqual(fn(v3), [])
        self.assertEqual(len(fn({**v3, "winn3_canary_ok_at": before})), 1)
        self.assertEqual(len(fn({**v3, "winn3_canary_status": "unknown"})), 1)

    # 7
    def test_rerun_hub_sourced_gate_is_accepted_only_for_the_rerun_reopen(self):
        slug = "gate"
        self.live_node(slug)
        self.rerun(slug)
        gate = self.offnode_gate(slug)
        with self.db() as conn:
            self.assertEqual(self.mod.verify_offnode_gate_for_use(conn, slug, gate), [],
                             "an operator gate stays acceptable everywhere")
            conn.execute("UPDATE node_offnode_gates SET source='hub' WHERE gate_sha256=?", (gate,))
            refused = self.mod.verify_offnode_gate_for_use(conn, slug, gate)
            self.assertIn("gate record source 'hub' is accepted only for an installer rerun or fresh install reopen",
                          refused)
            self.assertEqual(self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True), [])
            conn.execute("UPDATE nodes SET health_closed_reason='heartbeat_stale' WHERE slug=?", (slug,))
            self.assertIn("gate record source 'hub' is accepted only for an installer rerun or fresh install reopen",
                          self.mod.verify_offnode_gate_for_use(conn, slug, gate, allow_hub_source=True))
            conn.execute("UPDATE nodes SET health_closed_reason='installer_rerun' WHERE slug=?", (slug,))
        with self.assertRaises(harness.HTTPException) as caught:
            self.mod.admin_set_node_tier(self.request, slug=slug, tier="premium", evidence_sha256=gate,
                                         confirm_slug=slug, x_admin_token=dark.ADMIN_TOKEN)
        self.assertIn("accepted only for an installer rerun or fresh install reopen", caught.exception.detail)

    # 8
    def test_rerun_reopen_flip_restores_the_tier_and_records_everything(self):
        for tier in ("premium", "free"):
            with self.subTest(tier=tier):
                slug = f"flip-{tier}"
                self.live_node(slug, tier=tier)
                self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
                gate = self.offnode_gate(slug)
                with patch.object(self.mod, "node_auto_reopen_failures", return_value=[]), \
                        patch.object(self.mod, "installer_rerun_carry_failures", return_value=[]):
                    out = self.reopen()
                self.assertIn(slug, out["reopened"], out)
                row = self.node(slug)
                self.assertEqual(row["operator_enabled"], 1)
                self.assertEqual(row["free_access_enabled"], 1 if tier == "free" else 0)
                self.assertEqual(row["latch_cause"], "auto_reopen_installer_rerun")
                self.assertIsNone(row["health_closed_at"])
                with self.db() as conn:
                    event = conn.execute(
                        "SELECT * FROM node_promotion_events WHERE slug=? AND "
                        "operator_source_hash='auto_reopen_installer_rerun'", (slug,)).fetchone()
                    self.assertEqual(event["tier"], tier)
                    self.assertEqual(event["evidence_sha256"], gate)
                    latch = conn.execute(
                        "SELECT cause, detail_json FROM node_latch_events WHERE slug=? "
                        "ORDER BY event_id DESC LIMIT 1", (slug,)).fetchone()
                    self.assertEqual(latch["cause"], "auto_reopen_installer_rerun")
                    detail = json.loads(latch["detail_json"])
                    self.assertEqual(detail["installer_rerun"]["lineage_rule"], "same_revision")
                    self.assertEqual(conn.execute(
                        "SELECT used_for FROM node_offnode_gates WHERE gate_sha256=?", (gate,)).fetchone()[0],
                        "auto_reopened")
        # The daily budget is shared: installer-rerun reopens count against it.
        slug = "budget"
        self.live_node(slug)
        self.rerun(slug)
        with self.db() as conn:
            for _ in range(self.mod.NODE_AUTO_REOPEN_MAX_PER_DAY):
                conn.execute(
                    "INSERT INTO node_latch_events (slug, changed_at, from_value, to_value, cause) "
                    "VALUES (?, ?, 0, 1, 'auto_reopen_installer_rerun')", (slug, self.mod.utcnow().isoformat()))
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            failures = self.mod.node_auto_reopen_failures(conn, row, self.mod.utcnow().isoformat())
            self.assertTrue(any("automatic reopen used" in f for f in failures), failures)
            conn.execute("UPDATE node_latch_events SET cause='operator_promotion' "
                         "WHERE slug=? AND cause='auto_reopen_installer_rerun'", (slug,))
        with self.db() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone()
            failures = self.mod.node_auto_reopen_failures(conn, row, self.mod.utcnow().isoformat())
            self.assertFalse(any("automatic reopen used" in f for f in failures), failures)

    BUILDER = "offnode gate: hub-run check: the builder ran"

    def test_round2_gate_builder_order_and_expired_records(self):
        slug = "builder"
        self.live_node(slug)
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        gate_only = ["offnode gate: no verified node-side gate record with this digest for this node"]
        with patch.object(self.mod, "node_auto_reopen_failures", return_value=list(gate_only)), \
                patch.object(self.mod, "installer_rerun_carry_failures", return_value=[]):
            self.assertIn(self.BUILDER, self.reopen()["held"][slug])
            self.assertEqual(self.builder_calls, [slug])
            # Sol N-5: an unused record past the 2 h validity is not a usable gate.
            with self.db() as conn:
                conn.execute(
                    "INSERT INTO node_offnode_gates (gate_sha256, slug, recorded_at, cleanup_confirmed_at,"
                    " expected_v3_sha256, node_report, node_report_sha256) VALUES (?, ?, ?, '', '', 'r', ?)",
                    ("e" * 64, slug, (self.mod.utcnow() - timedelta(hours=3)).isoformat(), "f" * 64))
            self.assertEqual(self.mod.node_auto_reopen_gate_record(self._conn(), slug), "")
            self.assertIn(self.BUILDER, self.reopen()["held"][slug])
        # Anti-vacuity: a fresh unused record is usable, so no builder call.
        gate = self.offnode_gate(slug)
        self.assertEqual(self.mod.node_auto_reopen_gate_record(self._conn(), slug), gate)
        with patch.object(self.mod, "node_auto_reopen_failures", return_value=list(gate_only)), \
                patch.object(self.mod, "installer_rerun_carry_failures", return_value=[]):
            self.assertNotIn(self.BUILDER, self.reopen()["held"][slug])
        # And any other failing condition keeps the builder from running.
        with patch.object(self.mod, "node_auto_reopen_failures", return_value=["heartbeat is absent or stale"]), \
                patch.object(self.mod, "node_auto_reopen_gate_record", return_value=""), \
                patch.object(self.mod, "installer_rerun_carry_failures", return_value=[]):
            self.assertNotIn(self.BUILDER, self.reopen()["held"][slug])
        self.assertEqual(self.builder_calls, [slug, slug], "only the two runs without a usable record")

    def _conn(self):
        conn = sqlite3.connect(self.mod._DB)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn

    def test_round2_a_heartbeat_is_not_a_registration(self):
        slug = "heartbeat-only"
        self.live_node(slug)
        withdrawn = self.withdraw(slug)
        time.sleep(0.002)
        # Both retained heartbeat routes set status and last_heartbeat only.
        self.mod.heartbeat(types.SimpleNamespace(slug=slug, secret_token=dark.NODE_TOKEN, status="online"),
                           harness.FakeRequest(path="/api/v1/nodes/heartbeat"))
        row = self.node(slug)
        self.assertEqual(row["status"], "online")
        out = self.complete(slug, withdrawn["withdrawal_id"])
        self.assertFalse(out["auto_reopen_pending"], out)
        self.assertIn("no online registration since the withdrawal", out["reasons"])

    def test_round2_a_maintenance_registration_then_an_online_heartbeat_is_not_enough(self):
        slug = "maint-then-hb"
        self.live_node(slug)
        withdrawn = self.withdraw(slug)
        time.sleep(0.002)
        self.register_rev(slug, status="maintenance")
        self.mod.heartbeat(types.SimpleNamespace(slug=slug, secret_token=dark.NODE_TOKEN, status="online"),
                           harness.FakeRequest(path="/api/v1/nodes/heartbeat"))
        out = self.complete(slug, withdrawn["withdrawal_id"])
        self.assertFalse(out["auto_reopen_pending"], out)
        # Anti-vacuity: an online registration after the withdrawal is enough.
        other = "online-reg"
        self.live_node(other)
        self.assertTrue(self.rerun(other)["auto_reopen_pending"])

    def test_round2_open_nodes_without_promotion_evidence_are_reported_only(self):
        good, forged = "evidenced", "forged-open"
        self.live_node(good)
        self.live_node(forged)
        with self.db() as conn:
            # A closure, then an opening by direct SQL that names no cause:
            # the forger's shape (tools/apply_kansas_winn3.py).
            conn.execute("UPDATE nodes SET operator_enabled=0, latch_cause='operator_off' WHERE slug=?", (forged,))
            conn.execute("UPDATE nodes SET operator_enabled=1 WHERE slug=?", (forged,))
        self.alerts.clear()
        out = self.mod.audit_fleet_availability_once()
        reported = {item["slug"]: item for item in out.get("open_without_promotion_evidence", [])}
        self.assertIn(forged, reported)
        self.assertEqual(reported[forged]["last_opening_cause"], "unattributed")
        self.assertNotIn(good, reported, "an operator promotion after the last closure is evidence")
        self.assertIn((2, "open node without promotion evidence"), [(a[0], a[1]) for a in self.alerts])
        self.assertEqual(self.node(forged)["operator_enabled"], 1, "report only: no row is changed")
        # An automatic reopen after the closure is evidence too.
        with self.db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=0, latch_cause='health_x' WHERE slug=?", (forged,))
            conn.execute("UPDATE nodes SET operator_enabled=1, latch_cause='auto_reopen' WHERE slug=?", (forged,))
        out = self.mod.audit_fleet_availability_once()
        self.assertNotIn(forged, {i["slug"] for i in out.get("open_without_promotion_evidence", [])})

    def test_rerun_eligibility_is_rechecked_at_reopen_time(self):
        slug = "recheck"
        self.live_node(slug)
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        self.offnode_gate(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET endpoint='198.51.100.250:9110' WHERE slug=?", (slug,))
        with patch.object(self.mod, "node_auto_reopen_failures", return_value=[]), \
                patch.object(self.mod, "installer_rerun_carry_failures", return_value=[]):
            out = self.reopen()
        self.assertIn("eligibility: identity changed: endpoint", out["held"].get(slug, []), out)
        self.assertEqual(self.node(slug)["operator_enabled"], 0)

    # 9
    def test_rerun_switches_keep_each_class_under_its_own_flag(self):
        slug, stale = "switch", "stale"
        self.live_node(slug)
        self.rerun(slug)
        self.live_node(stale)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=0, health_closed_at=?, "
                         "health_closed_reason='heartbeat_stale', latch_cause='health_heartbeat_stale' "
                         "WHERE slug=?", (self.mod.utcnow().isoformat(), stale))
        self.assertFalse(self.mod.NODE_AUTO_REOPEN_ENABLED)
        out = self.reopen()
        self.assertIn(slug, out["held"])
        self.assertNotIn(stale, out["held"], "a health closure stays under NODE_AUTO_REOPEN_ENABLED")
        with patch.object(self.mod, "NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED", False):
            out = self.reopen()
            self.assertEqual(out["held"], {})
            self.assertEqual(out["reopened"], [])
            other = "switch-off"
            self.live_node(other)
            completed = self.rerun(other)
            self.assertFalse(completed["auto_reopen_pending"])
            self.assertTrue(any("NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED=0" in r for r in completed["reasons"]))

    # 10
    def test_rerun_window_expiry_converts_to_an_operator_closure_once(self):
        slug = "window"
        self.live_node(slug)
        self.rerun(slug)
        with self.db() as conn:
            conn.execute("UPDATE nodes SET deployment_completed_at=? WHERE slug=?",
                         ((self.mod.utcnow() - timedelta(hours=7)).isoformat(), slug))
        self.alerts.clear()
        out = self.reopen()
        self.assertEqual(out["installer_rerun_expired"], [slug])
        row = self.node(slug)
        self.assertIsNone(row["health_closed_at"])
        self.assertIsNone(row["health_closed_reason"])
        self.assertEqual(row["latch_cause"], "installer_rerun_expired")
        expired = [a for a in self.alerts if a[1].startswith("installer rerun reopen window expired")]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0][0], 2)
        self.reopen()
        self.assertEqual(len([a for a in self.alerts if a[1].startswith("installer rerun reopen window")]), 1)

    def test_rerun_hub_writes_the_switches_and_validates_them(self):
        source = HUB_INSTALLER.read_text(encoding="utf-8")
        body = source.split("\nwrite_env() {", 1)[1]
        for key in ("NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED", "NODE_INSTALLER_RERUN_REOPEN_WINDOW_SECONDS",
                    "WINS_EXPECTED_DATA_PLANE_REVISION"):
            self.assertIn(f"write_env_kv {key} ", body)
        self.assertIn('NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED_DEFAULT="${NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED:-1}"', source)
        self.assertNotIn("write_env_kv NODE_AUTO_REOPEN_ENABLED", source, "the owner's switch stays unwritten at 0")

    def test_rerun_data_plane_prints_the_hub_decision(self):
        data = DATA_INSTALLER.read_text(encoding="utf-8")
        completion = data.split("\ncomplete_data_deployment_after_postflight() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(".auto_reopen_pending == true", completion)
        self.assertIn(".reasons[]?", completion)
        self.assertNotIn("/admin/nodes/tier", completion.split("mark_data_deployment_ready", 1)[1])


# The two harness base classes' own tests belong to their files; only this
# file's tests run here.
for _cls, _base in ((RegistryGroupAbsentTests, roundo.DepartureGraceTests),
                    (InstallerRerunTests, dark.DataPlaneDarkStartTests)):
    for _name in dir(_base):
        if _name.startswith("test") and _name not in _cls.__dict__:
            setattr(_cls, _name, None)
del _cls, _base, _name


if __name__ == "__main__":
    unittest.main(verbosity=2)
