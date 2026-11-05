"""H2, design v17 3.5, 3.13, 3.14, 3.18; section 5.5 and 5.6.

The real extracted hub calls the real H1 signer with throwaway keys. SSH
transport and H3 probes are replaced at their boundaries; no host is contacted.
"""
from contextlib import contextmanager
import base64
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import threading
import time
import types

import pytest
import test_hub_h1_descriptor_signer as h1
import test_winn3_descriptor_hub as descriptors
import test_account_deletion_hub as harness


class Lane:
    def __init__(self, tmp, monkeypatch):
        self.keys = h1.Hub(tmp)
        self.clock = self.keys.clock
        self.mod = harness.load_hub(WINN3_INNER_POOL_CIDR="10.10.0.0/24",
                                    WINN3_AUTO_SIGN="1", WINN3_AUTO_CARRIER="1",
                                    WINN3_RECOVERY_MODE="0")
        monkeypatch.setenv("WINN3_DESCRIPTOR_PUBKEY_G2", base64.b64encode(self.keys.gpub).decode())
        self.mod.utcnow = lambda: datetime.fromtimestamp(self.clock[0], __import__('datetime').timezone.utc).replace(tzinfo=None)
        self.mod.time = types.SimpleNamespace(time=lambda: self.clock[0], monotonic=time.monotonic,
                                             sleep=time.sleep)
        # The slice exercises real SQLite writer transactions in memory. Host
        # file locking and get_db's WAL setup stay in the existing hub suites.
        self.database = sqlite3.connect(":memory:")
        self.database.row_factory = sqlite3.Row
        self.database_depth = 0
        @contextmanager
        def database():
            self.database_depth += 1
            try:
                yield self.database
            except BaseException:
                if self.database_depth == 1:
                    self.database.rollback()
                raise
            else:
                if self.database_depth == 1:
                    self.database.commit()
            finally:
                self.database_depth -= 1
        self.mod.get_db = database
        self.signer = self.keys.signer()
        self.slug = "lab-alpha"
        self.trace = []
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute("INSERT INTO nodes (slug,name,endpoint,status,last_heartbeat,public_key,"
                         "preshared_key,management_status,operator_enabled,free_access_enabled,"
                         "obfuscation_json,protocol_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (self.slug, "Lab Alpha", "203.0.113.10:9110", "online",
                          self.mod.utcnow().isoformat(), "A" * 43 + "=", "B" * 43 + "=", "ok", 1, 1,
                          json.dumps(descriptors.GOOD_OBFUSCATION), "winn/1"))
        self.ticket = self.keys.ticket(self.slug)
        self.pulled = self.keys.identity(self.slug)
        self.pulled["detected_public_ip"] = "203.0.113.10"
        identity = json.loads(base64.b64decode(self.pulled["identity"]))
        self.identity = identity
        hostline = identity["ssh_host_ed25519_key"]
        self.pin = tmp / "known_hosts"
        self.pin.write_text("node.example.test " + hostline + "\n")
        self.pin.chmod(0o600)
        self.mod.MANAGEMENT_KNOWN_HOSTS_PATH = str(self.pin)
        report = {"state": "active", "forward": True, "resolver": True,
                  "listen": "0.0.0.0:9111", "gateway_id": identity["gateway_id"],
                  "inner_v4": "10.10.0.1", "forward_cidr": "10.10.0.0/24",
                  "path_mtu": 1450, "plan": "udp"}
        self.update(node_token_hash=self.mod.token_digest("node-test-token"),
                    winn3_bootstrap_authorized=1, deployment_released_at=self.mod.utcnow().isoformat(),
                    ssh_host="node.example.test", winn3_gateway_report_json=json.dumps(report),
                    winn3_signer_ticket_json=json.dumps(self.ticket), operator_enabled=0)
        self.mod.resync_active_peers_to_node_exclusive = self.cleanup
        self.mod.winn3_closed_node_withdrawal_confirmed = lambda conn, slug: True
        self.mod.winn3_pull_identity = self.pull
        self.mod.winn3_pre_sign_canary = self.pre_sign
        self.mod.winn3_served_profile_canary = self.served
        self.mod.winn3_signer_client = self.sign
        self.mod.security_alert = lambda *args, **kwargs: None
        self.original_check = self.mod.winn3_check_pulled_identity
        self.mod.winn3_check_pulled_identity = self.check
        self.original_store = self.mod.winn3_store_descriptor
        self.mod.winn3_store_descriptor = self.store
        self.original_gate = self.mod.winn3_carrier_candidate_blockers
        self.mod.winn3_carrier_candidate_blockers = self.gate

    def update(self, **values):
        ticket = values.pop("winn3_signer_ticket_json", None)
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            if ticket is not None:
                # The single ticket store (H4's winn3_signer_tickets): the newest row wins.
                envelope = json.loads(ticket)
                fields = json.loads(base64.b64decode(envelope["payload"])) if set(envelope) == {"payload", "sig"} else {}
                conn.execute("DELETE FROM winn3_signer_tickets WHERE slug=?", (self.slug,))
                if fields:
                    conn.execute(
                        "INSERT INTO winn3_signer_tickets (slug, action, epoch, nonce, payload, sig, go_live,"
                        " tier, not_after, posted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (self.slug, fields.get("action"), fields.get("epoch") or 1, fields.get("nonce") or "n",
                         envelope["payload"], envelope["sig"], fields.get("go_live"), fields.get("tier"),
                         fields.get("not_after") or 0, self.mod.utcnow().isoformat()))
            if not values:
                return
            conn.execute("UPDATE nodes SET " + ",".join(name + "=?" for name in values) + " WHERE slug=?",
                         (*values.values(), self.slug))

    def row(self):
        with self.mod.get_db() as conn:
            return conn.execute(self.mod.WINN3_JOB_ROW_SQL, (self.slug,)).fetchone()

    def run(self):
        return self.mod.winn3_auto_provision(self.slug)

    def cleanup(self, slug, **kwargs):
        self.trace.append("cleanup")
        return {"ok": True, "failed": 0, "winn3_registry_failed": 0}

    def pull(self, row):
        self.trace.append("pull")
        return dict(self.pulled)

    def check(self, row, pulled):
        self.trace.append("host-signature-and-consistency")
        return self.original_check(row, pulled)

    def proof(self, identity, generation, seq=None):
        digest = self.mod.winn3_identity_digest(self.mod.winn3_identity_descriptor(
            identity, self.pulled["admission_secret"]))
        proof = {"status": "ok", "identity_sha256": digest, "generation": generation,
                 "checked_at": (self.mod.utcnow() + timedelta(microseconds=1)).isoformat(),
                 "handshake": True, "carried": True, "dns": True}
        if seq is not None:
            proof["seq"] = seq
        return proof

    def pre_sign(self, row, identity, generation):
        self.trace.append("pre-sign-canary")
        assert set(identity) == self.mod.WINN3_IDENTITY_FIELDS | {"admission_secret"}
        assert identity["admission_secret"] == self.pulled["admission_secret"]
        return self.proof(identity, generation)

    def sign(self, request):
        self.trace.append(request["verb"])
        response = self.signer.handle(request)
        if response.get("ok") is not True:
            raise ValueError(response["error"])
        return response

    def store(self, conn, row, payload, sig):
        self.trace.append("store")
        assert row["protocol_version"] == "winn/1" or self.trace.count("store") > 1
        return self.original_store(conn, row, payload, sig)

    def served(self, row, identity, descriptor, generation):
        self.trace.append("served-profile-canary")
        current = self.row()
        assert row["protocol_version"] == "winn/3"
        envelope, reason = self.mod.resolve_served_winn3_descriptor(
            row, capabilities=descriptors.caps(supports_winn3_descriptor=True, supports_winn3_dualauth=True),
            served_protocol_version="winn/3")
        assert reason == "winn3-descriptor"
        assert envelope["payload"] == json.loads(current["winn3_descriptor_json"])["payload"]
        return self.proof(identity, generation, descriptor["seq"])

    def gate(self, row, identity, descriptor):
        self.trace.append("candidate-gate")
        return self.original_gate(row, identity, descriptor)

    def changed(self, **kwargs):
        self.pulled = self.keys.identity(self.slug, **kwargs)
        self.pulled["detected_public_ip"] = "203.0.113.10"
        self.identity = json.loads(base64.b64decode(self.pulled["identity"]))

    def withdraw(self):
        return self.mod.withdraw_node_for_deployment(
            self.slug, harness.FakeRequest(), "node-test-token")

    def hold(self):
        return self.mod.admin_set_node_winn3(
            harness.FakeRequest(), slug=self.slug, enabled=False,
            protocol_params_json="", path_mtu="", carrier_classes="", x_admin_token=descriptors.ADMIN)

    def clear_hold(self):
        self.mod.admin_set_node_winn3(
            harness.FakeRequest(), slug=self.slug, enabled=True,
            protocol_params_json='{"carrier":"winn3"}', path_mtu="1450", carrier_classes="udp",
            x_admin_token=descriptors.ADMIN)

    def withhold(self):
        return self.mod.admin_set_node_winn3_descriptor(
            harness.FakeRequest(), slug=self.slug, enabled=False, descriptor_payload_b64="",
            descriptor_sig_b64="", x_admin_token=descriptors.ADMIN)


@pytest.fixture
def lane(tmp_path, monkeypatch):
    value = Lane(tmp_path, monkeypatch)
    yield value
    value.database.close()


def test_pipeline_order_and_prospective_row(lane):
    assert lane.run()["ok"]
    assert lane.trace == ["cleanup", "pull", "host-signature-and-consistency", "pre-sign-canary",
                          "status", "sign", "store", "served-profile-canary", "candidate-gate"]
    row = lane.row()
    assert row["protocol_version"] == "winn/3"
    assert row["operator_enabled"] == 0
    assert row["winn3_job_lease"] is None
    transition = json.loads(row["winn3_expected_transition_json"])
    assert transition == {"generation": 0, "winn3_identity_sha256": row["winn3_identity_sha256"],
                          "protocol_version": "winn/3", "path_mtu": 1450, "carrier_classes": "udp"}
    envelope = json.loads(row["winn3_descriptor_json"])
    payload = json.loads(base64.b64decode(envelope["payload"]))
    assert row["winn3_identity_sha256"] == lane.keys.mod.identity_sha256(payload)


@pytest.mark.parametrize("field,value,reason", [
    ("winn3_operator_hold", 1, "operator-hold"),
    ("management_status", "failed", "management-not-ok"),
    ("node_token_hash", None, "node-not-bootstrapped"),
    ("winn3_bootstrap_authorized", 0, "node-not-bootstrapped"),
    ("deployment_withdrawal_id", "a" * 32, "node-unavailable"),
    ("retired_at", "2026-01-01", "node-unavailable"),
])
def test_preconditions_before_any_contact(lane, field, value, reason):
    lane.update(**{field: value})
    assert lane.run()["reason"] == reason
    assert not lane.trace


def test_release_is_distinct_from_reopen_eligibility(lane):
    lane.update(deployment_released_at=None, deployment_completed_at=lane.mod.utcnow().isoformat())
    assert lane.run()["reason"] == "deployment-not-released"
    assert "sign" not in lane.trace
    assert not lane.row()["winn3_descriptor_json"]


@pytest.mark.parametrize("go_live", ["auto", "manual"])
def test_released_ineligible_deployment_can_be_signed(lane, monkeypatch, go_live):
    monkeypatch.setenv("NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED", "0")
    lane.update(deployment_completed_at=None, data_plane_code_revision="sha256:" + "a" * 64,
                winn3_signer_ticket_json=json.dumps(lane.keys.ticket(lane.slug, go_live=go_live)))
    assert lane.run()["ok"]
    assert lane.row()["operator_enabled"] == 0


@pytest.mark.parametrize("failed", ["handshake", "carried", "dns"])
def test_each_pre_sign_proof_required(lane, failed):
    lane.mod.winn3_pre_sign_canary = lambda row, identity, generation: dict(
        lane.proof(identity, generation), **{failed: False})
    assert lane.run()["reason"] == "pre-sign-canary-incomplete"
    assert "sign" not in lane.trace
    assert not lane.row()["winn3_descriptor_json"]


@pytest.mark.parametrize("field,value", [("seq", -1), ("generation", 999), ("status", "fail"),
                                         ("identity_sha256", "0" * 64), ("checked_at", "2000-01-01")])
def test_served_proof_binding_is_required(lane, field, value):
    lane.mod.winn3_served_profile_canary = lambda row, identity, descriptor, generation: dict(
        lane.proof(identity, generation, descriptor["seq"]), **{field: value})
    assert not lane.run()["ok"]
    assert lane.row()["winn3_descriptor_json"]
    assert lane.row()["protocol_version"] == "winn/1"
    assert lane.row()["path_mtu"] is None and lane.row()["carrier_classes"] is None


def test_h3_absent_refuses_before_sign(lane):
    lane.mod.winn3_pre_sign_canary = lambda *args: {"status": "fail"}
    assert not lane.run()["ok"]
    assert not lane.row()["winn3_descriptor_json"]
    assert "sign" not in lane.trace


@pytest.mark.parametrize("kind", ["tamper", "wrong-host", "wrong-slug", "missing-sig"])
def test_host_signature_negatives(lane, kind):
    if kind == "tamper":
        body = dict(lane.identity, static_pub_hex="44" * 32)
        lane.pulled["identity"] = base64.b64encode(lane.mod.winn3_canonical(body)).decode()
    elif kind == "wrong-host":
        lane.changed(sign_host="b")
    elif kind == "wrong-slug":
        lane.pulled = lane.keys.identity("other")
        lane.pulled["detected_public_ip"] = "203.0.113.10"
    else:
        lane.pulled["identity_sig"] = ""
    assert not lane.run()["ok"]
    assert "sign" not in lane.trace


@pytest.mark.parametrize("field,value", [
    ("endpoint", "203.0.113.10:9112"), ("endpoint", "203.0.113.11:9111"),
    ("gateway_id", "other-gw"), ("inner_router_v4", "10.11.0.1"),
    ("inner_resolver_v4", "10.10.0.2"), ("path_mtu", 1300), ("path_mtu", True),
    ("plan", "tcp"), ("static_pub_hex", "a" * 62), ("auth_ed25519_hex", "a" * 66),
    ("auth_mldsa65_hex", "a" * 3902), ("admission_fingerprint", "0" * 16),
    ("credential_record_sha256", "invalid"),
])
def test_consistency_refusals(lane, field, value):
    body = dict(lane.identity, **{field: value})
    lane.pulled["identity"] = base64.b64encode(lane.mod.winn3_canonical(body)).decode()
    assert not lane.run()["ok"]
    assert "sign" not in lane.trace


def test_noncanonical_identity_refused(lane):
    lane.pulled["identity"] = base64.b64encode(json.dumps(lane.identity).encode()).decode()
    assert lane.run()["reason"] == "identity-not-canonical"


def test_admission_secret_and_detected_ip_checked(lane):
    lane.pulled["admission_secret"] = "a" * 64
    assert lane.run()["reason"] == "admission-secret-fingerprint-mismatch"
    lane.pulled["admission_secret"] = hashlib.sha256(lane.slug.encode()).hexdigest()
    lane.pulled["detected_public_ip"] = "203.0.113.11"
    assert lane.run()["reason"] == "identity-endpoint-inconsistent"


def test_unpinned_host_refused(lane):
    lane.pin.write_text("other.example.test " + lane.identity["ssh_host_ed25519_key"] + "\n")
    assert lane.run()["reason"] == "management-host-key-unpinned"


def test_wrong_ticket_host_refused_by_both_hub_and_signer(lane):
    ticket = lane.keys.ticket(lane.slug, host="b")
    lane.update(winn3_signer_ticket_json=json.dumps(ticket))
    assert lane.run()["reason"] == "identity-not-ticketed"
    request = lane.mod.winn3_build_signer_request(lane.row(), "sign", 0, lane.pulled)
    assert lane.signer.handle(request)["error"] == "identity-host-key-not-ticketed"


@pytest.mark.parametrize("stage", ["store", "flip"])
@pytest.mark.parametrize("bump", ["withdrawal", "hold"])
def test_generation_move_refuses_every_commit(lane, stage, bump):
    def change():
        lane.withdraw() if bump == "withdrawal" else lane.hold()
    if stage == "store":
        original = lane.sign
        def signing(request):
            reply = original(request)
            if request["verb"] in ("sign", "renew", "rekey"):
                change()
            return reply
        lane.mod.winn3_signer_client = signing
    else:
        original = lane.served
        def served(*args):
            proof = original(*args)
            change()
            return proof
        lane.mod.winn3_served_profile_canary = served
    assert lane.run()["reason"] == "deployment-generation-or-lease-moved"
    assert lane.row()["protocol_version"] == "winn/1"
    assert lane.row()["deployment_generation"] == 1
    if stage == "store":
        assert lane.row()["winn3_descriptor_json"] is None


@pytest.mark.parametrize("change_identity", [False, True])
def test_orphan_refetch_and_supersede(lane, change_identity):
    original = lane.sign
    captured = []
    def signing(request):
        reply = original(request)
        if request["verb"] == "sign":
            captured.append(reply)
            lane.hold()
        return reply
    lane.mod.winn3_signer_client = signing
    assert not lane.run()["ok"]
    assert captured[0]["seq"] == 0
    lane.clear_hold()
    lane.mod.winn3_signer_client = original
    if change_identity:
        lane.changed(static=b"\x44" * 32)
        lane.update(winn3_signer_ticket_json=json.dumps(lane.keys.ticket(lane.slug, action="rekey")))
    assert lane.run()["ok"]
    stored = json.loads(lane.row()["winn3_descriptor_json"])
    if not change_identity:
        assert stored["payload"] == captured[0]["payload"]
        assert stored["sig"] == captured[0]["sig"]
    else:
        assert "supersede" in lane.trace
        assert lane.mod.winn3_stored_descriptor(lane.row())["seq"] == 1
        assert lane.signer.ledger["slugs"][lane.slug]["issuances"][0]["superseded"] is True


def test_withhold_retains_floor_in_real_request_builder(lane):
    assert lane.run()["ok"]
    seq = lane.mod.winn3_stored_descriptor(lane.row())["seq"]
    lane.withhold()
    request = lane.mod.winn3_build_signer_request(lane.row(), "renew", 1)
    assert request["expected_prior_seq"] == seq
    assert request["expected_prior_seq"] != -1


@pytest.mark.parametrize("field", ["sequence_floor", "current", "previous"])
def test_unequal_recovery_floors_and_request_bound(lane, field):
    ledger = {field: 41 if field == "sequence_floor" else {"seq": 41}}
    lane.update(winn3_admission_json=json.dumps(ledger))
    record = lane.keys.mod.slug_record(lane.signer.ledger, lane.slug, create=True)
    record["floor"] = 1_000_041
    record["state"] = "suspended"
    req = lane.mod.winn3_build_signer_request(lane.row(), "rekey", 0, lane.pulled)
    assert req["expected_prior_seq"] == 41
    assert lane.signer.handle(req)["error"] == "slug-suspended"
    unsuspend = lane.keys.ticket(lane.slug, action="unsuspend")
    assert lane.signer.handle({"verb": "unsuspend", "slug": lane.slug, "generation": 0,
                               "ticket": unsuspend})["ok"]
    assert lane.signer.handle(lane.mod.winn3_build_signer_request(lane.row(), "renew", 0))["error"] == "no-live-issuance"
    # The builder picks the verb from the ticket's action, so a rekey ticket
    # is installed on the row and the request rebuilt rather than patched.
    lane.update(winn3_signer_ticket_json=json.dumps(lane.keys.ticket(lane.slug, action="rekey")))
    req = lane.mod.winn3_build_signer_request(lane.row(), "rekey", 0, lane.pulled)
    assert req["verb"] == "rekey" and req["expected_prior_seq"] == 41
    reply = lane.signer.handle(req)
    assert reply["ok"] and reply["seq"] == 1_000_042
    with lane.mod.get_db() as conn:
        lane.original_store(conn, lane.row(), reply["payload"], reply["sig"])
    assert lane.mod.winn3_build_signer_request(lane.row(), "renew", 0)["expected_prior_seq"] == 1_000_042
    limit = 2 ** 53 - 1 - 2 ** 32
    lane.update(winn3_descriptor_json=None, winn3_admission_json=json.dumps({"sequence_floor": limit}))
    assert lane.mod.winn3_build_signer_request(lane.row(), "rekey", 0, lane.pulled)["expected_prior_seq"] == limit
    lane.update(winn3_admission_json=json.dumps({field: limit + 1 if field == "sequence_floor" else {"seq": limit + 1}}))
    with pytest.raises(ValueError, match="expected-prior-seq-out-of-bound"):
        lane.mod.winn3_build_signer_request(lane.row(), "rekey", 0, lane.pulled)


def test_two_renewal_windows_and_same_identity(lane):
    assert lane.run()["ok"]
    first = lane.mod.winn3_stored_descriptor(lane.row())
    for window in range(2):
        lane.clock[0] += 8 * h1.DAY
        assert lane.run()["ok"]
        next_descriptor = lane.mod.winn3_stored_descriptor(lane.row())
        assert next_descriptor["seq"] > first["seq"]
        assert next_descriptor["not_after"] > first["not_after"]
        assert lane.mod.winn3_identity_digest(first) == lane.mod.winn3_identity_digest(next_descriptor)
        assert {k: v for k, v in first.items() if k not in {"seq", "iat", "not_after"} and not k.startswith("_")} == {
            k: v for k, v in next_descriptor.items() if k not in {"seq", "iat", "not_after"} and not k.startswith("_")}
        first = next_descriptor


def test_sticky_hold_and_explicit_admin_clear(lane):
    assert lane.run()["ok"]
    lane.hold()
    assert lane.row()["winn3_operator_hold"] == 1
    assert lane.run()["reason"] == "operator-hold"
    with lane.mod.get_db() as conn:
        failures = lane.mod.node_auto_reopen_failures(conn, lane.row(), lane.mod.utcnow().isoformat())
    assert "winn3 operator hold is active" in failures
    lane.clear_hold()
    assert lane.row()["winn3_operator_hold"] == 0
    assert lane.row()["deployment_generation"] == 1
    assert lane.run()["ok"]


def test_descriptor_view_node_auth_and_no_secret(lane):
    assert lane.run()["ok"]
    with pytest.raises(harness.HTTPException) as error:
        lane.mod.node_winn3_descriptor_view(lane.slug, harness.FakeRequest(), descriptors.ADMIN)
    assert error.value.status_code == 401
    result = lane.mod.node_winn3_descriptor_view(lane.slug, harness.FakeRequest(), "node-test-token")
    encoded = json.dumps(result)
    assert lane.pulled["admission_secret"] not in encoded
    assert base64.b64encode(lane.pulled["admission_secret"].encode()).decode() not in encoded
    assert "payload" not in result
    assert result["identity_sha256"] == lane.row()["winn3_identity_sha256"]
    lane.withhold()
    assert not lane.mod.node_winn3_descriptor_view(lane.slug, harness.FakeRequest(), "node-test-token")["descriptor"]


def test_lease_exclusion_and_expiry(lane):
    lane.update(winn3_job_lease="another", winn3_job_lease_until=lane.clock[0] + 1)
    assert lane.run()["reason"] == "provision-already-running"
    assert lane.row()["winn3_job_lease"] == "another"
    lane.clock[0] += 2
    assert lane.run()["ok"]


def test_lease_expired_during_canary_cannot_store(lane):
    def proof(row, identity, generation):
        lane.clock[0] += lane.mod.WINN3_JOB_LEASE_SECONDS + 1
        return lane.proof(identity, generation)
    lane.mod.winn3_pre_sign_canary = proof
    assert lane.run()["reason"] == "deployment-generation-or-lease-moved"
    assert lane.row()["winn3_descriptor_json"] is None


def test_cleanup_failure_precedes_pull(lane):
    lane.mod.resync_active_peers_to_node_exclusive = lambda *a, **k: {"ok": False}
    assert lane.run()["reason"] == "closure-cleanup-failed"
    assert not lane.trace
    lane.mod.resync_active_peers_to_node_exclusive = lane.cleanup
    lane.mod.winn3_closed_node_withdrawal_confirmed = lambda *a: False
    assert lane.run()["reason"] == "closure-cleanup-unconfirmed"
    assert "pull" not in lane.trace


def test_switches_and_recovery_fail_closed(lane, monkeypatch):
    monkeypatch.setenv("WINN3_AUTO_SIGN", "0")
    assert lane.run()["reason"] == "auto-sign-disabled"
    assert "sign" not in lane.trace
    monkeypatch.setenv("WINN3_AUTO_SIGN", "1")
    monkeypatch.setenv("WINN3_AUTO_CARRIER", "0")
    assert lane.run()["reason"] == "auto-carrier-disabled"
    assert lane.row()["protocol_version"] == "winn/1"
    monkeypatch.setenv("WINN3_RECOVERY_MODE", "1")
    assert lane.run()["reason"] == "recovery-key-audit-unavailable"


def test_real_pull_uses_pinned_ssh_and_minimal_environment(lane, monkeypatch):
    namespace = harness.load_hub().__dict__
    raw_source = harness._extract_main_block()
    tree = __import__('ast').parse(raw_source)
    definition = next(n for n in tree.body if getattr(n, "name", None) == "winn3_pull_identity")
    exec(compile(__import__('ast').Module(body=[definition], type_ignores=[]), "pull", "exec"), namespace)
    calls = []
    namespace["node_ssh_command"] = lambda host, command, **kw: calls.append((host, command, kw)) or ["ssh-test"]
    namespace["management_ssh_env"] = lambda: {"PATH": "/usr/bin:/bin"}
    namespace["subprocess"] = types.SimpleNamespace(run=lambda argv, **kw: calls.append((argv, kw)) or
        types.SimpleNamespace(returncode=0, stdout=json.dumps(lane.pulled).encode()))
    assert namespace["winn3_pull_identity"](lane.row()) == lane.pulled
    assert calls[0][0] == "node.example.test"
    assert calls[0][2]["multiplex"] is False
    assert "python3 -I -c" in calls[0][1]
    assert calls[1][1]["env"] == {"PATH": "/usr/bin:/bin"}
    assert calls[1][1]["timeout"] == 30


@pytest.mark.parametrize("reply", [b'{"ok":true}', b'{"ok":true}\nextra', b'x' * 65537 + b'\n',
                                   b'{"ok":false,"error":"SECRET value"}\n'])
def test_signer_socket_framing_and_safe_errors(lane, tmp_path, reply):
    namespace = lane.mod.__dict__.copy()
    raw_source = harness._extract_main_block()
    tree = __import__('ast').parse(raw_source)
    definition = next(n for n in tree.body if getattr(n, "name", None) == "winn3_signer_client")
    exec(compile(__import__('ast').Module(body=[definition], type_ignores=[]), "socket", "exec"), namespace)
    client, server = socket.socketpair()
    class LocalSocket:
        def __enter__(self): return self
        def __exit__(self, *args): client.close()
        def connect(self, path): assert path == lane.mod.WINN3_SIGNER_SOCKET
        def settimeout(self, value): client.settimeout(value)
        def sendall(self, value): client.sendall(value)
        def recv(self, size): return client.recv(size)
    namespace["socket"] = types.SimpleNamespace(AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM,
                                               socket=lambda *args: LocalSocket())
    with server:
        def serve():
            with server:
                assert json.loads(server.recv(100)) == {"verb": "status"}
                server.sendall(reply)
        worker = threading.Thread(target=serve)
        worker.start()
        with pytest.raises(ValueError) as error:
            namespace["winn3_signer_client"]({"verb": "status"})
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert "SECRET" not in str(error.value)


def test_inventory_source_digest_is_current():
    source = h1.INSTALLER.read_bytes()
    inventory = json.loads((h1.INSTALLER.parent / "h0_privileged_jobs.json").read_text())
    assert inventory["source_sha256"] == hashlib.sha256(source).hexdigest()


def test_rebootstrap_closes_clears_context_retains_hold_floor_and_history(lane):
    assert lane.run()["ok"]
    lane.hold()
    lane.update(operator_enabled=1, deployment_withdrawal_id="previous", deployment_withdrawn_at="previous",
                deployment_prior_state_json="{}", deployment_completed_at="previous")
    with lane.mod.get_db() as conn:
        conn.execute("INSERT INTO bootstrap_grants (token_hash,role,subject_id,expires_at) VALUES (?,?,?,?)",
                     (lane.mod.token_digest("throwaway-grant"), "node", lane.slug,
                      (lane.mod.utcnow() + timedelta(minutes=5)).isoformat()))
        history = conn.execute("SELECT * FROM node_promotion_events WHERE slug=?", (lane.slug,)).fetchall()
    before = lane.row()["deployment_generation"]
    result = lane.mod.bootstrap_node(lane.mod.NodeBootstrapRequest(
        slug=lane.slug, bootstrap_token="throwaway-grant"), harness.FakeRequest())
    row = lane.row()
    assert result["ok"] and row["operator_enabled"] == 0
    assert row["deployment_generation"] == before + 1
    assert row["winn3_operator_hold"] == 1
    assert row["node_bootstrapped_at"] == lane.mod.utcnow().isoformat()
    for field in ("deployment_completed_at", "deployment_released_at", "deployment_withdrawal_id",
                  "deployment_withdrawn_at", "deployment_prior_state_json", "winn3_descriptor_json",
                  "winn3_identity_sha256",
                  "protocol_params_json", "path_mtu", "carrier_classes", "winn3_expected_transition_json"):
        assert row[field] is None
    assert row["protocol_version"] == "winn/1"
    assert lane.mod.winn3_admission_sequence_floor({}, lane.mod.parse_winn3_admission_ledger(
        row["winn3_admission_json"])) == 0
    with lane.mod.get_db() as conn:
        assert conn.execute("SELECT * FROM node_promotion_events WHERE slug=?", (lane.slug,)).fetchall() == history
        assert not lane.mod.consume_bootstrap_grant(conn, "throwaway-grant", "node", lane.slug)
    lane.clear_hold()
    assert lane.run()["reason"] == "deployment-not-released"
    lane.update(deployment_released_at=lane.mod.utcnow().isoformat(),
                winn3_signer_ticket_json=json.dumps(lane.keys.ticket(lane.slug, action="reset")))
    assert lane.run()["ok"]
    assert lane.trace[-4:] == ["rekey", "store", "served-profile-canary", "candidate-gate"]


def test_verified_identity_drives_prospective_mtu_and_classes(lane):
    lane.update(path_mtu=1280, carrier_classes="tcp")
    assert lane.run()["ok"]
    assert lane.row()["path_mtu"] == 1450 and lane.row()["carrier_classes"] == "udp"


@pytest.mark.parametrize("field,value", [("path_mtu", 1280), ("gateway_id", "other"),
                                         ("inner_v4", "10.10.0.2"), ("forward", False)])
def test_gateway_report_inconsistency_blocks_carrier(lane, field, value):
    report = json.loads(lane.row()["winn3_gateway_report_json"])
    report[field] = value
    lane.update(winn3_gateway_report_json=json.dumps(report))
    assert lane.run()["reason"] == "carrier-candidate-blocked"
    assert lane.row()["protocol_version"] == "winn/1"


def test_ticket_already_consumed_alerts_at_priority_two(lane):
    alerts = []
    original = lane.sign
    def sign(request):
        if request["verb"] == "sign":
            raise ValueError("ticket-already-spent")
        return original(request)
    lane.mod.winn3_signer_client = sign
    lane.mod.security_alert = lambda *args, **kwargs: alerts.append((args, kwargs))
    assert lane.run()["reason"] == "ticket-already-spent"
    assert alerts[0][0][0] == 2


@pytest.mark.parametrize("stage", ["store", "flip"])
def test_generation_change_alone_refuses_commit(lane, stage):
    if stage == "store":
        original = lane.sign
        def sign(request):
            result = original(request)
            if request["verb"] == "sign":
                lane.update(deployment_generation=1)
            return result
        lane.mod.winn3_signer_client = sign
    else:
        original = lane.served
        def served(*args):
            result = original(*args)
            lane.update(deployment_generation=1)
            return result
        lane.mod.winn3_served_profile_canary = served
    assert lane.run()["reason"] == "deployment-generation-or-lease-moved"
    assert lane.row()["protocol_version"] == "winn/1"


def test_settled_slug_costs_database_reads_only(lane):
    assert lane.run()["ok"]
    seen = len(lane.trace)
    assert lane.run() == {"ok": True, "slug": lane.slug, "settled": True}
    assert len(lane.trace) == seen
    # Anything that changes what a cycle would do runs the full cycle again.
    lane.update(deployment_generation=lane.row()["deployment_generation"] + 1)
    assert lane.run()["ok"] and lane.trace[seen:][:2] == ["cleanup", "pull"]
    seen = len(lane.trace)
    assert lane.run()["settled"] is True and len(lane.trace) == seen
    lane.update(winn3_identity_sha256="0" * 64)
    assert lane.run()["ok"] and lane.trace[seen:][:2] == ["cleanup", "pull"]
    seen = len(lane.trace)
    assert lane.run()["settled"] is True and len(lane.trace) == seen
    result = json.loads(lane.row()["winn3_served_profile_result_json"])
    lane.update(winn3_served_profile_result_json=json.dumps(dict(result, seq=result["seq"] + 1)))
    assert lane.run()["ok"] and lane.trace[seen:][:2] == ["cleanup", "pull"]
    seen = len(lane.trace)
    assert lane.run()["settled"] is True and len(lane.trace) == seen
    lane.clock[0] += 8 * h1.DAY
    assert lane.run()["ok"] and "renew" in lane.trace[seen:]
    seen = len(lane.trace)
    lane.update(winn3_operator_hold=1)
    assert lane.run()["reason"] == "operator-hold" and len(lane.trace) == seen


def test_stored_descriptor_with_unrecorded_identity_still_reaches_the_carrier(lane):
    assert lane.run()["ok"]
    # A descriptor stored before H2 never had winn3_identity_sha256 written.
    lane.update(winn3_identity_sha256=None, protocol_version="winn/1", protocol_params_json=None,
                path_mtu=None, carrier_classes=None, winn3_expected_transition_json=None,
                winn3_served_profile_result_json=None)
    assert lane.run()["ok"]
    row = lane.row()
    assert row["protocol_version"] == "winn/3"
    assert row["winn3_identity_sha256"] == lane.mod.winn3_identity_digest(
        lane.mod.winn3_stored_descriptor(row))
    seen = len(lane.trace)
    assert lane.run()["settled"] is True and len(lane.trace) == seen


def test_non_orphan_reply_for_another_identity_is_refused_not_superseded(lane):
    pulled, identity = dict(lane.pulled), lane.identity
    lane.changed(static=b"\x44" * 32)
    row = lane.row()
    other = lane.signer.handle(lane.mod.winn3_build_signer_request(
        row, "sign", row["deployment_generation"], lane.pulled))
    assert other["ok"] and other["orphan"] is False
    lane.pulled, lane.identity = pulled, identity
    lane.mod.winn3_signer_client = lambda request: (
        other if request["verb"] in ("sign", "rekey", "renew") else lane.sign(request))
    assert lane.run()["reason"] == "signer-identity-mismatch"
    assert "supersede" not in lane.trace


def test_renewal_identity_must_carry_the_pinned_host_key(lane):
    assert lane.run()["ok"]
    lane.changed(host="b")
    lane.clock[0] += 8 * h1.DAY
    lane.trace.clear()
    assert lane.run()["reason"] == "identity-host-key-not-pinned"
    assert "renew" not in lane.trace


def test_withdrawal_clears_release_so_a_failed_rerun_is_never_signed(lane):
    assert lane.run()["ok"]
    lane.withdraw()
    row = lane.row()
    assert row["deployment_released_at"] is None
    with pytest.raises(ValueError, match="deployment-not-released"):
        lane.mod.winn3_build_signer_request(row, "rekey", row["deployment_generation"], lane.pulled)


@pytest.mark.parametrize("hold", [0, 1])
def test_registration_never_bypasses_h2_carrier_gate(lane, monkeypatch, hold):
    """Sol H2-1: the legacy install-time opt-in cannot pick winn/3 at registration."""
    monkeypatch.setenv("WINN3_SET_CARRIER_STANDALONE", "1")
    monkeypatch.setenv("WINN3_STANDALONE_NODE_SLUG", lane.slug)
    lane.mod.HIDE_CONTROL_ORIGIN = False
    lane.update(endpoint=None, winn3_operator_hold=hold)
    scheduled = []
    lane.mod.winn3_schedule_auto_provision = scheduled.append
    payload = types.SimpleNamespace(
        slug=lane.slug, name="Lab Alpha", flag="", endpoint="203.0.113.10:9110",
        tunnel_gateway_ipv4="10.8.1.1", stealth_endpoint="", public_key="A" * 43 + "=",
        preshared_key=None, secret_token="node-test-token", status="online",
        obfuscation_json=json.dumps(descriptors.GOOD_OBFUSCATION), ssh_host="node.example.test",
        wg_port=9110, xray_uuid="", xray_path="/wins-stealth-tunnel", xray_security="none",
        xray_sni="", stealth_public_port=80, xray_inbound_port=10085,
        regional_aliases=[], stealth_transports=[], awg_rx_bytes=0, awg_tx_bytes=0,
        wan_rx_bytes=0, wan_tx_bytes=0, peer_count=0, max_peers=100, direct_awg_enabled=True,
        load_cpu_pct=None, load_net_pct=None, load_sessions_pct=None,
        data_plane_code_revision="", winn3_gateway=None, origin_cert_not_after=None,
    )
    assert lane.mod.register_node(payload, harness.FakeRequest())["ok"]
    row = lane.row()
    assert scheduled == [lane.slug]
    assert row["protocol_version"] == "winn/1"
    assert row["protocol_params_json"] is None
    assert row["path_mtu"] is None and row["carrier_classes"] is None
    assert row["winn3_operator_hold"] == hold
    assert row["winn3_descriptor_json"] is None


def test_changed_identity_after_withhold_waits_for_served_proof(lane):
    """Sol H2-2: a withheld previous descriptor must not leave the carrier on winn/3."""
    assert lane.run()["ok"]
    prior_seq = lane.mod.winn3_stored_descriptor(lane.row())["seq"]
    lane.withhold()
    assert lane.row()["protocol_version"] == "winn/3"
    lane.changed(static=b"\x44" * 32)
    lane.update(winn3_signer_ticket_json=json.dumps(lane.keys.ticket(lane.slug, action="rekey")))
    def fail_served(row, identity, descriptor, generation):
        committed = lane.row()
        assert committed["protocol_version"] == "winn/1"
        assert committed["protocol_params_json"] is None
        assert committed["path_mtu"] is None and committed["carrier_classes"] is None
        assert descriptor["seq"] > prior_seq
        return {"status": "fail"}
    lane.mod.winn3_served_profile_canary = fail_served
    assert lane.run()["reason"] == "canary-proof-missing-or-stale"
    assert lane.row()["protocol_version"] == "winn/1"
    assert lane.mod.winn3_stored_descriptor(lane.row())["seq"] > prior_seq
    lane.mod.winn3_served_profile_canary = lane.served
    assert lane.run()["ok"]
    assert lane.row()["protocol_version"] == "winn/3"


def test_new_ticket_after_unsuspend_of_never_issued_slug(lane):
    """Sol H2-3: an empty signer record is not issuance history."""
    ticket = lane.keys.ticket(lane.slug, action="unsuspend")
    assert lane.signer.handle({"verb": "unsuspend", "slug": lane.slug,
                               "generation": 0, "ticket": ticket})["ok"]
    assert lane.signer.handle({"verb": "status"})["slugs"][lane.slug]["live_seq"] is None
    assert lane.run()["ok"]
    assert "sign" in lane.trace and "rekey" not in lane.trace
    assert lane.mod.winn3_stored_descriptor(lane.row())["seq"] == 0


@pytest.mark.parametrize("action,verb", [("new", "sign"), ("rekey", "rekey"), ("endpoint", "rekey")])
def test_ticket_action_selects_the_signer_verb(lane, action, verb):
    lane.update(winn3_signer_ticket_json=json.dumps(lane.keys.ticket(lane.slug, action=action)))
    for asked in ("sign", "rekey"):
        request = lane.mod.winn3_build_signer_request(lane.row(), asked, 0, lane.pulled)
        assert request["verb"] == verb


def test_noncanonical_ticket_payload_refused_by_request_builder(lane):
    ticket = dict(lane.ticket)
    fields = json.loads(base64.b64decode(ticket["payload"]))
    ticket["payload"] = base64.b64encode(json.dumps(fields, indent=2).encode()).decode()
    lane.update(winn3_signer_ticket_json=json.dumps(ticket))
    with pytest.raises(ValueError, match="ticket-not-canonical"):
        lane.mod.winn3_build_signer_request(lane.row(), "sign", 0, lane.pulled)


def test_settled_pass_has_no_database_writer_statements(lane):
    assert lane.run()["ok"]
    statements = []
    lane.database.set_trace_callback(statements.append)
    try:
        assert lane.run()["settled"] is True
    finally:
        lane.database.set_trace_callback(None)
    forbidden = ("BEGIN", "UPDATE", "INSERT", "DELETE", "CREATE", "ALTER", "DROP", "REPLACE")
    assert not any(statement.lstrip().upper().startswith(forbidden)
                   for statement in statements)


@pytest.mark.parametrize("field,value", [
    ("endpoint", "203.0.113.11:9110"),
    ("ssh_host", "other.example.test"),
    ("path_mtu", 1280),
    ("carrier_classes", "tcp"),
    ("protocol_params_json", "{}"),
    ("winn3_gateway_report_json", "{}"),
    ("winn3_signer_ticket_json", "{}"),
])
def test_settled_cycle_requires_the_proved_row_state(lane, field, value):
    assert lane.run()["ok"]
    row = dict(lane.row())
    assert lane.mod.winn3_cycle_settled(row)
    row[field] = value
    assert not lane.mod.winn3_cycle_settled(row)


@pytest.mark.parametrize("value", ["[]", "null", "1"])
def test_settled_cycle_refuses_nonobject_results(lane, value):
    assert lane.run()["ok"]
    row = dict(lane.row(), winn3_served_profile_result_json=value)
    assert not lane.mod.winn3_cycle_settled(row)


def test_profile_change_during_served_probe_refuses_commit(lane):
    original = lane.served
    def served(*args):
        proof = original(*args)
        lane.update(ssh_host="other.example.test")
        return proof
    lane.mod.winn3_served_profile_canary = served
    assert lane.run()["reason"] == "profile-moved"
    assert lane.row()["protocol_version"] == "winn/1"


def test_commit_renews_only_an_unexpired_owned_lease(lane):
    lane.update(winn3_job_lease="owned", winn3_job_lease_until=lane.clock[0] + 1)
    generation = lane.row()["deployment_generation"]
    with lane.mod.get_db() as conn:
        conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        lane.mod.winn3_job_row(conn, lane.slug, generation, "owned", renew=True)
    deadline = lane.clock[0] + lane.mod.WINN3_JOB_LEASE_SECONDS
    assert lane.row()["winn3_job_lease_until"] == deadline
    lane.clock[0] = deadline + 1
    with pytest.raises(ValueError, match="deployment-generation-or-lease-moved"):
        with lane.mod.get_db() as conn:
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            lane.mod.winn3_job_row(conn, lane.slug, generation, "owned", renew=True)
    assert lane.row()["winn3_job_lease_until"] == deadline


def _sweep_rows(lane):
    """Copy the lane node into rows that differ only in the field under test."""
    with lane.mod.get_db() as conn:
        base = dict(conn.execute("SELECT * FROM nodes WHERE slug=?", (lane.slug,)).fetchone())
    base.update(winn3_bootstrap_authorized=1, node_token_hash="x" * 64, management_status="ok",
                winn3_operator_hold=0, retired_at=None, deployment_withdrawal_id=None)
    good = [f"sweep-ok-{index:02d}" for index in range(11)]
    bad = {"sweep-retired": {"retired_at": "2026-01-01T00:00:00"},
           "sweep-hold": {"winn3_operator_hold": 1},
           "sweep-withdrawn": {"deployment_withdrawal_id": "w1"},
           "sweep-no-token": {"node_token_hash": None},
           "sweep-empty-token": {"node_token_hash": ""},
           "sweep-unauthorized": {"winn3_bootstrap_authorized": 0},
           "sweep-bad-management": {"management_status": "pending"}}
    with lane.mod.get_db() as conn:
        for slug, changes in [(slug, {}) for slug in good] + list(bad.items()):
            row = dict(base, slug=slug, **changes)
            row.pop("id", None)
            conn.execute("INSERT INTO nodes (" + ",".join(row) + ") VALUES (" + ",".join("?" * len(row)) + ")",
                         tuple(row.values()))
    return sorted([lane.slug] + good)


def _run_sweep_once(lane, monkeypatch, provision):
    import asyncio

    async def stop(delay):
        raise asyncio.CancelledError()
    monkeypatch.setattr(asyncio, "sleep", stop)
    lane.mod.winn3_auto_provision = provision
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(lane.mod.winn3_auto_provision_sweep_loop())


def test_sweep_runs_only_eligible_slugs_four_at_a_time_and_survives_a_worker_failure(lane, monkeypatch):
    """H2-PERF-3: SQL prefilter, one bounded pass, a failing slug stops no other slug."""
    eligible = _sweep_rows(lane)
    seen, lock, release = [], threading.Lock(), threading.Event()
    state = {"now": 0, "peak": 0}

    def provision(slug):
        with lock:
            seen.append(slug)
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        try:
            # Hold the first calls in flight so the concurrency bound is measured, not guessed.
            release.wait(timeout=10)
            if slug == eligible[0]:
                raise RuntimeError("one worker fails")
            time.sleep(0.05)
            return {"ok": True}
        finally:
            with lock:
                state["now"] -= 1
    threading.Timer(0.5, release.set).start()
    _run_sweep_once(lane, monkeypatch, provision)
    release.set()
    assert sorted(seen) == eligible
    assert state["peak"] == 4


def test_sweep_initializes_the_schema_once_and_the_per_slug_job_never_does(lane, monkeypatch):
    calls = []
    original = lane.mod.ensure_schema
    lane.mod.ensure_schema = lambda conn: (calls.append(1), original(conn))[1]
    assert lane.run()["ok"] and lane.run()["settled"] is True
    assert calls == []
    _run_sweep_once(lane, monkeypatch, lambda slug: {"ok": True})
    assert calls == [1]


def test_lease_is_extended_at_each_writer_commit_and_one_long_stage_still_fails_closed(lane):
    """H2-PERF-5: three stages of 100 seconds fit a 180 second lease only by renewal."""
    lease = lane.mod.WINN3_JOB_LEASE_SECONDS
    assert lease < 300
    for name in ("winn3_pre_sign_canary", "winn3_signer_client", "winn3_served_profile_canary"):
        original = getattr(lane.mod, name)
        slowed = []
        def slow(*args, _original=original, _slowed=slowed):
            if not _slowed:
                _slowed.append(1)
                lane.clock[0] += 100
            return _original(*args)
        setattr(lane.mod, name, slow)
    assert lane.run()["ok"]
    assert lane.row()["protocol_version"] == "winn/3"
    lane.update(deployment_generation=lane.row()["deployment_generation"] + 1, protocol_version="winn/1",
                protocol_params_json=None, path_mtu=None, carrier_classes=None)
    original = lane.mod.winn3_pre_sign_canary
    def too_slow(*args):
        lane.clock[0] += lease + 1
        return original(*args)
    lane.mod.winn3_pre_sign_canary = too_slow
    assert lane.run()["reason"] == "deployment-generation-or-lease-moved"
    assert lane.row()["protocol_version"] == "winn/1"


@pytest.mark.parametrize("mutant", ["host-signature", "retained-floor", "store-generation", "flip-generation",
                                    "pre-sign", "served-seq", "served-generation", "release-ignored",
                                    "completed-instead-of-released", "hold", "sequence-bound",
                                    "registration-applies-opt-in", "withheld-previous-keeps-carrier",
                                    "ticket-action-ignored", "ticket-canonical-ignored",
                                    "management-pin-ignored", "non-orphan-superseded",
                                    "withdrawal-keeps-release", "settled-ignores-generation",
                                    "settled-ignores-seq", "settled-ignores-renewal-window",
                                    "settled-ignores-recorded-identity",
                                    "settled-ignores-row-state", "settled-accepts-nonobject",
                                    "profile-move-ignored", "lease-never-renewed",
                                    "sweep-prefilter-dropped", "sweep-serial", "sweep-unbounded",
                                    "sweep-worker-failure-escapes", "per-slug-schema-write"])
def test_h2_mutants_are_killed(lane, mutant, monkeypatch):
    import ast
    source = harness._extract_main_block()
    # The generation is now bound twice (the row check and the lease-renewal UPDATE, or the
    # recorded cycle state), so a mutant for it must remove every binding to be observable.
    extra = []
    if mutant == "host-signature":
        name, old, new = "winn3_check_pulled_identity", "if done.returncode != 0:", "if False:"
        check = lambda: test_host_signature_negatives(lane, "tamper")
    elif mutant == "retained-floor":
        name = "winn3_build_signer_request"
        old = "floor = winn3_admission_sequence_floor(\n        descriptor, parse_winn3_admission_ledger(_node_field(node, \"winn3_admission_json\")))"
        new = "floor = descriptor.get('seq', -1)"
        check = lambda: test_withhold_retains_floor_in_real_request_builder(lane)
    elif mutant in ("store-generation", "flip-generation"):
        name, old, new = "winn3_job_row", 'row["deployment_generation"] != generation', "False"
        extra = [("winn3_job_row", '"AND deployment_generation=? AND winn3_job_lease=? "',
                  '"AND (deployment_generation=? OR 1) AND winn3_job_lease=? "')]
        check = lambda: test_generation_change_alone_refuses_commit(lane, mutant.split("-")[0])
    elif mutant == "pre-sign":
        name, old, new = "winn3_check_canary", 'result.get(name) is not True', "False"
        check = lambda: test_each_pre_sign_proof_required(lane, "handshake")
    elif mutant in ("served-seq", "served-generation"):
        name = "winn3_check_canary"
        old = 'result["seq"] != seq' if mutant == "served-seq" else 'result["generation"] != generation'
        new = "False"
        field = "seq" if mutant == "served-seq" else "generation"
        check = lambda: test_served_proof_binding_is_required(lane, field, -1)
    elif mutant in ("release-ignored", "completed-instead-of-released"):
        name, old = "winn3_build_signer_request", 'if not _node_field(node, "deployment_released_at"):'
        new = "if False:" if mutant == "release-ignored" else 'if not _node_field(node, "deployment_completed_at"):'
        check = lambda: test_release_is_distinct_from_reopen_eligibility(lane)
    elif mutant == "hold":
        name, old, new = "winn3_auto_preconditions", 'if _node_field(node, "winn3_operator_hold"):', "if False:"
        check = lambda: test_preconditions_before_any_contact(lane, "winn3_operator_hold", 1, "operator-hold")
    elif mutant == "registration-applies-opt-in":
        name = "register_node"
        old = "        # Registration supplies facts, never a carrier choice: the legacy\n"
        new = ("        maybe_apply_install_time_standalone_carrier(\n"
               "            conn, payload.slug, prior_endpoint=prior_endpoint)\n" + old)
        check = lambda: test_registration_never_bypasses_h2_carrier_gate(lane, monkeypatch, 1)
    elif mutant == "withheld-previous-keeps-carrier":
        name = "winn3_auto_provision"
        old, new = "if not previous or winn3_identity_digest(previous) != digest:", "if previous and winn3_identity_digest(previous) != digest:"
        check = lambda: test_changed_identity_after_withhold_waits_for_served_proof(lane)
    elif mutant == "ticket-action-ignored":
        name, old, new = "winn3_build_signer_request", 'if ticket_fields.get("action") == "new":', "if False:"
        check = lambda: test_new_ticket_after_unsuspend_of_never_issued_slug(lane)
    elif mutant == "ticket-canonical-ignored":
        name, old, new = "winn3_build_signer_request", "winn3_canonical(ticket_fields) != ticket_raw", "False"
        check = lambda: test_noncanonical_ticket_payload_refused_by_request_builder(lane)
    elif mutant == "management-pin-ignored":
        name = "winn3_check_pulled_identity"
        old = 'if not any(len(pin) == 3 and pin == [management_host, "ssh-ed25519", parts[1]] for pin in pins):'
        new = "if False:"
        check = lambda: test_renewal_identity_must_carry_the_pinned_host_key(lane)
    elif mutant == "non-orphan-superseded":
        name, old, new = "winn3_auto_provision", 'if reply.get("orphan") is not True:', "if False:"
        check = lambda: test_non_orphan_reply_for_another_identity_is_refused_not_superseded(lane)
    elif mutant == "withdrawal-keeps-release":
        name = "withdraw_node_for_deployment"
        old, new = "deployment_completed_at=NULL, deployment_released_at=NULL, ", "deployment_completed_at=NULL, "
        check = lambda: test_withdrawal_clears_release_so_a_failed_rerun_is_never_signed(lane)
    elif mutant == "settled-ignores-row-state":
        name = "winn3_cycle_settled"
        old, new = 'result.get("cycle_state_sha256") == winn3_cycle_state_sha256(row)', "True"
        check = lambda: test_settled_cycle_requires_the_proved_row_state(lane, "endpoint", "203.0.113.11:9110")
    elif mutant == "settled-accepts-nonobject":
        name = "winn3_cycle_settled"
        old, new = "if not isinstance(result, dict):", "if False:"
        def check():
            try:
                test_settled_cycle_refuses_nonobject_results(lane, "[]")
            except AttributeError as exc:
                raise AssertionError("a non-object proof reached .get") from exc
    elif mutant == "profile-move-ignored":
        name = "winn3_auto_provision"
        old = "if winn3_cycle_state_sha256(winn3_prospective_row(row, identity)) != prospective_state:"
        new = "if False:"
        check = lambda: test_profile_change_during_served_probe_refuses_commit(lane)
    elif mutant == "lease-never-renewed":
        name, old, new = "winn3_job_row", "    if renew:\n", "    if False:\n"
        check = lambda: test_lease_is_extended_at_each_writer_commit_and_one_long_stage_still_fails_closed(lane)
    elif mutant.startswith("sweep-") or mutant == "per-slug-schema-write":
        name = "winn3_auto_provision" if mutant == "per-slug-schema-write" else "winn3_auto_provision_sweep_loop"
        old, new = {
            "sweep-prefilter-dropped": ("AND winn3_bootstrap_authorized=1 AND management_status='ok' ", ""),
            "sweep-serial": ("min(4, len(rows))", "1"),
            "sweep-unbounded": ("min(4, len(rows))", "len(rows)"),
            "sweep-worker-failure-escapes": (
                "except Exception as exc:\n                        logger.error(\"Winn3 provisioning worker failed",
                "except KeyError as exc:\n                        logger.error(\"Winn3 provisioning worker failed"),
            "per-slug-schema-write": ("            # Startup initializes the schema before starting jobs.\n",
                                      "            ensure_schema(conn)\n            conn.commit()\n"),
        }[mutant]
        if mutant == "per-slug-schema-write":
            check = lambda: test_sweep_initializes_the_schema_once_and_the_per_slug_job_never_does(lane, monkeypatch)
        else:
            check = lambda: test_sweep_runs_only_eligible_slugs_four_at_a_time_and_survives_a_worker_failure(lane, monkeypatch)
    elif mutant.startswith("settled-ignores-"):
        name = "winn3_cycle_settled"
        old, new = {
            "generation": ('and result["generation"] == row["deployment_generation"]', "and True"),
            "seq": ('and type(result.get("seq")) is int and result["seq"] == descriptor["seq"]', "and True"),
            "renewal-window": ('descriptor["not_after"] - time.time() < 7 * 86400', "False"),
            "recorded-identity": ('row["winn3_identity_sha256"] == digest and', "True and"),
        }[mutant[len("settled-ignores-"):]]
        if mutant == "settled-ignores-generation":
            extra = [("winn3_cycle_state_sha256", '"deployment_withdrawal_id", "winn3_operator_hold", "deployment_generation",',
                      '"deployment_withdrawal_id", "winn3_operator_hold",')]
        check = lambda: test_settled_slug_costs_database_reads_only(lane)
    else:
        name, old, new = "winn3_build_signer_request", "if floor > 2 ** 53 - 1 - 2 ** 32:", "if False:"
        check = lambda: test_unequal_recovery_floors_and_request_bound(lane, "sequence_floor")
    definition = next(node for node in ast.parse(source).body if getattr(node, "name", None) == name)
    function = ast.get_source_segment(source, definition)
    assert function.count(old) == 1
    exec(compile(function.replace(old, new), "h2-mutant", "exec"), lane.mod.__dict__)
    for extra_name, extra_old, extra_new in extra:
        extra_definition = next(node for node in ast.parse(source).body if getattr(node, "name", None) == extra_name)
        extra_function = ast.get_source_segment(source, extra_definition)
        if extra_name == name:
            extra_function = function.replace(old, new)
        assert extra_function.count(extra_old) == 1
        exec(compile(extra_function.replace(extra_old, extra_new), "h2-mutant", "exec"), lane.mod.__dict__)
    if name == "winn3_check_pulled_identity":
        lane.original_check = lane.mod.winn3_check_pulled_identity
        lane.mod.winn3_check_pulled_identity = lane.check
    with pytest.raises((AssertionError, pytest.fail.Exception, ValueError, KeyError)):
        check()


# H7-QUESTIONS Q1 (unanimous): H4's winn3_signer_tickets is the single ticket
# store. A ticket the operator posts through H4's route
# (POST /admin/nodes/winn3/signer-ticket, what prepare_subject calls) must be
# the one H2's automatic cycle spends; no nodes column carries it.
def test_a_ticket_posted_through_the_route_reaches_the_automatic_sign(lane, monkeypatch):
    with lane.mod.get_db() as conn:
        conn.execute("DELETE FROM winn3_signer_tickets")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(nodes)")}
        if "winn3_signer_ticket_json" in columns:
            conn.execute("UPDATE nodes SET winn3_signer_ticket_json=NULL")
    monkeypatch.setenv("WINN3_SIGNER_TICKET_PUBKEY_T1", base64.b64encode(lane.keys.t1pub).decode())
    ticket = lane.keys.ticket(lane.slug, action="new")
    posted = lane.mod.admin_post_node_winn3_signer_ticket(
        lane.mod.SignerTicketPost(slug=lane.slug, ticket=lane.mod.SignerTicketEnvelope(
            payload=ticket["payload"], sig=ticket["sig"])),
        harness.FakeRequest(), x_admin_token=descriptors.ADMIN)
    assert posted["stored"] is True
    result = lane.run()
    assert result["ok"] is True, result
    assert "sign" in lane.trace
    nonce = json.loads(base64.b64decode(ticket["payload"]))["nonce"]
    spent = lane.keys.signer().ledger["nonces"]
    assert spent[nonce]["slug"] == lane.slug and spent[nonce]["action"] == "new"
    # The newest identity ticket wins; a suspend or unsuspend ticket is never
    # read as the identity ticket.
    later = lane.keys.ticket(lane.slug, action="unsuspend")
    lane.mod.admin_post_node_winn3_signer_ticket(
        lane.mod.SignerTicketPost(slug=lane.slug, ticket=lane.mod.SignerTicketEnvelope(
            payload=later["payload"], sig=later["sig"])),
        harness.FakeRequest(), x_admin_token=descriptors.ADMIN)
    assert json.loads(lane.row()["winn3_signer_ticket_json"]) == ticket
    lane.clock[0] += 60
    newer = lane.keys.ticket(lane.slug, action="rekey")
    lane.mod.admin_post_node_winn3_signer_ticket(
        lane.mod.SignerTicketPost(slug=lane.slug, ticket=lane.mod.SignerTicketEnvelope(
            payload=newer["payload"], sig=newer["sig"])),
        harness.FakeRequest(), x_admin_token=descriptors.ADMIN)
    assert json.loads(lane.row()["winn3_signer_ticket_json"]) == newer
    # Another slug's newer ticket is never this slug's.
    lane.clock[0] += 60
    other = lane.keys.ticket("lab-beta", action="new")
    lane.mod.admin_post_node_winn3_signer_ticket(
        lane.mod.SignerTicketPost(slug="lab-beta", ticket=lane.mod.SignerTicketEnvelope(
            payload=other["payload"], sig=other["sig"])),
        harness.FakeRequest(), x_admin_token=descriptors.ADMIN)
    assert json.loads(lane.row()["winn3_signer_ticket_json"]) == newer
    # No nodes column of that name survives (H7/t4's guard, same ruling).
    assert "winn3_signer_ticket_json" not in columns
