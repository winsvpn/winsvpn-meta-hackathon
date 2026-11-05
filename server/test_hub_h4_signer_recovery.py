#!/usr/bin/env python3
"""H4: t1 tickets, ledger reconciliation, the operator bootstrap CLI and the
suspend/unsuspend transitions (design v17 3.8, 3.12 and their 5.5 / 5.6 tests).

The signer program is the H1 suite's extraction, driven in-process with
throwaway keys made in temp directories: a g-slot key, a t1 ticket key and SSH
host keys. No real key is used or created. The operator CLIs run in-process
too, with the root check and the signer-user lookup patched to the test's own
identity, the way the H1 installer-function tests patch their GNU shims.

Not run here: Tier A (the real systemd sandbox), the hub-lite end to end with
the real request builder (H2's signer client is tested by H2's own suite; only
the signer halves are tested here, as the H1 report states), and the operator
running a CLI as an actual non-root user (the root check is patched both ways
instead).

Rebased onto the integrated tree (H1/fix.next is the base for every 3.12 item
both slices implement): read_ledger returns (ledger, raw) and raises
ValueError("ledger-missing...") or ("ledger-malformed"); a missing ledger is
refused as ledger-integrity; the digest still runs on a missing ledger (rc 0,
BROKEN) and keeps the last valid checkpoint; the recovery allowance is H1's
recovery_allowance_remaining with a per-issuance recovery_allowance flag; and
the ticket is verified after the fleet rate limits, as H1 orders it.
"""
import _toolchain  # noqa: F401
import base64
import hashlib
import json
import os
import sqlite3
import stat
import sys
import threading
from pathlib import Path

import pytest

from test_hub_h1_descriptor_signer import (  # noqa: E402
    DAY, T0, Hub, openssl_sign, renew,
)

GAP = 1_000_000


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@pytest.fixture
def hub(tmp_path, monkeypatch):
    h = Hub(tmp_path)
    # The operator CLIs run as root and install files owned by the signer
    # service user; the tests stand in for both.
    monkeypatch.setattr(h.mod, "cli_is_root", lambda: True)
    monkeypatch.setattr(h.mod, "signer_user_ids", lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(h.mod, "cli_chown", lambda path, owner: None)
    return h


def as_non_root(hub, monkeypatch):
    monkeypatch.setattr(hub.mod, "cli_is_root", lambda: False)


def state(hub):
    return json.loads((hub.tmp / "state" / "ledger.json").read_text())


def epoch_file(hub):
    return (hub.tmp / "config" / "ticket-epoch").read_text().strip()


def descriptor_payload(slug, seq, iat=None, lifetime=14 * DAY):
    iat = T0 if iat is None else iat
    secret = hashlib.sha256(slug.encode()).hexdigest()
    return {"v": 3, "alg": "ed25519", "kid": "g2", "node": slug,
            "endpoint": "203.0.113.10:9111",
            "inner_router_v4": "10.10.0.1", "inner_resolver_v4": "10.10.0.1",
            "static_pub": base64.b64encode(b"\x11" * 32).decode(),
            "gateway_id": base64.b64encode(f"{slug}-gw1".encode()).decode(),
            "admission_secret": base64.b64encode(secret.encode()).decode(),
            "admission_gen": 1, "tag_size": 32, "padding": "bucket",
            "bucket_window_s": 10, "max_skew_s": 60,
            "auth_ed25519": base64.b64encode(b"\x22" * 32).decode(),
            "auth_mldsa65": base64.b64encode(b"\x33" * 1952).decode(),
            "seq": seq, "iat": iat, "not_after": iat + lifetime}


def descriptor_envelope(hub, payload, key=None):
    raw = canonical(payload)
    sig = openssl_sign(key or hub.gkey, hub.mod.DESCRIPTOR_DOMAIN + b"\x00" + raw, hub.tmp)
    return json.dumps({"payload": base64.b64encode(raw).decode(),
                       "sig": base64.b64encode(sig).decode()},
                      sort_keys=True, separators=(",", ":"))


def write_hub_db(path, hub, rows):
    """rows: {slug: (seq, admission ledger dict or None, key or None,
    lifetime or None)}. The stored descriptor is signed by the throwaway g
    key unless another is given."""
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE nodes (slug TEXT PRIMARY KEY,"
                 " winn3_descriptor_json TEXT, winn3_admission_json TEXT)")
    for slug, (seq, ledger, key, lifetime) in rows.items():
        envelope = descriptor_envelope(
            hub, descriptor_payload(slug, seq, lifetime=lifetime or 14 * DAY), key)
        conn.execute("INSERT INTO nodes (slug, winn3_descriptor_json, winn3_admission_json)"
                     " VALUES (?, ?, ?)",
                     (slug, envelope, json.dumps(ledger) if ledger else None))
    conn.commit()
    conn.close()


def write_env_file(path, hub):
    path.write_text(f"WINN3_DESCRIPTOR_PUBKEY_G2={base64.b64encode(hub.gpub).decode()}\n")


def write_digest(path, slugs):
    """slugs: {slug: (highest_seq, live_seq)}"""
    path.write_text(json.dumps({"version": 1, "slugs": {
        s: {"state": "active", "highest_seq": h, "live_seq": l}
        for s, (h, l) in slugs.items()}}))


def reconcile(hub, db, env, digest=None, high_water=None):
    args = ["--db", str(db), "--env-file", str(env)]
    if digest is not None:
        args += ["--digest", str(digest)]
    if high_water is not None:
        args += ["--high-water", str(high_water)]
    return hub.mod.operator_cli("reconcile", args)


def ledger_item(slug, issued_at, kind="identity"):
    return {"key": f"{slug}|sign|-|0", "verb": "sign", "kind": kind,
            "seq": 0, "kid": "g2", "payload": "", "sig": "",
            "identity_sha256": "", "admission_gen": 1, "issued_at": issued_at,
            "not_after": issued_at + 14 * DAY, "generation": 1, "eps": -1,
            "go_live": "auto", "tier": "free", "superseded": False,
            "ticket_action": "new",
            "nonce": hashlib.sha256(slug.encode()).hexdigest()[:32],
            "recovery_allowance": False}


# 5.5 / H1 contract ruling: the ticket payload is canonical JSON, and the
# signer refuses anything else (5.6 mutant: the canonical check removed).
def test_ticket_payload_must_be_canonical_json(hub):
    signer = hub.signer()
    body = {"slug": "cn", "action": "new", "epoch": 1, "endpoint_ip": "203.0.113.10",
            "gateway_id": "cn-gw1", "host_key_sha256": hub.host("a")[2],
            "go_live": "auto", "tier": "free", "nonce": "ab" * 32,
            "not_after": hub.clock[0] + 3 * DAY}
    raw = canonical(body)
    # A valid t1 signature over NON-canonical bytes is refused.
    shuffled = json.dumps(body, separators=(", ", ": ")).encode()
    sig = openssl_sign(hub.t1, hub.mod.TICKET_DOMAIN + b"\x00" + shuffled, hub.tmp)
    request = {"verb": "sign", "slug": "cn", "generation": 1, "expected_prior_seq": -1,
               "ticket": {"payload": base64.b64encode(shuffled).decode(),
                          "sig": base64.b64encode(sig).decode()},
               **hub.identity("cn")}
    assert signer.handle(request)["error"] == "ticket-not-canonical"
    # The canonical serialization of the same ticket is accepted.
    sig = openssl_sign(hub.t1, hub.mod.TICKET_DOMAIN + b"\x00" + raw, hub.tmp)
    request["ticket"] = {"payload": base64.b64encode(raw).decode(),
                         "sig": base64.b64encode(sig).decode()}
    assert signer.handle(request)["ok"]


# 5.5 / H1 review ruling: the signer refuses a missing ledger, and the
# operator bootstrap CLI creates the initial empty ledger explicitly.
def test_missing_ledger_is_refused_until_the_operator_bootstraps(hub, monkeypatch):
    (hub.tmp / "state" / "ledger.json").unlink()
    signer = hub.signer()
    # H1: a missing ledger is refused as ledger-integrity.
    assert hub.sign(signer, "nb")["error"] == "ledger-integrity"
    status = signer.handle({"verb": "status"})
    assert status["ok"] and status["ledger_present"] is False and status["ledger_ok"] is False
    # The digest never checkpoints a missing ledger: a checkpoint of an empty
    # ledger would let a restore skip the fail-closed reconciliation. H1: the
    # digest still runs (rc 0) and reports the chain as BROKEN.
    assert hub.mod.digest() == 0
    assert not (hub.tmp / "state" / "checkpoint.json").exists()
    assert "BROKEN" in (hub.tmp / "digest" / "latest.txt").read_text()
    # The operator bootstrap CLI creates the initial empty ledger explicitly.
    assert hub.mod.operator_cli("ledger-bootstrap", []) == 0
    fresh = state(hub)
    assert fresh == json.loads(hub.mod.canonical(hub.mod.empty_ledger()))
    assert stat.S_IMODE(os.stat(hub.tmp / "state" / "ledger.json").st_mode) == 0o600
    # Bootstrap is idempotent on an empty ledger and refused on a non-empty one.
    assert hub.mod.operator_cli("ledger-bootstrap", []) == 0
    assert hub.sign(hub.signer(), "nb")["ok"]
    assert hub.mod.operator_cli("ledger-bootstrap", []) != 0
    assert "nb" in state(hub)["slugs"]
    # ledger_bootstrap is absent from the app socket, and refused as non-root.
    assert hub.signer().handle({"verb": "ledger_bootstrap"})["error"] == "unknown-verb"
    as_non_root(hub, monkeypatch)
    before = (hub.tmp / "state" / "ledger.json").read_bytes()
    assert hub.mod.operator_cli("ledger-bootstrap", []) != 0
    assert (hub.tmp / "state" / "ledger.json").read_bytes() == before


# 5.5 ledger loss without a checkpoint: reconciliation fails closed, the
# transitions are authorized by tickets under the new epoch, and the floor
# includes the gap (D-TESTS additions, v8 fixes 6 and 8, v9 fix 8).
def test_reconcile_fails_closed_and_the_authorized_transitions_resume(hub, tmp_path, monkeypatch):
    db = tmp_path / "hub.db"
    env = tmp_path / "vpn_auth.env"
    digest = tmp_path / "latest.json"
    # The stored descriptor is inside its renewal window after the 24 h
    # advance, so the resumed renewal is the window rule, not the clock.
    write_hub_db(db, hub, {"rc": (41, {"sequence_floor": 41, "current": {"seq": 41},
                                      "previous": {"seq": 40}}, None, 8 * DAY)})
    write_env_file(env, hub)
    write_digest(digest, {"rc": (41, 41)})
    # A ticket consumed before the loss, while the ledger was healthy.
    spent = hub.ticket("rc", action="rekey")
    assert hub.sign(hub.signer(), "rc", eps=41, verb="rekey", action="rekey", ticket=spent)["ok"]
    (hub.tmp / "state" / "ledger.json").unlink()

    # Refusals: not root; a checkpoint present; a healthy ledger.
    as_non_root(hub, monkeypatch)
    assert reconcile(hub, db, env, digest) != 0
    monkeypatch.setattr(hub.mod, "cli_is_root", lambda: True)
    (hub.tmp / "state" / "checkpoint.json").write_text("{}")
    assert reconcile(hub, db, env, digest) != 0
    (hub.tmp / "state" / "checkpoint.json").unlink()
    assert hub.mod.operator_cli("ledger-bootstrap", []) == 0
    assert hub.sign(hub.signer(), "keep")["ok"]
    assert reconcile(hub, db, env, digest) != 0
    assert "keep" in state(hub)["slugs"]
    (hub.tmp / "state" / "ledger.json").unlink()

    assert reconcile(hub, db, env, digest) == 0
    # 3.12 step 1: the ticket epoch is incremented; every older ticket is refused.
    assert epoch_file(hub) == "2"
    # Steps 2 to 5: suspended, rebuilt from the highest-sequence stored
    # descriptor that verifies, lower known sequences burned, floor with the
    # gap, windows started as spent.
    fresh = state(hub)
    record = fresh["slugs"]["rc"]
    assert record["state"] == "suspended"
    assert record["floor"] == 41 + GAP
    live = hub.mod.live_issuance(record)
    assert live["seq"] == 41 and live["payload"]
    assert sorted(i["seq"] for i in record["issuances"] if i["superseded"]) == [40]
    assert hub.mod.audit_chain_ok(fresh)
    kinds = {(s["kind"], s.get("slug")) for s in fresh["window_spends"]}
    assert ("identity", None) in kinds and ("signature", None) in kinds and ("renewal", "rc") in kinds
    # Step 6: the signer refuses every change until the operator confirms.
    assert (hub.tmp / "config" / "RECOVERY-PENDING").exists()
    gated = hub.signer()
    assert hub.sign(gated, "rc", eps=41, verb="rekey", action="rekey",
                    ticket=hub.ticket("rc", action="rekey", epoch=2))["error"] == "recovery-unconfirmed"
    status = gated.handle({"verb": "status"})
    assert status["ok"] and status["recovery_pending"] is True
    # A running signer reloads the CLI's ledger after the confirmation.
    assert hub.mod.operator_cli("confirm", []) == 0
    assert not (hub.tmp / "config" / "RECOVERY-PENDING").exists()
    assert renew(hub, gated, "rc", 41)["error"] == "slug-suspended"
    # A rekey before the unsuspend is refused (suspended).
    assert hub.sign(gated, "rc", eps=41, verb="rekey", action="rekey",
                    ticket=hub.ticket("rc", action="rekey", epoch=2))["error"] == "slug-suspended"
    # The authorized transition: an unsuspend ticket under the new epoch.
    assert gated.handle({"verb": "unsuspend", "slug": "rc",
                         "ticket": hub.ticket("rc", action="unsuspend", epoch=2)})["ok"]
    # H1 checks the fleet windows before the ticket, so while the windows
    # 3.12 step 5 started as spent, every ticketed issuance is refused by them.
    assert hub.sign(gated, "rc", eps=41, verb="rekey", action="rekey",
                    ticket=spent)["error"] == "rate-limit-signatures"
    # Automatic renewal is refused while the windows 3.12 step 5 started as
    # spent; a 24 h advance resumes it, above the floor with the gap.
    assert renew(hub, gated, "rc", 41)["error"].startswith("rate-limit-")
    hub.clock[0] += DAY + 1
    # Old-epoch tickets are refused, spent or not: the ticket consumed before
    # the loss cannot be replayed, and an unconsumed one is refused too.
    assert hub.sign(gated, "rc", eps=41, verb="rekey", action="rekey",
                    ticket=spent)["error"] == "ticket-epoch-stale"
    assert hub.sign(gated, "rc", eps=41, verb="rekey", action="rekey",
                    ticket=hub.ticket("rc", action="rekey", epoch=1))["error"] == "ticket-epoch-stale"
    resumed = renew(hub, gated, "rc", 41)
    assert resumed["ok"] and resumed["seq"] == 41 + GAP + 1
    renewed = hub.payload(resumed)
    original = json.loads(base64.b64decode(live["payload"]))
    assert renewed["static_pub"] == original["static_pub"]
    assert renewed["seq"] == 41 + GAP + 1
    # A retry of the renewal returns identical bytes.
    assert renew(hub, gated, "rc", 41)["payload"] == resumed["payload"]


# 5.5: an unverified stored descriptor rebuilds no live issuance, so the
# no-live-issuance rule applies (the ticket and its epoch are the authority).
def test_reconcile_without_a_verifying_descriptor_leaves_no_live_issuance(hub, tmp_path):
    db = tmp_path / "hub.db"
    env = tmp_path / "vpn_auth.env"
    write_hub_db(db, hub, {"uv": (41, {"sequence_floor": 41}, None, 14 * DAY)})
    write_env_file(env, hub)
    # Tamper with the stored descriptor: the signature no longer verifies.
    conn = sqlite3.connect(str(db))
    row = conn.execute("SELECT winn3_descriptor_json FROM nodes WHERE slug = 'uv'").fetchone()
    envelope = json.loads(row[0])
    envelope["sig"] = base64.b64encode(b"\x00" * 64).decode()
    conn.execute("UPDATE nodes SET winn3_descriptor_json = ? WHERE slug = 'uv'",
                 (json.dumps(envelope),))
    conn.commit()
    conn.close()
    (hub.tmp / "state" / "ledger.json").unlink()
    assert reconcile(hub, db, env) == 0
    # The confirmation grants the one-time allowance this re-key spends, so
    # the window that step 5 started as spent does not hold it back.
    assert hub.mod.operator_cli("confirm", ["--allowance", "1"]) == 0
    signer = hub.signer()
    assert signer.handle({"verb": "unsuspend", "slug": "uv",
                          "ticket": hub.ticket("uv", action="unsuspend", epoch=2)})["ok"]
    # A renew after the unsuspend and before any rekey: no live issuance.
    assert renew(hub, signer, "uv", 41)["error"] == "no-live-issuance"
    reply = hub.sign(signer, "uv", eps=41, verb="rekey", action="rekey",
                     ticket=hub.ticket("uv", action="rekey", epoch=2))
    assert reply["ok"] and reply["seq"] == 41 + GAP + 1
    assert state(hub)["slugs"]["uv"]["presented_stored"] == 41


# 5.5 recovery allowance (D-TESTS addition, v9 fix 7): six ticketed re-keys
# issue within one window that 3.12 step 5 started as spent; a seventh is
# refused; each issuance needs its own ticket; the socket offers no grant.
def test_recovery_allowance_issues_six_and_refuses_the_seventh(hub, tmp_path, monkeypatch):
    db = tmp_path / "hub.db"
    env = tmp_path / "vpn_auth.env"
    rows = {f"r{n}": (n, {"sequence_floor": n}, None, 14 * DAY) for n in range(6)}
    write_hub_db(db, hub, rows)
    write_env_file(env, hub)
    (hub.tmp / "state" / "ledger.json").unlink()
    assert reconcile(hub, db, env) == 0
    assert hub.mod.operator_cli("confirm", ["--allowance", "6"]) == 0
    signer = hub.signer()
    for n in range(6):
        slug = f"r{n}"
        assert signer.handle({"verb": "unsuspend", "slug": slug,
                              "ticket": hub.ticket(slug, action="unsuspend", epoch=2)})["ok"]
        reply = hub.sign(signer, slug, eps=n, verb="rekey", action="rekey",
                         ticket=hub.ticket(slug, action="rekey", epoch=2))
        assert reply["ok"] and reply["seq"] == n + GAP + 1, reply
    # H1's allowance field: granted 6 by the confirmation, spent to 0, and
    # each issuance under it is flagged.
    assert state(hub)["recovery_allowance_remaining"] == 0
    assert [state(hub)["slugs"][f"r{n}"]["issuances"][-1]["recovery_allowance"]
            for n in range(6)] == [True] * 6
    # A seventh ticketed re-key in the spent window is refused.
    assert hub.sign(signer, "r0", eps=0 + GAP + 1, verb="rekey", action="rekey",
                    ticket=hub.ticket("r0", action="rekey", epoch=2))["error"] == "rate-limit-signatures"
    # An issuance without its own ticket is refused and spends no unit.
    assert hub.sign(signer, "r0", eps=GAP + 1, verb="rekey", action="rekey",
                    ticket={"payload": "", "sig": ""})["error"] == "ticket-malformed"
    assert state(hub)["recovery_allowance_remaining"] == 0
    # The allowance cannot be granted or raised through the app socket.
    for verb in ("grant_allowance", "confirm", "reconcile", "ledger_bootstrap"):
        assert signer.handle({"verb": verb})["error"] == "unknown-verb"
    # Only root grants it, and never more than the ledger's slug count.
    as_non_root(hub, monkeypatch)
    assert hub.mod.operator_cli("confirm", ["--allowance", "1"]) != 0
    monkeypatch.setattr(hub.mod, "cli_is_root", lambda: True)
    (hub.tmp / "state" / "ledger.json").unlink()
    assert reconcile(hub, db, env) == 0
    assert hub.mod.operator_cli("confirm", ["--allowance", "7"]) != 0
    assert hub.mod.operator_cli("confirm", ["--allowance", "6"]) == 0


# 5.5 recovery allowance on a checkpoint restore (D-TESTS addition, v10 fix 7):
# spent and clear windows, durability across a restart, retries, and the normal
# quotas after the allowance is spent.
def build_six_slug_ledger(hub, recent):
    """A six-slug ledger whose identity issuances are `recent` (4 of them in
    the last 24 h when True, all of them older when False)."""
    ledger = json.loads(hub.mod.canonical(hub.mod.empty_ledger()))
    for n in range(6):
        slug = f"r{n}"
        issued_at = hub.clock[0] - (3600 if (recent and n < 4) else 30 * 3600)
        ledger["slugs"][slug] = {
            "state": "active", "floor": 0, "presented_stored": 0,
            "issuances": [ledger_item(slug, issued_at)]}
    return ledger


def restore_with_six(hub, tmp_path, recent):
    ledger = build_six_slug_ledger(hub, recent)
    hub.mod.write_ledger(ledger)
    assert hub.mod.digest() == 0
    (hub.tmp / "state" / "ledger.json").unlink()
    assert hub.mod.operator_cli("restore-checkpoint", []) == 0
    assert hub.mod.operator_cli("confirm", ["--allowance", "6"]) == 0
    return hub.signer()


def test_recovery_allowance_on_a_checkpoint_restore(hub, tmp_path):
    # A restore whose normal identity window is spent (four new identities
    # already issued): six ticketed re-keys issue at once, a seventh is
    # refused until the window turns.
    signer = restore_with_six(hub, tmp_path, recent=True)
    for n in range(6):
        reply = hub.sign(signer, f"r{n}", eps=0, verb="rekey", action="rekey",
                         ticket=hub.ticket(f"r{n}", action="rekey"))
        assert reply["ok"] and reply["seq"] == 1, reply
    assert state(hub)["recovery_allowance_remaining"] == 0
    assert hub.sign(signer, "r0", eps=1, verb="rekey", action="rekey",
                    ticket=hub.ticket("r0", action="rekey"))["error"] == "rate-limit-new-identities"
    # The 64-signature count shows none of the six allowance issuances.
    since = hub.clock[0] - DAY
    assert hub.mod.issued_since(state(hub), since) == 4

    # A restore whose windows are clear: six under the allowance, then the
    # normal limit of 4 new identities per 24 h, and an eleventh refused.
    hub.clock[0] += 2 * DAY
    signer = restore_with_six(hub, tmp_path, recent=False)
    issued, tickets = [], []
    for n in range(6):
        ticket = hub.ticket(f"r{n}", action="rekey")
        tickets.append(ticket)
        reply = hub.sign(signer, f"r{n}", eps=0, verb="rekey", action="rekey", ticket=ticket)
        assert reply["ok"] and reply["seq"] == 1, reply
        issued.append(reply)
    for n in range(4):
        slug = f"r{n}"
        reply = hub.sign(signer, slug, eps=1, verb="rekey", action="rekey",
                         ticket=hub.ticket(slug, action="rekey"))
        assert reply["ok"] and reply["seq"] == 2, reply
    assert hub.sign(signer, "r0", eps=2, verb="rekey", action="rekey",
                    ticket=hub.ticket("r0", action="rekey"))["error"] == "rate-limit-new-identities"
    # The 64-signature count shows none of the six allowance issuances.
    since = hub.clock[0] - DAY
    assert hub.mod.issued_since(state(hub), since) == 4
    # A retry of an already issued re-key returns the identical envelope and
    # spends no second unit.
    retry = hub.sign(signer, "r0", eps=0, verb="rekey", action="rekey", ticket=tickets[0])
    assert retry["payload"] == issued[0]["payload"]
    assert state(hub)["recovery_allowance_remaining"] == 0

    # Durable: allowance consumption survives a signer restart between the
    # third and fourth re-key; the remaining allowance is 3 after it.
    hub.clock[0] += 2 * DAY
    signer = restore_with_six(hub, tmp_path, recent=False)
    for n in range(3):
        assert hub.sign(signer, f"r{n}", eps=0, verb="rekey", action="rekey",
                        ticket=hub.ticket(f"r{n}", action="rekey"))["ok"]
    restarted = hub.signer()
    assert state(hub)["recovery_allowance_remaining"] == 3
    for n in range(3, 6):
        assert hub.sign(restarted, f"r{n}", eps=0, verb="rekey", action="rekey",
                        ticket=hub.ticket(f"r{n}", action="rekey"))["ok"]
    assert state(hub)["recovery_allowance_remaining"] == 0


# 5.5 / 5.6: the checkpoint restore verifies the checkpoint, refuses a
# tampered one, and refuses to overwrite a healthy ledger.
def test_restore_checkpoint_verifies_and_refuses_tampering(hub, monkeypatch):
    original_ticket = hub.ticket("cp")
    assert hub.sign(hub.signer(), "cp", ticket=original_ticket)["ok"]
    assert hub.mod.digest() == 0
    original = (hub.tmp / "state" / "checkpoint.json").read_bytes()
    # A healthy ledger is never overwritten by a restore.
    assert hub.mod.operator_cli("restore-checkpoint", []) != 0
    (hub.tmp / "state" / "ledger.json").unlink()
    # A tampered checkpoint does not verify and is not restored.
    tampered = json.loads(original)
    tampered["ledger"]["slugs"]["cp"]["floor"] = 999
    (hub.tmp / "state" / "checkpoint.json").write_text(json.dumps(tampered))
    assert hub.mod.operator_cli("restore-checkpoint", []) != 0
    assert not (hub.tmp / "state" / "ledger.json").exists()
    # Not as a non-root user.
    as_non_root(hub, monkeypatch)
    assert hub.mod.operator_cli("restore-checkpoint", []) != 0
    monkeypatch.setattr(hub.mod, "cli_is_root", lambda: True)
    # The intact checkpoint restores, and the gate holds until confirmed.
    (hub.tmp / "state" / "checkpoint.json").write_bytes(original)
    assert hub.mod.operator_cli("restore-checkpoint", []) == 0
    gated = hub.signer()
    assert hub.sign(gated, "cp3")["error"] == "recovery-unconfirmed"
    # Confirming without a pending recovery is refused.
    assert hub.mod.operator_cli("confirm", []) == 0
    assert hub.mod.operator_cli("confirm", []) != 0
    # The restored ledger serves: the consumed nonce is retained, so the
    # ticket spent before the loss cannot be spent again (a same-key retry
    # still returns the identical envelope), and renewal works.
    signer = hub.signer()
    retry = hub.sign(signer, "cp", ticket=original_ticket)
    assert retry["ok"] and retry["seq"] == 0
    assert hub.sign(signer, "cp", eps=0, ticket=original_ticket)["error"] == "ticket-already-spent"
    hub.clock[0] += 8 * DAY  # inside the renewal window
    assert renew(hub, signer, "cp", 0)["ok"]


# 3.12: the operator CLIs replace ledger.json under a RUNNING signer. A signer
# that kept its in-memory copy would serve (and write back) the wrong ledger.
def _lost_slug_db(hub, tmp_path, slug="cn", seq=41):
    db, env = tmp_path / "hub.db", tmp_path / "hub.env"
    write_hub_db(db, hub, {slug: (seq, None, None, None)})
    write_env_file(env, hub)
    return db, env


def test_running_signer_picks_up_the_bootstrapped_ledger(hub):
    os.unlink(hub.tmp / "state" / "ledger.json")
    signer = hub.signer()
    assert hub.sign(signer, "cn")["error"] == "ledger-integrity"
    assert signer.handle({"verb": "status"})["ledger_present"] is False
    assert hub.mod.operator_cli("ledger-bootstrap", []) == 0
    assert signer.handle({"verb": "status"})["ledger_present"] is True
    assert hub.sign(signer, "cn")["ok"]


def test_running_signer_never_serves_a_stale_ledger_after_reconcile_and_confirm(hub, tmp_path):
    signer = hub.signer()          # an empty ledger, in memory
    db, env = _lost_slug_db(hub, tmp_path)
    assert reconcile(hub, db, env) == 0
    assert hub.mod.operator_cli("confirm", []) == 0
    # No request reached the signer between the reconcile and the confirmation.
    # The slug is suspended on disk, so it issues nothing, and nothing the
    # signer serves can write the stale copy back.
    assert hub.sign(signer, "cn", ticket=hub.ticket("cn", epoch=2))["error"] == "slug-suspended"
    assert state(hub)["slugs"]["cn"]["state"] == "suspended"
    assert signer.handle({"verb": "unsuspend", "slug": "cn",
                          "ticket": hub.ticket("cn", action="unsuspend", epoch=2)})["ok"]


def test_a_refusal_flush_while_pending_never_overwrites_the_cli_ledger(hub, tmp_path):
    signer = hub.signer()
    assert hub.sign(signer, "aa")["ok"]
    os.unlink(hub.tmp / "state" / "ledger.json")      # the ledger is lost
    db, env = _lost_slug_db(hub, tmp_path, slug="bb")
    assert reconcile(hub, db, env) == 0
    assert list(state(hub)["slugs"]) == ["bb"]
    junk = {"verb": "sign", "slug": "zz", "generation": 1, "expected_prior_seq": -1,
            "ticket": {"payload": "", "sig": ""}}
    assert signer.handle(junk)["error"] == "recovery-unconfirmed"
    assert list(state(hub)["slugs"]) == ["bb"]


def test_status_reports_the_epoch_reconcile_just_wrote(hub, tmp_path):
    signer = hub.signer()
    assert signer.handle({"verb": "status"})["epoch"] == 1
    db, env = _lost_slug_db(hub, tmp_path)
    assert reconcile(hub, db, env) == 0
    assert epoch_file(hub) == "2"
    assert signer.handle({"verb": "status"})["epoch"] == 2


def test_the_root_cli_hands_ledger_lock_and_files_to_the_signer_user(hub, monkeypatch):
    # A fresh install: the operator's root CLI is the first to take the lock,
    # and the signer service and the digest unit (not root) must open it.
    os.unlink(hub.tmp / "state" / "ledger.json")
    handed = []
    monkeypatch.setattr(hub.mod, "cli_chown",
                        lambda fd, owner: handed.append((os.fstat(fd).st_ino, owner)))
    assert hub.mod.operator_cli("ledger-bootstrap", []) == 0
    lock_ino = os.stat(hub.tmp / "state" / "ledger.lock").st_ino
    ledger_ino = os.stat(hub.tmp / "state" / "ledger.json").st_ino
    assert lock_ino in [ino for ino, _ in handed]
    assert ledger_ino in [ino for ino, _ in handed]
    # A symlinked lock is never followed by the root CLI.
    (hub.tmp / "state" / "ledger.lock").unlink()
    target = hub.tmp / "elsewhere"
    target.write_text("x")
    (hub.tmp / "state" / "ledger.lock").symlink_to(target)
    with pytest.raises(OSError):
        with hub.mod.LedgerLock(True):
            pass


def test_reconcile_ignores_an_unsigned_sequence_above_the_request_bound(hub, tmp_path):
    # The hub database is writable by the app: a poisoned floor must not leave
    # the slug unable to issue (sequence-exhausted) for good.
    db, env = tmp_path / "hub.db", tmp_path / "hub.env"
    write_hub_db(db, hub, {"cn": (41, {"sequence_floor": 2 ** 60,
                                       "current": {"seq": 2 ** 53}}, None, None)})
    write_env_file(env, hub)
    assert reconcile(hub, db, env) == 0
    assert state(hub)["slugs"]["cn"]["floor"] == 41 + GAP


# ---------------------------------------------------------------------------
# Turn 1 to Turn 2 fixes (Sol and Claude H4 review): the signer and the CLIs
# share one lock, the gate precedes the ledger it guards, recovery keeps every
# slug it knows, and bad evidence is refused rather than dropped.
# ---------------------------------------------------------------------------
def _recovery_inputs(hub, tmp_path, rows=None, digest_slugs=None):
    db, env, digest = tmp_path / "hub.db", tmp_path / "hub.env", tmp_path / "latest.json"
    write_hub_db(db, hub, rows if rows is not None else {"cn": (41, None, None, None)})
    write_env_file(env, hub)
    if digest_slugs is not None:
        write_digest(digest, digest_slugs)
    return db, env, digest


def _junk_sign():
    return {"verb": "sign", "slug": "zz", "generation": 1, "expected_prior_seq": -1,
            "ticket": {"payload": "", "sig": ""}}


# 3.12: an operator CLI holds the ledger lock for its whole operation, and a
# request waits for it, so no CLI replaces the ledger between a request's
# reload check and its write (Sol blocker 1).
def test_a_request_waits_for_the_ledger_lock_an_operator_cli_holds(hub):
    signer = hub.signer()
    done, out = threading.Event(), []

    def worker():
        out.append(signer.handle({"verb": "status"}))
        done.set()

    thread = threading.Thread(target=worker)
    with hub.mod.LedgerLock(True):
        thread.start()
        assert not done.wait(0.5)
    assert done.wait(10)
    thread.join()
    assert out[0]["ok"]


# Sol blocker 5, Claude defect 5: the descriptor is closed when the handover
# or the flock fails, so a failing CLI does not leak one per attempt.
def test_the_ledger_lock_closes_its_descriptor_when_the_handover_fails(hub, monkeypatch):
    seen = []

    def boom(fd, owner):
        seen.append(fd)
        raise OSError("chown")

    monkeypatch.setattr(hub.mod, "cli_chown", boom)
    with pytest.raises(OSError):
        hub.mod.LedgerLock(True).__enter__()
    assert seen
    with pytest.raises(OSError):
        os.fstat(seen[0])


# Sol blocker 2: a ledger lost under a running signer is refused, and no later
# commit or refusal flush recreates the old copy.
def test_running_signer_refuses_ledger_loss_without_recreating_it(hub):
    signer = hub.signer()
    assert hub.sign(signer, "live")["ok"]
    ledger_path = hub.tmp / "state" / "ledger.json"
    ledger_path.unlink()
    assert renew(hub, signer, "live", 0)["error"] == "ledger-integrity"
    assert hub.sign(signer, "other")["error"] == "ledger-integrity"
    assert not ledger_path.exists()
    signer.flush()
    assert not ledger_path.exists()


# Claude's surviving Turn 1 mutant: the real root test is never run by the
# suites above, which replace cli_is_root. Run it, as root and as not.
def test_cli_is_root_follows_the_effective_uid(tmp_path, monkeypatch):
    plain = tmp_path / "plain"
    plain.mkdir()
    mod = Hub(plain).mod
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert mod.cli_is_root() is True
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert mod.cli_is_root() is False
    assert mod.operator_cli("reconcile", []) != 0


# Sol blocker 3: a slug the hub knows but that has no v3 state, and a digest
# slug with no sequence, are kept: suspended, at the recovery gap.
def test_reconcile_keeps_known_slugs_without_state_suspended_at_the_gap(hub, tmp_path):
    db, env, digest = _recovery_inputs(hub, tmp_path, digest_slugs={"dg": (-1, None)})
    with sqlite3.connect(str(db)) as conn:
        conn.execute("INSERT INTO nodes (slug) VALUES ('allocated')")
    assert reconcile(hub, db, env, digest) == 0
    slugs = state(hub)["slugs"]
    assert set(slugs) == {"cn", "allocated", "dg"}
    for name in ("allocated", "dg"):
        assert slugs[name]["state"] == "suspended" and slugs[name]["floor"] == GAP - 1
        assert slugs[name]["issuances"] == []
    assert slugs["cn"]["floor"] == 41 + GAP


# Sol blocker 3, second half: a slug no source knows is suspended in a
# reconciled ledger and keeps the gap once an unsuspend ticket frees it.
def test_unrecorded_recovery_slug_requires_unsuspend_and_keeps_gap(hub):
    recovered = hub.mod.build_reconciled_ledger({}, {}, {}, {}, hub.clock[0])
    hub.mod.write_ledger(recovered)
    signer = hub.signer()
    assert hub.sign(signer, "lost")["error"] == "slug-suspended"
    assert "lost" not in state(hub)["slugs"]
    assert signer.handle({"verb": "unsuspend", "slug": "lost",
                          "ticket": hub.ticket("lost", action="unsuspend")})["ok"]
    assert state(hub)["slugs"]["lost"]["floor"] == GAP - 1
    hub.clock[0] += DAY + 1
    reply = hub.sign(signer, "lost")
    assert reply["ok"] and reply["seq"] == GAP


def test_an_ordinary_ledger_still_issues_for_a_new_slug(hub):
    signer = hub.signer()
    assert hub.sign(signer, "fresh")["ok"] and state(hub)["slugs"]["fresh"]["floor"] == 0


# Sol blocker 7: recovery evidence that is present but malformed is refused,
# never dropped (a dropped value would lower a floor). An absent digest is the
# operator's known case.
def test_reconcile_refuses_malformed_digest_and_high_water(hub, tmp_path):
    db, env, digest = _recovery_inputs(hub, tmp_path)
    lost = (hub.tmp / "state" / "ledger.json").read_bytes()
    os.unlink(hub.tmp / "state" / "ledger.json")
    for text in ("not json", json.dumps([1]), json.dumps({"slugs": []}),
                 json.dumps({"slugs": {"cn": "x"}}),
                 json.dumps({"slugs": {"Bad Slug": {"highest_seq": 1}}}),
                 json.dumps({"slugs": {"cn": {"highest_seq": "7"}}}),
                 json.dumps({"slugs": {"cn": {"highest_seq": -5}}}),
                 json.dumps({"slugs": {"cn": {"live_seq": True}}})):
        digest.write_text(text)
        assert reconcile(hub, db, env, digest) != 0, text
        assert not (hub.tmp / "state" / "ledger.json").exists()
        assert not hub.mod.recovery_pending()
    water = tmp_path / "water.json"
    for text in ("not json", json.dumps([1]), json.dumps({"cn": "7"}), json.dumps({"cn": -1}),
                 json.dumps({"cn": True}), json.dumps({"Bad Slug": 3})):
        water.write_text(text)
        assert reconcile(hub, db, env, high_water=water) != 0, text
        assert not (hub.tmp / "state" / "ledger.json").exists()
    # An absent digest is fine, and so is the digest the signer itself writes.
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    assert lost  # the lost ledger was an empty one


# Sol blocker 7 and Claude defect 1: a broken audit chain does not strand the
# operator, and a confirmation never clears the gate on a ledger that does not
# verify or is not the staged recovery.
def test_confirm_refuses_a_broken_chain_and_a_ledger_that_is_not_the_staged_one(hub, tmp_path):
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env) == 0
    staged = state(hub)
    # Not the staged ledger: a slug added behind the CLI's back.
    other = json.loads(json.dumps(staged))
    other["slugs"]["extra"] = {"state": "active", "floor": -1, "presented_stored": -1, "issuances": []}
    hub.mod.write_ledger(other)
    assert hub.mod.operator_cli("confirm", []) != 0
    assert hub.mod.recovery_pending()
    # A broken chain.
    broken = json.loads(json.dumps(staged))
    broken["audit_head"] = "broken"
    hub.mod.write_ledger(broken)
    assert hub.mod.operator_cli("confirm", []) != 0
    assert hub.mod.recovery_pending()
    # Even when the marker names exactly that broken ledger, the chain decides.
    marker = hub.tmp / "config" / "RECOVERY-PENDING"
    pending = json.loads(marker.read_text())
    pending["ledger_sha256"] = hashlib.sha256(hub.mod.canonical(broken)).hexdigest()
    marker.unlink()
    marker.write_bytes(hub.mod.canonical(pending) + b"\n")
    assert hub.mod.operator_cli("confirm", []) != 0
    assert hub.mod.recovery_pending()
    assert hub.mod.ledger_is_lost()
    # The broken ledger is recoverable by a fresh reconciliation.
    assert reconcile(hub, db, env) == 0
    assert hub.mod.operator_cli("confirm", []) == 0
    assert not hub.mod.recovery_pending()


def test_a_malformed_recovery_marker_is_refused_not_cleared(hub, tmp_path):
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env) == 0
    marker = hub.tmp / "config" / "RECOVERY-PENDING"
    for blob in (b"garbage", b"[]", b'{"kind":"reconcile"}'):
        marker.unlink()
        marker.write_bytes(blob)
        assert hub.mod.operator_cli("confirm", []) != 0
        assert marker.exists()


# Sol blocker 1, second half: the gate goes up before the ledger it guards is
# installed, for reconcile and for restore, and names that ledger.
def _gate_probe(hub, monkeypatch):
    real = hub.mod.install_ledger
    seen = []

    def checked(ledger):
        marker = hub.tmp / "config" / "RECOVERY-PENDING"
        assert marker.exists()
        if "recovery_confirmation" not in ledger:  # not the confirmation's own install
            seen.append(json.loads(marker.read_text()))
            assert seen[-1]["ledger_sha256"] == hashlib.sha256(hub.mod.canonical(ledger)).hexdigest()
        return real(ledger)

    monkeypatch.setattr(hub.mod, "install_ledger", checked)
    return seen


def test_the_reconcile_gate_is_up_before_the_recovered_ledger_is_installed(hub, tmp_path, monkeypatch):
    seen = _gate_probe(hub, monkeypatch)
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env) == 0
    assert [m["kind"] for m in seen] == ["reconcile"]
    assert hub.mod.operator_cli("confirm", []) == 0
    assert len(seen) == 1


def test_the_restore_gate_is_up_before_the_checkpoint_is_installed(hub, monkeypatch):
    assert hub.sign(hub.signer(), "rs")["ok"]
    assert hub.mod.digest() == 0
    os.unlink(hub.tmp / "state" / "ledger.json")
    seen = _gate_probe(hub, monkeypatch)
    assert hub.mod.operator_cli("restore-checkpoint", []) == 0
    assert [m["kind"] for m in seen] == ["restore"]
    assert "rs" in state(hub)["slugs"]


def test_a_crash_between_the_gate_and_the_install_leaves_a_gated_signer(hub, tmp_path, monkeypatch):
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")

    def crash(ledger):
        raise OSError("power cut")

    monkeypatch.setattr(hub.mod, "install_ledger", crash)
    with pytest.raises(OSError):
        reconcile(hub, db, env)
    assert hub.mod.recovery_pending()
    # The ledger is still missing, which H1 refuses first (ledger-integrity);
    # the gate is up behind it.
    assert hub.sign(hub.signer(), "zz")["error"] in ("recovery-unconfirmed", "ledger-integrity")


# Sol question 9: a confirmation interrupted after the ledger was installed and
# before the gate came down finishes on a rerun and grants nothing twice.
def test_an_interrupted_confirmation_is_finished_by_a_rerun_without_a_second_grant(hub, tmp_path, monkeypatch):
    rows = {"a": (1, None, None, None), "b": (2, None, None, None)}
    db, env, _ = _recovery_inputs(hub, tmp_path, rows=rows)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env) == 0
    real_clear = hub.mod.clear_pending_marker
    monkeypatch.setattr(hub.mod, "clear_pending_marker",
                        lambda: (_ for _ in ()).throw(OSError("interrupted")))
    with pytest.raises(OSError):
        hub.mod.operator_cli("confirm", ["--allowance", "2"])
    assert hub.mod.recovery_pending()
    first = state(hub)
    assert first["recovery_allowance_remaining"] == 2
    monkeypatch.setattr(hub.mod, "clear_pending_marker", real_clear)
    assert hub.mod.operator_cli("confirm", ["--allowance", "2"]) == 0
    assert not hub.mod.recovery_pending()
    assert state(hub) == first
    assert [e["event"] for e in first["audit"]].count("recovery-confirm") == 1


# Sol blocker 7: the last valid checkpoint is never replaced by one whose chain
# fails, and nothing is checkpointed while a recovery is pending.
def test_digest_never_overwrites_a_valid_checkpoint_with_a_broken_chain(hub):
    signer = hub.signer()
    assert hub.sign(signer, "ck")["ok"]
    assert hub.mod.digest() == 0
    checkpoint = hub.tmp / "state" / "checkpoint.json"
    good = checkpoint.read_bytes()
    report = json.loads((hub.tmp / "digest" / "latest.json").read_text())
    assert report["checkpoint_sha256"] == hashlib.sha256(good).hexdigest()
    broken = state(hub)
    broken["audit_head"] = "broken"
    hub.mod.write_ledger(broken)
    assert hub.mod.digest() == 0
    assert checkpoint.read_bytes() == good
    report = json.loads((hub.tmp / "digest" / "latest.json").read_text())
    assert report["chain_ok"] is False
    assert report["checkpoint_sha256"] == hashlib.sha256(good).hexdigest()


def test_digest_writes_no_checkpoint_while_a_recovery_is_pending(hub):
    assert hub.mod.digest() == 0
    checkpoint = hub.tmp / "state" / "checkpoint.json"
    before = checkpoint.read_bytes()
    hub.clock[0] += 60
    (hub.tmp / "config" / "RECOVERY-PENDING").write_text("{}")
    assert hub.mod.digest() == 0
    assert checkpoint.read_bytes() == before


# Sol blocker 6: the CLIs work with the service stopped, so WORK_DIR (the
# service's RuntimeDirectory) does not exist.
def test_reconcile_verifies_stored_descriptors_without_the_service_work_dir(hub, tmp_path):
    db, env, _ = _recovery_inputs(hub, tmp_path, rows={"cn": (41, None, None, 8 * DAY)})
    os.unlink(hub.tmp / "state" / "ledger.json")
    service_dir = hub.mod.WORK_DIR
    hub.mod.WORK_DIR = str(tmp_path / "no-such-runtime-directory")
    try:
        assert reconcile(hub, db, env) == 0
        assert hub.mod.WORK_DIR == str(tmp_path / "no-such-runtime-directory")
    finally:
        hub.mod.WORK_DIR = service_dir
    live = [i for i in state(hub)["slugs"]["cn"]["issuances"] if not i["superseded"]]
    assert len(live) == 1 and live[0]["seq"] == 41 and live[0]["payload"]


# Sol blocker 2: bootstrap is the first initialization only. A host that held a
# ledger and lost it is reconciled, never bootstrapped into an empty ledger.
def test_bootstrap_is_refused_once_a_ledger_has_existed(hub, tmp_path):
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert hub.mod.operator_cli("ledger-bootstrap", []) == 0
    marker = hub.tmp / "config" / "LEDGER-INITIALIZED"
    assert marker.exists() and stat.S_IMODE(os.stat(marker).st_mode) == 0o440
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert hub.mod.operator_cli("ledger-bootstrap", []) != 0
    assert not (hub.tmp / "state" / "ledger.json").exists()
    db, env, _ = _recovery_inputs(hub, tmp_path)
    assert reconcile(hub, db, env) == 0
    assert state(hub)["reconciled"] is True


def test_bootstrap_is_refused_on_a_reconciled_or_broken_ledger(hub, tmp_path):
    db, env, _ = _recovery_inputs(hub, tmp_path, rows={})
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env) == 0
    assert hub.mod.operator_cli("confirm", []) == 0
    assert hub.mod.operator_cli("ledger-bootstrap", []) != 0
    broken = hub.mod.empty_ledger()
    broken["audit_head"] = "broken"
    hub.mod.write_ledger(broken)
    assert hub.mod.operator_cli("ledger-bootstrap", []) != 0
    # Rebase: a reconciled ledger with no slug and no audit entry yet (built
    # directly) is still not an empty ledger to bootstrap over.
    bare = hub.mod.build_reconciled_ledger({}, {}, {}, {}, hub.clock[0])
    assert not bare["slugs"] and not bare["audit"] and not bare["nonces"]
    hub.mod.write_ledger(bare)
    assert hub.mod.operator_cli("ledger-bootstrap", []) != 0
    assert state(hub)["reconciled"] is True


# Rebase: a host that never held a ledger, with a recovery gate up and no
# ledger (a crash between the gate and the install), is never bootstrapped:
# only the pending check decides this case.
def test_bootstrap_is_refused_while_a_recovery_is_pending_on_a_fresh_host(hub, tmp_path, monkeypatch):
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert not (hub.tmp / "config" / "LEDGER-INITIALIZED").exists()

    def crash(ledger):
        raise OSError("power cut")

    monkeypatch.setattr(hub.mod, "install_ledger", crash)
    with pytest.raises(OSError):
        reconcile(hub, db, env)
    monkeypatch.undo()
    monkeypatch.setattr(hub.mod, "cli_is_root", lambda: True)
    monkeypatch.setattr(hub.mod, "signer_user_ids", lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(hub.mod, "cli_chown", lambda fd, owner: None)
    assert hub.mod.recovery_pending()
    assert hub.mod.operator_cli("ledger-bootstrap", []) != 0
    assert not (hub.tmp / "state" / "ledger.json").exists()


def test_a_ledger_of_the_wrong_shape_is_unreadable_and_never_raises(hub):
    for text in ('{"version":1}', '[]', '{"version":2,"slugs":{},"nonces":{},"refusals":{},"audit":[],"audit_head":""}',
                 '{"version":1,"slugs":[],"nonces":{},"refusals":{},"audit":[],"audit_head":""}'):
        (hub.tmp / "state" / "ledger.json").write_text(text)
        # H1's read_ledger raises ledger-malformed; the CLIs' view is
        # "present, unusable".
        with pytest.raises(ValueError, match="ledger-malformed"):
            hub.mod.read_ledger()
        assert hub.mod.ledger_on_disk() == (None, True)
        assert hub.sign(hub.signer(), "sh")["error"] == "ledger-integrity"
    assert hub.mod.audit_chain_ok({}) is False
    assert hub.mod.audit_chain_ok({"audit": [{"prev": 1}], "audit_head": ""}) is False
    assert hub.mod.audit_chain_ok({"audit": "x", "audit_head": ""}) is False


# Sol question 5 and blocker 1: a refusal while a recovery is pending changes
# nothing on disk, and its count reaches the ledger after the confirmation.
def test_refusals_during_a_pending_recovery_are_kept_not_written(hub, tmp_path):
    signer = hub.signer()
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env) == 0
    staged = (hub.tmp / "state" / "ledger.json").read_bytes()
    for _ in range(2):
        assert signer.handle(_junk_sign())["error"] == "recovery-unconfirmed"
        hub.clock[0] += hub.mod.REFUSAL_FLUSH_S + 1
    assert (hub.tmp / "state" / "ledger.json").read_bytes() == staged
    # The signer holds counts in memory; a flush while pending writes none.
    assert signer.ledger["refusals"]
    with hub.mod.LedgerLock(True):
        signer.flush()
    assert (hub.tmp / "state" / "ledger.json").read_bytes() == staged
    assert hub.mod.operator_cli("confirm", []) == 0
    assert signer.handle(_junk_sign())["error"] != "recovery-unconfirmed"
    with hub.mod.LedgerLock(True):
        signer.flush()
    counts = {}
    for per_day in state(hub)["refusals"].values():
        for reason, count in per_day.items():
            counts[reason] = counts.get(reason, 0) + count
    assert counts.get("recovery-unconfirmed") == 2, state(hub)["refusals"]



# Rebase onto H1: H1's digest still runs on a missing or broken ledger (rc 0,
# BROKEN) and then lists no or untrusted slugs. Reconcile must not read that
# file as 3.12 step 4 evidence (it would lower a floor without saying so): it
# is refused, and the last trusted digest is still accepted.
def test_reconcile_refuses_a_digest_written_from_a_missing_ledger(hub, tmp_path, capsys):
    db, env, _ = _recovery_inputs(hub, tmp_path, rows={"cn": (41, None, None, None)})
    signer = hub.signer()
    assert hub.sign(signer, "dg")["ok"]
    assert hub.mod.digest() == 0
    trusted = tmp_path / "trusted.json"
    trusted.write_bytes((hub.tmp / "digest" / "latest.json").read_bytes())
    assert json.loads(trusted.read_text())["chain_ok"] is True
    # The ledger and its checkpoint are both lost (reconcile, not restore).
    os.unlink(hub.tmp / "state" / "ledger.json")
    os.unlink(hub.tmp / "state" / "checkpoint.json")
    assert hub.mod.digest() == 0
    broken = hub.tmp / "digest" / "latest.json"
    assert json.loads(broken.read_text())["chain_ok"] is False
    capsys.readouterr()
    assert reconcile(hub, db, env, broken) != 0
    assert "chain_ok false" in capsys.readouterr().err
    assert not (hub.tmp / "state" / "ledger.json").exists()
    assert not hub.mod.recovery_pending()
    assert reconcile(hub, db, env, trusted) == 0
    slugs = state(hub)["slugs"]
    assert slugs["dg"]["floor"] == 0 + GAP and slugs["cn"]["floor"] == 41 + GAP


# Rebase onto H1: the signer refuses a recovery_allowance_remaining above
# MAX_SLUGS (recovery-allowance-malformed, every issuance), so the
# confirmation never grants more than the 64-slug cap, whatever the ledger's
# slug count.
def test_confirm_never_grants_an_allowance_the_signer_would_refuse(hub):
    hub_state = {f"s{n:02d}": {"descriptor": None, "sequences": set()} for n in range(65)}
    ledger = hub.mod.build_reconciled_ledger(hub_state, {}, {}, {}, hub.clock[0])
    os.unlink(hub.tmp / "state" / "ledger.json")
    with hub.mod.LedgerLock(True):
        hub.mod.write_pending_marker("reconcile", ledger)
        assert hub.mod.install_ledger(ledger) == 0
    assert hub.mod.operator_cli("confirm", ["--allowance", "65"]) != 0
    assert hub.mod.recovery_pending()
    assert hub.mod.operator_cli("confirm", ["--allowance", "64"]) == 0
    assert state(hub)["recovery_allowance_remaining"] == 64
    signer = hub.signer()
    assert signer.handle({"verb": "unsuspend", "slug": "s00",
                          "ticket": hub.ticket("s00", action="unsuspend")})["ok"]
    reply = hub.sign(signer, "s00", eps=-1, verb="rekey", action="rekey",
                     ticket=hub.ticket("s00", action="rekey"))
    assert reply["ok"] and reply["seq"] == GAP, reply
    assert state(hub)["recovery_allowance_remaining"] == 63


# Rebase onto H1: the request lock is re-entered by the ledger write inside
# it on the same thread only. A write from another thread still waits.
def test_the_request_lock_is_reentrant_on_its_own_thread_only(hub):
    done = threading.Event()

    def writer():
        hub.mod.write_ledger(hub.mod.empty_ledger())
        done.set()

    with hub.mod.LedgerLock(True):
        hub.mod.write_ledger(hub.mod.empty_ledger())   # same thread: no deadlock
        thread = threading.Thread(target=writer)
        thread.start()
        assert not done.wait(0.5)
    assert done.wait(10)
    thread.join()
    with hub.mod.LedgerLock(True):
        pass                                           # depth went back to zero



# Rebase: each window kind 3.12 step 5 starts as spent is honoured on its own
# (the reconciliation writes all three at once, so the shared signature window
# would otherwise hide a missing identity or renewal check).
def test_each_reconciled_window_kind_is_honoured_on_its_own(hub):
    signer = hub.signer()
    first = hub.sign(signer, "wk")
    assert first["ok"]
    spent = state(hub)
    spent["window_spends"] = [{"at": hub.clock[0], "kind": "identity", "count": 4}]
    hub.mod.write_ledger(spent)
    assert hub.sign(signer, "wk2")["error"] == "rate-limit-new-identities"
    hub.clock[0] += 8 * DAY          # inside wk's renewal window, identity window aged out
    spent = state(hub)
    spent["window_spends"] = [{"at": hub.clock[0], "slug": "wk", "kind": "renewal", "count": 1}]
    hub.mod.write_ledger(spent)
    assert renew(hub, signer, "wk", first["seq"])["error"] == "rate-limit-renewal"
    hub.clock[0] += DAY + 1
    assert renew(hub, signer, "wk", first["seq"])["ok"]


# R-8 (rebase, the seats' row): a refusal-counter flush never writes a ledger
# whose audit chain does not verify back to disk. H1 wrote the in-memory copy
# (the tampered ledger plus the counters) back; the tampered bytes must stay
# exactly as found, for the operator and for reconcile.
def test_a_refusal_flush_never_writes_a_ledger_whose_chain_fails(hub):
    signer = hub.signer()
    assert hub.sign(signer, "tp")["ok"]
    path = hub.tmp / "state" / "ledger.json"
    broken = state(hub)
    broken["audit_head"] = "broken"
    hub.mod.write_ledger(broken)
    tampered = path.read_bytes()
    # The running signer reloads the tampered file and refuses every change;
    # the first refusal is past the flush interval, so it would flush.
    assert hub.sign(signer, "tp2")["error"] == "ledger-integrity"
    assert signer.ledger["refusals"]
    assert path.read_bytes() == tampered
    hub.clock[0] += hub.mod.REFUSAL_FLUSH_S + 1
    assert hub.sign(signer, "tp3")["error"] == "ledger-integrity"
    assert path.read_bytes() == tampered
    with hub.mod.LedgerLock(True):
        signer.flush()
    assert path.read_bytes() == tampered
    # A restarted signer sees the same broken chain, never a rewritten file.
    assert hub.sign(hub.signer(), "tp4")["error"] == "ledger-integrity"


# R-8: a refusal-counter flush never rewrites a ledger whose audit chain does
# not verify (3.12: authorization state is never overwritten by a flush).
def test_a_refusal_flush_never_rewrites_a_ledger_whose_chain_fails(hub):
    assert hub.sign(hub.signer(), "tc")["ok"]
    tampered = state(hub)
    tampered["audit"][0]["seq"] = 7
    path = hub.tmp / "state" / "ledger.json"
    path.write_text(json.dumps(tampered))
    before = path.read_bytes()
    signer = hub.signer()
    hub.clock[0] += 2 * hub.mod.REFUSAL_FLUSH_S
    assert hub.sign(signer, "tc2")["error"] == "ledger-integrity"
    signer.flush()
    assert path.read_bytes() == before


# A ledger the signer cannot read on reload (EACCES, EIO) is refused, read
# again on the next request, and never overwritten with the old in-memory copy.
def test_an_unreadable_ledger_on_reload_is_never_overwritten_with_the_old_copy(hub, monkeypatch):
    signer = hub.signer()
    assert hub.sign(signer, "ur")["ok"]
    path = hub.tmp / "state" / "ledger.json"
    replaced = state(hub)
    replaced["refusals"] = {"marker": {"operator": 1}}
    path.write_text(json.dumps(replaced))
    real = hub.mod.read_ledger

    def unreadable():
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(hub.mod, "read_ledger", unreadable)
    try:
        first = hub.sign(signer, "ur2")
    except OSError:
        first = {"error": "internal-error"}
    assert first.get("ok") is not True
    monkeypatch.setattr(hub.mod, "read_ledger", real)
    assert hub.sign(signer, "ur3")["ok"]
    assert state(hub)["refusals"].get("marker") == {"operator": 1}


# A ledger whose parse raises neither ValueError nor OSError (a deeply nested
# file raises RecursionError) is refused, kept byte for byte, and read again on
# the next request; the old in-memory copy is never written back over it.
def test_a_ledger_that_cannot_be_parsed_on_reload_is_never_overwritten(hub):
    signer = hub.signer()
    assert hub.sign(signer, "dp")["ok"]
    path = hub.tmp / "state" / "ledger.json"
    good = path.read_bytes()
    deep = b"[" * 200000 + b"]" * 200000
    path.write_bytes(deep)
    try:
        first = hub.sign(signer, "dp2")
    except RecursionError:
        first = {"error": "internal-error"}
    assert first.get("ok") is not True
    assert hub.sign(signer, "dp3").get("ok") is not True
    signer.flush()
    assert path.read_bytes() == deep
    path.write_bytes(good)
    assert hub.sign(signer, "dp4")["ok"]


# A ledger whose parse raises RecursionError is unparseable like any other
# malformed file (3.12): the operator CLIs see it as present and lost, so
# reconcile replaces it instead of crashing, and the daily digest reports it as
# BROKEN, keeps the file byte for byte and writes no checkpoint from it.
def test_a_ledger_too_deep_to_parse_is_lost_to_the_operator_clis_and_the_digest(hub, tmp_path):
    path = hub.tmp / "state" / "ledger.json"
    deep = b"[" * 200000 + b"]" * 200000
    path.write_bytes(deep)
    assert hub.mod.ledger_on_disk() == (None, True)
    assert hub.mod.ledger_is_lost()
    assert hub.mod.digest() == 0
    assert path.read_bytes() == deep
    assert not (hub.tmp / "state" / "checkpoint.json").exists()
    db, env = _lost_slug_db(hub, tmp_path, slug="bb")
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    assert list(state(hub)["slugs"]) == ["bb"]


# ---------------------------------------------------------------------------
# H4R-T4: every parse of a file or a request the operator or an attacker can
# make malformed treats a nesting too deep to parse (RecursionError) like any
# other malformed input. MemoryError is deliberately not caught: it can be
# transient, and a healthy file read under memory pressure must never be
# classed as lost or malformed.
#
# The signer reads requests of at most 64 KiB. On the hub's interpreter
# (python 3.12) a nesting that fits there already exceeds the C recursion
# limit; on 3.14 the limit is the thread's stack. The bounded cases below run
# on a thread with a 2 MiB stack, and first check that the very bytes they
# send raise RecursionError there, so no case passes vacuously. 2 MiB, not
# less: 3.12's guard is a counter, not stack-aware, and on a 512 KiB or 1 MiB
# thread it overruns the stack (SIGBUS) before the counter trips; from about
# 1.5 MiB it raises RecursionError. On 3.14 a 2 MiB thread still refuses
# these depths (it parses at most about 14000 levels there).
# ---------------------------------------------------------------------------
SMALL_STACK = 2 * 1024 * 1024


def on_small_stack(fn):
    out = {}

    def run():
        try:
            out["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed back to the test
            out["error"] = exc

    previous = threading.stack_size(SMALL_STACK)
    try:
        worker = threading.Thread(target=run)
        worker.start()
    finally:
        threading.stack_size(previous)
    worker.join()
    if "error" in out:
        raise out["error"]
    return out["value"]


def deep_bytes(depth):
    return b"[" * depth + b"]" * depth


def too_deep_on_small_stack(blob):
    def parse():
        try:
            json.loads(blob)
        except RecursionError:
            return True
        return False
    return on_small_stack(parse)


class FakeConn:
    def __init__(self, data):
        self.data, self.sent = data, b""

    def settimeout(self, value):
        pass

    def recv(self, size):
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk

    def sendall(self, blob):
        self.sent += blob


# read_request runs outside serve_connection's catch: a request line nested
# too deep to parse is request-malformed, never an exception that ends serve().
def test_a_request_too_deep_to_parse_is_malformed_and_never_ends_the_signer(hub, monkeypatch):
    line = deep_bytes(32000)
    assert len(line) + 1 <= hub.mod.REQUEST_MAX_BYTES
    assert too_deep_on_small_stack(line)
    assert on_small_stack(lambda: hub.mod.read_request(FakeConn(line + b"\n"))) is None
    monkeypatch.setattr(hub.mod, "peer_is_hub", lambda conn: True)
    signer = hub.signer()
    conn = FakeConn(line + b"\n")
    on_small_stack(lambda: hub.mod.serve_connection(signer, conn))
    assert json.loads(conn.sent) == {"ok": False, "error": "request-malformed"}


# The nonce pre-parse reads unverified request bytes: a ticket payload nested
# too deep to parse is ticket-malformed for the issuing verbs and for suspend,
# and is counted like any other refusal.
def test_a_ticket_too_deep_to_parse_is_refused_as_malformed(hub):
    payload = deep_bytes(20000)
    assert too_deep_on_small_stack(payload)
    ticket = {"payload": base64.b64encode(payload).decode(),
              "sig": base64.b64encode(b"\x00" * 64).decode()}
    signer = hub.signer()
    sign = {"verb": "sign", "slug": "dt", "generation": 1, "expected_prior_seq": -1,
            "ticket": ticket, **hub.identity("dt")}
    assert len(canonical(sign)) + 1 <= hub.mod.REQUEST_MAX_BYTES
    assert on_small_stack(lambda: signer.handle(sign)) == {"ok": False, "error": "ticket-malformed"}
    suspend = {"verb": "suspend", "slug": "dt", "ticket": ticket}
    assert on_small_stack(lambda: signer.handle(suspend)) == {"ok": False, "error": "ticket-malformed"}
    on_disk = state(hub)
    assert "dt" not in on_disk["slugs"] and not on_disk["nonces"]
    assert any("ticket-malformed" in counts for counts in on_disk["refusals"].values())


# verify_ticket's own parse: a t1-signed payload nested too deep to parse is
# ticket-malformed. The request path parses the same bytes first, so this is
# met only at the stack's edge; the contract holds on its own.
def test_verify_ticket_refuses_a_signed_payload_too_deep_to_parse(hub):
    payload = deep_bytes(20000)
    assert too_deep_on_small_stack(payload)
    sig = openssl_sign(hub.t1, hub.mod.TICKET_DOMAIN + b"\x00" + payload, hub.tmp)
    envelope = {"payload": base64.b64encode(payload).decode(), "sig": base64.b64encode(sig).decode()}
    config = hub.mod.load_config()
    with pytest.raises(hub.mod.Refused) as refused:
        on_small_stack(lambda: hub.mod.verify_ticket(
            config, hub.mod.empty_ledger(), envelope, "dt", ("new",)))
    assert str(refused.value) == "ticket-malformed"


# The node's identity file is relayed by the hub: one nested too deep to parse
# is identity-malformed after a valid ticket, and the ticket is not spent.
def test_an_identity_too_deep_to_parse_is_refused_as_malformed(hub):
    identity = deep_bytes(20000)
    assert too_deep_on_small_stack(identity)
    signer = hub.signer()
    request = {"verb": "sign", "slug": "di", "generation": 1, "expected_prior_seq": -1,
               "ticket": hub.ticket("di"), "identity": base64.b64encode(identity).decode(),
               "identity_sig": base64.b64encode(b"sig").decode(),
               "admission_secret": hashlib.sha256(b"di").hexdigest()}
    assert len(canonical(request)) + 1 <= hub.mod.REQUEST_MAX_BYTES
    assert on_small_stack(lambda: signer.handle(request)) == {"ok": False, "error": "identity-malformed"}
    assert not state(hub)["nonces"]


# A signer.json that is malformed in any way (nested too deep to parse, not an
# object, a key half that is not text) is config-unavailable, at start and on
# a running signer, never a crash; the good file serves again.
def test_a_malformed_signer_config_is_unavailable_never_a_crash(hub):
    path = hub.tmp / "config" / "signer.json"
    good = path.read_bytes()
    pub = json.loads(good)["active_slot_pubkey"]
    running = hub.signer()
    for blob in (deep_bytes(200000), b"[]",
                 json.dumps({"active_slot": "g2", "active_slot_pubkey": 5}).encode(),
                 json.dumps({"active_slot": "g2", "active_slot_pubkey": pub,
                             "ticket_pubkey_t1": ["x"]}).encode()):
        path.write_bytes(blob)
        started = hub.signer()
        assert started.config is None, blob[:40]
        assert hub.sign(started, "mc")["error"] == "config-unavailable", blob[:40]
        assert hub.sign(running, "mc")["error"] == "config-unavailable", blob[:40]
        assert running.handle({"verb": "status"})["epoch"] is None
    path.write_bytes(good)
    assert hub.sign(hub.signer(), "mc")["ok"]


# A hub admission record (the app can write the database) nested too deep to
# parse is dropped like any other malformed record: the verifying stored
# descriptor still sets the floor, and reconcile completes.
def test_reconcile_drops_an_admission_record_too_deep_to_parse(hub, tmp_path):
    db, env = _lost_slug_db(hub, tmp_path, slug="dh", seq=41)
    conn = sqlite3.connect(str(db))
    conn.execute("UPDATE nodes SET winn3_admission_json = ? WHERE slug = 'dh'",
                 (deep_bytes(200000).decode(),))
    conn.commit()
    conn.close()
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    record = state(hub)["slugs"]["dh"]
    assert record["state"] == "suspended" and record["floor"] == 41 + GAP
    assert [item["seq"] for item in record["issuances"]] == [41]


# A stored descriptor nested too deep to parse does not verify: the slug is
# suspended at the gap with no live issuance, and reconcile completes.
def test_reconcile_treats_a_descriptor_too_deep_to_parse_as_unverified(hub, tmp_path):
    db, env = _lost_slug_db(hub, tmp_path, slug="dh", seq=41)
    conn = sqlite3.connect(str(db))
    conn.execute("INSERT INTO nodes (slug, winn3_descriptor_json, winn3_admission_json)"
                 " VALUES (?, ?, NULL)", ("dd", deep_bytes(200000).decode()))
    conn.commit()
    conn.close()
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    slugs = state(hub)["slugs"]
    assert slugs["dd"]["state"] == "suspended" and slugs["dd"]["floor"] == GAP - 1
    assert slugs["dd"]["issuances"] == []
    assert slugs["dh"]["floor"] == 41 + GAP


# Recovery evidence the operator passes that is nested too deep to parse is
# refused like any other malformed evidence (a dropped value would lower a
# floor): nothing is installed and no gate goes up.
def test_reconcile_refuses_a_digest_too_deep_to_parse(hub, tmp_path):
    db, env, digest = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    digest.write_bytes(deep_bytes(200000))
    assert reconcile(hub, db, env, digest) == 2
    assert not (hub.tmp / "state" / "ledger.json").exists()
    assert not hub.mod.recovery_pending()


def test_reconcile_refuses_a_high_water_file_too_deep_to_parse(hub, tmp_path):
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    water = tmp_path / "water.json"
    water.write_bytes(deep_bytes(200000))
    assert reconcile(hub, db, env, tmp_path / "absent.json", water) == 2
    assert not (hub.tmp / "state" / "ledger.json").exists()
    assert not hub.mod.recovery_pending()


def test_a_checkpoint_too_deep_to_parse_is_refused_not_restored(hub):
    os.unlink(hub.tmp / "state" / "ledger.json")
    (hub.tmp / "state" / "checkpoint.json").write_bytes(deep_bytes(200000))
    assert hub.mod.operator_cli("restore-checkpoint", []) == 2
    assert not (hub.tmp / "state" / "ledger.json").exists()
    assert not hub.mod.recovery_pending()


def test_a_recovery_marker_too_deep_to_parse_is_refused_not_cleared(hub, tmp_path):
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    marker = hub.tmp / "config" / "RECOVERY-PENDING"
    marker.unlink()
    marker.write_bytes(deep_bytes(200000))
    assert hub.mod.operator_cli("confirm", []) == 2
    assert marker.read_bytes() == deep_bytes(200000)


# str.isdigit accepts digits int() refuses (superscript two) and digits that
# are not ASCII; int() refuses more than 4300 digits. Each is refused with
# rc 2 and the gate stays up; a plain allowance still confirms.
def test_confirm_refuses_an_allowance_that_is_not_plain_ascii_digits(hub, tmp_path):
    db, env, _ = _recovery_inputs(hub, tmp_path)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    for raw in ("²", "١", "1" * 5000):
        assert hub.mod.operator_cli("confirm", ["--allowance", raw]) == 2, raw[:8]
        assert hub.mod.recovery_pending()
    assert hub.mod.operator_cli("confirm", ["--allowance", "1"]) == 0
    assert state(hub)["recovery_allowance_remaining"] == 1


# audit_chain_ok never raises: an audit entry nested too deep to re-serialize
# for its hash (json.dumps refuses depths json.loads accepts on 3.14) does
# not verify, so the operator CLIs see that ledger as lost.
def test_an_audit_entry_too_deep_to_hash_does_not_verify(hub, monkeypatch):
    nested = []
    for _ in range(200000):
        nested = [nested]
    ledger = hub.mod.empty_ledger()
    ledger["audit"] = [{"n": 0, "prev": "", "hash": "", "x": nested}]
    assert hub.mod.audit_chain_ok(ledger) is False
    monkeypatch.setattr(hub.mod, "read_ledger", lambda: (ledger, b""))
    assert hub.mod.ledger_is_lost()


# H4R-Q-SECRET: a stored descriptor that verifies under a ring key but whose
# admission_secret is not base64 of ASCII text is one this signer never
# writes. Reconcile completes: its signed sequence still sets the floor, and it
# is burned, never rebuilt as a live issuance.
def test_reconcile_burns_a_verifying_descriptor_with_a_malformed_admission_secret(hub, tmp_path):
    db, env = _lost_slug_db(hub, tmp_path, slug="dh", seq=41)
    conn = sqlite3.connect(str(db))
    for slug, secret in (("ds", "not base64!"), ("du", base64.b64encode(b"\xff" * 64).decode())):
        payload = descriptor_payload(slug, 77)
        payload["admission_secret"] = secret
        conn.execute("INSERT INTO nodes (slug, winn3_descriptor_json, winn3_admission_json)"
                     " VALUES (?, ?, NULL)", (slug, descriptor_envelope(hub, payload)))
    conn.commit()
    conn.close()
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    slugs = state(hub)["slugs"]
    for slug in ("ds", "du"):
        assert slugs[slug]["state"] == "suspended" and slugs[slug]["floor"] == 77 + GAP
        assert [(item["kind"], item["seq"]) for item in slugs[slug]["issuances"]] == [("burned", 77)]
    assert [item["kind"] for item in slugs["dh"]["issuances"]] == ["identity"]
    assert slugs["dh"]["floor"] == 41 + GAP


# H4R-Q-SECRET: a ring-signed stored descriptor this signer never minted (its
# admission_secret is not the base64 of 64 ASCII hex bytes, the only shape
# issue() writes and the hub accepts) keeps its sequence in the floor as a
# burned issuance and rebuilds no live identity; reconcile completes and names
# the slug. Nothing is dropped from the floor, nothing crashes.
def test_reconcile_burns_a_verified_descriptor_whose_secret_is_malformed(hub, tmp_path, capsys):
    db, env = tmp_path / "hub.db", tmp_path / "hub.env"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE nodes (slug TEXT PRIMARY KEY,"
                 " winn3_descriptor_json TEXT, winn3_admission_json TEXT)")
    for slug, secret in (("na", "!!not-base64"), ("nb", base64.b64encode(b"\xff" * 4).decode()),
                         ("nc", base64.b64encode(b"zz").decode())):
        payload = descriptor_payload(slug, 41)
        payload["admission_secret"] = secret
        conn.execute("INSERT INTO nodes (slug, winn3_descriptor_json, winn3_admission_json)"
                     " VALUES (?, ?, NULL)", (slug, descriptor_envelope(hub, payload)))
    conn.execute("INSERT INTO nodes (slug, winn3_descriptor_json, winn3_admission_json)"
                 " VALUES (?, ?, NULL)", ("nd", descriptor_envelope(hub, descriptor_payload("nd", 7))))
    conn.commit()
    conn.close()
    write_env_file(env, hub)
    os.unlink(hub.tmp / "state" / "ledger.json")
    capsys.readouterr()
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    slugs = state(hub)["slugs"]
    for slug in ("na", "nb", "nc"):
        assert slugs[slug]["state"] == "suspended" and slugs[slug]["floor"] == 41 + GAP, slug
        assert [(item["seq"], item["kind"]) for item in slugs[slug]["issuances"]] == [(41, "burned")], slug
    assert [(item["seq"], item["kind"]) for item in slugs["nd"]["issuances"]] == [(7, "identity")]
    err = capsys.readouterr().err
    assert all(f"reconcile: {slug} seq 41" in err for slug in ("na", "nb", "nc")), err
    assert "reconcile: nd " not in err, err


# H4R-Q-SECRET: identity_sha256 decodes the admission secret as strictly as the
# hub's winn3_identity_digest (validate=True, then 64 lowercase ASCII hex). The
# shape issue() mints keeps its digest; every other shape is a ValueError.
def test_identity_sha256_decodes_the_admission_secret_as_strictly_as_the_hub(hub):
    payload = descriptor_payload("dv", 5)
    canonical_secret = payload["admission_secret"]
    secret = base64.b64decode(canonical_secret).decode("ascii")
    fields = {name: payload.get(name, "") for name in hub.mod.IDENTITY_DIGEST_FIELDS}
    fields["admission_fingerprint"] = hub.mod.admission_fingerprint(secret)
    assert hub.mod.identity_sha256(payload) == hashlib.sha256(canonical(fields)).hexdigest()
    for bad in (canonical_secret[:8] + "!" + canonical_secret[8:],
                canonical_secret[:8] + "\n" + canonical_secret[8:],
                base64.b64encode(secret.upper().encode()).decode(),
                base64.b64encode(secret[:63].encode()).decode(),
                base64.b64encode(b"zz").decode(), "!!not-base64", 7, None):
        payload["admission_secret"] = bad
        with pytest.raises(ValueError):
            hub.mod.identity_sha256(payload)
    del payload["admission_secret"]
    with pytest.raises(ValueError):
        hub.mod.identity_sha256(payload)


# The reconciled live identity carries the digest of its own stored payload.
def test_reconcile_records_the_live_identity_digest_of_the_stored_payload(hub, tmp_path):
    db, env = _lost_slug_db(hub, tmp_path, slug="dl", seq=41)
    os.unlink(hub.tmp / "state" / "ledger.json")
    assert reconcile(hub, db, env, tmp_path / "absent.json") == 0
    (live,) = state(hub)["slugs"]["dl"]["issuances"]
    payload = json.loads(base64.b64decode(live["payload"]))
    assert live["kind"] == "identity" and live["seq"] == 41
    assert live["identity_sha256"] == hub.mod.identity_sha256(payload)
    assert len(live["identity_sha256"]) == 64 and set(live["identity_sha256"]) <= set("0123456789abcdef")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
