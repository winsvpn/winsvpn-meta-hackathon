#!/usr/bin/env python3
"""hub-lite (tools/onetouch_tiers/hub_lite.py): the real hub app and the real
descriptor signer from the control-plane installer, run locally (design v17
5.1 "Setup"; the Singapore runbook prerequisite 2 and the hub halves of
STEP-13 and STEP-14).

Every test runs the extracted main.py on the REAL fastapi and pydantic through
starlette's in-process TestClient, and the extracted wins-descriptor-signer as
its own process behind a real AF_UNIX socket. Keys g1, g2, g3, t1 and every
node host key are throwaway, made in temp directories. No host, DNS name or
network is contacted: hub_lite's network guard refuses it and its node
transport answers the hub's ssh commands from recorded state.

Mutants (7) are text edits to the EXTRACTED main.py or signer, each applied an
exact number of times (a changed installer shows up as a bad pattern, not a
silent survivor). MUTANTS maps each to the scenario and the test that kill it.

Run: cd server && python3 -B -m pytest -q -p no:cacheprovider test_winn3_onetouch_hublite.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TIERS = ROOT / "tools" / "onetouch_tiers"
sys.path.insert(0, str(TIERS))
import hub_lite as hl  # noqa: E402

INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
HUB_LITE = TIERS / "hub_lite.py"
OTHER_DIGEST = "b" * 64


@pytest.fixture
def hub(tmp_path):
    value = hl.HubLite(tmp_path / "hub", init=True)
    assert value.manifest["deviations"] == [] and value.env.get("HIDE_CONTROL_ORIGIN") is None
    yield value
    value.close()


def make_hub(tmp_path, name="hub", **kwargs):
    return hl.HubLite(tmp_path / name, init=True, **kwargs)


def released(hub, slug, stealth=None, go_live="auto", tier="free"):
    """node, a `new` ticket, complete-fresh: the fresh install of 3.17."""
    assert hub.node(slug, stealth=stealth)["ok"]
    assert hub.ticket(slug, "new", go_live=go_live, tier=tier)["posted_status"] == 200
    done = hub.complete_fresh(slug)
    assert done["status_code"] == 200, done
    return done


def provisioned(hub, slug, **kwargs):
    released(hub, slug, **kwargs)
    out = hub.provision(slug)
    assert out["result"]["ok"], out
    return out


def live(hub, slug, **kwargs):
    provisioned(hub, slug, **kwargs)
    out = hub.sweep(slug)                          # HL-F2 fixed: no budget wait with other nodes present
    assert out["armed"]["clock_advanced_s"] == 0.0 and out["armed"]["budget_trusted"], out
    assert out["reopened"] == [slug], out
    return out


def events(hub, kind):
    return [e for e in hub.events if e["event"] == kind]


# ------------------------------------------------------------- scenarios --
# Each returns True when the hub behaves as the design requires. The tests
# below assert True on the shipped code; test_mutants asserts False on each
# mutant.

def scenario_reset_needs_a_reset_ticket(hub):
    live(hub, "rs-1")
    hub.node("rs-1", fresh_machine=True)
    refused = hub.complete_fresh("rs-1")
    return (refused["status_code"] == 409 and "reset" in refused["body"]["detail"]
            and hub.status("rs-1")["operator_enabled"] == 0)


def scenario_go_live_needs_every_carry_proof(hub):
    provisioned(hub, "cp-1")
    out = hub.sweep("cp-1", carry={"udp": "stale"})
    return out["reopened"] == [] and hub.status("cp-1")["operator_enabled"] == 0


def scenario_go_live_needs_the_v3_canary(hub):
    provisioned(hub, "cn-1")
    out = hub.sweep("cn-1", canary="fail")
    return out["reopened"] == [] and hub.status("cn-1")["operator_enabled"] == 0


def scenario_flip_records_the_fresh_install_source(hub):
    live(hub, "ps-1")
    status = hub.status("ps-1")
    return (status["operator_enabled"] == 1 and status["latest_promotion_source"] == "auto_golive_fresh_install"
            and status["latch_cause"] == "auto_golive_fresh_install")


def scenario_ticket_is_single_use(hub):
    provisioned(hub, "tk-1")
    assert hub.ticket("tk-1", "rekey")["posted_status"] == 200
    assert hub.rerun("tk-1", new_gateway_keys=True)["ok"]       # new gateway keys, same machine
    first = hub.provision("tk-1")["result"]
    assert first["ok"] and first["seq"] == 1, first
    assert hub.rerun("tk-1", new_gateway_keys=True)["ok"]       # changed again; the rekey ticket is spent
    replay = hub.provision("tk-1")["result"]
    return (replay["ok"] is False and replay["reason"] == "ticket-already-spent"
            and hub.status("tk-1")["descriptor_seq"] == 1)


def scenario_installer_digest_must_match(hub):
    assert hub.node("dg-1")["ok"]
    hub.ticket("dg-1", "new")
    refused = hub.complete_fresh("dg-1", OTHER_DIGEST)
    return refused["status_code"] == 409 and "differs from the registered revision" in refused["body"]["detail"]


def scenario_suspended_slug_issues_nothing(hub):
    provisioned(hub, "sp-1")
    assert hub.hold("sp-1")["ok"]
    assert hub.signer_state_verb("sp-1", "suspend")["state"] == "suspended"
    hub.advance(8 * hl.DAY)                    # inside the renewal window
    renewed = hub.signer_request("sp-1", "renew", store=False)
    return renewed["ok"] is False and renewed["error"] == "slug-suspended"


MUTANTS = (
    {"id": "M1", "target": "main", "count": 1, "scenario": scenario_reset_needs_a_reset_ticket,
     "killed_by": "test_complete_fresh_refusals_and_the_reset_through_the_http_route",
     "what": "complete-fresh accepts a reset without a reset ticket",
     "old": '        refusals, reset_nonce = fresh_completion_reset_failures(conn, row)\n'
            '        if refusals:\n',
     "new": '        refusals, reset_nonce = fresh_completion_reset_failures(conn, row)\n'
            '        if False:\n'},
    {"id": "M2", "target": "main", "count": 1, "scenario": scenario_go_live_needs_every_carry_proof,
     "killed_by": "test_each_proof_failed_or_stale_keeps_the_node_dark",
     "what": "the go-live flip ignores a carry proof older than the completion",
     "old": '        if status != "ok" or not _iso_after(data.get(f"{column}_ok_at"), completed):\n',
     "new": '        if False:\n'},
    {"id": "M3", "target": "main", "count": 1, "scenario": scenario_flip_records_the_fresh_install_source,
     "killed_by": "test_fresh_install_goes_live_end_to_end",
     "what": "the flip writes a promotion source other than auto_golive_fresh_install",
     "old": "gate, AUTOMATIC_PROMOTION_SOURCES[1] if fresh else AUTOMATIC_PROMOTION_SOURCES[0],",
     "new": "gate, AUTOMATIC_PROMOTION_SOURCES[0],"},
    {"id": "M4", "target": "signer", "count": 1, "scenario": scenario_ticket_is_single_use,
     "killed_by": "test_signer_request_path_crosses_the_socket",
     "what": "the signer accepts a ticket replay",
     "old": '    if ticket["nonce"] in ledger["nonces"]:\n        raise Refused("ticket-already-spent")\n',
     "new": '    if False:\n        raise Refused("ticket-already-spent")\n'},
    {"id": "M5", "target": "main", "count": 1, "scenario": scenario_installer_digest_must_match,
     "killed_by": "test_complete_fresh_refusals_and_the_reset_through_the_http_route",
     "what": "complete-fresh accepts an installer digest other than the registered revision",
     "old": '        if str(row["data_plane_code_revision"] or "").strip().lower() != "sha256:" + digest:\n',
     "new": '        if False:\n'},
    {"id": "M6", "target": "main", "count": 1, "scenario": scenario_go_live_needs_the_v3_canary,
     "killed_by": "test_each_proof_failed_or_stale_keeps_the_node_dark",
     "what": "the go-live flip ignores a failed v3 canary",
     "old": '        if status != "ok" or not _iso_after(data.get("winn3_canary_ok_at"), completed):\n',
     "new": '        if False:\n'},
    {"id": "M7", "target": "signer", "count": 1, "scenario": scenario_suspended_slug_issues_nothing,
     "killed_by": "test_step14_hold_withhold_suspend_unsuspend_and_renew_from_the_retained_floor",
     "what": "the signer issues for a suspended slug",
     "old": '            or (record is not None and record["state"] == "suspended"):\n',
     "new": '            or False:\n'},
)


# ---------------------------------------------------------------- 1 -----

def test_extracted_digests_are_pinned_and_a_one_byte_change_moves_them(tmp_path):
    text = INSTALLER.read_text(encoding="utf-8")
    measured = hl.digests(text)
    assert measured["main_sha256"] == hl.PINNED_MAIN_SHA256 == \
        "076adc8d1a00be7d088dc1cde67d43876f57d524cb02762bf0fa3170e1baeadf"
    assert measured["signer_sha256"] == hl.PINNED_SIGNER_SHA256 == \
        "fd2c6aa234b032742452da960430b0e0c5b6b84bf9cc83e4dbb33129344b6afa"
    assert measured["main_lines"] == 37199
    for target, anchor in (("main_sha256", "def winn3_auto_provision(slug: str) -> dict:"),
                           ("signer_sha256", "def verify_ticket(config, ledger, envelope, slug, actions):")):
        assert text.count(anchor) == 1
        changed = text.replace(anchor, anchor.replace("def ", "def  ", 1), 1)
        assert len(changed) == len(text) + 1
        moved = hl.digests(changed)
        assert moved[target] != measured[target], target
        copy = tmp_path / f"{target}.sh"
        copy.write_text(changed, encoding="utf-8")
        with pytest.raises(hl.HubLiteError, match="not the pinned one"):
            hl.HubLite(tmp_path / f"state-{target}", copy, init=True)
        assert not (tmp_path / f"state-{target}" / "manifest.json").exists()


def test_the_real_app_loads_with_only_the_named_replacements_and_contacts_nothing(hub):
    import fastapi
    import socket
    assert [(old, count) for old, _p, count in hl.MAIN_SOURCE_REPLACEMENTS] == [
        ('"/var/log/winsvpn"', 1), ('"/var/log/winsvpn/master.log"', 1), ('"/var/lib/wins-security-alerts"', 1)]
    assert hub.replacements_applied == [(old, 1) for old, _p, _c in hl.MAIN_SOURCE_REPLACEMENTS]
    # The real framework, not the stubs the older suites install.
    assert isinstance(hub.mod.app, fastapi.FastAPI) and hub.mod.HTTPException is fastapi.HTTPException
    assert getattr(sys.modules["fastapi"], "__file__", None)
    assert {b["name"] for b in hl.BOUNDARIES} >= {
        "node transport (ssh)", "v3 canary probe binary", "Cloudflare edge", "SMTP and alerts",
        "in-process provisioning scheduler", "signer peer credential check"}
    for name, _why in hl.MAIN_PATH_REBINDS:
        assert str(getattr(hub.mod, name)).startswith(str(hub.state)) or str(getattr(hub.mod, name)).startswith(
            str(hub.socket_path.parent))
    # No lifespan or startup event runs: a sentinel startup handler stays unset.
    fired = []
    hub.mod.app.router.on_startup.append(lambda: fired.append(1))
    assert hub.http("GET", "/admin/nodes/winn3/signer-ticket", admin=True)[0] == 200
    assert fired == []
    # Real request parsing: a body the pydantic model refuses is a 422.
    assert hub.http("POST", "/admin/nodes/winn3/signer-ticket", admin=True, json_body={"slug": "x"})[0] == 422
    assert hub.http("POST", "/admin/nodes/winn3/signer-ticket", json_body={"slug": "x", "ticket": {}})[0] == 422
    assert hub.http("GET", "/admin/nodes/winn3/signer-ticket")[0] == 422
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("192.0.2.1", 80), timeout=1)
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(PermissionError):
        hub.mod.subprocess.run(["curl", "https://192.0.2.1/"])
    # The signer is its own process, admitting only this hub-lite process.
    assert hub._signer_proc.pid != os.getpid() and hub._signer_proc.poll() is None


# ---------------------------------------------------------------- 2 -----

def test_fresh_install_goes_live_end_to_end(hub):
    slug = "sg-fresh"
    assert hub.node(slug)["management_status"] == "ok"
    minted = hub.ticket(slug, "new", go_live="auto", tier="free")
    assert minted["posted_status"] == 200 and minted["fields"]["epoch"] == 1
    done = hub.complete_fresh(slug)
    assert done["status_code"] == 200
    assert done["body"]["ok"] is True and done["body"]["operator_enabled"] is False
    assert done["body"]["auto_golive_pending"] is True
    row = hub.row(slug)
    assert row["deployment_released_at"] and row["deployment_completed_at"]
    assert row["health_closed_reason"] == "fresh_install" and row["operator_enabled"] == 0
    assert hub.triggers == [slug, slug], "registration and the release each trigger the job (recorded, not run)"

    out = hub.provision(slug)
    assert out["result"]["ok"] and out["result"]["seq"] == 0, out
    stored = events(hub, "descriptor-stored")
    assert [(e["kid"], e["seq"], e["carrier_at_store"]) for e in stored] == [("g2", 0, "winn/1")]
    stages = {e["stage"]: e for e in events(hub, "canary-stage")}
    assert stages["pre_sign"]["carrier_in_database"] == "winn/1"
    assert stages["served"]["carrier_in_database"] == "winn/1", "3.1: served-profile proof before the flip"
    assert stages["served"]["carrier_on_probed_row"] == "winn/3", "the prospective row is probed"
    issued = [e for e in events(hub, "signer-request") if e["verb"] == "sign"]
    assert [(e["ok"], e["kid"], e["expected_prior_seq"]) for e in issued] == [(True, "g2", -1)]
    status = hub.status(slug)
    assert status["protocol_version"] == "winn/3" and status["descriptor_kid"] == "g2"
    assert status["operator_enabled"] == 0, "the carrier flip never opens the latch"

    swept = hub.sweep(slug)
    assert swept["armed"] == {"paired": True, "complete": True, "budget_trusted": True, "clock_advanced_s": 0.0}
    assert swept["reopened"] == [slug], swept
    status = hub.status(slug)
    assert status["operator_enabled"] == 1 and status["free_access_enabled"] == 1
    assert status["latest_promotion_source"] == "auto_golive_fresh_install"
    assert status["latest_promotion_tier"] == "free" and status["promotion_count"] == 1
    assert status["latch_cause"] == "auto_golive_fresh_install" and status["health_closed_reason"] is None
    assert ("fresh install node went live automatically" in [a["event"] for a in hub.alerts])
    with hub.db() as conn:
        gate = conn.execute("SELECT source, used_at FROM node_offnode_gates WHERE slug=?", (slug,)).fetchone()
    assert gate["source"] == "hub" and gate["used_at"], "the hub-run off-node gate was built and consumed"
    assert scenario_flip_records_the_fresh_install_source(hub)


def test_each_proof_failed_or_stale_keeps_the_node_dark(tmp_path):
    hub = make_hub(tmp_path)
    try:
        provisioned(hub, "tls-1", stealth="tls")
        provisioned(hub, "pln-1", stealth="plain")
        assert {k for k, v in hub.mod.node_promotion_transport_plan(hub.row("tls-1")).items() if v is not None} \
            == {"udp", "stealth_tls"}
        assert {k for k, v in hub.mod.node_promotion_transport_plan(hub.row("pln-1")).items() if v is not None} \
            == {"udp", "stealth"}
        # (slug, the one spoiled proof, a reason it must name, the prefix every
        # other held reason must carry). "offnode gate: no verified ..." is the
        # absent record: the hub builds its gate only once all else passes.
        variants = [
            ("tls-1", {"canary": "stale"}, "winn/3: no per-slug v3 canary newer than the rerun", "winn/3:"),
            ("tls-1", {"canary": "fail"}, "winn/3: no per-slug v3 canary newer than the rerun", "winn/3:"),
            ("tls-1", {"carry": {"udp": "fail"}}, "udp: no carrying proof newer than", "udp:"),
            ("tls-1", {"carry": {"udp": "stale"}}, "udp: no carrying proof newer than", "udp:"),
            ("tls-1", {"carry": {"stealth_tls": "fail"}}, "stealth_tls: no carrying proof newer than", "stealth_tls:"),
            ("tls-1", {"carry": {"stealth_tls": "stale"}}, "stealth_tls: no carrying proof newer than",
             "stealth_tls:"),
            ("pln-1", {"carry": {"stealth": "fail"}}, "stealth: no carrying proof newer than", "stealth:"),
            ("pln-1", {"carry": {"stealth": "stale"}}, "stealth: no carrying proof newer than", "stealth:"),
            ("tls-1", {"offnode": "fail"}, "offnode gate: hub-run check: 1 AWG peer(s) present",
             "offnode gate: hub-run check:"),
            ("pln-1", {"offnode": "missing"}, "offnode gate: hub-run check: the node-side check is not installed",
             "offnode gate: hub-run check:"),
        ]
        absent = "offnode gate: no verified node-side gate record with this digest for this node"
        for slug, spoil, reason, prefix in variants:
            out = hub.sweep(slug, **spoil)
            held = out["held"].get(slug, [])
            assert out["reopened"] == [] and hub.status(slug)["operator_enabled"] == 0, (slug, spoil, out)
            assert any(reason in item for item in held), (slug, spoil, held)
            assert all(item.startswith(prefix) for item in held if item != absent), (slug, spoil, held)
    finally:
        hub.close()
    # A new hub process (the hub-run check's 60 s retry memory is process
    # memory) with every proof fresh: both nodes were otherwise eligible.
    again = hl.HubLite(tmp_path / "hub")
    try:
        for slug in ("tls-1", "pln-1"):
            assert again.sweep(slug)["reopened"] == [slug]
            assert again.status(slug)["operator_enabled"] == 1
        assert scenario_go_live_needs_every_carry_proof(again)
        assert scenario_go_live_needs_the_v3_canary(again)
    finally:
        again.close()


def test_shipped_default_reaches_signing_and_go_live(tmp_path):
    """HL-F1 fixed: on the shipped default (no HL-D1, HIDE_CONTROL_ORIGIN=1) the
    pre-sign publication goes over the management path, the signer issues, the
    carrier flips, and the sweep opens the node."""
    hub = hl.HubLite(tmp_path / "hub", init=True)
    try:
        assert hub.manifest["deviations"] == [] and hub.env.get("HIDE_CONTROL_ORIGIN") is None
        assert hub.mod.HIDE_CONTROL_ORIGIN is True
        released(hub, "df-1")
        out = hub.provision("df-1")
        assert out["result"]["ok"] and out["result"]["seq"] == 0, out
        # The closure-cleanup resync publishes, then the pre-sign canary does:
        # on 705bedd only the first reached the node transport.
        assert out["node_transport"][:3] == ["awg-peer-sync", "registry-publish", "identity-pull"], out
        assert out["node_transport"].count("registry-publish") == 2, out
        issued = [e for e in events(hub, "signer-request") if e["verb"] == "sign"]
        assert [(e["ok"], e["kid"]) for e in issued] == [(True, "g2")]
        assert list(hub.ledger()["slugs"]) == ["df-1"]
        assert hub.status("df-1")["protocol_version"] == "winn/3"
        swept = hub.sweep("df-1")
        assert swept["armed"] == {"paired": True, "complete": True, "budget_trusted": True, "clock_advanced_s": 0.0}
        assert swept["reopened"] == ["df-1"], swept
        status = hub.status("df-1")
        assert status["operator_enabled"] == 1 and status["latest_promotion_source"] == "auto_golive_fresh_install"
        # Every node command went to the management host (the emulator answers
        # by ssh_host or endpoint IP; the trace records the slug it matched).
        assert all(t["rc"] == 0 for t in hub.emulator.trace), hub.emulator.trace
    finally:
        hub.close()


def test_a_recovery_node_that_is_not_winn3_no_longer_delays_the_arm_hl_f2(hub):
    released(hub, "wait-1")                     # published to, never flipped
    provisioned(hub, "go-1")
    swept = hub.sweep("go-1")
    assert swept["armed"] == {"paired": True, "complete": True, "budget_trusted": True, "clock_advanced_s": 0.0}
    assert swept["reopened"] == ["go-1"], swept
    with hub.activated(), hub.mod.get_db() as conn:
        assert "wait-1" in hub.mod.winn3_recovery_hosts(conn) and "wait-1" not in hub.mod.winn3_node_hosts(conn)
        assert hub.row("wait-1")["protocol_version"] == "winn/1"


def test_a_streak_that_began_before_the_closure_no_longer_holds_the_go_live_hl_f3(hub):
    live(hub, "st-1")
    green = hub.row("st-1")["data_plane_green_streak"]
    assert green > 0
    hub.node("st-1", fresh_machine=True)
    assert (hub.row("st-1")["data_plane_green_streak"], hub.row("st-1")["data_plane_green_since"]) == (0, None)
    hub.ticket("st-1", "reset")
    assert hub.complete_fresh("st-1")["body"]["auto_golive_pending"] is True
    assert hub.provision("st-1")["result"]["ok"]
    swept = hub.sweep("st-1")                   # no unreachable run, no budget wait
    assert swept["reopened"] == ["st-1"], swept
    status = hub.status("st-1")
    assert status["operator_enabled"] == 1 and status["promotion_count"] == 2
    assert status["latest_promotion_source"] == "auto_golive_fresh_install"


# ---------------------------------------------------------------- 3 -----

def test_complete_fresh_refusals_and_the_reset_through_the_http_route(hub):
    slug = "rf-1"
    assert hub.node(slug)["ok"]
    hub.ticket(slug, "new")
    assert scenario_installer_digest_must_match(hub)
    wrong_token = hub.complete_fresh(slug, token="not-the-node-token")
    assert wrong_token["status_code"] == 401
    assert hub.complete_fresh(slug)["status_code"] == 200
    again = hub.complete_fresh(slug)
    assert again["status_code"] == 200 and again["body"]["idempotent"] is True
    other = hub.complete_fresh(slug, OTHER_DIGEST)
    assert other["status_code"] == 409

    assert scenario_reset_needs_a_reset_ticket(hub)          # rs-1 went live, then a new machine
    reset = hub.ticket("rs-1", "reset", go_live="auto", tier="premium")
    assert reset["posted_status"] == 200
    done = hub.complete_fresh("rs-1")
    assert done["status_code"] == 200 and done["body"]["auto_golive_pending"] is True, done
    assert hub.row("rs-1")["health_closed_reason"] == "fresh_install"
    out = hub.provision("rs-1")
    assert out["result"]["ok"] and out["result"]["seq"] == 1, out
    rekeyed = [e for e in events(hub, "signer-request") if e["slug"] == "rs-1" and e["ok"]
               and e["verb"] in ("sign", "rekey")]
    assert rekeyed[-1]["verb"] == "rekey" and rekeyed[-1]["expected_prior_seq"] == 0, \
        "the re-bootstrap withheld the descriptor and kept its floor"
    assert hub.sweep("rs-1")["reopened"] == ["rs-1"]
    status = hub.status("rs-1")
    assert status["operator_enabled"] == 1 and status["promotion_count"] == 2
    assert status["latest_promotion_tier"] == "premium" and status["free_access_enabled"] == 0


# ---------------------------------------------------------------- 4 -----

def test_signer_request_path_crosses_the_socket(hub):
    slug = "sk-1"
    released(hub, slug)
    ledger_file = hub.dirs["signer-state"] / "ledger.json"
    before = ledger_file.stat()
    assert hub.ledger()["slugs"] == {}
    # A crash between ticket consumption and the store: the signer issued, the
    # hub stored nothing.
    first = hub.signer_request(slug, "sign", store=False)
    assert first["ok"] and first["seq"] == 0 and first["kid"] == "g2"
    after = ledger_file.stat()
    assert (after.st_ino, after.st_mtime_ns) != (before.st_ino, before.st_mtime_ns), "the signer process wrote it"
    record = hub.ledger()["slugs"][slug]
    assert len(record["issuances"]) == 1 and len(hub.ledger()["nonces"]) == 1
    issued_payload = record["issuances"][0]["payload"]
    # The job's retry carries the same key: identical bytes, no second ticket.
    out = hub.provision(slug)
    assert out["result"]["ok"] and out["result"]["seq"] == 0
    record = hub.ledger()["slugs"][slug]
    assert len(record["issuances"]) == 1 and len(hub.ledger()["nonces"]) == 1
    stored = json.loads(hub.row(slug)["winn3_descriptor_json"])
    assert stored["payload"] == issued_payload
    # Settled: a second pass does nothing and asks the signer nothing new.
    count = len(events(hub, "signer-request"))
    assert hub.provision(slug)["result"].get("settled") is True
    assert len(events(hub, "signer-request")) == count
    # An unticketed changed identity (an installer rerun that made new gateway
    # keys): the only stored ticket is spent.
    rerun = hub.rerun(slug, new_gateway_keys=True)
    assert rerun["ok"] and rerun["deployment_generation"] == 2
    refused = hub.provision(slug)["result"]
    assert refused == {"ok": False, "slug": slug, "reason": "ticket-already-spent"}
    assert hub.status(slug)["descriptor_seq"] == 0
    assert "node signing ticket already consumed" in [a["event"] for a in hub.alerts]
    # No signer process, no issuance: the bytes really go over the socket.
    hub.ticket(slug, "rekey")
    hub.stop_signer()
    down = hub.provision(slug)["result"]
    assert down["ok"] is False and down["reason"] in ("FileNotFoundError", "ConnectionRefusedError"), down
    hub.start_signer()
    up = hub.provision(slug)["result"]
    assert up["ok"] and up["seq"] == 1, up
    assert scenario_ticket_is_single_use(hub)


# ---------------------------------------------------------------- 5 -----

def test_step14_hold_withhold_suspend_unsuspend_and_renew_from_the_retained_floor(hub):
    slug = "rb-1"
    provisioned(hub, slug)
    assert hub.status(slug)["descriptor_seq"] == 0
    refused = hub.signer_state_verb(slug, "suspend")
    assert refused == {"ok": False, "error": "generation-not-bumped-first",
                       "detail": "hold (POST /admin/nodes/winn3 enabled=false) or withhold first (STEP-14)"}
    held = hub.hold(slug)
    assert held["ok"] and held["deployment_generation"] == held["generation_before"] + 1
    assert held["winn3_operator_hold"] == 1 and held["protocol_version"] == "winn/1"
    withheld = hub.withhold(slug)
    assert withheld["ok"] and withheld["deployment_generation"] == withheld["generation_before"] + 1
    assert withheld["descriptor_stored"] is False and withheld["admission_floor"] == 0
    suspended = hub.signer_state_verb(slug, "suspend")
    assert suspended["ok"] and suspended["state"] == "suspended"
    assert hub.ledger()["slugs"][slug]["state"] == "suspended"
    renew = hub.signer_request(slug, "renew", store=False)
    assert renew["request"]["expected_prior_seq"] == 0 and renew["error"] == "slug-suspended"
    unsuspended = hub.signer_state_verb(slug, "unsuspend")
    assert unsuspended["ok"] and unsuspended["state"] == "active"
    cleared = hub.hold(slug, enabled_hold=False)
    assert cleared["ok"] and cleared["winn3_operator_hold"] == 0
    early = hub.provision(slug)["result"]
    assert early == {"ok": False, "slug": slug, "reason": "outside-renewal-window"}
    hub.advance(8 * hl.DAY)
    resumed = hub.provision(slug)["result"]
    assert resumed["ok"] and resumed["seq"] == 1, resumed
    renewals = [e for e in events(hub, "signer-request") if e["verb"] == "renew" and e["ok"]]
    assert [(e["expected_prior_seq"], e["seq"]) for e in renewals] == [(0, 1)], "presented the retained floor"
    status = hub.status(slug)
    assert status["descriptor_seq"] == 1 and status["retained_floor"] == 1 and status["protocol_version"] == "winn/3"
    assert hub.ledger()["slugs"][slug]["state"] == "active"
    assert scenario_suspended_slug_issues_nothing(hub)


# ---------------------------------------------------------------- 6 -----

def test_step13_adopted_g1_descriptor_reconciles_and_the_next_request_presents_it(hub):
    slug = "ad-1"
    assert hub.node(slug)["ok"]
    adopted = hub.adopt_g1(slug, 41, allowance=1)
    assert adopted["ok"] and adopted["stored_status"] == 200 and adopted["confirm_rc"] == 0, adopted
    assert adopted["ledger_state"] == "suspended" and adopted["ledger_live_seq"] == 41
    assert adopted["ledger_live_kid"] == "g1" and adopted["ledger_floor"] == 41 + 1_000_000
    assert adopted["ticket_epoch"] == 2 and adopted["hub_floor"] == 41
    assert hub.status(slug)["descriptor_kid"] == "g1"
    assert hub.signer_request(slug, "rekey", store=False)["error"] == "deployment-not-released"
    assert hub.complete_fresh(slug)["status_code"] == 200
    assert hub.ticket(slug, "rekey")["fields"]["epoch"] == 2, "minted under the epoch the signer reports"
    stale_epoch = hub.ticket(slug, "rekey", epoch=1)
    assert stale_epoch["posted_status"] == 200
    assert hub.signer_request(slug, "rekey", store=False)["error"] == "slug-suspended"
    assert hub.signer_state_verb(slug, "unsuspend")["state"] == "active"
    assert hub.signer_request(slug, "rekey", store=False)["error"] == "ticket-epoch-stale"
    assert hub.signer_request(slug, "renew", store=False)["ok"] is False
    hub.ticket(slug, "rekey")
    rekeyed = hub.signer_request(slug, "rekey")
    assert rekeyed["ok"], rekeyed
    assert rekeyed["request"]["expected_prior_seq"] == 41, "5.5: the hub's real builder presents the stored seq"
    assert rekeyed["seq"] > 41 + 1_000_000 and rekeyed["kid"] == "g2"
    assert rekeyed["stored_seq"] == rekeyed["seq"]
    status = hub.status(slug)
    assert status["descriptor_seq"] == rekeyed["seq"] and status["descriptor_kid"] == "g2"
    assert hub.ledger()["slugs"][slug]["presented_stored"] == 41
    nxt = hub.signer_request(slug, "renew", store=False)
    assert nxt["request"]["expected_prior_seq"] == rekeyed["seq"], "after the store the next request presents it"


# ---------------------------------------------------------------- 7 -----

@pytest.mark.parametrize("mutant", MUTANTS, ids=[m["id"] for m in MUTANTS])
def test_mutants(tmp_path, mutant):
    parts = hl.extract(INSTALLER.read_text(encoding="utf-8"))
    text = parts[mutant["target"]]
    assert text.count(mutant["old"]) == mutant["count"], f"{mutant['id']}: the pattern moved; update MUTANTS"
    mutated = text.replace(mutant["old"], mutant["new"])
    assert mutated != text
    kwargs = {"main_source": mutated} if mutant["target"] == "main" else {"signer_source": mutated}
    hub = make_hub(tmp_path, **kwargs)
    try:
        assert hub.mutated[mutant["target"]] is True
        try:
            survived = mutant["scenario"](hub)
        except AssertionError:
            survived = False
        assert survived is False, f"{mutant['id']} ({mutant['what']}) survived {mutant['scenario'].__name__}"
    finally:
        hub.close()
    # The killing test runs the same scenario on the shipped text.
    killer = globals()[mutant["killed_by"]]
    assert mutant["scenario"].__name__ in killer.__code__.co_names


# ---------------------------------------------------------------- 8 -----

def cli(*args, check=True):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run([sys.executable, "-B", str(HUB_LITE), *args], capture_output=True, text=True,
                          env=env, timeout=600, check=False)
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    out = json.loads(lines[-1]) if lines else {}
    if check:
        assert done.returncode == 0, (args, done.stdout[-2000:], done.stderr[-2000:])
    return out, done


def test_cli_continues_one_hub_across_processes_and_prints_no_secret(tmp_path):
    state = tmp_path / "cli-hub"
    runs = []
    out, done = cli("init", "--state", str(state))
    runs.append(done)
    assert out["ok"] and out["extracted"]["main_sha256"] == hl.PINNED_MAIN_SHA256
    assert out["deviations"] == [] and out["ticket_epoch"] == 1
    out, done = cli("node", "--state", str(state), "--slug", "cli-1")
    runs.append(done)
    assert out["ok"] and out["management_status"] == "ok"
    out, done = cli("ticket", "--state", str(state), "--slug", "cli-1", "--action", "new", "--go-live", "auto",
                    "--tier", "free")
    runs.append(done)
    assert out["ok"] and out["posted_status"] == 200
    out, done = cli("complete-fresh", "--state", str(state), "--slug", "cli-1")
    runs.append(done)
    assert out["ok"] and out["body"]["auto_golive_pending"] is True
    out, done = cli("provision", "--state", str(state), "--slug", "cli-1")
    runs.append(done)
    assert out["ok"] and out["status"]["protocol_version"] == "winn/3"
    out, done = cli("sweep", "--state", str(state), "--slug", "cli-1")
    runs.append(done)
    assert out["reopened"] == ["cli-1"]
    out, done = cli("status", "--state", str(state), "--slug", "cli-1")
    runs.append(done)
    assert out["operator_enabled"] == 1 and out["latest_promotion_source"] == "auto_golive_fresh_install"
    assert set(out) >= {"operator_enabled", "protocol_version", "deployment_generation", "deployment_released_at",
                        "deployment_completed_at", "health_closed_reason", "winn3_operator_hold",
                        "descriptor_seq", "descriptor_kid", "latest_promotion_source"}
    refused, done = cli("serve", "--state", str(state), "--listen", "0.0.0.0:18080", check=False)
    runs.append(done)
    assert done.returncode == 1 and refused["ok"] is False and "non-loopback" in refused["error"]
    forbidden = Path(os.path.expanduser("~/.ssh")) / "hublite-must-not-exist"
    refused, done = cli("init", "--state", str(forbidden), check=False)
    runs.append(done)
    assert done.returncode == 1 and refused["ok"] is False and not forbidden.exists()

    # Modes, then: no output carries a token, a secret or key material.
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    for path in [state / "admin_token", state / "secrets.json", state / "nodes" / "cli-1" / "node_token",
                 state / "nodes" / "cli-1" / "pulled.json", state / "nodes" / "cli-1" / "host_ed25519",
                 *sorted((state / "keys").glob("*.pem"))]:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
    secrets_seen = [(state / "admin_token").read_text().strip(),
                    (state / "nodes" / "cli-1" / "node_token").read_text().strip(),
                    json.loads((state / "nodes" / "cli-1" / "pulled.json").read_text())["admission_secret"]]
    secrets_seen += list(json.loads((state / "secrets.json").read_text()).values())
    for pem in list((state / "keys").glob("*.pem")) + [state / "nodes" / "cli-1" / "host_ed25519"]:
        secrets_seen += [line for line in pem.read_text().splitlines() if line and not line.startswith("-----")]
    assert all(len(value) >= 16 for value in secrets_seen)
    for done in runs:
        for stream in (done.stdout, done.stderr):
            for value in secrets_seen:
                assert value not in stream, "a secret value reached CLI output"
