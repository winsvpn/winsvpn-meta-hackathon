#!/usr/bin/env python3
"""Offline contract tests for hub-to-aicore Smart Router selection."""
import hashlib
import hmac
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
import test_hub_hand_patch_reconciliation as nodes  # noqa: E402


ROUTER_URL = "https://router.example.test/route"
ROUTER_SECRET = "smart-router-test-secret-0123456789abcdef"


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, limit):
        assert limit >= len(self.payload)
        return self.payload


def load_router_hub():
    return harness.load_hub(
        SMART_ROUTER_URL=ROUTER_URL,
        SMART_ROUTER_HMAC_SECRET=ROUTER_SECRET,
        SMART_ROUTER_TIMEOUT_SECONDS="0.25",
    )


def seed_pair(mod):
    nodes.seed_node(mod, slug="route-a", peer_count=400, max_peers=500)
    nodes.seed_node(mod, slug="route-b", peer_count=20, max_peers=500)


def db(mod):
    conn = sqlite3.connect(mod._DB)
    conn.row_factory = sqlite3.Row
    return conn


def test_signed_payload_is_closed_set_and_contains_no_node_secrets():
    mod = load_router_hub()
    seed_pair(mod)
    captured = {}

    def open_request(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(json.dumps({
            "selected_route_id": "route-b",
            "decision": "switch",
            "confidence": 0.9,
            "reason_codes": ["lower_load"],
            "source": "local_gemma",
        }).encode())

    mod._smart_router_open = open_request
    with db(mod) as conn:
        selected = mod.smart_router_recommend_node(conn, existing_slug="route-a")
    assert selected == "route-b"
    request = captured["request"]
    assert request.full_url == ROUTER_URL
    assert captured["timeout"] == 0.25
    payload = json.loads(request.data)
    assert set(payload) == {"request_id", "current_route_id", "candidates", "trigger"}
    assert payload["current_route_id"] == "route-a"
    assert {item["route_id"] for item in payload["candidates"]} == {"route-a", "route-b"}
    for item in payload["candidates"]:
        assert item["protocol_version"] == "winn/1"
        assert item["carrier"] == "amneziawg"
        assert item["v1_engine_order"] == ["amneziawg", "xray"]
    serialized = request.data.decode()
    for forbidden in ("endpoint", "public_key", "private_key", "account_number", "device_id"):
        assert forbidden not in serialized

    headers = {key.lower(): value for key, value in request.header_items()}
    timestamp = headers["x-smart-router-timestamp"]
    nonce = headers["x-smart-router-nonce"]
    body_hash = hashlib.sha256(request.data).hexdigest()
    message = f"POST\n/route\n{timestamp}\n{nonce}\n{body_hash}".encode("ascii")
    expected = hmac.new(ROUTER_SECRET.encode(), message, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(headers["x-smart-router-signature"], expected)


def test_candidate_payload_marks_only_fresh_probe_success_as_reachable():
    mod = load_router_hub()
    fresh = nodes.minutes_ago(mod, 1)
    nodes.seed_node(
        mod,
        slug="proven-route",
        data_plane_status="ok",
        data_plane_ok_at=fresh,
        data_plane_fail_streak=0,
    )
    nodes.seed_node(
        mod,
        slug="unknown-route",
        data_plane_status="unknown",
        data_plane_ok_at=None,
        data_plane_fail_streak=0,
    )
    nodes.seed_node(
        mod,
        slug="degraded-route",
        data_plane_status="degraded",
        data_plane_ok_at=fresh,
        data_plane_fail_streak=2,
    )
    captured = {}

    def open_request(request, timeout):
        captured.update(json.loads(request.data))
        return FakeResponse(
            b'{"selected_route_id":"proven-route","decision":"switch",'
            b'"confidence":0.9,"reason_codes":["healthier_route"],'
            b'"source":"local_gemma"}'
        )

    mod._smart_router_open = open_request
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn, trigger="distress") == "proven-route"

    candidates = {item["route_id"]: item for item in captured["candidates"]}
    assert candidates["proven-route"]["reachable"] is True
    assert candidates["unknown-route"]["reachable"] is False
    assert candidates["degraded-route"]["reachable"] is False
    assert candidates["degraded-route"]["recent_failures"] == 2
    for candidate in candidates.values():
        assert candidate["handshake_ms"] is None
        assert candidate["packet_loss_pct"] is None
        assert candidate["jitter_ms"] is None
        assert candidate["dns_ok"] is None
        assert candidate["protocol_version"] == "winn/1"
        assert candidate["carrier"] == "amneziawg"
        assert candidate["v1_engine_order"] == ["amneziawg", "xray"]


def test_out_of_set_response_falls_back_without_using_the_slug():
    mod = load_router_hub()
    seed_pair(mod)
    mod._smart_router_open = lambda request, timeout: FakeResponse(
        b'{"selected_route_id":"invented-route","decision":"switch",'
        b'"confidence":0.9,"reason_codes":["invented_route"],'
        b'"source":"local_gemma"}'
    )
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn) == ""
        selected = mod.select_online_node(conn, "auto")
    assert selected["slug"] == "route-b"


def test_incomplete_or_duplicate_response_schema_falls_back_closed():
    mod = load_router_hub()
    seed_pair(mod)
    responses = (
        b'{"selected_route_id":"route-b","source":"local_gemma"}',
        b'{"selected_route_id":"route-a","selected_route_id":"route-b",'
        b'"decision":"switch","confidence":0.9,'
        b'"reason_codes":["healthier_route"],"source":"local_gemma"}',
    )
    with db(mod) as conn:
        for raw in responses:
            mod._smart_router_open = lambda request, timeout, raw=raw: FakeResponse(raw)
            assert mod.smart_router_recommend_node(conn) == ""


def test_preferred_advisory_is_revalidated_for_health_and_capacity():
    mod = load_router_hub()
    seed_pair(mod)
    with db(mod) as conn:
        preferred = mod.select_online_node(conn, "auto", preferred_slug="route-a")
        assert preferred["slug"] == "route-a"
        conn.execute("UPDATE nodes SET data_plane_status='unreachable' WHERE slug='route-a'")
        fallback = mod.select_online_node(conn, "auto", preferred_slug="route-a")
        assert fallback["slug"] == "route-b"


def test_healthy_existing_allocation_wins_over_ai_advisory():
    mod = load_router_hub()
    seed_pair(mod)
    with db(mod) as conn:
        selected = mod.select_online_node(
            conn,
            "auto",
            existing_slug="route-a",
            preferred_slug="route-b",
        )
    assert selected["slug"] == "route-a"


def test_machine_health_derives_initiation_or_distress_without_request_prose():
    mod = load_router_hub()
    seed_pair(mod)
    with db(mod) as conn:
        assert mod.smart_router_trigger_for_existing_node(conn, "") == "connection_initiation"
        assert mod.smart_router_trigger_for_existing_node(conn, "route-a") == "connection_initiation"
        conn.execute(
            "UPDATE nodes SET data_plane_status='degraded', data_plane_fail_streak=1 WHERE slug='route-a'"
        )
        assert mod.smart_router_trigger_for_existing_node(conn, "route-a") == "distress"


def test_distress_preferred_advisory_beats_healthy_but_distressed_existing():
    mod = load_router_hub()
    seed_pair(mod)
    with db(mod) as conn:
        conn.execute(
            "UPDATE nodes SET data_plane_status='degraded', data_plane_fail_streak=1 WHERE slug='route-a'"
        )
        assert mod.node_is_online_and_managed(
            conn.execute("SELECT * FROM nodes WHERE slug='route-a'").fetchone()
        )
        selected = mod.select_online_node(
            conn,
            "auto",
            existing_slug="route-a",
            preferred_slug="route-b",
            advisory_is_distress=True,
        )
    assert selected["slug"] == "route-b"


def test_distress_trigger_is_signed_into_the_closed_payload():
    mod = load_router_hub()
    seed_pair(mod)
    captured = {}

    def open_request(request, timeout):
        captured.update(json.loads(request.data))
        return FakeResponse(
            b'{"selected_route_id":"route-b","decision":"switch",'
            b'"confidence":0.9,"reason_codes":["healthier_route"],'
            b'"source":"local_gemma"}'
        )

    mod._smart_router_open = open_request
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn, trigger="distress") == "route-b"
    assert captured["trigger"] == "distress"


def test_explicit_selection_wins_and_never_needs_an_advisory():
    mod = load_router_hub()
    seed_pair(mod)
    with db(mod) as conn:
        selected = mod.select_online_node(
            conn,
            "route-a",
            require_selected=True,
            preferred_slug="route-b",
        )
    assert selected["slug"] == "route-a"


def test_free_recommendation_only_exposes_free_candidates():
    mod = load_router_hub()
    nodes.seed_node(mod, slug="free-route", free_access=1)
    nodes.seed_node(mod, slug="paid-route", free_access=0)
    captured = {}

    def open_request(request, timeout):
        captured.update(json.loads(request.data))
        return FakeResponse(
            b'{"selected_route_id":"free-route","decision":"switch",'
            b'"confidence":0.8,"reason_codes":["deterministic_fallback"],'
            b'"source":"fallback"}'
        )

    mod._smart_router_open = open_request
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn, free_only=True) == "free-route"
    assert [candidate["route_id"] for candidate in captured["candidates"]] == ["free-route"]


def test_redirect_handler_refuses_every_redirect():
    mod = load_router_hub()
    handler = mod._SmartRouterNoRedirect()
    assert handler.redirect_request(None, None, 302, "moved", {}, "https://other.test/") is None


def test_missing_or_partial_configuration_fails_to_deterministic():
    mod = harness.load_hub(SMART_ROUTER_URL="", SMART_ROUTER_HMAC_SECRET="")
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn) == ""
    mod = harness.load_hub(SMART_ROUTER_URL=ROUTER_URL, SMART_ROUTER_HMAC_SECRET="short")
    nodes.seed_node(mod, slug="route-a")
    mod._smart_router_open = lambda request, timeout: (_ for _ in ()).throw(
        AssertionError("network must not be called with incomplete authentication")
    )
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn) == ""


def test_current_allocation_remains_candidate_at_capacity():
    mod = load_router_hub()
    nodes.seed_node(mod, slug="route-a", peer_count=500, max_peers=500)
    captured = {}

    def open_request(request, timeout):
        captured.update(json.loads(request.data))
        return FakeResponse(
            b'{"selected_route_id":"route-a","decision":"keep",'
            b'"confidence":0.9,"reason_codes":["current_route_healthy"],'
            b'"source":"local_gemma"}'
        )

    mod._smart_router_open = open_request
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn, existing_slug="route-a") == "route-a"
    assert captured["candidates"][0]["route_id"] == "route-a"
    assert captured["candidates"][0]["load_ratio"] > 0.9


def test_at_capacity_reconnect_remains_valid_when_distress_advisory_keeps_current():
    mod = load_router_hub()
    nodes.seed_node(
        mod,
        slug="route-a",
        peer_count=500,
        max_peers=500,
        data_plane_status="degraded",
        data_plane_fail_streak=1,
    )
    with db(mod) as conn:
        selected = mod.select_online_node(
            conn,
            "auto",
            existing_slug="route-a",
            preferred_slug="route-a",
            advisory_is_distress=True,
        )
    assert selected["slug"] == "route-a"
import _toolchain  # noqa: F401  (V-01 preflight)
