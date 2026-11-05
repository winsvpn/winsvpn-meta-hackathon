#!/usr/bin/env python3
"""Offline hub tests for winn/3 registration and protocol selection.

Covers mixed v3/v1 candidates, malicious Smart Router picks, malformed
protocol_params_json, missing carrier, no healthy v3, stale v1
authorization, and the reproduced P1 bypasses: explicit node requests,
existing allocations, and free-tier selection skipping generation-bound
winn/3 primacy. No network.
"""
from __future__ import annotations
from contextlib import closing

import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import json
import os
import sqlite3
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import HTTPException  # noqa: E402
import test_hub_hand_patch_reconciliation as nodes  # noqa: E402
import test_smart_router_hub_selection as router  # noqa: E402
import test_winn3_serving_hub as serving  # noqa: E402


FAILURES = []
PASSED = [0]
GENERATION = "generation-01"
STALE_GENERATION = "generation-99"


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def db(mod):
    conn = sqlite3.connect(mod._DB)
    conn.row_factory = sqlite3.Row
    return conn


def seed_route(mod, slug, octet, **columns):
    letter = chr(65 + (int(octet) % 26))
    nodes.seed_node(
        mod,
        slug=slug,
        endpoint=f"198.51.100.{octet}:9110",
        ssh_host=f"198.51.100.{octet}",
        public_key=(letter * 43) + "=",
        **columns,
    )


def seed_v3(mod, slug, octet, **columns):
    columns.setdefault("protocol_version", "winn/3")
    columns.setdefault("protocol_params_json", json.dumps({"carrier": "winn3"}))
    seed_route(mod, slug, octet, **columns)


def seed_v1(mod, slug, octet, **columns):
    columns.setdefault("protocol_version", "winn/1")
    seed_route(mod, slug, octet, **columns)


def mark_fresh_ok(mod, slug):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE nodes SET data_plane_status=?, data_plane_ok_at=? WHERE slug=?",
            ("ok", nodes.minutes_ago(mod, 1), slug),
        )


def mark_unreachable(mod, slug):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE nodes SET data_plane_status=?, data_plane_ok_at=? WHERE slug=?",
            ("unreachable", nodes.minutes_ago(mod, 1), slug),
        )


def selected_slug(mod, **kwargs):
    with db(mod) as conn:
        row = mod.select_online_node(conn, "auto", **kwargs)
    return row["slug"] if row else None


def test_malformed_params_never_become_empty():
    mod = harness.load_hub()
    try:
        out = mod.parse_protocol_params("{")
    except mod.Winn3ContractError as exc:
        assert exc.reason == "protocol-params-malformed"
    else:
        raise AssertionError(f"malformed JSON became {out!r}")
    try:
        out = mod.parse_protocol_params("[1]")
    except mod.Winn3ContractError as exc:
        assert exc.reason == "protocol-params-not-an-object"
    else:
        raise AssertionError(f"non-object JSON became {out!r}")
    assert mod.parse_protocol_params(None) == {}
    assert mod.parse_protocol_params("  ") == {}


def test_malformed_stored_winn3_fails_closed_and_is_unlisted():
    mod = harness.load_hub()
    seed_v1(mod, "listed-v1", 11)
    seed_route(
        mod,
        "bad-json",
        12,
        protocol_version="winn/3",
        protocol_params_json="{",
    )
    row = nodes.node_row(mod, "bad-json")
    serving.expect_refused(
        mod, row, "params-invalid", capabilities=serving.caps(supports_winn3=True)
    )
    assert mod.node_protocol_route_metadata(row) is None
    listed = nodes.listing(mod)
    assert "bad-json" not in listed
    assert listed["listed-v1"]["protocol_version"] == "winn/1"
    assert listed["listed-v1"]["carrier"] == "amneziawg"
    assert listed["listed-v1"]["v1_engine_order"] == ["amneziawg", "xray"]


def test_missing_carrier_is_omitted_from_listing_and_smart_router():
    mod = router.load_router_hub()
    seed_v1(mod, "ok-v1", 21)
    seed_route(
        mod,
        "empty-carrier",
        22,
        protocol_version="winn/3",
        protocol_params_json="{}",
    )
    listed = nodes.listing(mod)
    assert "empty-carrier" not in listed
    captured = {}

    def open_request(request, timeout):
        captured.update(json.loads(request.data))
        return router.FakeResponse(
            b'{"selected_route_id":"ok-v1","decision":"switch",'
            b'"confidence":0.9,"reason_codes":["deterministic_fallback"],'
            b'"source":"fallback"}'
        )

    mod._smart_router_open = open_request
    mark_fresh_ok(mod, "ok-v1")
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn) == "ok-v1"
    slugs = {item["route_id"] for item in captured["candidates"]}
    assert slugs == {"ok-v1"}
    for item in captured["candidates"]:
        assert item["protocol_version"] == "winn/1"
        assert item["carrier"] == "amneziawg"
        assert item["v1_engine_order"] == ["amneziawg", "xray"]


def test_production_registration_requires_standalone_winn3():
    mod = harness.load_hub()
    serving.seed_node(mod, slug="lab-alpha")
    try:
        serving.admin_winn3(mod, slug="lab-alpha", enabled=True)
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "standalone carrier winn3" in str(exc.detail)
    else:
        raise AssertionError("empty production POST must be refused")
    assert serving.node_row(mod)["protocol_version"] == "winn/1"
    try:
        serving.admin_winn3(
            mod,
            slug="lab-alpha",
            enabled=True,
            protocol_params_json=json.dumps({"carrier": "direct-awg"}),
        )
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "carrier-not-standalone-winn3" in str(exc.detail)
    else:
        raise AssertionError("relay carrier must be refused")
    out = serving.admin_winn3(
        mod, slug="lab-alpha", enabled=True, **serving.STANDALONE_ADMIN
    )
    assert out["carrier"] == "winn3"


def test_mixed_healthy_v3_wins_initial_selection():
    mod = router.load_router_hub()
    seed_v1(mod, "v1-node", 31)
    seed_v3(mod, "v3-node", 32)
    mark_fresh_ok(mod, "v1-node")
    mark_fresh_ok(mod, "v3-node")
    assert selected_slug(mod) == "v3-node"
    captured = {}

    def open_request(request, timeout):
        captured.update(json.loads(request.data))
        return router.FakeResponse(
            b'{"selected_route_id":"v3-node","decision":"switch",'
            b'"confidence":0.9,"reason_codes":["healthier_route"],'
            b'"source":"fallback"}'
        )

    mod._smart_router_open = open_request
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn) == "v3-node"
    by_id = {item["route_id"]: item for item in captured["candidates"]}
    assert by_id["v3-node"]["protocol_version"] == "winn/3"
    assert by_id["v3-node"]["carrier"] == "winn3"
    assert by_id["v1-node"]["protocol_version"] == "winn/1"
    assert by_id["v1-node"]["carrier"] == "amneziawg"
    assert by_id["v1-node"]["v1_engine_order"] == ["amneziawg", "xray"]
    assert set(captured) == {"request_id", "current_route_id", "candidates", "trigger"}


def test_malicious_router_v1_is_rejected_when_healthy_v3_exists():
    mod = router.load_router_hub()
    seed_v1(mod, "v1-node", 41)
    seed_v3(mod, "v3-node", 42)
    mark_fresh_ok(mod, "v1-node")
    mark_fresh_ok(mod, "v3-node")
    mod._smart_router_open = lambda request, timeout: router.FakeResponse(
        b'{"selected_route_id":"v1-node","decision":"switch",'
        b'"confidence":0.9,"reason_codes":["healthier_route"],'
        b'"source":"local_gemma"}'
    )
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn) == ""
        picked = mod.select_online_node(conn, "auto", preferred_slug="v1-node")
    assert picked["slug"] == "v3-node"


def test_no_healthy_v3_does_not_select_v1_without_authorization():
    mod = router.load_router_hub()
    seed_v1(mod, "v1-node", 51)
    seed_v3(mod, "v3-node", 52)
    mark_fresh_ok(mod, "v1-node")
    mark_unreachable(mod, "v3-node")
    assert selected_slug(mod) is None
    captured = {}

    def open_request(request, timeout):
        captured.update(json.loads(request.data))
        return router.FakeResponse(
            b'{"selected_route_id":"v1-node","decision":"switch",'
            b'"confidence":0.9,"reason_codes":["healthier_route"],'
            b'"source":"local_gemma"}'
        )

    mod._smart_router_open = open_request
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(conn) == ""
    by_id = {item["route_id"]: item for item in captured["candidates"]}
    assert by_id["v3-node"]["reachable"] is False
    assert by_id["v3-node"]["protocol_version"] == "winn/3"


def test_stale_fallback_authorization_does_not_unlock_v1():
    mod = harness.load_hub()
    seed_v1(mod, "v1-node", 61)
    seed_v3(mod, "v3-node", 62)
    mark_fresh_ok(mod, "v1-node")
    mark_unreachable(mod, "v3-node")
    assert selected_slug(
        mod,
        selection_generation=GENERATION,
        ordinary_v3_failure_generation=STALE_GENERATION,
    ) is None


def test_matching_generation_allows_v1_after_ordinary_v3_failure():
    mod = router.load_router_hub()
    seed_v1(mod, "v1-node", 71)
    seed_v3(mod, "v3-node", 72)
    mark_fresh_ok(mod, "v1-node")
    mark_unreachable(mod, "v3-node")
    assert selected_slug(
        mod,
        selection_generation=GENERATION,
        ordinary_v3_failure_generation=GENERATION,
    ) == "v1-node"
    captured = {}

    def open_request(request, timeout):
        captured.update(json.loads(request.data))
        return router.FakeResponse(
            b'{"selected_route_id":"v1-node","decision":"switch",'
            b'"confidence":0.9,"reason_codes":["deterministic_fallback"],'
            b'"source":"fallback"}'
        )

    mod._smart_router_open = open_request
    with db(mod) as conn:
        assert mod.smart_router_recommend_node(
            conn,
            selection_generation=GENERATION,
            ordinary_v3_failure_generation=GENERATION,
        ) == "v1-node"
    assert captured["selection_generation"] == GENERATION
    assert captured["ordinary_v3_failure_generation"] == GENERATION


def mixed_fleet(mod):
    seed_v1(mod, "v1-node", 81)
    seed_v3(mod, "v3-node", 82)
    mark_fresh_ok(mod, "v1-node")
    mark_fresh_ok(mod, "v3-node")


def mixed_unhealthy_v3(mod):
    seed_v1(mod, "v1-node", 91)
    seed_v3(mod, "v3-node", 92)
    mark_fresh_ok(mod, "v1-node")
    mark_unreachable(mod, "v3-node")


def test_explicit_v1_request_does_not_bypass_healthy_v3():
    mod = harness.load_hub()
    mixed_fleet(mod)
    with db(mod) as conn:
        picked = mod.select_online_node(conn, "v1-node", require_selected=True)
    assert picked is None
    with db(mod) as conn:
        picked = mod.select_online_node(conn, "v3-node", require_selected=True)
    assert picked["slug"] == "v3-node"
    assert picked["protocol_version"] == "winn/3"


def test_explicit_unclassified_v3_remains_selectable():
    mod = harness.load_hub()
    seed_route(
        mod,
        "legacy-v3",
        88,
        protocol_version="winn/3",
        protocol_params_json=json.dumps({"max_datagram": "1280"}),
    )
    mark_fresh_ok(mod, "legacy-v3")
    with db(mod) as conn:
        picked = mod.select_online_node(conn, "legacy-v3", require_selected=True)
        auto = mod.select_online_node(conn, "auto")
    assert picked["slug"] == "legacy-v3"
    assert auto is None


def test_existing_v1_allocation_does_not_bypass_healthy_v3():
    mod = harness.load_hub()
    mixed_fleet(mod)
    with db(mod) as conn:
        picked = mod.select_online_node(
            conn, "auto", existing_slug="v1-node", preferred_slug="v1-node"
        )
    assert picked["slug"] == "v3-node"


def test_free_tier_auto_and_explicit_do_not_bypass_healthy_v3():
    mod = harness.load_hub()
    mixed_fleet(mod)
    with db(mod) as conn:
        assert mod.select_free_node(conn, "auto")["slug"] == "v3-node"
        assert mod.select_free_node(conn, "v1-node") is None
        assert mod.select_free_node(
            conn, "auto", existing_slug="v1-node"
        )["slug"] == "v3-node"
        assert mod.select_free_node(
            conn, "auto", preferred_slug="v1-node"
        )["slug"] == "v3-node"


def test_free_tier_v1_is_not_blocked_by_a_paid_healthy_v3():
    mod = harness.load_hub()
    seed_v1(mod, "free-v1", 101, free_access=1)
    seed_v3(mod, "paid-v3", 102, free_access=0)
    mark_fresh_ok(mod, "free-v1")
    mark_fresh_ok(mod, "paid-v3")
    with db(mod) as conn:
        free = mod.select_free_node(conn, "auto")
        paid = mod.select_online_node(conn, "auto")
    assert free["slug"] == "free-v1"
    assert paid["slug"] == "paid-v3"


def test_explicit_and_existing_v1_need_matching_generation_when_v3_is_unhealthy():
    mod = harness.load_hub()
    mixed_unhealthy_v3(mod)
    with db(mod) as conn:
        assert mod.select_online_node(conn, "v1-node", require_selected=True) is None
        assert mod.select_online_node(conn, "auto", existing_slug="v1-node") is None
        assert mod.select_free_node(conn, "v1-node") is None
        assert (
            mod.select_online_node(
                conn,
                "v1-node",
                require_selected=True,
                selection_generation=GENERATION,
                ordinary_v3_failure_generation=STALE_GENERATION,
            )
            is None
        )
        assert (
            mod.select_online_node(
                conn,
                "v1-node",
                require_selected=True,
                selection_generation=GENERATION,
                ordinary_v3_failure_generation=GENERATION,
            )["slug"]
            == "v1-node"
        )
        assert (
            mod.select_online_node(
                conn,
                "auto",
                existing_slug="v1-node",
                selection_generation=GENERATION,
                ordinary_v3_failure_generation=GENERATION,
            )["slug"]
            == "v1-node"
        )
        assert (
            mod.select_free_node(
                conn,
                "v1-node",
                selection_generation=GENERATION,
                ordinary_v3_failure_generation=GENERATION,
            )["slug"]
            == "v1-node"
        )


def test_malformed_generation_never_authorizes_v1():
    mod = harness.load_hub()
    mixed_unhealthy_v3(mod)
    for bad in ("short", "generation 01", "gen/01", 12345, ["generation-01"]):
        assert mod.v1_ordinary_failure_authorized(bad, bad) is False
        with db(mod) as conn:
            assert (
                mod.select_online_node(
                    conn,
                    "v1-node",
                    require_selected=True,
                    selection_generation=bad,
                    ordinary_v3_failure_generation=bad,
                )
                is None
            )


def test_typed_selection_generation_accepts_request_id_and_rejects_the_rest():
    mod = harness.load_hub()
    assert mod.typed_selection_generation(None) == ""
    assert mod.typed_selection_generation("") == ""
    assert mod.typed_selection_generation("generation-01") == GENERATION
    for bad in ("short", "generation 01", "gen/01", "x" * 65, " generation-01"):
        try:
            mod.typed_selection_generation(bad)
        except ValueError:
            continue
        raise AssertionError("accepted %r" % (bad,))


def test_request_models_declare_exact_typed_generation_fields():
    src = harness._extract_main_block()
    pattern = r"^(?:[A-Za-z0-9][A-Za-z0-9._:-]{7,63})?$"
    for model in ("class LoginRequest", "class FreeAccessRequest"):
        start = src.index(model)
        block = src[start : src.index("\nclass ", start + 1)]
        for field, alias in (
            ("selection_generation", "selectiongeneration"),
            ("ordinary_v3_failure_generation", "ordinaryv3failuregeneration"),
        ):
            idx = block.index(field + ":")
            chunk = block[idx : idx + 500]
            assert "max_length=64" in chunk, (model, field, chunk)
            assert pattern in chunk, (model, field)
            assert '"%s"' % field in chunk
            assert '"%s"' % alias in chunk
    assert "selection_generation=selection_generation," in src
    assert "ordinary_v3_failure_generation=ordinary_v3_failure_generation," in src
    assert "selection_generation=free_request.selection_generation" in src or (
        "selection_generation=selection_generation," in src
        and "typed_selection_generations(free_request)" in src
    )
    assert "descriptor-node-mismatch" in src
    assert 'WINN_V1_ENGINE_ORDER = ("amneziawg", "xray")' in src


def test_paid_activation_refuses_explicit_v1_while_healthy_v3_exists():
    mod = harness.load_hub()
    harness.seed_account(mod, devices=0)
    serving.arm_activation(mod)
    mixed_fleet(mod)
    serving.expect_http(
        503, lambda: serving.served_config(mod, location="v1-node")
    )
    serving.expect_http(
        400,
        lambda: serving.served_config(
            mod, location="auto", selection_generation="bad"
        ),
    )


def test_paid_and_free_activation_forward_typed_generations():
    mod = harness.load_hub()
    harness.seed_account(mod, devices=0)
    serving.arm_activation(mod)
    mixed_unhealthy_v3(mod)
    select_kw = []
    smart_kw = []
    orig_select = mod.select_online_node
    orig_free = mod.select_free_node
    orig_smart = mod.smart_router_recommend_node

    def wrap_select(*args, **kwargs):
        select_kw.append(dict(kwargs))
        return orig_select(*args, **kwargs)

    def wrap_free(*args, **kwargs):
        select_kw.append(dict(kwargs))
        return orig_free(*args, **kwargs)

    def wrap_smart(*args, **kwargs):
        smart_kw.append(dict(kwargs))
        return orig_smart(*args, **kwargs)

    mod.select_online_node = wrap_select
    mod.select_free_node = wrap_free
    mod.smart_router_recommend_node = wrap_smart
    try:
        serving.served_config(
            mod,
            location="auto",
            selection_generation=GENERATION,
            ordinary_v3_failure_generation=GENERATION,
        )
    except HTTPException:
        pass
    paid_select = [item for item in select_kw if item.get("free_only") is not True]
    assert paid_select, select_kw
    assert paid_select[0]["selection_generation"] == GENERATION
    assert paid_select[0]["ordinary_v3_failure_generation"] == GENERATION
    assert smart_kw
    assert smart_kw[0]["selection_generation"] == GENERATION
    assert smart_kw[0]["ordinary_v3_failure_generation"] == GENERATION

    select_kw.clear()
    smart_kw.clear()
    login = mod.LoginRequest(
        account_number="1111-2222-3333",
        device_id="device-abcdef0123456789",
        client_public_key="C" * 43 + "=",
        location="auto",
        selection_generation=GENERATION,
        ordinary_v3_failure_generation=GENERATION,
        free_access=True,
    )
    assert mod.typed_selection_generations(login) == (GENERATION, GENERATION)
    free = mod.FreeAccessRequest(
        device_id="device-abcdef0123456789",
        client_public_key="C" * 43 + "=",
        location="auto",
        selection_generation=GENERATION,
        ordinary_v3_failure_generation=GENERATION,
    )
    assert mod.typed_selection_generations(free) == (GENERATION, GENERATION)
    src = harness._extract_main_block()
    verify_free = src[src.index("async def verify_free_access") : src.index("def perform_authenticated_device_logout")]
    assert "typed_selection_generations(free_request)" in verify_free
    assert "selection_generation=selection_generation," in verify_free
    assert "ordinary_v3_failure_generation=ordinary_v3_failure_generation," in verify_free
    assert "selection_generation=selection_generation," in verify_free
    login_build = verify_free[verify_free.index("login = LoginRequest") :]
    assert "selection_generation=selection_generation," in login_build
    assert "ordinary_v3_failure_generation=ordinary_v3_failure_generation," in login_build


UNIT_TESTS = [
    test_malformed_params_never_become_empty,
    test_malformed_stored_winn3_fails_closed_and_is_unlisted,
    test_missing_carrier_is_omitted_from_listing_and_smart_router,
    test_production_registration_requires_standalone_winn3,
    test_mixed_healthy_v3_wins_initial_selection,
    test_malicious_router_v1_is_rejected_when_healthy_v3_exists,
    test_no_healthy_v3_does_not_select_v1_without_authorization,
    test_stale_fallback_authorization_does_not_unlock_v1,
    test_matching_generation_allows_v1_after_ordinary_v3_failure,
    test_explicit_v1_request_does_not_bypass_healthy_v3,
    test_explicit_unclassified_v3_remains_selectable,
    test_existing_v1_allocation_does_not_bypass_healthy_v3,
    test_free_tier_auto_and_explicit_do_not_bypass_healthy_v3,
    test_free_tier_v1_is_not_blocked_by_a_paid_healthy_v3,
    test_explicit_and_existing_v1_need_matching_generation_when_v3_is_unhealthy,
    test_malformed_generation_never_authorizes_v1,
    test_typed_selection_generation_accepts_request_id_and_rejects_the_rest,
    test_request_models_declare_exact_typed_generation_fields,
    test_paid_activation_refuses_explicit_v1_while_healthy_v3_exists,
    test_paid_and_free_activation_forward_typed_generations,
]


def main() -> int:
    asyncio.set_event_loop(asyncio.new_event_loop())
    print("hub protocol selection")
    for fn in UNIT_TESTS:
        check(fn.__name__, fn)
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, tb in FAILURES:
        print()
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
