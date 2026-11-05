#!/usr/bin/env python3
"""Hub tests for the standalone winn/3 PLAN: `path_mtu` and `carrier_classes`.

Until 2026-08-10 these two fields had ZERO occurrences in the control-plane
source, while every other host in the fleet planned at carrier.DefaultPathMTU.
The standalone client reads them per-device off vpn_config
(winn_protocol_dispatch.dart:2173-2175 and _winn3StandaloneStart) and hands
them to driver.NewSizing, which REFUSES a plan in the inner-IPv6 dead zone
(winn3/driver/params.go:142-231). So the control plane had two failure modes it
could not see:

  * it could serve a node whose plan the client refuses -- a disconnected
    client with no fallback, which is the anti-downgrade rule this whole
    surface exists to protect, and
  * it could serve a node with NO plan, which the engine silently substitutes
    with {"udp"} -- the empty-plan-handling divergence that makes a gateway's
    wider floor black-hole every full-size flow after a migration.

This suite is the proof that a v3-capable standalone client receives a USABLE
config while a v1 client is byte-for-byte unaffected.

Run:  python3 server/test_winn3_pathmtu_hub.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import base64
from datetime import timedelta
import json
import os
import re
import sqlite3
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402
import test_winn3_descriptor_hub as ddesc  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTOCOL_DIR = os.path.join(REPO_ROOT, "winn_protocol_experimental")
HUB = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "wins_control_plane_setup_ONETOUCH.sh",
)
# Development override only: point this at a private main.py copy while
# iterating. The shipped default reads the REAL installer heredoc, exactly as
# the sibling suites do, so a regression in the shipped installer fails this
# suite. Never committed pointing anywhere but the heredoc.
DEV_MAIN_PY = os.environ.get("WINS_MAIN_PY_PATH", "")

ADMIN = "test-admin-token"

# Documentation-range literals only. No project address in this file.
ENDPOINT = "198.51.100.7:9110"
HOST = "198.51.100.7"

GOOD_OBFUSCATION = {
    "Jc": 2, "Jmin": 10, "Jmax": 30,
    "S1": 16, "S2": 80, "S3": 16, "S4": 0,
    "H1": 11, "H2": 22, "H3": 33, "H4": 44,
}

FAILURES = []
PASSED = [0]


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def expect_raises(exc_type, fn, *, reason=None):
    try:
        fn()
    except exc_type as caught:
        if reason is not None:
            assert getattr(caught, "reason", None) == reason, (
                f"expected reason={reason!r}, got {getattr(caught, 'reason', None)!r}"
            )
        return caught
    raise AssertionError(f"expected {exc_type.__name__}, nothing was raised")


def expect_http(status, fn):
    try:
        fn()
    except HTTPException as exc:
        assert exc.status_code == status, (
            f"expected HTTP {status}, got {exc.status_code}: {exc.detail}"
        )
        return exc
    raise AssertionError(f"expected HTTPException {status}, nothing was raised")


def expect_refused(mod, node, reason, **kw):
    return expect_raises(
        mod.Winn3ContractError,
        lambda: resolve(mod, node, **kw),
        reason=reason,
    )


# ============================ the Go source pins ===========================
#
# The mirror discipline from the descriptor suite, applied to the plan floor.
# Every number the hub enforces is parsed out of the Go source it must agree
# with, never restated. A second copy of a constant that silently disagrees
# with the implementation is the failure this project has already had once.


def _go_src(rel):
    with open(os.path.join(PROTOCOL_DIR, rel), encoding="utf-8") as handle:
        return handle.read()


def _const_value(src, name):
    match = re.search(
        rf"^\s*(?:const\s+)?{re.escape(name)}\s*=\s*(.+?)\s*$", src, re.MULTILINE)
    assert match, f"{name} not found in the Go source"
    return _eval_expr(src, match.group(1))


def _eval_expr(src, expr):
    """Evaluate a Go constant RHS: integers, named constants, sums of both.

    `tcpHeaderBytes = 20 + 12` has to read 32, not 20 -- a naive first-number
    regex is exactly the kind of agreement-by-luck this drift test exists to
    kill."""
    expr = re.sub(r"\s+", "", expr)
    if not expr:
        raise AssertionError("empty constant expression")
    token = re.match(r"\d+|\w+", expr)
    if not token:
        raise AssertionError(f"cannot parse {expr!r}")
    value = int(token.group()) if token.group().isdigit() else \
        _const_value(src, token.group())
    rest = expr[token.end():]
    while rest:
        assert rest.startswith("+"), f"unsupported operation in {expr!r}"
        rest = rest[1:]
        token = re.match(r"\d+|\w+", rest)
        assert token, f"cannot parse {expr!r}"
        value += int(token.group()) if token.group().isdigit() else \
            _const_value(src, token.group())
        rest = rest[token.end():]
    return value


def _go_string(src, name):
    match = re.search(rf'return\s+"({re.escape(name)})"', src)
    return match.group(1) if match else None


def _expected_overheads():
    """Compute carrier.Overhead(class, ipv6) from the raw header constants."""
    sizing = _go_src("winn3/carrier/sizing.go")
    tcp = _const_value(sizing, "tcpHeaderBytes")
    tls = _const_value(sizing, "tlsRecordBytes")
    len_rec = _const_value(sizing, "LengthRecordOverhead")
    udp = _const_value(sizing, "udpHeaderBytes")
    ipv6 = _const_value(sizing, "ipv6HeaderBytes")
    return {
        "udp": ipv6 + udp,
        "tcp": ipv6 + tcp + len_rec,
        "tls": ipv6 + tcp + tls + len_rec,
    }


def test_plan_constants_do_not_drift(mod):
    sizing = _go_src("winn3/carrier/sizing.go")
    # carrier.DefaultPathMTU -- the fleet default, raised from 1280 2026-08-10.
    assert re.search(r"const DefaultPathMTU = (\d+)", sizing).group(1) == \
        str(mod.WINN3_DEFAULT_PATH_MTU), (
        "WINN3_DEFAULT_PATH_MTU drifted from carrier.DefaultPathMTU")
    # The inner-IPv6 floor lives in session/config.go as a sum, not a const.
    # 1280 + TransportOverhead() + frameHeaderSize + Overhead(class, ipv6).
    session = _go_src("winn3/session/config.go")
    assert re.search(r"IPv6MinimumLinkMTU", session)
    over = _expected_overheads()
    assert set(over) == set(mod.WINN3_PLAN_IPV6_CARRIER_OVERHEAD), (
        "WINN3_PLAN_IPV6_CARRIER_OVERHEAD drifted from carrier.Overhead")
    for cls, oh in over.items():
        assert mod.WINN3_PLAN_IPV6_CARRIER_OVERHEAD[cls] == oh, (
            f"WINN3_PLAN_IPV6_CARRIER_OVERHEAD[{cls}] != {oh}")
    # envelope = DemuxToken(8) + transportHeader(2) + AEADTag(16) + frame(3).
    core_session = _go_src("winn3/core/session.go")
    m = re.search(
        r"func TransportOverhead\(\) int \{ return (\w+) \+ (\w+) \+ (\w+) \}",
        core_session)
    assert m, "core.TransportOverhead no longer sums three named constants"
    params = _go_src("winn3/core/params.go")
    core_frame = _go_src("winn3/core/frame.go")
    # transportHeaderSize lives in session.go, the other two in params.go.
    all_core = core_session + "\n" + params
    envelope = _const_value(all_core, m.group(1)) + \
        _const_value(all_core, m.group(2)) + \
        _const_value(all_core, m.group(3)) + \
        _const_value(core_frame, "frameHeaderSize")
    assert mod.WINN3_TUN_ENVELOPE_OVERHEAD == envelope, (
        f"WINN3_TUN_ENVELOPE_OVERHEAD {mod.WINN3_TUN_ENVELOPE_OVERHEAD} != {envelope}")
    # The carrier class names, as carrier.Class.String() renders them.
    carrier_go = _go_src("winn3/carrier/carrier.go")
    for name in mod.WINN3_CARRIER_CLASSES:
        assert _go_string(carrier_go, name) == name, name
    assert mod.WINN3_IPV6_MINIMUM_LINK_MTU == 1280


# ============================== fixtures ==================================


def standalone_node(mod, *, slug="lab-alpha", protocol_version="winn/3",
                    protocol_params_json=None, path_mtu=None,
                    carrier_classes=None, descriptor_json=None,
                    admission_json=None):
    obfuscation = GOOD_OBFUSCATION
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        now = mod.utcnow().isoformat()
        # The proof must follow the release and the flip, so both precede it.
        before = (mod.utcnow() - timedelta(minutes=5)).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO nodes ("
            " slug, name, flag, endpoint, tunnel_gateway_ipv4, stealth_endpoint,"
            " public_key, preshared_key, status, last_heartbeat,"
            " obfuscation_json, ssh_host, wg_port, xray_uuid, xray_path,"
            " xray_security, xray_sni, stealth_public_port, xray_inbound_port,"
            " management_status, operator_enabled, free_access_enabled,"
            " direct_awg_enabled, max_peers, peer_count, protocol_version,"
            " protocol_params_json, path_mtu, carrier_classes,"
            " winn3_descriptor_json, winn3_admission_json"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                slug, "Lab Alpha", "\U0001F310", ENDPOINT, "10.8.1.1",
                f"{slug}.example.test:80",
                "A" * 43 + "=", "B" * 43 + "=", "online", now,
                json.dumps(obfuscation), HOST, 9110,
                "11111111-2222-4333-8444-555555555555", "/wins-stealth-tunnel",
                "none", f"{slug}.example.test", 80, 9111, "ok",
                1, 1, 1, 500, 0,
                protocol_version, protocol_params_json,
                path_mtu, carrier_classes, descriptor_json, admission_json,
            ),
        )
        # H3: a fresh canary is one bound to the row's identity, sequence and generation.
        conn.execute(
            "UPDATE nodes SET winn3_canary_status='ok', winn3_canary_ok_at=?, "
            "winn3_identity_sha256=COALESCE(NULLIF(winn3_identity_sha256, ''), ?), "
            "deployment_released_at=?, winn3_carrier_flipped_at=? WHERE slug=?",
            (now, "a" * 64, before, before, slug),
        )
    bind_canary(mod, slug)
    return node_row(mod, slug)


def bind_canary(mod, slug="lab-alpha"):
    """Bind the seeded ok canary to the row's current identity, sequence and generation."""
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        bound = mod.winn3_result_binding(conn.execute("SELECT * FROM nodes WHERE slug=?", (slug,)).fetchone())
        conn.execute(
            "UPDATE nodes SET winn3_canary_identity_sha256=?, winn3_canary_seq=?, winn3_canary_generation=? "
            "WHERE slug=?",
            (bound["identity_sha256"], bound["seq"], bound["generation"], slug),
        )


def node_row(mod, slug="lab-alpha"):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()


def caps(**overrides):
    base = {
        "supports_awg": True, "supports_xray": True,
        "supports_split_tunnel": False, "supports_per_app_split_tunnel": False,
        "supports_double_vpn": True,
        "supports_winn3": False, "supports_winn3_spa": False,
        "supports_winn3_descriptor": False,
    }
    base.update(overrides)
    return base


def resolve(mod, node, *, capabilities=None, steam=False, dbl=False, mtu=1280):
    return mod.resolve_served_winn_protocol(
        node,
        capabilities=caps() if capabilities is None else capabilities,
        obfuscation=GOOD_OBFUSCATION,
        stealth_mode=steam,
        double_vpn_active=dbl,
        mtu=mtu,
    )


def admin_winn3(mod, **kwargs):
    kwargs.setdefault("x_admin_token", ADMIN)
    kwargs.setdefault("request", FakeRequest(path="/admin/nodes/winn3"))
    return mod.admin_set_node_winn3(**kwargs)


def admin_list_winn3(mod):
    """GET /admin/nodes/winn3 — the operator pre-flight, not a SELECT * bypass."""
    return mod.admin_list_node_winn3(
        request=FakeRequest(path="/admin/nodes/winn3", method="GET"),
        x_admin_token=ADMIN,
    )


def served_config(mod, **login_overrides):
    from test_account_deletion_hub import BackgroundTasks
    mod.sync_peer_to_node = lambda *a, **k: True
    mod.sync_winn3_registry_to_node = lambda *a, **k: True
    login = ddesc.build_login(mod, **login_overrides)
    request = FakeRequest(
        path="/verify", headers={"x-wins-activation": ddesc.ACTIVATION_SECRET})
    result = asyncio.run(
        mod.verify_account(request, login, BackgroundTasks()))
    body = result.body if hasattr(result, "body") else result
    if isinstance(body, (bytes, str)):
        body = json.loads(body)
    return body


def install_descriptor(mod, slug="lab-alpha"):
    """Register a signed descriptor for an EXISTING node. The node must exist
    first -- /admin/nodes/winn3/descriptor 404s otherwise."""
    payload_b64, sig_b64 = ddesc.envelope_for(ddesc.descriptor_payload(node=slug))
    ddesc.admin_descriptor(
        mod, slug=slug, enabled=True,
        descriptor_payload_b64=payload_b64, descriptor_sig_b64=sig_b64)
    return payload_b64, sig_b64


def stored_descriptor_json(slug="lab-alpha", **payload_kw):
    """A structurally valid stored envelope. winn3_stored_descriptor validates
    the decoded payload, not the signature, so this is enough for the serve
    gate; /verify tests that need a signed blob still use install_descriptor."""
    payload_b64, sig_b64 = ddesc.envelope_for(
        ddesc.descriptor_payload(node=slug, **payload_kw))
    return json.dumps({"payload": payload_b64, "sig": sig_b64})


# ================= 1. the plan arithmetic (the contract) ===================


def test_full_plan_dead_zone_is_1421(mod):
    assert mod.winn3_plan_floor_threshold(["udp", "tcp", "tls"]) == 1421, (
        "1280 + 29 envelope + 112 TLS-over-IPv6 is where the shipping plan "
        "stops being the never-promotes band")


def test_udp_only_plan_crosses_at_1357(mod):
    assert mod.winn3_plan_floor_threshold(["udp"]) == 1357, (
        "the threshold is plan-aware: a udp-only plan carries inner IPv6 at 1357")


def test_plan_servable_accepts_the_fleet_default(mod):
    ok, reason = mod.winn3_standalone_plan_servable(1450, ["udp", "tcp", "tls"])
    assert ok and reason == ""
    ok, reason = mod.winn3_standalone_plan_servable(1400, ["udp"])
    assert ok and reason == "", "a udp-only plan at 1400 is NOT the dead zone"


def test_plan_servable_refuses_the_dead_zone(mod):
    for path_mtu in (1280, 1300, 1400, 1420):
        ok, reason = mod.winn3_standalone_plan_servable(
            path_mtu, ["udp", "tcp", "tls"])
        assert not ok and reason == "path-mtu-dead-zone", (path_mtu, ok, reason)
    # 1421 is exactly the edge; it must be servable.
    ok, reason = mod.winn3_standalone_plan_servable(1421, ["udp", "tcp", "tls"])
    assert ok, (ok, reason)


def test_plan_servable_refuses_bad_shapes(mod):
    assert mod.winn3_standalone_plan_servable(1450, [])[1] == \
        "path-mtu-plan-empty"
    assert mod.winn3_standalone_plan_servable(1450, ["udp", "quic"])[1] == \
        "path-mtu-plan-unknown-class"
    assert mod.winn3_standalone_plan_servable(1450, ["udp", "udp"])[1] == \
        "path-mtu-plan-duplicate-class"
    assert mod.winn3_standalone_plan_servable(1450, ["tcp"])[1] == \
        "path-mtu-plan-missing-udp"
    assert mod.winn3_standalone_plan_servable(1450, ["tls"])[1] == \
        "path-mtu-plan-missing-udp"
    assert mod.winn3_standalone_plan_servable(1450, ["tcp", "tls"])[1] == \
        "path-mtu-plan-missing-udp"
    assert mod.winn3_standalone_plan_servable(1450, ["udp", "tcp", "tls"]) == \
        (True, "")
    assert mod.winn3_standalone_plan_servable(0, ["udp"])[1] == \
        "path-mtu-out-of-range"
    assert mod.winn3_standalone_plan_servable(99999, ["udp"])[1] == \
        "path-mtu-out-of-range"


def test_effective_path_mtu_defaults_to_the_fleet_default(mod):
    assert mod.winn3_effective_path_mtu({}) == mod.WINN3_DEFAULT_PATH_MTU
    assert mod.winn3_effective_path_mtu({"path_mtu": None}) == \
        mod.WINN3_DEFAULT_PATH_MTU
    assert mod.winn3_effective_path_mtu({"path_mtu": "1500"}) == 1500
    assert mod.winn3_effective_path_mtu({"path_mtu": "junk"}) == \
        mod.WINN3_DEFAULT_PATH_MTU


def test_parse_carrier_classes(mod):
    assert mod.parse_winn3_carrier_classes(None) == []
    assert mod.parse_winn3_carrier_classes("") == []
    assert mod.parse_winn3_carrier_classes("udp,tcp,tls") == \
        ["udp", "tcp", "tls"]
    assert mod.parse_winn3_carrier_classes(" udp , TLS ") == ["udp", "tls"]


# ==================== 2. the serving gate (the teeth) =====================


def _standalone(mod, **kw):
    return standalone_node(
        mod, protocol_version="winn/3",
        protocol_params_json=json.dumps({"carrier": "winn3"}), **kw)


def test_gate_serves_a_standalone_plan_it_can_honour(mod):
    # A servable plan is not enough on its own: carrier=winn3 also needs a
    # stored valid descriptor (see test_gate_refuses_standalone_without_a_stored_descriptor).
    # This test isolates the PLAN half, so the node is otherwise ready.
    n = _standalone(
        mod, path_mtu=1450, carrier_classes="udp,tcp,tls",
        descriptor_json=stored_descriptor_json())
    ver, _, reason = resolve(
        mod, n, capabilities=caps(supports_winn3=True,
                                  supports_winn3_descriptor=True))
    assert ver == "winn/3" and reason == "winn3"


def test_gate_refuses_a_dead_zone_standalone_plan(mod):
    n = _standalone(mod, path_mtu=1400, carrier_classes="udp,tcp,tls")
    expect_refused(
        mod, n, "path-mtu-dead-zone",
        capabilities=caps(supports_winn3=True,
                          supports_winn3_descriptor=True))


def test_gate_refuses_a_planless_standalone_node(mod):
    n = _standalone(mod)
    expect_refused(
        mod, n, "path-mtu-plan-empty",
        capabilities=caps(supports_winn3=True,
                          supports_winn3_descriptor=True))


def test_gate_does_not_apply_the_plan_to_relay_carriers(mod):
    # direct-awg clients never read path_mtu/carrier_classes, so a stored plan
    # -- even a dead-zone one -- must not gate them. This is a SEPARATE surface
    # from the standalone plan, and gating it would over-refuse a working
    # relay config (the same rule that kept the dead-zone refusal plan-aware).
    n = standalone_node(
        mod, protocol_version="winn/3",
        protocol_params_json=json.dumps({"max_datagram": "1280"}),
        path_mtu=1400, carrier_classes="udp,tcp,tls")
    ver, _, reason = resolve(mod, n, capabilities=caps(supports_winn3=True))
    assert ver == "winn/3", (ver, reason)


def test_gate_refuses_standalone_to_a_client_without_descriptor_capability(mod):
    # carrier=winn3 IS the standalone branch: the client takes it at
    # _winn3StandaloneStart and refuses the whole connection if it cannot
    # verify a descriptor (winn3DescriptorUnverified). A device on the right
    # build with the datapath but no verifier ring advertises supports_winn3
    # WITHOUT supports_winn3_descriptor -- the hub must refuse rather than
    # rewrite the registered winn/3 node to winn/1. This is the negative half
    # of the descriptor gate: the descriptor is not merely withheld, and the
    # advertisement is not silently reverted.
    n = standalone_node(
        mod, protocol_version="winn/3",
        protocol_params_json=json.dumps({"carrier": "winn3"}),
        path_mtu=1450, carrier_classes="udp,tcp,tls",
        descriptor_json=stored_descriptor_json())
    # Datapath yes, verifier ring no: fail closed, named.
    expect_refused(mod, n, "client-not-descriptor-capable",
                   capabilities=caps(supports_winn3=True))
    # The same client with the ring can take the standalone config. The node
    # already has a stored descriptor so this half isolates the capability
    # flag, not the stored-blob gate.
    ver, _, reason = resolve(
        mod, n, capabilities=caps(supports_winn3=True,
                                  supports_winn3_descriptor=True))
    assert ver == "winn/3" and reason == "winn3", (ver, reason)
    # A fully absent client is refused by the earlier capability gate.
    expect_refused(mod, n, "client-not-winn3-capable")


def test_gate_refuses_standalone_without_a_stored_descriptor(mod):
    """Readiness already lists winn3_descriptor_missing_or_invalid as a
    blocker for carrier=winn3. The serving gate must refuse the same way:
    advertising carrier=winn3 with no stored, valid descriptor hands the
    client a config it refuses by name (fail-closed, no AWG fallback).

    Three controls live in this one test because they are the same gate:
    missing blob, invalid blob, and the positive (stored valid) that proves
    the refusal is the blob, not the plan or the client flag. A relay node
    with no descriptor must still be served winn/3 -- the stored-descriptor
    check is standalone-only, matching readiness.
    """
    capable = caps(supports_winn3=True, supports_winn3_descriptor=True)

    missing = _standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls")
    expect_refused(mod, missing, "winn3_descriptor_missing_or_invalid",
                   capabilities=capable)
    ready = mod.winn3_node_readiness(missing, GOOD_OBFUSCATION)
    assert "winn3_descriptor_missing_or_invalid" in ready["blockers"]
    assert ready["ready"] is False
    assert ready["carrier"] == "winn3"

    invalid = _standalone(
        mod, slug="lab-invalid", path_mtu=1450, carrier_classes="udp,tcp,tls",
        descriptor_json=stored_descriptor_json(slug="lab-invalid", tag_size=999))
    expect_refused(mod, invalid, "winn3_descriptor_missing_or_invalid",
                   capabilities=capable)
    assert not mod.winn3_stored_descriptor(invalid)
    ready_invalid = mod.winn3_node_readiness(invalid, GOOD_OBFUSCATION)
    assert "winn3_descriptor_missing_or_invalid" in ready_invalid["blockers"]

    present = _standalone(
        mod, slug="lab-present", path_mtu=1450, carrier_classes="udp,tcp,tls",
        descriptor_json=stored_descriptor_json(slug="lab-present"))
    ver, params, reason = resolve(mod, present, capabilities=capable)
    assert ver == "winn/3" and reason == "winn3", (ver, reason)
    assert params.get("carrier") == "winn3"
    assert mod.winn3_stored_descriptor(present)
    ready_ok = mod.winn3_node_readiness(present, GOOD_OBFUSCATION)
    assert "winn3_descriptor_missing_or_invalid" not in ready_ok["blockers"]

    relay = standalone_node(
        mod, slug="lab-relay", protocol_version="winn/3",
        protocol_params_json=json.dumps({"max_datagram": "1280"}))
    ver, _, reason = resolve(
        mod, relay, capabilities=caps(supports_winn3=True))
    assert ver == "winn/3", (ver, reason)
    assert not mod.winn3_stored_descriptor(relay)


# ===================== 3. admin registration (the gate, at the write) =====


def test_admin_refuses_a_standalone_registration_without_a_plan(mod):
    standalone_node(mod, protocol_version="winn/1")
    exc = expect_http(400, lambda: admin_winn3(
        mod, slug="lab-alpha", enabled=True,
        protocol_params_json=json.dumps({"carrier": "winn3"})))
    assert "plan" in exc.detail.lower()


def test_admin_refuses_a_dead_zone_path_mtu(mod):
    standalone_node(mod, protocol_version="winn/1")
    expect_http(400, lambda: admin_winn3(
        mod, slug="lab-alpha", enabled=True,
        protocol_params_json=json.dumps({"carrier": "winn3"}),
        path_mtu="1400", carrier_classes="udp,tcp,tls"))
    # Rollback guard: a refused registration must not change the row.
    row = node_row(mod)
    assert (row["protocol_version"] or "") == "winn/1"
    assert row["path_mtu"] is None and (row["carrier_classes"] or "") == ""


def test_admin_accepts_a_good_standalone_plan(mod):
    standalone_node(mod, protocol_version="winn/1")
    result = admin_winn3(
        mod, slug="lab-alpha", enabled=True,
        protocol_params_json=json.dumps({"carrier": "winn3"}),
        path_mtu="1500", carrier_classes="udp,tcp,tls")
    assert result["ok"] is True
    assert result["effective_path_mtu"] == 1500
    assert result["carrier_classes"] == "udp,tcp,tls"
    row = node_row(mod)
    assert row["protocol_version"] == "winn/3"
    assert row["path_mtu"] == 1500
    assert row["carrier_classes"] == "udp,tcp,tls"


def test_admin_defaults_an_absent_path_mtu_but_requires_the_plan(mod):
    standalone_node(mod, protocol_version="winn/1")
    result = admin_winn3(
        mod, slug="lab-alpha", enabled=True,
        protocol_params_json=json.dumps({"carrier": "winn3"}),
        carrier_classes="udp,tcp,tls")
    assert result["effective_path_mtu"] == mod.WINN3_DEFAULT_PATH_MTU
    assert node_row(mod)["path_mtu"] is None


def test_admin_refuses_an_unknown_class(mod):
    standalone_node(mod, protocol_version="winn/1")
    expect_http(400, lambda: admin_winn3(
        mod, slug="lab-alpha", enabled=True,
        protocol_params_json=json.dumps({"carrier": "winn3"}),
        carrier_classes="udp,quic"))


def test_admin_refuses_a_non_numeric_path_mtu(mod):
    standalone_node(mod, protocol_version="winn/1")
    expect_http(400, lambda: admin_winn3(
        mod, slug="lab-alpha", enabled=True,
        protocol_params_json=json.dumps({"carrier": "winn3"}),
        path_mtu="wide", carrier_classes="udp"))


def test_admin_rollback_clears_the_plan_columns(mod):
    _standalone(mod, path_mtu=1500, carrier_classes="udp,tcp,tls")
    admin_winn3(mod, slug="lab-alpha", enabled=True,
                protocol_params_json=json.dumps({"carrier": "winn3"}),
                path_mtu="1500", carrier_classes="udp,tcp,tls")
    result = admin_winn3(mod, slug="lab-alpha", enabled=False)
    assert result["protocol_version"] == "winn/1"
    assert result["path_mtu"] is None and result["carrier_classes"] == ""
    row = node_row(mod)
    assert row["path_mtu"] is None and (row["carrier_classes"] or "") == ""


# ======================= 4. readiness (operator view) ====================


def test_readiness_reports_the_plan_and_its_blockers(mod):
    _standalone(mod, path_mtu=1500, carrier_classes="udp,tcp,tls")
    ready = mod.winn3_node_readiness(node_row(mod), GOOD_OBFUSCATION)
    assert ready["path_mtu"] == 1500
    assert ready["carrier_classes"] == "udp,tcp,tls"
    assert ready["plan_reason"] is None
    assert "path-mtu-dead-zone" not in ready["blockers"]

    _standalone(mod, slug="dead-beat", path_mtu=1400,
                carrier_classes="udp,tcp,tls")
    dead = mod.winn3_node_readiness(node_row(mod, "dead-beat"), GOOD_OBFUSCATION)
    assert "path-mtu-dead-zone" in dead["blockers"]
    assert dead["plan_reason"] == "path-mtu-dead-zone"
    # The OPERATOR's value, reported as measured, not hidden: they must see the
    # 1400 that is the problem, and the classes.
    assert dead["path_mtu"] == 1400
    assert dead["carrier_classes"] == "udp,tcp,tls"


def test_http_readiness_sees_plan_and_descriptor_on_a_provisioned_standalone_node(mod):
    """GET /admin/nodes/winn3 must feed readiness the plan and descriptor
    columns. Calling winn3_node_readiness on SELECT * cannot catch a GET that
    omits them: a fully provisioned standalone node then always looks
    plan-empty and descriptor-missing.

    path_mtu is 1500, not WINN3_DEFAULT_PATH_MTU (1450): a missing column is
    read as NULL and winn3_effective_path_mtu substitutes the fleet default,
    which would make a default-MTU node look fine and a 1500 node look like
    1450.
    """
    _standalone(mod, path_mtu=1500, carrier_classes="udp,tcp,tls")
    install_descriptor(mod)

    full = mod.winn3_node_readiness(node_row(mod), GOOD_OBFUSCATION)
    assert full["path_mtu"] == 1500
    assert full["carrier_classes"] == "udp,tcp,tls"
    assert "path-mtu-plan-empty" not in full["blockers"]
    assert "winn3_descriptor_missing_or_invalid" not in full["blockers"]
    assert "carrier_requires_node_side_winn3_gateway" in full["blockers"]

    out = admin_list_winn3(mod)
    assert out["ok"] is True
    entry = [n for n in out["nodes"] if n["slug"] == "lab-alpha"][0]
    assert entry["path_mtu"] == 1500, (
        "GET omitted path_mtu; readiness substituted the fleet default"
    )
    assert entry["carrier_classes"] == "udp,tcp,tls"
    assert "path-mtu-plan-empty" not in entry["blockers"]
    assert "winn3_descriptor_missing_or_invalid" not in entry["blockers"]
    # Named, not assumed: the hub still cannot see cmd/winn3-gateway.
    # Do not drop this to make ready=True.
    assert "carrier_requires_node_side_winn3_gateway" in entry["blockers"]
    assert entry["ready"] is False
    assert entry["carrier"] == "winn3"


def test_http_readiness_still_names_real_plan_and_descriptor_blockers(mod):
    """Negative: going through the endpoint must not drop real blockers.

    A GET that simply stopped checking the plan would pass the provisioned
    case and fail this one.
    """
    _standalone(mod)
    out = admin_list_winn3(mod)
    entry = [n for n in out["nodes"] if n["slug"] == "lab-alpha"][0]
    assert "path-mtu-plan-empty" in entry["blockers"]
    assert "winn3_descriptor_missing_or_invalid" in entry["blockers"]
    assert "carrier_requires_node_side_winn3_gateway" in entry["blockers"]
    assert entry["ready"] is False

    _standalone(mod, slug="dead-beat", path_mtu=1400,
                carrier_classes="udp,tcp,tls")
    out = admin_list_winn3(mod)
    dead = [n for n in out["nodes"] if n["slug"] == "dead-beat"][0]
    assert dead["path_mtu"] == 1400, (
        "GET omitted path_mtu; a dead-zone 1400 was reported as the default"
    )
    assert dead["carrier_classes"] == "udp,tcp,tls"
    assert "path-mtu-dead-zone" in dead["blockers"]
    assert "path-mtu-plan-empty" not in dead["blockers"]
    assert dead["ready"] is False


# ================== 5. end to end /verify (the proof) =====================


def test_v1_client_is_byte_for_byte_unaffected(mod):
    """The load-bearing property. A client that advertises nothing against an
    explicit winn/1 node gets the exact winn/1 config this hub served before
    the plane ever existed, with the two new fields empty rather than absent
    or mis-populated."""
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    ddesc.arm_activation(mod)
    standalone_node(mod, protocol_version="winn/1")
    body = served_config(mod, location="lab-alpha")
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["protocol_version"] == "winn/1"
    assert config["protocol_params"] == {}
    assert config["winn3_descriptor"] == {}
    assert config["winn3_inner_v4"] == ""
    assert config["winn3_static_private"] == ""
    assert config["winn3_path_mtu"] == ""
    assert config["winn3_carrier_classes"] == ""
    compat = body.get("vpnconfig") or {}
    if compat:
        assert compat["winn3pathmtu"] == ""
        assert compat["winn3carrierclasses"] == ""


def test_standalone_client_receives_a_usable_config(mod):
    """The proof the task asks for: a v3-capable standalone client receives a
    config carrying the plan (path_mtu + carrier_classes), the signed
    descriptor and the per-device material -- all three halves a standalone
    session needs -- while protocol_params carries neither of the two plan
    fields (a closed allowlist that must not gain them)."""
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    ddesc.arm_activation(mod)
    _standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls")
    payload_b64, sig_b64 = install_descriptor(mod)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE nodes SET winn3_descriptor_json = ? WHERE slug = 'lab-alpha'",
            (json.dumps({"payload": payload_b64, "sig": sig_b64}),))
        conn.commit()
    bind_canary(mod)
    body = served_config(
        mod, location="lab-alpha", supports_winn3=True,
        supports_winn3_descriptor=True)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["protocol_version"] == "winn/3"
    assert config["protocol_params"]["carrier"] == "winn3"
    # The plan, served per-device on vpn_config exactly where the client reads
    # it (winn_protocol_dispatch.dart:2173-2175).
    assert config["winn3_path_mtu"] == "1450"
    assert config["winn3_carrier_classes"] == "udp,tcp,tls"
    # The gateway half, the device half, and the descriptors.
    assert config["winn3_descriptor"] == {"payload": payload_b64,
                                          "sig": sig_b64}
    inner = config["winn3_inner_v4"]
    priv = config["winn3_static_private"]
    assert mod.winn3_is_inner_ipv4(inner)
    assert mod.winn3_inner_router_in_pool(inner)
    assert len(base64.b64decode(priv, validate=True)) == 32
    # NOT key-shaped nor allowlist-surfaced on protocol_params.
    assert "path_mtu" not in config["protocol_params"]
    assert "carrier_classes" not in config["protocol_params"]
    # The no-underscore compat copy mirrors it, like every other key here.
    compat = body.get("vpnconfig") or {}
    if compat:
        assert compat["winn3pathmtu"] == "1450"
        assert compat["winn3carrierclasses"] == "udp,tcp,tls"


def test_a_dead_zone_standalone_node_is_refused_not_rewritten_to_winn1(mod):
    """A node whose plan is in the dead zone is refused to a winn/3-capable
    client, never rewritten to winn/1 and never served as a winn/3 config the
    client's engine would refuse by name."""
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    ddesc.arm_activation(mod)
    _standalone(mod, path_mtu=1400, carrier_classes="udp,tcp,tls")
    expect_http(503, lambda: served_config(
        mod, location="lab-alpha",
        supports_winn3=True,
        supports_winn3_descriptor=True))


def test_standalone_without_descriptor_is_refused_not_rewritten_to_winn1(mod):
    """The /verify counterpart of test_gate_refuses_standalone_without_a_stored_descriptor.

    A capable client hitting a carrier=winn3 node with a servable plan but no
    stored descriptor is refused, never rewritten to winn/1 and never served
    winn/3 + empty descriptor.
    """
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    ddesc.arm_activation(mod)
    _standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls")
    expect_http(503, lambda: served_config(
        mod, location="lab-alpha",
        supports_winn3=True,
        supports_winn3_descriptor=True))


# ================================ runner ==================================

UNIT_TESTS = [
    test_plan_constants_do_not_drift,
    test_full_plan_dead_zone_is_1421,
    test_udp_only_plan_crosses_at_1357,
    test_plan_servable_accepts_the_fleet_default,
    test_plan_servable_refuses_the_dead_zone,
    test_plan_servable_refuses_bad_shapes,
    test_effective_path_mtu_defaults_to_the_fleet_default,
    test_parse_carrier_classes,
    test_gate_serves_a_standalone_plan_it_can_honour,
    test_gate_refuses_a_dead_zone_standalone_plan,
    test_gate_refuses_a_planless_standalone_node,
    test_gate_does_not_apply_the_plan_to_relay_carriers,
    test_gate_refuses_standalone_to_a_client_without_descriptor_capability,
    test_gate_refuses_standalone_without_a_stored_descriptor,
    test_admin_refuses_a_standalone_registration_without_a_plan,
    test_admin_refuses_a_dead_zone_path_mtu,
    test_admin_accepts_a_good_standalone_plan,
    test_admin_defaults_an_absent_path_mtu_but_requires_the_plan,
    test_admin_refuses_an_unknown_class,
    test_admin_refuses_a_non_numeric_path_mtu,
    test_admin_rollback_clears_the_plan_columns,
    test_readiness_reports_the_plan_and_its_blockers,
    test_http_readiness_sees_plan_and_descriptor_on_a_provisioned_standalone_node,
    test_http_readiness_still_names_real_plan_and_descriptor_blockers,
    test_v1_client_is_byte_for_byte_unaffected,
    test_standalone_client_receives_a_usable_config,
    test_a_dead_zone_standalone_node_is_refused_not_rewritten_to_winn1,
    test_standalone_without_descriptor_is_refused_not_rewritten_to_winn1,
]


def _hub():
    if DEV_MAIN_PY:
        # Development override: load a private main.py copy verbatim, with the
        # descriptor verification ring loaded the same way production gets it.
        for slot in ("g1", "g2", "g3"):
            os.environ[f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}"] = \
                ddesc.SLOT_PUBS[slot]
        harness._install_stubs()
        import shutil
        import tempfile
        tmpdir = tempfile.mkdtemp(prefix="winshub-dev-")
        logdir = os.path.join(tmpdir, "log")
        os.makedirs(logdir, exist_ok=True)
        settings = {
            "DATABASE_PATH": os.path.join(tmpdir, "vpn_users.db"),
            "RATE_LIMIT_SECRET": "test-rate-limit-secret",
            "ADMIN_TOKEN": ADMIN,
            "SPA_HMAC": "test-spa-hmac",
            "SECURITY_EVENTS_DB": os.path.join(tmpdir, "security_events.db"),
            "SMTP_PASS": "",
            "DEVICE_LIMIT": "3",
            "ACCOUNT_DELETION_IP_RATE_LIMIT_PER_MINUTE": "1000",
            "ACCOUNT_DELETION_ACCOUNT_RATE_LIMIT_PER_HOUR": "1000",
        }
        os.environ.update(settings)
        src = open(DEV_MAIN_PY, encoding="utf-8").read()
        src = src.replace('"/var/log/winsvpn"', repr(logdir))
        src = src.replace('"/var/log/winsvpn/master.log"',
                          repr(os.path.join(logdir, "master.log")))
        src = src.replace('"/var/lib/wins-security-alerts"', repr(tmpdir))
        import types
        mod = types.ModuleType("wins_hub_dev")
        mod.__dict__["__file__"] = os.path.join(tmpdir, "main.py")
        exec(compile(src, "wins_hub_dev_main.py", "exec"), mod.__dict__)
        mod._TMPDIR = tmpdir
        mod._DB = settings["DATABASE_PATH"]
        return mod
    for slot in ("g1", "g2", "g3"):
        os.environ.pop(f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}", None)
    return ddesc.load_hub_with_ring(("g1", "g2", "g3"))


def main():
    import asyncio as _asyncio
    _asyncio.set_event_loop(_asyncio.new_event_loop())
    print("standalone winn/3 plan (path_mtu + carrier_classes)")
    tests = UNIT_TESTS
    focus = os.environ.get("WINN3_PATHMTU_FOCUS", "").strip()
    if focus:
        wanted = [name.strip() for name in focus.split(",") if name.strip()]
        tests = [fn for fn in UNIT_TESTS if fn.__name__ in wanted]
        missing = [name for name in wanted if name not in {fn.__name__ for fn in tests}]
        if missing:
            raise SystemExit(f"WINN3_PATHMTU_FOCUS names not in UNIT_TESTS: {missing}")
    for fn in tests:
        mod = _hub()
        check(fn.__name__, lambda f=fn, m=mod: f(m))
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed, "
          f"{len(tests)} run, {len(UNIT_TESTS)} in suite")
    for name, tb in FAILURES:
        print()
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
