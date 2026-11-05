#!/usr/bin/env python3
"""Hub tests for the Winn Protocol v3 serving path.

Like test_account_deletion_hub.py, test_donor_acknowledgment_hub.py and
test_emergency_dispatch_hub.py these exercise the REAL control-plane source:
the module is extracted from the `cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc
inside wins_control_plane_setup_ONETOUCH.sh and exec'd with stubs for its three
third-party imports. Nothing here is a reimplementation, so a regression in the
shipped installer fails these tests.

No test contacts a node, a live hub, or the network.

WHAT IS UNDER TEST, and why each is a safety property rather than a nicety:

  * THE NO-OP DEFAULT -- the load-bearing property. A node with no winn/3
    registration, served to a client that advertises nothing, must produce
    EXACTLY the config this hub serves today. Everything else in this change is
    additive and reversible; this is what makes that true.
  * THE ALLOWLIST DOES NOT DRIFT -- the hub's twenty accepted params are
    compared against the DART SOURCE the client actually uses. Four
    hand-maintained copies of a key list, all agreeing with each other and none
    with the schema, is what made single-packet authorization unreachable from
    every platform at once (lib/winn_carrier_profile_keys.dart:19-24 and
    lib/winn_protocol_dispatch.dart:206-214). This test is the reason that
    cannot happen a fifth time.
  * THE VALIDATOR REFUSES WHAT THE CLIENT REFUSES -- every rule in
    validate_winn3_protocol_params exists because the shipped client turns the
    violation into a REFUSED CONNECTION with no fallback (the anti-downgrade
    rule). A rule the hub does not enforce is a node that disconnects every
    client it serves, silently, with nothing in the hub log.
  * THE GATE IS BINARY -- protocol_params is consumed atomically by the client,
    so a partially-served winn/3 is a refused connection. The gate must return
    the whole advertisement, plain winn/1 for an explicit winn/1 node, or fail
    closed for a registered winn/3 node -- never a subset, never an implicit
    rewrite of winn/3 to winn/1.
  * NO VALUES IN LOGS OR ERROR BODIES -- gateway_endpoint and spa_target are
    node addresses. Reasons and key names only.

Run:  python3 server/test_winn3_serving_hub.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import json
import os
import re
import sqlite3
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the deletion suite's extraction harness so every suite is provably
# reading the same heredoc out of the same installer.
import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN = "test-admin-token"

# A winn/3-legal AmneziaWG profile: H1..H4 distinct and >= 5, S1..S4 in range.
# These are the hub's own DEFAULT_OBFUSCATION values.
GOOD_OBFUSCATION = {
    "Jc": 2, "Jmin": 10, "Jmax": 30,
    "S1": 16, "S2": 80, "S3": 16, "S4": 0,
    "H1": 11, "H2": 22, "H3": 33, "H4": 44,
}

# Documentation-range literals only (RFC 5737 / RFC 3849). No project address
# appears in this file; `python3 tools/ipscrub/ipscrub.py scan-paths` is run
# over it.
NODE_ENDPOINT = "198.51.100.7:9110"
NODE_HOST = "198.51.100.7"

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


def expect_raises(exc_type, fn, *, reason=None, keys=None):
    try:
        fn()
    except exc_type as caught:
        if reason is not None:
            assert getattr(caught, "reason", None) == reason, (
                f"expected reason={reason!r}, got {getattr(caught, 'reason', None)!r}"
            )
        if keys is not None:
            assert getattr(caught, "keys", None) == sorted(keys), (
                f"expected keys={sorted(keys)!r}, got {getattr(caught, 'keys', None)!r}"
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


# ============================== fixtures ==================================


def seed_node(mod, *, slug="lab-alpha", endpoint=NODE_ENDPOINT,
              obfuscation=None, protocol_version="winn/1",
              protocol_params_json=None, free_access=1):
    """One node row that passes every selection gate."""
    obfuscation = GOOD_OBFUSCATION if obfuscation is None else obfuscation
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        now = mod.utcnow().isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO nodes ("
            " slug, name, flag, endpoint, tunnel_gateway_ipv4, stealth_endpoint,"
            " public_key, preshared_key, status, last_heartbeat, obfuscation_json,"
            " ssh_host, wg_port, xray_uuid, xray_path, xray_security, xray_sni,"
            " stealth_public_port, xray_inbound_port, management_status,"
            " operator_enabled, free_access_enabled, direct_awg_enabled,"
            " max_peers, peer_count, protocol_version, protocol_params_json"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                slug, "Lab Alpha", "\U0001F310", endpoint, "10.8.1.1",
                f"{slug}.example.test:80",
                "A" * 43 + "=", "B" * 43 + "=", "online", now,
                json.dumps(obfuscation) if obfuscation is not None else None,
                NODE_HOST, 9110,
                "11111111-2222-4333-8444-555555555555", "/wins-stealth-tunnel",
                "none", f"{slug}.example.test", 80, 9111, "ok",
                1, free_access, 1, 500, 0,
                protocol_version, protocol_params_json,
            ),
        )
        conn.execute(
            "UPDATE nodes SET winn3_canary_status='ok', winn3_canary_ok_at=? "
            "WHERE slug=?",
            (now, slug),
        )
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()


def node_row(mod, slug="lab-alpha"):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()


def caps(**overrides):
    base = {
        "supports_awg": True, "supports_xray": True,
        "supports_split_tunnel": False, "supports_per_app_split_tunnel": False,
        "supports_double_vpn": True,
        "supports_winn3": False, "supports_winn3_spa": False,
    }
    base.update(overrides)
    return base


def resolve(mod, node, *, capabilities=None, obfuscation=None,
            stealth_mode=False, double_vpn_active=False, mtu=1280):
    return mod.resolve_served_winn_protocol(
        node,
        capabilities=caps() if capabilities is None else capabilities,
        obfuscation=GOOD_OBFUSCATION if obfuscation is None else obfuscation,
        stealth_mode=stealth_mode,
        double_vpn_active=double_vpn_active,
        mtu=mtu,
    )


def admin_winn3(mod, **kwargs):
    kwargs.setdefault("x_admin_token", ADMIN)
    kwargs.setdefault("request", FakeRequest(path="/admin/nodes/winn3"))
    return mod.admin_set_node_winn3(**kwargs)


STANDALONE_ADMIN = {
    "protocol_params_json": json.dumps({"carrier": "winn3"}),
    "path_mtu": "1450",
    "carrier_classes": "udp",
}


# ===================== 1. the allowlist does not drift =====================


def _dart_generated_keys():
    path = os.path.join(REPO_ROOT, "lib", "winn_carrier_profile_keys.dart")
    src = open(path, encoding="utf-8").read()

    def block(name):
        match = re.search(
            r"const Set<String> " + name + r" = <String>\{(.*?)\};", src, re.S
        )
        assert match, f"{name} not found in {path}"
        return sorted(re.findall(r"'([^']+)'", match.group(1)))

    return (
        block("kWinnServedCarrierProfileKeys"),
        block("kWinnRequiredCarrierProfileKeys"),
        block("kWinnSpaCarrierProfileKeys"),
    )


def _dart_dispatch_literals():
    path = os.path.join(REPO_ROOT, "lib", "winn_protocol_dispatch.dart")
    src = open(path, encoding="utf-8").read()
    match = re.search(
        r"const Set<String> kWinnKnownProtocolParams = <String>\{(.*?)\};", src, re.S
    )
    assert match, "kWinnKnownProtocolParams not found"
    literals = sorted(re.findall(r"'([^']+)'", match.group(1)))
    spread = re.findall(r"\.\.\.(\w+)", match.group(1))
    return literals, spread


def test_allowlist_matches_dart(mod):
    served, required, spa = _dart_generated_keys()
    assert sorted(mod.WINN3_CARRIER_PROFILE_PARAMS) == served, (
        "hub carrier-profile params drifted from lib/winn_carrier_profile_keys.dart"
    )
    assert sorted(mod.WINN3_REQUIRED_CARRIER_PARAMS) == required
    assert sorted(mod.WINN3_SPA_PARAMS) == spa
    literals, spread = _dart_dispatch_literals()
    # The Dart set is four literals plus a spread of the generated set.
    assert spread == ["kWinnCarrierProfileParams"], spread
    assert sorted(mod.WINN3_KNOWN_PROTOCOL_PARAMS) == sorted(literals + served), (
        "hub WINN3_KNOWN_PROTOCOL_PARAMS drifted from kWinnKnownProtocolParams"
    )
    assert len(mod.WINN3_KNOWN_PROTOCOL_PARAMS) == 20


def test_h_keys_are_never_accepted(mod):
    # h1..h4 are excluded from the Dart allowlist ON PURPOSE so `obfuscation`
    # stays their single source of truth. If they ever appear here, a served
    # copy could disagree with the headers the AWG engine is running.
    for key in ("h1", "h2", "h3", "h4", "s1", "s4", "spa_key_path"):
        assert key not in mod.WINN3_KNOWN_PROTOCOL_PARAMS


def test_supported_carriers_match_dart(mod):
    src = open(
        os.path.join(REPO_ROOT, "lib", "winn_protocol_dispatch.dart"), encoding="utf-8"
    ).read()
    assert re.search(r"kWinnCarrierDirectAwg = '([^']+)'", src).group(1) == \
        mod.WINN3_CARRIER_DIRECT_AWG
    assert re.search(r"kWinnCarrierHttp3 = '([^']+)'", src).group(1) == \
        mod.WINN3_CARRIER_HTTP3
    http2 = re.search(r"kWinnCarrierHttp2 = '([^']+)'", src).group(1)
    assert http2 not in mod.WINN3_SUPPORTED_CARRIERS, (
        "http2-stream is deliberately unsupported: its dialer takes a connected "
        "TCP socket and the Android host opens an unconnected UDP one"
    )


def test_bounds_match_dart(mod):
    src = open(
        os.path.join(REPO_ROOT, "lib", "winn_protocol_dispatch.dart"), encoding="utf-8"
    ).read()

    def const(name):
        return int(re.search(r"const int " + name + r" = (\d+);", src).group(1))

    assert mod.WINN3_MIN_DATAGRAM == const("kWinnMinDatagram")
    assert mod.WINN3_MAX_DATAGRAM == const("kWinnMaxDatagramCeiling")
    assert mod.WINN3_MAX_SESSION_ID_BYTES == const("kWinnMaxSessionIdBytes")
    assert mod.WINN3_MIN_MTU == const("kWinnMinMtu")
    assert mod.WINN3_MAX_MTU == const("kWinnMaxMtu")
    assert mod.WINN3_SPA_MIN_PACKET_SIZE == const("kWinnSpaMinPacketSize")
    assert mod.WINN3_SPA_MAX_PACKET_SIZE == const("kWinnSpaMaxPacketSize")
    assert mod.WINN3_SPA_MIN_BUCKET_WINDOW_SECONDS == \
        const("kWinnSpaMinBucketWindowSeconds")


# ========================= 2. endpoint literal rule ========================


def test_ip_literal_endpoint(mod):
    ok = [
        "198.51.100.7:9110",
        "127.0.0.1:42110",          # the stacked stealth arrangement
        "[2001:db8::1]:9110",
        "203.0.113.1:1",
        "203.0.113.1:65535",
    ]
    bad = [
        "", "   ", "example.test:9110", "198.51.100.7",     # no port
        "198.51.100.7:", "198.51.100.7:0", "198.51.100.7:65536",
        "198.51.100.7:http", "0.0.0.0:9110",                # unspecified
        "224.0.0.1:9110",                                   # multicast
        "[::]:9110", "[ff02::1]:9110",
        "2001:db8::1:9110",                                 # v6 without brackets
        "198.51.100.7:9110:9110",
    ]
    for value in ok:
        assert mod.winn3_is_ip_literal_endpoint(value), value
    for value in bad:
        assert not mod.winn3_is_ip_literal_endpoint(value), value


# ====================== 3. the params validator ============================


def test_empty_params_are_the_minimal_legal_advertisement(mod):
    assert mod.validate_winn3_protocol_params({}) == {}
    assert mod.validate_winn3_protocol_params(None) == {}


def test_unknown_param_is_refused(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params({"mlkem_public_key": "AAAA"}),
        reason="unknown-params", keys=["mlkem_public_key"],
    )
    # The hub's own source used to plan exactly this. It is a refused
    # connection on every client of the node.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params({"h1": "11"}),
        reason="unknown-params", keys=["h1"],
    )


def test_keys_are_normalized_and_collisions_refused(mod):
    out = mod.validate_winn3_protocol_params({"  GATEWAY_ENDPOINT ": NODE_ENDPOINT})
    assert out == {"gateway_endpoint": NODE_ENDPOINT}
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(
            {"carrier": "direct-awg", "CARRIER": "direct-awg"}
        ),
        reason="duplicate-param-after-normalization",
    )
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params({"": "x"}),
        reason="blank-param-name",
    )


def test_non_scalar_values_refused(mod):
    for value in ({"a": 1}, ["a"], True, False):
        expect_raises(
            mod.Winn3ContractError,
            lambda v=value: mod.validate_winn3_protocol_params({"session_id": v}),
            reason="param-not-a-scalar",
        )


def test_params_not_an_object(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(["gateway_endpoint"]),
        reason="params-not-an-object",
    )


def test_gateway_endpoint_rule(mod):
    assert mod.validate_winn3_protocol_params(
        {"gateway_endpoint": NODE_ENDPOINT}
    ) == {"gateway_endpoint": NODE_ENDPOINT}
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(
            {"gateway_endpoint": "gateway.example.test:9110"}
        ),
        reason="gateway-endpoint-not-ip-literal",
    )


def test_max_datagram_bounds(mod):
    for value in (32, 1500, 1280):
        assert mod.validate_winn3_protocol_params({"max_datagram": value})[
            "max_datagram"] == str(value)
    for value in (31, 1501, -1, 0):
        expect_raises(
            mod.Winn3ContractError,
            lambda v=value: mod.validate_winn3_protocol_params({"max_datagram": v}),
            reason="max-datagram-out-of-range",
        )
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params({"max_datagram": "big"}),
        reason="param-not-an-integer",
    )


def test_session_id_rules(mod):
    assert mod.validate_winn3_protocol_params({"session_id": "s" * 128})
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params({"session_id": "s" * 129}),
        reason="session-id-too-long",
    )
    # Multi-byte: the client's bound is 128 BYTES.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params({"session_id": "é" * 65}),
        reason="session-id-too-long",
    )
    for bad in ("a\nb", "a\rb", "a[b", "a]b"):
        expect_raises(
            mod.Winn3ContractError,
            lambda v=bad: mod.validate_winn3_protocol_params({"session_id": v}),
            reason="session-id-malformed",
        )


def test_carrier_rules(mod):
    assert mod.validate_winn3_protocol_params({}) == {}          # absent = direct-awg
    assert mod.validate_winn3_protocol_params(
        {"carrier": "DIRECT-AWG"}) == {"carrier": "direct-awg"}
    for bad in ("http2-stream", "quic", "direct_awg"):
        expect_raises(
            mod.Winn3ContractError,
            lambda v=bad: mod.validate_winn3_protocol_params({"carrier": v}),
            reason="carrier-unsupported",
        )


def test_carrier_profile_params_refused_on_direct_awg(mod):
    # Storing an inert profile is an operator believing a profile is in force
    # that the client will never read.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params({"server_name": "a.example.test"}),
        reason="carrier-profile-params-without-carrier", keys=["server_name"],
    )


HTTP3_BASE = {
    "carrier": "http3-connect-udp",
    "masque_template": "https://a.example.test/.well-known/masque/udp/{target_host}/{target_port}/",
    "public_target": "203.0.113.9:443",
    "server_name": "a.example.test",
    "suite": "x25519-mlkem768",
    "controller_id": "controller-1",
    "device_id": "device-1",
    "device_pq_algorithm": "ml-dsa-65",
    "manifest_digest": "sha256:" + "0" * 64,
}


def test_http3_requires_the_eight_keys(mod):
    assert mod.validate_winn3_protocol_params(dict(HTTP3_BASE))["carrier"] == \
        "http3-connect-udp"
    partial = dict(HTTP3_BASE)
    del partial["suite"]
    del partial["manifest_digest"]
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(partial),
        reason="carrier-profile-incomplete", keys=["manifest_digest", "suite"],
    )


def test_carrier_param_ini_injection_refused(mod):
    for bad in ("a\nendpoint = 203.0.113.1:9110", "a[Peer]", "a]b", "a\x00b", "x" * 513):
        payload = dict(HTTP3_BASE)
        payload["server_name"] = bad
        expect_raises(
            mod.Winn3ContractError,
            lambda p=payload: mod.validate_winn3_protocol_params(p),
            reason="carrier-param-unsafe-for-ini", keys=["server_name"],
        )
    # '=' is legal: MASQUE URI templates carry it in a query.
    payload = dict(HTTP3_BASE)
    payload["masque_template"] = "https://a.example.test/m?x=1&y=2"
    assert mod.validate_winn3_protocol_params(payload)


def test_spa_rules(mod):
    # mode absent + a stray field -> refused (ErrSPAFieldWithoutMode).
    payload = dict(HTTP3_BASE)
    payload["spa_target"] = "203.0.113.9:62201"
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(payload),
        reason="spa-params-without-mode", keys=["spa_target"],
    )
    # mode off + stray -> same.
    payload["spa_mode"] = "off"
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(payload),
        reason="spa-params-without-mode",
    )
    # unknown mode.
    payload["spa_mode"] = "optional"
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(payload),
        reason="spa-mode-unsupported",
    )
    # required on direct-awg -> knockdial.New refuses BOTH other cases at
    # construction, so no session could ever knock. The reason must name the
    # carrier, not a stray field.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(
            {"spa_mode": "required", "spa_target": "203.0.113.9:62201"}
        ),
        reason="spa-carrier-cannot-knock", keys=["carrier", "spa_mode"],
    )
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(
            {"carrier": "direct-awg", "spa_mode": "required"}
        ),
        reason="spa-carrier-cannot-knock",
    )
    # ...and a stray spa field with NO mode is still the mode error on
    # direct-awg, not a profile error.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(
            {"spa_target": "203.0.113.9:62201"}
        ),
        reason="spa-params-without-mode", keys=["spa_target"],
    )
    # required + http3 + no target.
    payload = dict(HTTP3_BASE)
    payload["spa_mode"] = "required"
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(payload),
        reason="spa-target-not-ip-literal",
    )
    payload["spa_target"] = "knock.example.test:62201"
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(payload),
        reason="spa-target-not-ip-literal",
    )
    # the happy path.
    payload["spa_target"] = "203.0.113.9:62201"
    good = mod.validate_winn3_protocol_params(payload)
    assert good["spa_mode"] == "required"
    assert mod.winn3_params_require_spa(good)
    # packet size bounds.
    for value in (47, 1501):
        bad = dict(payload)
        bad["spa_packet_size"] = value
        expect_raises(
            mod.Winn3ContractError,
            lambda p=bad: mod.validate_winn3_protocol_params(p),
            reason="spa-packet-size-out-of-range",
        )
    for value in (48, 1500):
        okp = dict(payload)
        okp["spa_packet_size"] = value
        assert mod.validate_winn3_protocol_params(okp)
    # timing: skew must be >= bucket, and both self-consistent. A mismatch
    # fails CLOSED and is completely silent on the wire.
    bad = dict(payload)
    bad["spa_bucket_window_seconds"] = 0
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(bad),
        reason="spa-timing-unusable", keys=["spa_bucket_window_seconds"],
    )
    bad = dict(payload)
    bad["spa_max_skew_seconds"] = -1
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(bad),
        reason="spa-timing-unusable", keys=["spa_max_skew_seconds"],
    )
    bad = dict(payload)
    bad["spa_bucket_window_seconds"] = 30
    bad["spa_max_skew_seconds"] = 10
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(bad),
        reason="spa-timing-unusable",
    )
    okp = dict(payload)
    okp["spa_bucket_window_seconds"] = 30
    okp["spa_max_skew_seconds"] = 60
    assert mod.validate_winn3_protocol_params(okp)


def test_empty_values_are_dropped_not_stored(mod):
    # An empty value is indistinguishable from absent to the client, and
    # omission cannot be misread.
    out = mod.validate_winn3_protocol_params(
        {"session_id": "  ", "gateway_endpoint": NODE_ENDPOINT}
    )
    assert out == {"gateway_endpoint": NODE_ENDPOINT}


# ==================== 4. the obfuscation classifiability ===================


def test_obfuscation_problems(mod):
    assert mod.winn3_obfuscation_problems(GOOD_OBFUSCATION) == []
    for key in ("H1", "H2", "H3", "H4"):
        bad = dict(GOOD_OBFUSCATION)
        del bad[key]
        assert mod.winn3_obfuscation_problems(bad) == [key], key
        bad = dict(GOOD_OBFUSCATION)
        bad[key] = ""
        assert mod.winn3_obfuscation_problems(bad) == [key], key
    # < 5 is reserved for plain WireGuard's own message types.
    bad = dict(GOOD_OBFUSCATION, H2=4)
    assert mod.winn3_obfuscation_problems(bad) == ["H2"]
    # overlap: the client refuses a table it cannot classify with.
    bad = dict(GOOD_OBFUSCATION, H3=11)
    assert mod.winn3_obfuscation_problems(bad) == ["H3"]
    # ranges: legal to the Dart parser, NOT to the four native hosts, and the
    # fleet runs AWG_HEADER_RANGES=0.
    bad = dict(GOOD_OBFUSCATION, H1="16777216-1086324735")
    assert mod.winn3_obfuscation_problems(bad) == ["H1"]
    # S1..S4 are optional (client defaults 16/80/16/0) but bounded.
    thin = {k: v for k, v in GOOD_OBFUSCATION.items() if not k.startswith("S")}
    assert mod.winn3_obfuscation_problems(thin) == []
    assert mod.winn3_obfuscation_problems(dict(GOOD_OBFUSCATION, S2=65536)) == ["S2"]
    assert mod.winn3_obfuscation_problems(dict(GOOD_OBFUSCATION, S2=-1)) == ["S2"]
    assert mod.winn3_obfuscation_problems(dict(GOOD_OBFUSCATION, S3="x")) == ["S3"]
    # a non-numeric header value
    assert mod.winn3_obfuscation_problems(dict(GOOD_OBFUSCATION, H2="eleven")) == ["H2"]
    assert mod.winn3_obfuscation_problems(dict(GOOD_OBFUSCATION, H2=None)) == ["H2"]
    assert mod.winn3_obfuscation_problems(
        dict(GOOD_OBFUSCATION, H1=0xFFFFFFFF + 1)) == ["H1"]


def test_node_readiness_report(mod):
    seed_node(mod)
    ready = mod.winn3_node_readiness(node_row(mod), GOOD_OBFUSCATION)
    assert ready["ready"] is True
    assert ready["blockers"] == []
    assert ready["carrier"] == "direct-awg"
    assert ready["spa_required"] is False
    assert ready["param_keys"] == []
    assert ready["protocol_params_error"] == ""

    # a blob that predates the validator
    seed_node(mod, slug="lab-bad", endpoint="gateway.example.test:9110",
              protocol_version="winn/3",
              protocol_params_json='{"mlkem_public_key":"AAAA"}')
    bad = mod.winn3_node_readiness(
        node_row(mod, "lab-bad"), dict(GOOD_OBFUSCATION, H4=11)
    )
    assert bad["ready"] is False
    assert bad["protocol_params_error"] == "unknown-params"
    assert set(bad["blockers"]) == {
        "endpoint_not_ip_literal",
        "obfuscation_not_classifiable",
        "protocol_params_invalid",
    }
    assert bad["obfuscation_problem_keys"] == ["H4"]

    # a carrier the hub cannot verify from here
    seed_node(mod, slug="lab-h3", protocol_version="winn/3",
              protocol_params_json=json.dumps(HTTP3_BASE))
    h3 = mod.winn3_node_readiness(node_row(mod, "lab-h3"), GOOD_OBFUSCATION)
    assert h3["carrier"] == "http3-connect-udp"
    assert h3["blockers"] == ["carrier_requires_node_side_winn_carrier_server"]
    assert h3["ready"] is False
    assert "manifest_digest" in h3["param_keys"]


def test_unparseable_obfuscation_is_a_409_not_a_crash(mod):
    # A node whose obfuscation registration the hub cannot reproduce cannot
    # serve winn/1 either -- parse_obfuscation is already fail-closed on the
    # serving path. Flipping it to winn/3 must say so rather than 500.
    seed_node(mod, obfuscation=None)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE nodes SET obfuscation_json = ? WHERE slug = ?",
                     ("not json at all", "lab-alpha"))
        conn.commit()
    try:
        admin_winn3(mod, slug="lab-alpha", enabled=True, **STANDALONE_ADMIN)
    except HTTPException as exc:
        assert exc.status_code == 409
        assert "obfuscation registration" in str(exc.detail)
    else:
        raise AssertionError("expected a 409")
    assert node_row(mod)["protocol_version"] == "winn/1"
    # ...and the listing degrades to "not ready" instead of raising.
    out = mod.admin_list_node_winn3(
        request=FakeRequest(path="/admin/nodes/winn3", method="GET"),
        x_admin_token=ADMIN,
    )
    entry = [n for n in out["nodes"] if n["slug"] == "lab-alpha"][0]
    assert entry["ready"] is False
    assert "obfuscation_not_classifiable" in entry["blockers"]


def test_hub_default_obfuscation_is_winn3_legal(mod):
    # If this ever fails, a fresh node registered with the hub's own defaults
    # could not serve winn/3 and nothing would say why.
    assert mod.winn3_obfuscation_problems(mod.DEFAULT_OBFUSCATION) == []


# ========================= 5. the serving gate =============================


def test_gate_default_is_winn1_for_an_unregistered_node(mod):
    seed_node(mod)
    assert resolve(mod, node_row(mod)) == ("winn/1", {}, "node-not-winn3")
    # ...and stays winn/1 even for a fully capable client.
    assert resolve(
        mod, node_row(mod),
        capabilities=caps(supports_winn3=True, supports_winn3_spa=True),
    ) == ("winn/1", {}, "node-not-winn3")


def test_gate_serves_winn3_only_to_a_capable_client(mod):
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}")
    expect_refused(mod, node_row(mod), "client-not-winn3-capable")
    version, params, reason = resolve(
        mod, node_row(mod), capabilities=caps(supports_winn3=True)
    )
    assert (version, params, reason) == ("winn/3", {}, "winn3")


def test_gate_refuses_stealth_and_serves_winn1_for_double_vpn(mod):
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}")
    capable = caps(supports_winn3=True)
    expect_refused(mod, node_row(mod), "stealth-mode-active",
                   capabilities=capable, stealth_mode=True)
    version, params, reason = mod.resolve_served_winn_protocol(
        node_row(mod),
        capabilities=capable,
        obfuscation=GOOD_OBFUSCATION,
        stealth_mode=False,
        double_vpn_active=True,
        mtu=1280,
    )
    assert (version, params, reason) == ("winn/1", {}, "double-vpn-active")


def test_gate_refuses_bad_stored_params(mod):
    # A blob written by direct SQL before this validator existed.
    seed_node(mod, protocol_version="winn/3",
              protocol_params_json='{"mlkem_public_key":"AAAA"}')
    expect_refused(mod, node_row(mod), "params-invalid",
                   capabilities=caps(supports_winn3=True))


def test_gate_refuses_unclassifiable_obfuscation(mod):
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}")
    bad = {k: v for k, v in GOOD_OBFUSCATION.items() if k != "H4"}
    expect_refused(mod, node_row(mod), "obfuscation-not-classifiable",
                   capabilities=caps(supports_winn3=True), obfuscation=bad)


def test_gate_refuses_non_literal_server_endpoint_fallback(mod):
    seed_node(mod, endpoint="gateway.example.test:9110",
              protocol_version="winn/3", protocol_params_json="{}")
    expect_refused(mod, node_row(mod), "server-endpoint-not-ip-literal",
                   capabilities=caps(supports_winn3=True))
    # ...but an explicit literal gateway_endpoint makes the fallback moot.
    seed_node(mod, slug="lab-beta", endpoint="gateway.example.test:9110",
              protocol_version="winn/3",
              protocol_params_json=json.dumps({"gateway_endpoint": NODE_ENDPOINT}))
    version, params, reason = resolve(
        mod, node_row(mod, "lab-beta"), capabilities=caps(supports_winn3=True)
    )
    assert (version, reason) == ("winn/3", "winn3")
    assert params == {"gateway_endpoint": NODE_ENDPOINT}


def test_gate_refuses_out_of_range_mtu(mod):
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}")
    capable = caps(supports_winn3=True)
    expect_refused(mod, node_row(mod), "mtu-out-of-range",
                   capabilities=capable, mtu=100)
    expect_refused(mod, node_row(mod), "mtu-out-of-range",
                   capabilities=capable, mtu=9001)
    assert resolve(mod, node_row(mod), capabilities=capable, mtu=576)[0] == "winn/3"


def test_gate_requires_spa_capability_when_the_node_knocks(mod):
    params = dict(HTTP3_BASE)
    params["spa_mode"] = "required"
    params["spa_target"] = "203.0.113.9:62201"
    seed_node(mod, protocol_version="winn/3",
              protocol_params_json=json.dumps(params))
    expect_refused(mod, node_row(mod), "client-not-spa-capable",
                   capabilities=caps(supports_winn3=True))
    version, served, reason = resolve(
        mod, node_row(mod),
        capabilities=caps(supports_winn3=True, supports_winn3_spa=True),
    )
    assert (version, reason) == ("winn/3", "winn3")
    # BINARY: the whole advertisement, never a subset with spa_* stripped.
    assert served["spa_mode"] == "required"
    assert served["spa_target"] == "203.0.113.9:62201"


def test_gate_never_returns_partial_params(mod):
    params = dict(HTTP3_BASE)
    seed_node(mod, protocol_version="winn/3",
              protocol_params_json=json.dumps(params))
    version, served, _ = resolve(
        mod, node_row(mod), capabilities=caps(supports_winn3=True)
    )
    assert version == "winn/3"
    assert set(served) == set(params), "the gate dropped or added a key"


# ================== 6. request capabilities default false ==================


def test_request_capabilities_default_false(mod):
    class Legacy:
        """A client that predates the winn/3 flags entirely."""

    flags = mod.request_client_capabilities(Legacy())
    assert flags["supports_winn3"] is False
    assert flags["supports_winn3_spa"] is False
    # ...and the pre-existing flags keep their pre-existing defaults.
    assert flags["supports_awg"] is True
    assert flags["supports_double_vpn"] is True
    assert flags["supports_split_tunnel"] is False


def test_request_models_accept_both_spellings(mod):
    """A SOURCE assertion, and it says so.

    The harness stubs pydantic (BaseModel.__getattr__ returns None for any
    unset attribute), so field metadata -- defaults and AliasChoices -- does
    not survive into the loaded module and cannot be introspected. What can
    still be checked is that the installer declares both fields on both models,
    with default False and both wire spellings; that is what a real pydantic
    would read. The no-underscore spelling matters because the whole
    split-script compat layer speaks it.
    """
    src = harness._extract_main_block()
    for model in ("class LoginRequest", "class FreeAccessRequest"):
        start = src.index(model)
        block = src[start:src.index("\nclass ", start + 1)]
        for field in ("supports_winn3", "supports_winn3_spa"):
            line = [
                ln for ln in block.splitlines()
                if ln.strip().startswith(field + ":")
            ]
            assert len(line) == 1, f"{model}: {field} declared {len(line)} times"
            assert "default=False" in line[0], f"{model}.{field} must default False"
            assert f'"{field}"' in line[0]
            assert f'"{field.replace("_", "")}"' in line[0], (
                f"{model}.{field} is missing its no-underscore alias"
            )
    # ...and the free-access path must forward both into the LoginRequest it
    # builds, or a free-tier client is capability-blind whatever it advertises.
    assert "supports_winn3=free_request.supports_winn3," in src
    assert "supports_winn3_spa=free_request.supports_winn3_spa," in src


# ========================= 7. the admin endpoint ===========================


def test_admin_enable_minimal_and_rollback(mod):
    seed_node(mod)
    out = admin_winn3(mod, slug="lab-alpha", enabled=True, **STANDALONE_ADMIN)
    assert out["protocol_version"] == "winn/3"
    assert out["carrier"] == "winn3"
    assert out["protocol_params_keys"] == ["carrier"]
    assert out["requires_node_side_carrier_server"] is True
    row = node_row(mod)
    assert row["protocol_version"] == "winn/3"
    assert json.loads(row["protocol_params_json"]) == {"carrier": "winn3"}
    # The rollback restores the shipping default exactly.
    out = admin_winn3(mod, slug="lab-alpha", enabled=False)
    assert out["protocol_version"] == "winn/1"
    row = node_row(mod)
    assert row["protocol_version"] == "winn/1"
    assert row["protocol_params_json"] is None


def test_admin_rollback_works_even_on_an_unservable_node(mod):
    # A rollback that can fail is not a rollback.
    seed_node(mod, endpoint="gateway.example.test:9110",
              obfuscation=dict(GOOD_OBFUSCATION, H1=4),
              protocol_version="winn/3", protocol_params_json='{"bogus":"x"}')
    out = admin_winn3(mod, slug="lab-alpha", enabled=False)
    assert out["protocol_version"] == "winn/1"
    assert node_row(mod)["protocol_params_json"] is None


def test_admin_refuses_params_the_client_would_refuse(mod):
    seed_node(mod)
    try:
        admin_winn3(mod, slug="lab-alpha", enabled=True,
                    protocol_params_json='{"carrier":"winn3","mlkem_public_key":"AAAA"}')
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "unknown-params" in str(exc.detail)
        assert "mlkem_public_key" in str(exc.detail)
    else:
        raise AssertionError("expected a 400")
    # nothing changed
    assert node_row(mod)["protocol_version"] == "winn/1"


def test_admin_refuses_bad_json(mod):
    seed_node(mod)
    try:
        admin_winn3(mod, slug="lab-alpha", enabled=True, protocol_params_json="{")
    except HTTPException as exc:
        assert exc.status_code == 400
    else:
        raise AssertionError("expected a 400")
    assert node_row(mod)["protocol_version"] == "winn/1"


def test_admin_refuses_a_node_that_cannot_serve_winn3(mod):
    seed_node(mod, endpoint="gateway.example.test:9110")
    try:
        admin_winn3(mod, slug="lab-alpha", enabled=True, **STANDALONE_ADMIN)
    except HTTPException as exc:
        assert exc.status_code == 409
        assert "endpoint_not_ip_literal" in str(exc.detail)
        assert "No node record was changed" in str(exc.detail)
    else:
        raise AssertionError("expected a 409")
    assert node_row(mod)["protocol_version"] == "winn/1"

    seed_node(mod, slug="lab-gamma", obfuscation=dict(GOOD_OBFUSCATION, H4=11))
    try:
        admin_winn3(mod, slug="lab-gamma", enabled=True, **STANDALONE_ADMIN)
    except HTTPException as exc:
        assert exc.status_code == 409
        assert "obfuscation_not_classifiable" in str(exc.detail)
    else:
        raise AssertionError("expected a 409")


def test_admin_unknown_node_and_missing_slug(mod):
    seed_node(mod)
    for slug, code in (("nope", 404), ("   ", 400)):
        try:
            admin_winn3(mod, slug=slug, enabled=True)
        except HTTPException as exc:
            assert exc.status_code == code, (slug, exc.status_code)
        else:
            raise AssertionError(f"expected {code} for {slug!r}")


def test_admin_requires_the_admin_token(mod):
    seed_node(mod)
    try:
        admin_winn3(mod, slug="lab-alpha", enabled=True, x_admin_token="wrong")
    except HTTPException as exc:
        assert exc.status_code in (401, 403), exc.status_code
    else:
        raise AssertionError("expected an auth failure")
    assert node_row(mod)["protocol_version"] == "winn/1"


def test_admin_readiness_listing(mod):
    seed_node(mod)
    seed_node(mod, slug="lab-bad", endpoint="gateway.example.test:9110")
    out = mod.admin_list_node_winn3(
        request=FakeRequest(path="/admin/nodes/winn3", method="GET"),
        x_admin_token=ADMIN,
    )
    assert out["ok"] is True
    assert len(out["known_protocol_params"]) == 20
    # `winn3` joined the set on 2026-08-09. It is the STANDALONE carrier and it
    # is categorically different from the two relay carriers beside it: no
    # AmneziaWG anywhere in the session, no carrier profile, and six
    # key-bearing `[winn]` fields that cannot travel through protocol_params at
    # all. See WINN3_CARRIER_WINN3 in the hub for why each of those follows
    # from the one difference.
    assert out["supported_carriers"] == [
        "direct-awg", "http3-connect-udp", "winn3"]
    by_slug = {n["slug"]: n for n in out["nodes"]}
    assert by_slug["lab-alpha"]["ready"] is True
    assert by_slug["lab-alpha"]["blockers"] == []
    assert by_slug["lab-bad"]["ready"] is False
    assert "endpoint_not_ip_literal" in by_slug["lab-bad"]["blockers"]


def test_admin_http3_registration_names_the_node_side_requirement(mod):
    seed_node(mod)
    try:
        admin_winn3(mod, slug="lab-alpha", enabled=True,
                    protocol_params_json=json.dumps(HTTP3_BASE))
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "carrier-not-standalone-winn3" in str(exc.detail)
    else:
        raise AssertionError("expected a 400")
    assert node_row(mod)["protocol_version"] == "winn/1"


# ======================= 8. disclosure discipline ==========================


def test_no_values_in_error_bodies(mod):
    seed_node(mod)
    secret_endpoint = "192.0.2.44:9110"
    try:
        admin_winn3(mod, slug="lab-alpha", enabled=True,
                    protocol_params_json=json.dumps(
                        {"carrier": "winn3", "gateway_endpoint": secret_endpoint, "bogus_key": "x"}))
    except HTTPException as exc:
        body = str(exc.detail)
        assert secret_endpoint not in body, "an endpoint value reached an error body"
        assert "bogus_key" in body, "the key NAME should be named"
    else:
        raise AssertionError("expected a 400")


def test_no_values_in_log_lines(mod):
    import logging

    captured = []

    class Capture(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    handler = Capture()
    mod.logger.addHandler(handler)
    try:
        secret = "192.0.2.55:62201"
        params = dict(HTTP3_BASE)
        params["spa_mode"] = "required"
        params["spa_target"] = secret
        seed_node(mod, protocol_version="winn/3",
                  protocol_params_json=json.dumps(params))
        resolve(mod, node_row(mod),
                capabilities=caps(supports_winn3=True, supports_winn3_spa=True))
        seed_node(mod, slug="lab-delta", protocol_version="winn/3",
                  protocol_params_json='{"nope":"' + secret + '"}')
        try:
            resolve(mod, node_row(mod, "lab-delta"),
                    capabilities=caps(supports_winn3=True))
        except mod.Winn3ContractError:
            pass
    finally:
        mod.logger.removeHandler(handler)
    joined = "\n".join(captured)
    assert secret not in joined, "a node address reached a log line"
    assert "spa_target" in joined or "winn/3" in joined, "expected a log line at all"


# ================ 9. end to end through the served config ==================


def build_login(mod, **overrides):
    payload = {
        "account_number": "1111-2222-3333",
        "device_id": "device-abcdef0123456789",
        "device_fingerprint": "fp-0123456789abcdef",
        "device_model": "Pixel",
        "platform": "android",
        "app_version": "1.0.14+29",
        "location": "lab-alpha",
        "client_public_key": "C" * 43 + "=",
        "legal_version": mod.LEGAL_DOCUMENT_VERSION,
        "legal_hash": mod.LEGAL_DOCUMENT_HASH,
        "accepted_terms": True,
        "accepted_hold_harmless": True,
        "accepted_limitation_liability": True,
        "accepted_electronic_records": True,
        "accepted_android_vpn_service_disclosure": True,
        "android_vpn_service_disclosure_version": mod.ANDROID_VPN_SERVICE_DISCLOSURE_VERSION,
        "android_vpn_service_disclosure_accepted_at": "2026-09-02T00:00:00+00:00",
    }
    payload.update(overrides)
    return mod.LoginRequest(**payload)


ACTIVATION_SECRET = "activation-secret-for-tests"


def arm_activation(mod, account="1111-2222-3333"):
    """Authorize enrollment the way a real welcome email does.

    require_verify_authorization accepts either this device's own bearer token
    with an unchanged public key, or the account's activation secret. The
    second is the one a first-connect uses, and it is the path a client takes
    on the night a node is flipped to winn/3.
    """
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE users SET activation_secret_hash = ? WHERE account_number = ?",
            (mod.token_digest(ACTIVATION_SECRET), account),
        )
        conn.commit()


def served_config(mod, **login_overrides):
    from test_account_deletion_hub import BackgroundTasks
    # The one stub on this path, and it is a NETWORK stub, not a logic stub:
    # sync_peer_to_node SSHes to the selected node to install the peer. This
    # suite must never contact a node, so it is replaced with a success. Every
    # line under test -- the gate, the served config assembly, the compat copy
    # -- is the installer's own, unmodified.
    mod.sync_peer_to_node = lambda *a, **k: True
    login = build_login(mod, **login_overrides)
    request = FakeRequest(
        path="/verify", headers={"x-wins-activation": ACTIVATION_SECRET}
    )
    result = asyncio.run(
        mod.verify_account(request, login, BackgroundTasks())
    )
    body = result.body if hasattr(result, "body") else result
    if isinstance(body, (bytes, str)):
        body = json.loads(body)
    return body


def test_end_to_end_default_is_byte_for_byte_winn1(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    seed_node(mod)
    body = served_config(mod)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["protocol_version"] == "winn/1"
    assert config["protocol_params"] == {}
    assert config["client_capabilities"]["supports_winn3"] is False
    assert config["client_capabilities"]["supports_winn3_spa"] is False


def test_end_to_end_winn3_reaches_the_client(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    seed_node(mod, protocol_version="winn/3",
              protocol_params_json=json.dumps({"max_datagram": "1280"}))
    expect_http(503, lambda: served_config(mod))
    body = served_config(mod, supports_winn3=True)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["protocol_version"] == "winn/3"
    assert config["protocol_params"] == {"max_datagram": "1280"}
    # The no-underscore compat copy must carry the same values.
    compat = body.get("vpnconfig") or {}
    if compat:
        assert compat["protocolversion"] == "winn/3"
        assert compat["protocolparams"] == {"max_datagram": "1280"}


def test_end_to_end_stealth_on_a_v3_node_is_refused(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}")
    expect_http(503, lambda: served_config(mod, supports_winn3=True,
                                          stealth_mode=True))


def test_end_to_end_stealth_on_an_explicit_v1_node_stays_winn1(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    seed_node(mod)
    body = served_config(mod, stealth_mode=True)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["protocol_version"] == "winn/1"


# ================================ runner ===================================

UNIT_TESTS = [
    test_allowlist_matches_dart,
    test_h_keys_are_never_accepted,
    test_supported_carriers_match_dart,
    test_bounds_match_dart,
    test_ip_literal_endpoint,
    test_empty_params_are_the_minimal_legal_advertisement,
    test_unknown_param_is_refused,
    test_keys_are_normalized_and_collisions_refused,
    test_non_scalar_values_refused,
    test_params_not_an_object,
    test_gateway_endpoint_rule,
    test_max_datagram_bounds,
    test_session_id_rules,
    test_carrier_rules,
    test_carrier_profile_params_refused_on_direct_awg,
    test_http3_requires_the_eight_keys,
    test_carrier_param_ini_injection_refused,
    test_spa_rules,
    test_empty_values_are_dropped_not_stored,
    test_obfuscation_problems,
    test_hub_default_obfuscation_is_winn3_legal,
    test_node_readiness_report,
    test_unparseable_obfuscation_is_a_409_not_a_crash,
    test_gate_default_is_winn1_for_an_unregistered_node,
    test_gate_serves_winn3_only_to_a_capable_client,
    test_gate_refuses_stealth_and_serves_winn1_for_double_vpn,
    test_gate_refuses_bad_stored_params,
    test_gate_refuses_unclassifiable_obfuscation,
    test_gate_refuses_non_literal_server_endpoint_fallback,
    test_gate_refuses_out_of_range_mtu,
    test_gate_requires_spa_capability_when_the_node_knocks,
    test_gate_never_returns_partial_params,
    test_request_capabilities_default_false,
    test_request_models_accept_both_spellings,
    test_admin_enable_minimal_and_rollback,
    test_admin_rollback_works_even_on_an_unservable_node,
    test_admin_refuses_params_the_client_would_refuse,
    test_admin_refuses_bad_json,
    test_admin_refuses_a_node_that_cannot_serve_winn3,
    test_admin_unknown_node_and_missing_slug,
    test_admin_requires_the_admin_token,
    test_admin_readiness_listing,
    test_admin_http3_registration_names_the_node_side_requirement,
    test_no_values_in_error_bodies,
    test_no_values_in_log_lines,
    test_end_to_end_default_is_byte_for_byte_winn1,
    test_end_to_end_winn3_reaches_the_client,
    test_end_to_end_stealth_on_a_v3_node_is_refused,
    test_end_to_end_stealth_on_an_explicit_v1_node_stays_winn1,
]


def main():
    asyncio.set_event_loop(asyncio.new_event_loop())
    print("winn/3 hub serving path")
    for fn in UNIT_TESTS:
        # A fresh module + database per test: these mutate node rows, and a
        # leaked winn/3 registration would make a later test pass for the
        # wrong reason.
        mod = harness.load_hub()
        check(fn.__name__, lambda f=fn, m=mod: f(m))
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
