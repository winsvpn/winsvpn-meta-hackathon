#!/usr/bin/env python3
"""Hub tests for the standalone Winn v3 control-plane binding.

Signed node descriptors and admission-key rotation. Like
test_winn3_serving_hub.py, test_account_deletion_hub.py,
test_donor_acknowledgment_hub.py and test_emergency_dispatch_hub.py these
exercise the REAL control-plane source: the module is extracted from the
`cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc inside
wins_control_plane_setup_ONETOUCH.sh and exec'd with stubs for its three
third-party imports. Nothing here is a reimplementation, so a regression in the
shipped installer fails these tests.

Signatures are produced by REAL openssl(1) at test time, never by fixtures
pasted from somewhere -- the hub verifies with openssl, so a suite that signed
with anything else would be testing its own arithmetic. `openssl genpkey
-algorithm ED25519` runs once per signing test.

No test contacts a node, a live hub, or the network.

WHAT IS UNDER TEST, and why each is a safety property rather than a nicety:

  * THE NO-OP DEFAULT. A node with no descriptor, served to a client that
    advertises nothing, must produce EXACTLY the config this hub serves today.
    Every other property here is additive and reversible; this is what makes
    that true.
  * THE DESCRIPTOR IS NOT A protocol_params KEY. That surface is a closed
    twenty-key allowlist whose one inviolable rule is that nothing key-shaped
    is ever served through it. The admission secret is key-shaped by
    definition. test_param_names_that_are_never_served makes the rule
    machine-checkable instead of a convention.
  * CORE CONSTANTS DO NOT DRIFT. Every bound the hub enforces on a descriptor
    is a copy of a constant in winn_protocol_experimental/winn3/core/params.go.
    A second hand-maintained copy that silently disagrees with the
    implementation is the failure that made single-packet authorization
    unreachable from every platform at once; test_core_constants_do_not_drift
    is the guard against a repeat.
  * THE FRESHNESS SPAN AND THE RETIREMENT FLOOR ARE THE SAME NUMBER. core sets
    the handshake replay-cache lifetime to (2*spread+1)*window
    (handshake.go:494-506) and that is also the span over which a captured
    initiation still verifies. The hub's retirement floor is computed from that
    same function, so widening max_skew moves both and they cannot separate.
  * REFUSAL SEMANTICS ARE NOT WEAKENED. The descriptor is served strictly
    downstream of resolve_served_winn_protocol, so stealth_active -- a
    PER-REQUEST choice -- refuses both at once, with no second gate that could
    disagree with the first.
  * NO SECRET IN A LOG LINE OR AN ERROR BODY. The admission secret is the
    per-gateway key the whole standalone design's unlinkability rests on.

Run:  python3 server/test_winn3_descriptor_hub.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import asyncio
import base64
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_DIR = os.path.join(
    REPO_ROOT, "winn_protocol_experimental", "winn3", "core")
ADMIN = "test-admin-token"

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
GATEWAY_ENDPOINT = "198.51.100.7:51820"
OTHER_ENDPOINT = "203.0.113.9:51820"

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
        assert exc.status_code == status, f"expected {status}, got {exc.status_code}"
        return exc
    raise AssertionError(f"expected HTTPException {status}, nothing was raised")


# ============================ signing fixtures =============================
#
# One Ed25519 key pair per slot, generated by openssl at import. The hub
# verifies with openssl, so signing with openssl is the only way this suite
# proves the real verification path rather than its own idea of one.

_KEYDIR = tempfile.mkdtemp(prefix="winn3desc-keys-")
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _generate_slot(slot):
    key_path = os.path.join(_KEYDIR, f"{slot}.pem")
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", key_path],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    der = subprocess.run(
        ["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    assert der.startswith(_ED25519_SPKI_PREFIX) and len(der) == 44, len(der)
    return key_path, base64.b64encode(der[-32:]).decode()


SLOT_KEYS = {}
SLOT_PUBS = {}
for _slot in ("g1", "g2", "g3"):
    SLOT_KEYS[_slot], SLOT_PUBS[_slot] = _generate_slot(_slot)


def sign_bytes(message, slot="g1"):
    """Detached Ed25519 signature over `message`, by real openssl."""
    with tempfile.TemporaryDirectory() as work:
        msg_path = os.path.join(work, "m.bin")
        with open(msg_path, "wb") as handle:
            handle.write(message)
        return subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin",
             "-inkey", SLOT_KEYS[slot], "-in", msg_path],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def load_hub_with_ring(slots=("g1", "g2", "g3"), **env):
    """A hub whose descriptor verification ring holds the named slots.

    Slots not named are actively CLEARED, not merely omitted -- os.environ is
    process-wide and a leaked key from an earlier test would make a later one
    pass for the wrong reason.
    """
    for slot in ("g1", "g2", "g3"):
        os.environ.pop(f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}", None)
    settings = {
        f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}": SLOT_PUBS[slot]
        for slot in slots
    }
    settings.update({k: str(v) for k, v in env.items()})
    return harness.load_hub(**settings)


# ============================== fixtures ==================================

DESCRIPTOR_DOMAIN = b"winsvpn-winn3-descriptor/v1"


# FORMAT VERSION 3, 2026-08-12. `inner_resolver_v4` joined the closed field set
# beside `inner_router_v4`, and `v` is inside the signed bytes, so every fixture
# below is a v3 descriptor and a v1 or v2 one is now exactly as invalid here as
# it is in production. (Fixtures updated 2026-08-12, lane d15_pool_validator:
# the hub half of this bump had landed and the fixture half had not, which left
# 46 of 83 tests here failing on `descriptor-missing-fields
# (inner_resolver_v4)`. No hub gate was relaxed to close that gap.)
#
# BOTH live inside the hub's default WINN3_INNER_POOL_CIDR (10.10.0.0/24) on
# purpose: the serving path refuses a descriptor whose inner next hop or inner
# resolver is outside the pool the hub allocates client addresses from, because
# a client in a different inner space than its gateway establishes a session and
# then carries nothing, with no error at either end. (The pool is /24, not the
# /16 this comment claimed until 2026-08-12 -- D7 pinned it and D15 pins it to
# EXACTLY /24; see the D15 section near the runner.)
#
# The shipping gateway resolver binds to -inner-v4, so the signed resolver must
# equal the signed router until a separately addressed resolver exists end to
# end. Distinct values are a signed false claim and are refused below.
INNER_ROUTER_V4 = "10.10.0.1"
INNER_RESOLVER_V4 = INNER_ROUTER_V4


def descriptor_payload(*, node="lab-alpha", gen=1, seq=1, iat=None,
                       ttl=None, endpoint=GATEWAY_ENDPOINT, kid="g1",
                       tag_size=32, padding="bucket", window=10, skew=60,
                       secret_bytes=64, static_bytes=32, gateway_id_bytes=16,
                       alg="ed25519", v=3, inner_router_v4=INNER_ROUTER_V4,
                       inner_resolver_v4=INNER_RESOLVER_V4,
                       drop=(), extra=None):
    # Fixtures are minted relative to now(): a hardcoded iat expires the whole
    # suite the day it passes (B-3). iat defaults to one minute ago so tests
    # that pass an explicit ttl (3600, 7200, ...) still yield a not_after in
    # the future; the default ttl keeps the hub's documented one-day shape
    # (the hub caps descriptor TTL at 30 days, so "now + 365 days" would be
    # refused as descriptor-ttl-too-long). Explicit iat/ttl still override
    # for the ttl-boundary and rejection tests below.
    if iat is None:
        iat = int(time.time()) - 60
    if ttl is None:
        ttl = 86400
    payload = {
        "v": v,
        "alg": alg,
        "kid": kid,
        "node": node,
        "endpoint": endpoint,
        "inner_router_v4": inner_router_v4,
        "inner_resolver_v4": inner_resolver_v4,
        "static_pub": base64.b64encode(b"S" * static_bytes).decode(),
        "gateway_id": base64.b64encode(b"G" * gateway_id_bytes).decode(),
        "admission_secret": base64.b64encode(b"a" * secret_bytes).decode(),
        "admission_gen": gen,
        "tag_size": tag_size,
        "padding": padding,
        "bucket_window_s": window,
        "max_skew_s": skew,
        "seq": seq,
        "iat": iat,
        "not_after": iat + ttl,
    }
    for key in drop:
        payload.pop(key, None)
    if extra:
        payload.update(extra)
    return payload


def dual_auth_pair():
    return (
        base64.b64encode(b"E" * 32).decode(),
        base64.b64encode(b"M" * 1952).decode(),
    )


def seed_dual_auth_node(mod, **kwargs):
    ed25519_b64, mldsa65_b64 = dual_auth_pair()
    payload = descriptor_payload(extra={
        "auth_ed25519": ed25519_b64, "auth_mldsa65": mldsa65_b64})
    payload_b64, sig_b64 = envelope_for(payload)
    kwargs.setdefault("protocol_version", "winn/3")
    kwargs.setdefault("protocol_params_json", "{}")
    node = seed_node(
        mod,
        descriptor_json=json.dumps({"payload": payload_b64, "sig": sig_b64}),
        **kwargs)
    return node, payload_b64, sig_b64, ed25519_b64, mldsa65_b64


def envelope_for(payload, slot="g1"):
    """(payload_b64, sig_b64) over the canonical bytes, really signed."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    signature = sign_bytes(DESCRIPTOR_DOMAIN + b"\x00" + raw, slot=slot)
    return base64.b64encode(raw).decode(), base64.b64encode(signature).decode()


def seed_node(mod, *, slug="lab-alpha", endpoint=NODE_ENDPOINT,
              obfuscation=None, protocol_version="winn/1",
              protocol_params_json=None, descriptor_json=None,
              admission_json=None, free_access=1):
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
            " max_peers, peer_count, protocol_version, protocol_params_json,"
            " winn3_descriptor_json, winn3_admission_json"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                descriptor_json, admission_json,
            ),
        )
        conn.execute(
            "UPDATE nodes SET winn3_canary_status='ok', winn3_canary_ok_at=? "
            "WHERE slug=?",
            (now, slug),
        )
    return node_row(mod, slug)


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
        "supports_winn3_dualauth": False,
    }
    base.update(overrides)
    return base


def admin_descriptor(mod, **kwargs):
    kwargs.setdefault("x_admin_token", ADMIN)
    kwargs.setdefault(
        "request", FakeRequest(path="/admin/nodes/winn3/descriptor"))
    return mod.admin_set_node_winn3_descriptor(**kwargs)


def admin_list_descriptors(mod, **kwargs):
    kwargs.setdefault("x_admin_token", ADMIN)
    kwargs.setdefault(
        "request", FakeRequest(path="/admin/nodes/winn3/descriptor"))
    return mod.admin_list_node_winn3_descriptors(**kwargs)


def admin_retire(mod, **kwargs):
    kwargs.setdefault("x_admin_token", ADMIN)
    kwargs.setdefault(
        "request", FakeRequest(path="/admin/nodes/winn3/admission/retire"))
    return mod.admin_retire_node_winn3_previous_admission(**kwargs)


def install(mod, payload, slot="g1", slug="lab-alpha"):
    payload_b64, sig_b64 = envelope_for(payload, slot=slot)
    return admin_descriptor(
        mod, slug=slug, enabled=True,
        descriptor_payload_b64=payload_b64, descriptor_sig_b64=sig_b64)


# ================== 1. the drift guards (the discipline) ==================


def _core_source(name):
    with open(os.path.join(CORE_DIR, name), "r", encoding="utf-8") as handle:
        return handle.read()


def _go_const_int(src, name):
    match = re.search(
        rf"^\s*{re.escape(name)}\s*(?:[a-zA-Z0-9_\[\]]+\s*)?=\s*([0-9]+)",
        src, re.MULTILINE)
    assert match, f"{name} not found in the Go source"
    return int(match.group(1))


def _go_const_duration_seconds(src, name):
    match = re.search(
        rf"^\s*{re.escape(name)}\s*=\s*([0-9]+)\s*\*\s*time\.(Second|Minute)",
        src, re.MULTILINE)
    assert match, f"{name} not found in the Go source"
    scale = 1 if match.group(2) == "Second" else 60
    return int(match.group(1)) * scale


def test_core_constants_do_not_drift(mod):
    """Every bound the hub enforces is a copy of a core constant.

    Parsed out of winn3/core/params.go, not restated. This is the same
    discipline as test_winn3_serving_hub.py::test_allowlist_matches_dart and it
    exists for the same reason: the hub refusing a descriptor the gateway would
    have accepted, or accepting one it will not, is a silent outage on a path
    where the gateway answers nothing.
    """
    params = _core_source("params.go")
    assert mod.WINN3_MIN_TAG_SIZE == _go_const_int(params, "MinTagSize")
    assert mod.WINN3_MAX_TAG_SIZE == _go_const_int(params, "MaxTagSize")
    assert mod.WINN3_DEFAULT_TAG_SIZE == _go_const_int(params, "DefaultTagSize")
    assert mod.WINN3_MIN_ADMISSION_SECRET_BYTES == _go_const_int(
        params, "minAdmissionKeySize")
    assert mod.WINN3_MAX_BUCKET_CANDIDATES == _go_const_int(
        params, "maxBucketCandidates")
    assert mod.WINN3_MAX_HANDSHAKE_MESSAGE == _go_const_int(
        params, "MaxHandshakeMessage")
    assert mod.WINN3_DEFAULT_BUCKET_WINDOW_SECONDS == _go_const_duration_seconds(
        params, "DefaultBucketWindow")
    assert mod.WINN3_DEFAULT_MAX_SKEW_SECONDS == _go_const_duration_seconds(
        params, "DefaultMaxSkew")
    # The gateway-id bound is expressed as a comparison, not a const.
    assert "more than 255" in params and mod.WINN3_MAX_GATEWAY_ID_BYTES == 255


def test_padding_policies_match_core(mod):
    params = _core_source("params.go")
    for go_name, hub_name in (("PadNone", "none"), ("PadBucket", "bucket"),
                              ("PadMimic", "mimic")):
        assert re.search(rf"^\s*{go_name}\b", params, re.MULTILINE), go_name
        assert hub_name in mod.WINN3_PADDING_POLICIES
    assert len(mod.WINN3_PADDING_POLICIES) == 3
    assert mod.WINN3_DEFAULT_PADDING_POLICY == "bucket", (
        "core documents PadBucket as the default")


def test_freshness_geometry_matches_core(mod):
    """spread = ceil(skew/window); candidates = 2*spread+1. Exactly core's."""
    for window, skew, spread in (
        (10, 60, 6), (10, 10, 1), (10, 11, 2), (1, 1, 1), (5, 100, 20),
        (10, 100, 10), (30, 60, 2), (7, 60, 9),
    ):
        got_spread, candidates, span = mod.winn3_freshness_geometry(window, skew)
        assert got_spread == spread, (window, skew, got_spread, spread)
        assert candidates == 2 * spread + 1
        assert span == candidates * window
    # The defaults land on the number the gateway-table lane pins: 13 buckets
    # of 10 s = 130 s.
    _, candidates, span = mod.winn3_freshness_geometry(
        mod.WINN3_DEFAULT_BUCKET_WINDOW_SECONDS,
        mod.WINN3_DEFAULT_MAX_SKEW_SECONDS)
    assert candidates == 13 and span == 130


def test_acceptance_span_is_the_replay_cache_lifetime(mod):
    """The two are one formula in core; they must be one function here.

    handshake.go's NewResponder sets the handshake replay cache lifetime to
    exactly (2*spread+1)*window. If the hub's retirement arithmetic used a
    different expression for the acceptance window, the two could drift -- and
    the gap between them is a span in which a censor's recorded initiation is a
    working gateway detector again.
    """
    handshake = _core_source("handshake.go")
    assert re.search(
        r"lifetime\s*:=\s*time\.Duration\(2\*spread\+1\)\s*\*\s*window",
        handshake), "core no longer derives the cache lifetime this way"
    _, _, span = mod.winn3_freshness_geometry(10, 60)
    assert span == 13 * 10


def test_freshness_refuses_what_core_refuses(mod):
    expect_raises(mod.Winn3ContractError,
                  lambda: mod.winn3_freshness_geometry(0, 60),
                  reason="bucket-window-below-one-second")
    expect_raises(mod.Winn3ContractError,
                  lambda: mod.winn3_freshness_geometry(10, 5),
                  reason="max-skew-below-bucket-window")
    expect_raises(mod.Winn3ContractError,
                  lambda: mod.winn3_freshness_geometry(1, 10000),
                  reason="bucket-candidates-over-core-ceiling")


def test_admission_hmac_cost_is_the_product(mod):
    """keys outermost, buckets innermost, no early exit -- so it multiplies."""
    admission = _core_source("admission.go")
    assert "for ki, key := range g.AdmissionKeys" in admission
    assert "for _, b := range buckets" in admission
    assert mod.winn3_admission_hmac_cost(13, 1) == 13
    assert mod.winn3_admission_hmac_cost(13, 2) == 26
    assert mod.winn3_admission_hmac_cost(721, 2) == 1442


def test_param_names_that_are_never_served(mod):
    """The key-shaped-name discipline, made machine-checkable.

    The twenty-key allowlist already refuses all of these. This is the second,
    named line of defence added by the lane that introduced admission material
    to the hub: the failure it guards is a future maintainer widening the
    allowlist by one obviously-harmless key.
    """
    pattern = mod.WINN3_PARAM_NAME_NEVER_SERVED
    for dangerous in ("spa_key_path", "mlkem_public_key", "admission_secret",
                      "device_private_key", "pq_seed", "client_secret",
                      "preshared_key", "static_priv_seed"):
        assert pattern.search(dangerous), dangerous
    # The hole the obvious spelling has, pinned so it cannot come back: a bare
    # `_key$` anchor does NOT match spa_key_path, which is the one name this
    # surface has always had to exclude by hand.
    assert not re.compile(r"(?:_key$|secret|private|seed)").search("spa_key_path")
    assert pattern.search("spa_key_path")
    # And it must not fire on anything the hub legitimately serves, or it would
    # be a guard nobody could keep.
    for allowed in mod.WINN3_KNOWN_PROTOCOL_PARAMS:
        assert not pattern.search(allowed), allowed
    # The guard is on a LIVE PATH, not just in this file: both of these are
    # reported by GET /admin/nodes/winn3/descriptor and both must be empty.
    assert mod.winn3_key_shaped_names_in_params_allowlist() == []
    assert mod.winn3_unguarded_descriptor_secret_fields() == []
    # Pointed the other way: every declared secret field IS key-shaped, so the
    # enumeration and the pattern cannot silently disagree.
    for field in mod.WINN3_DESCRIPTOR_SECRET_FIELDS:
        assert pattern.search(field), field


def test_the_descriptor_is_not_a_protocol_params_key(mod):
    """No descriptor field may reach the closed twenty-key allowlist.

    The client refuses the whole connection on any protocol_params key outside
    that list, and the list must stay exactly twenty.
    """
    assert len(mod.WINN3_KNOWN_PROTOCOL_PARAMS) == 20
    assert "winn3_descriptor" not in mod.WINN3_KNOWN_PROTOCOL_PARAMS
    for field in mod.WINN3_DESCRIPTOR_REQUIRED_FIELDS:
        assert field not in mod.WINN3_KNOWN_PROTOCOL_PARAMS, field
    # Uploading a descriptor field through the params endpoint is a refusal.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params({"admission_secret": "AAAA"}),
        reason="unknown-params", keys=["admission_secret"])


def test_signature_domain_is_disjoint_from_the_other_two_families(mod):
    assert mod.WINN3_DESCRIPTOR_DOMAIN == b"winsvpn-winn3-descriptor/v1"
    assert mod.WINN3_DESCRIPTOR_DOMAIN != mod.ANNOUNCE_SIGNATURE_DOMAIN
    assert set(mod.WINN3_DESCRIPTOR_KEY_SLOTS) == {"g1", "g2", "g3"}
    # The hub-side announcement signer (and ANNOUNCE_SIGNING_KEY_ID) was
    # removed by the 2026-09-29 ruling; the family is now the a1..a3 slots the
    # hub only VERIFIES against.
    assert not hasattr(mod, "ANNOUNCE_SIGNING_KEY_ID")
    assert set(mod.ANNOUNCE_KEY_SLOTS) == {"a1", "a2", "a3"}
    assert not set(mod.ANNOUNCE_KEY_SLOTS) & set(mod.WINN3_DESCRIPTOR_KEY_SLOTS)


# ===================== 2. descriptor payload validation ====================


def test_valid_descriptor_round_trip(mod):
    out = mod.validate_winn3_descriptor_payload(
        descriptor_payload(), slug="lab-alpha")
    assert out["admission_gen"] == 1 and out["seq"] == 1
    assert out["padding"] == "bucket" and out["tag_size"] == 32
    assert out["_bucket_candidates"] == 13
    assert out["_acceptance_span_s"] == 130
    assert out["_ttl_s"] == 86400


def test_dual_auth_descriptor_returns_its_attestation_keys(mod):
    """B-1 regression, half two: the validator must not only ACCEPT the
    optional pair but RETURN it, so the served descriptor carries the exact
    attestation keys the gateway will accept. Losing them here strips the
    dual-auth upgrade for every client of the node."""
    ed25519_b64 = base64.b64encode(b"E" * 32).decode()
    mldsa65_b64 = base64.b64encode(b"M" * 1952).decode()
    out = mod.validate_winn3_descriptor_payload(
        descriptor_payload(extra={
            "auth_ed25519": ed25519_b64,
            "auth_mldsa65": mldsa65_b64,
        }), slug="lab-alpha")
    assert out["auth_ed25519"] == ed25519_b64
    assert out["auth_mldsa65"] == mldsa65_b64
    # The non-dual keys ride along unchanged.
    assert out["admission_gen"] == 1 and out["kid"] == "g1"
    assert out["_ttl_s"] == 86400


def test_legacy_descriptor_returns_its_dict_not_none(mod):
    """B-1 regression, half one: a descriptor without dual-auth keys used to
    fall off the end of the validator and return None, so the serve path saw
    "no descriptor" and silently downgraded every legacy client. A legacy
    payload must round-trip to a dict carrying its non-dual fields, with no
    attestation keys."""
    out = mod.validate_winn3_descriptor_payload(
        descriptor_payload(), slug="lab-alpha")
    assert isinstance(out, dict) and out
    assert out["kid"] == "g1"
    assert out["admission_secret"] == base64.b64encode(b"a" * 64).decode()
    assert "auth_ed25519" not in out
    assert "auth_mldsa65" not in out


def test_legacy_stored_descriptor_survives_the_serve_path(mod):
    """The B-1 legacy path end to end: a signed, stored, non-dual descriptor
    must come back out of winn3_stored_descriptor (read path re-validation),
    otherwise resolve_served_winn3_descriptor downgrades the client."""
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    node = seed_node(mod, protocol_version="winn/3",
                     descriptor_json=json.dumps(
                         {"payload": payload_b64, "sig": sig_b64}))
    stored = mod.winn3_stored_descriptor(node)
    assert isinstance(stored, dict) and stored
    assert stored["admission_gen"] == 1 and stored["seq"] == 1
    assert stored["node"] == "lab-alpha"
    assert "auth_ed25519" not in stored and "auth_mldsa65" not in stored
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True,
                                supports_winn3_descriptor=True),
        served_protocol_version="winn/3")
    assert served and reason == "winn3-descriptor"


def test_dual_auth_stored_descriptor_keeps_attestation_keys(mod):
    """Dual-auth half of B-1 on the stored-descriptor path: the read-path
    re-validation must return the attestation keys too."""
    ed25519_b64 = base64.b64encode(b"E" * 32).decode()
    mldsa65_b64 = base64.b64encode(b"M" * 1952).decode()
    payload = descriptor_payload(extra={
        "auth_ed25519": ed25519_b64, "auth_mldsa65": mldsa65_b64})
    payload_b64, sig_b64 = envelope_for(payload)
    node = seed_node(mod, protocol_version="winn/3",
                     descriptor_json=json.dumps(
                         {"payload": payload_b64, "sig": sig_b64}))
    stored = mod.winn3_stored_descriptor(node)
    assert stored.get("auth_ed25519") == ed25519_b64
    assert stored.get("auth_mldsa65") == mldsa65_b64


def test_descriptor_not_an_object(mod):
    for bad in ("{}", 7, None, [1, 2], True):
        expect_raises(mod.Winn3ContractError,
                      lambda b=bad: mod.validate_winn3_descriptor_payload(
                          b, slug="lab-alpha"),
                      reason="descriptor-not-an-object")


def test_descriptor_missing_fields(mod):
    exc = expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(drop=("static_pub", "tag_size")),
            slug="lab-alpha"),
        reason="descriptor-missing-fields")
    assert exc.keys == ["static_pub", "tag_size"]


def test_descriptor_unknown_fields(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(extra={"mlkem_public_key": "AAAA"}),
            slug="lab-alpha"),
        reason="descriptor-unknown-fields", keys=["mlkem_public_key"])


def test_descriptor_format_version_and_algorithm(mod):
    assert mod.WINN3_DESCRIPTOR_FORMAT_VERSION == 3
    # v1 and v2 are the RETIRED formats, and these assertions are the whole cost
    # of each bump made visible: every descriptor signed before inner_router_v4
    # (v2) and then before inner_resolver_v4 (v3) joined the field set fails
    # here, and the only remedy is an offline re-sign the hub deliberately
    # cannot perform for itself.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(v=1, drop=("inner_router_v4",
                                          "inner_resolver_v4")),
            slug="lab-alpha"),
        reason="descriptor-missing-fields")
    # A v2 descriptor is well-formed for ITS format and still refused: it is
    # missing inner_resolver_v4, which is what the v3 bump exists to require.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(v=2, drop=("inner_resolver_v4",)),
            slug="lab-alpha"),
        reason="descriptor-missing-fields")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(v=1), slug="lab-alpha"),
        reason="descriptor-unsupported-format-version")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(v=2), slug="lab-alpha"),
        reason="descriptor-unsupported-format-version")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(v=4), slug="lab-alpha"),
        reason="descriptor-unsupported-format-version")
    # ML-DSA is named but NOT supported: the shipped client has no verifier for
    # it. See the handoff for the gap and its cost.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(alg="ml-dsa-65"), slug="lab-alpha"),
        reason="descriptor-unsupported-algorithm")
    assert mod.WINN3_DESCRIPTOR_SUPPORTED_ALGS == ("ed25519",)


def test_descriptor_kid_must_be_a_known_slot(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(kid="a1"), slug="lab-alpha"),
        reason="descriptor-unknown-key-slot")


def test_descriptor_node_must_match_the_slug(mod):
    """A descriptor for gateway A must not be installable on gateway B.

    The control-plane half of the GatewayID binding core already does on the
    wire: without it, every client of B would seal initiations only A can open,
    silently, because a failed admission tag is never answered.
    """
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(node="lab-beta"), slug="lab-alpha"),
        reason="descriptor-node-mismatch")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(node=""), slug="lab-alpha"),
        reason="descriptor-missing-node")
    # Case is normalized on both sides rather than being a second way to fail.
    ok = mod.validate_winn3_descriptor_payload(
        descriptor_payload(node="LAB-ALPHA"), slug="lab-alpha")
    assert ok["node"] == "lab-alpha"


def test_descriptor_endpoint_must_be_an_ip_literal(mod):
    for bad in ("gateway.example.test:51820", "", "198.51.100.7", "0.0.0.0:51820"):
        expect_raises(
            mod.Winn3ContractError,
            lambda b=bad: mod.validate_winn3_descriptor_payload(
                descriptor_payload(endpoint=b), slug="lab-alpha"),
            reason="descriptor-endpoint-not-ip-literal")
    ok = mod.validate_winn3_descriptor_payload(
        descriptor_payload(endpoint="[2001:db8::1]:51820"), slug="lab-alpha")
    assert ok["endpoint"] == "[2001:db8::1]:51820"


def test_descriptor_static_pub_must_be_32_bytes(mod):
    for size in (31, 33, 0):
        expect_raises(
            mod.Winn3ContractError,
            lambda s=size: mod.validate_winn3_descriptor_payload(
                descriptor_payload(static_bytes=s), slug="lab-alpha"),
            reason=("descriptor-field-not-base64" if size == 0
                    else "descriptor-field-wrong-length"),
            keys=["static_pub"])
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(extra={"static_pub": "not base64!!"}),
            slug="lab-alpha"),
        reason="descriptor-field-not-base64", keys=["static_pub"])


def test_descriptor_gateway_id_bounds(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(gateway_id_bytes=0), slug="lab-alpha"),
        reason="descriptor-field-not-base64", keys=["gateway_id"])
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(gateway_id_bytes=256), slug="lab-alpha"),
        reason="descriptor-field-too-long", keys=["gateway_id"])
    assert mod.validate_winn3_descriptor_payload(
        descriptor_payload(gateway_id_bytes=255), slug="lab-alpha")


def test_descriptor_inner_router_must_be_a_plain_dotted_quad(mod):
    """inner_router_v4 is the one descriptor field that is NOT base64.

    It is an ADDRESS and it reaches `[winn] inner_router_v4` as text. Encoding
    it would give every host one more decode to disagree about, which is
    exactly how the gateway_id defect happened -- so the validator refuses
    anything that is not a bare dotted quad, including the base64 spelling that
    every OTHER byte-valued field uses.
    """
    for bad in (
        base64.b64encode(b"10.10.0.1").decode(),   # the wrong-by-analogy form
        "10.10.0.1:51820",                          # an endpoint, not an address
        "gateway.example.test",                     # a name the engine cannot use
        "fd00::1",                                  # v4 only
        "0.0.0.0", "127.0.0.1", "224.0.0.1",        # cannot be a next hop
        "10.10.0",                                  # truncated
        "",
    ):
        expect_raises(
            mod.Winn3ContractError,
            lambda b=bad: mod.validate_winn3_descriptor_payload(
                descriptor_payload(inner_router_v4=b), slug="lab-alpha"),
            reason="descriptor-inner-address-not-ipv4",
            keys=["inner_router_v4"])
    normalized = mod.validate_winn3_descriptor_payload(
        descriptor_payload(
            inner_router_v4="  10.10.7.1  ",
            inner_resolver_v4="10.10.7.1",
        ),
        slug="lab-alpha",
    )
    assert normalized["inner_router_v4"] == "10.10.7.1"


def test_descriptor_resolver_must_match_gateway_bind_address(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(inner_resolver_v4="10.10.0.2"),
            slug="lab-alpha",
        ),
        reason="descriptor-resolver-does-not-match-gateway-bind",
        keys=["inner_resolver_v4", "inner_router_v4"],
    )


def test_descriptor_refuses_edge_whitespace_in_operator_values(mod):
    """Trap 3, refused at the one surface every device's copy passes through.

    A trailing space in a gateway name keys 9 bytes on cmd/winn3-gateway and on
    Apple and 8 on Android -- MEASURED by the conformance suite and held as its
    `operator-value-whitespace-normalisation` divergence. The value is an
    authenticated input to the admission tag and is never transmitted, so
    neither end can ever discover the disagreement: iOS connects, Android does
    not, and nothing anywhere logs a reason.

    The hub cannot fix the hosts' normalisation. It can refuse to be the thing
    that ships the space, which is one 400 to one operator instead.
    """
    for spelling in ("winsgw01 ", " winsgw01", "winsgw01\n", "\twinsgw01"):
        expect_raises(
            mod.Winn3ContractError,
            lambda s=spelling: mod.validate_winn3_descriptor_payload(
                descriptor_payload(extra={
                    "gateway_id": base64.b64encode(s.encode()).decode()}),
                slug="lab-alpha"),
            reason="descriptor-gateway-id-has-edge-whitespace",
            keys=["gateway_id"])
    # The same asymmetry applies to the admission secret: Android trims it, the
    # gateway does not, and the outcome is a session that BUILDS and then never
    # answers -- strictly worse than a refusal, because a host watching for
    # "did the gateway see me" sees yes.
    hex_secret = "ab" * 32
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(extra={
                "admission_secret":
                    base64.b64encode((hex_secret + " ").encode()).decode()}),
            slug="lab-alpha"),
        reason="descriptor-admission-secret-has-edge-whitespace",
        keys=["admission_secret"])
    # Interior whitespace is NOT refused: it is not the copy-paste accident
    # this guard is for, and a gateway name is opaque text the operator chose.
    assert mod.validate_winn3_descriptor_payload(
        descriptor_payload(extra={
            "gateway_id": base64.b64encode(b"wins gw 01").decode()}),
        slug="lab-alpha")


def test_descriptor_admission_secret_floor(mod):
    """core's minAdmissionKeySize, enforced where a mistake is still cheap."""
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(secret_bytes=31), slug="lab-alpha"),
        reason="descriptor-field-too-short", keys=["admission_secret"])
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(secret_bytes=32), slug="lab-alpha"),
        reason="descriptor-admission-secret-noncanonical",
        keys=["admission_secret"])
    uppercase = descriptor_payload()
    uppercase["admission_secret"] = base64.b64encode(b"A" * 64).decode()
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            uppercase, slug="lab-alpha"),
        reason="descriptor-admission-secret-noncanonical",
        keys=["admission_secret"])
    assert mod.validate_winn3_descriptor_payload(
        descriptor_payload(secret_bytes=64), slug="lab-alpha")


def test_descriptor_tag_size_bounds(mod):
    for bad in (15, 33, 0, -1):
        expect_raises(
            mod.Winn3ContractError,
            lambda b=bad: mod.validate_winn3_descriptor_payload(
                descriptor_payload(tag_size=b), slug="lab-alpha"),
            reason="descriptor-tag-size-out-of-range")
    for good in (16, 24, 32):
        assert mod.validate_winn3_descriptor_payload(
            descriptor_payload(tag_size=good), slug="lab-alpha")


def test_descriptor_padding_policy(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(padding="random"), slug="lab-alpha"),
        reason="descriptor-unknown-padding-policy")
    for good in ("none", "bucket", "mimic"):
        assert mod.validate_winn3_descriptor_payload(
            descriptor_payload(padding=good), slug="lab-alpha")


def test_descriptor_freshness_bounds(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(window=0, skew=60), slug="lab-alpha"),
        reason="bucket-window-below-one-second")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(window=10, skew=5), slug="lab-alpha"),
        reason="max-skew-below-bucket-window")


def test_descriptor_freshness_is_bounded_by_the_rotation_budget(mod):
    """The coupling, enforced: a wide skew is a DoS gift DURING a rotation.

    An unauthenticated datagram costs len(keys) * (2*spread+1) HMACs. The
    budget is checked at the two-key worst case, not the current one-key
    reality, so the refusal lands on the operator BEFORE a rotation rather than
    in the middle of one.
    """
    # 10 s window, 60 s skew -> 13 candidates -> 26 HMACs with two keys. Fine.
    assert mod.validate_winn3_descriptor_payload(
        descriptor_payload(window=10, skew=60), slug="lab-alpha")
    # 10 s window, 3600 s skew -> 721 candidates -> 1442 HMACs. Refused.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(window=10, skew=3600), slug="lab-alpha"),
        reason="descriptor-freshness-exceeds-rotation-budget")
    # The exact boundary: budget 64, two keys -> 32 candidates max -> spread 15.
    _, candidates, _ = mod.winn3_freshness_geometry(10, 150)
    assert candidates == 31
    assert mod.validate_winn3_descriptor_payload(
        descriptor_payload(window=10, skew=150), slug="lab-alpha")
    _, candidates, _ = mod.winn3_freshness_geometry(10, 160)
    assert candidates == 33
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(window=10, skew=160), slug="lab-alpha"),
        reason="descriptor-freshness-exceeds-rotation-budget")


def test_descriptor_ttl_bounds(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(ttl=60), slug="lab-alpha"),
        reason="descriptor-ttl-too-short")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(ttl=31 * 24 * 3600), slug="lab-alpha"),
        reason="descriptor-ttl-too-long")
    assert mod.validate_winn3_descriptor_payload(
        descriptor_payload(ttl=3600), slug="lab-alpha")


def test_descriptor_integers_are_not_booleans(mod):
    """True is an int in Python. tag_size=True must not become tag_size=1."""
    for field in ("tag_size", "seq", "iat", "admission_gen", "v",
                  "bucket_window_s", "max_skew_s", "not_after"):
        expect_raises(
            mod.Winn3ContractError,
            lambda f=field: mod.validate_winn3_descriptor_payload(
                descriptor_payload(extra={f: True}), slug="lab-alpha"),
            reason="descriptor-field-not-an-integer", keys=[field])
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(extra={"tag_size": "32"}), slug="lab-alpha"),
        reason="descriptor-field-not-an-integer", keys=["tag_size"])


def test_descriptor_negative_generation_and_sequence(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(gen=-1), slug="lab-alpha"),
        reason="descriptor-negative-admission-generation")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_descriptor_payload(
            descriptor_payload(seq=-1), slug="lab-alpha"),
        reason="descriptor-negative-sequence")


# ========================= 3. signature verification =======================


def test_signature_verifies_with_real_openssl(mod):
    payload = descriptor_payload()
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    signature = sign_bytes(mod.WINN3_DESCRIPTOR_DOMAIN + b"\x00" + raw, "g1")
    assert mod.winn3_verify_descriptor_signature(raw, signature, "g1") == "g1"


def test_signature_refuses_a_forged_payload(mod):
    payload = descriptor_payload()
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    signature = sign_bytes(mod.WINN3_DESCRIPTOR_DOMAIN + b"\x00" + raw, "g1")
    tampered = raw.replace(b'"admission_gen":1', b'"admission_gen":2')
    assert tampered != raw
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.winn3_verify_descriptor_signature(tampered, signature, "g1"),
        reason="descriptor-signature-invalid")


def test_signature_is_bound_to_its_slot(mod):
    payload = descriptor_payload(kid="g2")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    signature = sign_bytes(mod.WINN3_DESCRIPTOR_DOMAIN + b"\x00" + raw, "g2")
    assert mod.winn3_verify_descriptor_signature(raw, signature, "g2") == "g2"
    # The same bytes under a different slot's key must not verify.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.winn3_verify_descriptor_signature(raw, signature, "g1"),
        reason="descriptor-signature-invalid")


def test_signature_domain_separation_is_real(mod):
    """A signature over the ANNOUNCEMENT domain must not verify as a descriptor.

    Asserted against real openssl output in both directions rather than argued
    from the constants, because domain separation that is only in a comment is
    not domain separation.
    """
    payload = descriptor_payload()
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    wrong_domain = sign_bytes(
        mod.ANNOUNCE_SIGNATURE_DOMAIN + b"\x00" + raw, "g1")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.winn3_verify_descriptor_signature(raw, wrong_domain, "g1"),
        reason="descriptor-signature-invalid")
    # And with no domain prefix at all.
    no_domain = sign_bytes(raw, "g1")
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.winn3_verify_descriptor_signature(raw, no_domain, "g1"),
        reason="descriptor-signature-invalid")


def test_signature_length_is_screened_before_openssl(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.winn3_verify_descriptor_signature(b"x", b"\x00" * 63, "g1"),
        reason="descriptor-signature-length")


def test_signature_refuses_an_unknown_or_unprovisioned_slot(mod):
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.winn3_verify_descriptor_signature(b"x", b"\x00" * 64, "zz"),
        reason="descriptor-unknown-key-slot")


def test_a_hub_with_no_ring_says_so_rather_than_reporting_a_bad_signature(mod):
    """A build mistake and an attack must not read the same in a log.

    Mirrors DiscoverySignatureFailure.noKeysCompiled, which exists so an
    operator does not go hunting for the wrong bug.
    """
    assert mod.winn3_descriptor_verification_available() is False
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.winn3_verify_descriptor_signature(b"x", b"\x00" * 64, "g1"),
        reason="descriptor-no-verification-keys-configured")


def test_a_partial_ring_names_the_missing_slot(mod):
    assert sorted(mod.winn3_descriptor_public_keys()) == ["g1"]
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.winn3_verify_descriptor_signature(b"x", b"\x00" * 64, "g3"),
        reason="descriptor-key-slot-not-provisioned")


def test_a_malformed_public_key_is_dropped_not_tolerated(mod):
    """A typo in a build define must degrade to "that key does not exist".

    Never to a verifier that accepts something it should not, and never to a
    crash. Same rule as DiscoveryKeyRing.droppedSlotIds.
    """
    ring = mod.winn3_descriptor_public_keys()
    assert "g1" not in ring, "a 31-byte key must not be usable"
    assert "g3" not in ring, "a key that is not base64 must not be usable"
    assert "g2" in ring
    assert mod.winn3_descriptor_verification_available() is True


# ========================= 4. the serving gate =============================


def test_descriptor_is_not_served_without_winn3(mod):
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    node = seed_node(mod, descriptor_json=json.dumps(
        {"payload": payload_b64, "sig": sig_b64}))
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3_descriptor=True),
        served_protocol_version="winn/1")
    assert served == {} and reason == "not-serving-winn3"


def test_descriptor_is_not_served_without_the_capability(mod):
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    node = seed_node(mod, protocol_version="winn/3",
                     descriptor_json=json.dumps(
                         {"payload": payload_b64, "sig": sig_b64}))
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True),
        served_protocol_version="winn/3")
    assert served == {} and reason == "client-not-descriptor-capable"


def test_descriptor_is_served_verbatim(mod):
    """The client verifies the exact bytes that were signed.

    A hub that re-encoded the payload would invalidate every signature the
    first time a JSON library changed a separator.
    """
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    stored = json.dumps({"payload": payload_b64, "sig": sig_b64})
    node = seed_node(mod, protocol_version="winn/3", descriptor_json=stored)
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True,
                                supports_winn3_descriptor=True),
        served_protocol_version="winn/3")
    assert reason == "winn3-descriptor"
    assert served == {"payload": payload_b64, "sig": sig_b64}
    assert set(served) == {"payload", "sig"}


def test_descriptor_is_not_served_when_the_stored_blob_does_not_validate(mod):
    """Re-validated on the READ path, exactly like protocol_params.

    A row can predate the validator, and serving a descriptor the gateway will
    not honour is worse than serving none: the gateway answers nothing, so the
    client sees a timeout rather than an error. The refusal carries the
    SPECIFIC contract reason, not a generic one.
    """
    bad = descriptor_payload(tag_size=999)
    payload_b64, sig_b64 = envelope_for(bad)
    node = seed_node(mod, protocol_version="winn/3", descriptor_json=json.dumps(
        {"payload": payload_b64, "sig": sig_b64}))
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True,
                                supports_winn3_descriptor=True),
        served_protocol_version="winn/3")
    assert served == {} and reason == "descriptor-tag-size-out-of-range"


def test_a_forged_signature_in_storage_is_refused_on_the_serve_path(mod):
    """F-2 regression: the serve path re-verifies the Ed25519 signature on
    EVERY read, not only at upload.

    The envelope below is valid-shape and its payload validates exactly as it
    would have at upload time; only the signature was substituted after the
    fact, exactly like a GCS-replica restore of a tampered row. The one call
    that keeps it out of client hands is the read-path verify in
    winn3_stored_descriptor: delete it, and this row becomes servable while
    every other test in this file stays green. This test is what pins that
    call down.
    """
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    forged_sig = base64.b64encode(b"\x00" * 64).decode()
    assert forged_sig != sig_b64
    node = seed_node(mod, protocol_version="winn/3", descriptor_json=json.dumps(
        {"payload": payload_b64, "sig": forged_sig}))
    assert mod.winn3_stored_descriptor(node) == {}
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True,
                                supports_winn3_descriptor=True),
        served_protocol_version="winn/3")
    assert served == {} and reason == "descriptor-signature-invalid"
    # A signature that is simply ABSENT is the same refusal, from the envelope
    # layer: the blob does not even reach the verifier.
    node = seed_node(mod, protocol_version="winn/3",
                     descriptor_json=json.dumps({"payload": payload_b64}))
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True,
                                supports_winn3_descriptor=True),
        served_protocol_version="winn/3")
    assert served == {} and reason == "no-descriptor-registered"


def test_an_expired_descriptor_in_storage_is_refused_on_the_serve_path(mod):
    """F-2 mirror: the EVERY-READ expiry is pinned the same way.

    The serve path re-runs the full validator on every read, so a stored
    descriptor whose lifetime lapsed after it was stored is withheld with the
    expiry reason, not served on the strength of having validated yesterday.
    The signature here is genuine; the failure is the clock check, and it must
    survive on the READ path exactly like the signature check does.
    """
    expired = descriptor_payload(iat=int(time.time()) - 7200, ttl=3600)
    assert expired["not_after"] <= int(time.time())
    payload_b64, sig_b64 = envelope_for(expired)
    node = seed_node(mod, protocol_version="winn/3", descriptor_json=json.dumps(
        {"payload": payload_b64, "sig": sig_b64}))
    assert mod.winn3_stored_descriptor(node) == {}
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True,
                                supports_winn3_descriptor=True),
        served_protocol_version="winn/3")
    assert served == {} and reason == "descriptor-expired"


def test_a_missing_or_malformed_envelope_is_no_descriptor_not_a_crash(mod):
    for stored in (None, "", "not json", "[]", '{"payload":""}',
                   '{"sig":"AAAA"}', "7"):
        node = seed_node(mod, protocol_version="winn/3", descriptor_json=stored)
        served, reason = mod.resolve_served_winn3_descriptor(
            node, capabilities=caps(supports_winn3=True,
                                    supports_winn3_descriptor=True),
            served_protocol_version="winn/3")
        assert served == {}, stored
        assert reason == "no-descriptor-registered", stored


def test_descriptor_inherits_every_refusal_the_winn3_gate_makes(mod):
    """Requirement: do not weaken the client's refusal semantics.

    stealth_active is a PER-REQUEST choice, so the same node is winn/3-servable
    to one request and not the next. The descriptor is served strictly
    downstream of resolve_served_winn_protocol, so there is no second gate that
    could disagree with the first -- proven here by driving the real gate.
    """
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    node = seed_node(mod, protocol_version="winn/3", protocol_params_json="{}",
                     descriptor_json=json.dumps(
                         {"payload": payload_b64, "sig": sig_b64}))
    capable = caps(supports_winn3=True, supports_winn3_descriptor=True)

    def served_for(**gate):
        version, _, _ = mod.resolve_served_winn_protocol(
            node, capabilities=capable, obfuscation=GOOD_OBFUSCATION,
            stealth_mode=gate.get("stealth_mode", False),
            double_vpn_active=gate.get("double_vpn_active", False),
            mtu=gate.get("mtu", 1280))
        return mod.resolve_served_winn3_descriptor(
            node, capabilities=capable, served_protocol_version=version)

    # The same node, the same client, two consecutive requests.
    assert served_for()[1] == "winn3-descriptor"
    expect_raises(mod.Winn3ContractError,
                  lambda: served_for(stealth_mode=True),
                  reason="stealth-mode-active")
    assert served_for()[1] == "winn3-descriptor"
    assert served_for(double_vpn_active=True) == ({}, "not-serving-winn3")
    expect_raises(mod.Winn3ContractError,
                  lambda: served_for(mtu=100),
                  reason="mtu-out-of-range")
    # And an unclassifiable obfuscation profile, which the gate also refuses.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.resolve_served_winn_protocol(
            node, capabilities=capable, obfuscation={"H1": 11},
            stealth_mode=False, double_vpn_active=False, mtu=1280),
        reason="obfuscation-not-classifiable")


def test_capability_defaults_false_everywhere(mod):
    """A client that predates the flag is served exactly what it is served
    today. Absent means False, and it is the whole backward-compatibility
    argument for this change."""
    class Legacy:
        """A client that predates the descriptor flag entirely."""

    flags = mod.request_client_capabilities(Legacy())
    assert flags["supports_winn3_descriptor"] is False
    assert flags["supports_winn3_dualauth"] is False
    # ...and it did not disturb the flags around it.
    assert flags["supports_winn3"] is False
    assert flags["supports_winn3_spa"] is False
    assert flags["supports_awg"] is True

    class OptedIn:
        supports_winn3_descriptor = True

    assert mod.request_client_capabilities(OptedIn())[
        "supports_winn3_descriptor"] is True


def test_request_models_accept_both_wire_spellings(mod):
    """A SOURCE assertion, and it says so.

    The harness stubs pydantic (BaseModel.__getattr__ returns None for any
    unset attribute), so field metadata -- defaults and AliasChoices -- does
    not survive into the loaded module and cannot be introspected. What can
    still be checked is that the installer declares the field on both models,
    with default False and both wire spellings, and forwards it from
    /free/verify. The no-underscore spelling matters because the whole
    split-script compat layer speaks it.
    """
    src = harness._extract_main_block()
    for model in ("class LoginRequest", "class FreeAccessRequest"):
        start = src.index(model)
        block = src[start:src.index("\nclass ", start + 1)]
        line = [ln for ln in block.splitlines()
                if ln.strip().startswith("supports_winn3_descriptor:")]
        assert len(line) == 1, f"{model} declares {len(line)} descriptor fields"
        assert "default=False" in line[0], (model, line[0])
        assert '"supports_winn3_descriptor"' in line[0], (model, line[0])
        assert '"supportswinn3descriptor"' in line[0], (model, line[0])
        dual = [ln for ln in block.splitlines()
                if ln.strip().startswith("supports_winn3_dualauth:")]
        assert len(dual) == 1, f"{model} declares {len(dual)} dualauth fields"
        assert "default=False" in dual[0], (model, dual[0])
        assert '"supports_winn3_dualauth"' in dual[0], (model, dual[0])
        assert '"supportswinn3dualauth"' in dual[0], (model, dual[0])
    # /free/verify builds a LoginRequest by hand; a field it forgets to
    # forward is a capability silently dropped for every free-tier client.
    assert "supports_winn3_descriptor=free_request.supports_winn3_descriptor" in src
    assert "supports_winn3_dualauth=free_request.supports_winn3_dualauth" in src


# ================= 4b. dual-auth capability negotiation ====================


def test_dual_auth_capability_true_releases_both_keys(mod):
    """A client that advertised supports_winn3_dualauth=true against a
    dual-provisioned node must be served both public keys."""
    node, payload_b64, sig_b64, ed25519_b64, mldsa65_b64 = seed_dual_auth_node(mod)
    capable = caps(supports_winn3=True, supports_winn3_descriptor=True,
                   supports_winn3_dualauth=True)
    keys = mod.winn3_dual_auth_keys_for_capabilities(
        mod.winn3_stored_descriptor(node), capable)
    assert keys["auth_ed25519"] == ed25519_b64
    assert keys["auth_mldsa65"] == mldsa65_b64
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=capable, served_protocol_version="winn/3")
    assert reason == "winn3-descriptor"
    assert served["payload"] == payload_b64 and served["sig"] == sig_b64
    assert served["auth_ed25519"] == ed25519_b64
    assert served["auth_mldsa65"] == mldsa65_b64


def test_dual_auth_capability_false_does_not_release_keys(mod):
    """A client that advertised false must not be handed the pair, even when
    the stored descriptor carries both keys."""
    node, payload_b64, sig_b64, ed25519_b64, mldsa65_b64 = seed_dual_auth_node(mod)
    off = caps(supports_winn3=True, supports_winn3_descriptor=True,
               supports_winn3_dualauth=False)
    keys = mod.winn3_dual_auth_keys_for_capabilities(
        mod.winn3_stored_descriptor(node), off)
    assert keys == {}
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=off, served_protocol_version="winn/3")
    assert reason == "winn3-descriptor"
    assert served["payload"] == payload_b64 and served["sig"] == sig_b64
    assert "auth_ed25519" not in served
    assert "auth_mldsa65" not in served
    body = json.loads(base64.b64decode(served["payload"]))
    assert body["auth_ed25519"] == ed25519_b64
    assert body["auth_mldsa65"] == mldsa65_b64


def test_dual_auth_capability_absent_defaults_false(mod):
    """A client that predates the flag is served no dual-auth keys. Absent
    means False; that is the whole backward-compatibility argument."""
    class Legacy:
        pass

    flags = mod.request_client_capabilities(Legacy())
    assert flags["supports_winn3_dualauth"] is False

    node, payload_b64, sig_b64, _, _ = seed_dual_auth_node(mod)
    absent = caps(supports_winn3=True, supports_winn3_descriptor=True)
    absent.pop("supports_winn3_dualauth", None)
    assert "supports_winn3_dualauth" not in absent
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=absent, served_protocol_version="winn/3")
    assert reason == "winn3-descriptor"
    assert served == {"payload": payload_b64, "sig": sig_b64}
    assert mod.winn3_dual_auth_keys_for_capabilities(
        mod.winn3_stored_descriptor(node), absent) == {}
    assert mod.winn3_dual_auth_keys_for_capabilities(
        mod.winn3_stored_descriptor(node), None) == {}


def test_dual_auth_malformed_capability_is_refused(mod):
    """Non-bool values are refused, never coerced. bool("false") is True."""
    class Bad:
        def __init__(self, value):
            self.supports_winn3_dualauth = value

    for bad in ("true", "false", "yes", "no", 1, 0, "1", [], {}, "True"):
        expect_raises(
            mod.Winn3ContractError,
            lambda v=bad: mod.request_client_capabilities(Bad(v)),
            reason="client-capability-malformed",
            keys=["supports_winn3_dualauth"])
        expect_raises(
            mod.Winn3ContractError,
            lambda v=bad: mod.resolve_served_winn3_descriptor(
                None,
                capabilities=caps(supports_winn3_dualauth=v),
                served_protocol_version="winn/3"),
            reason="client-capability-malformed",
            keys=["supports_winn3_dualauth"])
        expect_raises(
            mod.Winn3ContractError,
            lambda v=bad: mod.winn3_capability_bool(v, "supports_winn3_dualauth"),
            reason="client-capability-malformed",
            keys=["supports_winn3_dualauth"])
    assert mod.winn3_capability_bool(True, "supports_winn3_dualauth") is True
    assert mod.winn3_capability_bool(False, "supports_winn3_dualauth") is False
    assert mod.winn3_capability_bool(None, "supports_winn3_dualauth") is False


def test_dual_auth_mixed_clients_of_one_node(mod):
    """The same dual-provisioned node serves the pair to a true client and
    withholds it from a false client. The signed envelope bytes stay identical
    so verification is not a second, drifting object."""
    node, payload_b64, sig_b64, ed25519_b64, mldsa65_b64 = seed_dual_auth_node(mod)
    true_caps = caps(supports_winn3=True, supports_winn3_descriptor=True,
                     supports_winn3_dualauth=True)
    false_caps = caps(supports_winn3=True, supports_winn3_descriptor=True,
                      supports_winn3_dualauth=False)
    served_true, reason_true = mod.resolve_served_winn3_descriptor(
        node, capabilities=true_caps, served_protocol_version="winn/3")
    served_false, reason_false = mod.resolve_served_winn3_descriptor(
        node, capabilities=false_caps, served_protocol_version="winn/3")
    assert reason_true == reason_false == "winn3-descriptor"
    assert served_true["payload"] == served_false["payload"] == payload_b64
    assert served_true["sig"] == served_false["sig"] == sig_b64
    assert served_true["auth_ed25519"] == ed25519_b64
    assert served_true["auth_mldsa65"] == mldsa65_b64
    assert "auth_ed25519" not in served_false
    assert "auth_mldsa65" not in served_false


def test_dual_auth_required_request_is_not_silently_downgraded(mod):
    """Downgrade mutation: a true advertisement against a dual-provisioned
    descriptor must receive both stored keys. Dropping either is refused
    rather than served as a non-dual session. The serve path names that
    refusal, so deleting the check cannot hide behind a green helper.
    """
    node, _, _, ed25519_b64, mldsa65_b64 = seed_dual_auth_node(mod)
    capable = caps(supports_winn3=True, supports_winn3_descriptor=True,
                   supports_winn3_dualauth=True)
    stored = mod.winn3_stored_descriptor(node)
    keys = mod.winn3_dual_auth_keys_for_capabilities(stored, capable)
    assert keys["auth_ed25519"] == stored["auth_ed25519"] == ed25519_b64
    assert keys["auth_mldsa65"] == stored["auth_mldsa65"] == mldsa65_b64
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=capable, served_protocol_version="winn/3")
    assert reason == "winn3-descriptor"
    assert served["auth_ed25519"] == ed25519_b64
    assert served["auth_mldsa65"] == mldsa65_b64
    src = hub_function_source("resolve_served_winn3_descriptor")
    assert "winn3_dual_auth_keys_for_capabilities" in src, (
        "the serve path must call the capability gate; inlining a `return "
        "envelope` would re-introduce the silent dual-auth downgrade")
    assert "client-dual-auth-downgrade" in src, (
        "a true client against a dual-provisioned descriptor that would drop "
        "either key must be a named refusal, not an implicit omit")
    helper_src = hub_function_source("winn3_dual_auth_keys_for_capabilities")
    assert "winn3_client_advertises_dualauth" in helper_src
    assert "auth_ed25519" in helper_src and "auth_mldsa65" in helper_src
    assert "supports_winn3_dualauth" in src or "WINN3_DUALAUTH_CLIENT_CAPABILITY" in src


def test_dual_auth_capability_preserves_legacy_descriptors_and_winn_policy(mod):
    """A legacy non-dual descriptor stays non-dual for every client, and the
    dual-auth flag must not rewrite winn/3 to winn/1 or winn/1 to winn/3."""
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    legacy = seed_node(
        mod, protocol_version="winn/3", protocol_params_json="{}",
        descriptor_json=json.dumps({"payload": payload_b64, "sig": sig_b64}))
    true_caps = caps(supports_winn3=True, supports_winn3_descriptor=True,
                     supports_winn3_dualauth=True)
    false_caps = caps(supports_winn3=True, supports_winn3_descriptor=True,
                      supports_winn3_dualauth=False)
    for client in (true_caps, false_caps):
        stored = mod.winn3_stored_descriptor(legacy)
        assert "auth_ed25519" not in stored and "auth_mldsa65" not in stored
        assert mod.winn3_dual_auth_keys_for_capabilities(stored, client) == {}
        served, reason = mod.resolve_served_winn3_descriptor(
            legacy, capabilities=client, served_protocol_version="winn/3")
        assert reason == "winn3-descriptor"
        assert served == {"payload": payload_b64, "sig": sig_b64}

    v1 = seed_node(mod, slug="lab-v1", protocol_version="winn/1")
    version, params, reason = mod.resolve_served_winn_protocol(
        v1, capabilities=true_caps, obfuscation=GOOD_OBFUSCATION,
        stealth_mode=False, double_vpn_active=False, mtu=1280)
    assert (version, params, reason) == ("winn/1", {}, "node-not-winn3")

    v3 = seed_node(mod, slug="lab-v3", protocol_version="winn/3",
                   protocol_params_json="{}")
    version, _, reason = mod.resolve_served_winn_protocol(
        v3, capabilities=caps(supports_winn3=True,
                              supports_winn3_dualauth=False),
        obfuscation=GOOD_OBFUSCATION, stealth_mode=False,
        double_vpn_active=False, mtu=1280)
    assert version == "winn/3" and reason == "winn3"


# ============================ 5. rotation ==================================


def test_rotation_state_is_none_without_a_descriptor(mod):
    node = seed_node(mod)
    state = mod.winn3_rotation_state(node)
    assert state["phase"] == "none"
    assert state["current_generation"] is None
    assert state["safe_to_retire_previous"] is False


def test_rotation_state_is_steady_after_a_first_install(mod):
    seed_node(mod, protocol_version="winn/3")
    out = install(mod, descriptor_payload(gen=1, seq=1))
    assert out["rotated"] is False
    state = out["rotation"]
    assert state["phase"] == "steady"
    assert state["current_generation"] == 1
    assert state["gateway_admission_keys_expected"] == 1
    assert state["reject_path_hmacs"] == 13
    assert state["previous_generation"] is None


def test_a_generation_change_opens_an_overlap_with_a_computed_floor(mod):
    """retire_after = promoted_at + previous ttl + (2*spread+1)*window.

    The third term is the freshness coupling and it is ADDED, not assumed to be
    absorbed by the ttl: an initiation sealed at the last instant a client used
    the old key stays acceptable across the whole acceptance span.
    """
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=1, seq=1, ttl=3600))
    out = install(mod, descriptor_payload(gen=2, seq=2, ttl=3600))
    assert out["rotated"] is True
    state = out["rotation"]
    assert state["phase"] == "overlap"
    assert state["current_generation"] == 2
    assert state["previous_generation"] == 1
    assert state["gateway_admission_keys_expected"] == 2
    assert state["reject_path_hmacs"] == 26, "two live keys double the reject path"
    assert state["safe_to_retire_previous"] is False
    # 3600 s ttl + 130 s acceptance span, to the second.
    assert 3720 <= state["seconds_until_retire"] <= 3730, state


def test_the_retire_floor_moves_with_the_freshness_parameters(mod):
    """Not a constant. Widening max_skew widens the floor.

    This is the whole point of computing it from winn3_freshness_geometry: a
    hub that hardcoded 130 s would silently strand clients the first time an
    operator widened the window for skewed device clocks.
    """
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=1, seq=1, ttl=3600, window=10, skew=60))
    narrow = install(
        mod, descriptor_payload(gen=2, seq=2, ttl=3600, window=10, skew=60))
    seed_node(mod, slug="lab-wide", protocol_version="winn/3")
    install(mod, descriptor_payload(node="lab-wide", gen=1, seq=1, ttl=3600,
                                    window=10, skew=60), slug="lab-wide")
    wide = install(mod, descriptor_payload(node="lab-wide", gen=2, seq=2,
                                           ttl=3600, window=10, skew=150),
                   slug="lab-wide")
    assert narrow["rotation"]["acceptance_span_s"] == 130
    assert wide["rotation"]["acceptance_span_s"] == 310
    assert (wide["rotation"]["seconds_until_retire"]
            - narrow["rotation"]["seconds_until_retire"]) >= 179


def test_a_reissue_of_the_same_generation_does_not_forget_an_open_rotation(mod):
    """Re-issuing the current generation (e.g. a longer ttl) mid-rotation must
    not drop the previous generation's retirement floor. If it did, the old key
    would silently become "safe to retire" the moment someone refreshed a ttl.
    """
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=1, seq=1, ttl=3600))
    install(mod, descriptor_payload(gen=2, seq=2, ttl=3600))
    out = install(mod, descriptor_payload(gen=2, seq=3, ttl=7200))
    assert out["rotated"] is False
    assert out["rotation"]["phase"] == "overlap"
    assert out["rotation"]["previous_generation"] == 1
    assert out["rotation"]["safe_to_retire_previous"] is False


def test_rotation_reports_the_reject_path_cost_the_gateway_will_pay(mod):
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=1, seq=1, window=10, skew=150))
    out = install(mod, descriptor_payload(gen=2, seq=2, window=10, skew=150))
    assert out["rotation"]["bucket_candidates"] == 31
    assert out["rotation"]["reject_path_hmacs"] == 62
    assert out["rotation"]["reject_path_hmacs"] <= mod.WINN3_MAX_ADMISSION_HMAC_BUDGET


def test_the_two_key_ceiling_is_a_constant_not_a_hope(mod):
    assert mod.WINN3_MAX_LIVE_ADMISSION_KEYS == 2
    assert mod.WINN3_MAX_ADMISSION_HMAC_BUDGET == 64


# ========================== 6. the admin endpoints =========================


def test_admin_upload_then_clear(mod):
    seed_node(mod, protocol_version="winn/3")
    out = install(mod, descriptor_payload())
    assert out["ok"] is True and out["accepted_key_slot"] == "g1"
    assert out["requires_gateway_side_key_install"] is True
    row = node_row(mod)
    assert row["winn3_descriptor_json"]
    cleared = admin_descriptor(mod, slug="lab-alpha", enabled=False)
    assert cleared["descriptor"] == {}
    row = node_row(mod)
    assert row["winn3_descriptor_json"] is None
    ledger = json.loads(row["winn3_admission_json"])
    assert ledger["sequence_floor"] == 1
    assert ledger["current"]["generation"] == 1


def test_disable_preserves_replay_floor_and_withholds_serving(mod):
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=2, seq=5))
    admin_descriptor(mod, slug="lab-alpha", enabled=False)
    row = node_row(mod)
    served, reason = mod.resolve_served_winn3_descriptor(
        row,
        capabilities=caps(
            supports_winn3=True, supports_winn3_descriptor=True),
        served_protocol_version="winn/3",
    )
    assert served == {} and reason == "no-descriptor-registered"
    ledger = json.loads(row["winn3_admission_json"])
    assert ledger["sequence_floor"] == 5

    exc = expect_http(409, lambda: install(
        mod, descriptor_payload(gen=1, seq=4)))
    assert "strictly increase" in str(exc.detail)
    expect_http(409, lambda: install(mod, descriptor_payload(gen=2, seq=5)))
    assert node_row(mod)["winn3_descriptor_json"] is None


def test_disable_is_idempotent_and_higher_sequence_reenables(mod):
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=2, seq=5, ttl=3600))
    admin_descriptor(mod, slug="lab-alpha", enabled=False)
    first = node_row(mod)["winn3_admission_json"]
    admin_descriptor(mod, slug="lab-alpha", enabled=False)
    assert node_row(mod)["winn3_admission_json"] == first

    out = install(mod, descriptor_payload(gen=3, seq=6, ttl=3600))
    assert out["ok"] is True and out["rotated"] is True
    assert out["rotation"]["phase"] == "overlap"
    assert out["rotation"]["current_generation"] == 3
    assert out["rotation"]["previous_generation"] == 2
    ledger = json.loads(node_row(mod)["winn3_admission_json"])
    assert ledger["sequence_floor"] == 6
    assert ledger["previous"]["seq"] == 5


def test_admin_clear_is_never_refused(mod):
    """A rollback that can fail is not a rollback.

    Works on a node with a garbage stored blob and on one that never had a
    descriptor at all.
    """
    seed_node(mod, descriptor_json="{{{ not json")
    assert admin_descriptor(mod, slug="lab-alpha", enabled=False)["ok"] is True
    assert admin_descriptor(mod, slug="lab-alpha", enabled=False)["ok"] is True


def test_admin_refuses_a_bad_signature(mod):
    seed_node(mod, protocol_version="winn/3")
    payload_b64, _ = envelope_for(descriptor_payload())
    exc = expect_http(400, lambda: admin_descriptor(
        mod, slug="lab-alpha", enabled=True,
        descriptor_payload_b64=payload_b64,
        descriptor_sig_b64=base64.b64encode(b"\x00" * 64).decode()))
    assert "descriptor-signature-invalid" in str(exc.detail)
    assert node_row(mod)["winn3_descriptor_json"] is None


def test_admin_refuses_bad_base64_and_bad_json(mod):
    seed_node(mod, protocol_version="winn/3")
    expect_http(400, lambda: admin_descriptor(
        mod, slug="lab-alpha", enabled=True,
        descriptor_payload_b64="not base64!!", descriptor_sig_b64="AAAA"))
    expect_http(400, lambda: admin_descriptor(
        mod, slug="lab-alpha", enabled=True,
        descriptor_payload_b64=base64.b64encode(b"{not json").decode(),
        descriptor_sig_b64=base64.b64encode(b"\x00" * 64).decode()))
    expect_http(400, lambda: admin_descriptor(
        mod, slug="lab-alpha", enabled=True,
        descriptor_payload_b64="", descriptor_sig_b64=""))


def test_admin_refuses_an_oversized_payload(mod):
    seed_node(mod, protocol_version="winn/3")
    huge = base64.b64encode(b"{" + b"x" * 8192 + b"}").decode()
    exc = expect_http(400, lambda: admin_descriptor(
        mod, slug="lab-alpha", enabled=True, descriptor_payload_b64=huge,
        descriptor_sig_b64=base64.b64encode(b"\x00" * 64).decode()))
    assert "ceiling" in str(exc.detail)


def test_admin_refuses_a_descriptor_for_another_node(mod):
    seed_node(mod, protocol_version="winn/3")
    seed_node(mod, slug="lab-beta", protocol_version="winn/3")
    exc = expect_http(400, lambda: install(
        mod, descriptor_payload(node="lab-beta"), slug="lab-alpha"))
    assert "descriptor-node-mismatch" in str(exc.detail)
    assert node_row(mod, "lab-alpha")["winn3_descriptor_json"] is None


def test_admin_refuses_a_sequence_rollback(mod):
    """The one thing a leaked admin token could otherwise do.

    Reinstating an older, RETIRED descriptor would resurrect an admission
    secret that has already been burnt.
    """
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=2, seq=5))
    exc = expect_http(409, lambda: install(
        mod, descriptor_payload(gen=1, seq=4)))
    assert "strictly increase" in str(exc.detail)
    expect_http(409, lambda: install(mod, descriptor_payload(gen=2, seq=5)))
    # Forward is fine.
    assert install(mod, descriptor_payload(gen=3, seq=6))["ok"] is True


def test_admin_refuses_a_descriptor_this_hub_cannot_verify(mod):
    seed_node(mod, protocol_version="winn/3")
    exc = expect_http(400, lambda: install(
        mod, descriptor_payload(kid="g2"), slot="g2"))
    assert "descriptor-key-slot-not-provisioned" in str(exc.detail)


def test_admin_unknown_node_and_missing_slug(mod):
    expect_http(404, lambda: admin_descriptor(
        mod, slug="nope", enabled=False))
    expect_http(400, lambda: admin_descriptor(mod, slug="  ", enabled=False))
    expect_http(404, lambda: admin_retire(mod, slug="nope"))
    expect_http(400, lambda: admin_retire(mod, slug=""))


def test_admin_requires_the_admin_token(mod):
    seed_node(mod, protocol_version="winn/3")
    for call in (
        lambda: admin_descriptor(mod, slug="lab-alpha", enabled=False,
                                 x_admin_token="wrong"),
        lambda: admin_list_descriptors(mod, x_admin_token="wrong"),
        lambda: admin_retire(mod, slug="lab-alpha", x_admin_token="wrong"),
    ):
        try:
            call()
        except HTTPException as exc:
            assert exc.status_code in (401, 403), exc.status_code
        else:
            raise AssertionError("admin endpoint accepted a wrong token")


def test_admin_listing_reports_the_ring_and_the_rotation(mod):
    seed_node(mod, protocol_version="winn/3")
    seed_node(mod, slug="lab-beta")
    install(mod, descriptor_payload(gen=1, seq=1))
    install(mod, descriptor_payload(gen=2, seq=2))
    out = admin_list_descriptors(mod)
    assert out["verification_available"] is True
    assert out["verification_key_slots"] == ["g1", "g2", "g3"]
    assert out["descriptor_domain"] == "winsvpn-winn3-descriptor/v1"
    assert out["supported_algorithms"] == ["ed25519"]
    assert out["max_live_admission_keys"] == 2
    assert out["allowlist_key_shaped_names"] == []
    assert out["unguarded_descriptor_secret_fields"] == []
    by_slug = {entry["slug"]: entry for entry in out["nodes"]}
    assert by_slug["lab-alpha"]["has_descriptor"] is True
    assert by_slug["lab-alpha"]["descriptor_valid"] is True
    assert by_slug["lab-alpha"]["rotation"]["phase"] == "overlap"
    assert by_slug["lab-beta"]["has_descriptor"] is False
    assert by_slug["lab-beta"]["rotation"]["phase"] == "none"


def test_admin_listing_on_a_hub_with_no_ring_says_so(mod):
    out = admin_list_descriptors(mod)
    assert out["verification_available"] is False
    assert out["verification_key_slots"] == []


def test_admin_retire_requires_an_open_rotation(mod):
    seed_node(mod, protocol_version="winn/3")
    expect_http(409, lambda: admin_retire(mod, slug="lab-alpha"))
    install(mod, descriptor_payload(gen=1, seq=1))
    exc = expect_http(409, lambda: admin_retire(mod, slug="lab-alpha"))
    assert "steady" in str(exc.detail)


def test_admin_retire_refuses_before_the_floor(mod):
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=1, seq=1, ttl=3600))
    install(mod, descriptor_payload(gen=2, seq=2, ttl=3600))
    exc = expect_http(409, lambda: admin_retire(mod, slug="lab-alpha"))
    assert "Too early" in str(exc.detail)
    assert "strand" in str(exc.detail)
    # The previous generation is still on the books.
    assert mod.winn3_rotation_state(node_row(mod))["previous_generation"] == 1


def test_admin_retire_forced_is_allowed_and_logged(mod):
    """The one override, for a key believed leaked.

    Stranding some clients beats leaving a burnt secret live -- but it is the
    only call in this path that can knock a user offline, so it is explicit.
    """
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=1, seq=1, ttl=3600))
    install(mod, descriptor_payload(gen=2, seq=2, ttl=3600))
    out = admin_retire(mod, slug="lab-alpha", force=True)
    assert out["retired_generation"] == 1
    assert out["forced"] is True
    assert out["requires_gateway_side_key_removal"] is True
    assert out["rotation"]["phase"] == "steady"
    assert out["rotation"]["reject_path_hmacs"] == 13


def test_admin_retire_after_the_floor_has_passed(mod):
    """A rotation whose floor is in the past retires without force."""
    seed_node(mod, protocol_version="winn/3")
    install(mod, descriptor_payload(gen=1, seq=1, ttl=3600))
    install(mod, descriptor_payload(gen=2, seq=2, ttl=3600))
    # Rewind promoted_at past the floor. Nothing else is touched, so the
    # arithmetic under test is the hub's own.
    row = node_row(mod)
    ledger = json.loads(row["winn3_admission_json"])
    past = (mod.utcnow() - mod.timedelta(seconds=3600 + 130 + 5)).isoformat()
    ledger["current"]["promoted_at"] = past
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE nodes SET winn3_admission_json = ? WHERE slug = ?",
                     (json.dumps(ledger), "lab-alpha"))
    state = mod.winn3_rotation_state(node_row(mod))
    assert state["safe_to_retire_previous"] is True
    assert state["seconds_until_retire"] == 0
    out = admin_retire(mod, slug="lab-alpha")
    assert out["retired_generation"] == 1 and out["forced"] is False
    assert out["rotation"]["phase"] == "steady"


def test_a_corrupt_ledger_degrades_to_a_report_not_a_crash(mod):
    """A rotation report is what an operator reads mid-window. It must never be
    the thing that 500s, whatever is in the ledger column."""
    open_rotation = '{"current":{"promoted_at":"%s","ttl_s":3600},"previous":' \
                    '{"generation":1,"ttl_s":3600,"promoted_at":"%s"}}'
    for ledger in (
        None, "", "not json", "[]", "7", '{"current":7}',
        # previous exists but promoted_at is unparseable
        open_rotation % ("not-a-date", "not-a-date"),
        # previous exists but carries no ttl, so no floor can be computed
        '{"current":{"promoted_at":"2026-08-08T00:00:00"},'
        '"previous":{"generation":1}}',
        # previous exists but current has no promoted_at at all
        '{"current":{},"previous":{"generation":1,"ttl_s":3600}}',
    ):
        payload_b64, sig_b64 = envelope_for(descriptor_payload())
        node = seed_node(mod, protocol_version="winn/3",
                         descriptor_json=json.dumps(
                             {"payload": payload_b64, "sig": sig_b64}),
                         admission_json=ledger)
        state = mod.winn3_rotation_state(node)
        assert state["phase"] in ("steady", "overlap"), ledger
        assert state["current_generation"] == 1, ledger
        # An uncomputable floor is reported as NOT safe. Failing open here
        # would tell an operator it is safe to retire a key on the strength of
        # a corrupt ledger.
        if state["phase"] == "overlap":
            assert state["safe_to_retire_previous"] is False, ledger


def test_the_rotation_clock_stays_inside_the_hubs_naive_utc_contract(mod):
    """utcnow() is NAIVE UTC by this hub's own contract.

    An aware timestamp reaching the subtraction would raise TypeError and turn
    a rotation report into a 500 -- during a window, which is the only time
    anyone reads it. Both sides are normalised, and both directions are driven
    here.
    """
    from datetime import datetime, timedelta, timezone
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    aware = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    node = seed_node(
        mod, protocol_version="winn/3",
        descriptor_json=json.dumps({"payload": payload_b64, "sig": sig_b64}),
        admission_json=json.dumps({
            "current": {"generation": 2, "ttl_s": 3600, "promoted_at": aware},
            "previous": {"generation": 1, "ttl_s": 3600,
                         "promoted_at": aware},
        }))
    state = mod.winn3_rotation_state(node)
    assert state["phase"] == "overlap"
    assert state["seconds_until_retire"] is not None
    assert 3600 <= state["seconds_until_retire"] <= 3730, state
    # And an aware `now` passed in by a caller.
    state = mod.winn3_rotation_state(node, now=datetime.now(timezone.utc))
    assert state["phase"] == "overlap"
    assert 3600 <= state["seconds_until_retire"] <= 3730, state


def test_an_unreadable_stored_payload_is_no_descriptor(mod):
    """Not every bad blob is a contract error. A payload that base64-decodes to
    bytes that are not UTF-8 JSON must also degrade to "no descriptor". The
    refusal reason is the specific contract reason where one exists and the
    generic class where the blob failed outside the contract."""
    _, sig_b64 = envelope_for(descriptor_payload())
    for bad_payload, expected in (
        (base64.b64encode(b"\xff\xfe\x00").decode(), "descriptor-does-not-validate"),
        (base64.b64encode(b"[1,2,3]").decode(), "descriptor-not-an-object"),
        ("!!!not base64!!!", "descriptor-does-not-validate"),
    ):
        node = seed_node(mod, protocol_version="winn/3",
                         descriptor_json=json.dumps(
                             {"payload": bad_payload, "sig": sig_b64}))
        assert mod.winn3_stored_descriptor(node) == {}, bad_payload
        served, reason = mod.resolve_served_winn3_descriptor(
            node, capabilities=caps(supports_winn3=True,
                                    supports_winn3_descriptor=True),
            served_protocol_version="winn/3")
        assert served == {} and reason == expected, bad_payload


# ============================= 7. disclosure ===============================


def test_the_admission_secret_never_reaches_a_response_body(mod):
    seed_node(mod, protocol_version="winn/3")
    secret_marker = base64.b64encode(b"a" * 64).decode()
    out = install(mod, descriptor_payload())
    blob = json.dumps(out)
    assert secret_marker not in blob
    assert "admission_secret" not in out["descriptor"]
    assert out["descriptor"]["admission_secret_bytes"] == 64
    listing = json.dumps(admin_list_descriptors(mod))
    assert secret_marker not in listing
    # And the endpoint -- a node address -- is not in the ROTATION report,
    # which is the object an operator pastes into a chat during a window.
    assert GATEWAY_ENDPOINT not in json.dumps(out["rotation"])


def test_no_secret_and_no_address_in_error_bodies(mod):
    seed_node(mod, protocol_version="winn/3")
    secret_marker = base64.b64encode(b"K" * 32).decode()
    bad = descriptor_payload(tag_size=999, endpoint=OTHER_ENDPOINT)
    exc = expect_http(400, lambda: install(mod, bad))
    detail = str(exc.detail)
    assert secret_marker not in detail
    assert OTHER_ENDPOINT not in detail
    assert "203.0.113" not in detail
    # The FIELD NAME is present -- that is the whole point of the error.
    assert "tag_size" in detail


def test_no_secret_and_no_address_in_log_lines(mod):
    seed_node(mod, protocol_version="winn/3")
    secret_marker = base64.b64encode(b"K" * 32).decode()
    lines = []

    class Spy:
        def __getattr__(self, _name):
            def record(msg, *args, **kwargs):
                try:
                    lines.append(msg % args if args else str(msg))
                except Exception:
                    lines.append(str(msg))
            return record

    real, mod.logger = mod.logger, Spy()
    try:
        try:
            install(mod, descriptor_payload(tag_size=999,
                                            endpoint=OTHER_ENDPOINT))
        except HTTPException:
            pass
        install(mod, descriptor_payload())
        install(mod, descriptor_payload(gen=2, seq=2))
        admin_retire(mod, slug="lab-alpha", force=True)
    finally:
        mod.logger = real
    joined = "\n".join(lines)
    assert lines, "the spy captured nothing; the log path was not exercised"
    assert secret_marker not in joined
    assert OTHER_ENDPOINT not in joined and "203.0.113" not in joined
    assert GATEWAY_ENDPOINT not in joined and "198.51.100" not in joined
    assert "tag_size" in joined, "field names ARE expected in the log"
    assert "descriptor stored" in joined


def test_public_fields_never_carry_a_secret_field(mod):
    descriptor = mod.validate_winn3_descriptor_payload(
        descriptor_payload(), slug="lab-alpha")
    public = mod.winn3_descriptor_public_fields(descriptor)
    for field in mod.WINN3_DESCRIPTOR_SECRET_FIELDS:
        assert field not in public, field
    for key in public:
        assert not key.startswith("_"), key
    assert mod.winn3_descriptor_public_fields({}) == {}
    assert mod.winn3_descriptor_public_fields(
        {"admission_secret": "not base64!!"})["admission_secret_bytes"] == 0


def test_the_served_config_carries_the_envelope_and_nothing_else(mod):
    """The envelope is opaque base64. The secret is inside the SIGNED bytes,
    which is where it has to be -- but it must not also appear as a field."""
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    node = seed_node(mod, protocol_version="winn/3", descriptor_json=json.dumps(
        {"payload": payload_b64, "sig": sig_b64}))
    served, _ = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True,
                                supports_winn3_descriptor=True),
        served_protocol_version="winn/3")
    assert set(served) == {"payload", "sig"}
    assert "admission_secret" not in json.dumps(served)


# ============================ 8. end to end ================================

ACTIVATION_SECRET = "activation-secret-value"


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


def arm_activation(mod, account="1111-2222-3333"):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE users SET activation_secret_hash = ?, activation_secret_used_at = NULL, "
            "activation_secret_expires_at = NULL WHERE account_number = ?",
            (mod.token_digest(ACTIVATION_SECRET), account))
        conn.commit()


def served_config(mod, request_headers=None, **login_overrides):
    from test_account_deletion_hub import BackgroundTasks
    # The one stub on this path, and it is a NETWORK stub: sync_peer_to_node
    # SSHes to the selected node. This suite must never contact a node.
    mod.sync_peer_to_node = lambda *a, **k: True
    mod.sync_winn3_registry_to_node = lambda *a, **k: True
    request = FakeRequest(
        path="/verify", headers=request_headers or {"x-wins-activation": ACTIVATION_SECRET})
    result = asyncio.run(
        mod.verify_account(request, build_login(mod, **login_overrides),
                           BackgroundTasks()))
    body = result.body if hasattr(result, "body") else result
    if isinstance(body, (bytes, str)):
        body = json.loads(body)
    return body


def test_end_to_end_default_is_unchanged(mod):
    """The load-bearing property. A normal client sees an empty descriptor slot
    and winn/1, exactly as before this change."""
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    seed_node(mod, descriptor_json=json.dumps(
        {"payload": payload_b64, "sig": sig_b64}))
    body = served_config(mod)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["protocol_version"] == "winn/1"
    assert config["protocol_params"] == {}
    assert config["winn3_descriptor"] == {}
    assert config["client_capabilities"]["supports_winn3_descriptor"] is False


def test_end_to_end_descriptor_reaches_a_capable_client(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}",
              descriptor_json=json.dumps(
                  {"payload": payload_b64, "sig": sig_b64}))
    # winn/3-capable but NOT descriptor-capable: winn/3, no descriptor.
    body = served_config(mod, supports_winn3=True)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["protocol_version"] == "winn/3"
    assert config["winn3_descriptor"] == {}
    # Both flags: the envelope, byte for byte.
    body = served_config(mod, request_headers={"authorization": f"Bearer {body['device_auth_token']}"},
                         supports_winn3=True, supports_winn3_descriptor=True)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["winn3_descriptor"] == {"payload": payload_b64,
                                          "sig": sig_b64}
    compat = body.get("vpnconfig") or {}
    if compat:
        assert compat["winn3descriptor"] == {"payload": payload_b64,
                                             "sig": sig_b64}


def test_end_to_end_stealth_request_gets_neither(mod):
    """stealth_active + winn/3 is a client refusal, and it is per-request."""
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}",
              descriptor_json=json.dumps(
                  {"payload": payload_b64, "sig": sig_b64}))
    expect_http(503, lambda: served_config(
        mod, supports_winn3=True, supports_winn3_descriptor=True,
        stealth_mode=True))
    # The very next request, without stealth, gets both.
    body = served_config(mod, supports_winn3=True,
                         supports_winn3_descriptor=True)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert config["protocol_version"] == "winn/3"
    assert config["winn3_descriptor"]["payload"] == payload_b64


def test_end_to_end_per_device_standalone_material(mod):
    """The device half of a standalone config: inner_v4 and static_private.

    THEY ARE NOT protocol_params KEYS AND CANNOT BE. That surface is a closed
    twenty-key allowlist whose one inviolable rule is that nothing key-shaped
    is ever served through it, and WINN3_PARAM_NAME_NEVER_SERVED matches
    `static_private` by construction. They ride vpn_config, beside
    client_private_key -- the surface that already carries a per-device private
    key to its own device.
    """
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}",
              descriptor_json=json.dumps(
                  {"payload": payload_b64, "sig": sig_b64}))

    # A client with neither flag is refused: this node is registered winn/3.
    # Empty-string type stability for explicit winn/1 is covered by
    # test_end_to_end_default_is_unchanged.
    expect_http(503, lambda: served_config(mod))

    body = served_config(mod, supports_winn3=True,
                         supports_winn3_descriptor=True)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    inner = config["winn3_inner_v4"]
    private_key = config["winn3_static_private"]
    assert mod.winn3_is_inner_ipv4(inner)
    assert mod.winn3_inner_router_in_pool(inner)
    assert inner != config["client_ip"], (
        "the standalone inner address must not be the AmneziaWG one: the v3 tun "
        "layer drops every packet whose source does not match ITS assignment")
    assert len(base64.b64decode(private_key, validate=True)) == 32
    assert private_key != config["client_private_key"], (
        "a standalone session has no AmneziaWG identity to borrow; reusing the "
        "relay key would make a v3 compromise a v1 compromise")

    # STABLE ACROSS RECONNECTS. The gateway's session table is provisioned
    # against this address and this public key, so re-rolling either on an
    # ordinary reconnect would strand the device silently -- the gateway would
    # drop its packets and, being a v3 gateway, answer nothing.
    body = served_config(mod, request_headers={"authorization": f"Bearer {body['device_auth_token']}"},
                         supports_winn3=True, supports_winn3_descriptor=True)
    again = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    assert again["winn3_inner_v4"] == inner
    assert again["winn3_static_private"] == private_key

    # And the private half is never key-shaped ON protocol_params.
    assert "static_private" not in config["protocol_params"]
    assert "inner_v4" not in config["protocol_params"]


def test_peer_registry_binds_issued_public_key_to_inner_address(mod):
    """The node receives only the authenticated public key and issued address."""
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}",
              descriptor_json=json.dumps(
                  {"payload": payload_b64, "sig": sig_b64}))
    body = served_config(mod, supports_winn3=True,
                         supports_winn3_descriptor=True)
    config = body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        document = mod.winn3_peer_registry_document(conn, "lab-alpha")
        stored = conn.execute(
            "SELECT winn3_static_public FROM devices WHERE device_id = ?",
            ("device-abcdef0123456789",),
        ).fetchone()
    assert document == {
        "version": 1,
        "peers": [{
            "static_public": stored["winn3_static_public"],
            "inner_v4": config["winn3_inner_v4"],
            "not_after": document["peers"][0]["not_after"],
        }],
    }
    serialized = json.dumps(document)
    assert "account" not in serialized
    assert "device" not in serialized
    assert config["winn3_static_private"] not in serialized
    assert document["peers"][0]["not_after"] > int(mod.utcnow().timestamp())


def test_external_canary_is_required_and_its_identity_is_in_the_registry(mod):
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    node = seed_node(
        mod,
        protocol_version="winn/3",
        protocol_params_json=json.dumps({"carrier": "winn3"}),
        descriptor_json=json.dumps({"payload": payload_b64, "sig": sig_b64}),
    )
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE nodes SET winn3_canary_status='probe_error', "
            "winn3_canary_ok_at=NULL, path_mtu=1450, "
            "carrier_classes='udp,tcp,tls' WHERE slug='lab-alpha'"
        )
    node = node_row(mod)
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.resolve_served_winn_protocol(
            node,
            capabilities=caps(
                supports_winn3=True, supports_winn3_descriptor=True
            ),
            obfuscation=GOOD_OBFUSCATION,
            stealth_mode=False,
            double_vpn_active=False,
            mtu=1280,
        ),
        reason="winn3_external_canary_not_fresh",
    )

    previous = {
        name: os.environ.get(name)
        for name in (
            "WINN3_CANARY_NODE_SLUG",
            "WINN3_CANARY_STATIC_PUBLIC",
            "WINN3_CANARY_INNER_V4",
        )
    }
    os.environ["WINN3_CANARY_NODE_SLUG"] = "lab-alpha"
    os.environ["WINN3_CANARY_STATIC_PUBLIC"] = base64.b64encode(b"C" * 32).decode()
    os.environ["WINN3_CANARY_INNER_V4"] = "10.10.0.44"
    try:
        with closing(sqlite3.connect(mod._DB)) as conn, conn:
            conn.row_factory = sqlite3.Row
            document = mod.winn3_peer_registry_document(conn, "lab-alpha")
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    assert document["peers"] == [{
        "static_public": base64.b64encode(b"C" * 32).decode(),
        "inner_v4": "10.10.0.44",
        "not_after": 0,
    }]


def test_schema_repairs_legacy_duplicate_inner_addresses_before_unique_index(mod):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute("DROP INDEX idx_devices_winn3_inner_v4_unique")
        for device_id in ("legacy-a", "legacy-b"):
            conn.execute(
                "INSERT INTO devices (device_id, winn3_inner_v4, "
                "winn3_static_private, winn3_static_public) VALUES (?, ?, ?, ?)",
                (device_id, " 10.10.0.44 ", "private-" + device_id,
                 "public-" + device_id),
            )
        conn.commit()
        assert mod.ensure_unique_winn3_inner_addresses(conn) == 2
        repaired = conn.execute(
            "SELECT winn3_inner_v4, winn3_static_private, winn3_static_public "
            "FROM devices WHERE device_id LIKE 'legacy-%' ORDER BY device_id"
        ).fetchall()
        assert all(row["winn3_inner_v4"] is None for row in repaired)
        assert all(row["winn3_static_private"] for row in repaired)
        assert all(row["winn3_static_public"] for row in repaired)
        conn.execute(
            "UPDATE devices SET winn3_inner_v4='10.10.0.44' "
            "WHERE device_id='legacy-a'"
        )
        try:
            conn.execute(
                "UPDATE devices SET winn3_inner_v4='10.10.0.44' "
                "WHERE device_id='legacy-b'"
            )
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("database accepted a duplicate Winn3 inner address")


def test_concurrent_inner_address_claims_retry_after_unique_collision(mod):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.executemany(
            "INSERT INTO devices (device_id) VALUES (?)",
            [("concurrent-a",), ("concurrent-b",)],
        )
        conn.commit()

    real_allocate = mod.allocate_winn3_inner_ip
    first_claim = threading.Barrier(2)
    thread_state = threading.local()

    def collide_once(conn):
        calls = getattr(thread_state, "calls", 0)
        thread_state.calls = calls + 1
        if calls == 0:
            first_claim.wait(timeout=10)
            return "10.10.0.44"
        return real_allocate(conn)

    mod.allocate_winn3_inner_ip = collide_once
    results = {}
    failures = []

    def issue(device_id):
        try:
            with closing(sqlite3.connect(mod._DB, timeout=30)) as conn, conn:
                conn.row_factory = sqlite3.Row
                result = mod.ensure_winn3_device_material(
                    conn, {"device_id": device_id}
                )
                conn.commit()
                results[device_id] = result
        except Exception as exc:
            failures.append(exc)

    workers = [
        threading.Thread(target=issue, args=(device_id,))
        for device_id in ("concurrent-a", "concurrent-b")
    ]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=40)
    finally:
        mod.allocate_winn3_inner_ip = real_allocate
    assert not any(worker.is_alive() for worker in workers)
    assert failures == []
    assert set(results) == {"concurrent-a", "concurrent-b"}
    addresses = {result[0] for result in results.values()}
    assert len(addresses) == 2
    assert "10.10.0.44" in addresses


def test_peer_registry_sync_is_atomic_and_root_controlled(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    payload_b64, sig_b64 = envelope_for(descriptor_payload())
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}",
              descriptor_json=json.dumps(
                  {"payload": payload_b64, "sig": sig_b64}))
    real_sync = mod.sync_winn3_registry_to_node
    served_config(mod, supports_winn3=True,
                  supports_winn3_descriptor=True)
    mod.sync_winn3_registry_to_node = real_sync

    calls = []
    real_run = mod.subprocess.run

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def capture(args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    mod.subprocess.run = capture
    # H0 (D3): the hub never runs a node command locally; the command goes
    # through node_ssh_command, stubbed here so the remote text can be read.
    real_ssh = mod.node_ssh_command
    mod.node_ssh_command = lambda host, command, **kwargs: ["ssh", host, command]
    try:
        with closing(sqlite3.connect(mod._DB)) as conn, conn:
            conn.row_factory = sqlite3.Row
            assert mod.sync_winn3_registry_to_node(
                conn, "127.0.0.1", "lab-alpha")
    finally:
        mod.subprocess.run = real_run
        mod.node_ssh_command = real_ssh
    assert len(calls) == 1
    command = calls[0][0]
    assert command[:2] == ["ssh", "127.0.0.1"]
    remote = command[2]
    assert "mktemp /etc/winn/.winn3-peers." in remote
    assert "chown root:winn3-gateway" in remote
    assert "chmod 0640" in remote
    assert 'mv -f "$tmp" /etc/winn/winn3-peers.json' in remote


def test_location_change_bounds_the_previous_node_registry(mod):
    """A moved identity stays at its previous gateway only for a bounded grace.

    Until 2026-09-23 this asserted that the previous snapshot was empty at
    reply time. That is the removal that let the previous gateway refuse the
    switch reply travelling through its own tunnel (lane L17). The previous
    gateway now keeps the unchanged identity with a finite not_after of at
    most WINN3_DEPARTURE_GRACE_SECONDS, and an inactive account clears it.
    """
    from test_account_deletion_hub import BackgroundTasks

    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    alpha_payload, alpha_sig = envelope_for(descriptor_payload())
    seed_node(
        mod,
        protocol_version="winn/3",
        protocol_params_json="{}",
        descriptor_json=json.dumps(
            {"payload": alpha_payload, "sig": alpha_sig}
        ),
    )
    enrolled = served_config(
        mod, supports_winn3=True, supports_winn3_descriptor=True
    )

    beta_payload, beta_sig = envelope_for(
        descriptor_payload(node="lab-beta")
    )
    seed_node(
        mod,
        slug="lab-beta",
        endpoint="198.51.100.43:9110",
        protocol_version="winn/3",
        protocol_params_json="{}",
        descriptor_json=json.dumps(
            {"payload": beta_payload, "sig": beta_sig}
        ),
    )
    synchronized = []
    mod.sync_peer_to_node = lambda *a, **k: True
    mod.sync_winn3_registry_to_node = (
        lambda conn, host, slug, *a, **k: synchronized.append(slug) or True
    )
    if hasattr(mod, "maintain_winn3_authority_epoch"):
        # A hub whose authority recovery has completed (lane L17 v3). The
        # barrier itself is exercised in test_winn3_departure_grace_hub.py.
        with closing(sqlite3.connect(mod._DB)) as conn, conn:
            conn.row_factory = sqlite3.Row
            mod.maintain_winn3_authority_epoch(conn)
        with mod.winn3_authority_ledger() as ledger:
            ledger.executemany(
                "INSERT OR REPLACE INTO winn3_ledger_meta (key, value) VALUES (?, ?)",
                (("recovery_complete", "1"), ("budget_trusted_after", "0")),
            )
    request = FakeRequest(
        path="/verify", headers={"authorization": f"Bearer {enrolled['device_auth_token']}"}
    )
    asyncio.run(
        mod.verify_account(
            request,
            build_login(
                mod,
                location="lab-beta",
                supports_winn3=True,
                supports_winn3_descriptor=True,
            ),
            BackgroundTasks(),
        )
    )
    assert synchronized == ["lab-beta", "lab-alpha"]
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        moved = conn.execute("SELECT winn3_static_public FROM devices").fetchone()[0]
        previous = mod.winn3_peer_registry_document(conn, "lab-alpha")["peers"]
        assert [entry["static_public"] for entry in previous] == [moved]
        assert 0 < previous[0]["not_after"] <= int(time.time()) + mod.WINN3_DEPARTURE_GRACE_SECONDS
        assert len(mod.winn3_peer_registry_document(conn, "lab-beta")["peers"]) == 1
        conn.execute("UPDATE users SET status='disabled'")
        assert mod.winn3_peer_registry_document(conn, "lab-alpha")["peers"] == []


def test_a_descriptor_outside_the_hub_pool_is_withheld(mod):
    """The one gateway/hub binding the hub can actually verify.

    The descriptor names the gateway's inner next hop; the hub allocates the
    client's inner address from WINN3_INNER_POOL_CIDR. If the two are not the
    same space the session establishes and then carries nothing, and NEITHER
    END CAN TELL. So a mismatch refuses the request rather than serving a
    descriptor without device material, and rather than rewriting to winn/1.
    """
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    arm_activation(mod)
    payload_b64, sig_b64 = envelope_for(
        descriptor_payload(
            inner_router_v4="172.31.0.1",
            inner_resolver_v4="172.31.0.1",
        ))
    seed_node(mod, protocol_version="winn/3", protocol_params_json="{}",
              descriptor_json=json.dumps(
                  {"payload": payload_b64, "sig": sig_b64}))
    expect_http(503, lambda: served_config(
        mod, supports_winn3=True, supports_winn3_descriptor=True))


def test_winn3_is_a_supported_carrier_and_needs_no_carrier_profile(mod):
    """(A) and its consequence, in one place.

    `winn3` is refused nowhere anymore, and it takes the profile-FREE branch:
    a standalone session dials its own transport with its own handshake and
    reads no MASQUE profile, so a profile param on a winn3 node is exactly as
    inert -- and exactly as misleading -- as one on a direct-awg node.
    """
    assert mod.WINN3_CARRIER_WINN3 == "winn3"
    assert mod.WINN3_CARRIER_WINN3 in mod.WINN3_SUPPORTED_CARRIERS
    assert mod.WINN3_CARRIER_WINN3 not in mod.WINN3_CARRIER_PROFILE_CARRIERS
    assert mod.WINN3_CARRIER_DIRECT_AWG not in mod.WINN3_CARRIER_PROFILE_CARRIERS
    assert mod.WINN3_CARRIER_HTTP3 in mod.WINN3_CARRIER_PROFILE_CARRIERS

    assert mod.validate_winn3_protocol_params({"carrier": "winn3"}) == {
        "carrier": "winn3"}
    # A profile param on a standalone node is refused, not silently kept.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(
            {"carrier": "winn3", "server_name": "example.test"}),
        reason="carrier-profile-params-without-carrier")
    # A standalone session cannot knock: SPA belongs to the http3 dialer, and
    # knockdial.New refuses the pairing at CONSTRUCTION.
    expect_raises(
        mod.Winn3ContractError,
        lambda: mod.validate_winn3_protocol_params(
            {"carrier": "winn3", "spa_mode": "required",
             "spa_target": "203.0.113.9:443"}),
        reason="spa-carrier-cannot-knock")
    # And NOTHING key-shaped became reachable through protocol_params by
    # widening the carrier set. This is the guard the descriptor exists behind.
    assert mod.winn3_key_shaped_names_in_params_allowlist() == []


# ================= D15: ONE pool validator, pinned to exactly /24 ==========
#
# D7 pinned the pool to /24. It left TWO implementations of that one rule --
# winn3_inner_pool() and an inline copy in startup_event() -- and they disagreed
# three ways: on a malformed CIDR the validator returned None silently while the
# guard swallowed the ValueError and started; on a non-IPv4 pool both passed
# silently; only a too-wide pool was ever reported. So a typo'd
# WINN3_INNER_POOL_CIDR (`10.10.0/24` for `10.10.0.0/24`) BOOTED CLEANLY, then
# allocated "" for every device, failed every in-pool check -- misreporting
# healthy descriptors as "outside pool" in the readiness path -- and downgraded
# the whole fleet to winn/1 with no diagnostic anywhere. Zero-working dressed as
# running, which is strictly worse than the half-working state D7 refuses to
# serve.
#
# The fix is structural, not additive: the guard now CALLS the validator and
# cannot hold an opinion of its own. These tests assert that equivalence over
# the whole case matrix rather than trusting the two to stay in step, because
# drifting apart is exactly how the original defect arose.
#
# None of these tests use descriptor_payload(): they exercise the pool
# validator, the startup guard and the membership check directly, so they are
# independent of the descriptor field set.

class LevelSpy:
    """Captures (level, rendered message) for every logger call.

    Level-aware, unlike the Spy in test_no_secret_and_no_address_in_log_lines:
    "the hub said why" is only true if it said so at ERROR. A refusal whispered
    at debug is the silent failure this whole section exists to remove.
    """

    def __init__(self):
        self.records = []

    def __getattr__(self, level):
        def record(msg, *args, **kwargs):
            try:
                text = msg % args if args else str(msg)
            except Exception:
                text = str(msg)
            self.records.append((level, text))
        return record

    def at(self, level):
        return "\n".join(text for lvl, text in self.records if lvl == level)


def hub_with_pool(cidr):
    """A hub whose WINN3_INNER_POOL_CIDR is `cidr`.

    THE CALLER MUST POP THE KEY IN A `finally` THAT ALSO COVERS THIS CALL.
    harness.load_hub updates os.environ BEFORE it exec's the module, so a load
    that raises leaves the pool behind -- and os.environ is process-wide, so
    every hub loaded later in this process would inherit it. Nothing at hub
    module level consults the validator today, so that cannot fire yet; a
    module-level pool check is the natural next strengthening of this very
    guard, at which point the leak would cascade through the suite as a
    confusing set of unrelated failures. Hence `try:` opens above this call,
    not below it.
    """
    return load_hub_with_ring(("g1", "g2", "g3"), WINN3_INNER_POOL_CIDR=cidr)


def hub_function_source(name):
    """The EXACT source of one top-level hub function, start to end.

    Deliberately not a fixed-size window. startup_event is already ~2.4k
    characters and this codebase routinely writes 30-line comment blocks, so a
    window would expire silently as the function grew -- and an inline pool
    parser reintroduced past the window, behind a comment block, would make the
    anti-divergence test below PASS on precisely the regression it exists to
    catch. (Found by the different-model review of this change, which built
    that mutation and demonstrated the false pass.)
    """
    source = harness._extract_main_block()
    tree = ast.parse(source)
    found = [node for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name == name]
    assert len(found) == 1, (
        f"expected exactly one top-level {name}, found {len(found)}; a second "
        "definition would shadow the first and this slice would read the wrong "
        "one")
    segment = ast.get_source_segment(source, found[0])
    assert segment, f"could not recover the source of {name}"
    return segment


def unusable_pool(cidr):
    """Assert `cidr` is unusable, and return (error text, startup exception).

    Every unusable-pool case goes through here so each one asserts the SAME
    three properties, which together are the ruling:

      1. winn3_inner_pool() returns None                 -- it is refused,
      2. it logged the reason at ERROR                   -- loudly,
      3. require_winn3_inner_pool() raises RuntimeError  -- and the guard agrees.

    (3) is checked for every case, not just the wide one. That is the
    anti-divergence property: a guard that reached a different verdict from its
    validator on ANY input would fail here.
    """
    try:
        mod = hub_with_pool(cidr)
        spy = LevelSpy()
        real, mod.logger = mod.logger, spy
        try:
            pool = mod.winn3_inner_pool()
        finally:
            mod.logger = real
        assert pool is None, f"{cidr!r} was accepted as a pool: {pool!r}"
        errors = spy.at("error")
        assert errors, (
            f"{cidr!r} was refused SILENTLY -- no error line. A pool refused "
            "without a reason is the silent fleet-wide downgrade D15 removes")
        raised = expect_raises(RuntimeError, mod.require_winn3_inner_pool)
        assert cidr in str(raised), (
            "the startup refusal must NAME the offending value; an operator "
            f"reading it has to know which string to fix. Got: {raised}")
        return errors, raised
    finally:
        os.environ.pop("WINN3_INNER_POOL_CIDR", None)


def usable_pool(cidr):
    """Assert `cidr` is accepted by BOTH the validator and the guard."""
    try:
        mod = hub_with_pool(cidr)
        pool = mod.winn3_inner_pool()
        assert pool is not None, f"{cidr!r} should be a usable pool"
        assert str(pool) == cidr
        # The guard must not disagree in this direction either: a guard that
        # refused a pool its validator accepts would refuse every deploy.
        mod.require_winn3_inner_pool()
        return mod
    finally:
        os.environ.pop("WINN3_INNER_POOL_CIDR", None)


def test_a_malformed_pool_refuses_startup_and_names_the_value(_mod):
    """The typo that used to boot clean and carry nothing.

    `10.10.0/24` is not a CIDR to Python's ipaddress. It used to hit
    `except ValueError: return None` in the validator and
    `except ValueError: pass` in the guard -- so the hub started, every
    allocation returned "", every in-pool check failed, and the fleet ran winn/1
    with zero diagnostics. Now it is a named startup refusal.
    """
    errors, raised = unusable_pool("10.10.0/24")
    assert "10.10.0/24" in errors, "the error line must quote the bad value"
    lowered = f"{errors}\n{raised}".lower()
    # "cidr" alone would be satisfied by the variable NAME appearing in the
    # message, so this asks for the negation that only a malformed-value reason
    # carries.
    assert "not a valid" in lowered, (
        "the reason must say the value is not a valid CIDR, not merely that "
        f"something was wrong. Got: {errors} / {raised}")
    # And the reason must be SPECIFIC -- a malformed pool must not be reported
    # as a width problem, which would send an operator to change the wrong
    # thing. This is the divergence that made the three behaviours possible.
    assert "wider" not in lowered, (
        "a malformed CIDR was misreported as a width problem")


def test_an_ipv6_pool_refuses_startup(_mod):
    """winn/3 inner addressing is IPv4-only, and used to pass silently.

    `isinstance(network, ipaddress.IPv4Network)` was false in BOTH places: the
    validator returned None without a word, and the guard's conjunct simply
    evaluated false and let startup continue. The most silent case of the three.
    """
    errors, raised = unusable_pool("fd00::/64")
    lowered = f"{errors}\n{raised}".lower()
    assert "ipv6" in lowered or "ipv4" in lowered, (
        f"the reason must name the address family. Got: {errors} / {raised}")


def test_the_pool_is_pinned_to_exactly_a_24(_mod):
    """Not "at least a /24" -- exactly one.

    WIDER breaks client derivation: the mobile hosts derive inner reachability
    against a hard /24 floor (0xFFFFFF00), so a /16 splits the fleet at device
    254. NARROWER has no articulated use and includes the degenerate /32, which
    offers a single address for the entire fleet -- the gateway's own inner
    address and nothing else. Both are refused, and a future /25 sharding
    scheme is a deliberate revisit with client-derivation analysis, not
    latitude left open by an inequality.
    """
    for cidr in ("10.10.0.0/16", "10.10.0.0/8", "10.10.0.0/25", "10.10.0.0/32"):
        errors, raised = unusable_pool(cidr)
        assert "/24" in f"{errors}\n{raised}", (
            f"the refusal of {cidr} must say what IS accepted")
    usable_pool("10.10.0.0/24")


def test_the_startup_guard_cannot_disagree_with_the_validator(_mod):
    """The durable half of D15, and the reason it is a refactor not a patch.

    Two implementations of one rule is what produced three behaviours from one
    sentence of policy. The guard now calls winn3_inner_pool() and has no
    parsing of its own, so a future change to the rule cannot land in one place
    and miss the other.
    """
    body = hub_function_source("startup_event")
    assert "ipaddress.ip_network(" not in body, (
        "startup_event() parses the pool itself again -- that inline "
        "re-implementation is precisely how D7's rule grew three behaviours")
    assert "prefixlen" not in body, (
        "startup_event() re-implements the width rule; it must ask "
        "winn3_inner_pool() instead")
    assert "require_winn3_inner_pool()" in body, (
        "startup_event() must call the guard, or the guard is unreachable "
        "and a malformed pool boots clean again")


def test_the_startup_guard_is_actually_wired_into_startup(_mod):
    """A guard nothing calls is not a guard.

    Runs the REAL startup_event coroutine against a malformed pool. The refusal
    sits above every side effect that reaches outside the process -- the SPA UDP
    listener, the account-deletion sweep, the Monero RPC validation -- so this
    raises before any of them: the process must die on the pool, not after
    opening sockets. Only ensure_schema runs first, which is idempotent DDL on
    the hub's own database and leaves nothing half-initialised.
    """
    try:
        mod = hub_with_pool("10.10.0/24")
        raised = expect_raises(
            RuntimeError, lambda: asyncio.run(mod.startup_event()))
        assert "10.10.0/24" in str(raised)
    finally:
        os.environ.pop("WINN3_INNER_POOL_CIDR", None)


def test_host_bits_in_the_pool_are_accepted_but_not_silently(_mod):
    """`10.10.0.5/24` is usable, and says so out loud.

    ip_network(strict=False) masks it to 10.10.0.0/24, which is almost certainly
    the intent -- but silently normalising an operator's stated value is the
    same class of quiet fixup D15 removes, and the gateway is stricter:
    parseForwardCIDR refuses a -forward-cidr with host bits set rather than
    masking it, so the two configurations do not read alike. Accepted (refusing
    would fail a working deploy over a cosmetic difference, a cost D15 did not
    license) and WARNED, at startup only so it cannot become per-request spam.

    Behaviour previously unpinned in EITHER direction; this test is what makes
    the choice deliberate. Raised by the different-model review.
    """
    try:
        mod = hub_with_pool("10.10.0.5/24")
        assert str(mod.winn3_inner_pool()) == "10.10.0.0/24"
        spy = LevelSpy()
        real, mod.logger = mod.logger, spy
        try:
            mod.require_winn3_inner_pool()
        finally:
            mod.logger = real
        assert not spy.at("error"), "a usable pool must not log an error"
        warned = spy.at("warning")
        assert "10.10.0.5/24" in warned and "10.10.0.0/24" in warned, (
            "the warning must show both what was written and how it was read. "
            f"Got: {warned!r}")
    finally:
        os.environ.pop("WINN3_INNER_POOL_CIDR", None)

    # The exact network address stays silent -- the warning fires on the
    # difference, not on every startup.
    try:
        mod = hub_with_pool("10.10.0.0/24")
        spy = LevelSpy()
        real, mod.logger = mod.logger, spy
        try:
            mod.require_winn3_inner_pool()
        finally:
            mod.logger = real
        assert not spy.records, (
            f"a clean pool must start silently; got {spy.records!r}")
    finally:
        os.environ.pop("WINN3_INNER_POOL_CIDR", None)


def test_network_and_broadcast_are_not_in_pool_inner_addresses(_mod):
    """Match the gateway's own rule, so the hub cannot bless what it refuses.

    cmd/winn3-gateway/main.go parseForwardCIDR rejects an -inner-v4 equal to the
    network or broadcast address of -forward-cidr: `ip addr add` accepts either
    but neither is a usable host address. Until now the hub's membership check
    was a plain `in pool`, which accepts both -- so the hub could accept, store
    and serve a descriptor the gateway itself would refuse to start with, and
    the mismatch would surface as a session that carries nothing.
    """
    mod = usable_pool("10.10.0.0/24")
    assert not mod.winn3_inner_router_in_pool("10.10.0.0"), (
        "the network address is not a usable inner next hop")
    assert not mod.winn3_inner_router_in_pool("10.10.0.255"), (
        "the broadcast address is not a usable inner next hop")
    assert mod.winn3_inner_router_in_pool("10.10.0.1")
    assert mod.winn3_inner_router_in_pool("10.10.0.254")
    # Same check, same rule, for the resolver: winn3_inner_router_in_pool is
    # used for inner_resolver_v4 too, and a resolver at the broadcast address is
    # exactly as unusable as a next hop there.
    assert not mod.winn3_inner_router_in_pool("10.10.0.0")
    # Nothing outside the pool became acceptable in the process.
    assert not mod.winn3_inner_router_in_pool("172.31.0.1")
    assert not mod.winn3_inner_router_in_pool("")
    assert not mod.winn3_inner_router_in_pool("not-an-address")


def test_the_membership_check_accepts_everything_the_allocator_issues(_mod):
    """The two must not disagree, or the hub refuses its own allocations.

    allocate_winn3_inner_ip() hands out pool.hosts(). Tightening the membership
    check is only safe if it still accepts every address that allocator can
    return -- otherwise the hub would issue a client address and then reject it
    on the next readiness pass.
    """
    mod = usable_pool("10.10.0.0/24")
    pool = mod.winn3_inner_pool()
    issuable = [str(h) for h in pool.hosts()]
    assert len(issuable) == 254
    rejected = [ip for ip in issuable if not mod.winn3_inner_router_in_pool(ip)]
    assert rejected == [], (
        f"the membership check refuses addresses the allocator issues: {rejected[:5]}")


def test_the_allocator_ignores_descriptors_that_fail_verification(mod):
    """A-DEP-002: only signature-verified descriptors reserve inner addresses.

    allocate_winn3_inner_ip used to raw-decode every stored envelope and
    reserve inner_router_v4/inner_resolver_v4 from it, with no verification.
    A forged row (written without the ceremony key, or a tampered
    GCS-replica restore) then reserved addresses exactly like a real one, so
    a write-capable attacker could stuff the nodes table with junk
    descriptors and exhaust the /24 pool without ever holding a signing key.
    Reservation must follow the same verification the serve path enforces:
    a descriptor no client can be served must reserve no address either.
    """
    # Phase 1 -- the forged shape. The payload is fully valid (and would
    # validate at upload); ONLY the signature is junk. Its inner_router_v4 is
    # 10.10.0.1, the pool's very first host. If the allocator still trusted
    # unverified envelopes, .1 would come back reserved and the first
    # allocation would be .2. With the fix, the forged row reserves nothing.
    payload_b64, sig_b64 = envelope_for(descriptor_payload(
        inner_router_v4="10.10.0.1", inner_resolver_v4="10.10.0.1"))
    forged_sig = base64.b64encode(b"\x00" * 64).decode()
    assert forged_sig != sig_b64
    seed_node(mod, slug="lab-alpha", protocol_version="winn/3",
              descriptor_json=json.dumps(
                  {"payload": payload_b64, "sig": forged_sig}))
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM nodes WHERE slug = 'lab-alpha'").fetchone()
        assert mod.winn3_stored_descriptor(row) == {}
        first = mod.allocate_winn3_inner_ip(conn)
    assert first == "10.10.0.1", (
        f"the allocator reserved an address for a descriptor whose signature "
        f"fails verification: first allocation was {first!r}, expected "
        f"'10.10.0.1' (the forged reservation at .1 must be ignored)")

    # Phase 2 -- the control. Same node, same address claim, but REALLY
    # signed by g1. Now .1 is genuinely reserved and the first allocation
    # must skip it. This proves phase 1 passed because verification was
    # enforced, not because reservation stopped working.
    valid_b64, valid_sig = envelope_for(descriptor_payload(
        inner_router_v4="10.10.0.1", inner_resolver_v4="10.10.0.1"))
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        conn.execute(
            "UPDATE nodes SET winn3_descriptor_json = ? WHERE slug = ?",
            (json.dumps({"payload": valid_b64, "sig": valid_sig}),
             "lab-alpha"))
        second = mod.allocate_winn3_inner_ip(conn)
    assert second == "10.10.0.2", (
        f"a VERIFIED descriptor's inner_router_v4 was not reserved: first "
        f"allocation was {second!r}, expected '10.10.0.2'")


def test_an_expired_descriptor_still_reserves_its_inner_addresses(mod):
    """F-02: expiry must not cancel an authentic descriptor's reservation.

    The A-DEP-002 fix routed the allocator through winn3_stored_descriptor(),
    which refuses expired descriptors on the serve path -- correct there, but
    the allocator inherited the refusal. Expiry is a SERVING control, not a
    gateway stop: the node's gateway keeps answering on its inner_router_v4
    after the clock lapses, so an expired descriptor's .1 claim must stay
    reserved or the allocator hands a device the address of a live gateway.
    """
    # Phase 1 -- expired but GENUINELY SIGNED, claiming 10.10.0.1. The
    # reservation must survive the clock: first allocation is .2.
    expired = descriptor_payload(
        iat=int(time.time()) - 7200, ttl=3600,
        inner_router_v4="10.10.0.1", inner_resolver_v4="10.10.0.1")
    assert expired["not_after"] <= int(time.time())
    payload_b64, sig_b64 = envelope_for(expired)
    seed_node(mod, slug="lab-alpha", protocol_version="winn/3",
              descriptor_json=json.dumps(
                  {"payload": payload_b64, "sig": sig_b64}))
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        first = mod.allocate_winn3_inner_ip(conn)
    assert first == "10.10.0.2", (
        f"an expired AUTHENTIC descriptor's inner_router_v4 was not reserved: "
        f"first allocation was {first!r}, expected '10.10.0.2' (F-02)")

    # Phase 2 -- the serve path still refuses the same expired descriptor.
    # Clock tolerance is for reservations only; a client must never be served
    # a descriptor whose clock has lapsed.
    node = node_row(mod, "lab-alpha")
    served, reason = mod.resolve_served_winn3_descriptor(
        node, capabilities=caps(supports_winn3=True,
                                supports_winn3_descriptor=True),
        served_protocol_version="winn/3")
    assert served == {} and reason == "descriptor-expired"

    # Phase 3 -- expired AND forged claims nothing: clock tolerance must not
    # reopen the A-DEP-002 exhaustion attack. The forged row claims .1 on a
    # SECOND node; with the genuine (expired) row on lab-alpha reserving .1,
    # the forged row is ignored entirely, and .1 stays reserved either way.
    forged_sig = base64.b64encode(b"\x00" * 64).decode()
    payload_b64_2, _sig = envelope_for(descriptor_payload(
        node="lab-beta", iat=int(time.time()) - 7200, ttl=3600,
        inner_router_v4="10.10.0.1", inner_resolver_v4="10.10.0.1"))
    seed_node(mod, slug="lab-beta", protocol_version="winn/3",
              descriptor_json=json.dumps(
                  {"payload": payload_b64_2, "sig": forged_sig}))
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        second = mod.allocate_winn3_inner_ip(conn)
    assert second == "10.10.0.2", (
        f"a forged expired descriptor affected allocation: {second!r}")


def test_a_rotation_cannot_claim_an_issued_device_address(mod):
    """B-02 (Sol audit, 2026-08-28): the reverse direction of reservation.

    The allocator reserves a STORED descriptor's router/resolver addresses,
    but the store path never checked the mirror image: a valid signed
    rotation naming an address already issued to a device was accepted
    (Sol's probe: ROUTATION_ACCEPTED=True with
    ROUTER_COLLIDES_WITH_ISSUED_DEVICE=True), and every session for that
    device then collided with its own next hop. The store must refuse.
    """
    # A device holds 10.10.0.2 on a seeded node.
    seed_node(mod, slug="lab-alpha", protocol_version="winn/3")
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT INTO devices (device_id, winn3_inner_v4) VALUES (?, ?)",
            ("dev-b02", "10.10.0.2"),
        )

    # Phase 1 -- a GENUINELY SIGNED rotation claiming the device's address.
    # The store must refuse with the named reason.
    payload_b64, sig_b64 = envelope_for(descriptor_payload(
        node="lab-alpha", gen=2, seq=2,
        inner_router_v4="10.10.0.2", inner_resolver_v4="10.10.0.2"))
    exc = expect_http(
        409,
        lambda: admin_descriptor(
            mod, slug="lab-alpha", enabled=True,
            descriptor_payload_b64=payload_b64,
            descriptor_sig_b64=sig_b64))
    assert "descriptor-claims-issued-device-address" in str(exc.detail), exc.detail
    # And nothing was stored.
    node = node_row(mod, "lab-alpha")
    assert mod.winn3_stored_descriptor(node) == {}

    # Phase 2 -- the same rotation claiming a free address (.1) is accepted;
    # the check refuses the collision, not rotation itself.
    ok_payload, ok_sig = envelope_for(descriptor_payload(
        node="lab-alpha", gen=2, seq=2,
        inner_router_v4="10.10.0.1", inner_resolver_v4="10.10.0.1"))
    admin_descriptor(
        mod, slug="lab-alpha", enabled=True,
        descriptor_payload_b64=ok_payload, descriptor_sig_b64=ok_sig)
    node = node_row(mod, "lab-alpha")
    assert mod.winn3_stored_descriptor(node) != {}


def test_an_unusable_pool_degrades_allocation_rather_than_raising(_mod):
    """Defence in depth, kept deliberately unreachable.

    Startup now refuses a bad pool outright, so the runtime None path should
    never be reached in production. It stays because a 503 from an allocation
    would take down an ORDINARY winn/1 login, and v1 is the product while v3 is
    the addition. Removing it would make the next refactor's mistake fatal
    instead of merely degraded.
    """
    try:
        mod = hub_with_pool("10.10.0.0/16")
        with closing(sqlite3.connect(mod._DB)) as conn, conn:
            conn.row_factory = sqlite3.Row
            mod.ensure_schema(conn)
            assert mod.allocate_winn3_inner_ip(conn) == ""
        assert mod.winn3_inner_router_in_pool("10.10.0.1") is False
    finally:
        os.environ.pop("WINN3_INNER_POOL_CIDR", None)


# ================================ runner ===================================
#
# Each entry is (test, ring) -- `ring` is the set of g-slots the hub's
# verification ring holds for that test, because "no keys compiled" and "one
# key compiled" are themselves properties under test.

FULL = ("g1", "g2", "g3")

UNIT_TESTS = [
    (test_core_constants_do_not_drift, FULL),
    (test_padding_policies_match_core, FULL),
    (test_freshness_geometry_matches_core, FULL),
    (test_acceptance_span_is_the_replay_cache_lifetime, FULL),
    (test_freshness_refuses_what_core_refuses, FULL),
    (test_admission_hmac_cost_is_the_product, FULL),
    (test_param_names_that_are_never_served, FULL),
    (test_the_descriptor_is_not_a_protocol_params_key, FULL),
    (test_signature_domain_is_disjoint_from_the_other_two_families, FULL),

    (test_valid_descriptor_round_trip, FULL),
    (test_dual_auth_descriptor_returns_its_attestation_keys, FULL),
    (test_legacy_descriptor_returns_its_dict_not_none, FULL),
    (test_legacy_stored_descriptor_survives_the_serve_path, FULL),
    (test_dual_auth_stored_descriptor_keeps_attestation_keys, FULL),
    (test_descriptor_not_an_object, FULL),
    (test_descriptor_missing_fields, FULL),
    (test_descriptor_unknown_fields, FULL),
    (test_descriptor_format_version_and_algorithm, FULL),
    (test_descriptor_kid_must_be_a_known_slot, FULL),
    (test_descriptor_node_must_match_the_slug, FULL),
    (test_descriptor_endpoint_must_be_an_ip_literal, FULL),
    (test_descriptor_static_pub_must_be_32_bytes, FULL),
    (test_descriptor_gateway_id_bounds, FULL),
    (test_descriptor_admission_secret_floor, FULL),
    (test_descriptor_tag_size_bounds, FULL),
    (test_descriptor_padding_policy, FULL),
    (test_descriptor_freshness_bounds, FULL),
    (test_descriptor_freshness_is_bounded_by_the_rotation_budget, FULL),
    (test_descriptor_ttl_bounds, FULL),
    (test_descriptor_integers_are_not_booleans, FULL),
    (test_descriptor_negative_generation_and_sequence, FULL),

    (test_signature_verifies_with_real_openssl, FULL),
    (test_signature_refuses_a_forged_payload, FULL),
    (test_signature_is_bound_to_its_slot, FULL),
    (test_signature_domain_separation_is_real, FULL),
    (test_signature_length_is_screened_before_openssl, FULL),
    (test_signature_refuses_an_unknown_or_unprovisioned_slot, FULL),
    (test_a_hub_with_no_ring_says_so_rather_than_reporting_a_bad_signature, ()),
    (test_a_partial_ring_names_the_missing_slot, ("g1",)),
    (test_a_malformed_public_key_is_dropped_not_tolerated, "malformed"),

    (test_descriptor_is_not_served_without_winn3, FULL),
    (test_descriptor_is_not_served_without_the_capability, FULL),
    (test_descriptor_is_served_verbatim, FULL),
    (test_descriptor_is_not_served_when_the_stored_blob_does_not_validate, FULL),
    (test_a_forged_signature_in_storage_is_refused_on_the_serve_path, FULL),
    (test_an_expired_descriptor_in_storage_is_refused_on_the_serve_path, FULL),
    (test_a_missing_or_malformed_envelope_is_no_descriptor_not_a_crash, FULL),
    (test_descriptor_inherits_every_refusal_the_winn3_gate_makes, FULL),
    (test_capability_defaults_false_everywhere, FULL),
    (test_request_models_accept_both_wire_spellings, FULL),
    (test_dual_auth_capability_true_releases_both_keys, FULL),
    (test_dual_auth_capability_false_does_not_release_keys, FULL),
    (test_dual_auth_capability_absent_defaults_false, FULL),
    (test_dual_auth_malformed_capability_is_refused, FULL),
    (test_dual_auth_mixed_clients_of_one_node, FULL),
    (test_dual_auth_required_request_is_not_silently_downgraded, FULL),
    (test_dual_auth_capability_preserves_legacy_descriptors_and_winn_policy, FULL),

    (test_rotation_state_is_none_without_a_descriptor, FULL),
    (test_rotation_state_is_steady_after_a_first_install, FULL),
    (test_a_generation_change_opens_an_overlap_with_a_computed_floor, FULL),
    (test_the_retire_floor_moves_with_the_freshness_parameters, FULL),
    (test_a_reissue_of_the_same_generation_does_not_forget_an_open_rotation, FULL),
    (test_rotation_reports_the_reject_path_cost_the_gateway_will_pay, FULL),
    (test_the_two_key_ceiling_is_a_constant_not_a_hope, FULL),

    (test_admin_upload_then_clear, FULL),
    (test_disable_preserves_replay_floor_and_withholds_serving, FULL),
    (test_disable_is_idempotent_and_higher_sequence_reenables, FULL),
    (test_admin_clear_is_never_refused, FULL),
    (test_admin_refuses_a_bad_signature, FULL),
    (test_admin_refuses_bad_base64_and_bad_json, FULL),
    (test_admin_refuses_an_oversized_payload, FULL),
    (test_admin_refuses_a_descriptor_for_another_node, FULL),
    (test_admin_refuses_a_sequence_rollback, FULL),
    (test_admin_refuses_a_descriptor_this_hub_cannot_verify, ("g1",)),
    (test_admin_unknown_node_and_missing_slug, FULL),
    (test_admin_requires_the_admin_token, FULL),
    (test_admin_listing_reports_the_ring_and_the_rotation, FULL),
    (test_admin_listing_on_a_hub_with_no_ring_says_so, ()),
    (test_admin_retire_requires_an_open_rotation, FULL),
    (test_admin_retire_refuses_before_the_floor, FULL),
    (test_admin_retire_forced_is_allowed_and_logged, FULL),
    (test_admin_retire_after_the_floor_has_passed, FULL),
    (test_a_corrupt_ledger_degrades_to_a_report_not_a_crash, FULL),
    (test_the_rotation_clock_stays_inside_the_hubs_naive_utc_contract, FULL),
    (test_an_unreadable_stored_payload_is_no_descriptor, FULL),

    (test_the_admission_secret_never_reaches_a_response_body, FULL),
    (test_no_secret_and_no_address_in_error_bodies, FULL),
    (test_no_secret_and_no_address_in_log_lines, FULL),
    (test_public_fields_never_carry_a_secret_field, FULL),
    (test_the_served_config_carries_the_envelope_and_nothing_else, FULL),

    (test_end_to_end_default_is_unchanged, FULL),
    (test_end_to_end_descriptor_reaches_a_capable_client, FULL),
    (test_end_to_end_stealth_request_gets_neither, FULL),

    # --- the standalone serving path, 2026-08-09 ---------------------------
    (test_winn3_is_a_supported_carrier_and_needs_no_carrier_profile, FULL),
    (test_descriptor_inner_router_must_be_a_plain_dotted_quad, FULL),
    (test_descriptor_resolver_must_match_gateway_bind_address, FULL),
    (test_descriptor_refuses_edge_whitespace_in_operator_values, FULL),
    (test_end_to_end_per_device_standalone_material, FULL),
    (test_peer_registry_binds_issued_public_key_to_inner_address, FULL),
    (test_external_canary_is_required_and_its_identity_is_in_the_registry, FULL),
    (test_schema_repairs_legacy_duplicate_inner_addresses_before_unique_index, FULL),
    (test_concurrent_inner_address_claims_retry_after_unique_collision, FULL),
    (test_peer_registry_sync_is_atomic_and_root_controlled, FULL),
    (test_location_change_bounds_the_previous_node_registry, FULL),
    (test_a_descriptor_outside_the_hub_pool_is_withheld, FULL),

    # --- D15: one pool validator, pinned to exactly /24, 2026-08-12 --------
    # These load their OWN hub per case (each needs a different
    # WINN3_INNER_POOL_CIDR) and ignore the module the runner hands them, so
    # they take `_mod`.
    (test_a_malformed_pool_refuses_startup_and_names_the_value, FULL),
    (test_an_ipv6_pool_refuses_startup, FULL),
    (test_the_pool_is_pinned_to_exactly_a_24, FULL),
    (test_the_startup_guard_cannot_disagree_with_the_validator, FULL),
    (test_the_startup_guard_is_actually_wired_into_startup, FULL),
    (test_host_bits_in_the_pool_are_accepted_but_not_silently, FULL),
    (test_network_and_broadcast_are_not_in_pool_inner_addresses, FULL),
    (test_the_membership_check_accepts_everything_the_allocator_issues, FULL),
    (test_the_allocator_ignores_descriptors_that_fail_verification, FULL),
    (test_a_rotation_cannot_claim_an_issued_device_address, FULL),
    (test_an_expired_descriptor_still_reserves_its_inner_addresses, FULL),
    (test_an_unusable_pool_degrades_allocation_rather_than_raising, FULL),
]


def _hub_for(ring):
    if ring == "malformed":
        # g1 present but 31 bytes: a typo in a build define.
        for slot in ("g1", "g2", "g3"):
            os.environ.pop(f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}", None)
        return harness.load_hub(
            WINN3_DESCRIPTOR_PUBKEY_G1=base64.b64encode(b"x" * 31).decode(),
            WINN3_DESCRIPTOR_PUBKEY_G2=SLOT_PUBS["g2"],
            WINN3_DESCRIPTOR_PUBKEY_G3="not base64!!")
    return load_hub_with_ring(ring)


def main():
    asyncio.set_event_loop(asyncio.new_event_loop())
    print("winn/3 descriptors and admission-key rotation")
    try:
        for fn, ring in UNIT_TESTS:
            # A fresh module + database per test: these mutate node rows and
            # process environment, and a leaked descriptor or key slot would
            # make a later test pass for the wrong reason.
            mod = _hub_for(ring)
            check(fn.__name__, lambda f=fn, m=mod: f(m))
    finally:
        shutil.rmtree(_KEYDIR, ignore_errors=True)
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed, "
          f"{len(UNIT_TESTS)} total")
    for name, tb in FAILURES:
        print()
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
