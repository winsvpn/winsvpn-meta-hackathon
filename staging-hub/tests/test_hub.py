import base64
import hmac
import importlib
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DEMO_KEY = "test-demo-key-local-suite"

# The hub fails closed on import without a >= 16 char DEMO_KEY (D-4); keep the
# suite importable even when it runs standalone (no fixture sets the env yet).
os.environ.setdefault("DEMO_KEY", DEMO_KEY)

HUB_DIR = Path(__file__).resolve().parent.parent
FIELD_MAP = HUB_DIR / "FIELD_MAP.md"

# The forbidden set is pinned here too (not only parsed out of FIELD_MAP.md)
# because dropping every AWG field is the owner's pivot ruling, not just a
# documentation claim.
# server_public_key/server_endpoint/client_ip are DELIBERATELY served as AWG
# compat fields (real hub does the same so VpnConfigValidator.isUsable passes).
FORBIDDEN_FIELDS = (
    "stealth_active",
    "xray",
    "preshared_key",
)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def make_descriptor(slug: str, egress: str, subnet_prefix: str) -> dict:
    """A structurally valid envelope shaped exactly as the supervisor's
    ceremony files (payload JSON per FIELD_MAP.md section 2).

    The signature bytes are DELIBERATELY fake: this lane cannot sign (the
    ceremony private keys live outside the repository). Since the hub now
    verifies signatures at serve time (F-06), these fixtures are only valid
    for NEGATIVE payload-level paths (wrong node, expired, malformed), where
    the refusal reason fires before the signature check. Positive serve-path
    tests must use the real ceremony envelopes from descriptors/ instead."""
    now = int(time.time())
    payload = {
        "v": 3,
        "kid": "g1",
        "node": slug,
        "endpoint": f"{egress}:9111",
        "inner_router_v4": f"{subnet_prefix}.1",
        "inner_resolver_v4": f"{subnet_prefix}.1",
        "static_pub": _b64(bytes(range(32))),
        "gateway_id": _b64(slug.encode()),
        "admission_secret": _b64(bytes((i * 7 + 3) % 256 for i in range(32))),
        "iat": now - 60,
        "not_after": now + 86400,
    }
    return {
        "payload": _b64(json.dumps(payload).encode()),
        "sig": _b64(bytes((i * 3 + 1) % 256 for i in range(64))),
    }


def real_descriptor(slug: str) -> dict:
    """The REAL committed ceremony envelope for a slug (descriptors/<slug>.json).

    Signed by the g1 ceremony key, which is in the pinned ring
    (tools/winn3_descriptor_ring_defines.py), so it must verify at serve time.
    """
    path = HUB_DIR / "descriptors" / f"{slug}.json"
    return json.loads(path.read_text())


# Inside both real demo envelopes' iat/not_after window (2026-08-22 17:04 UTC
# to 2026-08-23 17:04 UTC). Positive serve-path tests freeze the hub's clock
# here so the ceremony files keep verifying even after the demo window closes
# (re-signing is a manual supervisor ceremony).
CEREMONY_WINDOW_NOW = 1787418357.0


def descriptor_payload(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"], validate=True))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    nodes = {
        "announcement": "AI-routed demo network",
        "nodes": [
            {
                "slug": "demo-route-a",
                "name": "AI Route A - US Central",
                "flag": "US",
                "region": "us-central1",
                "subnet": "10.10.0.0/24",
                "egress_ip": "203.0.113.10",
                "gateway_id": "demo-gw-a",
                "listen_port": 9111,
                "reachable": True,
                "winn3_descriptor": {"payload": "TO_BE_SET", "sig": "TO_BE_SET"},
            },
            {
                "slug": "demo-route-b",
                "name": "AI Route B - US East",
                "flag": "US",
                "region": "us-east1",
                "subnet": "10.11.0.0/24",
                "egress_ip": "203.0.113.20",
                "gateway_id": "demo-gw-b",
                "listen_port": 9111,
                "reachable": True,
                "winn3_descriptor": {"payload": "TO_BE_SET", "sig": "TO_BE_SET"},
            },
        ],
    }
    nodes_file = tmp_path / "nodes.json"
    state_file = tmp_path / "state.json"
    descriptors_dir = tmp_path / "descriptors"
    descriptors_dir.mkdir()
    nodes_file.write_text(json.dumps(nodes))
    # Landed supervisor envelopes: the REAL ceremony files, so serve-time
    # signature verification (F-06) passes and positive serve-path tests
    # exercise the actual shipped envelopes rather than unverifiable fakes.
    (descriptors_dir / "demo-route-a.json").write_text(
        json.dumps(real_descriptor("demo-route-a"))
    )
    (descriptors_dir / "demo-route-b.json").write_text(
        json.dumps(real_descriptor("demo-route-b"))
    )
    monkeypatch.setenv("NODES_FILE", str(nodes_file))
    monkeypatch.setenv("STATE_FILE", str(state_file))
    monkeypatch.setenv("DESCRIPTORS_DIR", str(descriptors_dir))
    monkeypatch.setenv("ROUTER_URL", "http://router.invalid")
    monkeypatch.setenv("DEMO_KEY", DEMO_KEY)
    import app as app_module

    importlib.reload(app_module)
    # Freeze the hub's wall clock inside the real envelopes' validity window
    # so ceremony descriptors do not start failing as expired between manual
    # re-signing ceremonies. (monkeypatch restores time.time after each test.)
    monkeypatch.setattr(app_module.time, "time", lambda: CEREMONY_WINDOW_NOW)
    from fastapi.testclient import TestClient

    # Auto-probe on /nodes is exercised by dedicated probe tests with mocked
    # sockets; the existing suite keeps its pre-probe behavior (no network I/O,
    # cached health) so it stays fast and deterministic.
    app_module.PROBE_CACHE_S = 10**9
    app_module._last_probe_cycle_ts = time.time()

    client = TestClient(app_module.app)
    return client, app_module, state_file, descriptors_dir


def free_verify_body(device_id="dev-1", location="auto", public_key="CLIENTPUBKEYABC"):
    return {
        "device_id": device_id,
        "device_fingerprint": device_id,
        "device_model": "Pixel 8",
        "platform": "android",
        "app_version": "1.0.0",
        "locale": "en_US",
        "location": location,
        "stealth_mode": False,
        "double_vpn": False,
        "double_vpn_enabled": False,
        "client_public_key": public_key,
        "supports_awg": True,
        "supports_xray": True,
        "unknown_extra_field": "ignored",
    }


def verify(client, **kwargs):
    response = client.post("/free/verify", json=free_verify_body(**kwargs))
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "authenticated"
    return body


# ---------------------------------------------------------------------------
# (1) FIELD_MAP coverage: every client-required winn/3 field is present and
# well-formed; every forbidden AWG field is absent.
# ---------------------------------------------------------------------------


def _field_map_rows():
    rows = []
    in_table = False
    for line in FIELD_MAP.read_text(encoding="utf-8").splitlines():
        if line.startswith("| field (vpn_config.*)"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 4 and not cells[0].startswith("-") and cells[0]:
                rows.append(cells)
    assert rows, "FIELD_MAP.md vpn_config table not found"
    return rows


def test_field_map_coverage(env):
    """Every row FIELD_MAP.md marks required is served with the exact client
    expectation; every row marked forbidden is absent (and the whole forbidden
    AWG set is absent regardless of the doc)."""
    client, _, _, _ = env
    body = verify(client, device_id="dev-map", location="demo-route-a")
    config = body["vpn_config"]
    selected = body["selected_node"]["slug"]

    required = [row[0] for row in _field_map_rows() if row[1] == "required"]
    assert "protocol_version" in required
    assert "winn3_inner_v4" in required
    assert "winn3_descriptor" in required
    assert "winn3_static_private" in required

    # protocol_version: exactly "winn/3" (dispatch protocol gate).
    assert config["protocol_version"] == "winn/3"
    # protocol_params.carrier: "winn3" (standalone-only platforms refuse else).
    assert config["protocol_params"] == {"carrier": "winn3"}
    # winn3_inner_v4: inner dotted quad inside the SELECTED node's subnet,
    # not the gateway's .1 (client refuses inner_v4 == inner_router_v4).
    inner = config["winn3_inner_v4"]
    octets = [int(o) for o in inner.split(".")]
    assert inner == "10.10.0.2"
    assert octets[-1] >= 2
    # winn3_static_private: base64 of raw bytes (X25519 static, 32 bytes via
    # openssl path; both twin paths emit 32).
    private_raw = base64.b64decode(config["winn3_static_private"], validate=True)
    assert len(private_raw) == 32
    # winn3_descriptor: envelope with payload/sig strings, payload a bounded
    # UTF-8 JSON object whose node slug is the SELECTED node (hub binding).
    envelope = config["winn3_descriptor"]
    assert set(envelope) == {"payload", "sig"}
    payload = descriptor_payload(envelope)
    assert payload["v"] == 3
    assert payload["node"] == selected
    # The real ceremony envelope for demo-route-a (the fixture lands the
    # committed descriptors/, which verify under the pinned g1 key).
    assert payload["endpoint"] == "203.0.113.10:9111"
    assert base64.b64decode(envelope["sig"], validate=True)
    # node_slug / dns / mtu presence and pinned values.
    assert config["node_slug"] == selected
    assert config["dns"] == "1.1.1.1"  # single IP: client isIpv4(dns) rejects comma lists
    assert config["mtu"] == 1280
    # Optional plan fields, when served, must be client-parseable.
    assert config["winn3_path_mtu"] == "1450"
    assert "udp" in config["winn3_carrier_classes"].split(",")

    forbidden = {row[0] for row in _field_map_rows() if row[1] == "forbidden"}
    assert forbidden == set(FORBIDDEN_FIELDS)
    for field in FORBIDDEN_FIELDS:
        assert field not in config
    assert "client_private_key" not in config
    assert config["obfuscation"] == {"Jc": 2, "Jmin": 10, "Jmax": 30, "S1": 16, "S2": 80, "S3": 16, "S4": 0, "H1": 11, "H2": 22, "H3": 33, "H4": 44}

    # Response envelope around vpn_config stands from the prior study.
    assert set(body) >= {
        "status",
        "vpn_config",
        "selected_node",
        "expiration_date",
        "device_auth_token",
        "announcement",
    }
    assert set(body["selected_node"]) == {"slug", "name", "flag", "status"}
    assert body["expiration_date"] == "Free Server"
    assert len(body["device_auth_token"]) == 24


# ---------------------------------------------------------------------------
# (2) auto -> router consulted and its selection honored.
# ---------------------------------------------------------------------------


def test_auto_consults_router_and_honors_selection(env):
    client, app_module, _, _ = env
    captured = {}

    def fake_router(payload):
        captured.update(payload)
        return {
            "selected_route_id": "demo-route-b",
            "decision": "switch",
            "confidence": 0.87,
            "reason_codes": ["latency"],
        }

    app_module.call_router = fake_router
    # Cache design: first verify on a fresh health state serves deterministic
    # while a background thread warms the cache; the SECOND verify honors it.
    verify(client)
    thread = app_module._ROUTER_CACHE.get("thread")
    if thread is not None:
        thread.join(timeout=5)
    body = verify(client)
    assert body["selected_node"]["slug"] == "demo-route-b"
    assert body["vpn_config"]["node_slug"] == "demo-route-b"
    assert body["vpn_config"]["winn3_inner_v4"] == "10.11.0.2"
    assert body["demo_provisioning"]["selection_source"] == "router"
    assert [c["route_id"] for c in captured["candidates"]] == ["demo-route-a", "demo-route-b"]
    # Exercise the real strict router boundary. A Python fake alone previously
    # accepted candidates that the deployed Pydantic schema rejected with 422.
    from router.schemas import RouteRequest

    RouteRequest.model_validate(captured)
    for candidate in captured["candidates"]:
        assert set(candidate) >= {
            "route_id",
            "reachable",
            "protocol_version",
            "carrier",
            "handshake_ms",
            "packet_loss_pct",
            "jitter_ms",
            "dns_ok",
            "recent_failures",
        }
        assert candidate["protocol_version"] == "winn/3"
        assert candidate["carrier"] == "winn3"
    assert set(captured["signals"]) == {"udp_ok", "tcp443_ok", "tls_ok", "control_plane_ok", "dns_ok"}


# ---------------------------------------------------------------------------
# (3) router down -> deterministic pick, still authenticated.
# ---------------------------------------------------------------------------


def test_router_refresh_coalesces_requests_while_in_flight(env, monkeypatch):
    _, app_module, _, _ = env
    started = threading.Event()
    release = threading.Event()
    calls = []

    def blocked_router(payload):
        calls.append(payload)
        started.set()
        release.wait(3)
        return {"selected_route_id": "demo-route-a", "source": "router"}

    monkeypatch.setattr(app_module, "call_router", blocked_router)
    payload = app_module.build_router_payload("dev-refresh")
    try:
        for _ in range(5):
            app_module._refresh_router_cache_async(payload)
        assert started.wait(1)
        assert len(calls) == 1
    finally:
        release.set()
        thread = app_module._ROUTER_CACHE["thread"]
        if thread is not None:
            thread.join(timeout=3)
    # A finished refresh does not block the next one.
    app_module._refresh_router_cache_async(payload)
    app_module._ROUTER_CACHE["thread"].join(timeout=3)
    assert len(calls) == 2


class _RouterResponse:
    def __init__(self, status_code):
        self.status_code = status_code

    def json(self):
        return {"selected_route_id": "demo-route-b", "source": "router"}


def test_router_consult_carries_the_router_hmac_admission(env, monkeypatch):
    _, app_module, _, _ = env
    from router.security import _NONCE_RE, sign_request
    from router.schemas import RouteRequest

    secret = "synthetic-router-test-secret-" + "x" * 16
    monkeypatch.setenv("SMART_ROUTER_HMAC_SECRET", secret)
    monkeypatch.delenv("EDGE_ROUTER_SECRET", raising=False)
    monkeypatch.setattr(app_module, "ROUTER_URL", "https://router.example.test/")
    sent = []

    def fake_post(url, **kwargs):
        sent.append((url, kwargs))
        headers = kwargs.get("headers") or {}
        body = kwargs.get("content", b"")
        expected = sign_request(
            secret, "POST", urlsplit(url).path,
            headers.get("X-Smart-Router-Timestamp", ""),
            headers.get("X-Smart-Router-Nonce", ""), body,
        )
        ok = hmac.compare_digest(headers.get("X-Smart-Router-Signature", ""), expected)
        return _RouterResponse(200 if ok else 401)

    monkeypatch.setattr(app_module.httpx, "post", fake_post)
    payload = app_module.build_router_payload("dev-signed")
    assert app_module.call_router(payload) == {"selected_route_id": "demo-route-b", "source": "router"}
    assert app_module.call_router(payload) is not None
    (url, first), (_, second) = sent
    assert url == "https://router.example.test/route"
    assert json.loads(first["content"]) == payload
    RouteRequest.model_validate_json(first["content"])
    assert _NONCE_RE.fullmatch(first["headers"]["X-Smart-Router-Nonce"])
    assert first["headers"]["X-Smart-Router-Nonce"] != second["headers"]["X-Smart-Router-Nonce"]
    assert abs(time.time() - int(first["headers"]["X-Smart-Router-Timestamp"])) < 5


def test_router_consult_without_secret_makes_no_request(env, monkeypatch):
    _, app_module, _, _ = env
    monkeypatch.delenv("SMART_ROUTER_HMAC_SECRET", raising=False)
    monkeypatch.delenv("EDGE_ROUTER_SECRET", raising=False)
    monkeypatch.setattr(app_module, "ROUTER_URL", "https://router.example.test")
    sent = []
    monkeypatch.setattr(app_module.httpx, "post", lambda *a, **k: sent.append(a) or _RouterResponse(200))
    assert app_module.call_router(app_module.build_router_payload("dev-unsigned")) is None
    assert sent == []


def test_router_down_deterministic_pick_still_authenticated(env):
    client, app_module, _, _ = env
    app_module.call_router = lambda payload: None
    body = verify(client, location="auto")
    assert body["selected_node"]["slug"] == "demo-route-a"
    assert body["vpn_config"]["protocol_version"] == "winn/3"
    decisions = client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).json()["router_decisions"]
    assert decisions[-1]["selection_source"] == "deterministic_fallback"


# ---------------------------------------------------------------------------
# (4) explicit slug honored.
# ---------------------------------------------------------------------------


def test_explicit_slug_honored_when_reachable(env):
    client, _, _, _ = env
    body = verify(client, location="demo-route-b")
    assert body["selected_node"]["slug"] == "demo-route-b"
    assert body["vpn_config"]["node_slug"] == "demo-route-b"
    assert body["demo_provisioning"]["selection_source"] == "explicit"


def test_unreachable_explicit_slug_graceful_fallback(env):
    """Documented choice (stands from the prior study): an unreachable explicit
    slug serves the other reachable node with selected_node set, HTTP 200 +
    authenticated, because 409/503 is a TERMINAL login failure
    (gateway_failover.dart:29-52)."""
    client, _, _, _ = env
    flip = client.post(
        "/admin/health",
        json={"slug": "demo-route-b", "reachable": False},
        headers={"X-Demo-Key": DEMO_KEY},
    )
    assert flip.status_code == 200
    body = verify(client, location="demo-route-b")
    assert body["selected_node"]["slug"] == "demo-route-a"


# ---------------------------------------------------------------------------
# (5) sticky winn3_inner_v4 per device per node subnet.
# ---------------------------------------------------------------------------


def test_sticky_inner_v4(env):
    client, _, state_file, _ = env
    first = verify(client, device_id="dev-sticky")
    again = verify(client, device_id="dev-sticky")
    assert first["vpn_config"]["winn3_inner_v4"] == "10.10.0.2"
    assert again["vpn_config"]["winn3_inner_v4"] == first["vpn_config"]["winn3_inner_v4"]
    other = verify(client, device_id="dev-other")
    assert other["vpn_config"]["winn3_inner_v4"] == "10.10.0.3"
    # Sticky is per (device, node): same device on the other subnet gets that
    # subnet's next address, and returning to the first node keeps its own.
    moved = verify(client, device_id="dev-sticky", location="demo-route-b")
    assert moved["vpn_config"]["winn3_inner_v4"] == "10.11.0.2"
    back = verify(client, device_id="dev-sticky", location="demo-route-a")
    assert back["vpn_config"]["winn3_inner_v4"] == "10.10.0.2"
    stored = json.loads(state_file.read_text())
    assert stored["allocations"]["dev-sticky"]["demo-route-a"] == "10.10.0.2"
    assert stored["allocations"]["dev-sticky"]["demo-route-b"] == "10.11.0.2"
    # The device static key is per DEVICE and sticky across nodes.
    assert (
        moved["vpn_config"]["winn3_static_private"]
        == first["vpn_config"]["winn3_static_private"]
    )
    assert (
        back["vpn_config"]["winn3_static_private"]
        == first["vpn_config"]["winn3_static_private"]
    )
    assert other["vpn_config"]["winn3_static_private"] != first["vpn_config"]["winn3_static_private"]


# ---------------------------------------------------------------------------
# (6) descriptor selection follows the selected node.
# ---------------------------------------------------------------------------


def test_descriptor_selection_follows_node(env):
    client, _, _, descriptors_dir = env
    a = verify(client, device_id="dev-desc-a", location="demo-route-a")
    b = verify(client, device_id="dev-desc-b", location="demo-route-b")
    payload_a = descriptor_payload(a["vpn_config"]["winn3_descriptor"])
    payload_b = descriptor_payload(b["vpn_config"]["winn3_descriptor"])
    assert payload_a["node"] == "demo-route-a"
    assert payload_a["inner_router_v4"] == "10.10.0.1"
    assert payload_b["node"] == "demo-route-b"
    assert payload_b["inner_router_v4"] == "10.11.0.1"
    assert a["vpn_config"]["winn3_descriptor"] != b["vpn_config"]["winn3_descriptor"]
    # Served verbatim from the landed file.
    landed = json.loads((descriptors_dir / "demo-route-a.json").read_text())
    assert a["vpn_config"]["winn3_descriptor"] == landed
    # The device inner address never collides with its node's gateway address.
    assert a["vpn_config"]["winn3_inner_v4"] != payload_a["inner_router_v4"]
    assert b["vpn_config"]["winn3_inner_v4"] != payload_b["inner_router_v4"]


def test_descriptor_missing_served_empty_with_reason(env):
    """Until the supervisor's files land (or if a landed one is bad), the
    envelope is {} and the reason is surfaced in demo_provisioning - fail
    closed and loud, never a fabricated envelope."""
    client, _, _, descriptors_dir = env
    (descriptors_dir / "demo-route-a.json").unlink()
    body = verify(client, device_id="dev-nodesc", location="demo-route-a")
    assert body["vpn_config"]["winn3_descriptor"] == {}
    assert body["demo_provisioning"]["descriptor_source"] == "nodes-json"
    assert body["demo_provisioning"]["descriptor_reason"] == "descriptor-not-landed"
    # A descriptor signed for the WRONG node is refused even from a landed file.
    wrong = make_descriptor("demo-route-b", "203.0.113.20", "10.11.0")
    (descriptors_dir / "demo-route-a.json").write_text(json.dumps(wrong))
    body = verify(client, device_id="dev-nodesc", location="demo-route-a")
    assert body["vpn_config"]["winn3_descriptor"] == {}
    assert body["demo_provisioning"]["descriptor_reason"] == "descriptor-node-mismatch"
    state = client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).json()
    assert state["descriptors"]["demo-route-a"]["served"] is False


def test_forged_descriptor_signature_refused(env):
    """F-06: the hub verifies the Ed25519 signature at serve time, so a forged
    signature on an otherwise shaped, unexpired envelope is refused by name
    instead of being served to the client (the client's refusal is the same
    class, but the forged blob must never leave the hub)."""
    client, _, _, descriptors_dir = env
    forged = real_descriptor("demo-route-a")
    raw = bytearray(base64.b64decode(forged["sig"], validate=True))
    raw[0] ^= 0xFF
    forged["sig"] = _b64(bytes(raw))
    (descriptors_dir / "demo-route-a.json").write_text(json.dumps(forged))
    body = verify(client, device_id="dev-forged", location="demo-route-a")
    assert body["vpn_config"]["winn3_descriptor"] == {}
    assert body["demo_provisioning"]["descriptor_source"] == "file"
    assert body["demo_provisioning"]["descriptor_reason"] == "descriptor-signature-invalid"


def test_short_forged_descriptor_signature_refused(env):
    """The 37-byte forged signature shape is refused: anything that is not
    exactly 64 bytes can never be an Ed25519 signature for this envelope, so
    it is refused by name rather than handed to openssl or served."""
    client, _, _, descriptors_dir = env
    forged = real_descriptor("demo-route-a")
    forged["sig"] = _b64(bytes((i * 5 + 2) % 256 for i in range(37)))
    (descriptors_dir / "demo-route-a.json").write_text(json.dumps(forged))
    body = verify(client, device_id="dev-short-forged", location="demo-route-a")
    assert body["vpn_config"]["winn3_descriptor"] == {}
    assert body["demo_provisioning"]["descriptor_reason"] == "descriptor-signature-invalid"


def test_valid_ceremony_descriptor_served(env):
    """Positive control for F-06: the committed ceremony envelope (signed by
    the g1 ceremony key, which is in the pinned ring) verifies and is served
    verbatim with reason winn3-descriptor."""
    client, _, _, descriptors_dir = env
    body = verify(client, device_id="dev-valid-desc", location="demo-route-a")
    served = body["vpn_config"]["winn3_descriptor"]
    landed = json.loads((descriptors_dir / "demo-route-a.json").read_text())
    assert served == landed
    assert body["demo_provisioning"]["descriptor_source"] == "file"
    assert body["demo_provisioning"]["descriptor_reason"] == "winn3-descriptor"
    payload = descriptor_payload(served)
    assert payload["kid"] == "g1"


# ---------------------------------------------------------------------------
# (7) /nodes envelope unchanged.
# ---------------------------------------------------------------------------


def test_nodes_envelope_unchanged(env):
    """Same envelope as the AWG era (structure is the app parser's contract,
    main.dart _parseNodesResponse :8279-8369 / _normalizeNodeItem :4031-4069);
    only inventory values (egress, port 9111) changed."""
    client, _, _, _ = env
    body = client.get("/nodes").json()
    assert set(body) >= {
        "nodes",
        "free_access",
        "maintenance",
        "min_supported_app_version",
        "app_update_url",
        "double_vpn_available",
        "announcement",
    }
    assert body["maintenance"] is False
    assert body["min_supported_app_version"] == ""
    assert body["app_update_url"] == ""
    assert body["double_vpn_available"] is False
    assert body["announcement"] == "AI-routed demo network"
    assert body["free_access"]["node_slugs"] == ["demo-route-a", "demo-route-b"]
    assert len(body["nodes"]) == 2
    for node in body["nodes"]:
        assert set(node) >= {
            "name",
            "flag",
            "slug",
            "status",
            "endpoint",
            "free_access_enabled",
            "direct_awg_enabled",
            "protocol_version",
            "reachable",
            "transports",
            "regional_aliases",
        }
        assert node["status"] == "online"
        assert node["free_access_enabled"] is True
        assert node["reachable"] is True
        assert node["endpoint"].endswith(":9111")
    slugs = {n["slug"] for n in body["nodes"]}
    assert slugs == {"demo-route-a", "demo-route-b"}


# ---------------------------------------------------------------------------
# (8) admin health flip flows recent_failures to the router.
# ---------------------------------------------------------------------------


def test_health_flip_flows_recent_failures_to_router(env):
    client, app_module, _, _ = env
    captured = {}

    def fake_router(payload):
        captured["payload"] = payload
        return {"selected_route_id": "demo-route-a", "decision": "keep", "confidence": 0.9, "reason_codes": []}

    app_module.call_router = fake_router
    assert (
        client.post(
            "/admin/health",
            json={"slug": "demo-route-b", "reachable": False},
            headers={"X-Demo-Key": DEMO_KEY},
        ).status_code
        == 200
    )
    nodes = client.get("/nodes").json()["nodes"]
    by_slug = {n["slug"]: n for n in nodes}
    assert by_slug["demo-route-b"]["reachable"] is False
    assert by_slug["demo-route-b"]["status"] == "offline"
    assert by_slug["demo-route-b"]["transports"]["udp"] == "down"
    assert by_slug["demo-route-a"]["reachable"] is True
    assert client.post("/free/verify", json=free_verify_body()).status_code == 200
    candidates = {c["route_id"]: c for c in captured["payload"]["candidates"]}
    assert candidates["demo-route-b"]["reachable"] is False
    assert candidates["demo-route-b"]["recent_failures"] >= 1
    state = client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).json()
    assert state["nodes"]["demo-route-b"]["recent_failures"] >= 1


# ---------------------------------------------------------------------------
# Retained guardrails (not part of the 8, still required to pass).
# ---------------------------------------------------------------------------


def test_admin_requires_demo_key(env):
    client, _, _, _ = env
    assert client.get("/admin/state").status_code == 401
    assert client.get("/admin/state", headers={"X-Demo-Key": "wrong"}).status_code == 401
    assert client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).status_code == 200


def test_admin_state_hides_private_material(env):
    client, _, state_file, _ = env
    verify(client, device_id="dev-secret")
    state = json.loads(state_file.read_text())
    served = verify(client, device_id="dev-secret")["vpn_config"]["winn3_static_private"]
    assert "static_private" not in json.dumps(
        client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).json()
    )
    assert state["winn3_devices"]["dev-secret"]["static_private"] == served


def test_state_file_private_material_is_owner_only(env):
    client, _, state_file, _ = env
    old_umask = os.umask(0o022)
    try:
        verify(client, device_id="dev-private-state")
        assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
        state_file.chmod(0o644)
        verify(client, device_id="dev-private-state-2")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert "dev-private-state-2" in json.loads(state_file.read_text())["winn3_devices"]
    assert list(state_file.parent.glob("." + state_file.name + ".*")) == []
    assert not state_file.with_suffix(state_file.suffix + ".tmp").exists()


def test_missing_device_id_rejected(env):
    client, _, _, _ = env
    response = client.post("/free/verify", json={"location": "auto"})
    assert response.status_code == 400
    assert response.json()["detail"] == "missing device_id"


def test_free_status_and_all_nodes_down(env):
    client, _, _, _ = env
    assert client.get("/free/status").json() == {
        "status": "ok",
        "free_access": True,
        "maintenance": False,
    }
    for slug in ("demo-route-a", "demo-route-b"):
        client.post("/admin/health", json={"slug": slug, "reachable": False}, headers={"X-Demo-Key": DEMO_KEY})
    status = client.get("/free/status").json()
    assert status == {"status": "unavailable", "free_access": True, "maintenance": False}
    verify_response = client.post("/free/verify", json=free_verify_body())
    assert verify_response.status_code == 503
    assert "not online" in verify_response.json()["detail"]


def test_inner_pool_exhaustion_and_gateway_reservation(env):
    """The descriptor's gateway addresses are reserved: with a /30 there is
    exactly one allocatable host (.2), so the second device 503s rather than
    colliding with the next hop."""
    tmp_nodes = json.loads((Path(os.environ["NODES_FILE"])).read_text())
    tmp_nodes["nodes"] = [tmp_nodes["nodes"][0]]
    tmp_nodes["nodes"][0]["subnet"] = "10.10.0.0/30"
    Path(os.environ["NODES_FILE"]).write_text(json.dumps(tmp_nodes))
    import app as app_module

    importlib.reload(app_module)
    from fastapi.testclient import TestClient

    client = TestClient(app_module.app)
    first = client.post("/free/verify", json=free_verify_body(device_id="dev-pool-1", location="demo-route-a"))
    assert first.status_code == 200
    assert first.json()["vpn_config"]["winn3_inner_v4"] == "10.10.0.2"
    second = client.post("/free/verify", json=free_verify_body(device_id="dev-pool-2", location="demo-route-a"))
    assert second.status_code == 503


# ---------------------------------------------------------------------------
# (9) REAL TCP probes (mocked sockets): failure flips health + failures, success
# records latency / recovers, /nodes auto-probes at most every cache window.
# ---------------------------------------------------------------------------


class _FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _probe_ready(app_module, monkeypatch):
    """Force the next /nodes (or /admin/probe) to run a probe cycle and stub
    socket.create_connection with `fn(hostport, timeout)` returning _FakeConn
    or raising OSError."""
    app_module.PROBE_CACHE_S = 30.0
    app_module._last_probe_cycle_ts = 0.0

    def patch(fn):
        monkeypatch.setattr(app_module.socket, "create_connection", fn)

    return patch


def test_admin_probe_failure_marks_node_offline_and_increments_failures(env, monkeypatch):
    client, app_module, _, _ = env
    patch = _probe_ready(app_module, monkeypatch)

    def refuse(hostport, timeout=None):
        raise OSError("simulated gateway down")

    patch(refuse)
    result = client.post("/admin/probe", headers={"X-Demo-Key": DEMO_KEY}).json()
    assert result["probes"] == {"demo-route-a": None, "demo-route-b": None}
    state = client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).json()["nodes"]
    for slug in ("demo-route-a", "demo-route-b"):
        assert state[slug]["reachable"] is False
        assert state[slug]["latency_ms"] is None
        assert state[slug]["last_probe_ts"] is not None
        assert state[slug]["recent_failures"] == 1
    nodes = client.get("/nodes").json()["nodes"]
    by_slug = {n["slug"]: n for n in nodes}
    assert by_slug["demo-route-a"]["reachable"] is False
    assert by_slug["demo-route-a"]["status"] == "offline"
    assert by_slug["demo-route-a"]["transports"]["udp"] == "down"


def test_probe_success_records_latency(env, monkeypatch):
    client, app_module, _, _ = env
    patch = _probe_ready(app_module, monkeypatch)

    def ok(hostport, timeout=None):
        return _FakeConn()

    patch(ok)
    result = client.post("/admin/probe", headers={"X-Demo-Key": DEMO_KEY}).json()
    for slug in ("demo-route-a", "demo-route-b"):
        assert result["probes"][slug] >= 1
    state = client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).json()["nodes"]
    for slug in ("demo-route-a", "demo-route-b"):
        assert state[slug]["reachable"] is True
        assert state[slug]["latency_ms"] >= 1
        assert state[slug]["last_probe_ts"] is not None


def test_probe_recovers_admin_flipped_node(env, monkeypatch):
    """A successful probe on a node the admin flipped down restores it: the
    probe reflects reality in addition to the manual flip."""
    client, app_module, _, _ = env
    client.post(
        "/admin/health",
        json={"slug": "demo-route-b", "reachable": False},
        headers={"X-Demo-Key": DEMO_KEY},
    )
    patch = _probe_ready(app_module, monkeypatch)

    def ok(hostport, timeout=None):
        return _FakeConn()

    patch(ok)
    client.post("/admin/probe", headers={"X-Demo-Key": DEMO_KEY})
    state = client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).json()["nodes"]
    assert state["demo-route-b"]["reachable"] is True
    assert state["demo-route-b"]["recent_failures"] == 0


def test_nodes_auto_probes_at_most_every_cache_window(env, monkeypatch):
    client, app_module, _, _ = env
    app_module.PROBE_CACHE_S = 30.0
    app_module._last_probe_cycle_ts = 0.0
    calls = {"n": 0}

    def ok(hostport, timeout=None):
        calls["n"] += 1
        return _FakeConn()

    monkeypatch.setattr(app_module.socket, "create_connection", ok)
    client.get("/nodes")
    first_pass = calls["n"]
    assert first_pass == 2  # one probe per node
    client.get("/nodes")
    client.get("/nodes")
    assert calls["n"] == first_pass  # cached inside the 30s window
    app_module._last_probe_cycle_ts = 0.0
    client.get("/nodes")
    assert calls["n"] == first_pass + 2  # window elapsed -> new probe pass


def test_admin_state_uptime_and_probe_fields(env):
    client, _, _, _ = env
    state = client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).json()
    assert isinstance(state["uptime_s"], int) and state["uptime_s"] >= 0
    for slug in ("demo-route-a", "demo-route-b"):
        node = state["nodes"][slug]
        assert "reachable" in node
        assert "recent_failures" in node
        assert "latency_ms" in node
        assert "last_probe_ts" in node
    assert isinstance(state["router_decisions"], list)


def test_landed_ceremony_descriptors_pass_identity_checks():
    """The REAL supervisor ceremony files in descriptors/ (not fixtures) must
    keep passing the twin's identity checks and stay inside their lifetime, or
    the demo login breaks (client refuses by name winn3DescriptorUnverified).

    This is the shipping guard: it re-reads the actual on-disk envelopes so a
    stale/expired/wrong-node descriptor is caught by the suite before the demo,
    not on the day of the carry run."""
    import app as app_module

    landed_dir = HUB_DIR / "descriptors"
    app_module.DESCRIPTORS_DIR = landed_dir
    for slug in ("demo-route-a", "demo-route-b"):
        path = landed_dir / f"{slug}.json"
        assert path.is_file(), f"ceremony descriptor missing: {path}"
        envelope = app_module._parse_descriptor_envelope(
            json.loads(path.read_text()))
        assert envelope, f"{slug}: landed file is not a payload/sig envelope"
        payload = app_module._decode_descriptor_payload(envelope)
        assert payload, f"{slug}: payload not bounded UTF-8 JSON"
        problem = app_module._descriptor_payload_problems(payload, slug)
        assert problem == "", f"{slug}: ceremony descriptor refused: {problem}"
        assert payload["node"] == slug
        assert payload["kid"] == "g1"
        # The twin serves the envelope byte-verbatim: never re-encoded.
        served = app_module.descriptor_for_node(
            {"slug": slug, "winn3_descriptor": {"payload": "TO_BE_SET"}})
        assert served[0] == envelope
        assert served[3] == "winn3-descriptor"
    # Fresh enough for the demo window: not_after must still be in the future
    # with a generous safety margin (the signing ceremony is a manual step).
    now = time.time()
    for slug in ("demo-route-a", "demo-route-b"):
        envelope = app_module._parse_descriptor_envelope(
            json.loads((landed_dir / f"{slug}.json").read_text()))
        payload = app_module._decode_descriptor_payload(envelope)
        assert payload["not_after"] - now > 3600, (
            f"{slug}: ceremony descriptor expires within 1h "
            f"(not_after={payload['not_after']})")


# ---------------------------------------------------------------------------
# (10) Hardening lanes: startup fail-closes without a real DEMO_KEY (D-4) and
# /admin/* is throttled per client (D-2, 30/min sliding window + daily cap)
# while the public paths stay unthrottled.
# ---------------------------------------------------------------------------


def test_startup_refuses_missing_or_short_demo_key():
    """Importing app without a valid DEMO_KEY in the environment must fail
    closed (RuntimeError), never boot a guessable-default admin surface."""
    import subprocess

    for env_setup in (
        "os.environ.pop('DEMO_KEY', None)",
        "os.environ['DEMO_KEY'] = 'short'",
    ):
        result = subprocess.run(
            [sys.executable, "-c", f"import os; {env_setup}; import app"],
            cwd=HUB_DIR,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode != 0, result.stdout + result.stderr


def test_admin_endpoints_rate_limited_per_minute(env):
    client, _, _, _ = env
    for _ in range(30):
        assert (
            client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).status_code
            == 200
        )
    assert client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).status_code == 429


def test_admin_unauthenticated_guesses_hit_same_window(env):
    """Bad x_demo_key guesses count against the same per-client window, so key
    guess floods are throttled exactly like authenticated floods."""
    client, _, _, _ = env
    for _ in range(30):
        assert (
            client.get("/admin/state", headers={"X-Demo-Key": "wrong-key"}).status_code
            == 401
        )
    assert client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).status_code == 429


def test_admin_daily_cap(env):
    client, app_module, _, _ = env
    with app_module.ADMIN_RATE_LIMITER._lock:
        app_module.ADMIN_RATE_LIMITER._daily[
            ("testclient", time.strftime("%Y-%m-%d"))
        ] = app_module.ADMIN_REQUESTS_PER_DAY
    assert client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).status_code == 429


def test_public_paths_unaffected_by_admin_limit(env):
    client, app_module, _, _ = env
    with app_module.ADMIN_RATE_LIMITER._lock:
        app_module.ADMIN_RATE_LIMITER._daily[
            ("testclient", time.strftime("%Y-%m-%d"))
        ] = app_module.ADMIN_REQUESTS_PER_DAY
    assert client.get("/admin/state", headers={"X-Demo-Key": DEMO_KEY}).status_code == 429
    assert client.get("/nodes").status_code == 200
    assert client.get("/free/status").status_code == 200
    assert client.get("/health").status_code == 200


def test_health_reuses_cached_signature_verdict(env, monkeypatch):
    """Descriptor signature verdicts are time-independent: repeated public
    /health calls verify each landed envelope with openssl at most once."""
    client, app_module, _, _ = env
    calls = {"pkeyutl": 0}
    real_run = app_module.subprocess.run

    def counting_run(args, *a, **kw):
        if isinstance(args, (list, tuple)) and "pkeyutl" in [str(x) for x in args]:
            calls["pkeyutl"] += 1
        return real_run(args, *a, **kw)

    monkeypatch.setattr(app_module.subprocess, "run", counting_run)
    for _ in range(3):
        assert client.get("/health").status_code == 200
    # Two landed nodes, verified once each across all three calls.
    assert calls["pkeyutl"] == 2


def test_verify_rejects_malformed_device_id(env):
    client, _, _, _ = env
    assert client.post("/free/verify", json=free_verify_body(device_id="x" * 65)).status_code == 400
    assert client.post("/free/verify", json=free_verify_body(device_id="../etc")).status_code == 400
    assert client.post("/free/verify", json=free_verify_body(device_id="ok-device-1")).status_code == 200


def test_verify_rate_limited_per_client(env, monkeypatch):
    client, app_module, _, _ = env
    monkeypatch.setattr(
        app_module, "VERIFY_RATE_LIMITER", app_module._AdminRateLimiter(2, 100, 60.0)
    )
    assert client.post("/free/verify", json=free_verify_body(device_id="rl-1")).status_code == 200
    assert client.post("/free/verify", json=free_verify_body(device_id="rl-1")).status_code == 200
    assert client.post("/free/verify", json=free_verify_body(device_id="rl-1")).status_code == 429


def test_verify_device_capacity_is_bounded(env, monkeypatch):
    client, app_module, _, _ = env
    monkeypatch.setattr(app_module, "MAX_DEVICES", 1)
    assert client.post("/free/verify", json=free_verify_body(device_id="cap-1")).status_code == 200
    assert client.post("/free/verify", json=free_verify_body(device_id="cap-2")).status_code == 503
    # An existing device is never refused by the cap.
    assert client.post("/free/verify", json=free_verify_body(device_id="cap-1")).status_code == 200
