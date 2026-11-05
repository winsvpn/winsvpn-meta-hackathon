import base64
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("staging-hub")
log.setLevel(logging.WARNING if os.environ.get("QUIET") else logging.INFO)

BASE_DIR = Path(__file__).resolve().parent
NODES_FILE = Path(os.environ.get("NODES_FILE", BASE_DIR / "nodes.json"))
STATE_FILE = Path(os.environ.get("STATE_FILE", BASE_DIR / "state.json"))
DESCRIPTORS_DIR = Path(os.environ.get("DESCRIPTORS_DIR", BASE_DIR / "descriptors"))
ROUTER_URL = os.environ.get("ROUTER_URL", "").strip()
# D-4: no default admin key. The historical baked-in default is removed;
# DEMO_KEY must come from the environment and be >= 16 characters or the hub
# refuses to import/start (fail closed). An unconfigured deploy must never
# expose a guessable /admin surface.
DEMO_KEY = os.environ.get("DEMO_KEY", "")
if not DEMO_KEY or len(DEMO_KEY) < 16:
    raise RuntimeError(
        "DEMO_KEY is required and must be at least 16 characters; "
        "refusing to start with a missing or trivial admin key"
    )
# Gemini's minimum API deadline is 10s and real decisions return in ~4s;
# supervisor rule: consult timeout must be 12s (SUPERVISOR_NOTES.md). Fail-open
# order is unchanged: unreachable/slow/malformed -> deterministic local pick.
ROUTER_TIMEOUT_S = float(os.environ.get("ROUTER_TIMEOUT_S", "12.0"))
# Real TCP connect probe against each gateway egress_ip:9111. Unreachable
# hosts are detected by the connect failing (or not completing) within the
# timeout; 3s keeps the probe tight for a live demo while still completing on
# slow-but-UP gateways. Nodes with no egress_ip (TO_BE_SET) report no probe.
PROBE_TIMEOUT_S = float(os.environ.get("PROBE_TIMEOUT_S", "3.0"))
# Automatic probe pass runs on /nodes fetch at most this often; between passes
# the cached latency/health from the last probe is served. /admin/probe forces
# a pass immediately (and resets the cache window).
PROBE_CACHE_S = float(os.environ.get("PROBE_CACHE_S", "30.0"))
MAX_ROUTER_DECISIONS = 50
TO_BE_SET = "TO_BE_SET"

# Winn Protocol v3 standalone serving constants (SPEC v2). Field names are
# extracted from the client dispatch (winn_protocol_dispatch.dart) and the real
# hub (server/wins_control_plane_setup_ONETOUCH.sh); see FIELD_MAP.md.
WINN_PROTOCOL_V3 = "winn/3"
WINN3_CARRIER = "winn3"
WINN3_DESCRIPTOR_FORMAT_VERSION = 3
WINN3_MAX_DESCRIPTOR_BYTES = 4096

# F-06 serve-time signature verification. The same constants the production
# hub pins (server/wins_control_plane_setup_ONETOUCH.sh): domain prefix,
# key slots, and the RFC 8410 Ed25519 SubjectPublicKeyInfo prefix wrapped
# around the raw 32-byte ceremony keys.
WINN3_DESCRIPTOR_DOMAIN = b"winsvpn-winn3-descriptor/v1"
WINN3_DESCRIPTOR_KEY_SLOTS = ("g1", "g2", "g3")
WINN3_ED25519_PUBLIC_KEY_BYTES = 32
WINN3_ED25519_SIGNATURE_BYTES = 64
WINN3_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _ed25519_spki_pem(raw_key: bytes) -> str:
    """An RFC 8410 'PUBLIC KEY' PEM rebuilt around a raw 32-byte Ed25519 key.

    The ceremony (tools/winn3_descriptor_ring_defines.py) emits the raw key
    base64 because that is what a --dart-define carries; openssl pkeyutl wants
    an SPKI, so one is rebuilt here exactly as the production hub does
    (ONETOUCH WINN3_ED25519_SPKI_PREFIX)."""
    encoded = base64.b64encode(WINN3_ED25519_SPKI_PREFIX + raw_key).decode("ascii")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(lines)
        + "\n-----END PUBLIC KEY-----\n"
    )


def _load_descriptor_ring() -> dict[str, str]:
    """{slot: SPKI PEM} from the pinned ceremony ring (tools/..._ring_defines.py).

    Resolution order: WINN3_DESCRIPTOR_RING_DEFINES env override, the repo
    source of record (../tools/...), then a copy staged next to app.py (the
    Docker image carries one because the build context cannot reach ../tools).
    """
    candidates = [
        os.environ.get("WINN3_DESCRIPTOR_RING_DEFINES", "").strip(),
        str(BASE_DIR.parent / "tools" / "winn3_descriptor_ring_defines.py"),
        str(BASE_DIR / "winn3_descriptor_ring_defines.py"),
    ]
    defines_path = next(
        (Path(candidate) for candidate in candidates if candidate and Path(candidate).is_file()),
        None,
    )
    if defines_path is None:
        raise RuntimeError(
            "descriptor ring defines not found (tried WINN3_DESCRIPTOR_RING_DEFINES, "
            "tools/winn3_descriptor_ring_defines.py, and a copy beside app.py)"
        )
    spec = importlib.util.spec_from_file_location(
        "winn3_descriptor_ring_defines", str(defines_path)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load descriptor ring defines from {defines_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ring: dict[str, str] = {}
    for slot in WINN3_DESCRIPTOR_KEY_SLOTS:
        encoded = str(module.RING.get(slot) or "")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except Exception as error:
            raise RuntimeError(f"descriptor ring slot {slot} is not base64") from error
        if len(raw) != WINN3_ED25519_PUBLIC_KEY_BYTES:
            raise RuntimeError(
                f"descriptor ring slot {slot} is {len(raw)} bytes, expected 32"
            )
        ring[slot] = _ed25519_spki_pem(raw)
    return ring


def _resolve_openssl() -> str:
    """A working OpenSSL >= 3 binary (pkeyutl -rawin Ed25519 needs it).

    LibreSSL (macOS /usr/bin/openssl) cannot verify Ed25519 with -rawin, so
    the binary is capability-checked rather than assumed. Returns "" when
    none is found: verification then fails closed on every envelope."""
    candidates = [os.environ.get("OPENSSL_BIN", "").strip()]
    candidates += [
        "openssl",
        "/opt/homebrew/opt/openssl/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/opt/openssl/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/bin/openssl",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = shutil.which(candidate) if "/" not in candidate else candidate
        if not path or not os.access(path, os.X_OK):
            continue
        try:
            result = subprocess.run(
                [path, "version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            continue
        version_line = (result.stdout or "").strip()
        if result.returncode == 0 and re.match(r"^OpenSSL [3-9]\.", version_line):
            return path
    return ""


# Ring material is derived ONCE at import into a private cache directory:
# mode-700 directory, mode-600 per-slot PEM files, never regenerated per
# request. (Alternative to a persistent 600 cache file; same one-time
# derivation contract, nothing secret either way -- these are public keys.)
_RING_CACHE_DIR = tempfile.mkdtemp(prefix="winn3-ring-")
os.chmod(_RING_CACHE_DIR, 0o700)
_RING_KEY_PATHS: dict[str, str] = {}
for _slot, _pem in _load_descriptor_ring().items():
    _key_path = Path(_RING_CACHE_DIR) / f"{_slot}.pem"
    with open(_key_path, "w", encoding="ascii") as _handle:
        _handle.write(_pem)
    os.chmod(_key_path, 0o600)
    _RING_KEY_PATHS[_slot] = str(_key_path)

_OPENSSL_BIN = _resolve_openssl()
if not _OPENSSL_BIN:
    log.error(
        "no OpenSSL >= 3 binary found; winn3 descriptor signature verification "
        "will refuse every envelope (fail closed)"
    )

VPN_DNS = os.environ.get("VPN_DNS", "1.1.1.1,1.0.0.1")
# The real hub serves vpn_config["mtu"] = 1280 byte-for-byte (ONETOUCH:18199);
# the v3 datapath sizes itself from winn3_path_mtu instead
# (winn_protocol_dispatch.dart:2597-2627). Fleet default plan is 1450/udp
# (ONETOUCH WINN3_DEFAULT_PATH_MTU :9254, classes default :9768).
VPN_MTU = int(os.environ.get("VPN_MTU", "1280"))
WINN3_PATH_MTU = str(os.environ.get("WINN3_PATH_MTU", "1450"))
WINN3_CARRIER_CLASSES = os.environ.get("WINN3_CARRIER_CLASSES", "udp")
EXPIRATION_DATE = "Free Server"

# RFC 8410 SubjectPublicKeyInfo prefix for X25519 and the DER lengths, exactly
# as the real hub unwraps them (ONETOUCH:11674-11683): winn/3 wants the RAW 32
# bytes base64, not the wrapped key openssl emits.
WINN3_X25519_SPKI_PREFIX = bytes.fromhex("302a300506032b656e032100")
WINN3_X25519_SPKI_BYTES = 44
WINN3_X25519_PKCS8_BYTES = 48
WINN3_X25519_KEY_BYTES = 32

_state_lock = threading.Lock()
_probe_lock = threading.Lock()
_last_probe_cycle_ts = 0.0
_START_TS = time.monotonic()

# D-2: in-memory admin rate limiting, stdlib only. Per client IP: a sliding
# window of at most ADMIN_REQUESTS_PER_MINUTE hits per 60s plus an absolute
# ADMIN_REQUESTS_PER_DAY daily cap on top, guarded by one lock. Only allowed
# requests consume window slots, so a denied flood stays denied without extra
# bookkeeping. State is keyed per active IP and pruned on every check
# (bounded memory, nothing on disk; this hub is a single-process uvicorn
# deploy so module-level state is authoritative).
ADMIN_REQUESTS_PER_MINUTE = int(os.environ.get("ADMIN_RATE_LIMIT_PER_MIN", "30"))
ADMIN_REQUESTS_PER_DAY = int(os.environ.get("ADMIN_RATE_LIMIT_PER_DAY", "500"))
_ADMIN_WINDOW_S = 60.0

# Logs never carry the raw client address: the same keyed-HMAC source bucket
# expression as the production hub (server/wins_control_plane_setup_ONETOUCH.sh
# security_event_hash: HMAC-SHA256 of the value under a secret, first 16 hex).
# The key is RATE_LIMIT_SECRET when set, else this process's DEMO_KEY (never
# logged, printed or served, and required to be >= 16 chars at startup).
_RATE_LIMIT_HMAC_KEY = os.environ.get("RATE_LIMIT_SECRET", "") or DEMO_KEY


def _security_event_bucket(value: str) -> str:
    return hmac.new(
        _RATE_LIMIT_HMAC_KEY.encode(), str(value or "").encode(), hashlib.sha256
    ).hexdigest()[:16]


class _AdminRateLimiter:
    def __init__(self, per_minute: int, per_day: int, window_s: float) -> None:
        self.per_minute = per_minute
        self.per_day = per_day
        self.window_s = window_s
        self._lock = threading.Lock()
        self._sliding: dict[str, deque] = {}
        self._daily: dict[tuple[str, str], int] = {}

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        day = time.strftime("%Y-%m-%d")
        with self._lock:
            window = self._sliding.setdefault(ip, deque())
            cutoff = now - self.window_s
            while window and window[0] <= cutoff:
                window.popleft()
            if (
                len(window) >= self.per_minute
                or self._daily.get((ip, day), 0) >= self.per_day
            ):
                return False
            window.append(now)
            self._daily[(ip, day)] = self._daily.get((ip, day), 0) + 1
            for key in [key for key in self._daily if key[1] != day]:
                self._daily.pop(key, None)
            return True


ADMIN_RATE_LIMITER = _AdminRateLimiter(
    ADMIN_REQUESTS_PER_MINUTE, ADMIN_REQUESTS_PER_DAY, _ADMIN_WINDOW_S
)

# The public verify path is bounded the same way: a real client verifies once
# per connect, and every new device_id costs this hub key minting plus a full
# state rewrite and a permanent state entry. Without bounds an unauthenticated
# caller turns that into disk growth and process-spawn load.
VERIFY_REQUESTS_PER_MINUTE = int(os.environ.get("VERIFY_RATE_LIMIT_PER_MIN", "60"))
VERIFY_REQUESTS_PER_DAY = int(os.environ.get("VERIFY_RATE_LIMIT_PER_DAY", "2000"))
VERIFY_RATE_LIMITER = _AdminRateLimiter(
    VERIFY_REQUESTS_PER_MINUTE, VERIFY_REQUESTS_PER_DAY, _ADMIN_WINDOW_S
)
MAX_DEVICES = int(os.environ.get("STAGING_MAX_DEVICES", "1000"))
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


def _admin_rate_limited(request: Request) -> None:
    """FastAPI dependency: throttle every /admin/* call per client IP.

    Runs before the handler (and before the demo-key compare), so x_demo_key
    guess floods and authenticated request floods share one window. The direct
    client address (request.client.host) is used; this hub is a single-process
    uvicorn deploy, so the module-level limiter sees every admin request.
    """
    client_ip = getattr(request.client, "host", "") if request.client else ""
    ip = str(client_ip or "unknown")
    if not ADMIN_RATE_LIMITER.allow(ip):
        log.warning(
            "admin rate limit exceeded from source bucket %s",
            _security_event_bucket(ip),
        )
        raise HTTPException(status_code=429, detail="too many admin requests")


def _parse_descriptor_envelope(raw: Any) -> dict[str, str]:
    """A descriptor envelope {"payload": b64, "sig": b64}, or {} when absent.

    Field names and String-typing mirror the client reader
    (winn_protocol_dispatch.dart:1716-1741, keys "payload" and "sig") and the
    hub's stored-envelope parser (ONETOUCH parse_winn3_descriptor_envelope
    :10647-10665). The twin serves the envelope VERBATIM: it never re-encodes
    and never decodes-and-rebuilds. Signature VERIFICATION happens at serve
    time in _descriptor_signature_problem (F-06), not in this parser.
    """
    if not isinstance(raw, dict):
        return {}
    payload = str(raw.get("payload") or "").strip()
    signature = str(raw.get("sig") or "").strip()
    if not payload or not signature:
        return {}
    return {"payload": payload, "sig": signature}


def _decode_descriptor_payload(envelope: dict[str, str]) -> Optional[dict[str, Any]]:
    """The decoded, JSON-object payload of a shaped envelope, or None.

    Shape-only, mirroring the client's pre-verification bounds
    (dispatch:1765-1795): base64 with validate, <=4096 decoded bytes, UTF-8
    JSON object. No field values are interpreted here beyond the checks in
    _descriptor_payload_problems.
    """
    if not envelope:
        return None
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
    except Exception:
        return None
    if not raw or len(raw) > WINN3_MAX_DESCRIPTOR_BYTES:
        return None
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def _descriptor_payload_problems(payload: dict[str, Any], slug: str) -> str:
    """Named, non-secret reasons a descriptor cannot be served for this node.

    Only the checks that bind the descriptor to THIS node's identity and clock:
    format version (dispatch:1826-1830), node slug inside the signed bytes
    (ONETOUCH validate_winn3_descriptor_payload :10483-10493 refuses a
    descriptor installed on the wrong node), and lifetime shape/expiry
    (dispatch:1831-1843). Everything else is the phone's to verify
    (Ed25519 over DOMAIN||0x00||payload) and the supervisor ceremony's to mint.
    """
    if payload.get("v") != WINN3_DESCRIPTOR_FORMAT_VERSION:
        return "descriptor-unsupported-format-version"
    if str(payload.get("node") or "").strip().lower() != slug:
        return "descriptor-node-mismatch"
    iat = payload.get("iat")
    not_after = payload.get("not_after")
    if not isinstance(iat, int) or not isinstance(not_after, int) or not_after <= iat:
        return "descriptor-lifetime-malformed"
    if int(time.time()) >= not_after:
        return "descriptor-expired"
    return ""


def _descriptor_signature_problem(
    envelope: dict[str, str], payload: dict[str, Any]
) -> str:
    """Return "" or a named refusal for the envelope's Ed25519 signature.

    Serve-time verification (F-06), mirroring the production hub's
    winn3_verify_descriptor_signature (ONETOUCH :10372): the signature covers
    DOMAIN || 0x00 || payload_bytes and is verified under the ring slot named
    by the signed `kid` field via `openssl pkeyutl -verify -rawin`. Shape and
    expiry checks alone used to serve a 37-byte forged signature; that now
    refuses with descriptor-signature-invalid before the envelope can reach a
    client.
    """
    ring_slot = str(payload.get("kid") or "").strip().lower()
    if ring_slot not in WINN3_DESCRIPTOR_KEY_SLOTS:
        return "descriptor-unknown-key-slot"
    cache_key = (envelope["payload"], envelope["sig"], ring_slot)
    with _SIG_CACHE_LOCK:
        cached_problem = _SIG_CACHE.get(cache_key)
    if cached_problem is not None:
        return cached_problem
    try:
        payload_bytes = base64.b64decode(envelope["payload"], validate=True)
        signature_bytes = base64.b64decode(envelope["sig"], validate=True)
    except Exception:
        return "descriptor-signature-invalid"
    if len(signature_bytes) != WINN3_ED25519_SIGNATURE_BYTES:
        return "descriptor-signature-invalid"
    key_path = _RING_KEY_PATHS.get(ring_slot)
    if not key_path or not _OPENSSL_BIN:
        # No verifier can ever return success without an OpenSSL >= 3
        # binary and the pinned ring, so refusing everything is the only
        # fail-closed outcome.
        return "descriptor-signature-invalid"
    message = WINN3_DESCRIPTOR_DOMAIN + b"\x00" + payload_bytes
    with tempfile.TemporaryDirectory() as work_dir:
        msg_path = os.path.join(work_dir, "descriptor.bin")
        sig_path = os.path.join(work_dir, "descriptor.sig")
        with open(msg_path, "wb") as handle:
            handle.write(message)
        with open(sig_path, "wb") as handle:
            handle.write(signature_bytes)
        completed = subprocess.run(
            [
                _OPENSSL_BIN,
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                key_path,
                "-sigfile",
                sig_path,
                "-in",
                msg_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    problem = "descriptor-signature-invalid" if completed.returncode != 0 else ""
    with _SIG_CACHE_LOCK:
        if len(_SIG_CACHE) >= 64:
            _SIG_CACHE.clear()
        _SIG_CACHE[cache_key] = problem
    return problem


def _load_nodes() -> dict[str, Any]:
    with open(NODES_FILE, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    nodes = raw.get("nodes", [])
    if not nodes:
        raise RuntimeError(f"{NODES_FILE} contains no nodes")
    for node in nodes:
        if node.get("egress_ip") == TO_BE_SET:
            log.warning("node %s: egress_ip is TO_BE_SET", node.get("slug"))
        if not _parse_descriptor_envelope(node.get("winn3_descriptor")):
            log.warning(
                "node %s: no winn3_descriptor in nodes.json and none landed in %s yet",
                node.get("slug"),
                DESCRIPTORS_DIR,
            )
    return raw


NODES_CONFIG = _load_nodes()
NODES: list[dict[str, Any]] = NODES_CONFIG["nodes"]
NODES_BY_SLUG: dict[str, dict[str, Any]] = {n["slug"]: n for n in NODES}
ANNOUNCEMENT = NODES_CONFIG.get("announcement", "AI-routed demo network")


def _default_state() -> dict[str, Any]:
    return {
        "node_health": {
            node["slug"]: {
                "reachable": bool(node.get("reachable", True)),
                "recent_failures": 0,
                "latency_ms": None,
                "last_probe_ts": None,
            }
            for node in NODES
        },
        "allocations": {},
        "winn3_devices": {},
        "device_last_node": {},
        "router_decisions": [],
    }


def _load_state() -> dict[str, Any]:
    state = _default_state()
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as handle:
                stored = json.load(handle)
            for key, value in stored.items():
                if key in state:
                    if isinstance(state[key], dict) and isinstance(value, dict):
                        state[key].update(value)
                    else:
                        state[key] = value
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("state file unreadable, starting fresh: %s", exc)
    for node in NODES:
        state["node_health"].setdefault(
            node["slug"],
            {"reachable": True, "recent_failures": 0, "latency_ms": None, "last_probe_ts": None},
        )
    return state


STATE: dict[str, Any] = _load_state()


def _persist_state_locked() -> None:
    # STATE holds per-device static private keys: write an owner-only (0600,
    # mkstemp) unpredictable temporary, never a umask-dependent fixed name.
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{STATE_FILE.name}.", dir=STATE_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(STATE, handle, indent=2)
        os.replace(tmp, STATE_FILE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _health(slug: str) -> dict[str, Any]:
    return STATE["node_health"][slug]


def _reachable(slug: str) -> bool:
    return bool(_health(slug).get("reachable"))


def _reachable_nodes() -> list[dict[str, Any]]:
    return [n for n in NODES if _reachable(n["slug"])]


def _synthetic_latency_ms(node: dict[str, Any]) -> int:
    return 40 + 15 * NODES.index(node)


def _node_host(node: dict[str, Any]) -> Optional[str]:
    egress = str(node.get("egress_ip", ""))
    if egress and egress != TO_BE_SET:
        return egress
    return None


def probe_node_latency(node: dict[str, Any]) -> Optional[int]:
    host = _node_host(node)
    if not host:
        return None
    port = int(node.get("listen_port", 9111) or 9111)
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT_S):
            elapsed_ms = int((time.monotonic() - started) * 1000)
    except OSError:
        return None
    return max(1, elapsed_ms)


def refresh_probes() -> dict[str, Optional[int]]:
    """One real TCP probe pass over every node; returns slug -> latency_ms.

    A failed probe marks the node unreachable and increments recent_failures
    (the same signal /admin/health produces manually), so a real gateway kill
    is seen by the router without anyone flipping it by hand. A successful
    probe on a node the admin (or a previous probe) had marked down restores
    it: reachable back to True and recent_failures cleared, mirroring reality.
    """
    results: dict[str, Optional[int]] = {}
    for node in NODES:
        slug = node["slug"]
        measured = probe_node_latency(node)
        with _state_lock:
            health = _health(slug)
            health["latency_ms"] = measured
            health["last_probe_ts"] = time.time()
            if measured is None:
                if _reachable(slug):
                    log.warning("probe failed for %s: marking unreachable", slug)
                health["recent_failures"] = int(health.get("recent_failures", 0)) + 1
                health["reachable"] = False
            else:
                if not _reachable(slug):
                    log.info("probe OK for %s: restoring reachable, clearing failures", slug)
                    health["recent_failures"] = 0
                health["reachable"] = True
            _persist_state_locked()
        results[slug] = measured
    return results


def maybe_refresh_probes() -> None:
    """Run a probe pass if the cache window has elapsed (at most PROBE_CACHE_S)."""
    global _last_probe_cycle_ts
    with _probe_lock:
        if time.time() - _last_probe_cycle_ts < PROBE_CACHE_S:
            return
        refresh_probes()
        _last_probe_cycle_ts = time.time()


def _handshake_ms(node: dict[str, Any]) -> int:
    slug = node["slug"]
    cached = _health(slug).get("latency_ms")
    if isinstance(cached, int) and cached > 0:
        return cached
    return _synthetic_latency_ms(node)


def build_router_payload(device_id: str) -> dict[str, Any]:
    candidates = []
    for node in NODES:
        slug = node["slug"]
        reachable = _reachable(slug)
        handshake = _handshake_ms(node)
        candidates.append(
            {
                "route_id": slug,
                "reachable": reachable,
                "protocol_version": WINN_PROTOCOL_V3,
                "carrier": WINN3_CARRIER,
                "handshake_ms": handshake if reachable else 0,
                "packet_loss_pct": 0 if reachable else 2,
                "jitter_ms": max(1, handshake // 10) if reachable else 0,
                "dns_ok": True,
                "recent_failures": int(_health(slug).get("recent_failures", 0)),
            }
        )
    current = STATE["device_last_node"].get(device_id)
    if current not in NODES_BY_SLUG or not _reachable(current):
        current = (_reachable_nodes() or NODES)[0]["slug"]
    return {
        "request_id": secrets.token_hex(8),
        "current_route_id": current,
        "candidates": candidates,
        "signals": {
            "udp_ok": True,
            "tcp443_ok": True,
            "tls_ok": True,
            "control_plane_ok": True,
            "dns_ok": True,
        },
    }


def _record_router_decision(payload: dict[str, Any], decision: Optional[dict[str, Any]], chosen: str, source: str) -> None:
    STATE["router_decisions"].append(
        {
            "ts": time.time(),
            "request_id": payload.get("request_id"),
            "router_selected": decision.get("selected_route_id") if decision else None,
            "decision": decision.get("decision") if decision else None,
            "confidence": decision.get("confidence") if decision else None,
            "reason_codes": decision.get("reason_codes") if decision else None,
            "enforced_choice": chosen,
            "selection_source": source,
        }
    )
    del STATE["router_decisions"][:-MAX_ROUTER_DECISIONS]


class AllNodesDown(Exception):
    pass


def _router_cache_key() -> tuple:
    """Cache key: the full node-health tuple. Same health -> same decision."""
    return tuple(
        (n["slug"], bool(_health(n["slug"]).get("reachable")), int(_health(n["slug"]).get("recent_failures", 0)))
        for n in NODES
    )


_SIG_CACHE: dict[tuple[str, str, str], str] = {}
_SIG_CACHE_LOCK = threading.Lock()

_ROUTER_CACHE: dict[str, Any] = {"key": None, "decision": None, "thread": None}
_ROUTER_REFRESH_LOCK = threading.Lock()


def _refresh_router_cache_async(payload: dict[str, Any]) -> None:
    """Fetch a router decision in the background; never blocks a request."""
    def worker() -> None:
        decision = call_router(payload)
        if decision is not None:
            _ROUTER_CACHE["key"] = _router_cache_key()
            _ROUTER_CACHE["decision"] = decision
            log.info("router cache refreshed (background): %s -> %s", payload.get("request_id"), decision.get("selected_route_id"))
    # At most one refresh in flight: a slow or blackholed router must not turn
    # every public auto-verify into another 12-second outbound thread.
    with _ROUTER_REFRESH_LOCK:
        active = _ROUTER_CACHE["thread"]
        if active is not None and active.is_alive():
            return
        thread = threading.Thread(target=worker, daemon=True)
        _ROUTER_CACHE["thread"] = thread
        thread.start()


def call_router(payload: dict[str, Any]) -> Optional[dict[str, Any]]:
    if not ROUTER_URL:
        return None
    url = ROUTER_URL.rstrip("/") + "/route"
    try:
        # The router admits /route only with its HMAC headers (router/security.py
        # signing_message): sign the exact body bytes that are sent.
        secret = (
            os.environ.get("SMART_ROUTER_HMAC_SECRET", "").strip()
            or os.environ.get("EDGE_ROUTER_SECRET", "").strip()
        )
        if len(secret) < 32:
            log.warning("router authentication is not configured")
            return None
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        target = urlsplit(url)
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        message = "\n".join((
            "POST", path, timestamp, nonce, hashlib.sha256(body).hexdigest(),
        )).encode("ascii")
        signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        response = httpx.post(
            url, content=body, timeout=ROUTER_TIMEOUT_S,
            headers={
                "Content-Type": "application/json",
                "X-Smart-Router-Timestamp": timestamp,
                "X-Smart-Router-Nonce": nonce,
                "X-Smart-Router-Signature": signature,
            },
        )
        if response.status_code == 200:
            decision = response.json()
            if isinstance(decision, dict):
                return decision
        log.warning("router %s returned HTTP %s", url, response.status_code)
    except Exception as exc:
        log.warning("router unreachable (%s): %s", url, exc)
    return None


def select_node(location: Optional[str], device_id: str) -> tuple[dict[str, Any], str]:
    requested = (location or "").strip().lower()
    reachable = _reachable_nodes()
    if requested and requested != "auto":
        node = NODES_BY_SLUG.get(requested)
        if node is not None and _reachable(node["slug"]):
            return node, "explicit"
        if requested not in NODES_BY_SLUG:
            log.warning("unknown location slug %r requested; treating as auto", requested)
        elif reachable:
            fallback = reachable[0]
            log.warning(
                "requested node %s unreachable; serving %s instead",
                requested,
                fallback["slug"],
            )
            return fallback, "explicit_fallback"
        if not reachable:
            raise AllNodesDown()
        return reachable[0], "explicit_fallback"

    # The client aborts slow POSTs at 4s and Gemini needs ~4s, so the decision
    # comes from a cache keyed on node health: serve the cached decision
    # instantly (same health = same decision is deterministic policy anyway)
    # and refresh from the router in a background thread. First request on a
    # NEW health state serves deterministic while the refresh warms the cache;
    # /admin/probe also warms it.
    payload = build_router_payload(device_id)
    cache_key = _router_cache_key()
    decision = None
    if _ROUTER_CACHE["key"] == cache_key and _ROUTER_CACHE["decision"] is not None:
        decision = dict(_ROUTER_CACHE["decision"])
    else:
        _refresh_router_cache_async(payload)
    if decision is not None:
        selected = str(decision.get("selected_route_id") or "")
        node = NODES_BY_SLUG.get(selected)
        if node is not None and _reachable(node["slug"]):
            _record_router_decision(payload, decision, node["slug"], "router" if decision.get("source") != "fallback" else "router_cache_fallback")
            return node, "router"
        log.warning(
            "cached router decision selected %r which is unknown or unreachable; enforcing deterministic pick",
            selected,
        )
        _record_router_decision(payload, decision, (reachable[0]["slug"] if reachable else ""), "router_enforced_fallback")
    else:
        _record_router_decision(payload, None, (reachable[0]["slug"] if reachable else ""), "deterministic_fallback")
    if reachable:
        return reachable[0], "deterministic"
    raise AllNodesDown()


# =============================================================================
# Winn Protocol v3 standalone serving (SPEC v2: no AWG, no Xray)
# =============================================================================


def descriptor_for_node(node: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any], str, str]:
    """(envelope, decoded_payload, source, reason) for a node's descriptor.

    Precedence: the supervisor ceremony files DESCRIPTORS_DIR/<slug>.json (the
    real envelopes, landed as descriptors/demo-route-a.json etc.), then the
    nodes.json placeholder, then none. A landed file that does not validate is
    a deploy error and is served as {} with a loud log -- never silently
    downgraded to the placeholder.
    """
    slug = node["slug"]
    file_path = DESCRIPTORS_DIR / f"{slug}.json"
    if file_path.exists():
        try:
            landed = json.loads(file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            log.error("node %s: descriptor file %s unreadable (%s)", slug, file_path, exc)
            return {}, {}, "file", "descriptor-file-unreadable"
        envelope = _parse_descriptor_envelope(landed)
        if not envelope:
            log.error("node %s: descriptor file %s is not a payload/sig envelope", slug, file_path)
            return {}, {}, "file", "descriptor-envelope-incomplete"
        payload = _decode_descriptor_payload(envelope)
        if payload is None:
            log.error("node %s: descriptor payload in %s is not bounded UTF-8 JSON", slug, file_path)
            return {}, {}, "file", "descriptor-payload-unreadable"
        problem = _descriptor_payload_problems(payload, slug)
        if not problem:
            problem = _descriptor_signature_problem(envelope, payload)
        if problem:
            log.error("node %s: refusing descriptor from %s (%s)", slug, file_path, problem)
            return {}, {}, "file", problem
        return envelope, payload, "file", "winn3-descriptor"

    placeholder = _parse_descriptor_envelope(node.get("winn3_descriptor"))
    if not placeholder:
        return {}, {}, "nodes-json", "descriptor-not-landed"
    payload = _decode_descriptor_payload(placeholder)
    if payload is None:
        return {}, {}, "nodes-json", "descriptor-not-landed"
    problem = _descriptor_payload_problems(payload, slug)
    if not problem:
        problem = _descriptor_signature_problem(placeholder, payload)
    if problem:
        return {}, {}, "nodes-json", problem
    return placeholder, payload, "nodes-json", "winn3-descriptor"


def _is_inner_ipv4(text: str) -> bool:
    """Dotted-quad shape check mirroring isWinnInnerIpv4 (dispatch:1947-1975):
    four plain-decimal octets, no leading zeros, not 0/127/224+ first octets."""
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 1 <= len(part) <= 3:
            return False
        if len(part) > 1 and part.startswith("0"):
            return False
        if int(part) > 255:
            return False
    first = int(parts[0])
    if first == 0 or first == 127 or first >= 224:
        return False
    return True


def allocate_winn3_inner_v4(
    device_id: str, node: dict[str, Any], descriptor_payload: dict[str, Any]
) -> str:
    """Sticky per-device tunnel address from the selected node's subnet, start .2.

    Mirrors the hub's lazy allocation (ONETOUCH allocate_winn3_inner_ip
    :11628-11671 + ensure_winn3_device_material :11743-11836): idempotent once
    issued (the gateway's session table is provisioned against the address),
    .1 is the gateway's inner_router_v4, and any inner address the descriptor
    names is reserved so a device can never collide with its own next hop
    (client refuses inner_v4 == inner_router_v4, dispatch:2538-2545).
    """
    subnet = ipaddress.ip_network(node["subnet"])
    prefix = subnet.network_address
    existing = STATE["allocations"].get(device_id, {}).get(node["slug"])
    if existing:
        return existing
    used = set()
    for per_node in STATE["allocations"].values():
        assigned = per_node.get(node["slug"])
        if assigned:
            used.add(ipaddress.ip_address(assigned))
    for field in ("inner_router_v4", "inner_resolver_v4"):
        value = str(descriptor_payload.get(field) or "").strip()
        if _is_inner_ipv4(value):
            used.add(ipaddress.ip_address(value))
    for offset in range(2, subnet.num_addresses - 1):
        candidate = prefix + offset
        if candidate not in used:
            STATE["allocations"].setdefault(device_id, {})[node["slug"]] = str(candidate)
            _persist_state_locked()
            return str(candidate)
    raise HTTPException(status_code=503, detail="no free tunnel addresses")


def _generate_winn3_static_material() -> tuple[str, str, str]:
    """A fresh X25519 (private_b64, public_b64, source) for one device.

    Mirrors generate_winn3_static_material (ONETOUCH:11686-11740): openssl
    emits PKCS#8/SPKI-wrapped keys and winn/3 wants the RAW 32 bytes base64.
    If openssl is unavailable the fallback draws 32 random bytes for the
    private half only: X25519 clamps at use time, so any 32 bytes are a valid
    scalar (the hub records the same fact about wg genkey, ONETOUCH:11694-
    11699). The public half exists only for gateway registry sync, which is
    not this twin's job, so it stays "" under the fallback.
    """
    try:
        with tempfile.TemporaryDirectory() as work_dir:
            key_path = os.path.join(work_dir, "winn3_static.der")
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "X25519",
                 "-outform", "DER", "-out", key_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True, timeout=15,
            )
            with open(key_path, "rb") as handle:
                pkcs8 = handle.read()
            spki = subprocess.run(
                ["openssl", "pkey", "-inform", "DER", "-in", key_path,
                 "-pubout", "-outform", "DER"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True, timeout=15,
            ).stdout
        if len(pkcs8) != WINN3_X25519_PKCS8_BYTES:
            raise ValueError("unexpected X25519 private key encoding")
        if len(spki) != WINN3_X25519_SPKI_BYTES or not spki.startswith(
            WINN3_X25519_SPKI_PREFIX
        ):
            raise ValueError("unexpected X25519 public key encoding")
        private_raw = pkcs8[-WINN3_X25519_KEY_BYTES:]
        public_raw = spki[-WINN3_X25519_KEY_BYTES:]
    except Exception as exc:
        log.warning(
            "openssl X25519 unavailable (%s); using urandom private scalar, "
            "empty static_public", exc,
        )
        return base64.b64encode(secrets.token_bytes(32)).decode(), "", "urandom-fallback"
    return (
        base64.b64encode(private_raw).decode(),
        base64.b64encode(public_raw).decode(),
        "openssl",
    )


def ensure_winn3_device_material(device_id: str) -> tuple[str, str, str]:
    """(static_private, static_public, reason) for this device, minting if needed.

    The static key is PER DEVICE and sticky for its life, not per node
    (ONETOUCH ensure_winn3_device_material :11743-11836: re-rolling would
    strand the device against every gateway's admission table). The private
    half is served only to its own device and never logged or echoed in any
    admin surface.
    """
    stored = STATE["winn3_devices"].get(device_id, {})
    private_key = str(stored.get("static_private") or "").strip()
    if private_key:
        return private_key, str(stored.get("static_public") or ""), "winn3-material-on-file"
    private_key, public_key, source = _generate_winn3_static_material()
    if not private_key:
        raise HTTPException(status_code=503, detail="could not issue device key material")
    STATE["winn3_devices"][device_id] = {
        "static_private": private_key,
        "static_public": public_key,
        "source": source,
    }
    _persist_state_locked()
    return private_key, public_key, "winn3-material-issued"


def _endpoint_or_empty(node: dict[str, Any]) -> str:
    egress = str(node.get("egress_ip", ""))
    if not egress or egress == TO_BE_SET:
        return ""
    return f"{egress}:{int(node.get('listen_port', 9111))}"


def _public_node_view(node: dict[str, Any]) -> dict[str, Any]:
    slug = node["slug"]
    reachable = _reachable(slug)
    latency = _health(slug).get("latency_ms")
    view: dict[str, Any] = {
        "name": node["name"],
        "flag": node.get("flag", "🌐"),
        "slug": slug,
        "status": "online" if reachable else "offline",
        "endpoint": _endpoint_or_empty(node),
        "free_access_enabled": True,
        "direct_awg_enabled": True,
        "protocol_version": "",
        "reachable": reachable,
        "transports": {"udp": "ok" if reachable else "down"},
        "regional_aliases": [],
    }
    if isinstance(latency, int) and latency > 0:
        view["latency_ms"] = latency
    return view


app = FastAPI(title="Win's VPN XPRIZE staging hub", docs_url=None, redoc_url=None)


@app.get("/nodes")
def get_nodes() -> dict[str, Any]:
    maybe_refresh_probes()
    return {
        "nodes": [_public_node_view(node) for node in NODES],
        "free_access": {
            "node_slugs": [node["slug"] for node in NODES],
            "enabled": True,
        },
        "maintenance": False,
        "min_supported_app_version": "",
        "app_update_url": "",
        "double_vpn_available": False,
        "announcement": ANNOUNCEMENT,
    }


@app.get("/free/status")
def free_status() -> dict[str, Any]:
    any_reachable = bool(_reachable_nodes())
    return {
        "status": "ok" if any_reachable else "unavailable",
        "free_access": True,
        "maintenance": False,
    }


@app.post("/free/verify")
def free_verify(request: Request, payload: dict[str, Any] = Body(...)) -> JSONResponse:
    client_ip = str(getattr(request.client, "host", "") or "unknown")
    if not VERIFY_RATE_LIMITER.allow(client_ip):
        raise HTTPException(status_code=429, detail="too many verify requests")
    device_id = str(payload.get("device_id") or "").strip()
    if not device_id:
        raise HTTPException(status_code=400, detail="missing device_id")
    if not _DEVICE_ID_RE.fullmatch(device_id):
        raise HTTPException(status_code=400, detail="invalid device_id")
    # client_public_key is accepted but unused: winn/3 admission is via the
    # signed descriptor's admission_key plus per-device X25519 static keys,
    # not runtime WireGuard/AWG peer pushes (owner ruling, SPEC v2).
    location = payload.get("location")
    with _state_lock:
        if (
            device_id not in STATE["winn3_devices"]
            and len(STATE["winn3_devices"]) >= MAX_DEVICES
        ):
            raise HTTPException(status_code=503, detail="device capacity reached")
        try:
            node, selection_source = select_node(location, device_id)
        except AllNodesDown:
            raise HTTPException(status_code=503, detail="not online")
        STATE["device_last_node"][device_id] = node["slug"]
        envelope, descriptor_payload, descriptor_source, descriptor_reason = (
            descriptor_for_node(node)
        )
        inner_v4 = allocate_winn3_inner_v4(device_id, node, descriptor_payload)
        static_private, static_public, material_reason = ensure_winn3_device_material(device_id)
        if not envelope:
            log.error(
                "serving winn/3 to %s on %s WITHOUT a verifiable descriptor (%s/%s); "
                "the client will refuse by name until the supervisor lands %s",
                device_id, node["slug"], descriptor_source, descriptor_reason,
                DESCRIPTORS_DIR / f"{node['slug']}.json",
            )
        vpn_config = {
            "protocol_version": WINN_PROTOCOL_V3,
            "protocol_params": {"carrier": WINN3_CARRIER},
            "winn3_inner_v4": inner_v4,
            "winn3_static_private": static_private,
            "winn3_descriptor": dict(envelope),
            "winn3_path_mtu": WINN3_PATH_MTU,
            "winn3_carrier_classes": WINN3_CARRIER_CLASSES,
            "node_slug": node["slug"],
            "dns": "1.1.1.1",
            "mtu": VPN_MTU,
            # AWG compatibility fields, served by the real hub alongside the
            # winn/3 fields (ONETOUCH :18089-18100) so the client's
            # VpnConfigValidator.isUsable passes. The v3 dispatch ignores
            # them: endpoint/keys for the tunnel come from the signed
            # descriptor. Values are syntactically valid and node-scoped.
            # DISPATCH:2561-2569 refuses client_ip == winn3_inner_v4; serve the
            # gateway's own inner address (.1) as the compat stand-in.
            "client_ip": str(ipaddress.ip_address(inner_v4) + (-1)),
            "server_public_key": node.get("awg_compat_public_key", ""),
            "server_endpoint": f"{node['egress_ip']}:{node.get('listen_port', 9111)}",
            # AWG obfuscation block: the client's _normalizeVpnConfig forces
            # obfuscation to at least {} and VpnConfigValidator then requires
            # every Jc..S4/H1..H4 field to be a valid int, so an absent/empty
            # block FAILS validation even on the winn/3 path. The real hub
            # serves these too (ONETOUCH:18101). v3 dispatch ignores them.
            "obfuscation": {
                "Jc": 2, "Jmin": 10, "Jmax": 30,
                "S1": 16, "S2": 80, "S3": 16, "S4": 0,
                "H1": 11, "H2": 22, "H3": 33, "H4": 44,
            },
        }
        response = {
            "status": "authenticated",
            "vpn_config": vpn_config,
            "selected_node": {
                "slug": node["slug"],
                "name": node["name"],
                "flag": node.get("flag", "🌐"),
                "status": "online",
            },
            "expiration_date": EXPIRATION_DATE,
            "device_auth_token": secrets.token_hex(12),
            "announcement": ANNOUNCEMENT,
            "demo_provisioning": {
                "selection_source": selection_source,
                "descriptor_source": descriptor_source,
                "descriptor_reason": descriptor_reason,
                "material_reason": material_reason,
            },
        }
        _persist_state_locked()
    return JSONResponse(response)


def _require_demo_key(x_demo_key: str) -> None:
    # D-4: constant-time comparison; == is never used for the admin key.
    # compare_digest refuses non-ASCII-encodable headers (TypeError or
    # UnicodeEncodeError), which must also read as a bad key, not a 500.
    try:
        matches = hmac.compare_digest(x_demo_key, DEMO_KEY)
    except (TypeError, UnicodeEncodeError):
        matches = False
    if not matches:
        raise HTTPException(status_code=401, detail="bad demo key")


@app.post("/admin/health")
def admin_health(
    payload: dict[str, Any] = Body(...),
    x_demo_key: str = Header(default=""),
    _rate_limit: None = Depends(_admin_rate_limited),
) -> dict[str, Any]:
    _require_demo_key(x_demo_key)
    slug = str(payload.get("slug") or "").strip()
    reachable = bool(payload.get("reachable"))
    if slug not in NODES_BY_SLUG:
        raise HTTPException(status_code=404, detail=f"unknown slug {slug}")
    with _state_lock:
        health = _health(slug)
        health["reachable"] = reachable
        if not reachable:
            health["recent_failures"] = int(health.get("recent_failures", 0)) + 1
        _persist_state_locked()
    return {"slug": slug, "reachable": reachable, "recent_failures": _health(slug)["recent_failures"]}


@app.get("/admin/state")
def admin_state(
    x_demo_key: str = Header(default=""),
    _rate_limit: None = Depends(_admin_rate_limited),
) -> dict[str, Any]:
    _require_demo_key(x_demo_key)
    with _state_lock:
        # No private key material in any admin surface: the private half is
        # served only to its own device (same rule as the real hub's logging,
        # ONETOUCH:11829-11835).
        devices = {
            device_id: {
                "static_public": str(material.get("static_public") or ""),
                "material_source": material.get("source", ""),
                "inner_v4": dict(per_node),
            }
            for device_id, material in STATE["winn3_devices"].items()
            for per_node in [STATE["allocations"].get(device_id, {})]
        }
        descriptors = {}
        for node in NODES:
            envelope, _, source, reason = descriptor_for_node(node)
            descriptors[node["slug"]] = {
                "served": bool(envelope),
                "source": source,
                "reason": reason,
            }
        snapshot = {
            "uptime_s": int(time.monotonic() - _START_TS),
            "nodes": {
                node["slug"]: {
                    "reachable": _health(node["slug"])["reachable"],
                    "recent_failures": _health(node["slug"])["recent_failures"],
                    "latency_ms": _health(node["slug"]).get("latency_ms"),
                    "last_probe_ts": _health(node["slug"]).get("last_probe_ts"),
                }
                for node in NODES
            },
            "allocations": STATE["allocations"],
            "winn3_devices": devices,
            "descriptors": descriptors,
            "device_last_node": STATE["device_last_node"],
            "router_decisions": list(STATE["router_decisions"]),
        }
    return snapshot


@app.post("/admin/probe")
def admin_probe(
    x_demo_key: str = Header(default=""),
    _rate_limit: None = Depends(_admin_rate_limited),
) -> dict[str, Any]:
    _require_demo_key(x_demo_key)
    global _last_probe_cycle_ts
    with _probe_lock:
        results = refresh_probes()
        _last_probe_cycle_ts = time.time()
    # Warm the router decision cache for the (possibly changed) health state
    # so the next client verify is instant and carries the Gemini decision.
    _refresh_router_cache_async(build_router_payload("admin-probe"))
    return {"probes": results}


@app.get("/health")
def hub_health() -> dict[str, Any]:
    descriptors = {}
    for node in NODES:
        envelope, _, _source, _reason = descriptor_for_node(node)
        descriptors[node["slug"]] = bool(envelope)
    return {
        "ok": True,
        "reachable_nodes": [n["slug"] for n in _reachable_nodes()],
        "descriptors_ready": descriptors,
    }
