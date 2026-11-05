"""Locked httpx2 transport tests for provider redirect and body-ceiling custody."""
from __future__ import annotations

import asyncio
import gzip
import importlib
import json
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from importlib.metadata import version
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import pytest
from pydantic import ValidationError


ROUTER_DIR = Path(__file__).resolve().parent.parent
LOCKED_HTTPX2 = "2.13.1"
MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024
GOOGLE_SECRET = "google-test-secret-0123456789abcdef"
LOCAL_SECRET = "local-test-secret-0123456789abcdef"
LOCAL_MODEL = "reviewed-gemma-runtime:release"
LOCAL_MODEL_REVISION = "0123456789abcdef0123456789abcdef01234567"
LOCAL_ARTIFACT_INVENTORY = "f" * 64
GOOGLE_MODEL = "reviewed-gemini-model"
FIXED_GOOGLE_ORIGIN = "https://generativelanguage.googleapis.com/v1beta/models"


def _ensure_locked_httpx2():
    cache = Path.home() / ".cache" / "uv" / "wheels-v6" / "pypi"
    packages = (
        ("idna", "3.20-py3-none-any"),
        ("h11", "0.16.0-py3-none-any"),
        ("anyio", "4.15.1-py3-none-any"),
        ("truststore", "0.10.4-py3-none-any"),
        ("httpcore2", "2.13.1-py3-none-any"),
        ("httpx2", "2.13.1-py3-none-any"),
    )
    existing = sys.modules.get("httpx2")
    if existing is not None and getattr(existing, "__file__", None) is None:
        for name in list(sys.modules):
            if name == "httpx2" or name.startswith("httpx2."):
                del sys.modules[name]
            elif name == "httpcore2" or name.startswith("httpcore2."):
                del sys.modules[name]
    for package, folder in packages:
        path = cache / package / folder
        if path.is_dir() and str(path) not in sys.path:
            sys.path.insert(0, str(path))
    if str(ROUTER_DIR) not in sys.path:
        sys.path.insert(0, str(ROUTER_DIR))
    import httpx2

    if version("httpx2") != LOCKED_HTTPX2:
        raise RuntimeError(f"locked httpx2 {LOCKED_HTTPX2} is required, found {version('httpx2')}")
    for mod_name in ("gemini_client", "local_gemma_client"):
        mod = sys.modules.get(mod_name)
        if mod is not None:
            importlib.reload(mod)
    return httpx2


httpx2 = _ensure_locked_httpx2()

import gemini_client
import local_gemma_client
from provider_common import (
    ProviderRouteDecision,
    ProviderSupportAnswer,
    SharedProviderClients,
    bounded_provider_request,
)
from schemas import RouteRequest


@dataclass
class Exchange:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    host: str


@dataclass
class LoopbackHTTP:
    responder: Callable[["LoopbackHTTP", Exchange, socket.socket], None]
    exchanges: list[Exchange] = field(default_factory=list)
    closed: int = 0
    accepts: int = 0
    keepalive: bool = False
    _host: str = "127.0.0.1"
    _port: int = 0
    _sock: socket.socket | None = None
    _thread: threading.Thread | None = None
    _stop: threading.Event = field(default_factory=threading.Event)

    def start(self) -> "LoopbackHTTP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        sock.settimeout(0.2)
        self._host, self._port = sock.getsockname()
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    @property
    def origin(self) -> str:
        return f"http://{self._host}:{self._port}"

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.accepts += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(2.0)
            while True:
                exchange = _read_request(conn)
                if exchange is None:
                    break
                self.exchanges.append(exchange)
                self.responder(self, exchange, conn)
                if not self.keepalive:
                    break
        except Exception:
            pass
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
            self.closed += 1


def _read_request(conn: socket.socket) -> Exchange | None:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            if not buf:
                return None
            break
        buf += chunk
        if len(buf) > MAX_PROVIDER_RESPONSE_BYTES:
            raise RuntimeError("request exceeded test limit")
    if not buf:
        return None
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    method, path, _proto = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.lower().strip()] = value.strip()
    body = rest
    length = int(headers.get("content-length") or "0")
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return Exchange(
        method=method,
        path=path,
        headers=headers,
        body=body[:length],
        host=headers.get("host", ""),
    )


def _send(
    conn: socket.socket,
    status: int,
    headers: dict[str, str],
    body: bytes,
    *,
    keepalive: bool = False,
) -> None:
    header_lines = [
        f"HTTP/1.1 {status} X",
        f"Connection: {'keep-alive' if keepalive else 'close'}",
        f"Content-Length: {len(body)}",
    ]
    for key, value in headers.items():
        header_lines.append(f"{key}: {value}")
    conn.sendall(("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii") + body)


def _send_redirect(conn: socket.socket, location: str, status: int = 302) -> None:
    _send(conn, status, {"Location": location}, b"")


def _send_chunked(conn: socket.socket, chunks: list[bytes], headers: dict[str, str] | None = None) -> None:
    header_lines = [
        "HTTP/1.1 200 X",
        "Connection: close",
        "Transfer-Encoding: chunked",
    ]
    for key, value in (headers or {}).items():
        header_lines.append(f"{key}: {value}")
    conn.sendall(("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii"))
    for chunk in chunks:
        conn.sendall(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
    conn.sendall(b"0\r\n\r\n")


def _route_request() -> RouteRequest:
    return RouteRequest.model_validate(
        {
            "request_id": "request-0001",
            "current_route_id": "demo-route-a",
            "candidates": [
                {
                    "route_id": "demo-route-a",
                    "reachable": True,
                    "protocol_version": "winn/1",
                    "carrier": "amneziawg",
                    "v1_engine_order": ["amneziawg", "xray"],
                    "handshake_ms": 220,
                    "packet_loss_pct": 8.0,
                    "jitter_ms": 30,
                    "dns_ok": True,
                    "recent_failures": 3,
                },
                {
                    "route_id": "demo-route-b",
                    "reachable": True,
                    "protocol_version": "winn/1",
                    "carrier": "amneziawg",
                    "v1_engine_order": ["amneziawg", "xray"],
                    "handshake_ms": 180,
                    "packet_loss_pct": 0.5,
                    "jitter_ms": 6,
                    "dns_ok": True,
                    "recent_failures": 0,
                },
            ],
            "signals": {
                "udp_ok": True,
                "tcp443_ok": True,
                "tls_ok": True,
                "control_plane_ok": True,
                "dns_ok": True,
            },
            "trigger": "distress",
        }
    )


def _decision_json() -> str:
    return ProviderRouteDecision(
        selected_route_id="demo-route-b",
        decision="switch",
        confidence=0.87,
        reason_codes=["healthier_alternate"],
    ).model_dump_json()


def _gemini_body(inner: str | None = None) -> bytes:
    return json.dumps(
        {"candidates": [{"content": {"parts": [{"text": inner or _decision_json()}]}}]}
    ).encode("utf-8")


def _gemma_body(
    inner: str | None = None,
    *,
    model: str = LOCAL_MODEL,
    model_revision: str = LOCAL_MODEL_REVISION,
    artifact_inventory_sha256: str = LOCAL_ARTIFACT_INVENTORY,
) -> bytes:
    return json.dumps(
        {
            "model": model,
            "model_revision": model_revision,
            "artifact_inventory_sha256": artifact_inventory_sha256,
            "choices": [{"message": {"content": inner or _decision_json()}}],
        }
    ).encode("utf-8")


@pytest.fixture(autouse=True)
def provider_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", GOOGLE_SECRET)
    monkeypatch.setenv("GEMINI_MODEL", GOOGLE_MODEL)
    monkeypatch.setenv("SMART_ROUTER_GEMMA_MODEL", LOCAL_MODEL)
    monkeypatch.setenv("SMART_ROUTER_GEMMA_MODEL_REVISION", LOCAL_MODEL_REVISION)
    monkeypatch.setenv("SMART_ROUTER_GEMMA_ARTIFACT_ROOT", "/opt/gemma-artifact")
    monkeypatch.setenv(
        "SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256", LOCAL_ARTIFACT_INVENTORY
    )
    monkeypatch.setenv("SMART_ROUTER_GEMMA_URL", "http://127.0.0.1:8002")
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.delenv("all_proxy", raising=False)
    yield


@pytest.fixture
def spy_clients(monkeypatch):
    captured: list[dict] = []

    class Spy(httpx2.AsyncClient):
        def __init__(self, *args, **kwargs):
            captured.append(dict(kwargs))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(gemini_client.httpx2, "AsyncClient", Spy)
    monkeypatch.setattr(local_gemma_client.httpx2, "AsyncClient", Spy)
    return captured


def _pin_installer_gemma_origin(monkeypatch, origin: str) -> None:
    monkeypatch.setenv("SMART_ROUTER_GEMMA_URL", "http://127.0.0.1:8002")
    monkeypatch.setattr(local_gemma_client, "get_local_url", lambda: origin.rstrip("/"))


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize(
    "missing_name",
    [
        "SMART_ROUTER_GEMMA_MODEL_REVISION",
        "SMART_ROUTER_GEMMA_ARTIFACT_ROOT",
        "SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256",
    ],
)
def test_local_configuration_requires_owner_reviewed_identity(
    monkeypatch, missing_name
):
    monkeypatch.delenv(missing_name)
    assert local_gemma_client.local_configured() is False


def test_locked_httpx2_is_the_pinned_runtime():
    assert version("httpx2") == LOCKED_HTTPX2
    assert gemini_client.GOOGLE_GENERATE_BASE == FIXED_GOOGLE_ORIGIN


def test_provider_pool_exactly_matches_eight_admitted_operations(monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_MAX_CONCURRENT_REQUESTS", "8")
    captured: list[dict] = []

    class Spy(httpx2.AsyncClient):
        def __init__(self, *args, **kwargs):
            captured.append(dict(kwargs))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", Spy)
    clients = SharedProviderClients(connect_cap=0.25)

    async def create_and_close():
        client, _timeout = await clients.get(httpx2, 0.5)
        await client.aclose()

    _run(create_and_close())
    assert len(captured) == 1
    limits = captured[0]["limits"]
    assert limits.max_connections == 8
    assert limits.max_keepalive_connections == 4


@pytest.mark.parametrize(
    ("configured", "message"),
    [
        ("not-an-integer", "must be an integer"),
        ("0", "must be between 1 and 64"),
        ("65", "must be between 1 and 64"),
    ],
)
def test_provider_pool_rejects_hostile_operation_bounds(monkeypatch, configured, message):
    monkeypatch.setenv("SMART_ROUTER_MAX_CONCURRENT_REQUESTS", configured)
    with pytest.raises(RuntimeError, match=message):
        SharedProviderClients(connect_cap=0.25)


@pytest.mark.parametrize("max_connections", [True, 0, 7, 65])
def test_provider_pool_rejects_invalid_or_smaller_explicit_bounds(
    monkeypatch, max_connections
):
    monkeypatch.setenv("SMART_ROUTER_MAX_CONCURRENT_REQUESTS", "8")
    with pytest.raises(RuntimeError, match="provider max_connections"):
        SharedProviderClients(
            connect_cap=0.25,
            max_connections=max_connections,
        )


def test_eight_admitted_operations_all_reach_hostile_http1_barrier(monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_MAX_CONCURRENT_REQUESTS", "8")
    barrier = threading.Barrier(8)

    def responder(_svc, _ex, conn):
        barrier.wait(timeout=1.0)
        _send(conn, 200, {"Content-Type": "application/json"}, b"{}")

    server = LoopbackHTTP(responder).start()
    clients = SharedProviderClients(connect_cap=0.25)
    try:
        async def concurrent_requests():
            client, timeout = await clients.get(httpx2, 1.5)

            async def request(index: int):
                _response, body = await bounded_provider_request(
                    client,
                    "GET",
                    f"{server.origin}/hostile-barrier/{index}",
                    label="hostile provider",
                    timeout=timeout,
                )
                return body

            try:
                return await asyncio.wait_for(
                    asyncio.gather(*(request(index) for index in range(8))),
                    timeout=2.0,
                )
            finally:
                await client.aclose()

        bodies = _run(concurrent_requests())
    finally:
        server.stop()
    assert bodies == [b"{}"] * 8
    assert server.accepts == 8
    assert len(server.exchanges) == 8


def test_google_happy_path_keeps_origin_header_contract_and_trust_env(spy_clients, monkeypatch):
    server = LoopbackHTTP(
        lambda _svc, _ex, conn: _send(conn, 200, {"Content-Type": "application/json"}, _gemini_body())
    ).start()
    try:
        monkeypatch.setattr(
            gemini_client,
            "GOOGLE_GENERATE_BASE",
            f"{server.origin}/v1beta/models",
        )
        decision = _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()
    assert decision.selected_route_id == "demo-route-b"
    assert spy_clients[0]["trust_env"] is False
    assert spy_clients[0]["follow_redirects"] is False
    assert spy_clients[0]["max_redirects"] == 0
    exchange = server.exchanges[0]
    assert exchange.method == "POST"
    assert exchange.path.endswith(f"/{GOOGLE_MODEL}:generateContent")
    assert "key=" not in exchange.path
    parsed = urlsplit(f"{server.origin}{exchange.path}")
    assert parsed.query == ""
    assert exchange.headers["x-goog-api-key"] == GOOGLE_SECRET
    assert GOOGLE_SECRET not in exchange.path
    assert GOOGLE_SECRET not in exchange.body.decode("utf-8")


def test_local_happy_path_uses_loopback_and_openai_schema(spy_clients, monkeypatch):
    server = LoopbackHTTP(
        lambda _svc, _ex, conn: _send(conn, 200, {"Content-Type": "application/json"}, _gemma_body())
    ).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        decision = _run(local_gemma_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()
    assert decision.selected_route_id == "demo-route-b"
    assert spy_clients[0]["trust_env"] is False
    assert spy_clients[0]["follow_redirects"] is False
    exchange = server.exchanges[0]
    assert exchange.path == "/v1/chat/completions"
    payload = json.loads(exchange.body)
    assert payload["model"] == LOCAL_MODEL
    assert payload["temperature"] == 0
    assert payload["max_tokens"] == 128
    assert payload["stream"] is False


@pytest.mark.parametrize(
    "identity_kwargs",
    [
        {"model": "same-alias-drifted-revision"},
        {"model_revision": "f" * 40},
        {"artifact_inventory_sha256": "e" * 64},
    ],
)
def test_local_response_identity_drift_fails_closed(monkeypatch, identity_kwargs):
    server = LoopbackHTTP(
        lambda _svc, _ex, conn: _send(
            conn,
            200,
            {"Content-Type": "application/json"},
            _gemma_body(**identity_kwargs),
        )
    ).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(RuntimeError, match="model identity"):
            _run(local_gemma_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()


def test_local_health_rejects_same_alias_with_different_revision(monkeypatch):
    def responder(_svc, exchange, conn):
        if exchange.path == "/health":
            _send(conn, 200, {}, b"", keepalive=True)
            return
        body = json.dumps(
            {
                "data": [
                    {
                        "id": LOCAL_MODEL,
                        "model_revision": "f" * 40,
                        "artifact_inventory_sha256": LOCAL_ARTIFACT_INVENTORY,
                    }
                ]
            }
        ).encode("utf-8")
        _send(conn, 200, {"Content-Type": "application/json"}, body)

    server = LoopbackHTTP(responder).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        health = _run(local_gemma_client.provider_health(0.5))
    finally:
        server.stop()
    assert health["engine_healthy"] is True
    assert health["model_served"] is False
    assert health["ready"] is False


def test_local_stock_vllm_openai_shapes_are_accepted(monkeypatch):
    """Stock vLLM emits OpenAI shapes: chat carries only "model", and
    /v1/models entries carry id+root -- never this project's revision or
    inventory extension fields. The local lane must accept exactly that."""
    stock_chat = json.loads(_gemma_body())
    stock_chat.pop("model_revision")
    stock_chat.pop("artifact_inventory_sha256")
    stock_chat_body = json.dumps(stock_chat).encode("utf-8")

    def responder(_svc, exchange, conn):
        if exchange.path == "/health":
            _send(conn, 200, {}, b"", keepalive=True)
            return
        if exchange.path == "/v1/models":
            body = json.dumps(
                {"data": [{"id": LOCAL_MODEL, "object": "model",
                           "owned_by": "vllm", "root": "/opt/gemma-artifact",
                           "parent": None, "max_model_len": 4096}]}
            ).encode("utf-8")
            _send(conn, 200, {"Content-Type": "application/json"}, body)
            return
        _send(conn, 200, {"Content-Type": "application/json"}, stock_chat_body)

    server = LoopbackHTTP(responder).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        decision = _run(local_gemma_client.decide_route(_route_request(), 0.5))
        assert decision.selected_route_id
        health = _run(local_gemma_client.provider_health(0.5))
    finally:
        server.stop()
    assert health["engine_healthy"] is True
    assert health["model_served"] is True
    assert health["ready"] is True


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_google_cross_origin_redirect_sends_zero_bytes_to_target(status, monkeypatch):
    target = LoopbackHTTP(lambda _svc, _ex, conn: _send(conn, 200, {}, _gemini_body())).start()
    origin = LoopbackHTTP(
        lambda _svc, _ex, conn: _send_redirect(conn, f"{target.origin}/stolen", status)
    ).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{origin.origin}/v1beta/models")
        with pytest.raises(RuntimeError, match="Google Gemini redirect refused"):
            _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        origin.stop()
        target.stop()
    assert origin.exchanges
    assert target.exchanges == []
    assert GOOGLE_SECRET in origin.exchanges[0].headers.get("x-goog-api-key", "")


def test_google_same_origin_redirect_is_refused(monkeypatch):
    stolen = {"count": 0}

    def responder(_svc, exchange, conn):
        if exchange.path.endswith("/stolen"):
            stolen["count"] += 1
            _send(conn, 200, {}, _gemini_body())
            return
        _send_redirect(conn, "/stolen", 307)

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(RuntimeError, match="Google Gemini redirect refused"):
            _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()
    assert stolen["count"] == 0
    assert all(not item.path.endswith("/stolen") for item in server.exchanges)


def test_local_cross_origin_and_same_origin_redirects_are_refused(monkeypatch):
    target = LoopbackHTTP(lambda _svc, _ex, conn: _send(conn, 200, {}, _gemma_body())).start()
    origin = LoopbackHTTP(
        lambda _svc, _ex, conn: _send_redirect(conn, f"{target.origin}/stolen", 302)
    ).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, origin.origin)
        with pytest.raises(RuntimeError, match="local Gemma redirect refused"):
            _run(local_gemma_client.decide_route(_route_request(), 0.5))
    finally:
        origin.stop()
        target.stop()
    assert target.exchanges == []

    stolen = {"count": 0}

    def responder(_svc, exchange, conn):
        if exchange.path == "/stolen":
            stolen["count"] += 1
            _send(conn, 200, {}, _gemma_body())
            return
        _send_redirect(conn, "/stolen", 302)

    server = LoopbackHTTP(responder).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(RuntimeError, match="local Gemma redirect refused"):
            _run(local_gemma_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()
    assert stolen["count"] == 0


def test_oversized_chunked_response_is_refused_before_full_buffer(monkeypatch):
    chunk = b"A" * 8192
    chunks = [chunk] * 10
    started = time.perf_counter()

    def responder(_svc, _ex, conn):
        _send_chunked(conn, chunks)
        time.sleep(1.0)

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(RuntimeError, match="Google Gemini response exceeded size limit"):
            _run(gemini_client.decide_route(_route_request(), 2.0))
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(RuntimeError, match="local Gemma response exceeded size limit"):
            _run(local_gemma_client.decide_route(_route_request(), 2.0))
    finally:
        server.stop()
    assert time.perf_counter() - started < 1.8


def test_content_length_lie_declared_over_ceiling_fails_closed_without_waiting(monkeypatch):
    started = time.perf_counter()

    def responder(_svc, _ex, conn):
        header = (
            "HTTP/1.1 200 X\r\n"
            "Connection: close\r\n"
            f"Content-Length: {MAX_PROVIDER_RESPONSE_BYTES + 1}\r\n"
            "\r\n"
        )
        conn.sendall(header.encode("ascii"))
        time.sleep(1.2)

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(RuntimeError, match="Google Gemini response exceeded size limit"):
            _run(gemini_client.decide_route(_route_request(), 2.0))
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(RuntimeError, match="local Gemma response exceeded size limit"):
            _run(local_gemma_client.decide_route(_route_request(), 2.0))
    finally:
        server.stop()
    assert time.perf_counter() - started < 1.0


def test_content_length_lie_short_declaration_does_not_consume_trailer(monkeypatch):
    inner = _gemini_body()
    declared = 16

    def responder(_svc, _ex, conn):
        payload = inner[:declared] + b"X" * 200000
        header = (
            "HTTP/1.1 200 X\r\n"
            "Connection: close\r\n"
            f"Content-Length: {declared}\r\n"
            "\r\n"
        )
        conn.sendall(header.encode("ascii") + payload)

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(json.JSONDecodeError):
            _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()


def test_decompression_expansion_is_capped_at_64kib(monkeypatch):
    raw = gzip.compress(b"A" * (MAX_PROVIDER_RESPONSE_BYTES + 4096), compresslevel=9)
    assert len(raw) < MAX_PROVIDER_RESPONSE_BYTES

    def responder(_svc, _ex, conn):
        _send(
            conn,
            200,
            {"Content-Encoding": "gzip", "Content-Type": "application/json"},
            raw,
        )

    server = LoopbackHTTP(responder).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(RuntimeError, match="local Gemma response exceeded size limit"):
            _run(local_gemma_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()


def test_timeout_is_enforced_on_the_locked_transport(monkeypatch):
    def responder(_svc, _ex, conn):
        time.sleep(1.0)

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(httpx2.TimeoutException):
            _run(gemini_client.decide_route(_route_request(), 0.15))
    finally:
        server.stop()


def test_partial_response_fails_closed(monkeypatch):
    def responder(_svc, _ex, conn):
        conn.sendall(
            b"HTTP/1.1 200 X\r\nConnection: close\r\n\r\n{\"candidates\":[{\"content\":"
        )

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(json.JSONDecodeError):
            _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()


def test_connection_cleanup_after_oversized_abort_allows_a_later_success(monkeypatch):
    payloads = iter([None, _gemini_body()])

    def responder(_svc, _ex, conn):
        body = next(payloads)
        if body is None:
            _send_chunked(conn, [b"A" * 9000] * 12)
            return
        _send(conn, 200, {"Content-Type": "application/json"}, body)

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(RuntimeError, match="exceeded size limit"):
            _run(gemini_client.decide_route(_route_request(), 0.5))
        deadline = time.time() + 2.0
        while server.closed < 1 and time.time() < deadline:
            time.sleep(0.01)
        assert server.closed >= 1
        decision = _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()
    assert decision.selected_route_id == "demo-route-b"
    assert len(server.exchanges) == 2


def test_trust_env_false_ignores_http_proxy(monkeypatch):
    proxy = LoopbackHTTP(lambda _svc, _ex, conn: _send(conn, 500, {}, b"proxy")).start()
    origin = LoopbackHTTP(
        lambda _svc, _ex, conn: _send(conn, 200, {}, _gemini_body())
    ).start()
    try:
        monkeypatch.setenv("HTTP_PROXY", proxy.origin)
        monkeypatch.setenv("HTTPS_PROXY", proxy.origin)
        monkeypatch.setenv("ALL_PROXY", proxy.origin)
        monkeypatch.setenv("http_proxy", proxy.origin)
        monkeypatch.setenv("https_proxy", proxy.origin)
        monkeypatch.setenv("all_proxy", proxy.origin)
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{origin.origin}/v1beta/models")
        decision = _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        origin.stop()
        proxy.stop()
    assert decision.selected_route_id == "demo-route-b"
    assert proxy.exchanges == []
    assert origin.exchanges


def test_terse_json_and_unknown_keys_still_fail_closed(monkeypatch):
    inners = [
        json.dumps(
            {
                "selected_route_id": "demo-route-b",
                "decision": "switch",
                "confidence": 0.9,
                "reason_codes": ["healthier_alternate"],
                "prose": "extra",
            }
        ),
        json.dumps(
            {
                "selected_route_id": "demo-route-b",
                "decision": "switch",
                "confidence": 0.9,
                "reason_codes": ["NOT_SNAKE"],
            }
        ),
    ]

    def responder(_svc, _exchange, conn):
        _send(conn, 200, {}, _gemini_body(inners.pop(0)))

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(ValidationError):
            _run(gemini_client.decide_route(_route_request(), 0.5))
        with pytest.raises(ValidationError):
            _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()
    with pytest.raises(ValidationError):
        ProviderRouteDecision(
            selected_route_id="demo-route-b",
            decision="switch",
            confidence=0.9,
            reason_codes=["one", "two", "three", "four"],
        )


def test_local_health_bounds_model_list_and_refuses_redirects(monkeypatch):
    def oversized(_svc, exchange, conn):
        if exchange.path == "/health":
            _send(conn, 200, {}, b"")
            return
        _send_chunked(conn, [b"B" * 9000] * 12)

    huge = LoopbackHTTP(oversized).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, huge.origin)
        health = _run(local_gemma_client.provider_health(0.5))
    finally:
        huge.stop()
    assert health["ready"] is False
    assert health["error_kind"]

    def redirected(_svc, exchange, conn):
        _send_redirect(conn, "/elsewhere", 302)

    bounced = LoopbackHTTP(redirected).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, bounced.origin)
        health = _run(local_gemma_client.provider_health(0.5))
    finally:
        bounced.stop()
    assert health["ready"] is False
    assert health["error_kind"] == "RuntimeError"


def _valid_route_dict():
    return {
        "selected_route_id": "demo-route-b",
        "decision": "switch",
        "confidence": 0.87,
        "reason_codes": ["healthier_alternate"],
    }


def _valid_support_dict():
    return {"answer": "Use the healthier route.", "escalated": False}


class _NonStreamingClient:
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def request(self, *args, **kwargs):
        raise AssertionError("non-streaming request must not send")

    async def get(self, *args, **kwargs):
        raise AssertionError("non-streaming get must not send")

    async def post(self, *args, **kwargs):
        raise AssertionError("non-streaming post must not send")

    async def aclose(self):
        return None

    @property
    def is_closed(self):
        return False


def test_provider_schemas_reject_string_to_float_and_string_to_bool_coercion():
    route = _valid_route_dict()
    with pytest.raises(ValidationError):
        ProviderRouteDecision.model_validate({**route, "confidence": "0.87"})
    with pytest.raises(ValidationError):
        ProviderRouteDecision.model_validate({**route, "confidence": "1"})
    with pytest.raises(ValidationError):
        ProviderRouteDecision.model_validate_json(
            json.dumps({**route, "confidence": "0.87"})
        )
    support = _valid_support_dict()
    with pytest.raises(ValidationError):
        ProviderSupportAnswer.model_validate({**support, "escalated": "true"})
    with pytest.raises(ValidationError):
        ProviderSupportAnswer.model_validate({**support, "escalated": "false"})
    with pytest.raises(ValidationError):
        ProviderSupportAnswer.model_validate({**support, "escalated": "1"})
    with pytest.raises(ValidationError):
        ProviderSupportAnswer.model_validate_json(
            json.dumps({**support, "escalated": "true"})
        )
    ProviderRouteDecision.model_validate(route)
    ProviderSupportAnswer.model_validate(support)


def test_double_encoded_terse_decision_is_unwrapped_once_and_validated(monkeypatch):
    outer = json.dumps(_valid_route_dict())
    payloads = [_gemini_body(outer), _gemma_body(outer)]

    def responder(_svc, _ex, conn):
        _send(conn, 200, {"Content-Type": "application/json"}, payloads.pop(0))

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        assert _run(gemini_client.decide_route(_route_request(), 0.5)).selected_route_id == "demo-route-b"
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        assert _run(local_gemma_client.decide_route(_route_request(), 0.5)).selected_route_id == "demo-route-b"
    finally:
        server.stop()


def test_terse_decision_unwraps_exactly_one_level(monkeypatch):
    outer = json.dumps(_valid_route_dict())
    deeper = json.dumps(json.dumps(outer))
    payloads = [_gemini_body(outer), _gemma_body(outer), _gemini_body(deeper)]

    def responder(_svc, _ex, conn):
        _send(conn, 200, {"Content-Type": "application/json"}, payloads.pop(0))

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        assert _run(gemini_client.decide_route(_route_request(), 0.5)).selected_route_id == "demo-route-b"
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        assert _run(local_gemma_client.decide_route(_route_request(), 0.5)).selected_route_id == "demo-route-b"
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(RuntimeError, match="no structured content"):
            _run(gemini_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()


def test_terse_decision_allows_whitespace_padded_double_encode(monkeypatch):
    outer = f"  {json.dumps(_valid_route_dict())}\n"
    payloads = [_gemini_body(outer), _gemma_body(outer)]

    def responder(_svc, _ex, conn):
        _send(conn, 200, {"Content-Type": "application/json"}, payloads.pop(0))

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        assert _run(gemini_client.decide_route(_route_request(), 0.5)).selected_route_id == "demo-route-b"
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        assert _run(local_gemma_client.decide_route(_route_request(), 0.5)).selected_route_id == "demo-route-b"
    finally:
        server.stop()


def test_double_encoded_terse_decision_rejects_trailing_or_bad_inner(monkeypatch):
    malformed = [
        _gemini_body('"not a json object literal"'),
        _gemma_body('"{"unterminated"'),
    ]

    def responder(_svc, _ex, conn):
        _send(conn, 200, {"Content-Type": "application/json"}, malformed.pop(0))

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(RuntimeError, match="no structured content"):
            _run(gemini_client.decide_route(_route_request(), 0.5))
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(RuntimeError, match="no structured content"):
            _run(local_gemma_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()


def test_double_encoded_terse_decision_still_rejects_unknown_keys(monkeypatch):
    bad = {**_valid_route_dict(), "prose": "extra"}
    payloads = [_gemini_body(json.dumps(bad)), _gemma_body(json.dumps(bad))]

    def responder(_svc, _ex, conn):
        _send(conn, 200, {"Content-Type": "application/json"}, payloads.pop(0))

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(ValidationError):
            _run(gemini_client.decide_route(_route_request(), 0.5))
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(ValidationError):
            _run(local_gemma_client.decide_route(_route_request(), 0.5))
    finally:
        server.stop()


def test_provider_wire_json_rejects_string_coerced_confidence_and_escalated(monkeypatch):
    payloads = [
        _gemini_body(json.dumps({**_valid_route_dict(), "confidence": "0.87"})),
        _gemma_body(json.dumps({**_valid_route_dict(), "confidence": "0.87"})),
        _gemini_body(json.dumps(_valid_support_dict() | {"escalated": "true"})),
        _gemma_body(json.dumps(_valid_support_dict() | {"escalated": "true"})),
    ]

    def responder(_svc, _ex, conn):
        _send(conn, 200, {"Content-Type": "application/json"}, payloads.pop(0))

    server = LoopbackHTTP(responder).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(ValidationError):
            _run(gemini_client.decide_route(_route_request(), 0.5))
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(ValidationError):
            _run(local_gemma_client.decide_route(_route_request(), 0.5))
        with pytest.raises(ValidationError):
            _run(gemini_client.answer_support("Need help", "", 0.5))
        with pytest.raises(ValidationError):
            _run(local_gemma_client.answer_support("Need help", "", 0.5))
    finally:
        server.stop()
    assert payloads == []


def test_non_streaming_client_fails_closed_before_sending(monkeypatch):
    sent = []

    class Guard(_NonStreamingClient):
        async def request(self, *args, **kwargs):
            sent.append("request")
            raise AssertionError("non-streaming request must not send")

        async def get(self, *args, **kwargs):
            sent.append("get")
            raise AssertionError("non-streaming get must not send")

        async def post(self, *args, **kwargs):
            sent.append("post")
            raise AssertionError("non-streaming post must not send")

    monkeypatch.setattr(gemini_client.httpx2, "AsyncClient", Guard)
    monkeypatch.setattr(local_gemma_client.httpx2, "AsyncClient", Guard)
    server = LoopbackHTTP(
        lambda _svc, _ex, conn: _send(conn, 200, {}, _gemini_body())
    ).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")
        with pytest.raises(RuntimeError, match="Google Gemini client does not support streaming"):
            _run(gemini_client.decide_route(_route_request(), 0.5))
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        with pytest.raises(RuntimeError, match="local Gemma client does not support streaming"):
            _run(local_gemma_client.decide_route(_route_request(), 0.5))
        health = _run(local_gemma_client.provider_health(0.5))
        assert health["ready"] is False
        assert health["error_kind"] == "RuntimeError"
    finally:
        server.stop()
    assert sent == []
    assert server.exchanges == []
    assert server.accepts == 0


def test_google_keepalive_reuses_one_authenticated_connection(spy_clients, monkeypatch):
    def responder(_svc, _ex, conn):
        _send(conn, 200, {"Content-Type": "application/json"}, _gemini_body(), keepalive=True)

    server = LoopbackHTTP(responder, keepalive=True).start()
    try:
        monkeypatch.setattr(gemini_client, "GOOGLE_GENERATE_BASE", f"{server.origin}/v1beta/models")

        async def consecutive():
            first = await gemini_client.decide_route(_route_request(), 0.5)
            second = await gemini_client.decide_route(_route_request(), 0.5)
            return first, second

        first, second = _run(consecutive())
    finally:
        server.stop()
    assert first.selected_route_id == "demo-route-b"
    assert second.selected_route_id == "demo-route-b"
    assert len(spy_clients) == 1
    assert spy_clients[0]["trust_env"] is False
    assert spy_clients[0]["follow_redirects"] is False
    assert spy_clients[0]["max_redirects"] == 0
    assert spy_clients[0]["headers"]["Accept-Encoding"] == "identity"
    assert GOOGLE_SECRET not in str(spy_clients[0].get("headers"))
    assert server.accepts == 1
    assert len(server.exchanges) == 2
    assert all(item.headers.get("x-goog-api-key") == GOOGLE_SECRET for item in server.exchanges)
    assert all("key=" not in item.path for item in server.exchanges)


def test_local_keepalive_reuses_one_authenticated_loopback_connection(spy_clients, monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_VLLM_API_KEY", LOCAL_SECRET)

    def responder(_svc, _ex, conn):
        _send(conn, 200, {"Content-Type": "application/json"}, _gemma_body(), keepalive=True)

    server = LoopbackHTTP(responder, keepalive=True).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, server.origin)

        async def consecutive():
            first = await local_gemma_client.decide_route(_route_request(), 0.5)
            second = await local_gemma_client.decide_route(_route_request(), 0.5)
            return first, second

        first, second = _run(consecutive())
    finally:
        server.stop()
    assert first.selected_route_id == "demo-route-b"
    assert second.selected_route_id == "demo-route-b"
    assert len(spy_clients) == 1
    client_headers = spy_clients[0].get("headers") or {}
    assert client_headers.get("Accept-Encoding") == "identity"
    assert "Authorization" not in client_headers
    assert LOCAL_SECRET not in str(client_headers)
    assert spy_clients[0]["trust_env"] is False
    assert server.accepts == 1
    assert len(server.exchanges) == 2
    assert all(item.headers.get("authorization") == f"Bearer {LOCAL_SECRET}" for item in server.exchanges)
    assert all(item.path == "/v1/chat/completions" for item in server.exchanges)


def test_local_health_keepalive_reuses_connection_across_consecutive_calls(monkeypatch):
    monkeypatch.setenv("SMART_ROUTER_VLLM_API_KEY", LOCAL_SECRET)

    def responder(_svc, exchange, conn):
        if exchange.path == "/health":
            _send(conn, 200, {}, b"", keepalive=True)
            return
        body = json.dumps(
            {
                "data": [
                    {
                        "id": LOCAL_MODEL,
                        "model_revision": LOCAL_MODEL_REVISION,
                        "artifact_inventory_sha256": LOCAL_ARTIFACT_INVENTORY,
                    }
                ]
            }
        ).encode("utf-8")
        _send(conn, 200, {"Content-Type": "application/json"}, body, keepalive=True)

    server = LoopbackHTTP(responder, keepalive=True).start()
    try:
        _pin_installer_gemma_origin(monkeypatch, server.origin)
        health = _run(local_gemma_client.provider_health(0.5))
    finally:
        server.stop()
    assert health["ready"] is True
    assert health["model_served"] is True
    assert server.accepts == 1
    assert [item.path for item in server.exchanges] == ["/health", "/v1/models"]
    assert all(item.headers.get("authorization") == f"Bearer {LOCAL_SECRET}" for item in server.exchanges)
