"""Win's VPN fail-safe Smart Router service.

Normal connection initiation is deterministic. Distress requests may use
local Gemma on aicore, then server-side Google Gemini, before falling back to
the same deterministic scorer. Every AI result is advisory and revalidated
against the caller's closed candidate set.
"""
import asyncio
import csv
import concurrent.futures
import hashlib
import importlib.metadata
import io
import itertools
import json
import os
import re
import time
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

import security as router_security
from fallback import candidate_is_protocol_eligible, deterministic_decision
from gemini_client import (
    answer_support,
    decide_route as decide_google_route,
    gemini_configured,
    provider_health as google_provider_health,
)
from local_gemma_client import (
    answer_support as answer_local_support,
    decide_route as decide_local_route,
    get_local_model,
    local_configured,
    provider_health as local_provider_health,
)
from provider_common import ProviderRouteDecision, ProviderSupportAnswer, provider_payload
from schemas import RouteDecision, RouteRequest, strict_json_loads
from security import (
    DECISION_LOG,
    auth_secret,
    decision_log_path,
    replay_journal_ready,
)

__VERSION__ = "2.2.1"

DECISIONS_RING_SIZE = 500
DECISIONS_PAGE_SIZE = 50
HOPPY_DOCS_PAGE = "https://www.winsvpn.org/support/"
HOPPY_FALLBACK_ANSWER = (
    "Hoppy could not reach the AI brain just now, so here is the safe answer: "
    f"check the Win's VPN support page at {HOPPY_DOCS_PAGE} for setup and troubleshooting. "
    "You can also switch routes from the app; the deterministic router keeps you online."
)

DECISIONS: deque = deque(maxlen=DECISIONS_RING_SIZE)

STATS_WINDOW_H = 1.0  # /stats looks back one hour

PROVIDER_STATUS = {
    "local_gemma": {"last_error": None, "last_success": None},
    "google_gemini": {"last_error": None, "last_success": None},
}
LAST_LOG_ERROR: Optional[dict] = None

_TOKEN_REDACT = re.compile(
    r"(?i)(?:bearer\s+)?(?:AIza[0-9A-Za-z_-]{20,}|[A-Za-z0-9_-]{32,})"
)

FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="14" fill="#0b0f14"/>
<circle cx="20" cy="32" r="7" fill="#3fb950"/>
<circle cx="44" cy="32" r="7" fill="#4f8cff"/>
<path d="M27 32h10" stroke="#8b98a5" stroke-width="3" fill="none"/>
<circle cx="44" cy="15" r="4" fill="#d29922"/>
<path d="M40 18 L32 28" stroke="#8b98a5" stroke-width="3" fill="none"/>
<circle cx="20" cy="49" r="4" fill="#d29922"/>
<path d="M24 46 L32 36" stroke="#8b98a5" stroke-width="3" fill="none"/>
</svg>"""

CSV_COLUMNS = [
    "timestamp",
    "request_id",
    "current",
    "selected",
    "decision",
    "source",
    "confidence",
    "reason_codes",
    "latency_ms",
]

_BUDGET_STARTED_KEY = "winsvpn_router_budget_started"
_BUDGET_DEADLINE_KEY = "winsvpn_router_budget_deadline"
_STORAGE_MAX_WORKERS = 4
_STORAGE_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=_STORAGE_MAX_WORKERS,
    thread_name_prefix="wins-router-storage",
)
_STORAGE_SLOTS = threading.BoundedSemaphore(_STORAGE_MAX_WORKERS)
# Public /ready probes never take an admission slot: unauthenticated traffic
# must not be able to occupy the pool that signed /route admission needs.
# Concurrent public probes share one in-flight journal probe.
_PUBLIC_READY_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix="wins-router-ready",
)
_PUBLIC_READY_LOCK = threading.Lock()
_PUBLIC_READY_INFLIGHT: Optional[concurrent.futures.Future] = None


async def _run_storage_with_deadline(
    call: Callable,
    *args,
    deadline: float,
    deadline_keyword: Optional[str] = None,
):
    """Run blocking storage in a bounded pool while bounding the await.

    Timed-out and cancelled awaits cannot stop a Python worker that is already
    inside an OS call. The fixed slot count prevents those workers from growing
    without bound. Security-sensitive workers additionally receive the exact
    monotonic deadline and must check it before committing durable state.
    """
    loop = asyncio.get_running_loop()
    remaining = deadline - loop.time()
    if remaining <= 0:
        raise TimeoutError("total routing budget exhausted")
    # OI-39 as corrected in the Round 37 cross-examination: a raw
    # BoundedSemaphore.acquire blocks the calling thread, which here is the
    # event loop; 250 ms of loop stall under contention became a self-inflicted
    # 503 storm. The bounded wait therefore runs on the default executor, and
    # the event loop stays free.
    slot_wait = min(max(remaining, 0.0), 0.25)
    try:
        acquired = await loop.run_in_executor(
            None, lambda: _STORAGE_SLOTS.acquire(blocking=True, timeout=slot_wait)
        )
    except TimeoutError:
        acquired = False
    if not acquired:
        raise TimeoutError("storage worker capacity exhausted")

    def invoke():
        try:
            if time.monotonic() >= deadline:
                raise TimeoutError("storage worker deadline exhausted before start")
            if deadline_keyword is None:
                return call(*args)
            return call(*args, **{deadline_keyword: deadline})
        finally:
            _STORAGE_SLOTS.release()

    future = loop.run_in_executor(_STORAGE_EXECUTOR, invoke)
    try:
        # The slot wait above already spent part of the budget; bound the
        # worker await by the same absolute deadline, not the pre-admission
        # remainder, so a contended request never overruns the routing budget.
        async with asyncio.timeout_at(deadline):
            return await asyncio.shield(future)
    except BaseException:
        # Shielding deliberately leaves a started worker alive so its finally
        # block releases the bounded slot. A security worker may commit only if
        # its own deadline check still succeeds.
        raise


class DeadlineRouterSecurityMiddleware:
    """Preserve authenticated admission while offloading its SQLite journal."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "/")
        # OI-37 (Round 36 treaty): deny by default. Public probe/favicon paths
        # pass; known application paths get the full HMAC admission; anything
        # else is a 404 before any handler runs, so a future route cannot
        # silently serve unauthenticated traffic.
        if path in router_security.PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return
        if path not in router_security.PROTECTED_PATHS:
            await router_security._reject(scope, receive, send, 404, "not found")
            return

        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            deadline = started + routing_budget_s()
            limit = router_security.max_body_bytes()
        except RuntimeError:
            await router_security._reject(
                scope,
                receive,
                send,
                503,
                "router security configuration invalid",
            )
            return
        state = scope.setdefault("state", {})
        state[_BUDGET_STARTED_KEY] = started
        state[_BUDGET_DEADLINE_KEY] = deadline

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > limit:
                    await router_security._reject(
                        scope, receive, send, 413, "request body too large"
                    )
                    return
            except ValueError:
                await router_security._reject(
                    scope, receive, send, 400, "invalid content length"
                )
                return

        try:
            async with asyncio.timeout_at(deadline):
                body, exceeded = await router_security._read_bounded_body(receive, limit)
        except TimeoutError:
            await router_security._reject(
                scope, receive, send, 503, "routing deadline exceeded"
            )
            return
        if exceeded:
            await router_security._reject(scope, receive, send, 413, "request body too large")
            return

        timestamp_raw = headers.get(b"x-smart-router-timestamp", b"").decode(
            "ascii", "ignore"
        )
        nonce = headers.get(b"x-smart-router-nonce", b"").decode("ascii", "ignore")
        supplied = headers.get(b"x-smart-router-signature", b"").decode(
            "ascii", "ignore"
        )
        try:
            secret = router_security.auth_secret()
            window = router_security.auth_window_seconds()
        except RuntimeError:
            await router_security._reject(
                scope, receive, send, 503, "router authentication unavailable"
            )
            return
        try:
            timestamp = int(timestamp_raw)
        except ValueError:
            await router_security._reject(
                scope, receive, send, 401, "authentication required"
            )
            return

        now_wall = time.time()
        if (
            not router_security._NONCE_RE.fullmatch(nonce)
            or not router_security._SIGNATURE_RE.fullmatch(supplied)
            or abs(now_wall - timestamp) > window
        ):
            await router_security._reject(
                scope, receive, send, 401, "authentication required"
            )
            return
        query = scope.get("query_string", b"")
        expected = router_security.sign_request(
            secret,
            scope.get("method", "GET"),
            scope.get("path", "/"),
            timestamp_raw,
            nonce,
            body,
            query=query,
        )
        if not router_security.hmac.compare_digest(supplied, expected):
            await router_security._reject(
                scope, receive, send, 401, "authentication required"
            )
            return

        client = scope.get("client") or ("unknown", 0)
        rate_key = str(client[0])
        try:
            allowed = router_security.RATE_LIMITER.allow(rate_key, time.monotonic())
        except RuntimeError:
            await router_security._reject(
                scope,
                receive,
                send,
                503,
                "router security configuration invalid",
            )
            return
        if not allowed:
            await router_security._reject(scope, receive, send, 429, "rate limit exceeded")
            return

        try:
            replay_decision = await _run_storage_with_deadline(
                router_security.REPLAY_GUARD.accept,
                nonce,
                None,
                float(window),
                float(timestamp),
                deadline=deadline,
                deadline_keyword="deadline",
            )
        except TimeoutError:
            await router_security._reject(
                scope, receive, send, 503, "routing deadline exceeded"
            )
            return
        if replay_decision is router_security.ReplayDecision.REPLAY:
            await router_security._reject(scope, receive, send, 401, "replayed request")
            return
        if replay_decision is not router_security.ReplayDecision.ACCEPTED:
            await router_security._reject(
                scope, receive, send, 503, "replay protection unavailable"
            )
            return

        sent = False

        async def replay_receive() -> dict:
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)


class StrictJSONMiddleware:
    """Reject duplicate keys, non-finite numbers, and trailing JSON before routing."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") not in {"POST", "PUT", "PATCH"}
            or scope.get("path") not in router_security.PROTECTED_PATHS
        ):
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        if body:
            try:
                parsed = strict_json_loads(body)
            except json.JSONDecodeError:
                response = JSONResponse({"detail": "malformed json"}, status_code=422)
                await response(scope, receive, send)
                return
            except (TypeError, UnicodeDecodeError, ValueError) as err:
                detail = str(err)
                if detail not in {"duplicate JSON key", "non-finite JSON number"}:
                    detail = "malformed json"
                response = JSONResponse({"detail": detail}, status_code=422)
                await response(scope, receive, send)
                return
            if not isinstance(parsed, dict):
                response = JSONResponse({"detail": "malformed json"}, status_code=422)
                await response(scope, receive, send)
                return
        sent = False

        async def replay_receive() -> dict:
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)


app = FastAPI(
    title="Win's VPN Smart Router",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(StrictJSONMiddleware)
app.add_middleware(DeadlineRouterSecurityMiddleware)


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(
    _request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return useful locations without reflecting rejected values or secrets."""
    details = [
        {
            "type": error.get("type", "value_error"),
            "loc": list(error.get("loc", ())),
            "msg": error.get("msg", "invalid request"),
        }
        for error in exc.errors()
    ]
    return JSONResponse({"detail": details}, status_code=422)


def _bounded_ms(name: str, default_ms: int, minimum_ms: int, maximum_ms: int) -> float:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw) if raw else default_ms
    except ValueError as err:
        raise RuntimeError(f"{name} must be an integer") from err
    if not minimum_ms <= value <= maximum_ms:
        raise RuntimeError(f"{name} must be between {minimum_ms} and {maximum_ms}")
    return value / 1000.0


def routing_budget_s() -> float:
    return _bounded_ms("SMART_ROUTER_TOTAL_BUDGET_MS", 2000, 250, 5000)


def _request_budget(request: Request) -> tuple[float, float]:
    state = request.scope.get("state", {})
    started = state.get(_BUDGET_STARTED_KEY)
    deadline = state.get(_BUDGET_DEADLINE_KEY)
    if isinstance(started, (int, float)) and isinstance(deadline, (int, float)):
        return float(started), float(deadline)
    started = asyncio.get_running_loop().time()
    return started, started + routing_budget_s()


def local_timeout_s() -> float:
    return _bounded_ms("SMART_ROUTER_LOCAL_TIMEOUT_MS", 900, 100, 3000)


def google_timeout_s() -> float:
    return _bounded_ms("SMART_ROUTER_GOOGLE_TIMEOUT_MS", 900, 100, 3000)


def queue_timeout_s() -> float:
    return _bounded_ms("SMART_ROUTER_QUEUE_TIMEOUT_MS", 20, 1, 250)


def max_provider_concurrency() -> int:
    raw = os.environ.get("SMART_ROUTER_MAX_CONCURRENT_REQUESTS", "").strip()
    try:
        value = int(raw) if raw else 8
    except ValueError as err:
        raise RuntimeError("SMART_ROUTER_MAX_CONCURRENT_REQUESTS must be an integer") from err
    if not 1 <= value <= 64:
        raise RuntimeError("SMART_ROUTER_MAX_CONCURRENT_REQUESTS must be between 1 and 64")
    return value


PROVIDER_SEMAPHORE = asyncio.Semaphore(max_provider_concurrency())


def decisions_file_path() -> str:
    return str(decision_log_path())


def _sanitize_error(err: BaseException) -> dict:
    """Turn an exception into a small, secret-safe diagnostic record."""
    msg = str(err) or type(err).__name__
    for name in (
        "SMART_ROUTER_HMAC_SECRET",
        "EDGE_ROUTER_SECRET",
        "GEMINI_API_KEY",
        "SMART_ROUTER_VLLM_API_KEY",
        "VLLM_API_KEY",
    ):
        value = os.environ.get(name, "").strip()
        if value:
            msg = msg.replace(value, "[REDACTED]")
    msg = _TOKEN_REDACT.sub("[REDACTED]", msg)
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": type(err).__name__,
        "detail": " ".join(msg.split())[:200],
    }


def _deps() -> dict:
    names = ["fastapi", "uvicorn", "pydantic", "starlette", "httpx2"]
    out = {}
    for name in names:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = None
    return out


def _audit_request(request: RouteRequest) -> dict:
    payload = provider_payload(request)
    payload["request_id_hash"] = hashlib.sha256(
        request.request_id.encode("utf-8")
    ).hexdigest()[:16]
    return payload


def _model_for_source(source: str) -> Optional[str]:
    if source == "local_gemma":
        try:
            return get_local_model()
        except RuntimeError:
            return None
    if source == "google_gemini":
        return os.environ.get("GEMINI_MODEL", "").strip() or None
    return None


async def record_decision(
    request: RouteRequest,
    decision: RouteDecision,
    latency_ms: float,
    deadline: float,
    provider_errors: Optional[dict] = None,
) -> dict:
    global LAST_LOG_ERROR
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": _model_for_source(decision.source),
        "request": _audit_request(request),
        "decision": decision.model_dump(),
        "latency_ms": round(latency_ms, 2),
        "provider_errors": provider_errors or {},
    }
    DECISIONS.append(record)
    try:
        await _run_storage_with_deadline(
            DECISION_LOG.append,
            record,
            deadline=deadline,
        )
        LAST_LOG_ERROR = None
    except TimeoutError as err:
        LAST_LOG_ERROR = _sanitize_error(err)
    except (OSError, RuntimeError, TypeError, ValueError) as err:
        LAST_LOG_ERROR = _sanitize_error(err)
    return record


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def compute_stats() -> dict:
    """Aggregate stats over the last 1h window (and all time) from the ring."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=STATS_WINDOW_H)

    by_source = {"explicit": 0, "local_gemma": 0, "google_gemini": 0, "fallback": 0}
    per_route: dict = {}
    per_decision: dict = {}
    latencies: list = []
    for rec in DECISIONS:
        ts = _parse_ts(rec.get("timestamp", ""))
        if ts is not None and ts >= cutoff:
            source = rec.get("decision", {}).get("source", "fallback")
            by_source[source] = by_source.get(source, 0) + 1
            route = rec.get("decision", {}).get("selected_route_id", "unknown")
            per_route[route] = per_route.get(route, 0) + 1
            decision = rec.get("decision", {}).get("decision", "switch")
            per_decision[decision] = per_decision.get(decision, 0) + 1
            latencies.append(float(rec.get("latency_ms", 0.0) or 0.0))

    avg_ms = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    max_ms = round(max(latencies), 2) if latencies else 0.0

    return {
        "generated_at": now.isoformat(),
        "window_start": cutoff.isoformat(),
        "window_end": now.isoformat(),
        "window_hours": STATS_WINDOW_H,
        "total": len(latencies),
        "by_source": by_source,
        "latency_ms": {"avg": avg_ms, "max": max_ms},
        "per_route": per_route,
        "per_decision": per_decision,
        "all_time_total": len(DECISIONS),
    }


def _decision_row(rec: dict) -> dict:
    return {
        "timestamp": rec.get("timestamp", ""),
        "request_id": rec.get("request", {}).get("request_id_hash", ""),
        "current": rec.get("request", {}).get("current_route_id", ""),
        "selected": rec.get("decision", {}).get("selected_route_id", ""),
        "decision": rec.get("decision", {}).get("decision", ""),
        "source": rec.get("decision", {}).get("source", ""),
        "confidence": rec.get("decision", {}).get("confidence", 0.0),
        "reason_codes": "|".join(rec.get("decision", {}).get("reason_codes", [])),
        "latency_ms": rec.get("latency_ms", 0.0),
    }


def _iter_csv_rows() -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    for rec in DECISIONS:
        writer.writerow(_decision_row(rec))
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)


def csv_response() -> StreamingResponse:
    headers = {"Content-Disposition": 'attachment; filename="router_decisions.csv"'}
    return StreamingResponse(
        _iter_csv_rows(),
        media_type="text/csv",
        headers=headers,
    )


class EscalateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=1000)
    context: str = Field(default="", max_length=2000)


def _set_provider_result(name: str, error: Optional[dict]) -> None:
    PROVIDER_STATUS[name]["last_error"] = error
    if error is None:
        PROVIDER_STATUS[name]["last_success"] = datetime.now(timezone.utc).isoformat()


def _authentication_ready() -> bool:
    try:
        auth_secret()
        return True
    except RuntimeError:
        return False


async def _journal_ready(deadline: float) -> bool:
    try:
        await _run_storage_with_deadline(
            replay_journal_ready,
            deadline=deadline,
            deadline_keyword="deadline",
        )
        return True
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError):
        return False


async def _public_journal_ready(deadline: float) -> bool:
    """Readiness for the public probe, outside the bounded admission pool."""
    global _PUBLIC_READY_INFLIGHT
    with _PUBLIC_READY_LOCK:
        future = _PUBLIC_READY_INFLIGHT
        if future is None or future.done():
            future = _PUBLIC_READY_EXECUTOR.submit(
                replay_journal_ready, deadline=deadline
            )
            _PUBLIC_READY_INFLIGHT = future
    try:
        async with asyncio.timeout_at(deadline):
            await asyncio.shield(asyncio.wrap_future(future))
        return True
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError):
        return False


def _local_health_without_pool(error_kind: str) -> dict:
    model = None
    try:
        model = get_local_model()
    except RuntimeError:
        pass
    return {
        "configured": local_configured(),
        "runtime": "vllm",
        "model": model,
        "engine_healthy": False,
        "model_served": False,
        "ready": False,
        "error_kind": error_kind,
    }


async def _admitted_local_provider_health(deadline: float) -> dict:
    loop = asyncio.get_running_loop()
    remaining = deadline - loop.time()
    if remaining <= 0:
        return _local_health_without_pool("RoutingDeadlineExceeded")
    acquired = False
    try:
        await asyncio.wait_for(
            PROVIDER_SEMAPHORE.acquire(),
            timeout=min(queue_timeout_s(), remaining, 0.25),
        )
        acquired = True
        remaining = deadline - loop.time()
        if remaining <= 0:
            return _local_health_without_pool("RoutingDeadlineExceeded")
        return await local_provider_health(timeout_s=min(0.25, remaining))
    except TimeoutError:
        return _local_health_without_pool("ProviderCapacityUnavailable")
    finally:
        if acquired:
            PROVIDER_SEMAPHORE.release()


def _probe_body(*, ok: bool) -> dict:
    return {"ok": ok, "version": __VERSION__}


def _validated_provider_decision(
    raw: ProviderRouteDecision,
    request: RouteRequest,
    source: str,
) -> RouteDecision:
    by_id = {candidate.route_id: candidate for candidate in request.candidates}
    candidate = by_id.get(raw.selected_route_id)
    if candidate is None:
        raise ValueError(f"{source} selected a route outside the closed candidate set")
    if not candidate.reachable or candidate.dns_ok is False:
        raise ValueError(f"{source} selected an ineligible candidate")
    if not candidate_is_protocol_eligible(request, candidate.route_id):
        raise ValueError(f"{source} selected a protocol-ineligible candidate")
    expected = "keep" if candidate.route_id == request.current_route_id else "switch"
    if raw.decision != expected:
        raise ValueError(f"{source} decision field did not match selected route")
    return RouteDecision(
        selected_route_id=candidate.route_id,
        decision=expected,
        confidence=raw.confidence,
        reason_codes=list(raw.reason_codes),
        source=source,
    )


def _explicit_decision(request: RouteRequest) -> RouteDecision:
    selected = request.explicit_route_id
    if selected is None:
        raise ValueError("explicit_route_id is required")
    candidate = next(
        (item for item in request.candidates if item.route_id == selected),
        None,
    )
    if candidate is None:
        raise HTTPException(status_code=422, detail="explicit route is not eligible")
    if not candidate.reachable or candidate.dns_ok is False:
        raise HTTPException(status_code=422, detail="explicit route is not eligible")
    if not candidate_is_protocol_eligible(request, candidate.route_id):
        raise HTTPException(status_code=422, detail="explicit route is not eligible")
    return RouteDecision(
        selected_route_id=selected,
        decision="keep" if selected == request.current_route_id else "switch",
        confidence=1.0,
        reason_codes=["explicit_selection"],
        source="explicit",
    )


async def _attempt_provider(
    name: str,
    call,
    request: RouteRequest,
    timeout_s: float,
    deadline: float,
    errors: dict,
) -> Optional[RouteDecision]:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        error = _sanitize_error(TimeoutError("total routing budget exhausted"))
        errors[name] = error
        _set_provider_result(name, error)
        return None
    bound = max(0.001, min(timeout_s, remaining))
    try:
        raw = await asyncio.wait_for(call(request, bound), timeout=bound)
        decision = _validated_provider_decision(raw, request, name)
        _set_provider_result(name, None)
        return decision
    except Exception as err:
        error = _sanitize_error(err)
        errors[name] = error
        _set_provider_result(name, error)
        return None


@app.post("/route", response_model=RouteDecision)
async def route(request: RouteRequest, http_request: Request) -> RouteDecision:
    """Honor explicit selection; use AI only for an authenticated distress."""
    loop = asyncio.get_running_loop()
    started, deadline = _request_budget(http_request)
    if request.explicit_route_id is not None:
        decision = _explicit_decision(request)
        latency_ms = (loop.time() - started) * 1000.0
        await record_decision(
            request,
            decision,
            latency_ms,
            deadline,
            provider_errors={},
        )
        return decision
    if request.trigger != "distress":
        decision = deterministic_decision(request)
        latency_ms = (loop.time() - started) * 1000.0
        await record_decision(
            request,
            decision,
            latency_ms,
            deadline,
            provider_errors={},
        )
        return decision
    errors: dict = {}
    decision: Optional[RouteDecision] = None
    use_local = local_configured()
    use_google = gemini_configured()
    if use_local or use_google:
        try:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError("total routing budget exhausted")
            await asyncio.wait_for(
                PROVIDER_SEMAPHORE.acquire(),
                timeout=min(queue_timeout_s(), remaining),
            )
        except Exception as err:
            errors["capacity"] = _sanitize_error(err)
        else:
            try:
                if use_local:
                    decision = await _attempt_provider(
                        "local_gemma",
                        decide_local_route,
                        request,
                        local_timeout_s(),
                        deadline,
                        errors,
                    )
                if decision is None and use_google:
                    decision = await _attempt_provider(
                        "google_gemini",
                        decide_google_route,
                        request,
                        google_timeout_s(),
                        deadline,
                        errors,
                    )
            except Exception as err:
                errors["configuration"] = _sanitize_error(err)
            finally:
                PROVIDER_SEMAPHORE.release()

    if decision is None:
        decision = deterministic_decision(request)

    latency_ms = (loop.time() - started) * 1000.0
    await record_decision(
        request,
        decision,
        latency_ms,
        deadline,
        provider_errors=errors,
    )
    return decision


@app.get("/decisions")
async def decisions(request: Request) -> list:
    """Last 50 decision records, most recent first. ?format=csv streams the ring."""
    if request.query_params.get("format") == "csv":
        return csv_response()
    page = list(itertools.islice(reversed(DECISIONS), DECISIONS_PAGE_SIZE))
    return page


@app.get("/decisions.csv")
async def decisions_csv() -> StreamingResponse:
    """Evidence export: stream the full decision ring as CSV (one URL)."""
    return csv_response()


@app.get("/stats")
async def stats() -> dict:
    """Aggregates over the last 1h window: by source, latency, per-route counts."""
    return compute_stats()


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(content=FAVICON_SVG, media_type="image/svg+xml")


@app.post("/hoppy/escalate")
async def hoppy_escalate(body: EscalateRequest, request: Request) -> dict:
    """Run local Gemma, then Google, then the canned safe support answer."""
    acquired = False
    try:
        loop = asyncio.get_running_loop()
        _started, deadline = _request_budget(request)
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError("total routing budget exhausted")
        await asyncio.wait_for(
            PROVIDER_SEMAPHORE.acquire(),
            timeout=min(queue_timeout_s(), remaining),
        )
        acquired = True
        providers = []
        if local_configured():
            providers.append(("local_gemma", answer_local_support, local_timeout_s()))
        if gemini_configured():
            providers.append(("google_gemini", answer_support, google_timeout_s()))
        for name, call, provider_timeout in providers:
            remaining = deadline - loop.time()
            if remaining <= 0:
                error = _sanitize_error(TimeoutError("total routing budget exhausted"))
                _set_provider_result(name, error)
                break
            bound = max(0.001, min(provider_timeout, remaining))
            try:
                raw = await asyncio.wait_for(
                    call(body.question, body.context, bound),
                    timeout=bound,
                )
                answer = ProviderSupportAnswer.model_validate(raw).model_dump()
                _set_provider_result(name, None)
                return answer
            except Exception as err:
                _set_provider_result(name, _sanitize_error(err))
                continue
    except Exception:
        pass
    finally:
        if acquired:
            PROVIDER_SEMAPHORE.release()
    return {"answer": HOPPY_FALLBACK_ANSWER, "escalated": False}


@app.get("/health")
async def health(request: Request) -> JSONResponse:
    _started, deadline = _request_budget(request)
    authentication_ready = _authentication_ready()
    journal_ready = await _journal_ready(deadline) if authentication_ready else False
    local = await _admitted_local_provider_health(deadline)
    google = google_provider_health()
    local.update(PROVIDER_STATUS["local_gemma"])
    google.update(PROVIDER_STATUS["google_gemini"])
    ok = authentication_ready and journal_ready
    body = {
        "ok": ok,
        "ordering": [
            "deterministic_connection_initiation",
            "local_gemma_distress",
            "google_gemini_distress",
            "deterministic_distress_fallback",
        ],
        "authentication_ready": authentication_ready,
        "providers": {
            "local_gemma": local,
            "google_gemini": google,
            "deterministic_fallback": {"ready": True},
        },
        "logging_last_error": LAST_LOG_ERROR,
        "version": __VERSION__,
        "deps": _deps(),
    }
    return JSONResponse(body, status_code=200 if ok else 503)


@app.get("/live")
async def live() -> dict:
    """Credential-free process liveness only. No provider diagnostics."""
    return _probe_body(ok=True)


@app.get("/ready")
async def ready() -> JSONResponse:
    """Public readiness: auth secret and replay journal, no provider diagnostics."""
    authentication_ready = _authentication_ready()
    deadline = asyncio.get_running_loop().time() + min(0.25, routing_budget_s())
    ok = authentication_ready and await _public_journal_ready(deadline)
    return JSONResponse(_probe_body(ok=ok), status_code=200 if ok else 503)


DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Win's VPN Smart Router - deterministic Winn v3 first</title>
<link rel="icon" href="/favicon.ico" type="image/svg+xml">
<style>
:root{--bg:#0b0f14;--panel:#121923;--panel2:#0e141c;--line:#1f2a37;--text:#e6edf3;--muted:#8b98a5;--accent:#4f8cff;--good:#3fb950;--warn:#d29922}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;padding:32px 20px}
.wrap{max-width:880px;margin:0 auto}
header{display:flex;align-items:center;gap:12px;margin-bottom:24px}
.dot{width:10px;height:10px;border-radius:50%;background:var(--good);box-shadow:0 0 8px var(--good)}
h1{font-size:20px;font-weight:600;letter-spacing:.2px}
.sub{color:var(--muted);font-size:12px;margin-top:2px}
.grid{display:grid;grid-template-columns:1fr;gap:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px}
.card h2{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:14px}
.kv{display:flex;flex-wrap:wrap;gap:14px 30px}
.item{display:flex;flex-direction:column;gap:3px}
.label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.value{font-size:16px;font-weight:600;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:600;letter-spacing:.4px}
.badge.keep{background:rgba(63,185,80,.15);color:var(--good)}
.badge.switch{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.gemini{background:rgba(79,140,255,.15);color:var(--accent)}
.badge.fallback{background:rgba(210,153,34,.15);color:var(--warn)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:2px 8px;font-size:11px;font-family:ui-monospace,Menlo,monospace;color:var(--muted)}
.timeline{list-style:none}
.timeline li{display:flex;gap:14px;align-items:center;padding:9px 2px;border-bottom:1px solid var(--line);font-size:13px}
.timeline li:last-child{border-bottom:0}
.t{color:var(--muted);font-family:ui-monospace,Menlo,monospace;font-size:12px;min-width:78px}
.route{font-family:ui-monospace,Menlo,monospace;font-weight:600}
.meta{margin-left:auto;color:var(--muted);font-size:12px;display:flex;gap:10px;align-items:center}
.empty{color:var(--muted);font-size:13px}
.bar{height:4px;border-radius:2px;background:var(--line);width:130px;overflow:hidden;margin-top:5px}
.bar>span{display:block;height:100%;background:var(--accent)}
footer{margin-top:26px;color:var(--muted);font-size:11px;text-align:center}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="dot"></div>
    <div>
      <h1>Win's VPN Smart Router - deterministic Winn v3 first</h1>
      <div class="sub">Winn v3 deterministic first &middot; local Gemma on distress &middot; bounded Google fallback</div>
    </div>
  </header>
  <div class="grid">
    <section class="card">
      <h2>Routing stats &middot; last 1h</h2>
      <div class="kv">
        <div class="item"><span class="label">Model</span><span class="value" id="s-model">-</span></div>
        <div class="item"><span class="label">Local Gemma</span><span class="value" id="s-gemini-status" style="font-size:13px">-</span></div>
        <div class="item"><span class="label">Decisions</span><span class="value" id="s-total">-</span></div>
        <div class="item"><span class="label">Avg latency</span><span class="value" id="s-avg">-</span></div>
        <div class="item"><span class="label">Max latency</span><span class="value" id="s-max">-</span></div>
        <div class="item"><span class="label">Last updated</span><span class="value" style="font-size:13px" id="s-updated">-</span></div>
      </div>
      <div style="margin-top:14px;display:flex;flex-wrap:wrap;gap:6px;align-items:center">
        <span class="badge gemini" id="s-gemini">local Gemma -</span>
        <span class="badge gemini" id="s-google">Google -</span>
        <span class="badge fallback" id="s-explicit">explicit -</span>
        <span class="badge fallback" id="s-fallback">fallback -</span>
        <span style="margin-left:auto" class="label">per-route selections</span>
      </div>
      <div class="chips" style="margin-top:8px" id="s-routes"></div>
    </section>
    <section class="card">
      <h2>Last decision</h2>
      <div class="empty" id="last-empty">No decisions yet. POST /route to begin.</div>
      <div id="last-body" style="display:none">
        <div class="kv">
          <div class="item"><span class="label">Route</span><span class="value" id="d-route"></span></div>
          <div class="item"><span class="label">Decision</span><span class="value" id="d-decision"></span></div>
          <div class="item"><span class="label">Confidence</span><span class="value" id="d-conf"></span><div class="bar"><span id="d-confbar"></span></div></div>
          <div class="item"><span class="label">Latency</span><span class="value" id="d-lat"></span></div>
          <div class="item"><span class="label">Model</span><span class="value" id="d-model"></span></div>
        </div>
        <div style="margin-top:16px">
          <div class="label" style="margin-bottom:6px">Reason codes</div>
          <div class="chips" id="d-codes"></div>
        </div>
      </div>
    </section>
    <section class="card">
      <h2>Decision timeline</h2>
      <ul class="timeline" id="timeline"><li class="empty">Waiting for decisions&hellip;</li></ul>
    </section>
  </div>
  <footer>Win's VPN &middot; XPRIZE demo &middot; AI Router lane &middot; GET /stats &middot; GET /decisions.csv</footer>
</div>
<script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const $ = id => document.getElementById(id);
function renderStats(health, stats){
  const local=health&&health.providers&&health.providers.local_gemma;
  $('s-model').textContent=(local&&local.model)||'-';
  $('s-updated').textContent=new Date().toLocaleTimeString();
  const gerr=local&&local.last_error;
  $('s-gemini-status').textContent=health
    ? (local&&local.ready ? 'vLLM ready' : (gerr ? 'error: '+gerr.kind : 'not ready'))
    : '-';
  if(!stats) return;
  $('s-total').textContent=stats.total+' ('+stats.all_time_total+' all)';
  $('s-avg').textContent=stats.latency_ms.avg+' ms';
  $('s-max').textContent=stats.latency_ms.max+' ms';
  $('s-gemini').textContent='local Gemma '+(stats.by_source.local_gemma||0);
  $('s-google').textContent='Google '+(stats.by_source.google_gemini||0);
  $('s-explicit').textContent='explicit '+(stats.by_source.explicit||0);
  $('s-fallback').textContent='fallback '+(stats.by_source.fallback||0);
  const routes=Object.entries(stats.per_route||{});
  $('s-routes').innerHTML=routes.length
    ? routes.map(([r,n])=>'<span class="chip">'+esc(r)+' &times;'+n+'</span>').join('')
    : '<span class="chip">no selections yet</span>';
}
function renderLast(d){
  document.getElementById('last-empty').style.display='none';
  document.getElementById('last-body').style.display='block';
  document.getElementById('d-route').textContent=d.decision.selected_route_id;
  document.getElementById('d-decision').innerHTML=
    '<span class="badge '+esc(d.decision.decision)+'">'+esc(d.decision.decision)+'</span> '+
    '<span class="badge '+esc(d.decision.source)+'">'+esc(d.decision.source)+'</span>';
  const conf=Math.round(d.decision.confidence*100);
  document.getElementById('d-conf').textContent=conf+'%';
  document.getElementById('d-confbar').style.width=conf+'%';
  document.getElementById('d-lat').textContent=Math.round(d.latency_ms)+' ms';
  document.getElementById('d-model').textContent=d.model||'';
  document.getElementById('d-codes').innerHTML=
    (d.decision.reason_codes||[]).map(c=>'<span class="chip">'+esc(c)+'</span>').join('')||'<span class="chip">none</span>';
}
function renderTimeline(items){
  const ul=document.getElementById('timeline');
  if(!items.length){ul.innerHTML='<li class="empty">Waiting for decisions&hellip;</li>';return}
  ul.innerHTML=items.map(d=>
    '<li><span class="t">'+esc(new Date(d.timestamp).toLocaleTimeString())+'</span>'+
    '<span class="route">'+esc(d.decision.selected_route_id)+'</span>'+
    '<span class="badge '+esc(d.decision.decision)+'">'+esc(d.decision.decision)+'</span>'+
    '<span class="meta"><span class="badge '+esc(d.decision.source)+'">'+esc(d.decision.source)+'</span>'+
    '<span>'+Math.round(d.decision.confidence*100)+'%</span><span>'+Math.round(d.latency_ms)+'ms</span></span></li>').join('');
}
async function refresh(){
  try{
    const [dr, sr, hr] = await Promise.all([
      fetch('/decisions',{cache:'no-store'}),
      fetch('/stats',{cache:'no-store'}),
      fetch('/health',{cache:'no-store'}),
    ]);
    const items=await dr.json();
    let stats=null, health=null;
    try{stats=await sr.json();}catch(e){}
    try{health=await hr.json();}catch(e){}
    renderStats(health, stats);
    if(items.length){renderLast(items[0]);}
    else{
      document.getElementById('last-empty').style.display='block';
      document.getElementById('last-body').style.display='none';
    }
    renderTimeline(items);
  }catch(e){}
}
refresh();
setInterval(refresh,2000);
</script>
</body>
</html>"""


@app.get("/", include_in_schema=False, response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    return HTMLResponse(DASHBOARD)
