# Lane A Report - Gemini Adaptive Router

> Historical Gemini-only Cloud Run lane report. It is superseded by `README.md` and the
> current `main.py` Smart Router contract: deterministic Winn v3 first, local aicore vLLM
> Gemma on distress, then Google Gemini API, then deterministic fallback. Hoppy is a
> separate `/hoppy/escalate` support path. Do not use this report as current deployment
> or readiness evidence.

## What was built

FastAPI service: the AI routing brain of Win's VPN. Gemini picks a route from
the closed set the caller supplies; a deterministic scorer enforces the
allowed set and takes over on any failure. Routing never blocks connectivity.

## Resume pass (2026-08-17, 16:05 UTC)

- **Live status verified**: `/favicon.ico`, `/stats`, `/decisions.csv` now
  return 200 on the deployed URL (the earlier 404 blocker is gone; the
  supervisor redeployed). `receipts/prod_sanity.txt` refreshed: 10/10
  `POST /route` -> 200, all new endpoints 200.
- **Live Gemini regression observed**: every `/route` post this run returned
  `source=fallback` (0 gemini out of 15+ posts; the old `/stats` gemini count
  is stale). Returns are instant (~0.4s), not 12s timeouts, so the Gemini call
  errors immediately on the deployed revision. Suspects: `GEMINI_API_KEY` /
  `GEMINI_MODEL` env not propagated to the new revision, or Gemini API
  degradation. Requires the supervisor to check the revision env and Cloud Run
  logs (owner-required). The new `/health` diagnostic makes this visible on
  the next deploy.
- **Reproducible build**: `requirements.txt` pinned to the versions proven in
  the lane `.venv` (`fastapi==0.141.1`, `uvicorn==0.52.3`,
  `google-genai==2.18.1`, `pydantic==2.13.4`, `pytest==9.1.1`,
  `httpx2==2.10.0`). Each was cross-checked as current latest on PyPI; pinning
  makes the deploy auditable.
- **Ops self-diagnosis**: `main.py` now records a sanitized `gemini_error`
  (API-key/token redaction, 200-char cap) per decision (ring + JSONL) and
  exposes it as `/health.gemini_last_error`. `/health` also reports
  `version 1.1.0` and `deps` (google-genai, fastapi, uvicorn, pydantic,
  starlette, httpx2) so the deployed artifact is verifiable. The dashboard
  Routing stats card gained a Gemini status line (configured / error: kind /
  no key).
- **Artifact validated locally**: `docker build` succeeds with the pinned
  versions; the container was run on :8080 and every endpoint smoke-tested
  (health, dashboard, favicon, stats, `/route` deterministic fallback,
  `/decisions`, `/decisions.csv`, `/hoppy/escalate` docs fallback). The
  no-key `gemini_error` surfaced correctly. Image removed after the test.
- **Tests**: 26 green (19 prior + 7 new: health diagnostics, error recorded +
  sanitized, error clears on success, `/stats` 1h-window filtering, CSV comma
  quoting, malformed JSON -> 422, JSONL parent-dir creation).

## Ops pass (2026-08-17)

Live-ops hardening for the demo video and the submission evidence pack:

- **`GET /favicon.ico`** - inline SVG response (`image/svg+xml`), no more 404
  in the demo capture; dashboard now links it via `<link rel="icon">`.
- **`GET /stats`** - 1h-window aggregates from the in-memory ring:
  `total`, `by_source {gemini, fallback}`, `latency_ms {avg, max}`,
  `per_route` selection counts, `per_decision`, `all_time_total`,
  `window_start/end`, `generated_at`.
- **`GET /decisions.csv`** - streams the full decision ring as CSV
  (columns `timestamp,request_id,current,selected,decision,source,confidence,reason_codes,latency_ms`)
  with `Content-Disposition: attachment`. One-URL evidence export for the
  submission pack. Same output available as `GET /decisions?format=csv`.
- **Dashboard polish** - title "Win's VPN AI Router - Gemini adaptive
  routing"; new Routing stats card (model id from `/health`, gemini/fallback
  badge counts, avg/max latency, per-route selection chips, last-updated
  timestamp); still dark theme, single file, zero external assets, polls
  `/decisions` + `/stats` + `/health` every 2s.

## Files

- `schemas.py` - pydantic models: `Candidate`, `Signals`, `RouteRequest`, `RouteDecision`
- `gemini_client.py` - google-genai SDK client (`from google import genai`). Key from `GEMINI_API_KEY`, model from `GEMINI_MODEL` (default `gemini-2.5-flash`). Structured output via `response_schema=RouteDecision` minus `source`. Budget: SDK-level `HttpOptions(timeout=10000)` (ms) plus an `asyncio.wait_for(12.0)` wrapper in `main.py`. Prompt frames censorship-resilience priorities (connect > interference pattern > alternate available > healthiest > latency) and embeds the caller's candidate and signal JSON verbatim. Timeout / error / malformed / out-of-set selection all raise so fallback engages.
- `fallback.py` - deterministic scorer: signal bonuses (udp 100, tcp443 50, tls 30, dns 20) minus penalties (10x recent failures, latency/10 capped at 500, loss/2, jitter/10). Reachable candidates only; current route preferred on ties within 5%. All-unreachable degrades to best-effort with `decision=switch`. Returns `source=fallback`, `reason_codes=["deterministic_fallback"]`.
- `main.py` - `POST /route` (validates, calls Gemini with allowed set = candidate route_ids, verifies pick is in-set AND reachable, annotates `source`, appends full record {timestamp, model, request, decision, latency_ms, gemini_error} to an in-memory ring of 500 and JSONL at `DECISIONS_FILE`, default `/tmp/router_decisions.jsonl`); `GET /decisions` (last 50, reversed; `?format=csv` streams the ring); `GET /decisions.csv` (streaming CSV export); `GET /stats` (1h-window aggregates); `GET /favicon.ico` (inline SVG); `POST /hoppy/escalate` (short AI answer, docs-page fallback answer on failure); `GET /health` (`ok, model, gemini_configured, gemini_last_error` (sanitized), `version`, `deps`); `GET /` dark single-file dashboard (no external assets, polls `/decisions` + `/stats` + `/health` every 2s, Gemini status line).
- `tests/test_router.py` - 26 tests, Gemini fully mocked, no network, no key.
- `requirements.txt`, `Dockerfile` (python:3.12-slim, port 8080, uvicorn), `README.md`.

## Test results

```
$ .venv/bin/python -m pytest -q
..........................                                                      [100%]
26 passed, 2 warnings in 2.95s
```

Warnings are upstream deprecation notices (starlette testclient on Python 3.14,
google-genai types), not failures. Covers all 7 required cases plus extras:
out-of-set -> fallback, gemini raises -> fallback, timeout -> fallback, all
unreachable -> best-effort switch, hoppy failure -> docs fallback, decisions
JSONL written + `/decisions` reversed order + endpoint name exactly
`/decisions`, ring caps at 50 for the API, health, dashboard, input
validation (422), plus the ops-pass coverage: favicon SVG, `/stats`
aggregates (populated and empty), `/decisions.csv` streaming with exact
column order, `?format=csv` equivalence, dashboard polish markers, and the
resume-pass coverage: health diagnostics (version/deps/gemini_last_error),
gemini_error recorded + sanitized (fake key redacted from JSONL too), error
clears on next success, `/stats` 1h-window filtering, CSV comma quoting,
malformed JSON -> 422, JSONL parent-dir creation.

## Smoke test (live uvicorn, since killed)

With no `GEMINI_API_KEY`: `/health` -> `{"ok":true,"model":"gemini-2.5-flash","gemini_configured":false}`;
`POST /route` -> instant deterministic `demo-route-b` switch decision;
`/hoppy/escalate` -> docs-page fallback answer; `/decisions` -> full audit
record; `/` -> dashboard 200 with correct title. Server was started briefly
and killed per constraints.

## How to run

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
GEMINI_API_KEY=... .venv/bin/uvicorn main:app --port 8080
```

Tests: `python3 -m pytest -q` (or `.venv/bin/python3 -m pytest -q`).

Deploy: supervisor deploys to Cloud Run from the Dockerfile; this lane does
not run gcloud.

## Caveats

- Without `GEMINI_API_KEY` the service still runs, in pure fallback mode; `/health` reports `gemini_configured: false`.
- The fallback `dns_ok` score term uses `signals.dns_ok` (global path capability); per-candidate `dns_ok` participates via the reachability/DNS gating in the Gemini prompt and is validated in `main.py`'s reachability check.
- Decision ring is in-memory (lost on restart); the JSONL file is the durable audit trail. `/decisions`, `/stats`, and `/decisions.csv` read the ring, so their contents reset on instance restart; the JSONL is the archival source.
- `/hoppy/escalate` fallback names the live support page at `https://www.winsvpn.org/support/` through `HOPPY_DOCS_PAGE` in `main.py`.
- The Gemini deadline is bounded by the SDK HTTP timeout (`DEADLINE_MS=10000` in `gemini_client.py`) plus `asyncio.wait_for(ROUTING_BUDGET_S=12.0)` in `main.py`; worst case is fallback engaging at the bound. Live `/route` measures ~4-5s against gemini-3-flash-preview when it works; currently every live call falls back instantly (see Resume pass), so the supervisor must verify the revision's `GEMINI_API_KEY`/`GEMINI_MODEL` and check logs.
- `GET /stats` window is the last 1h (UTC), computed at request time.
- The deployed image must be rebuilt from the updated Dockerfile to pick up the pinned `requirements.txt` and the `/health` diagnostics. The live instance still runs the pre-diagnostics build.
