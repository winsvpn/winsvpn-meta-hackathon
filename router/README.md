# Win's VPN Smart Router

This service implements the owner-approved routing decision order:

0. If the hub sends `explicit_route_id`, that candidate is returned immediately. Gemma and Google are not called.
1. Normal connection initiation uses the deterministic scorer immediately.
2. Distress routing uses local Gemma running on the `aicore` RTX 5060 Ti host.
3. Google Gemini API is a bounded secondary distress provider when local Gemma fails or is invalid.
4. Distress falls back to the deterministic scorer if both providers fail.

The earlier Gemini-only Cloud Run router did not satisfy this architecture. This directory now
contains the Smart Router orchestrator, and the hub has an authenticated advisory integration.
Live deployment proof remains separate work. AI output is advisory. Every selected route is checked against the exact
closed candidate set, reachability, and DNS eligibility before it can be returned. A hub-supplied
`explicit_route_id` bypasses both providers and the scorer only after the same reachability and DNS
eligibility checks pass.

The hub derives `distress` only from its machine-measured health record for the device's existing
node. A degraded, unreachable, probe-error, or nonzero external data-plane probe failure streak can
trigger the distress cascade. User prose never controls this field. A normal first connection and a
clean reconnect keep `connection_initiation`; an explicit route bypasses the advisory call entirely.

## Terse-JSON routing contract

Routing providers return only `selected_route_id`, `decision`, `confidence`, and one to three
short snake_case `reason_codes`. Local Gemma and Google both run at temperature 0 with a
128-token output ceiling. The service adds the trusted `source` field only after validating the
closed-set decision. Provider prose, Markdown fences, extra keys, a fourth reason code, malformed
confidence, or an unknown route fails provider validation and advances the bounded cascade. The
deterministic fallback emits the same terse response shape without using an AI provider.

This terse contract applies to routing decisions only. Hoppy support answers have a separate
bounded schema because the answer text is itself the deliverable.

`selected_route_id`, `current_route_id`, and `explicit_route_id` must be exact hub node slugs
from the closed candidate set (`^[a-z0-9][a-z0-9-]{1,39}$`). Endpoint-shaped values are rejected
before routing. Provider output is bound back to the matching candidate's `route_id` after closed-set,
reachability, DNS, and protocol checks.

## Integrations represented here

This directory is the repository Smart Router. Google's role is the bounded Gemini API
distress/support fallback, not a separate Google Cloud Network Connectivity Center or
Cloud Router product. The hub's HMAC advisory client lives outside `router/` and is
out of this lane. Live aicore deploy, hub HMAC wiring, and Gemini key issuance remain
owner-held configuration.

Hoppy is represented as `POST /hoppy/escalate`. That path uses local Gemma, then bounded
Google, then a canned docs answer. It is support text, not VPN route selection.

## Single canonical AICORE implementation

`router/` is the only AICORE router. The earlier root `edge_router.py`, its
bearer-authentication test, and the competing unit, drop-ins, and environment
template under `deploy/edge-router-aicore/` were removed on 2026-09-02. The
remaining files in that deployment directory describe only the supporting
vLLM, Cloudflare tunnel, and host-performance services.

An inbound `Authorization: Bearer` header is inert. Every protected path admits
a request only after the HMAC signature, timestamp window, durable nonce
admission, and per-source rate limit all pass. `EDGE_ROUTER_SECRET` survives
only as a compatibility alias for `SMART_ROUTER_HMAC_SECRET`; its value is an
HMAC key, never a bearer token.

`wins-edge-router.service` has one repository definition:
`router/wins-edge-router.service.example`. The canonical installer writes it
with one `ExecStart` for `main:app`, one environment file at
`/etc/winsvpn/router.env`, and no service drop-ins. `--verify-runtime` refuses
startup if the installed unit differs at those execution or environment
boundaries, or if a drop-in directory exists in `/etc`, `/run`, or `/usr/lib`.

The retired snapshot's `/v1` Cursor proxy and `/api/chat` shim were not ported.
Hoppy integrations use `/hoppy/escalate`. The legacy `signals` plus `rt_ms`
shape and optional route protocol fields were also retired; `/route` requires
the exact closed-set schema documented here.

## Security boundary

Protected endpoints require a replay-resistant server-to-server HMAC. No app contains this secret.
For each request, the hub sends:

- `X-Smart-Router-Timestamp`: current Unix time in seconds.
- `X-Smart-Router-Nonce`: a unique 16 to 64 character base64url-style value.
- `X-Smart-Router-Signature`: lowercase HMAC-SHA256 hex.

The signed bytes are:

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256_HEX_OF_EXACT_BODY
```

The server rejects stale timestamps, replayed nonces, bad signatures, oversized bodies, and
over-rate callers before routing. Logs contain a hash of the request ID plus bounded route-health
data. They never contain the HMAC secret, Google API key, request signature, or provider headers.
Support text is scrubbed for configured secrets and key-shaped material before it is sent to Google.

## Endpoints

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `POST` | `/route` | HMAC | Explicit node if supplied; deterministic for initiation; Gemma, Google, then deterministic for distress. |
| `POST` | `/hoppy/escalate` | HMAC | Local Gemma, then bounded Google, then a canned safe answer. |
| `GET` | `/health` | HMAC | Authentication and deterministic-routing readiness plus provider-specific diagnostics. Optional AI-provider failure does not make this endpoint unhealthy. |
| `GET` | `/decisions` | HMAC | Last 50 sanitized decisions. `?format=csv` returns CSV. |
| `GET` | `/decisions.csv` | HMAC | Sanitized decision CSV. |
| `GET` | `/stats` | HMAC | One-hour decision aggregates. |
| `GET` | `/` | HMAC | Operator dashboard. Its background requests require a trusted proxy that signs every upstream request. |
| `GET` | `/live` | Public | Process liveness only, with no provider diagnostics. |
| `GET` | `/ready` | Public | Deployable readiness: HMAC secret configured and replay journal path usable. Same terse `{ok, version}` shape as `/live`. Optional AI-provider failure does not make this endpoint unready. |

## Exact server-only environment

No model name is guessed. `SMART_ROUTER_GEMMA_MODEL` must be set to the exact served model ID
returned by aicore vLLM `/v1/models`. `/health` reports local model and model-ID validation as
provider diagnostics while its overall status remains tied to authentication and deterministic
routing readiness. The live topology is vLLM on loopback port 8002 and this edge router on port 8090. The current
Gemma 4 12B NVFP4 launch settings, including DFlash speculation and KV FP8, remain owned by the
`vllm-gemma4` systemd service rather than being duplicated in this application. The router unit only
weakly wants and orders after that provider. A failed or stopped vLLM unit does not stop the router or
block its Google and deterministic fallbacks.

Live verification on 2026-08-23 found the active safety override at 8 sequences and 4,096 batched
tokens with DFlash-16. The base unit's larger value is not the effective runtime configuration.
Any proposed increase, including 12 sequences, requires a measured no-restart and no-OOM acceptance
run before changing the safety override. The application-side concurrency default remains 8.

| Variable | Required/default | Meaning |
|---|---|---|
| `SMART_ROUTER_HMAC_SECRET` | Required, at least 32 characters | Hub-to-router signing secret. Server only. |
| `EDGE_ROUTER_SECRET` | Compatibility alias | Live-compatible alias for `SMART_ROUTER_HMAC_SECRET`. It is mandatory if the canonical name is absent. The old optional-auth behavior is not supported, and this value is never accepted as a bearer token. |
| `SMART_ROUTER_GEMMA_MODEL` | Required, no default | Reviewed local Gemma runtime identifier. |
| `EDGE_ROUTER_GEMMA_MODEL`, `LOCAL_LLM_MODEL`, `LOCAL_MODEL`, `GEMMA_MODEL` | Compatibility aliases | Checked in that order after the canonical model name. Live aicore currently uses `GEMMA_MODEL=gemma12b`. |
| `SMART_ROUTER_GEMMA_URL` | `http://127.0.0.1:8002` | vLLM loopback URL. Non-loopback URLs are rejected. |
| `EDGE_ROUTER_GEMMA_URL`, `LOCAL_LLM_URL`, `VLLM_URL` | Compatibility aliases | Checked in that order after the canonical URL. A live full endpoint such as `http://127.0.0.1:8002/v1/chat/completions` is normalized to the vLLM base so `/health` and `/v1/models` also work. |
| `SMART_ROUTER_VLLM_API_KEY`, `VLLM_API_KEY` | Optional | Loopback vLLM bearer credential. Server only. |
| `GEMINI_API_KEY` | Optional | Google fallback credential. Server only. |
| `GEMINI_MODEL` | Required when Google fallback is enabled | Reviewed Google model identifier. No default. |
| `SMART_ROUTER_TOTAL_BUDGET_MS` | `2000` | Entire provider-cascade budget. Range 250 to 5000. |
| `SMART_ROUTER_LOCAL_TIMEOUT_MS` | `900` application default, `850` deployment example | Local Gemma bound. Range 100 to 3000. |
| `SMART_ROUTER_GOOGLE_TIMEOUT_MS` | `900` application default, `850` deployment example | Google bound. Range 100 to 3000. |
| `SMART_ROUTER_QUEUE_TIMEOUT_MS` | `20` | Provider-capacity wait. Range 1 to 250. |
| `SMART_ROUTER_MAX_CONCURRENT_REQUESTS` | `8` | In-process provider cascade cap. Range 1 to 64. Read at startup. |
| `SMART_ROUTER_MAX_BODY_BYTES` | `32768` | Protected request-body limit. Range 4096 to 262144. |
| `SMART_ROUTER_RATE_LIMIT_REQUESTS` | `120` | Requests allowed per source address per window. |
| `SMART_ROUTER_RATE_WINDOW_SECONDS` | `60` | Rate-limit window. |
| `SMART_ROUTER_AUTH_WINDOW_SECONDS` | `30` | Maximum HMAC timestamp skew and replay-cache lifetime. |
| `SMART_ROUTER_NONCE_JOURNAL_PATH` | `/var/lib/winsvpn-router/replay-nonces.sqlite3` | Durable replay journal. The normalized absolute path, its 0700 parent, and its 0600 single-link database are enforced on every request. |
| `SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES` | `10000` | Maximum unexpired nonces. Admission fails closed when full. |
| `SMART_ROUTER_NONCE_JOURNAL_MAX_BYTES` | `16777216` | Maximum journal bytes. Admission fails closed when exceeded. |
| `SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS` | `2000` | Bounded SQLite lock wait before admission fails closed. |
| `DECISIONS_FILE` | `/tmp/router_decisions.jsonl` application default, `/var/lib/winsvpn-router/router-decisions.jsonl` in the service | Sanitized local decision log. Production keeps it inside the private systemd state directory. |

Keep `SMART_ROUTER_LOCAL_TIMEOUT_MS + SMART_ROUTER_GOOGLE_TIMEOUT_MS` below
`SMART_ROUTER_TOTAL_BUDGET_MS`. The total budget still wins if the individual settings are larger.

## Local run and offline tests

For local development only. Authenticated routes fail closed unless the HMAC secret is
set and the replay/decision parent directory exists as mode 0700 owned by the process
user. `.env.example` uses `/tmp/winsvpn-router-state` for that directory. Do not source
the example file in a shell until those values are filled; the installer never sources it.

```sh
python3.14 -m venv .venv
.venv/bin/python -I -m pip install --require-hashes --only-binary=:all: -r requirements.lock
mkdir -m 700 /tmp/winsvpn-router-state
.venv/bin/python -I -m uvicorn main:app --host 127.0.0.1 --port 8090 --no-access-log
```

The test suite uses provider doubles and performs no local vLLM, Google, Cloud Run, or other cloud call:

```sh
python3 -m pytest -q
```

## Audited aicore deployment

`install_aicore_router.sh` is the only supported bare-host producer. It never
downloads application source. Deploy first copies the complete declared source
closure through no-follow descriptors into a private root-owned staging
directory and re-executes that staged installer before preflight. The release
manifest and release ID bind the installer helper and canonical unit as well as
the modular runtime files. The immutable release is created under
`/opt/winsvpn-router/releases/`, provisions a Python 3.14.7 virtual environment,
and installs only hash-locked binary wheels from `requirements.lock`.
Application code and its virtual environment are root-owned. The service
continues to run as `aicore`.

Create `/etc/winsvpn/router.env` from `aicore.env.example`, set it to
`root:root` mode `0600`, and supply the real HMAC secret and exact served Gemma
model without placing either in an app, command line, or installer log. The
installer parses this file as data. It never sources it. Alias collisions,
unknown keys, missing required values, partial Google configuration, unsafe
permissions, and non-loopback vLLM URLs fail closed.

Run the read-only gate first:

```sh
sudo router/install_aicore_router.sh --preflight
```

Preflight validates Python 3.14.7, the `aicore` account, the complete source
closure, the hashed lock, the environment file, destination ancestry, required
commands, and that every TCP listener on port 8002 is bound only to
`127.0.0.1` or `::1`. It does not create a lock file, write a release, call
`daemon-reload`, enable a unit, or restart a process.

Only the explicit deploy mode mutates the host:

```sh
sudo router/install_aicore_router.sh --deploy
```

Deploy serializes concurrent writers, builds an inactive immutable release,
rechecks that the original source directory and every declared leaf retain the
descriptor-recorded preflight identity, and refuses a pathname or parent swap.
It installs the helper only from the verified release and independently checks
the installed helper digest, mode, ownership, link count, stable identity, and
root-controlled path ancestry before installing the unit or issuing any systemd
action. It then atomically replaces the unit and `current` symlink, enables, and
restarts the service. A failed build, systemd operation, active-state check, or
public `/live` and `/ready` check restores the prior helper, unit, symlink,
enablement, and service state. Re-running the same active release verifies it
and exits without a restart. If that exact release is installed but inactive,
deploy starts it and checks `/live` and `/ready` without mislabeling the inactive
state as ready.

Production deployment must keep the router on `aicore`, keep vLLM loopback-only, place TLS at the
hub-to-aicore boundary, and inject secrets through the server secret manager. Shipping apps receive
only final validated VPN configuration from the production hub.

The installed systemd unit declares `StateDirectory=winsvpn-router` and
`StateDirectoryMode=0700` while running as `User=aicore`. This creates the only writable replay
state directory with the owner and mode enforced by `security.py`. A unit that omits either line
will fail authenticated routing closed rather than silently reverting to process-memory replay
protection. The container image creates the same 0700 directory and runs as its dedicated
non-root `winsrouter` user.

`aicore.env.example` intentionally leaves secrets and the served model empty.
Obtain the exact model ID from the loopback vLLM `/v1/models` response, review
it, then write it to the root-only environment file before preflight.
