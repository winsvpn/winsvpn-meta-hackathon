# Win's VPN XPRIZE Staging Hub (Lane B)

Minimal FastAPI control plane that the real Win's VPN Android debug build
(pointing at it via `WINS_GATEWAY_BASE`) can log into and connect through.
Serves standalone Winn Protocol v3 configs only (owner ruling: NO AWG, NO Xray).

Serves the app-facing API exactly as the app source expects
(see LANE_REPORT.md and FIELD_MAP.md for the line-cited study):

- `GET /nodes` - node discovery envelope; automatically runs a real TCP probe
  pass against every gateway (`egress_ip:9111`) at most once per 30s
  (`PROBE_CACHE_S`), so a killed gateway flips `reachable`/`status` on its own
- `POST /free/verify` - free login (account `9999-9999-9999`, any 4-digit PIN
  is client-side only), returns `status: "authenticated"` + `vpn_config`
  (`protocol_version "winn/3"`, per-device `winn3_inner_v4` +
  `winn3_static_private`, the node's signed descriptor envelope verbatim,
  `node_slug`, `dns`, `mtu`)
- `GET /free/status` - login preflight

Admin/demo-trigger endpoints (header `X-Demo-Key`), all rate limited per
client IP (30 requests/min sliding window + 500/day, `ADMIN_RATE_LIMIT_PER_MIN`
/ `ADMIN_RATE_LIMIT_PER_DAY`; over the limit -> HTTP 429):

- `POST /admin/health` `{"slug": "...", "reachable": false}` - manual
  impairment trigger; flips reachability and increments `recent_failures`
- `GET /admin/state` - `uptime_s`, node health (reachability, `recent_failures`,
  `latency_ms`, `last_probe_ts`), sticky allocations, descriptor readiness,
  last 50 router decisions (no key material)
- `POST /admin/probe` - force a real TCP connect probe pass now (also resets
  the /nodes auto-probe cache window)
- `GET /health` - hub liveness

On every free verify with `location: "auto"` the hub asks the Gemini router
(`POST $ROUTER_URL/route`) for a selection and ENFORCES it: unknown or
unreachable router picks are overridden with a deterministic first-reachable
fallback; router unreachable/slow/malformed -> deterministic pick (fail open,
never blocks login). The consult HTTP timeout is 12s (Gemini's minimum API
deadline is 10s; real decisions return in ~4s). No peers are pushed anywhere:
winn/3 admission flows through the signed descriptor's `admission_key` plus
per-device X25519 static keys, so there is no SSH/paramiko in this twin.

## Env vars

| var | default | meaning |
|---|---|---|
| `ROUTER_URL` | (unset: router never consulted) | Gemini router base URL |
| `SMART_ROUTER_HMAC_SECRET` | (unset; `EDGE_ROUTER_SECRET` is also accepted) | the router's HMAC secret (>= 32 chars), from the environment; required to consult the authenticated router, otherwise the router is never called and the deterministic pick is served |
| `NODES_FILE` | `./nodes.json` | node inventory (template with `TO_BE_SET`) |
| `STATE_FILE` | `./state.json` | runtime state (health, sticky IPs, key material, decisions) |
| `DESCRIPTORS_DIR` | `./descriptors` | supervisor ceremony envelopes, one `<slug>.json` per node |
| `DEMO_KEY` | (required: >= 16 chars, no default; hub refuses to start without it) | `X-Demo-Key` for /admin/* |
| `ROUTER_TIMEOUT_S` | `12.0` | router consult deadline |
| `PROBE_TIMEOUT_S` | `3.0` | TCP connect timeout per gateway probe |
| `PROBE_CACHE_S` | `30.0` | min seconds between automatic /nodes probe passes |
| `VPN_DNS` | `1.1.1.1,1.0.0.1` | `dns` served in vpn_config (SPEC v2 pin) |
| `ADMIN_RATE_LIMIT_PER_MIN` | `30` | per-client /admin requests per 60s before 429 |
| `ADMIN_RATE_LIMIT_PER_DAY` | `500` | absolute per-client /admin request cap per day |
| `VPN_MTU` | `1280` | `mtu` served (inert; datapath uses `winn3_path_mtu`) |
| `WINN3_PATH_MTU` | `1450` | `winn3_path_mtu` plan field |
| `WINN3_CARRIER_CLASSES` | `udp` | `winn3_carrier_classes` plan field |

## Run locally

```
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8080 --no-access-log
```

(`--no-access-log` keeps client IPs out of uvicorn's request log; set `DEMO_KEY`
to a >= 16 char secret or the hub refuses to start.)

Tests (router mocked; descriptor envelopes generated in fixtures):

```
python3 -m pytest -q
```

## Deploy (supervisor)

Built behind Caddy (TLS via the `sslip.io` hostname); Caddy proxies 443 to the
container's 8080:

```
docker build -t wins-staging-hub -f staging-hub/Dockerfile .
docker run -d --name wins-staging-hub \
  -p 8443:8080 \
  -e ROUTER_URL=https://<router-cloud-run-url> \
  -e DEMO_KEY=<key> \
  -e DESCRIPTORS_DIR=/srv/hub/descriptors \
  -e NODES_FILE=/srv/hub/nodes.json \
  -e STATE_FILE=/srv/hub/state.json \
  -v /srv/wins-hub:/srv/hub \
  wins-staging-hub
```

`STATE_FILE` points at a path inside the `/srv/wins-hub:/srv/hub` bind mount so
runtime state (health, sticky IPs, key material, decisions) survives container
restarts and deploys. The env var is honored with its default unchanged
(`./state.json`); the supervisor only has to add the `-e STATE_FILE` + volume
lines above. Keep descriptors/nodes read-only by convention: the twin never
writes them.

The supervisor's signing ceremony lands `descriptors/demo-route-a.json` and
`descriptors/demo-route-b.json` (payload/sig envelopes, private key never in
this lane). Until they land, the twin serves `winn3_descriptor: {}` with a
loud log and a `demo_provisioning.descriptor_reason` (the client refuses by
name, so the demo needs the files before login). A landed file that fails the
identity-binding checks (format v3, node slug, lifetime) is served as `{}`
too, never silently swapped for the placeholder.

Never point this hub (or its tests) at production Win's VPN domains; it only
calls the staging router and staging nodes.
