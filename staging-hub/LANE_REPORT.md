# Lane B Report: Staging Hub Twin (winn/3 standalone)

Date: 2026-08-17. Directory: `/Users/owner/xprize/staging-hub`. All work
confined to this directory; the reference tree
(`/Users/owner/Documents/wins/source/wins_vpn/`) was read-only.

This revision supersedes the AWG-era report: owner ruling made the demo
transport standalone Winn Protocol v3 (SPEC v2), so the twin no longer serves
AWG fields and no longer pushes peers over SSH.

## 1. Endpoint study table (path -> source lines)

Reference: `.../lib/{main.dart,gateway_failover.dart}` (READ-ONLY). Stands
from the pre-pivot pass; free-verify flow unchanged.

| Contract item | Path / key | Authoritative source lines |
|---|---|---|
| Free verify path | `POST /free/verify` | gateway_failover.dart:292-297 (`freeVerifyGateways`); sent main.dart:10049-10056 & :10067-10076 |
| Node discovery | `GET /nodes` | gateway_failover.dart:264-269 (`nodeDiscoveryUrls`); fetched main.dart:7561-7591 |
| Free status preflight | `GET /free/status?platform=android` | gateway_failover.dart:299-304; preflight main.dart:1472-1498 |
| Success predicate | HTTP 200 + JSON `status == "authenticated"` | main.dart:1250-1257 (`_postAuthenticatedRace`) |
| `/nodes` envelope | `nodes[]`, `free_access{node_slugs,enabled}`, `maintenance`, `min_supported_app_version`, `app_update_url`, `double_vpn_available`, `announcement` | main.dart:8279-8369 (`_parseNodesResponse`) |
| Per-node fields | `name, flag, slug, status, endpoint, free_access_enabled, direct_awg_enabled, protocol_version, reachable, transports, regional_aliases, latency_ms` | main.dart:4031-4069 (`_normalizeNodeItem`) |
| Verify response keys | `status, vpn_config, selected_node{slug,name,flag,status}, expiration_date, device_auth_token, announcement` | main.dart:10107-10203 (`_onAuthSuccess`), :4609-4632 (`_applySelectedNodeFromAuth`) |
| Free login account | `9999-9999-9999` (PIN is client-side only) | main.dart:762 |

## 2. winn/3 serving contract (extracted, not invented)

The full machine-checked field table with per-field source citations lives in
`FIELD_MAP.md`; `tests/test_hub.py::test_field_map_coverage` asserts every
`required` row appears with the exact client expectation and every
`forbidden` row is absent. Summary of what the twin serves on
`POST /free/verify`:

- `protocol_version: "winn/3"` + `protocol_params: {"carrier": "winn3"}`
  (client protocol gate winn_protocol_dispatch.dart:2106-2120, :2183-2191;
  the twin speaks nothing else).
- `winn3_inner_v4`: sticky per (device_id, node slug), allocated lazily from
  the selected node's subnet starting at `.2`; the descriptor's
  `inner_router_v4`/`inner_resolver_v4` (`.1`) are reserved so a device can
  never collide with its next hop (dispatch:2538-2545 refuses equality).
- `winn3_static_private`: X25519 raw-32-bytes base64, minted once per device
  (openssl path mirrors ONETOUCH:11686-11740, unwrap at :11674-11683;
  urandom fallback when openssl is absent), sticky for the device's life,
  never logged or echoed in admin surfaces.
- `winn3_descriptor`: the signed envelope `{"payload", "sig"}` served
  byte-verbatim from `DESCRIPTORS_DIR/<slug>.json` (supervisor ceremony) with
  nodes.json as placeholder until those land. Twin is shape-only by design
  (no ceremony keys in this lane): bounded base64, 4096-byte ceiling, UTF-8
  JSON object, `v==3`, `node==slug`, sane non-expired lifetime
  (dispatch:1716-1878, :1826-1843; ONETOUCH:10474-10513). A bad landed file
  fails closed to `{}` with a loud log and a named
  `demo_provisioning.descriptor_reason`, never a fabricated envelope.
- `node_slug`, `dns "1.1.1.1,1.0.0.1"` (SPEC v2 pin; app splits the list at
  main.dart:4811-4822), `mtu 1280` (inert-but-present exactly as the real hub
  serves it, ONETOUCH:18199; datapath sizes from `winn3_path_mtu`),
  `winn3_path_mtu "1450"`, `winn3_carrier_classes "udp"` (plan fields,
  ONETOUCH:9254, :9768).
- FORBIDDEN (asserted absent): `server_public_key`, `server_endpoint`,
  `client_ip`, `obfuscation`, `stealth_active`, `xray`, `preshared_key`,
  `client_private_key` (pivot ruling; dispatch:2150-2158, :2193-2209,
  :2487-2499, :2561-2569, :2651-2656).
- No SSH/paramiko anywhere: winn/3 admission rides the descriptor's
  `admission_key` + device static keys, not runtime peer pushes.

## 3. Files

- `app.py` - FastAPI control plane: `GET /nodes`, `POST /free/verify`,
  `GET /free/status`, `GET /health`, admin (`/admin/health`, `/admin/state`,
  `/admin/probe` behind `X-Demo-Key`). Real TCP connect probes (3s timeout)
  run automatically on `/nodes` at most every 30s (`PROBE_CACHE_S`) and record
  `latency_ms`/`last_probe_ts`; a failed probe flips the node unreachable and
  increments `recent_failures` (so a real gateway kill reaches the router), a
  successful probe recovers it. Router consult with 12s deadline
  (SUPERVISOR_NOTES.md: Gemini min deadline 10s, real ~4s), sticky
  per-device inner_v4 + static material persisted in `STATE_FILE`
  (env-honored, default `./state.json`), descriptor serving with
  identity-binding shape checks.
- `nodes.json` - inventory per SPEC v2 (egress IPs, subnets 10.10/10.11.0.0/24,
  gateway_ids demo-gw-a/b, port 9111); `winn3_descriptor` placeholder
  `{"payload":"TO_BE_SET","sig":"TO_BE_SET"}` until ceremony files land.
- `FIELD_MAP.md` - field-by-field extraction table (this lane's deliverable).
- `tests/test_hub.py` - 15 tests, router mocked, envelopes generated in
  fixtures.
- `Dockerfile`, `requirements.txt`, `README.md` (deploy + env reference),
  `PROGRESS.json`, `CONTINUE.md`.

## 4. Selection + routing behavior

- Explicit reachable slug -> served as-is (`selection_source: "explicit"`).
- Explicit unreachable/unknown slug -> other reachable node served with
  `selected_node` set (graceful, still authenticated): 409/503 + detail is a
  TERMINAL login failure (gateway_failover.dart:29-52), so an error response
  would abort the demo login.
- auto -> `POST $ROUTER_URL/route` with candidates from live health
  (`reachable`, `handshake_ms` = cached TCP:9111 probe else deterministic
  synthetic 40/55ms, `packet_loss_pct`, `jitter_ms`, `dns_ok`,
  `recent_failures`) and `current_route_id` = device's sticky node. Router
  pick ENFORCED; unknown/unreachable pick -> deterministic first-reachable.
  Router unreachable/slow/malformed -> deterministic pick, still
  authenticated (fail open, never blocks connectivity).
- All nodes down -> 503 `{"detail": "not online"}` (app classifies as
  `offline` terminal) and `/free/status` serves `unavailable` so the
  preflight matches.
- `/admin/health {slug, reachable:false}` flips health AND increments
  `recent_failures` (manual demo impairment trigger); `/nodes` reflects it
  immediately and the router payload carries the counter.
- Real gateway probes: `socket.create_connection` to each node's
  `egress_ip:9111` with a 3s timeout. The probe pass runs automatically on
  `/nodes` fetch at most every 30s (cached between passes) and on demand via
  `/admin/probe`; each pass records `latency_ms`/`last_probe_ts`. A failed
  probe marks the node unreachable and increments `recent_failures`, so killing
  the gateway flips the demo health WITHOUT the manual flip; a successful probe
  restores a down node and clears its failures. This is additive to the admin
  flip, and both paths feed the router payload.
- Live-router verification (2026-08-17): POST /route returns gemini
  decisions in ~3.0-3.5s with `source: "gemini"`; /health and /decisions OK.

## 5. Test summary

`python3 -m pytest -q` -> **20 passed** (fresh venv). The 8 required cases
plus the new probe/state pass:

1. FIELD_MAP coverage: every required winn/3 field present with exact client
   expectation, forbidden set absent (pinned + parsed from FIELD_MAP.md).
2. auto consults router + honors selection + payload shape.
3. router down -> deterministic pick, still authenticated.
4. explicit slug honored (plus graceful fallback for unreachable explicit).
5. sticky inner_v4 per device per node subnet + sticky per-device static key.
6. descriptor selection follows node (route-a device gets route-a descriptor,
   served verbatim from its landed file; missing/wrong-node files fail closed
   with reasons).
7. /nodes envelope unchanged from the AWG era (app parser contract).
8. health flip -> /nodes offline + router candidate `recent_failures >= 1`.

New probe/state cases (mocked sockets, no real network):

9. probe failure (socket raises OSError) -> `/admin/probe` reports
   `latency_ms: null`, node `reachable:false` + `status:"offline"` in /nodes,
   `recent_failures` incremented, `last_probe_ts` set.
10. probe success records `latency_ms >= 1` and leaves the node reachable.
11. probe success RECOVERS a node the admin had flipped down (failures cleared).
12. `/nodes` auto-probes at most once per `PROBE_CACHE_S` window (calls counted
    through the mocked socket; forcing the window re-probes all nodes).
13. `/admin/state` exposes `uptime_s` plus per-node `latency_ms`/`last_probe_ts`.

Guardrails retained: admin 401 on bad key, admin state hides private
material, missing device_id 400, free/status + 503 when all down, inner pool
exhaustion vs gateway reservation (/30 -> second device 503s).

## 6. Deploy notes

- `docker build -t wins-staging-hub .`; run with `-p 8443:8080`,
  `ROUTER_URL`, `DEMO_KEY`, `DESCRIPTORS_DIR` mounted read-only, writable
  `STATE_FILE` volume (`-e STATE_FILE=/srv/hub/state.json` with `/srv/wins-hub`
  bind-mounted at `/srv/hub`; README has the full command). Caddy (supervisor)
  terminates TLS on the sslip.io hostname and proxies to 8080.
- App debug build needs `WINS_GATEWAY_BASE`/`WINS_GATEWAY_BASES` =
  `https://<STAGING_HUB_SSLTIP_HOST>`, `WINS_HUB_HOST` = hostname only, plus the
  SPEC v2 winn3 defines (WINS_WINN3_ENABLED_PLATFORMS=android,
  WINS_WINN3_DESCRIPTOR_PUBKEY_G1, WINS_WINN3_DESCRIPTOR_RING_SHA256).
- Before demo: supervisor lands `descriptors/demo-route-a.json` +
  `demo-route-b.json` (signing ceremony private key never enters this lane).
  Without them the twin logs loudly and serves `winn3_descriptor: {}`
  (client refuses by name `winn3DescriptorUnverified`), so the files are the
  last dependency for a working login.
- Proven prior art for the carry demo: the 2026-08-11 physical carry run doc
  (same handset, debug APK + packaged engine + gateway serve mode).

## 7. Caveats

- The twin serves `dns "1.1.1.1,1.0.0.1"` verbatim per SPEC v2. The v1-era
  single-IP warning no longer applies: the AWG-era validator caveat was about
  `_hasUsableVpnConfig` on the old path; the v3 tunnel consumes dns from
  `_nativeTunnelDnsServers` (main.dart:4811-4822) which splits the list.
- `mtu` 1280 is inert (the v3 datapath ignores it and sizes from
  `winn3_path_mtu`); both are served because the real hub serves both
  (ONETOUCH:18199, plan fields at :18044-18052).
- Descriptor signature verification is intentionally NOT performed by the
  twin (no ceremony keys in this lane; the phone verifies Ed25519 over
  DOMAIN||0x00||payload). The twin's checks only bind the descriptor to the
  node's identity and clock; that is the documented fail-closed surface.
- The app always keeps compiled production gateways as fallback candidates
  after ours; app-side behavior, cannot be disabled from the hub. The hub
  itself never contacts production domains (only the staging router, verified
  live this run).
- Router candidates use cached `latency_ms` from the last probe pass when one
  has run, else deterministic synthetic 40/55ms, so the demo story stays stable
  between 30s probe cycles; `POST /admin/probe` forces a real probe pass now
  and `/nodes` auto-probes at most every 30s. Nodes with no real egress
  (`TO_BE_SET`) always report `latency_ms: null` and never probe.
