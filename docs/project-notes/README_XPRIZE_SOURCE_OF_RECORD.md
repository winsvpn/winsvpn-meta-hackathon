# Win's VPN: Gemini Adaptive Routing for a Censorship-Resistant VPN

Built for the **Build with Gemini XPRIZE**. A Gemini model picks the VPN exit
route a user connects through, in the live connection path, with a
deterministic gate that can never block connectivity. Running today on Google
Cloud: Cloud Run for the AI router, Compute Engine for the staging control
plane and two Winn Protocol v3 demo gateways.

This repository is the readable source of record for all of it. Judges can open
the live endpoints below and cross-check the decision log against the evidence
pack; nothing here is a claim on a slide.

## 1. What this is

Win's VPN is a real product of a US 501(c)(3) nonprofit: a privacy and
anti-censorship VPN with a calculator camouflage mode, priced at $0.99/month,
because the people who need it can pay almost nothing. When a censor throttles
a tunnel, the connection does not die and wait for a human: a Gemini model
reads live probe data, decides in the connection path which exit route
survives, and moves the tunnel before the user notices.

The piece built in this hackathon window is the **adaptive censorship-resistance
layer**: the Gemini routing brain, the Cloud Run deployment, the staging control
plane twin, the winn/3 demo gateway network, and the rebuilt debug APK. The VPN
client app itself and the nonprofit predate the window and are disclosed
verbatim in section 6.

## 2. Architecture

```
Phone (Android debug build, winn/3 enabled, descriptor ring G1 pinned)
  -> staging hub (Compute Engine, Caddy TLS, FastAPI twin)
       serves /nodes + free-verify with protocol_version "winn/3"
  -> Gemini Router (Cloud Run, google-genai SDK, structured output)
       gemini-3-flash-preview, enum-constrained decisions, 2.0s deadline
  -> 2x winn3 gateways (Compute Engine, UDP/TCP 9111)
       demo-route-a us-central1 203.0.113.10, subnet 10.10.0.0/24
       demo-route-b us-east1    203.0.113.20,  subnet 10.11.0.0/24
```

One paragraph: the phone and the staging hub probe every candidate exit route
(handshake latency, packet loss, jitter, DNS health, recent failures, plus
transport signals). The hub forwards the probe snapshot to the Cloud Run
router. Gemini returns a structured decision constrained to the allowed route
ids, so it can never invent a server that does not exist. A deterministic gate
validates the answer; if Gemini is slow, wrong, or unreachable within the
deadline, the gate picks the best reachable route by fixed rules. The phone
switches tunnels to the winning route. The AI can improve routing; it can never
block connectivity.

Transport: **Winn Protocol v3** (standalone). A post-quantum hybrid of X25519
and ML-KEM-768, Ed25519-signed gateway descriptors carrying a compiled-in
verification ring and a fail-closed policy. No AWG, no Xray, no obfuscation on
this path: v3 ignores them by design. The descriptor signing key never enters
this repository; the repo holds only the scripts, the hub twin that serves the
finished envelopes verbatim, and the public node facts.

## 3. The decision flow (in code)

1. **Probe**: app and hub measure each candidate (`reachable`, `handshake_ms`,
   `packet_loss_pct`, `jitter_ms`, `dns_ok`, `recent_failures`) and network
   signals (`udp_ok`, `tcp443_ok`, `tls_ok`, `control_plane_ok`, `dns_ok`).
2. **Ask**: `POST /route` `{request_id, current_route_id, candidates, signals}`
   to the router.
3. **Decide**: Gemini structured decision
   `{selected_route_id, decision keep|switch, confidence, reason_codes[]}` with
   `selected_route_id` enum-constrained to `demo-route-a` / `demo-route-b`.
4. **Gate**: schema check, allowed-route check, reachability check, 2.0s
   deadline. Any failure means rule-based fallback (`source: "fallback"`,
   `DETERMINISTIC_FALLBACK`). Never blocks.
5. **Switch**: the phone tunnels to the selected route.

Every call is logged with its request id, the full input, the decision, the
source, and latency, to a JSONL audit log exposed at `GET /decisions`.

## 4. What's in this repository

```
README.md            this file
SPEC.md              the demo spec v2 (winn/3 transport; supersedes the dead AWG spec)
capture_evidence.sh  operator script that captures the demo-stage evidence pack
router/              Cloud Run Gemini router: decision service, deterministic gate,
                     decision log, dark dashboard, /hoppy/escalate, tests
staging-hub/         Compute Engine hub source: FastAPI /nodes + /free/verify serving
                     winn/3 config, Caddy TLS config, router client, tests
winn3-nodes/         winn3 gateway deploy assets: provision + deploy/verify scripts
dashboard/           mission-control dashboard (server.py + index.html + state.json)
```

### Live demo endpoints (SUPERVISOR RECEIPT 2026-08-17)

- **Gemini router (live)**: https://AI_ROUTER_HOST
  - `GET /` dark live decision dashboard, 2s refresh
  - `GET /decisions` last 50 decision records, most recent first
  - `GET /decisions.csv` same ring as CSV export
  - `GET /stats` aggregated stats over the last hour (by source, per route,
    per decision, latency)
  - `GET /health` `{ok, model, gemini_configured}`
  - `POST /route` route decision; `POST /hoppy/escalate` support escalation
- **Staging hub (live)**: https://<STAGING_HUB_SSLTIP_HOST>
  - `GET /nodes` node discovery envelope
  - `POST /free/verify` free login, returns `status: "authenticated"` +
    `vpn_config` (`protocol_version "winn/3"`, per-device `winn3_inner_v4` +
    `winn3_static_private`, the node's signed descriptor envelope verbatim)
  - `POST /admin/health` impairment trigger (`X-Demo-Key` header) that flips a
    route's reachability and increments `recent_failures`; the switch you watch
    in the demo
- **Gateway egress (live, verified)**: demo-route-a `203.0.113.10:9111`,
  demo-route-b `203.0.113.20:9111` (UDP/TCP)

### How to run the router locally (uvicorn)

```
cd router
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
GEMINI_MODEL=gemini-3-flash-preview uvicorn main:app --port 8080
```

Without `GEMINI_API_KEY` the router still runs in pure fallback mode
(`/health` reports `gemini_configured: false`), which is exactly the fail-open
behavior in production. The tests need no network and no key:

```
python3 -m pytest -q
```

### How the hub twin serves winn/3

`staging-hub/app.py` is a minimal FastAPI control plane the real Android debug
build can log into and connect through. On every free verify it serves the
`vpn_config` exactly as the client dispatch expects: `protocol_version "winn/3"`
with `protocol_params.carrier "winn3"`, a sticky per-device `winn3_inner_v4`
from the selected node's subnet, a per-device X25519 `winn3_static_private`, and
the node's signed descriptor envelope verbatim (the phone verifies the Ed25519
signature; the twin never re-encodes and never holds ceremony keys). With
`location: "auto"` it consults the Gemini router and enforces the selection,
falling back deterministically when the router is slow or unreachable. Every
field is documented line-by-line against the client source in
`staging-hub/FIELD_MAP.md`, and `staging-hub/tests/test_hub.py` machine-checks
that coverage against a live `/free/verify` response.

`staging-hub/nodes.json` is a redacted template: the `winn3_descriptor` payload
and signature are `TO_BE_SET`, and the AWG-compat public-key values are
redacted. The supervisor's signing ceremony lands real envelopes in
`descriptors/<slug>.json` (excluded here) at deploy time; until then the twin
serves `winn3_descriptor: {}` with a loud log and a named
`descriptor_reason`.

### Where the receipts live

The evidence pack captured per `evidence/EVIDENCE_CHECKLIST.md` accompanies the
submission: the decisions JSON (healthy keep `[STABLE_LINK, LATENCY_OPTIMIZED]`
and the impaired switch to `demo-route-b`), the Cloud Run / hub / gateway
console screenshots, the dashboard switch recording, phone screenshots, the
gateway handshake + inner ICMP + NAT egress receipts, the APK sha256, and the
secret-scan output. Live cross-checks are `GET /decisions` on the router URL
and `GET /admin/state` on the hub.

## 5. How to run the judge test

The full step-by-step is in the submission text: `evidence/SUBMISSION_DRAFT.md`
section **Testing instructions for judges**. In one breath: install the staging
debug APK (`org.winsvpn.app.debug`, v1.0.15, sha256
`106ec293342e84d0c67cbb5389a812babe564d9a5dabd0ff05788938e7a21867`), log in with
free account `9999-9999-9999` and any 4-digit PIN, connect through AI Route A,
verify the browser shows egress `203.0.113.10`, flip route A unreachable via
`POST /admin/health`, and watch the decision card and the phone flip to route B
(egress `203.0.113.20`) with reason codes, then cross-check the `request_id`
in `GET /decisions`. Nothing in the judge path touches production VPN
infrastructure.

## 6. Pre-existing work disclosure

Copied verbatim from `evidence/SUBMISSION_DRAFT.md`:

> We disclose exactly what predates the hackathon window and what was built for
> it.
>
> The VPN client and the nonprofit predate the window minimally, and they are
> disclosed. The client app (Flutter, the calculator camouflage, account and
> free-tier login, the Winn Protocol tunnel client) and the nonprofit business
> itself existed before the window. So did the Hoppy support framework (site
> chat widget and hub proxy).
>
> Built during the hackathon window for this submission: the entire Gemini
> adaptive routing layer, the Cloud Run deployment, and the v3 demo gateway
> network. Concretely: the Cloud Run Gemini router (structured-output decision
> service, deterministic gate, decision log and dashboard, /hoppy/escalate
> Gemini path), the Cloud Run deployment and its container image in Artifact
> Registry, the Google Cloud wiring (Secret Manager, Cloud Logging, project
> "Win's VPN XPRIZE"), the staging control-plane twin serving the winn/3
> protocol config on Compute Engine, the two winn3 gateway nodes with their
> signed descriptor ring, and the rebuilt debug APK carrying the freshly
> rebuilt winn engine (libwinnengine.so for three ABIs) pinned to descriptor
> ring G1. None of that existed before the window.

## 7. What is deliberately NOT in this repo

- **No private keys of any kind**: server, peer, signing, or SSH. The winn/3
  descriptor signing key (`g1.pem`) never enters this repo or any lane workdir;
  the repo holds only public node facts.
- **No admission keys**: the signed descriptor envelopes ride an
  `admission_secret` inside the payload, so the real descriptor files
  (`staging-hub/descriptors/*.json`) and the gateway admission keys
  (`winn3-nodes/keys/`) are excluded entirely. `staging-hub/nodes.json` ships as
  a redacted template.
- **No hub runtime state**: the hub's runtime `state.json` holds per-device
  `winn3_static_private` keys and sticky allocations; it is excluded. The twin
  regenerates it at runtime.
- **No `.env` files, service-account JSONs, gcloud configs, or Cloud Run deploy
  flags containing secrets.** The Gemini API key lives in Secret Manager; the
  router reads it from `GEMINI_API_KEY` at deploy.
- **No dead AWG artifacts**: AmneziaWG install/verify scripts and
  `awg_compat_public_key` values are stripped. The repo ships the current winn/3
  deploy assets only.
- **No working-tree directories**: `dashboard` here is the mission-control
  source; lane scratch dirs, `keys/`, `logs/`, `briefs/`, binaries, caches, and
  virtualenvs stay out.
- **The full VPN client source is NOT here.** The router, hub, nodes, and build
  script are this repo's judged content. The complete Win's VPN client
  application is a larger production codebase, available to judges on request
  through a separate private repo share (granted to the same judge emails via
  the Devpost discussion tab). The winn/3 engine source in `winn3-nodes/` is
  the same closed source; the deploy scripts reference it.

## 8. License

Proprietary. All rights reserved, Win's VPN Inc. and Win Empire LLC. Judges and
Devpost reviewers receive evaluation access for the duration of judging. No
open-source license is granted by sharing this repository.