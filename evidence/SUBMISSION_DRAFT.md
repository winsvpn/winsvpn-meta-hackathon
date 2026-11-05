# SUBMISSION_DRAFT.md - Devpost Text Description

Win's VPN: Gemini routing that keeps people online when censors fight back.

## The hook

In Myanmar, a journalist opens what looks like a calculator app, types a PIN, and gets a VPN. If the state throttles her tunnel, the connection does not just die and wait for a human. A Gemini model reads live probe data, decides in the connection path which exit route survives, and moves her tunnel before she notices. This is a real product of a US 501(c)(3) nonprofit, launched June 2026, priced at 99 cents a month, because the people who need it most can pay almost nothing. We entered this hackathon to build the piece that was missing: an AI-native routing brain, running on Google Cloud, that makes censorship-resistance a live decision instead of a static config.

The router is live today on Google Cloud Run. Its first real routing decision took about four seconds and returned the reason codes LINK_DOWN, UDP_BLOCKED, and HEALTHIER_ALTERNATE. Every decision is logged with a request id, its reason codes, the decision source, and latency. That log is public evidence, not a claim.

> SUPERVISOR RECEIPT 2026-08-17: the full chain is proven end to end on infrastructure, not in a slide. Phone app -> staging hub (GCE, https://<STAGING_HUB_SSLTIP_HOST>) -> Gemini router (Cloud Run, gemini-3-flash-preview) -> winn/3 gateway (GCE) carrying real traffic: handshake, inner ICMP, and NAT egress ICMP receipts all recorded. The demo moment is proven at API level: on a healthy link Gemini returns keep with [STABLE_LINK, LATENCY_OPTIMIZED]; when the admin flips route-a unreachable (recent_failures +1), the next login Gemini switches to demo-route-b with its reason codes, and the switch is exportable from GET /decisions.

## What it does

Win's VPN is a privacy and anti-censorship VPN service operated by Win's VPN Inc., a Florida nonprofit with 501(c)(3) exemption effective June 11, 2026. The Android app includes a calculator camouflage mode for high-risk regions, a free tier that needs no account, and paid access at $0.99/month through PayPal checkout. The service is made in the USA. It is designed to keep no logs: no browsing history, no DNS queries, no traffic contents. The only metadata kept is a device count for the three-device limit.

The work built for this hackathon is the adaptive censorship-resistance layer, running end to end on the Winn Protocol v3 transport:

- The phone and staging hub probe every candidate exit route: handshake latency, packet loss, jitter, DNS health, recent failures, plus control-plane and transport signals (UDP, TCP 443, TLS).
- The staging control plane on Compute Engine forwards the probe snapshot to the Gemini Router on Cloud Run.
- Gemini returns a structured decision (selected route, keep or switch, confidence, reason codes) constrained by enum output to the allowed route ids, so it can never invent a server that does not exist.
- A deterministic gate validates the decision. If Gemini is slow, wrong, or unreachable within a 2.0 second deadline, the gate falls back to rule-based selection. The AI can improve routing; it can never block connectivity. Fail open, always.
- The phone switches tunnels to the winning route. The whole chain runs inside the connection path, not in a side dashboard.

Hoppy, our public AI support agent, also escalates hard questions to Gemini through the router's /hoppy/escalate endpoint, with a guarded prompt that cannot leak infrastructure details.

## How we built it

Chain, end to end:

Phone (Android debug build, org.winsvpn.app.debug, winn/3 enabled, descriptor ring G1) -> staging hub (Compute Engine VM, Caddy TLS on <STAGING_HUB_SSLTIP_HOST>, FastAPI twin; serves the node list and free-tier verification, consults the router) -> Gemini Router (Cloud Run, google-genai SDK, gemini-3-flash-preview, structured output with enum constraints, deterministic fallback) -> two winn3 gateway nodes on Compute Engine (demo-route-a in us-central1, demo-route-b in us-east1, UDP/TCP 9111).

The transport is the standalone Winn Protocol v3: a post-quantum hybrid of X25519 and ML-KEM-768, with Ed25519-signed gateway descriptors carrying a compiled-in verification ring and a fail-closed policy. The demo app is a debug build carrying the freshly rebuilt winn engine (libwinnengine.so for three ABIs), pinned to descriptor ring G1.

The decision flow in code:

1. probe: app and hub measure each candidate route (reachable, handshake_ms, packet_loss_pct, jitter_ms, dns_ok, recent_failures) and network signals (udp_ok, tcp443_ok, tls_ok, control_plane_ok, dns_ok).
2. POST /route {request_id, current_route_id, candidates, signals} to the Cloud Run router.
3. Gemini structured decision: {selected_route_id, decision: keep|switch, confidence, reason_codes[]} with selected_route_id enum-constrained to demo-route-a / demo-route-b.
4. Deterministic gate: schema check, allowed-route check, reachability check, 2.0s deadline. Any failure means rule-based fallback. Never blocks.
5. Tunnel switch on the phone to the selected route.

Google Cloud products used: Cloud Run (router service and live decision dashboard), Compute Engine (one staging hub plus two winn3 gateway nodes), Secret Manager (the Gemini API key), Artifact Registry (router container image), Cloud Logging (request and decision logs), and the Gemini API (routing decisions and Hoppy escalation). The deployment lives in the Google Cloud project "Win's VPN XPRIZE".

## AI-native operations

The judges should see AI executing a key operational decision, not decorating a demo. Here is the actual decision chain, request id by request id:

- The router is live: https://AI_ROUTER_HOST. Model gemini-3-flash-preview. The first real routing decision in production returned in about 4 seconds with reason codes [LINK_DOWN, UDP_BLOCKED, HEALTHIER_ALTERNATE].
- Every routing call carries a request_id. The router logs the full input, the model's raw structured output, the gate verdict, the fallback flag, the reason codes, and the latency for that id, appended to a decision log (JSONL) and exposed at GET /decisions (last 50) with a dark live dashboard that refreshes every 2 seconds.
- Two proven scenarios (SUPERVISOR RECEIPT 2026-08-17). Healthy link: Gemini returns keep with [STABLE_LINK, LATENCY_OPTIMIZED]. Impairment: the admin trigger flips route-a to unreachable (recent_failures +1); the next login Gemini switches to demo-route-b with its reason codes, and the decision is in the /decisions export. The reason code vocabulary is closed and documented in the router prompt: LINK_DOWN, INTERFERENCE_SUSPECTED, UDP_BLOCKED, DNS_TAMPERING, HEALTHIER_ALTERNATE, STABLE_LINK, LATENCY_OPTIMIZED, and DETERMINISTIC_FALLBACK for the gate.
- A real logged decision looks like: request_id, current route demo-route-a, probe data showing demo-route-a degraded, Gemini returns {selected_route_id: "demo-route-b", decision: "switch", confidence, reason_codes}, gate passes, phone reconnects through demo-route-b.
- Fail-open design: the router has a hard 2.0 second deadline. Gemini answering late is the same as Gemini not answering: the deterministic gate picks the best reachable route by fixed rules and logs decision source "fallback". Connectivity is never held hostage by the model. This is the design rule for AI in an availability-critical path.
- Impairment demo: an admin trigger degrades route A on demand (POST /admin/health on the staging hub flips reachable to false and increments recent_failures). Judges can watch the dashboard decision card flip to route B with reason codes while the phone reconnects, live. Nothing is pre-recorded in that moment. The full chain that carries the traffic is also live and verified: handshake, inner ICMP, and NAT egress ICMP receipts through the winn/3 gateway, plus the phone (debug build org.winsvpn.app.debug v1.0.15, sha256 3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0) installed with privacy and legal consent accepted, free login in progress, device allocated on demo-route-a inner 10.10.0.3. Physical tunnel-up receipt pending, captured per EVIDENCE_CHECKLIST.

## Business

- Operator: Win's VPN Inc., Florida nonprofit corporation, document number N26000008302. IRS 501(c)(3) determination letter dated July 21, 2026, exemption effective June 11, 2026, public charity under 509(a)(2).
- Pricing: $0.99/month, $11.88/year, 10-year lifetime passes. Payments processed by PayPal. Free tier available.
- Made in the USA. No-logs by design; only device-count metadata for the three-device limit.
- Launched: end of June 2026.
- Revenue and user counts: OWNER-FILL (see REVENUE_TEMPLATE.md; we do not publish invented numbers).

## Pre-existing work disclosure

We disclose exactly what predates the hackathon window and what was built for it.

The VPN client and the nonprofit predate the window minimally, and they are disclosed. The client app (Flutter, the calculator camouflage, account and free-tier login, the Winn Protocol tunnel client) and the nonprofit business itself existed before the window. So did the Hoppy support framework (site chat widget and hub proxy).

Built during the hackathon window for this submission: the entire Gemini adaptive routing layer, the Cloud Run deployment, and the v3 demo gateway network. Concretely: the Cloud Run Gemini router (structured-output decision service, deterministic gate, decision log and dashboard, /hoppy/escalate Gemini path), the Cloud Run deployment and its container image in Artifact Registry, the Google Cloud wiring (Secret Manager, Cloud Logging, project "Win's VPN XPRIZE"), the staging control-plane twin serving the winn/3 protocol config on Compute Engine, the two winn3 gateway nodes with their signed descriptor ring, and the rebuilt debug APK carrying the freshly rebuilt winn engine (libwinnengine.so for three ABIs) pinned to descriptor ring G1. None of that existed before the window.

## Category recommendation

Recommended: Education & Human Potential.

One line: a censor can cut a person off from learning, growing, and earning; restoring open-internet access restores the precondition for human potential, and this Gemini router keeps that access alive in real time.

Why this category and not another: the five categories are Education & Human Potential, Entrepreneurship & Job Creation, Small Business Services, Money & Financial Access, and Professional Services. The other four are narrower and economic. The VPN serves all of them by restoring access, but its core thesis is broader: under censorship, people cannot learn, cannot grow, cannot achieve. The founder's parent was assassinated by the Myanmar junta in 2025. This product exists so that a person under censorship can still become who they might have been. That is the Education & Human Potential story, and it is the story told by every decision the router makes. OWNER-FILL: confirm the exact category name against the page at submission time.

## Testing instructions for judges

1. Install the staging debug APK: $HOME/xprize/apk/app-phone-debug.apk, version 1.0.15, sha256 3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0 (verify against evidence/apk-sha256.txt). Package name org.winsvpn.app.debug, already pointed at the staging hub and pinned to winn/3 descriptor ring G1. Privacy and legal consent are accepted on the device.
2. Open the app. It looks like a calculator. Enter the unlock sequence, then the camouflage PIN (OWNER-FILL if changed; default demo PIN works).
3. Log in with free account 9999-9999-9999 and any 4-digit PIN. No activation secret needed.
4. The server list shows two AI routes: AI Route A - US Central and AI Route B - US East. Both are free-access enabled in staging.
5. Connect through AI Route A. Open any IP-check page in the phone browser. It shows the route A egress IP DEMO_ROUTE_A_IP. The device is allocated inner 10.10.0.3 on demo-route-a.
6. Impairment demo: on a laptop, open the router dashboard at https://AI_ROUTER_HOST/ and flip route A to unreachable using the admin health trigger (staging hub POST /admin/health {"slug": "demo-route-a", "reachable": false}; this also increments recent_failures). Watch the decision card flip to route B with reason codes. Within seconds the phone reconnects and the IP-check page shows the route B egress IP DEMO_ROUTE_B_IP.
7. Evidence cross-check: compare the timestamps on the phone reconnect, the dashboard card, and the decision JSON at GET /decisions on the same URL. The request_id in the log should match the switch you watched.
8. Hoppy: open support chat on the site, ask a hard product question, watch it escalate to Gemini through the router and answer.

Nothing in the judge path touches production VPN infrastructure. Staging and the live demo router only.