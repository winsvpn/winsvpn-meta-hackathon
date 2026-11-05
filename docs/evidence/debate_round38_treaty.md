# WINTHOS ROUND 38 TREATY: SPEEDTEST VARIANCE AND THE MEASUREMENT QUESTION

Date: 2026-09-20
Protocol: ICDP (AGENTS.md Section 13). Arbiter: session model (separate lineage).
Packet: the endpoint-selection finding plus the one-knob experiment record,
dispatched to the three standing podiums; receipts per dispatch.

## Council

- Seat 1: Antigravity (Gemini 3.8 Flash High) via agy CLI
- Seat 2: Claude Opus 5 via claude CLI
- Seat 3: GPT-5.6 Sol Pro via OpenRouter (flex; :batch fallback wired)

## The finding (as now established)

Upload numbers split into two bands by the speedtest target-family label:
"North America" runs 681-790 Mbps up, "Global Backbone" runs 234-301 Mbps up,
across three build configurations (warm-up, 4 MiB carrier buffers, reverted),
downloads 717-792 throughout, engine drops zero. The one-knob experiment
(4 MiB ~= 1 BDP carrier buffers) REPRODUCED the slow band, refuting the
Round 37 deep-buffer derivation. The label is chosen by the run's own
download winner; every upload leg goes to speed.cloudflare.com/__up.

## Stage 1: three competing mechanisms, all testable

- opus: H1 IPv6/MTU asymmetry, H2 the fast number may be fake (CDN ingest),
  H3 run-order; voted D (measure the tunnel, gate validity, disclose target).
- solpro: run-order carryover and per-request vs aggregate limits; voted
  D-variant (fixed labeled primary + disclosed diagnostics).
- agy: HTTP/2 stream flow control vs Cloudflare, or peering policing; voted
  C (order-swap) as the pragmatic fix.

## Arbiter post-Turn-1 measurements (M-1..M-3)

- M-1: curl -6 through the tunnel cannot resolve the target (no AAAA):
  IPv6 asymmetry is refuted on this path.
- M-2: single-stream uploads to speed.cloudflare.com/__up measure
  152-202 Mbps from the phone (same IP 172.66.0.218 each time) and about
  316 Mbps DIRECT from <CANADA_MGMT_SSH_ALIAS>: the endpoint caps per-connection rate.
- M-3: the label/upload mapping in lib/main.dart confirmed: the run's best
  download names the family and only cloudflare winners map to /__up.

## Stage 3 votes

- RV-B (four-point product design: primary ingest on the exit node, validity
  gate, disclosed target, per-family history): UNANIMOUS AGREE.
- RV-D (measurement-wording corrections accepted): UNANIMOUS AGREE.
- RV-A (mechanism): 2-1; opus's dissent is ACCEPTED by the Arbiter: my
  M-3 reading had the label direction inverted, and single-stream ceilings
  cannot bound the 32-stream aggregate the app actually runs. Cause remains
  OPEN pending the instrumented per-run data.
- RV-C (revert state): 2-1; opus's dissent is ACCEPTED: the code reverts are
  ratified, but the MainActivity causal comment was rewritten to record the
  observed association without any causal claim.
- RV-E recorded per seat: opus (b), agy (c), solpro (b with fail-closed
  fallback). The RV-2 fork stays with the User.

## Implemented in this round (verified)

- MainActivity mechanism comment rewritten (association-only, cause open).
- Per-run upload instrumentation shipped (log WinsSpeedUpload upload-run:
  URL, per-stream HTTP status distribution, served host, acked bytes,
  window, streams, Mbps), built and installed on the physical device.
- First instrumented runs captured: fast band run = 31/32 streams HTTP 200
  to speed.cloudflare.com, 790233088 bytes in the 8 s window = 790.2 Mbps;
  second run 769392640 bytes = 769.4 Mbps (783/769 displayed). The slow-band
  instrumentation capture is the next measurement.
- Buffer and warm-up reverts re-verified; Go suites pass; APK builds.

## Open

- Cause of the two upload bands: the instrumented per-run logs decide it
  (statuses/hosts/bytes per band). Next measurement session.
- RV-B implementation: gateway-side authenticated speedtest ingest endpoint
  (Round 39, with the install script), client primary/fallback wiring.
- RV-2: with the User (2 seats (b), 1 seat (c)).
- Operator items: kansas IONOS UDP 51820, spain luksAddKey, Play declaration,
  Apple/extension custody receipts.

## Receipts

- docs/evidence/debate_round38_stage1_{agy,opus5,solpro}.md
- docs/evidence/debate_round38_stage3_{agy,opus5,solpro}.md
- docs/evidence/debate_round38_oi_docket.md; docs/evidence/round38_runner.log
- .agent/debates/round38/packet_dispatched.txt
- MainActivity.kt ROUND 37/38 EXPERIMENT RECORD comment; WinsSpeedUpload
  upload-run log lines.
