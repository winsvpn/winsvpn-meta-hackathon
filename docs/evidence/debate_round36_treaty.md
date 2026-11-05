# WINTHOS ROUND 36 TREATY: SURFACE-WIDE AUDIT (PASS 1)

Date: 2026-09-20
Protocol: ICDP (AGENTS.md Section 13), three stages plus one dispute cycle plus one
final vote. Arbiter: session model (separate lineage from all podiums).

## Council

- Seat 1: Antigravity (Gemini 3.8 Flash High) via agy CLI
- Seat 2: Claude Opus 5 via claude CLI
- Seat 3: GPT-5.6 Sol Pro via OpenRouter (flex tier, reasoning effort high)

## Result

All 50 open items ratified UNANIMOUSLY:
- 46 items unanimous in the first Turn 3 vote.
- OI-2, OI-18, OI-34 ratified after dispute-cycle Turn 2 + Turn 3 (Arbiter amendments
  adopted: monero-wallet-owned 0600 config file via --config-file; expired-first
  eviction with 429 instead of evicting fresh entries; serve last reviewed asset on
  digest mismatch, fail closed only with no reviewed prior).
- OI-35 ratified in a final single-item vote after two objectors specified the
  resolution (independent command -v docker / command -v git checks, each paired
  only with its own package name).

Non-defect ratifications: OI-44 (pac.js wvMatch suffix match is correct as written)
and OI-46 (keep foregroundServiceType specialUse; no systemExempted).

## Evidence resolved by the Arbiter between turns

- EV-1: monero-wallet-rpc supports --config-file with rpc-login inside (docs.getmonero.org).
- EV-2: smart router runs as non-root aicore, so OI-12 is P1.
- EV-3: spain-mgmt SSH management plane down (websocket: bad handshake); became OI-50.
- EV-4: <CANADA_MGMT_SSH_ALIAS> kernel buffers 128 MiB, multi-stream egress above 1.8 Gbps; the
  1000/1000 Mbps target is not gateway-limited.
- EV-5: Play QUERY_ALL_PACKAGES policy per support.google.com answer 10158779.

## Implementation ledger (updated as fixes land)

- OI-7 (CSP tracker removal): DONE. web/_headers and web/_worker.js CONTENT_SECURITY_POLICY
  tightened (tracker origins and img-src https: wildcard removed; PayPal, Apple Pay,
  Google Pay retained). web/verify_inline_csp.py passes: OK, hash-pinned.
- All other items: PENDING implementation in priority order (P0 first).
- Non-repo changes (Cloudflare zone WAF rules, OI-9 Play declaration, spain-mgmt SSH
  repair) require operator action or explicit approval per the external side-effect gate.

## Uplink track (separate from the docket, in-flight during the round)

- Re-baseline on the S26 Ultra over the Canada gateway: 774 down / 531 up (median of 3).
- Shipped and verified: JNI bulk TUN read (libwinn_tun_bulk.so + WinnV3AndroidTun.kt
  bulk burst reader) and 16 MB upload SO_SNDBUF. Result: 766/712/704 up (median 712,
  +34 percent), download median 722, engine drops zero. Upload at 98.6 percent of
  download. Target raised by the User to 1000+ both directions; pre-warm measurement
  change and further datapath work continue toward it.

## Receipts

- docs/evidence/debate_round36_stage{1,2,3,4,5,6}_*.md (per-seat turns)
- docs/evidence/debate_round36_surface_raw.json (cache; digests per dispatch)
- docs/evidence/debate_round36_oi_docket.md (canonical docket)
- docs/evidence/round36_runner.log (dispatch log)
- .agent/debates/round36/receipts.raw.jsonl (per-dispatch SHA-256 receipt line items)
- .agent/debates/round36/arbiter_evidence.md (EV-1..EV-5)
- .agent/debates/round36/packet_dispatched.txt (canonical packet, sha256
  d6cf3bb89ce1b955569fc3d3301c7a08924bf59cf3d5a11be0f4457e364376de)
