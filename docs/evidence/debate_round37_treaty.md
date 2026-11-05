# WINTHOS ROUND 37 TREATY: IMPLEMENTATION VERIFICATION

Date: 2026-09-20
Protocol: ICDP (AGENTS.md Section 13). Arbiter: session model (separate lineage).
Packet: the Round 36 implementation ledger (11 fix groups + verified-conforming
list + the pre-warm collapse finding + OI-3 divergence), sha256
fb7fe4be0aa4d21be8163f61670d769612c3097ecd684b63786f6c40d389cead.

## Council

- Seat 1: Antigravity (Gemini 3.8 Flash High) via agy CLI
- Seat 2: Claude Opus 5 via claude CLI
- Seat 3: GPT-5.6 Sol Pro via OpenRouter (flex; :batch backup wired per User)

## Stage 1 outcome (cross-examination)

The seats confirmed the fixes coherent and found real defects in the
implementations. All accepted findings were fixed on the working tree between
Turn 1 and the Turn 3 vote, each re-verified:

1. Response-oracle shape: the guardrail's `mode:"guardrail"` field removed; the
   guardrail response is byte-identical in shape and body to the local fallback.
2. Router storage-slot wait moved to the default executor: the raw
   BoundedSemaphore.acquire blocked the event loop for up to 250 ms.
3. Route-inventory test extended: no template ("{") may appear in either
   admission set (middleware matches concrete paths).
4. Extension version: semver prerelease stripped, per-component 0..65535 cap
   (solpro counterexample 65536), comment/quote-robust pubspec parsing; build
   fails loudly; drift suite 4/4.
5. Monero config file written under umask 077 (no world-readable window).
6. Per-interface fq qdisc made durable: udev rule 99-winn3gw0-qdisc.rules
   reapplies on every device add; the deploy waiter remains as belt-and-braces.
7. verify-node staged-secret cleanup now runs on an EXIT trap (failed verify and
   interruption included), not only the success path.
8. wins_require_trusted_env_file (both ONETOUCH installers) walks every ancestor
   to /: root-owned, no group/other write.
9. PAC fail-closed: both adapters catch a buildPac throw and install
   PAC_FAIL_CLOSED (dead loopback proxy 127.0.0.1:1); the first-run throw used
   to leave the browser unproxied (fail-open).

## Stage 3 + Turn 4 outcome

- 11 of 12 docket items ratified unanimously (RV-1, RV-3..RV-12, with RV-6
  closed by the per-component cap amendment: AGREE x3).
- RV-2 (the AI-chat guardrail) SPLIT 2-to-1 and is ESCALATED TO THE USER as
  sovereign under 13.2.5:
  - (b) LOCAL-ONLY ROUTE: opus + solpro. /ai-chat serves only the local topic
    fallback; the hub LLM is never called. Closes the enumeration oracle
    completely and zeroes third-party AI exposure; loses real LLM answers.
  - (c) KEEP-SUPPRESSION: agy (and the Arbiter's recommendation). The
    guardrail holds; the keyword list remains enumerable at one request per
    candidate while the hub is up; documented as residual.
  The User's ruling is final and closes RV-2.

## Verified with the Round 37 packet (test evidence)

- spain contract tests 7/7; gateway memory suite PASS; router suites
  (router, decision_log, fallback_metrics, protocol_selection, route_inventory)
  all exit 0; extension manifest drift 4/4; standalone v3 artifact 18/18;
  _worker.js parses as ES module; bash -n clean on all edited scripts;
  phone APK builds.

## Open items carried (none block the treaty)

- RV-2 ruling (User).
- Pre-warm collapse: Opus's window-over-inflated-RTT derivation (32 MiB
  in-flight ceiling) vs solpro's burst-size sweep; discriminating experiment
  queued: warm-up with in-flight window and carrier send buffer near one
  bandwidth-delay product.
- OI-3: AWG MTU (node 1280 vs repo 1440) and node-map owner decisions; hardened
  installer redeploy awaits approval.
- Operator items: spain cloudflared connector restart (IONOS console), Play
  QUERY_ALL_PACKAGES declaration, checkout retest on enumerated payment origins,
  RSS measurement to ground the 1536 KiB/session constant, gateway restart +
  `tc qdisc show dev winn3gw0` as qdisc-persistence confirmation, extension
  naming decision (OI-36).
- Next datapath lever: carrier in-flight window and buffer sizing (the 1000/1000
  blocker per the Round 37 derivation), then batch 256 -> 512.

## Receipts

- docs/evidence/debate_round37_stage1_{agy,opus5,solpro}.md
- docs/evidence/debate_round37_stage3_{agy,opus5,solpro}.md
- docs/evidence/debate_round37_stage4_{agy,opus5,solpro}.md (micro-vote)
- docs/evidence/debate_round37_verify_raw.json (digest per dispatch)
- docs/evidence/debate_round37_oi_docket.md; docs/evidence/round37_runner.log
- .agent/debates/round37/packet_dispatched.txt
