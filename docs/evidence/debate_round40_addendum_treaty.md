# Debate Round 40 Addendum Treaty (UNANIMOUS, Turn 6)

Certified 2026-09-21 by the Arbiter (session model via the ZCode harness,
Arbiter role under AGENTS.md 13.7). Three podium seats, four arbiter-verified
facts, six turns. Every item below is unanimous on identical text.

## Agreed specification digest

- Turn 6 (final vote) packet sha256:
  9675ccff01e8f3b945d0b15cab74becb18459071433f21dba3114e163d26e006
- Roster receipt: agy (Gemini 3.8 Flash High, Antigravity CLI),
  claude-opus5 (Claude Opus 5, Claude Code CLI), solpro (GPT-5.6 Sol Pro,
  OpenRouter flex; one :batch fallback during upstream rate limiting, one
  truncated stage-1 retried as stage1b continuation per 13.5).
- Receipts: docs/evidence/debate_round40_addendum_stage1{,b,2,3,4,5,6}_*.md;
  dispatched packets mirrored under .agent/debates/round40/; cache keys
  r40add_stage*_* in docs/evidence/debate_round37_verify_raw.json.
- Runner: tools/run_round40_addendum.py (+ _stage2.._stage6.py), seats
  imported from the run_round37_verify.py chain. One retry rule applied per
  seat per stage; no silent model substitution.

## Arbiter-verified facts (A to D)

- A (code): DefaultTokenWindow is RECEIVE-SIDE ONLY. core/params.go:164-177
  ("how many future demux tokens a receiver precomputes ... the reordering
  tolerance and the exact replay filter"); the sender Seal path
  (core/session.go:384-403) computes sendPRF.token(counter) with no window
  check; the carrier layer has no ACK, credit, or outstanding cap. The
  Round 40 "inbox 256 to 2048" premise was wrong before deploy: production
  inboxes derive from the token window (512, tolerance 511) and were never
  the plateau.
- B (measured): paced vs burst-32 UDP at matched mean rate on the same path,
  random payloads: 400 Mbps: paced 5.83%, burst 5.35/5.89% loss; 550 Mbps:
  paced 8.76/9.87%, burst 8.16/8.28%. Burst shape adds no loss; the loss is
  rate-dependent policing. Constant-pattern payloads die near 100% at every
  rate including 150 Mbps; high-entropy payloads pass.
- C (measured via adb, no app PIN): the phone's own Wi-Fi counters: Tx link
  1441 Mbps (75% of Rx link 1921), "Calculated Tx" 692 Mbps, cumulative TX
  retry rate 9.2%, RSSI -50, 6 GHz. The same radio carries 1166 Mbps tunnel
  DOWN (Rx side). The ingest plateau (437-445 inner, about 470 carrier) is
  68% of Calculated Tx.
- D (code): carrier/pmtud.go derives PMTU from kernel EMSGSIZE on oversized
  Sends; it emits NO probe datagrams. carrier/doc.go: carriers emit nothing
  unbidden; keepalives are PING frames inside AEAD messages.

## Ratified items (all unanimous)

- OI-1 (ingress ceiling) + OI-5 (measurement design), CONJOINT: attribution
  comes ONLY from same-session paired comparison on the same radio: raw leg
  (adb iperf3, random payload, phone to LAN receiver AND phone to
  canada:9111, canada-side counted, 300-700 Mbps sweep, per-step TX-retry
  deltas) vs tunnel leg (live tunnel carrier delivery during the ingest
  run). Cuts: tunnel-carrier near raw-carrier within noise = shared
  infrastructure cap (radio or path); tunnel-carrier well below raw-carrier
  with clean carrier loss = tunnel-specific cause (userspace processing or
  tunnel-discriminating policing); carrier loss over 4% at the tunnel
  operating point = consistency alarm that re-opens the Mathis inversion
  that run. LOW LOSS ATTRIBUTES NOTHING: a binding policer at a TCP-limited
  equilibrium reads near-zero loss. The phone uplink envelope (Fact C) is
  the current best first-rank explanation, held open pending the paired
  measurement. Token starvation and gateway-side are REMOVED (facts A, D).
- OI-2 (carrier send pacing): a latency/jitter feature ONLY. Never claimed
  as capacity; gated on queue-delay measurements before any ship; reopens
  nothing in the D23 geometry (pacing alters timing, never sequence).
- OI-3 (1000/1000 target): 1000 Mbps TUNNELED upload is not certifiable on
  this home Wi-Fi vantage (1043-1070 Mbps carrier required for 1000 inner
  against 560-580 Mbps best measured path delivery). Product claim wording:
  "delivers your device's own measured raw uplink rate less measured
  protocol encapsulation overhead, within measurement noise". Acceptance
  band computed per session from real constants (Winn 26 B + UDP/IP 28 B =
  54 B per datagram; core/params.go:38,59, core/session.go:38,263):
  ratio_pred = ((M - 40) / (M + 54)) / (D_r / (D_r + 28)), M = session inner
  MTU, D_r = raw leg datagram payload; band = ratio_pred plus or minus twice
  the largest leg's spread across 3 runs per leg in the same session
  (examples at D_r=1400: M 1440 gives 0.956, M 1280 gives 0.948). A residual
  gap below the band is an OPEN FINDING, never silently named overhead. The
  raw leg is measured on-device, never the radio's Calculated Tx estimate.
  Owner-report items: ISP plan symmetry, phone radio, vantage (cellular for
  headline numbers). 1166 Mbps down stands as the demonstrated download.
- OI-4 (scrubber): no redesign forced (fact D). STANDING RULE, AEAD-first:
  every future diagnostic, probe, or keepalive on the wire is AEAD-sealed;
  CSPRNG-filled bodies are the pre-key exception only; constant-pattern
  payloads are measured to die near 100% at any rate (fact B).

## Exceptions and open items

- The phone app camouflage PIN on BOTH test devices (Motorola org.winsvpn.app
  via wireless adb, Samsung org.winsvpn.app.debug via USB) now rejects the
  standing default 1357 on both submit paths. Owner must supply the PIN; the
  tunnel-leg comparisons and the instrumented three-point phone measurement
  are queued behind it. No brute force attempted (lockout enforcement).
- The OI-5 raw sweeps are adb-only and PIN-free; the tunnel-leg comparison
  needs the PIN (or an app-independent trigger).
- canada IONOS inbound-UDP scrub characterization stays an owner item, now
  with RV-41 evidence attached (constant-payload scrub near 100%,
  rate-policed loss 5-10% above 400 Mbps offered from the LAN vantage).

## Execution queue (from this treaty)

1. OI-5 raw sweeps (adb iperf3 push; PIN-free).
2. Per-tunnel carrier loss counters at the plateau (PIN-gated).
3. Product wording change in client copy per OI-3.
4. Pacing as a latency feature only if queue-delay data justifies it.
