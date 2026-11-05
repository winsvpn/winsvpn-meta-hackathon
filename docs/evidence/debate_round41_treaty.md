# Debate Round 41 Treaty (the tunnel-death defect) — Turn 3, vote recorded

Certified 2026-09-21 by the Arbiter (session model via the ZCode harness,
Arbiter role under AGENTS.md 13.7). Seats: agy (Gemini 3.8 Flash High),
Qwen 3.8 Max 0902 xhigh via OpenRouter (substitute for Claude Opus 5, whose
weekly limit was exhausted; owner-authorized roster change), opus 5 (standing
Turn 2 votes with an explicit conditional pre-commitment), Astra via Codex CLI
(substitute for GPT-5.6 Sol Pro; vote pending provider unlock, see
exceptions). Dispatched packets and full per-seat verdicts:
.agent/debates/round41/ + docs/evidence/debate_round41_stage{1,2,3}_*.md.
Turn 3 packet sha256 0670d433368b77e726d0fe10c306c2c0af4b39d97f6b4b3f965221edf7d70863.

## Defect (reproduced twice on a physical device)

A heavy tunnel download burst (about 496 Mbps, up to 60k carrier datagrams/s
toward the phone's 1024-token receive window with 511 reorder tolerance)
drove the receive window's force-advance past the gateway's true transmit
position. The window then classified arriving datagrams as beyond-window and
froze tun delivery (rx_packets frozen at 383,255 while carrier receives kept
counting at +7/s). The gateway's jittered in-band rekey (5-minute minimum
timer, fired at session second 348) and the phone's liveness responses were
subsequently dropped as replays; the 15 s RekeyTimeout and the 4-lost-probe
liveness bound expired together (06:14:32/33) and both ends tore the tunnel
down. A replacement session died in 24 s on one stale-epoch datagram
consuming its whole handshake budget. Every Win's VPN v3 session through a
bursty path is exposed at its first jittered rekey (5 to 6 minutes).

## Ratified vote (Turn 3, amended text)

- OI-1 root cause (post-burst receive-window latch via force-advance
  overshoot): agy AGREE, qwen AGREE, opus pre-committed AGREE.
- OI-2 fix package (four parts: force-advance clamp; recoverable rekey
  rollover with NEW RejectAfterBytes/Time epoch bounds — the Arbiter verified
  only RejectAfterMessages is enforced today, session/batch.go:135;
  make-before-break epoch replacement; handshake budget counts only
  well-formed messages): agy AGREE, qwen AGREE, opus pre-committed AGREE.
- OI-3 loss split (471 wire loss, 14,077 accept-path rejections during the
  burst; the clamp recovers most of those; only the terminal latch was
  fatal): agy AGREE, qwen AGREE (independently re-verified the arithmetic),
  opus pre-committed AGREE.
- OI-4 app latch as a derived property with a generation guard:
  agy AGREE, qwen AGREE, opus pre-committed AGREE.
- OI-5 ordering plus the two-condition verification (post-burst rx tracking
  messages_received for at least 120 s AND a forced rekey within 20 s of
  burst end completing without StateFailed, with drop-reason
  instrumentation): agy AGREE, qwen AGREE, opus pre-committed AGREE.

## Exceptions

- Astra's Turn 3 vote is UNRECORDED (provider gate: the astra model was not
  yet served to the ChatGPT-account Codex CLI during the entire poll window;
  SEAT-ERROR captured in the round cache). Its vote is taken when it
  unlocks; a DISAGREE reopens the affected item.
- Sol Pro's Turn 1/2 votes (rate-limited, :batch slug 404) are superseded by
  the roster change; its Turn 1 ranking agreed with the window-aging family.

## Execution

1. Astra implements the six-part fix per
   scratch/rv41/astra_implementation_brief.md (dispatch:
   scratch/rv41/dispatch_astra_impl.sh, polling until the provider unlocks).
2. The council ratifies Astra's implementation (the seats-write-the-code
   standing rule; the Arbiter does not author production code).
3. The device verification gate: two speedtests 60 s apart plus a forced
   rekey inside 20 s of burst end, post-burst rx tracking for 120 s,
   drop-reason instrumentation recorded (scratch/rv41/repro_stall.py).
