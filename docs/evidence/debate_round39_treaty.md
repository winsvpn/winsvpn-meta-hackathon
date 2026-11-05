# WINTHOS ROUND 39 TREATY: RV-B IMPLEMENTATION VERIFIED + INGRESS RESOLUTION

Date: 2026-09-20
Protocol: ICDP (AGENTS.md Section 13). Arbiter: session model (separate lineage).

## Council

- Seat 1: Antigravity (Gemini 3.8 Flash High) via agy CLI
- Seat 2: Claude Opus 5 via claude CLI
- Seat 3: GPT-5.6 Sol Pro via OpenRouter (flex; :batch fallback wired)

## Verified implemented state (all seats reviewed; fixes applied and tested live)

1. Gateway ingest: cmd/winn3-gateway/speedtest_ingest.go — inner-only HTTP
   listener (bind assign.V4, flag -speedtest-ingest-port, default 0 = off),
   POST /speedtest/up (1 GiB MaxBytesReader cap, server-ACKNOWLEDGED byte
   count in the response), GET /speedtest/down?bytes=N (1 GiB cap), method
   gating, timeouts. Concurrency 64 (the first 2-slot deployment benchmarked
   242 Mbps serving 2 of 32 streams). Go tests: 5 passing.
2. Client: Dart prepends the 'Tunnel Ingest' target (from the latched signed
   descriptor router) when connected; the upload leg uses the NEW native
   measureUploadViaTunnelIngest — RAW TCP sockets (rationale: Android's
   cleartext HTTP policy governs HTTP stacks; its purpose does not apply to
   intra-tunnel traffic; the destination is pinned to the signed descriptor's
   inner router, latched by the running session and cleared at teardown).
   32 raw-socket streams, server-ACKNOWLEDGED byte counts, 1500 ms connect
   deadline (RV-E amendment, applied).
3. Canada production: new linux/amd64 binary installed; unit carries
   -speedtest-ingest-port 8455; WINN3GW-INPUT rule 6 accepts tcp/8455 from
   10.10.0.0/24 to 10.10.0.1, persisted. Live on the physical phone:
   'Last VPN test: Tunnel Ingest' with 1166 Mbps down (highest ever) and
   358-445 Mbps ingest uploads; Round 39 final verification run measured the
   tunnel-ingest upload at 403.8 Mbps (32/32 HTTP 200).

## Stage 3 outcome

- RV-A (ingress mechanism): UNANIMOUS AGREE — bufferbloat component
  confirmed (4 MiB carrier buffers raised ingress 358 to 445), the stable
  tunnel-ingest primary is established, and the consumer-access-link question
  is recorded as open (testable by a public-family upload comparison on the
  same radio).
- RV-B (EOF/413 conflation): UNANIMOUS AGREE — fixed (mid-body EOF now
  answers 200 with the accurate count; only MaxBytesError is 413).
- RV-C (blocking semaphore): UNANIMOUS AGREE — fixed (select-with-default
  answers 503 immediately on exhaustion).
- RV-D (stale Dart latch): UNANIMOUS AGREE — fixed (Dart field cleared at
  the disconnect transition; native equality gate covers the rest).
- RV-E (port standardization + per-source cap + sub-window reporting):
  UNANIMOUS AGREE on the AMENDED text — Opus's connect-time objection was
  addressed by the applied 1500 ms connect deadline on the raw-socket ingest
  (verified against the timeout mechanics: HttpURLConnection's download leg
  keeps its own 5 s connect timeout).
- RV-F (batch/inbox ordering): UNANIMOUS AGREE — the gateway inbox moves
  first and alone (256 -> 2048, measured); the client batch NEVER moves ahead
  of the inbox. Batch 256->512 is REJECTED as framed: a 512-frame batch
  against a 256-deep inbox guarantees synchronized tail-drop across 32 flows.

## Measured state after Round 39 (physical S26 Ultra, canada, winn v3)

- Download (via cloudflare/NA through the tunnel): 724-786 Mbps typical.
- Download (tunnel ingest, when it wins): 1166 Mbps (Round 38-verified) and
  726 Mbps (winning the Round 39 contest).
- Upload (tunnel ingest, the true client->gateway ingress): 358 (8 MiB
  buffers) -> 403-445 Mbps (4 MiB buffers). The ingress bufferbloat
  component is confirmed and partially mitigated; the remaining gap to
  1000 is the carrier ingress investigation (pipe inbox depth, driver loop,
  access link) per the RV-F ordering.
- The app's headline number now rides the stable Tunnel Ingest path: no
  more 3x swings from third-party target rotation.

## Round 40 correction (2026-09-20, post-ratification)

The ratified RV-F ordering ("gateway inbox 256 -> 2048 first and alone") was
implemented and then REVERTED before deploy: the repo's pinned audit
(cmd/winn3-gateway/inbox_4096_ceiling_test.go, TestDefaultPipeDepthIsStillSend
ParityNot4096, and the D23 derivation) shows production sessions never use
carrier.DefaultPipeDepth (256 = reflector send-queue parity). The per-session
inbox derives from the token window: DefaultTokenWindow/2 = 512, reorder
tolerance 511. During every load sample the gateway counters showed
rx_offered == rx_packets: the 512 inbox never dropped, so inbox depth is not
the ingress ceiling. Deepening past the 511 reorder tolerance is also
pointless (the token filter rejects beyond-window frames as replays
regardless of inbox space), and 2048 is exactly the D23-shaped cap the audit
exists to prevent. The ingress investigation continues with the ceilling
localized between the phone's carrier send and Canada's NIC (access uplink
airtime sharing, provider inbound UDP treatment, or the client engine's send
path). The clean second-vantage discriminator (winn-datapath client from the
Kansas hub against canada's ingest) requires registering new client
credentials against canada's peer registry: an owner-approved production
admission change.

## Open items

- RV-2: with the User (opus + solpro: (b) local-only; agy: (c) keep
  suppression).
- Operator: kansas IONOS firewall inbound UDP 51820; spain luksAddKey
  one-liner; Play QUERY_ALL_PACKAGES declaration; Apple/extension custody
  receipts.
- Round 40 plan (ratified ordering): gateway inbox 256 -> 2048 first and
  alone, measured; then carrier pacing work; then the client batch question,
  only if still bound.
- Windows builds (winpc toolchain check; Win11 ARM64 VM down).

## Receipts

- docs/evidence/debate_round39_stage1_{agy,opus5,solpro}.md
- docs/evidence/debate_round39_stage3_{agy,opus5,solpro}.md
- docs/evidence/debate_round39_oi_docket.md; docs/evidence/round39_runner.log
- .agent/debates/round39/packet_dispatched.txt
