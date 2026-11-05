# Round 40 addendum stage1: claude-opus5

## Packet hygiene (one line)

RV-41 is stamped 2026-09-21; the session date is 2026-09-20. Future-dated receipt: correct the stamp or record the capture timezone before it enters the certification chain.

---

## 1. Re-ranked ingress ceiling candidates

The packet's own arithmetic argues against its lead candidate. Mathis for the inner streams, MSS 1400 B = 11,200 bits:

- **At p = 0.06, RTT 25 ms:** 1.83 Mbps per stream, 32 streams = 58 Mbps.
- **At p = 0.06, RTT 5 ms:** 9.1 Mbps per stream, 32 streams = 292 Mbps.
- **To actually deliver 437 Mbps across 32 streams:** p must be about 2.7% at RTT 5 ms, 0.67% at RTT 10 ms, 0.11% at RTT 25 ms.

The observed 437 to 445 therefore falsifies the premise that the inner streams see the 5 to 8% blast loss curve. Whatever the MacBook's open-loop constant-rate UDP measured, the phone's carrier traffic is not experiencing it. Candidate (i) explains the wrong number.

Now the coincidence the packet did not run. DefaultTokenWindow 1024 at 1400 B is 1,433,600 B = 11.47 Mbit of in-flight budget. Divide by RTT:

- 20 ms gives 573 Mbps
- 25 ms gives 459 Mbps
- 26 ms gives 441 Mbps
- 32 ms gives 358 Mbps

The entire observed spread, 358 to 445, maps onto RTT 32 ms down to 26 ms. That is an ordinary run-to-run RTT wobble on a Wi-Fi plus WAN path to a Canadian VPS (RTT to canada: UNVERIFIED-LIVE, not in this packet). Three independent facts corroborate:

- **FACT 2 null is predicted.** If the gate is a protocol credit window upstream of the socket, SO_SNDBUF 8 vs 4 MiB cannot move anything. A null carrier A/B is the signature, not a dead end.
- **FACT 1 clean inbox counters are predicted.** A sender held to 1024 outstanding never presents the receiver with spread that exhausts 511 reorder tolerance.
- **644 offered, 445 delivered is predicted.** The TUN reader accepts the offered rate, the gate releases one BDP per RTT, the excess bloats the engine queue, inner TCP settles at the drain rate. Window-capped flows show exactly this flat, offered-load-insensitive plateau.

The down/up asymmetry seals it against the radio hypothesis. Ingest down measured 1166 over the same phone radio, the same 160 MHz link, the same LAN. A wlan0 that RX's 1166 is not the thing capping TX at 470.

**Ranking:**

1. **(iv) token window as a send-side credit gate.** BDP cap of 1024 × 1400 B ÷ RTT.
2. **(iii) client send path.** Also produces a flat plateau, but would not track RTT and would leave CPU or queue evidence.
3. **(i) loss-limited inner TCP.** Demoted on the Mathis arithmetic above.
4. **(ii) phone radio.** Largely killed by 1166 down on the same radio.
5. **(v) gateway side.** Killed by zero UdpRcvbufErrors, zero UdpInErrors, flat engine CPU, 560 to 580 drained, clean inbox counters.

**Falsification that kills this ranking:** pair each archived run's throughput with its RTT. If throughput × RTT is not approximately constant at 11.5 Mbit, or if the engine source shows DefaultTokenWindow sizing only the receive anti-replay structure with no send-side credit gate (UNVERIFIED-LIVE, I cannot read the tree from this packet), rank 1 collapses and (iii) takes the top.

---

## 2. Round 41 carrier send pacing

Split the question, because the packet conflates two claims.

**Design: ratified.** Pacing at or above the measured drain rate is never worse than bursting. It cuts jitter, cuts the instantaneous reorder spread the 511-entry inbox has to absorb, and is the correct answer to the problem Round 40 tried to solve by deepening the inbox.

**"Recovers toward the 600 knee": rejected.** Two reasons. The 600 figure is an open-loop number measured while accepting 5% loss; no closed-loop inner transport lives at a rate where loss is nonzero, so the honest target from FACT 3a's curve is nearer 300 (0.84% loss), not 600. And if rank 1 above holds, pacing changes timing inside a window and cannot move a window cap by one bit.

**Sequencing objection.** Do not ship the pacer as the next change. If the token window is the limiter, the pacer A/B reads null, burns a measurement window, and manufactures a false "pacing does not help" receipt. Gate the ship on item 5.

**Exact design, when it ships:**

- **Bucket rate source:** windowed max-filtered delivery-rate estimator on the client, BBR-style, updated every 50 ms, pacing gain 1.25 steady state and 2.0 during startup so ramp is not slowed. Floor 50 Mbps. A static constant is prohibited: a pacer set below true capacity is a self-inflicted cap.
- **Burst size:** bucket depth = max(2 × MTU, rate × 250 µs), capped at 16 datagrams (about 22 KB, roughly 11 datagrams at 500 Mbps). Release via sendmmsg with a computed inter-batch gap. Per-datagram timers on Android burn CPU and re-add the jitter you are removing.
- **Placement:** last stage before the UDP socket write, after AEAD seal and after nonce and token assignment, one instance per carrier socket. Strict FIFO within a path. Ahead of encryption, the encrypt loop re-bursts the output and crypto latency contaminates the interval.
- **Token window and D23 interaction:** pacing alters timing only, never sequence, so DefaultTokenWindow 1024, the derived 512 inbox, and 511 reorder tolerance are untouched, and DefaultTokenWindow 4096 is not required. The pinned 4095 death shape in nonce_window_past_4096_test.go and inbox_4096_ceiling_test.go stays unperturbed. Bound the pacer queue delay at 5 ms with bypass beyond it, so a held datagram never becomes a window-slide loss.
- **Proof:** fixed inner offered load of 600 Mbps, pacer off vs on, 60 s each, 5 interleaved repeats. Primary metric is carrier loss ratio (client sent counter vs canada iptables arrivals). Secondary: inner goodput, inner retransmits, p50/p99 carrier one-way delay, receiver reorder-depth histogram, engine CPU. Ratify as a throughput fix only if loss ratio halves and goodput rises 10% or more with no CPU regression, and only if canada's UdpRcvbufErrors and UdpInErrors stay zero throughout. Otherwise it ships documented as a latency feature.

**Named risk:** a correct pacer can lower measured throughput by removing burst overshoot that was masking a lower sustainable rate. Do not treat that as a regression.

---

## 3. The 1000/1000 target from this vantage

Not achievable here, and the blocker is now two blockers.

**Path.** Open-loop UDP tops out at 560 to 580 delivered while accepting 5% loss. The loss curve is also non-monotonic (8.27% at 400, 5.95% at 500, 7.40% at 550), which is inconsistent with a fixed-rate policer and consistent with burst or airtime loss. No client change creates uplink capacity that is absent.

**Protocol.** 1000 Mbps inner needs W = 1000e6 × RTT ÷ 11200 datagrams in flight: 2232 at 25 ms, 1786 at 20 ms, 893 at 10 ms. A single 1024-token flow reaches 1000 up only below about 11.5 ms RTT. Above that, 1000 up requires DefaultTokenWindow 4096, which is the exact path Round 40 reverted and the 4095 death shape pins shut. The unblocked lever is concurrent carrier flows: 2 flows at 25 ms give 918 Mbps, 3 give 1376. That is an architecture item for Round 42, not a tuning knob.

**Product promises:**

- **2000/500-class plan:** promise no uplink number. Claim "saturates your uplink." Expect roughly 450 to 480 inner up after about 7% Winn overhead, down bounded by plan or the measured 1166.
- **2000/2000-class plan:** 1000 up is plausible and currently unproven. Gate the claim on a wired 2.5 GbE client on a 2000/2000 line delivering over 1000 carrier arrivals at canada at under 0.5% loss, with either a sub-11 ms gateway or multi-flow carrier shipped. canada's own NIC speed and any provider rate cap: UNVERIFIED-LIVE.
- **Either plan:** the headline number is an owner-report item. ISP tier, gateway RTT, and vantage (Wi-Fi vs wired vs cellular) decide it, not the client.

---

## 4. Scrubber consequences for v3

Yes, it changes a design assumption, and the rule it forces is absolute. Bulk carrier traffic is safe because AEAD ciphertext is high entropy. The exposure is every datagram that is not bulk. I cannot grep the tree from this packet, so the following are the shapes to audit, marked UNVERIFIED-LIVE on exact symbol names:

- **Path MTU probes.** The standard implementation pads to the probe size with a repeated filler byte. Constant-pattern by construction, dropped by this filter, and a dropped probe reads as "MTU too large." Silent MTU collapse is the highest-consequence failure here and would present as a client bug.
- **Keepalives.** Safe if AEAD-sealed under a fresh nonce. Fatal if emitted as a bare magic constant outside the seal. Rate offers no protection: fact 3c killed constant-pattern at 150 Mbps, so a 1 pps keepalive is equally exposed.
- **Handshake and hello.** A short datagram with a fixed magic prefix and little else is the marginal case, and its failure mode is total, since no session forms at all.
- **Padding and cover traffic.** Constant-byte padding inside the sealed plaintext is fine. Anything appended outside the AEAD is not.
- **Byte-identical repeats.** An unchanged datagram resent verbatim is a pattern even at full entropy. Vary it.

**Rule to adopt:** every carrier datagram on the wire, including probes, keepalives, retransmit requests, and cover traffic, is AEAD ciphertext or CSPRNG-filled. No constant filler, no repeated-byte padding, no all-zero probe bodies.

**Interaction the packet has not costed:** if the token window gates sends, a scrubbed probe is not merely a lost probe, it is a credit leak that stalls the gate unless tokens reclaim on timeout. Check the reclaim path. Ship a startup canary pair (one constant-pattern, one random) so the client detects a scrubbed path and logs it instead of failing opaquely.

---

## 5. Most valuable check without the phone PIN

**The token-window BDP check.** No phone, no PIN, no new code, minutes of work, and it either explains the whole plateau or eliminates the top-ranked candidate.

1. Read the engine carrier send path and answer one question: does DefaultTokenWindow gate outstanding carrier sends, or does it only size the receive anti-replay and inbox structure?
2. Measure RTT from this LAN to canada's carrier port, idle and under 400 Mbps load.
3. Re-open the archived per-run logs from the 358 to 445 and 437 to 447 runs, pair each run's throughput with its RTT, and test whether throughput × RTT holds near 11.5 Mbit.

If the product is constant and a send gate exists, the ingress investigation is finished and Round 41 becomes a multi-flow carrier design instead of a pacer.

**Immediate fallback if step 1 shows no send gate:** paced vs bursty randomized UDP from the MacBook to canada:9111 at matched mean rate. Three arms at 470 Mbps mean, 60 s each, 5 interleaved repeats: bursts of 32 to 64 matching the engine batch shape, evenly paced at a 23.8 µs gap, and the current tool default. Repeat at 600. If the bursty arm loses materially more at identical mean rate, burst-induced loss is proven and the Round 41 pacer ships on measurement rather than theory. If the arms are within noise, the pacer is latency-only and PIN recovery becomes the critical path.

---

## VERDICT

**OI-1 (plateau cause and ranking): DISAGREE** with candidate (i) as lead. Falsifiable reason: Mathis at p = 0.06 caps 32 streams of MSS 1400 at 58 Mbps (RTT 25 ms) or 292 Mbps (RTT 5 ms), both below the observed 437, so the inner streams demonstrably do not see the blast loss curve; (iv) leads because 1024 × 1400 B ÷ RTT spans 358 to 445 across RTT 32 to 26 ms and independently predicts the FACT 2 null and the clean FACT 1 counters. Dies if throughput × RTT is not near 11.5 Mbit per run.

**OI-2a (ratify the pacer design): AGREE.** Falsifiable reason: pacing at or above measured drain alters timing only and cannot reduce goodput; flips if the A/B shows inner goodput falling more than 5% with the pacer on at matched offered load.

**OI-2b (pacer recovers inner throughput toward the 600 knee): DISAGREE.** Falsifiable reason: 600 is an open-loop figure measured while accepting 5% loss, and a window-capped sender cannot exceed its BDP regardless of send timing; flips if the paced arm exceeds 550 Mbps inner sustained with under 1% carrier loss.

**OI-2c (ship the pacer as the next change): DISAGREE.** Falsifiable reason: with the window question open, the A/B reads null for the wrong reason and produces a false negative receipt; flips if item 5 step 1 shows no send-side gate.

**OI-3 (1000-up is not achievable from this vantage; owner-report item): AGREE.** Falsifiable reason: the path delivers at most 560 to 580 open-loop at 5% loss and a single 1024-token flow needs sub-11.5 ms RTT to carry 1000; flips if a wired client on this access network delivers over 1000 carrier arrivals at canada at under 0.5% loss.

**OI-4 (scrubber changes v3 probe, keepalive, and cover-traffic assumptions): AGREE.** Falsifiable reason: constant-pattern UDP died near 100% at every tested rate including 150 Mbps, so any non-AEAD constant-payload datagram we ship dies on this path; flips if an audit shows every emitted carrier datagram, MTU probes included, is already sealed or CSPRNG-padded.

**OI-5 (token-window BDP check is the highest-value phone-free next step): AGREE.** Falsifiable reason: it costs one source read plus one RTT measurement and resolves or eliminates the top-ranked cause; flips if the engine source is unavailable or the archived runs carry no per-run RTT, in which case the paced-vs-bursty matched-rate test takes first position.
