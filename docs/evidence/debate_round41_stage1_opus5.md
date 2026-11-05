# Round 41 stage1: claude-opus5

## 1. ROOT CAUSE

**Lead: (b), widened.** The burst did not drop the rekey datagrams specifically. It left the phone's receive path permanently deaf, and the rekey was simply the first exchange after that which required a round trip.

The tell is in your own counters, and it is an asymmetry:

- Phone `rx_packets` FROZEN at 383,255 from 06:13:41 onward, while phone `messages_received` keeps creeping +7/s.
- Gateway `recv` keeps creeping +7/s, and the gateway's own window never had to absorb more than 7,470 datagrams.

Datagrams are arriving at the phone's carrier and being counted, and zero inner packets come out the other side. That is not a dead radio, not a dead peer, and not a lost handshake packet. That is an accept-side filter rejecting everything. The only accept-side filter in the D23 geometry that can latch is the token window.

The direction that carried 398k datagrams at up to 60k pps is exactly the direction that went deaf. The direction that carried 7,470 stayed healthy for the full 52 s afterward. One burst, one deaf window, same side.

Mechanism, stated so it can be killed: 1024 tokens at 60k pps is 17.1 ms of window depth, and reorder tolerance 511 is 8.5 ms. Wi-Fi 7 MLO reorders across links by design, and the depth of that reordering under a 496 Mbps download is not bounded by 8.5 ms. Every time a frame lands past tolerance, force-advance retires the low edge. The defect is that force-advance moves the edge by a window quantum rather than clamping it to the highest counter actually authenticated, so 398k datagrams under MLO reorder walk the low edge past the gateway's real transmit counter and leave it there. The residual fits: gateway delta 397,803 against phone delta 382,665 is 15,138 frames lost inside the burst, which is the force-advance event population, not ordinary loss (ordinary loss at 3.8% on a 6 GHz link at 44k pps average would be visible in the radio counters, and your fallback upload proves the radio is fine).

Everything downstream falls out of that single state:

- Gateway rekey init at 06:14:17 plus its 0.5 to 8 s retry ladder: transmitted, received at the phone's carrier, dropped as replays before reaching the rekey state machine. Gateway's 15 s budget expires, `ErrRekeyFailed`.
- Phone liveness probes: sent fine (gateway `recv` proves the uplink works), responses dropped as replays. Four lost probes at ~20 s spacing lands inside "roughly half a minute typical, eighty seconds worst case." Deafness at 06:13:41 plus 52 s gives 06:14:33. `ErrPeerUnreachable`, exactly as logged.
- The two deaths one second apart are not one event. They are two independent timers, both started by the same 06:13:41 deafness, that happened to expire together.

**Falsification of the lead:** instrument nothing, just read the phone's post-burst drop attribution. If the +7/s arriving datagrams are dropped with a reason other than beyond-window/replay (auth failure, pipe full, decode error), or if the window low edge post-burst sits at or below the gateway's transmit counter, (b) is dead and (d) inherits the lead. Second falsifier: if the phone's `rx_packets` resumes at any point in the 52 s window, the deafness is not latched and the whole model collapses to transient loss, which is (c).

**Ranking of the rest:**

- **(c), dead on arithmetic.** The gate left `StateCarrying` at 06:14:18, which dates the rekey initiation at 06:14:17 plus or minus a second. The burst ended at 06:13:40. The entire retry ladder ran from 06:14:17 to 06:14:32, 37 s of idle keepalive traffic after the burst. No retry attempt was inside the burst window. This candidate should be struck, not ranked.
- **(a), dead on evidence.** A simultaneous rekey collision produces matching rekey errors, or at minimum `ErrRekeyUnconfirmed` on one end. The phone reported `ErrPeerUnreachable`. It never reported a rekey error at all, and its own jittered timer (independent draw, mean 15 min) shows no sign of having fired at 363 s. Only one initiator existed.
- **(d), real as a co-factor, not as root.** The coupling that would make it possible: rekey control frames sharing the single bounded frame pipe with data, with no priority lane, so a full pipe at `DefaultPipeDepth 256` (4.3 ms of buffer at 60k pps) head-of-line blocks the control path. That is a genuine design hazard and the 2026-09-20 revert to 256 makes it worse. But a pipeline stall cannot survive 37 s of idle at +7/s, and it does not explain why `messages_received` advances while `rx_packets` does not. It explains burst-window drops, not post-burst deafness. UNVERIFIED-LIVE: whether rekey frames actually share the data pipe in this tree.
- **(e), one addition that is not in your candidate list and is a separate shipping defect.** Session #19 died in 24 s because "the handshake budget was spent on messages that could not be authenticated (1 datagram)." One stale old-epoch datagram from the phone consumed the entire handshake budget of the replacement session. Even with a perfect rekey fix, that path guarantees the recovery handshake dies whenever the peer is still transmitting on the dead epoch, which is always.

## 2. THE 363 s LIFETIME

One trigger explains it exactly. No second trigger is needed.

- Admitted 06:08:29. Gate leaves `StateCarrying` at 06:14:18, so the rekey timer fired at session second 348.
- 348 plus `DefaultRekeyTimeout` 15 s equals 363, which is 06:14:32, which is the logged `ErrRekeyFailed`. Exact to the second.

348 s clears the 5 min floor by 48 s. It sits low against a mean of 15 min, but that is a single draw from a jittered distribution with a 300 s minimum and 2700 s maximum, and one low draw is not evidence of a second mechanism.

The byte trigger did not fire and cannot have. `DefaultRekeyAfterBytes` is 1<<32, or 4.295 GB. The session moved about 536 MB inner, 12.5% of the threshold.

The tempting inference to reject: yesterday's death was also about 55 s after a burst, so the burst looks like it schedules the death. It does, but not through the rekey timer. The burst schedules the deafness. After deafness, the session dies at whichever round-trip-dependent timer expires first, and both the rekey ladder and the four-probe liveness ladder land in the 50 to 80 s band. That is why two independent runs with independently jittered rekey timers both died about 55 s after a burst, and why the two runs produced two different terminal signatures (`closed` with nil error yesterday, `failed` with `ErrRekeyFailed` today) from one defect family. Burst-correlated timing, no burst-correlated trigger.

Kill this if the recorded scheduled rekey deadline for session #18 is not within a second of 06:14:17.

## 3. THE FALLBACK GAP

The comment at config.go:92-104 describes a design that was never built. The promise is "on rekey expiry the session closes and the fallback is a full handshake." The word doing all the damage is *closes*. A close is not a fallback. The comment assumes a fresh session is observationally equivalent to a continuing one, and that is false at three layers: the frame device closes, the tun is torn down, and the app's inner-router latch is cleared.

**Where the path is missing.** There is no branch anywhere between the rekey timeout and the terminal check that produces a non-terminal outcome. The chain, exactly:

1. Rekey timeout at 15 s maps `ErrRekeyFailed` (config.go:126-136) into a terminal session state rather than a recoverable one.
2. `writeLoop`'s terminal check (driver/loop.go:499-577) sees `StateFailed` and returns the session error, so `loop.Run` exits. Nothing between the drain, `syncGate`, and the terminal check can absorb a rekey failure.
3. The gate latches down on terminal states (driver/doc.go:62), which is why `carrying` reads 0 at 06:14:18 even though the data path was still perfectly capable of carrying on the old epoch.
4. `CloseRekeyFailed` (session/frames.go:46) turns a one-sided timeout into a wire-level close, converting one end's failure into a two-ended teardown.
5. `loop.Run` exiting closes the frame device, which surfaces on the phone as "the frame device is closed; engine stopped unexpectedly; tun torn down."

The spins guard at loop.go is also not a backstop here: it needs 4096 no-progress wakes AND frozen recv, and the +7/s keepalive creep defeats the recv condition permanently. The one mechanism that could have noticed the deafness is disarmed by the exact traffic pattern deafness produces.

**Minimal change, four parts, smallest set that delivers the promised behavior:**

1. **Demote the timeout.** On `RekeyTimeout` expiry, do not enter `StateFailed`. Return a non-terminal rekey-retry outcome that the terminal check in loop.go:499-577 does not treat as terminal. The old epoch keeps carrying. `ErrRekeyFailed` becomes a metric and a log line, not a session error. Schedule a retry with backoff.
2. **Bound it by the epoch, not by the rekey.** Terminal transition happens only when the old epoch hits its own limits: RejectAfterTime, RejectAfterMessages, or nonce exhaustion. That is the real safety boundary, and it is the one the comment implicitly assumed was doing the work. UNVERIFIED-LIVE: whether RejectAfter* limits are actually enforced independently of the rekey timer in this tree. If they are not, they must be added, or the demotion in (1) removes the only bound on epoch age.
3. **Stop broadcasting the failure.** Do not emit `CloseRekeyFailed` on timeout. Reserve it for the case where the old epoch is genuinely unusable. Today, one end's 15 s budget expiring takes down an end that had no complaint.
4. **Make before break.** Start the replacement full handshake in a new epoch while the old epoch still carries, and cut over on the first authenticated data in the new epoch. The driver keeps the same frame device and the same tun across the swap, so the app observes nothing. This is what makes the comment's "adds no new observable" true instead of aspirational.

Two corollaries that are part of the same fix, not separate work:

- **Gate semantics.** The gate must have a Rekeying or Degraded state distinct from leaving `StateCarrying`. Today `carrying` drops to 0 the moment a rekey begins, which means the gateway's primary health counter lies about a session that is carrying fine, and it lied for 14 s before anything was actually wrong.
- **Handshake budget.** Unauthenticatable datagrams must not decrement the new session's handshake budget (the cmd/winn3-gateway admit path). Session #19 was killed by one of them. Count only well-formed handshake messages against the budget, and rate-limit garbage separately.

**Underneath all of it, the window fix,** without which the fallback just gives you a longer-lived deaf session: clamp force-advance so the low edge can never move ahead of the highest counter actually authenticated, and size `DefaultTokenWindow` to the real peak rate rather than to 17 ms of it. 1024 tokens against 60k pps on a reordering MLO link is not a window, it is a coin flip. Scale it to seconds of peak pps and keep reorder tolerance proportional.

## 4. THE APP BUG

`latchedInnerRouterV4` is armed only as a side effect of the staged-start path, via `WinnV3SessionPlan.innerNextHopOf`, and cleared unconditionally at teardown. The engine-initiated death drove teardown (clearing the latch) and then a reconnect that did not traverse the staged path, so nothing re-armed it. The ingest bind then saw `latched=null` and refused the primary target at port 8455. The latch is not broken; it is owned by one code path out of two.

**Minimal fix.** Make the latch a derived property of the active plan rather than a side effect of one start path. Compute it in the single callback that every path traverses on the transition into carrying:

```
latchedInnerRouterV4 = plan.innerNextHopOf()   // on every transition to StateCarrying
```

Then remove the unconditional clear at teardown, or narrow it to the case where a new plan supplies a different inner next hop. Keeping the clear while the arm lives on only one path is precisely the asymmetry that produced null.

The structural half of the fix matters more than the line: make the field private and settable only through that one arming function, so a future reconnect path cannot reach carrying without arming it. A fix that only adds a second call site leaves the third one waiting.

**Test that pins it.** An instrumented service test, not a unit test, because the bug lives in the path taken rather than in any function:

1. Start via the staged path. Assert `latchedInnerRouterV4 == 10.10.0.1`.
2. Inject an engine terminal failure (`ErrPeerUnreachable`) to force the real teardown and reconnect chain, not a synthetic restart.
3. Wait for the new session to reach carrying.
4. Assert `latchedInnerRouterV4 == 10.10.0.1`, not null.
5. Assert the ingest bind to port 8455 resolves to the latched router and succeeds.

Add a second, cheaper test that enumerates every transition into carrying and asserts each one passes through the arming function. That is the test that catches reconnect path number three when someone adds it.

## 5. SEVERITY AND ORDER

The tunnel-death fix ships first, and the 1000-up work should not merge until it does. The throughput work raises a ceiling on a path that destroys itself the first time it approaches the current ceiling, so the number it is trying to produce is not measurable today: a 496 Mbps burst killed this session about 52 s later, and the app then refused the speedtest primary target, which means the very instrument you would use to validate 1000-up is the instrument that triggers the defect. Worse, the two work items point in opposite directions on the same mechanism. Higher throughput means higher pps against the same 1024-token window, and 17 ms of window depth at 60k pps becomes 8 ms at 120k pps, so the throughput work makes the force-advance defect fire harder and sooner. The failure is also not self-limiting: the replacement session died in 24 s to a single unauthenticatable datagram, and the app lost its ingest latch, so the user's observable outcome is a dead tunnel, a failed reconnect, and a refused primary, with the traffic silently riding the physical route as your fallback upload showed. Ordering the throughput work first would mean tuning a path whose failure mode invalidates every measurement taken on it.

## 6. NEXT

**One check: read the phone's receive-window state and drop attribution at burst plus 25 s, with no code shipped.**

Run the speedtest download leg to reproduce the burst. Then, at 20 to 30 s after the burst ends and before any timer kills the session, send a known-count series of inner packets through the tunnel (a fixed number of pings to the inner router is enough) and capture, from the existing debug build's `winn3-debug` output and posture counters:

1. Phone `messages_received` delta. Expect it to increment 1:1 with arrivals.
2. Phone `rx_packets` delta. Expect zero.
3. Phone token-window low edge and high edge. Expect the low edge to exceed the gateway's current transmit counter.
4. The drop-reason attribution for the arrivals. Expect beyond-window/replay.

That single observation separates the lead from every other candidate in one shot. Confirmed if items 1 through 4 hold. Dead if the drops are attributed to auth failure or pipe pressure, which promotes (d), or if `rx_packets` moves at all, which demotes everything to transient loss and revives (c). It also directly measures the overshoot magnitude, which is the number the window fix has to be sized against.

UNVERIFIED-LIVE: whether the v1.0.16 debug build already exports the window edges and drop-reason breakdown. If it exports the counters but not the edges, the fallback form of the same check is the counter comparison alone (items 1, 2, 4), which still separates deafness from loss, just without the overshoot magnitude.

---

## VERDICT

1. **ROOT CAUSE: DISAGREE with (b) as worded, AGREE with its mechanism widened.** The packet's (b) claims the rekey datagrams specifically fell outside the window; the evidence supports the stronger claim that every datagram after 06:13:41 did, with the rekey merely being the first exchange that needed a reply. Falsified if the phone's post-burst arrivals are dropped for any reason other than beyond-window/replay, or if the low edge does not exceed the gateway's transmit counter, in which case (d) leads.

2. **363 s LIFETIME: AGREE, one trigger, exactly.** 348 s jittered fire plus 15 s timeout equals 363 s equals 06:14:32, and `RekeyAfterBytes` at 4.295 GB was never approached with 536 MB moved. Falsified if the recorded scheduled rekey deadline for session #18 is not within one second of 06:14:17.

3. **FALLBACK GAP: AGREE.** The timeout maps to a terminal state that loop.go:499-577 propagates and driver/doc.go:62 latches, with no non-terminal branch anywhere in between, and `CloseRekeyFailed` exports the failure to the peer. Falsified if a recoverable rekey-timeout branch already exists ahead of the terminal check, in which case the defect is that branch failing to engage rather than being absent.

4. **APP BUG: AGREE.** The latch is armed only in the staged-start path and cleared unconditionally at teardown, so an engine-initiated reconnect on any other path yields null. Falsified if the reconnect did traverse `innerNextHopOf` and still produced null, which would relocate the fault into inner next hop resolution on the replacement plan.

5. **SEVERITY AND ORDER: AGREE, tunnel-death first.** The throughput work increases pps against the same 1024-token window and therefore worsens the defect, and no 1000-up measurement is valid on a path that dies about 52 s after a 496 Mbps burst. Falsified if the 1000-up work already includes the token-window resize, in which case the two items merge rather than order.

6. **NEXT: AGREE.** The post-burst window-edge and drop-reason read is the only check that distinguishes "delivered but rejected" from "not delivered" and from "pipe stalled" in a single observation. Falsified if the v1.0.16 debug build exports neither the window edges nor drop-reason attribution, in which case this check requires shipping code and the item fails as stated.
