# Round 41 stage1: solpro

1. **Root cause**

The packet does not prove a single mechanism because it lacks rekey attempt timestamps, nonce values, receive-window edges, and replay decisions. My provisional ranking is:

1. **Rank 1, candidate (b): rekey datagram aged out of the token window**

   At 60,000 packets/s, a 1,024-token window spans only:

   `1,024 / 60,000 = 0.0171 s`, or 17.1 ms.

   The 511-token reorder tolerance spans:

   `511 / 60,000 = 0.00852 s`, or 8.52 ms.

   Even at the observed average, `(398,375 - 572) / 9 = 44,200` messages/s, 1,024 tokens represent 23.2 ms. A rekey message on that nonce stream can therefore become older than the low edge after 17 to 23 ms of overtaking traffic. D23 then classifies it as replay traffic. That directly connects the measured rate, the 1,024-token geometry, and the stated replay behavior.

   The counter increases were 397,803 gateway messages and 382,665 phone frame packets, a difference of 15,138. That is not a measured loss rate because the counters have different names and may count different objects, but it does show that the supplied counters cannot prove one-for-one delivery.

   Timing limits confidence. A rekey started during session seconds 302 to 311 would exhaust a fixed 15 s budget at seconds 317 to 326. The carrying gate dropped at second 349 and the error was logged at second 363. Candidate (b) therefore also needs delayed rekey scheduling, delayed terminal observation, or stale retransmission of the original token.

   Falsification: candidate (b) is false if a synchronized trace shows every rekey message arriving within the then-current 1,024-token window, passing replay and authentication checks, and still timing out.

2. **Rank 2, candidate (d): frame-side backpressure starved session control**

   The required coupling is serialization of rekey control behind frame work in the same driver loop, bounded pipe, or `syncGate`. At 60,000 arrivals/s, a depth-256 pipe represents only `256 / 60,000 = 4.27 ms` of arrivals if its consumer stops. The supplied `writeLoop` facts also say its 4,096-wake guard does not fire while keepalives advance receive posture, matching the observed keepalive creep.

   The packet does not show pipe occupancy, a blocked `syncGate`, or that phone receive dispatch serializes control behind frame delivery. Candidate (d) is therefore possible but unproved. It is false if control dispatch and frame delivery use independent queues and the control handler continued running throughout the burst.

3. **Rank 3, candidate (c): ordinary loss consumed every retry**

   If an initial send counts as attempt one, retries at 0.5, 1.5, 3.5, and 7.5 s all fit inside an 8 s burst. If the stated ladder instead includes waits of 0.5, 1, 2, 4, and 8 s, its span is 15.5 s and cannot fit inside 8 s. The packet does not define which counting convention applies.

   The later terminal timestamps also require the exchange to have started after the burst or to have been delayed. No ordinary datagram-loss measurement is supplied, so candidate (c) ranks below the deterministic token-window hazard.

4. **Rank 4, candidate (a): simultaneous initiators**

   Both peers began the session together, but the packet supplies neither their selected jitter values nor their initiator roles. No collision log is present. A probability cannot be calculated because the jitter distribution and collision interval are not given. This candidate is false if only one side entered initiator state.

5. **Rank 5, candidate (e): epoch-commit divergence unrelated to window loss**

   `ErrRekeyUnconfirmed` exists for local commit without peer confirmation, but the observed gateway error was `ErrRekeyFailed`. Session #19's one unauthenticated datagram happened after the original session had failed, so its timestamp makes it evidence of broken recovery rather than the initiating cause.

2. **The 363 s lifetime**

No second trigger is mathematically required.

Admission at 06:08:29 and the logged failure at 06:14:32 differ by 363 s. A timer firing at session second 348 followed by the 15 s timeout gives:

`348 + 15 = 363`.

Second 348 is permitted because the rekey interval starts at 300 s and can extend to 2,700 s.

The carrying transition gives a second interpretation. Carrying dropped at 06:14:18, session second 349. If that transition marks timeout, initiation was approximately:

`349 - 15 = 334`.

Second 334 is also permitted. The 14 s difference between the gate transition and the logged `writeLoop` failure means the packet cannot identify which timestamp is the actual timeout boundary.

The burst occupied seconds 302 to 311. A rekey fired in that interval would expire at seconds 317 to 326, which is 23 to 32 s before the gate drop and 37 to 46 s before the log. Thus the lifetime fits an ordinary interval plus timeout exactly, but it does not by itself prove that the rekey exchange overlapped the burst. No byte trigger, liveness trigger, or second rekey trigger is required by the arithmetic.

3. **The fallback gap**

The broken path established by the packet is:

`rekey expiry -> StateFailed with ErrRekeyFailed -> driver.writeLoop terminal branch at loop.go:499-577 returns the session error -> loop.Run exits failed -> Loop.Close -> carrying gate latches down`.

The logs record that sequence on the gateway. The phone then reports `ErrPeerUnreachable` 15 s after the gateway carrying transition and tears down its frame device and TUN.

A full handshake is not entirely absent because session #19 was admitted after session #18 closed. What is absent is make-before-break replacement. The shipped path closes session #18 before #19 becomes carrying, exposing the failure to the data plane and application. That contradicts the comment's promise of no new observable.

The smallest behaviorally sufficient change is:

1. Treat `ErrRekeyFailed` and `ErrRekeyUnconfirmed` as recoverable rollover events at the session owner, not immediate driver-fatal events.
2. Keep the old epoch carrying only until its existing `RejectAfter*` limits.
3. Start a fresh full handshake in parallel.
4. Keep the TUN, frame device, route owner, and application state alive.
5. Atomically switch frame routing when the replacement reaches `StateCarrying`.
6. Buffer inner packets if the old epoch reaches `RejectAfter*` before replacement completes, because closing or rejecting them would violate the requested no-drop behavior.
7. Retire the old session only after the replacement is carrying.

Changing `StateFailed` to `StateClosed` or suppressing the returned error is insufficient: either action still reaches `Loop.Close` unless ownership and replacement sequencing also change.

The packet does not identify the internal function that converts rekey timeout into `StateFailed`, so that source location cannot be named from the supplied facts. The exact exposed fatal branch is `winn3/driver/loop.go:499-577`.

4. **The app bug**

The lifecycle is sufficient to identify the defect:

1. Staged start assigns `latchedInnerRouterV4` from `WinnV3SessionPlan.innerNextHopOf`.
2. Teardown clears the latch.
3. Reconnect reached ingest with `router=10.10.0.1 latched=null`.
4. Therefore the reconnect path did not successfully rerun the staged assignment before port 8455 ingest.

The packet does not identify whether reconnect selected a non-staged branch or whether staged planning returned without assignment. The minimal safe fix is to assign the latch in the common successful plan-activation path used by both initial start and reconnect, before ingest can run. It should be recomputed from the replacement `WinnV3SessionPlan`, rather than preserving a possibly stale router indefinitely. Clearing should occur on final VPN-service shutdown, or transient teardown must be followed by reassignment before traffic resumes.

The pinning test should:

1. Activate a plan whose `innerNextHopOf` is `10.10.0.1`.
2. Assert the latch is `10.10.0.1`.
3. Inject `ErrRekeyFailed` through the production reconnect path.
4. Complete replacement activation.
5. Before opening ingest port 8455, assert the latch again equals `10.10.0.1`.
6. Send an ingest request and assert it selects the inner router rather than returning `latched=null`.
7. Stop the VPN service finally and assert the latch is then cleared.

That test fails on the reproduced sequence because ingest observed `latched=null`.

5. **Severity and order**

The tunnel-death and recovery fix ships before the 1000-up throughput work. The reproduced session accepted about 536 MB during download, then lost carrying state, tore down the TUN, and refused the primary upload because the latch was null. The physical route subsequently delivered 2,624 to 2,895 Mbps with 32 of 32 HTTP 200 responses twice, proving that high physical uplink capacity did not restore the tunnel path. Throughput work cannot satisfy the primary upload case while the tunnel and router latch are absent, so recovery is a functional prerequisite for measuring or shipping tunnel upload gains.

6. **Next live check**

UNVERIFIED-LIVE: collect one synchronized rekey trace at the gateway sender and phone session receiver during the same burst. For each rekey request and response, record send time, receive time, nonce or token, current receive-window low edge, replay decision, authentication result, retry number, and initiator role. This single trace distinguishes the leading candidates: a token below the low edge confirms (b), a timely in-window message blocked behind frame processing supports (d), missing arrivals support (c), and simultaneous initiator states support (a). No production binary needs to ship if the existing debug build or attached debugger can expose those fields.

VERDICT:

1. **AGREE:** Candidate (b) is the provisional lead because a 1,024-token window lasts only 17.1 ms at 60,000 packets/s; an in-window trace with no replay rejection falsifies it.
2. **AGREE:** No second trigger is required because `348 + 15 = 363`; a recorded deadline outside the permitted interval would falsify that explanation.
3. **DISAGREE:** The shipped path does not deliver the promised invisible fallback because session #18 closes before #19 is carrying; a test preserving carrying state, TUN ownership, and inner packets through replacement would falsify this finding.
4. **AGREE:** The latch lifecycle is defective because reconnect reached port 8455 with `latched=null`; a production-path test showing reassignment before ingest would falsify it.
5. **AGREE:** Recovery ships before throughput because the measured physical 2,624 to 2,895 Mbps could not serve the refused tunnel target; a controlled rekey test that preserves the primary upload path would remove that ordering basis.
6. **AGREE:** The synchronized nonce and window trace is the highest-value check because it directly observes the discriminator for all four named mechanisms; a trace lacking token, window, replay, and role fields would not perform that discrimination.
