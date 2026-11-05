# Round 41 stage1: agy

# Presidential Council Debate Round 41: Independent Stage 1 Verdict
Podium: Seat 1 (Antigravity, Gemini 3.8 Flash High)
Topic: Tunnel-Death Defect and Rekey Failure Analysis

### 1. Root Cause Ranking

- **Rank 1 (Lead: Candidate d)**: The primary root cause is a post-burst stall in the phone engine writeLoop coupled with queue backpressure. Telemetry records that the gateway sent 398,375 messages while the phone accepted 383,255 inner packets, after which rx_packets froze completely. In `winn3/driver/loop.go`, writeLoop entered a zero-progress spin where keepalive creep (+7/s) defeated the 4096-wake guard that produced yesterday's clean exit (`state=closed err=<nil>`). When the gateway initiated in-band rekey at session second 348, the phone's wedged pipeline could not process the exchange within the 15-second budget.
- **Rank 2 (Candidate b)**: Replay window force-advance drop. D23 geometry defines DefaultTokenWindow as 1024 packets. The download burst ended at session second 311, whereas the gateway initiated rekey at session second 348 (06:14:17). By session second 348, the carrier channel had settled into an idle state where keepalives creeping at +7/s were successfully accepted by both endpoints. Candidate (b) is therefore rejected as the primary initiator.
- **Rank 3 (Candidate c)**: Retry ladder window capture. The 5-attempt retry ladder spans 15.5 seconds with exponential backoff from 0.5 s to 8 s. Because the rekey exchange started at session second 348, exactly 37 seconds after the burst ended at second 311, the entire retry sequence executed during post-burst idle keepalive exchange. Ordinary burst loss did not consume the retry budget. This timing sequence falsifies candidate (c).
- **Rank 4 (Candidate a)**: Simultaneous rekey collision. If both peers initiated rekey concurrently without handling glare, both peers would log `in-band rekey did not complete` or `CloseRekeyFailed`. Gateway telemetry logged `err=winn3/session: in-band rekey did not complete`, whereas the phone engine logged `err=winn3/session: peer did not answer liveness probes`. The phone never initiated rekey. The asymmetric error logs falsify candidate (a).
- **Falsification for Lead**: Trigger an in-band rekey exchange on an established idle session that has experienced no preceding burst. If the idle rekey succeeds, candidate (a) and general rekey protocol bugs are eliminated. If a subsequent test injects a burst that halts rx_packets and causes the next rekey to fail after 15 seconds, candidate (d) is confirmed.

### 2. The 363 s Lifetime

- **Mathematical derivation**: The 363-second lifetime is explained by the jittered time trigger plus the 15-second timeout, without requiring any secondary trigger. Session admission occurred at 06:08:29. Configuration specifies DefaultRekeyIntervalMin as 5 minutes (300 seconds), Mean 15 minutes, and Max 45 minutes. A pseudo-random draw of 348 seconds (5 minutes 48 seconds) scheduled the rekey at 06:14:17. At 06:14:18 (session second 349), gateway carrying dropped from 1 to 0 when the session gate left StateCarrying, and 14 seconds later DefaultRekeyTimeout marked the session failed.
- **Evaluation of secondary triggers**: The byte threshold in config.go is DefaultRekeyAfterBytes at 1<<32 (4 GiB). The 8-second burst transferred approximately 536 MB of payload, reaching only 12.5% of the 4 GiB volume limit. Byte volume could not have tripped the rekey. The burst merely crippled the phone's processing pipeline, creating a latent failure that triggered when the timer fired at second 348.

### 3. The Fallback Gap

- **Broken code path**: The defect resides in `winn3/driver/loop.go:499-577` and `session/frames.go:46`. When an in-band rekey exceeds DefaultRekeyTimeout (15 s), the session loop emits ErrRekeyFailed and transitions the driver gate to StateFailed. The writeLoop treats StateFailed as terminal, calls `Loop.Close()`, tears down the carrier socket, and closes the TUN frame device. The design comment in `winn3/session/config.go:92-104` promised that rekey expiry would fall back to a full handshake with no new observable, but the implementation terminates the transport immediately.
- **Minimal fix**:
  1. Decouple rekey timeout from session teardown by preventing DefaultRekeyTimeout expiration from setting StateFailed or calling Loop.Close.
  2. Maintain the active session in StateCarrying, continuing payload encryption and decryption on the current key epoch until reaching hard RejectAfter thresholds.
  3. Spawn an asynchronous out-of-band full handshake over the existing transport to negotiate a fresh session epoch.
  4. Atomically swap cipher states and reset token windows upon handshake completion, keeping TUN packet processing and the application routing latch uninterrupted.

### 4. The App Bug

- **Root cause in application**: VpnTunnelService stores `latchedInnerRouterV4`, which is initialized during staged startup via `WinnV3SessionPlan.innerNextHopOf` and cleared on teardown. When the engine terminated unexpectedly due to the closed frame device, teardown executed and set `latchedInnerRouterV4` to null. The subsequent automatic reconnect followed a recovery path that started the engine without re-running the staged session plan, leaving `latchedInnerRouterV4` unassigned. The speedtest ingest upload then refused connection because no inner router was latched.
- **Minimal fix**: Require `VpnTunnelService` to re-arm `latchedInnerRouterV4` via `innerNextHopOf` before declaring the tunnel connected during any reconnect sequence. Guard teardown cleanup with a session generation counter so an asynchronous teardown from a prior dead session cannot overwrite the latch of an active session.
- **Pinning test**: Create an instrumentation test in `android/app` that simulates an engine crash by closing the frame device. The test verifies that the reconnect sequence invokes the staged planning path, re-establishes `latchedInnerRouterV4` with `10.10.0.1`, and validates that speedtest ingest accepts the latched gateway.

### 5. Severity and Order

The tunnel-death defect must ship before any 1000-up throughput work. A VPN client that drops its transport connection five minutes after a traffic burst and fails to recover its routing latch makes speed optimizations completely unusable. In high-threat environments, an unexpected tunnel teardown that leaks traffic onto physical interfaces creates an unacceptable security risk for users. Sustained throughput testing cannot produce valid data on an engine that dies at its first rekey window. Stabilizing rekey fallback and reconnect latching is the prerequisite for all downstream performance tuning.

### 6. Next Diagnostic Action

- **Single most valuable live check**: Stream live logcat output on the physical device during a post-burst window, filtering for `winn3-debug`, `driver.writeLoop`, and `VpnTunnelService` without modifying code. Observe writeLoop spin counts, queue occupancy, and `rx_packets` immediately after the 8-second download burst stops. Verifying that writeLoop enters a no-progress spin while carrier keepalives continue to increment confirms the pipeline stall directly from operational telemetry.

### 7. Verdict

- **Item 1**: AGREE. Burst-induced writeLoop stall (candidate d) is the only explanation consistent with the 37-second post-burst delay, frozen rx_packets, keepalive creep defeating the spins guard, and asymmetric error logs.
- **Item 2**: AGREE. The 363-second timestamp matches the 5-minute minimum jittered interval firing at second 348 plus the 15-second timeout, while 536 MB transferred remains far below the 4 GiB byte trigger.
- **Item 3**: AGREE. Rekey fallback is broken in `winn3/driver/loop.go` where ErrRekeyFailed forces terminal StateFailed and closes the frame device, rather than maintaining the old epoch and initiating an out-of-band full handshake.
- **Item 4**: AGREE. Reconnect produces `latched=null` because the auto-reconnect flow bypasses staged `innerNextHopOf` initialization after teardown nulls the reference, which must be guarded and verified with a crash-reconnect test.
- **Item 5**: AGREE. Connection persistence and routing safety take strict precedence over throughput tuning, as high transfer speeds cannot function on an unstable transport.
- **Item 6**: AGREE. Monitoring writeLoop spin counters and packet metrics via live logcat during a post-burst window provides immediate non-invasive verification of the lead root cause.
