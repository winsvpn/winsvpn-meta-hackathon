# Turn 2 Submission: claude-opus5

# Turn 2 Cross-Examination: claude-opus5

## 1. Steelmanning the Peer Podiums

- **Podium 1 (agy) strongest point: the arithmetic identity between clamp width and measured plateau is not a coincidence that can be waved away.** agy computed that a 96 KiB effective window over 32 streams at 65 ms yields 378.2 Mbps, and Sol Pro independently computed 387.167 Mbps for 98,304 bytes and 403.298 Mbps for 102,400 bytes. The Run 18 band of 366 to 401 Mbps sits inside that bracket with no fitting parameters. My Turn 1 objection was that ~95 KiB is not a canonical default and therefore indicates active autotuning rather than a static clamp. agy's implicit rebuttal is stronger than I credited: autotuning that has converged to a low fixed point is observationally identical to a clamp, and `tcp_wmem[1]` on Android is commonly 16 KiB with growth gated by `sk_sndbuf` doubling against measured `rcv_space`. A converged-low autotuner is exactly what an explicit `SO_SNDBUF` request overrides. The window-limited hypothesis survives my objection.

- **Podium 1 strongest point on OI-2: promotion invalidates the descriptor identity, not just its contents.** agy noted that `Builder.establish()` on a staged promotion returns a distinct open file description (bootstrap fd 84, promoted fd 102). Any descriptor the Go engine adopted at bootstrap references the pre-promotion file description, which becomes a dead tunnel after promotion. This is a sharper objection than the freeze-invariant argument alone, because it means the handover would need a second handover, plus a barrier, plus a quiesce, all before the first byte of a speedtest. Stage D cannot absorb that.

- **Podium 3 (Sol Pro) strongest point: `SO_SNDBUF` does not expand `cwnd`, and the slow-start timeline proves the ceiling is sustained rather than transient.** Sol Pro computed that reaching 253,906 bytes in flight from an IW of roughly 13,330 bytes needs 19.05x growth, achievable in five lossless doublings at 325 ms, well inside an 8 second window. That is the single most useful piece of reasoning produced in Turn 1, because it splits the hypothesis space cleanly. If the plateau were slow-start limited it would clear in under half a second. It does not clear. Therefore the binding constraint is a standing ceiling: send buffer, receive window, or loss. Sol Pro's demand for `TCP_INFO` readback (`snd_wnd`, `notsent_bytes`, `rcv_space`) is the correct discriminator among those three, and `notsent_bytes` near zero with `snd_cwnd` pinned is the specific signature that falsifies the send-buffer theory.

- **Podium 3 strongest point on OI-3: the `oldCount == 0` wake must be retained.** My Turn 1 position proposed removing it to force accumulation. Sol Pro's counter is decisive and I concede it: a consumer sleeping on an empty ring has no running park timer, so with the zero-transition wake removed the consumer never enters the timed-park state and packets sit until some unrelated wake occurs. The park deadline is only armed after a wake. Removing the arming condition removes the deadline. My proposal was wrong.

- **Podium 3 strongest point on instrumentation discipline: the 2.416 ratio is measured at the wrong boundary.** Sol Pro refused to attribute the carrier packets-per-call ratio to `txDrainGate` without a `popBatch` length histogram, a wake-reason counter, and a GSO segment counter. This converges with my own Turn 1 finding that 711,887 calls over 8 seconds gives an 11.238 µs mean inter-call interval, which is 22x shorter than the 250 µs park ceiling. Both of us reached the same conclusion from different directions: the park timer is not the dominant wake path during the active phase.

## 2. First-Principles Arithmetic

### 2.1 Reconciling the park-timer interval against the batch ratio

The synthesis asserts the reader was "timing out on the 250 µs timer with only ~2.4 packets accumulated." Test this directly.

If every carrier call were preceded by a 250 µs park expiry, the maximum call rate is:

```
1 / 0.000250 = 4,000 calls/second
```

Observed call rate:

```
711,887 / 8.0 = 88,985.875 calls/second
```

Ratio:

```
88,985.875 / 4,000 = 22.246
```

The observed call rate exceeds the park-expiry ceiling by 22.25x. Therefore at most:

```
4,000 / 88,985.875 = 4.495% of calls
```

can be park-expiry wakes. The remaining 95.5% are threshold or zero-transition wakes. The synthesis statement in finding 3 is arithmetically false as a causal account of the 2.41 ratio.

The consistent account: `oldCount == 0` fires on nearly every push because the consumer drains faster than the producer fills. Mean inter-call interval 11.238 µs times 2.41597 packets per call gives a producer inter-arrival of:

```
11.238 / 2.41597 = 4.652 µs/packet
```

which is 214,987 packets/second at the ring boundary. At 1,373 bytes that is 2.362 Gbps, which exceeds the 401 Mbps uplink by 5.89x. Either the counter spans downlink ACK traffic and both test phases, or it counts post-segmentation units. Sol Pro flagged exactly this. Neither `lowWater` nor `maxPark` can be calibrated against a ratio whose denominator is unidentified.

### 2.2 Recomputing the `lowWater = 16` claim on correct premises

Accept the smooth-arrival model for the moment. Per-packet interval at 1 Gbps:

```
1,373 * 8 / 1,000,000,000 = 10.984 µs
```

Accumulation times:

```
16 packets: 16 * 10.984 = 175.744 µs
32 packets: 32 * 10.984 = 351.488 µs
```

At 401 Mbps, interval is 27.391 µs:

```
16 packets: 438.256 µs   (exceeds 250 µs park)
32 packets: 876.512 µs   (exceeds 250 µs park)
```

So `lowWater = 16` is reached before the deadline at 1 Gbps but not at the current 401 Mbps. The change is forward-looking, not corrective of the present state. At 401 Mbps the park still expires first, yielding:

```
250 / 27.391 = 9.127 packets per park expiry
```

That is 3.78x better than the observed 2.41, which is itself evidence that park expiry is not the current wake path (as proven in 2.1). The recalibration is harmless and directionally correct. It is not the mechanism that lifts 401 Mbps to 1 Gbps.

### 2.3 Downlink ACK delay under `lowWater = 16`

This is the arithmetic that decides my OI-4 vote. The transmit ring carries uplink data packets and downlink-phase TCP ACKs on the same path.

Downlink sustained rate 675 Mbps, segment size 1,373 bytes, one ACK per two segments (standard delayed-ACK):

```
segments/s = 675,000,000 / (1,373 * 8) = 61,453.0
ACKs/s     = 61,453.0 / 2 = 30,726.5
ACK interval = 1 / 30,726.5 = 32.55 µs
```

Time to accumulate `lowWater = 16` ACKs:

```
16 * 32.55 = 520.8 µs
```

That exceeds `maxPark = 250 µs`, so the park deadline binds and the realized worst-case ACK delay is 250 µs, not 520.8 µs. With `lowWater = 32` the same bound applies. So the bound is unchanged by the `lowWater` edit.

Magnitude of the 250 µs delay against the path:

```
250 µs / 65,000 µs = 0.3846% of RTT
```

Effect on measured RTT as seen by the downlink sender:

```
65.000 ms -> 65.250 ms
```

Slow-start doublings to reach a 675 Mbps window:

```
BDP_down = 84,375,000 * 0.065 = 5,484,375 bytes
IW = 10 * 1,373 = 13,730 bytes
doublings = log2(5,484,375 / 13,730) = log2(399.4) = 8.643 -> 9
time at 65.000 ms RTT: 9 * 65.000 = 585.00 ms
time at 65.250 ms RTT: 9 * 65.250 = 587.25 ms
delta = 2.25 ms
```

Steady-state throughput penalty from RTT inflation alone:

```
65.000 / 65.250 = 0.99617  ->  0.383% reduction
675 Mbps * 0.99617 = 672.42 Mbps
```

So the downlink datapath code is frozen, but the downlink observable is shifted by 0.383% in steady state and 2.25 ms in ramp. This is small. It is not zero. My Turn 1 DISAGREE on OI-4 rested on this. I reassess below.

### 2.4 Send buffer sizing and bufferbloat bound

Linux doubles the `SO_SNDBUF` request for skb overhead accounting. A request of 1,048,576 yields a reported 2,097,152 with usable payload capacity near the requested figure. Standing queue if all 32 sockets fill:

```
32 * 1,048,576 = 33,554,432 bytes usable
drain at 125,000,000 bytes/s = 268.4 ms
```

Compared against per-stream BDP:

```
1,048,576 / 253,906.25 = 4.130x
```

The 4.13x figure is correct but it is a headroom ratio, not a safety property. A CUBIC sender will fill the buffer only as far as `cwnd` permits, and `cwnd` is bounded by loss and by the receiver window, not by `SO_SNDBUF`. `SO_SNDBUF` sets a ceiling, not a target. Therefore the 268.4 ms figure is a worst case that requires 32 senders each having grown `cwnd` to 1 MiB, which requires the path to actually sustain 4.13 Gbps. It cannot. The bufferbloat objection I raised in Turn 1 is bounded by `cwnd`, not by `SO_SNDBUF`, and I withdraw it.

A tighter alternative exists. Requesting 393,216 bytes (384 KiB) gives:

```
393,216 / 253,906.25 = 1.549x headroom
32 * 393,216 = 12,582,912 bytes  ->  100.7 ms max standing queue
```

This is sufficient for the 32-stream case and bounds the queue at 100.7 ms. However 1 MiB is the safer choice across stream-count changes: at 8 streams the requirement is 1,015,625 bytes and 384 KiB would be a hard clamp at:

```
8 * 393,216 * 8 / 0.065 = 387.2 Mbps
```

which reproduces the exact failure being fixed. I therefore accept 1,048,576 as the correct value for robustness against concurrency changes.

### 2.5 The loss-rate bound that the plateau also satisfies

The window hypothesis and the loss hypothesis both reproduce 401 Mbps. Reno square-root bound, per stream at 12.53 Mbps, MSS 1,321 bytes, RTT 65 ms:

```
cwnd = 12,530,000 * 0.065 / 8 / 1,321 = 77.05 segments
p = (1.22 / 77.05)^2 = 2.507e-4  ->  1 loss per 3,989 packets
```

Total uplink packets in an 8 second 401 Mbps run:

```
401,000,000 * 8 / (1,321 * 8) = 303,558 packets
expected losses = 303,558 * 2.507e-4 = 76.1
```

76 losses across 303,558 packets is invisible to any counter that reports zero at integer aggregation across the outer tunnel, because the outer tunnel does not carry inner TCP retransmit state. The two hypotheses are not distinguishable from the data in the docket. They are distinguishable by one read: `tx_dropped` on `tun0` in `/proc/net/dev`, and `TCP_INFO.tcpi_total_retrans` summed across the 32 sockets. The docket cites `tun1` counters with zero drops but does not cite `tun0` during the upload phase.

This does not block OI-1. Setting `SO_SNDBUF` is correct under the window hypothesis and neutral under the loss hypothesis, since `cwnd` remains loss-bounded and the larger ceiling is simply unused. It does mean the predicted outcome must be stated as a falsifiable threshold rather than an expectation.

## 3. Exact Surgical Code Diffs

### Diff 1: upload worker send buffer plus readback verification

```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt
@@ -1527,8 +1527,20 @@ class MainActivity : FlutterActivity() {
                         try {
                             windowStart.compareAndSet(0L, System.nanoTime())
                             socket = java.net.Socket()
+                            // Round 46 OI-1: 1 Gbps at 65 ms RTT needs
+                            // 8,125,000 B in flight; 8,125,000 / 32 =
+                            // 253,906 B per stream. Must be set before
+                            // connect() so the window-scale option is
+                            // negotiated in the SYN.
+                            socket.sendBufferSize = 1048576
                             socket.tcpNoDelay = true
+                            if (workerIndex == 0) {
+                                android.util.Log.i(
+                                    "WinnUpload",
+                                    "sndbuf_req=1048576 " +
+                                    "sndbuf_eff=${socket.sendBufferSize}"
+                                )
+                            }
                             // Round 39 convergence (opus): a node whose
                             // firewall DROPs (rather than rejects) the ingest
```

The readback line is mandatory. `net.core.wmem_max` on Android is frequently 4,194,304 but is vendor-configurable and can be lower than the request. Without the readback the patch has no way to report that the kernel clamped it, and the whole OI-1 arithmetic would be invalidated silently.

### Diff 2: `lowWater` recalibration only, `maxPark` retained

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
@@ -8,8 +8,12 @@ import (
 
 const (
 	winn3RingPushBatch = 512
 	winn3RingPopBatch  = 256
-	winn3DrainLowWater = 32
+	// Round 46 OI-3: at 1 Gbps the inner packet interval is 10.984 us,
+	// so 32 packets need 351.49 us and can never be reached inside the
+	// 250 us park deadline. 16 packets need 175.74 us.
+	winn3DrainLowWater = 16
 	winn3DrainMaxPark  = 250 * time.Microsecond
 )
```

`maxPark` stays at 250 µs. Lowering it to 50 µs, as agy proposed, yields at 1 Gbps:

```
50 / 10.984 = 4.552 packets per park expiry
```

which is below the current 2.41-to-16 improvement target and moves occupancy in the wrong direction. Sol Pro's arithmetic on this is correct and agy's Diff 2 second line should be dropped.

### Diff 3: signal condition, threshold-crossing edge only

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
@@
 	newCount := oldCount + n
-	if oldCount == 0 || newCount >= r.lowWater {
+	if oldCount == 0 || (oldCount < r.lowWater && newCount >= r.lowWater) {
 		r.signalNotify()
 	}
@@
 	newCount := oldCount + 1
-	if oldCount == 0 || newCount >= r.lowWater {
+	if oldCount == 0 || (oldCount < r.lowWater && newCount >= r.lowWater) {
 		r.signalNotify()
 	}
```

I withdraw my Turn 1 proposal to delete the `oldCount == 0` clause. Sol Pro proved it arms the park timer; deleting it strands packets on an empty-ring sleep with no deadline.

### Diff 4: inbound batch flush on drained input

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
@@ -368,6 +368,16 @@ func (s *winn3FrameServer) serve(ctx context.Context, input io.Reader) error {
 			if done {
 				return nil
 			}
 		}
 
+		// Round 46 OI-2: do not hold a partial batch waiting for 512
+		// packets once the AF_UNIX receive queue is empty. A partial
+		// batch held here is invisible to txDrainGate and inflates
+		// measured inter-arrival at the ring boundary.
+		if len(inboundBatch) > 0 &&
+			(bufInput == nil || bufInput.Buffered() < duplex.HeaderSize) {
+			if err := s.flushInboundBatch(&inboundBatch); err != nil {
+				return err
+			}
+		}
+
 		if bufInput != nil {
 			for !s.closed.Load() {
```

### Diff 5: instrumentation required to validate the vote, not optional

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
@@
 type winn3ToEngineRing struct {
 	mu       sync.Mutex
 	notify   chan struct{}
 	lowWater int
 	maxPark  time.Duration
+
+	// Round 46: wake-reason attribution. Section 2.1 proves at most
+	// 4.495% of Run 18 carrier calls could have been park expiries,
+	// so the 2.41 batch ratio must be re-measured at this boundary.
+	wakeThreshold atomic.Uint64
+	wakeZero      atomic.Uint64
+	wakePark      atomic.Uint64
+	popLenSum     atomic.Uint64
+	popCalls      atomic.Uint64
 }
```

Increment `wakeZero` when the signal fires on `oldCount == 0`, `wakeThreshold` on the crossing edge, `wakePark` when the timer expires, and accumulate `popLenSum` and `popCalls` in `popBatch`. Without these four counters the `lowWater` change cannot be validated or falsified; `popLenSum / popCalls` is the true batch occupancy and the 2.41 carrier figure is not a substitute for it.

## 4. Convergence Votes

- **OI-1:** AGREE. The 366 to 401 Mbps band maps to 92,930 through 101,816 in-flight bytes per stream against a 253,906 byte requirement, Sol Pro's slow-start arithmetic (19.05x growth in 325 ms) rules out a transient ramp as the cause, and 1,048,576 bytes gives 4.130x headroom that stays valid if stream count drops to 8. I withdraw my Turn 1 objection that Android `tcp_wmem[2]` of 4 MiB makes the explicit set redundant: an autotuner converged to a low fixed point is behaviorally a clamp, and the readback in Diff 1 makes the claim falsifiable. Falsification condition: if `socket.sendBufferSize` reads back at or above 262,144 before the patch, or if aggregate uplink stays below 500 Mbps after the patch with `tun0 tx_dropped` at zero and `tcpi_total_retrans` under 100, the window hypothesis is dead and the ceiling is elsewhere.

- **OI-2:** AGREE. `Builder.establish()` returns a new open file description at promotion, so a descriptor adopted at bootstrap becomes a dead tunnel, and Go assuming `tun0` read ownership forces the downlink write path to move with it. The three-part cost (barrier frame, quiesce window, atomic source swap) is Stage E scope. Retaining `LocalSocket` plus the Diff 4 partial-batch flush captures the available Stage D gain without touching downlink writes. I withdraw my Turn 1 enthusiasm for SCM_RIGHTS in this stage: my own analysis established that `IFF_VNET_HDR` cannot be set post-attach on a `VpnService` descriptor, which removes the GSO super-frame payoff that was the main justification for accepting the promotion complexity.

- **OI-3:** AGREE on the three specific parameter decisions. `lowWater = 16` (175.74 µs at 1 Gbps versus 351.49 µs for 32), `maxPark = 250 µs` retained, and the threshold-crossing-edge signal condition with `oldCount == 0` preserved. I withdraw my Turn 1 proposal to remove the zero-transition wake and to set `maxPark = 150 µs`. One correction to the synthesis text rather than to the vote: finding 3's claim that the reader "was timing out on the 250 µs timer with only ~2.4 packets accumulated" is arithmetically impossible, since 88,985.875 calls/second is 22.246x the 4,000 calls/second ceiling that pure park expiry permits. The parameter changes are still correct; the stated causal mechanism is not, and Diff 5 is required to establish the real one.

- **OI-4:** AGREE. I reverse my Turn 1 DISAGREE. My objection was that the transmit ring carries downlink-phase TCP ACKs, so `maxPark` leaks delay into the downlink observable. The arithmetic in section 2.3 holds (250 µs is 0.3846% of the 65 ms RTT, 2.25 ms added to a 585 ms nine-doubling ramp, 0.383% steady-state reduction), but it does not support a DISAGREE vote on OI-4 as written, because OI-4 scopes the invariant to code paths and the `lowWater` edit does not change the realized ACK delay bound at all: at 30,726.5 ACKs/second the 32-packet threshold needed 1,041.6 µs and the 16-packet threshold needs 520.8 µs, both above `maxPark`, so the park deadline binds identically before and after. The delay bound is a pre-existing property of the unchanged `maxPark = 250 µs`, not a Stage D regression. Falsification condition: if a `maxPark = 0` control run reaches 675 Mbps downlink more than 1% faster in time-to-plateau than the `maxPark = 250 µs` run, the gate is a live downlink constraint and OI-4 must be reopened as a separate docket item.
