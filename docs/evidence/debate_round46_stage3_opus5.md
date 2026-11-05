# Turn 3 Final Vote: claude-opus5

## Steelman of the Peer Positions

**Podium 3 (GPT-5.6 Sol Pro) on reverse-path ACKs.** The strongest form of Sol Pro's objection is not about payload code at all. It is about the definition of "frozen." A freeze stated over source files is weaker than a freeze stated over observable behavior, and `toEngineRing` is a shared resource carrying two logically independent traffic classes: uplink payload segments and reverse-path ACKs belonging to downlink flows. Any change to the wake predicate of a shared queue is, by construction, a change to the latency distribution of every class in that queue. Sol Pro's 1+15 burst construction is the correct minimal counterexample: with `lowWater = 32` the sixteenth enqueue is silent, with `lowWater = 16` it signals, so the two configurations are distinguishable by an external observer timing ACK egress. The freeze clause as originally drafted would have been falsified by that test. Amending the clause rather than defending it is the right disposition.

**Podium 1 on `LocalSocket` retention and Stage E deferral.** The steelman here is risk topology, not performance. SCM_RIGHTS descriptor handover collapses two processes onto one TUN fd, which means the promotion barrier must guarantee that exactly one writer owns the descriptor at every instant, including during crash-restart of the datapath. There is no partial-credit failure mode: a duplicated writer produces interleaved `tun0` writes and corrupted downlink frames, which is precisely the surface the Round 35/38/43/44/45 treaty line protects. Deferring to Stage E buys the atomic hot-swap design at the cost of one `AF_UNIX` copy, and the copy is affordable at target rate.

---

## First-Principles Arithmetic

**BDP and per-stream send buffer (OI-1).**
- Path capacity times delay: 1.0e9 bit/s times 0.065 s = 6.5e7 bit = 8.125e6 bytes in flight.
- Per stream across 32 workers: 8.125e6 / 32 = 253,906.25 bytes, so 253,907 bytes is the hard per-socket floor.
- Requested buffer: 1,048,576 / 253,906.25 = 4.130x headroom. Confirmed.
- Kernel accounting caveat: Linux sets `sk_sndbuf = 2 * requested` and `getsockopt(SO_SNDBUF)` returns `sk_sndbuf`, so a healthy readback on worker 0 is 2,097,152. A readback below 507,814 indicates the request was clamped by `net.core.wmem_max`; a readback below 253,907 means per-stream BDP is not covered and the 1 Gbps target is unreachable by construction, regardless of anything else in Stage D. This is why the readback log is load-bearing and not decoration.
- Receiver side: for uplink, the binding window is the Canada gateway receive window, not the handset send buffer. Explicit `SO_RCVBUF` freezes `tcp_rmem` autotuning and pins the window at the set value; leaving it unset lets autotuning grow toward `tcp_rmem[2]`, which needs to exceed 253,907 bytes per connection. On a 6 MiB default cap that is 25x margin. The proposal's decision to not hardcode `SO_RCVBUF` is the only configuration that keeps window scale negotiation and autotuning both intact.

**Reverse ACK residency under the amended freeze (OI-4).**
- Downlink 675 Mbps at 1,373 bytes of payload per segment: 8.4375e7 bytes/s / 1,373 = 61,453 segments/s; delayed ACK at one per two segments gives 30,726.5 ACKs/s, interval 32.55 µs. Confirmed.
- Sixteen ACK accumulation time: 16 times 32.55 µs = 520.8 µs, which exceeds `maxPark = 250 µs` by 2.08x. The park deadline therefore fires first in the ACK-only regime, and the threshold value is not reachable before the timer. This is the load-bearing result: the 250 µs ceiling binds identically at `lowWater = 32` and at `lowWater = 16`.
- Fraction of RTT: 250 µs / 65,000 µs = 0.3846%. Window-limited throughput scales as RTT, so 1 - (65 / 65.25) = 0.383%. Confirmed.
- Both figures are conservative ceilings, not expected values. In the ACK-only regime the ring drains empty between arrivals, so the `oldCount == 0` clause signals on the first ACK and residency approaches the futex wake cost, not 250 µs. Under concurrent saturated uplink at 12 µs inter-arrival, an ACK enqueued mid-burst rides out within 192 µs at `lowWater = 16`. The 250 µs case requires a specific interleaving: ring non-empty, occupancy below threshold, consumer already parked.

**Ring wake economics at wire speed (OI-3).**
- Uplink 1.0e9 bit/s at 1,500 bytes on the wire: 83,333 packets/s, 12.0 µs inter-arrival.
- At `lowWater = 32`: 32 times 12.0 µs = 384 µs, which exceeds 250 µs, so the park timer binds. Wake rate 4,000/s, mean drain batch 250/12 = 20.8 frames.
- At `lowWater = 16`: 16 times 12.0 µs = 192 µs, below 250 µs, so the threshold binds. Wake rate 5,208/s, mean drain batch 16.0 frames.
- Net effect of the recalibration in the saturated regime: mean residency falls from 250 µs to 192 µs (a 23.2% cut), wake rate rises 30.2%, and mean batch occupancy falls 23.1%. At roughly 3 µs of futex plus scheduler cost per wake this is about 3.6 ms of CPU per second, plus about 1.8 ms/s of extra `writev` amortization loss, so near 0.5% of one core. Small, but directionally against the Stage D goal, and currently unmeasured.
- Regime boundary worth stating explicitly: `lowWater` only binds when the consumer is the bottleneck. Whenever inter-arrival exceeds drain service time, the ring empties and `oldCount == 0` signals every push, so wake rate equals arrival rate and the threshold is dead code. At 30,726 ACKs/s that predicts `wakeZero` dominance by two orders of magnitude over `wakeThreshold`. That prediction is directly falsifiable by the counters this item proposes.

---

## Surgical Diffs

### Diff 1: `MainActivity.kt` (upload worker socket, near line 1530)

```diff
@@ companion object / file-level constants
+    // 1.0e9 bit/s * 0.065 s / 32 streams = 253,907 B per-stream floor.
+    private const val UPLOAD_SNDBUF_BYTES = 1_048_576      // 4.130x BDP headroom
+    private const val UPLOAD_SNDBUF_FLOOR_BYTES = 253_907  // hard per-stream floor
@@ upload worker socket setup (MainActivity.kt:1530)
     val socket = Socket()
+    // Must precede connect() so the value is in place for the first window advance.
+    // Linux reports 2 * requested on readback; a value below the floor means
+    // net.core.wmem_max clamped the request and per-stream BDP is not covered.
+    socket.sendBufferSize = UPLOAD_SNDBUF_BYTES
     socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
+    if (workerIndex == 0) {
+        val eff = socket.sendBufferSize
+        android.util.Log.i(
+            "WinnUpload",
+            "sndbuf_req=$UPLOAD_SNDBUF_BYTES sndbuf_eff=$eff floor=$UPLOAD_SNDBUF_FLOOR_BYTES"
+        )
+        if (eff < UPLOAD_SNDBUF_FLOOR_BYTES) {
+            android.util.Log.w("WinnUpload", "sndbuf clamped below per-stream BDP floor")
+        }
+    }
```

I deliberately exclude `tcpNoDelay` from this diff. Bulk upload writes are already larger than MSS, so Nagle is inert here, and adding an unrelated socket option to a treaty-scoped change widens the audit surface for zero measured gain.

### Diff 2: `cmd/winn-datapath/winn3_frame.go` (flush before a read that can block)

The proposed predicate `bufInput == nil || bufInput.Buffered() < duplex.HeaderSize` catches the empty and partial-header cases but misses the partial-body case. With a 4,096 byte `bufio` reader and 1,373 byte frames, `Buffered()` can sit at `HeaderSize + 1` and still block for up to 1,372 bytes while a full batch waits behind it. The fix below is a strict superset of the proposed condition.

```diff
+// frameReady reports whether one complete frame is already buffered, so the
+// next decode cannot block in Read.
+func frameReady(r *bufio.Reader) bool {
+    if r == nil {
+        return false
+    }
+    n := r.Buffered()
+    if n < duplex.HeaderSize {
+        return false
+    }
+    h, err := r.Peek(duplex.HeaderSize)
+    if err != nil {
+        return false
+    }
+    return n >= duplex.HeaderSize+int(duplex.PayloadLen(h))
+}
@@ inbound decode loop
     for {
+        if len(inboundBatch) > 0 && !frameReady(bufInput) {
+            if err := flushInboundBatch(); err != nil {
+                return err
+            }
+        }
         hdr, err := readHeader(bufInput)
         if err != nil {
             return err
         }
```

Cost bound: at most one extra `writev` per idle transition. Worst case is a pathological one-frame-per-flush pattern at low rate, which is the correct behavior at low rate.

### Diff 3: `cmd/winn-datapath/winn3_to_engine_ring.go` (telemetry now, constant on a gate)

```diff
+// ringLowWaterDefault stays at 32 until ring telemetry falsifies the
+// park-bound model. Promotion criterion is stated in the vote on OI-3.
+var ringLowWaterDefault = 32
@@ type winn3ToEngineRing struct {
     mu       sync.Mutex
     notify   chan struct{}
     lowWater int
     maxPark  time.Duration
     // ...
+    // Wake attribution and batch occupancy. Incremented under mu on the push
+    // path so attribution matches the observed count transition exactly.
+    wakeThreshold atomic.Uint64
+    wakeZero      atomic.Uint64
+    wakePark      atomic.Uint64
+    popLenSum     atomic.Uint64
+    popCalls      atomic.Uint64
 }
@@ push path
-    if oldCount == 0 || (oldCount < r.lowWater && newCount >= r.lowWater) {
-        r.signalNotify()
-    }
+    switch {
+    case oldCount == 0:
+        r.wakeZero.Add(1)
+        r.signalNotify()
+    case oldCount < r.lowWater && newCount >= r.lowWater:
+        r.wakeThreshold.Add(1)
+        r.signalNotify()
+    }
@@ pop path, after the copy into dst
     n := copy(dst, r.buf[head:head+avail])
+    r.popCalls.Add(1)
+    r.popLenSum.Add(uint64(n))
@@ park path
     case <-timer.C:
+        r.wakePark.Add(1)
         return 0
@@ snapshot accessor for the existing stats endpoint
+func (r *winn3ToEngineRing) statsSnapshot() ringStats {
+    return ringStats{
+        WakeThreshold: r.wakeThreshold.Load(),
+        WakeZero:      r.wakeZero.Load(),
+        WakePark:      r.wakePark.Load(),
+        PopLenSum:     r.popLenSum.Load(),
+        PopCalls:      r.popCalls.Load(),
+    }
+}
```

The signaling condition is retained verbatim in semantics. The `switch` is behavior-identical to the original `||` because the two clauses are mutually exclusive when `lowWater >= 1`: `oldCount == 0` and `oldCount < lowWater <= newCount` can both hold, and in that case the original fired once, as does the `switch`. No third state is introduced.

---

## Final Convergence Votes

- **OI-1**: AGREE: the per-stream floor of 253,907 bytes and the 4.130x headroom at 1,048,576 bytes are arithmetically exact, and the failure mode is falsifiable in one line of logcat, since a `sndbuf_eff` readback below 253,907 on worker 0 proves `net.core.wmem_max` clamping and predicts a hard uplink ceiling below 1 Gbps before any other Stage D variable is tested.
- **OI-2**: AGREE: retaining `AF_UNIX` costs one copy per frame at 61,453 frames/s, which is measurable and bounded, whereas SCM_RIGHTS handover without an atomic descriptor swap admits a two-writer window on `tun0` that would corrupt downlink frames and is falsifiable by a single datapath crash-restart test under load.
- **OI-3**: DISAGREE: `lowWater` binds only in the consumer-saturated regime, and at 83,333 packets/s the change converts 4,000 park-bound wakes/s into 5,208 threshold wakes/s while cutting mean drain batch from 20.8 to 16.0 frames, so the recalibration ships a 30.2% wake-rate increase justified only by telemetry that lands in the same commit. Concrete resolution: land the five counters with `lowWater = 32` and a runtime override, then promote to 16 if and only if, over a 60 s window at sustained uplink above 900 Mbps, `wakePark / (wakePark + wakeThreshold + wakeZero) > 0.50` and `popLenSum / popCalls < 24.0`. If instead `wakeZero` exceeds 90% of all wakes as the regime analysis predicts, `lowWater` is dead code at this load and neither 16 nor 32 is the correct lever.
- **OI-4**: AGREE: the 0.385% RTT bound is `lowWater`-independent because 16 ACK arrivals at 32.55 µs require 520.8 µs, which exceeds the 250 µs park ceiling by 2.08x, so the timer binds in both configurations. The claim is falsifiable by a reverse-ACK ring-residency histogram whose p99.9 must sit at or below 250 µs; note that this bounds ring residency only, so the 0.383% throughput figure holds on the additional condition that every code path downstream of `pop` is non-blocking, which the same histogram plus a pop-to-egress timestamp pair will confirm or refute.

## Residual Trigger for Round 47

One item only. If the OI-3 counters show `wakeZero` above 90% of total wakes at 900 Mbps uplink, then the txDrainGate design question changes shape: the cost driver is per-arrival wakes on an empty ring, not threshold selection, and the correct Stage D lever becomes a minimum inter-wake interval on the zero path with the reverse-ACK class exempted. That redesign would touch the shared queue for both traffic classes and therefore requires a fresh reading against the amended OI-4 invariant rather than an in-stage tuning change.
