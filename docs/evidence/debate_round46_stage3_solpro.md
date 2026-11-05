# Turn 3 Final Vote: solpro

- **Peer synthesis**: Podium 2’s calculation correctly shows that sustained downlink ACK traffic cannot reach `lowWater = 16` before `maxPark` expires. The OI-4 amendment also correctly narrows the freeze claim to downlink payload code and architecture while acknowledging that reverse ACKs share `toEngineRing`.

- **First-principles arithmetic**:
  - Aggregate BDP: `1,000,000,000 bit/s * 0.065 s / 8 = 8,125,000 bytes`.
  - Per stream: `8,125,000 / 32 = 253,906.25 bytes`, or `247.96 KiB`.
  - Send-buffer headroom: `1,048,576 / 253,906.25 = 4.1298x`.
  - ACK interval: `1,000,000 / 30,726.5 = 32.545 µs`.
  - Empty-epoch accumulation of 16 ACKs: `16 * 32.545 = 520.72 µs`.
  - First-to-sixteenth ACK span: `15 * 32.545 = 488.18 µs`.
  - Both exceed `maxPark = 250 µs`, so the park deadline remains controlling under sustained traffic.
  - Intentional park delay relative to RTT: `250 / 65,000 * 100 = 0.3846%`.
  - RTT-limited throughput reduction: `1 - 65 / 65.25 = 0.3831%`.
  - The 250 µs value bounds intentional ring parking. OS scheduling stalls remain separately measurable runtime latency.

- **Surgical change set**:
```diff
--- a/MainActivity.kt
+++ b/MainActivity.kt
@@
     val socket = Socket()
+    socket.sendBufferSize = 1048576
+    if (workerIndex == 0) {
+        android.util.Log.i(
+            "WinnUpload",
+            "sndbuf_req=1048576 sndbuf_eff=${socket.sendBufferSize}"
+        )
+    }
     socket.connect(...)
```

```diff
--- a/cmd/winn-datapath/winn3_frame.go
+++ b/cmd/winn-datapath/winn3_frame.go
@@
+    if len(inboundBatch) != 0 &&
+        (bufInput == nil || bufInput.Buffered() < duplex.HeaderSize) {
+        if err := flushInboundBatch(); err != nil {
+            return err
+        }
+    }
     // Existing next-frame read remains unchanged.
```

```diff
--- a/cmd/winn-datapath/winn3_to_engine_ring.go
+++ b/cmd/winn-datapath/winn3_to_engine_ring.go
@@
-    lowWater: 32,
+    lowWater: 16,
     maxPark: 250 * time.Microsecond,
```

```diff
 type winn3ToEngineRing struct {
     ...
+    wakeThreshold atomic.Uint64
+    wakeZero      atomic.Uint64
+    wakePark      atomic.Uint64
+    popLenSum     atomic.Uint64
+    popCalls      atomic.Uint64
 }
@@
     if oldCount == 0 || (oldCount < r.lowWater && newCount >= r.lowWater) {
+        if oldCount == 0 {
+            r.wakeZero.Add(1)
+        } else {
+            r.wakeThreshold.Add(1)
+        }
         r.signalNotify()
     }
@@
     case <-parkTimer.C:
+        r.wakePark.Add(1)
         // Existing drain operation remains unchanged.
@@
     n := r.popBatchInto(dst)
+    r.popCalls.Add(1)
+    r.popLenSum.Add(uint64(n))
```

  The gateway listener receives no `SO_RCVBUF` change. Every pop attempt must increment `popCalls` exactly once, including zero-length results, so `popLenSum / popCalls` measures actual ring-boundary occupancy without survivor bias.

- **OI-1**: AGREE: The requested buffer supplies `4.1298x` the calculated per-stream BDP, and worker-0 readback makes kernel clamping directly falsifiable.

- **OI-2**: AGREE: A `net.Pipe` test that sends one complete frame followed by less than `duplex.HeaderSize` bytes can verify that the completed `inboundBatch` is flushed before the next blocking read.

- **OI-3**: AGREE: A transition from count 1 to count 16 must increment `wakeThreshold`, while an enqueue at count 0 must increment `wakeZero`, providing a deterministic test of both calibration and attribution.

- **OI-4**: AGREE: A zero-context diff can verify that no Stage D hunk modifies `RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, downlink crypto workers, or measurement mathematics, while the computed intentional ACK park budget remains 0.3846% of 65 ms RTT.
