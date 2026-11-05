# Turn 1 Verdict: solpro

Baseline arithmetic

Run 14 delivered:

```text
415,498,240 bytes * 8 bits / 8 seconds
= 415,498,240 bit/s
= 415.5 Mbit/s
```

The 1,000 Mbit/s target requires exactly 1,000,000,000 bytes during the same 8 second measurement window. The required improvement is:

```text
1,000 / 415.5 = 2.407 times
```

At 1,373 payload bytes per packet:

```text
1,000,000,000 / 8 / 1,373 = 91,041 packets/s
415,500,000 / 8 / 1,373 = 37,837 packets/s
```

A 3.63 GHz core has approximately 39,872 cycles per packet at the target rate. This is ample for three 1,373 byte copies and basic framing. It is not ample for frequent scheduler handoffs, blocking channel operations, crypto, and repeated queue serialization all landing on the same core.

Zero sink drops proves that this particular queue did not overflow. It does not prove that batching is the sole bottleneck. TCP backpressure can reduce production before any engine queue drops occur.

1. **OI-1: Two-phase consumer reservation**

The proposed epoch validation is incorrect.

If a producer publishes while the consumer is copying, `queueEpoch` changes. Phase 3 then refuses to advance `head` or decrement `count`, even though the claimed packet storage remained valid. The next invocation copies the same packets again. Under continuous production this can repeat until the queue remains full.

The claimed slots are already protected without an epoch comparison because they remain included in `count`. A producer may fill preexisting free slots, but it cannot reach the claimed head slots until the consumer decrements `count`.

Correct protocol

1. Under `state`, wait for any queue transition and any prior consumer claim.
2. Run `awaitPacket()`.
3. Record `head`, packet count, lengths, and generation.
4. Mark one active consumer claim. Do not decrement `count`.
5. Copy outside `state`.
6. Under `state`, commit `head` and `count` without comparing the normal producer publish epoch.
7. Queue reset, discard, rebind, and generation changes must wait for the active claim.
8. A close may set `closed` immediately to wake waiters, but it must not clear or reuse the slab until the active claim completes.

JMM reasoning

The producer writes packet bytes before publishing under `synchronized(state)`. Its monitor release happens before the consumer's later monitor acquire. The consumer therefore sees both `lengths[]` and slab bytes.

While copying outside the monitor, no producer can overwrite the claimed region because `count` still includes it. The final monitor release publishes the updated `head` and `count`.

No volatile access to each slab byte is needed. The queue transition flag and claim flag are monitor protected.

Recommended Kotlin diff

```diff
diff --git a/.../WinnV3AndroidTun.kt b/.../WinnV3AndroidTun.kt
@@
+    // Accessed only while synchronized(state).
+    private var outgoingClaimActive = false
+    private var queueTransitionActive = false
+
+    private fun waitStateLocked() {
+        waiters++
+        try {
+            @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
+            (state as java.lang.Object).wait()
+        } finally {
+            waiters--
+        }
+    }
+
+    private fun signalStateLocked() {
+        @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
+        (state as java.lang.Object).notifyAll()
+    }
+
+    /*
+     * Every operation that clears the queue, changes readerGeneration,
+     * changes slab ownership, or resets head/tail/count must call these
+     * while synchronized(state).
+     */
+    private fun beginQueueTransitionLocked() {
+        while (queueTransitionActive) {
+            waitStateLocked()
+        }
+        queueTransitionActive = true
+        while (outgoingClaimActive) {
+            waitStateLocked()
+        }
+    }
+
+    private fun endQueueTransitionLocked() {
+        check(queueTransitionActive)
+        queueTransitionActive = false
+        signalStateLocked()
+    }
@@
-    override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int = synchronized(state) {
+    override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int {
         batch.clear()
-        if (!awaitPacket()) return@synchronized -1
-        batch.generation = readerGeneration.get()
-        while (count > 0 && batch.canAppend(lengths[head])) {
-            batch.append(
-                WinnFraming.OP_INBOUND,
-                slab,
-                head * packetCapacity,
-                lengths[head]
-            )
-            head = (head + 1) % queueDepth
-            count--
+
+        val claimHead: Int
+        val claimCount: Int
+        val claimGeneration: Long
+
+        synchronized(state) {
+            while (queueTransitionActive || outgoingClaimActive) {
+                if (closed.get()) return -1
+                waitStateLocked()
+            }
+
+            if (!awaitPacket()) return -1
+
+            /*
+             * awaitPacket() can release state while waiting. Recheck the
+             * transition condition after it returns.
+             */
+            while (queueTransitionActive || outgoingClaimActive) {
+                if (closed.get()) return -1
+                waitStateLocked()
+                if (!awaitPacket()) return -1
+            }
+
+            claimHead = head
+            claimGeneration = readerGeneration.get()
+
+            var n = 0
+            while (n < count) {
+                val slot = (claimHead + n) % queueDepth
+                if (!batch.canAppend(lengths[slot])) break
+                n++
+            }
+
+            if (n == 0) {
+                throw IOException("Winn tun batch destination too small")
+            }
+
+            claimCount = n
+            outgoingClaimActive = true
         }
-        if (batch.count == 0) throw IOException("Winn tun batch destination too small")
-        batch.count
+
+        var copied = false
+        try {
+            batch.generation = claimGeneration
+            for (i in 0 until claimCount) {
+                val slot = (claimHead + i) % queueDepth
+                batch.append(
+                    WinnFraming.OP_INBOUND,
+                    slab,
+                    slot * packetCapacity,
+                    lengths[slot]
+                )
+            }
+            copied = true
+        } finally {
+            synchronized(state) {
+                check(outgoingClaimActive)
+
+                if (copied) {
+                    /*
+                     * Producer publishes are allowed during the copy.
+                     * count includes both the claimed packets and any
+                     * packets published after the claim.
+                     */
+                    check(head == claimHead)
+                    check(readerGeneration.get() == claimGeneration)
+                    check(count >= claimCount)
+                    head = (claimHead + claimCount) % queueDepth
+                    count -= claimCount
+                }
+
+                outgoingClaimActive = false
+                signalStateLocked()
+            }
+        }
+
+        return batch.count
     }
```

Every destructive queue operation needs this wrapping:

```diff
 synchronized(state) {
+    beginQueueTransitionLocked()
+    try {
         // Existing reset, discard, rebind, generation, or slab mutation.
+    } finally {
+        endQueueTransitionLocked()
+    }
 }
```

Close should wake `awaitPacket()` before waiting for an active copy:

```diff
 synchronized(state) {
     closed.set(true)
-    signalStateLocked()
+    signalStateLocked()
+    beginQueueTransitionLocked()
+    try {
+        // Existing queue cleanup.
+    } finally {
+        endQueueTransitionLocked()
+    }
 }
```

`queueEpoch` may still guard structural reset and rebind. It must not cause a consumer claim to fail merely because a producer published normally.

Expected effect

A 256 packet payload batch is approximately:

```text
256 * 1,373 = 351,488 bytes
```

At a conservative effective copy and framing rate of 5 GB/s, its raw copy time is about 70 microseconds. At 415.5 Mbit/s there are about 148 such batches per second, so raw lock occupancy is roughly 10 ms/s plus Kotlin framing overhead. Decoupling can remove producer latency bubbles, but raw copy arithmetic does not support a 2.4 times gain by itself.

Projected isolated improvement is 5 to 20 percent, with a larger result possible only if telemetry confirms scheduler stalls around `state`.

Vote: DISAGREE: a normal producer publish changes `queueEpoch`, causing the proposed Phase 3 to reject a valid claim and recopy the same head packets.

2. **OI-2: Expanding batch sizing**

A 512 packet batch contains approximately:

```text
512 * 1,373 = 702,976 payload bytes
```

Even with framing headers, it remains comfortably below 1 MiB. At 1 Gbit/s it represents:

```text
702,976 / 125,000,000 = 5.624 ms
```

A 256 packet batch represents 2.812 ms. If code waits for a full batch, the worst-case batching delay increases by about 2.8 ms and average delay by about 1.4 ms. If it drains immediately available packets and merely permits up to 512, low-load latency is unchanged.

The expected callback count at 1 Gbit/s is:

```text
91,041 / 256 = 355.6 batches/s
91,041 / 512 = 177.8 batches/s
```

This halves batch-level calls, but not necessarily kernel reads. AF_UNIX is a byte stream. A 703 KiB write can be split into several kernel operations, and a 1 MiB socket buffer does not make that write atomic.

The proposal conflicts with the frozen downlink constraint in two places:

1. Changing `WinnV3PacketBatch` defaults changes every caller using defaults, including any downlink allocation.
2. Changing `pumpOutboundBatch` in `winn3/tun/tun.go` changes the Go to Android downlink path.

The correct patch is uplink-specific. Defaults and `pumpOutboundBatch` must remain unchanged.

Recommended Kotlin diff

```diff
diff --git a/.../WinnV3PacketBatch.kt b/.../WinnV3PacketBatch.kt
@@
 class WinnV3PacketBatch(
-    val packetCapacity: Int = 256,
-    val byteCapacity: Int = 512 * 1024,
+    val packetCapacity: Int = 256,
+    val byteCapacity: Int = 512 * 1024,
 ) {
```

That file intentionally has no functional change. Do not alter the defaults.

Instantiate the uplink object explicitly in `WinnV3Bridge.kt`:

```diff
diff --git a/.../WinnV3Bridge.kt b/.../WinnV3Bridge.kt
@@
-    private val outgoingBatch = WinnV3PacketBatch()
+    private val outgoingBatch = WinnV3PacketBatch(
+        packetCapacity = 512,
+        byteCapacity = 1024 * 1024,
+    )
```

If the bridge currently shares one object between directions, split it:

```diff
-    private val packetBatch = WinnV3PacketBatch()
+    private val uplinkBatch = WinnV3PacketBatch(
+        packetCapacity = 512,
+        byteCapacity = 1024 * 1024,
+    )
+    private val downlinkBatch = WinnV3PacketBatch(
+        packetCapacity = 256,
+        byteCapacity = 512 * 1024,
+    )
```

Recommended Go uplink diff:

```diff
diff --git a/cmd/winn-datapath/winn3_frame.go b/cmd/winn-datapath/winn3_frame.go
@@
-    inboundBatch := make([][]byte, 0, 256)
+    inboundBatch := make([][]byte, 0, 512)
```

Explicitly rejected downlink diff:

```diff
diff --git a/winn3/tun/tun.go b/winn3/tun/tun.go
@@
-    const batchSize = 256
+    const batchSize = 512
```

Do not apply that hunk.

Memory increase per active bridge is approximately:

```text
Kotlin uplink byte storage:       +512 KiB
Kotlin packet metadata:           about +1 to +4 KiB
Go slice headers, 256 * 24 bytes: +6 KiB
Total direct increase:            about 519 to 522 KiB
```

Projected isolated throughput improvement is 1 to 6 percent. At only 356 batch events per second, syscall reduction alone cannot account for the missing 584.5 Mbit/s.

Vote: DISAGREE: changing the global Kotlin default and `pumpOutboundBatch` modifies frozen downlink allocations, which is directly detectable in the downlink file diff.

3. **OI-3: Go copy and channel optimization**

Copy cost

At 1 Gbit/s, each full payload copy moves 125 MB/s. Three copies move 375 MB/s.

At an intentionally conservative 10 GB/s effective memory rate:

```text
375 MB/s / 10,000 MB/s = 0.0375 CPU-seconds/s
```

That is about 3.75 percent of one core for raw copying. Cache misses and pool operations increase the real cost, but three copies alone should not saturate an Oryon performance core.

Channel cost is more concerning:

```text
91,041 packet sends/s
91,041 packet receives/s
182,082 channel-side operations/s
```

With 512 packet descriptors:

```text
177.8 batch sends/s
177.8 batch receives/s
355.6 channel-side operations/s
```

Option A must not expose `reader.Read()` storage asynchronously. The next read reuses `r.buffer`, so sending a slice referencing it creates a data race and packet corruption. Eliminating `allocPacket` requires a new reader operation that reads the payload directly into an owned pool slab.

Option B is the appropriate first patch. The packet payload copy into the pool remains. Only ownership descriptors are batched.

The backing `[][]byte` array must not be reused immediately after sending. Reusing it would let the producer overwrite slice headers while the consumer reads them. A pooled batch descriptor solves this.

Recommended Go structure

```diff
diff --git a/cmd/winn-datapath/winn3_frame_device.go b/cmd/winn-datapath/winn3_frame_device.go
@@
 import (
     "sync"
+    "sync/atomic"
 )
 
+const maxQueuedInboundPackets int64 = 65536
+const maxInboundBatchPackets = 512
+
+type inboundPacketBatch struct {
+    packets [][]byte
+}
+
+var inboundPacketBatchPool = sync.Pool{
+    New: func() any {
+        return &inboundPacketBatch{
+            packets: make([][]byte, 0, maxInboundBatchPackets),
+        }
+    },
+}
+
 type frameDevice struct {
-    toEngine chan []byte
+    toEngine chan *inboundPacketBatch
+
+    queuedInboundPackets int64
+    pendingInbound       *inboundPacketBatch
+    pendingInboundIndex  int
 }
```

Initialization:

```diff
-    toEngine: make(chan []byte, 65536),
+    /*
+     * Channel capacity is descriptor capacity. The atomic packet credit
+     * below preserves the original 65,536 packet bound.
+     */
+    toEngine: make(chan *inboundPacketBatch, 65536),
```

Credit reservation and batch offer:

```go
func (d *frameDevice) reserveInboundPackets(n int) bool {
    delta := int64(n)
    for {
        old := atomic.LoadInt64(&d.queuedInboundPackets)
        if old+delta > maxQueuedInboundPackets {
            return false
        }
        if atomic.CompareAndSwapInt64(
            &d.queuedInboundPackets,
            old,
            old+delta,
        ) {
            return true
        }
    }
}

func (d *frameDevice) offerInboundBatch(packets [][]byte) bool {
    if len(packets) == 0 {
        return true
    }
    if len(packets) > maxInboundBatchPackets {
        panic("inbound packet batch exceeds maximum")
    }
    if !d.reserveInboundPackets(len(packets)) {
        return false
    }

    batch := inboundPacketBatchPool.Get().(*inboundPacketBatch)
    batch.packets = append(batch.packets[:0], packets...)

    select {
    case d.toEngine <- batch:
        return true
    default:
        atomic.AddInt64(
            &d.queuedInboundPackets,
            -int64(len(batch.packets)),
        )
        batch.packets = batch.packets[:0]
        inboundPacketBatchPool.Put(batch)
        return false
    }
}
```

The `append` copies only slice headers:

```text
512 * 24 = 12,288 bytes per full batch
12,288 * 177.8 = 2.18 MB/s
```

That copy is negligible and prevents a slice-header race.

The device `ReadBatch` keeps a descriptor pending while filling the engine-provided buffers:

```go
func (d *frameDevice) releasePendingInbound() {
    batch := d.pendingInbound
    if batch == nil {
        return
    }

    atomic.AddInt64(
        &d.queuedInboundPackets,
        -int64(len(batch.packets)),
    )
    batch.packets = batch.packets[:0]
    inboundPacketBatchPool.Put(batch)

    d.pendingInbound = nil
    d.pendingInboundIndex = 0
}
```

The existing per-packet receive section should be replaced with logic of this form:

```go
for produced < len(bufs) {
    if d.pendingInbound == nil {
        select {
        case batch := <-d.toEngine:
            d.pendingInbound = batch
            d.pendingInboundIndex = 0
        case <-d.closed:
            if produced != 0 {
                return produced, nil
            }
            return 0, os.ErrClosed
        }
    }

    batch := d.pendingInbound
    for produced < len(bufs) &&
        d.pendingInboundIndex < len(batch.packets) {

        pkt := batch.packets[d.pendingInboundIndex]
        n := copy(bufs[produced][offset:], pkt)
        sizes[produced] = n

        recyclePacket(pkt)

        batch.packets[d.pendingInboundIndex] = nil
        d.pendingInboundIndex++
        produced++
    }

    if d.pendingInboundIndex == len(batch.packets) {
        d.releasePendingInbound()
    }
}
```

The exact existing close error and packet recycle helper names should be retained. The ownership invariants are:

1. `allocPacket` owns the payload before `offerInboundBatch`.
2. Successful offer transfers all payload ownership to the device.
3. The sender may reuse its local `inboundBatch` slice because the descriptor copied the slice headers.
4. The receiver returns each payload to `packetPool` only after copying it.
5. The descriptor returns to its pool only after every payload has been consumed.
6. A failed offer leaves payload ownership with the caller, matching the existing drop path.

`session/driver.go` still performs its final copy into `d.data`. Removing that copy requires changing queue ownership and is too invasive for this round.

Projected isolated improvement is 5 to 15 percent if channel blocking is visible in a mutex or block profile. The result could be smaller if crypto or outer UDP processing dominates.

Vote: AGREE: batching 512 payload owners reduces approximately 182,082 channel-side operations per second to 356 while preserving the existing packet payload ownership and wire bytes.

4. **OI-4: Invariants, verification, and total projection**

Compliance of the revised recommendation:

| Constraint | Result |
|---|---|
| Downlink datapath frozen | `pumpOutboundBatch` and downlink batch allocation stay at 256 |
| Measurement mathematics frozen | No measurement code changes |
| Kotlin to Go framing bit-identical | Opcode, header fields, byte order, and payload remain unchanged |
| Android API compatibility | Only monitors, arrays, and existing JVM primitives are used |
| Go public device API | `ReadBatch` signature remains unchanged |
| Packet queue bound | Atomic credit remains 65,536 packets |
| 601 Android tests | Required before acceptance |
| All Go tests | Required before acceptance |
| Race safety | Required `go test -race` coverage |

Android verification:

```bash
./gradlew clean \
  :app:testDebugUnitTest \
  :app:lintDebug
```

Count tests and reject failures:

```bash
python3 - <<'PY'
import glob
import xml.etree.ElementTree as ET

tests = failures = errors = skipped = 0
for path in glob.glob("**/build/test-results/**/*.xml", recursive=True):
    root = ET.parse(path).getroot()
    tests += int(root.attrib.get("tests", 0))
    failures += int(root.attrib.get("failures", 0))
    errors += int(root.attrib.get("errors", 0))
    skipped += int(root.attrib.get("skipped", 0))

print({
    "tests": tests,
    "failures": failures,
    "errors": errors,
    "skipped": skipped,
})
assert tests == 601, tests
assert failures == 0, failures
assert errors == 0, errors
PY
```

Go verification:

```bash
cd winn_protocol_experimental
gofmt -w cmd/winn-datapath/winn3_frame.go \
          cmd/winn-datapath/winn3_frame_device.go
go vet ./...
go test ./...
go test -race ./...
```

Frozen downlink verification:

```bash
git diff --exit-code -- winn3/tun/tun.go
```

Also inspect that no default Kotlin batch allocation changed:

```bash
git diff -- WinnV3PacketBatch.kt
```

Wire compatibility should be checked with the same golden framed packets in both languages. At minimum include:

```text
empty rejection case
minimum IPv4 packet
1,373 byte payload
maximum accepted payload
256 packet sequence
512 packet sequence
mixed packet lengths
```

For every vector, compare the complete framed byte stream rather than decoded fields only.

Physical acceptance procedure:

1. Run at least five 8 second uplink tests.
2. Report median and minimum, not only the best run.
3. Require `tx_dropped_sink == 0` and no socket errors.
4. Record `state` monitor wait time before and after OI-1.
5. Record Go block and CPU profiles before and after OI-3.
6. Verify downlink remains within the previously accepted Treaty tolerance.
7. Use syscall counts to verify that 512 packet batches actually reduce AF_UNIX writes. Capacity alone does not prove coalescing.

Throughput projection

The direct costs identified here are too small to justify a prediction above 1,000 Mbit/s:

```text
Batch callbacks at target:             356/s
Saved callbacks after expansion:       178/s
Go payload copy traffic:               375 MB/s
Target per-packet CPU budget:           39,872 cycles
Required throughput multiplication:    2.407 times
```

A defensible projection for all revised changes together is 480 to 600 Mbit/s, with 650 Mbit/s possible if current monitor and channel stalls trigger scheduler handoffs. The effects are not additive because they optimize successive stages of the same pipeline.

If physical throughput remains below 600 Mbit/s, the next investigation should profile encryption, outer UDP send batching, Go scheduler placement, gateway receive processing, and actual TCP backpressure. The current evidence does not establish that AF_UNIX batching is responsible for the full gap.

Vote: AGREE: the revised patch is compliant if `git diff --exit-code -- winn3/tun/tun.go` succeeds, all 601 Android tests pass, and `go test -race ./...` reports no ownership race.
