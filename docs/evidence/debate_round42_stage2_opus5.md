# Turn 2 Verdict: claude-opus5

# Turn 2: Cross-Examination and Convergence Vote (Podium: claude-opus5)

## 0. Anchoring disclaimer, unchanged from Turn 1

No tools were permitted in either turn, so no file under `/private/tmp/r42_seat_claude` was read. Every diff below is anchored to code text quoted inside the Turn 1 and Turn 2 packets and to symbol names the Arbiter asserts exist. They are reconstructions. Each hunk must be re-anchored against the real file before application, and any hunk whose context does not match verbatim is invalid and must be regenerated rather than forced.

---

## 1. Steelmanning the opposing podiums

- **Sol Pro on transition serialization (strongest point in its submission).** Sol Pro's `beginQueueTransitionLocked` / `endQueueTransitionLocked` pair is the only Turn 1 proposal that makes rebind and close *wait* for an in-flight consumer claim rather than racing it and discarding the result afterward. Its reasoning: an epoch check is a detector, not an exclusion mechanism, and a detector permits the window where `rebindDevice` swaps or refills the slab while the consumer is mid-`arraycopy`. In a language with manual memory management that argument wins outright, because the swap would be a use-after-free. It does not change my position, for one reason that is specific to this runtime: on the JVM the consumer holds a strong reference to whichever array it snapshotted, so a concurrent rebind cannot free or unmap it. The worst outcome is that the consumer copies bytes that are subsequently ruled stale, and the Arbiter's ground truth 1 now mandates `batch.clear()` plus non-delivery on exactly that condition. Serialization buys nothing extra there, and it costs something real: `close()` would block behind a copy window, and a `close()` invoked from the consumer thread itself would self-deadlock against `outgoingClaimActive`. I accept Sol Pro's construction as a strict superset if the council prefers it, provided close sets `closed` and signals before entering `beginQueueTransitionLocked`, which Sol Pro's own diff already does.

- **Sol Pro's livelock objection, now resolved by ground truth.** Its Turn 1 DISAGREE on OI-1 was that a normal producer publish would bump `queueEpoch`, causing Phase 3 to reject a valid claim and recopy the same head packets indefinitely. That was the correct question to ask against the packet as written. Arbiter ground truth 1 answers it with line-level evidence: `queueEpoch` is incremented only at `WinnV3AndroidTun.kt:851` (`rebindDevice`) and `:894` (`close`), and `runBurstReaderBulk` lines 598 to 605 publish with `count += reserved; enqueuedCount += reserved; state.notifyAll()` and no epoch mutation. Under that enumeration the epoch check fires only on rebind and close, both of which legitimately invalidate a claim, and there is no repeated-recopy path. Sol Pro's objection is retired by evidence, not by argument.

- **Gemini on LocalSocket buffer alignment.** Gemini is right that batch geometry should be reasoned about against the socket buffer rather than in isolation, and its instinct that a full framed batch should fit the socket buffer is sound. Where it stops short: it paired a 1 MiB `byteCapacity` with the Run 14 1 MiB socket buffer, which makes the maximum batch exactly equal to the whole send buffer and degrades the handoff to lockstep, since the writer cannot stage batch N+1 until the peer has drained batch N. The Arbiter's move to a 2 MiB socket buffer fixes this and my Turn 1 rule survives intact: maximum batch bytes at or below half the socket buffer. At 512 packets, 1373 B MTU and a 16-byte frame header, 512 * 1389 = 711,168 B = 694.5 KiB, which is 33.9% of 2 MiB. Comfortable.

- **Gemini on batch-granularity tail drop (its OI-3 Option B objection).** This is the strongest substantive point anyone raised against carrier batching, and it is correct as far as it goes: 512 contiguous dropped packets spread across concurrent flows produce RTO timeouts rather than SACK-recoverable holes, whereas per-packet tail drop leaves the head of each flow intact. My Turn 1 carrier diff had exactly that defect. Section 4.3 below removes it with partial credit reservation, so the number of packets dropped under overload equals the number by which the offer exceeds the 65,536 packet bound, which is bit-for-bit the granularity of the existing per-packet loop. Gemini's objection is answered by design change, not by dismissal.

- **Definitional correction that affects the consensus record.** Arbiter ground truth 3 states all three podiums rejected Option A. Gemini's Turn 1 text votes "Option A AGREE". The two are not in conflict: Gemini defined Option A as retaining the per-packet channel push *with* `allocPacket` and `sync.Pool` intact, which is the status quo, while the docket, Sol Pro, and I defined Option A as removing the `allocPacket` copy and publishing a slice aliasing `r.buffer`. Under the docket definition the rejection is genuinely unanimous. Under Gemini's definition its vote is an endorsement of the status quo, not of buffer aliasing. The record should carry the docket definition explicitly, otherwise a later reader reconstructs a disagreement that does not exist.

---

## 2. Defect found in both peer Turn 1 diffs (Phase 1 capacity accounting)

Both peer implementations of the Phase 1 claim loop are unsound, in the same way, and the defect will propagate into the ratified text if it is not corrected now.

Gemini:

```kotlin
while (fits < count && batch.canAppend(lengths[(claimHead + fits) % queueDepth])) { fits++ }
```

Sol Pro:

```kotlin
while (n < count) { if (!batch.canAppend(lengths[slot])) break; n++ }
```

Neither loop appends anything, so `batch`'s internal `count` and `byteLength` stay at their post-`clear()` values for every iteration. `canAppend` is evaluated against an empty batch on every pass and therefore returns the same answer every time. The loop degenerates to `fits = count`. Phase 2 then appends `count` packets into a batch whose `packetCapacity` is 512 and whose `byteCapacity` is 1024 KiB, with no bound linking `count` to either.

Falsification, one unit test, no device required: construct the tun with `queueDepth` greater than 512, publish 600 packets of 1373 B, call `readOutgoingBatch` with a 512-packet batch. Phase 1 claims 600, Phase 2 appends 600, and the 513th `append` overflows the batch arrays (`ArrayIndexOutOfBoundsException`, or a silent byte-region overrun depending on how `append` indexes). The original code never had this bug because it interleaved `append` with the capacity test inside one loop.

Correcting it requires stateful admission accounting during the claim. Section 4.1 puts that accounting inside `WinnV3PacketBatch` as a single source of truth rather than duplicating capacity arithmetic in the tun file.

---

## 3. First-principles arithmetic

### 3.1 Rate identities, recomputed

Target: 1,000 Mbps = 125,000,000 B/s. At 1373 B inner MTU, 125,000,000 / 1373 = **91,041.5 pps**, giving 10.984 µs of aggregate budget per packet.

Run 14: 415,498,240 B / 8.000 s = 51,937,280 B/s = **415.5 Mbps**; 51,937,280 / 1373 = **37,827.2 pps**, giving **26.44 µs per packet** of observed wall time. Required multiplier 91,041.5 / 37,827.2 = **2.407×**.

### 3.2 Per-packet time this round can actually retire

Each item removes time from the 26.44 µs figure. Upper bounds, using the per-stage costs from my Turn 1 Section 2.2, which no podium contested:

| Item | Mechanism | Upper bound removed, per packet |
|---|---|---|
| OI-1 | monitor hold during framing, 512 × 0.25 µs = 128 µs per claim, amortized | 0.25 µs |
| OI-2 | one write/read pair per 512 instead of per 256, ~6 µs per pair | 0.012 µs |
| OI-3B | 2 channel ops per packet to 2 per 512, parked-path cost 4.0 µs | 4.00 µs |
| **Sum** | | **4.26 µs** |

Residual per-packet time: 26.44 - 4.26 = **22.18 µs**. Resulting ceiling: 1373 × 8 / 22.18e-6 = **495.2 Mbps**.

That is a ceiling, not a projection, and it assumes the parked-channel path is the live one (the optimistic branch for OI-3B). If wakeups are already amortized per batch, OI-3B removes 0.30 µs instead of 4.00 µs and the ceiling falls to 1373 × 8 / 26.14e-6 = **420.2 Mbps**.

Gemini's projection of 1,050 to 1,180 Mbps requires removing 26.44 - 10.46 = **15.98 µs per packet** (10.46 µs being the 1,050 Mbps budget). The three items bound out at 4.26 µs, which is **26.7%** of what that projection needs. Gemini's number is falsified unless it names the additional 11.72 µs per packet it retires and which stage supplies it. Sol Pro's 480 to 600 Mbps is within a factor of 1.2 of my ceiling and is defensible. My range stands at **445 to 495 Mbps**, unchanged from Turn 1.

### 3.3 OI-2 geometry against the 2 MiB socket buffer

Full 512-packet batch at 1373 B and a 16-byte frame header: 512 × 1389 = **711,168 B = 694.5 KiB**. (Turn 1 used a 12-byte header and got 709,120 B; the Arbiter and Gemini both state 16, so 711,168 is the operative figure. Neither value changes any conclusion.)

Against the 1024 KiB `byteCapacity`: 711,168 / 1,048,576 = 67.8%. The byte cap is therefore **never binding at full MTU**; `packetCapacity = 512` is the binding constraint. The practical consequence of 1024 KiB versus my Turn 1 recommendation of 768 KiB is 256 KiB of additional resident allocation per uplink batch instance if the batch preallocates its byte array eagerly. That is a footprint note, not a defect, and I do not block on it.

Against the 2 MiB send buffer: 711,168 / 2,097,152 = **33.9%**, which satisfies the max-batch-at-or-below-half-socket-buffer rule with margin. `net.core.wmem_max = 8 MiB` admits the 2 MiB request.

One property makes the whole OI-2 change low risk and should be on the record: the uplink stream is a sequence of independently framed packets, each 16-byte header plus payload, so a larger Kotlin batch changes only write coalescing on the AF_UNIX stream. No frame boundary, no reader buffer size, and no wire byte changes. Sol Pro's point that a 694.5 KiB write is not atomic on a byte-stream socket is correct and is precisely why the change is safe: the Go reader already reassembles across kernel copy boundaries.

### 3.4 OI-3B channel arithmetic and memory

Per-packet channel operations today: 2 × 91,041.5 = **182,083/s**. With 512-packet carriers: 2 × 177.8 = **355.6/s**, a reduction factor of 512.

CPU recovered: 0.30 µs/packet (hot receiver, no park) × 91,041.5 = **27.3 ms/s = 2.73% of one core**. 4.00 µs/packet (parked receiver, cross-core unpark) × 91,041.5 = **364 ms/s = 36.4% of one core**. The spread between those two numbers is the single largest unresolved quantity in this round, and the measurement that resolves it is in Section 6.

Slice-header copy introduced by the carrier: 512 × 24 B = 12,288 B per carrier × 177.8 carriers/s = **2.18 MB/s**, roughly 0.02% of a core at 10 GB/s. Sol Pro computed the same figure independently. Negligible, and it is what buys immunity from the backing-array reuse race.

Channel slot memory at 8,192 carrier slots: 8,192 × 8 B = **65,536 B**, down from 65,536 × 24 B = **1,572,864 B** for the existing `chan []byte` at depth 65,536. Worst-case tiny-carrier occupancy 8,192 packets = 1.38 BDP at 1 Gbps and 65 ms RTT (BDP = 8,125,000 / 1373 = 5,918 packets), so even the degenerate one-packet-per-carrier case retains more than a full BDP of buffering. The 65,536 packet bound itself is preserved exactly by the credit counter, so drop threshold behavior is unchanged.

---

## 4. Final ratified diffs

### 4.1 OI-1: two-phase claim with corrected admission accounting and mandated clear-on-mismatch

Preconditions to verify in the real file before applying. Each one makes the patch unsound if false:

1. `queueEpoch` is incremented under `synchronized(state)` by every path that resets `head`/`count` or rewrites already-published slots. Arbiter ground truth 1 enumerates exactly two such paths, `rebindDevice:851` and `close:894`. Any future reset path must bump it, and that requirement belongs in a comment at the declaration.
2. `batch.append` grows the batch by exactly `WinnFraming.HEADER_BYTES + length` bytes and one packet slot. If the file names the header-size constant differently, use the file's constant; do not introduce a second literal.
3. `awaitPacket()` releases the monitor while waiting and returns false when `closed` is set.

```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt
@@ queue state fields
     private val state = Object()
+    // Guards the single-consumer invariant of readOutgoingBatch. Phase 2 runs
+    // with the monitor released, so a second consumer would claim the same
+    // slots and deliver every packet twice.
+    private var claimActive = false
 
-    override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int = synchronized(state) {
-        batch.clear()
-        if (!awaitPacket()) return@synchronized -1
-        batch.generation = readerGeneration.get()
-        while (count > 0 && batch.canAppend(lengths[head])) {
-            batch.append(WinnFraming.OP_INBOUND, slab, head * packetCapacity, lengths[head])
-            head = (head + 1) % queueDepth
-            count--
-        }
-        if (batch.count == 0) throw IOException("Winn tun batch destination too small")
-        batch.count
-    }
+    override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int {
+        batch.clear()
+
+        val claimHead: Int
+        val claimCount: Int
+        val claimEpoch: Int
+        val claimGeneration: Long
+        // Snapshot the ring backing stores under the monitor. rebindDevice may
+        // reassign them; a plain field read from the unlocked Phase 2 loop has
+        // no ordering guarantee against that assignment and could mix two rings.
+        val claimSlab: ByteArray
+        val claimLengths: IntArray
+        val claimDepth: Int
+        val claimStride: Int
+
+        // Phase 1: claim under the monitor without advancing head or count, so
+        // the producer's free-slot computation still excludes the claimed range
+        // for the entire unlocked window.
+        synchronized(state) {
+            check(!claimActive) { "Winn tun readOutgoingBatch is single-consumer" }
+            if (!awaitPacket()) return -1
+            claimGeneration = readerGeneration.get()
+            claimEpoch = queueEpoch
+            claimHead = head
+            claimSlab = slab
+            claimLengths = lengths
+            claimDepth = queueDepth
+            claimStride = packetCapacity
+            // Stateful admission. A canAppend loop without accumulation always
+            // tests the empty batch and would claim every queued packet
+            // regardless of packetCapacity, overflowing Phase 2.
+            claimCount = batch.planClaim(claimLengths, claimHead, count, claimDepth)
+            if (claimCount == 0) throw IOException("Winn tun batch destination too small")
+            claimActive = true
+        }
+
+        batch.generation = claimGeneration
+
+        // Phase 2: framing and payload copy with the monitor released.
+        // Visibility: the Phase 1 monitor acquire is ordered after the
+        // producer's publishing monitor release, and these reads follow that
+        // acquire in program order on this thread, so the slab bytes and
+        // lengths are visible without any additional fence.
+        try {
+            for (i in 0 until claimCount) {
+                val slot = (claimHead + i) % claimDepth
+                batch.append(
+                    WinnFraming.OP_INBOUND,
+                    claimSlab,
+                    slot * claimStride,
+                    claimLengths[slot],
+                )
+            }
+        } catch (t: Throwable) {
+            synchronized(state) {
+                claimActive = false
+                if (waiters > 0) state.notifyAll()
+            }
+            batch.clear()
+            throw t
+        }
+
+        // Phase 3: commit only if the ring was untouched for the whole unlocked
+        // window. On mismatch the copied bytes are suspect, so the batch is
+        // cleared and nothing is delivered. Gating only the head/count advance
+        // would still hand torn or duplicated frames to the caller.
+        synchronized(state) {
+            claimActive = false
+            if (closed.get()) {
+                batch.clear()
+                if (waiters > 0) state.notifyAll()
+                return -1
+            }
+            if (readerGeneration.get() != claimGeneration || queueEpoch != claimEpoch) {
+                batch.clear()
+                if (waiters > 0) state.notifyAll()
+                return 0
+            }
+            head = (claimHead + claimCount) % claimDepth
+            count -= claimCount
+            if (waiters > 0) state.notifyAll()
+        }
+        return batch.count
+    }
```

`state.notifyAll()` must match the notify idiom already used by `awaitPacket` and the producer publish path at lines 598 to 605. If that path uses the `(state as java.lang.Object).notifyAll()` form with the platform-class suppression, use that form here; do not introduce a second style.

Caller contract change, which must be checked at the `inboundPump` call site: `readOutgoingBatch` can now return `0` where previously it returned either a positive count or `-1`. Zero means the claim was invalidated by rebind and the caller should loop and call again. `-1` retains its meaning of closed. If the current call site treats any non-positive return as terminal, it will tear down the pump on the first rebind, which is a live regression and must be fixed in the same commit.

Batch-side accounting, single source of truth so Phase 1 and `canAppend` cannot drift:

```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
+    /** Pure admission predicate against an explicit accumulator state. */
+    private fun admits(packets: Int, bytes: Int, length: Int): Boolean =
+        packets < packetCapacity &&
+            bytes + WinnFraming.HEADER_BYTES + length <= byteCapacity
+
+    /**
+     * Number of leading ring packets, starting at [head], that this batch can
+     * accept in order given its current occupancy. Mirrors exactly what
+     * [append] consumes, so a claim planned here cannot overflow.
+     */
+    fun planClaim(lengths: IntArray, head: Int, available: Int, depth: Int): Int {
+        var planned = 0
+        var packets = count
+        var bytes = byteLength
+        while (planned < available) {
+            val length = lengths[(head + planned) % depth]
+            if (!admits(packets, bytes, length)) break
+            bytes += WinnFraming.HEADER_BYTES + length
+            packets++
+            planned++
+        }
+        return planned
+    }
+
-    fun canAppend(length: Int): Boolean = /* existing inline accounting */
+    fun canAppend(length: Int): Boolean = admits(count, byteLength, length)
```

`byteLength` must be the same accumulator `append` advances. If the field carries another name in the file, use that name in both methods.

Non-blocking refinement, offered but not a condition of my vote: bounding the unlocked window with a `CLAIM_CHUNK = 64` loop caps producer stall at roughly 16 µs regardless of `packetCapacity`, bounds discarded work on epoch mismatch to 64 packets instead of 512, and wakes free-slot waiters up to 8× sooner. Its value is jitter and stall bound, not throughput (3.2 shows the throughput term is 0.25 µs per packet either way). I do not block on its absence.

### 4.2 OI-2: uplink-only geometry, class defaults frozen

```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
 internal class WinnV3PacketBatch(
+    // Defaults are the downlink geometry and are frozen by Treaty R35/R38.
+    // The uplink instance passes explicit arguments from WinnV3Bridge.
     val packetCapacity: Int = 256,
     byteCapacity: Int = 512 * 1024,
 ) {
     init {
-        require(packetCapacity in 1..256)
-        require(byteCapacity in WinnFraming.HEADER_BYTES + 1..1024 * 1024)
+        require(packetCapacity in 1..512)
+        require(byteCapacity in WinnFraming.HEADER_BYTES + 1..2 * 1024 * 1024)
     }
```

```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
@@ inboundPump
             val batchedSeam = seam as? WinnV3BatchedIpPacketSeam
             val batchTransport = transport as? WinnV3BatchTransport
-            val batch = WinnV3PacketBatch()
+            // Uplink geometry only. 512 * (1373 MTU + 16 header) = 711,168 B,
+            // so the 1 MiB byte cap is not binding at full MTU and
+            // packetCapacity is the operative limit. Downlink keeps the frozen
+            // 256 / 512 KiB defaults.
+            val batch = WinnV3PacketBatch(
+                packetCapacity = 512,
+                byteCapacity = 1024 * 1024,
+            )
```

The `outboundPump` construction site must remain a default construction, `WinnV3PacketBatch()`, with no argument list. If the bridge currently shares one batch object across both pumps, it must be split into two fields before this change lands, otherwise the downlink allocation changes and OI-4 is violated.

```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/<LocalSocket sizing site, Run 14 change #3>
+++ b/android/app/src/main/kotlin/org/winsvpn/app/<same>
-        socket.sendBufferSize = 1 * 1024 * 1024
+        // Max uplink batch is 694.5 KiB. Keeping it at or below half the send
+        // buffer lets batch N+1 be staged while batch N drains, instead of
+        // lockstep. net.core.wmem_max = 8 MiB on SM-S948U1 admits 2 MiB.
+        socket.sendBufferSize = 2 * 1024 * 1024
```

Scoped amendment recommended, not blocking. The Arbiter's text reads "LocalSocket buffer size is set to 2 MiB" without distinguishing direction. Kotlin's `sendBufferSize` governs uplink; `receiveBufferSize` governs the downlink delivery into Kotlin. Raising the receive side changes a downlink kernel buffer allocation and can shift the frozen 848.1 Mbps downlink reference, which contaminates the comparison baseline. That is falsifiable in one downlink run before and after. My recommendation is to bump send only and leave `receiveBufferSize` at its Run 14 value. My AGREE on OI-2 stands under either text.

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
+// maxInboundBatchPackets mirrors the Kotlin uplink batch packetCapacity.
+// It is a slice sizing hint, not a wire value: frames remain independently
+// length-prefixed, so the two sides drifting apart wastes capacity and
+// nothing more.
+const maxInboundBatchPackets = 512
+
@@ inbound batch construction
-	inboundBatch := make([][]byte, 0, 256)
+	inboundBatch := make([][]byte, 0, maxInboundBatchPackets)
```

`winn3/tun/tun.go` `pumpOutboundBatch` with `const batchSize = 256` stays untouched, per Arbiter ground truth 2. I withdraw the Turn 1 request for a direction ruling: the Arbiter has ruled it frozen, and 3.2 puts its value at 0.012 µs per packet, so the expected value of touching it is negative regardless of direction.

### 4.3 OI-3 Option B: carrier batching with partial credit reservation

Option A is rejected under the docket definition (publishing a slice aliasing the frame reader's `r.buffer`), because the next `reader.Read()` overwrites bytes the consumer has not yet copied. Detectable with `go test -race` plus a reader driving more than one frame per drain.

Gemini's drop-granularity objection is answered structurally: credits are reserved partially, so overload drops exactly the packets that exceed the 65,536 packet bound, one packet at a time, identical to the current per-packet loop. No whole-batch discard path exists on the overload route.

Ownership invariants, stated so the reviewer can check each line against them:

1. `allocPacket` owns a slab until `offerBatch` is called.
2. Packets beyond the granted credit are returned to `packetPool` by the producer and never enter a carrier.
3. A successful channel send transfers ownership of every slab in the carrier to the consumer.
4. A failed channel send refunds credits and returns every slab in that carrier, and is the only whole-carrier drop path. It requires the channel to be full while credits remain, which 3.4 shows needs at least 8,192 queued packets.
5. The consumer returns each slab to `packetPool` immediately after copying it into `bufs`, and returns the carrier to its pool only after the last slab is consumed.
6. Teardown drains both the pending carrier and the channel.

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
+// maxQueuedInboundPackets preserves the packet bound of the previous
+// chan []byte at depth 65536. The channel now carries batch descriptors, so
+// the bound is enforced by credits rather than by channel capacity.
+const maxQueuedInboundPackets int64 = 65536
+
+// inboundCarrier hands ownership of a run of pooled slabs across the channel.
+// The backing array is copied on offer, so the producer may reuse its local
+// batch slice immediately without racing the consumer on slice headers.
+type inboundCarrier struct {
+	packets [][]byte
+}
+
+var inboundCarrierPool = sync.Pool{
+	New: func() any {
+		return &inboundCarrier{packets: make([][]byte, 0, maxInboundBatchPackets)}
+	},
+}
+
 type frameDevice struct {
 	// ...
-	toEngine chan []byte
+	// 8192 slots * 8 B = 64 KiB, against 65536 * 24 B = 1.5 MiB for the
+	// previous per-packet channel. Credits bind before slots for any carrier
+	// averaging 8 packets or more; the degenerate one-packet-per-carrier case
+	// still buffers 8192 packets = 1.38 BDP at 1 Gbps / 65 ms.
+	toEngine chan *inboundCarrier
+
+	queuedInbound atomic.Int64
+
+	// Carrier spill state. ReadBatch is single-consumer (one engine read
+	// goroutine per device) and these fields are not otherwise synchronized.
+	pendingInbound      *inboundCarrier
+	pendingInboundIndex int
 }
@@ device construction
-		toEngine: make(chan []byte, 65536),
+		toEngine: make(chan *inboundCarrier, 8192),
+
+// reserveInbound grants up to n packet credits and returns the number granted.
+// Partial grants keep overload drop granularity at one packet, matching the
+// per-packet enqueue loop this replaces.
+func (d *frameDevice) reserveInbound(n int) int {
+	for {
+		cur := d.queuedInbound.Load()
+		room := maxQueuedInboundPackets - cur
+		if room <= 0 {
+			return 0
+		}
+		grant := int64(n)
+		if grant > room {
+			grant = room
+		}
+		if d.queuedInbound.CompareAndSwap(cur, cur+grant) {
+			return int(grant)
+		}
+	}
+}
+
+// releasePendingInbound returns a partially consumed carrier on teardown so
+// pooled slabs are not stranded across rebind cycles.
+func (d *frameDevice) releasePendingInbound() {
+	carrier := d.pendingInbound
+	if carrier == nil {
+		return
+	}
+	for i := d.pendingInboundIndex; i < len(carrier.packets); i++ {
+		packetPool.Put(carrier.packets[i])
+		carrier.packets[i] = nil
+	}
+	d.queuedInbound.Add(-int64(len(carrier.packets) - d.pendingInboundIndex))
+	carrier.packets = carrier.packets[:0]
+	inboundCarrierPool.Put(carrier)
+	d.pendingInbound = nil
+	d.pendingInboundIndex = 0
+}
```

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
-func (s *frameServer) offerBatch(pkts [][]byte) {
-	for _, p := range pkts {
-		select {
-		case s.toEngine <- p:
-		default:
-			s.inboundDropped.Add(1)
-			packetPool.Put(p)
-		}
-	}
-}
+func (s *frameServer) offerBatch(pkts [][]byte) {
+	if len(pkts) == 0 {
+		return
+	}
+	granted := s.dev.reserveInbound(len(pkts))
+	// Tail drop at one packet granularity, exactly as the previous per-packet
+	// loop did. A whole-batch discard here would drop hundreds of contiguous
+	// segments across concurrent flows and force RTO instead of SACK recovery.
+	for i := granted; i < len(pkts); i++ {
+		packetPool.Put(pkts[i])
+		pkts[i] = nil
+	}
+	if dropped := len(pkts) - granted; dropped > 0 {
+		s.inboundDropped.Add(uint64(dropped))
+	}
+	if granted == 0 {
+		return
+	}
+	carrier := inboundCarrierPool.Get().(*inboundCarrier)
+	carrier.packets = append(carrier.packets[:0], pkts[:granted]...)
+	select {
+	case s.dev.toEngine <- carrier:
+		// Ownership of every slab in the carrier passes to the consumer.
+	default:
+		for i, p := range carrier.packets {
+			packetPool.Put(p)
+			carrier.packets[i] = nil
+		}
+		s.dev.queuedInbound.Add(-int64(granted))
+		s.inboundDropped.Add(uint64(granted))
+		carrier.packets = carrier.packets[:0]
+		inboundCarrierPool.Put(carrier)
+	}
+}
```

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
 func (d *frameDevice) ReadBatch(bufs [][]byte, sizes []int, offset int) (int, error) {
-	pkt, ok := <-d.toEngine
-	if !ok {
-		return 0, os.ErrClosed
-	}
-	n := 0
-	sizes[n] = copy(bufs[n][offset:], pkt)
-	packetPool.Put(pkt)
-	n++
-	for n < len(bufs) {
-		select {
-		case pkt, ok := <-d.toEngine:
-			if !ok {
-				return n, nil
-			}
-			sizes[n] = copy(bufs[n][offset:], pkt)
-			packetPool.Put(pkt)
-			n++
-		default:
-			return n, nil
-		}
-	}
-	return n, nil
+	n := 0
+	for n < len(bufs) {
+		if d.pendingInbound == nil {
+			if n > 0 {
+				// Do not block once the caller has packets in hand.
+				select {
+				case carrier, ok := <-d.toEngine:
+					if !ok {
+						return n, nil
+					}
+					d.pendingInbound = carrier
+					d.pendingInboundIndex = 0
+				default:
+					return n, nil
+				}
+			} else {
+				carrier, ok := <-d.toEngine
+				if !ok {
+					return 0, os.ErrClosed
+				}
+				d.pendingInbound = carrier
+				d.pendingInboundIndex = 0
+			}
+		}
+		carrier := d.pendingInbound
+		for n < len(bufs) && d.pendingInboundIndex < len(carrier.packets) {
+			pkt := carrier.packets[d.pendingInboundIndex]
+			sizes[n] = copy(bufs[n][offset:], pkt)
+			packetPool.Put(pkt)
+			carrier.packets[d.pendingInboundIndex] = nil
+			d.pendingInboundIndex++
+			d.queuedInbound.Add(-1)
+			n++
+		}
+		if d.pendingInboundIndex == len(carrier.packets) {
+			carrier.packets = carrier.packets[:0]
+			inboundCarrierPool.Put(carrier)
+			d.pendingInbound = nil
+			d.pendingInboundIndex = 0
+		}
+	}
+	return n, nil
 }
```

The existing `Close` path must call `d.releasePendingInbound()` and then drain `toEngine`, returning every slab in every remaining carrier and zeroing `queuedInbound`. Without it, teardown strands up to 65,536 slabs per session, which shows up as a leak across rebind cycles rather than as a test failure.

Two semantics changes that require test review rather than re-baselining. `inboundDropped` now increments by the shortfall count rather than once per failed send, so any test asserting an exact drop count changes meaning. And `packetPool.Put(p)` with `p` of type `[]byte` boxes a slice header into an interface on every call; that is the existing idiom and is preserved to keep the diff surgical, but `staticcheck` SA6002 will flag it. Converting the pool to `*[]byte` changes producer and consumer together and belongs in a separate item.

**Execution order, answering the Arbiter's OI-3 question directly.** Land OI-1 and OI-2 as deployment A, with the two counters from Section 6 instrumented. Land OI-3B as deployment B. Reasons, in order of weight: OI-3B's value spans 2.73% to 36.4% of a core depending on a quantity nobody has measured, and deployment A's counters resolve that span before the riskier change is committed; bundling all three makes attribution impossible across a 7% to 19% combined effect that is comparable to run-to-run variance; and OI-3B carries the only pool-ownership and teardown-leak surface in the round, which is better isolated in its own commit for bisection. If the council insists on a single deployment, my AGREE still holds provided OI-3B ships with `go test -race` green and a teardown drain test asserting `queuedInbound == 0` and full pool return after `Close`.

---

## 5. Convergence votes

- **OI-1: AGREE.** Arbiter ground truth 1 retires my Turn 1 objection on both counts: delivery is now gated, not just the pointer advance, and the epoch enumeration (`rebindDevice:851`, `close:894` only) proves normal publishes cannot invalidate a claim. My AGREE is on the Section 4.1 text. Flip condition, stated so it is testable rather than rhetorical: if the ratified text retains the stateless `canAppend` claim loop from either peer diff, I vote DISAGREE, falsified by a ring holding more than `packetCapacity` packets, where Phase 1 claims `count` and Phase 2 overflows the batch on append number `packetCapacity + 1`.

- **OI-2: AGREE.** Class defaults frozen, uplink instance explicit, `tun.go` untouched, preconditions widened, 2 MiB send buffer against a 694.5 KiB maximum batch. The uplink stream is a sequence of independently length-prefixed frames, so no wire byte and no frame boundary changes. Recorded non-blocking exception: the isolated contribution is 0.012 µs per packet, roughly 0.107% of one core at target rate, so any certification language attributing a material share of the 584.5 Mbps gap to this item is arithmetically false. Recommendation carried forward: restrict the 2 MiB change to `sendBufferSize`.

- **OI-3: AGREE.** Option A rejected under the docket definition. Option B as specified in Section 4.3, with partial credit reservation preserving the 65,536 packet bound and one-packet drop granularity, which answers Gemini's TCP objection without discarding the item. Sequenced as deployment B behind the Section 6 measurement.

- **OI-4: AGREE.** The invariant set is correct and sufficient. Two additions and one clarification are in Section 6. The clarification matters procedurally: OI-1 requires new concurrency tests, so the test total rises above 601 and Sol Pro's `assert tests == 601` will fail on a correct tree. The invariant should read "all 601 pre-existing tests pass with zero failures and zero errors, total count greater than or equal to 601".

Recorded exception, non-blocking on all four items and directed at the round's stated goal rather than its changes. Section 3.2 bounds this round at 495.2 Mbps under the optimistic parked-channel branch and 420.2 Mbps under the hot branch. If the certified specification text asserts that OI-1 through OI-3 reach 1,000 Mbps, I vote DISAGREE on that text specifically, falsified by the requirement to remove 15.98 µs per packet against a 4.26 µs ceiling across the three items.

---

## 6. Verification, and the two items that close the residual gap

Gates, adding to the Arbiter's set. Names in angle brackets must come from the repository.

```
./gradlew --no-daemon :app:testDebugUnitTest :app:lintDebug
./gradlew --no-daemon :app:testDebugUnitTest --tests '*WinnV3AndroidTunConcurrency*'
```

New Android tests required by OI-1, none of which exist today: rebind injected between Phase 1 and Phase 2, asserting the returned batch is empty and the return value is 0 with no torn frame; two concurrent `readOutgoingBatch` callers, asserting `IllegalStateException`; a ring holding more than `packetCapacity` packets, asserting the claim is capped at `packetCapacity` and no overflow occurs; `close()` during Phase 2, asserting return of -1 and an empty batch; a call site test asserting the pump loops rather than terminating on a 0 return.

```
cd winn_protocol_experimental
gofmt -l ./cmd/winn-datapath
go vet ./...
go test ./... -count=1
go test -race -count=1 ./cmd/winn-datapath/... ./winn3/... ./session/...
go test -run TestInboundCarrier -race -count=200 ./cmd/winn-datapath/...
```

Two gates absent from the Arbiter's list and mandatory given that OI-4 asserts bit-identical framing. First, wire identity: frame a fixed 1,000-packet corpus through `WinnFraming`, SHA-256 the resulting stream, and compare against the digest captured on the parent commit, in both Kotlin and Go, over Sol Pro's vector set (empty rejection, minimum IPv4, 1373 B, maximum accepted, 256-packet sequence, 512-packet sequence, mixed lengths), comparing complete framed bytes rather than decoded fields. Second, frozen-path proof:

```
git diff --exit-code -- winn_protocol_experimental/winn3/tun/tun.go
git diff -- android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
```

The second must show only the `require` widening and the new `planClaim` and `admits` members, with both default argument values byte-identical.

Physical protocol: five 8-second runs per configuration against the gateway, median reported with p10 and p90, same band and MLO state, battery above 50%, `adb shell dumpsys thermalservice` clean before each run. A 7% to 19% effect is not resolvable from a single run. Any delta smaller than the baseline p10-to-p90 spread is not a result.

The two counters that decide OI-3B's value, neither of which appears in the packet:

- **Wakeup rate.** `adb shell simpleperf stat -p <vpn_pid> -e task-clock,context-switches,sched:sched_switch --duration 8`, plus `GODEBUG=schedtrace=1000` on the datapath process. Near 37,000 context switches per second means roughly one wakeup per packet, OI-3B takes the 4.00 µs branch, and it is the dominant item in the round. Near 150 per second means wakeups are already amortized per batch, OI-3B takes the 0.30 µs branch and is worth under 3%.
- **Actual batch occupancy.** Histogram `batch.count` and `batch.byteLength` at the `readOutgoingBatch` return, and `len(pkts)` at `offerBatch`. If p99 `batch.count` sits materially below 256 today, OI-2 raises a ceiling that is never reached and its measured effect is exactly zero, which independently falsifies the item.

Two items for a Turn 2 amendment, unaddressed by this round and larger than everything in it by Section 3.2:

- **OI-5, outer UDP transmit batching.** If the outer socket issues one `sendto` per inner packet, 1,000 Mbps costs 91,041 syscalls per second at roughly 2.0 µs each, about 182 ms/s and 18.2% of a core, plus 91,041 kernel Wi-Fi transmit entries. `UDP_SEGMENT` (GSO) at 45 segments per 64 KiB write, or `sendmmsg`, cuts that to roughly 2,000 syscalls per second, recovering up to 1.96 µs per packet. That single item is larger than OI-1, OI-2, and OI-3 combined. Kernel 6.x on the target device supports both.
- **OI-6, TUN read floor.** A tun fd is not a socket, so there is no `recvmmsg` and no `IFF_VNET_HDR` through `VpnService`. 91,041 `read()` calls per second at about 1.7 µs is roughly 155 ms/s, a hard floor of 15.5% of a core that sets the first stage's per-packet latency. It should be measured rather than assumed, since it bounds whatever architecture replaces the current uplink path.
