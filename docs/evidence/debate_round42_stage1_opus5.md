# Turn 1 Verdict: claude-opus5

## 0. Scope note

No tools were permitted, so no file in `/private/tmp/r42_seat_claude` was read. Every diff below is anchored to the code text quoted inside the packet itself (Sections 2.1, 2.2, 2.3) and to symbol names the packet asserts exist. They are reconstructions, not verified exact edits: each must be re-anchored against the real file before application, and any hunk whose context does not match verbatim is invalid and must be regenerated, not forced.

---

## 1. VERDICT

| Item | Vote |
|---|---|
| OI-1 | **DISAGREE:** Phase 3 gates only the `head`/`count` advance on `queueEpoch == epoch`. It does not gate *delivery*. On an epoch change during Phase 2 the ring is reset and the producer refills the claimed slots, so `batch` already holds torn/duplicated payload bytes and is still returned to the caller with `batch.count > 0`. Falsifiable in one unit test: claim a batch, invoke `discard()`/rebind between Phase 1 and Phase 2, assert the returned frames against the pre-discard corpus. |
| OI-2 | **DISAGREE:** two independent defects. (a) Arithmetic: at the 1,000 Mbps target, 256-packet batching already costs 355.6 write/read pairs per second ≈ 2.1 ms of CPU per second (0.21% of one core); halving it recovers ≈1 ms/s, which is below run-to-run variance and cannot move 415.5 Mbps. (b) Correctness against OI-4: changing the **class defaults** in `WinnV3PacketBatch.kt` changes the downlink batch allocation too, violating the Round 35/38 freeze on downlink buffer allocations. |
| OI-3 | **DISAGREE:** Option A is unsound as stated. `allocPacket(pay)` copies out of the frame reader's internal `r.buffer`; deleting that copy publishes a slice aliasing a buffer that the next `reader.Read()` overwrites, producing a read/write data race and corrupted inner packets. Detectable with `go test -race` plus a concurrent reader driving >1 frame per drain. Option B alone is sound and is the only one of the three items with a defensible magnitude. |
| OI-4 | **AGREE.** Constraints are correct and sufficient. Verification command set and the two missing gates (wire-identity golden vectors, race detector) are specified in Section 5. |

Structural finding that outranks all four votes: OI-1 + OI-2 + OI-3B together are bounded at roughly +6% to +13%. The round as packaged cannot reach 1,000 Mbps and the packet contains no measurement that discriminates the actual limiter. Section 6 gives the one command that does.

---

## 2. FIRST-PRINCIPLES ARITHMETIC

### 2.1 Rate identities

Target 1,000 Mbps = 125.0 MB/s. At 1373 B inner MTU: 125,000,000 / 1373 = **91,041 pps**, 10.98 µs per packet of aggregate budget. Packet's figure confirmed.

Run 14: 415,498,240 B / 8.000 s = 51,937,280 B/s = **415.5 Mbps**, 51,937,280 / 1373 = **37,827 pps**, 26.44 µs per packet. (The reported byte total equals the bit rate numerically only because the 8-second window cancels the 8 bits/byte factor. Coincidence, not an error.)

Gap to close: 2.407×.

### 2.2 Per-packet cost inventory at the 91,041 pps target

Copy bandwidth assumption: 1373 B at 10-13 GB/s effective single-core streaming on Oryon ≈ **0.11 µs per copy**.

| Stage | Per packet | Per second at 91,041 pps | % of one core |
|---|---|---|---|
| TUN `read()` syscall + framework/JNI | ~1.7 µs | 155 ms | 15.5% |
| staging → ring slab copy | 0.11 µs | 10 ms | 1.0% |
| `batch.append` (5 puts + `System.arraycopy`) | 0.15-0.25 µs | 14-23 ms | 1.4-2.3% |
| `LocalSocket` write, amortized over 256 | 0.012 µs | 1.1 ms | 0.11% |
| Go `allocPacket` copy + pool | 0.16 µs | 15 ms | 1.5% |
| Go channel send + recv (hot, no park) | 0.30 µs | 27 ms | 2.7% |
| Go channel send + recv (parked, cross-core unpark) | 4.0 µs | 364 ms | 36.4% |
| `ReadBatch` copy | 0.11 µs | 10 ms | 1.0% |
| `EnqueueBatch` copy | 0.11 µs | 10 ms | 1.0% |
| AEAD seal (arm64 asm, ~2.5 GB/s) | 0.55 µs | 50 ms | 5.0% |
| Outer UDP `sendto`, one per packet | ~2.0 µs | 182 ms | 18.2% |

Two conclusions fall straight out.

**All three memory copies in the Go engine together cost 0.38 µs per packet = 35 ms/s = 3.5% of one core at full target rate.** Eliminating every one of them buys at most 3.5%. OI-3 Option A is chasing 3.5% while introducing a use-after-overwrite race.

**The only line in the table that can plausibly consume a third of a core is the channel pair under parking**, and the only line that is large *and* structurally unavoidable without a design change is the per-packet `sendto`. Neither is addressed by OI-1 or OI-2.

### 2.3 OI-1 magnitude

`batch.append` × 256 packets at 0.15-0.25 µs = **38-64 µs monitor hold** per batch. At the target rate, 91,041 / 256 = 355.6 batches/s, so monitor duty cycle = 355.6 × 64 µs = **22.8 ms/s = 2.3% of one core**. At the observed 37,827 pps it is 147.8 batches/s × 64 µs = 9.5 ms/s = **0.95%**.

Add the producer's park/unpark when it collides: Android futex park→unpark round trip ≈ 5-20 µs, at most 355 collisions/s = 7 ms/s. Total OI-1 headroom: **under 3% of one core**. It is worth doing for jitter and for the stall bound, not for throughput.

Producer exposure during the claim window: at 91,041 pps ingress, a 64 µs window admits 91,041 × 64e-6 = **5.8 packets**; a 512-packet window (130 µs) admits **11.8 packets**. Ring overrun risk is therefore negligible *provided the window is bounded*, which is the reason the amended design commits in chunks rather than all-or-nothing.

### 2.4 OI-2 magnitude

At 91,041 pps: 256-packet batches → 355.6 iterations/s; 512-packet batches → 177.8 iterations/s. Saving = 177.8 write+read pairs per second. At a generous 6 µs per pair including the kernel copy scheduling: **1.07 ms/s = 0.107% of one core**. The packet's rationale ("halving kernel context switches and channel synchronization events") is arithmetically real and economically zero.

Byte-capacity check for 512 packets, assuming a 12-byte frame header: 512 × (1373 + 12) = **709,120 B = 692.5 KiB**. The proposed 512 KiB (524,288 B) caps at 524,288 / 1385 = **378 packets**, so the proposed `packetCapacity = 512` with `byteCapacity = 512 KiB` would never reach 512 at full MTU anyway. 768 KiB (786,432 B) admits all 512 with 77,312 B spare.

Socket-buffer interaction: a 1 MiB `byteCapacity` against a 1 MiB `SO_SNDBUF` means a full batch consumes the entire send buffer, so the writer blocks until the peer drains and the handoff degrades to lockstep. Design rule: **max batch bytes ≤ ½ socket buffer**, so 692.5 KiB requires ≥ 1,385 KiB, round to 2 MiB. `net.core.wmem_max = 8388608` permits a 2 MiB request (kernel stores `2 × val` = 4 MiB accounted, still under the 8 MiB cap). No sysctl change needed.

Memory: 768 KiB per uplink batch instance. Two instances (double-buffered) = 1.5 MiB. Acceptable, but only if the downlink instance keeps its frozen 256/512 KiB geometry, which requires constructor-site parameters rather than default changes.

### 2.5 OI-3 Option B magnitude

Channel operations per packet drop from 2 to 2/512 = 0.0039. Saving per packet = 0.30 µs (hot path) to 4.0 µs (park path):

- hot-receiver case: 0.30 × 91,041 = 27 ms/s recovered = **2.7% of a core**
- parking case: 4.0 × 91,041 = 364 ms/s recovered = **36.4% of a core**

Channel ring memory: `chan []byte` at depth 65536 holds 65536 × 24 B slice headers = **1.57 MB** resident. A carrier channel at depth 16 holds 16 × 8 B = 128 B.

Queue-depth sanity, because the existing depth is wrong in the other direction: BDP at 1 Gbps × 65 ms RTT = 8.125 MB = **5,917 packets of 1373 B**. The current 65,536-packet channel is 11 BDP ≈ 720 ms of standing buffer, and worst-case pool residency is 65,536 × 2048 = **134 MB** on a phone. A carrier channel of depth 16 × 512 = 8,192 packets = 1.38 BDP = 90 ms, worst-case 16.8 MB. Switching to carriers should reduce depth, not preserve 65,536.

### 2.6 Combined projection on SM-S948U1 against <NODE_CANADA_IP>

Baseline 415.5 Mbps.

| Change | Δ | Result |
|---|---|---|
| OI-1 amended | +0% to +3% | 415.5 → 415-428 |
| OI-2 amended | +0% to +1% | 428 → 428-432 |
| OI-2 **as written** (1 MiB batch vs 1 MiB sndbuf) | −3% to −8% | regression risk |
| OI-3 Option B | +3% to +15% | 432 → 445-497 |
| **All three, amended** | **+7% to +19%** | **445-495 Mbps** |

Residual gap to 1,000 Mbps after the full round lands: **2.0× to 2.25×**. No combination of OI-1, OI-2, and OI-3 reaches the stated target, and any position claiming otherwise must show which line of the Section 2.2 table it is retiring.

### 2.7 What the 26.44 µs per packet actually implies

Section 2.2 sums to roughly 5.5 µs per packet of real work, split across at least two processes and multiple cores. Observed is 26.44 µs of wall time per packet with **zero drops at the sink**. Zero drops means the sink is never overrun, so the pipeline is pull-limited: it is starved, not saturated. A starved pipeline with ~5× more wall time than work time is the signature of a serialized wakeup chain, one park/unpark per unit of work, where the unit is far smaller than the configured batch cap. That hypothesis makes an exact prediction, given in Section 6.

---

## 3. EXACT DIFFS

### 3.1 OI-1 amended: bounded-window chunked claim with commit-time validation

Two defects are corrected relative to the proposal: delivery is gated on the epoch, not just the pointer advance; and the unlocked window is bounded by `CLAIM_CHUNK` instead of by the whole batch, capping producer stall at ~16 µs regardless of OI-2.

Preconditions that must be verified in the real file before applying, since each one makes the epoch check unsound if false:
1. `queueEpoch` is a 64-bit monotonically non-decreasing counter, incremented under `synchronized(state)` by **every** path that resets `head`/`count` or rewrites already-published slots (discard, rebind, close). If it is an `Int`, or if discard does not bump it, this patch is invalid.
2. `readOutgoingBatch` has exactly one caller thread. The added `claimActive` check converts a violation into a loud failure instead of silent duplicate delivery.
3. `WinnV3PacketBatch` exposes `count` and `byteLength` reads.

```diff
--- a/.../WinnV3AndroidTun.kt
+++ b/.../WinnV3AndroidTun.kt
@@ companion object
     const val MAX_BURST_PACKETS = 512
+    // Bounds the unlocked copy window so the producer never stalls longer than
+    // CLAIM_CHUNK * per-packet framing cost (64 * ~0.25us = ~16us).
+    private const val CLAIM_CHUNK = 64
 
@@ state fields
     private val state = Object()
+    // Guards the single-consumer invariant of readOutgoingBatch: Phase 2 runs
+    // unlocked, so a second consumer would claim the same slots.
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
+        while (true) {
+            batch.clear()
+            var generation = 0
+            var epoch = 0L
+            var aborted = false
+            synchronized(state) {
+                check(!claimActive) { "Winn tun readOutgoingBatch is single-consumer" }
+                if (!awaitPacket()) {
+                    aborted = true
+                } else {
+                    generation = readerGeneration.get()
+                    epoch = queueEpoch
+                    claimActive = true
+                }
+            }
+            if (aborted) return -1
+            batch.generation = generation
+            var stale = false
+            try {
+                while (true) {
+                    var claimHead = 0
+                    var claimCount = 0
+                    var drained = false
+                    // Phase 1: claim without advancing head/count, so the producer
+                    // still treats these slots as unread and cannot overwrite them.
+                    synchronized(state) {
+                        if (closed.get() || readerGeneration.get() != generation || queueEpoch != epoch) {
+                            stale = true
+                        } else {
+                            claimHead = head
+                            var taken = 0
+                            var bytes = batch.byteLength
+                            while (taken < CLAIM_CHUNK && taken < count) {
+                                val len = lengths[(claimHead + taken) % queueDepth]
+                                if (!batch.admits(batch.count + taken, bytes, len)) break
+                                bytes += WinnFraming.frameLength(len)
+                                taken++
+                            }
+                            claimCount = taken
+                            if (taken == 0) drained = true
+                        }
+                    }
+                    if (stale || drained) break
+                    // Phase 2: framing and payload copy with the monitor released.
+                    // Visibility: the Phase 1 monitor acquire is ordered after the
+                    // producer's publishing release, and these reads follow it in
+                    // program order on this thread, so the slab bytes are visible
+                    // without an extra fence.
+                    var i = 0
+                    while (i < claimCount) {
+                        val slot = (claimHead + i) % queueDepth
+                        batch.append(WinnFraming.OP_INBOUND, slab, slot * packetCapacity, lengths[slot])
+                        i++
+                    }
+                    // Phase 3: commit only if the ring was untouched for the whole
+                    // unlocked window. On mismatch the copied bytes are suspect and
+                    // the entire batch is discarded rather than delivered.
+                    synchronized(state) {
+                        if (closed.get() || readerGeneration.get() != generation || queueEpoch != epoch) {
+                            stale = true
+                        } else {
+                            head = (claimHead + claimCount) % queueDepth
+                            count -= claimCount
+                            if (waiters > 0) (state as Object).notifyAll()
+                        }
+                    }
+                    if (stale) break
+                }
+            } finally {
+                synchronized(state) { claimActive = false }
+            }
+            if (stale) {
+                batch.clear()
+                if (closed.get()) return -1
+                continue
+            }
+            if (batch.count == 0) throw IOException("Winn tun batch destination too small")
+            return batch.count
+        }
+    }
```

The `(state as Object).notifyAll()` form must match the idiom already used by `awaitPacket` and the producer publish path in this file. Do not introduce a second notify style.

Supporting change, so Phase 1 admission and `canAppend` cannot drift apart:

```diff
--- a/.../WinnV3PacketBatch.kt
+++ b/.../WinnV3PacketBatch.kt
+    /** Pure admission predicate. Single source of truth for capacity accounting. */
+    fun admits(currentCount: Int, currentBytes: Int, length: Int): Boolean =
+        currentCount < packetCapacity &&
+            currentBytes + WinnFraming.frameLength(length) <= byteCapacity
+
-    fun canAppend(length: Int): Boolean = /* existing inline accounting */
+    fun canAppend(length: Int): Boolean = admits(count, byteLength, length)
```

`WinnFraming.frameLength(length)` must return exactly the byte count `append` writes (header plus payload). If no such helper exists, add it beside the header constant `append` already uses; do not hardcode a second literal.

### 3.2 OI-2 amended: uplink-only geometry, 768 KiB, 2 MiB socket buffers

Class defaults stay frozen so the downlink allocation is bit-identical to Round 38.

```diff
--- a/.../WinnV3PacketBatch.kt
+++ b/.../WinnV3PacketBatch.kt
-    val packetCapacity: Int = 256,
-    val byteCapacity: Int = 512 * 1024,
+    val packetCapacity: Int = 256,
+    val byteCapacity: Int = 512 * 1024,
```

(No change. The default is the downlink geometry and is frozen.)

```diff
--- a/.../WinnV3Bridge.kt
+++ b/.../WinnV3Bridge.kt
-    private val uplinkBatch = WinnV3PacketBatch()
+    // Uplink geometry only. 512 * (1373 MTU + frame header) = 709,120 B, so
+    // 768 KiB admits a full 512-packet batch with 77,312 B of headroom.
+    // Downlink keeps the frozen 256 / 512 KiB defaults (Treaty R35/R38).
+    private val uplinkBatch = WinnV3PacketBatch(
+        packetCapacity = 512,
+        byteCapacity = 768 * 1024,
+    )
```

```diff
--- a/.../<LocalSocket buffer sizing site from Run 14 change #3>
+++ b/.../<same>
-        socket.sendBufferSize = 1 * 1024 * 1024
-        socket.receiveBufferSize = 1 * 1024 * 1024
+        // Max uplink batch is 692.5 KiB; keep it at or below half the socket
+        // buffer so the next batch can be written while the previous drains.
+        // net.core.wmem_max = 8 MiB on SM-S948U1, so 2 MiB is accepted.
+        socket.sendBufferSize = 2 * 1024 * 1024
+        socket.receiveBufferSize = 2 * 1024 * 1024
```

```diff
--- a/cmd/winn-datapath/winn3_frame.go
+++ b/cmd/winn-datapath/winn3_frame.go
-	inboundBatch := make([][]byte, 0, 256)
+	inboundBatch := make([][]byte, 0, maxInboundBatch)
```

```diff
--- a/cmd/winn-datapath/winn3_frame.go
+++ b/cmd/winn-datapath/winn3_frame.go
+// maxInboundBatch mirrors the Kotlin uplink batch packetCapacity. Changing one
+// without the other only wastes slice capacity; it is not a wire-format value.
+const maxInboundBatch = 512
```

`winn3/tun/tun.go` `pumpOutboundBatch batchSize = 256` is **held at 256 pending an Arbiter ruling**. "Outbound" in `tun.go` is named from the engine's perspective and, if it feeds the tun device, it is the downlink path and is frozen by OI-4. Confirm the direction from the call site before touching it. Changing it costs 1 ms/s of CPU by Section 2.4 and risks a treaty violation, so the expected value is negative until the direction is established.

### 3.3 OI-3 Option B: carrier batching through `toEngine`

Option A is rejected outright. Option B, with pool ownership stated explicitly: a packet slab is owned by the producer until the carrier is accepted by the channel, then by the consumer, which returns it to `packetPool` immediately after the `copy` into `bufs`. On a failed send the producer returns every slab itself. On close the drainer returns everything still queued.

```diff
--- a/cmd/winn-datapath/winn3_frame.go
+++ b/cmd/winn-datapath/winn3_frame.go
-	toEngine chan []byte
+	toEngine chan *[][]byte
 
+// Carrier pool avoids allocating a [][]byte per batch handoff.
+var batchCarrierPool = sync.Pool{
+	New: func() any {
+		s := make([][]byte, 0, maxInboundBatch)
+		return &s
+	},
+}
+
-	toEngine: make(chan []byte, 65536),
+	// Depth in batches, not packets. 16 * 512 = 8,192 packets = 1.38 BDP at
+	// 1 Gbps / 65 ms (BDP = 5,917 packets). The prior 65,536-packet depth was
+	// 11 BDP (~720 ms of standing queue, 134 MB of worst-case pool residency).
+	toEngine: make(chan *[][]byte, 16),
 
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
+	carrier := batchCarrierPool.Get().(*[][]byte)
+	*carrier = append((*carrier)[:0], pkts...)
+	select {
+	case s.toEngine <- carrier:
+		// Ownership of every slab in the carrier passes to the consumer.
+	default:
+		for i, p := range *carrier {
+			packetPool.Put(p)
+			(*carrier)[i] = nil
+		}
+		s.inboundDropped.Add(uint64(len(*carrier)))
+		*carrier = (*carrier)[:0]
+		batchCarrierPool.Put(carrier)
+	}
+}
```

Field and counter names (`toEngine`, `inboundDropped`, `packetPool`) must be matched to the real declarations; `inboundDropped` in particular now increments by batch length rather than by one, so any test asserting drop counts changes semantics and must be reviewed rather than re-baselined.

```diff
--- a/cmd/winn-datapath/winn3_frame_device.go
+++ b/cmd/winn-datapath/winn3_frame_device.go
 type frameDevice struct {
 	// ...
+	// Carrier spill state. ReadBatch is single-consumer (one engine read
+	// goroutine per device); these fields are not otherwise synchronized.
+	pending    *[][]byte
+	pendingIdx int
 }
 
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
+	if d.pending == nil {
+		carrier, ok := <-d.toEngine
+		if !ok {
+			return 0, os.ErrClosed
+		}
+		d.pending = carrier
+		d.pendingIdx = 0
+	}
+	src := *d.pending
+	n := 0
+	for d.pendingIdx < len(src) && n < len(bufs) {
+		pkt := src[d.pendingIdx]
+		sizes[n] = copy(bufs[n][offset:], pkt)
+		packetPool.Put(pkt)
+		src[d.pendingIdx] = nil
+		d.pendingIdx++
+		n++
+	}
+	if d.pendingIdx == len(src) {
+		*d.pending = src[:0]
+		batchCarrierPool.Put(d.pending)
+		d.pending = nil
+		d.pendingIdx = 0
+	}
+	return n, nil
 }
+
+// releasePending returns any partially consumed carrier on teardown so pooled
+// slabs are not stranded.
+func (d *frameDevice) releasePending() {
+	if d.pending == nil {
+		return
+	}
+	src := *d.pending
+	for i := d.pendingIdx; i < len(src); i++ {
+		packetPool.Put(src[i])
+		src[i] = nil
+	}
+	*d.pending = src[:0]
+	batchCarrierPool.Put(d.pending)
+	d.pending = nil
+	d.pendingIdx = 0
+}
```

The existing `Close` path must call `releasePending` and then drain `toEngine`, returning every slab in every remaining carrier. Without that, teardown strands up to 8,192 slabs (16.8 MB) per session, which will show as a leak across rebind cycles.

`packetPool.Put(p)` with `p` of type `[]byte` boxes a slice header into an interface on every call. That is the existing idiom and is preserved here to keep the diff surgical, but `go vet`'s `SA6002` equivalent will flag it; if the pool is later converted to `*[]byte`, both the producer and consumer sides change together.

---

## 4. THREAD-SAFETY ANALYSIS FOR OI-1 (JMM)

**Payload visibility.** The producer writes packet bytes into `slab`, then publishes by mutating `count` inside `synchronized(state)`. The monitor release at the end of that block happens-before the consumer's monitor acquire in Phase 1. The consumer's Phase 2 reads of `slab` follow that acquire in program order on the same thread, and happens-before is transitive, so the producer's slab writes are visible in Phase 2 without any additional volatile or fence. Publishing `lengths[]` must occur inside the same producer critical section as the `count` mutation; if it does not, this argument fails and the patch is invalid.

**Producer exclusion.** Phase 1 records `claimHead` and `claimCount` but leaves `head` and `count` untouched, so the producer's free-slot computation (`queueDepth - count`) still excludes the claimed slots for the whole unlocked window. No overwrite is possible absent a reset.

**Reset races.** `discard`, `rebind`, and `close` are the only operations that can invalidate a claim, and they are exactly the operations that bump `queueEpoch` or `readerGeneration`. Phase 3 rechecks all three under the monitor; on any mismatch the batch is cleared and not delivered. Because `queueEpoch` is monotone, there is no ABA window. Chunking bounds the discarded work to at most `CLAIM_CHUNK` packets of copy rather than the full batch.

**Multiple consumers.** Not safe, and never was under the proposal as written. `claimActive` turns the violation into an `IllegalStateException` at the first colliding call instead of silent duplicate transmission.

**Exception safety.** `batch.append` can throw; the `finally` clears `claimActive` under the monitor, so a throwing consumer does not wedge the queue permanently.

**Backpressure.** `notifyAll` now fires at chunk commit rather than at batch completion, so producers waiting on free slots wake up to 8× sooner for a 512-packet batch. This is a strict improvement over both the current code and the proposal.

---

## 5. OI-4 COMPLIANCE AND VERIFICATION

Compliance under the amended items: downlink `WinnV3PacketBatch` geometry unchanged (defaults untouched); `tun.go` `batchSize` held pending direction confirmation; no measurement mathematics touched; `WinnFraming.OP_INBOUND` and the header layout untouched, so the byte stream is unchanged. OI-1 as originally proposed would have violated the bit-identity invariant through torn frames on rebind, which is the primary basis for that DISAGREE.

Verification commands. Names marked `<...>` must be taken from the repository, not invented.

```
# Android, all 601 tests
./gradlew --no-daemon test
./gradlew --no-daemon :app:testDebugUnitTest --tests '*WinnV3*'

# Concurrency-specific: must be added, not assumed present
#  - discard()/rebind injected between Phase 1 and Phase 2, assert no torn frame
#  - two concurrent readOutgoingBatch callers, assert IllegalStateException
#  - ring-full producer during a CLAIM_CHUNK window, assert zero overwrite
./gradlew --no-daemon :app:testDebugUnitTest --tests '*WinnV3AndroidTunConcurrency*'

# Go
go build ./...
go vet ./...
go test ./... -count=1
go test -race -count=1 ./cmd/winn-datapath/... ./winn3/... ./session/...
go test -run TestFrameCarrier -race -count=200 ./cmd/winn-datapath/...

# Wire identity, mandatory addition
#  Frame a fixed 1,000-packet corpus through WinnFraming, SHA-256 the stream,
#  compare against the pre-change digest captured on the parent commit.
./gradlew --no-daemon :app:testDebugUnitTest --tests '*WinnFramingGoldenVector*'
go test -run TestWinnFramingGoldenVector -count=1 ./cmd/winn-datapath/...

# Gates
./gradlew --no-daemon lintDebug          # NewApi / API-level gate
<repository's existing forbidden-import task>
```

Physical measurement protocol, since a single 8 s run cannot resolve a 7-19% effect: five runs per configuration against <NODE_CANADA_IP>:9111, report median with p10/p90, same band and same MLO state, battery above 50%, and `adb shell dumpsys thermalservice` confirming no throttling before each run. Any reported delta smaller than the p10-to-p90 spread of the baseline is not a result.

---

## 6. THE MEASUREMENT THIS ROUND IS MISSING

Section 2.7 leaves one unresolved question that decides whether OI-3B is worth 2.7% or 36%, and whether OI-2 is worth anything at all. Both are answered by two counters, neither of which appears anywhere in the packet.

**Wakeup rate.** Run during an uplink test:

```
adb shell simpleperf stat -p <vpn_pid> \
  -e task-clock,context-switches,sched:sched_switch --duration 8
GODEBUG=schedtrace=1000 on the Go datapath process
```

If context switches land near 37,000/s, the pipeline pays roughly one wakeup per packet, OI-3 Option B is the dominant fix in this round, and its upper bound in Section 2.5 applies. If they land near 150/s, the wakeups are already amortized per batch, OI-3B is worth under 3%, and the limiter is elsewhere.

**Actual batch occupancy.** Histogram `batch.count` and `batch.byteLength` at the `readOutgoingBatch` return and `len(pkts)` at `offerBatch`. If p99 `batch.count` is materially below 256 today, OI-2 raises a cap that is never reached and its measured effect is exactly zero, which is an independent falsification of that item.

Two items the packet does not contain and that the Section 2.2 table says dominate the residual after this round:

1. **Outer UDP transmit batching.** If the outer socket issues one `sendto` per inner packet, 1,000 Mbps costs 91,041 syscalls/s ≈ 182 ms/s ≈ 18% of a core plus 91,041 kernel Wi-Fi transmit entries. `UDP_SEGMENT` (GSO) at 45 segments per 64 KiB write, or `sendmmsg`, reduces that to roughly 2,000 syscalls/s. Kernel 6.x on SM-S948U1 supports both. This is larger than OI-1, OI-2, and OI-3 combined.
2. **TUN read floor.** A tun fd is not a socket, so there is no `recvmmsg` and no `IFF_VNET_HDR` through `VpnService`. 91,041 `read()` calls per second is a hard floor at ~155 ms/s. It fits inside one core, but it sets the per-packet latency of the first stage and should be measured rather than assumed.

Both belong in a Turn 2 amendment as OI-5 and OI-6. Voting AGREE on OI-1 through OI-3 as a path to 1,000 Mbps, without either of them, would certify a specification that the arithmetic in Section 2.6 says falls 2× short.
