# Turn 2 Verdict: solpro

# Turn 2 convergence

## Peer steelman

1. Opus 5 identified the decisive OI-1 correctness condition. Validating the epoch only before advancing `head` and `count` is insufficient. The already-populated `batch` must be cleared when the epoch, generation, or closed state changes. Otherwise the caller can transmit bytes copied from slots concurrently reset or repopulated by rebind.

2. Sol Pro correctly identified the value of serializing destructive transitions against an active claim. Such serialization prevents even transient concurrent slab mutation and avoids wasted copies. It is stronger than the required delivery invariant. It is not necessary in this patch because:
   - `queueEpoch` changes only for rebind and close.
   - Phase 3 clears every stale batch.
   - Phase 1 captures the slab reference and packet lengths.
   - Blocking rebind or close on a claim adds lifecycle coupling and possible shutdown latency.

3. Gemini correctly emphasized socket buffer headroom. A full 512 packet batch at the 1,373 byte MTU is:

```text
512 * (1,373 + 16) = 711,168 bytes
```

A 1 MiB socket buffer leaves only 337,408 bytes after one such batch. A 2 MiB request gives sufficient headroom for the preceding batch to drain while the next is framed. This does not make an AF_UNIX stream write atomic, but it avoids immediate writer lockstep caused by sizing the socket and application batch too closely.

## Position changes

OI-1 changes from DISAGREE to AGREE. The Arbiter established that normal publication does not increment `queueEpoch`, eliminating the duplicate-head objection. Mandatory Phase 3 clearing resolves the stale delivery objection.

OI-2 changes from DISAGREE to AGREE. The corrected package preserves the 256 packet and 512 KiB defaults, changes only the uplink constructor site, and leaves `pumpOutboundBatch` untouched.

OI-3 changes from immediate inclusion to staged deferral. Option A remains rejected as an aliasing race. Option B can reduce channel operations substantially, but the submitted whole-batch admission implementations change queue saturation behavior and should not be mixed into the OI-1 and OI-2 deployment.

OI-4 remains AGREE.

# Independent item analysis and votes

## OI-1

At the measured 415.5 Mbit/s:

```text
415,500,000 / 8 / 1,373 = 37,837 packets/s
37,837 / 256 = 147.8 full batches/s
256 * (1,373 + 16) = 355,584 framed bytes/batch
355,584 / 5,000,000,000 = 71.1 microseconds of copy time/batch
147.8 * 71.1 microseconds = 10.5 milliseconds/s of monitor occupancy
```

At 1 Gbit/s, the same monitor-protected copy consumes approximately 25.3 milliseconds per second. The direct CPU saving is small, but releasing the monitor removes producer scheduling stalls and bounds queue service latency.

The JMM ordering is valid:

1. The producer writes `slab` and `lengths`, then publishes `count` while holding `state`.
2. The producer's monitor release happens before Phase 1 acquires `state`.
3. The claimed slots remain included in `count`, so ordinary publication cannot reuse them during Phase 2.
4. Rebind and close are detected through `queueEpoch`, generation, and `closed`.
5. Phase 3 clears the batch before returning on every mismatch.

Vote: AGREE: a test that injects rebind between Phase 1 and Phase 3 will observe `batch.count == 0`, while normal publication during Phase 2 will still commit exactly once because it does not change `queueEpoch`.

## OI-2

At 1 Gbit/s:

```text
1,000,000,000 / 8 / 1,373 = 91,041 packets/s
91,041 / 256 = 355.6 maximum-size batches/s
91,041 / 512 = 177.8 maximum-size batches/s
```

The change can save at most 177.8 batch-level write and read events per second. It is useful but cannot independently explain a 2.407 times throughput gap.

Memory growth per active uplink is approximately:

```text
Kotlin batch storage increase:       512 KiB
Go slice headers, 256 additional:      6 KiB
Total direct user-space increase:    about 518 KiB
```

The downlink defaults and Go outbound batch remain unchanged.

Vote: AGREE: `git diff --exit-code -- winn_protocol_experimental/winn3/tun/tun.go` will succeed, while the only 512 packet Kotlin construction is the inbound uplink pump.

## OI-3

Option A remains unsafe. A payload slice that aliases `r.buffer` is overwritten by the next `reader.Read()`. Publishing that slice asynchronously creates corrupted packets and a race detectable with `go test -race`.

Option B has meaningful arithmetic:

```text
Per-packet channel:
91,041 sends/s + 91,041 receives/s = 182,082 channel operations/s

512-packet descriptor channel:
177.8 sends/s + 177.8 receives/s = 355.6 channel operations/s
```

However, both proposed descriptor implementations change saturation admission. With one packet credit remaining, the existing per-packet loop accepts one packet from a two-packet input and drops one. A whole-batch reservation rejects both. This changes loss granularity and can be tested deterministically without throughput measurement.

Option B should follow OI-1 and OI-2 in a separate deployment after it supports partial descriptor admission or explicitly ratifies changed drop semantics.

Vote: DISAGREE: with one queue credit remaining, a two-packet descriptor drops two packets while the current per-packet queue accepts one, which is a directly testable change in overload behavior.

## OI-4

The ratified production changes do not alter frame headers, byte order, opcode values, measurement calculations, downlink allocation geometry, or `pumpOutboundBatch`.

Vote: AGREE: the frozen-path gate will show no diff in `winn3/tun/tun.go`, and golden framing hashes for identical packet corpora must remain byte-for-byte equal.

# Ratified surgical diffs

## 1. Widen batch validation without changing defaults

```diff
diff --git a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
@@
 internal class WinnV3PacketBatch(
     val packetCapacity: Int = 256,
-    byteCapacity: Int = 512 * 1024,
+    val byteCapacity: Int = 512 * 1024,
 ) {
     init {
-        require(packetCapacity in 1..256)
-        require(byteCapacity in (WinnFraming.HEADER_BYTES + 1)..(1024 * 1024))
+        require(packetCapacity in 1..512)
+        require(
+            byteCapacity in
+                (WinnFraming.HEADER_BYTES + 1)..(2 * 1024 * 1024)
+        )
     }
```

The default remains exactly 256 packets and 512 KiB.

## 2. Move the outgoing consumer copy outside `state`

```diff
diff --git a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt
@@
     private val state = Object()
+    // Protected by state. readOutgoingBatch is architecturally single-consumer.
+    private var outgoingClaimActive = false
+    private val outgoingClaimLengths = IntArray(512)
@@
-    override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int =
-        synchronized(state) {
-            batch.clear()
-            if (!awaitPacket()) return@synchronized -1
-            batch.generation = readerGeneration.get()
-            while (count > 0 && batch.canAppend(lengths[head])) {
-                batch.append(
-                    WinnFraming.OP_INBOUND,
-                    slab,
-                    head * packetCapacity,
-                    lengths[head],
-                )
-                head = (head + 1) % queueDepth
-                count--
-            }
-            if (batch.count == 0) {
-                throw IOException("Winn tun batch destination too small")
-            }
-            batch.count
-        }
+    override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int {
+        batch.clear()
+
+        var claimHead = 0
+        var claimCount = 0
+        var claimGeneration = 0L
+        var claimEpoch = 0
+        lateinit var claimSlab: ByteArray
+
+        synchronized(state) {
+            if (!awaitPacket()) return -1
+            check(!outgoingClaimActive) {
+                "Winn tun outgoing batch reader must be single-consumer"
+            }
+
+            claimHead = head
+            claimGeneration = readerGeneration.get()
+            claimEpoch = queueEpoch
+            claimSlab = slab
+
+            var framedBytes = 0
+            while (claimCount < count &&
+                claimCount < batch.packetCapacity
+            ) {
+                val slot = (claimHead + claimCount) % queueDepth
+                val length = lengths[slot]
+                val nextBytes =
+                    framedBytes + WinnFraming.HEADER_BYTES + length
+
+                if (nextBytes > batch.byteCapacity) break
+
+                outgoingClaimLengths[claimCount] = length
+                framedBytes = nextBytes
+                claimCount++
+            }
+
+            if (claimCount == 0) {
+                throw IOException("Winn tun batch destination too small")
+            }
+
+            outgoingClaimActive = true
+        }
+
+        var phase3Complete = false
+        try {
+            batch.generation = claimGeneration
+
+            for (i in 0 until claimCount) {
+                val slot = (claimHead + i) % queueDepth
+                batch.append(
+                    WinnFraming.OP_INBOUND,
+                    claimSlab,
+                    slot * packetCapacity,
+                    outgoingClaimLengths[i],
+                )
+            }
+
+            var result = 0
+            synchronized(state) {
+                val isClosed = closed.get()
+                val isStale =
+                    isClosed ||
+                        queueEpoch != claimEpoch ||
+                        readerGeneration.get() != claimGeneration
+
+                if (isStale) {
+                    // Phase 2 may have observed a destructive transition.
+                    // No copied frame may escape to the transport.
+                    batch.clear()
+                    result = if (isClosed) -1 else 0
+                } else {
+                    check(head == claimHead)
+                    check(count >= claimCount)
+                    head = (claimHead + claimCount) % queueDepth
+                    count -= claimCount
+                    result = batch.count
+                }
+
+                outgoingClaimActive = false
+                phase3Complete = true
+                if (waiters > 0) state.notifyAll()
+            }
+
+            return result
+        } finally {
+            if (!phase3Complete) {
+                batch.clear()
+                synchronized(state) {
+                    outgoingClaimActive = false
+                    if (waiters > 0) state.notifyAll()
+                }
+            }
+        }
+    }
```

This deliberately does not make rebind or close wait for Phase 2. The captured slab reference and lengths keep Phase 2 bounded, while the mandatory Phase 3 gate prevents stale bytes from reaching the caller.

## 3. Increase only the inbound bridge batch

```diff
diff --git a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
@@
         inboundPump = Thread {
             started.countDown()
             val batchedSeam = seam as? WinnV3BatchedIpPacketSeam
             val batchTransport = transport as? WinnV3BatchTransport
-            val batch = WinnV3PacketBatch()
+            val batch = WinnV3PacketBatch(
+                packetCapacity = 512,
+                byteCapacity = 1024 * 1024,
+            )
             val buffer =
                 if (batchedSeam == null) {
                     ByteArray(bufferSizeFor(config.innerMtu))
                 } else {
                     null
                 }
```

There is intentionally no `outboundPump` hunk. It continues to use the frozen defaults.

## 4. Set LocalSocket buffers to 2 MiB

Apply at the existing LocalSocket configuration site:

```diff
diff --git a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
@@
-        socket.sendBufferSize = 1024 * 1024
-        socket.receiveBufferSize = 1024 * 1024
+        socket.sendBufferSize = 2 * 1024 * 1024
+        socket.receiveBufferSize = 2 * 1024 * 1024
```

## 5. Expand only the Go inbound accumulator

```diff
diff --git a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
@@
-	inboundBatch := make([][]byte, 0, 256)
+	inboundBatch := make([][]byte, 0, 512)
 	defer func() {
 		_ = s.flushInboundBatch(&inboundBatch)
 	}()
@@
 		if opcode == duplex.OpInbound {
 			inboundBatch = append(inboundBatch, allocPacket(payload))
-			if len(inboundBatch) >= 256 {
+			if len(inboundBatch) >= 512 {
 				if err := s.flushInboundBatch(&inboundBatch); err != nil {
 					return err
 				}
 			}
@@
 				if op == duplex.OpInbound {
 					inboundBatch = append(inboundBatch, allocPacket(pay))
-					if len(inboundBatch) >= 256 {
+					if len(inboundBatch) >= 512 {
 						if err := s.flushInboundBatch(&inboundBatch); err != nil {
 							return err
 						}
 					}
```

No changes are ratified for `winn3/tun/tun.go`.

# Required verification gates

```bash
# Android production and unit verification
./gradlew --no-daemon clean :app:testDebugUnitTest :app:lintDebug

# Confirm exactly the required existing Android test population passed.
python3 - <<'PY'
import glob
import xml.etree.ElementTree as ET

tests = failures = errors = 0
for path in glob.glob("**/build/test-results/**/*.xml", recursive=True):
    root = ET.parse(path).getroot()
    tests += int(root.attrib.get("tests", 0))
    failures += int(root.attrib.get("failures", 0))
    errors += int(root.attrib.get("errors", 0))

print({"tests": tests, "failures": failures, "errors": errors})
assert tests == 601
assert failures == 0
assert errors == 0
PY

# Go verification
cd winn_protocol_experimental
gofmt -w cmd/winn-datapath/winn3_frame.go
go vet ./...
go test ./...
go test -race ./...

# Frozen downlink gate
git diff --exit-code -- winn3/tun/tun.go

# Reject accidental default changes.
grep -A3 'internal class WinnV3PacketBatch' \
  ../android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
```

The OI-1 concurrency test must inject each event after Phase 1 and before Phase 3:

```text
normal producer publication:
    expected return > 0
    expected head advance exactly once

rebind:
    expected return 0
    expected batch.count == 0

close:
    expected return -1
    expected batch.count == 0

append exception:
    expected queue head unchanged
    expected outgoing claim released
```

Final deployment order is OI-1, OI-2, then the OI-4 gates. OI-3 Option B remains a separate measured change with partial-admission semantics required before ratification.
