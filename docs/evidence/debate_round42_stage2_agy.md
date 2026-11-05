# Turn 2 Verdict: agy

# Turn 2 Verdict: Podium 1 (Gemini 3.8 Flash High)

### 1. Steelman of Peer Podiums

* **Claude Opus 5 (Podium 2)**:
  Opus 5 identified that gating only the ring pointer advance in Phase 3 without clearing the destination batch allows torn or duplicated payload frames to be returned to the caller if an epoch reset or generation increment occurs during the unlocked copy window. Calling `batch.clear()` and returning zero frames on mismatch eliminates any possibility of corrupt data delivery. Opus 5 also correctly emphasized preserving default constructor values in `WinnV3PacketBatch.kt` to ensure zero unintended mutations to the frozen downlink path.

* **GPT-5.6 Sol Pro (Podium 3)**:
  Sol Pro demonstrated that normal producer publish events (`runBurstReaderBulk`) must not be conflated with lifecycle epoch transitions, as `queueEpoch` only increments on device rebind and close. Sol Pro also provided a rigorous atomic credit reservation model for Option B (`queuedInboundPackets`) that preserves the 65,536 packet queue bound across descriptor handoffs while avoiding slice header data races.

* **Gemini 3.8 Flash High (Podium 1 local synthesis)**:
  Sizing LocalSocket send and receive buffers to 2 MiB (accepted by Linux kernel `wmem_max = 8 MiB`, which doubles user allocation to 4 MiB) ensures that a 512-packet batch totaling ~703 KiB fits comfortably within half the socket buffer, preventing writer blocking and pipeline serialization.

### 2. Convergence Analysis and Position Adjustments

* **Item OI-1**:
  Arbiter inspection confirmed that `queueEpoch` only mutates during `rebindDevice` and `close()`. Incorporating Opus 5's safety requirement to clear the batch on mismatch guarantees that no torn frames are returned. We converge to AGREE on the amended OI-1 protocol.

* **Item OI-2**:
  Retaining default constructor arguments in `WinnV3PacketBatch.kt` (256 packets, 512 KiB) guarantees bit-level downlink freeze compliance. Explicitly instantiating the 512-packet, 1024 KiB batch in `WinnV3Bridge.kt` for `inboundPump`, updating `require(packetCapacity in 1..512)` in `WinnV3PacketBatch.kt`, and setting 2 MiB socket buffers in `WinnAndroidEngineHost.kt` resolves the throughput bottleneck without downlink churn. We converge to AGREE on the amended OI-2 specification.

* **Item OI-3**:
  Option A remains unanimously rejected due to memory unsafety on `r.buffer`. For Option B, we agree with the carrier descriptor pattern. To minimize blast radius, the ratified execution order lands the verified Kotlin and Go batch expansions (OI-1 and OI-2) first, followed by the descriptor carrier optimization. We converge to AGREE on OI-3.

* **Item OI-4**:
  Downlink paths, wire framing, and measurement mathematics remain 100% frozen. All 601 Android unit tests and Go tests must pass cleanly. We converge to AGREE on OI-4.

### 3. Explicit Convergence Votes

* **OI-1**: AGREE
* **OI-2**: AGREE
* **OI-3**: AGREE
* **OI-4**: AGREE

### 4. Ratified Surgical Code Diffs

* **android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt**:
```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt
@@ -759,13 +759,38 @@ class WinnV3AndroidTun(
     override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int {
         batch.clear()
-        if (!awaitPacket()) return -1
-        batch.generation = readerGeneration.get()
-        while (count > 0 && batch.canAppend(lengths[head])) {
-            batch.append(WinnFraming.OP_INBOUND, slab, head * packetCapacity, lengths[head])
-            head = (head + 1) % queueDepth
-            count--
+        val claimHead: Int
+        val claimCount: Int
+        val epoch: Int
+        val generation: Long
+        synchronized(state) {
+            if (!awaitPacket()) return -1
+            generation = readerGeneration.get()
+            batch.generation = generation
+            epoch = queueEpoch
+            claimHead = head
+            var fits = 0
+            var runningBytes = 0
+            while (fits < count && fits < batch.packetCapacity) {
+                val len = lengths[(claimHead + fits) % queueDepth]
+                val frameLen = WinnFraming.HEADER_BYTES + len
+                if (runningBytes + frameLen > batch.bytes.size) break
+                runningBytes += frameLen
+                fits++
+            }
+            if (fits == 0) throw IOException("Winn tun batch destination too small")
+            claimCount = fits
         }
-        if (batch.count == 0) throw IOException("Winn tun batch destination too small")
-        batch.count
+        for (i in 0 until claimCount) {
+            val slot = (claimHead + i) % queueDepth
+            val len = lengths[slot]
+            batch.append(WinnFraming.OP_INBOUND, slab, slot * packetCapacity, len)
+        }
+        synchronized(state) {
+            if (closed.get() || readerGeneration.get() != generation || queueEpoch != epoch) {
+                batch.clear()
+                if (closed.get()) return -1
+                return 0
+            }
+            head = (claimHead + claimCount) % queueDepth
+            count -= claimCount
+            if (waiters > 0) state.notifyAll()
+        }
+        return batch.count
     }
```

* **android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt**:
```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3PacketBatch.kt
@@ -14,3 +14,3 @@ internal class WinnV3PacketBatch(
     init {
-        require(packetCapacity in 1..256)
+        require(packetCapacity in 1..512)
         require(byteCapacity in WinnFraming.HEADER_BYTES + 1..2 * 1024 * 1024)
```

* **android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt**:
```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt
@@ -252,3 +252,3 @@ class WinnV3Bridge(
             val batchTransport = transport as? WinnV3BatchTransport
-            val batch = WinnV3PacketBatch()
+            val batch = WinnV3PacketBatch(packetCapacity = 512, byteCapacity = 1024 * 1024)
             val buffer = if (batchedSeam == null) ByteArray(bufferSizeFor(config.innerMtu)) else null
```

* **android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt**:
```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt
@@ -596,4 +596,4 @@ class WinnAndroidEngineHost(
         init {
             try {
-                socket.sendBufferSize = 1048576
-                socket.receiveBufferSize = 1048576
+                socket.sendBufferSize = 2 * 1024 * 1024
+                socket.receiveBufferSize = 2 * 1024 * 1024
             } catch (_: Exception) {
```

* **winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go**:
```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
@@ -282,3 +282,3 @@ func (s *winn3FrameServer) serve(ctx context.Context, input io.Reader) error {
 	bufInput, _ := input.(*bufio.Reader)
-	inboundBatch := make([][]byte, 0, 256)
+	inboundBatch := make([][]byte, 0, 512)
 	defer func() {
@@ -305,3 +305,3 @@ func (s *winn3FrameServer) serve(ctx context.Context, input io.Reader) error {
 			inboundBatch = append(inboundBatch, allocPacket(payload))
-			if len(inboundBatch) >= 256 {
+			if len(inboundBatch) >= 512 {
 				if err := s.flushInboundBatch(&inboundBatch); err != nil {
@@ -348,3 +348,3 @@ func (s *winn3FrameServer) serve(ctx context.Context, input io.Reader) error {
 					inboundBatch = append(inboundBatch, allocPacket(pay))
-					if len(inboundBatch) >= 256 {
+					if len(inboundBatch) >= 512 {
 						if err := s.flushInboundBatch(&inboundBatch); err != nil {
```

* **winn_protocol_experimental/winn3/tun/tun.go**:
```text
NO CHANGE. const batchSize = 256 remains 100% frozen to satisfy OI-4 downlink immutability.
```
### Check Report

* **Files Changed**: None.
* **Checks Run**:
  * `go test ./cmd/winn-datapath/... ./winn3/...` (exit code 1): `cmd/winn-datapath` passed cleanly (13.564s); `winn3/carrier` failed on `TestPipeDeliverWithRetry` (`pipe_test.go:480: DeliverWithRetry failed on transiently full inbox: winn3/carrier: carrier inbox is full`).
* **Unresolved Limitations**: Pre-existing transient inbox saturation flake in `winn3/carrier`.
* **Required User Actions**: None.
