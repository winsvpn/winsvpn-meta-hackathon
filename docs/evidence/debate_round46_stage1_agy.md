# Turn 1 Submission: agy

### Turn 1 Position: Podium 1 (Gemini 3.8 Flash High)

Evaluation of Android Winn Protocol v3 Uplink Wire-Speed Optimization (>1,000 Mbps) Stage D Docket.

---

### 1. First-Principles Arithmetic & Empirical Calibration

* **Wire-speed packet rate at 1,000 Mbps**:
  The inner MTU is 1,373 bytes (10,984 bits per packet).
  At 1,000 Mbps line rate ($125,000,000\text{ bytes/sec}$), the required packet rate is:
  $$\text{pps} = \frac{125,000,000}{1,373} \approx 91,041.5\text{ packets/second}$$
  The per-packet processing budget is:
  $$T_{\text{packet}} = \frac{1}{91,041.5} \approx 10.984\text{ microseconds}$$

* **Syscall frequency and batch occupancy**:
  In Run 18, 1,719,899 packets were emitted over 711,887 carrier socket calls during an 8.0-second window.
  The call rate was $711,887 / 8.0 = 88,985.9\text{ calls/second}$, or one carrier invocation every $11.238\text{ µs}$.
  Average batch occupancy was $1,719,899 / 711,887 = 2.4158\text{ packets/message}$.
  At 16 packets per batch, the socket invocation rate drops to $91,041.5 / 16 \approx 5,690.1\text{ calls/second}$.
  At 32 packets per batch, the socket invocation rate drops to $91,041.5 / 32 \approx 2,845.0\text{ calls/second}$.
  Achieving 16 to 32 packets per call cuts carrier syscall overhead by $93.6\%$ to $96.8\%$.

* **Bandwidth-Delay Product (BDP) at 65 ms RTT**:
  With $R = 125,000,000\text{ bytes/sec}$ and $\text{RTT} = 0.065\text{ s}$:
  $$\text{BDP}_{\text{total}} = 125,000,000 \times 0.065 = 8,125,000\text{ bytes} \approx 7.7485\text{ MiB} \approx 7,934.57\text{ KiB}$$
  Assuming TCP MSS of 1,321 bytes ($1,373 - 20\text{ IP} - 32\text{ TCP options}$), total packets in flight must be:
  $$N_{\text{flight}} = \frac{8,125,000}{1,321} \approx 6,151\text{ packets}$$

* **Per-stream allocation across stream topologies**:
  For 32 streams:
  Target rate per stream is $1,000 / 32 = 31.25\text{ Mbps}$ ($3,906,250\text{ B/s}$).
  Required in-flight BDP is $8,125,000 / 32 = 253,906.25\text{ bytes} \approx 247.96\text{ KiB}$ (192.2 packets).
  If Android defaults clamp the send window to ~96 KiB, each stream caps at $96,000 / 0.065 \times 8 \approx 11.82\text{ Mbps}$.
  Aggregate throughput across 32 clamped streams is $32 \times 11.82 = 378.2\text{ Mbps}$, precisely explaining the 366 to 401 Mbps plateau in Run 18.
  Setting `socket.sendBufferSize = 1,048,576` (1 MiB) yields a headroom ratio of $1,048,576 / 253,906.25 = 4.13\times$.

  For 16 streams:
  Target rate per stream is $1,000 / 16 = 62.5\text{ Mbps}$ ($7,812,500\text{ B/s}$).
  Required in-flight BDP is $8,125,000 / 16 = 507,812.5\text{ bytes} \approx 495.91\text{ KiB}$ (384.4 packets).
  Setting `socket.sendBufferSize = 1,048,576` (1 MiB) yields a headroom ratio of $1,048,576 / 507,812.5 = 2.06\times$.
  Setting `socket.sendBufferSize = 2,097,152` (2 MiB) yields a headroom ratio of $4.13\times$.

  For 8 streams:
  Target rate per stream is $1,000 / 8 = 125.0\text{ Mbps}$ ($15,625,000\text{ B/s}$).
  Required in-flight BDP is $8,125,000 / 8 = 1,015,625\text{ bytes} \approx 991.82\text{ KiB}$ (768.8 packets).
  A 1 MiB buffer gives $1,048,576 / 1,015,625 = 1.032\times$, leaving insufficient margin against retransmissions.
  An 8-stream configuration requires `socket.sendBufferSize = 2,097,152` (2 MiB) for a $2.06\times$ safety margin.

* **Drain gating pause penalty**:
  At 1,000 Mbps line rate, a 250 µs park duration represents:
  $$1,000,000,000\text{ bps} \times 0.000250\text{ s} = 250,000\text{ bits} = 31,250\text{ bytes} \approx 22.76\text{ packets}$$
  Parking the consumer for 250 µs when fewer than 32 packets are present forces an artificial void of up to 23 packet transmission slots.
  Calibrating `maxPark` to 50 µs bounds the idle window to:
  $$1,000,000,000\text{ bps} \times 0.000050\text{ s} = 50,000\text{ bits} = 6,250\text{ bytes} \approx 4.55\text{ packets}$$
  A 50 µs park introduces only $0.050\text{ ms} / 65\text{ ms} = 0.077\%$ latency relative to the path RTT.

---

### 2. Architectural Adjudication of Open Items

#### OI-1: Handset TCP Sockets & Ingest Server BDP Window Scaling

* **Question 1.1: Handset socket buffer expansion**:
  In `MainActivity.kt`, worker sockets currently omit `socket.sendBufferSize`.
  The Linux kernel auto-tuning for local virtual interfaces defaults to small initial windows that clamp in-flight unacknowledged data on high-latency tunnels.
  Setting `socket.sendBufferSize = 1048576` (1 MiB) or `2097152` (2 MiB) explicitly sets `SO_SNDBUF`.
  Under Linux, calling `setsockopt(SO_SNDBUF)` before `connect()` doubles the allocated space to accommodate `sk_buff` overhead and advertises proper TCP window scaling during the three-way handshake.
  This allows each stream to expand its congestion window to 254 KiB, eliminating the 12 Mbps per-stream ceiling.

* **Question 1.2: Gateway ingest server configuration**:
  In `cmd/winn3-gateway/speedtest_ingest.go`, `handleUpload` executes `io.Copy(io.Discard, body)`.
  The Go runtime drains incoming data into user space using 32 KiB internal buffers without application-level blocking.
  Because the gateway runs on Linux with `tcp_rmem` default maximum of 6 MiB, the TCP autotuning engine dynamically scales the receive window up to several megabytes.
  Explicitly setting `SO_RCVBUF` on the gateway listener locks the receive buffer and disables Linux dynamic window autotuning, which risks degrading single-stream throughput.
  The gateway listener should remain on kernel autotuning, but `ReadHeaderTimeout` and timeouts must remain bounded as configured.

* **Question 1.3: Mathematical synthesis**:
  32 streams with 1 MiB send buffers require $32 \times 1\text{ MiB} = 32\text{ MiB}$ of application memory (64 MiB kernel socket memory).
  On the retail Samsung Galaxy S26 Ultra (16 GB RAM), 64 MiB constitutes $0.39\%$ of physical memory.
  Reducing concurrency to 16 streams with 2 MiB send buffers also consumes 32 MiB while halving JVM thread context switching on the 8 Oryon CPU cores.
  Both configurations provide $>4\times$ BDP headroom per stream.

* **Vote on OI-1**:
  AGREE

---

#### OI-2: Eliminating IPC Copies & Streamlining the Ingress Pipeline

* **Question 2.1: SCM_RIGHTS TUN handover**:
  Passing the promoted TUN file descriptor directly to `winn-datapath` would allow the Go engine to read from `tun0` directly.
  However, Android VPN architecture creates a hard boundary during session promotion.
  The Android system cannot reconfigure a running `VpnService` interface.
  `Builder.establish()` generates a distinct new file descriptor upon promotion (e.g. bootstrap fd=84 replaced by promoted fd=102).
  Adopting the descriptor directly inside the Go engine at startup creates an invalid descriptor once promotion occurs.

* **Question 2.2: Promotion transition handling**:
  Transferring `tun0` ownership to the Go engine requires an atomic descriptor hot-swap protocol inside `winn3_frame.go`.
  More critically, if the Go engine owns `tun0`, it must also perform direct `WritePacket` calls to `tun0` for downlink delivery.
  Downlink writes bypassing the Kotlin layer alter the execution path of `outboundPump` and `WinnV3AndroidTun`.
  This violates the Downlink Freeze Invariant for Stage D.

* **Question 2.3: IPC copy reduction within LocalSocket transport**:
  Retaining `LocalSocket` (`AF_UNIX`) preserves stability while still allowing copy reduction.
  In Kotlin, `WinnV3AndroidTun.kt` currently performs Copy 1 from `staging` DirectByteBuffer to `this.slab` byte array, and Copy 2 from `this.slab` to `WinnV3PacketBatch`.
  By allocating a DirectByteBuffer for the ring slab itself, the C++ bulk reader reads directly into slab slots.
  In `winn3_frame.go`, `allocPacket` copies slice headers while recycling memory from `packetPool`.
  Furthermore, `serve()` must immediately flush pending `inboundBatch` packets into `toEngineRing` when the socket input buffer empties, rather than waiting for 512 packets.

* **Vote on OI-2**:
  DISAGREE: Adopting TUN descriptor handover in Stage D breaks the Downlink Freeze Invariant by transferring the downlink tun0 write path to the Go engine, and risks connection drops during Android VpnService staged promotion without an atomic descriptor swap protocol.

---

#### OI-3: Transmit Drain Gating (txDrainGate) Parameter Calibration

* **Question 3.1: Root cause of Run 18 low batch occupancy**:
  Run 18 achieved 2.41 packets per carrier call because `lowWater = 32` and `maxPark = 250 µs` formed a pathological interaction with upstream trickle.
  In `pushBatch` and `pushOne`, notification was only fired when `oldCount == 0` or when crossing `lowWater`.
  When a batch of 2 to 5 packets arrived, the consumer woke, observed `count < 32`, and parked for up to 250 µs.
  Intermediate pushes with counts between 1 and 31 did not wake the consumer.
  The consumer stayed parked until the full 250 µs timer expired, drained whatever 2 or 3 packets had accumulated, and emitted them to the carrier socket.
  This produced 88,985 carrier calls per second carrying only 2.4 packets each.

* **Question 3.2: Parameter recalibration**:
  `maxPark = 250 µs` is excessive. It represents 23 packet transmission times at gigabit speed.
  Recalibrating `maxPark` to $50\text{ µs}$ limits the worst-case timer latency to 4.5 packet slots.
  Recalibrating `lowWater` from 32 to 16 packets ($16 \times 1,373 = 21,968\text{ bytes}$) aligns with the GSO burst profile and prevents unnecessary timer parking.

* **Question 3.3: Push signaling semantics**:
  `pushBatch` should signal notify when `oldCount == 0 || newCount >= r.lowWater`.
  When incoming bursts reach or exceed `lowWater` (16 packets), the consumer wakes instantly and drains without parking.
  When the timer expires after 50 µs, any accumulated packets drain immediately.
  In `winn3_frame.go`, `flushInboundBatch` must be invoked whenever the input buffer has fewer than `HeaderSize` bytes available, ensuring packets reach `toEngineRing` without stalling in Go user-space buffers.

* **Vote on OI-3**:
  AGREE

---

#### OI-4: Downlink Freeze Invariant 100% Preservation

* **Question 4.1: Uplink exclusivity**:
  All proposed modifications are strictly confined to:
  1. `MainActivity.kt`: socket buffer options in `measureUploadViaTunnelIngest`.
  2. `winn3_to_engine_ring.go`: uplink queue constants and notification logic.
  3. `winn3_frame.go`: `inboundBatch` flushing logic in `serve()`.
  Zero changes touch the downlink datapath.

* **Question 4.2: Invariant reaffirmation**:
  The following components remain completely unaltered:
  - `RecvBatch` and `carrier.ReceiveBatch`
  - `outboundPump` in Kotlin and Go
  - `toHost` channel and delivery queues
  - `fromEngine` processing loops
  - Downlink cryptographic decryption workers
  - Speedtest download endpoints and measurement mathematics

* **Vote on OI-4**:
  AGREE

---

### 3. Exact Surgical Code Diffs

#### Diff 1: Client Socket Buffer Expansion (`android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt`)

```diff
--- a/android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt
+++ b/android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt
@@ -1528,6 +1528,8 @@ class MainActivity : FlutterActivity() {
                         try {
                             windowStart.compareAndSet(0L, System.nanoTime())
                             socket = java.net.Socket()
+                            socket.sendBufferSize = 1048576
+                            socket.receiveBufferSize = 262144
                             socket.tcpNoDelay = true
                             // Round 39 convergence (opus): a node whose
                             // firewall DROPs (rather than rejects) the ingest
```

#### Diff 2: Recalibration of Transmit Drain Gating (`winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go`)

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
@@ -8,8 +8,8 @@ import (
 
 const (
 	winn3RingPushBatch = 512
 	winn3RingPopBatch  = 256
-	winn3DrainLowWater = 32
-	winn3DrainMaxPark  = 250 * time.Microsecond
+	winn3DrainLowWater = 16
+	winn3DrainMaxPark  = 50 * time.Microsecond
 )
 
 var ringTimerPool = sync.Pool{
```

#### Diff 3: Ingress Batch Flushing on Empty Buffer (`winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go`)

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go
@@ -328,6 +328,11 @@ func (s *winn3FrameServer) serve(ctx context.Context, input io.Reader) error {
 			if done {
 				return nil
 			}
 		}
 
+		if len(inboundBatch) > 0 && (bufInput == nil || bufInput.Buffered() < duplex.HeaderSize) {
+			if err := s.flushInboundBatch(&inboundBatch); err != nil {
+				return err
+			}
+		}
+
 		if bufInput != nil {
 			for !s.closed.Load() {
```

---

### 4. Summary of Votes

* **OI-1 (Socket Buffers & BDP Scaling)**: AGREE
* **OI-2 (TUN Descriptors & IPC Copies)**: DISAGREE: Adopting TUN descriptor handover in Stage D breaks the Downlink Freeze Invariant by transferring the downlink tun0 write path to the Go engine, and risks connection drops during Android VpnService staged promotion without an atomic descriptor swap protocol.
* **OI-3 (txDrainGate Recalibration)**: AGREE
* **OI-4 (Downlink Freeze Invariant)**: AGREE
