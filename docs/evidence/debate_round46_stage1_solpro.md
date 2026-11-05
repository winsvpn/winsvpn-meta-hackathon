# Turn 1 Submission: solpro

- **Baseline arithmetic**

  The 1,373 byte packet size gives:

  \[
  pps_{1G}=\frac{1,000,000,000}{1,373 \times 8}=91,041.515
  \]

  Aggregate packet time budget:

  \[
  \frac{1}{91,041.515}=10.984\ \mu s
  \]

  At the measured upload rates:

  | Rate | Packets per second | Aggregate packet interval |
  |---:|---:|---:|
  | 366 Mbps | 33,321.195 | 30.011 us |
  | 400 Mbps | 36,416.606 | 27.460 us |
  | 401 Mbps | 36,507.648 | 27.391 us |
  | 1,000 Mbps | 91,041.515 | 10.984 us |

  If 1,373 includes a 40 byte IPv4 and TCP header, application payload is 1,333 bytes. In that interpretation, 1 Gbps of application payload requires 93,773.443 packets/s and a 10.664 us aggregate interval. Both interpretations should be retained in profiling because the docket does not specify whether the displayed speed is TCP payload or inner IP bytes.

  At 1 Gbps, the three explicit 1,373 byte copies move:

  \[
  91,041.515 \times 1,373 \times 3
  =375,000,000\ bytes/s
  \]

  That is 375 MB/s or 357.63 MiB/s. This is meaningful cache traffic, but it is not by itself proof of DRAM saturation. The packet rate, JNI crossings, wakeups, allocations, and serialization are more likely to dominate than raw DRAM bandwidth.

  The carrier telemetry gives:

  \[
  \frac{1,719,899}{8}=214,987.375\ carrier\ packets/s
  \]

  \[
  \frac{711,887}{8}=88,985.875\ carrier\ calls/s
  \]

  \[
  \frac{1,719,899}{711,887}=2.41597\ packets/call
  \]

  \[
  \frac{1}{88,985.875}=11.238\ \mu s/call
  \]

  Carrier packet count includes encapsulation, acknowledgements, control traffic, and possibly segmentation behavior. It cannot be treated as the `toEngineRing.popBatch` occupancy without a histogram at that exact boundary.

- **OI-1: TCP socket and receive-window scaling**

  1. The exact aggregate bandwidth-delay product is:

     \[
     125,000,000\ bytes/s \times 0.065s
     =8,125,000\ bytes
     \]

     That is 7.7486 MiB.

     Per-stream requirements are:

     | Streams | Target per stream | Required in-flight bytes | Required KiB |
     |---:|---:|---:|---:|
     | 32 | 31.25 Mbps | 253,906.25 | 247.955 |
     | 16 | 62.50 Mbps | 507,812.50 | 495.911 |
     | 8 | 125.00 Mbps | 1,015,625.00 | 991.821 |

  2. For a fixed effective per-stream window \(W\), the receive-window-limited aggregate rate is:

     \[
     T=\frac{8NW}{RTT}
     \]

     A 96 KiB effective window would produce:

     \[
     \frac{8 \times 32 \times 98,304}{0.065}
     =387.167\ Mbps
     \]

     A 100 KiB effective window would produce:

     \[
     \frac{8 \times 32 \times 102,400}{0.065}
     =403.298\ Mbps
     \]

     The measured range implies these per-stream in-flight quantities if a window ceiling is the cause:

     | Aggregate rate | Implied bytes per stream |
     |---:|---:|
     | 366 Mbps | 92,929.688 |
     | 400 Mbps | 101,562.500 |
     | 401 Mbps | 101,816.406 |

     That correspondence makes a roughly 96 through 100 KiB window a credible hypothesis. It is not causal proof.

  3. A requested 1 MiB send buffer has these ideal window ceilings:

     | Streams | Aggregate ceiling with 1 MiB per stream |
     |---:|---:|
     | 32 | 4,129.776 Mbps |
     | 16 | 2,064.888 Mbps |
     | 8 | 1,032.444 Mbps |

     A 2 MiB request doubles those ceilings. For the current 32-stream test, 1 MiB already provides more than four times the required per-stream BDP and avoids allocating a nominal 64 MiB across the sender.

  4. `SO_SNDBUF` does not directly expand the congestion window. Linux congestion control expands `cwnd` from acknowledgements. The send buffer only ensures that the application can keep enough data queued for the current `cwnd`, receiver window, and pacing state.

     With an initial congestion window near ten segments and a 1,333 byte TCP payload:

     \[
     IW \mathrel{\approx} 13,330\ bytes
     \]

     A 32-stream connection needs about:

     \[
     \frac{253,906}{13,330}=19.05
     \]

     times its initial window. Five lossless slow-start doublings exceed that value, taking approximately:

     \[
     5 \times 65ms=325ms
     \]

     An eight-second upload is long enough. If throughput remains limited after the first second, the initial congestion window is not the sustained ceiling.

  5. The send-buffer setting must occur before `connect()`. Linux can clamp the request through `net.core.wmem_max`, and Linux commonly reports a doubled internal accounting value. The effective value must be read back rather than assumed.

  6. The gateway receive side should not be changed blindly. Linux TCP receive autotuning normally negotiates window scaling and grows `sk_rcvbuf` as required. Setting `SO_RCVBUF` explicitly marks the socket as user-locked on Linux and can disable further receive autotuning. A fixed value can therefore make a correctly tuned server worse.

     Before changing the listener, collect `ss -tinm` or `TCP_INFO` for an upload connection and inspect:

     * negotiated window scaling
     * `snd_wnd`
     * `rcv_space`
     * `rcv_ssthresh`
     * bytes in flight
     * unacknowledged segments
     * sender `notsent_bytes`

     A listener-level receive-buffer change is justified only if `snd_wnd` repeatedly limits bytes in flight or the negotiated receive scale is inadequate. Setting the accepted socket after the handshake cannot renegotiate the window-scale option.

  7. The surgical handset change is:

```diff
diff --git a/android/app/src/main/kotlin/com/winn/MainActivity.kt b/android/app/src/main/kotlin/com/winn/MainActivity.kt
--- a/android/app/src/main/kotlin/com/winn/MainActivity.kt
+++ b/android/app/src/main/kotlin/com/winn/MainActivity.kt
@@
                 val socket = Socket()
+                socket.sendBufferSize = 1_048_576
                 socket.tcpNoDelay = true
                 socket.connect(InetSocketAddress("10.10.0.1", 8455))
```

  This line must be confined to the upload worker block. It must not be added to the downlink test path.

  I do not recommend a gateway code diff yet. An unconditional `SetReadBuffer` patch would replace autotuning without evidence that the receive window is limiting the test.

  Vote OI-1: `AGREE: the observed 366 through 401 Mbps range corresponds to only 92,930 through 101,816 in-flight bytes per stream, while 1 Gbps over 32 streams requires 253,906 bytes per stream.`

- **OI-2: TUN descriptor handover and copy elimination**

  1. A TUN descriptor can be passed with `SCM_RIGHTS`. The receiving process obtains another descriptor referencing the same open file description. Closing the Kotlin-side duplicate does not invalidate the Go-side descriptor.

  2. Under the downlink freeze invariant, the entire `LocalSocket` cannot be removed. It is still the existing Go-to-Kotlin downlink route. The safe Stage D architecture is:

     * Go becomes the only reader of the TUN descriptor.
     * Kotlin retains the descriptor only for downlink writes.
     * Kotlin's `TunRead` thread is permanently stopped.
     * The existing AF_UNIX route remains intact for downlink frames.
     * Uplink payload frames stop traversing AF_UNIX after promotion.

  3. Concurrent reads by Kotlin and Go are prohibited. Duplicated descriptors reference the same TUN queue, and two readers would distribute packets nondeterministically.

  4. A live transition needs an ordered state machine:

     1. Kotlin requests promotion and stops issuing new TUN reads.
     2. A read already in progress is allowed to complete.
     3. Kotlin sends every completed packet batch over the existing stream.
     4. Kotlin sends an `UPLINK_BARRIER` control frame after those batches.
     5. Kotlin sends the TUN descriptor with `SCM_RIGHTS`.
     6. Go parses and enqueues all frames preceding `UPLINK_BARRIER`.
     7. Go installs the descriptor in its poller.
     8. Go starts its direct TUN reader only after the barrier has entered the same ordered ingress queue.
     9. Go sends `UPLINK_PROMOTED`.
     10. Kotlin terminates `TunRead` permanently.

     Packets arriving during the transition remain queued on TUN. If the queue fills, TCP can retransmit a dropped packet, but the connection itself is not reset. Performing promotion before application traffic starts removes even that transient risk.

  5. `winn3_frame.go` should not parse raw TUN packets as framed AF_UNIX records. Direct TUN ingress needs a separate reader that feeds the same enqueue primitive used after AF_UNIX frame validation. The frame reader handles the control barrier and bootstrap traffic only.

  6. If AF_UNIX must continue carrying uplink payloads, a true payload zero-copy path requires shared memory:

     * Allocate a sealed `memfd` slot ring.
     * Map it in Kotlin native code and Go.
     * Read TUN directly into a free shared slot.
     * Send only slot index, length, and generation over AF_UNIX.
     * Let Go encrypt directly from the mapped slot.
     * Return the slot to `FREE` only after encryption has stopped referencing it.

     The slot states must be `FREE`, `FILLING`, `READY`, and `INFLIGHT`. A generation counter prevents a stale descriptor from referencing a reused slot.

     This removes the three listed userspace payload copies. The kernel still copies from the TUN queue into the shared mapping, which is unavoidable unless the packet remains entirely in kernel space.

  7. A less invasive single-copy design reads the AF_UNIX payload directly into a correctly sized Go pool slice:

```go
func allocPacketLen(n int) []byte {
	p := packetPool.Get().([]byte)
	if cap(p) < n {
		return make([]byte, n)
	}
	return p[:n]
}
```

     The frame parser must call `io.ReadFull(reader, packet)` where `packet` came from `allocPacketLen(payloadLen)`. It must not read into a temporary payload slice and then call the copying `allocPacket(payload)` function.

     That Go-side change alone removes Copy 3, but it does not remove the Kotlin staging and batching copies.

  8. I am not providing a fabricated unified diff for descriptor promotion. The docket does not include the existing descriptor message format, JNI `sendmsg` entry point, control-frame constants, process bootstrap code, ring enqueue signature, or descriptor receiver. Inventing those interfaces would not be an exact or compilable patch. Descriptor handover should be a separate reviewed patch after those files are supplied.

  Vote OI-2: `AGREE: SCM_RIGHTS can duplicate the TUN descriptor into the Go process, and an ordered barrier permits Go to become the sole TUN reader without consuming any packet before previously framed uplink packets.`

- **OI-3: Transmit drain gating**

  1. At 400 Mbps, expected arrivals during 250 us are:

     \[
     36,416.606 \times 0.00025=9.104
     \]

     At 1 Gbps:

     \[
     91,041.515 \times 0.00025=22.760
     \]

     Therefore a `lowWater` of 32 is not reached within 250 us even at the target rate under a smooth arrival model.

  2. Time required to accumulate each threshold is:

     | Threshold | At 400 Mbps | At 1 Gbps |
     |---:|---:|---:|
     | 8 packets | 219.68 us | 87.87 us |
     | 16 packets | 439.36 us | 175.74 us |
     | 32 packets | 878.72 us | 351.49 us |

     `lowWater = 16` with `maxPark = 250 us` has the desired behavior:

     * At the present rate, the timer yields approximately 8 through 9 packets.
     * At the target rate, the threshold wakes the reader after approximately 176 us.
     * Sparse interactive traffic waits no more than the existing 250 us.

  3. Reducing `maxPark` to 100 us produces only:

     \[
     36,416.606 \times 0.0001=3.642
     \]

     packets at 400 Mbps and 9.104 packets at 1 Gbps.

     Reducing it to 50 us produces 1.821 packets at 400 Mbps and 4.552 packets at 1 Gbps.

     Those values move occupancy away from the stated 16 through 32 target. A shorter park may reduce latency, but it does not improve batching and does not explain a sustained 400 Mbps ceiling.

  4. Signalling whenever `r.count > 0` would defeat coalescing. Once the consumer catches the producer, every arriving packet would wake it and tend toward one-packet batches.

  5. The 2.416 carrier packets per call cannot be explained solely by the 250 us timer. If the ring received a continuous 400 Mbps stream, the timer model predicts about nine inner packets per expiration. Possible causes include:

     * the carrier statistic is measured after a split or transformation
     * input is bursty with idle gaps
     * another downstream stage limits vector length
     * the consumer is being notified before the intended gate completes
     * control and acknowledgement traffic are included
     * GSO and non-GSO calls are aggregated into one counter

     Add separate histograms for `popBatch` result length, wake reason, send vector length, and GSO segment count before attributing the 2.416 ratio to `txDrainGate`.

  6. The surgical calibration is to lower only `lowWater` to 16 and retain 250 us:

```diff
diff --git a/cmd/winn-datapath/winn3_to_engine_ring.go b/cmd/winn-datapath/winn3_to_engine_ring.go
--- a/cmd/winn-datapath/winn3_to_engine_ring.go
+++ b/cmd/winn-datapath/winn3_to_engine_ring.go
@@
-		lowWater: 32,
+		lowWater: 16,
 		maxPark:  250 * time.Microsecond,
```

  Notification should occur on an empty-to-nonempty transition or a crossing of the threshold, not on every push after the threshold:

```diff
diff --git a/cmd/winn-datapath/winn3_to_engine_ring.go b/cmd/winn-datapath/winn3_to_engine_ring.go
--- a/cmd/winn-datapath/winn3_to_engine_ring.go
+++ b/cmd/winn-datapath/winn3_to_engine_ring.go
@@
-	if oldCount == 0 || newCount >= r.lowWater {
+	if oldCount == 0 || (oldCount < r.lowWater && newCount >= r.lowWater) {
 		r.signal()
 	}
@@
-	if oldCount == 0 || newCount >= r.lowWater {
+	if oldCount == 0 || (oldCount < r.lowWater && newCount >= r.lowWater) {
 		r.signal()
 	}
```

  The `oldCount == 0` condition must remain. Without it, a consumer sleeping on an empty ring might never wake to start its parking timer.

  Vote OI-3: `AGREE: at 1 Gbps a 32-packet threshold requires 351.49 us and therefore cannot be reached before the current 250 us deadline, while a 16-packet threshold is reached in 175.74 us.`

- **OI-4: Downlink freeze invariant**

  The authorized immediate patch set modifies only:

  * the upload worker socket in `MainActivity.kt`
  * transmit-side drain gating in `winn3_to_engine_ring.go`

  It does not modify:

  * `RecvBatch`
  * `outboundPump`
  * `toHost`
  * `fromEngine`
  * downlink cryptographic workers
  * downlink GSO or receive batching
  * downlink counters
  * throughput measurement windows
  * byte-to-bit conversion
  * UI smoothing or reporting

  A future TUN descriptor patch must remain uplink-only. Go may read directly from TUN, but Kotlin must retain the existing downlink write path. Removing AF_UNIX entirely is not compatible with the freeze invariant unless the downlink architecture is also redesigned, which is outside this round.

  The gateway receive-buffer change is not included, so it cannot affect downlink server behavior.

  Vote OI-4: `AGREE: the two authorized diffs touch only upload socket queueing and the transmit-side toEngine ring, and neither diff reaches any receive, toHost, downlink crypto, or measurement code path.`
