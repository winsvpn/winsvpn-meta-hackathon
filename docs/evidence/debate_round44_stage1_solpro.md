# Turn 1 Submission: solpro

**1. Baseline arithmetic**

Using the stated 1,373 byte mean inner packet size:

\[
P_{1000}=\frac{125{,}000{,}000}{1{,}373}=91{,}041.5149\ packets/s
\]

\[
T_{1000}=\frac{1{,}000{,}000}{91{,}041.5149}=10.9840\ \mu s/packet
\]

Run 16 median:

\[
B=\frac{389{,}677{,}056}{8}=48{,}709{,}632\ bytes/s
\]

\[
P_{16}=\frac{48{,}709{,}632}{1{,}373}=35{,}476.7895\ packets/s
\]

\[
T_{16}=\frac{1{,}000{,}000}{35{,}476.7895}=28.1874\ \mu s/packet
\]

Required service-time reduction:

\[
28.1874-10.9840=17.2034\ \mu s/packet
\]

The required packet-rate multiplier is:

\[
\frac{91{,}041.5149}{35{,}476.7895}=2.56623
\]

These calculations assume the stated 1,373 byte mean payload. If 1,373 is only the maximum, actual required pps is higher.

**2. OI-1: Batched `toEngine` ring**

The proposed count of 356 lock acquisitions per second omits producer acquisitions.

At full batches:

\[
L_{channel}=2P=182{,}083.0298\ acquisitions/s
\]

\[
L_{push}=\frac{P}{512}=177.8155\ acquisitions/s
\]

\[
L_{pop}=\frac{P}{256}=355.6309\ acquisitions/s
\]

\[
L_{ring}=533.4464\ acquisitions/s
\]

The reduction is:

\[
182{,}083.0298-533.4464=181{,}549.5834
\]

That is a 99.70703125 percent reduction in synchronization entry count, assuming every push and pop batch is full.

The exact CPU time saving cannot be derived from acquisition count. The missing quantity is the measured cost of one contended channel operation on this device. Buffered channel operations that find the queue neither empty nor full normally do not park a goroutine, so the docket's assumption of parking and unparking on every packet is incorrect.

If \(C_c\) is the cost of one channel send or receive and \(C_p,C_r\) are the ring push and pop lock costs, then:

\[
S_{packet}=2C_c-\frac{C_p}{512}-\frac{C_r}{256}
\]

If all acquisition costs are approximated by the same value \(L\):

\[
S_{packet}=L\left(2-\frac{1}{512}-\frac{1}{256}\right)
=1.994140625L
\]

For this change alone to retire the entire 17.2034 microsecond gap:

\[
L=\frac{17.2034}{1.994140625}=8.6270\ \mu s
\]

An average 8.627 microseconds for every buffered channel send and receive would be exceptionally large. It must be measured rather than assumed.

Illustrative upper bounds, ignoring ring slot processing and all other bottlenecks:

| Assumed channel acquisition cost | Saving per packet | Predicted throughput |
|---:|---:|---:|
| 50 ns | 0.0997 microseconds | 391.1 Mbps |
| 100 ns | 0.1994 microseconds | 392.5 Mbps |
| 500 ns | 0.9971 microseconds | 404.0 Mbps |
| 1 microsecond | 1.9941 microseconds | 419.3 Mbps |
| 8.627 microseconds | 17.2034 microseconds | 1,000 Mbps |

The ring is architecturally sound, but it is not a sufficient analytical explanation for reaching 1,000 Mbps.

Closing semantics should be linearized by the ring mutex:

1. `close()` sets `closed` while holding `mu`.
2. A producer that wins the mutex first commits its packets, which remain drainable.
3. A producer that loses to `close()` gets `io.ErrClosedPipe` and recycles every packet it still owns.
4. The consumer drains committed packets.
5. Once `closed && count == 0`, the consumer receives `io.EOF`.
6. Shutdown must wait for the consumer to observe EOF before destroying device-owned resources.

This prevents premature disposal of accepted packets. A forced abort is a different operation and would need to drain and recycle every queued pointer explicitly.

`Signal()` is sufficient during normal operation because there is exactly one consumer. `Broadcast()` should be used on close so any waiter is guaranteed to wake, including accidental additional readers.

Vote: AGREE: with full 512 packet pushes and 256 packet pops, the synchronization acquisition rate falls from 182,083.03 to 533.45 per second, which is directly falsifiable with mutex and scheduler profiling.

**3. Exact OI-1 code diff**

The ring implementation does not copy payload bytes while holding its mutex. It copies only slice headers into caller-owned scratch storage, releases the mutex, and then performs payload copies and recycling.

```diff
diff --git a/cmd/winn-datapath/winn3_to_engine_ring.go b/cmd/winn-datapath/winn3_to_engine_ring.go
new file mode 100644
index 0000000..3180d85
--- /dev/null
+++ b/cmd/winn-datapath/winn3_to_engine_ring.go
@@ -0,0 +1,109 @@
+package main
+
+import (
+	"io"
+	"sync"
+)
+
+type toEngineRing struct {
+	mu      sync.Mutex
+	cond    *sync.Cond
+	storage [][]byte
+	head    int
+	tail    int
+	count   int
+	closed  bool
+}
+
+func newToEngineRing(capacity int) *toEngineRing {
+	if capacity <= 0 {
+		panic("toEngine ring capacity must be positive")
+	}
+	r := &toEngineRing{
+		storage: make([][]byte, capacity),
+	}
+	r.cond = sync.NewCond(&r.mu)
+	return r
+}
+
+func (r *toEngineRing) pushBatch(packets [][]byte) (int, error) {
+	r.mu.Lock()
+	defer r.mu.Unlock()
+
+	if r.closed {
+		return 0, io.ErrClosedPipe
+	}
+
+	available := len(r.storage) - r.count
+	n := len(packets)
+	if n > available {
+		n = available
+	}
+	if n == 0 {
+		return 0, nil
+	}
+
+	wasEmpty := r.count == 0
+	first := n
+	if remaining := len(r.storage) - r.tail; first > remaining {
+		first = remaining
+	}
+	copy(r.storage[r.tail:r.tail+first], packets[:first])
+
+	second := n - first
+	if second != 0 {
+		copy(r.storage[:second], packets[first:n])
+	}
+
+	r.tail = (r.tail + n) % len(r.storage)
+	r.count += n
+
+	if wasEmpty {
+		r.cond.Signal()
+	}
+	return n, nil
+}
+
+func (r *toEngineRing) popBatch(dst [][]byte) (int, error) {
+	r.mu.Lock()
+	defer r.mu.Unlock()
+
+	for r.count == 0 && !r.closed {
+		r.cond.Wait()
+	}
+	if r.count == 0 {
+		return 0, io.EOF
+	}
+
+	n := len(dst)
+	if n > r.count {
+		n = r.count
+	}
+
+	first := n
+	if remaining := len(r.storage) - r.head; first > remaining {
+		first = remaining
+	}
+	copy(dst[:first], r.storage[r.head:r.head+first])
+	clear(r.storage[r.head : r.head+first])
+
+	second := n - first
+	if second != 0 {
+		copy(dst[first:n], r.storage[:second])
+		clear(r.storage[:second])
+	}
+
+	r.head = (r.head + n) % len(r.storage)
+	r.count -= n
+	return n, nil
+}
+
+func (r *toEngineRing) close() {
+	r.mu.Lock()
+	if !r.closed {
+		r.closed = true
+		r.cond.Broadcast()
+	}
+	r.mu.Unlock()
+}
diff --git a/cmd/winn-datapath/winn3_frame_device.go b/cmd/winn-datapath/winn3_frame_device.go
index 0000000..f50df6c 100644
--- a/cmd/winn-datapath/winn3_frame_device.go
+++ b/cmd/winn-datapath/winn3_frame_device.go
@@ -1,6 +1,6 @@
 type winn3FrameDevice struct {
 	mtu                   int
-	toEngine              chan []byte
+	toEngine              *toEngineRing
 	toHost                chan []byte
+	toEngineOfferPackets  [][]byte
+	toEngineReadPackets   [][]byte
 	droppedToEngine       atomic.Uint64
 	oversize              atomic.Uint64
 }
@@ -20,7 +22,9 @@ func newWinn3FrameDevice(mtu int) *winn3FrameDevice {
 	return &winn3FrameDevice{
-		mtu:      mtu,
-		toEngine: make(chan []byte, winn3FrameQueueDepth),
-		toHost:   make(chan []byte, winn3FrameQueueDepth),
+		mtu:                  mtu,
+		toEngine:             newToEngineRing(winn3FrameQueueDepth),
+		toHost:               make(chan []byte, winn3FrameQueueDepth),
+		toEngineOfferPackets: make([][]byte, 0, 512),
+		toEngineReadPackets:  make([][]byte, 256),
 	}
 }
@@ -40,15 +44,40 @@ func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
-	for _, pkt := range packets {
+	valid := d.toEngineOfferPackets[:0]
+	for _, pkt := range packets {
 		if len(pkt) > d.mtu {
 			d.oversize.Add(1)
 			d.recycle(pkt)
 			continue
 		}
-		d.push(d.toEngine, pkt, &d.droppedToEngine, false)
+		valid = append(valid, pkt)
+	}
+
+	accepted, err := d.toEngine.pushBatch(valid)
+	if err != nil {
+		for _, pkt := range valid {
+			d.recycle(pkt)
+		}
+		clear(valid)
+		d.toEngineOfferPackets = valid[:0]
+		return err
 	}
+
+	dropped := valid[accepted:]
+	if len(dropped) != 0 {
+		d.droppedToEngine.Add(uint64(len(dropped)))
+		for _, pkt := range dropped {
+			d.recycle(pkt)
+		}
+	}
+
+	clear(valid)
+	d.toEngineOfferPackets = valid[:0]
 	return nil
 }
 
 func (d *winn3FrameDevice) ReadBatch(bufs [][]byte) ([]int, error) {
-	var lengths []int
-	var first []byte
-
-	select {
-	case pkt, ok := <-d.toEngine:
-		if !ok {
-			return nil, io.EOF
-		}
-		first = pkt
-	}
-
-	n0 := copy(bufs[0], first)
-	d.recycle(first)
-	lengths = append(lengths, n0)
-
-	for len(lengths) < len(bufs) {
-		select {
-		case pkt, ok := <-d.toEngine:
-			if !ok {
-				return lengths, nil
-			}
-			idx := len(lengths)
-			ni := copy(bufs[idx], pkt)
-			d.recycle(pkt)
-			lengths = append(lengths, ni)
-		default:
-			return lengths, nil
-		}
+	if len(bufs) == 0 {
+		return nil, nil
+	}
+
+	if len(d.toEngineReadPackets) < len(bufs) {
+		d.toEngineReadPackets = make([][]byte, len(bufs))
+	}
+	packets := d.toEngineReadPackets[:len(bufs)]
+
+	n, err := d.toEngine.popBatch(packets)
+	if n == 0 {
+		return nil, err
 	}
-	return lengths, nil
+
+	lengths := make([]int, n)
+	for i := 0; i < n; i++ {
+		lengths[i] = copy(bufs[i], packets[i])
+		d.recycle(packets[i])
+		packets[i] = nil
+	}
+	return lengths, nil
 }
@@ -100,7 +129,7 @@ func (d *winn3FrameDevice) Close() error {
 	d.closeOnce.Do(func() {
-		close(d.toEngine)
+		d.toEngine.close()
 		close(d.toHost)
 	})
 	return nil
```

The two scratch slices rely on the stated single producer and single consumer architecture. If either method can be called concurrently by multiple goroutines, those scratch slices require separate ownership or synchronization.

The diff intentionally leaves payload copying outside `toEngineRing.mu`.

**4. OI-2: Intermediate memory copies**

At 1,000 Mbps payload throughput:

\[
125{,}000{,}000\ bytes/s
\]

Three full payload copies produce:

\[
3 \times 125{,}000{,}000=375{,}000{,}000\ copied\ bytes/s
\]

Per packet:

\[
3 \times 1{,}373=4{,}119\ copied\ bytes
\]

At Run 16:

\[
3 \times 48{,}709{,}632=146{,}128{,}896\ copied\ bytes/s
\]

This is not enough information to assign an exact CPU cost. If effective copy bandwidth for these buffers is \(M\) GB/s, copy time per packet is:

\[
T_{copy}=\frac{4.119}{M}\ \mu s
\]

Examples:

| Effective copy bandwidth | Three-copy time |
|---:|---:|
| 5 GB/s | 0.8238 microseconds |
| 10 GB/s | 0.4119 microseconds |
| 20 GB/s | 0.2060 microseconds |

Even the 5 GB/s case accounts for less than one microsecond of the 17.2034 microsecond gap. Cache allocation, pool synchronization, and ownership transitions can add costs, but 375 MB/s is not a DRAM bandwidth bottleneck on this hardware.

Under the current interfaces, Copy 1 and Copy 2 have distinct lifetime purposes:

1. `duplex.Reader.Read()` returns data backed by reusable `r.buffer`.
2. `allocPacket` creates storage that remains valid after the next `Read()`.
3. `ReadBatch` is contractually given destination buffers and returns only lengths, so it must populate those buffers.
4. The interface has no release callback through which the caller can return a borrowed pooled packet.

Consequently, `packetPool` is allocation-efficient but not copy-optimal. Copy 1 could be removed only by adding a reader API that decodes directly into caller-provided durable storage. Copy 2 could be removed only by changing `tun.BatchDevice` to transfer buffer ownership or by introducing a Winn-specific extension. Copy 3 could be removed only if the session driver accepts ownership of a buffer with the necessary encryption and header headroom.

A safe zero-copy design would require all of the following:

1. Session-owned buffers are loaned upstream.
2. The frame reader reads directly into those buffers.
3. The session driver accepts them without another copy.
4. Completion of encryption and carrier transmission returns them to the owning pool.
5. Every close, drop, and error path has exactly one release.

That is a larger ownership protocol, not a surgical Stage B change.

The OI-1 ring does not remove any of the 375 MB/s copy traffic. It cannot be claimed sufficient for 1,000 Mbps without a device benchmark showing at least 17.2034 microseconds of bottleneck service-time reduction per packet. The lock-cost threshold calculation above makes that result unlikely.

No OI-2 code diff is appropriate under the frozen `tun.BatchDevice` contract. Assigning pooled packet slices directly into `bufs[i]` would silently transfer ownership without a release mechanism and would either leak those packets or recycle them while still in use.

Vote: DISAGREE: with the present `duplex.Reader.Read` and `tun.BatchDevice.ReadBatch` contracts, removing the intermediate copy permits the next reader call to overwrite a packet before the outbound consumer has finished with it.

**5. OI-3: Gateway ingress audit**

At 91,041.5149 pps, a full 64-entry `recvmmsg` batch requires:

\[
\frac{91{,}041.5149}{64}=1{,}422.5237\ calls/s
\]

A 64-packet batch spans:

\[
64 \times 10.984=702.976\ \mu s
\]

This syscall rate is reasonable. It does not establish that the demultiplexer, decryption stage, or UDP socket receive queue has enough CPU headroom.

For 256-packet TUN batches:

\[
\frac{91{,}041.5149}{256}=355.6309\ batches/s
\]

With ideal four-way distribution:

\[
\frac{91{,}041.5149}{4}=22{,}760.3787\ packets/s/queue
\]

However, source-IP-only hashing does not provide four-way distribution for this test. All 32 TCP streams originate from the same inner client source IP, so they can all select the same TUN descriptor. The relevant worst case is therefore 91,041.5 pps on one queue, not 22,760.4 pps on each queue.

The speedtest application receives:

\[
\frac{125{,}000{,}000}{32}=3{,}906{,}250\ bytes/s/stream
\]

With ideal 32 KiB `io.Copy` reads, aggregate application read frequency is approximately:

\[
\frac{125{,}000{,}000}{32{,}768}=3{,}814.6973\ reads/s
\]

That is about 119.2 reads per second per stream. The application layer is unlikely to be the first bottleneck, but TCP processing and TUN injection still need measurement.

Run 16 established zero drops at 35,476.8 pps. This is only:

\[
\frac{35{,}476.8}{91{,}041.5}=38.968\%
\]

of the target packet rate. It does not verify gateway capacity at 1,000 Mbps.

No gateway modification should be made speculatively. Before certification, the gateway must sustain at least 91,042 inner packets per second, preferably 110,000 pps for margin, while recording:

1. `SO_RXQ_OVFL`.
2. UDP receive errors and kernel drops.
3. Demultiplexer queue drops.
4. Decryption worker saturation.
5. Per-TUN-queue packet counts.
6. TUN write errors and `EAGAIN`.
7. NIC receive rate including Winn, UDP, IP, and Ethernet overhead.
8. Per-core utilization and softirq utilization.

The physical gateway link also needs more than 1 Gbps if the target is 1,000 Mbps of inner payload. Outer protocol and Ethernet overhead necessarily make physical ingress exceed 1,000 Mbps.

No OI-3 code diff is justified until this load test identifies a saturated stage.

Vote: DISAGREE: Run 16 exercised only 35,476.8 pps, so its zero-drop result does not verify the gateway at the required 91,041.5 pps.

**6. OI-4: Downlink Freeze Invariant**

The OI-1 patch changes only the host-to-engine queue and its uplink scratch storage. It does not modify:

1. `toHost chan []byte`.
2. `take()`.
3. `tryTake()`.
4. `WritePacket()`.
5. Downlink buffer allocation.
6. Downlink measurement arithmetic.
7. Carrier receive batching.
8. Session receive or decrypt processing.

The close call for `toHost` remains unchanged.

The logical directions are:

```text
Uplink:   host frame reader -> toEngine -> pumpOutboundBatch -> session -> carrier
Downlink: carrier -> session -> WritePacket -> toHost -> host frame writer
```

They are queue-independent. They are not physically resource-independent because they can still share CPU capacity, cache, memory bandwidth, the packet pool, and process scheduling. Therefore, unchanged code is a valid freeze claim, while unchanged runtime throughput must still be regression-tested.

The observed downlink is 673 Mbps. The supplied evidence does not demonstrate a measured downlink above 1,000 Mbps, so no such empirical claim can be confirmed from this docket. What can be confirmed is that the proposed patch does not alter the downlink implementation.

Vote: AGREE: the proposed diff contains no modification to `toHost`, `take`, `tryTake`, or `WritePacket`, which is directly falsifiable by the repository diff.
