# Turn 2 Verdict: solpro

1. **Steelman of peer arguments**

OI-1 concurrency and locality

- Opus correctly identified that a buffered Go channel is already a mutex-protected circular queue. The architectural gain comes from moving 512 producer slot updates and 256 consumer slot updates under two aggregate lock acquisitions, not from the circular layout itself.
- Sol correctly rejected any fixed microsecond saving derived solely from acquisition count. At 1,000 Mbps:

  \[
  P=\frac{125{,}000{,}000}{1{,}373}=91{,}041.5149\ packets/s
  \]

  Existing channel synchronization:

  \[
  2P=182{,}083.0298\ acquisitions/s
  \]

  Batched ring synchronization:

  \[
  \frac{P}{512}+\frac{P}{256}
  =177.8155+355.6309
  =533.4464\ acquisitions/s
  \]

  Reduction factor:

  \[
  \frac{182{,}083.0298}{533.4464}=341.3333
  \]

  This proves synchronization frequency reduction. It does not prove Gemini's estimated 1.85 microseconds per packet without device profiling.
- Sol's strongest implementation point was keeping payload copies and `packetPool.Put` operations outside the ring mutex. The mutex should protect only ring metadata and slice-header transfers. Holding it while copying as much as 351,488 bytes per 256-packet batch would unnecessarily block the producer.
- Opus's strongest condition-variable point was signaling after unlocking. The queue predicate is changed while holding `mu`, so signaling after unlock is safe and avoids waking the consumer directly into a blocked `Lock`.
- The custom ring still transfers packet cache lines from producer to consumer. It specifically removes almost all contention on shared queue metadata such as `hchan.lock`, `qcount`, `sendx`, and `recvx`.

OI-2 ownership

- The strongest argument is the frozen `tun.BatchDevice` contract:

  ```go
  ReadBatch(bufs [][]byte) ([]int, error)
  ```

  The caller owns `bufs`. The callee cannot substitute pooled packet slices or communicate when borrowed storage may be recycled.
- Copy 1 gives frame data a lifetime beyond the next reuse of `duplex.Reader` storage. Copy 2 fulfills the caller-owned destination contract. Copy 3 moves data into session storage with the required encryption and carrier headroom.
- Eliminating any of those copies safely requires an explicit ownership-transfer and release protocol. Recycling a lent packet before encryption completes creates use-after-recycle aliasing. Never recycling it leaks the pool object.
- At wire speed, the three copies account for:

  \[
  3\times125{,}000{,}000=375{,}000{,}000\ bytes/s
  \]

  This is approximately:

  \[
  \frac{375}{68{,}000}=0.551\%
  \]

  of a 68 GB/s memory subsystem when measured as logical copied bytes. At an effective 8.8 to 25.7 GB/s copy rate, 4,119 copied bytes take approximately 0.47 to 0.16 microseconds per packet. That cannot retire the 17.2034 microsecond service-time gap.

OI-3 gateway distribution

- Opus and Sol raised the correct failure mode for a hypothetical source-IP-only hash. Thirty-two flows from one client IP would select one TUN descriptor.
- The Arbiter's live-code verification disproves that premise. The gateway incorporates the source port and destination port:

  ```go
  h := int(a[3]) ^ (srcPort >> 2) ^ dstPort
  idx = h % len(s.files)
  ```

  For the fixed speedtest endpoint, source-port variation distributes the 32 connections across the four descriptors. No gateway hash patch is warranted.

OI-4 isolation

- The strongest qualification from Sol is that code-path isolation does not mean physical resource independence. Uplink and downlink still share CPU capacity, caches, scheduling, and potentially `packetPool`.
- Nevertheless, the proposed patch changes no downlink function, queue, batch parameter, or measurement parameter. The factual frozen baseline is 673 Mbps sustained, not more than 1,000 Mbps.

2. **Position changes after cross-examination**

- OI-1 remains AGREE. The implementation below incorporates the peer recommendation to move only slice headers while holding the ring lock.
- OI-2 remains DISAGREE with changing the copy architecture during Stage B.
- OI-3 changes from my Turn 1 DISAGREE to AGREE. The prior objection depended on source-IP-only hashing, which the verified gateway code does not use.
- OI-4 remains AGREE. The measured downlink reference is corrected to 673 Mbps.

3. **Independent adjudication**

OI-1

The ring must linearize enqueue, close, and dequeue through the same mutex:

1. An enqueue that acquires `mu` before `Close` commits its accepted packets.
2. `Close` sets `closed` while holding `mu` and broadcasts.
3. An enqueue that observes `closed` accepts nothing and recycles every packet it still owns.
4. A consumer continues dequeuing while `count > 0`, even after closure.
5. `errWinn3DeviceClosed` is returned only when `closed && count == 0`.

The implementation uses one `Signal` per successful push batch and one `Broadcast` on closure. Payload copying and recycling occur after dequeue releases the mutex.

OI-2

Preserving `packetPool` retains stable ownership:

```text
frame reader storage
    -> durable packetPool packet
    -> caller-owned BatchDevice buffer
    -> session-owned send buffer
```

Each boundary has an unambiguous owner. Removing Copy 2 alone would violate `ReadBatch` because the interface returns lengths, not replacement buffers or release callbacks. Therefore no Stage B diff is appropriate in `tun.BatchDevice`, `winn3_frame.go`, or `session/driver.go`.

OI-3

At 1,000 Mbps:

\[
\frac{91{,}041.5149}{64}=1{,}422.5237\ recvmmsg\ calls/s
\]

With four-way flow distribution:

\[
\frac{91{,}041.5149}{4}=22{,}760.3787\ packets/s/descriptor
\]

The verified port-aware hash addresses the previously identified queue-collapse risk. Capacity still requires load testing, but there is no identified gateway defect requiring a Stage B code change.

OI-4

The only replaced object is `toEngine`. The following remain byte-for-byte unchanged:

- `toHost chan []byte`
- `take`
- `tryTake`
- `WritePacket`
- `pumpOutboundBatch` downlink-independent behavior
- `outboundPump`
- Downlink batching and measurement parameters

4. **Final convergence votes**

- OI-1: AGREE: with full 512-packet pushes and 256-packet pops, queue synchronization falls from 182,083.03 to 533.45 acquisitions per second, which is falsifiable with mutex profiling at 91,041.51 packets per second.
- OI-2: DISAGREE: replacing the Copy 2 boundary without changing `ReadBatch(bufs [][]byte) ([]int, error)` provides no release point for borrowed pooled packets, which is falsifiable by either an alias race or unrecycled pool ownership.
- OI-3: AGREE: the verified gateway code already includes `srcPort >> 2` and `dstPort` in queue selection, so the asserted single-source-IP queue collapse does not occur for the 32-flow test.
- OI-4: AGREE: the ratified diff contains no modification to `toHost`, `take`, `tryTake`, `WritePacket`, or any downlink measurement parameter.

5. **Ratified surgical code diff**

This version transfers only slice headers while holding the ring mutex. Packet copying and recycling remain outside the critical section.

```diff
diff --git a/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go b/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
new file mode 100644
--- /dev/null
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
@@ -0,0 +1,197 @@
+package main
+
+import (
+	"sync"
+	"sync/atomic"
+)
+
+// toEngineRing is the uplink queue. It batches synchronization while moving
+// only slice headers under its mutex. Packet payload copying remains outside
+// the critical section.
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
+		panic("winn3: toEngine ring capacity must be positive")
+	}
+	r := &toEngineRing{
+		storage: make([][]byte, capacity),
+	}
+	r.cond = sync.NewCond(&r.mu)
+	return r
+}
+
+// pushBatch takes ownership of every packet in packets. Accepted packets move
+// into the ring. Rejected packets are recycled after releasing the mutex.
+func (r *toEngineRing) pushBatch(
+	packets [][]byte,
+	mtu int,
+	oversize *atomic.Uint64,
+	dropped *atomic.Uint64,
+	recycle func([]byte),
+) error {
+	if len(packets) == 0 {
+		return nil
+	}
+
+	// The input belongs exclusively to this call. Compact rejected pointers
+	// into its prefix so no temporary allocation is required.
+	rejected := packets[:0]
+	var oversizeCount uint64
+	var droppedCount uint64
+	enqueued := 0
+
+	r.mu.Lock()
+	if r.closed {
+		r.mu.Unlock()
+		for _, pkt := range packets {
+			recycle(pkt)
+		}
+		clear(packets)
+		return errWinn3DeviceClosed
+	}
+
+	for _, pkt := range packets {
+		if len(pkt) > mtu {
+			oversizeCount++
+			rejected = append(rejected, pkt)
+			continue
+		}
+		if r.count == len(r.storage) {
+			droppedCount++
+			rejected = append(rejected, pkt)
+			continue
+		}
+
+		r.storage[r.tail] = pkt
+		r.tail++
+		if r.tail == len(r.storage) {
+			r.tail = 0
+		}
+		r.count++
+		enqueued++
+	}
+	r.mu.Unlock()
+
+	if enqueued != 0 {
+		r.cond.Signal()
+	}
+	if oversizeCount != 0 {
+		oversize.Add(oversizeCount)
+	}
+	if droppedCount != 0 {
+		dropped.Add(droppedCount)
+	}
+	for _, pkt := range rejected {
+		recycle(pkt)
+	}
+	clear(packets)
+	return nil
+}
+
+func (r *toEngineRing) pushSingle(
+	pkt []byte,
+	dropped *atomic.Uint64,
+	recycle func([]byte),
+) error {
+	r.mu.Lock()
+	if r.closed {
+		r.mu.Unlock()
+		recycle(pkt)
+		return errWinn3DeviceClosed
+	}
+	if r.count == len(r.storage) {
+		r.mu.Unlock()
+		dropped.Add(1)
+		recycle(pkt)
+		return nil
+	}
+
+	r.storage[r.tail] = pkt
+	r.tail++
+	if r.tail == len(r.storage) {
+		r.tail = 0
+	}
+	r.count++
+	r.mu.Unlock()
+
+	r.cond.Signal()
+	return nil
+}
+
+// popBatch copies packet slice headers into dst under one lock acquisition.
+// firstBufferSize preserves the existing first-packet short-buffer behavior:
+// if the first packet cannot fit, only that packet is claimed.
+func (r *toEngineRing) popBatch(
+	dst [][]byte,
+	firstBufferSize int,
+) (int, error) {
+	if len(dst) == 0 {
+		return 0, nil
+	}
+
+	r.mu.Lock()
+	for r.count == 0 && !r.closed {
+		r.cond.Wait()
+	}
+	if r.count == 0 && r.closed {
+		r.mu.Unlock()
+		return 0, errWinn3DeviceClosed
+	}
+
+	n := len(dst)
+	if n > r.count {
+		n = r.count
+	}
+	if len(r.storage[r.head]) > firstBufferSize {
+		n = 1
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
+	r.mu.Unlock()
+	return n, nil
+}
+
+func (r *toEngineRing) popSingle() ([]byte, error) {
+	r.mu.Lock()
+	for r.count == 0 && !r.closed {
+		r.cond.Wait()
+	}
+	if r.count == 0 && r.closed {
+		r.mu.Unlock()
+		return nil, errWinn3DeviceClosed
+	}
+
+	pkt := r.storage[r.head]
+	r.storage[r.head] = nil
+	r.head++
+	if r.head == len(r.storage) {
+		r.head = 0
+	}
+	r.count--
+	r.mu.Unlock()
+	return pkt, nil
+}
+
+// Close prevents new enqueues, wakes every waiter, and leaves committed
+// packets available for draining.
+func (r *toEngineRing) Close() {
+	r.mu.Lock()
+	if !r.closed {
+		r.closed = true
+		r.cond.Broadcast()
+	}
+	r.mu.Unlock()
+}
diff --git a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
@@ -103,8 +103,9 @@ type winn3FrameDevice struct {
 	// toEngine is what the host offered and the tun layer has not yet read.
 	// toHost is what the tun layer delivered and the host has not yet taken.
-	toEngine chan []byte
-	toHost   chan []byte
+	toEngine            *toEngineRing
+	toHost              chan []byte
+	toEngineReadPackets [256][]byte
 
 	droppedToEngine atomic.Uint64
 	droppedToHost   atomic.Uint64
@@ -131,7 +132,7 @@ func newWinn3FrameDevice(mtu int) (*winn3FrameDevice, error) {
 	d := &winn3FrameDevice{
 		mtu:      mtu,
-		toEngine: make(chan []byte, winn3FrameQueueDepth),
+		toEngine: newToEngineRing(winn3FrameQueueDepth),
 		toHost:   make(chan []byte, winn3FrameQueueDepth),
 	}
 	return d, nil
@@ -163,10 +164,7 @@ func (d *winn3FrameDevice) offer(packet []byte) error {
 	cp := d.allocPacket(len(packet))
 	copy(cp, packet)
-	// Tail drop on the uplink: never remove the head of an in-order stream.
-	d.push(d.toEngine, cp, &d.droppedToEngine, false)
-	return nil
+	return d.toEngine.pushSingle(cp, &d.droppedToEngine, d.recycle)
 }
 
 func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
@@ -176,16 +174,13 @@ func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
 		}
 		return errWinn3DeviceClosed
 	}
-	for _, pkt := range packets {
-		if len(pkt) > d.mtu {
-			d.oversize.Add(1)
-			d.recycle(pkt)
-			continue
-		}
-		d.push(d.toEngine, pkt, &d.droppedToEngine, false)
-	}
-	return nil
+	return d.toEngine.pushBatch(
+		packets,
+		d.mtu,
+		&d.oversize,
+		&d.droppedToEngine,
+		d.recycle,
+	)
 }
 
 func (d *winn3FrameDevice) ReadPacket(buf []byte) (int, error) {
@@ -231,26 +226,15 @@ func (d *winn3FrameDevice) ReadPacket(buf []byte) (int, error) {
-	var pkt []byte
-	select {
-	case pkt = <-d.toEngine:
-	case <-d.closed:
-		select {
-		case pkt = <-d.toEngine:
-		default:
-			return 0, errWinn3DeviceClosed
-		}
-	}
+	pkt, err := d.toEngine.popSingle()
+	if err != nil {
+		return 0, err
+	}
 	defer d.recycle(pkt)
+
 	n := copy(buf, pkt)
 	if n < len(pkt) {
-		// A short buffer is the caller's bug, not a reason to lose a packet
-		// silently: a truncated IP packet is undetectable corruption at the
-		// next layer.
 		return n, fmt.Errorf(
 			"winn3: read buffer of %d bytes is shorter than the %d-byte packet",
 			len(buf), len(pkt))
@@ -328,6 +312,7 @@ func (d *winn3FrameDevice) Close() error {
 	if d.once.CompareAndSwap(false, true) {
 		close(d.closed)
+		d.toEngine.Close()
 	}
 	return nil
 }
@@ -339,59 +324,56 @@ func (d *winn3FrameDevice) ReadBatch(bufs [][]byte) ([]int, error) {
 	if len(bufs) == 0 {
 		return nil, nil
 	}
-	var first []byte
-	select {
-	case pkt, ok := <-d.toEngine:
-		if !ok {
-			return nil, errWinn3DeviceClosed
-		}
-		first = pkt
-	case <-d.closed:
-		select {
-		case pkt := <-d.toEngine:
-			first = pkt
-		default:
-			return nil, errWinn3DeviceClosed
-		}
-	}
 
 	lengths := d.readLengths[:0]
 	if cap(lengths) < len(bufs) {
 		lengths = make([]int, 0, len(bufs))
 	}
-	if len(first) > len(bufs[0]) {
+
+	limit := len(bufs)
+	if limit > len(d.toEngineReadPackets) {
+		limit = len(d.toEngineReadPackets)
+	}
+	packets := d.toEngineReadPackets[:limit]
+
+	n, err := d.toEngine.popBatch(packets, len(bufs[0]))
+	if n == 0 {
+		return nil, err
+	}
+
+	if len(packets[0]) > len(bufs[0]) {
 		d.oversize.Add(1)
-		d.recycle(first)
+		d.recycle(packets[0])
+		packets[0] = nil
 		return nil, errors.New("read batch buffer too small for first packet")
 	}
-	n0 := copy(bufs[0], first)
-	d.recycle(first)
+
+	n0 := copy(bufs[0], packets[0])
+	d.recycle(packets[0])
+	packets[0] = nil
 	lengths = append(lengths, n0)
 
-	for len(lengths) < len(bufs) {
-		select {
-		case pkt, ok := <-d.toEngine:
-			if !ok {
-				d.readLengths = lengths
-				return lengths, nil
-			}
-			idx := len(lengths)
-			if len(pkt) > len(bufs[idx]) {
-				d.oversize.Add(1)
-				d.recycle(pkt)
-				continue
-			}
-			ni := copy(bufs[idx], pkt)
+	for i := 1; i < n; i++ {
+		pkt := packets[i]
+		packets[i] = nil
+
+		idx := len(lengths)
+		if len(pkt) > len(bufs[idx]) {
+			d.oversize.Add(1)
 			d.recycle(pkt)
-			lengths = append(lengths, ni)
-		default:
-			if len(d.toEngine) > 0 && len(lengths) < len(bufs) {
-				continue
-			}
-			d.readLengths = lengths
-			return lengths, nil
+			continue
 		}
+
+		ni := copy(bufs[idx], pkt)
+		d.recycle(pkt)
+		lengths = append(lengths, ni)
 	}
 
 	d.readLengths = lengths
 	return lengths, nil
 }
```

No code diff is ratified for OI-2, OI-3, or OI-4.

6. **Application checks**

Run immediately after applying the patch:

```sh
gofmt -w \
  winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go \
  winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go

go test ./winn_protocol_experimental/cmd/winn-datapath/...
go test -race ./winn_protocol_experimental/cmd/winn-datapath/...
```

Required runtime assertions:

- A close with queued packets drains those packets before `errWinn3DeviceClosed`.
- A push after `Close` recycles every supplied packet.
- A full ring tail-drops and recycles only the unaccepted suffix.
- Mutex profiling approaches 533.45 ring acquisitions per second at 91,041.51 packets per second when 512-packet producer batches and 256-packet consumer batches are full.
- Run 16 downlink behavior remains at the frozen 673 Mbps baseline within the existing regression tolerance.
