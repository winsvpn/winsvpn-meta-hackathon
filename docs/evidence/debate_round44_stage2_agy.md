# Turn 2 Verdict: agy

# Turn 2 Verdict: agy

# Podium 1 Verdict: Gemini 3.8 Flash High

## 1. Steelmanning of Peer Podiums

* **Claude Opus 5 (Stage B ceiling and coalescing mathematics)**: Opus 5 identified that retiring lock ping-ponging (0.209 us) and memory copies (0.467 us) saves at most 0.676 us per packet (3.93% of the 17.203 us gap), leaving 27.51 us per packet and projecting 399.25 Mbps. Opus 5 demonstrated that beating 1,000 Mbps requires amortizing fixed per-packet overhead (F = 26.58 us) through segmentation coalescing at factor N >= 3 to 4 (such as TUN super-frames and carrier UDP GSO). Opus 5 proved that condition variable signaling must occur after releasing the mutex (`r.mu.Unlock()`) to eliminate lock contention on waiter wakeup.
* **GPT-5.6 Sol Pro (Critical section decoupling and lock cost accounting)**: Sol Pro proved from first principles that 512-push and 256-pop batching reduces synchronization acquisitions from 182,083 to 533.45 per second (a 99.71% reduction). Sol Pro demonstrated that channel lock contention alone cannot explain the full 17.203 us gap, because that would require an implausible average channel operation cost of 8.627 us. Sol Pro established the architectural requirement that `toEngineRing` must transfer only 24-byte slice headers under its mutex, performing all payload copying and packet recycling outside the critical section to prevent lock holding during memory moves.
* **Consensus on memory safety and buffer ownership**: Both Opus 5 and Sol Pro demonstrated that bypassing intermediate copies in Stage B breaks the frozen `tun.BatchDevice` contract (`ReadBatch(bufs [][]byte) ([]int, error)`). Directly lending pooled slices without an upstream release protocol introduces buffer aliasing and memory overwrite hazards, confirming that `packetPool` retention is required in Stage B.

---

## 2. Position Evolution and Arbiter Ground-Truth Resolutions

* **OI-1 architectural refinement**: We adopt the peer improvements for `toEngineRing`. Payload copying and `packetPool` recycling are extracted from the critical section, and condition variable signaling is executed after releasing `r.mu.Unlock()`.
* **OI-2 memory preservation**: We converge fully with Opus 5 and Sol Pro. Retaining zero-allocation `packetPool` copying preserves the frozen `tun.BatchDevice` contract and isolates buffer lifetimes, while zero-copy optimizations are correctly sequenced into Stage C coalescing.
* **OI-3 factual resolution**: Live verification by the Arbiter in `cmd/winn3-gateway/forward_linux.go` lines 272-286 confirmed that the Canada gateway already implements inner TCP 4-tuple hashing (`srcPort >> 2 ^ dstPort`). This distributes the 32 speedtest streams across all 4 TUN queues, disproving the single-queue collapse hypothesis and confirming that zero gateway modifications are required.
* **OI-4 downlink freeze clarification**: We accept Opus 5 and Sol Pro's factual correction to strike the unmeasured ">1,000 Mbps" parenthetical. The downlink datapath remains 100% frozen, with empirical performance anchored to the 673 Mbps sustained rate measured in Run 16.

---

## 3. Explicit Convergence Votes

* **OI-1 (Lock-Batched Ring Buffer)**: AGREE: Batching 512-packet pushes and 256-packet pops reduces lock acquisitions from 182,083 to 533.45 per second (a 99.71% reduction), eliminating cross-core cache-line ping-ponging on `hchan.lock`.
* **OI-2 (Preserving packetPool in Stage B)**: AGREE: Preserving the existing zero-allocation `packetPool` copying in Stage B maintains the frozen `tun.BatchDevice` contract and eliminates buffer-aliasing hazards while deferring zero-copy ownership transfer to Stage C coalescing.
* **OI-3 (Gateway Ingress Verification)**: AGREE: Live codebase verification in `cmd/winn3-gateway/forward_linux.go` lines 272-286 confirms that inner TCP 4-tuple hashing is already active and distributes speedtest streams across all 4 TUN queues without gateway edits.
* **OI-4 (Downlink Freeze Invariant)**: AGREE: The downlink datapath implementation remains 100% frozen with zero modifications to `toHost`, `take`, `tryTake`, `WritePacket`, or measurement parameters.

---

## 4. Final Ratified Surgical Code Diff

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
@@ -10,6 +10,7 @@
 	"fmt"
 	"io"
 	"sync"
 	"sync/atomic"
 
 	"winsvpn.local/winnprotocol/winn3/tun"
@@ -78,6 +79,165 @@
 var errWinn3DeviceClosed = errors.New("winn3: the frame device is closed")
 
+// toEngineRing is a lock-batched circular ring buffer for the uplink queue.
+// It replaces the scalar Go channel to eliminate per-packet mutex contention
+// and cross-core cache-line bouncing at wire speed.
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
+	r := &toEngineRing{
+		storage: make([][]byte, capacity),
+	}
+	r.cond = sync.NewCond(&r.mu)
+	return r
+}
+
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
+	r.mu.Lock()
+	if r.closed {
+		r.mu.Unlock()
+		for _, pkt := range packets {
+			recycle(pkt)
+		}
+		return errWinn3DeviceClosed
+	}
+
+	capacity := len(r.storage)
+	var droppedCount uint64
+	var oversizeCount uint64
+	enqueued := 0
+
+	for _, pkt := range packets {
+		if len(pkt) > mtu {
+			oversizeCount++
+			recycle(pkt)
+			continue
+		}
+		if r.count == capacity {
+			droppedCount++
+			recycle(pkt)
+			continue
+		}
+		r.storage[r.tail] = pkt
+		r.tail = (r.tail + 1) % capacity
+		r.count++
+		enqueued++
+	}
+	r.mu.Unlock()
+
+	if enqueued > 0 {
+		r.cond.Signal()
+	}
+	if oversizeCount > 0 {
+		oversize.Add(oversizeCount)
+	}
+	if droppedCount > 0 {
+		dropped.Add(droppedCount)
+	}
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
+		recycle(pkt)
+		dropped.Add(1)
+		return nil
+	}
+	r.storage[r.tail] = pkt
+	r.tail = (r.tail + 1) % len(r.storage)
+	r.count++
+	r.mu.Unlock()
+
+	r.cond.Signal()
+	return nil
+}
+
+func (r *toEngineRing) popBatch(dst [][]byte) (int, error) {
+	r.mu.Lock()
+	for r.count == 0 && !r.closed {
+		r.cond.Wait()
+	}
+	if r.count == 0 && r.closed {
+		r.mu.Unlock()
+		return 0, errWinn3DeviceClosed
+	}
+
+	capacity := len(r.storage)
+	n := min(len(dst), r.count)
+	for i := 0; i < n; i++ {
+		dst[i] = r.storage[r.head]
+		r.storage[r.head] = nil
+		r.head = (r.head + 1) % capacity
+	}
+	r.count -= n
+	r.mu.Unlock()
+	return n, nil
+}
+
+func (r *toEngineRing) popSingle(
+	buf []byte,
+	oversize *atomic.Uint64,
+	recycle func([]byte),
+) (int, error) {
+	r.mu.Lock()
+	for r.count == 0 && !r.closed {
+		r.cond.Wait()
+	}
+	if r.count == 0 && r.closed {
+		r.mu.Unlock()
+		return 0, errWinn3DeviceClosed
+	}
+
+	capacity := len(r.storage)
+	pkt := r.storage[r.head]
+	r.storage[r.head] = nil
+	r.head = (r.head + 1) % capacity
+	r.count--
+	r.mu.Unlock()
+
+	defer recycle(pkt)
+	if len(pkt) > len(buf) {
+		oversize.Add(1)
+		return 0, fmt.Errorf("winn3: read buffer of %d bytes is shorter than the %d-byte packet", len(buf), len(pkt))
+	}
+	return copy(buf, pkt), nil
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
+
 // winn3FrameDevice is a tun.Device backed by the duplex frame channel.
@@ -106,3 +266,3 @@
 	// toEngine is what the host offered and the tun layer has not yet read.
 	// toHost is what the tun layer delivered and the host has not yet taken.
-	toEngine chan []byte
+	toEngine *toEngineRing
 	toHost   chan []byte
@@ -116,2 +276,3 @@
 	readLengths []int
+	readPackets [][]byte
 }
@@ -131,3 +292,4 @@
 		mtu:      mtu,
-		toEngine: make(chan []byte, winn3FrameQueueDepth),
+		toEngine: newToEngineRing(winn3FrameQueueDepth),
 		toHost:   make(chan []byte, winn3FrameQueueDepth),
 		closed:   make(chan struct{}),
+		readPackets: make([][]byte, 256),
 	}, nil
@@ -165,4 +327,3 @@
 	copy(cp, packet)
-	// Tail drop on the uplink: never remove the head of an in-order stream.
-	d.push(d.toEngine, cp, &d.droppedToEngine, false)
-	return nil
+	return d.toEngine.pushSingle(cp, &d.droppedToEngine, d.recycle)
 }
@@ -179,9 +340,3 @@
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
+	return d.toEngine.pushBatch(packets, d.mtu, &d.oversize, &d.droppedToEngine, d.recycle)
 }
@@ -230,23 +385,3 @@
 func (d *winn3FrameDevice) ReadPacket(buf []byte) (int, error) {
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
-	defer d.recycle(pkt)
-	n := copy(buf, pkt)
-	if n < len(pkt) {
-		// A short buffer is the caller's bug, not a reason to lose a packet
-		// silently: a truncated IP packet is undetectable corruption at the
-		// next layer.
-		return n, fmt.Errorf(
-			"winn3: read buffer of %d bytes is shorter than the %d-byte packet",
-			len(buf), len(pkt))
-	}
-	return n, nil
+	return d.toEngine.popSingle(buf, &d.oversize, d.recycle)
 }
@@ -330,2 +465,3 @@
 		close(d.closed)
+		d.toEngine.close()
 	}
@@ -341,58 +477,29 @@
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
-
-	lengths := d.readLengths[:0]
-	if cap(lengths) < len(bufs) {
-		lengths = make([]int, 0, len(bufs))
-	}
-	if len(first) > len(bufs[0]) {
-		d.oversize.Add(1)
-		d.recycle(first)
-		return nil, errors.New("read batch buffer too small for first packet")
-	}
-	n0 := copy(bufs[0], first)
-	d.recycle(first)
-	lengths = append(lengths, n0)
-
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
-			d.recycle(pkt)
-			lengths = append(lengths, ni)
-		default:
-			if len(d.toEngine) > 0 && len(lengths) < len(bufs) {
-				continue
-			}
-			d.readLengths = lengths
-			return lengths, nil
-		}
+	if len(d.readPackets) < len(bufs) {
+		d.readPackets = make([][]byte, len(bufs))
+	}
+	packets := d.readPackets[:len(bufs)]
+
+	n, err := d.toEngine.popBatch(packets)
+	if n == 0 {
+		return nil, err
+	}
+
+	lengths := d.readLengths[:0]
+	if cap(lengths) < n {
+		lengths = make([]int, 0, n)
+	}
+
+	for i := 0; i < n; i++ {
+		pkt := packets[i]
+		packets[i] = nil
+		if len(pkt) > len(bufs[i]) {
+			d.oversize.Add(1)
+			d.recycle(pkt)
+			continue
+		}
+		copied := copy(bufs[i], pkt)
+		d.recycle(pkt)
+		lengths = append(lengths, copied)
 	}
 
 	d.readLengths = lengths
-	return lengths, nil
+	return lengths, nil
 }
```
