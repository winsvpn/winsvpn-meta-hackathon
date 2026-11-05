# Turn 2 Verdict: claude-opus5

# Turn 2: Cross-Examination and Final Convergence Vote (Claude Opus 5)

## 0. Evidence status

Tool use is prohibited for this seat. External claims stay tagged `UNVERIFIED-LIVE` per 13.3. One thing changed materially since Turn 1: the Arbiter and the Gemini seat quoted file text I could not read, so `errWinn3DeviceClosed`, the real `Close()` body, the `d.readLengths` field, and `forward_linux.go` lines 272 to 286 are now ground truth in this record. My Section 3 diffs are built against that quoted text. Line anchors are taken from the Gemini quotation, not from my own read, so apply by context match.

---

## 1. Steelman of the opposing seats

- **Sol Pro on lock cost, the strongest point in the round.** The acquisition count is falsifiable arithmetic; the microsecond saving is not derivable from it. Sol Pro inverted the relation and got the falsifying number: for OI-1 alone to retire 17.2034 us you need `L = 17.2034 / 1.994140625 = 8.6270 us` per channel operation. That is absurd on its face, and it converts the whole OI-1 claim from "this closes the gap" to "this removes a named contention source worth roughly 1% of it." This changes nothing in my vote and everything in what the certified text may assert. Adopted.

- **Sol Pro on payload copies outside the mutex.** The ring must move slice headers under the lock and do payload copies plus pool recycling after the unlock. Gemini's `popBatch` does the opposite: it runs `copy(bufs[idx], pkt)` and `recycle(pkt)` for up to 256 packets while holding `r.mu`. Arithmetic on that hold: 256 x 1,373 = 351,488 B at roughly 10 GB/s effective is 35.1 us, plus 256 pool Puts at about 25 ns is 6.4 us, so 41.5 us of hold per pop batch. At 355.6 pop batches per second that is 14.76 ms/s, a 1.48% mutex duty cycle, and about 2.6 producer stalls per second averaging 20.8 us. Honest read: that is not a throughput defect (roughly 0.005% of wall time). I reject the under-lock copy for lock discipline and producer tail latency, since a stall of 41.5 us is 3.8 wire-speed packet budgets, and because `recycle` is a caller-supplied callback invoked under a lock the ring does not own. Sol Pro's separation is the correct shape. Adopted.

- **Sol Pro on memory ownership, which settles OI-2.** `ReadBatch(bufs [][]byte) ([]int, error)` returns lengths and nothing else. There is no release callback on that signature, so assigning a pooled packet into `bufs[i]` transfers ownership with no path to return it: either the buffer never goes back to `packetPool` or it goes back while `pumpOutboundBatch` still reads it. That is a cleaner disqualification of copy elimination than my throughput argument, because it holds regardless of what the copies cost. Adopted as the primary reason.

- **Sol Pro on bulk header movement.** Two `copy` calls over contiguous ring segments beat a per-packet store loop with a mask advance and a counter bump on every iteration. Order of magnitude: 512 headers is 12,288 B in two memmoves, roughly 0.61 us per batch, about 1.2 ns/packet, against roughly 3 to 4 ns/packet for the scalar loop. Real but small. Adopted because the code is shorter and the critical section becomes independent of batch content, not because it moves the throughput number.

- **Gemini on ring/device coupling.** The case for passing `mtu`, the atomics, and `recycle` into the ring is that `offerBatch` then needs one pass instead of a filter pass plus a push. That argument is sound on instruction count and I am rejecting it anyway: policy in the ring is what forces the payload copy and the pool Put under `mu`. Keeping the ring a pure data structure is what makes the lock discipline provable by inspection.

- **Gemini on graceful drain.** Gemini and I converged independently on the same closing rule: `closed` under the lock, `Broadcast` once, and `popBatch` reporting EOF only when closed and empty so the consumer still gets the backlog. Sol Pro's six step linearization is the same rule stated as an ordering proof. No dispute here.

- **Gemini on condition variable signaling, where I was wrong in Turn 1.** I wrote that unconditional `Signal` is the multi-consumer safe choice against Sol Pro's `wasEmpty` gate. It is not. A 512 packet push signals once; consumer A takes 256 and consumer B stays parked on the remaining 256. Unconditional `Signal` and edge-gated `Signal` are both lossy with more than one consumer; only `Broadcast`, or a re-signal when a remainder survives the drain, is safe. The ratified ring re-signals after the drain when `count > 0`, which costs one call per non-emptying pop and makes the structure correct for any consumer count. Correction folded into Section 3.

- **CPU cache locality, both seats.** I am tightening this claim rather than repeating it. `hchan.buf` is a contiguous array and so is `storage`, so there is no spatial locality win: the two layouts are equivalent. Ring storage is 65,536 x 24 B = 1,572,864 B, but the touched window at steady state is the live span between head and tail, which the 512/256 batch sizes hold near 12,288 B, or 192 cache lines. No L2 displacement concern. There is no producer/consumer index padding here, so `mu`, `head`, and `count` share a line by design under a single lock; separating them only pays in a lock free SPSC design, which after a 341x lock reduction would buy under 0.7 ns/packet. Not worth the proof obligation. The entire OI-1 win is lock amortization, not locality.

- **Gemini's 1.85 us/packet, which I dispute on the arithmetic.** Working backward, 1.85 / 1.994140625 = 0.92773 us per channel operation, roughly 4,000 cycles on a 4.32 GHz prime core. A buffered channel send that neither parks nor blocks costs on the order of 30 to 60 ns `(UNVERIFIED-LIVE)`. The figure only works if every packet parks a goroutine, and the `ReadBatch` code Gemini itself quoted drains with `default:` after the first element, so the consumer parks at most once per batch, not once per packet. The park premise contradicts the quoted source. The Arbiter's restated OI-1 text carries the 341.3x acquisition reduction and the queue mechanics but no microsecond figure, so this does not block my AGREE. It does mean no microsecond savings number may enter the certified text without a measurement.

---

## 2. First-principles arithmetic

### 2.1 Baseline, reproduced independently

```
wire:   125,000,000 / 1,373        =  91,041.5149 pps
budget: 1e6 / 91,041.5149          =  10.9840 us/packet
run16:  389,677,056 / 8.000        =  48,709,632 B/s
        48,709,632 / 1,373         =  35,476.7896 pps
        1e6 / 35,476.7896          =  28.1874 us/packet
gap:    28.1874 - 10.9840          =  17.2034 us/packet
ratio:  91,041.5149 / 35,476.7896  =   2.56623x
```

All three seats reproduce these. The empirical block is internally consistent.

### 2.2 Lock acquisition arithmetic, the one OI-1 claim that certifies

```
channel: 2 x 91,041.5149            = 182,083.0298 /s
push:      91,041.5149 / 512        =     177.8155 /s
pop:       91,041.5149 / 256        =     355.6309 /s
ring total                          =     533.4464 /s
factor:  182,083.0298 / 533.4464    =     341.34x
percent: 1 - (1/512 + 1/256)/2      =      99.70703125% reduction
```

This is directly falsifiable with `runtime/metrics` `/sync/mutex/wait/total:seconds` plus a mutex profile. It is the acceptance criterion I vote on.

### 2.3 Time saving, stated as a band rather than a point

Per-packet channel cost decomposes into a CAS on a remote-dirty lock line, the `hchan` body work including a 24 B header move, and the release store with its invalidation, on each of the two sides. Central estimate 115 ns per side, 230 ns per packet, plausible range 60 to 250 ns per side `(UNVERIFIED-LIVE: no perf counters exist anywhere in this docket)`. Ring residual is one segment-copy slot plus a masked index advance on each side, about 20 ns, plus amortized lock at `150/512 + 150/256 = 0.88 ns`.

```
central: 230.0 - 20.9   = 209.1 ns = 0.2091 us/packet  = 1.216% of gap
low:     120.0 - 20.0   = 100.0 ns = 0.1000 us/packet  = 0.581% of gap
high:    500.0 - 21.0   = 479.0 ns = 0.4790 us/packet  = 2.784% of gap
```

### 2.4 Stage B ceiling with OI-2 preserved

OI-2 now means "change nothing," so Stage B is OI-1 alone.

```
central: 28.1874 - 0.2091 = 27.9783 us -> 35,741.7 pps -> 49,073,766 B/s -> 392.59 Mbps
low:     28.1874 - 0.1000 = 28.0874 us -> 35,603.0 pps -> 48,882,919 B/s -> 391.06 Mbps
high:    28.1874 - 0.4790 = 27.7084 us -> 36,090.0 pps -> 49,551,570 B/s -> 396.41 Mbps
```

**Stage B lands at 391 to 396 Mbps against a 389.68 Mbps median baseline, a gain of 0.4% to 1.7%.** Round 43's projection overshot measurement by 6.1% to 8.8%. A 1.7% predicted gain sits inside that calibration error and inside ordinary run-to-run variance on a thermally throttled handset. Certifying Stage B on a Mbps delta is therefore not sound. Certify it on the mutex counter in 2.2, which moves by a factor of 341 and cannot hide in variance.

Residual after Stage B: `27.9783 - 10.9840 = 16.9943 us`, still 2.547x short of budget.

### 2.5 Coalescing model, updated for the post-OI-1 baseline

Byte-proportional term unchanged: three copies 0.412 us, AEAD at an effective 1.5 GB/s 0.915 us, `copy_from_user` inside `sendmmsg` at 5 GB/s 0.275 us, so `P = 1.602 us`. Fixed term `F = 27.9783 - 1.602 = 26.3763 us`.

```
cost(N) = 26.3763/N + 1.602

N=1: 27.978 us ->  35,742 pps ->   392.6 Mbps   (Stage B)
N=2: 14.790 us ->  67,613 pps ->   742.7 Mbps
N=3: 10.394 us ->  96,209 pps -> 1,056.8 Mbps
N=4:  8.196 us -> 122,011 pps -> 1,340.2 Mbps
```

N >= 3 remains the threshold that clears 1,000 Mbps. N >= 4 remains the engineering target. `F` is a two-term fit, not a measurement, and Round 45 should not open until a profile attributes it to named call sites.

---

## 3. Final convergence votes

- **OI-1 (lock-batched ring buffer): AGREE.** Certified on the falsifiable claim only: uplink queue synchronization entries fall from 182,083.03/s to 533.45/s at 91,041.51 pps with 512 packet pushes and 256 packet pops, a 341.34x reduction, verifiable by mutex profile. No microsecond or Mbps figure enters the certified text without a measurement.

- **OI-2 (preserve the zero-allocation `packetPool` in Stage B): AGREE.** My Turn 1 DISAGREE attached to the original premise that copy elimination reaches wire speed. The Arbiter's restated item inverts that premise into "preserve, zero changes to `tun.BatchDevice` or `session/driver.go`," which is what my Turn 1 recommendation asked for. Sol Pro's ownership argument is the controlling reason: `ReadBatch(bufs [][]byte) ([]int, error)` carries no release callback, so lending a pooled slice either leaks it or recycles it while the outbound pump still reads it. The throughput arithmetic is the secondary reason: total elimination of all three copies is worth 0.467 us against a 17.2034 us gap, 2.7%.

- **OI-3 (no gateway modifications required for Stage B): AGREE.** My Turn 1 DISAGREE rested on the hypothesis that the gateway hashed source IP alone. The Arbiter's quotation of `forward_linux.go` lines 272 to 286 shows `h := int(a[3]) ^ (srcPort >> 2) ^ dstPort` already in shipped code, which falsifies my premise. I withdraw it. My second reason, that no ingest measurement above 48,709,632 B/s exists, survives as fact but does not contradict this item: Stage B projects 391 to 396 Mbps, which is 48.9 to 49.6 MB/s, inside the zero-drop envelope Run 16 established. Recorded as an exception under 13.7.9 rather than a blocking dissent, with the wording below.

- **OI-4 (downlink freeze invariant): AGREE.** No hunk in Section 4 references `toHost`, `take`, `tryTake`, `WritePacket`, `pumpOutboundBatch`, or `outboundPump`. Falsifiable by `grep -n 'toEngine' cmd/winn-datapath/` returning only the sites this diff touches. The Arbiter's clarification 4 already struck the unmeasured "wire speed (>1,000 Mbps)" parenthetical and bound the text to 673 Mbps measured in Run 16, which resolves the scope defect I flagged in Turn 1.

**Exception to record in the certificate under 13.7.9:** gateway ingress capacity above 48,709,632 B/s is unverified. The zero-drop result in Run 16 covers 35,476.8 pps, which is 38.968% of the 91,041.5 pps that 1,000 Mbps requires. OI-3 certifies only that Stage B needs no gateway change; it does not certify the gateway at wire speed. A load test recording `SO_RXQ_OVFL`, UDP receive errors, demux queue drops, per-queue TUN counters, TUN `EAGAIN`, and per-core softirq utilization at 91,042 pps or above remains a precondition for any Stage C certification.

**Correction of my own Turn 1, stated once:** the `close(d.toEngine)` anchor in my hunk 3.6 does not exist; `Close()` guards on `d.once.CompareAndSwap(false, true)` and closes `d.closed`. The `errFrameDeviceClosed` placeholder resolves to `errWinn3DeviceClosed`. Unconditional `Signal` is not multi-consumer safe, as argued above. The `sync.Pool` scratch in my Turn 1 `ReadBatch` is replaced by a device field, because the repository already carries `d.readLengths` as a device field with the identical single-caller assumption, and adding a pool would be inconsistent without removing any existing race.

---

## 4. Ratified surgical diffs

Design merged from all three seats: Sol Pro's pure data structure with two-segment bulk header copies and payload work outside the mutex, Gemini's `errWinn3DeviceClosed` sentinel and drain-before-EOF closing rule, my post-unlock signaling, remainder re-signal, and teardown drain.

### 4.1 New file: `winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go`

```go
package main

import "sync"

// winn3RingPushBatch and winn3RingPopBatch record the batch sizes the uplink
// path is expected to use. The ring imposes neither; they are the figures the
// 341x acquisition reduction is derived from.
const (
	winn3RingPushBatch = 512
	winn3RingPopBatch  = 256
)

// toEngineRing is the uplink queue that replaces toEngine chan []byte.
//
// A Go buffered channel is already a mutex guarded ring. The only reason this
// type exists is that it amortizes one lock acquisition across a whole batch
// instead of paying one per packet. At 91,041.5 pps the uplink queue drops from
// 182,083.0 acquisitions per second to 533.4 with 512 packet pushes and 256
// packet pops.
//
// The ring moves slice headers only. It never copies payload bytes and never
// calls back into the device while mu is held, so no 1,373 byte memmove and no
// packetPool operation ever runs inside the critical section.
//
// The downlink toHost channel is deliberately untouched. See treaty rounds 35
// and 38.
type toEngineRing struct {
	mu      sync.Mutex
	notify  sync.Cond
	storage [][]byte
	mask    int
	head    int
	count   int
	closed  bool
}

// newToEngineRing rounds capacity up to a power of two so the index advance is
// a mask rather than a divide. winn3FrameQueueDepth (65536) is already exact.
func newToEngineRing(capacity int) *toEngineRing {
	if capacity <= 0 {
		panic("winn3: toEngine ring capacity must be positive")
	}
	size := 1
	for size < capacity {
		size <<= 1
	}
	r := &toEngineRing{
		storage: make([][]byte, size),
		mask:    size - 1,
	}
	r.notify.L = &r.mu
	return r
}

// pushBatch enqueues as much of packets as fits, in order, under one lock
// acquisition. It returns the number accepted and whether the ring is open.
// The rejected suffix stays the caller's to recycle: dropping the tail keeps
// the head of an in-order stream intact.
func (r *toEngineRing) pushBatch(packets [][]byte) (int, bool) {
	if len(packets) == 0 {
		return 0, true
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, false
	}

	n := len(r.storage) - r.count
	if n > len(packets) {
		n = len(packets)
	}
	if n > 0 {
		tail := (r.head + r.count) & r.mask
		first := len(r.storage) - tail
		if first > n {
			first = n
		}
		copy(r.storage[tail:tail+first], packets[:first])
		if second := n - first; second > 0 {
			copy(r.storage[:second], packets[first:n])
		}
		r.count += n
	}
	r.mu.Unlock()

	// Signal after the unlock so the woken consumer does not land straight on a
	// held mutex. The predicate changed under the lock, so this cannot lose a
	// wakeup: a consumer parks only from inside Wait, which enqueues it on the
	// notify list before it releases mu, and a producer cannot have pushed
	// without holding mu.
	if n > 0 {
		r.notify.Signal()
	}
	return n, true
}

// pushOne enqueues a single packet. It reports whether the packet was accepted
// and whether the ring is open, so the caller can tell a tail drop from a
// closed device.
func (r *toEngineRing) pushOne(pkt []byte) (accepted, open bool) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false, false
	}
	if r.count == len(r.storage) {
		r.mu.Unlock()
		return false, true
	}
	r.storage[(r.head+r.count)&r.mask] = pkt
	r.count++
	r.mu.Unlock()

	r.notify.Signal()
	return true, true
}

// popBatch blocks until at least one packet is queued or the ring is closed,
// then moves up to len(dst) slice headers out under one lock acquisition. It
// reports false only when the ring is both closed and empty, so a closed ring
// still hands its backlog to the consumer before signalling EOF.
func (r *toEngineRing) popBatch(dst [][]byte) (int, bool) {
	if len(dst) == 0 {
		return 0, true
	}

	r.mu.Lock()
	for r.count == 0 && !r.closed {
		r.notify.Wait()
	}
	if r.count == 0 {
		r.mu.Unlock()
		return 0, false
	}

	n := r.count
	if n > len(dst) {
		n = len(dst)
	}
	first := len(r.storage) - r.head
	if first > n {
		first = n
	}
	copy(dst[:first], r.storage[r.head:r.head+first])
	for i := r.head; i < r.head+first; i++ {
		r.storage[i] = nil
	}
	if second := n - first; second > 0 {
		copy(dst[first:n], r.storage[:second])
		for i := 0; i < second; i++ {
			r.storage[i] = nil
		}
	}
	r.head = (r.head + n) & r.mask
	r.count -= n
	remainder := r.count
	r.mu.Unlock()

	// One consumer makes this a no-op, since Signal with no waiter costs a pair
	// of atomic loads. With several consumers it is what keeps a peer from
	// staying parked on a backlog a single Signal per push cannot cover.
	if remainder > 0 {
		r.notify.Signal()
	}
	return n, true
}

// popOne blocks until one packet is available or the ring is closed and empty.
func (r *toEngineRing) popOne() ([]byte, bool) {
	r.mu.Lock()
	for r.count == 0 && !r.closed {
		r.notify.Wait()
	}
	if r.count == 0 {
		r.mu.Unlock()
		return nil, false
	}
	pkt := r.storage[r.head]
	r.storage[r.head] = nil
	r.head = (r.head + 1) & r.mask
	r.count--
	remainder := r.count
	r.mu.Unlock()

	if remainder > 0 {
		r.notify.Signal()
	}
	return pkt, true
}

// close marks the ring closed and wakes every waiter. Queued packets stay in
// place so an in-flight consumer drains them before it sees EOF.
func (r *toEngineRing) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.mu.Unlock()

	r.notify.Broadcast()
}

// drain removes every packet still queued and returns them to the caller for
// recycling. Call it only after the consumer has stopped calling popBatch:
// recycling a packet the pump is still reading is a use after free against the
// packet pool.
func (r *toEngineRing) drain() [][]byte {
	r.mu.Lock()
	if r.count == 0 {
		r.mu.Unlock()
		return nil
	}
	out := make([][]byte, 0, r.count)
	for r.count > 0 {
		out = append(out, r.storage[r.head])
		r.storage[r.head] = nil
		r.head = (r.head + 1) & r.mask
		r.count--
	}
	r.mu.Unlock()
	return out
}

// depth reports the queued packet count for any telemetry that previously read
// len(d.toEngine).
func (r *toEngineRing) depth() int {
	r.mu.Lock()
	n := r.count
	r.mu.Unlock()
	return n
}
```

### 4.2 `winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go`

```diff
@@ type winn3FrameDevice struct @@
 	// toEngine is what the host offered and the tun layer has not yet read.
 	// toHost is what the tun layer delivered and the host has not yet taken.
-	toEngine chan []byte
+	toEngine *toEngineRing
 	toHost   chan []byte
+	// offerScratch and readPackets are reused across calls. They follow the
+	// single caller assumption the existing readLengths field already carries:
+	// one serve goroutine offers, one pumpOutboundBatch goroutine reads.
+	offerScratch [][]byte
+	readPackets  [][]byte
```

```diff
@@ func newWinn3FrameDevice(mtu int) (*winn3FrameDevice, error) @@
 		mtu:      mtu,
-		toEngine: make(chan []byte, winn3FrameQueueDepth),
+		toEngine: newToEngineRing(winn3FrameQueueDepth),
 		toHost:   make(chan []byte, winn3FrameQueueDepth),
+		offerScratch: make([][]byte, 0, winn3RingPushBatch),
+		readPackets:  make([][]byte, 0, winn3RingPopBatch),
```

```diff
@@ func (d *winn3FrameDevice) offer(packet []byte) error @@
 	copy(cp, packet)
 	// Tail drop on the uplink: never remove the head of an in-order stream.
-	d.push(d.toEngine, cp, &d.droppedToEngine, false)
+	accepted, open := d.toEngine.pushOne(cp)
+	if !open {
+		d.recycle(cp)
+		return errWinn3DeviceClosed
+	}
+	if !accepted {
+		d.droppedToEngine.Add(1)
+		d.recycle(cp)
+	}
 	return nil
 }
```

```diff
@@ func (d *winn3FrameDevice) offerBatch(packets [][]byte) error @@
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
+	valid := d.offerScratch[:0]
+	for _, pkt := range packets {
+		if len(pkt) > d.mtu {
+			d.oversize.Add(1)
+			d.recycle(pkt)
+			continue
+		}
+		valid = append(valid, pkt)
+	}
+
+	accepted, open := d.toEngine.pushBatch(valid)
+	if !open {
+		for _, pkt := range valid {
+			d.recycle(pkt)
+		}
+		d.releaseOfferScratch(valid)
+		return errWinn3DeviceClosed
+	}
+	// Tail drop on the uplink: never remove the head of an in-order stream.
+	if rejected := valid[accepted:]; len(rejected) > 0 {
+		d.droppedToEngine.Add(uint64(len(rejected)))
+		for _, pkt := range rejected {
+			d.recycle(pkt)
+		}
+	}
+	d.releaseOfferScratch(valid)
+	return nil
+}
+
+// releaseOfferScratch clears the retained packet pointers so a recycled buffer
+// is not kept reachable by the scratch slice until the next offerBatch.
+func (d *winn3FrameDevice) releaseOfferScratch(valid [][]byte) {
+	for i := range valid {
+		valid[i] = nil
+	}
+	d.offerScratch = valid[:0]
 }
```

```diff
@@ func (d *winn3FrameDevice) ReadPacket(buf []byte) (int, error) @@
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
+	pkt, ok := d.toEngine.popOne()
+	if !ok {
+		return 0, errWinn3DeviceClosed
+	}
 	defer d.recycle(pkt)
 	n := copy(buf, pkt)
 	if n < len(pkt) {
 		// A short buffer is the caller's bug, not a reason to lose a packet
 		// silently: a truncated IP packet is undetectable corruption at the
 		// next layer.
 		return n, fmt.Errorf(
 			"winn3: read buffer of %d bytes is shorter than the %d-byte packet",
 			len(buf), len(pkt))
 	}
 	return n, nil
 }
```

```diff
@@ func (d *winn3FrameDevice) Close() error @@
 func (d *winn3FrameDevice) Close() error {
 	if d.once.CompareAndSwap(false, true) {
 		close(d.closed)
+		d.toEngine.close()
 	}
 	return nil
 }
+
+// drainToEngine returns every packet the ring still holds to the packet pool.
+// Call it from the teardown path that joins the outbound pump goroutine, after
+// that goroutine has returned. Leaving it uncalled is correct but wasteful: the
+// queued buffers become garbage instead of returning to packetPool.
+func (d *winn3FrameDevice) drainToEngine() {
+	for _, pkt := range d.toEngine.drain() {
+		d.recycle(pkt)
+	}
+}
```

```diff
@@ func (d *winn3FrameDevice) ReadBatch(bufs [][]byte) ([]int, error) @@
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
-	}
-
-	d.readLengths = lengths
-	return lengths, nil
+	if cap(d.readPackets) < len(bufs) {
+		d.readPackets = make([][]byte, len(bufs))
+	}
+	packets := d.readPackets[:len(bufs)]
+
+	// The ring hands out slice headers only. Payload copies and pool recycling
+	// run here, after popBatch has released the ring mutex, so a 256 packet
+	// drain never holds the lock for 256 memmoves of 1,373 bytes.
+	n, ok := d.toEngine.popBatch(packets)
+	if !ok {
+		return nil, errWinn3DeviceClosed
+	}
+
+	lengths := d.readLengths[:0]
+	if cap(lengths) < len(bufs) {
+		lengths = make([]int, 0, len(bufs))
+	}
+	for i := 0; i < n; i++ {
+		pkt := packets[i]
+		packets[i] = nil
+		// Index by len(lengths), not by i: a skipped packet must not leave a
+		// hole that shifts every later length onto the wrong buffer.
+		idx := len(lengths)
+		if len(pkt) > len(bufs[idx]) {
+			d.oversize.Add(1)
+			d.recycle(pkt)
+			continue
+		}
+		lengths = append(lengths, copy(bufs[idx], pkt))
+		d.recycle(pkt)
+	}
+
+	d.readLengths = lengths
+	return lengths, nil
 }
```

### 4.3 Application notes

- **Import hygiene:** `errors` may become unused in `winn3_frame_device.go` once the `errors.New("read batch buffer too small for first packet")` site is gone. It stays if `errWinn3DeviceClosed` is declared in the same file, which the quoted line 79 indicates. Compile before assuming either way.
- **Builtin avoidance:** no `clear` and no `min` anywhere in these hunks, so the change carries no minimum Go version above what the file already needs.
- **Behavior change to record:** `offer()` now returns `errWinn3DeviceClosed` on a closed device where it previously returned `nil`. This matches `offerBatch` and prevents the silent packet loss the old scalar push allowed on a closed channel.
- **Behavior change to record:** `ReadBatch` no longer aborts the whole batch when the first packet exceeds `bufs[0]`. It counts oversize, recycles, and continues. Every packet entering the ring through `offerBatch` is already mtu filtered, so this path only triggers for packets that entered through `offer`, which does no mtu check.
- **Verification before merge:** `grep -n 'toEngine' cmd/winn-datapath/` must return only the sites above; `grep -n 'len(d.toEngine)\|cap(d.toEngine)' cmd/winn-datapath/` must return zero hits or be migrated to `d.toEngine.depth()`.

---

## 5. Closing report

- **Votes:** OI-1 AGREE, OI-2 AGREE, OI-3 AGREE, OI-4 AGREE. All four on the Arbiter's restated text as circulated in Turn 2 clarifications 1 through 4.
- **Position changes from Turn 1:** OI-2 and OI-3 flip from DISAGREE to AGREE. OI-2 because the restated item now says preserve rather than eliminate, which is what my Turn 1 recommendation asked for. OI-3 because the Arbiter's quotation of `forward_linux.go` lines 272 to 286 falsifies my source-IP-hash premise.
- **Certification limit I am voting for:** OI-1 certifies the acquisition-rate reduction (182,083.03/s to 533.45/s, 341.34x), not any throughput figure. Stage B projects 391 to 396 Mbps against a 389.68 Mbps baseline, which is inside Round 43's 6.1% to 8.8% calibration error. A Mbps acceptance test would be unfalsifiable at this effect size.
- **Exception for the certificate under 13.7.9:** gateway capacity above 48,709,632 B/s (38.968% of the 91,041.5 pps target) is unverified by any measurement in this docket.
- **Standing gate on Stage C:** `F = 26.3763 us` is a two-term fit, not a measurement. Round 45 should not open until a profile attributes the residual 16.9943 us to named call sites. My hypothesis remains three syscalls per packet across the VpnService and IPC boundary at 1.5 to 3 us each, plus 1.6x to 1.9x DVFS inflation under sustained load `(UNVERIFIED-LIVE)`.
- **Escalation carried forward from Turn 1, unanswered:** nothing in this docket shows the handset uplink radio can carry 1,000 Mbps. Downlink measured 673 Mbps in Run 16 and 663 in Run 15. Measure iperf3 uplink to the gateway with the datapath bypassed before any target above 1,000 Mbps is certified.
- **Checks run:** none. Tool use was prohibited for this seat. Every diff in Section 4 is unbuilt, has not passed `go vet`, and is untested. Treat all of it as unverified until compiled.
