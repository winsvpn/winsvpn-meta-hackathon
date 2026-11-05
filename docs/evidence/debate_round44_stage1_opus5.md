# Turn 1 Submission: claude-opus5

## 0. Evidence status

Tool use is prohibited for this seat, so live verification is unavailable. Per Section 13.3 I mark external claims `UNVERIFIED-LIVE` inline; per the offline fallback rule every unverified assertion is tagged. All arithmetic below is derived from first principles against the figures in the packet and is independently checkable.

I could not read `winn3_frame_device.go`, `winn3_frame.go`, `winn3/session/driver.go`, or any gateway file. Diffs are exact only where they patch text the packet quoted verbatim. Hunks touching unquoted lines are labeled `INFERRED` with their anchors named.

---

## 1. First-principles arithmetic

### 1.1 Budget verification

Wire speed 1,000 Mbps = 1.0e9 bit/s / 8 = 125,000,000 B/s.

```
pps   = 125,000,000 / 1,373        = 91,041.51 pps
budget= 1e6 / 91,041.51            = 10.9840 us/packet
```

Run 16 measured: 389,677,056 B / 8.000 s = 48,709,632 B/s.

```
pps   = 48,709,632 / 1,373         = 35,476.79 pps
actual= 1e6 / 35,476.79            = 28.1874 us/packet
gap   = 28.1874 - 10.9840          = 17.2034 us/packet
```

The packet's 91,041 pps, 10.984 us, 35,476 pps, 28.18 us, and ~17.20 us all reproduce. The empirical block is internally consistent.

### 1.2 Two defects in the Section 1.1 narrative

**Defect A, syscall counts are line-rate figures presented as measurements.** 2,845 calls/sec x 32 datagrams = 91,040 pps, and 356 x 256 = 91,136 pps. Both are the 1,000 Mbps figure. At the rate actually measured (35,476.79 pps) the observed counts must have been 1,108.6/sec before Stage A and 138.6/sec after. The stated 2,845 and 356 were never on the wire in Run 16.

**Defect B, the 0.273 us implies a 10 us sendmmsg, not "fixed entry overhead".** Amortized syscall cost per packet is `C/32` before and `C/256` after, so savings = `C x (1/32 - 1/256)` = `C x 0.027344`. Solving `0.273 = C x 0.027344` gives `C = 9.984 us` for one 32-datagram `sendmmsg`. A ~10 us call is dominated by per-datagram work inside the kernel (~0.3 us x 32), not by entry cost. Entry cost on arm64 is roughly 0.3 to 0.8 us `(UNVERIFIED-LIVE)`. Restating it as entry overhead predicts that further batch expansion keeps paying, which it will not: the residual per-datagram term does not amortize.

**Calibration note.** Round 43's predicted Stage A ceiling of 424 Mbps overshot the 389.68 Mbps median by 8.8% and the best iteration (399.6) by 6.1%. Apply the same band to every projection below.

### 1.3 OI-1 saving, derived

The current design costs two `hchan.lock` acquire/release pairs per packet. The consumer parks at most once per `ReadBatch`, not once per packet, because the quoted code blocks only on the first element and then drains with `default:`. Park cost is therefore already amortized to 91,041/256 = 355.6 parks/sec, which at ~2 us each is 711 us/sec, 0.07% of one core. Parking is not the cost. Lock traffic is.

Per-packet channel cost, decomposed:

```
producer: CAS on remote-dirty lock line   ~60 ns   (cross-L2 transfer via SLC)
          hchan body (qcount, sendx,
          24B slice header move)          ~30 ns
          release store + invalidation    ~25 ns
                                          -------
                                          115 ns
consumer: same shape                       115 ns
                                          -------
total                                      230 ns/packet
```

Range 150 to 500 ns depending on whether the reader and pump land in the same Oryon cluster `(UNVERIFIED-LIVE: no perf counters in the packet)`.

After batching, per-packet residual is one ring-slot store plus a masked index increment on each side, ~20 ns total, plus the amortized lock:

```
push: 1 acquisition / 512 pkt  = 150 ns / 512 = 0.29 ns/pkt
pop:  1 acquisition / 256 pkt  = 150 ns / 256 = 0.59 ns/pkt
ring body                                     = 20.0 ns/pkt
                                                --------
                                                20.9 ns/pkt
```

**OI-1 saving = 230 - 20.9 = 209.1 ns = 0.2091 us/packet.**

Lock operations fall from 2.000 to 0.005859 per packet, a 341x reduction. The time saved is 0.2091 / 17.2034 = **1.216% of the gap**.

Resulting throughput, OI-1 alone:

```
28.1874 - 0.2091 = 27.9783 us -> 35,741.7 pps -> 49,073,354 B/s -> 392.59 Mbps
```

### 1.4 OI-2 saving, derived

Three copies of 1,373 B each = 4,119 B/packet. Go's arm64 `memmove` for a ~1.3 KB block into a cache-cold destination runs at roughly 10 GB/s effective once read-for-ownership traffic on the destination lines is counted (Go emits no non-temporal stores) `(UNVERIFIED-LIVE)`.

```
per copy: 1,373 / 10e9 = 137.3 ns
x3                     = 411.9 ns
sync.Pool Get+Put pair  = ~55 ns
                         --------
                          467 ns = 0.467 us/packet
```

The packet's framing of "375 MB/s of memory bus bandwidth" overstates the harm by a wide margin. LPDDR5X on this SoC sustains well above 60 GB/s, so 375 MB/s is under 0.7% of bus capacity `(UNVERIFIED-LIVE)`. The copies cost CPU cycles, not bandwidth. **0.467 / 17.2034 = 2.715% of the gap.**

### 1.5 Combined Stage B ceiling

```
saving   = 0.2091 + 0.4670          = 0.6761 us
new cost = 28.1874 - 0.6761         = 27.5113 us/packet
pps      = 1e6 / 27.5113            = 36,348.4 pps
B/s      = 36,348.4 x 1,373         = 49,906,354 B/s
Mbps     = x 8 / 1e6                = 399.25 Mbps
```

**Stage B as fully specified yields 399.25 Mbps, band 363 to 435 Mbps at the Round 43 calibration error.** That is 39.9% of the 1,000 Mbps target. The combined change retires 3.93% of the required 17.2034 us and leaves 27.5113 us against a 10.9840 us budget, a factor of 2.505 short.

### 1.6 Where the remaining 16.53 us must come from

Split the 28.1874 us into a per-packet fixed term `F` and a per-byte term `P`. The byte-proportional components are the three copies (0.412 us), AEAD at a thermally realistic 1.5 GB/s effective (1,373 / 1.5e9 = 0.915 us), and `copy_from_user` inside `sendmmsg` at ~5 GB/s (0.275 us):

```
P = 0.412 + 0.915 + 0.275 = 1.602 us
F = 28.1874 - 1.602       = 26.585 us
```

With a coalescing factor N, meaning N inner packets traverse the fixed path in one pass:

```
cost(N) = 26.585/N + 1.602

N=1: 28.187 us ->  35,477 pps ->   389.7 Mbps   (matches Run 16, model validated)
N=2: 14.895 us ->  67,137 pps ->   737.5 Mbps
N=3: 10.464 us ->  95,566 pps -> 1,049.7 Mbps
N=4:  8.248 us -> 121,242 pps -> 1,331.7 Mbps
N=8:  4.925 us -> 203,046 pps -> 2,230.3 Mbps
```

**N >= 3 is the minimum coalescing factor that clears 1,000 Mbps. N >= 4 is the engineering target.** This is the same structural move wireguard-go made to escape the same ceiling: enable TUN offload so the kernel hands up 64 KB super-frames, and use `UDP_SEGMENT` GSO on the carrier so one `sendmsg` emits N encrypted datagrams `(UNVERIFIED-LIVE: I cannot check whether Android's `VpnService.establish()` fd permits `TUNSETOFFLOAD` with `IFF_VNET_HDR` on kernel 6.12.30-android16, and that single fact decides whether Stage C is cheap or requires userspace coalescing)`.

`F = 26.585 us` is a model, not a measurement. The candidate contributors, in descending suspected magnitude: one `read(2)` per frame on the VpnService tun fd plus a second syscall pair crossing the host IPC duplex boundary (3 syscalls/packet at 1.5 to 3 us each = 4.5 to 9 us); scheduler wakeups across a process boundary; DVFS collapse of the 4.74 GHz prime core under an 8-second sustained radio-plus-crypto load, which inflates every CPU term by 1.6x to 1.9x `(UNVERIFIED-LIVE)`.

---

## 2. Open item adjudication

### OI-1: ring buffer replacing `toEngine chan []byte`

**Vote: `AGREE`**

The replacement is correct, strictly dominant over the channel, and cheap to land. A Go buffered channel already is a mutex-guarded ring; the entire win comes from amortizing the lock across a batch, which is what the proposal does. Sizing at 65,536 x 24 B = 1,572,864 B matches the existing `hchan` buffer exactly, so there is no added memory pressure or cache displacement.

**Q1.** 0.2091 us/packet saved, derivation in 1.3. Lock acquisitions fall 2.000 -> 0.005859 per packet.

**Q2.** Closing needs three distinct operations, and conflating them leaks buffers. `close()` sets the flag and `Broadcast()`s so every waiter exits. `popBatch` drains a non-empty closed ring and only reports EOF when both closed and empty, which preserves the backlog for the consumer. `drain()` recycles whatever the consumer never claimed and is called after the consumer has stopped. Tail-dropped and oversize packets are recycled inside the push loop, so no allocation escapes the pool on any path.

**Q3.** `Signal()` for the data path, `Broadcast()` exactly once on close. With one consumer they are equivalent in effect but `Broadcast` costs an extra list walk. With N consumers, `Signal` wakes exactly one, which is the correct behavior since a woken consumer finding the ring already drained by a peer simply re-waits; `Broadcast` would produce N-1 wasted wakeups per batch. I signal unconditionally rather than only on the empty-to-nonempty edge, because the edge optimization is correct only under a proven single consumer and the unconditional path costs one atomic load (~2 ns) at 356 calls/sec.

One correction to the proposal as written: signal after `mu.Unlock()`, not before. Signaling under the lock hands the woken goroutine straight into a blocked `Lock()`. The predicate change already happened under the lock, so post-unlock signaling is race-free with `sync.Cond`.

### OI-2: intermediate copy elimination

**Vote: `DISAGREE: OI-2 Q2's premise is arithmetically false. OI-1 combined with total elimination of all three copies yields 27.5113 us/packet (399.25 Mbps), while 1,000 Mbps requires 10.9840 us/packet; the combined saving of 0.6761 us retires 3.93% of the 17.2034 us gap.`**

The dissent is against the premise, not against the copies. Taking the sub-questions separately:

**Q1.** All three copies are removable, and `packetPool` recycling is not optimal. Copy 1 dies if `duplex.Reader` gains a `ReadInto(dst []byte) (int, error)` so the frame lands directly in a pool buffer. Copy 2 is forced by the `tun.BatchDevice` signature `ReadBatch(bufs [][]byte) ([]int, error)` and dies only if the interface changes to hand ownership out, for example `ReadBatchOwned() ([][]byte, func(), error)`. Copy 3 dies if `bufs[i]` is allocated with AEAD headroom and tail reserve so `session/driver.go` encrypts in place instead of calling `getDataBuf`.

**Q2.** No. The arithmetic is in 1.5. Removing all three copies takes 27.98 us to 27.51 us. Against a 10.98 us budget that is not close.

**Recommendation attached to this DISAGREE:** defer OI-2 implementation entirely. It costs a `tun.BatchDevice` interface break plus an ownership-lifetime audit across three files, it carries real buffer-aliasing risk on the freeze boundary, and it buys 0.467 us. Land it only after coalescing, where it becomes part of the `P` term that actually matters at high N.

### OI-3: gateway ingress audit

**Vote: `DISAGREE: IP source-hashing across 4 tun queues degenerates to a single active queue for this workload, because all 32 speedtest streams share one client source IP; 3 of 4 descriptors carry zero uplink packets, and the maximum ingest ever measured is 48,709,632 B/s, 39% of the 125,000,000 B/s the item claims is "already verified capable".`**

The per-component arithmetic is otherwise comfortable, and I want that on record so the dissent is not read as a general capacity objection:

```
splitUDP.pumpBatch,  demuxBatchSize=64:  91,041.51 / 64  = 1,422.5 recvmmsg/s
sharedGatewayTun,    batch=256:          91,041.51 / 256 =   355.6 writev/s
  spread over 4 queues (as designed)                     =    88.9 /s/queue
  actual under source-hash collapse                      =   355.6 /s on one queue
io.Discard ReadFrom, 8,192 B buffer:     125,000,000 / 8,192 = 15,258.8 read/s
  across 32 streams                                      =   476.8 /s/stream
```

`io.Discard` implements `io.ReaderFrom`, so `io.Copy` takes the pooled 8 KB path and performs no user-space payload copy `(UNVERIFIED-LIVE against the Go version pinned in the gateway's go.mod, which I cannot read)`. At 477 reads/sec/stream the ingest server is not the constraint at any rate under discussion.

The hash collapse is the finding. A single tun queue at 91,041 pps with 1,373 B frames must absorb 125 MB/s through one fd; single-queue tun write throughput is typically 1 to 3 Gbps `(UNVERIFIED-LIVE)`, so it may survive, but the multi-queue design is contributing nothing and there is no measurement above 48.7 MB/s to say which side of that line it lands on.

**Remedy:** hash the inner packet's full 4-tuple (src IP, src port, dst IP, dst port) rather than source IP alone. That distributes 32 distinct TCP streams across 4 queues at roughly 8 streams each. I cannot supply an exact diff because I have not read `forward_linux.go`; Section 4 of this report states exactly what I need to produce one.

### OI-4: downlink freeze invariant

**Vote: `AGREE`**

**Q1.** Yes, under the diff in Section 3. `push()` keeps its `chan []byte` parameter and stays the code path for `toHost`; only the two `toEngine` call sites move to the ring. `take()`, `tryTake()`, `WritePacket()`, and the `toHost` field are not referenced by any hunk. Verification condition: `grep -n 'toEngine' cmd/winn-datapath/` must return only the sites this diff touches, and `grep -n 'len(d.toEngine)\|cap(d.toEngine)' cmd/winn-datapath/` must return zero hits after the change or be migrated to `d.toEngine.depth()`.

**Q2.** Decoupled by direction. `toEngine` carries host-to-engine (uplink) frames exclusively; downlink runs gateway to carrier recv to session decrypt to `WritePacket()` to `toHost`. The two shared resources are `packetPool` and the device struct. Pool Get/Put counts per downlink packet are unchanged (the ring performs exactly the same one Get per enqueue and one Put per dequeue the channel did), and ring storage is byte-identical in size to the `hchan` buffer it replaces, so downlink cache footprint does not move. Reduced uplink CPU is a non-regression for downlink.

**Scope defect flagged, not voted against:** OI-4 Q2 asks to confirm "downlink wire speed (>1,000 Mbps)". Run 16 measured downlink at 673 Mbps and Run 15 at 663 Mbps. No downlink measurement above 1,000 Mbps exists anywhere in this packet. The freeze holds, which is what the item actually verifies; the parenthetical asserts a number not in evidence and should be struck from the treaty text before certification.

---

## 3. Diffs

Hunks marked `INFERRED` touch lines the packet did not quote. I name the anchor for each. One identifier, `errFrameDeviceClosed`, must be supplied from the file: it is the expression the existing `case pkt, ok := <-d.toEngine:` branch returns when `ok` is false, inside the region the packet elided as `// ...`. Substitute the file's actual identifier at that one site.

### 3.1 New file: `cmd/winn-datapath/winn3_frame_ring.go`

```go
package main

import (
	"sync"
	"sync/atomic"
)

// toEngineRing is a slice ring that replaces the toEngine channel on the uplink
// path. A Go buffered channel is already a mutex-guarded ring; the only reason
// this type exists is that it amortizes one hchan.lock acquisition across a
// whole batch instead of paying one per packet. At 91,041 pps that moves lock
// acquisitions from 182,082/sec to 534/sec (512-push, 256-pop).
//
// The downlink toHost channel is deliberately untouched. See treaty rounds 35
// and 38.
type toEngineRing struct {
	mu      sync.Mutex
	notify  sync.Cond
	storage [][]byte
	mask    int
	head    int
	tail    int
	count   int
	closed  bool

	recycle  func([]byte)
	oversize *atomic.Uint64
	dropped  *atomic.Uint64
}

// newToEngineRing rounds capacity up to a power of two so the index advance is
// a mask rather than a divide. winn3FrameQueueDepth (65536) is already exact.
func newToEngineRing(capacity int, recycle func([]byte), oversize, dropped *atomic.Uint64) *toEngineRing {
	size := 1
	for size < capacity {
		size <<= 1
	}
	r := &toEngineRing{
		storage:  make([][]byte, size),
		mask:     size - 1,
		recycle:  recycle,
		oversize: oversize,
		dropped:  dropped,
	}
	r.notify.L = &r.mu
	return r
}

// pushBatch enqueues an entire offerBatch under one lock acquisition. Packets
// longer than mtu are counted oversize and recycled. When the ring is full the
// remainder is tail dropped, counted, and recycled.
//
// Recycling runs under the lock on both reject paths. A full ring means the
// consumer is already behind, so the extra hold time costs nothing that is not
// lost regardless, and hoisting it out would need a per-call scratch slice.
func (r *toEngineRing) pushBatch(packets [][]byte, mtu int) {
	if len(packets) == 0 {
		return
	}

	r.mu.Lock()
	if r.closed {
		for _, pkt := range packets {
			r.recycle(pkt)
		}
		r.mu.Unlock()
		return
	}

	capacity := len(r.storage)
	for _, pkt := range packets {
		if len(pkt) > mtu {
			r.oversize.Add(1)
			r.recycle(pkt)
			continue
		}
		if r.count == capacity {
			r.dropped.Add(1)
			r.recycle(pkt)
			continue
		}
		r.storage[r.tail] = pkt
		r.tail = (r.tail + 1) & r.mask
		r.count++
	}
	queued := r.count
	r.mu.Unlock()

	// Signal after unlock so the woken consumer does not immediately block on
	// mu. The predicate change happened under the lock, so this is race free.
	//
	// Signal, not Broadcast: with one consumer they are equivalent and Signal
	// skips a list walk; with several, Signal wakes exactly one and a consumer
	// that finds the ring drained by a peer re-waits. Broadcast would burn
	// N-1 wakeups per batch.
	if queued > 0 {
		r.notify.Signal()
	}
}

// popBatch blocks until at least one packet is queued or the ring is closed,
// then drains up to len(dst) packets under one lock acquisition. It reports
// false only when the ring is both closed and empty, so a closed ring still
// hands its backlog to the consumer before signalling EOF.
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
	for i := 0; i < n; i++ {
		dst[i] = r.storage[r.head]
		r.storage[r.head] = nil
		r.head = (r.head + 1) & r.mask
	}
	r.count -= n
	r.mu.Unlock()

	return n, true
}

// close marks the ring closed and wakes every waiter. Queued packets stay in
// place so an in-flight consumer can drain them.
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

// drain returns every packet still held by the ring to the pool. Call it after
// close once the consumer has stopped calling popBatch.
func (r *toEngineRing) drain() {
	r.mu.Lock()
	for r.count > 0 {
		pkt := r.storage[r.head]
		r.storage[r.head] = nil
		r.head = (r.head + 1) & r.mask
		r.count--
		r.recycle(pkt)
	}
	r.mu.Unlock()
}

// depth reports the queued packet count for telemetry that previously read
// len(d.toEngine).
func (r *toEngineRing) depth() int {
	r.mu.Lock()
	n := r.count
	r.mu.Unlock()
	return n
}

// readBatchScratch supplies the [][]byte landing area popBatch drains into.
// One Get/Put pair per ReadBatch call is 356/sec at 1,000 Mbps. Using a pool
// rather than a device field keeps ReadBatch safe under any number of
// concurrent callers.
var readBatchScratch = sync.Pool{
	New: func() any {
		s := make([][]byte, 0, 256)
		return &s
	},
}
```

### 3.2 `cmd/winn-datapath/winn3_frame_device.go`, `offerBatch`

Exact, against the text quoted in packet Section 2.1. The leading `// ...` region is untouched.

```diff
 func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
     // ...
-    for _, pkt := range packets {
-        if len(pkt) > d.mtu {
-            d.oversize.Add(1)
-            d.recycle(pkt)
-            continue
-        }
-        d.push(d.toEngine, pkt, &d.droppedToEngine, false)
-    }
+    d.toEngine.pushBatch(packets, d.mtu)
     return nil
 }
```

### 3.3 `cmd/winn-datapath/winn3_frame_device.go`, `ReadBatch`

Exact for the quoted region. The `// ...` preamble before the first `select` is untouched.

```diff
 func (d *winn3FrameDevice) ReadBatch(bufs [][]byte) ([]int, error) {
     // ...
-    select {
-    case pkt, ok := <-d.toEngine:
-        first = pkt
-    // ...
-    }
-    n0 := copy(bufs[0], first)
-    d.recycle(first)
-    lengths = append(lengths, n0)
-
-    for len(lengths) < len(bufs) {
-        select {
-        case pkt, ok := <-d.toEngine:
-            // ...
-            ni := copy(bufs[idx], pkt)
-            d.recycle(pkt)
-            lengths = append(lengths, ni)
-        default:
-            // ...
-            return lengths, nil
-        }
-    }
+    if len(bufs) == 0 {
+        return nil, nil
+    }
+
+    scratchp := readBatchScratch.Get().(*[][]byte)
+    scratch := *scratchp
+    if cap(scratch) < len(bufs) {
+        scratch = make([][]byte, len(bufs))
+    }
+    scratch = scratch[:len(bufs)]
+
+    n, ok := d.toEngine.popBatch(scratch)
+    if !ok {
+        *scratchp = scratch[:0]
+        readBatchScratch.Put(scratchp)
+        return nil, errFrameDeviceClosed
+    }
+
+    lengths := make([]int, 0, n)
+    for i := 0; i < n; i++ {
+        pkt := scratch[i]
+        scratch[i] = nil
+        ni := copy(bufs[i], pkt)
+        d.recycle(pkt)
+        lengths = append(lengths, ni)
+    }
+
+    *scratchp = scratch[:0]
+    readBatchScratch.Put(scratchp)
+    return lengths, nil
 }
```

Two notes on this hunk. `errFrameDeviceClosed` is the one substitution required: replace it with the expression the current `!ok` branch returns. And any declarations of `first`, `lengths`, `idx`, or `n0` that live in the elided preamble become unused; delete exactly those declarations, since `lengths` is now declared inside this hunk.

### 3.4 `cmd/winn-datapath/winn3_frame_device.go`, struct field `INFERRED`

Anchor: the `toEngine` field declaration in the `winn3FrameDevice` struct.

```diff
-    toEngine chan []byte
+    toEngine *toEngineRing
```

### 3.5 `cmd/winn-datapath/winn3_frame_device.go`, constructor `INFERRED`

Anchor: the composite literal that currently contains `toEngine: make(chan []byte, winn3FrameQueueDepth)`. The ring needs `d.recycle` as a method value, so construction has to move after the literal.

```diff
     d := &winn3FrameDevice{
-        toEngine: make(chan []byte, winn3FrameQueueDepth),
         toHost:   make(chan []byte, winn3FrameQueueDepth),
         mtu:      mtu,
     }
+    d.toEngine = newToEngineRing(
+        winn3FrameQueueDepth,
+        d.recycle,
+        &d.oversize,
+        &d.droppedToEngine,
+    )
     return d
```

Keep every other field in the literal exactly as it stands; only the `toEngine` line is removed and only the `toHost` and `mtu` lines are shown for anchoring.

### 3.6 `cmd/winn-datapath/winn3_frame_device.go`, `Close` `INFERRED`

Anchor: wherever `close(d.toEngine)` appears. Do not touch any `close(d.toHost)` in the same function.

```diff
-    close(d.toEngine)
+    d.toEngine.close()
```

And after the outbound pump has stopped calling `ReadBatch`, at the teardown site that joins the pump goroutine:

```diff
+    d.toEngine.drain()
```

---

## 4. Closing report

**Votes**

| Item | Vote |
| --- | --- |
| OI-1 | `AGREE` |
| OI-2 | `DISAGREE: OI-1 plus total elimination of all three copies yields 27.5113 us/packet (399.25 Mbps); 1,000 Mbps requires 10.9840 us/packet.` |
| OI-3 | `DISAGREE: single-source-IP hashing collapses all 32 uplink streams onto 1 of 4 gateway tun queues, and no ingest measurement above 48,709,632 B/s exists.` |
| OI-4 | `AGREE` |

**Headline finding.** Stage B does not reach 1,000 Mbps and no arrangement of OI-1 and OI-2 can. It retires 0.6761 us of a 17.2034 us gap (3.93%) and lands at 399.25 Mbps, band 363 to 435. Stage A retired 1.59%. Two consecutive rounds of micro-optimization have moved 5.5% of the gap.

**Recommended Stage C mandate.** Segmentation coalescing at factor N >= 4, which under the `26.585/N + 1.602` model clears 1,000 Mbps at N = 3 and reaches 1,331.7 Mbps at N = 4. Copy elimination (OI-2) folds into the `P` term there and should be sequenced after, not before.

**Blocking gate before Stage C is specified.** `F = 26.585 us` is modeled from a two-term fit, not measured. Round 45 should not open until a 30-second `perf record -g` plus a Go execution trace attributes the 17.2034 us to named call sites. My leading hypothesis is 3 syscalls per packet (tun `read`, IPC write, IPC read) at 4.5 to 9 us combined, plus 1.6x to 1.9x DVFS inflation under sustained load. If that is right, Stage C's real target is the process boundary, and coalescing is the mechanism that makes the boundary crossings amortizable.

**Unresolved evidence, escalated to the User under 13.3.** Nothing in this packet establishes that the S26 Ultra's uplink radio can carry 1,000 Mbps. Downlink measured 673 Mbps in Run 16 and 663 in Run 15, both well under 1,000. If the link caps below 1 Gbps in either direction, the entire Stage B/C program optimizes toward an unreachable number. Measure iperf3 uplink to the gateway with the VPN datapath bypassed, and record the result, before certifying any >1,000 Mbps target.

**Packet defects for the Arbiter to correct before Turn 2 circulation.** Section 1.1 presents line-rate syscall counts (2,845 and 356) as Run 16 measurements; the observed values were 1,108.6 and 138.6/sec. Section 1.1 attributes 0.273 us/packet to "fixed syscall entry overhead" when the arithmetic implies a 9.984 us `sendmmsg` dominated by per-datagram work. OI-4 Q2 asserts a downlink wire speed above 1,000 Mbps that has never been measured.

**Items I could not complete.** No exact diff for OI-3's hash remedy: I have not read `forward_linux.go` and will not invent its contents. To produce one I need the `sharedGatewayTun` struct, its `write` method, and the queue selection function. No exact diff for OI-2: I have not read `winn3_frame.go`, `winn3/session/driver.go`, or the `tun.BatchDevice` definition, and OI-2 is deferred on arithmetic grounds regardless.

**Checks run.** None. Tool use was prohibited for this seat, so the diffs in Section 3 are unbuilt, unvetted by `go vet`, and untested. Treat every one of them as unverified until compiled.
