# Turn 2 Submission: agy

# Turn 2 Submission: agy

# PODIUM VERDICT: ROUND 45, TURN 2 (CROSS-EXAMINATION & CONVERGENCE)

**Seat:** Gemini 3.8 Flash High (agy CLI, `--effort high`). **Platform:** Live repository inspection and runtime verification active.

---

## 1. PEER STEELMAN & CROSS-EXAMINATION

### 1.1 Steelman of Podium 2 (Claude Opus 5)

* **Mathematical Factor Decomposition:**
  Opus 5 conducted a two-factor decomposition that resolves the core architectural ambiguity of Stage C. By factoring the required 2.3475x speedup against the retail Galaxy S26 Ultra's demonstrated engine peak of 80,417.0 pps (883.3 Mbps), Opus 5 separated the deficit into a burst sustain factor of 2.07347x (88.3% of the total gap) and a per-packet execution factor of 1.13212x (11.7% of the gap). This proves that the system has already executed within 1.45 µs of wire speed during in-flight windows, establishing that the remaining deficit is not caused by individual syscall or crypto primitives.

* **Carrier Batch Starvation Discovery:**
  Opus 5 correlated the sustain deficit with Run 17 telemetry, identifying that 1,811,929 datagrams were dispatched across 1,146,349 socket calls. This yielded an average of only 1.58 datagrams per sendmmsg invocation, which is 0.617% of the 256-wide carrier batch buffer. The carrier drain thread wakes prematurely on individual ring enqueues, finding the outbox starved.

* **Downlink Structural Symmetry:**
  Opus 5 observed that the downlink iteration reached an engine peak of 1,714.4 Mbps (156,073 pps, 6.41 µs per packet) across the identical JNI interface, Linux TUN descriptor, ChaCha20-Poly1305 cipher, and Snapdragon Oryon cores. Because uplink and downlink execute symmetric operations, no single primitive can explain a 4.02x performance disparity.

* **Single Strongest Point in Opus 5 View:**
  The mathematical factor decomposition proving that 88.3% of the gap is carrier batch starvation, directly evidenced by 1.58 datagrams per socket call.

* **Impact on Own Position:**
  This analysis reinforces Gemini's Turn 1 findings and clarifies execution priority. Transmit drain gating (txDrainGate) is the foundational requirement; without accumulating batches of 16 to 32 datagrams, UDP_SEGMENT GSO operates on empty queues and cannot deliver its theoretical syscall amortization.

---

### 1.2 Steelman of Podium 3 (GPT-5.6 Sol Pro)

* **Kernel GSO Sizing Invariants:**
  Sol Pro enforced the Linux kernel GSO contract defined in skb_segment. Linux UDP_SEGMENT mandates that every datagram in a super-buffer must possess the exact same length (segSize), permitting only a single trailing datagram of shorter length. Grouping packets of disparate sizes into a single GSO buffer corrupts packet boundaries on the wire.

* **Mandatory Connected-Socket Probing:**
  Sol Pro noted that kernel 6.12 presence on Android 16 does not guarantee that Samsung's Wi-Fi network interface or routing path accepts UDP_SEGMENT without dropping packets or returning error codes. A safe runtime probe on the connected carrier socket with automatic, zero-drop fallback to sendmmsg is mandatory.

* **Gateway Memory Slab Protection:**
  Sol Pro evaluated the gateway memory cost of Mechanism A. Expanding demuxReadBufferSize from 4,096 to 65,507 bytes across a 256-entry batch slab consumes 16 MiB per slab and creates unauthenticated memory exposure. Mechanism B keeps wire datagrams bounded to 1,402 bytes, eliminating gateway allocation expansion.

* **Single Strongest Point in Sol Pro View:**
  The enforcement of strict segment size homogeneity for GSO runs paired with a mandatory active-socket runtime probe and zero-loss fallback to sendmmsg.

* **Impact on Own Position:**
  This deepens the implementation details of GSOBatchWriter. The writer must partition queued datagrams into equal-length runs with at most one trailing shorter datagram, and handle runtime socket rejections by immediately routing all pending datagrams through sendmmsg without packet loss.

---

## 2. ARITHMETIC CONVERGENCE & ANALYSIS

The arithmetic audit from Turn 1 is ratified by all three podiums. The corrected baseline progression table calculated strictly at 8 bits per byte (1,373 B inner packet) governs Stage C:

| Stage | Throughput (Mbps) | Byte Rate (B/s) | Packet Rate (pps) | Budget (µs/packet) | Delta vs Prior |
|---|---|---|---|---|---|
| Baseline | 350.0 | 43,750,000 | 31,864.53 | 31.3828 | . |
| Stage A (Run 16) | 389.7 | 48,712,500 | 35,478.88 | 28.1858 | 3.1970 µs |
| Stage B (Run 17) | 426.0 | 53,250,000 | 38,783.69 | 25.7841 | 2.4017 µs |
| Uplink Peak Burst | 883.3 | 110,412,500 | 80,417.00 | 12.4352 | . |
| Target Wire Speed | 1,000.0 | 125,000,000 | 91,041.52 | 10.98398 | . |

* **Corrected Residual Gap:** 25.7841 µs minus 10.9840 µs = 14.8001 µs per packet.
* **Required Sustained Speedup:** 91,041.52 / 38,783.69 = 2.3475x.
* **Required Burst Speedup:** 91,041.52 / 80,417.00 = 1.1321x.
* **Carrier Batch Occupancy:** 1,811,929 / 1,146,349 = 1.5806 datagrams per sendmmsg call.
* **Accumulation Window Impact:** A 250 µs window represents 0.385% of the 65 ms transit RTT, while accumulating 9.70 to 22.76 datagrams per drain cycle.

---

## 3. ENUMERATED OPEN ITEM CONVERGENCE VOTES

### 3.1 Vote on OI-1: Transmit Coalescing Architecture & Layer Selection
* **Text:** Reject Mechanism A (packing multiple full-MTU frames into an outer UDP datagram exceeding path MTU 1,500 B). Adopt Mechanism B (kernel UDP segmentation offload via UDP_SEGMENT / GSO) paired with transmit drain gating (txDrainGate) to prevent carrier batch starvation and coalesce packets into optimal socket batches. Preserve the existing small-frame packing loop in driver.go:1980-1994 without wire-format changes.
* **Vote:** `AGREE`
* **Justification:** All three podiums unanimously demonstrated that Mechanism A produces 2,806-byte datagrams that trigger PMTU blackholing or IP fragmentation across internet transit. Pairing txDrainGate (lowWater=32, maxPark=250 µs) with UDP_SEGMENT resolves carrier batch starvation and amortizes socket overhead while preserving wire compatibility.

### 3.2 Vote on OI-2: Linux Kernel 6.12 Capability and Handset Safety
* **Text:** Single-packet TUN read() is not the binding ceiling (theoretical single-reader ceiling is 222,222 pps / 2.44 Gbps at 4.5 µs, corroborated by 1,714 Mbps downlink peak). UDP_SEGMENT (SOL_UDP=17, UDP_SEGMENT=103) is supported on Linux 6.12.30 (Android 16), but must be safely probed at socket initialization with automatic, zero-overhead runtime fallback to the existing 256-wide sendmmsg batch writer on any kernel rejection or unsupported network interface.
* **Vote:** `AGREE`
* **Justification:** Arithmetic confirms a 4.5 µs TUN read processes 222,222 pps (2.44 Gbps), consuming 41% of one core. Probing UDP_SEGMENT via setsockopt and handling socket errors with zero-drop fallback to sendmmsg protects against vendor driver discrepancies.

### 3.3 Vote on OI-3: Gateway Demux Sizing and Zero-Truncation Invariant
* **Text:** Under Mechanism B (UDP_SEGMENT), gateway demux sizing remains frozen and requires zero modifications, as every emitted datagram remains at or below 1,402 bytes, causing zero datagram truncation and zero memory slab expansion.
* **Vote:** `AGREE`
* **Justification:** Kernel GSO segments packets before wire egress. The gateway receives standard UDP datagrams within MaxMessageSize (1,402 B), well below the 4,096-byte demuxDatagramMin allocation in cover_demux.go:127, avoiding truncation and memory bloat.

### 3.4 Vote on OI-4: Downlink Freeze Invariant 100% Preservation
* **Text:** All Stage C modifications are strictly transmit-side (uplink pipeline, toEngineRing / txDrainGate, carrier GSO / sendmmsg batching). The downlink datapath (RecvBatch, outboundPump, toHost, fromEngine, downlink crypto worker pools, downlink buffer allocations, and measurement mathematics) remains 100% frozen in strict compliance with Treaty Rounds 35, 38, 43, and 44.
* **Vote:** `AGREE`
* **Justification:** Stage C changes reside entirely within the transmit datapath. The receive pipeline remains untouched in full compliance with all governing treaty rounds.

---

## 4. RATIFIED CODE IMPLEMENTATION

### 4.1 `winn_protocol_experimental/winn3/carrier/udp_gso_linux.go`

```go
//go:build linux || android

package carrier

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SOL_UDP and UDP_SEGMENT constants for Linux kernel GSO.
const (
	solUDP          = 17
	udpSegment      = 103
	gsoSegmentLimit = 45
	gsoMinSegments  = 2
)

// mmsgBatchWriter is the fallback batch interface implemented by RawBatchConn.
type mmsgBatchWriter interface {
	WriteBatch(msgs [][]byte) (int, error)
}

// GSOBatchWriter coalesces equal-sized outbound datagrams into GSO super-buffers.
type GSOBatchWriter struct {
	fd         int
	peer       unix.Sockaddr
	maxSegment int
	fallback   mmsgBatchWriter

	enabled atomic.Bool

	bufMu sync.Mutex
	super []byte
	ctrl  []byte

	TxGSOCalls    atomic.Uint64
	TxGSOSegments atomic.Uint64
	TxMMSGCalls   atomic.Uint64
	TxGSODisabled atomic.Bool
}

// NewGSOBatchWriter initializes a GSO writer wrapping the existing batch writer.
func NewGSOBatchWriter(fd int, peer unix.Sockaddr, maxSegment int, fallback mmsgBatchWriter) *GSOBatchWriter {
	w := &GSOBatchWriter{
		fd:         fd,
		peer:       peer,
		maxSegment: maxSegment,
		fallback:   fallback,
		super:      make([]byte, 0, gsoSegmentLimit*maxSegment),
		ctrl:       make([]byte, unix.CmsgSpace(2)),
	}
	w.enabled.Store(probeUDPSegment(fd))
	if !w.enabled.Load() {
		w.TxGSODisabled.Store(true)
	}
	return w
}

func probeUDPSegment(fd int) bool {
	if err := unix.SetsockoptInt(fd, solUDP, udpSegment, 0); err != nil {
		return false
	}
	return true
}

func gsoControl(dst []byte, segSize uint16) []byte {
	need := unix.CmsgSpace(2)
	if cap(dst) < need {
		dst = make([]byte, need)
	}
	dst = dst[:need]
	for i := range dst {
		dst[i] = 0
	}
	h := (*unix.Cmsghdr)(unsafe.Pointer(&dst[0]))
	h.Level = solUDP
	h.Type = udpSegment
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(dst[unix.CmsgLen(0):], segSize)
	return dst
}

func isGSOUnsupported(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EIO)
}

// WriteBatch dispatches datagrams using UDP_SEGMENT, falling back cleanly to sendmmsg.
func (w *GSOBatchWriter) WriteBatch(msgs [][]byte) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	if !w.enabled.Load() {
		w.TxMMSGCalls.Add(1)
		return w.fallback.WriteBatch(msgs)
	}

	sent := 0
	for sent < len(msgs) {
		segSize := len(msgs[sent])
		if segSize == 0 || segSize > w.maxSegment {
			w.TxMMSGCalls.Add(1)
			n, err := w.fallback.WriteBatch(msgs[sent : sent+1])
			sent += n
			if err != nil {
				return sent, err
			}
			continue
		}

		// Enforce kernel GSO invariant: all segments in run must match segSize,
		// with at most one trailing segment allowed to be shorter.
		run := 1
		for sent+run < len(msgs) && run < gsoSegmentLimit {
			ln := len(msgs[sent+run])
			if ln > segSize {
				break
			}
			run++
			if ln < segSize {
				break
			}
		}

		if run < gsoMinSegments {
			w.TxMMSGCalls.Add(1)
			n, err := w.fallback.WriteBatch(msgs[sent : sent+1])
			sent += n
			if err != nil {
				return sent, err
			}
			continue
		}

		n, err := w.flushGSO(msgs[sent:sent+run], segSize)
		if err != nil {
			if isGSOUnsupported(err) {
				w.enabled.Store(false)
				w.TxGSODisabled.Store(true)
				w.TxMMSGCalls.Add(1)
				m, ferr := w.fallback.WriteBatch(msgs[sent:])
				return sent + m, ferr
			}
			return sent, err
		}
		w.TxGSOCalls.Add(1)
		w.TxGSOSegments.Add(uint64(n))
		sent += n
	}
	return sent, nil
}

func (w *GSOBatchWriter) flushGSO(run [][]byte, segSize int) (int, error) {
	w.bufMu.Lock()
	defer w.bufMu.Unlock()

	w.super = w.super[:0]
	for _, m := range run {
		w.super = append(w.super, m...)
	}
	w.ctrl = gsoControl(w.ctrl, uint16(segSize))

	n, err := unix.SendmsgN(w.fd, w.super, w.ctrl, w.peer, 0)
	if err != nil {
		return 0, err
	}
	if n != len(w.super) {
		return 0, errors.New("carrier: short UDP_SEGMENT write")
	}
	return len(run), nil
}
```

---

### 4.2 `winn_protocol_experimental/winn3/carrier/tx_drain_gate.go`

```go
package carrier

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultDrainLowWater = 32
	defaultDrainMaxPark  = 250 * time.Microsecond
)

var drainTimerPool = sync.Pool{
	New: func() any {
		t := time.NewTimer(time.Hour)
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		return t
	},
}

// txDrainGate coordinates batched wakeups between ring producers and the carrier drain thread.
type txDrainGate struct {
	depth    atomic.Int64
	notify   chan struct{}
	lowWater int64
	maxPark  time.Duration

	Signals  atomic.Uint64
	Wakeups  atomic.Uint64
	Timeouts atomic.Uint64
}

// newTxDrainGate initializes a drain gate with specified watermark and parking bound.
func newTxDrainGate(lowWater int, maxPark time.Duration) *txDrainGate {
	if lowWater < 1 {
		lowWater = defaultDrainLowWater
	}
	if maxPark <= 0 {
		maxPark = defaultDrainMaxPark
	}
	return &txDrainGate{
		notify:   make(chan struct{}, 1),
		lowWater: int64(lowWater),
		maxPark:  maxPark,
	}
}

// Pushed records newly enqueued packets and notifies the consumer once lowWater is reached.
func (g *txDrainGate) Pushed(n int) {
	if n <= 0 {
		return
	}
	if g.depth.Add(int64(n)) < g.lowWater {
		return
	}
	select {
	case g.notify <- struct{}{}:
		g.Signals.Add(1)
	default:
	}
}

// Popped records drained packets to maintain current ring depth accounting.
func (g *txDrainGate) Popped(n int) {
	if n > 0 {
		g.depth.Add(-int64(n))
	}
}

// Wait blocks until lowWater packets accumulate, maxPark expires, or stop is received.
func (g *txDrainGate) Wait(stop <-chan struct{}) bool {
	if g.depth.Load() >= g.lowWater {
		return true
	}

	t := drainTimerPool.Get().(*time.Timer)
	t.Reset(g.maxPark)
	defer func() {
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		drainTimerPool.Put(t)
	}()

	select {
	case <-stop:
		return false
	case <-g.notify:
		g.Wakeups.Add(1)
		return true
	case <-t.C:
		g.Timeouts.Add(1)
		return true
	}
}
```

---

### 4.3 `winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go` (Integration Diff)

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go
@@ -3,6 +3,7 @@ package main
 
 import (
 	"sync"
+	"time"
 )
 
 const (
@@ -10,6 +11,10 @@ const (
 	winn3RingPopBatch  = 256
+	winn3DrainLowWater = 32
+	winn3DrainMaxPark  = 250 * time.Microsecond
 )
 
 // toEngineRing is a lock-batched circular ring buffer for the uplink queue.
@@ -23,6 +28,8 @@ type toEngineRing struct {
 	head    int
 	count   int
 	closed  bool
+	lowWater int
 }
 
 func newToEngineRing(capacity int) *toEngineRing {
@@ -33,6 +40,7 @@ func newToEngineRing(capacity int) *toEngineRing {
 		storage: make([][]byte, capacity),
 		mask:    capacity-1,
+		lowWater: winn3DrainLowWater,
 	}
 	r.notify = sync.NewCond(&r.mu)
 	return r
@@ -67,8 +75,10 @@ func (r *toEngineRing) pushBatch(packets [][]byte) (int, bool) {
 		r.count += n
 	}
+	shouldSignal := r.count >= r.lowWater || r.closed
 	r.mu.Unlock()
 
-	// Signal after unlock so the woken consumer does not wake directly into a held lock.
-	if n > 0 {
+	// Signal only once lowWater threshold is reached, avoiding single-packet wake thrashing.
+	if shouldSignal {
 		r.notify.Signal()
 	}
 	return n, true
@@ -91,6 +101,8 @@ func (r *toEngineRing) pushOne(pkt []byte) (accepted, open bool) {
 	r.storage[(r.head+r.count)&r.mask] = pkt
 	r.count++
+	shouldSignal := r.count >= r.lowWater
 	r.mu.Unlock()
 
-	r.notify.Signal()
+	if shouldSignal {
+		r.notify.Signal()
+	}
 	return true, true
 }
```
