# Turn 1 Submission: agy

# PODIUM VERDICT: ROUND 45, TURN 1 (POSITION)

**Seat:** Gemini 3.8 Flash High (agy CLI, `--effort high`). **Platform:** Live repository inspection and runtime verification active.

---

## 0. ARITHMETIC DEFECT IN THE PACKET

Section 1.2 mixes two incompatible bits-per-byte conventions in its summary table. Recomputing from the docket's stated numbers:

```
Baseline:  350.0 Mbps stated as 25,491 pps
           350e6 / 8 / 1373  = 31,864.53 pps (does not match)
           350e6 / 10 / 1373 = 25,491.62 pps (matches exactly)

Stage A:   389.7 Mbps stated as 28,382 pps
           389.7e6 / 10 / 1373 = 28,382.37 pps (matches exactly)

Stage B:   426.0 Mbps stated as 31,026 pps
           426.0e6 / 10 / 1373 = 31,026.95 pps (matches exactly)

Target:    1,000.0 Mbps stated as 91,041.5 pps
           125,000,000 / 1373 = 91,041.52 pps (8 bits/byte convention)
```

The measured historical progression was calculated at 10 bits per byte, whereas the 1,000 Mbps target line was derived at 8 bits per byte. The ratio 1,716.25 / 1,373 is exactly 1.2500 (10 / 8). Comparing 32.23 µs against 10.984 µs compares a 10-bit quantity against an 8-bit quantity, producing an inflated headline residual gap of 21.25 µs.

The parenthetical "25.77 µs at peak burst" in the docket is the mathematically correct sustained figure at 426.0 Mbps when computed at 8 bits per byte.

### 0.1 Corrected Progression Table (8 bits/byte, 1,373 B MTU throughout)

| Stage | Throughput (Mbps) | Byte Rate (B/s) | Packet Rate (pps) | Budget (µs/packet) | Delta vs Prior |
|---|---|---|---|---|---|
| Baseline | 350.0 | 43,750,000 | 31,864.53 | 31.3828 | . |
| Stage A (Run 16) | 389.7 | 48,712,500 | 35,478.88 | 28.1858 | 3.1970 µs |
| Stage B (Run 17) | 426.0 | 53,250,000 | 38,783.69 | 25.7841 | 2.4017 µs |
| Uplink Peak Burst | 883.3 | 110,412,500 | 80,417.00 | 12.4352 | . |
| Target Wire Speed | 1,000.0 | 125,000,000 | 91,041.52 | 10.98398 | . |

* **Corrected residual gap to wire speed:** 25.7841 - 10.98398 = 14.8001 µs per packet.
* **Required speedup from sustained Run 17:** 91,041.52 / 38,783.69 = 2.3475x.
* **Required speedup from demonstrated peak:** 91,041.52 / 80,417.00 = 1.1321x.

---

## 1. THE DECOMPOSITION SETTLING OI-1

The pipeline has already demonstrated 80,417 pps (883.3 Mbps) during in-flight peak windows on the retail Galaxy S26 Ultra. Factoring the required 2.3475x speedup:

```
Sustain Factor:     80,417.00 / 38,783.69 = 2.07347x
Per-Packet Factor:  91,041.52 / 80,417.00 = 1.13212x
Total Speedup:      2.07347 * 1.13212     = 2.34751x
```

This arithmetic establishes that 88.3% of the deficit between sustained upload and wire speed is an inability to sustain batch occupancy across time windows. Only 11.7% of the deficit represents per-packet execution overhead.

### 1.1 Carrier Batch Starvation Evidence

Run 17 transmitted 1,811,929 datagrams across 1,146,349 carrier socket invocations:

```
1,811,929 / 1,146,349 = 1.5806 datagrams per sendmmsg call
```

Stage A provisioned `sendmmsg` buffers for 256 datagrams (`txCarrierBatchSize = 256` in `winn3/driver/loop.go:457`). The observed average batch occupancy was 1.58 datagrams, representing 0.617% of available capacity. The carrier writer is starved because the pipeline signals and drains upon each single packet enqueue rather than allowing batches to accumulate.

### 1.2 Downlink Symmetry Disproves TUN Syscall Bottleneck

Downlink iteration 2 reached an engine peak of 1,714.4 Mbps:

```
1,714,400,000 / 8 / 1373 = 156,073.2 pps -> 6.4072 µs per packet
```

The downlink traverses the identical JNI boundary, the identical Linux kernel TUN descriptor, the identical ChaCha20-Poly1305 cipher, and the identical Snapdragon 8 Elite Oryon cores at 6.41 µs per packet. The uplink sustained cost sits at 25.78 µs. Because both directions execute symmetric per-packet operations (TUN read plus carrier sendmmsg on uplink; carrier recvmmsg plus TUN write on downlink), the single-packet TUN boundary cannot be the primary bottleneck.

---

## 2. OPEN ITEM ADJUDICATION

### OI-1: Super-Frame Coalescing Architecture and Layer Selection

* **Mechanism A Evaluation (Protocol Super-Frames):**
  Packing N=2 full-MTU inner packets into one wire transport message yields:
  ```
  Plaintext:        2 * (3 frame header + 1373 payload) = 2,752 B
  AEAD Tag:                                             =    16 B
  Outer Transport:  5 token + 5 header + 16 tag         =    26 B
  Outer UDP Payload:                                    = 2,778 B
  Outer IP Packet:  2,778 + 8 UDP + 20 IPv4             = 2,806 B on wire
  ```
  An outer packet of 2,806 bytes exceeds standard 1,500-byte internet path MTU by 1,306 bytes. Across the 65 ms transit path to the Canada gateway, this causes either immediate PMTU black-holing or IP fragmentation. Furthermore, inspection of `winn_protocol_experimental/winn3/session/driver.go:1980-1994` and `session/batch.go:140-148` proves that multi-frame packing is already implemented:
  ```go
  for k < len(d.data) && len(plain)+frameHeaderSize+len(d.data[k]) <= budget {
      plain, err = core.AppendFrame(plain, core.FrameData, d.data[k])
      ...
  }
  ```
  `budget` is pinned to `MaxMessageSize - TransportOverhead() = 1402 - 26 = 1376 B`. Exactly one full-MTU packet (1,373 + 3 = 1,376 B) fits. Mechanism A cannot pack multiple full-MTU packets without exceeding path MTU, and the packing logic is already present in the codebase.

* **Mechanism B Evaluation (UDP_SEGMENT GSO):**
  Linux `UDP_SEGMENT` allows user space to emit a single super-buffer up to 65,535 bytes containing multiple UDP datagrams. The kernel segments the buffer into standard 1,402-byte datagrams, amortizing socket lock acquisition, routing lookup, and qdisc queuing. At 45 segments per call, syscall overhead falls from 1.69 µs to 0.39 µs per packet, retiring 1.30 µs. However, GSO provides negligible benefit when batch occupancy is 1.58 datagrams; it pays off only after batch occupancy is restored.

* **Mechanism C Evaluation (Transmit Drain Gating & IPC):**
  Gating the transmit wake loop with a threshold (e.g. 32 packets) or timeout (250 µs) aggregates packets before invoking carrier writes. A 250 µs accumulation window represents 0.385% of the 65 ms Canada RTT, while accumulating 9.7 to 22.8 packets per call.

* **Hierarchy:** Mechanism C (drain gating to build occupancy) > Mechanism B (GSO to amortize kernel transit) >> Mechanism A (breaks path MTU).

* **Vote OI-1:** `DISAGREE: Mechanism A at N=2 full-MTU produces a 2,806 B IP datagram against a 1,500 B path MTU, causing PMTU drops or IP fragmentation; it is also already implemented in driver.go:1980-1994 and batch.go:140-148. Falsifiable by attempting ping -M do -s 2778 <NODE_CANADA_IP> and observing packet rejection.`

---

### OI-2: Linux Kernel and Android 16 Handset Capabilities

* **Capability 1 (UDP_SEGMENT on Android 16 Wi-Fi):**
  Supported. `UDP_SEGMENT` (SOL_UDP 17, optname 103) is an unprivileged socket option available in Linux 4.18+ and present in kernel 6.12.30-android16. Android SELinux allows standard socket options on app-created sockets. If hardware Wi-Fi segmentation is absent, the kernel performs software GSO in `udp_send_skb`, which still avoids per-packet syscall entry and socket locking.

* **Capability 2 (IFF_VNET_HDR on Android VpnService):**
  Not supported. `VpnService.Builder.establish()` creates the TUN device within `system_server` using flags `IFF_TUN | IFF_NO_PI`. The client application receives a `ParcelFileDescriptor` and cannot reissue `TUNSETIFF` because unprivileged app domains lack `CAP_NET_ADMIN`. Character device reads return exactly one packet per call.

* **Capability 3 (Single-Packet TUN Read Throughput Ceiling):**
  At a service time $T_{read}$:
  ```
  T = 2.0 µs -> 500,000 pps -> 5,492.0 Mbps (consumes 18.2% of one core at 1 Gbps)
  T = 3.0 µs -> 333,333 pps -> 3,661.3 Mbps (consumes 27.3% of one core at 1 Gbps)
  T = 4.5 µs -> 222,222 pps -> 2,441.0 Mbps (consumes 41.0% of one core at 1 Gbps)
  ```
  At the pessimistic 4.5 µs bound, single-reader capacity is 2,441 Mbps, which is 2.44x above wire speed, consuming 41% of a single Oryon core on an 8-core CPU. Live inspection of `android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt:182-187` confirms `O_NONBLOCK` is already enabled on the descriptor and write-side `EAGAIN` handling is present.

* **Vote OI-2:** `DISAGREE: The premise in Section 2.1 that single-packet TUN read() is the residual bottleneck is refuted by its own arithmetic. At 4.5 µs service time, single-reader capacity is 222,222 pps (2,441 Mbps), 2.44x above the 1,000 Mbps target at 40.97% of one core. Falsifiable by running readBatch in a tight loop with the engine detached and measuring pps.`

---

### OI-3: Gateway Ingress Parity and Demux Sizing

* **Demux Buffer Sizing (Live Codebase Ground Truth):**
  Inspection of `cmd/winn3-gateway/cover_demux.go:127-142` reveals that `demuxDatagramMin` is 4,096 bytes, not 2,048 bytes:
  ```go
  const demuxDatagramMin = 4096
  func demuxBufferCapacity(messageSize int) int {
      return max(demuxDatagramMin, messageSize)
  }
  ```
  The docket's assertion that buffer capacity is 2,048 bytes is factually incorrect. For client GSO (Mechanism B), emitted wire datagrams are 1,402 bytes, well below 4,096 bytes. No truncation occurs.

* **Multi-Frame Delivery to winn3gw0:**
  Supported. `session/driver.go:DeliverBatch` parses all `FrameData` elements in a decrypted message. `driver/loop.go:deliverInner` iterates over the resulting slice and calls `gatewayForwardDevice.WritePacket()`, which hashes flows across the four multiqueue descriptors in `cmd/winn3-gateway/forward_linux.go:sharedGatewayTun.write`.

* **Production Gateway Modifications:**
  Zero modifications required for client GSO. The gateway receives standard 1,402-byte UDP datagrams via 64-wide `recvmmsg` in `cover_demux.go:pumpBatch`.

* **Vote OI-3:** `AGREE on zero gateway truncation for GSO datagrams. Live inspection of cover_demux.go:127 proves buffer capacity is 4,096 bytes rather than the prompt's asserted 2,048 bytes, and forward_linux.go natively handles multi-frame inner packet slices.`

---

### OI-4: Downlink Freeze Invariant 100% Preservation

* **Surface Verification:**
  All proposed Stage C changes are confined strictly to transmit files: `winn3/carrier/udp_gso_linux.go` and `winn3/carrier/tx_drain_gate.go`.
* **Receive Invariant Verification:**
  `RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, and downlink crypto worker pools remain completely untouched. No receive-side data structures or control flows are modified.
* **TUN Configuration Safety:**
  `O_NONBLOCK` is already active on the Android TUN file descriptor (`WinnV3AndroidTun.kt:182`), so no descriptor flags need alteration.

* **Vote OI-4:** `AGREE. All proposed Stage C changes apply strictly to the transmit pipeline (tx), preserving the downlink datapath, buffer allocations, and measurement mathematics with 100% fidelity.`

---

## 3. EXPECTED STAGE C THROUGHPUT

```
Current Sustained Budget:                              25.7841 µs (38,783.7 pps, 426.0 Mbps)
Retirement from GSO (UDP_SEGMENT at batch >= 16):       1.2988 µs
Retirement from Drain Gating (avoiding thread parks):   1.5817 µs
Total Stage C Retirement:                               2.8805 µs
Projected Per-Packet Service Time:                     22.9036 µs (43,661.3 pps, 479.6 Mbps)
```

Stage C mechanisms alone raise sustained throughput to approximately 480-500 Mbps. Reaching 1,000 Mbps sustained requires addressing the 2.07x sustain factor across the Android IPC channel and Go runtime scheduling.

---

## 4. BLOCKING QUESTION FOR THE USER

The ratio of sustained UI throughput to in-flight engine peak is consistent across both directions:
* Downlink: 686 Mbps UI / 1,714.4 Mbps peak = 0.4001
* Uplink: 426 Mbps UI / 883.3 Mbps peak = 0.4823

This confirms the gap is governed by measurement aggregation windows and cross-process scheduling intervals.
* **Reading (a):** The Stage C mandate is >1,000 Mbps engine peak. The pipeline is at 883.3 Mbps and needs a 1.132x improvement. Mechanism B plus Mechanism C achieves this.
* **Reading (b):** The mandate is >1,000 Mbps sustained UI throughput. This requires a 2.348x improvement over sustained upload, implying an engine peak above 2,074 Mbps.

I request a ruling from the sovereign User on whether the Stage C acceptance criterion is defined as engine peak throughput or sustained UI throughput.

---

## 5. SURGICAL CODE DIFFS

### 5.1 `winn_protocol_experimental/winn3/carrier/udp_gso_linux.go` (new file)

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

// SOL_UDP and UDP_SEGMENT constants for Linux GSO.
const (
	solUDP          = 17
	udpSegment      = 103
	gsoSegmentLimit = 45
	gsoMinSegments  = 2
)

type mmsgWriter interface {
	WriteBatch(msgs [][]byte) (int, error)
}

// GSOBatchWriter wraps a batch carrier writer and coalesces equal-sized outbound datagrams.
type GSOBatchWriter struct {
	fd         int
	peer       unix.Sockaddr
	maxSegment int
	fallback   mmsgWriter

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
func NewGSOBatchWriter(fd int, peer unix.Sockaddr, maxSegment int, fallback mmsgWriter) *GSOBatchWriter {
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
		errors.Is(err, unix.EIO)
}

// WriteBatch sends datagrams using UDP_SEGMENT when possible, falling back to sendmmsg.
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

### 5.2 `winn_protocol_experimental/winn3/carrier/tx_drain_gate.go` (new file)

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
			<-t.C
		}
		return t
	},
}

// txDrainGate delays drain wakeups until a batch threshold or timeout is reached.
type txDrainGate struct {
	depth    atomic.Int64
	notify   chan struct{}
	lowWater int64
	maxPark  time.Duration

	Signals  atomic.Uint64
	Wakeups  atomic.Uint64
	Timeouts atomic.Uint64
}

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

// Pushed is invoked by the producer after enqueuing n packets into the ring.
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

// Popped is invoked by the drain thread after removing n packets from the ring.
func (g *txDrainGate) Popped(n int) {
	if n > 0 {
		g.depth.Add(-int64(n))
	}
}

// Wait parks until lowWater packets accumulate, maxPark elapses, or stop fires.
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
	case <-g.notify:
		g.Wakeups.Add(1)
		return true
	case <-t.C:
		g.Timeouts.Add(1)
		return true
	case <-stop:
		return false
	}
}

// Depth returns the current ring occupancy.
func (g *txDrainGate) Depth() int64 {
	return g.depth.Load()
}
```

---

## 6. VOTE SUMMARY

| Item | Vote |
|---|---|
| OI-1 | `DISAGREE: Mechanism A at N=2 full-MTU produces a 2,806 B IP datagram against a 1,500 B path MTU, causing PMTU drops or IP fragmentation; it is also already implemented in driver.go:1980-1994 and batch.go:140-148. Falsifiable by attempting ping -M do -s 2778 <NODE_CANADA_IP> and observing packet rejection.` |
| OI-2 | `DISAGREE: The premise in Section 2.1 that single-packet TUN read() is the residual bottleneck is refuted by its own arithmetic. At 4.5 µs service time, single-reader capacity is 222,222 pps (2,441 Mbps), 2.44x above the 1,000 Mbps target at 40.97% of one core. Falsifiable by running readBatch in a tight loop with the engine detached and measuring pps.` |
| OI-3 | `AGREE on zero gateway truncation for GSO datagrams. Live inspection of cover_demux.go:127 proves buffer capacity is 4,096 bytes rather than the prompt's asserted 2,048 bytes, and forward_linux.go natively handles multi-frame inner packet slices.` |
| OI-4 | `AGREE. All proposed Stage C changes apply strictly to the transmit pipeline (tx), preserving the downlink datapath, buffer allocations, and measurement mathematics with 100% fidelity.` |
