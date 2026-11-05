# Turn 2 Submission: solpro

# Round 45 Turn 2: Cross-Examination and Convergence

## 1. Peer steelman

### Podium 1, Gemini

The strongest point is its live repository inspection. It resolved two factual uncertainties that could not be settled from the docket excerpts:

1. The actual plaintext packing budget is 1,376 bytes, not 1,373 bytes. One full inner packet therefore fits exactly:

```text
1,373 inner bytes + 3 frame-header bytes = 1,376 bytes
```

2. `demuxDatagramMin` is 4,096 bytes in the inspected gateway source, not 2,048 bytes.

The first finding resolves the dimensional contradiction in my Turn 1 analysis. The existing packing loop can carry one full 1,373-byte packet, while retaining useful packing for smaller packets. It cannot carry two full packets without increasing the outer datagram beyond path MTU.

This changes my position on that narrow factual question. It does not change my rejection of Mechanism A or selection of GSO plus drain gating.

### Podium 2, Opus

The strongest point is the carrier starvation evidence:

```text
1,811,929 datagrams / 1,146,349 socket calls
= 1.580612 datagrams per socket call
```

That is only:

```text
1.580612 / 256 = 0.006174
```

or 0.6174 percent occupancy of the configured batch width.

This directly identifies an actionable defect. Expanding `sendmmsg` or adding GSO without first allowing packets to accumulate cannot recover the intended syscall amortization.

I also agree that the Stage C acceptance metric must distinguish engine peak from full-test sustained throughput. The projected 470 to 500 Mbps numbers remain cost-model estimates because their syscall and futex costs were assumed rather than measured.

One correction is required. The claim that 88.3 percent of the deficit is a sustain problem does not follow from the stated factors. Using packet-rate increments:

```text
Current sustained: 38,783.685 pps
Observed peak:     80,416.970 pps
Target:            91,041.515 pps

Total gap:
91,041.515 - 38,783.685 = 52,257.830 pps

Recovered by sustaining the observed peak:
80,416.970 - 38,783.685 = 41,633.285 pps

Sustain share:
41,633.285 / 52,257.830 = 79.67 percent

Remaining peak-rate share:
10,624.545 / 52,257.830 = 20.33 percent
```

The 88.3 percent figure is instead:

```text
80,416.970 / 91,041.515 = 88.33 percent
```

That is the observed peak as a fraction of the target, not the fraction of the deficit attributable to sustaining performance.

This correction does not alter the selected architecture.

## 2. First-principles convergence arithmetic

For 1,373-byte inner packets:

```text
Bits per packet:
1,373 * 8 = 10,984 bits

Target packet rate:
1,000,000,000 / 10,984 = 91,041.515 pps

Target packet budget:
1,000,000 / 91,041.515 = 10.983999 microseconds
```

Run 17 sustained:

```text
426,000,000 / 10,984 = 38,783.685 pps
1,000,000 / 38,783.685 = 25.784038 microseconds
```

Observed engine peak:

```text
883,300,000 / 10,984 = 80,416.970 pps
1,000,000 / 80,416.970 = 12.435184 microseconds
```

Residuals:

```text
Sustained residual:
25.784038 - 10.983999 = 14.800039 microseconds

Peak residual:
12.435184 - 10.983999 = 1.451185 microseconds
```

Drain-gate accumulation at a 250 microsecond timeout:

```text
At current sustained rate:
38,783.685 * 0.000250 = 9.696 packets

At observed peak:
80,416.970 * 0.000250 = 20.104 packets

At target:
91,041.515 * 0.000250 = 22.760 packets
```

Therefore, with smooth arrivals, a `lowWater` of 32 will normally be bounded by the 250 microsecond timeout. Expected batches are approximately 10 packets at current sustained throughput and approximately 23 at target throughput. Bursty arrivals can still reach 32.

The latency bound relative to a 65 millisecond RTT is:

```text
0.250 ms / 65 ms = 0.003846 = 0.3846 percent
```

GSO super-buffer sizing at 45 full outer messages:

```text
45 * 1,402 = 63,090 bytes
```

Each segment remains an independently encrypted 1,402-byte Winn datagram. The receiver never observes the 63,090-byte userspace super-buffer.

For rejected Mechanism A, using the inspected 10-byte pre-ciphertext transport overhead:

```text
Two plaintext frames:
2 * (1,373 + 3) = 2,752 bytes

Outer UDP payload:
2,752 + 16-byte AEAD tag + 10-byte transport header
= 2,778 bytes

IPv4 datagram:
2,778 + 8-byte UDP + 20-byte IPv4
= 2,806 bytes
```

That exceeds a 1,500-byte path MTU by 1,306 bytes.

## 3. Convergence votes

### OI-1

`AGREE: Two full frames produce a 2,806-byte IPv4 datagram, while UDP_SEGMENT with a 1,402-byte segment size emits independently authenticated datagrams no larger than 1,402 bytes. This is falsifiable with gateway packet capture and IP length inspection.`

### OI-2

`AGREE: At 4.5 microseconds per TUN read, one reader can process 222,222 packets per second, which equals 2.441 Gbps for 1,373-byte packets and exceeds the 91,042 pps target. UDP_SEGMENT support is falsifiable by applying option 103 to the production socket and submitting the first eligible equal-length batch, with permanent sendmmsg fallback on rejection.`

The initialization probe establishes socket-option support. The first real segmented send is the authoritative routed-path test because no harmless initialization-only call can prove that the eventual Wi-Fi route accepts GSO.

### OI-3

`AGREE: UDP_SEGMENT performs sender-side segmentation before wire transmission, so recvmmsg at the gateway receives separate datagrams no larger than 1,402 bytes. A gateway capture showing any Stage C UDP datagram above 1,402 bytes would falsify this invariant.`

The result holds with either the circulated 2,048-byte assumption or the live-inspected 4,096-byte minimum.

### OI-4

`AGREE: The ratified implementation modifies only transmit batch formation, transmit waiting, and UDP send operations, and contains no reference to RecvBatch, outboundPump, toHost, fromEngine, receive crypto workers, or downlink allocation structures. A source diff touching any listed receive symbol would falsify compliance.`

## 4. Ratified implementation

The following files are source-complete. They intentionally expose small interfaces because the circulated record does not contain the concrete type of the existing `sendmmsg` writer or the exact ring method signatures.

The GSO writer has these properties:

1. It groups only equal-length, already encrypted Winn datagrams.
2. It never treats one ciphertext as several protocol messages.
3. It preserves ordering.
4. It returns the original fallback directly if the initialization probe fails.
5. It permanently delegates to the fallback after a routed-path capability rejection.
6. It does not fall back on transient errors such as `EAGAIN`.
7. It performs no GSO assembly after permanent disablement.

The gate differs deliberately from the peer implementation in one important respect. It does not wake every 250 microseconds while idle. The timer starts only after the first queued packet.

### `winn_protocol_experimental/winn3/carrier/udp_gso_linux.go`

```diff
diff --git a/winn_protocol_experimental/winn3/carrier/udp_gso_linux.go b/winn_protocol_experimental/winn3/carrier/udp_gso_linux.go
new file mode 100644
index 0000000..8e7b1c4
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/udp_gso_linux.go
@@ -0,0 +1,269 @@
+//go:build linux || android
+
+package carrier
+
+import (
+	"errors"
+	"fmt"
+	"io"
+	"sync"
+	"sync/atomic"
+	"unsafe"
+
+	"golang.org/x/sys/unix"
+)
+
+const (
+	stageCSOLUDP          = 17
+	stageCUDPSegment      = 103
+	stageCGSOMaxSegments  = 45
+	stageCMaxSuperPayload = 65535
+)
+
+// DatagramBatchWriter is implemented by the existing sendmmsg writer.
+// The return value is the number of datagrams accepted by the kernel.
+type DatagramBatchWriter interface {
+	WriteBatch(datagrams [][]byte) (int, error)
+}
+
+// UDPSegmentStats contains transmit-only Stage C telemetry.
+type UDPSegmentStats struct {
+	ProbeFailures atomic.Uint64
+	ProbeErrno    atomic.Int64
+
+	GSOCalls    atomic.Uint64
+	GSOSegments atomic.Uint64
+	GSOBytes    atomic.Uint64
+
+	FallbackCalls     atomic.Uint64
+	FallbackDatagrams atomic.Uint64
+
+	RuntimeDisables atomic.Uint64
+	RuntimeErrno   atomic.Int64
+	Disabled       atomic.Bool
+}
+
+// udpSegmentBatchWriter wraps the existing sendmmsg implementation.
+//
+// The writer receives complete, already encrypted Winn datagrams. It only
+// concatenates equal-length datagrams, so every kernel-generated segment is
+// independently parseable and authenticated by the gateway.
+type udpSegmentBatchWriter struct {
+	fd         int
+	peer       unix.Sockaddr
+	maxSegment int
+	fallback   DatagramBatchWriter
+	stats      *UDPSegmentStats
+
+	mu       sync.Mutex
+	disabled atomic.Bool
+	super    []byte
+	control  []byte
+}
+
+// NewUDPSegmentBatchWriter probes UDP_SEGMENT before the socket is used
+// concurrently.
+//
+// If the probe fails, the existing fallback writer is returned directly.
+// Therefore an unsupported handset pays no wrapper, copy, or branch cost
+// during steady-state transmission.
+//
+// The first real GSO send remains the authoritative route test. A socket can
+// accept the option while a later route or vendor network hook rejects GSO.
+func NewUDPSegmentBatchWriter(
+	fd int,
+	peer unix.Sockaddr,
+	maxSegment int,
+	fallback DatagramBatchWriter,
+) (DatagramBatchWriter, *UDPSegmentStats, error) {
+	if fallback == nil {
+		return nil, nil, errors.New("carrier: nil UDP fallback writer")
+	}
+	if fd < 0 {
+		return nil, nil, fmt.Errorf("carrier: invalid UDP fd %d", fd)
+	}
+	if maxSegment < 1 || maxSegment > 65535 {
+		return nil, nil, fmt.Errorf(
+			"carrier: invalid UDP segment size %d",
+			maxSegment,
+		)
+	}
+
+	stats := &UDPSegmentStats{}
+	if err := probeUDPSegment(fd, maxSegment); err != nil {
+		stats.ProbeFailures.Add(1)
+		stats.ProbeErrno.Store(errnoValue(err))
+		stats.Disabled.Store(true)
+		return fallback, stats, nil
+	}
+
+	capacity := stageCGSOMaxSegments * maxSegment
+	if capacity > stageCMaxSuperPayload {
+		capacity = stageCMaxSuperPayload
+	}
+
+	writer := &udpSegmentBatchWriter{
+		fd:         fd,
+		peer:       peer,
+		maxSegment: maxSegment,
+		fallback:   fallback,
+		stats:      stats,
+		super:      make([]byte, 0, capacity),
+		control:    make([]byte, unix.CmsgSpace(2)),
+	}
+	return writer, stats, nil
+}
+
+// probeUDPSegment verifies that this socket recognizes a nonzero
+// UDP_SEGMENT value, then restores the ordinary non-GSO default.
+func probeUDPSegment(fd int, segmentSize int) error {
+	if err := unix.SetsockoptInt(
+		fd,
+		stageCSOLUDP,
+		stageCUDPSegment,
+		segmentSize,
+	); err != nil {
+		return err
+	}
+
+	if err := unix.SetsockoptInt(
+		fd,
+		stageCSOLUDP,
+		stageCUDPSegment,
+		0,
+	); err != nil {
+		return err
+	}
+	return nil
+}
+
+func errnoValue(err error) int64 {
+	var errno unix.Errno
+	if errors.As(err, &errno) {
+		return int64(errno)
+	}
+	return 0
+}
+
+// permanentGSORejection identifies errors for which retrying GSO on every
+// batch would be wasteful. Transient congestion and interruption errors are
+// intentionally excluded.
+func permanentGSORejection(err error) bool {
+	return errors.Is(err, unix.ENOPROTOOPT) ||
+		errors.Is(err, unix.EOPNOTSUPP) ||
+		errors.Is(err, unix.EPROTONOSUPPORT) ||
+		errors.Is(err, unix.ENOSYS) ||
+		errors.Is(err, unix.EPERM) ||
+		errors.Is(err, unix.EINVAL) ||
+		errors.Is(err, unix.EMSGSIZE) ||
+		errors.Is(err, unix.EIO)
+}
+
+func (w *udpSegmentBatchWriter) WriteBatch(
+	datagrams [][]byte,
+) (int, error) {
+	if len(datagrams) == 0 {
+		return 0, nil
+	}
+
+	w.mu.Lock()
+	defer w.mu.Unlock()
+
+	if w.disabled.Load() {
+		return w.writeFallback(datagrams)
+	}
+
+	sent := 0
+	for sent < len(datagrams) {
+		run := w.equalLengthRun(datagrams, sent)
+		if run >= 2 {
+			n, err := w.writeGSO(datagrams[sent : sent+run])
+			if err == nil {
+				sent += n
+				continue
+			}
+
+			if permanentGSORejection(err) {
+				w.disabled.Store(true)
+				w.stats.Disabled.Store(true)
+				w.stats.RuntimeDisables.Add(1)
+				w.stats.RuntimeErrno.Store(errnoValue(err))
+
+				n, fallbackErr := w.writeFallback(datagrams[sent:])
+				return sent + n, fallbackErr
+			}
+
+			return sent, err
+		}
+
+		// Preserve later GSO opportunities while batching all intervening
+		// variable-length datagrams through the existing sendmmsg writer.
+		end := sent + 1
+		for end < len(datagrams) {
+			if w.equalLengthRun(datagrams, end) >= 2 {
+				break
+			}
+			end++
+		}
+
+		n, err := w.writeFallback(datagrams[sent:end])
+		sent += n
+		if err != nil {
+			return sent, err
+		}
+	}
+
+	return sent, nil
+}
+
+// equalLengthRun returns the number of consecutive equal-sized datagrams
+// that can safely occupy one GSO super-buffer.
+func (w *udpSegmentBatchWriter) equalLengthRun(
+	datagrams [][]byte,
+	start int,
+) int {
+	if start < 0 || start >= len(datagrams) {
+		return 0
+	}
+
+	segmentSize := len(datagrams[start])
+	if segmentSize < 1 || segmentSize > w.maxSegment {
+		return 1
+	}
+
+	limit := stageCGSOMaxSegments
+	byteLimit := stageCMaxSuperPayload / segmentSize
+	if byteLimit < limit {
+		limit = byteLimit
+	}
+	if limit < 2 {
+		return 1
+	}
+
+	run := 1
+	for start+run < len(datagrams) && run < limit {
+		if len(datagrams[start+run]) != segmentSize {
+			break
+		}
+		run++
+	}
+	return run
+}
+
+func (w *udpSegmentBatchWriter) writeFallback(
+	datagrams [][]byte,
+) (int, error) {
+	total := 0
+	for total < len(datagrams) {
+		n, err := w.fallback.WriteBatch(datagrams[total:])
+		w.stats.FallbackCalls.Add(1)
+
+		if n < 0 || n > len(datagrams)-total {
+			return total, errors.New(
+				"carrier: fallback returned invalid datagram count",
+			)
+		}
+		if n > 0 {
+			total += n
+			w.stats.FallbackDatagrams.Add(uint64(n))
+		}
+		if err != nil {
+			return total, err
+		}
+		if n == 0 {
+			return total, io.ErrNoProgress
+		}
+	}
+	return total, nil
+}
+
+func (w *udpSegmentBatchWriter) writeGSO(
+	datagrams [][]byte,
+) (int, error) {
+	segmentSize := len(datagrams[0])
+
+	w.super = w.super[:0]
+	for _, datagram := range datagrams {
+		if len(datagram) != segmentSize {
+			return 0, unix.EINVAL
+		}
+		w.super = append(w.super, datagram...)
+	}
+	if len(w.super) > stageCMaxSuperPayload {
+		return 0, unix.EMSGSIZE
+	}
+
+	w.buildControl(uint16(segmentSize))
+
+	n, err := unix.SendmsgN(
+		w.fd,
+		w.super,
+		w.control,
+		w.peer,
+		0,
+	)
+	if err != nil {
+		return 0, err
+	}
+	if n != len(w.super) {
+		return 0, io.ErrShortWrite
+	}
+
+	w.stats.GSOCalls.Add(1)
+	w.stats.GSOSegments.Add(uint64(len(datagrams)))
+	w.stats.GSOBytes.Add(uint64(n))
+	return len(datagrams), nil
+}
+
+// buildControl creates one SOL_UDP/UDP_SEGMENT control message. The kernel
+// ABI expects the segment size as a native-endian uint16.
+func (w *udpSegmentBatchWriter) buildControl(segmentSize uint16) {
+	for i := range w.control {
+		w.control[i] = 0
+	}
+
+	header := (*unix.Cmsghdr)(unsafe.Pointer(&w.control[0]))
+	header.Level = stageCSOLUDP
+	header.Type = stageCUDPSegment
+	header.SetLen(unix.CmsgLen(2))
+
+	dataOffset := unix.CmsgLen(0)
+	*(*uint16)(unsafe.Pointer(&w.control[dataOffset])) = segmentSize
+}
```

### `winn_protocol_experimental/winn3/carrier/tx_drain_gate.go`

```diff
diff --git a/winn_protocol_experimental/winn3/carrier/tx_drain_gate.go b/winn_protocol_experimental/winn3/carrier/tx_drain_gate.go
new file mode 100644
index 0000000..5aa5d31
--- /dev/null
+++ b/winn_protocol_experimental/winn3/carrier/tx_drain_gate.go
@@ -0,0 +1,211 @@
+package carrier
+
+import (
+	"sync"
+	"sync/atomic"
+	"time"
+)
+
+const (
+	DefaultTxDrainLowWater = 32
+	DefaultTxDrainMaxPark  = 250 * time.Microsecond
+)
+
+var txDrainTimerPool = sync.Pool{
+	New: func() any {
+		timer := time.NewTimer(time.Hour)
+		if !timer.Stop() {
+			<-timer.C
+		}
+		return timer
+	},
+}
+
+// TxDrainGate tracks packets made visible to one transmit-ring consumer.
+//
+// The consumer must use Claim before popping from the ring. This avoids the
+// accounting race produced by independently popping packets and decrementing
+// a mirrored depth afterward.
+type TxDrainGate struct {
+	depth      atomic.Int64
+	firstNanos atomic.Int64
+	notify     chan struct{}
+
+	lowWater int64
+	maxPark  time.Duration
+
+	Signals  atomic.Uint64
+	Wakeups  atomic.Uint64
+	Timeouts atomic.Uint64
+	Claims   atomic.Uint64
+}
+
+func NewTxDrainGate(lowWater int, maxPark time.Duration) *TxDrainGate {
+	if lowWater < 1 {
+		lowWater = DefaultTxDrainLowWater
+	}
+	if maxPark <= 0 {
+		maxPark = DefaultTxDrainMaxPark
+	}
+
+	return &TxDrainGate{
+		notify:   make(chan struct{}, 1),
+		lowWater: int64(lowWater),
+		maxPark:  maxPark,
+	}
+}
+
+// Pushed records packets after the ring has accepted them. accepted must be
+// exactly the number made visible to the consumer.
+func (g *TxDrainGate) Pushed(accepted int) {
+	if accepted <= 0 {
+		return
+	}
+
+	added := int64(accepted)
+	newDepth := g.depth.Add(added)
+	oldDepth := newDepth - added
+
+	if oldDepth == 0 {
+		g.firstNanos.Store(time.Now().UnixNano())
+	}
+
+	if oldDepth == 0 ||
+		(oldDepth < g.lowWater && newDepth >= g.lowWater) {
+		g.signal()
+	}
+}
+
+// Claim reserves up to max packets for the sole drain consumer. The caller
+// must subsequently pop exactly the returned count from the ring.
+//
+// If the ring returns fewer packets, the caller must pass the shortfall to
+// Restore.
+func (g *TxDrainGate) Claim(max int) int {
+	if max <= 0 {
+		return 0
+	}
+
+	limit := int64(max)
+	for {
+		oldDepth := g.depth.Load()
+		if oldDepth <= 0 {
+			return 0
+		}
+
+		claimed := oldDepth
+		if claimed > limit {
+			claimed = limit
+		}
+
+		start := g.firstNanos.Load()
+		newDepth := oldDepth - claimed
+		if !g.depth.CompareAndSwap(oldDepth, newDepth) {
+			continue
+		}
+
+		if newDepth == 0 {
+			// If a producer changed firstNanos after the depth transition,
+			// this comparison fails and preserves the new batch timestamp.
+			g.firstNanos.CompareAndSwap(start, 0)
+		}
+
+		g.Claims.Add(uint64(claimed))
+		return int(claimed)
+	}
+}
+
+// Restore returns claimed packets that the ring consumer did not pop.
+func (g *TxDrainGate) Restore(count int) {
+	if count <= 0 {
+		return
+	}
+
+	added := int64(count)
+	newDepth := g.depth.Add(added)
+	oldDepth := newDepth - added
+
+	if oldDepth == 0 {
+		g.firstNanos.Store(time.Now().UnixNano())
+	}
+	if oldDepth == 0 ||
+		(oldDepth < g.lowWater && newDepth >= g.lowWater) {
+		g.signal()
+	}
+}
+
+// Wait blocks while the queue is empty. After the first packet arrives, it
+// waits until lowWater is reached or maxPark has elapsed.
+//
+// Unlike a periodic timer loop, an idle gate performs no 250 microsecond
+// polling and consumes no idle wakeups.
+func (g *TxDrainGate) Wait(stop <-chan struct{}) bool {
+	for {
+		select {
+		case <-stop:
+			return false
+		default:
+		}
+
+		depth := g.depth.Load()
+		if depth >= g.lowWater {
+			return true
+		}
+
+		if depth == 0 {
+			select {
+			case <-g.notify:
+				g.Wakeups.Add(1)
+				continue
+			case <-stop:
+				return false
+			}
+		}
+
+		start := g.firstNanos.Load()
+		now := time.Now().UnixNano()
+		if start == 0 {
+			if g.firstNanos.CompareAndSwap(0, now) {
+				start = now
+			} else {
+				start = g.firstNanos.Load()
+			}
+		}
+
+		elapsed := time.Duration(now - start)
+		if elapsed < 0 {
+			// Protect the bound from a wall-clock correction.
+			elapsed = 0
+		}
+		if elapsed >= g.maxPark {
+			g.Timeouts.Add(1)
+			return true
+		}
+
+		timer := txDrainTimerPool.Get().(*time.Timer)
+		timer.Reset(g.maxPark - elapsed)
+
+		select {
+		case <-g.notify:
+			g.Wakeups.Add(1)
+			stopAndDrainTxTimer(timer)
+			txDrainTimerPool.Put(timer)
+			continue
+
+		case <-timer.C:
+			g.Timeouts.Add(1)
+			txDrainTimerPool.Put(timer)
+			return true
+
+		case <-stop:
+			stopAndDrainTxTimer(timer)
+			txDrainTimerPool.Put(timer)
+			return false
+		}
+	}
+}
+
+func (g *TxDrainGate) Depth() int64 {
+	depth := g.depth.Load()
+	if depth < 0 {
+		return 0
+	}
+	return depth
+}
+
+func (g *TxDrainGate) signal() {
+	select {
+	case g.notify <- struct{}{}:
+		g.Signals.Add(1)
+	default:
+	}
+}
+
+func stopAndDrainTxTimer(timer *time.Timer) {
+	if timer.Stop() {
+		return
+	}
+	select {
+	case <-timer.C:
+	default:
+	}
+}
```

## 5. Required call-site integration contract

The exact caller bodies were not included in the circulated repository excerpts, so fabricating surrounding identifiers would not constitute an exact patch. The required integration sequence is nevertheless strict:

```go
gate := carrier.NewTxDrainGate(
	carrier.DefaultTxDrainLowWater,
	carrier.DefaultTxDrainMaxPark,
)
```

After each successful ring push:

```go
accepted := toEngineRingPush(...)
gate.Pushed(accepted)
```

The existing unconditional per-push `toEngineCond.Signal()` must be removed.

The sole drain consumer must use:

```go
if !gate.Wait(stopCh) {
	return
}

wanted := gate.Claim(txCarrierBatchSize)
if wanted == 0 {
	continue
}

popped := toEngineRingPopAtMost(wanted)
if popped < wanted {
	gate.Restore(wanted - popped)
}

writeTransmitBatch(popped)
```

The carrier construction must retain the existing batch writer as fallback:

```go
txWriter, txGSOStats, err := carrier.NewUDPSegmentBatchWriter(
	socketFD,
	peerAddress,
	1402,
	existingSendmmsgWriter,
)
if err != nil {
	return err
}
```

No receive-side writer, socket read method, gateway buffer, or downlink symbol is part of this integration.

## 6. Ratification conditions

Stage C should be accepted only if telemetry demonstrates all of the following:

1. Mean transmit batch occupancy rises materially above 1.58.
2. `GSOCalls` and `GSOSegments` confirm that equal-sized encrypted datagrams are entering GSO batches.
3. Gateway packet capture shows no UDP payload above 1,402 bytes.
4. Forced `UDP_SEGMENT` rejection preserves delivery through `sendmmsg`.
5. The gateway reports no increase in authentication failures, truncation, `SO_RXQ_OVFL`, or packet loss.
6. The downlink benchmark and measurement equations are byte-for-byte unchanged.
7. Sustained and peak throughput are reported separately using packet count, inner bytes, elapsed interval, and CPU time from the same measurement window.

The architecture is converged. A claim that it guarantees 1 Gbps sustained is not yet ratified because the available measurements do not identify the remaining 14.800 microseconds per sustained packet with sufficient precision.
