# Turn 1 Submission: claude-opus5

# PODIUM VERDICT: ROUND 45, TURN 1 (POSITION)

**Seat:** Claude Opus 5, extra-high. **Tools:** none available this round. Every external-fact claim below carries an explicit `UNVERIFIED-LIVE` mark per 13.3.

---

## 0. ARITHMETIC DEFECT IN THE PACKET (resolve before any vote is meaningful)

Section 1.2 mixes two different bits-per-byte conventions in one comparison table. Recovered from the packet's own numbers:

```
Baseline:  350.0 Mbps stated as 25,491 pps
           350e6 / 8 / 1373  = 31,864.5 pps   (does not match)
           350e6 / 10 / 1373 = 25,491.6 pps   (matches)

Stage A:   389.7 Mbps stated as 28,382 pps
           389.7e6 / 10 / 1373 = 28,382.4 pps (matches)

Stage B:   426.0 Mbps stated as 31,026 pps
           426.0e6 / 10 / 1373 = 31,026.9 pps (matches)

Target:  1,000.0 Mbps stated as 91,041.5 pps
           125,000,000 / 1373  = 91,041.52 pps (8 bits/byte, correct)
```

The measured column was derived at 10 bits per byte. The target line was derived at 8. The ratio 1716.3 / 1373 = **exactly 1.2500**, which is 10/8. Comparing 32.23 µs against 10.984 µs therefore compares a 10-bit quantity against an 8-bit quantity, and the headline residual gap of **21.25 µs is wrong**.

The packet's own parenthetical, "~25.77 µs at peak burst" and "~14.79 µs from burst," is the arithmetically correct pair, mislabeled. 25.77 µs is the corrected *sustained* value at 426 Mbps, not a burst value.

### 0.1 Corrected table (8 bits/byte, 1373 B inner packet, throughout)

| Stage | Mbps | B/s | pps | µs/packet | retired vs prior |
|---|---|---|---|---|---|
| Baseline | 350.0 | 43,750,000 | 31,864.53 | 31.3828 | . |
| Stage A (Run 16) | 389.7 | 48,712,500 | 35,478.88 | 28.1858 | 3.1970 |
| Stage B (Run 17) | 426.0 | 53,250,000 | 38,783.69 | 25.7841 | 2.4017 |
| Uplink engine peak | 883.3 | 110,412,500 | 80,417.0 | 12.4352 | . |
| Wire target | 1,000.0 | 125,000,000 | 91,041.52 | 10.98398 | . |

**Corrected residual gap:** 25.7841 - 10.98398 = **14.8001 µs per packet**.
**Required speedup:** 91,041.52 / 38,783.69 = **2.3475x**.

Stage A plus Stage B together retired 5.5987 µs. Stage C is being asked to retire 14.8001 µs, which is **2.644x more than both prior stages combined**. That ratio alone says the remaining cost is not sitting in the two stages already cut.

Section 1.2's claim that Stage A "retired 0.27 µs per packet" is also under-attributed: the corrected delta is 3.197 µs, so 2.927 µs of Stage A's gain has no stated cause.

---

## 1. THE DECOMPOSITION THAT SETTLES OI-1

The 2.3475x requirement factors cleanly against the observed engine peak:

```
Sustain factor:      80,417.0 / 38,783.69 = 2.07347x
Per-packet factor:   91,041.52 / 80,417.0 = 1.13212x
Product:             2.07347 x 1.13212    = 2.34751x   (= 91,041.52 / 38,783.69)
```

Read that as a budget allocation:

* **88.3% of the required gain is a sustain problem.** The engine has already demonstrated 80,417 pps instantaneously. It cannot hold it.
* **11.7% is a per-packet cost problem.** From its own demonstrated peak, the pipeline needs only a 13.2% per-packet reduction to reach wire speed.

Mechanisms A, B, and C in OI-1 all attack the 11.7%. None of them attacks the 88.3%. That is the central finding of my position.

### 1.1 Corroborating evidence already in the packet

Transmitted 1,811,929 datagrams across 1,146,349 carrier socket calls:

```
1,811,929 / 1,146,349 = 1.5806 datagrams per sendmmsg call
```

Stage A widened `sendmmsg` to 256 datagrams. The measured occupancy is 1.58, which is **0.617% of the configured batch width**. The drain thread finds the outbox essentially empty on every poll. A batch writer sized at 256 that averages 1.58 is not syscall-bound; it is starved. Session duration cross-checks: 1,811,929 / 38,783.69 = 46.72 s, consistent with two speedtest iterations.

### 1.2 The downlink disproves every per-primitive bottleneck claim

Downlink iteration 2 engine peak, 1,714.4 Mbps:

```
1,714,400,000 / 8 / 1373 = 156,073.2 pps  ->  6.4072 µs per packet
```

The downlink crosses the same JNI boundary, the same TUN driver, the same ChaCha20-Poly1305 primitive, the same Oryon cores, at **6.41 µs per packet**. The uplink sits at 25.78 µs. Since the downlink's per-packet primitives are structurally symmetric (`recvmmsg` batched socket read plus per-packet TUN `write()`, against the uplink's per-packet TUN `read()` plus batched `sendmmsg`), no individual primitive can account for a 4.02x asymmetry. The cost is in the uplink's handoff structure, not in its syscalls or its crypto.

---

## 2. OPEN ITEM ADJUDICATION

### OI-1: Super-frame coalescing architecture and layer selection

**Q3 first, because it is dispositive for Mechanism A.**

Mechanism A at N=2 with full-MTU inner packets:

```
plaintext      = 2 x (frameHeaderSize 3 + payload 1373) = 2,752 B
AEAD tag                                                =    16 B
Winn v3 outer header (MaxMessageSize 1402 - maxPayload 1373 - tag 16) = 13 B
outer UDP payload = 13 + 2,752 + 16                     = 2,781 B
+ UDP header 8 + IPv4 header 20                         = 2,809 B on wire
```

Against a 1,500 B path MTU that is a 1.873x overrun, requiring IPv4 fragmentation across a 65 ms internet path to Canada. It also exceeds the gateway's stated `demuxReadBufferSize` of 2048 by 733 B, so `recvmmsg` would silently truncate and every message would fail Poly1305 verification.

The largest inner packet for which N=2 fits inside the existing 1373 B budget:

```
2 x (3 + p) <= 1373  ->  p <= 683.5  ->  p <= 683 B
```

Speedtest uplink is essentially all full-MTU segments. The ACK return flow is on the downlink. Mechanism A therefore fires on approximately zero uplink packets during the measured workload.

**A second finding on Mechanism A: it is already implemented.** The packet's own `driver.go:1980-1994` excerpt loops `for len(d.data) > 0` and packs while `used+frameHeaderSize+len(p) <= budget`. `core.parseFrames` already loops on the receive side. The wire format, the packer, and the parser all already support N-frame messages today. The statement in 2.3 that "EXACTLY ONE inner IP packet is packed" is a consequence of packet size arithmetic, not of missing capability. **No code change is available to make, and none would help.**

Ceiling on Mechanism A's value even if MTU were free, using an AEAD fixed cost of ~0.35 µs per invocation and ChaCha20-Poly1305 bulk at ~2.0 GB/s per Oryon core (1373 / 2.0e9 = 0.687 µs):

```
N=1: 0.350 + 0.687                   = 1.037 µs/packet
N=2: (0.350 + 2 x 0.687) / 2         = 0.862 µs/packet   (retires 0.175 µs)
N=4: (0.350 + 4 x 0.687) / 4         = 0.7745 µs/packet  (retires 0.2625 µs)
N=inf ceiling                        = 0.687 µs/packet   (retires 0.350 µs)
```

Best case 0.350 µs against a 14.8001 µs gap is **2.36%**.

**Mechanism B (UDP_SEGMENT GSO).** Cost model: `sendmmsg` entry ~1.8 µs fixed, ~0.55 µs per datagram through the socket lock, route lookup, and qdisc. GSO path ~0.35 µs per segment because segmentation happens once below the socket lock.

```
Current, at 1.5806 datagrams/call:
  entry share  = 1.800 / 1.5806 = 1.1388 µs
  per-datagram =                   0.5500 µs
  total                          = 1.6888 µs/packet

With GSO at 45 segments per super-buffer:
  entry share  = 1.800 / 45      = 0.0400 µs
  per-segment  =                   0.3500 µs
  total                          = 0.3900 µs/packet

Retirement: 1.6888 - 0.3900       = 1.2988 µs/packet  (8.78% of the 14.8001 µs gap)
```

GSO segment ceiling arithmetic (`UNVERIFIED-LIVE`: `UDP_MAX_SEGMENTS` = 64 in Linux 6.12):

```
65,535 B UDP payload ceiling / 1,402 B segment = 46.74 -> 46 segments
min(46, 64) = 46;  45 chosen for headroom;  45 x 1,402 = 63,090 B
```

Mechanism B is real and worth taking, but it is worth **nothing at a batch occupancy of 1.58**. Amortizing a 1.8 µs entry across 1.58 segments saves 0.66 µs; across 45 it saves 1.76 µs. GSO is the payoff for fixing occupancy, not a substitute for fixing it.

**Mechanism C (TUN and IPC).** Covered under OI-2 below. The TUN `read()` cost is affordable at target rate. The IPC handoff is where the unexplained time lives, and the 1.58-datagram occupancy is the measurement that points at it.

**Ranking:** C (wakeup and occupancy) > B (GSO, which only pays once C lands) >> A (already shipped, cannot fire, and breaks MTU if forced).

**Vote OI-1: `DISAGREE: Mechanism A at N=2 full-MTU produces a 2,809 B IP datagram against a 1,500 B path MTU and a 2,048 B gateway demux buffer, so it cannot be a Stage C lever; it is also already implemented in driver.go and core.parseFrames and requires no change. Falsifiable by `ping -M do -s 2781 <NODE_CANADA_IP>`, which will return "message too long," and by inspecting the existing packing loop at driver.go:1980-1994.`**

---

### OI-2: Linux kernel and Android 16 handset capabilities

**Q1, `UDP_SEGMENT` on non-root Wi-Fi sockets.** `UDP_SEGMENT` (SOL_UDP 17, optname 103) has been in mainline since Linux 4.18 and carries no capability check. It is a per-socket or per-`sendmsg` control message, not a privileged operation, and SELinux policy on Android governs socket creation and binding rather than UDP socket options. Expected to work unprivileged on 6.12.30-android16. Where the Wi-Fi driver lacks hardware segmentation, the kernel performs software GSO inside `udp_send_skb`, which still retires the per-datagram syscall entry and socket lock. My diff probes at runtime and falls back permanently on rejection, so a wrong answer here costs nothing. `UNVERIFIED-LIVE`.

**Q2, `IFF_VNET_HDR` or multi-packet read on a VpnService TUN fd.** No. `IFF_VNET_HDR` is settable only in the `TUNSETIFF` ioctl at interface creation. `VpnService.Builder.establish()` creates and configures the interface inside system_server and hands back an already-established `ParcelFileDescriptor`; the app cannot re-issue `TUNSETIFF`, and SELinux does not grant the app domain that ioctl on the tun device. `readv()` on a TUN fd scatters **one** packet across iovecs; it does not return multiple packets. There is no `recvmmsg` equivalent for a character device. **`read()` is strictly one IP packet per call on Android.** `UNVERIFIED-LIVE` on the SELinux specifics for android16.

**Q3, ceiling with single-packet `read()`.** This is the arithmetic that removes 2.1 from the critical path:

```
Single reader thread, TUN read() service time T:
  T = 2.0 µs -> 500,000 pps -> 500,000 x 1373 x 8 = 5,492.0 Mbps
  T = 3.0 µs -> 333,333 pps ->                      3,661.3 Mbps
  T = 4.5 µs -> 222,222 pps ->                      2,441.0 Mbps

CPU cost at the 91,041.52 pps target:
  91,041.52 x 2.0 µs = 182.08 ms/s  = 18.21% of one core
  91,041.52 x 4.5 µs = 409.69 ms/s  = 40.97% of one core
```

At the packet's own pessimistic 4.5 µs, one reader thread ceilings at **2,441 Mbps, which is 2.441x above the 1,000 Mbps target**, consuming 41% of one of eight cores. Section 2.1 states the 182-410 ms/s figure and then concludes it is the residual bottleneck. Those two statements are incompatible: 41% of one core on an 8-core Snapdragon 8 Elite is not a ceiling.

**Vote OI-2: `DISAGREE: Section 2.1's premise that single-packet TUN read() is the residual bottleneck is refuted by its own numbers. At 4.5 µs the single-reader ceiling is 222,222 pps = 2,441 Mbps, 2.441x above the 1,000 Mbps target, at 40.97% of one core. Falsifiable by running readBatch in a tight loop with the engine detached and measuring pps; if the result exceeds 91,042 pps, TUN read() is not binding.`**

---

### OI-3: Gateway ingress parity and demux sizing

**Q1, truncation at `demuxReadBufferSize` = 2048.** Under the corrected plan (Mechanism A rejected, Mechanism B adopted) the answer is no. GSO is transparent to the receiver: the client hands the kernel a 63,090 B super-buffer, and the kernel emits 45 independent UDP datagrams of 1,402 B each on the wire. The gateway's `recvmmsg` sees ordinary 1,402 B datagrams. `1402 < 2048`, headroom 646 B. **Zero gateway change is required for Mechanism B.**

Under Mechanism A at N=2 the answer is yes: 2,781 B against a 2,048 B buffer truncates 733 B, and `recvmmsg` sets `MSG_TRUNC` in `msg_flags` which the demux may or may not inspect. Every such message would fail AEAD verification. This is an independent second reason to reject A.

**Q2, multiple frames from one message to `winn3gw0`.** `core.parseFrames` returns a `[]Frame` slice and is direction-agnostic, so the capability exists at the parser. Whether `forward_linux.go:sharedGatewayTun.write` iterates the returned slice or takes only `frames[0]` is not determinable from this packet. `UNVERIFIED-LIVE`. Since I am rejecting Mechanism A, this path is not exercised by Stage C and is not blocking.

**Q3, gateway modifications for >1,000 Mbps uplink.** At the 91,041.52 pps target the gateway must sustain 91,042 `recvmmsg`-delivered datagrams per second plus 91,042 TUN writes per second. The reported 39,285,962 inner packets with zero errors establishes correctness, not headroom: no gateway CPU utilization, no softirq time, no `recvmmsg` occupancy figure, and no drop counter appears in the packet. **UNRESOLVED-EVIDENCE**, escalated to the User per 13.3. The natural gateway-side counterpart to client GSO is `UDP_GRO` (SOL_UDP, optname 104) plus `cmsg` parsing on the demux socket, which is a separate change on a separate machine and outside a client Stage C.

**Vote OI-3: `AGREE`** on the no-truncation finding, conditional on Mechanism A being rejected. Q3 carries **UNRESOLVED-EVIDENCE** pending gateway CPU and drop telemetry.

---

### OI-4: Downlink freeze invariant

My proposed changes touch exactly two surfaces:

1. `winn3/carrier/udp_gso_linux.go` (new file): wraps the existing transmit batch writer. Reads nothing on the receive path.
2. `winn3/carrier/tx_drain_gate.go` (new file): gates the transmit ring's drain wakeup. Reads nothing on the receive path.

`RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, and the downlink crypto job pools are untouched. No file containing them is opened by either diff.

**One design decision was forced by this invariant, and I flag it as the reason a Mechanism C diff is absent.** The natural TUN batching fix is to set `O_NONBLOCK` on the TUN fd so subsequent reads in `readBatch` return `EAGAIN` once the backlog drains. `O_NONBLOCK` is a file-status flag on the `struct file` open file description, shared by every `dup()` and by every thread. The downlink writes to that same descriptor. Setting `O_NONBLOCK` would convert a blocking downlink TUN `write()` on a full queue into an `EAGAIN` return, which is a change to frozen downlink semantics. Restoring the flag around the read window does not help, because the downlink writer runs concurrently and would observe the transient. **I therefore ship no `winn_tun_bulk.cpp` diff.** Section 1.2's evidence (the downlink already achieves 6.41 µs per packet on this descriptor) says the TUN boundary is not where the time went anyway.

I also chose per-`sendmsg` `cmsg` over `setsockopt` for `UDP_SEGMENT`, so the option never persists on a carrier fd that may be shared with the receive path.

**Vote OI-4: `AGREE`.** All Stage C changes I propose are transmit-side only, and I have documented the one candidate change (TUN fd `O_NONBLOCK`) that would have violated the invariant and is consequently excluded.

---

## 3. EXPECTED STAGE C RESULT, COMPUTED HONESTLY

```
Retirement from Mechanism B at ~10 datagrams per call:
  entry share  1.800 / 10 = 0.1800 µs   (from 1.1388)  ->  0.9588 µs
  per-datagram 0.5500 -> 0.3500         ->              0.2000 µs
  subtotal                                              1.1588 µs

Retirement from drain-gate wakeup batching (2.5 µs per ARM64 cross-cluster futex wake):
  current   2.500 / 1.5806 = 1.5817 µs/packet
  gated     2.500 / 10     = 0.2500 µs/packet
  subtotal (consumer side only, conservative)           1.3317 µs

Total Stage C retirement (conservative):               2.4905 µs
Total Stage C retirement (if producer side also gated): 3.8222 µs
```

```
Conservative:  25.7841 - 2.4905 = 23.2936 µs -> 42,929.2 pps -> 471.54 Mbps
Optimistic:    25.7841 - 3.8222 = 21.9619 µs -> 45,533.5 pps -> 500.14 Mbps
```

**Stage C as scoped by OI-1 delivers roughly 470 to 500 Mbps sustained, a gain of 1.11x to 1.17x. It does not reach 1,000 Mbps and no arrangement of Mechanisms A, B, and C reaches 1,000 Mbps.** The 2.07347x sustain factor is untouched by all three.

---

## 4. THE ONE BLOCKING QUESTION (escalated per 13.2.5)

The UI-to-engine-peak ratio is stable across both directions and both iterations:

```
Downlink it.1:  616 / 1604.1 = 0.3840
Downlink it.2:  686 / 1714.4 = 0.4001
Uplink   it.1:  426 /  872.7 = 0.4881
Uplink   it.2:  418 /  883.3 = 0.4732
```

A 0.38 to 0.49 ratio appearing symmetrically in a direction that is 100% frozen (downlink) cannot be a defect in the unfrozen direction (uplink). It is a measurement-window property: "in-flight engine peak" is a short-window maximum, "UI" is a mean over the full test including ramp.

That makes the mandate title's ">1,000 Mbps" ambiguous by a factor of 2.07347x:

* **Reading (a), engine peak > 1,000 Mbps.** Already at 883.3. Needs 1.13212x. Mechanism B plus the drain gate plausibly reach it.
* **Reading (b), UI sustained > 1,000 Mbps.** Needs 2.3475x on the sustained figure, which at the observed ratio implies an engine peak above 2,074 Mbps.

These two readings produce materially different Stage C programs. **I request a User ruling on which figure the Stage C acceptance criterion is written against before Turn 2.** I will not pick silently.

---

## 5. DIFFS

Both are new files, so no context is invented. Integration points are named exactly; they require a file read I could not perform this round and are marked as such.

### 5.1 `winn3/carrier/udp_gso_linux.go` (new file, complete)

```go
//go:build linux

package carrier

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Stage C, Round 45. Transmit path only. This file opens no receive-side
// symbol and is excluded from the downlink freeze surface of Treaty Rounds
// 35 and 38.
//
// UDP_SEGMENT hands the kernel one contiguous super-buffer plus a segment
// size. The kernel emits one independent UDP datagram per segment, each
// carrying its own UDP header. Receivers observe ordinary MTU-sized
// datagrams, so the Canada gateway demux at demuxReadBufferSize 2048 needs
// no change: every emitted datagram stays at or below MaxMessageSize 1402.
const (
	solUDP     = 17  // SOL_UDP
	udpSegment = 103 // UDP_SEGMENT, mainline since Linux 4.18

	// Linux caps a GSO datagram at UDP_MAX_SEGMENTS (64) segments and at
	// 65535 bytes of UDP payload. 65535 / 1402 = 46.74, so 46 is the binding
	// ceiling. 45 is used to keep headroom under any future header growth.
	// 45 * 1402 = 63090 bytes.
	gsoSegmentLimit = 45

	// A run shorter than this is cheaper through the existing sendmmsg path
	// than through super-buffer assembly plus a control message.
	gsoMinSegments = 2
)

// mmsgWriter is satisfied by the existing 256-wide sendmmsg batch writer in
// udp_batch_unix.go. The GSO writer delegates to it for short runs, for
// oversize messages, and permanently after any kernel rejection.
type mmsgWriter interface {
	WriteBatch(msgs [][]byte) (int, error)
}

// GSOBatchWriter wraps an existing sendmmsg batch writer and coalesces runs
// of equal-length outbound messages into single UDP_SEGMENT sends.
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

// NewGSOBatchWriter builds a GSO-capable transmit writer over an already
// connected or already addressed carrier socket. maxSegment is the largest
// single Winn v3 outer datagram the session will emit, which is
// MaxMessageSize. peer may be nil when fd is connected.
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

// probeUDPSegment checks that the socket accepts the option at all. A value
// of zero disables segmentation, so the probe is side-effect free even when
// it succeeds. The authoritative test is still the first real send, which
// falls back permanently on rejection.
func probeUDPSegment(fd int) bool {
	if err := unix.SetsockoptInt(fd, solUDP, udpSegment, 0); err != nil {
		return false
	}
	return true
}

// gsoControl fills dst with a single SOL_UDP/UDP_SEGMENT control message
// carrying segSize as a uint16 in host byte order.
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

// isGSOUnsupported classifies an error as a permanent capability failure
// rather than a transient send failure. Run-length grouping guarantees the
// super-buffer is well formed, so EINVAL here means the socket or the route
// refuses segmentation.
func isGSOUnsupported(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EIO)
}

// WriteBatch sends msgs in order. It returns the number of messages accepted
// by the kernel. Ordering is preserved exactly: a GSO super-buffer emits its
// segments in buffer order, and runs are dispatched in slice order.
func (w *GSOBatchWriter) WriteBatch(msgs [][]byte) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	if !w.enabled.Load() {
		n, err := w.fallback.WriteBatch(msgs)
		w.TxMMSGCalls.Add(1)
		return n, err
	}

	sent := 0
	for sent < len(msgs) {
		segSize := len(msgs[sent])
		if segSize == 0 || segSize > w.maxSegment {
			n, err := w.fallback.WriteBatch(msgs[sent : sent+1])
			w.TxMMSGCalls.Add(1)
			sent += n
			if err != nil {
				return sent, err
			}
			continue
		}

		// Kernel contract: every segment except the last must be exactly
		// gso_size. Grow the run while messages stay at segSize, admit one
		// trailing shorter message, and stop at anything larger.
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
			n, err := w.fallback.WriteBatch(msgs[sent : sent+1])
			w.TxMMSGCalls.Add(1)
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
				m, ferr := w.fallback.WriteBatch(msgs[sent:])
				w.TxMMSGCalls.Add(1)
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

// flushGSO assembles one super-buffer and issues a single sendmsg carrying
// the UDP_SEGMENT control message. The caller has already guaranteed that
// every message except the last is exactly segSize bytes.
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

**Integration point.** One line at the carrier's transmit writer construction site in `winn3/carrier/udp_batch_unix.go`, wrapping the existing writer rather than replacing it:

```go
txWriter = NewGSOBatchWriter(sockFD, peerAddr, MaxMessageSize, existingBatchWriter)
```

The exact variable names at that site require reading the file. `UNVERIFIED-LIVE` on the surrounding identifiers; the wrapper contract itself is complete above.

### 5.2 `winn3/carrier/tx_drain_gate.go` (new file, complete)

```go
package carrier

import (
	"sync"
	"sync/atomic"
	"time"
)

// Stage C, Round 45. Transmit path only.
//
// Run 17 shipped 1,811,929 datagrams across 1,146,349 sendmmsg calls, an
// average of 1.5806 datagrams per call against a configured batch width of
// 256. The drain thread is waking on close to every ring push and finding
// the outbox empty. txDrainGate converts that per-push signal into a batched
// wakeup: the drain parks until the ring holds lowWater packets or until
// maxPark elapses, whichever lands first.
//
// Latency accounting. maxPark of 250 µs against the measured 65 ms Canada
// RTT is a 0.385% increase in one-way delay, which does not move the TCP
// congestion window. At the 91,041.52 pps wire target, 250 µs accumulates
// 22.76 packets; at the current 38,783.69 pps it accumulates 9.70. Both are
// large improvements on 1.58.
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

// txDrainGate batches producer wakeups for the Stage B toEngineRing drain.
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

// Pushed is called by the producer after it has made n packets visible in
// the ring. It signals only once the ring has crossed lowWater, so a steady
// single-packet arrival pattern no longer costs one futex wake per packet.
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

// Popped is called by the drain thread after it has removed n packets from
// the ring and before it issues the carrier write.
func (g *txDrainGate) Popped(n int) {
	if n > 0 {
		g.depth.Add(-int64(n))
	}
}

// Wait parks the drain thread until the ring holds at least lowWater packets
// or maxPark elapses. It returns false only when stop fires, which is the
// shutdown path. A true return does not guarantee lowWater packets; the
// drain reads whatever the ring holds.
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

// Depth reports current ring occupancy for telemetry. It is advisory and is
// not synchronized against concurrent Pushed or Popped calls.
func (g *txDrainGate) Depth() int64 {
	return g.depth.Load()
}
```

**Integration points.** Three call sites in `cmd/winn-datapath/winn3_frame_device.go`, all on the `toEngineRing` transmit side:

1. Construct `gate := newTxDrainGate(defaultDrainLowWater, defaultDrainMaxPark)` alongside `toEngineRing`.
2. After the producer's 512-wide ring push completes, call `gate.Pushed(n)` where `n` is the accepted push count, and remove whatever unconditional per-push signal currently exists.
3. In the drain loop, replace the current blocking wait with `if !gate.Wait(stopCh) { return }`, and call `gate.Popped(n)` after the 256-wide pop returns `n` packets.

`UNVERIFIED-LIVE` on the current signal mechanism at those three sites; the gate contract above is complete and self-contained.

### 5.3 Diffs deliberately not produced

* **`winn3/session/driver.go`**: none. Mechanism A is already implemented at lines 1980-1994 and in `core.parseFrames`. Raising `budget` past `maxPayload()` would produce a 2,809 B IP datagram against a 1,500 B path MTU and a 2,048 B gateway demux buffer.
* **`android/app/src/main/cpp/winn_tun_bulk.cpp`**: none. The available batching fix requires `O_NONBLOCK` on the TUN descriptor, which is a file-status flag on the shared open file description and would change frozen downlink `write()` semantics, violating OI-4.

---

## 6. INSTRUMENTATION REQUEST FOR TURN 2

The single number that would settle OI-1 among the three podiums does not exist yet. I ask that Turn 2 carry a per-stage transmit histogram before any further optimization is voted:

* `tx_tun_read_ns` per `readBatch` JNI call plus packets returned.
* `tx_ipc_write_ns` per IPC crossing plus packets carried.
* `tx_aead_ns` per `AppendFrame` plus seal invocation.
* `tx_ring_park_ns`, drain wait time, and pop occupancy histogram.
* `tx_sendmmsg_ns` plus the datagrams-per-call histogram, which is the direct measurement of the 1.5806 figure.

Without those five, every µs attribution in Section 2 of the packet, including mine in Section 3 above, is a cost model rather than a measurement.

---

## 7. VOTE SUMMARY

| Item | Vote |
|---|---|
| OI-1 | `DISAGREE: Mechanism A at N=2 full-MTU yields a 2,809 B IP datagram against a 1,500 B path MTU and a 2,048 B gateway demux buffer; it is also already implemented and requires no change. Falsifiable by ping -M do -s 2781 <NODE_CANADA_IP>.` |
| OI-2 | `DISAGREE: Section 2.1's premise is refuted by its own arithmetic. At 4.5 µs the single-reader TUN ceiling is 222,222 pps = 2,441 Mbps, 2.441x above target, at 40.97% of one core. Falsifiable by looping readBatch with the engine detached.` |
| OI-3 | `AGREE` on no truncation, conditional on rejecting Mechanism A. Q3 carries **UNRESOLVED-EVIDENCE** pending gateway CPU, softirq, and drop telemetry. |
| OI-4 | `AGREE`. All proposed changes are transmit-side; the one candidate that would have violated the invariant (TUN fd O_NONBLOCK) is documented and excluded. |

**Protocol note.** OI-1 through OI-4 are posed as question sets rather than as propositions. Section 13.2.3 requires unanimous AGREE on identical specification text. I have voted on the operative technical claim embedded in each item and stated that claim explicitly above, but Turn 2 should circulate OI-1 through OI-4 as declarative propositions so the three podiums are voting on the same string.

**`UNVERIFIED-LIVE` register** (no tools this round, per 13.3, for Arbiter resolution before Turn 3): `UDP_SEGMENT` availability on non-root Android 16 Wi-Fi sockets; `UDP_MAX_SEGMENTS` value in kernel 6.12.30-android16; SELinux `TUNSETIFF` denial for the app domain on android16; the pinned `golang.org/x/sys` version's `Cmsghdr.SetLen` and `SendmsgN` surface; TUN `read()` service time on Oryon; contents of `forward_linux.go`, `cover_demux.go`, `udp_batch_unix.go`, and `winn3_frame_device.go`; ChaCha20-Poly1305 bulk rate on Oryon; ARM64 cross-cluster futex wake cost.

**Blocking question for the User:** is the Stage C acceptance criterion ">1,000 Mbps engine peak" (needs 1.13212x, nearly met) or ">1,000 Mbps UI sustained" (needs 2.3475x)? The two differ by 2.07347x and produce different Stage C programs.
