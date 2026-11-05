# Stage 3 Synthesis: stage3_fable51

# Podium 4, Stage 3: Synthesis and Position Lock

## 0. Ruling first

The docket target changes. 2,000 Mbps of application goodput over a 2 Gbps Ethernet line was never available; every podium that ran the arithmetic agrees, and the one that did not (Podium 1) never disputed it. The locked ceiling is a formula with one unmeasured input, the Winn v3 record overhead. Section 2 states it.

Five specifications follow. Each one is the merged position of Podiums 2, 3 and 4 after the Stage 2 corrections, with two of my own Stage 1 defects removed and three critiques of other podiums withdrawn because they do not survive a source-level check.

I still have no tool access. Every kernel or Android constant below that carries weight is tagged `[V#]` and listed in Section 9 for verification before deployment. Nothing in this document is presented as measured.

---

## 1. Concessions ledger

### 1.1 What I withdraw

**Ceiling.** My 1.733 Gbps figure charged 1538 wire bytes per tunnel frame against a 1373 byte inner packet. That only holds if Winn framing is around 127 bytes. Opus assumed 32 bytes and derived 1,812.6 Mbps. Neither of us knows W. I concede the method, and I concede that if W = 32 then Opus's number is the one to quote.

**Kotlin `fcntl` line.** `detachFd()` zeroes the descriptor before `.fileDescriptor` is read. The line throws `EBADF` on every launch. Deleted. Non-blocking mode is set once, in Go, with `unix.SetNonblock`.

**ChaCha20-Poly1305 on arm64.** Only the cipher half has arm64 assembly in `golang.org/x/crypto`. The MAC runs generic Go. My per-core throughput estimate drops from 1.5 to 2.5 GB/s down to 1.0 to 1.5 GB/s. Crypto still is not the serialized per-packet cost, but the margin is thinner, and Opus's AEAD negotiation (AES-GCM where ARMv8 CE exists) goes into the spec.

**Reordering.** My multi-writer TUN fan-out reorders segments within a flow. Opus's design had the same gap. Fixed in Spec C with per-flow sharding.

### 1.2 What I accept from others

* Sol Pro: GSO and GRO must be deployed on both ends, in both directions. Podium 1's single-direction plan optimizes upload only.
* Sol Pro: the "1.2 us context switch per syscall" multiplication is unproven. A syscall is a privilege transition, not a scheduler event. `simpleperf stat` replaces the estimate.
* Sol Pro: `SO_RCVBUF` is clamped then doubled, and the accounted number includes `truesize`. Reported capacity is not payload capacity.
* Opus: direct TUN descriptor ownership in Go, with no Kotlin relay, is the largest architectural change available on the handset. Quantification waits for measurement.
* Opus: a blocking TUN reader that cannot be interrupted is a shipping defect. Spec C uses the Go poller so `Close()` unparks the reader.
* Opus: a GSO sender with no error path loses whole batches. Spec A has the fallback.
* Opus and Sol Pro: MASQUERADE is the wrong NAT target for the Double VPN path. I agree with the conclusion; see 1.3 for why I reject one of the stated reasons.

### 1.3 Critiques I reject

**Opus 1.4, Failure 1: "MASQUERADE on a /32 point-to-point tunnel resolves to 0.0.0.0 and blackholes."** `nf_nat_masquerade_ipv4` calls `inet_select_addr(dev, nh, RT_SCOPE_UNIVERSE)`, which returns the first primary address on the device with sufficient scope. Prefix length is not consulted `[V1]`. MASQUERADE out of a WireGuard interface carrying a /32 is the most common WireGuard NAT configuration in existence, and it works. The genuine MASQUERADE defects are different: `masq_device_event` flushes every conntrack entry bound to the device on link-down, which kills all sessions on that exit whenever the tunnel flaps `[V2]`; and MASQUERADE performs an address lookup at flow creation that static SNAT does not need. Same recommendation, correct reasons. The recommendation is not "SNAT instead of MASQUERADE", it is "no NAT on aicore at all" (Spec D).

**Opus 1.3: "the kernel segments to UDP_SEGMENT size regardless, then each resulting datagram hits `ip_fragment()`."** No. `udp_send_skb` rejects the whole send with `EINVAL` when `hlen + gso_size > cork->fragsize`, where `fragsize` is the route MTU `[V3]`. The kernel refuses rather than fragments. That is worse for a naive sender (the entire batch fails) and it is exactly why Spec A validates the segment size against `IP_MTU` and downgrades on `EINVAL`.

**Opus 1.3: `UDP_MAX_SEGMENTS` is 64.** It was `1 << 6` when Willem de Bruijn added GSO in 4.18. I believe it is `1 << 7` on current kernels `[V4]`. The dispute is moot: at a 1405 byte record the 65,507 byte datagram budget caps a batch at 46 segments, and the 60 KiB safety budget in Spec A caps it at 43. Neither cap is reached on any kernel. We keep 64 as the code constant so the batch shape is kernel-independent.

**Sol Pro 3.6 direction, applied to me:** Sol Pro is right that 16 MB versus 8 MB is a no-op on the handset if AOSP's `rmem_max` is 8 MiB `[V5]`. If the S25 kernel instead ships the older 262,144 value, both requests clamp to 256 KiB and the buffer story changes entirely: the handset then has about 2 ms of absorption at 2 Gbps and GRO plus pacing on aicore become the only levers. Section 4 covers both branches.

---

## 2. The ceiling, locked as a formula

Definitions: I = inner IP packet (1373 today), W = Winn v3 record overhead in bytes, outer IPv4 (20) plus UDP (8), Ethernet line overhead 38 bytes (14 header, 4 FCS, 8 preamble, 12 IFG), P = inner TCP payload = I minus 40 for IPv4 without options.

$$
f_{\max} = \frac{2\times10^{9}}{8\,(I + 28 + W + 38)} \qquad
T_{tcp} = f_{\max}\times 8\times(I-40)
$$

| W (bytes) | Outer datagram | Wire frame | Frames/s | Inner TCP goodput |
|---|---|---|---|---|
| 17 | 1418 | 1456 | 171,703 | 1,831.2 Mbps |
| 32 | 1433 | 1471 | 169,952 | 1,812.6 Mbps |
| 64 | 1465 | 1503 | 166,334 | 1,774.0 Mbps |
| 127 | 1528 | 1566 | 159,642 | 1,702.6 Mbps |

At W = 127 the outer datagram already exceeds 1500 and fragments on the outer path, so the last row is a warning rather than an operating point.

Raising the inner MTU only helps if W is known:

$$
I_{\max} = \min(\text{PMTU}_{outer}, 1500) - H_o - 8 - W
$$

With W = 32 that is 1440 for an IPv4 outer path and 1420 for IPv6. The handset must compute I from the actual outer family and a PMTU probe at handshake, and fall back to the current 1373 if the probe fails. Nobody ships a hard-coded 1440.

**Locked position.** Publish the UI scale as 100 percent = the computed ceiling for the measured W. Until W is measured by capturing one record with `tcpdump -ni <wan> udp port <winn>` and subtracting 1373 from the UDP length, the working target is 1,800 Mbps and nobody quotes anything higher.

Also locked, on the physical meaning of the 2.47 Gbps baseline: Podium 1's 1347 + 1122 Mbps sum is a valid result for whatever path SpeedBench actually traversed. It becomes a WAN result only when `ip -s link show dev <aicore-wan>` byte counters move by the tested volume. Sol Pro's demand stands.

---

## 3. Spec A: UDP GSO and GRO in Go

### 3.1 Contract

1. Each inner packet is sealed individually with its own nonce before it enters a batch. The kernel sees ciphertext only. A batch is a contiguous byte slice of N complete records.
2. All records in a batch have identical length except the last, which may be shorter. A shorter record seals the batch.
3. Segment size for the `UDP_SEGMENT` cmsg equals the sealed record length (inner length plus W), never the inner length.
4. Segment size must satisfy `seg + outer headers <= route MTU` as reported by `getsockopt(IP_MTU)` on the connected socket. If not, GSO is off for that endpoint.
5. Flush happens on: destination change, size change, 64 segments, 60 KiB aggregate, or the TUN queue draining (`EAGAIN`). No timers.
6. `EINVAL`, `EIO`, `EOPNOTSUPP` from a GSO send disable GSO on that socket permanently for the session, log at error level with the errno, and resend the same records unbatched. Nothing is dropped and nothing is hidden.
7. Receive side sets `UDP_GRO`, provides a 65,535 byte buffer per message, and reads the `int`-sized `UDP_GRO` cmsg (4 bytes, not 2).
8. `UDP_SEGMENT` is `__u16` on send. `UDP_GRO` is `int` on receive `[V6]`. That asymmetry is the defect Podium 2 shipped and it is now a compile-time constant.

### 3.2 Implementation

```go
// Package udpbatch: UDP GSO transmit and UDP GRO receive for the Winn v3 outer
// socket on Linux (handset and aicore share this file).
//
// Records are AEAD-sealed one at a time by the caller before Batch.Add. The
// kernel never sees plaintext and never sees a partial record.
package udpbatch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	// UDP_MAX_SEGMENTS is 64 on older kernels and 128 on newer ones. 64 keeps
	// the batch shape identical everywhere; the byte budget below binds first.
	maxSegments = 64
	// 60 KiB leaves slack under the 65,507 byte UDP payload ceiling.
	safeAggregateBytes = 61440
	maxDatagram        = 65535
	segCmsgData        = 2 // __u16: UDP_SEGMENT on sendmsg
	groCmsgData        = 4 // int:   UDP_GRO on recvmsg
)

// BatchLimit returns how many records of recordSize fit in one GSO send.
func BatchLimit(recordSize int) int {
	if recordSize <= 0 {
		return 1
	}
	n := safeAggregateBytes / recordSize
	if n > maxSegments {
		n = maxSegments
	}
	if n < 1 {
		n = 1
	}
	return n
}

// Batch accumulates sealed records bound for one destination.
type Batch struct {
	dst  netip.AddrPort
	seg  int
	segs int
	last int
	buf  []byte
}

func NewBatch() *Batch {
	return &Batch{buf: make([]byte, 0, safeAggregateBytes)}
}

// Add appends one sealed record. False means the record cannot join this
// batch; the caller must Flush and call Add again with the same record.
func (b *Batch) Add(dst netip.AddrPort, rec []byte) bool {
	if len(rec) == 0 || len(rec) > maxDatagram {
		return false
	}
	if b.segs == 0 {
		b.dst = dst
		b.seg = len(rec)
	} else {
		switch {
		case dst != b.dst:
			return false
		case b.last != b.seg: // previous record was short: batch is sealed
			return false
		case len(rec) > b.seg:
			return false
		case b.segs >= maxSegments:
			return false
		case len(b.buf)+len(rec) > safeAggregateBytes:
			return false
		}
	}
	b.buf = append(b.buf, rec...)
	b.segs++
	b.last = len(rec)
	return true
}

func (b *Batch) Len() int { return b.segs }

func (b *Batch) reset() {
	b.segs, b.seg, b.last = 0, 0, 0
	b.buf = b.buf[:0]
}

// appendSegmentCmsg writes a SOL_UDP/UDP_SEGMENT control message carrying a
// __u16 segment size, matching __udp_cmsg_send in net/ipv4/udp.c.
func appendSegmentCmsg(oob []byte, seg uint16) []byte {
	space := unix.CmsgSpace(segCmsgData)
	start := len(oob)
	for i := 0; i < space; i++ {
		oob = append(oob, 0)
	}
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[start]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(segCmsgData))
	binary.NativeEndian.PutUint16(oob[start+unix.CmsgLen(0):], seg)
	return oob
}

// groSegmentSize extracts the int gso_size the kernel attaches when UDP_GRO
// coalesced the datagram. 0 means the datagram was not coalesced.
func groSegmentSize(oob []byte) (int, error) {
	if len(oob) == 0 {
		return 0, nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, fmt.Errorf("udpbatch: parse cmsg: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_UDP || m.Header.Type != unix.UDP_GRO {
			continue
		}
		if len(m.Data) < groCmsgData {
			return 0, fmt.Errorf("udpbatch: UDP_GRO cmsg is %d bytes, want %d", len(m.Data), groCmsgData)
		}
		return int(int32(binary.NativeEndian.Uint32(m.Data[:groCmsgData]))), nil
	}
	return 0, nil
}

// batchConn is satisfied by both *ipv4.PacketConn and *ipv6.PacketConn
// because ipv4.Message and ipv6.Message alias the same socket.Message type.
type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

// Socket wraps one outer UDP socket with GSO transmit and GRO receive.
type Socket struct {
	conn   *net.UDPConn
	bc     batchConn
	v6     bool
	gso    atomic.Bool
	mtu    int
	onDown func(err error)

	txMsgs []ipv4.Message
	txOOB  []byte

	rxMsgs []ipv4.Message
}

// Open configures a connected or unconnected UDPConn for batching. rxDepth is
// the recvmmsg vector length (16 to 64 is sensible). onDown is invoked once
// if GSO has to be switched off mid-session.
func Open(conn *net.UDPConn, rxDepth int, onDown func(error)) (*Socket, error) {
	if rxDepth < 1 {
		rxDepth = 1
	}
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("udpbatch: not a UDP socket")
	}
	s := &Socket{conn: conn, onDown: onDown}
	s.v6 = la.IP.To4() == nil
	if s.v6 {
		s.bc = ipv6.NewPacketConn(conn)
	} else {
		s.bc = ipv4.NewPacketConn(conn)
	}

	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1); e != nil {
			cerr = fmt.Errorf("udpbatch: UDP_GRO: %w", e)
			return
		}
		// Drop counter delivered as SO_RXQ_OVFL cmsg; the engine's own
		// "0 dropped" cannot see kernel-side socket overflow without it.
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1)
		lvl, opt := unix.IPPROTO_IP, unix.IP_MTU
		if s.v6 {
			lvl, opt = unix.IPPROTO_IPV6, unix.IPV6_MTU
		}
		if m, e := unix.GetsockoptInt(int(fd), lvl, opt); e == nil {
			s.mtu = m // only meaningful on a connected socket
		}
	}); err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}

	s.txMsgs = make([]ipv4.Message, maxSegments)
	s.txOOB = make([]byte, 0, unix.CmsgSpace(segCmsgData))

	s.rxMsgs = make([]ipv4.Message, rxDepth)
	for i := range s.rxMsgs {
		s.rxMsgs[i].Buffers = [][]byte{make([]byte, maxDatagram)}
		s.rxMsgs[i].OOB = make([]byte, 128)
	}
	s.gso.Store(true)
	return s, nil
}

// EnableGSO validates one record size against the route MTU. Call it once the
// socket is connected and W is known. outerHeaders is 28 (IPv4) or 48 (IPv6).
func (s *Socket) EnableGSO(recordSize, outerHeaders int) bool {
	if s.mtu > 0 && recordSize+outerHeaders > s.mtu {
		s.gso.Store(false)
		return false
	}
	s.gso.Store(true)
	return true
}

func (s *Socket) addr(ap netip.AddrPort) *net.UDPAddr {
	if s.v6 {
		// AF_INET6 socket: IPv4 peers must be presented as v4-mapped.
		ap = netip.AddrPortFrom(netip.AddrFrom16(ap.Addr().As16()), ap.Port())
	} else {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return net.UDPAddrFromAddrPort(ap)
}

// Flush transmits the batch. One sendmsg with UDP_SEGMENT when GSO is live,
// one sendmmsg of individual datagrams otherwise. The batch is reset on return.
func (s *Socket) Flush(b *Batch) error {
	if b.segs == 0 {
		return nil
	}
	defer b.reset()
	dst := s.addr(b.dst)

	if b.segs == 1 || !s.gso.Load() {
		return s.writePlain(b, dst)
	}

	s.txOOB = appendSegmentCmsg(s.txOOB[:0], uint16(b.seg))
	s.txMsgs[0] = ipv4.Message{Buffers: [][]byte{b.buf}, OOB: s.txOOB, Addr: dst}
	_, err := s.bc.WriteBatch(s.txMsgs[:1], 0)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.EIO), errors.Is(err, unix.EOPNOTSUPP):
		// EINVAL: segment plus headers exceeds route MTU, or checksum tx is
		// disabled on the socket. EIO: xfrm policy on the route. Neither is
		// transient. Announce, disable, resend unbatched.
		if s.gso.CompareAndSwap(true, false) && s.onDown != nil {
			s.onDown(fmt.Errorf("udpbatch: GSO disabled after sendmsg: %w", err))
		}
		return s.writePlain(b, dst)
	default:
		return err
	}
}

func (s *Socket) writePlain(b *Batch, dst *net.UDPAddr) error {
	n := 0
	for off := 0; off < len(b.buf); off += b.seg {
		end := off + b.seg
		if end > len(b.buf) {
			end = len(b.buf)
		}
		s.txMsgs[n] = ipv4.Message{Buffers: [][]byte{b.buf[off:end]}, Addr: dst}
		n++
	}
	sent := 0
	for sent < n {
		k, err := s.bc.WriteBatch(s.txMsgs[sent:n], 0)
		if err != nil {
			return err
		}
		sent += k
	}
	return nil
}

// Recv performs one recvmmsg and invokes fn once per individual record, in
// arrival order, splitting GRO-coalesced datagrams by their gso_size.
func (s *Socket) Recv(fn func(src netip.AddrPort, rec []byte)) error {
	n, err := s.bc.ReadBatch(s.rxMsgs, 0)
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		m := &s.rxMsgs[i]
		data := m.Buffers[0][:m.N]
		ua, ok := m.Addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		src := ua.AddrPort()
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())

		seg, perr := groSegmentSize(m.OOB[:m.NN])
		if perr != nil {
			return perr
		}
		if seg <= 0 || seg >= len(data) {
			fn(src, data)
			continue
		}
		for off := 0; off < len(data); off += seg {
			end := off + seg
			if end > len(data) {
				end = len(data)
			}
			fn(src, data[off:end])
		}
	}
	return nil
}
```

Transmit call site, showing the seal-before-batch order and the drain flush:

```go
// txLoop: one goroutine per TUN reader shard. seal is the per-session AEAD
// wrapper; it allocates a fresh nonce per record.
func txLoop(tun *TUN, sock *Socket, peer netip.AddrPort, seal func(dst, inner []byte) []byte) error {
	const depth = 64
	inner := make([][]byte, depth)
	for i := range inner {
		inner[i] = make([]byte, 1500)
	}
	sealed := make([]byte, 1500+64)
	batch := NewBatch()

	for {
		n, err := tun.ReadAvailable(inner)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			rec := seal(sealed[:0], inner[i])
			if !batch.Add(peer, rec) {
				if err := sock.Flush(batch); err != nil {
					return err
				}
				batch.Add(peer, rec)
			}
		}
		// ReadAvailable returns on EAGAIN: the TUN queue is empty right now.
		// Flushing here adds zero latency under load and zero delay when idle.
		if err := sock.Flush(batch); err != nil {
			return err
		}
	}
}
```

### 3.3 Deployment matrix (locked)

| Direction | Transmit side | Receive side |
|---|---|---|
| Handset upload | Handset `Flush` with GSO | aicore `Recv` with GRO |
| Handset download | aicore `Flush` with GSO | Handset `Recv` with GRO |

All four cells ship together. Wi-Fi drivers do not advertise `NETIF_F_GSO_UDP_L4`, so handset segmentation is software in `__udp_gso_segment`. That still removes the per-packet `sendmsg`, which is the entire point. GRO effectiveness on the handset depends on the Wi-Fi driver calling `napi_gro_receive` and on burst density within a NAPI poll; aicore-side pacing (Spec D) shapes that burst density. Measure `UdpInDatagrams` versus `recvmmsg` call rate to see the actual coalescing ratio.

On aicore only, where the daemon is root and opens its own tun, add `IFF_VNET_HDR` and `IFF_MULTI_QUEUE` and pass `virtio_net_hdr` TSO/GRO descriptors so the tun side also batches. The handset cannot do this; VpnService hands over a single-queue fd without vnet headers.

---

## 4. Spec B: socket buffers

Two hosts, two different truths.

**aicore.** Stock `net.core.rmem_max` is 212,992 `[V7]`. Every 16 MB request the daemon has been making clamps to 208 KiB and doubles to 416 KiB. At 2 Gbps that is 1.7 ms. This is the buffer that has actually been starving.

```bash
sysctl -w net.core.rmem_max=67108864
sysctl -w net.core.wmem_max=67108864
sysctl -w net.core.netdev_max_backlog=16384
sysctl -w net.core.optmem_max=1048576
```

And in the daemon, because it runs as root, request via the force variant so a missing sysctl cannot silently undo it:

```go
rc.Control(func(fd uintptr) {
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 16<<20)
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, 16<<20)
	got, _ := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	log.Printf("outer socket SO_RCVBUF accounted=%d (payload capacity roughly half)", got)
})
```

Verification on aicore: `nstat -az UdpRcvbufErrors UdpSndbufErrors` before and after a run. Non-zero deltas are kernel-side drops the Go counter never saw.

**Handset.** Request 16 MiB if the mandate wants the number in the code; it is harmless. Log `getsockopt(SO_RCVBUF)`. If it reports 16,777,216, `rmem_max` is 8 MiB and the request was clamped to it; the app cannot go higher without `CAP_NET_ADMIN`. If it reports 524,288, the S25 kernel carries the old 262,144 default, the handset has roughly 2 ms of absorption at 2 Gbps, and the mitigation is not a buffer at all: it is `SO_RXQ_OVFL` visibility, GRO, a dedicated locked reader thread, and aicore pacing.

The BDP anchor everyone accepted: 2 Gbps × 40 ms = 10 MB of payload. Either the 8 MiB request (16 MiB accounted, about 8 MiB usable payload after `truesize`) covers about 33 ms, or the buffer is 512 KiB and nothing short of pacing covers it. `SO_RXQ_OVFL` decides which world we are in.

---

## 5. Spec C: handset fast path

### 5.1 Descriptor ownership

One rule. `establish()` returns a `ParcelFileDescriptor`; Kotlin calls `detachFd()` exactly once, hands the integer to Go, and never touches the descriptor again. Go owns it and closes it. No `adoptFd` anywhere, on any fd, in either direction. The outer UDP socket is created by Go; its fd is handed to Kotlin for `protect()` only, and Kotlin does not wrap it.

```kotlin
class WinnVpnService : VpnService() {

    private var engine: Engine? = null          // gomobile binding
    private var wakeLock: PowerManager.WakeLock? = null
    private var hintSession: PerformanceHintManager.Session? = null

    private val protector = object : Protector {
        override fun protect(fd: Int): Boolean = this@WinnVpnService.protect(fd)
    }

    fun connect(cfg: TunnelConfig) {
        startForeground(NOTIF_ID, buildNotification(),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)

        val pfd = Builder()
            .setSession("Winn")
            .setMtu(cfg.innerMtu)               // computed from PMTU probe and W, default 1373
            .addAddress(cfg.innerAddress, 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(cfg.dns)
            .setBlocking(false)                 // O_NONBLOCK on the tun fd; Go sets it again idempotently
            .establish() ?: throw IllegalStateException("establish() returned null")

        val tunFd = pfd.detachFd()              // ownership moves to Go here, permanently

        val pm = getSystemService(PowerManager::class.java)
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "winn:datapath").apply {
            setReferenceCounted(false)
            acquire()                           // untimed by design: released in disconnect()
        }

        engine = Engine.start(tunFd, cfg.toJson(), protector).also { e ->
            // Go locks each datapath goroutine to an OS thread and reports the tids.
            val tids = e.datapathThreadIds()
            val phm = getSystemService(PerformanceHintManager::class.java)
            hintSession = phm?.createHintSession(tids, 1_000_000L)   // 1 ms per batch target
            e.setWorkReporter { actualNanos -> hintSession?.reportActualWorkDuration(actualNanos) }
        }
    }

    fun disconnect() {
        engine?.stop()                          // Go closes the tun fd and the outer socket
        engine = null
        hintSession?.close()
        hintSession = null
        wakeLock?.takeIf { it.isHeld }?.release()
        wakeLock = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        disconnect()
        stopSelf()
    }
}
```

The untimed partial wake lock stays, as the mandate requests. It keeps the CPU out of suspend. It does nothing about DVFS or core placement; the `PerformanceHintManager` session is what tells the Samsung scheduler that these threads have a deadline `[V8]`.

### 5.2 Go side: pollable TUN, drain-aware reads, sharded writes

```go
package tunnel

import (
	"hash/fnv"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type TUN struct {
	f  *os.File
	rc syscall.RawConn
	fd int
}

// NewTUN takes ownership of fd. It is closed by Close and nowhere else.
func NewTUN(fd int) (*TUN, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	// os.NewFile registers a non-blocking fd with the runtime poller, so reads
	// park the goroutine (not the thread) and Close unparks it with ErrClosed.
	f := os.NewFile(uintptr(fd), "tun")
	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &TUN{f: f, rc: rc, fd: fd}, nil
}

// ReadAvailable reads up to len(out) packets that are already queued, then
// returns on EAGAIN so the caller can flush. If nothing is queued it parks on
// the poller instead of returning zero.
func (t *TUN) ReadAvailable(out [][]byte) (int, error) {
	n := 0
	var rerr error
	err := t.rc.Read(func(fd uintptr) bool {
		for n < len(out) {
			buf := out[n][:cap(out[n])]
			m, e := unix.Read(int(fd), buf)
			switch e {
			case nil:
				out[n] = buf[:m]
				n++
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				return n > 0 // drained: deliver what we have, or park if empty
			default:
				rerr = e
				return true
			}
		}
		return true
	})
	if rerr != nil {
		return n, rerr
	}
	return n, err
}

// Write injects one decrypted inner packet. tun_chr_write_iter does not
// return EAGAIN; it copies into an skb and hands it to netif_rx.
func (t *TUN) Write(pkt []byte) error {
	for {
		_, err := unix.Write(t.fd, pkt)
		if err == unix.EINTR {
			continue
		}
		return err
	}
}

func (t *TUN) Close() error { return t.f.Close() }

// flowShard returns a stable shard index for an inner IPv4 or IPv6 packet so
// one flow never crosses writer threads. Reordering inside a flow costs the
// inner TCP a DSACK exchange per event; this removes the cause.
func flowShard(pkt []byte, shards int) int {
	if shards <= 1 || len(pkt) < 20 {
		return 0
	}
	h := fnv.New32a()
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		h.Write(pkt[12:20])
		if (pkt[9] == 6 || pkt[9] == 17) && len(pkt) >= ihl+4 {
			h.Write(pkt[ihl : ihl+4])
		}
	case 6:
		if len(pkt) < 40 {
			return 0
		}
		h.Write(pkt[8:40])
		if (pkt[6] == 6 || pkt[6] == 17) && len(pkt) >= 44 {
			h.Write(pkt[40:44])
		}
	}
	return int(h.Sum32() % uint32(shards))
}
```

Receive fan-out, with each writer locked to an OS thread so its tid can be given to ADPF:

```go
func (e *Engine) rxLoop(sock *udpbatch.Socket, open func(dst, rec []byte) ([]byte, bool)) {
	rings := make([]chan []byte, e.writers)
	for i := range rings {
		rings[i] = make(chan []byte, 1024)
		go func(ring chan []byte) {
			runtime.LockOSThread()
			e.registerTid(unix.Gettid())
			for pkt := range ring {
				if err := e.tun.Write(pkt); err != nil {
					e.fail(err)
					return
				}
				e.pool.Put(pkt)
			}
		}(rings[i])
	}
	runtime.LockOSThread()
	e.registerTid(unix.Gettid())
	for {
		err := sock.Recv(func(_ netip.AddrPort, rec []byte) {
			buf := e.pool.Get()
			plain, ok := open(buf[:0], rec)
			if !ok {
				e.pool.Put(buf)
				return
			}
			rings[flowShard(plain, e.writers)] <- plain
		})
		if err != nil {
			for _, r := range rings {
				close(r)
			}
			e.fail(err)
			return
		}
	}
}
```

Each TUN write still costs one syscall per inner packet; nothing on Android changes that. What changes is that the outer socket costs one syscall per 43 packets, the reader parks on the poller instead of spinning or blocking a thread, and writers scale across `netif_rx` backlogs without reordering.

---

## 6. Spec D: Double VPN routing on aicore

### 6.1 Model

Hop 1 terminates on `winn3gw0`. The decrypted inner packet is forwarded by the kernel into one of four exit tunnels. Hop 2 encrypts it fresh. Tunnel overheads do not add. Set every exit tunnel MTU to the same inner MTU as `winn3gw0` and the clamp is 1333 (IPv4) or 1313 (IPv6), once, and only on SYN.

### 6.2 Exit selection: pool per exit, four static rules

Forwarded skbs carry no socket and no mark, so per-session `SO_MARK` cannot steer them. Per-client `ip rule from <ip>/32` works but costs a netlink round trip per session and a growing rule chain. The locked design gives each exit a client pool. The daemon assigns an inner address from the pool that matches the client's chosen exit at handshake, and the rule set never changes.

| Exit | Device | Table | Client pool | aicore inner address on exit |
|---|---|---|---|---|
| Kansas Core | `wg-kc` | 101 | 10.11.0.0/24 | 10.200.1.2 |
| Canada ca1 | `wg-ca1` | 102 | 10.12.0.0/24 | 10.200.2.2 |
| Germany de1 | `wg-de1` | 103 | 10.13.0.0/24 | 10.200.3.2 |
| Spain | `wg-es` | 104 | 10.14.0.0/24 | 10.200.4.2 |
| Single VPN | WAN | main | 10.10.0.0/24 | (public IP) |

Each exit table ends in `unreachable default`. A Double VPN pool must never fall through to the main table and leave through the WAN as a single hop; that is a privacy failure, not a degraded mode.

### 6.3 NAT: none, when we control the exit

We control all four exits. Each exit's peer entry for aicore gets `AllowedIPs = 10.200.N.2/32, 10.1N.0.0/24`, and the exit performs its own SNAT to its public address, which it must do anyway. aicore then forwards with no conntrack and no NAT on the Double VPN path. That is the largest CPU saving on aicore after GSO.

If an exit's configuration cannot be changed, the fallback is a static `snat to 10.200.N.2` for that exit only, with conntrack enabled for that pool and a flowtable to keep the per-packet cost out of the netfilter slow path. MASQUERADE is rejected everywhere.

### 6.4 Script

```bash
#!/bin/sh
# aicore: Double VPN forwarding, zero NAT on the double path, stateless
# forward filter, MSS clamp on SYN, pacing on the WAN NIC.
set -eu

WAN="eth0"
WAN_IP="$(ip -4 -o addr show dev "$WAN" scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)"
INNER_MTU=1373

# name  device  table  pool
EXITS="
kc  wg-kc  101 10.11.0.0/24
ca1 wg-ca1 102 10.12.0.0/24
de1 wg-de1 103 10.13.0.0/24
es  wg-es  104 10.14.0.0/24
"

# 1. Sysctls. rp_filter takes max(all, dev); forwarding takes OR(all, dev).
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.all.forwarding=1
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv4.conf.all.rp_filter=2
sysctl -q -w net.ipv4.conf.default.rp_filter=2
sysctl -q -w net.ipv4.ip_forward_use_pmtu=1
sysctl -q -w net.core.rmem_max=67108864
sysctl -q -w net.core.wmem_max=67108864
sysctl -q -w net.core.netdev_max_backlog=16384
sysctl -q -w net.core.optmem_max=1048576

# 2. Tunnel MTUs and queue depth. A tun ptr_ring is txqueuelen deep (500 by
#    default, 3 ms at 170 kpps). Raise it.
ip link set dev winn3gw0 mtu "$INNER_MTU" txqueuelen 10000
sysctl -q -w net.ipv4.conf.winn3gw0.rp_filter=2

# 3. Per-exit tables and pool rules. Source-based rules also satisfy strict
#    rp_filter on the return path, because fib_validate_source consults the
#    same rules with the reply's destination as source.
echo "$EXITS" | while read -r name dev table pool; do
    [ -z "$name" ] && continue
    ip link set dev "$dev" mtu "$INNER_MTU"
    sysctl -q -w "net.ipv4.conf.${dev}.rp_filter=2"
    ip route flush table "$table" 2>/dev/null || true
    ip route add default dev "$dev" table "$table" metric 100
    ip route add unreachable default table "$table" metric 200
    ip rule del from "$pool" lookup "$table" 2>/dev/null || true
    ip rule add from "$pool" lookup "$table" pref "$((1000 + table))"
done

# 4. nftables. Double pools are stateless and untracked. Single VPN
#    (10.10.0.0/24) is tracked, SNATed to the static WAN address, and
#    offloaded to a software flowtable after the handshake.
nft -f - <<'EOF'
flush ruleset

define DOUBLE_POOLS = { 10.11.0.0/24, 10.12.0.0/24, 10.13.0.0/24, 10.14.0.0/24 }
define EXIT_DEVS    = { "wg-kc", "wg-ca1", "wg-de1", "wg-es" }

table inet winn {
    flowtable single_ft {
        hook ingress priority 0
        devices = { winn3gw0, eth0 }
    }

    chain raw_pre {
        type filter hook prerouting priority raw; policy accept;
        iifname "winn3gw0" ip saddr $DOUBLE_POOLS notrack
        iifname $EXIT_DEVS notrack
    }

    chain mangle_fwd {
        type filter hook forward priority mangle; policy accept;
        tcp flags syn tcp option maxseg size set rt mtu
    }

    chain fwd {
        type filter hook forward priority filter; policy drop;

        # Double VPN: pool to its exit and back. Stateless by design.
        iifname "winn3gw0" ip saddr $DOUBLE_POOLS oifname $EXIT_DEVS accept
        iifname $EXIT_DEVS ip daddr $DOUBLE_POOLS oifname "winn3gw0" accept

        # Single VPN through the WAN, tracked, offloaded once established.
        iifname "winn3gw0" ip saddr 10.10.0.0/24 oifname "eth0" ip protocol { tcp, udp } flow add @single_ft
        iifname "winn3gw0" ip saddr 10.10.0.0/24 oifname "eth0" accept
        iifname "eth0" oifname "winn3gw0" ct state established,related ip protocol { tcp, udp } flow add @single_ft
        iifname "eth0" oifname "winn3gw0" ct state established,related accept

        # No client-to-client, no pool-to-WAN leak. Policy drop covers both.
    }

    chain nat_post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" ip saddr 10.10.0.0/24 snat ip to WAN_IP_PLACEHOLDER
    }
}
EOF
nft replace rule inet winn nat_post handle "$(nft -a list chain inet winn nat_post | awk '/snat/ {print $NF}')" \
    oifname "$WAN" ip saddr 10.10.0.0/24 snat ip to "$WAN_IP"

# 5. Qdiscs. fq on the WAN NIC paces the daemon's outer UDP socket via
#    SO_MAX_PACING_RATE (set in the daemon). Forwarded packets have no socket,
#    so fq cannot pace them: tunnel devices get fq_codel instead.
tc qdisc replace dev "$WAN" root fq limit 20000 flow_limit 1000
tc qdisc replace dev winn3gw0 root fq_codel
echo "$EXITS" | while read -r name dev table pool; do
    [ -z "$name" ] && continue
    tc qdisc replace dev "$dev" root fq_codel
done
```

Two notes on that file.

The `nft replace rule` step exists because nft define blocks do not interpolate shell variables; it swaps the placeholder for the real static WAN address after load. If aicore ever loses its static address, that rule becomes a `masquerade` on `eth0` only, never on an exit tunnel.

The clamp `tcp option maxseg size set rt mtu` acts on SYN in both directions and reads the outgoing route MTU, which is the exit tunnel's 1373 for the double path and the WAN's 1500 for the single path. Flowtable offload never sees a SYN, so the clamp and the fast path coexist.

### 6.5 Pacing in the daemon

`fq` paces a UDP socket only if that socket sets a rate. On aicore's Hop 1 transmit socket:

```go
rc.Control(func(fd uintptr) {
	// 1.9 Gbps ceiling per outer socket. A 43-segment GSO burst is then spread
	// rather than emitted as a 240 us line-rate spike into the handset's AP.
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MAX_PACING_RATE, 237_500_000)
})
```

That is the "FQ qdisc pacing" the mandate asked for, placed where it works: the physical egress, keyed by the local socket. On `winn3gw0` in forwarding mode `fq` would degrade to a hashed FIFO, which is why the script does not put it there.

---

## 7. Spec E: ingress demux on aicore

Three protocols, two transports.

**XRay fallback** is TCP (VLESS with Reality on 443). It is its own listener and its own process. It shares nothing with the UDP fast path and must not be threaded through the Winn daemon; an XRay TCP path will not reach 1.8 Gbps and is not expected to.

**Winn v3 and Winn v1 AWG** are both UDP. The locked position is distinct ports. AWG runs best as the `amneziawg` kernel module, which binds its own socket inside the kernel and cannot participate in userspace demux. Forcing AWG through the Winn v3 daemon's socket would pull AWG traffic into userspace and lose the kernel path for no gain.

If product policy requires a single UDP port for both (a censorship-resistance requirement, not a performance one), the demux belongs in the kernel, not in the daemon:

1. Both daemons (Winn v3 and `amneziawg-go`) bind the same port with `SO_REUSEPORT`.
2. A `BPF_PROG_TYPE_SK_REUSEPORT` program attached with `SO_ATTACH_REUSEPORT_EBPF` reads the first four bytes of the UDP payload and selects the socket index from a `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` `[V9]`. AWG data packets carry the configured `H4` type value; Winn v3 records carry whatever the (still undocumented) Winn v3 header puts first. The program needs a per-tenant table of AWG type values because AWG randomizes them per config.
3. Cost: one map lookup per datagram in softirq, well under 100 ns. No userspace involvement.

Either way, within the Winn v3 daemon itself, aicore should open N `SO_REUSEPORT` sockets (one per worker thread) so the kernel's 4-tuple hash spreads clients across cores. GRO coalesces per socket and per 5-tuple, so a client's records are never interleaved with another protocol's.

The Winn v3 record layout must be documented in the repository before the demux program can be written. That is the same missing fact that blocks the ceiling in Section 2, and it is the single most important deliverable of the next work day.

---

## 8. Remaining disagreement

None on design. What remains is measurement, and the council should say so plainly rather than manufacture a dispute.

* W, the Winn v3 overhead. Determines the ceiling, the GSO segment size, and the raised MTU.
* `rmem_max` on the S25 kernel. Determines whether the handset buffer is 8 MiB accounted or 256 KiB.
* Whether the 2.47 Gbps baseline crossed the WAN.
* Whether the exit tunnels' peer configurations can be edited to carry `AllowedIPs` for the pools (they can; we own them; the question is only who runs the change).

Sol Pro's fourth correction (that routing versus SNAT depends on undisclosed route tables) is resolved by Spec D's design decision rather than by discovery: we choose the route tables, and we choose pure routing.

---

## 9. Verification tags

Each item must be checked against source or a live system before the code in this document is merged.

* `[V1]` `net/ipv4/devinet.c`, `inet_select_addr`: confirm selection ignores prefix length.
* `[V2]` `net/netfilter/nf_nat_masquerade.c`, `masq_device_event`: confirm conntrack flush on `NETDEV_DOWN`.
* `[V3]` `net/ipv4/udp.c`, `udp_send_skb`: confirm `EINVAL` when `hlen + gso_size > cork->fragsize`.
* `[V4]` `net/ipv4/udp.c`, `UDP_MAX_SEGMENTS` value on the aicore kernel and on the S25 GKI kernel.
* `[V5]` `adb shell cat /proc/sys/net/core/rmem_max` on the S25.
* `[V6]` `net/ipv4/udp.c`, `__udp_cmsg_send` (expects `__u16`) and `udp_cmsg_recv` (emits `int`).
* `[V7]` `sysctl net.core.rmem_max` on aicore as currently running.
* `[V8]` `PerformanceHintManager.createHintSession` availability and behavior on the S25's One UI build.
* `[V9]` `SO_ATTACH_REUSEPORT_EBPF` with `sk_reuseport_md.data` giving UDP payload access on the aicore kernel.

---

## 10. Vote

**Podium 4 votes to lock.** Target restated at 1,800 Mbps pending W. Specs A through E as written above, with the concessions in Section 1 recorded against my Stage 1 and Stage 2 submissions, and the two Opus mechanisms in 1.3 struck from the record while their conclusions stand.
