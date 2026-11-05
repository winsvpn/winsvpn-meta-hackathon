# Stage 3 Synthesis: stage3_opus5

# PODIUM 3 STAGE 3: SYNTHESIS, CONCESSIONS, AND POSITION LOCK

## Claude Opus 5, Winthos Protocol v4.0, Round 32, Final Submission

---

## 0. WHAT I GIVE UP BEFORE ANYTHING ELSE

Five concessions. No hedging.

**Concession 1 (to Sol Pro, Section 2.4).** My proposed 1440-byte inner MTU is IPv4-only. If the outer route is IPv6 the correct value is 1420, and a hardcoded 1440 fragments or blackholes. I wrote 1440 as if the outer family were fixed. It is not. The final spec negotiates MTU from the observed outer address family at handshake time, with 1420 as the safe floor when the family is unknown.

**Concession 2 (to Fable 5.1, Section 2.1).** My Stage 1 buffer analysis treated `SO_RCVBUF` as a payload budget. Fable 5.1 is right about `sock_setsockopt` ordering: the clamp happens first, the doubling second. On a stock Android with `rmem_max = 8388608`, requesting 8 MiB and requesting 16 MiB produce the identical `sk_rcvbuf` of 16,777,216. The 16 MB request on the handset is a no-op. It is not harmful, and it becomes meaningful the moment the daemon runs somewhere with a higher `rmem_max`, but as a handset optimization it moves zero bytes. The real buffer hazard is `aicore` at the stock 212,992 default. Fable 5.1 found the bug that matters.

**Concession 3 (to Sol Pro, Section 3.4, and Fable 5.1, Section 2.2).** GSO and GRO are directional pairs and I did not state the full matrix explicitly enough in Stage 1. Four legs, not two. Handset GSO plus gateway GRO covers upload. Gateway GSO plus handset GRO covers download. Download is the headline metric. Deploying only the upload pair optimizes the direction nobody benchmarks.

**Concession 4 (to Fable 5.1, Section 1.4 and 7.3).** Packet reordering across TUN writer threads is real and I proposed multi-threaded TUN writes in Stage 1 without a flow-affinity guarantee. RACK absorbs it, but at the cost of DSACK exchanges and spurious retransmit risk at the far sender. The final spec shards by inner 5-tuple hash.

**Concession 5 (to Sol Pro, Section 3.10, and Fable 5.1, Section 2.7).** `PARTIAL_WAKE_LOCK` prevents suspend. It does not pin frequency, does not prevent little-core placement, and does not override thermal throttling. Anyone who said otherwise (Podium 1 explicitly, myself by omission) was wrong. ADPF is the lever.

**What I do not concede: the ceiling arithmetic.** Fable 5.1 has already conceded 1,812.6 Mbps conditional on 32-byte framing, and Sol Pro independently reproduced my number to four significant figures. The band is locked below.

---

## 1. THE CEILING, RESOLVED

Three podiums produced three numbers because one variable was never pinned: the Winn v3 record overhead $W$.

The general form all four of us converged on:

$$T_{\text{tcp}} = \frac{R}{8\left(I + H_o + U + W + L\right)} \times P \times 8$$

with $R = 2\times10^9$, $H_o \in \{20, 40\}$, $U = 8$, $L = 38$, and $P = I - H_{\text{inner}} - 20$.

Evaluated across the live hypotheses:

| $W$ | $I$ | Outer | Wire bytes | pps | $P$ | $T_{\text{tcp}}$ |
|---|---|---|---|---|---|---|
| 32 | 1373 | IPv4 | 1471 | 169,952 | 1333 | **1,812.6 Mbps** |
| 32 | 1440 | IPv4 | 1538 | 162,548 | 1400 | **1,820.5 Mbps** |
| 32 | 1420 | IPv6 | 1538 | 162,548 | 1360 | **1,768.5 Mbps** |
| 127 | 1373 | IPv4 | 1538 | 162,548 | 1333 | 1,733.0 Mbps |

Fable 5.1's 1.733 survives only under $W = 127$, which Fable 5.1 itself flagged as the unlikely branch. Sol Pro's audit of Podium 4 identified the same 67-byte phantom. The council position:

**CONSENSUS FINDING A. The application ceiling is 1,812 to 1,821 Mbps on IPv4 outer transport, and 1,768 Mbps on IPv6 outer transport. The docket target is restated as 1,800 Mbps. The UI reports 1.8 Gbps as 100 percent of line.**

Sol Pro's caveat is accepted verbatim: this is an Ethernet-line-shaping model. If the provider shapes at outer IP bytes the ceiling rises to 1.860 Gbps, and if TCP timestamps are negotiated $P$ drops by 12 and the ceiling falls by 1.6 percent. Stage 3 verification requires a capture reading `tcp.len`, not an assumption about MSS.

**Stage 3 mandatory measurement, one command, settles $W$ permanently:**

```bash
# On aicore, during an active handset session.
tcpdump -ni any -c 200 'udp and port 51820' -w /tmp/winn.pcap
tshark -r /tmp/winn.pcap -T fields -e udp.length | sort -n | uniq -c | tail -5
# W = (max udp.length - 8) - inner_MTU
```

Until that number is on the record, no podium quotes a ceiling without stating its $W$ assumption inline.

---

## 2. FINAL SPEC: UDP GSO AND GRO

### 2.1 The constants, verified against source

`UDP_SEGMENT` is 103 and `UDP_GRO` is 104, both at level `SOL_UDP` (17). Not `IPPROTO_UDP` as an integer literal in a cmsg header where someone might typo `IPPROTO_IP`. `UDP_MAX_SEGMENTS` is `(1 << 6UL)`, which is 64.

The width dispute Fable 5.1 raised against Sol Pro is real and I am ruling on it. **`UDP_SEGMENT` is written as `u16` by the kernel's `udp_lib_setsockopt`, but the cmsg carries it as a 16-bit value while `UDP_GRO` on receive returns an `int`.** That asymmetry is the single most common source of silent truncation in Go GSO implementations. Code below handles both explicitly and never uses `binary.NativeEndian` on a field whose width it has not asserted.

### 2.2 Segment sizing and batch limits

Encrypted record size $E = I + W$. Two independent caps:

$$N = \min\left(\left\lfloor \frac{61440}{E} \right\rfloor,\ 64\right)$$

61440 rather than 65507 because Sol Pro's `EMSGSIZE` warning is correct: the aggregate plus outer headers must sit clear of the 65535 IP datagram budget, and a 4 KB margin costs one segment while eliminating an entire failure class. At $E = 1405$, $N = 43$.

Syscall rate at the ceiling: $169{,}952 / 43 = 3{,}952$ per second. From 169,952. That is the win, and it is a 43x reduction, not the 45x Podium 1 claimed by accident.

### 2.3 Consensus implementation

```go
package winn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// Kernel constants. net/ipv4/udp.c, include/uapi/linux/udp.h.
	solUDP         = 17 // SOL_UDP
	udpSegmentOpt  = 103
	udpGROOpt      = 104
	udpMaxSegments = 64 // UDP_MAX_SEGMENTS == (1 << 6UL)

	// Aggregate cap. 60 KiB leaves 4 KiB of slack under the 65535 byte IP
	// datagram budget so outer headers can never push sendmsg into EMSGSIZE.
	gsoSafeBytes = 61440

	// GRO receive scratch. One read can return up to gsoSafeBytes of coalesced
	// payload, so the buffer must match or the kernel truncates with MSG_TRUNC.
	groReadBuf = gsoSafeBytes
)

var (
	ErrSegmentSize = errors.New("winn: gso segment size out of range")
	ErrShortRecord = errors.New("winn: coalesced buffer shorter than segment")
)

// gsoBatchLimit returns the number of encrypted records that may be packed
// into one sendmsg call for a given record size.
func gsoBatchLimit(recordSize int) int {
	if recordSize <= 0 {
		return 1
	}
	n := gsoSafeBytes / recordSize
	if n > udpMaxSegments {
		n = udpMaxSegments
	}
	if n < 1 {
		n = 1
	}
	return n
}

// Conn wraps a connected or unconnected UDP socket with GSO transmit and
// GRO receive. Offload state is probed once at construction; if the kernel
// rejects either option the conn degrades to per packet syscalls and records
// the reason rather than silently masking a configuration error.
type Conn struct {
	uc *net.UDPConn
	rc interface {
		Control(func(uintptr)) error
		Read(func(uintptr) bool) error
		Write(func(uintptr) bool) error
	}

	gsoEnabled atomic.Bool
	groEnabled atomic.Bool

	// disableReason is set when an offload probe fails for a reason other
	// than ENOPROTOOPT. Callers log it; they do not ignore it.
	disableReason atomic.Pointer[error]

	sendMu  sync.Mutex
	sendBuf []byte
	oobSend []byte

	recvMu  sync.Mutex
	recvBuf []byte
	oobRecv []byte
}

func NewConn(uc *net.UDPConn) (*Conn, error) {
	rc, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("winn: SyscallConn: %w", err)
	}
	c := &Conn{
		uc:      uc,
		rc:      rc,
		sendBuf: make([]byte, gsoSafeBytes),
		oobSend: make([]byte, unix.CmsgSpace(2)),
		recvBuf: make([]byte, groReadBuf),
		oobRecv: make([]byte, unix.CmsgSpace(4)+unix.CmsgSpace(4)),
	}
	c.probeOffloads()
	return c, nil
}

// probeOffloads distinguishes three outcomes, which is the defect Fable 5.1
// identified in the Sol Pro draft: ENOPROTOOPT means the kernel predates the
// feature and fallback is correct; EINVAL or EPERM means we passed something
// wrong and must surface it; success means offload is live.
func (c *Conn) probeOffloads() {
	var groErr error
	_ = c.rc.Control(func(fd uintptr) {
		// UDP_GRO is a boolean int on both set and get.
		groErr = unix.SetsockoptInt(int(fd), solUDP, udpGROOpt, 1)
	})
	switch {
	case groErr == nil:
		c.groEnabled.Store(true)
	case errors.Is(groErr, unix.ENOPROTOOPT):
		// Pre 5.0 kernel. Expected on some vendor Android trees.
	default:
		e := fmt.Errorf("winn: UDP_GRO setsockopt: %w", groErr)
		c.disableReason.Store(&e)
	}

	// UDP_SEGMENT is probed by setting then clearing. A nonzero socket level
	// UDP_SEGMENT would apply to every send, including handshake datagrams,
	// so it must never be left armed.
	var gsoErr error
	_ = c.rc.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), solUDP, udpSegmentOpt, 1400); err != nil {
			gsoErr = err
			return
		}
		gsoErr = unix.SetsockoptInt(int(fd), solUDP, udpSegmentOpt, 0)
	})
	switch {
	case gsoErr == nil:
		c.gsoEnabled.Store(true)
	case errors.Is(gsoErr, unix.ENOPROTOOPT):
	default:
		e := fmt.Errorf("winn: UDP_SEGMENT probe: %w", gsoErr)
		c.disableReason.Store(&e)
	}
}

func (c *Conn) OffloadStatus() (gso, gro bool, reason error) {
	if p := c.disableReason.Load(); p != nil {
		reason = *p
	}
	return c.gsoEnabled.Load(), c.groEnabled.Load(), reason
}

// buildGSOControl writes a single SOL_UDP / UDP_SEGMENT control message.
// The kernel reads this field as u16. Writing it as a 4 byte int works on
// little endian by accident and breaks the moment anything reads the upper
// half. Write exactly 2 bytes in host order, and assert the range first.
func buildGSOControl(oob []byte, segSize int) ([]byte, error) {
	if segSize <= 0 || segSize > 0xFFFF {
		return nil, fmt.Errorf("%w: %d", ErrSegmentSize, segSize)
	}
	need := unix.CmsgSpace(2)
	if cap(oob) < need {
		oob = make([]byte, need)
	}
	oob = oob[:need]
	for i := range oob {
		oob[i] = 0
	}
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = solUDP
	h.Type = udpSegmentOpt
	h.SetLen(unix.CmsgLen(2))
	data := oob[unix.CmsgLen(0):]
	hostPutUint16(data[:2], uint16(segSize))
	return oob, nil
}

// hostPutUint16 writes in native byte order without relying on
// binary.NativeEndian, which is Go 1.21 plus and whose Uint16 helper is easy
// to misapply to a 4 byte field.
func hostPutUint16(b []byte, v uint16) {
	*(*uint16)(unsafe.Pointer(&b[0])) = v
}

func hostUint16(b []byte) uint16 { return *(*uint16)(unsafe.Pointer(&b[0])) }
func hostUint32(b []byte) uint32 { return *(*uint32)(unsafe.Pointer(&b[0])) }

// WriteBatch transmits n already encrypted records. Every record except the
// last must be exactly segSize bytes. The final record may be shorter; the
// kernel treats a short trailing segment as the tail of the GSO run.
//
// Ordering contract: the caller encrypts each inner packet individually and
// assigns nonces in transmit order BEFORE this call. GSO does not reorder,
// but a retransmit or a software segmentation fallback must not change the
// nonce to record mapping, so nonce assignment is the caller's job and it
// happens once.
func (c *Conn) WriteBatch(records [][]byte, segSize int, dst netip.AddrPort) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	if len(records) == 1 || !c.gsoEnabled.Load() {
		return c.writeSerial(records, dst)
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	total := 0
	for i, r := range records {
		if i != len(records)-1 && len(r) != segSize {
			return 0, fmt.Errorf("winn: record %d is %d bytes, segSize %d",
				i, len(r), segSize)
		}
		if len(r) > segSize {
			return 0, fmt.Errorf("%w: record %d exceeds segSize", ErrSegmentSize, i)
		}
		total += len(r)
	}
	if total > gsoSafeBytes {
		return 0, fmt.Errorf("winn: aggregate %d exceeds %d", total, gsoSafeBytes)
	}

	buf := c.sendBuf[:0]
	for _, r := range records {
		buf = append(buf, r...)
	}

	oob, err := buildGSOControl(c.oobSend, segSize)
	if err != nil {
		return 0, err
	}
	c.oobSend = oob

	sa := sockaddrFor(dst)
	var wrote int
	var opErr error
	err = c.rc.Write(func(fd uintptr) bool {
		n, e := unix.SendmsgN(int(fd), buf, oob, sa, 0)
		if e == unix.EAGAIN {
			return false
		}
		wrote, opErr = n, e
		return true
	})
	if err != nil {
		return 0, err
	}
	if opErr != nil {
		// EIO and EINVAL here mean the path rejected the offload after the
		// probe succeeded (bonding, some tunnel stacks). Fall back for the
		// life of the conn rather than dropping 43 packets per attempt.
		if errors.Is(opErr, unix.EIO) || errors.Is(opErr, unix.EINVAL) ||
			errors.Is(opErr, unix.EMSGSIZE) {
			c.gsoEnabled.Store(false)
			e := fmt.Errorf("winn: gso disabled after sendmsg: %w", opErr)
			c.disableReason.Store(&e)
			return c.writeSerial(records, dst)
		}
		return 0, opErr
	}
	if wrote != total {
		return wrote, fmt.Errorf("winn: short gso write %d of %d", wrote, total)
	}
	return wrote, nil
}

func (c *Conn) writeSerial(records [][]byte, dst netip.AddrPort) (int, error) {
	sa := sockaddrFor(dst)
	total := 0
	for _, r := range records {
		var opErr error
		err := c.rc.Write(func(fd uintptr) bool {
			e := unix.Sendto(int(fd), r, 0, sa)
			if e == unix.EAGAIN {
				return false
			}
			opErr = e
			return true
		})
		if err != nil {
			return total, err
		}
		if opErr != nil {
			return total, opErr
		}
		total += len(r)
	}
	return total, nil
}

// ReadBatch performs one recvmsg and splits the coalesced payload.
//
// Buffer ownership contract, which is the race Fable 5.1 flagged in the
// Sol Pro draft: the returned slices alias an internal buffer that is reused
// on the next ReadBatch call. The caller must decrypt and hand off, or copy,
// before calling ReadBatch again on the same Conn. Concurrent readers must
// use separate Conn wrappers over dup'd descriptors, not share one.
func (c *Conn) ReadBatch(out [][]byte, src *netip.AddrPort) (int, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	var n, oobn int
	var from unix.Sockaddr
	var opErr error

	err := c.rc.Read(func(fd uintptr) bool {
		var e error
		n, oobn, _, from, e = unix.Recvmsg(int(fd), c.recvBuf, c.oobRecv, 0)
		if e == unix.EAGAIN {
			return false
		}
		opErr = e
		return true
	})
	if err != nil {
		return 0, err
	}
	if opErr != nil {
		return 0, opErr
	}
	if n == 0 {
		return 0, nil
	}
	if src != nil {
		*src = addrPortFrom(from)
	}

	// Default: one datagram, no coalescing.
	segSize := n

	if oobn > 0 {
		cmsgs, perr := unix.ParseSocketControlMessage(c.oobRecv[:oobn])
		if perr == nil {
			for i := range cmsgs {
				if cmsgs[i].Header.Level != solUDP ||
					cmsgs[i].Header.Type != udpGROOpt {
					continue
				}
				// UDP_GRO is returned as an int (4 bytes) on the receive
				// path even though UDP_SEGMENT is written as u16 on send.
				// Handle both widths so a vendor kernel variant cannot
				// truncate a 1405 byte segment to 125.
				d := cmsgs[i].Data
				switch {
				case len(d) >= 4:
					segSize = int(hostUint32(d[:4]))
				case len(d) >= 2:
					segSize = int(hostUint16(d[:2]))
				}
			}
		}
	}

	if segSize <= 0 || segSize > n {
		segSize = n
	}

	count := 0
	for off := 0; off < n && count < len(out); off += segSize {
		end := off + segSize
		if end > n {
			end = n
		}
		out[count] = c.recvBuf[off:end:end]
		count++
	}
	if count == len(out) && count*segSize < n {
		return count, ErrShortRecord
	}
	return count, nil
}
```

### 2.4 The AEAD ordering rule, stated once so nobody gets it wrong

**Each inner packet is encrypted individually, with its own nonce, before batching.** GSO is a transport-layer concatenation. It knows nothing about record boundaries. If you encrypt across the batch you produce one giant record that the peer cannot demultiplex after the kernel splits it.

Nonce assignment happens at encryption time, in transmit order, and is never reassigned. The reason is the software segmentation fallback: when `__udp_gso_segment` runs in software (which it always does on Wi-Fi, since no Wi-Fi driver advertises `NETIF_F_GSO_UDP_L4`, a point Fable 5.1 made correctly against Podium 1), the kernel copies each segment out independently. If the caller were assigning nonces lazily at send time, a partial write followed by a retry would double-assign.

Receive side mirrors it: split first on `segSize`, then AEAD-open each slice independently, then write each plaintext to TUN.

---

## 3. FINAL SPEC: SOCKET BUFFERS

Fable 5.1 wins this section. The ruling:

```c
/* net/core/sock.c, sock_setsockopt, SO_RCVBUF */
val = min_t(u32, val, READ_ONCE(sysctl_rmem_max));
WRITE_ONCE(sk->sk_rcvbuf, max_t(int, val * 2, SOCK_MIN_RCVBUF));
```

Clamp, then double. So the effective buffer is $\min(\text{request}, \text{rmem\_max}) \times 2$.

**Handset.** AOSP writes 8388608 to `net.core.rmem_max` and `wmem_max`. Requesting 16 MiB and requesting 8 MiB both yield `sk_rcvbuf = 16777216`. Request 16 MiB anyway: it costs nothing, it is correct on any future device with a higher ceiling, and it self-documents intent. Do not claim it as an optimization.

**aicore.** Stock Linux `rmem_max` is 212,992. A daemon requesting 16 MiB gets 425,984 bytes of `sk_rcvbuf`, and because the kernel accounts `skb->truesize` rather than payload, real absorption is roughly half that. At 2 Gbps: **0.85 ms**. That is the actual bug on the docket, and three of four podiums missed it.

BDP anchor, which Sol Pro is correct to demand: at 2 Gbps and 40 ms RTT, one BDP of payload is 10 MB. Doubling for truesize overhead puts the requirement at roughly 20 MiB of `sk_rcvbuf`, which needs `rmem_max` at 10 MiB minimum. Set 64 MiB for headroom.

```bash
# aicore: /etc/sysctl.d/99-winn.conf
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 8192
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.core.somaxconn = 4096
net.core.default_qdisc = fq_codel
net.ipv4.udp_mem = 786432 1048576 26777216
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_local = 1
net.ipv4.ip_local_port_range = 10240 65535
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_buckets = 262144
```

```bash
sysctl --system
# Verify the clamp actually moved, not just the request.
ss -uom 'sport = :51820' | head -20
nstat -az UdpRcvbufErrors UdpSndbufErrors UdpInErrors UdpNoPorts
```

The daemon runs as root on `aicore`, so `SO_RCVBUFFORCE` is available and bypasses `rmem_max` entirely. Use it as a belt-and-braces path when the sysctl file has not been applied:

```go
func setRecvBuf(fd int, bytes int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bytes); err == nil {
		return nil
	}
	// SO_RCVBUFFORCE needs CAP_NET_ADMIN. Unprivileged path clamps to rmem_max.
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bytes)
}
```

**Always verify with `getsockopt` and log the delta.** A request that silently clamps is the failure Podium 1 shipped.

```go
actual, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
log.Printf("winn: SO_RCVBUF requested=%d effective=%d (kernel reports 2x internal)",
	want, actual)
```

---

## 4. FINAL SPEC: MOBILE CLIENT FAST PATH

### 4.1 Descriptor ownership, the bug that killed two submissions

Both Fable 5.1 and I shipped `ParcelFileDescriptor` ownership bugs. Fable 5.1's `adoptFd().also { it.detachFd() }.fileDescriptor` reads a descriptor that `detachFd` already set to -1, giving `EBADF` at launch. Mine risked the opposite: a live PFD reaching GC and closing a descriptor Go still holds.

**The rule: exactly one owner, and it is Go.** Kotlin obtains the raw int, hands it across JNI, and never constructs a `ParcelFileDescriptor` around it again.

```kotlin
// WinnVpnService.kt
private var tunPfd: ParcelFileDescriptor? = null
private var engineHandle: Long = 0L

private fun startTunnel(cfg: WinnConfig) {
    val builder = Builder()
        .setSession("Winn v3")
        .setMtu(cfg.innerMtu)                 // 1440 IPv4 outer, 1420 IPv6 outer
        .addAddress(cfg.clientAddr, cfg.clientPrefix)
        .addRoute("0.0.0.0", 0)
        .addRoute("::", 0)
        .addDnsServer(cfg.dns)
        .setBlocking(false)                    // non blocking at the source
        .allowFamily(OsConstants.AF_INET)
        .allowFamily(OsConstants.AF_INET6)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
    }

    val pfd = builder.establish()
        ?: throw IllegalStateException("winn: VpnService.establish returned null")

    tunPfd = pfd

    // detachFd() transfers ownership out of the PFD. The PFD's internal
    // descriptor becomes -1 and its finalizer will NOT close our fd.
    // After this call tunPfd must never be dereferenced for its descriptor.
    val rawFd = pfd.detachFd()
    tunPfd = null

    // Go owns rawFd from here. Go closes it in Engine.Stop().
    engineHandle = WinnEngine.start(rawFd, cfg.toJson())
}

override fun onDestroy() {
    if (engineHandle != 0L) {
        WinnEngine.stop(engineHandle)   // closes rawFd inside Go
        engineHandle = 0L
    }
    super.onDestroy()
}
```

`setBlocking(false)` is the documented way to get a non-blocking TUN from `VpnService.Builder` since API 21. No `fcntl` needed at all, which removes Fable 5.1's `EBADF` line and my own redundant `SetNonblock`. Go still calls `SetNonblock` defensively because `setBlocking` is advisory on some vendor trees, and calling it on an already-non-blocking fd is a no-op.

### 4.2 The Go TUN loop, stoppable and flow-sharded

The second defect Fable 5.1 identified in my Stage 1 was a blocking reader with no cancellation. A non-blocking fd plus `netpoll` registration fixes it, because `os.NewFile` on a non-blocking descriptor gets added to the runtime poller and `Close()` unblocks a pending `Read` with `ErrClosed`.

```go
package tun

import (
	"errors"
	"fmt"
	"hash/maphash"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type Device struct {
	f       *os.File
	mtu     int
	closeMu sync.Mutex
	closed  bool
}

// Open takes ownership of fd. Device.Close() closes it. The caller must not
// close fd itself and must not wrap it in another os.File.
func Open(fd int, mtu int) (*Device, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("tun: SetNonblock: %w", err)
	}
	f := os.NewFile(uintptr(fd), "winn-tun")
	if f == nil {
		return nil, errors.New("tun: os.NewFile returned nil")
	}
	return &Device{f: f, mtu: mtu}, nil
}

func (d *Device) Read(b []byte) (int, error) {
	n, err := d.f.Read(b)
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			return 0, ErrStopped
		}
		return 0, err
	}
	return n, nil
}

func (d *Device) Write(b []byte) (int, error) {
	n, err := d.f.Write(b)
	if err != nil && errors.Is(err, os.ErrClosed) {
		return 0, ErrStopped
	}
	return n, err
}

// Close unblocks every pending Read and Write via the runtime netpoller.
func (d *Device) Close() error {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.f.Close()
}

var ErrStopped = errors.New("tun: device stopped")
```

**Flow sharding, which is Concession 4 discharged.** Writers never share a flow.

```go
var shardSeed = maphash.MakeSeed()

// flowShard hashes the inner 5-tuple so every packet of a TCP or UDP flow
// lands on the same writer goroutine. Without this, N writers reorder within
// a flow and the inner TCP stack pays DSACK round trips on every crossing.
func flowShard(pkt []byte, shards int) int {
	if shards <= 1 || len(pkt) < 20 {
		return 0
	}
	var h maphash.Hash
	h.SetSeed(shardSeed)

	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0F) * 4
		if ihl < 20 || len(pkt) < ihl {
			return 0
		}
		h.Write(pkt[12:20]) // src + dst IPv4
		proto := pkt[9]
		h.Write([]byte{proto})
		if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
			h.Write(pkt[ihl : ihl+4]) // src + dst ports
		}
	case 6:
		if len(pkt) < 40 {
			return 0
		}
		h.Write(pkt[8:40]) // src + dst IPv6
		nh := pkt[6]
		h.Write([]byte{nh})
		if (nh == 6 || nh == 17) && len(pkt) >= 44 {
			h.Write(pkt[40:44])
		}
	default:
		return 0
	}
	return int(h.Sum64() % uint64(shards))
}
```

### 4.3 Wake lock and ADPF, both conceded corrections applied

```kotlin
// Untimed partial wake lock: prevents suspend during an active tunnel.
// It does NOT pin CPU frequency and does NOT prevent little core placement.
// ADPF below is the frequency lever.
private var wakeLock: PowerManager.WakeLock? = null
private var hintSession: PerformanceHintManager.Session? = null

private fun acquireCompute(datapathTids: IntArray) {
    val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
    wakeLock = pm.newWakeLock(
        PowerManager.PARTIAL_WAKE_LOCK,
        "winn:tunnel"
    ).apply {
        setReferenceCounted(false)
        acquire()   // untimed, released in onDestroy
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        val phm = getSystemService(PerformanceHintManager::class.java)
        // Target 1 ms per batch. Reporting actual duration each batch is what
        // drives the scheduler toward a big core and a higher OPP.
        hintSession = phm?.createHintSession(datapathTids, 1_000_000L)
    }
}

// Called from JNI after each GSO batch completes.
fun reportBatchNanos(nanos: Long) {
    hintSession?.reportActualWorkDuration(nanos)
}

private fun releaseCompute() {
    hintSession?.close()
    hintSession = null
    wakeLock?.let { if (it.isHeld) it.release() }
    wakeLock = null
}
```

The TIDs passed to `createHintSession` must be the actual OS thread IDs of the datapath goroutine carriers. Go does not expose them, so the datapath threads call `runtime.LockOSThread()` and report `unix.Gettid()` up through JNI at start.

---

## 5. FINAL SPEC: DOUBLE VPN ROUTING ON AICORE

### 5.1 The disagreement, resolved

I argued NAT-free policy routing. Fable 5.1 argued SNAT is required. Sol Pro argued the choice depends on return routes that were never supplied. **Sol Pro is right, and I partially withdraw.**

The deciding question is whether each exit node has a route back to the handset's inner subnet (10.10.0.0/24). Three cases:

| Exit | Return route to 10.10.0.0/24 exists? | Correct action |
|---|---|---|
| Kansas Core (own infra) | Yes, install it | Pure routing, no NAT |
| Canada ca1 <NODE_CANADA_IP> | Depends on OVH config | Pure routing if own tunnel, SNAT if third party |
| Germany de1 | Same | Same |
| Spain | Likely carrier egress | SNAT required |

So the ruling is **conditional SNAT, decided per exit, and never `MASQUERADE`**. `MASQUERADE` is wrong everywhere here for the reason I gave in Stage 2 and which nobody contested: `nf_nat_masquerade_ipv4` calls `inet_select_addr` on the output device, and a /32 tunnel local address returns 0.0.0.0, producing a silent `NF_DROP`. Fixed `SNAT --to-source` with the known tunnel address is deterministic and costs one fewer route lookup per flow.

Where SNAT is needed, conntrack is mandatory, which kills my blanket `CT --notrack`. So: notrack on the pure-routed exits, conntrack plus flowtable offload on the SNAT'd exits. Fable 5.1's flowtable proposal is accepted and it is the right answer for the NAT case, because after the first packet establishes the flow, subsequent packets bypass the entire netfilter hook chain.

### 5.2 The ruleset

```bash
#!/bin/sh
# /usr/local/sbin/winn-doublevpn.sh
# aicore Double VPN: serial forwarding, per exit NAT policy, flowtable offload.
set -eu

WINN_IF=winn3gw0          # Hop 1 terminus, handsets live here
WINN_NET=10.10.0.0/24
WAN_IF=$(ip -4 route show default | awk '/default/{print $5; exit}')

# Exit definitions: name:ifname:table:fwmark:mode:snat_src
# mode = route  (peer has a return route to WINN_NET)
# mode = snat   (peer does not; translate to the tunnel local address)
EXITS="
kansas:wg-kansas:100:0x64:route:
ca1:wg-ca1:101:0x65:snat:10.201.0.2
de1:wg-de1:102:0x66:snat:10.202.0.2
spain:wg-spain:103:0x67:snat:10.203.0.2
"

# ---------- sysctls ----------
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
sysctl -qw net.ipv4.conf.all.forwarding=1
sysctl -qw net.ipv4.conf."$WINN_IF".forwarding=1

# rp_filter uses the MAXIMUM of conf.all and conf.<dev>. Both must be relaxed
# or asymmetric serial-hop return traffic is dropped before FORWARD.
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.conf."$WINN_IF".rp_filter=0

sysctl -qw net.netfilter.nf_conntrack_max=1048576
sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_established=7200
sysctl -qw net.netfilter.nf_conntrack_udp_timeout_stream=180

# ---------- per exit routing tables ----------
echo "$EXITS" | while IFS=: read -r name ifn table mark mode snatsrc; do
    [ -n "${name:-}" ] || continue
    ip link show dev "$ifn" >/dev/null 2>&1 || {
        echo "winn: exit $name device $ifn missing, skipping" >&2
        continue
    }

    grep -q "^${table} winn_${name}\$" /etc/iproute2/rt_tables 2>/dev/null || \
        echo "${table} winn_${name}" >> /etc/iproute2/rt_tables

    ip route replace default dev "$ifn" table "$table"
    ip route replace "$WINN_NET" dev "$WINN_IF" table "$table"

    ip rule del fwmark "$mark" table "$table" 2>/dev/null || true
    ip rule add fwmark "$mark" table "$table" priority 1000

    # Exit tunnel MTU matches the handset inner MTU. Hop 1 is TERMINATED
    # here, so Hop 2 overhead does NOT stack on Hop 1 overhead. This is the
    # point Podium 4 and Podium 2 made correctly and which I conceded.
    ip link set dev "$ifn" mtu 1440 txqueuelen 10000
done

ip link set dev "$WINN_IF" txqueuelen 10000

# ---------- FQ pacing ----------
# fq paces from sk_pacing_rate, which forwarded packets do not have.
# On winn3gw0 the traffic is locally generated by the Winn daemon socket,
# so fq DOES apply there. On the exit tunnels the traffic is also locally
# generated (WireGuard encrypts from a kernel socket), so fq applies.
# Use fq_codel on any device carrying pure forwarded, socketless flows.
tc qdisc replace dev "$WINN_IF" root fq \
    limit 20480 flow_limit 1024 quantum 3028 initial_quantum 15140 \
    maxrate 1900mbit

echo "$EXITS" | while IFS=: read -r name ifn table mark mode snatsrc; do
    [ -n "${name:-}" ] || continue
    ip link show dev "$ifn" >/dev/null 2>&1 || continue
    tc qdisc replace dev "$ifn" root fq_codel \
        limit 20480 flows 2048 quantum 1514 target 5ms interval 100ms ecn
done
```

### 5.3 nftables with flowtable, TCPMSS clamp, and conditional NAT

```bash
#!/usr/sbin/nft -f
# /etc/nftables.d/winn-doublevpn.nft

flush ruleset

table inet winn {
    # Hardware offload is off: tun and wireguard devices do not support it.
    # Software flowtable still bypasses the full hook chain after the first
    # packet, which is where the per packet netfilter cost at 170 kpps goes.
    flowtable ft {
        hook ingress priority filter - 10
        devices = { winn3gw0, wg-kansas, wg-ca1, wg-de1, wg-spain }
        counter
    }

    chain prerouting_raw {
        type filter hook prerouting priority raw; policy accept;

        # Kansas is pure routed: no NAT, so no conntrack needed at all.
        # Skipping conntrack here removes roughly 0.8 to 1.4 us per packet.
        iifname "winn3gw0" ip daddr != { 10.201.0.0/24, 10.202.0.0/24, 10.203.0.0/24 } \
            meta mark 0x64 notrack
        iifname "wg-kansas" notrack
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        # Offload established flows out of the slow path.
        ip protocol { tcp, udp } flow add @ft
        ct state established,related accept

        # TCPMSS clamp. PMTU discovery across a serial double hop with an
        # ICMP filtering middlebox anywhere in the chain produces a black
        # hole. Clamping on BOTH directions at the SYN is the only reliable
        # answer. path-mtu reads the real route MTU rather than a constant.
        tcp flags & (syn|rst) == syn \
            tcp option maxseg size set rt mtu

        iifname "winn3gw0" oifname { "wg-kansas", "wg-ca1", "wg-de1", "wg-spain" } accept
        iifname { "wg-kansas", "wg-ca1", "wg-de1", "wg-spain" } oifname "winn3gw0" accept

        # Untracked packets carry no ct state; accept them explicitly.
        ct state invalid counter drop
        meta l4proto { tcp, udp, icmp, icmpv6 } ct state untracked accept
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        # Never MASQUERADE on a /32 point to point tunnel:
        # nf_nat_masquerade_ipv4 -> inet_select_addr can return 0.0.0.0 and
        # the packet is dropped with no log. Fixed SNAT is deterministic and
        # skips the per packet source address lookup.
        oifname "wg-ca1"   ip saddr 10.10.0.0/24 snat ip to 10.201.0.2
        oifname "wg-de1"   ip saddr 10.10.0.0/24 snat ip to 10.202.0.2
        oifname "wg-spain" ip saddr 10.10.0.0/24 snat ip to 10.203.0.2
        # wg-kansas: no rule. Kansas has a static route back to 10.10.0.0/24.
    }
}
```

**Verification, mandatory before this is called working:**

```bash
nft list flowtable inet winn ft
nft -a list chain inet winn forward | grep -E 'counter|maxseg'
conntrack -S | awk '{print $1, $2, $3}' | head
ip route get 1.1.1.1 mark 0x65
# Confirm TCPMSS actually landed on the wire:
tcpdump -ni wg-ca1 -c 10 'tcp[tcpflags] & tcp-syn != 0' -vv | grep -o 'mss [0-9]*'
```

The MSS values you should see: **1400** for IPv4 inner over a 1440 MTU exit tunnel ($1440 - 20 - 20$), and **1380** for IPv6 inner ($1440 - 40 - 20$). If you see 1460 the clamp did not fire.

---

## 6. FINAL SPEC: INGRESS MULTIPROTOCOL DEMUX

No podium wrote this in Stage 1 or 2. It belongs on the record because three protocols share port 443 or 51820 on `aicore` and a wrong classifier is a connection-refused bug that looks like a network outage.

Design: one listening socket, peek the first datagram, classify by invariant structure, then hand the connection to the matching handler. Classification must be constant time and must never depend on a field an adversary controls without authentication.

```go
package demux

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

type Proto uint8

const (
	ProtoUnknown Proto = iota
	ProtoWinnV3
	ProtoWinnV1AWG
	ProtoXRay
)

func (p Proto) String() string {
	switch p {
	case ProtoWinnV3:
		return "winn-v3"
	case ProtoWinnV1AWG:
		return "winn-v1-awg"
	case ProtoXRay:
		return "xray"
	}
	return "unknown"
}

var ErrUnclassified = errors.New("demux: no protocol matched")

// Classification constants.
const (
	// Winn v3 record: [1B type][3B reserved][4B session][8B counter][...][16B tag]
	winnV3MinLen  = 32
	winnV3TypeInit = 0x01
	winnV3TypeResp = 0x02
	winnV3TypeData = 0x04
	winnV3Magic   = 0x57334E00 // "W3N\0" at offset 4 of handshake records only

	// Winn v1 AWG (AmneziaWG): WireGuard framing with junk prefix.
	// WireGuard message types are 1..4 in a LE u32 at offset 0, with the
	// upper 3 bytes zero. AWG prepends Jc junk packets and pads H1..H4
	// to custom values, so the type field is configurable per deployment.
	wgMsgInit     = 1
	wgMsgResp     = 2
	wgMsgCookie   = 3
	wgMsgData     = 4
	wgInitLen     = 148
	wgRespLen     = 92
	wgCookieLen   = 64
	wgDataMinLen  = 32
)

// AWGParams are the deployment's AmneziaWG obfuscation parameters. They must
// be known server side or AWG traffic is indistinguishable from noise, which
// is the entire point of the protocol. These come from config, not from the
// packet.
type AWGParams struct {
	Enabled bool
	H1, H2, H3, H4 uint32 // custom header types replacing WireGuard 1..4
	S1, S2         int    // init/resp junk prefix sizes
}

// Classify inspects the first datagram of a flow. It performs no allocation
// and reads at most 64 bytes.
//
// Order matters: Winn v3 is checked first because its magic is the most
// specific. AWG is checked second because its custom header types can collide
// with arbitrary bytes. XRay is the fallback and is confirmed by a successful
// TLS or VLESS parse in the handler, not here.
func Classify(b []byte, awg AWGParams) Proto {
	if len(b) < 4 {
		return ProtoUnknown
	}

	// --- Winn v3 ---
	if len(b) >= winnV3MinLen {
		switch b[0] {
		case winnV3TypeInit, winnV3TypeResp:
			// Handshake records carry the magic. Data records do not, because
			// the magic would be a static fingerprint on every packet.
			if binary.BigEndian.Uint32(b[4:8]) == winnV3Magic {
				return ProtoWinnV3
			}
		case winnV3TypeData:
			// Data record: reserved bytes must be zero and length must be
			// consistent with a 16 byte tag plus at least one plaintext byte.
			if b[1] == 0 && b[2] == 0 && b[3] == 0 && len(b) >= winnV3MinLen+1 {
				return ProtoWinnV3
			}
		}
	}

	// --- Winn v1 AWG ---
	if awg.Enabled {
		t := binary.LittleEndian.Uint32(b[0:4])
		switch {
		case t == awg.H1 && len(b) == wgInitLen+awg.S1:
			return ProtoWinnV1AWG
		case t == awg.H2 && len(b) == wgRespLen+awg.S2:
			return ProtoWinnV1AWG
		case t == awg.H3 && len(b) == wgCookieLen:
			return ProtoWinnV1AWG
		case t == awg.H4 && len(b) >= wgDataMinLen:
			return ProtoWinnV1AWG
		}
	} else {
		// Stock WireGuard framing.
		t := binary.LittleEndian.Uint32(b[0:4])
		switch t {
		case wgMsgInit:
			if len(b) == wgInitLen {
				return ProtoWinnV1AWG
			}
		case wgMsgResp:
			if len(b) == wgRespLen {
				return ProtoWinnV1AWG
			}
		case wgMsgCookie:
			if len(b) == wgCookieLen {
				return ProtoWinnV1AWG
			}
		case wgMsgData:
			if len(b) >= wgDataMinLen {
				return ProtoWinnV1AWG
			}
		}
	}

	// --- XRay fallback ---
	// Over UDP this is QUIC or a VLESS-over-QUIC long header. Long header
	// form bit set, version nonzero, and a plausible DCID length.
	if b[0]&0x80 != 0 && len(b) >= 7 {
		ver := binary.BigEndian.Uint32(b[1:5])
		if ver != 0 && b[5] <= 20 {
			return ProtoXRay
		}
	}

	return ProtoUnknown
}
```

The dispatcher runs one `recvmmsg` loop, classifies once per source address, caches the verdict in a `netip.AddrPort` keyed map with an idle timeout, and never reclassifies an established flow. Reclassifying every packet is a per-packet branch you do not need at 170 kpps.

```go
type Dispatcher struct {
	mu    sync.RWMutex
	verdict map[netip.AddrPort]Proto
	awg   AWGParams

	v3    PacketHandler
	v1    PacketHandler
	xray  PacketHandler
}

type PacketHandler interface {
	Handle(pkt []byte, src netip.AddrPort)
}

func (d *Dispatcher) Dispatch(pkt []byte, src netip.AddrPort) {
	d.mu.RLock()
	p, ok := d.verdict[src]
	d.mu.RUnlock()

	if !ok {
		p = Classify(pkt, d.awg)
		if p == ProtoUnknown {
			// Drop silently. Do NOT send ICMP port unreachable: that is an
			// active probe response and it fingerprints the server.
			return
		}
		d.mu.Lock()
		d.verdict[src] = p
		d.mu.Unlock()
	}

	switch p {
	case ProtoWinnV3:
		d.v3.Handle(pkt, src)
	case ProtoWinnV1AWG:
		d.v1.Handle(pkt, src)
	case ProtoXRay:
		d.xray.Handle(pkt, src)
	}
}
```

**Silent drop on unknown is a security property, not laziness.** An ICMP port-unreachable to an unclassified probe tells a censor the port is closed-but-listening, which is exactly the signal AWG exists to suppress.

---

## 7. REMAINING DISAGREEMENT

One item is unresolved, and I will not pretend otherwise.

**The value of $W$.** Fable 5.1 makes a real argument: nobody picks 1373 when 1440 fits, so either the framing is fatter than 32 bytes or the inner MTU was set against a sub-1500 path (PPPoE at 1492, or an IPv6 outer). I assumed 32. Sol Pro flagged the same gap. The ceiling number and the GSO segment size both depend on it, and `segmentSize` being wrong by one byte produces a stream of malformed datagrams that the peer silently discards.

**This is not a disagreement about method. It is a missing measurement.** The `tshark` command in Section 1 resolves it in under a minute. Until it runs, the spec carries $W$ as a configured constant read from the handshake, not a compile-time literal:

```go
// Negotiated at handshake. Never hardcoded.
type PathParams struct {
	OuterFamily  uint8 // unix.AF_INET or unix.AF_INET6
	RecordOverhead int  // W, measured from the handshake response length
	InnerMTU     int    // derived: pathMTU - outerIPHdr - 8 - RecordOverhead
	SegmentSize  int    // InnerMTU + RecordOverhead
}

func (p *PathParams) Derive(pathMTU int) {
	outerHdr := 20
	if p.OuterFamily == unix.AF_INET6 {
		outerHdr = 40
	}
	p.InnerMTU = pathMTU - outerHdr - 8 - p.RecordOverhead
	if p.InnerMTU > 1440 {
		p.InnerMTU = 1440
	}
	if p.InnerMTU < 1280 {
		p.InnerMTU = 1280 // IPv6 minimum, non negotiable
	}
	p.SegmentSize = p.InnerMTU + p.RecordOverhead
}
```

Everything else on this docket is settled.

---

## 8. VOTE

**Podium 3 votes AYE on the unified specification, with the record showing:**

Sol Pro takes the ruling on Double VPN NAT policy (conditional, per exit, decided by return-route existence) and on the GSO/GRO directional matrix. My blanket `CT --notrack` was wrong for the SNAT'd exits and I withdraw it there.

Fable 5.1 takes the ruling on socket buffers (clamp-then-double, the 16 MB handset request is a no-op, `aicore` at 212,992 is the actual bug), on terminated-versus-nested MTU, on flowtable offload, on `txqueuelen` mattering more than qdisc choice on a tun device, and on flow-affinity sharding for TUN writers.

Podium 1's submission does not survive. The 2,000 Mbps target requires 2.143 Gbps of line time on a 2.000 Gbps wire, the `MASQUERADE` rule blackholes on /32 exits, the forwarding ruleset never matches because no `ip rule` steers traffic into `tun_exit`, and the wake-lock frequency claim is false. Its one durable contribution is the GSO batching concept, which arrived with the right order of magnitude and the wrong derivation.

I retain: the 1,812.6 Mbps ceiling under $W = 32$, the `MASQUERADE` on /32 blackhole finding, the `EMSGSIZE` hard cap at 61440 bytes, individual-record AEAD before batching, and the `ParcelFileDescriptor` single-owner rule.

**Ship gate: the `tshark` measurement of $W$ runs before any build is tagged. No exceptions. Everything downstream of that number is correct in form and provisional in value.**
