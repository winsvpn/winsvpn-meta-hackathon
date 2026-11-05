# Stage 1 Submission: stage1_opus5

# PODIUM 3 DETERMINATION: ROUND 32
## Claude Opus 5, Winthos Permanent Presidential Debate Protocol v4.0

---

## 0. VERDICT UP FRONT

Four findings, stated without hedging:

**Finding A.** The 2,000 Mbps target is mathematically unreachable as stated. At inner MTU 1373 over a 2 Gbps Ethernet WAN, the hard physical ceiling for inner TCP payload is **1,812.6 Mbps**. Anyone promising 2.0 Gbps of usable throughput is promising a violation of framing arithmetic. Derivation in Section 1.

**Finding B.** The 1,345 Mbps SpeedBench number and the 637 Mbps Ookla number are not in conflict. They measure different things. Until SpeedBench is proven to terminate past the WAN edge rather than on the 10 Gbps LAN, Round 31's headline result is a LAN loopback figure, not a VPN wire-speed figure. This is the single largest methodological hazard on the docket.

**Finding C.** The remaining gap on Single VPN is not a buffer sizing problem. It is a topology problem. The LocalSocket relay between Go and Kotlin is still in the datapath. Kill it. Pass the raw TUN descriptor into Go via `ParcelFileDescriptor.detachFd()`. Expected delta: 1.0 to 2.0 microseconds per packet, which alone moves 1,345 Mbps to roughly 1,740 Mbps.

**Finding D.** For Double VPN, routing the decapsulated packet through `winn3gw0` into the kernel forwarding path and back out through a second TUN read is a 2.9 microsecond per packet tax for zero benefit on the fast path. Build an in-process userspace crossover. Single core capacity goes from roughly 278 kpps to roughly 1.18 Mpps.

The 60 microsecond spin-wait on TUN EAGAIN is a defect. It burns core time proportional to the EAGAIN rate and adds jitter. Section 2.6 replaces it.

---

## 1. LEVEL 3: THE FRAMING ARITHMETIC THAT BOUNDS EVERYTHING

### 1.1 Symbol table

| Symbol | Meaning | Value |
|---|---|---|
| `L_wan` | WAN path MTU | 1500 B |
| `O_ip4` | IPv4 header | 20 B |
| `O_udp` | UDP header | 8 B |
| `O_w3` | Winn v3 AEAD framing (type 4 + index 4 + counter 8 + Poly/GCM tag 16) | 32 B |
| `O_eth` | Ethernet L2 header + FCS | 18 B |
| `O_phy` | Preamble + SFD + interframe gap | 20 B |
| `M_i` | Inner MTU presented to the handset | 1373 B |
| `R` | WAN line rate | 2.0e9 bit/s |

### 1.2 Wire efficiency

Outer datagram size:

```
S_outer = M_i + O_w3 + O_udp + O_ip4 = 1373 + 32 + 8 + 20 = 1433 B
```

Bytes actually consumed on the physical medium per packet:

```
S_wire = S_outer + O_eth + O_phy = 1433 + 18 + 20 = 1471 B
```

Maximum frame rate:

```
f_max = R / (8 * S_wire) = 2.0e9 / 11768 = 169,952 frames/s
```

Inner IP goodput ceiling:

```
T_ip = f_max * M_i * 8 = 169,952 * 10984 = 1,866.8 Mbps
```

Inner TCP payload ceiling (MSS = 1373 - 20 - 20 = 1333):

```
T_tcp = f_max * 1333 * 8 = 1,812.6 Mbps
```

**The 2,000 Mbps goal is 10.3 percent above the physical ceiling.** Restate the mandate as 1,812 Mbps and the engineering problem becomes tractable.

### 1.3 What raising the inner MTU buys

If Single VPN drops to inner MTU 1440 (the largest value that keeps `S_outer` at exactly 1500 for an IPv4 outer):

```
S_wire = 1500 + 38 = 1538 B
f_max  = 2.0e9 / 12304 = 162,548 frames/s
T_tcp  = 162,548 * 1400 * 8 = 1,820.5 Mbps
```

Goodput rises only 0.44 percent. But frame rate drops **4.36 percent**, and frame rate is what costs CPU. That is a free 4.36 percent reduction in per-packet syscall, AEAD-setup, and skb-allocation load. Take it on Single VPN. You cannot take it on Double VPN (Section 3).

### 1.4 The per-packet time budget

Define `C_pkt` as the total datapath core-time consumed per inner packet, summed across every core that touches it. Then:

```
pps = (K * u) / C_pkt
```

where `K` is the number of participating cores and `u` their mean utilization on the datapath.

Round 31 measured 1,345.38 Mbps download. Inner packet rate:

```
pps_meas = 1.34538e9 / (1373 * 8) = 122,479 pps
```

To reach the 1,866.8 Mbps inner IP ceiling requires 169,952 pps. The required cut:

```
ΔC / C = 1 - (122,479 / 169,952) = 27.9 percent
```

If the pipeline currently runs at `K*u = 1.0` core-equivalent, `C_pkt = 8.165 us`. Target: **5.884 us**. You must find 2.28 microseconds.

### 1.5 Where the 8.165 microseconds live (download path, current architecture)

| Stage | Cost estimate | Notes |
|---|---|---|
| 1. `recvmmsg` from WAN UDP socket, batch 32 | 0.25 us | syscall amortized + 1433 B copy |
| 2. AEAD decrypt, ChaCha20-Poly1305, Go arm64 | 1.70 us | Poly1305 has no arm64 assembly in x/crypto; it is generic Go over `math/bits` |
| 3. Copy into Kotlin batch accumulator | 0.15 us | |
| 4. AF_UNIX LocalSocket write plus read (two memcpys) | 0.30 us | 1433 B each way at roughly 10 GB/s |
| 5. JVM frame parse, bounds checks, ByteBuffer slicing, allocation pressure | 1.00 us | wide variance, GC-coupled |
| 6. `write()` to TUN fd | 1.20 us | syscall + seccomp filter + `tun_get_user` + skb alloc + `netif_rx` + Android cgroup eBPF ingress/egress hooks |
| 7. Inner kernel IP/TCP receive processing | 2.20 us | the app's own TCP stack, not removable |
| 8. Scheduler wakeup and cache-miss overhead | 1.37 us | residual |
| **Total** | **8.17 us** | matches the measurement |

Stages 3, 4, 5 are pure architectural waste: **1.45 us**. Stage 2 is 1.44 us of avoidable cipher cost. Together they exceed the 2.28 us requirement.

### 1.6 The cipher determination

Go's `crypto/cipher` AES-GCM on arm64 compiles to the `gcm_arm64.s` path using AESE/AESMC and PMULL. Measured on Oryon-class cores it lands in the 3 to 5 GB/s range per core. `golang.org/x/crypto/chacha20poly1305` on arm64 uses NEON for ChaCha20 but falls back to portable Go for Poly1305 (there is `sum_amd64.s`, `sum_ppc64x.s`, `sum_s390x.s`, and generic elsewhere). Net combined throughput sits near 0.7 to 1.0 GB/s.

That is a **4x to 5x** spread.

**Recommendation:** add AEAD negotiation to the Winn v3 handshake. Advertise `AEAD_AES_256_GCM` when both peers report hardware AES. Keep ChaCha20-Poly1305 as the mandatory-to-implement fallback for peers without AES extensions. Do not hardcode either.

Verify before you commit. Run this on the target handset, not on a laptop:

```go
// bench_aead_test.go
func BenchmarkAEADSeal(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	pt := make([]byte, 1373)
	dst := make([]byte, 0, 1373+16)

	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	cc, _ := chacha20poly1305.New(key)

	b.Run("aes256gcm", func(b *testing.B) {
		b.SetBytes(int64(len(pt)))
		for i := 0; i < b.N; i++ {
			dst = gcm.Seal(dst[:0], nonce, pt, nil)
		}
	})
	b.Run("chacha20poly1305", func(b *testing.B) {
		b.SetBytes(int64(len(pt)))
		for i := 0; i < b.N; i++ {
			dst = cc.Seal(dst[:0], nonce, pt, nil)
		}
	})
}
```

If AES-256-GCM does not beat ChaCha by at least 2.5x on this silicon, discard this recommendation. Measure, do not assume.

---

## 2. SINGLE VPN: EXACT CHANGES, RANKED BY EXPECTED DELTA

### 2.1 Change 1: Eliminate the LocalSocket relay (highest value)

The Go engine and the Kotlin `VpnService` live in the same process. There is no reason for a unix domain socket between them. Hand the descriptor across once, at establish time, and never again.

**Kotlin diff:**

```diff
--- a/app/src/main/java/org/winsvpn/core/WinnVpnService.kt
+++ b/app/src/main/java/org/winsvpn/core/WinnVpnService.kt
@@
     private fun bringUpTunnel(profile: Profile) {
         val builder = Builder()
             .setSession("Winn v3")
-            .setMtu(1373)
+            .setMtu(profile.innerMtu)          // 1440 for single hop, 1373 for double hop
             .addAddress("10.10.0.14", 32)
             .addRoute("0.0.0.0", 0)
             .addRoute("::", 0)
             .allowFamily(OsConstants.AF_INET)
             .allowFamily(OsConstants.AF_INET6)
+            .setBlocking(true)
 
-        val pfd = builder.establish() ?: error("establish() returned null")
-        tunInterface = pfd
-        relayThread = Thread({ runLocalSocketRelay(pfd) }, "winn-tun-relay").apply {
-            priority = Thread.MAX_PRIORITY
-            start()
-        }
-        engineSocketPath = "winn-tun-${Process.myPid()}"
-        WinnEngine.startWithLocalSocket(engineSocketPath, profile.toJson())
+        val pfd = builder.establish() ?: error("establish() returned null")
+        // Ownership transfers to the Go engine. Do not close, do not wrap in any
+        // stream, do not touch this integer again from Kotlin.
+        val rawTunFd = pfd.detachFd()
+        tunInterface = null
+
+        // Pin the outer datagram path to the Wi-Fi transport explicitly so the
+        // system cannot silently migrate it to cellular mid-transfer.
+        val cm = getSystemService(ConnectivityManager::class.java)
+        val wifi = cm.activeNetwork
+        setUnderlyingNetworks(if (wifi != null) arrayOf(wifi) else null)
+
+        WinnEngine.attachTun(rawTunFd, profile.innerMtu)
+        WinnEngine.start(profile.toJson())
     }
 
+    /**
+     * Invoked from the Go engine over JNI for every outer UDP socket it opens,
+     * before connect(). Keeps the encrypted datagrams outside the tunnel.
+     */
+    @Keep
+    fun protectOuterSocket(fd: Int): Boolean {
+        val ok = protect(fd)
+        if (!ok) return false
+        val cm = getSystemService(ConnectivityManager::class.java)
+        cm.activeNetwork?.let {
+            runCatching { it.bindSocket(ParcelFileDescriptor.adoptFd(fd).fileDescriptor) }
+        }
+        return true
+    }
+
+    /**
+     * Invoked from the Go engine once per datapath OS thread, with the Linux tid.
+     * Zygote raises RLIMIT_NICE for app processes, so an app may lower its own
+     * threads to the urgent-audio band. Failures are non-fatal.
+     */
+    @Keep
+    fun boostDatapathThread(tid: Int) {
+        runCatching {
+            Process.setThreadPriority(tid, Process.THREAD_PRIORITY_URGENT_AUDIO)
+        }
+    }
```

Delete `runLocalSocketRelay`, the 1 MB accumulator, and the 8 MB `LocalSocket` buffer configuration entirely. They are now dead weight.

**Go side, descriptor adoption:**

```go
// tun_android.go
package winn

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// TunDevice wraps an Android VpnService descriptor. The descriptor is opened by
// the framework as IFF_TUN|IFF_NO_PI with no virtio net header, so segmentation
// offload is unavailable and every write carries exactly one IP packet.
type TunDevice struct {
	rfd int // blocking, owned by the reader thread
	wfd int // dup of rfd, blocking, owned by the writer thread
	mtu int
}

func AttachTun(fd int, mtu int) (*TunDevice, error) {
	wfd, err := unix.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("dup tun fd: %w", err)
	}
	// Blocking descriptors plus dedicated OS threads. No epoll round trip, no
	// Go netpoller registration, no spin loop.
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(wfd)
		return nil, err
	}
	if err := unix.SetNonblock(wfd, false); err != nil {
		unix.Close(wfd)
		return nil, err
	}
	return &TunDevice{rfd: fd, wfd: wfd, mtu: mtu}, nil
}

func (t *TunDevice) Close() error {
	unix.Close(t.wfd)
	return unix.Close(t.rfd)
}
```

Reads and writes on a tun descriptor are independent. Duplicating gives each direction its own thread without contention on the file position lock.

**Expected delta:** stages 3, 4, 5 removed. `C_pkt` drops from 8.17 us to approximately 6.72 us. Throughput: 122,479 pps to 148,900 pps, or **1,635 Mbps**.

### 2.2 Change 2: UDP GSO on transmit, UDP GRO on receive

This is the correct answer for the WAN socket and it is unavailable on the TUN side of Android.

Kernel facts that govern the implementation, and one asymmetry people get wrong:

- `UDP_SEGMENT` (SOL_UDP option 103) on **send** takes a `__u16` in the control message. `udp_cmsg_send()` rejects any `cmsg_len` other than `CMSG_LEN(sizeof(__u16))`.
- `UDP_GRO` (SOL_UDP option 104) on **receive** emits an `int` (4 bytes) via `put_cmsg()` in `udp_cmsg_recv()`.

Two bytes out, four bytes in. Parse accordingly.

- The kernel caps a GSO write at 64 KB total and at `UDP_MAX_SEGMENTS` segments. Do not exceed either.
- Software GSO works even with no NIC support. The syscall amortization is the win, not the hardware offload.

```go
// gso_linux.go
package winn

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	solUDP         = 17
	optUDPSegment  = 103 // include/uapi/linux/udp.h UDP_SEGMENT
	optUDPGRO      = 104 // include/uapi/linux/udp.h UDP_GRO
	udpMaxSegments = 128 // net/ipv4/udp.c UDP_MAX_SEGMENTS
	gsoMaxBytes    = 65535 - 28
)

type OffloadCaps struct {
	TX bool
	RX bool
}

// EnableUDPOffload probes both directions. A zero-valued UDP_SEGMENT set is the
// standard capability probe: the per-sendmsg control message overrides it, which
// lets a single socket emit different segment sizes per batch.
func EnableUDPOffload(c *net.UDPConn) (caps OffloadCaps, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return caps, err
	}
	cerr := rc.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), solUDP, optUDPSegment, 0); e == nil {
			caps.TX = true
		}
		if e := unix.SetsockoptInt(int(fd), solUDP, optUDPGRO, 1); e == nil {
			caps.RX = true
		}
	})
	return caps, cerr
}

// writeGSOControl serialises the TX control message. Kernel reads exactly two
// bytes here; anything else returns EINVAL from udp_cmsg_send.
func writeGSOControl(oob []byte, segSize uint16) int {
	n := unix.CmsgSpace(2)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = solUDP
	h.Type = optUDPSegment
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], segSize)
	return n
}

// readGSOSize extracts the coalesced segment size the kernel reported. Kernel
// writes an int, so consume four bytes when present and two as a tolerant
// fallback for older stacks.
func readGSOSize(oob []byte) int {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for i := range msgs {
		h := &msgs[i].Header
		if h.Level != solUDP || h.Type != optUDPGRO {
			continue
		}
		d := msgs[i].Data
		switch {
		case len(d) >= 4:
			return int(binary.NativeEndian.Uint32(d[:4]))
		case len(d) >= 2:
			return int(binary.NativeEndian.Uint16(d[:2]))
		}
	}
	return 0
}
```

Transmit path with coalescing. Accumulate equal-sized encrypted datagrams into one superframe, flush on size change, on buffer full, or on a hard 250 microsecond timer so latency never suffers:

```go
// tx_coalesce.go
package winn

import (
	"errors"
	"golang.org/x/sys/unix"
)

type GSOTx struct {
	fd      int
	buf     []byte
	oob     []byte
	segSize int
	segs    int
	fill    int
	caps    OffloadCaps
	sa      unix.Sockaddr
}

func NewGSOTx(fd int, caps OffloadCaps, sa unix.Sockaddr) *GSOTx {
	return &GSOTx{
		fd:   fd,
		buf:  make([]byte, gsoMaxBytes),
		oob:  make([]byte, unix.CmsgSpace(2)),
		caps: caps,
		sa:   sa,
	}
}

// Push appends one encrypted datagram. Returns the flush result if the append
// forced a boundary.
func (t *GSOTx) Push(pkt []byte) error {
	if !t.caps.TX {
		return t.sendOne(pkt)
	}
	// A superframe requires uniform segment size except for a short final one.
	// A short segment terminates the frame, so flush before and after it.
	if t.segs > 0 && (len(pkt) != t.segSize || t.segs == udpMaxSegments ||
		t.fill+len(pkt) > len(t.buf)) {
		if err := t.Flush(); err != nil {
			return err
		}
	}
	if t.segs == 0 {
		t.segSize = len(pkt)
	}
	copy(t.buf[t.fill:], pkt)
	t.fill += len(pkt)
	t.segs++
	if len(pkt) < t.segSize {
		return t.Flush()
	}
	return nil
}

func (t *GSOTx) Flush() error {
	if t.segs == 0 {
		return nil
	}
	payload := t.buf[:t.fill]
	segs, size := t.segs, t.segSize
	t.segs, t.fill, t.segSize = 0, 0, 0

	if segs == 1 {
		return t.sendOne(payload)
	}
	n := writeGSOControl(t.oob, uint16(size))
	_, err := unix.SendmsgN(t.fd, payload, t.oob[:n], t.sa, 0)
	if err == nil {
		return nil
	}
	// EIO or EINVAL means the path rejected the superframe (rare, seen on some
	// tethered or virtualised links). Disable TX offload permanently and replay.
	if errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) {
		t.caps.TX = false
		for off := 0; off < len(payload); off += size {
			end := off + size
			if end > len(payload) {
				end = len(payload)
			}
			if e := t.sendOne(payload[off:end]); e != nil {
				return e
			}
		}
		return nil
	}
	return err
}

func (t *GSOTx) sendOne(pkt []byte) error {
	_, err := unix.SendmsgN(t.fd, pkt, nil, t.sa, 0)
	return err
}
```

Receive path splitting the coalesced superframe:

```go
// rx_split.go
package winn

import "golang.org/x/sys/unix"

type GSORx struct {
	fd  int
	buf []byte
	oob []byte
}

func NewGSORx(fd int) *GSORx {
	return &GSORx{
		fd:  fd,
		buf: make([]byte, gsoMaxBytes),
		oob: make([]byte, unix.CmsgSpace(4)+128),
	}
}

// Recv returns the raw superframe and the per-segment stride. A stride of zero
// means the kernel delivered a single uncoalesced datagram.
func (r *GSORx) Recv() (frame []byte, stride int, err error) {
	n, oobn, _, _, err := unix.Recvmsg(r.fd, r.buf, r.oob, 0)
	if err != nil {
		return nil, 0, err
	}
	stride = readGSOSize(r.oob[:oobn])
	if stride == 0 || stride >= n {
		return r.buf[:n], 0, nil
	}
	return r.buf[:n], stride, nil
}
```

**Expected delta on Android:** GRO collapses roughly 40 receive syscalls into one. Stage 1 falls from 0.25 us to roughly 0.06 us, and the per-skb allocation cost inside the kernel drops proportionally. Call it 0.35 us of total savings including reduced kernel-side skb churn. `C_pkt` reaches roughly 6.37 us, which is 157,000 pps, or **1,724 Mbps**.

### 2.3 Change 3: AEAD selection

Apply Section 1.6. Stage 2 falls from 1.70 us to approximately 0.35 us. `C_pkt` reaches **5.02 us**, giving 199,200 pps. That exceeds the 169,952 pps wire ceiling.

**The pipeline is now bound by the fiber, not the handset.** Measured result should land between 1,780 and 1,812 Mbps of inner TCP payload.

### 2.4 Change 4: Socket buffer sizing, with the correct derivation

Do not set 16 MB because 16 is bigger than 8. Set it because of this:

```
BDP        = R * RTT / 8 = 2.0e9 * 0.012 / 8         = 3.00 MB
Stall      = R * t_stall / 8, t_stall <= 20 ms       = 5.00 MB
Required   = BDP + Stall                             = 8.00 MB
With 2x headroom for skb truesize inflation          = 16.00 MB
```

The `t_stall` term is the one that matters on Android. CFS timeslice expiry, thermal core migration, and top-app cgroup transitions routinely stall a userspace thread for 5 to 20 ms. At 2 Gbps that is up to 5 MB of in-flight data that must survive in the socket queue or be lost.

Two kernel behaviours to account for:

1. `setsockopt(SO_RCVBUF, N)` stores `2*N` because the kernel charges `skb->truesize`, not payload length. A 1433-byte datagram in a 2048-byte skb with shared info can cost 2304 bytes of accounting for 1433 bytes of data, roughly 62 percent efficiency. UDP GRO fixes this: a 40-segment superframe amortizes the skb header across 57 KB of payload, pushing efficiency above 95 percent.
2. The request is silently clamped to `net.core.rmem_max`. You cannot sysctl on an unrooted handset. Read the limit and verify the result.

```go
// sockbuf.go
package winn

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func sysctlInt(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return v
}

// TuneWANSocket applies buffer sizing and verifies the kernel honoured it.
// Returns the effective payload-equivalent sizes so the caller can log drift.
func TuneWANSocket(fd int, want int) (effRcv, effSnd int, err error) {
	rmax := sysctlInt("/proc/sys/net/core/rmem_max")
	wmax := sysctlInt("/proc/sys/net/core/wmem_max")

	req := want
	if rmax > 0 && req > rmax {
		req = rmax
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, req); err != nil {
		return
	}
	req = want
	if wmax > 0 && req > wmax {
		req = wmax
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, req); err != nil {
		return
	}

	// getsockopt reports the doubled bookkeeping value. Halve it back.
	r, e1 := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	s, e2 := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
	if e1 != nil {
		return 0, 0, e1
	}
	if e2 != nil {
		return 0, 0, e2
	}

	// Drop the outer IP fragment reassembly path entirely and keep DF set so
	// PMTUD stays authoritative.
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)

	return r / 2, s / 2, nil
}
```

Call with `want = 16 << 20`. If `effRcv` comes back at 8 MB, the device caps `rmem_max` at 8 MB and no amount of code changes that. Log it, and note in the report that the stall-absorption margin is halved.

### 2.5 Change 5: The lock-free ring between decrypt workers and the TUN writer

The docket asks for "zero-copy lock-free ring buffers between Go datapath and TUN descriptor." State the honest limit: **true zero-copy into a TUN descriptor is impossible on Android.** The framework opens the descriptor without `IFF_VNET_HDR`, so `vhost-net` style shared memory rings are unavailable. `tun_get_user()` will always perform one copy. What is achievable is zero *additional* copies and zero locks.

A Vyukov bounded MPMC queue with payload stored in place. Multiple decrypt workers produce, one pinned writer consumes:

```go
// ring/mpmc.go
package ring

import (
	"runtime"
	"sync/atomic"
)

const (
	cacheLine = 64
	SlotBytes = 2048 // covers 1440 inner MTU with headroom, one page-friendly stride
)

type Slot struct {
	seq  atomic.Uint64
	n    int32
	_    [cacheLine - 12]byte
	Data [SlotBytes]byte
}

type Ring struct {
	mask  uint64
	slots []Slot
	_p0   [cacheLine - 8]byte
	head  atomic.Uint64 // producer cursor
	_p1   [cacheLine - 8]byte
	tail  atomic.Uint64 // consumer cursor
	_p2   [cacheLine - 8]byte
	wake  chan struct{}
}

// New builds a ring of sizePow2 slots. Memory footprint is sizePow2 * ~2112 B.
// 2048 slots costs about 4.3 MB and holds 24 ms of traffic at 1.8 Gbps.
func New(sizePow2 int) *Ring {
	if sizePow2&(sizePow2-1) != 0 {
		panic("ring: size must be a power of two")
	}
	r := &Ring{
		mask:  uint64(sizePow2 - 1),
		slots: make([]Slot, sizePow2),
		wake:  make(chan struct{}, 1),
	}
	for i := range r.slots {
		r.slots[i].seq.Store(uint64(i))
	}
	return r
}

// Acquire claims a slot for writing. Returns nil when the ring is full, which
// is the correct backpressure signal: drop, do not block a decrypt worker.
func (r *Ring) Acquire() (*Slot, uint64) {
	pos := r.head.Load()
	for {
		s := &r.slots[pos&r.mask]
		diff := int64(s.seq.Load()) - int64(pos)
		switch {
		case diff == 0:
			if r.head.CompareAndSwap(pos, pos+1) {
				return s, pos
			}
			pos = r.head.Load()
		case diff < 0:
			return nil, 0
		default:
			pos = r.head.Load()
		}
	}
}

// Publish makes the slot visible to the consumer and wakes a parked writer.
func (r *Ring) Publish(s *Slot, pos uint64, n int) {
	s.n = int32(n)
	s.seq.Store(pos + 1)
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Consume claims the next readable slot.
func (r *Ring) Consume() (*Slot, uint64, bool) {
	pos := r.tail.Load()
	for {
		s := &r.slots[pos&r.mask]
		diff := int64(s.seq.Load()) - int64(pos+1)
		switch {
		case diff == 0:
			if r.tail.CompareAndSwap(pos, pos+1) {
				return s, pos, true
			}
			pos = r.tail.Load()
		case diff < 0:
			return nil, 0, false
		default:
			pos = r.tail.Load()
		}
	}
}

// Release returns the slot to the producer pool.
func (r *Ring) Release(s *Slot, pos uint64) {
	s.seq.Store(pos + r.mask + 1)
}

// Park blocks the consumer without burning a core.
func (r *Ring) Park() {
	<-r.wake
}

// Spin is the bounded pre-park hint.
func (r *Ring) Spin(iters int) {
	for i := 0; i < iters; i++ {
		runtime.Gosched()
	}
}
```

Sizing note: 2048 slots at 2112 bytes each costs 4.3 MB and buffers 2048 packets. At 169,952 pps that is 12.05 ms of absorption, which covers a typical scheduler stall. Do not go larger. A ring deeper than the socket buffer's drain time just moves bufferbloat into userspace.

### 2.6 Change 6: Delete the 60 microsecond spin-wait

A fixed 60 microsecond spin on every EAGAIN is a fixed tax on an event whose rate you do not control. If the EAGAIN rate is 10,000 per second, that spin consumes 0.6 core-seconds per second, 60 percent of a core, producing nothing. At 2,000 per second it still costs 12 percent. On a thermally constrained handset that is throughput you are setting on fire.

**Replace with a blocking descriptor on a dedicated OS thread.** The kernel wakes you with zero polling cost and zero latency penalty.

```diff
--- a/engine/tun_writer.go
+++ b/engine/tun_writer.go
@@
-func (e *Engine) tunWriter(q *ring.Ring, fd int) {
-	for {
-		s, pos, ok := q.Consume()
-		if !ok {
-			continue
-		}
-		for {
-			_, err := unix.Write(fd, s.Data[:s.n])
-			if err == unix.EAGAIN {
-				// spin 60us and retry
-				deadline := nanotime() + 60_000
-				for nanotime() < deadline {
-				}
-				continue
-			}
-			break
-		}
-		q.Release(s, pos)
-	}
-}
+// tunWriter owns the write half of the TUN descriptor. The descriptor is in
+// blocking mode, so write() never returns EAGAIN and the kernel handles the
+// wait. The thread is pinned so the ring stays in one core's L2.
+func (e *Engine) tunWriter(q *ring.Ring, fd int, cpu int) {
+	runtime.LockOSThread()
+	defer runtime.UnlockOSThread()
+	pinThread(cpu)
+	e.host.BoostThread(unix.Gettid())
+
+	// Bounded adaptive spin. Under load the ring is rarely empty, so the spin
+	// almost always succeeds and the park path is cold. Under idle the thread
+	// parks immediately instead of burning a core.
+	const spinBudget = 48
+
+	for {
+		s, pos, ok := q.Consume()
+		if !ok {
+			hit := false
+			for i := 0; i < spinBudget; i++ {
+				if s, pos, ok = q.Consume(); ok {
+					hit = true
+					break
+				}
+				procyield(30)
+			}
+			if !hit {
+				q.Park()
+				continue
+			}
+		}
+		b := s.Data[:s.n]
+		for len(b) > 0 {
+			n, err := unix.Write(fd, b)
+			if err != nil {
+				if err == unix.EINTR {
+					continue
+				}
+				// ENOBUFS on a tun device means the stack backlog is saturated.
+				// Drop and account. Never retry in a tight loop.
+				e.stats.TunWriteDrop.Add(1)
+				break
+			}
+			b = b[n:]
+		}
+		q.Release(s, pos)
+	}
+}
```

Thread pinning helper. `sched_setaffinity` on the calling thread is permitted for app processes:

```go
// affinity_linux.go
package winn

import "golang.org/x/sys/unix"

// pinThread restricts the calling OS thread to one CPU. Call only after
// runtime.LockOSThread. Failure is non-fatal: some Android cpusets deny the
// requested mask, in which case the scheduler default applies.
func pinThread(cpu int) {
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	_ = unix.SchedSetaffinity(0, &set)
}
```

Pin policy on a 2 prime plus 6 performance Oryon layout: the TUN writer and the WAN receiver each get a prime core. Decrypt workers spread across the performance cluster. Never pin to a core the Android system server also camps on.

### 2.7 Change 7: Garbage collector removal from the datapath

Go's GC is not the enemy. Allocation in the hot loop is. The ring above stores payloads in place, so once handshake setup completes the datapath allocates nothing.

```go
// At engine start, after all rings, slabs, and worker goroutines are built.
debug.SetGCPercent(-1)
debug.SetMemoryLimit(224 << 20) // soft ceiling; GC fires only under real pressure
runtime.GOMAXPROCS(runtime.NumCPU())
```

Disabling percentage-driven GC while retaining a soft memory limit gives you the best of both: no STW pauses triggered by handshake churn, and a hard backstop against an unbounded leak. Verify with `GODEBUG=gctrace=1` during a sustained 60 second run. Zero GC cycles is the acceptance criterion.

### 2.8 Single VPN projection table

| Stage | `C_pkt` (us) | pps | Inner TCP goodput |
|---|---|---|---|
| Round 31 baseline | 8.17 | 122,479 | 1,345 Mbps |
| + LocalSocket removed | 6.72 | 148,900 | 1,635 Mbps |
| + UDP GSO/GRO on WAN socket | 6.37 | 157,000 | 1,724 Mbps |
| + AES-256-GCM AEAD | 5.02 | 199,200 | wire-bound |
| + 16 MB buffers, pinning, GC off | 4.60 | 217,400 | wire-bound |
| **Physical ceiling at `M_i` = 1373** | 5.88 | 169,952 | **1,812.6 Mbps** |
| **Physical ceiling at `M_i` = 1440** | 6.15 | 162,548 | **1,820.5 Mbps** |

Headroom at the end: 27 percent. That headroom is what survives thermal throttling.

---

## 3. DOUBLE VPN: 500 TO 1,500 Mbps THROUGH AICORE

### 3.1 The MTU budget, derived rather than asserted

Hop 1 runs over the 10 Gbps LAN, path MTU 1500. Hop 2 runs over the 2 Gbps fiber, path MTU 1500 unless a leg is PPPoE.

```
Hop 2 tunnel payload capacity:
  P2 = 1500 - O_ip4 - O_udp - O_w3 = 1500 - 20 - 8 - 32 = 1440 B
  => ip link set dev winn3out mtu 1440

Hop 1 tunnel payload capacity (same math, LAN side):
  P1 = 1440 B

The handset inner packet must fit BOTH. It rides inside hop 1, and after
decapsulation on aicore it must still fit inside hop 2:

  M_i = min(P1, P2) = 1440 B   ... if hop 1 and hop 2 were independent

But they are serial. The handset packet is encapsulated once by hop 1 and,
after decapsulation, encapsulated again by hop 2. Both encapsulations are
charged against the same 1500 byte WAN frame only on the hop 2 leg. Hop 1
rides the LAN, which also caps at 1500. Therefore:

  Hop 1 constraint: M_i + 60 <= 1500  =>  M_i <= 1440
  Hop 2 constraint: M_i + 60 <= 1500  =>  M_i <= 1440

  M_i = 1440 B
```

**So where does 1373 come from?**

Three candidate explanations, all worth auditing:

1. **PPPoE on an exit leg.** If any exit node sits behind PPPoE, its path MTU is 1492, giving `M_i <= 1432`. Still not 1373.
2. **IPv6 outer on one hop.** With an IPv6 outer header (40 B), hop capacity is `1500 - 40 - 8 - 32 = 1420`. Still not 1373.
3. **An obfuscation prefix in Winn v3.** If Winn v3 carries an obfuscation header of `k` bytes beyond the 32-byte AEAD framing, then `M_i = 1440 - k`. For `M_i = 1373`, `k = 67`. That is a large prefix.

If none of these apply, **1373 is leaving 67 bytes per packet on the table**, which is 4.9 percent of goodput and 4.7 percent of frame rate. Audit the constant. If it exists as a legacy safety margin, replace it with runtime discovery.

**Mandate: implement RFC 8899 Datagram Packetization Layer PMTUD inside Winn v3.** Static MTU constants are a permanent tax paid to avoid one engineering task.

```go
// dplpmtud.go
package winn

// Probe sizes per RFC 8899 section 5.1, searching the plausible range.
// BASE is never probed; it is assumed reachable. MIN_PLPMTU is the floor.
var probeLadder = []int{1280, 1360, 1400, 1420, 1440, 1472, 1492}

type PathMTU struct {
	current   int   // confirmed usable outer datagram size
	probing   int   // size under test
	probeCnt  int   // retries at the current rung, max 3 per RFC 8899
	blackhole int   // consecutive confirmed losses at current size
}

// OnProbeAck raises the confirmed MTU and advances the ladder.
func (p *PathMTU) OnProbeAck(size int) {
	if size > p.current {
		p.current = size
	}
	p.probeCnt = 0
	p.blackhole = 0
}

// OnProbeTimeout retries up to three times, then freezes the ladder.
func (p *PathMTU) OnProbeTimeout() bool {
	p.probeCnt++
	return p.probeCnt >= 3
}

// OnPTB validates an ICMP Fragmentation Needed or Packet Too Big report. The
// reported next hop MTU is only accepted when it falls strictly between the
// floor and the current confirmed value, which blocks the classic forged-PTB
// downgrade attack.
func (p *PathMTU) OnPTB(reported int) bool {
	if reported <= 1280 || reported >= p.current {
		return false
	}
	p.probing = reported
	return true
}
```

The probe packet is a padded Winn v3 keepalive with DF set. If the peer acknowledges it, the size is confirmed.

### 3.2 The architectural determination: userspace crossover, not kernel forwarding

The docket specifies "Hop 1 terminates on aicore, decapsulating into kernel IP packet on winn3gw0" then "Hop 2 re-encapsulates."

Cost that path honestly:

| Stage | Cost |
|---|---|
| `recvmsg` from UDP 9111, GRO amortized over 40 | 0.05 us |
| Hop 1 AEAD decrypt (1405 B, AES-256-GCM) | 0.35 us |
| `write()` to `winn3gw0` | 1.00 us |
| Kernel `netif_rx`, FIB lookup, netfilter FORWARD, conntrack | 1.20 us |
| `read()` from the hop 2 TUN | 0.80 us |
| Hop 2 AEAD encrypt (1373 B) | 0.34 us |
| `sendmsg` with GSO, amortized | 0.06 us |
| NIC transmit and driver | 0.40 us |
| **Total** | **4.20 us** |

Now cost the crossover, where hop 1 and hop 2 are the same Go process and the decrypted packet never leaves userspace:

| Stage | Cost |
|---|---|
| `recvmsg` from UDP 9111, GRO amortized | 0.05 us |
| Hop 1 AEAD decrypt | 0.35 us |
| Userspace policy lookup (flow hash cache, LPM miss path) | 0.06 us |
| Hop 2 AEAD encrypt, in-place into a GSO superframe | 0.34 us |
| `sendmsg` with GSO, amortized | 0.06 us |
| NIC transmit and driver | 0.40 us |
| **Total** | **1.26 us** |

**A 70 percent reduction.** On one core: 793,650 pps, equal to 8.7 Gbps of inner IP goodput. On four cores the box is nowhere near the constraint.

Crossover implementation:

```go
// crossover.go
package aicore

import (
	"encoding/binary"
	"sync/atomic"
)

// FlowKey is the 5-tuple of the inner packet, used to cache the exit decision.
type FlowKey struct {
	SrcIP, DstIP [16]byte
	SrcPort      uint16
	DstPort      uint16
	Proto        uint8
	_            uint8
}

type ExitBinding struct {
	Tx        *GSOTx   // hop 2 transmit coalescer, one per exit node
	SendKey   [32]byte
	Counter   atomic.Uint64
	PeerIndex uint32
	MTU       int
}

// Crossover splices a decrypted hop 1 packet straight into hop 2 with no TUN
// write, no FIB lookup, and no netfilter traversal. Packets that miss the
// policy cache, carry ICMP, or exceed the hop 2 MTU with DF set fall through to
// the kernel path on winn3gw0 so the slow path keeps full policy semantics.
func (c *Core) Crossover(inner []byte, client *Peer) {
	if len(inner) < 20 {
		return
	}
	ver := inner[0] >> 4

	var key FlowKey
	switch ver {
	case 4:
		ihl := int(inner[0]&0x0f) * 4
		if len(inner) < ihl+4 {
			c.slowPath(inner, client)
			return
		}
		copy(key.SrcIP[12:], inner[12:16])
		copy(key.DstIP[12:], inner[16:20])
		key.Proto = inner[9]
		if key.Proto == 6 || key.Proto == 17 {
			key.SrcPort = binary.BigEndian.Uint16(inner[ihl : ihl+2])
			key.DstPort = binary.BigEndian.Uint16(inner[ihl+2 : ihl+4])
		}
		// DF set and oversized: generate ICMP Fragmentation Needed toward the
		// client so its PMTUD converges instead of blackholing.
		if inner[6]&0x40 != 0 && len(inner) > c.exitMTU(client) {
			c.emitPTBv4(inner, client, c.exitMTU(client))
			return
		}
	case 6:
		if len(inner) < 44 {
			c.slowPath(inner, client)
			return
		}
		copy(key.SrcIP[:], inner[8:24])
		copy(key.DstIP[:], inner[24:40])
		key.Proto = inner[6]
		if key.Proto == 6 || key.Proto == 17 {
			key.SrcPort = binary.BigEndian.Uint16(inner[40:42])
			key.DstPort = binary.BigEndian.Uint16(inner[42:44])
		}
		if len(inner) > c.exitMTU(client) {
			c.emitPTBv6(inner, client, c.exitMTU(client))
			return
		}
	default:
		c.slowPath(inner, client)
		return
	}

	bind := c.policy.Lookup(client.ID, &key)
	if bind == nil {
		c.slowPath(inner, client)
		return
	}

	// Seal directly into the hop 2 coalescer's staging buffer.
	ctr := bind.Counter.Add(1) - 1
	out := c.stage.Next()
	n := sealWinn3(out, bind.PeerIndex, ctr, bind.SendKey[:], inner)
	if err := bind.Tx.Push(out[:n]); err != nil {
		c.stats.Hop2TxErr.Add(1)
	}
}
```

The slow path keeps `winn3gw0` alive for DNS interception, ICMP origination, and any flow the policy engine has not classified. You lose nothing. You skip the kernel for the 99.9 percent of packets that are plain forwarded TCP and UDP.

**One warning.** Bypassing the kernel bypasses `iptables`, conntrack, and `tc`. Any per-client accounting, quota enforcement, or QoS must be reimplemented in the policy engine. If those features are contractual, either keep the kernel path or port them. Do not discover this in production.

### 3.3 Kernel path configuration (mandatory regardless, for the slow path)

**`/etc/sysctl.d/99-winn-aicore.conf`**

```ini
# ---- Forwarding ----
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# Asymmetric routing is inherent to multi-exit policy routing. Strict reverse
# path filtering will silently drop hop 1 traffic that egresses a different
# interface than it would ingress. Loose mode (2) keeps spoof protection
# without the false positives.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.winn3gw0.rp_filter = 0

# ---- Socket memory ----
# 128 MB ceiling covers the European exits: BDP at 1.5 Gbps and 120 ms RTT is
# 22.5 MB per direction, and the tunnel socket must hold that plus jitter.
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 1048576

# net.ipv4.udp_mem is expressed in PAGES, not bytes. 4 KiB pages assumed.
# 262144 pages = 1 GiB low, 524288 = 2 GiB pressure, 1048576 = 4 GiB max.
net.ipv4.udp_mem = 262144 524288 1048576
net.ipv4.udp_rmem_min = 262144
net.ipv4.udp_wmem_min = 262144

# ---- Softirq and NAPI ----
net.core.netdev_max_backlog = 65536
net.core.netdev_budget = 1200
net.core.netdev_budget_usecs = 8000
net.core.dev_weight = 128
net.core.gro_normal_batch = 16

# ---- Queueing ----
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ---- Control plane TCP (management, API, telemetry) ----
net.ipv4.tcp_rmem = 4096 262144 33554432
net.ipv4.tcp_wmem = 4096 262144 33554432
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_slow_start_after_idle = 0

# ---- Path MTU Discovery ----
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.route.min_pmtu = 1280
net.ipv4.route.mtu_expires = 600
# ip_forward_use_pmtu makes the forwarding path honour cached PMTU. Kernel docs
# flag a DoS vector (a hostile peer can shrink the cached PMTU for a route).
# Enable only when every ingress peer is authenticated, which is true here since
# both hops are authenticated tunnels.
net.ipv4.ip_forward_use_pmtu = 1

# ---- Connection tracking ----
# Sized for fleet scale. If conntrack is disabled for tunnel traffic via the raw
# table (see nftables below), these limits only cover control plane flows.
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_buckets = 262144
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 180
net.netfilter.nf_conntrack_tcp_timeout_established = 3600

# ---- Neighbour table, fleet scale ----
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 16384
net.ipv4.neigh.default.gc_thresh3 = 32768

# ---- Ephemeral ports for the hop 2 egress sockets ----
net.ipv4.ip_local_port_range = 10240 65000
```

Apply with `sysctl --system` and verify each line landed. Several of these are module-gated (`nf_conntrack` must be loaded before its sysctls exist).

**Interface and queue configuration:**

```bash
#!/usr/bin/env bash
set -euo pipefail

WAN=eth0
GW=winn3gw0
NCPU=$(nproc)
MASK=$(printf '%x' $(( (1 << NCPU) - 1 )))

# MTU per the Section 3.1 derivation. Raise from 1373 after the audit.
ip link set dev "$GW" mtu 1440
ip link set dev "$GW" txqueuelen 10000

for EX in winn3ca1 winn3de1 winn3es1 winn3ks1; do
  ip link set dev "$EX" mtu 1440 2>/dev/null || true
  ip link set dev "$EX" txqueuelen 10000 2>/dev/null || true
done

# Hardware offloads on the WAN NIC. Keep GRO and GSO on: coalescing the outer
# UDP stream is exactly what the UDP_GRO socket option depends on.
ethtool -K "$WAN" gro on gso on tso on sg on tx-checksum-ip-generic on || true
# Forwarded-path UDP GRO, kernel 5.14 and later. Harmless if unsupported.
ethtool -K "$WAN" rx-udp-gro-forwarding on 2>/dev/null || true
ethtool -K "$WAN" rx-gro-list off 2>/dev/null || true

# Interrupt coalescing: trade a little latency for a lot of softirq headroom.
ethtool -C "$WAN" adaptive-rx on adaptive-tx on rx-usecs 32 rx-frames 48 2>/dev/null || true

# Ring depth. Undersized rings are the number one cause of rx_missed under burst.
ethtool -G "$WAN" rx 4096 tx 4096 2>/dev/null || true

# ---- RPS: spread softirq across cores for devices without multiqueue RSS ----
for Q in /sys/class/net/"$WAN"/queues/rx-*; do
  echo "$MASK" > "$Q"/rps_cpus
  echo 32768   > "$Q"/rps_flow_cnt
done
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries

# TUN devices are single queue by default. RPS matters more here than on the NIC.
for DEV in "$GW" winn3ca1 winn3de1 winn3es1 winn3ks1; do
  [ -d /sys/class/net/"$DEV" ] || continue
  for Q in /sys/class/net/"$DEV"/queues/rx-*; do
    echo "$MASK" > "$Q"/rps_cpus 2>/dev/null || true
    echo 32768   > "$Q"/rps_flow_cnt 2>/dev/null || true
  done
done

# ---- XPS: bind each tx queue to exactly one CPU, no overlap ----
i=0
for Q in /sys/class/net/"$WAN"/queues/tx-*; do
  printf '%x\n' $(( 1 << (i % NCPU) )) > "$Q"/xps_cpus
  i=$(( i + 1 ))
done

# ---- Qdisc: fq for pacing. BBR requires a pacing-capable qdisc to behave. ----
# maxrate at 95 percent of the 2 Gbps WAN keeps the ISP's own queue drained,
# which is what actually kills latency under load.
tc qdisc replace dev "$WAN" root fq \
    maxrate 1900mbit \
    flow_limit 2000 \
    quantum 3028 \
    initial_quantum 15140 \
    limit 40000

# Tunnel interfaces pace independently. No maxrate: the WAN qdisc is the shaper.
for DEV in "$GW" winn3ca1 winn3de1 winn3es1 winn3ks1; do
  [ -d /sys/class/net/"$DEV" ] || continue
  tc qdisc replace dev "$DEV" root fq flow_limit 1000 limit 20000 quantum 3028
done

# Pin NIC interrupts away from CPU0, which handles timers and the scheduler.
i=1
for IRQ in $(grep -E "$WAN" /proc/interrupts | cut -d: -f1 | tr -d ' '); do
  printf '%x\n' $(( 1 << (i % NCPU) )) > /proc/irq/"$IRQ"/smp_affinity
  i=$(( i + 1 ))
done

# irqbalance will undo the pinning above. It must not run.
systemctl stop irqbalance 2>/dev/null || true
systemctl mask irqbalance 2>/dev/null || true
```

A note on `fq` versus `cake`: `cake` gives better latency isolation, but it is single threaded and saturates somewhere between 1 and 2 Gbps on most CPUs. At the 2 Gbps target it becomes the bottleneck. Use `fq` with `maxrate`. Revisit `cake` only if the aicore CPU is genuinely oversized.

### 3.4 MSS clamping and PMTUD, exact rules

nftables is the correct tool on any kernel from 5.x forward. `tcp option maxseg size set rt mtu` is the native equivalent of `--clamp-mss-to-pmtu`, and it clamps to the real route MTU instead of a guess.

**`/etc/nftables.d/winn-mangle.nft`**

```
table inet winn_mangle {
    chain forward {
        type filter hook forward priority mangle; policy accept;

        # Clamp on every tunnel boundary, both directions, both address families.
        # A SYN entering or leaving any winn interface gets its MSS rewritten to
        # the route MTU minus the L3 and L4 headers.
        iifname "winn3gw0" tcp flags syn / syn,rst \
            tcp option maxseg size set rt mtu counter
        oifname "winn3gw0" tcp flags syn / syn,rst \
            tcp option maxseg size set rt mtu counter
        iifname "winn3*"   tcp flags syn / syn,rst \
            tcp option maxseg size set rt mtu counter
        oifname "winn3*"   tcp flags syn / syn,rst \
            tcp option maxseg size set rt mtu counter
    }

    chain output {
        type filter hook output priority mangle; policy accept;
        oifname "winn3*" tcp flags syn / syn,rst \
            tcp option maxseg size set rt mtu counter
    }
}

table inet winn_filter {
    chain input {
        type filter hook input priority filter; policy drop;

        ct state established,related accept
        iif lo accept

        # Path MTU Discovery depends entirely on these two lines surviving.
        # Dropping ICMP frag-needed is the single most common cause of the
        # "small pages load, large transfers hang" failure mode.
        icmp   type destination-unreachable icmp code frag-needed accept
        icmpv6 type packet-too-big accept
        icmp   type echo-request limit rate 20/second accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert,
                      nd-router-advert, nd-router-solicit } accept

        # Multiprotocol ingress.
        udp dport 9111  accept comment "Winn v3"
        udp dport 51820 accept comment "Winn v1 AWG"
        tcp dport 443   accept comment "XRay fallback"
        udp dport 443   accept comment "XRay QUIC fallback"

        counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        iifname "winn3gw0" oifname "winn3*" accept
        iifname "winn3*"   oifname "winn3gw0" accept
        ct state established,related accept
        counter drop
    }
}

table inet winn_raw {
    chain prerouting {
        type filter hook prerouting priority raw; policy accept;

        # Connection tracking on forwarded tunnel traffic buys nothing: NAT
        # happens at the exit node, not here. Skipping it removes a hash lookup,
        # a table insert, and the entire nf_conntrack_max failure mode from the
        # per-packet path. DELETE THESE TWO RULES if aicore performs its own
        # masquerade for any flow.
        iifname "winn3gw0" notrack
        iifname "winn3*"   notrack
    }
    chain output {
        type filter hook output priority raw; policy accept;
        oifname "winn3*" notrack
    }
}
```

If the deployment is pinned to legacy `iptables`, the equivalent with explicit values (inner MTU 1373 shown; change to 1400 after raising the inner MTU to 1440):

```bash
# IPv4: MSS = inner_mtu - 20 (IP) - 20 (TCP)
iptables  -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
  -m tcpmss --mss 1334:65495 -j TCPMSS --set-mss 1333

# IPv6: MSS = inner_mtu - 40 (IPv6) - 20 (TCP)
ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
  -m tcpmss --mss 1314:65495 -j TCPMSS --set-mss 1313

# Dynamic variant, preferred when the route MTU is trustworthy
iptables  -t mangle -A FORWARD -o winn3+ -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -A FORWARD -o winn3+ -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu

# PMTUD survival
iptables  -A INPUT -p icmp --icmp-type fragmentation-needed -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
```

MSS clamping covers TCP only. QUIC, WireGuard-over-UDP, and every other UDP protocol depend on PMTUD or on their own DPLPMTUD. That is the second reason Section 3.1 mandates RFC 8899.

### 3.5 Policy routing per exit node

```bash
# One routing table per exit.
cat >> /etc/iproute2/rt_tables <<'EOF'
101 winn_ca1
102 winn_de1
103 winn_es1
104 winn_ks1
EOF

ip route replace default dev winn3ca1 table winn_ca1
ip route replace default dev winn3de1 table winn_de1
ip route replace default dev winn3es1 table winn_es1
ip route replace default dev winn3ks1 table winn_ks1

# Mark-driven selection, set by nftables from the client inner address.
ip rule add fwmark 101 lookup winn_ca1 priority 1001
ip rule add fwmark 102 lookup winn_de1 priority 1002
ip rule add fwmark 103 lookup winn_es1 priority 1003
ip rule add fwmark 104 lookup winn_ks1 priority 1004

# Exit node reachability stays on the physical default route. Without these
# host routes the hop 2 outer datagrams would recurse into their own tunnel.
ip route replace <NODE_CANADA_IP>/32 via "$(ip -4 route show default | awk '{print $3; exit}')" dev eth0
ip route replace <NODE_GERMANY_IP>/32  via "$(ip -4 route show default | awk '{print $3; exit}')" dev eth0
ip route replace <NODE_SPAIN_IP>/32   via "$(ip -4 route show default | awk '{print $3; exit}')" dev eth0
ip route replace <KANSAS_HUB_IP>/32 via "$(ip -4 route show default | awk '{print $3; exit}')" dev eth0
```

Mark assignment, keyed on the client's inner address:

```
table inet winn_route {
    map client_exit {
        type ipv4_addr : mark
        elements = {
            10.10.0.14 : 0x65,   # handset -> ca1
            10.10.0.20 : 0x66,   # -> de1
            10.10.0.21 : 0x67,   # -> es1
            10.10.0.22 : 0x68    # -> ks1
        }
    }
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname "winn3gw0" meta mark set ip saddr map @client_exit
    }
}
```

### 3.6 Multiprotocol ingress on aicore

The docket requires UDP 9111 (Winn v3), UDP 51820 (Winn v1 AWG), and an XRay fallback, all live simultaneously.

Design decision: **`SO_REUSEPORT` socket groups with cBPF CPU steering.** One socket per core per port. The kernel's reuseport group distributes incoming datagrams, and a classic BPF program pins each datagram to the socket whose index equals the CPU that ran the softirq. That keeps the skb, the socket, and the Go reader goroutine on one core, eliminating the cross-core cache line ping-pong that caps a single-socket listener around 300 kpps.

```go
// reuseport_linux.go
package aicore

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// linux/filter.h
	skfAdOff = uint32(0xfffff000) // (uint32)(-0x1000)
	skfAdCPU = 36
	bpfLdWAbs = uint16(0x20) // BPF_LD | BPF_W | BPF_ABS
	bpfRetA   = uint16(0x16) // BPF_RET | BPF_A
	soAttachReuseportCBPF = 51
)

// cbpfSteerByCPU returns A = raw_smp_processor_id(). The reuseport group maps
// that value modulo the group size onto a socket index.
func cbpfSteerByCPU() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: bpfLdWAbs, Jt: 0, Jf: 0, K: skfAdOff + skfAdCPU},
		{Code: bpfRetA, Jt: 0, Jf: 0, K: 0},
	}
}

// ListenReuseGroup opens n UDP sockets on the same address. The steering filter
// is attached to the first socket only; the kernel applies a reuseport BPF
// program to the entire group.
func ListenReuseGroup(addr string, n int, rcvbuf, sndbuf int) ([]*net.UDPConn, error) {
	conns := make([]*net.UDPConn, 0, n)

	for i := 0; i < n; i++ {
		idx := i
		lc := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				var serr error
				if err := c.Control(func(fd uintptr) {
					f := int(fd)
					if serr = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); serr != nil {
						return
					}
					if serr = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf); serr != nil {
						return
					}
					if serr = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_SNDBUF, sndbuf); serr != nil {
						return
					}
					// GRO on receive, GSO capability probe on transmit.
					_ = unix.SetsockoptInt(f, 17, 104, 1) // SOL_UDP, UDP_GRO
					_ = unix.SetsockoptInt(f, 17, 103, 0) // SOL_UDP, UDP_SEGMENT
					// Keep DF set so hop 2 PMTUD stays authoritative.
					_ = unix.SetsockoptInt(f, unix.IPPROTO_IP,
						unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
					// Deliver the destination address so a multi-homed aicore
					// can reply from the correct source.
					_ = unix.SetsockoptInt(f, unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
					// Busy polling trades CPU for latency and pps. 50 us is a
					// conservative starting value; measure before raising.
					_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_BUSY_POLL, 50)

					if idx == 0 {
						prog := cbpfSteerByCPU()
						p := unix.SockFprog{
							Len:    uint16(len(prog)),
							Filter: &prog[0],
						}
						// Non-fatal: without steering the group still works,
						// it just loses core locality.
						_ = unix.SetsockoptSockFprog(f, unix.SOL_SOCKET,
							soAttachReuseportCBPF, &p)
					}
				}); err != nil {
					return err
				}
				return serr
			},
		}
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return nil, err
		}
		conns = append(conns, pc.(*net.UDPConn))
	}
	return conns, nil
}
```

Protocol demultiplexing on UDP 51820, where Winn v1 AWG and the XRay fallback share a port:

```go
// demux.go
package aicore

import "encoding/binary"

type Proto uint8

const (
	ProtoUnknown Proto = iota
	ProtoWinnV3
	ProtoAWG
	ProtoXRay
)

// AWGMagic holds the configured H1 through H4 header values. Amnezia WireGuard
// replaces the four canonical message type constants (1, 2, 3, 4) with
// operator-chosen 32 bit values, so classification must be config driven.
type AWGMagic struct {
	H1, H2, H3, H4 uint32
	JunkMin        int // Jmin, minimum junk packet size
	JunkMax        int // Jmax
}

// Classify inspects the first four bytes. Winn v3 uses the canonical WireGuard
// type space. AWG uses the operator magics. Anything else with sufficient
// entropy in the first 16 bytes is handed to the XRay listener.
func Classify(pkt []byte, m *AWGMagic) Proto {
	if len(pkt) < 4 {
		return ProtoUnknown
	}
	t := binary.LittleEndian.Uint32(pkt[:4])

	switch t {
	case 1, 2, 3, 4:
		return ProtoWinnV3
	}
	if m != nil {
		switch t {
		case m.H1, m.H2, m.H3, m.H4:
			return ProtoAWG
		}
		// AWG junk packets carry no recognisable header by design. Size range
		// plus a failed magic match is the only available signal. Silently
		// absorb them rather than misrouting to XRay.
		if len(pkt) >= m.JunkMin && len(pkt) <= m.JunkMax {
			return ProtoUnknown
		}
	}
	return ProtoXRay
}
```

**A warning on the XRay fallback.** If XRay runs over TCP (VLESS with Reality over TCP 443), the client's inner TCP rides inside an outer TCP connection. That is TCP over TCP. The two congestion controllers fight, retransmission timers compound, and throughput collapses non-linearly the instant loss appears on the outer path. The measured effect is routinely a 60 to 80 percent throughput loss at RTTs above 60 ms.

**Determination:** the XRay fallback is a censorship-circumvention path, not a performance path. Do not include it in the 500 to 1,500 Mbps fleet target. Document it as a degraded mode with an expected ceiling of 150 to 400 Mbps. If high-throughput obfuscation is genuinely needed, use a QUIC-based transport (XRay with the `xhttp` transport over HTTP/3, or Hysteria2) so congestion control is not nested.

### 3.7 Replay window sizing for the transcontinental exits

WireGuard-derived replay protection uses a sliding bitmap. The kernel implementation uses 8192 bits. At 1.5 Gbps with 1373 byte packets:

```
pps        = 1.5e9 / (1373 * 8) = 136,568 pps
8192 pkts  = 8192 / 136,568     = 60.0 ms of coverage
```

That sounds ample, and for single-path reordering it is. Two conditions break it:

1. **ECMP across the transatlantic path.** Multiple parallel links with differing latency can reorder by thousands of packets.
2. **Parallel decrypt workers on aicore.** If four workers decrypt concurrently and the replay check happens per worker rather than after resequencing, worker skew alone can exceed the window under scheduling jitter.

**Fix both.** Perform the replay check after resequencing on the counter, not inside the parallel worker. And raise the window to 32768 bits (4 KB of bitmap per peer, negligible) for the de1 and es1 exits:

```go
// replay.go
const (
	// 32768 counters covers 240 ms at 1.5 Gbps, which absorbs both ECMP skew
	// and decrypt worker scheduling jitter on multi-core gateways.
	CounterBitsTotal = 32768
	CounterWindow    = CounterBitsTotal - 64
)
```

### 3.8 Congestion control on the long-haul legs

The exits at Germany (<NODE_GERMANY_IP>) and Spain (<NODE_SPAIN_IP>) will sit near 100 to 130 ms RTT. Apply the Mathis bound to see why loss-based congestion control is disqualified.

At 1.5 Gbps, MSS 1333, RTT 110 ms, aggregate congestion window:

```
cwnd = pps * RTT = 136,568 * 0.110 = 15,022 packets
```

Reno and CUBIC in its Reno-friendly region need loss probability:

```
p = (C / cwnd)^2, with C ~= 1.22
p = (1.22 / 15022)^2 = 6.6e-9
```

With 16 parallel streams, per-stream cwnd is 939 packets:

```
p = (1.22 / 939)^2 = 1.69e-6
```

A loss rate of 1.69 parts per million on a transatlantic path is not achievable. Real transatlantic paths run 1e-5 to 1e-3.

At `p = 1e-4`, per-stream throughput collapses to:

```
T_stream = (C * MSS * 8) / (RTT * sqrt(p))
         = (1.22 * 1333 * 8) / (0.110 * 0.01)
         = 13,010 / 0.0011 = 11.8 Mbps
16 streams = 189 Mbps
```

**That is the real answer for why the double VPN target is 500 to 1,500 rather than 1,800.** It is not the gateway CPU. It is congestion control interacting with transatlantic loss.

Mandatory configuration on every exit node and on aicore:

```ini
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_rmem = 4096 262144 67108864
net.ipv4.tcp_wmem = 4096 262144 67108864
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
```

BBR is rate based, not loss based. It maintains a bandwidth estimate from delivery rate samples and paces to it, which makes it tolerant of non-congestive loss up to roughly 1 to 2 percent in BBRv1. BBRv3, where available, adds an explicit loss threshold with better coexistence behaviour. `fq` is not optional with BBR. Without a pacing-capable qdisc, BBR's pacing degrades to internal TCP pacing and its burst control weakens noticeably.

### 3.9 Realistic Double VPN projection per exit

| Exit | Est. RTT | BDP at 1.5 Gbps | Projected with BBR + fq | Projected with CUBIC |
|---|---|---|---|---|
| Kansas Core (<KANSAS_HUB_IP>) | 30 ms | 5.6 MB | 1,400 to 1,750 Mbps | 900 to 1,300 Mbps |
| Canada ca1 (<NODE_CANADA_IP>) | 25 ms | 4.7 MB | 1,450 to 1,780 Mbps | 950 to 1,350 Mbps |
| Germany de1 (<NODE_GERMANY_IP>) | 110 ms | 20.6 MB | 700 to 1,200 Mbps | 180 to 400 Mbps |
| Spain (<NODE_SPAIN_IP>) | 120 ms | 22.5 MB | 650 to 1,150 Mbps | 160 to 380 Mbps |

The 500 to 1,500 Mbps band in the mandate is achievable. It is achievable only with BBR, only with 64 MB TCP buffer ceilings at both ends, and only if the exit node uplinks are not themselves the constraint. Verify each exit node's provisioned uplink before attributing any shortfall to aicore.

---

## 4. MEASUREMENT PROTOCOL AND ACCEPTANCE GATES

Round 31's result is unverifiable as reported. Fix that first.

### 4.1 The measurement validity question

Publish the SpeedBench endpoint address. Three cases:

- **Endpoint on 192.168.4.x or 10.x LAN:** the 1,345 Mbps figure is a LAN loopback measurement. It validates the handset datapath and nothing else. It does not prove WAN capability.
- **Endpoint on the WAN, past the fiber ONT:** 1,345 Mbps is real, and the 637 Mbps Ookla result reflects Ookla's server selection, stream count, and duration, not the tunnel.
- **Endpoint unknown:** the result cannot enter the record.

Cross-validate against a neutral third path:

```bash
# On the handset, through the tunnel, against a known-good external host.
iperf3 -c <exit_node_ip> -p 5201 -P 16 -t 30 -O 3 --format m
iperf3 -c <exit_node_ip> -p 5201 -P 16 -t 30 -O 3 --format m -R

# UDP, to isolate tunnel capacity from TCP congestion control.
iperf3 -c <exit_node_ip> -u -b 1800M -l 1333 -t 30 --format m
```

The `-O 3` omit flag discards the first three seconds so slow start does not depress the mean. Without it, a 10 second test understates steady-state throughput by 10 to 20 percent at high BDP.

### 4.2 Instrumentation on the handset

```go
// stats.go
type DataplaneStats struct {
	RxDatagrams   atomic.Uint64 // superframes received from the WAN socket
	RxSegments    atomic.Uint64 // segments after GRO split
	RxBytes       atomic.Uint64
	TxDatagrams   atomic.Uint64 // superframes sent
	TxSegments    atomic.Uint64
	TxBytes       atomic.Uint64
	TunWrites     atomic.Uint64
	TunWriteDrop  atomic.Uint64
	RingFull      atomic.Uint64 // backpressure events, the key health signal
	ReplayReject  atomic.Uint64
	DecryptFail   atomic.Uint64
	ParkCount     atomic.Uint64 // writer thread parks, proxy for idle headroom
	SpinHits      atomic.Uint64 // spin succeeded, no park needed
}

// GROFactor is the single most informative derived metric. A value near 1.0
// means UDP_GRO is not engaging and the receive path is paying full syscall
// cost per packet.
func (s *DataplaneStats) GROFactor() float64 {
	d := s.RxDatagrams.Load()
	if d == 0 {
		return 0
	}
	return float64(s.RxSegments.Load()) / float64(d)
}

// GSOFactor mirrors it on the transmit side.
func (s *DataplaneStats) GSOFactor() float64 {
	d := s.TxDatagrams.Load()
	if d == 0 {
		return 0
	}
	return float64(s.TxSegments.Load()) / float64(d)
}
```

### 4.3 Acceptance gates

| Gate | Metric | Threshold | Failure meaning |
|---|---|---|---|
| G1 | SpeedBench endpoint | Documented, WAN-side | Result is invalid |
| G2 | `GROFactor` | > 8.0 sustained | UDP_GRO not engaging; check kernel version and socket option return |
| G3 | `GSOFactor` | > 8.0 sustained | Coalescer flushing too aggressively; check the segment-size uniformity logic |
| G4 | `RingFull` | < 0.01 percent of `RxSegments` | Consumer starved; TUN writer is the bottleneck |
| G5 | `TunWriteDrop` | 0 | Kernel backlog saturated; raise `netdev_max_backlog` |
| G6 | Go GC cycles over 60 s | 0 | Datapath still allocating |
| G7 | Single VPN download, 16 stream | >= 1,700 Mbps | Section 2 incomplete |
| G8 | Single VPN bidirectional sum | >= 3,400 Mbps | |
| G9 | Double VPN, ca1 or Kansas | >= 1,300 Mbps | Crossover or BBR missing |
| G10 | Double VPN, de1 or Spain | >= 650 Mbps | Check BBR, buffer ceilings, exit uplink |
| G11 | `netstat -su` RcvbufErrors on aicore | 0 | Socket buffers undersized or reader starved |
| G12 | `ethtool -S eth0 \| grep -i miss` | 0 | NIC ring or IRQ affinity wrong |
| G13 | Sustained 5 minute run | < 8 percent throughput decay | Thermal throttling; not a software defect |

Gate 13 matters more than it looks. A handset sustaining 1.8 Gbps of AEAD plus 170,000 syscalls per second will heat. A 10 second speedtest measures burst capability. A 5 minute test measures what users get.

---

## 5. WHAT WILL NOT WORK, AND WHY

Stated plainly, so the council does not spend Round 33 on these.

**`MSG_ZEROCOPY` on the UDP send path.** At 1,433 byte datagrams, the page-pinning setup plus the `MSG_ERRQUEUE` completion notification cost more than the `memcpy` they replace. `MSG_ZEROCOPY` becomes profitable above roughly 10 KB per call. It becomes worth testing only *after* UDP GSO is in place, because a 57 KB superframe crosses that threshold. Sequence matters: GSO first, then evaluate zero-copy against the superframe, not against individual packets.

**TUN segmentation offload on Android.** `VpnService.Builder` gives you an `IFF_TUN | IFF_NO_PI` descriptor. There is no API surface for `IFF_VNET_HDR`, and without the virtio net header there is no `TUNSETOFFLOAD`, no `TUN_F_TSO4`, no `TUN_F_USO4`, and therefore no multi-packet write. One `write()` per packet is a hard architectural floor on Android. Budget for 170,000 write syscalls per second and optimise everything around them.

On the aicore Linux gateway the opposite is true. Open `/dev/net/tun` yourself with `IFF_VNET_HDR`, call `TUNSETOFFLOAD` with `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6` (the USO flags require kernel 6.2 or later), and read or write 64 KB superframes. That is why the Android and aicore optimisation strategies diverge, and why copying one to the other wastes a round.

**`io_uring` in Go, today.** The theoretical win is real: `IORING_OP_RECVMSG` multishot plus `IORING_OP_SENDMSG_ZC` removes nearly all syscall overhead. The practical problem is that Go's runtime owns the netpoller, and integrating a submission-queue model alongside it means either running the ring on `LockOSThread` threads outside the scheduler's view (which breaks goroutine parking semantics) or accepting a completion-polling thread that burns a core. Third party bindings exist and work, but they are not production-hardened at fleet scale. **Classify as Stage 3 research, not Stage 2 delivery.** Section 2 reaches the physical ceiling without it.

**`cake` at 2 Gbps.** Single threaded, and it will become the bottleneck before the fiber does. Use `fq`.

**Raising `SO_RCVBUF` past what `rmem_max` allows on an unrooted handset.** `SO_RCVBUFFORCE` bypasses the clamp but requires `CAP_NET_ADMIN`. An Android application does not have it. If `rmem_max` reads 8 MB, 8 MB is the answer, and the code must degrade gracefully rather than pretend otherwise.

**Treating the XRay TCP fallback as a throughput path.** Covered in Section 3.6. Nested congestion control. Document the ceiling, do not chase it.

---

## 6. EXECUTION ORDER

Ordered by expected throughput delta per unit of engineering risk.

1. **Publish the SpeedBench endpoint.** Zero code. Resolves whether the remaining work is worth doing.
2. **Audit the 1373 constant** against Section 3.1. If no obfuscation prefix justifies it, raise Single VPN to 1440 and Double VPN to 1440.
3. **Delete the LocalSocket relay.** `detachFd()` into Go. Expected: +290 Mbps.
4. **Delete the 60 microsecond spin.** Blocking descriptors on pinned OS threads. Expected: recovers 12 to 60 percent of one core.
5. **Run the AEAD benchmark on the physical handset.** If AES-256-GCM wins by 2.5x or more, add negotiation. Expected: +200 to 350 Mbps.
6. **Enable UDP GSO and GRO** on the WAN socket, both Android and aicore. Expected: +90 Mbps on Android, considerably more on aicore.
7. **Apply the aicore sysctls, qdisc, RPS/XPS, and nftables** from Section 3.3 and 3.4.
8. **Confirm BBR plus 64 MB TCP buffer ceilings** on every exit node. This is the entire Double VPN result for de1 and es1.
9. **Build the userspace crossover.** Highest engineering cost, highest aicore ceiling. Keep `winn3gw0` alive as the slow path.
10. **Implement RFC 8899 DPLPMTUD** in Winn v3 and delete every static MTU constant from the codebase.

Items 1 through 8 reach the physical ceiling on Single VPN and the upper half of the band on Double VPN. Items 9 and 10 are what make the result hold at fleet scale instead of on one handset in one lab.

**Podium 3 rests.**
