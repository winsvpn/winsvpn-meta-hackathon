# Stage 1 Submission: stage1_fable51

# Podium 4 Determination: Round 32

## 0. Verdict up front

The 1.35 Gbps plateau is not a buffer problem and it is not a crypto problem. It is a syscall count problem, and the evidence is already in the docket. Zero drops across 3.73 million packets tells you the pipe never overflowed. Download alone hit 1,347 Mbps; download during full-duplex load hit 1,347 Mbps. Identical. The two directions are not contending for a shared resource. Each direction is hitting its own serialized ceiling, which is the signature of a single hot thread per direction doing one syscall per packet, and probably three.

Three findings, ranked by payoff:

1. If the current architecture bridges Go to Kotlin over a LocalSocket and lets Kotlin write the TUN, that bridge is the ceiling. Hand the TUN file descriptor to Go and write it directly. Three syscalls per packet become one. This alone is worth more than every other item on the docket combined.
2. UDP GSO on transmit and UDP GRO on receive are correct, available on the S26 Ultra kernel, and should ship. They cut the UDP side from one syscall per packet to one per 16 to 45 packets.
3. Raising SO_RCVBUF to 16 MB is harmless and mildly useful, but Android will silently clamp it to `net.core.rmem_max`, so verify with `getsockopt` before believing the number. Zero-copy rings to the TUN do not exist. `tun_get_user` performs a mandatory `copy_from_user`. Rings belong between pipeline stages, not at the TUN boundary.

For the double hop: terminated tunnels do not stack MTU loss. Hop 1 ends on aicore, hop 2 begins fresh. The 1373 inner MTU survives both hops untouched provided the egress tunnel interface on aicore is also 1373 and MSS is clamped to 1333. No fragmentation, no ICMP dependence, no headroom math beyond one subtraction.

---

## 1. Level 3: Where the ceiling comes from

### 1.1 Packet rate at target

Take the Ethernet wire on the fiber side. One full-size IPv4 packet of 1500 bytes costs 1538 bytes of line time (14 header, 4 FCS, 8 preamble, 12 interframe gap).

$$
\text{pps}_{2\,\text{Gbps}} = \frac{2 \times 10^9}{1538 \times 8} = 162{,}548 \text{ packets/s}
$$

Every one of those packets is a tunnel datagram. Every one becomes exactly one TUN write on the handset. There is no aggregation available at the Android TUN boundary, for reasons covered in 1.3. So the handset must sustain 162.5 k TUN writes per second on download and 162.5 k TUN reads per second on upload, plus the UDP side.

Per-packet time budget across all cores, per direction:

$$
t_{\text{budget}} = \frac{1}{162{,}548} = 6.15\ \mu\text{s}
$$

Now the current plateau. SpeedBench reports payload, and payload per packet inside the tunnel is 1373 minus 40 bytes of IPv4 plus TCP headers, so 1333 bytes:

$$
\text{pps}_{\text{current}} = \frac{1.345 \times 10^9}{1333 \times 8} = 126{,}125 \text{ packets/s} \quad\Rightarrow\quad t_{\text{observed}} = 7.93\ \mu\text{s}
$$

Roughly 8 microseconds per packet, serialized. On a modern ARM prime core with spectre mitigations enabled, a small syscall costs 1.0 to 2.5 microseconds. A TUN write is heavier because `tun_get_user` builds an skb, copies the payload, and calls `netif_rx` into the backlog: budget 3 to 4 microseconds. ChaCha20-Poly1305 with the arm64 assembly in `golang.org/x/crypto` decrypts 1373 bytes in well under a microsecond. Add a UDP `recvmsg` at 1.5 to 2 microseconds and a LocalSocket hop and you land at exactly 8 microseconds. The model fits the measurement without any free parameters.

Crypto is not on the critical path. Proof: 2 Gbps is 250 MB/s. ChaCha20-Poly1305 on a single big core runs 1.5 to 2.5 GB/s in the Go assembly path. That is 10 to 17 percent of one core. Nothing more.

### 1.2 The real ceiling on a 2 Gbps line

The docket asks for 2,000 Mbps. As a speed-test number, inside the tunnel, on a 2 Gbps circuit, that number is physically unreachable. Payload efficiency is fixed by framing:

$$
\text{Goodput}_{\max} = 162{,}548 \times 1333 \times 8 = 1.733 \text{ Gbps}
$$

Without the VPN, with a 1460 byte MSS, the same line gives 1.898 Gbps. The tunnel tax at perfect efficiency is 8.7 percent. So the honest target is 1.70 to 1.73 Gbps on SpeedBench download, wire-side 2.0 Gbps. Anyone promising 2,000 Mbps in the app UI is promising a violation of arithmetic.

The bidirectional result of 2,470 Mbps combined confirms Wi-Fi 7 airtime is not the limiter. Wi-Fi is half duplex; if the client can move 2.47 Gbps of aggregate airtime, it can move 2.0 Gbps in one direction.

### 1.3 Why Android TUN cannot batch

On desktop Linux, wireguard-go reaches multi-Gbps by opening the TUN with `IFF_VNET_HDR` and enabling `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6` through `TUNSETOFFLOAD`. The kernel then hands the user one 64 KB superpacket per read and accepts one per write. Forty-plus packets per syscall.

Android forbids this. `VpnService.Builder.establish()` returns a descriptor that `netd` already configured with `TUNSETIFF` using `IFF_TUN | IFF_NO_PI` and no `IFF_VNET_HDR`. The vnet header flag can only be set at `TUNSETIFF` time, and the app SELinux domain restricts the `ioctl` xperm set on `tun_device` to a short allow list that does not include changing the interface flags. wireguard-go acknowledges this in `CreateUnmonitoredTUNFromFD`, which disables all offloads on Android. `io_uring` is also off the table: Android's app seccomp filter blocks `io_uring_setup`.

So the handset invariant is hard: one IP packet, one TUN syscall. The only levers left are (a) do not add other syscalls on top of it, and (b) run the TUN syscalls on several threads at once.

### 1.4 TUN writes parallelize cleanly

`tun_get_user` takes no global lock in the write path. It allocates the skb, copies, then calls `netif_rx`, which enqueues onto the per-CPU backlog of the CPU currently executing the write and raises a softirq on that same CPU. Consequence: N writer threads on N cores spread not only the syscall but also the entire IP receive processing across N cores. With four writer threads the per-thread budget at 162.5 k pps becomes 24.6 microseconds per packet. Comfortable.

TUN reads also parallelize. Multiple threads calling `read()` on the same tun fd each dequeue from the same `ptr_ring`. No global serialization beyond the ring itself.

One Go-specific trap: if you wrap the fd in `*os.File` and call `Read` from several goroutines, `internal/poll` serializes them on `fdmu.readLock`. You will have N goroutines and one effective reader. Use raw `unix.Read` and `unix.Write` on the integer fd from goroutines pinned with `runtime.LockOSThread`.

### 1.5 Buffer sizing derivation

A socket buffer is time, not bytes. At 2 Gbps:

$$
T_{\text{absorb}}(8\,\text{MB}) = \frac{8 \times 2^{20} \times 8}{2 \times 10^9} = 33.5\ \text{ms}, \qquad T_{\text{absorb}}(16\,\text{MB}) = 67.1\ \text{ms}
$$

Android scheduler stalls under thermal throttling or cluster migration run 10 to 30 milliseconds. 8 MB is borderline. 16 MB is safe. But `setsockopt(SO_RCVBUF)` is capped at `net.core.rmem_max`, and `SO_RCVBUFFORCE` needs `CAP_NET_ADMIN`, which the app does not have. Set 16 MB, read back with `getsockopt`, log the effective value, and design for whatever the platform grants. Zero drops at 8 MB in the current data suggests the receive buffer is not the constraint today.

---

## 2. Handset engineering: Go and Kotlin diffs

### 2.1 Kotlin: hand the descriptor to Go, delete the LocalSocket bridge

```kotlin
// WinnVpnService.kt

package org.winsvpn.engine

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants

class WinnVpnService : VpnService() {

    private var tunFd: Int = -1

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val pfd: ParcelFileDescriptor = Builder()
            .setSession("Winn v3")
            .setMtu(1373)
            .addAddress("10.10.0.14", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("10.10.0.1")
            .setBlocking(false)
            .setMetered(false)
            .establish() ?: return START_NOT_STICKY

        // detachFd transfers ownership to native code. Kotlin never touches the fd again.
        tunFd = pfd.detachFd()

        // Belt and braces: the Go side will poll on EAGAIN, so keep the fd nonblocking.
        Os.fcntlInt(
            ParcelFileDescriptor.adoptFd(tunFd).also { it.detachFd() }.fileDescriptor,
            OsConstants.F_SETFL,
            OsConstants.O_NONBLOCK
        )

        val udpFd = Engine.openUdpSocket()   // gomobile binding, returns int fd
        protect(udpFd)                      // bypass the VPN for the outer socket

        Engine.start(tunFd, udpFd, "192.168.4.36:9111", EngineConfig(
            rcvBufBytes = 16 shl 20,
            sndBufBytes = 16 shl 20,
            workers = 4,
            enableGso = true,
            enableGro = true
        ))
        return START_STICKY
    }

    override fun onDestroy() {
        Engine.stop()   // Go closes the tun fd and the udp fd itself
        tunFd = -1
        super.onDestroy()
    }
}
```

Every reference to the 1 MB batch accumulator and the 8 MB LocalSocket goes away. The Kotlin process is now control plane only.

### 2.2 Go: TUN reader and writer without spin-wait

The 60 microsecond spin on EAGAIN burns a core when idle and does nothing when saturated (a saturated reader almost never sees EAGAIN). Replace it with: try `read`, and on EAGAIN fall into `poll()` on the tun fd plus a cancel eventfd. Under load the poll path is rarely taken; at idle the thread sleeps properly.

```go
// engine/tun_android.go

package engine

import (
	"errors"
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const tunFrameCap = 1500 // inner MTU is 1373, keep slack for future MTU changes

type TUN struct {
	fd       int
	cancelFd int // eventfd used to wake readers on shutdown
	closed   atomic.Bool
}

func NewTUN(fd int) (*TUN, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &TUN{fd: fd, cancelFd: efd}, nil
}

// Read fills buf with exactly one IP packet. Safe to call from many goroutines at once.
// Callers must have called runtime.LockOSThread so that the poll and read stay on one OS thread.
func (t *TUN) Read(buf []byte) (int, error) {
	for {
		if t.closed.Load() {
			return 0, errTUNClosed
		}
		n, err := unix.Read(t.fd, buf)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, unix.EAGAIN) {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, err
		}
		// Queue empty. Sleep in the kernel until a packet or a cancel arrives.
		fds := [2]unix.PollFd{
			{Fd: int32(t.fd), Events: unix.POLLIN},
			{Fd: int32(t.cancelFd), Events: unix.POLLIN},
		}
		if _, perr := unix.Poll(fds[:], -1); perr != nil && !errors.Is(perr, unix.EINTR) {
			return 0, perr
		}
		if fds[1].Revents&unix.POLLIN != 0 {
			return 0, errTUNClosed
		}
	}
}

// Write injects one IP packet. tun_get_user never blocks, so no poll is needed here.
// Concurrent writers from different OS threads spread netif_rx across CPUs.
func (t *TUN) Write(pkt []byte) error {
	for {
		_, err := unix.Write(t.fd, pkt)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func (t *TUN) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	// Wake every parked reader. Writing 1 to an eventfd is enough because
	// each reader checks t.closed after poll returns.
	var one = [8]byte{1}
	_, _ = unix.Write(t.cancelFd, one[:])
	_ = unix.Close(t.cancelFd)
	return unix.Close(t.fd)
}

var errTUNClosed = errors.New("tun: closed")

// pinToPerformanceCores is best effort. Android allows an app to set affinity on its own
// threads; the foreground cpuset normally includes the full cluster set.
func pinToPerformanceCores(mask []int) {
	runtime.LockOSThread()
	var set unix.CPUSet
	for _, c := range mask {
		set.Set(c)
	}
	_ = unix.SchedSetaffinity(0, &set)
}
```

### 2.3 Go: UDP GSO transmit and GRO receive

`UDP_SEGMENT` exists since Linux 4.18 and `UDP_GRO` since 5.0. The S26 Ultra ships a GKI kernel far past both. Neither is gated by a `CONFIG_` option and neither requires hardware USO: without NIC support the kernel segments in software inside `__udp_gso_segment`, which is still one socket lookup, one route lookup, one netfilter pass per superpacket instead of per datagram.

Constraints that shape the batcher:

- All segments in one GSO datagram must be the same size except the last, which may be shorter.
- At most `UDP_MAX_SEGMENTS` (64) segments, and total payload under 65507 bytes for IPv4.
- One destination per `sendmsg`. Fine: one peer.

Bulk traffic produces long runs of equal-length encrypted datagrams (every full inner packet encrypts to the same outer length), so runs coalesce naturally.

```go
// engine/udp_gso_linux.go

package engine

import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	maxGSOSegments = 64
	maxGSOPayload  = 65507
	batchMsgs      = 32 // sendmmsg / recvmmsg vector length
	groBufBytes    = 65535
)

type UDPBind struct {
	conn  *net.UDPConn
	pc    *ipv4.PacketConn
	fd    int
	peer  *net.UDPAddr
	gso   bool
	gro   bool
	msgs  []ipv4.Message
	oobs  [][]byte
	coals [][]byte // scratch: coalesced GSO payloads
}

func NewUDPBind(fd int, peer *net.UDPAddr, rcvBuf, sndBuf int, wantGSO, wantGRO bool) (*UDPBind, error) {
	f := unixFileFromFd(fd)
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		return nil, errors.New("udp: fd is not a UDP socket")
	}

	b := &UDPBind{conn: uc, pc: ipv4.NewPacketConn(uc), fd: fd, peer: peer}

	// Ask for 16 MB. Android clamps to net.core.rmem_max / wmem_max. Read back and log.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBuf)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, sndBuf)
	effRcv, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	effSnd, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
	logf("udp: SO_RCVBUF effective=%d SO_SNDBUF effective=%d (kernel reports doubled values)", effRcv, effSnd)

	if wantGSO {
		// Probe: setting UDP_SEGMENT to 0 at socket level is legal and proves kernel support.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0); err == nil {
			b.gso = true
		} else {
			logf("udp: UDP_SEGMENT unsupported, falling back to sendmmsg only: %v", err)
		}
	}
	if wantGRO {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1); err == nil {
			b.gro = true
		} else {
			logf("udp: UDP_GRO unsupported, falling back to recvmmsg only: %v", err)
		}
	}

	b.msgs = make([]ipv4.Message, batchMsgs)
	b.oobs = make([][]byte, batchMsgs)
	b.coals = make([][]byte, batchMsgs)
	for i := range b.msgs {
		b.oobs[i] = make([]byte, unix.CmsgSpace(4))
		b.coals[i] = make([]byte, maxGSOPayload)
	}
	return b, nil
}

// gsoControl encodes a UDP_SEGMENT cmsg carrying segSize into oob and returns the used slice.
func gsoControl(oob []byte, segSize uint16) []byte {
	oob = oob[:unix.CmsgSpace(2)]
	for i := range oob {
		oob[i] = 0
	}
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], segSize)
	return oob
}

// SendBatch transmits encrypted datagrams. Equal-length runs are coalesced into GSO
// superpackets; the remainder still goes out through a single sendmmsg call.
func (b *UDPBind) SendBatch(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	n := 0
	for i := 0; i < len(pkts); {
		if n == batchMsgs {
			if err := b.flush(n); err != nil {
				return err
			}
			n = 0
		}
		m := &b.msgs[n]
		m.Addr = b.peer

		if !b.gso {
			m.Buffers = [][]byte{pkts[i]}
			m.OOB = nil
			i++
			n++
			continue
		}

		// Coalesce run: pkts[i..j) where every packet has len == segSize,
		// plus optionally one trailing shorter packet.
		segSize := len(pkts[i])
		dst := b.coals[n][:0]
		segs := 0
		j := i
		for j < len(pkts) && segs < maxGSOSegments {
			l := len(pkts[j])
			if l > segSize || len(dst)+l > maxGSOPayload {
				break
			}
			dst = append(dst, pkts[j]...)
			segs++
			j++
			if l < segSize {
				break // shorter packet must be the final segment
			}
		}
		m.Buffers = [][]byte{dst}
		if segs > 1 {
			m.OOB = gsoControl(b.oobs[n], uint16(segSize))
		} else {
			m.OOB = nil
		}
		i = j
		n++
	}
	return b.flush(n)
}

func (b *UDPBind) flush(n int) error {
	sent := 0
	for sent < n {
		k, err := b.pc.WriteBatch(b.msgs[sent:n], 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		sent += k
	}
	return nil
}

// RecvBatch reads datagrams. With GRO the kernel may return one buffer holding several
// equal-size datagrams and a UDP_GRO cmsg with the segment size. Output is a flat slice of
// individual datagrams backed by bufs; the caller owns bufs for the lifetime of the batch.
func (b *UDPBind) RecvBatch(bufs [][]byte, out [][]byte) ([][]byte, error) {
	for i := range b.msgs[:len(bufs)] {
		b.msgs[i].Buffers = [][]byte{bufs[i]}
		b.msgs[i].OOB = b.oobs[i][:cap(b.oobs[i])]
		b.msgs[i].N = 0
		b.msgs[i].NN = 0
	}
	n, err := b.pc.ReadBatch(b.msgs[:len(bufs)], unix.MSG_WAITFORONE)
	if err != nil {
		return out, err
	}
	out = out[:0]
	for i := 0; i < n; i++ {
		m := &b.msgs[i]
		data := bufs[i][:m.N]
		segSize := groSegmentSize(m.OOB[:m.NN])
		if segSize <= 0 || segSize >= m.N {
			out = append(out, data)
			continue
		}
		for off := 0; off < m.N; off += segSize {
			end := off + segSize
			if end > m.N {
				end = m.N
			}
			out = append(out, data[off:end])
		}
	}
	return out, nil
}

// groSegmentSize parses a UDP_GRO cmsg. The kernel stores gso_size as a C int (4 bytes).
func groSegmentSize(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, c := range cmsgs {
		if c.Header.Level == unix.IPPROTO_UDP && c.Header.Type == unix.UDP_GRO && len(c.Data) >= 4 {
			return int(binary.NativeEndian.Uint32(c.Data[:4]))
		}
	}
	return 0
}
```

Receive buffers for `RecvBatch` must be `groBufBytes` (65535) each when GRO is on, otherwise the kernel truncates coalesced payloads. That is 32 × 64 KB = 2 MB per receiver batch. Preallocate once. Never allocate on the hot path.

### 2.4 Go: pipeline shape and where the ring buffer belongs

```
DOWNLOAD (peer -> app)
  [1 receiver goroutine]  recvmmsg + GRO  -->  SPSC ring per worker (round robin by batch)
  [N=4 workers, pinned]   decrypt batch   -->  unix.Write(tunfd) per packet, in batch order

UPLOAD (app -> peer)
  [N=4 readers, pinned]   unix.Read(tunfd) into per-thread frame pool
                          encrypt inline  -->  per-thread output vector  -->  SendBatch (GSO)
```

The receiver stage is cheap with GRO (one syscall per 20 to 45 packets on a well aggregated Wi-Fi 7 A-MPDU burst), so a single receiver never becomes the bottleneck. The decrypt-plus-TUN-write stage is the heavy one and it is the one that gets N threads.

Ordering: hand out whole batches to workers and have each worker write its batch sequentially. Reordering then only occurs across batch boundaries between workers, which TCP absorbs as occasional out-of-order arrivals within its reordering window. If measurement shows dup-ACK inflation, add a ticket sequencer (each batch takes a monotonically increasing ticket; workers spin on an atomic until their ticket is current before writing). wireguard-go does the equivalent with per-element channels.

The ring itself:

```go
// engine/ring.go

package engine

import (
	"runtime"
	"sync/atomic"
)

// SPSCRing is a single producer, single consumer ring of batch pointers.
// Capacity must be a power of two.
type SPSCRing[T any] struct {
	mask uint64
	buf  []T
	head atomic.Uint64 // consumer position
	tail atomic.Uint64 // producer position
}

func NewSPSCRing[T any](capacity uint64) *SPSCRing[T] {
	if capacity == 0 || capacity&(capacity-1) != 0 {
		panic("ring: capacity must be a power of two")
	}
	return &SPSCRing[T]{mask: capacity - 1, buf: make([]T, capacity)}
}

func (r *SPSCRing[T]) Push(v T) bool {
	t := r.tail.Load()
	if t-r.head.Load() > r.mask {
		return false // full
	}
	r.buf[t&r.mask] = v
	r.tail.Store(t + 1)
	return true
}

func (r *SPSCRing[T]) Pop() (T, bool) {
	var zero T
	h := r.head.Load()
	if h == r.tail.Load() {
		return zero, false
	}
	v := r.buf[h&r.mask]
	r.buf[h&r.mask] = zero
	r.head.Store(h + 1)
	return v, true
}

// PopWait spins briefly then yields. Under saturating load the spin path almost always wins.
func (r *SPSCRing[T]) PopWait() T {
	for spins := 0; ; spins++ {
		if v, ok := r.Pop(); ok {
			return v
		}
		if spins < 64 {
			continue
		}
		runtime.Gosched()
	}
}
```

Also set `debug.SetGCPercent(400)` and a `debug.SetMemoryLimit` sized to the preallocated pools. With no per-packet allocation the GC has nothing to do, but the safety margin costs nothing.

---

## 3. Level 1: Empirical protocol and expected outcome

I cannot execute on the handset from this podium. What follows is the measurement contract the council should hold the implementation to.

Profile first, then change. `simpleperf` from the NDK works on a debuggable build without root:

```bash
adb shell simpleperf record -p $(adb shell pidof org.winsvpn) -g --duration 20 -o /data/local/tmp/perf.data
adb pull /data/local/tmp/perf.data && simpleperf report -i perf.data --sort dso,symbol | head -40
```

Prediction for the current build: `[kernel.kallsyms]` above 55 percent of samples, dominated by `tun_get_user`, `__sys_sendto` or `unix_stream_sendmsg`, `netif_rx`, `copy_from_user` and `el0_svc` entry. Crypto symbols under 12 percent. If crypto shows above 25 percent, my model is wrong and the council should say so in Round 33.

Then the staged rollout, one change per run, 16-stream SpeedBench, three runs each, median:

| Stage | Change | Predicted DL | Predicted UL |
|---|---|---|---|
| S1 (docket) | current | 1,345 | 1,135 |
| S2 | direct TUN fd in Go, LocalSocket removed, 1 worker | 1,500 to 1,600 | 1,350 to 1,450 |
| S3 | S2 + 4 pinned TUN workers | 1,650 to 1,730 | 1,500 to 1,650 |
| S4 | S3 + GSO/GRO | 1,700 to 1,733 | 1,650 to 1,730 |
| S5 | S4 + 16 MB buffers | same as S4 | same as S4 |

Stage 5 is expected to move nothing on throughput. Its value is stall tolerance under thermal throttling during long transfers, which SpeedBench's short window does not exercise. Run a 10 minute iperf3 with `-P 16 -R` to see it.

The Ookla 637 Mbps figure is not an engine number. Ookla uses fewer streams and traverses the public path to a third-party server. Compare Ookla with VPN off on the same server before drawing any conclusion from it.

---

## 4. Double VPN: MTU budget with derivation

### 4.1 The overhead constant

The handset runs 1373 inside on a 1500 byte Wi-Fi path. That fixes the Winn v3 outer overhead:

$$
H_3 = 1500 - 1373 = 127 \text{ bytes} \quad (20\ \text{IPv4} + 8\ \text{UDP} + 99\ \text{Winn v3 framing and tag})
$$

If the actual frame header differs, the arithmetic below holds with the substituted value; only the constant changes.

### 4.2 Terminated hops do not compound

```
Handset          Hop 1 (LAN, 1500)        aicore               Hop 2 (fiber, 1500)        Exit
[inner <= 1373] --encap +127--> [<= 1500] --decap--> [inner <= 1373 on winn3gw0]
                                                      --route--> winn3ex0 (MTU 1373)
                                                      --encap +127--> [<= 1500] --> ca1/de1/es1/ks
```

Hop 1 is decapsulated on aicore. The packet that enters the kernel on `winn3gw0` is the original inner packet, at most 1373 bytes. Hop 2 encapsulates it once, adding 127, producing at most 1500. This is not nesting. A nested design (tunnel inside tunnel end to end) would cost 2 × 127 = 254 and force a 1246 inner MTU. Termination costs one overhead only.

Condition for zero fragmentation on hop 2:

$$
\text{MTU}(\text{winn3ex0}) \geq 1373 \quad\text{and}\quad \text{PMTU}(\text{aicore} \to \text{exit}) \geq 1500
$$

Set `winn3ex0` MTU to exactly 1373. Not higher: if it were 1420, a locally originated 1420 byte packet from aicore itself would fragment. Not lower: a 1373 byte handset packet with DF set would need an ICMP Fragmentation Needed back through hop 1, which works but costs a round trip and depends on the handset stack honoring it.

If the fiber path from aicore has a smaller PMTU (PPPoE at 1492 is the common case), then `winn3ex0` MTU becomes `PMTU - 127` and the handset MTU must drop to match, fleet wide. Probe it once with `ping -M do -s 1472 <NODE_CANADA_IP>`.

### 4.3 MSS clamping

TCP inside a 1373 byte IPv4 packet carries at most:

$$
\text{MSS}_{v4} = 1373 - 20 - 20 = 1333, \qquad \text{MSS}_{v6} = 1373 - 40 - 20 = 1313
$$

Clamp on the forward path in both directions so neither the handset nor the remote server ever emits a segment that would need fragmentation.

### 4.4 Winn v1 AWG and XRay ingress

AWG on UDP 51820 terminates on its own interface (`awg0`) and XRay terminates in userspace and emits into a TUN (`xray0`) or via a SOCKS to TUN bridge. Both must be treated as additional ingress interfaces feeding the same egress. Their inner MTU should also be 1373 for consistency, or lower if their own outer overhead demands it. MSS clamping via `rt mtu` handles any mix automatically.

---

## 5. aicore gateway configuration

### 5.1 sysctls

```bash
# /etc/sysctl.d/90-winn-gateway.conf

net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Asymmetric return paths through tunnels break strict rp_filter. Use loose mode.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.winn3gw0.rp_filter = 0
net.ipv4.conf.winn3ex0.rp_filter = 0

# Socket buffer ceilings for the Go engine's UDP sockets
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.ipv4.udp_rmem_min = 262144
net.ipv4.udp_wmem_min = 262144
net.ipv4.udp_mem = 1048576 2097152 4194304

# Softirq budget: TUN writes land on the per-CPU backlog via netif_rx
net.core.netdev_max_backlog = 250000
net.core.netdev_budget = 1200
net.core.netdev_budget_usecs = 8000

# Receive Packet Steering flow table (paired with rps_cpus below)
net.core.rps_sock_flow_entries = 65536

# Default qdisc for new interfaces
net.core.default_qdisc = fq

# Conntrack sizing if SNAT is used on egress (see 5.3)
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

# Accept PMTU signals, never force fragmentation
net.ipv4.ip_no_pmtu_disc = 0
```

Conntrack hash buckets are a module parameter, not a sysctl:

```bash
echo 262144 > /sys/module/nf_conntrack/parameters/hashsize
```

### 5.2 Interface tuning: txqueuelen, RPS, qdisc

On a TUN device `txqueuelen` sets the size of the `ptr_ring` that userspace reads from (`tun_queue_resize` applies `dev->tx_queue_len`). The default is 500 packets, which at 137 k pps is 3.6 milliseconds of buffering. A Go reader that gets descheduled for 5 milliseconds drops packets. Raise it.

```bash
#!/usr/bin/env bash
# /usr/local/sbin/winn-gw-tune.sh
set -euo pipefail

WAN=eth0
GW=winn3gw0
EX=winn3ex0
AWG=awg0

for dev in "$GW" "$EX" "$AWG"; do
  ip link set dev "$dev" txqueuelen 10000
  tc qdisc replace dev "$dev" root fq limit 20000 flow_limit 2000
done

# Spread backlog processing of TUN injected packets across all cores.
# Mask 'ff' assumes 8 CPUs; adjust to the machine.
for dev in "$GW" "$EX" "$AWG"; do
  for q in /sys/class/net/"$dev"/queues/rx-*; do
    echo ff > "$q/rps_cpus"
    echo 4096 > "$q/rps_flow_cnt"
  done
done

# WAN NIC: one fq child per hardware queue, XPS pins tx queues to cores.
tc qdisc replace dev "$WAN" root mq
i=1
for q in /sys/class/net/"$WAN"/queues/tx-*; do
  tc qdisc replace dev "$WAN" parent 1:"$(printf '%x' $i)" fq limit 20000
  echo "$(printf '%x' $((1 << (i - 1))))" > "$q/xps_cpus"
  i=$((i + 1))
done

# Interrupt coalescing on the WAN NIC: trade 50us of latency for fewer IRQs at 160k pps
ethtool -C "$WAN" adaptive-rx on adaptive-tx on rx-usecs 50 tx-usecs 50 2>/dev/null || true
ethtool -K "$WAN" gro on gso on tso on rx-udp-gro-forwarding on 2>/dev/null || true
```

`rx-udp-gro-forwarding` is worth the attempt: on kernels 5.17 and later it lets the WAN NIC's GRO coalesce inbound UDP that will be forwarded, which matters for the return path from exit nodes into hop 2's socket.

### 5.3 nftables: policy routing, MSS clamp, SNAT

Return traffic from the exit node arrives at aicore addressed to aicore's inner address on `winn3ex0`, so aicore must SNAT the handset's 10.10.0.14 to its own hop-2 inner address. That requires conntrack. If the fleet exit nodes are instead taught a route for 10.10.0.0/24 back through aicore's tunnel, the SNAT and conntrack can be dropped entirely and the forward path becomes stateless. That is the faster design; the SNAT version is shown because it works today without touching the exit nodes.

```nft
#!/usr/sbin/nft -f
# /etc/nftables.d/winn-gateway.nft

flush ruleset

define INGRESS = { "winn3gw0", "awg0", "xray0" }
define EGRESS  = "winn3ex0"
define HOP2_INNER = 10.20.0.2   # aicore's inner address on the hop 2 tunnel

table inet winn {

    # Steer every ingress tunnel into routing table 100 (default via winn3ex0).
    # Equivalent to: ip rule add iif winn3gw0 lookup 100
    chain prerouting_mark {
        type filter hook prerouting priority mangle; policy accept;
        iifname $INGRESS meta mark set 0x64
    }

    # MSS clamp in both directions on the forward path. 'rt mtu' derives the clamp
    # from the outbound route MTU, which gives 1333 for IPv4 and 1313 for IPv6 on a 1373 link.
    chain forward_mangle {
        type filter hook forward priority mangle; policy accept;
        iifname $INGRESS oifname $EGRESS tcp flags syn tcp option maxseg size set rt mtu
        iifname $EGRESS oifname $INGRESS tcp flags syn tcp option maxseg size set rt mtu
    }

    chain forward_filter {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname $INGRESS oifname $EGRESS accept
        # Explicitly refuse hairpinning one client into another via the gateway
        iifname $INGRESS oifname $INGRESS drop
    }

    chain postrouting_nat {
        type nat hook postrouting priority srcnat; policy accept;
        oifname $EGRESS snat ip to $HOP2_INNER
    }
}
```

Routing table setup that the mark points at:

```bash
ip rule add fwmark 0x64 lookup 100 priority 100
ip route add default dev winn3ex0 table 100
ip route add 10.10.0.0/24 dev winn3gw0 table 100
ip link set dev winn3ex0 mtu 1373
ip link set dev winn3gw0 mtu 1373
```

The iptables equivalent of the clamp, for hosts still on legacy tables:

```bash
iptables -t mangle -A FORWARD -i winn3gw0 -o winn3ex0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1333
iptables -t mangle -A FORWARD -i winn3ex0 -o winn3gw0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1333
```

### 5.4 The aicore Go engine gets what Android denies

aicore is real Linux. The same Go engine binary should open its TUN devices with `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR | IFF_MULTI_QUEUE`, one queue fd per worker, and call `TUNSETOFFLOAD` with `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6` (USO needs kernel 6.2 or newer; fall back to the TSO set on older). The kernel then delivers coalesced superpackets on read and accepts them on write, so the forward path on aicore handles 40 packets per syscall on each of the four TUN crossings a double-hop packet makes.

```go
// engine/tun_linux.go (aicore side)

package engine

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunF_CSUM = 0x01
	tunF_TSO4 = 0x02
	tunF_TSO6 = 0x04
	tunF_USO4 = 0x20
	tunF_USO6 = 0x40
)

type ifreq struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	pad   [22]byte
}

// OpenMultiQueueTUN opens n queues on the same interface. Each fd is independently
// readable; the kernel steers flows to queues by rxhash.
func OpenMultiQueueTUN(name string, n int) ([]int, error) {
	fds := make([]int, 0, n)
	for i := 0; i < n; i++ {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			closeAll(fds)
			return nil, err
		}
		var req ifreq
		copy(req.name[:], name)
		req.flags = unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE
		if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req))); e != 0 {
			unix.Close(fd)
			closeAll(fds)
			return nil, e
		}
		offload := uintptr(tunF_CSUM | tunF_TSO4 | tunF_TSO6 | tunF_USO4 | tunF_USO6)
		if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETOFFLOAD, offload); e != 0 {
			// Pre 6.2 kernel: retry without USO
			offload = uintptr(tunF_CSUM | tunF_TSO4 | tunF_TSO6)
			if _, _, e2 := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETOFFLOAD, offload); e2 != 0 {
				unix.Close(fd)
				closeAll(fds)
				return nil, e2
			}
		}
		fds = append(fds, fd)
	}
	return fds, nil
}

func closeAll(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}
```

The virtio-net header parsing and TSO/USO segmentation logic on read, and the coalescing of same-flow TCP segments into superpackets on write, are the same code paths wireguard-go ships in `tun/offload_linux.go`. Reuse that logic rather than rewriting it; it is subtle in exactly the places (checksum offload flags, `hdr_len`, `gso_size`) that produce silent corruption when done by hand.

### 5.5 The stretch path: in-process cut-through

Both hops terminate in one Go process on aicore. The kernel round trip (`winn3gw0` write, route, `winn3ex0` read) exists to give nftables a place to clamp MSS and to keep policy in one place. For established flows that have already been clamped on SYN, that round trip is dead weight: two TUN syscalls and one full IP forwarding pass per packet.

A cut-through table keyed on the inner 5-tuple, populated after the SYN has passed through the kernel path, lets the hop 1 decrypt worker hand the plaintext directly to the hop 2 encrypt worker. Packets not in the table (SYNs, ICMP, first packet of any UDP flow) still take the kernel path and get clamped and counted. This roughly halves per-packet cost on aicore and is the path to the 1,500 Mbps end of the docket range for the nearer exit nodes. It is also a correctness risk (state divergence from conntrack), so it belongs behind a feature flag and after the kernel path has been validated at 1,000 Mbps.

### 5.6 Expected double VPN numbers

| Exit | Approx RTT from aicore | Expected DL (kernel path) | Expected DL (cut-through) |
|---|---|---|---|
| Kansas Core <KANSAS_HUB_IP> | 15 to 30 ms | 1,000 to 1,300 | 1,300 to 1,500 |
| Canada ca1 <NODE_CANADA_IP> | 35 to 60 ms | 800 to 1,100 | 1,000 to 1,300 |
| Germany de1 <NODE_GERMANY_IP> | 90 to 130 ms | 500 to 800 | 600 to 900 |
| Spain <NODE_SPAIN_IP> | 100 to 140 ms | 500 to 750 | 600 to 850 |

Transatlantic figures are bounded by the internet path and the exit node's own engine, not by aicore. A single UDP tunnel across the Atlantic riding on one 5-tuple gets one path through every ECMP hash along the way; 800 Mbps sustained is a good day.

---

## 6. Rulings on the three Single VPN questions

**UDP GSO and GRO.** Adopt. Available on the handset kernel, no hardware dependency, well trodden in wireguard-go since 2023. Expected effect: 20 to 35 percent reduction in UDP-side CPU per packet, which shows up as throughput only once the TUN side stops being the wall. Order of operations matters: TUN fd handoff first, TUN parallelism second, GSO/GRO third.

**Buffers 8 MB to 16 MB.** Adopt as a request, not a guarantee. Read back the effective value. It buys stall tolerance, not throughput. On aicore raise `rmem_max` and `wmem_max` to 32 MB so the engine's request lands.

**Zero-copy lock-free rings to the TUN.** Reject the framing, adopt the mechanism in the right place. There is no zero-copy TUN on Android and none on Linux either without vhost or AF_XDP, neither of which applies here. An SPSC ring per worker between the GRO receiver and the decrypt-and-write workers is correct and cheap. It replaces Go channels (which take a mutex and can park goroutines) with a spin-then-yield handoff. Worth a few percent. Not a headline.

The headline is the one the docket did not list: stop routing packets through Kotlin. That is where the 8 microseconds went.
