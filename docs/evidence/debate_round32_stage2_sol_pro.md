# Stage 2 Rebuttal: stage2_sol_pro

# Stage 2 adversarial cross-rebuttal

## 0. Scope limitation

The supplied record truncates three submissions:

* Podium 2 ends at `Continue f`.
* Podium 3 ends at `Parse`.
* Podium 4 ends at `pinToP`.

I can audit every visible claim and code path. I cannot certify code hidden after those cut points. In particular, Podium 3's and Podium 4's complete GSO and GRO implementations are not present.

## 1. Consolidated verdict

Four corrections control the entire docket.

**First. Direct TUN descriptor ownership is the largest credible handset change if a Go to Kotlin LocalSocket relay is still active.** That conclusion is architectural, not yet quantitative. Podium 3's claimed 1.0 to 2.0 us saving and 1,740 Mbps projection require `simpleperf`, CPU-cycle, and packet-rate measurements before acceptance.

**Second. UDP GSO and GRO must be symmetric across endpoints.**

* Upload: handset GSO, gateway GRO.
* Download: gateway GSO, handset GRO.

Deploying only handset GSO and gateway GRO optimizes upload, not download.

**Third. A 2.00 Gbps application result cannot be certified from the phrase "2 Gbps service."** The ceiling depends on whether the provider shapes Ethernet line bytes, IP bytes, or customer payload. It also depends on actual Winn record overhead and whether the outer route is IPv4 or IPv6.

**Fourth. Double VPN routing cannot be assigned a universal MASQUERADE rule.** Pure routing, fixed SNAT, and MASQUERADE are three different configurations. The correct choice depends on the return routes and source-address policy installed on Kansas Core, ca1, de1, and Spain. Those route tables were not supplied.

---

# 2. Physical ceiling and MTU reconciliation

Let:

* \(M\) be the outer path MTU.
* \(H_o\) be the outer IP header, 20 bytes for IPv4 or 40 for IPv6.
* \(U\) be the UDP header, 8 bytes.
* \(W\) be the measured Winn record overhead.
* \(I\) be the inner IP packet size.
* \(L\) be Ethernet line overhead, normally 38 bytes without a VLAN.
* \(P\) be actual TCP data bytes per inner packet.

The no-fragmentation condition is:

\[
I + H_o + U + W \le M
\]

The application goodput ceiling on a 2 Gbps Ethernet line is:

\[
T_{\max}
=
\frac{2 \times 10^9}{8(I+H_o+U+W+L)}
\times P \times 8
\]

## 2.1 If Winn overhead is 32 bytes

Podium 3 uses \(W=32\). With IPv4 outer transport and \(I=1373\):

\[
S_{\text{outer}}=1373+20+8+32=1433
\]

\[
S_{\text{wire}}=1433+38=1471
\]

\[
PPS=\frac{2 \times 10^9}{1471 \times 8}=169,952
\]

For IPv4 TCP without TCP options:

\[
P=1373-20-20=1333
\]

\[
T_{\max}=169,952 \times 1333 \times 8
=1.8126\text{ Gbps}
\]

Podium 3's arithmetic is correct under those assumptions.

It is not an unconditional physical law. If the provider shapes at outer IP bytes rather than Ethernet line bytes:

\[
T_{\max,\text{IP shape}}
=
2.0 \times \frac{1333}{1433}
=
1.8604\text{ Gbps}
\]

TCP timestamps can reduce actual packet payload below 1333 bytes. The definitive value must come from a packet capture using `tcp.len`, not merely the advertised MSS.

## 2.2 Podium 4's 1.733 Gbps ceiling is internally inconsistent

Podium 4 calculates the frame rate using full 1538-byte Ethernet line occupancy:

\[
PPS=\frac{2 \times 10^9}{1538 \times 8}=162,548
\]

It then assigns only 1333 inner TCP bytes to each frame.

But with a 1373-byte inner packet and 32 bytes of Winn overhead, the outer packet is 1433 bytes, not 1500. It consumes 1471 line bytes, not 1538.

Podium 4's lower 1.733 Gbps result therefore assumes 67 bytes of unexplained padding or additional overhead per packet. The submission does not identify such overhead.

## 2.3 Podium 2's 1.899 Gbps ceiling omits VPN overhead

Podium 2 uses:

\[
2.0 \times \frac{1460}{1538}=1.899\text{ Gbps}
\]

That is a valid approximate ceiling for ordinary IPv4 TCP over Ethernet. It is not the Winn VPN ceiling because it excludes UDP and Winn framing.

The caveat in Podium 2 that tunnel overhead lowers the value is correct. The headline 1.85 to 1.92 Gbps range remains too broad until the actual Winn record length is captured.

## 2.4 Raising the Single VPN MTU

With 32 bytes of Winn overhead and IPv4 outer transport:

\[
I_{\max}=1500-20-8-32=1440
\]

That validates Podium 3's proposed 1440-byte inner MTU for IPv4.

For IPv6 outer transport:

\[
I_{\max}=1500-40-8-32=1420
\]

A fixed 1440-byte inner MTU would fragment or fail on the IPv6 outer route.

The implementation must select MTU from the actual outer address family or conservatively use 1420. Better still, measure the record overhead and path MTU at connection establishment.

---

# 3. Audit of Podium 1

## 3.1 Baseline measurements

Accepted with scope.

The supplied measurements prove that the tested path handled:

\[
1347.18+1122.62=2469.80\text{ Mbps}
\]

They do not prove that 2.47 Gbps crossed the public WAN. Podium 3 correctly identifies the missing topology evidence. If SpeedBench terminated on aicore or another LAN host, the result is a Hop 1 or LAN result.

Required proof:

```bash
ip -s link show dev <aicore-wan>
tcpdump -ni <aicore-wan> host <speedbench-server>
```

WAN byte counters must rise by approximately the tested encrypted byte volume.

## 3.2 Packet-rate calculation

Podium 1 computes:

\[
\frac{2 \times 10^9}{1373 \times 8}=182,083\text{ pps}
\]

That is correct only if 2 Gbps denotes inner IP bytes.

If 2 Gbps denotes TCP application payload and the no-option payload is 1333 bytes:

\[
PPS=\frac{2 \times 10^9}{1333 \times 8}=187,547
\]

The docket must stop mixing inner IP throughput, TCP payload throughput, and Ethernet line rate.

## 3.3 The 1.2 us "context switch" claim

Rejected as unproven.

A syscall changes privilege level, but it does not necessarily trigger a scheduler context switch. The claimed 1.2 us value therefore cannot be multiplied by syscall count and labeled context-switch time.

The calculation is also incomplete. GSO removes outer UDP transmit calls. It does not remove the handset's one-packet-per-call TUN reads. GRO removes UDP receive calls. It does not remove TUN writes.

Measure instead:

```bash
simpleperf stat \
  -e task-clock,cycles,instructions,context-switches,cpu-migrations \
  --app <package> --duration 20
```

## 3.4 GSO and GRO directionality

Podium 1 optimizes only one direction explicitly.

For handset download, the required pair is:

1. Gateway uses UDP GSO to transmit encrypted records.
2. Handset enables UDP GRO and parses `UDP_GRO` ancillary data.
3. Handset still performs one TUN write per inner packet.

For handset upload:

1. Handset uses UDP GSO.
2. Gateway enables UDP GRO.
3. Handset still performs one TUN read per inner packet.

Podium 2 is technically superior on this point.

## 3.5 GSO batch size

Podium 1 uses 45 records of 1402 bytes:

\[
45 \times 1402=63,090\text{ bytes}
\]

That is conservative. It is not derived from the stated 1373-byte inner MTU because encrypted record size is:

\[
E=1373+W
\]

If \(W=32\):

\[
E=1405
\]

\[
\left\lfloor\frac{65507}{1405}\right\rfloor=46
\]

The GSO segment size must be the complete encrypted UDP payload for one record, not the inner packet size.

## 3.6 Socket buffer calculation

Podium 1's basic payload calculation is correct:

\[
2 \times 10^9 \times 0.040 / 8=10,000,000\text{ bytes}
\]

The conclusion that a nominal 16 MB socket buffer "provides complete absorption" is not established.

Linux applies three complications:

1. `SO_RCVBUF` is capped by `net.core.rmem_max`.
2. Linux internally doubles the requested value for bookkeeping.
3. Receive memory accounts skb overhead, not only UDP payload.

The proof is in `net/core/sock.c`, where `SO_RCVBUF` is capped and stored after multiplication. Therefore `getsockopt(SO_RCVBUF)` must be logged, and its value cannot be interpreted as pure payload capacity.

Podium 2 is right that buffer growth is secondary unless `SO_RXQ_OVFL`, softnet drops, or scheduling gaps are observed.

## 3.7 Double VPN MTU

Podium 1 describes Hop 2 as possibly nested inside Hop 1. That does not match the stated terminated topology:

```text
Handset -> aicore terminates Hop 1
aicore -> external gateway starts Hop 2
```

Once Hop 1 terminates, its outer UDP and Winn headers are gone. Hop 2 encapsulates the original inner IP packet afresh.

Podium 4 is correct here.

If both tunnel interfaces carry 1373-byte inner IP packets:

* IPv4 TCP MSS ceiling: \(1373-20-20=1333\).
* IPv6 TCP MSS ceiling: \(1373-40-20=1313\).

There is no second subtraction of both tunnels' outer headers unless one encrypted tunnel packet is literally carried as payload inside the other tunnel.

## 3.8 "Zero-copy kernel forwarding"

Rejected.

If Hop 2 is a userspace tunnel attached through `tun_exit`, forwarding includes:

1. A userspace write into `winn3gw0`.
2. `tun_get_user()` copying into an skb.
3. Kernel forwarding.
4. A userspace read from `tun_exit`.
5. Hop 2 userspace encryption.

Linux `drivers/net/tun.c` uses user-copy operations on those boundaries. That is not zero-copy.

If Hop 2 is kernel WireGuard, the forwarding path avoids the second userspace TUN exchange. It still performs skb processing and encryption.

## 3.9 FQ configuration

The proposed queue can hold:

\[
32768 \times 1400 \times 8
=
367,001,600\text{ bits}
\]

At 1.5 Gbps:

\[
367,001,600 / 1.5 \times 10^9
=
244.7\text{ ms}
\]

A 245 ms maximum queue is not proof of low latency.

The qdisc is also attached only to `winn3gw0`. Linux qdiscs control egress. Upload congestion toward Hop 2 occurs on `tun_exit` or the physical WAN, not on `winn3gw0`.

## 3.10 Wake lock

A partial wake lock prevents CPU suspension. It does not lock Snapdragon frequencies. Android DVFS, scheduler placement, and thermal controls remain active.

Therefore the statement that a permanent wake lock prevents downclocking is false. Frequency residency and thermal status must be measured separately.

---

# 4. Self-audit of Podium 2

## 4.1 Correct conclusions

These survive the adversarial review:

* A 1.5 Gbps Single VPN result needs only an 11.5 percent gain from 1,345.38 Mbps.
* GSO and GRO must be installed on both endpoints according to traffic direction.
* App-level zero-drop telemetry does not prove absence of socket, softirq, NIC, or TCP loss.
* Double VPN cannot be certified without isolated Hop 1, isolated Hop 2, and combined tests.
* The two-stage CPU bound is correctly modeled as a sum when both stages serialize on one core.

## 4.2 Error in GSO batch arithmetic

The original calculation used 1373 bytes as the encrypted GSO segment size:

\[
\left\lfloor 65507/1373 \right\rfloor=47
\]

That is wrong if 1373 is the inner MTU. GSO segments are outer UDP payloads and therefore include Winn framing.

With 32 bytes of framing:

\[
E=1373+32=1405
\]

\[
\left\lfloor 65507/1405 \right\rfloor=46
\]

## 4.3 GRO ancillary-data width

The visible Podium 2 code reads `UDP_GRO` as a 2-byte value.

Podium 3 is correct that Linux uses asymmetric widths:

* `UDP_SEGMENT` transmit cmsg: `__u16`, 2 bytes.
* `UDP_GRO` receive cmsg: native `int`, 4 bytes.

The proof is in Linux `net/ipv4/udp.c`. `udp_cmsg_send()` checks `sizeof(__u16)`, while `udp_cmsg_recv()` passes `sizeof(gso_size)` to `put_cmsg()`, where `gso_size` is an `int`.

Reading only the first two bytes happens to work on little-endian ARM64 for segment sizes below 65,536, but it is ABI-fragile and should be corrected.

## 4.4 Other defects in the visible GSO and GRO code

1. `SO_RXQ_OVFL` failure is treated as fatal. It should be optional because traffic can continue without that metric.
2. Effective buffer values are logged without explaining Linux's doubling semantics.
3. `EINVAL` is classified as GSO unsupported. It can also identify a malformed cmsg or invalid segment layout.
4. Arbitrary variable-length encrypted records cannot be concatenated into one GSO slab. Every segment except the last must have the same length.
5. The callback receives slices backed by a reused receive buffer. It must consume them synchronously or copy them.
6. `SocketDrops` is cumulative and wraps at 32 bits. Metrics should record unsigned deltas, not repeatedly store or add the absolute value.
7. A connected `UDPConn` must use a nil destination in `WriteMsgUDP`.

## 4.5 Socket BDP argument

The 12 ms BDP calculation is arithmetically correct:

\[
2 \times 10^9 \times 0.012 / 8=3,000,000\text{ bytes}
\]

But BDP is not the sole sizing rule for a UDP receive socket. The UDP socket must also absorb application scheduling stalls and burst aggregation. The correct conclusion remains conditional: enlarge only after measuring drops, queue occupancy, or stalls.

## 4.6 SPSC ring vulnerability

The visible record does not contain the ring implementation, so it cannot be certified line by line.

The decisive answer is this:

**A bare atomic SPSC ring does not handle goroutine parking.** If full, its producer must either spin, drop, or wait through a separate notification mechanism. Under sustained TUN backpressure:

* Spinning consumes a core.
* Dropping loses IP packets.
* Parking without a race-safe notification can lose wakeups.

It is also SPSC only. Adding a second TUN reader, crypto worker, or writer invalidates its ownership assumptions.

A 4096-slot ring at 182,083 pps contains:

\[
4096/182083=22.5\text{ ms}
\]

If each slot owns a 1536-byte slab:

\[
4096 \times 1536=6.29\text{ MiB}
\]

That is useful burst absorption, not an unlimited solution.

### Hardened parking-capable SPSC ring

```go
package queue

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var ErrClosed = errors.New("spsc: closed")

type SPSC[T any] struct {
	slots []T
	mask  uint64

	head atomic.Uint64
	tail atomic.Uint64

	notEmpty chan struct{}
	notFull  chan struct{}
	done     chan struct{}

	closed atomic.Bool
	once   sync.Once
}

func NewSPSC[T any](capacity int) *SPSC[T] {
	if capacity < 2 || capacity&(capacity-1) != 0 {
		panic("capacity must be a power of two")
	}
	return &SPSC[T]{
		slots:    make([]T, capacity),
		mask:     uint64(capacity - 1),
		notEmpty: make(chan struct{}, 1),
		notFull:  make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Producer only.
func (q *SPSC[T]) TryPush(v T) bool {
	t := q.tail.Load()
	h := q.head.Load()

	if t-h == uint64(len(q.slots)) {
		return false
	}

	q.slots[t&q.mask] = v
	q.tail.Store(t + 1)
	signal(q.notEmpty)
	return true
}

// Producer only.
func (q *SPSC[T]) Push(ctx context.Context, v T) error {
	for {
		if q.closed.Load() {
			return ErrClosed
		}
		if q.TryPush(v) {
			return nil
		}

		select {
		case <-q.notFull:
		case <-q.done:
			return ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Consumer only.
func (q *SPSC[T]) TryPop() (T, bool) {
	h := q.head.Load()
	if h == q.tail.Load() {
		var zero T
		return zero, false
	}

	i := h & q.mask
	v := q.slots[i]

	var zero T
	q.slots[i] = zero
	q.head.Store(h + 1)
	signal(q.notFull)
	return v, true
}

// Consumer only.
func (q *SPSC[T]) Pop(ctx context.Context) (T, error) {
	for {
		if v, ok := q.TryPop(); ok {
			return v, nil
		}
		if q.closed.Load() {
			var zero T
			return zero, ErrClosed
		}

		select {
		case <-q.notEmpty:
		case <-q.done:
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
	}
}

// Close must be called by the producer after its final Push.
func (q *SPSC[T]) Close() {
	q.once.Do(func() {
		q.closed.Store(true)
		close(q.done)
	})
}
```

The one-slot notification channels preserve an event that occurs immediately before the opposite goroutine parks. Every wakeup is followed by a condition recheck, so coalesced notifications are safe.

A standard bounded Go channel is still a valid alternative. Benchmark both on the actual handset.

---

# 5. Audit of Podium 3

## 5.1 Strongest contributions

Three Podium 3 findings are superior:

1. SpeedBench endpoint topology must be proven.
2. Direct TUN descriptor access is architecturally better than a per-packet LocalSocket relay.
3. `UDP_SEGMENT` uses 2 bytes while received `UDP_GRO` uses 4 bytes.

The recommendation to benchmark AES-GCM against ChaCha20-Poly1305 on the target binary is also correct. Cipher performance depends on Go version, assembly selection, CPU features, and packet length.

## 5.2 Unsupported cost table

The table assigning costs such as 1.70 us to ChaCha20-Poly1305 and 1.00 us to JVM parsing is not empirical evidence. The 1.37 us "residual" is selected to make the total equal the observed 8.17 us.

That gives the model multiple free parameters. It cannot establish that the LocalSocket relay saves exactly 1.45 us.

Required measurement:

* CPU samples by function.
* Packets processed during the sample.
* Cycles per packet before and after direct TUN attachment.
* GC allocation and pause counters.
* Syscall counts by type.

## 5.3 Cipher claims

Podium 3 and Podium 4 make conflicting ChaCha20-Poly1305 claims. Both cite throughput ranges without a target-device benchmark.

The correct decision rule is Podium 3's own benchmark condition. Negotiate AES-GCM only if the actual Android build demonstrates a repeatable packet-rate or cycles-per-byte advantage without changing protocol security properties.

## 5.4 Descriptor duplication

Podium 3 uses `unix.Dup(fd)`. That duplicates the descriptor but not the underlying open file description.

Consequences:

* Closing one descriptor does not close the other.
* `FD_CLOEXEC` is descriptor-specific.
* `O_NONBLOCK` is shared because it belongs to the open file description.

Thus a duplicated TUN descriptor cannot be blocking for reads and nonblocking for writes. Changing `O_NONBLOCK` through either duplicate changes both.

Use `F_DUPFD_CLOEXEC` rather than plain `dup`:

```go
dup, err := unix.FcntlInt(
	uintptr(fd),
	unix.F_DUPFD_CLOEXEC,
	0,
)
```

## 5.5 Blocking TUN shutdown

A blocking `unix.Read` cannot be assumed to terminate immediately when another goroutine closes a duplicate descriptor. Linux permits an in-flight blocking operation to retain a reference to the open file description.

A stop path therefore needs:

* Nonblocking TUN mode.
* `poll` or `epoll`.
* An eventfd or pipe cancellation descriptor.
* A worker join before descriptors are closed.

Podium 4 has the better basic cancellation design, although its implementation contains a close race discussed later.

## 5.6 Broken `adoptFd()` use in `protectOuterSocket`

This code is unsafe:

```kotlin
ParcelFileDescriptor.adoptFd(fd).fileDescriptor
```

`adoptFd(fd)` transfers ownership to the new Java object. Closing or finalizing that object can close the Go-owned UDP socket. That creates a double-close and descriptor-reuse hazard.

Use a duplicate:

```kotlin
fun prepareOuterSocket(fd: Int, network: Network): Boolean {
    if (!protect(fd)) return false

    ParcelFileDescriptor.fromFd(fd).use { duplicate ->
        network.bindSocket(duplicate.fileDescriptor)
    }
    return true
}
```

`fromFd()` duplicates the descriptor. Closing the Java duplicate leaves the Go descriptor open. Socket options applied through the duplicate affect the same socket object.

This must execute before `connect()`.

## 5.7 Network selection

`ConnectivityManager.activeNetwork` is not proof that the selected network is Wi-Fi. It may be cellular, VPN, or another default transport.

The service should retain a validated `Network` obtained from a `NetworkCallback` requiring `TRANSPORT_WIFI`, then pass that specific network to `setUnderlyingNetworks()` and `bindSocket()`.

## 5.8 Thread priority

`THREAD_PRIORITY_URGENT_AUDIO` is intended for latency-sensitive audio work. Podium 3 provides no measurement showing it improves VPN packet throughput or that the operation succeeds under the app's scheduling limits.

Log success and compare:

* Throughput.
* CPU migrations.
* Frequency residency.
* Thermal throttling.
* Audio and UI latency.

## 5.9 In-process Double VPN crossover

The architecture is sound if both Winn stages run in one aicore process:

```text
Hop 1 decrypt -> validate inner packet -> Hop 2 encrypt
Hop 2 decrypt -> validate inner packet -> Hop 1 encrypt
```

This avoids both intermediate TUN copies.

The claimed 2.9 us saving and 1.18 Mpps capacity are unsupported without measurements.

It also bypasses kernel NAT, policy routing, firewalling, and conntrack. That is safe only if:

* The external exit routes the original handset address back through Hop 2.
* Source addresses are unique or session-scoped.
* Anti-spoof checks accept those sources.
* The userspace crossover enforces equivalent route and ACL policy.

---

# 6. Audit of Podium 4

## 6.1 Overstated diagnosis

Zero application drops do not prove that "the pipe never overflowed." Packets can be lost before the engine's receive counter or after its delivered-to-TUN counter.

The identical 1.347 Gbps download values in unidirectional and bidirectional tests show that the added upload did not reduce observed download throughput. They do not uniquely identify a syscall bottleneck.

Other compatible causes include:

* Per-direction worker limits.
* Per-flow pacing.
* Server shaping.
* TUN writer saturation.
* Per-direction CPU affinity.
* Receive-side protocol serialization.

Podium 2's demand for `SO_RXQ_OVFL`, softnet, retransmission, and interface counters is the stronger inference.

## 6.2 Android TUN batching

Podium 4 is likely correct that the standard `VpnService` TUN descriptor lacks `IFF_VNET_HDR` and therefore does not expose Linux TSO or USO superpackets to the app.

That means the normal invariant is one inner IP packet per TUN read or write.

The practical conclusion is valid: remove avoidable per-packet relays and batch only at the outer UDP boundary.

## 6.3 Multiple TUN workers

Concurrent raw `unix.Read` and `unix.Write` calls avoid Go `os.File` read locking. Podium 4 correctly identifies that `internal/poll.FD` can serialize concurrent reads.

But multiple workers introduce ordering hazards.

If two writers receive consecutive packets and the second completes first, TCP sees reordering. TCP tolerates some reordering, but duplicate ACKs and unnecessary retransmission can reduce throughput.

Safer designs are:

* One ordered TUN writer fed by batched decryption workers.
* Per-flow hashing to fixed workers.
* Sequence-number reassembly before TUN injection.

The same concern applies to upload encryption if protocol counters or anti-replay windows assume ordered emission.

## 6.4 Broken Kotlin descriptor expression

This expression is invalid lifecycle management:

```kotlin
ParcelFileDescriptor.adoptFd(tunFd)
    .also { it.detachFd() }
    .fileDescriptor
```

After `detachFd()`, the `ParcelFileDescriptor` no longer owns a valid descriptor. Fetching `fileDescriptor` afterward is not a safe way to call `fcntl`.

It is also redundant because Go calls `unix.SetNonblock()`.

Delete the Kotlin `fcntl` block entirely.

## 6.5 Eventfd shutdown race

Podium 4 performs:

1. Set `closed`.
2. Write to eventfd.
3. Immediately close eventfd.
4. Immediately close TUN fd.

That races polling workers. Linux does not guarantee that closing an fd from another thread safely cancels every in-flight poll without reuse hazards.

The hardened order is:

1. Set `closed`.
2. Write eventfd.
3. Wait for all reader and writer goroutines to exit.
4. Close the TUN fd.
5. Close eventfd.

```go
type TUN struct {
	fd       int
	cancelFd int
	closed   atomic.Bool
	wg       sync.WaitGroup
}

func (t *TUN) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}

	var one [8]byte
	binary.NativeEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(t.cancelFd, one[:])

	t.wg.Wait()

	_ = unix.Close(t.fd)
	return unix.Close(t.cancelFd)
}
```

Every worker must register with `wg` before entering its poll loop.

## 6.6 TUN write assumptions

The statement that `tun_get_user` "never blocks" is too strong. Allocation and memory-pressure paths can sleep, and a nonblocking operation can return `EAGAIN`.

The code also ignores short writes.

Use:

```go
func writePacket(fd int, pkt []byte) error {
	for {
		n, err := unix.Write(fd, pkt)
		if err == nil {
			if n != len(pkt) {
				return io.ErrShortWrite
			}
			return nil
		}

		if errors.Is(err, unix.EINTR) {
			continue
		}

		if errors.Is(err, unix.EAGAIN) {
			fds := []unix.PollFd{{
				Fd:     int32(fd),
				Events: unix.POLLOUT,
			}}
			if _, err := unix.Poll(fds, -1); err != nil &&
				!errors.Is(err, unix.EINTR) {
				return err
			}
			continue
		}

		return err
	}
}
```

## 6.7 Double VPN MTU

Podium 4 is right that terminated tunnels do not automatically compound their outer overhead.

Its MSS statement covers only IPv4. IPv6 needs 1313, not 1333, for a 1373-byte inner MTU.

---

# 7. Hardened UDP GSO and GRO rules

## 7.1 Required invariants

A valid GSO batch must satisfy all of these:

1. Every record is independently encrypted and authenticated.
2. Every segment except the last has identical length.
3. All segments use the same destination, socket, traffic class, and path.
4. The segment size is the encrypted UDP payload length.
5. The resulting datagram fits path MTU.
6. The segment count is limited to the kernel-supported maximum, conservatively 64.
7. Interactive traffic has a flush timer so it does not wait for a full 64 KB batch.

At 182,083 pps, filling 47 packets takes:

\[
47/182083=258\text{ us}
\]

A 16-packet batch takes:

\[
16/182083=87.9\text{ us}
\]

A practical policy is count-based flush plus a measured 50 to 100 us maximum residence time.

## 7.2 Correct GSO ancillary message

```go
const (
	udpSegment = 103
	udpGRO     = 104
)

func makeGSOCmsg(segmentSize uint16) []byte {
	oob := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))

	h.Level = int32(unix.SOL_UDP)
	h.Type = int32(udpSegment)
	h.SetLen(unix.CmsgLen(2))

	start := unix.CmsgLen(0)
	binary.NativeEndian.PutUint16(
		oob[start:start+2],
		segmentSize,
	)
	return oob
}
```

## 7.3 Correct GRO parser

```go
type GROControl struct {
	SegmentSize int
	SocketDrops uint32
}

func parseGROControl(
	oob []byte,
	oobn int,
) (GROControl, error) {
	var out GROControl

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return out, err
	}

	for _, msg := range msgs {
		switch {
		case msg.Header.Level == unix.SOL_UDP &&
			msg.Header.Type == udpGRO:

			if len(msg.Data) != 4 {
				return out, fmt.Errorf(
					"UDP_GRO cmsg length %d, want 4",
					len(msg.Data),
				)
			}

			n := binary.NativeEndian.Uint32(msg.Data)
			if n == 0 || n > 65535 {
				return out, fmt.Errorf(
					"invalid UDP_GRO segment size %d",
					n,
				)
			}
			out.SegmentSize = int(n)

		case msg.Header.Level == unix.SOL_SOCKET &&
			msg.Header.Type == unix.SO_RXQ_OVFL:

			if len(msg.Data) != 4 {
				return out, fmt.Errorf(
					"SO_RXQ_OVFL cmsg length %d, want 4",
					len(msg.Data),
				)
			}
			out.SocketDrops =
				binary.NativeEndian.Uint32(msg.Data)
		}
	}

	return out, nil
}
```

Drop deltas must use unsigned arithmetic:

```go
delta := uint32(current - previous)
previous = current
metrics.SocketDrops.Add(uint64(delta))
```

## 7.4 Runtime probing

Kernel version strings are insufficient because Android vendors backport and disable features.

Enable GRO and classify only documented unsupported errors:

```go
func enableGRO(fd int) (bool, error) {
	err := unix.SetsockoptInt(
		fd,
		unix.SOL_UDP,
		udpGRO,
		1,
	)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) {
		return false, nil
	}

	return false, err
}
```

Do not silently classify every `EINVAL` as unsupported. It can expose an implementation defect.

When GRO is unavailable, use `recvmmsg`. When GSO is unavailable, use `sendmmsg` if available, otherwise per-datagram sends.

---

# 8. Android TUN descriptor lifecycle

## 8.1 `detachFd()`

Correct when Java permanently transfers ownership to native code.

Contract:

1. Java calls `detachFd()` exactly once.
2. Java never closes or wraps that integer again.
3. Native code closes it exactly once.
4. Native attach failure must still consume and close the descriptor, or clearly return ownership.

This is fast, but ownership mistakes become double-close or descriptor-reuse bugs.

## 8.2 Synchronous `dup()` handoff

This is the safest same-process design.

Kotlin retains the original until native confirms duplication:

```kotlin
val pfd = builder.establish()
    ?: error("establish failed")

val ok = Engine.attachBorrowedTun(
    pfd.fd,
    profile.innerMtu
)

// Native owns its duplicate after success.
pfd.close()

if (!ok) {
    error("native TUN attachment failed")
}
```

Native side:

```go
func AttachBorrowedTun(fd int, mtu int) error {
	dupFD, err := unix.FcntlInt(
		uintptr(fd),
		unix.F_DUPFD_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("dup tun fd: %w", err)
	}

	if err := unix.SetNonblock(dupFD, true); err != nil {
		unix.Close(dupFD)
		return err
	}

	installTun(dupFD, mtu)
	return nil
}
```

The setup cost is one `fcntl` call per connection. It has no per-packet cost.

## 8.3 `SCM_RIGHTS`

Use `SCM_RIGHTS` only when the engine runs in another process or security domain. Raw integer fd values are process-local.

`SCM_RIGHTS` duplicates the open file description in the receiving process. The receiver should use `MSG_CMSG_CLOEXEC` or immediately set `FD_CLOEXEC`.

It is valid to use one Unix socket operation for descriptor setup. It is not valid to relay every VPN packet through that socket.

On Android, Binder transfer of a `ParcelFileDescriptor` is often simpler than manually implementing `SCM_RIGHTS`.

---

# 9. Double VPN routing and NAT decision

No supplied evidence identifies the return routes or anti-spoof policy on Kansas Core, ca1, de1, or Spain. Therefore no podium can honestly prescribe one universal NAT rule.

## 9.1 Pure policy routing

Use pure routing when the external exit:

* Accepts source `10.10.0.14` or the assigned handset subnet.
* Has a return route through Hop 2.
* Does not require Hop 2 traffic to use only aicore's assigned address.

Example:

```bash
ip rule add pref 100 \
  from 10.10.0.0/24 \
  lookup hop2

ip route add table hop2 \
  default dev tun_exit

ip route add \
  10.10.0.0/24 dev winn3gw0
```

Firewall:

```nft
table inet winn {
    chain forward {
        type filter hook forward priority filter;
        policy drop;

        iifname "winn3gw0" oifname "tun_exit" \
            ct state new,established,related accept

        iifname "tun_exit" oifname "winn3gw0" \
            ct state established,related accept
    }
}
```

## 9.2 Fixed SNAT

Use fixed SNAT when Hop 2 accepts only aicore's assigned tunnel address.

```nft
table ip winn_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat;

        oifname "tun_exit" \
            ip saddr 10.10.0.0/24 \
            snat to $HOP2_FIXED_ADDRESS
    }
}
```

For a stable tunnel address, fixed SNAT is more precise than MASQUERADE.

## 9.3 MASQUERADE

Use MASQUERADE only when the Hop 2 address is dynamic and can change when the interface reconnects:

```nft
oifname "tun_exit" ip saddr 10.10.0.0/24 masquerade
```

MASQUERADE performs dynamic address selection and conntrack cleanup associated with interface-address changes. That behavior is unnecessary for a stable address.

## 9.4 Multiple clients with overlapping addresses

If every handset is assigned `10.10.0.14`, pure routing cannot distinguish multiple simultaneous clients carried over one Hop 2 tunnel.

The options are:

* Assign unique inner addresses.
* Allocate separate Hop 2 sessions.
* Apply per-session SNAT.
* Carry a session identifier in the protocol and demultiplex in userspace.

This requirement must be resolved before certifying the Double VPN design.

## 9.5 Required node verification

Run on every named exit:

```bash
ip route get 10.10.0.14
ip rule show
ip route show table all
nft list ruleset
```

Then capture both directions:

```bash
tcpdump -ni tun_exit host 10.10.0.14
```

Decision rule:

* Request and reply both traverse Hop 2 with source `10.10.0.14`: pure routing works.
* Request arrives but no reply route exists: install return route or use SNAT.
* Request is rejected by source policy: use the assigned Hop 2 source or change the ACL.
* Hop 2 address changes on reconnect: MASQUERADE may be appropriate.

---

# 10. TCP MSS hardening

`TCPMSS --clamp-mss-to-pmtu` is correct only if the kernel route exposes the actual tunnel MTU.

If `tun_exit` reports 1500 while the userspace tunnel accepts only 1373, automatic clamping will advertise an oversized MSS.

Set interface MTUs correctly:

```bash
ip link set dev winn3gw0 mtu 1373
ip link set dev tun_exit mtu 1373
```

Then clamp forwarded SYN and SYN-ACK packets:

```bash
iptables -t mangle -A FORWARD \
  -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu

ip6tables -t mangle -A FORWARD \
  -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
```

Expected ceilings:

\[
MSS_{IPv4}=1373-20-20=1333
\]

\[
MSS_{IPv6}=1373-40-20=1313
\]

MSS clamping does nothing for UDP or QUIC. Correct interface MTU and ICMP fragmentation-needed or IPv6 packet-too-big delivery remain necessary.

---

# 11. Final engineering order

1. **Prove the test topology.** Confirm whether SpeedBench crosses aicore's WAN.
2. **Measure actual Winn overhead.** Capture encrypted UDP lengths and determine whether framing is 17, 32, or another value.
3. **Remove any per-packet Go to Kotlin relay.** Use synchronous native `dup()` handoff or a strict `detachFd()` ownership contract.
4. **Deploy GSO and GRO in both traffic directions.** Correct the 4-byte GRO ancillary parser.
5. **Replace spin-only SPSC behavior.** Use bounded parking with race-safe notification.
6. **Set and verify interface MTUs.** Use 1333 IPv4 MSS and 1313 IPv6 MSS for a 1373-byte inner MTU.
7. **Choose routing or NAT per exit.** Do not install unconditional MASQUERADE.
8. **Test Hop 1, Hop 2, and Double VPN separately.**
9. **Measure socket drops, softnet drops, retransmissions, cycles per packet, and thermal state.**
10. **Treat 1.8 Gbps as the likely Single VPN payload ceiling only after line-rate semantics and protocol overhead are verified.**

The strongest combined design is direct TUN access, bidirectional UDP offload, terminated-hop MTU accounting, bounded scheduler-safe queues, and exit-specific routing policy. The claimed 2.00 Gbps application target and 1.50 Gbps Double VPN target remain hypotheses until the WAN topology and isolated Hop 2 capacity are measured.
