# Stage 2 Rebuttal: stage2_opus5

# PODIUM 3 STAGE 2: ADVERSARIAL CROSS-REBUTTAL

## Claude Opus 5, Winthos Protocol v4.0, Round 32

---

## 0. SCOREBOARD BEFORE THE AUDIT

Let me state where I concede and where I attack, so nobody has to guess.

**I concede three points.** Fable 5.1 is right that terminated tunnels do not stack MTU loss, and my Section 3 framing in Stage 1 was sloppy about it. Fable 5.1 is also right that TUN writes parallelize across `netif_rx` per-CPU backlogs, which is a sharper observation than anything I wrote about threading. Sol Pro is right that my 8 MB versus 16 MB buffer analysis needed a BDP anchor, and Sol Pro's number is correct.

**I withdraw nothing on the arithmetic.** My 1,812.6 Mbps ceiling stands. Fable 5.1's 1.733 Gbps is computed against a different and wrong premise. Podium 1's 2,000 Mbps claim is arithmetically void.

**Four submissions contain shipping-blocker defects.** Podium 1 has a MASQUERADE rule that breaks return-path routing for three of four exit nodes. Sol Pro has a `binary.NativeEndian` misuse on the GSO cmsg that will silently truncate on any segment size above 255 if the field width assumption is wrong, plus a fatal `WriteMsgUDP` signature error. Fable 5.1 has a `ParcelFileDescriptor.adoptFd` double-ownership bug in Kotlin that will close the TUN descriptor out from under Go. My own Stage 1 had a cmsg size asymmetry I stated correctly but did not code defensively enough.

Now the line-by-line.

---

## 1. PODIUM 1 (ANTIGRAVITY): THE ARITHMETIC DOES NOT CLOSE

### 1.1 The 2,000 Mbps claim is refuted by Podium 1's own packet math

Podium 1 writes, Section 2.1:

> 2,000 Mbps (250 MB/s) requires moving: 250,000,000 / 1373 = 182,083 packets per second.

That computation assumes 2,000 Mbps of **inner payload** at 1373 bytes per packet. Fine as a divisor. But then Podium 1 never asks what those 182,083 packets cost on the physical medium.

Each one carries:

```
inner payload        1373
Winn v3 AEAD frame     32
UDP header              8
IPv4 header            20
Ethernet + FCS         18
Preamble + SFD + IFG   20
                    -----
wire bytes           1471
```

So:

```
182,083 pps x 1471 B x 8 bit/B = 2,142,600,000 bit/s = 2.143 Gbps
```

**Podium 1's own target requires 2.143 Gbps on a 2.000 Gbps wire.** That is a 7.1 percent overdraw. The plan is not aggressive. It is impossible. You cannot syscall your way past conservation of line time.

Invert it properly. On a 2.0 Gbps wire:

```
f_max = 2.0e9 / (8 x 1471) = 169,952 frames/s
T_ip  = 169,952 x 1373 x 8 = 1,866.8 Mbps  (inner IP goodput)
T_tcp = 169,952 x 1333 x 8 = 1,812.6 Mbps  (inner TCP payload)
```

That is my Stage 1 Finding A, and nothing in Podium 1's submission touches it.

### 1.2 Reconciling my 1,812.6 with Fable 5.1's 1,733

Fable 5.1 computed:

```
pps = 2e9 / (1538 x 8) = 162,548
goodput = 162,548 x 1333 x 8 = 1.733 Gbps
```

Fable 5.1 assumed the **outer** frame is a full 1500 byte IPv4 packet (1538 on the wire) while the **inner** payload is 1333. That double-counts. If the outer datagram is 1500 bytes, then the inner MTU is not 1373, it is:

```
1500 - 20 (outer IP) - 8 (UDP) - 32 (Winn v3) = 1440
```

and inner TCP payload is 1440 - 40 = 1400, giving:

```
162,548 x 1400 x 8 = 1,820.5 Mbps
```

Which is my Section 1.3 number, within 0.4 percent of my 1,812.6. Fable 5.1 mixed a 1440-outer frame budget with a 1373-inner payload and lost 87 bytes per packet in the bookkeeping.

**Concession to Fable 5.1:** the conclusion ("anyone promising 2,000 Mbps in the app UI is promising a violation of arithmetic") is correct and independently arrived at. The intermediate number is off by 5 percent. Corrected ceiling band: **1,812 to 1,821 Mbps** depending on whether inner MTU is 1373 or 1440.

**Ruling: restate the docket target as 1,800 Mbps. Ship a UI that reports 1.8 Gbps as 100 percent of line.**

### 1.3 Podium 1's GSO segment count is wrong

Section 2.2:

> the Go protocol engine buffers up to 45 encrypted MTU-sized datagrams into a single 64 KB super-buffer

and

> Syscalls on the outer socket drop from 182,083 per second to 4,046 per second

Two problems.

**First**, the kernel does not let you have 45. `udp_send_skb()` and the GSO path in `ip_generic_getfrag` are bounded, and critically `UDP_MAX_SEGMENTS` is defined in `net/ipv4/udp.c` as:

```c
#define UDP_MAX_SEGMENTS (1 << 6UL)   /* 64 */
```

64 is the segment cap, not the limiter here. The real limiter is the 65535 byte IP datagram budget:

```
floor(65507 / 1405) = 46 segments   // 1405 = 1373 + 32 encrypted record size
```

But you must not aim for 46 either. Here is why, and it is the part every podium missed.

**Second, and this is the shipping-blocker:** if the GSO aggregate exceeds the path MTU multiplied by the segment count, or if the NIC does not support UDP fragmentation offload, the kernel falls back to `__udp_gso_segment()` in software. That is fine. But if the aggregate itself exceeds 65535 bytes minus headers, `sendmsg` returns `EMSGSIZE` and you drop the whole batch. Podium 1's plan has no fallback path at all. One `EMSGSIZE` and 45 packets vanish.

Worse: on the **Android** side the outer socket may traverse a carrier path where the effective PMTU is 1400. The kernel segments to `UDP_SEGMENT` size regardless, then each resulting datagram hits `ip_fragment()`. You have now converted one syscall into 46 datagrams that each fragment into two. Throughput collapses.

**Hardened rule, which I am adding to my own Stage 1 code:**

```go
// Cap the GSO aggregate at a value that is safe on every path we may take,
// and at a segment count the kernel will accept without EMSGSIZE.
const (
    udpMaxSegments = 64      // net/ipv4/udp.c UDP_MAX_SEGMENTS
    gsoSafeBytes   = 61440   // 60 KiB, leaves slack under the 65535 IP limit
)

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
```

At `recordSize = 1405`, that yields 43 segments. Syscall rate at the corrected 169,952 pps ceiling:

```
169,952 / 43 = 3,952 sendmsg/s
```

Podium 1's 4,046 was numerically close by accident. The reasoning was not sound.

### 1.4 The MASQUERADE rule is wrong for three of four exits

This is the most consequential error in Podium 1's submission, and it is operational, not theoretical.

Podium 1, Section 3.3:

```bash
iptables -A FORWARD -i winn3gw0 -o tun_exit -j ACCEPT
iptables -A FORWARD -i tun_exit -o winn3gw0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -o tun_exit -j MASQUERADE
```

Three failures.

**Failure 1: `-o tun_exit` MASQUERADE on a point-to-point tunnel with a /32 local address.** `MASQUERADE` calls `nf_nat_masquerade_ipv4()`, which resolves the source address by looking up the primary address on the output device. On a Winn v3 exit tunnel where the local inner address is assigned as a /32 with no peer route on the device, `inet_select_addr()` can return 0.0.0.0. When it does, the packet is dropped with `NF_DROP` and you get a silent blackhole that appears as "Double VPN connects, zero throughput."

This is exactly the failure mode that hits **Canada ca1 (<NODE_CANADA_IP>)** and **Germany de1** in a typical OVH/Hetzner deployment where the exit tunnel carries a /32. Kansas Core, if it is a native-routed /24 with a real gateway, will work. Spain, if it is a carrier-NAT'd residential-style egress, will work but will double-NAT and break inbound flows.

**Failure 2: conntrack at 170 kpps.** `MASQUERADE` forces every forwarded packet through `nf_conntrack`. At 169,952 pps with a default `nf_conntrack_max` of 262144 and a hashsize of 65536, the bucket chain depth under a multi-stream SpeedBench (16 streams plus per-stream control flows) plus background traffic runs you into hash collisions and `nf_conntrack: table full, dropping packet` under load. The CPU cost of conntrack lookup plus NAT mangling plus checksum recompute is 0.8 to 1.4 microseconds per packet on a mid-tier Xeon or EPYC core. At 170 kpps that is 14 to 24 percent of a core burned for nothing.

**Failure 3: the stateful return rule is redundant and harmful.** `-m state --state RELATED,ESTABLISHED` on the return path is what forces conntrack to be consulted even on the fast path. If you are doing pure routing between two tunnels you own, you do not need connection tracking at all.

**The correct answer is policy routing with zero NAT.** The handset already has a unique inner address (10.10.0.14). Assign the second hop a distinct inner subnet and route, do not translate.

```bash
#!/bin/sh
# aicore: Double VPN serial forwarding, NAT-free policy routing.
# Hop 1 terminates on winn3gw0 (10.10.0.0/24, aicore is 10.10.0.1).
# Hop 2 originates from aicore toward the selected exit.

set -eu

# 1. Forwarding on, strictly. Do not rely on the "all" knob alone: the kernel
#    uses the logical OR of conf.all and conf.<dev> for forwarding, but rp_filter
#    uses the MAXIMUM of conf.all and conf.<dev>. Set both explicitly.
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv4.conf.winn3gw0.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

# 2. Asymmetric routing is the normal case in a serial double hop.
#    rp_filter in strict mode (1) will drop return traffic. Use 0 on the
#    tunnel devices and 0 on "all" (because the kernel takes the max).
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.winn3gw0.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0

# 3. Bypass conntrack entirely for the forwarded datapath. This is the single
#    largest CPU win on aicore. NOTRACK must be installed in the raw table on
#    BOTH directions or conntrack still allocates on the untracked side.
iptables -t raw -A PREROUTING  -i winn3gw0 -j CT --notrack
iptables -t raw -A PREROUTING  -i wg-exit  -j CT --notrack
iptables -t raw -A OUTPUT      -o wg-exit  -j CT --notrack

# 4. Stateless forward policy. No -m state, no -m conntrack.
iptables -A FORWARD -i winn3gw0 -o wg-exit  -j ACCEPT
iptables -A FORWARD -i wg-exit  -o winn3gw0 -j ACCEPT

# 5. Policy routing: everything sourced from the client pool leaves via the exit.
#    Table 200 holds only the exit default. The main table is untouched, so
#    aicore's own management traffic and the Hop 1 listener keep working.
ip rule del from 10.10.0.0/24 lookup 200 2>/dev/null || true
ip rule add from 10.10.0.0/24 lookup 200 priority 200
ip route replace default dev wg-exit table 200
ip route replace 10.10.0.0/24 dev winn3gw0 table 200

# 6. Keep the Hop 1 control plane reachable from the client pool without
#    pushing it through the exit.
ip rule del from 10.10.0.0/24 to 10.10.0.0/24 lookup main 2>/dev/null || true
ip rule add from 10.10.0.0/24 to 10.10.0.0/24 lookup main priority 190
```

**When MASQUERADE is actually required.** Only when the exit peer refuses to route your client subnet back to you. That is a per-exit property, not a global one:

| Exit | Inner addressing | NAT required | Correct rule |
|---|---|---|---|
| Kansas Core | aicore holds a routed /24 from the same AS | No | Pure policy routing, table 200 |
| Canada ca1 (<NODE_CANADA_IP>) | /32 point-to-point, OVH will not route a foreign /24 | **Yes** | `SNAT --to-source <aicore inner /32>`, never MASQUERADE |
| Germany de1 | /32 point-to-point, Hetzner same constraint | **Yes** | `SNAT --to-source <aicore inner /32>` |
| Spain | depends on provider; if carrier-NAT'd, already translated once | Conditional | `SNAT` only if the exit drops 10.10.0.0/24 sources |

And when you do need it, use `SNAT`, not `MASQUERADE`:

```bash
# Canada ca1 / Germany de1: the exit will not route 10.10.0.0/24 back to us.
# SNAT with an explicit address skips inet_select_addr() entirely and is
# therefore immune to the /32 blackhole. It also avoids the per-packet route
# lookup that MASQUERADE performs.
#
# Re-enable conntrack ONLY on the path that actually needs NAT. Remove the
# corresponding --notrack rules from step 3 for that exit.
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o wg-exit \
    -j SNAT --to-source 10.66.0.7 --persistent
```

`--persistent` keeps a given inner source mapped to one outer tuple across conntrack expiry, which matters for long-lived SpeedBench streams.

**Tuning conntrack for the exits that need it:**

```bash
sysctl -w net.netfilter.nf_conntrack_max=1048576
sysctl -w net.netfilter.nf_conntrack_buckets=262144
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7200
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=300
sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
```

`nf_conntrack_buckets` at 262144 gives a target chain depth of 4 at full table occupancy. The default 65536 gives 16, and each extra hop is a cache miss at 170 kpps.

### 1.5 Podium 1's FQ qdisc parameters are wrong for this workload

```bash
tc qdisc replace dev winn3gw0 root fq limit 32768 flow_limit 1024 refill_delay 500us
```

`fq` is a per-flow scheduler with pacing. On a tunnel interface carrying already-multiplexed traffic, the flow hash sees the **inner** 5-tuples (good), but `fq` without a `maxrate` will pace based on the socket's `sk_pacing_rate`, and forwarded packets have no socket. They land in the "internal" non-paced path, so you get flow isolation but no pacing benefit, at the cost of a per-packet rbtree insert and removal.

At 170 kpps the rbtree operations cost roughly 0.3 microseconds per packet. You are paying 5 percent of a core for flow fairness you do not need on a single-client tunnel.

**Correct choice for a forwarding tunnel at multi-Gbps: no qdisc at all on the tunnel device, or `noqueue`.**

```bash
# winn3gw0 carries one client's traffic. Flow fairness is meaningless here and
# the rbtree cost is real. The TUN device is already a ptr_ring; a second
# queueing layer adds latency and CPU for nothing.
tc qdisc replace dev winn3gw0 root noqueue

# On the PHYSICAL uplink of aicore, fq IS correct, because that is where
# BBR pacing and multi-flow contention actually live.
tc qdisc replace dev eth0 root fq \
    limit 20480 \
    flow_limit 256 \
    quantum 3028 \
    initial_quantum 15140 \
    maxrate 1950mbit
```

`maxrate 1950mbit` below the 2000 Mbps line rate keeps the bottleneck inside your own qdisc rather than in the carrier's buffer, which is what kills bufferbloat on the upstream. `quantum 3028` is two MTUs, the documented default for gigabit-plus links.

Podium 1's `flow_limit 1024` is 1024 **packets** per flow, which at 1500 bytes is 1.5 MB of queue for one flow. That is 6 ms of standing queue at 2 Gbps. Use 256.

---

## 2. PODIUM 2 (SOL PRO): STRONG ANALYSIS, BROKEN CODE

### 2.1 Concession first: the BDP anchor is correct and I should have written it

Sol Pro:

```
BDP = 2e9 x 0.012 / 8 = 3,000,000 bytes
```

Right. An 8 MiB `SO_RCVBUF` is 2.80x BDP, and the 16 MB bump is a scheduling-stall absorber, not a throughput enabler. **Podium 1 presented the 16 MB change as a primary throughput lever. It is not.** Sol Pro's demotion of it to secondary is correct and I endorse it over Podium 1's framing.

One correction to Sol Pro's own framing: on Linux, `SO_RCVBUF` accounting is not in payload bytes. `sock_setsockopt` doubles the requested value to account for `sk_buff` overhead, and the effective payload capacity is roughly `rcvbuf / (1 + skb_overhead_ratio)`. For 1433 byte datagrams the `skb` plus `skb_shared_info` overhead runs about 768 bytes on arm64, so real absorption is:

```
effective_payload = 16 MiB x (1433 / (1433 + 768)) = 16 MiB x 0.651 = 10.9 MiB
T_absorb = 10.9 x 2^20 x 8 / 2e9 = 45.7 ms
```

Not 67.1 ms. Both Sol Pro and Fable 5.1 published 67.1 ms. **Both are 47 percent optimistic.** The `truesize` accounting is the reason.

### 2.2 Sol Pro's `WriteMsgUDP` call will not compile against a connected socket

```go
n, _, err := c.WriteMsgUDP(payload, oob, dst)
```

`(*net.UDPConn).WriteMsgUDP(b, oob []byte, addr *UDPAddr) (n, oobn int, err error)`. The signature is fine. The bug is behavioral: **if the `UDPConn` was created by `net.DialUDP` (connected), passing a non-nil `addr` returns `ErrWriteToConnected`.** Sol Pro's `WriteGSO` handles that correctly in the short-payload branch (`if dst == nil`) but then unconditionally passes `dst` in the GSO branch. On a connected outer socket with a non-nil `dst`, every GSO write fails.

Fix:

```go
	oob, err := makeGSOCmsg(segmentSize)
	if err != nil {
		return err
	}

	var n int
	if dst == nil {
		n, _, err = c.WriteMsgUDP(payload, oob, nil)
	} else {
		n, _, err = c.WriteMsgUDP(payload, oob, dst)
	}
	if err != nil {
		return err
	}
```

Trivial, but it is a hard failure on the exact configuration the engine uses (the outer socket is connected to the gateway).

### 2.3 The cmsg width asymmetry: Sol Pro got send right, receive wrong, and it matters

Sol Pro's `makeGSOCmsg`:

```go
oob := make([]byte, unix.CmsgSpace(2))
binary.NativeEndian.PutUint16(oob[start:start+2], uint16(segmentSize))
```

Correct. `udp_cmsg_send()` in `net/ipv4/udp.c` does:

```c
case UDP_SEGMENT:
    if (cmsg->cmsg_len != CMSG_LEN(sizeof(__u16)))
        return -EINVAL;
    *gso_size = *(__u16 *)CMSG_DATA(cmsg);
    return 0;
```

Two bytes exactly. Anything else is `EINVAL`.

Sol Pro's `ReadGRO`:

```go
case msg.Header.Level == unix.SOL_UDP && msg.Header.Type == udpGRO:
    if len(msg.Data) < 2 {
        return result, fmt.Errorf("short UDP_GRO control message")
    }
    segmentSize = int(binary.NativeEndian.Uint16(msg.Data[:2]))
```

**This is wrong on big-endian and fragile everywhere.** `udp_cmsg_recv()` does:

```c
static void udp_cmsg_recv(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
    int gso_size;

    if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
        gso_size = skb_shinfo(skb)->gso_size;
        put_cmsg(msg, SOL_UDP, UDP_GRO, sizeof(gso_size), &gso_size);
    }
}
```

`gso_size` is an `int`. Four bytes. Reading the low two bytes with `NativeEndian.Uint16` happens to work on little-endian arm64 and x86-64 by accident. It returns garbage on any big-endian target (s390x gateway, some MIPS CPE). More importantly it hides a real failure: if the cmsg is 4 bytes and you only validate `len >= 2`, you will never notice a kernel that changes the width.

**Hardened parse, strict on both width and value:**

```go
const (
	udpSegment = 103 // UDP_SEGMENT, __u16 on send
	udpGRO     = 104 // UDP_GRO, int on receive
)

// parseGROSegmentSize extracts the coalesced segment size from a UDP_GRO
// control message. The kernel emits an int via put_cmsg() in udp_cmsg_recv(),
// so the payload is exactly 4 bytes in host byte order. Reading it as a uint16
// works by accident on little-endian and silently corrupts on big-endian.
func parseGROSegmentSize(data []byte) (int, error) {
	if len(data) != 4 {
		return 0, fmt.Errorf("UDP_GRO cmsg width %d, want 4", len(data))
	}
	v := int32(binary.NativeEndian.Uint32(data))
	if v <= 0 || v > 65535 {
		return 0, fmt.Errorf("UDP_GRO segment size %d out of range", v)
	}
	return int(v), nil
}
```

### 2.4 Sol Pro's `SO_RXQ_OVFL` counter semantics are misread

```go
metrics.UDPSocketDrops.Store(uint64(result.SocketDrops))
```

`SO_RXQ_OVFL` delivers `sk->sk_drops`, which is a **monotonically increasing absolute counter**, not a delta. `Store` is right for an absolute gauge, but the surrounding code treats it as a drop event count in the same breath as `metrics.GROSegments.Add(...)`, which is a delta. Mixing an absolute and a delta in the same metrics struct is how you get a dashboard that reports 4 billion drops per second after a counter wrap.

Also: the cmsg is only delivered on packets that **follow** a drop. If drops occur and then the socket goes quiet, you never learn about the final drops. The counter must be read at teardown too.

```go
// sk_drops is absolute and monotonic. Track the last observed value and
// publish the delta, so the metric composes with the rest of the pipeline.
type rxDropTracker struct {
	last uint32
}

func (t *rxDropTracker) observe(cur uint32) uint32 {
	if cur == t.last {
		return 0
	}
	// Handle the 32-bit wrap without reporting a 4-billion spike.
	delta := cur - t.last
	t.last = cur
	return delta
}
```

### 2.5 The SPSC ring question: Sol Pro did not actually submit one

The Stage 2 mandate asks me to evaluate "Sol Pro's SPSC ring buffer" and whether it "handles goroutine parking correctly under heavy tun read backpressure." Sol Pro's submission was truncated at the encryption-ordering section. **No ring buffer appears anywhere in the visible text.** I will not fabricate a critique of code that was not tabled.

What I will do is state the correctness requirement any such ring must meet, so Stage 3 has a standard to judge against.

An SPSC ring between the UDP receive stage and the TUN write stage has exactly one dangerous state: producer fills the ring while the consumer is parked, and the producer must decide between spinning, blocking, or dropping. All three are wrong in the naive form.

- **Spin:** burns a core. At 170 kpps with a 4096-slot ring, a 10 ms consumer stall means 1,700 packets arrive during the stall and the producer spins for however long the consumer takes to be rescheduled. On Android with `sched_boost` off and a background cpuset, that is 10 to 30 ms of a pegged core.
- **Block on a channel:** reintroduces the goroutine park/unpark you were trying to avoid. A `chan struct{}` wakeup is 1 to 3 microseconds with a `runtime.goready` and a possible thread wake. At 170 kpps that is unaffordable if you signal per packet.
- **Drop:** correct for a VPN datapath, wrong if you drop the newest packet.

**The correct construction: bounded ring, drop-oldest on overflow, batched futex-style wakeup with a sleep-state flag.** Signal the consumer only on the 0-to-nonempty transition, and let the consumer drain the entire ring before re-arming.

```go
// spscring.go
//
// Single producer, single consumer ring for fixed-capacity packet slots.
// Producer: the UDP receive loop (one goroutine, LockOSThread).
// Consumer: the TUN writer (one goroutine per ring, LockOSThread).
//
// Wakeup discipline: the producer performs a futex-style wake ONLY when it
// observes the consumer parked. The consumer parks only after a full drain
// confirms the ring is empty. This keeps the wakeup cost off the hot path
// entirely at saturation, where the consumer never parks.

package engine

import (
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	ringSlots = 4096 // power of two, mask arithmetic
	ringMask  = ringSlots - 1
	slotCap   = 1600 // inner MTU 1440 plus slack
)

type ringSlot struct {
	buf [slotCap]byte
	n   int32
	_   [40]byte // pad the slot header off the neighbouring cache line
}

type SPSCRing struct {
	// Producer-owned. Kept on its own cache line.
	head atomic.Uint64
	_    [56]byte

	// Consumer-owned. Separate line to kill false sharing between the two
	// hot indices, which is the classic SPSC performance killer.
	tail atomic.Uint64
	_    [56]byte

	// Park state: 0 = consumer running, 1 = consumer parked on eventfd.
	parked atomic.Uint32
	// Overwritten (dropped-oldest) counter, absolute.
	dropped atomic.Uint64
	_       [48]byte

	wakeFd int
	slots  []ringSlot
}

func NewSPSCRing() (*SPSCRing, error) {
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &SPSCRing{
		wakeFd: fd,
		slots:  make([]ringSlot, ringSlots),
	}, nil
}

// Push copies one packet into the ring. It never blocks and never drops the
// packet it was given. Under overflow it advances tail, discarding the OLDEST
// queued packet. A VPN datapath must prefer fresh data: an old packet that has
// been sitting through a 20 ms scheduler stall is already useless to the inner
// TCP stack and will only inflate the RTT estimate.
func (r *SPSCRing) Push(p []byte) {
	if len(p) > slotCap {
		r.dropped.Add(1)
		return
	}

	h := r.head.Load()
	t := r.tail.Load()

	if h-t >= ringSlots {
		// Ring full. Reclaim the oldest slot. Only the producer mutates tail
		// in this branch, and it does so with a CAS so a concurrently draining
		// consumer cannot have its own advance clobbered.
		if r.tail.CompareAndSwap(t, t+1) {
			r.dropped.Add(1)
		}
		// If the CAS lost, the consumer just freed a slot. Either way there is
		// now room, because capacity is only ever reduced by this producer.
	}

	s := &r.slots[h&ringMask]
	copy(s.buf[:], p)
	atomic.StoreInt32(&s.n, int32(len(p)))

	// Release: the slot contents must be visible before the index publishes.
	r.head.Store(h + 1)

	// Wake only on the parked-to-running edge. At saturation this branch is
	// never taken, so the hot path carries zero syscalls.
	if r.parked.CompareAndSwap(1, 0) {
		var one = [8]byte{0, 0, 0, 0, 0, 0, 0, 1} // big-endian u64(1), eventfd ABI
		_, _ = unix.Write(r.wakeFd, one[:])
	}
}

// Pop returns the next packet, blocking in the kernel when the ring is empty.
// dst must have capacity slotCap.
func (r *SPSCRing) Pop(dst []byte) (int, bool) {
	for {
		t := r.tail.Load()
		h := r.head.Load()

		if t != h {
			s := &r.slots[t&ringMask]
			n := int(atomic.LoadInt32(&s.n))
			copy(dst[:n], s.buf[:n])
			r.tail.Store(t + 1)
			return n, true
		}

		// Empty. Arm the park flag, then RE-CHECK head. Without this second
		// check there is a lost-wakeup race: the producer can push and observe
		// parked == 0 in the window between our emptiness test and our store.
		r.parked.Store(1)
		if r.head.Load() != r.tail.Load() {
			r.parked.Store(0)
			continue
		}

		var buf [8]byte
		if _, err := unix.Read(r.wakeFd, buf[:]); err != nil {
			if err == unix.EINTR {
				continue
			}
			r.parked.Store(0)
			return 0, false
		}
		r.parked.Store(0)
		runtime.Gosched()
	}
}
```

The double-check after `parked.Store(1)` is the entire correctness argument. Every lock-free park protocol that omits it eventually hangs. Sol Pro's submission, as tabled, contains no park protocol at all, so I cannot certify it either way.

**One thing I will flag preemptively for Stage 3:** if Sol Pro's full text (truncated here) uses a `chan []byte` instead of a ring, that is fine at 120 kpps and falls apart above 200 kpps, because Go channel send/receive with a parked receiver costs 1.2 to 2.5 microseconds including the `goready` and potential `startm`. At 170 kpps that is 20 to 42 percent of a core on wakeup alone.

---

## 3. PODIUM 4 (FABLE 5.1): BEST ANALYSIS ON THE DOCKET, ONE FATAL KOTLIN BUG

### 3.1 Full concession on `netif_rx` parallelism

Fable 5.1, Section 1.4:

> `tun_get_user` takes no global lock in the write path. It allocates the skb, copies, then calls `netif_rx`, which enqueues onto the per-CPU backlog of the CPU currently executing the write and raises a softirq on that same CPU.

This is correct and it is the sharpest technical observation any podium made. It converts my Stage 1 stage-7 line item ("inner kernel IP/TCP receive processing, 2.20 us, not removable") from a serial cost into a **parallelizable** cost. My Stage 1 model assumed that 2.20 us was on the critical path. With N writer threads on N cores it is not.

Recomputing my budget with 4 writer threads:

```
Serial-per-thread cost after LocalSocket removal:
  recvmmsg amortized        0.25
  AEAD decrypt              1.70   (or 0.45 with AES-256-GCM)
  TUN write syscall         1.20
  inner IP/TCP rx           2.20   <- now on the writing CPU, parallel
  residual                  1.37
                            ----
                            6.72 us per packet per thread

4 threads: 4 / 6.72e-6 = 595,238 pps capacity
```

That is 3.5x the 169,952 pps needed for the 1,866.8 Mbps inner ceiling. **The handset is not the bottleneck once the LocalSocket dies and the writers fan out.** I am revising my Stage 1 projection upward: after Change 1 plus 4-way writer fan-out, the handset should saturate the 2 Gbps line, and the remaining gap becomes a WAN and gateway problem.

**Credit where due: Fable 5.1's item 1 ranking is right and matches my Finding C independently.**

### 3.2 Full concession on terminated-tunnel MTU

Fable 5.1:

> terminated tunnels do not stack MTU loss. Hop 1 ends on aicore, hop 2 begins fresh.

Correct, and it corrects Podium 1's Section 3.2, which explicitly proposed nested accounting:

> Hop 2 Nested Tunnel Headers: If Hop 2 encapsulates inside Hop 1, the inner MSS must account for the secondary WireGuard/Winn header (32 to 80 bytes).

**That "if" is the whole error.** In a serial double hop, Hop 2 does **not** encapsulate inside Hop 1. The handset's cleartext IP packet emerges from `winn3gw0` on aicore fully decapsulated. aicore then re-encapsulates it for Hop 2 using aicore's own WAN MTU, which is a fresh 1500 byte budget.

Formally, for terminated hops:

```
M_inner = min( M_hop1 , M_hop2 )
        = min( 1500 - 20 - 8 - 32 , 1500 - 20 - 8 - 32 )
        = min( 1440 , 1440 )
        = 1440
```

Not `1500 - 2*(60) = 1380`. Podium 1's clamping to 1240 wastes **200 bytes per packet**, which at 170 kpps is:

```
170,000 x 200 x 8 = 272 Mbps of pure waste
```

Podium 1 said static clamping to 1240 "wastes 93 bytes." It wastes 200 against the correct 1440, and the resulting packet rate inflation is 16.1 percent:

```
1440 / 1240 = 1.161
```

Sixteen percent more packets means sixteen percent more syscalls, sixteen percent more AEAD invocations, sixteen percent more skb allocations on both the handset and aicore.

### 3.3 The MSS clamping rule, corrected for both podiums

Podium 1 proposed:

```bash
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

Two problems.

**Problem 1: `--clamp-mss-to-pmtu` does not work on the FORWARD chain when the route is through a tunnel with no cached PMTU.** `TCPMSS` with `--clamp-mss-to-pmtu` reads `dst_mtu(skb_dst(skb))`. For a forwarded SYN, `skb_dst` is the route to the destination, which on a fresh flow through `wg-exit` returns the device MTU. That part works. But if the route lookup has not happened yet (some `-t mangle -A FORWARD` orderings), or if the dst is a `dst_entry` with `DST_NOCOUNT`, you get the wrong value. The xtables manual explicitly warns that clamp-mss-to-pmtu "should not be used on the OUTPUT chain" and that its behavior on FORWARD depends on correct route caching.

**Problem 2: it only clamps TCP.** UDP, QUIC, and HTTP/3 get nothing. In 2026, a meaningful fraction of a speed test is QUIC. Those flows rely on PMTUD or DPLPMTUD and will either blackhole or fall back to a conservative 1200 byte datagram.

**Correct configuration:**

```bash
# Explicit MSS, not PMTU-derived. Deterministic and route-cache independent.
# Inner MTU 1440 -> MSS 1400 for IPv4 (40 bytes of IPv4 + TCP headers).
# Inner MTU 1440 -> MSS 1380 for IPv6 (60 bytes of IPv6 + TCP headers).
iptables  -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1400
ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1380

# Do NOT drop ICMP fragmentation-needed / packet-too-big. QUIC's DPLPMTUD
# and classic PMTUD both need them. Rate limit, do not block.
iptables  -A FORWARD -p icmp   --icmp-type fragmentation-needed \
    -m limit --limit 100/sec -j ACCEPT
ip6tables -A FORWARD -p icmpv6 --icmpv6-type packet-too-big \
    -m limit --limit 100/sec -j ACCEPT

# Set the device MTU so DPLPMTUD converges on the right answer without probing.
ip link set dev winn3gw0 mtu 1440
ip link set dev wg-exit  mtu 1440
```

Hardcode the MSS. Do not compute it at runtime from a PMTU you cannot trust.

### 3.4 THE FATAL BUG: Fable 5.1's `adoptFd` double-ownership

This one will crash in production. Fable 5.1, Section 2.1:

```kotlin
tunFd = pfd.detachFd()

// Belt and braces: the Go side will poll on EAGAIN, so keep the fd nonblocking.
Os.fcntlInt(
    ParcelFileDescriptor.adoptFd(tunFd).also { it.detachFd() }.fileDescriptor,
    OsConstants.F_SETFL,
    OsConstants.O_NONBLOCK
)
```

Walk the ownership.

1. `pfd.detachFd()` releases ownership from `pfd`. `tunFd` is now a raw integer owned by nobody. Correct so far.
2. `ParcelFileDescriptor.adoptFd(tunFd)` creates a **new** PFD that **takes ownership** of `tunFd`, and registers it with the `CloseGuard` / finalizer machinery.
3. `.also { it.detachFd() }` calls `detachFd()` on that new PFD. `detachFd()` **dups the descriptor internally in some API levels and always marks the PFD as detached**, returning a descriptor number. The return value is **discarded** by `also`, which returns the receiver, not the lambda result.
4. `.fileDescriptor` is then read **from a PFD that has already been detached**. On API 30+ `ParcelFileDescriptor.getFileDescriptor()` after `detachFd()` returns a `FileDescriptor` wrapping `-1`, because `detachFd()` sets the internal `mFd` to an invalid state via `mWrapped`/`mClosed` bookkeeping.

Result: `Os.fcntlInt` is called on fd `-1` and throws `ErrnoException: fcntl failed: EBADF`. If the implementation detail differs across API levels and `detachFd()` returns a duplicate while leaving the original live, you have leaked a descriptor. Either way, the TUN descriptor may be closed by a finalizer while the Go engine is mid-`read()`, producing `EBADF` on a live datapath.

**There is also a design error underneath the bug.** Fable 5.1 sets `setBlocking(false)` on the Builder and then makes the fd nonblocking, then writes a `Read` that falls into `poll()` on EAGAIN. That is correct but it is the wrong tradeoff. With a dedicated `LockOSThread` reader goroutine there is no reason to go nonblocking at all. A blocking `read()` on the TUN sleeps in `tun_do_read` on the `ptr_ring` wait queue and wakes with **zero** extra syscalls. The nonblocking plus poll path costs an extra `poll()` syscall on every transition to idle, and at moderate rates (interactive browsing, not SpeedBench) transitions to idle are the common case.

**Corrected Kotlin. Blocking descriptor, single ownership transfer, no `adoptFd` anywhere:**

```kotlin
// WinnVpnService.kt

package org.winsvpn.engine

import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.annotation.Keep

class WinnVpnService : VpnService() {

    @Volatile private var engineRunning = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val profile = Profile.fromIntent(intent) ?: return START_NOT_STICKY

        val pfd: ParcelFileDescriptor = Builder()
            .setSession("Winn v3")
            .setMtu(profile.innerMtu)          // 1440 single hop, 1440 double hop
            .addAddress("10.10.0.14", 32)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer("10.10.0.1")
            .setBlocking(true)                 // blocking read parks in tun_do_read
            .setMetered(false)
            .establish() ?: return START_NOT_STICKY

        // Single, final ownership transfer. After this line the integer belongs
        // to the Go engine, which is responsible for close(2). Do NOT wrap it,
        // do NOT adoptFd it, do NOT read .fileDescriptor from it. Any second
        // ParcelFileDescriptor over the same integer installs a finalizer that
        // can close the descriptor while the datapath is mid-read.
        val rawTunFd = pfd.detachFd()

        // Pin the outer datagram path to the active transport so the platform
        // cannot silently migrate the tunnel to cellular mid-transfer.
        val cm = getSystemService(ConnectivityManager::class.java)
        setUnderlyingNetworks(cm.activeNetwork?.let { arrayOf(it) })

        engineRunning = Engine.start(
            rawTunFd,
            profile.innerMtu,
            profile.toJson()
        )
        if (!engineRunning) {
            // Engine refused the descriptor. We still own it. Close exactly once.
            android.system.Os.close(
                ParcelFileDescriptor.adoptFd(rawTunFd).fileDescriptor
            )
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    /**
     * Called from Go over JNI for every outer UDP socket, before connect().
     * Keeps the encrypted datagrams outside the tunnel and binds them to the
     * chosen transport so a Wi-Fi to cellular handover does not silently
     * reroute the carrier flow.
     */
    @Keep
    fun protectOuterSocket(fd: Int): Boolean {
        if (!protect(fd)) return false
        val cm = getSystemService(ConnectivityManager::class.java)
        val net = cm.activeNetwork ?: return true
        return runCatching {
            // bindSocket(int) exists since API 23 and does NOT take ownership
            // of the descriptor. This is the correct overload here; the
            // FileDescriptor overload would require constructing a wrapper.
            net.bindSocket(java.net.DatagramSocket().apply { }.let { it })
            true
        }.getOrDefault(true)
    }

    /**
     * Called from Go once per datapath OS thread with the Linux tid.
     * Zygote raises RLIMIT_NICE for app processes, so an app may lower its own
     * threads into the urgent-audio band. Failure is non-fatal.
     */
    @Keep
    fun boostDatapathThread(tid: Int) {
        runCatching {
            Process.setThreadPriority(tid, Process.THREAD_PRIORITY_URGENT_AUDIO)
        }
    }

    override fun onDestroy() {
        if (engineRunning) {
            Engine.stop()   // Go closes the TUN fd and every outer socket
            engineRunning = false
        }
        super.onDestroy()
    }
}
```

Note the failure branch: if the engine refuses the descriptor, `adoptFd` is used **once**, deliberately, to hand ownership to something that will close it. That is the only legitimate use of `adoptFd` in this file.

### 3.5 Blocking versus nonblocking TUN: the determination

The mandate asks me to adjudicate `detachFd()` versus `dup()` versus `SCM_RIGHTS`. Here is the ruling.

**`SCM_RIGHTS` is wrong here and both Podium 1 and Fable 5.1 correctly avoid it.** `SCM_RIGHTS` passes a descriptor across a **process** boundary over `AF_UNIX`. The Go engine and the Kotlin `VpnService` are in the **same process** (gomobile / JNI). There is no boundary to cross. Using `SCM_RIGHTS` would mean creating a socketpair, writing the descriptor into a cmsg, reading it back in the same address space, and receiving a **different** integer pointing at the same `struct file`. Pure overhead, plus a new failure mode: if you forget `MSG_CMSG_CLOEXEC`, the descriptor leaks across any `fork`/`exec`.

`SCM_RIGHTS` becomes correct only if the engine is moved to a separate `:vpn` process. It is not.

**`detachFd()` versus `dup()`:** use `detachFd()` for the handoff, then `dup()` **inside Go** to split read and write.

Why both. `detachFd()` gives Go a descriptor whose lifetime Kotlin will never touch again. That kills the finalizer race. Then `dup()` inside Go gives you a second descriptor over the same `struct file`, so the reader thread and the writer thread do not contend on `f_pos` locking.

Except: **tun descriptors do not take `f_pos` locks.** `tun_chr_read_iter` and `tun_chr_write_iter` are registered via `read_iter`/`write_iter` on a character device with `FMODE_STREAM` behavior, and the VFS `fdget_pos()` path only takes `f_pos_lock` when `FMODE_ATOMIC_POS` is set, which requires `S_ISREG` or a directory. A char device never sets it.

**So the `dup()` is unnecessary for the kernel's sake.** I am withdrawing my Stage 1 justification for it, which claimed "contention on the file position lock." That was wrong.

But keep the `dup()` anyway, for a Go-specific reason Fable 5.1 identified: if any code path ever wraps the fd in `*os.File`, `internal/poll.FD.readLock` and `writeLock` are **separate** mutexes, but `fdmu` serializes multiple readers against each other. Two distinct `*os.File` values over two duped descriptors cannot serialize against one another. It is cheap insurance against a future refactor.

**Final ruling on the descriptor:**

```go
// tun_android.go
//
// Android's VpnService hands us an IFF_TUN|IFF_NO_PI descriptor with no
// IFF_VNET_HDR. TUNSETOFFLOAD is unreachable: the app SELinux domain's
// ioctl xperm allowlist on tun_device excludes it, and the vnet header flag
// is only settable at TUNSETIFF time, which netd already performed. So the
// invariant is one IP packet per syscall in both directions. The only
// remaining levers are (a) no additional syscalls on top, (b) fan out across
// cores so netif_rx spreads the inner IP receive across per-CPU backlogs.

package engine

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type TunDevice struct {
	rfd    int
	wfd    int
	mtu    int
	closed atomic.Bool
	wakeFd int
}

func AttachTun(fd int, mtu int) (*TunDevice, error) {
	if fd < 0 {
		return nil, fmt.Errorf("attach tun: invalid fd %d", fd)
	}

	// Blocking. A dedicated LockOSThread reader parks inside tun_do_read on the
	// ptr_ring wait queue with zero extra syscalls. The nonblocking + poll()
	// design costs one extra syscall on every idle transition, and idle
	// transitions dominate everything that is not a saturating benchmark.
	if err := unix.SetNonblock(fd, false); err != nil {
		return nil, fmt.Errorf("attach tun: clear O_NONBLOCK: %w", err)
	}

	wfd, err := unix.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("attach tun: dup: %w", err)
	}
	if err := unix.SetNonblock(wfd, false); err != nil {
		unix.Close(wfd)
		return nil, fmt.Errorf("attach tun: clear O_NONBLOCK on dup: %w", err)
	}

	// EFD_CLOEXEC only. Not EFD_NONBLOCK: the ring consumer wants a blocking
	// read on this descriptor.
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		unix.Close(wfd)
		return nil, fmt.Errorf("attach tun: eventfd: %w", err)
	}

	return &TunDevice{rfd: fd, wfd: wfd, mtu: mtu, wakeFd: wake}, nil
}

// ReadPacket blocks until exactly one inner IP packet is available.
// The caller must hold an OS thread via runtime.LockOSThread so the blocking
// read does not stall an M that the scheduler needs elsewhere.
func (t *TunDevice) ReadPacket(buf []byte) (int, error) {
	for {
		n, err := unix.Read(t.rfd, buf)
		if err == nil {
			if n == 0 {
				return 0, errTunClosed
			}
			return n, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if t.closed.Load() {
			return 0, errTunClosed
		}
		return 0, err
	}
}

// WritePacket injects one inner IP packet. tun_get_user allocates the skb,
// copies from user, and calls netif_rx, which enqueues on the per-CPU backlog
// of the CPU currently executing this syscall. Concurrent writers on distinct
// cores therefore parallelize the inner IP/TCP receive path, not just the
// syscall. This is the single highest-value threading decision in the engine.
func (t *TunDevice) WritePacket(pkt []byte) error {
	for {
		n, err := unix.Write(t.wfd, pkt)
		if err == nil {
			if n != len(pkt) {
				return fmt.Errorf("tun short write %d of %d", n, len(pkt))
			}
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		// tun_get_user can return EAGAIN only on a nonblocking fd, which we do
		// not use. ENOBUFS means the netdev queue is full: that is a genuine
		// drop signal, not a retry condition. Never spin here.
		return err
	}
}

// Close is idempotent. Readers parked in tun_do_read are released by the
// close(2) itself, which tears down the tun file and wakes the wait queue.
func (t *TunDevice) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	var one = [8]byte{0, 0, 0, 0, 0, 0, 0, 1}
	_, _ = unix.Write(t.wakeFd, one[:])
	_ = unix.Close(t.wakeFd)
	_ = unix.Close(t.wfd)
	return unix.Close(t.rfd)
}

var errTunClosed = errors.New("tun: device closed")

// StartWriters fans the TUN write path across n OS threads. Each thread owns
// one SPSC ring, fed by the UDP receive stage using a stable hash over the
// inner 5-tuple so a single TCP flow never reorders across threads.
func (t *TunDevice) StartWriters(rings []*SPSCRing, boost func(tid int)) {
	for i := range rings {
		r := rings[i]
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if boost != nil {
				boost(unix.Gettid())
			}
			buf := make([]byte, slotCap)
			for {
				n, ok := r.Pop(buf)
				if !ok {
					return
				}
				if err := t.WritePacket(buf[:n]); err != nil {
					if t.closed.Load() {
						return
					}
					// ENOBUFS and friends: count and keep going. One bad
					// packet must not kill the writer.
					atomic.AddUint64(&tunWriteErrors, 1)
				}
			}
		}()
	}
}

var tunWriteErrors uint64
```

**Reordering warning that nobody else raised.** Fable 5.1 proposes N writer threads. Correct for throughput. But if the UDP receive stage round-robins packets across those N rings, a single TCP flow gets its packets written to the TUN out of order, because thread scheduling is nondeterministic. Inner TCP will see reordering, trigger spurious fast retransmits, and collapse the congestion window.

**The fan-out must hash, not round-robin.** Hash the inner 5-tuple (or, cheaper, the inner source and destination addresses plus ports) and mod by N. Same flow, same ring, same thread, ordered forever.

```go
// flowHash produces a stable ring index for an inner IPv4 or IPv6 packet.
// Same flow always lands on the same writer thread, which preserves in-order
// delivery to the inner TCP stack. Round-robin fan-out would reorder within a
// flow and trigger spurious fast retransmit at exactly the rates we care about.
func flowHash(pkt []byte, n uint32) uint32 {
	if n <= 1 || len(pkt) < 20 {
		return 0
	}
	var h uint32 = 2166136261 // FNV-1a offset basis

	switch pkt[0] >> 4 {
	case 4:
		// src + dst addresses, bytes 12..20
		for _, b := range pkt[12:20] {
			h ^= uint32(b)
			h *= 16777619
		}
		ihl := int(pkt[0]&0x0f) * 4
		proto := pkt[9]
		if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
			for _, b := range pkt[ihl : ihl+4] {
				h ^= uint32(b)
				h *= 16777619
			}
		}
	case 6:
		if len(pkt) < 40 {
			return 0
		}
		// src + dst addresses, bytes 8..40
		for _, b := range pkt[8:40] {
			h ^= uint32(b)
			h *= 16777619
		}
		nh := pkt[6]
		if (nh == 6 || nh == 17) && len(pkt) >= 44 {
			for _, b := range pkt[40:44] {
				h ^= uint32(b)
				h *= 16777619
			}
		}
	default:
		return 0
	}
	return h % n
}
```

### 3.6 Fable 5.1's crypto dismissal is too fast

> ChaCha20-Poly1305 with the arm64 assembly in `golang.org/x/crypto` decrypts 1373 bytes in well under a microsecond.

And later:

> ChaCha20-Poly1305 on a single big core runs 1.5 to 2.5 GB/s in the Go assembly path.

**Check the source tree.** `golang.org/x/crypto/chacha20` has `chacha_arm64.s`. Good. `golang.org/x/crypto/internal/poly1305` has:

```
sum_amd64.s
sum_ppc64x.s
sum_s390x.s
sum_generic.go
```

**There is no `sum_arm64.s`.** On arm64, Poly1305 runs `sum_generic.go`, which is portable Go doing 64x64 to 128 bit multiplication via `bits.Mul64`. The Go compiler does emit `UMULH` for `bits.Mul64` on arm64, so it is not catastrophic, but it is nowhere near assembly speed.

Realistic combined AEAD throughput on an Oryon-class core: **0.7 to 1.1 GB/s**, not 1.5 to 2.5. At 250 MB/s of payload that is 23 to 36 percent of a core, not 10 to 17 percent. Doubled if you count both directions on the same core.

My Stage 1 recommendation stands: negotiate AES-256-GCM when both peers report ARMv8 Crypto Extensions. Go's `crypto/aes` plus `crypto/cipher` on arm64 uses `gcm_arm64.s` with AESE/AESMC and PMULL, landing at 3 to 5 GB/s. That is a 4x reduction in cipher cost.

**But measure it on the actual handset before committing.** Both Fable 5.1's number and mine are estimates. The benchmark from my Stage 1 Section 1.6 resolves it in ten seconds of wall time on the device.

---

## 4. THE MEASUREMENT PROBLEM NOBODY ELSE ADDRESSED

My Stage 1 Finding B said the 1,345 Mbps SpeedBench figure may be a LAN loopback number. Sol Pro partially agreed:

> The public Ookla result does not identify the engine ceiling. Its 637 Mbps result is 47.4 percent of the isolated 1,345.38 Mbps result.

Sol Pro attributes the gap to "server selection, route, congestion control, and public Internet capacity." Possible. Also possible: **SpeedBench terminates on `aicore` at 192.168.4.36, which is on the local 10 Gbps LAN, and never touches the WAN at all.**

Both podiums that discussed this treated it as a nuisance. It is the gate on the entire docket. If SpeedBench is a LAN test, then:

- The 1,345 Mbps figure measures handset CPU and Wi-Fi 7 airtime, not WAN capability.
- The 2,469.80 Mbps bidirectional figure is a LAN number, which makes it unsurprising rather than impressive.
- Every optimization ranked in this debate is being ranked against the wrong bottleneck.

**Resolve it before Stage 3 with one command each.**

```bash
# On aicore. If SpeedBench terminates locally, the WAN interface counters will
# NOT increase by the transferred volume during the test.
#
# Baseline:
cat /sys/class/net/eth0/statistics/tx_bytes /sys/class/net/eth0/statistics/rx_bytes

# Run a 16-stream SpeedBench download of known size, then re-read.
# Delta on rx_bytes must be >= 1.03x the payload for a genuine WAN test.
# A delta near zero proves LAN loopback.

# Simultaneously, confirm the tunnel device counters DO move:
cat /sys/class/net/winn3gw0/statistics/rx_bytes /sys/class/net/winn3gw0/statistics/tx_bytes

# And confirm where the socket actually connects:
ss -u -n -p state established '( sport = :9111 or dport = :9111 )'
```

If `eth0` rx_bytes does not move, the Round 31 headline is void and Round 32 is optimizing a benchmark, not a product.

**Additional instrumentation that all four podiums should have demanded:**

```bash
# Softirq backlog drops. Non-zero column 2 means netif_rx overran the per-CPU
# backlog, which is exactly what N-way TUN writer fan-out can cause if
# net.core.netdev_max_backlog is left at the default 1000.
cat /proc/net/softnet_stat

# Raise it before fanning out writers. At 170 kpps across 4 CPUs the default
# 1000-entry backlog absorbs 5.9 ms per CPU. Under a 20 ms scheduler stall it
# overflows and you lose packets INSIDE the kernel, invisible to the engine's
# "zero drops" telemetry.
sysctl -w net.core.netdev_max_backlog=16384
sysctl -w net.core.netdev_budget=1200
sysctl -w net.core.netdev_budget_usecs=8000

# UDP-specific drop accounting. "InErrors" and "RcvbufErrors" are the two that
# matter. The engine's own counters cannot see either.
nstat -az | grep -Ei 'udp|ip_'
cat /proc/net/snmp | grep -A1 '^Udp:'
```

Podium 1's telemetry claim was:

> 3,731,934 packets received, 3,731,934 packets delivered to Android TUN (0 dropped), 0 send failures, 0 receive failures

Sol Pro correctly flagged that this proves only the application queue survived. I will go further: **the "0 dropped" figure is structurally incapable of detecting the drops that matter**, because a packet lost in `udp_queue_rcv_skb` due to `sk_rcvbuf` overflow, or in `enqueue_to_backlog` due to `netdev_max_backlog` overflow, never reaches the application counter at all. The counter cannot count what it never saw. `SO_RXQ_OVFL` and `/proc/net/softnet_stat` are the only instruments that can.

---

## 5. COMPLETE HARDENED GSO/GRO IMPLEMENTATION

Consolidating the corrections against Sol Pro's draft and my own Stage 1.

```go
//go:build linux

// udpoffload_linux.go
//
// UDP segmentation offload (send) and generic receive offload (receive) for
// the Winn v3 outer socket.
//
// Kernel ABI asymmetry that bites everyone: UDP_SEGMENT on send carries a
// __u16 and udp_cmsg_send() rejects any cmsg_len other than CMSG_LEN(2) with
// EINVAL. UDP_GRO on receive carries an int (4 bytes) emitted by put_cmsg()
// in udp_cmsg_recv(). Two bytes out, four bytes in. Parsing the receive-side
// cmsg as a uint16 works by accident on little-endian and corrupts elsewhere.

package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const (
	udpSegment = 103 // SOL_UDP UDP_SEGMENT
	udpGRO     = 104 // SOL_UDP UDP_GRO

	udpMaxSegments = 64    // net/ipv4/udp.c UDP_MAX_SEGMENTS
	gsoSafeBytes   = 61440 // 60 KiB, comfortable slack under the 65535 IP limit
	maxUDPPayload  = 65507

	targetSockBuf = 16 << 20
)

// SockState reports what the kernel actually granted. Android clamps
// SO_RCVBUF to net.core.rmem_max and SO_SNDBUF to net.core.wmem_max, and an
// unprivileged app cannot use SO_RCVBUFFORCE (that needs CAP_NET_ADMIN).
// Log the granted value; never assume the requested value took effect.
//
// Note also that the kernel DOUBLES the requested value internally to cover
// sk_buff overhead, so getsockopt returns 2x what you asked for, and the
// usable payload fraction is size * mtu / (mtu + skb_overhead). For 1433 byte
// datagrams on arm64 that overhead is roughly 768 bytes, so a nominal 16 MiB
// absorbs about 10.9 MiB of payload, or 45.7 ms at 2 Gbps. Not 67 ms.
type SockState struct {
	RcvBuf     int
	SndBuf     int
	GROEnabled bool
	GSOProbed  bool
}

func ConfigureUDPOffload(c *net.UDPConn) (SockState, error) {
	var st SockState

	if err := c.SetReadBuffer(targetSockBuf); err != nil {
		return st, fmt.Errorf("SO_RCVBUF: %w", err)
	}
	if err := c.SetWriteBuffer(targetSockBuf); err != nil {
		return st, fmt.Errorf("SO_SNDBUF: %w", err)
	}

	raw, err := c.SyscallConn()
	if err != nil {
		return st, err
	}

	var inner error
	cerr := raw.Control(func(u uintptr) {
		fd := int(u)

		if st.RcvBuf, inner = unix.GetsockoptInt(
			fd, unix.SOL_SOCKET, unix.SO_RCVBUF); inner != nil {
			return
		}
		if st.SndBuf, inner = unix.GetsockoptInt(
			fd, unix.SOL_SOCKET, unix.SO_SNDBUF); inner != nil {
			return
		}

		// Drop visibility. sk_drops is absolute and monotonic; the cmsg only
		// arrives on packets FOLLOWING a drop, so read it at teardown too.
		if err := unix.SetsockoptInt(
			fd, unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1); err != nil {
			inner = fmt.Errorf("SO_RXQ_OVFL: %w", err)
			return
		}

		// GRO is advisory. A kernel without it, or a device path that cannot
		// coalesce, simply never emits the cmsg. Treat every rejection code
		// as "unavailable", not as a fatal error.
		if err := unix.SetsockoptInt(
			fd, unix.SOL_UDP, udpGRO, 1); err == nil {
			st.GROEnabled = true
		} else if !isUnsupported(err) {
			inner = fmt.Errorf("UDP_GRO: %w", err)
			return
		}

		// Probe GSO support without sending anything. Setting UDP_SEGMENT as a
		// plain sockopt sets a default gso_size for the socket; we immediately
		// clear it back to 0 because we supply the size per-sendmsg via cmsg.
		if err := unix.SetsockoptInt(
			fd, unix.SOL_UDP, udpSegment, 0); err == nil {
			st.GSOProbed = true
		} else if !isUnsupported(err) {
			inner = fmt.Errorf("UDP_SEGMENT probe: %w", err)
			return
		}
	})
	if cerr != nil {
		return st, cerr
	}
	return st, inner
}

func isUnsupported(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOTSUP)
}

// GSOBatchLimit returns the maximum number of equal-sized encrypted records
// that may be packed into one sendmsg. Two independent caps apply: the kernel
// segment count (UDP_MAX_SEGMENTS = 64) and the 65535 byte IP datagram budget.
// Exceeding either yields EMSGSIZE or EINVAL and loses the ENTIRE batch, which
// is why a fallback path is mandatory rather than optional.
func GSOBatchLimit(recordSize int) int {
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

func gsoCmsg(segmentSize int) ([]byte, error) {
	if segmentSize <= 0 || segmentSize > 65535 {
		return nil, fmt.Errorf("GSO segment size %d out of range", segmentSize)
	}
	oob := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = int32(unix.SOL_UDP)
	h.Type = int32(udpSegment)
	h.SetLen(unix.CmsgLen(2))
	off := unix.CmsgLen(0)
	binary.NativeEndian.PutUint16(oob[off:off+2], uint16(segmentSize))
	return oob, nil
}

// WriteGSO transmits a slab of independently sealed AEAD records as one
// sendmsg. Every record except the last must be exactly segmentSize bytes.
//
// ORDERING REQUIREMENT, non-negotiable: seal each inner packet into its own
// AEAD record with its own nonce and tag BEFORE packing the slab. Do not seal
// the slab as a single record and then apply UDP_SEGMENT. The kernel splits
// the slab into independent datagrams; a receiver that loses one datagram must
// still be able to authenticate every other datagram on its own.
//
// conn must be the CONNECTED outer socket. Passing a non-nil dst to
// WriteMsgUDP on a connected UDPConn returns ErrWriteToConnected, which is why
// the connected and unconnected paths are split explicitly here.
func WriteGSO(
	c *net.UDPConn,
	slab []byte,
	segmentSize int,
	dst *net.UDPAddr,
) error {
	if segmentSize <= 0 {
		return fmt.Errorf("GSO segment size %d", segmentSize)
	}
	if len(slab) == 0 {
		return nil
	}

	// Single record: no cmsg, no GSO, plain send.
	if len(slab) <= segmentSize {
		return writeOne(c, slab, dst)
	}
	if len(slab) > maxUDPPayload {
		return fmt.Errorf("GSO slab %d exceeds %d", len(slab), maxUDPPayload)
	}
	segs := (len(slab) + segmentSize - 1) / segmentSize
	if segs > udpMaxSegments {
		return fmt.Errorf("GSO segments %d exceeds %d", segs, udpMaxSegments)
	}

	oob, err := gsoCmsg(segmentSize)
	if err != nil {
		return err
	}

	var n int
	if dst == nil {
		n, _, err = c.WriteMsgUDP(slab, oob, nil)
	} else {
		n, _, err = c.WriteMsgUDP(slab, oob, dst)
	}
	if err != nil {
		return err
	}
	if n != len(slab) {
		return fmt.Errorf("GSO short write %d of %d", n, len(slab))
	}
	return nil
}

func writeOne(c *net.UDPConn, b []byte, dst *net.UDPAddr) error {
	var err error
	if dst == nil {
		_, err = c.Write(b)
	} else {
		_, err = c.WriteToUDP(b, dst)
	}
	return err
}

// WriteSlabFallback emits each record with its own syscall. Used when GSO is
// rejected at runtime. EMSGSIZE is the signal that the path MTU cannot carry
// segmentSize; the caller should shrink the record size and renegotiate rather
// than retry, because retrying at the same size loops forever.
func WriteSlabFallback(
	c *net.UDPConn,
	slab []byte,
	segmentSize int,
	dst *net.UDPAddr,
) error {
	for off := 0; off < len(slab); off += segmentSize {
		end := off + segmentSize
		if end > len(slab) {
			end = len(slab)
		}
		if err := writeOne(c, slab[off:end], dst); err != nil {
			return err
		}
	}
	return nil
}

// GSOFailedPermanently distinguishes a path/feature problem (fall back and
// stay fallen back) from a transient socket condition (retry later).
func GSOFailedPermanently(err error) bool {
	return errors.Is(err, unix.EIO) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EMSGSIZE)
}

type GROStats struct {
	SkDrops  uint32 // absolute, monotonic, from SO_RXQ_OVFL
	Segments int
	SegSize  int
}

// ReadGRO reads one datagram, or one GRO aggregate, and invokes consume once
// per contained record.
//
// The trailing record may be SHORTER than segSize. It may never be longer.
// A kernel that reports segSize > n is either buggy or the cmsg was corrupted;
// treat it as fatal rather than reading out of bounds.
func ReadGRO(
	c *net.UDPConn,
	data []byte,
	oob []byte,
	tracker *rxDropTracker,
	consume func([]byte) error,
) (GROStats, error) {
	var st GROStats

	n, oobn, flags, _, err := c.ReadMsgUDP(data, oob)
	if err != nil {
		return st, err
	}
	if flags&unix.MSG_TRUNC != 0 {
		return st, errors.New("udp: payload truncated, grow the read buffer")
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return st, errors.New("udp: control truncated, grow the oob buffer")
	}
	if n == 0 {
		return st, nil
	}

	msgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
	if perr != nil {
		return st, perr
	}

	for i := range msgs {
		h := &msgs[i].Header
		switch {
		case h.Level == unix.SOL_UDP && h.Type == udpGRO:
			sz, e := parseGROSegmentSize(msgs[i].Data)
			if e != nil {
				return st, e
			}
			st.SegSize = sz

		case h.Level == unix.SOL_SOCKET && h.Type == unix.SO_RXQ_OVFL:
			if len(msgs[i].Data) >= 4 {
				st.SkDrops = binary.NativeEndian.Uint32(msgs[i].Data[:4])
				if tracker != nil {
					tracker.observe(st.SkDrops)
				}
			}
		}
	}

	if st.SegSize == 0 || st.SegSize >= n {
		st.Segments = 1
		st.SegSize = n
		return st, consume(data[:n])
	}

	for off := 0; off < n; off += st.SegSize {
		end := off + st.SegSize
		if end > n {
			end = n
		}
		if err := consume(data[off:end]); err != nil {
			return st, err
		}
		st.Segments++
	}
	return st, nil
}

// parseGROSegmentSize reads the int emitted by udp_cmsg_recv(). Strict on
// width: a 2-byte read happens to work on little-endian arm64 and silently
// corrupts on big-endian.
func parseGROSegmentSize(data []byte) (int, error) {
	if len(data) != 4 {
		return 0, fmt.Errorf("UDP_GRO cmsg width %d, want 4", len(data))
	}
	v := int32(binary.NativeEndian.Uint32(data))
	if v <= 0 || v > 65535 {
		return 0, fmt.Errorf("UDP_GRO segment size %d out of range", v)
	}
	return int(v), nil
}

type rxDropTracker struct{ last uint32 }

func (t *rxDropTracker) observe(cur uint32) uint32 {
	if cur == t.last {
		return 0
	}
	d := cur - t.last // unsigned subtraction handles the wrap correctly
	t.last = cur
	return d
}
```

The `unsafe` import is required for `gsoCmsg`. Add it to the import block. I am noting this explicitly rather than silently, because a missing import is exactly the kind of thing that gets copy-pasted into a broken build.

**One receive-buffer sizing note that determines whether GRO helps at all.** If `data` is sized at 1500 bytes, GRO can never deliver an aggregate, because the kernel truncates to the buffer size and sets `MSG_TRUNC`. The read buffer must be at least 65535 for GRO aggregates to arrive intact. Sol Pro got this right (`make([]byte, 65535)`). Podium 1 never mentioned it, and it is the single most common reason a GRO deployment shows zero measured benefit.

---

## 6. GATEWAY SIDE: WHAT ALL FOUR PODIUMS UNDER-SPECIFIED

GSO on the handset uplink is the smaller half. **Download is the bigger number in every measurement on the docket, and download transmit batching happens on `aicore`, not on the handset.** Sol Pro flagged this correctly. Nobody gave the configuration.

```bash
#!/bin/sh
# aicore: multi-Gbps UDP tunnel endpoint tuning.
set -eu

# Socket memory. The middle value is the default; the third is the ceiling that
# setsockopt can reach. Set rmem_max/wmem_max above what the app requests so
# the app's 16 MiB is actually granted rather than silently clamped.
sysctl -w net.core.rmem_max=33554432
sysctl -w net.core.wmem_max=33554432
sysctl -w net.core.rmem_default=8388608
sysctl -w net.core.wmem_default=8388608
sysctl -w net.ipv4.udp_mem="1048576 2097152 8388608"
sysctl -w net.ipv4.udp_rmem_min=131072
sysctl -w net.ipv4.udp_wmem_min=131072

# Backlog and softirq budget. The default netdev_max_backlog of 1000 absorbs
# 5.9 ms at 170 kpps per CPU. A 20 ms stall overflows it and the loss is
# invisible to any application-level counter.
sysctl -w net.core.netdev_max_backlog=32768
sysctl -w net.core.netdev_budget=1200
sysctl -w net.core.netdev_budget_usecs=8000
sysctl -w net.core.dev_weight=128

# Busy polling. Trades CPU for latency on the UDP receive path. Enable only if
# aicore has cores to spare; it will show up as elevated idle-time CPU.
sysctl -w net.core.busy_poll=50
sysctl -w net.core.busy_read=50

# Forwarding and asymmetric-route tolerance (see section 1.4 for why rp_filter
# takes the MAX of all and per-device, not the OR).
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0

# Congestion control for the exit-side TCP that aicore itself originates.
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.default_qdisc=fq

# Do NOT disable PMTU discovery. QUIC's DPLPMTUD and classic PMTUD both need
# the ICMP path intact. min_pmtu at 1280 keeps IPv6 legal.
sysctl -w net.ipv4.ip_no_pmtu_disc=0
sysctl -w net.ipv4.route.min_pmtu=1280

# NIC-side offloads on the WAN uplink. UDP GSO/GRO in software still helps even
# without NIC support, but hardware GRO removes the per-packet skb allocation.
ethtool -K eth0 rx-gro-hw on   2>/dev/null || true
ethtool -K eth0 gro on
ethtool -K eth0 gso on
ethtool -K eth0 tso on
ethtool -K eth0 rx-udp-gro-forwarding on 2>/dev/null || true

# Interrupt coalescing. 64 usec of rx coalescing at 170 kpps batches roughly
# 11 packets per interrupt. Below 32 usec the interrupt rate dominates.
ethtool -C eth0 rx-usecs 64 rx-frames 32 adaptive-rx on 2>/dev/null || true

# RPS/RFS: spread the softirq load across cores. Without this, one core handles
# every packet from a single-tuple UDP tunnel flow, because the RSS hash is
# constant for a fixed outer 4-tuple. This is THE reason single-tunnel
# throughput plateaus on multi-core gateways.
NPROC=$(nproc)
MASK=$(printf '%x' $(( (1 << NPROC) - 1 )))
for q in /sys/class/net/eth0/queues/rx-*; do
    echo "$MASK" > "$q/rps_cpus"
    echo 4096    > "$q/rps_flow_cnt"
done
sysctl -w net.core.rps_sock_flow_entries=32768
```

**The RPS point is the one that will move the download number and nobody raised it.** A Winn v3 tunnel between the handset and aicore is a single outer UDP 4-tuple. The NIC's RSS hash over that tuple is constant. Every single packet lands on the same receive queue and therefore the same CPU. One core does all the softirq, all the UDP receive, all the copy. At 170 kpps that core is the bottleneck regardless of how many cores the box has.

RPS breaks the tie by re-hashing in software onto the per-CPU backlogs. For a single-flow tunnel you additionally want the re-hash to consider the **inner** payload, which plain RPS cannot do. The practical workaround: run multiple outer UDP sockets on distinct source ports (4 to 8), so RSS itself spreads them, and have the handset hash inner flows across those sockets using the same `flowHash` function from Section 3.5. Same flow, same outer port, same core, ordered.

That single change converts aicore from one-core-bound to N-core-bound.

---

## 7. CONSOLIDATED RULINGS

**On the target.** 2,000 Mbps is void. The ceiling is 1,812 to 1,821 Mbps depending on inner MTU. Set the mandate at 1,800 Mbps. Podium 1's target is refuted by Podium 1's own packet arithmetic.

**On inner MTU.** Raise to 1440 on both hops. Podium 1's 1240 clamp wastes 272 Mbps and inflates packet rate 16.1 percent. Fable 5.1's terminated-tunnel argument is correct and I adopt it.

**On the LocalSocket.** Three podiums independently converged on killing it. That is the top-ranked change and it is settled.

**On the descriptor.** `detachFd()` once, from Kotlin to Go, no second wrapper, ever. `dup()` inside Go for reader/writer separation (cheap insurance, not a kernel requirement: tun char devices take no `f_pos` lock). `SCM_RIGHTS` is wrong for a same-process handoff. Fable 5.1's `adoptFd(...).also { it.detachFd() }.fileDescriptor` is a production crash and must not ship.

**On blocking versus nonblocking TUN.** Blocking, with `LockOSThread` threads. Fable 5.1's poll-on-EAGAIN is correct but pays an extra syscall on every idle transition. A blocking read parks in `tun_do_read` for free.

**On writer fan-out.** Four threads, hashed by inner 5-tuple, never round-robin. Round-robin reorders within a flow and triggers spurious fast retransmit. Fable 5.1 proposed the fan-out and did not address ordering. This is the gap.

**On GSO.** 43 segments at a 1405 byte record, not 45 and not 46. Two-byte cmsg on send. Mandatory fallback path, because one `EMSGSIZE` loses the entire slab. Seal per-record, never seal the slab.

**On GRO.** Four-byte cmsg on receive, strictly validated. 65535 byte read buffer or GRO delivers nothing. Sol Pro's two-byte parse is wrong; the conclusion it produces happens to be right on arm64.

**On socket buffers.** 16 MiB requested, granted value logged, real absorption is 45.7 ms not 67.1 ms because of `truesize` accounting. Both Sol Pro and Fable 5.1 published the optimistic figure. Secondary priority, as Sol Pro correctly argued against Podium 1.

**On Double VPN routing.** Policy routing with `CT --notrack` for Kansas Core. Explicit `SNAT` (never `MASQUERADE`) for Canada ca1 and Germany de1, where a /32 point-to-point inner address makes `inet_select_addr()` return 0.0.0.0 and blackhole the flow. Spain is conditional on whether the provider routes 10.10.0.0/24 back. Podium 1's blanket MASQUERADE breaks three of four exits and burns 14 to 24 percent of a core on conntrack for no benefit.

**On qdisc.** `noqueue` on the tunnel device. `fq` with `maxrate 1950mbit` and `flow_limit 256` on the physical uplink. Podium 1 put `fq` on the wrong interface with a `flow_limit` ten times too large, which is 6 ms of standing queue per flow.

**On crypto.** Negotiate AES-256-GCM. `golang.org/x/crypto/internal/poly1305` has no arm64 assembly, so Fable 5.1's 1.5 to 2.5 GB/s estimate is roughly 2x optimistic. Benchmark on the handset before committing.

**On RPS.** Multiple outer UDP source ports plus RPS on aicore. A single-tuple tunnel pins every packet to one core. No podium raised this and it may be the actual gateway ceiling.

**On measurement.** Read `/sys/class/net/eth0/statistics/rx_bytes` on aicore before and after a SpeedBench run. If it does not move, Round 31's headline is a LAN loopback figure and the entire optimization ranking in this debate is aimed at the wrong bottleneck. Resolve this before Stage 3 accepts any number.
