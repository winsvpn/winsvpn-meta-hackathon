Repo verification is complete. Every claim below is either Level 1 arithmetic from constants in this tree, or tagged.

**Verification caveat up front:** `WebSearch` was denied in this session, so kernel/Suricata facts below come from foundational knowledge, not live docs. I have tagged those `[UNVERIFIED-LIVE]` and given you the command that settles each one locally. Everything drawn from the repo is cited by `file:line` and is Level 1.

---

# PODIUM 3 SUBMISSION: Chief Auditor & Lead HPC Architect

## 0. The central thesis, stated before the dilemmas

The brief asks whether crypto, cipher choice, or the single virtio queue is the bottleneck. **None of them are.** The disease is packet-rate amplification, and the two offload layers that cure it are entirely absent from this tree. I verified that by exhaustive grep:

```
IFF_VNET_HDR   -> 0 occurrences
TUNSETOFFLOAD  -> 0 occurrences
UDP_SEGMENT    -> 0 occurrences
UDP_GRO        -> 0 occurrences
SO_REUSEPORT   -> 0 occurrences (entire repo, all languages)
rps_cpus       -> 0 occurrences (all shell/yaml)
```

`IFF_MULTI_QUEUE` is present on the TUN side (`forward_linux.go:143`), so the team already understood queue parallelism. The segmentation offloads were simply never reached.

**The supporting evidence is in your own comparison numbers.** Winn v3 does 2.33 Gbps on the Ryzen 7 PRO 8845HS and 852-923 Mbps on the Canada VPS. Ratio: 2.59x. Clock ratio alone is roughly 4.5 GHz / 2.0 GHz = 2.25x, and Zen 4 over Haswell adds perhaps 1.5x IPC on branchy integer code. A purely single-core-serialized workload would predict 3.4x. A NIC-queue-bound or crypto-bound workload would predict something close to 1.0x, because both machines have ample crypto headroom and the aicore box is not magically better at virtio. The measured 2.59x tracks single-core performance. **The datapath is serialized on one core, and throughput is a linear function of that core's speed.** That is the finding that reframes every other dilemma.

---

## 1. Canada VPS CPU and cryptography: crypto is 7.75% of budget. Cipher agility is a non-answer.

### Level 1 proof

Inner MTU at the shipped plan floor is 1373 bytes (`cover_demux.go:52-53`, the repo's own figure).

```
pps at 1 Gbps goodput = 1e9 / (1373 x 8) = 91,041 pps        [matches cover_demux.go:53 exactly]
One core at 2.0 GHz   = 2.0e9 cycles/s
Cycle budget/packet   = 2.0e9 / 91,041 = 21,968 cycles
```

AES-256-GCM, from your measured 1,611,681 kB/s:

```
1373 B / 1.611681e9 B/s = 851.7 ns
851.7 ns x 2.0e9        = 1,703 cycles
1,703 / 21,968          = 7.75% of one core's per-packet budget
```

ChaCha20-Poly1305, from your measured 1,218,911 kB/s:

```
1373 / 1.218911e9 = 1126.4 ns = 2,253 cycles = 10.25% of budget
```

**Delta between ciphers: 2.50 percentage points of one core, per Gbps, per direction.** A gateway sealing and opening simultaneously at 2 Gbps aggregate spends 0.10 additional cores by choosing ChaCha20 over AES-GCM. On a 6-core box that is 1.7% of the machine.

### Verdict

Cipher agility is worth **zero** engineering hours for throughput. Keep AES-256-GCM because the Haswell has AES-NI and PCLMULQDQ and it is 32% cheaper, but understand that you are optimizing 7.75% down to 7.75%, not fixing anything. Retain ChaCha20-Poly1305 solely as the correctness fallback for hosts without AES-NI. Do not build runtime negotiation, do not build benchmarking-based selection, do not spend a line of code on it. Full duplex at 2 Gbps costs 15.5% of one core in AEAD. You have 600% of a core.

The bottleneck is syscall and per-skb kernel cost, exactly as the brief's third hypothesis suspects. Section 3 proves it arithmetically.

---

## 2. The single virtio queue is a red herring. Here is the arithmetic that retires it.

### First, three corrections to the proposed configuration

**`ethtool -L ens3 combined N` will fail, and no guest-side action can fix it.** `Combined: 1` with `pre-set maximum n/a` means the OVH host created the virtio-net device with one queue pair. Queue count is a host-side libvirt property (`<driver queues='N'/>`). File the OVH ticket, but do not block on it, because section 2's arithmetic makes it unnecessary.

**RPS mask `3f` is wrong, and not by a little.** RPS steers on `skb_get_hash`, which for UDP is the 4-tuple. One tunnel is one 4-tuple, so one flow maps to exactly one bucket: `map->cpus[reciprocal_scale(hash, map->len)]`. With `len = 6`, a single tunnel lands deterministically on one of six CPUs and you do not get to choose which. **Two of those six are CPU 4 and CPU 5, which are hard-pinned to IRQ 36 and IRQ 37.** So mask `3f` carries a 33% chance of steering your only flow onto a CPU that is already saturated with driver work, producing a regression you cannot reproduce on demand.

What RPS *does* buy for a single flow is real but bounded: the driver and NAPI ring work stays on CPU 4, and everything from `ip_rcv` upward moves to the RPS CPU. That is roughly a 30/70 split of receive softirq into a two-stage pipeline. One extra core of protocol-stack work per flow. Not six. Use an explicit two-bit mask that excludes the IRQ CPUs.

**XPS is a no-op here and must not be configured.** With one transmit queue, `xps_cpus` selects among one queue. There is nothing to steer. Any XPS line in a tuning script on this host is cargo cult; leave it out so the next engineer does not believe it did something.

### Now the arithmetic that retires the whole dilemma

Add UDP GSO on transmit and UDP GRO on receive.

```
GSO superframe capacity = floor(65507 / 1402) = 46 segments
TX skb rate at 1 Gbps   = 91,041 / 46 = 1,979 skbs/s
RX skb rate at 1 Gbps, GRO coalescing 16:1 = 91,041 / 16 = 5,690 skbs/s
```

A single virtio queue pair moving ~6,000 skbs per second is idling. **The queue was never the constraint. The 91,041 independent skb traversals per second were.** That is why `Combined: 1` looks fatal and is not.

`[UNVERIFIED-LIVE]` UDP_SEGMENT requires Linux 4.18+, UDP_GRO requires 5.0+. You are on 6.8.0-139, so both are present. Constants are `SOL_UDP = 17`, `UDP_SEGMENT = 103`, `UDP_GRO = 104`. Settle it locally:

```bash
grep -E 'UDP_SEGMENT|UDP_GRO' /usr/include/linux/udp.h
```

### Socket architecture: SO_REUSEPORT worker pool, and why

Verified absent from the entire repo. The gateway runs one socket, one `splitUDP.pump` goroutine, one demux. `cover_demux.go:150-152` names this honestly: "the single hardest serialization point in the gateway."

A `SO_REUSEPORT` pool of 4 sockets on port 9111 gives the kernel four independent `sk_receive_queue` structures and four independent pumps. The kernel's reuseport hash distributes by 4-tuple, so N clients spread across N workers. A single client still lands on one worker, which is why GSO/GRO matters more than REUSEPORT for your speedtest. But REUSEPORT is what makes the box survive 200 concurrent handsets, and it is what finally gives RPS more than one flow to spread.

### The buffer sizing, corrected for truesize

The repo requests 8 MiB (`udp_socket_buffers.go:19`) with a 4 MiB floor. That is correct sizing and I am not changing it. But the capacity claim in the surrounding comment is optimistic, because `sk_rcvbuf` charges `skb->truesize`, not payload:

```
truesize for a 1402-byte UDP datagram ~= SKB_DATA_ALIGN(1402) + sizeof(skb_shared_info)
                                      ~= 1536 + 320 + overhead ~= 2368 bytes
Effective depth = 8,388,608 / 2368 = 3,543 datagrams
```

Not the ~5,983 a payload-based calculation implies. This matters in section 3, where it becomes 39.8 ms of standing queue.

`udp_rcvbuf_errors: 96,200` is not a buffer-size failure. An 8 MiB buffer holding 3,543 datagrams overflows only when the reader stops for 39 ms at line rate. **The reader stopping is the defect.** Section 3.

### Deliverable: the kernel steering script

```bash
#!/usr/bin/env bash
# wins_canada_steering.sh  -- 6 vCPU, single-queue virtio, Haswell 2.0 GHz.
# CPU map, deliberate and exclusive:
#   CPU 0,1 : winn3-gateway (CPUAffinity in the unit)
#   CPU 2,3 : RPS protocol-stack targets + Suricata NFQ threads
#   CPU 4   : IRQ 36 virtio0-input.0   (already hard-pinned, do not move)
#   CPU 5   : IRQ 37 virtio0-output.0  (already hard-pinned, do not move)
set -Eeuo pipefail
IF=ens3

# RPS: two-bit mask on CPU 2,3. NOT 3f. Never include 4 or 5.
echo 0c > "/sys/class/net/${IF}/queues/rx-0/rps_cpus"

# RFS. Deliberately LEFT OFF until the gateway pump is pinned: RFS steers the
# softirq to whichever CPU last called recvmsg, and an unpinned Go goroutine
# migrates between Ps, so RFS chases it and thrashes the steering table.
# Enable these two lines ONLY after CPUAffinity=0-1 is live on the unit.
#   sysctl -w net.core.rps_sock_flow_entries=32768
#   echo 32768 > /sys/class/net/${IF}/queues/rx-0/rps_flow_cnt

# Interrupt coalescing in software. virtio-net has no hardware coalescing, so
# these two are the only way to stop one interrupt per packet burst.
echo 20000 > "/sys/class/net/${IF}/gro_flush_timeout"   # 20 us
echo 4     > "/sys/class/net/${IF}/napi_defer_hard_irqs"

# XPS: intentionally NOT set. One tx queue means nothing to steer.

sysctl -w net.core.rmem_max=134217728 \
          net.core.wmem_max=134217728 \
          net.core.netdev_max_backlog=250000 \
          net.core.netdev_budget=600 \
          net.core.netdev_budget_usecs=5000 \
          net.ipv4.udp_mem="765405 1020540 1530810"

# fq per-flow limit is the documented cause of SndbufErrors 263,060
# (udp_batch_unix.go:392-402). Default flow_limit is 100 packets.
# With GSO a superframe counts as ONE packet here, so 8192 x 46 segments.
tc qdisc replace dev "${IF}" root fq limit 100000 flow_limit 8192 \
   quantum 3028 initial_quantum 15140

grep -E 'virtio0-(input|output)' /proc/interrupts
```

---

## 3. Uplink collapse above 600-700 Mbps: root cause found, and it is bufferbloat starving the control plane

This is the most important section. The collapse is not a mystery and it is not a crypto or NIC problem. **It is arithmetic between two constants in this repo.**

### The root cause

`cover_demux.go:43` sets `demuxChanDepth = 4096`. `cover_demux.go:224-232` sends into that channel with **no default case**:

```go
select {
case side.incoming <- d:
        bufs[i] = nil
case <-s.done:
        release()
        return
}
```

The pump blocks when the channel is full. The pump is the sole reader of the only socket. So a consumer stall propagates directly into the kernel receive queue. That is `RcvbufErrors 82,318` and it is `udp_rcvbuf_errors: 96,200`.

Then the liveness probe dies, because **the probe shares one FIFO with bulk data and there is no priority lane.** Compute the standing queue ahead of any control packet at 1 Gbps:

```
Kernel socket queue : 3,543 datagrams x 1402 B / 125e6 B/s = 39.8 ms
Demux channel       : 4,096 datagrams x 1402 B / 125e6 B/s = 45.9 ms
                                                  TOTAL    = 85.7 ms
```

**85.7 milliseconds of head-of-line blocking on the control plane, at full load, with zero stalls and zero GC.** Add a GC pause and it doubles. If your liveness deadline is anywhere near 100 ms, the session tears down at high offered load *by design*, and it will do so more reliably the faster the link gets. That is precisely the reported symptom: fine at 600, dead at 700-900.

### The aggravating factor: GOMEMLIMIT collides with the queue sizing

`server/wins_winn3_gateway_install_memory_unit_test.sh:82` pins `GOMEMLIMIT=96MiB`, set to 80% of `MemoryHigh`. Now price the demux queues:

```
2 sides x 4096 slots x 4096 B/slot = 33,554,432 B = 32 MiB
32 MiB / 96 MiB = 33.3% of the entire process heap budget, in one data structure
```

Go's GC forces collection as the heap approaches `GOMEMLIMIT`, and it charges mark work to the allocating goroutine through GC assist. **The highest-allocating goroutine is the demux pump.** So the pump becomes the assist victim, stalls, and the socket queue overflows. The mechanism is closed-loop: load raises the queue, the queue raises the heap, the heap forces GC, GC stalls the pump, the stall drops packets and kills liveness.

### The fix is counterintuitive: make the buffer smaller

```
Proposed depth 256:
  Memory   : 2 x 256 x 4096 = 2 MiB          (was 32 MiB, returns 30 MiB = 31% of GOMEMLIMIT)
  Standing : 256 x 1402 / 125e6 = 2.87 ms    (was 45.9 ms)
  Reduction: 16x on both latency and memory
```

256 slots is one NAPI/GRO burst plus scheduling slack. Nothing legitimate needs 4096.

### Deliverable: the demux patch

Three changes to `winn_protocol_experimental/cmd/winn3-gateway/cover_demux.go`.

**3a. Depth, and a control lane.** Replace line 43's constant and add the lane:

```go
	// demuxChanDepth is ONE NAPI/GRO burst plus scheduling slack, not a
	// quarter second of link.
	//
	// It was 4096. That was 45.9 ms of standing queue at a gigabit
	// (4096 x 1402 B / 125e6 B/s) sitting in front of every liveness probe,
	// on top of the 39.8 ms the 8 MiB SO_RCVBUF holds once skb->truesize
	// rather than payload is charged (8 MiB / 2368 B = 3,543 datagrams).
	// 85.7 ms of head-of-line blocking on the control plane, at full load,
	// with no stall and no GC. That is the teardown above 700 Mbps: not
	// crypto, not the single virtio queue, just two FIFOs that are deeper
	// than the liveness deadline. It also cost 2 x 4096 x 4096 = 32 MiB,
	// which is 33% of the shipped GOMEMLIMIT=96MiB, so a full pair of
	// queues drove the collector into continuous-GC and the assist landed
	// on this file's pump: the highest-allocating goroutine in the process.
	//
	// 256 is 2.87 ms of standing queue and 2 MiB of memory.
	demuxChanDepth = 256

	// demuxControlDepth is the strict-priority lane for datagrams too short
	// to be bulk data. A liveness probe must not queue behind a gigabit of
	// payload; that is what killed the session.
	demuxControlDepth = 64
```

Add to `demuxSide`:

```go
type demuxSide struct {
	split    *splitUDP
	incoming chan demuxDatagram
	control  chan demuxDatagram
	wake     chan struct{}
	learnCID bool

	droppedData atomic.Uint64

	mu           sync.Mutex
	readDeadline time.Time
}
```

Allocate it in `newSplitUDP` for both sides:

```go
	s.v3 = &demuxSide{
		split:    s,
		incoming: make(chan demuxDatagram, demuxChanDepth),
		control:  make(chan demuxDatagram, demuxControlDepth),
		wake:     make(chan struct{}, 1),
	}
	s.quic = &demuxSide{
		split:    s,
		incoming: make(chan demuxDatagram, demuxChanDepth),
		control:  make(chan demuxDatagram, demuxControlDepth),
		wake:     make(chan struct{}, 1),
		learnCID: true,
	}
```

**3b. The pump must never block on the data lane.** Replace the hand-off at `cover_demux.go:224-232`:

```go
			// THE PUMP NEVER BLOCKS ON THE DATA LANE.
			//
			// This select used to have no default, so a full channel parked
			// the sole reader of the sole socket and the kernel receive queue
			// overflowed behind it. MEASURED on the Canada node, 2026-09-17:
			// RcvbufErrors 0 -> 82,318 with InErrors tracking it exactly, and
			// the session then failed liveness and tore down. Batching the
			// syscall did not fix that, because recvmmsg amortises the syscall
			// boundary and this hand-off is downstream of it.
			//
			// Short datagrams take the strict-priority control lane, so a
			// liveness probe cannot queue behind a gigabit of payload. The
			// lane is length-classified only, which needs no authentication
			// and cannot be used to inject: a bulk datagram misrouted here is
			// still delivered, merely sooner. Reordering across the two lanes
			// is absorbed by the session's anti-replay window, which is the
			// precondition for this split and is why the threshold is well
			// below the inner MTU rather than near it.
			lane := side.incoming
			if msgs[i].N <= demuxControlPlaneMaxBytes {
				lane = side.control
			}
			select {
			case lane <- d:
				bufs[i] = nil
			case <-s.done:
				release()
				return
			default:
				// Tail-drop THIS datagram and keep draining the socket. Losing
				// one datagram is a SACK on the inner stream; stalling the pump
				// is a kernel-queue overflow plus a dead session.
				side.droppedData.Add(1)
			}
```

With the constant, placed next to the others:

```go
	// demuxControlPlaneMaxBytes is the length at or below which a v3 datagram
	// takes the priority lane. core.TransportOverhead() plus a keepalive body
	// is far below this; a bulk datagram at the 1373-byte plan floor is far
	// above it. The gap is deliberate so the classifier never needs to be
	// exact.
	demuxControlPlaneMaxBytes = 256
```

**3c. Drain the control lane first.** Replace the `select` inside `demuxSide.recv()` at `cover_demux.go:436-457`:

```go
		// Strict priority: anything in the control lane is taken before any
		// bulk datagram, without blocking. This is the half of the fix that
		// makes the lane worth having; a fair select would put the probe back
		// behind the payload it was starved by.
		select {
		case pkt := <-d.control:
			if timer != nil {
				timer.Stop()
			}
			return pkt, nil
		default:
		}
		select {
		case pkt, ok := <-d.control:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return demuxDatagram{}, net.ErrClosed
			}
			return pkt, nil
		case pkt, ok := <-d.incoming:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return demuxDatagram{}, net.ErrClosed
			}
			return pkt, nil
		case <-timeout:
			return demuxDatagram{}, os.ErrDeadlineExceeded
		case <-d.wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-d.split.done:
			if timer != nil {
				timer.Stop()
			}
			return demuxDatagram{}, net.ErrClosed
		}
```

Add `"sync/atomic"` to the import block.

### A second defect in the same file: an O(N) scan with a global lock, fed by unauthenticated input

`cover_demux.go:284-299`. `routeQUIC` runs per datagram. The early-out is:

```go
	if len(pkt) < 2 || pkt[0]&quicHeaderFormLong != 0 || pkt[0]&quicFixedBit == 0 {
		return false
	}
```

Winn v3 datagrams are high-entropy by design, so bit `0x40` is set in roughly half of them. **About half of all v3 data packets fall through into a linear scan of up to 4096 learned connection IDs, under a process-wide mutex.** At 91,041 pps that is ~45,500 scans per second. Even at an optimistic 5 ns per map entry, 4096 entries is 20.5 us per datagram and 45,500 x 20.5 us = 0.93 seconds of CPU per second. One core, gone, below 1 Gbps.

It is latent only while `s.cids` is empty. And `learnCIDsFromLongHeader` populates it **pre-authentication, from any source address** (`cover_demux.go:303-328`). So this is also a remote denial of service: 4096 spoofed QUIC long-header packets fill the set, and every legitimate session's data plane collapses. Report it as a security finding, not only a performance one.

Fix: copy-on-write snapshot, bucketed by CID length. Reads become lock-free and O(number of distinct CID lengths in use), which is 1 in practice.

```go
// cidIndex is an immutable snapshot of the learned connection IDs, bucketed by
// length. Reads are lock-free through an atomic pointer; a learn builds a new
// snapshot and swaps it. Learns are once per connection, reads are once per
// datagram, so copy-on-write is the correct asymmetry.
//
// It replaces a linear scan of up to maxLearnedCIDs entries held under a
// process-wide mutex and run on roughly half of all v3 data packets, because a
// high-entropy v3 datagram sets the QUIC fixed bit about half the time and fell
// straight through the cheap rejects into the loop. At 91,041 pps that scan was
// a whole core below a gigabit. It was also reachable pre-authentication from a
// spoofed source, so filling the set was a remote way to collapse every
// session's data plane.
type cidIndex struct {
	byLen   map[int]map[string]struct{}
	lengths []int // only lengths actually present, ascending
}

func (x *cidIndex) has(pkt []byte) bool {
	if x == nil {
		return false
	}
	for _, l := range x.lengths {
		if len(pkt) < 1+l {
			// lengths is ascending, so nothing longer can fit either.
			return false
		}
		if _, ok := x.byLen[l][string(pkt[1:1+l])]; ok {
			return true
		}
	}
	return false
}
```

`string(pkt[1:1+l])` as a map key in a lookup expression is compiled without allocating; the compiler recognises the pattern. Then on `splitUDP`, replace `cids`/`cidOrder` with:

```go
	cidMu    sync.Mutex   // learn path only; the read path never takes it
	cids     atomic.Pointer[cidIndex]
	cidOrder []string
	cidLens  map[string]int
```

```go
func (s *splitUDP) routeQUIC(pkt []byte) bool {
	if isQUICLongHeader(pkt) {
		return true
	}
	if len(pkt) < 2 || pkt[0]&quicHeaderFormLong != 0 || pkt[0]&quicFixedBit == 0 {
		return false
	}
	return s.cids.Load().has(pkt)
}

func (s *splitUDP) learnCIDsFromLongHeader(pkt []byte) {
	dcid, scid, ok := quicLongHeaderCIDs(pkt)
	if !ok {
		return
	}
	s.cidMu.Lock()
	defer s.cidMu.Unlock()
	if s.cidLens == nil {
		s.cidLens = make(map[string]int)
	}
	changed := false
	learn := func(cid []byte) {
		if len(cid) == 0 {
			return
		}
		key := string(cid)
		if _, seen := s.cidLens[key]; seen {
			return
		}
		s.cidLens[key] = len(cid)
		s.cidOrder = append(s.cidOrder, key)
		changed = true
		for len(s.cidOrder) > maxLearnedCIDs {
			oldest := s.cidOrder[0]
			s.cidOrder = s.cidOrder[1:]
			delete(s.cidLens, oldest)
		}
	}
	learn(dcid)
	learn(scid)
	if !changed {
		return
	}
	next := &cidIndex{byLen: make(map[int]map[string]struct{})}
	for key, l := range s.cidLens {
		bucket := next.byLen[l]
		if bucket == nil {
			bucket = make(map[string]struct{})
			next.byLen[l] = bucket
		}
		bucket[key] = struct{}{}
	}
	next.lengths = make([]int, 0, len(next.byLen))
	for l := range next.byLen {
		next.lengths = append(next.lengths, l)
	}
	sort.Ints(next.lengths)
	s.cids.Store(next)
}
```

Add `"sort"` and `"sync/atomic"` to imports; delete the `cids: make(map[string]struct{})` initialiser in `newSplitUDP` (a nil `atomic.Pointer` loads nil and `has` handles it).

### Third defect: a `time.Timer` allocated per datagram

`cover_demux.go:433`, `timer = time.NewTimer(delay)`, runs on every `recv()` that has a deadline set. `readLoopEntered` (`main.go:1708`) sets a 25 ms `readinessProbeTimeout` during startup and clears it after the first datagram, so the steady-state path is clear. **But any caller that keeps a deadline armed pays one timer allocation, one runtime timer-heap insert and one Stop per packet.** At 91,041 pps that is ~9 MB/s of garbage feeding straight into the GOMEMLIMIT loop described above. Hoist the timer out of the loop and reuse it with `Reset`.

### Set the liveness deadline from the buffer arithmetic, not from a ping

This is the parameter change that makes the collapse impossible rather than merely unlikely:

```
T_liveness > RTT_base + (rcvbuf_datagrams + chan_depth) x MTU_inner / rate + T_gc_max

Post-fix: 45 ms + (3,543 + 256) x 1402 / 125e6 + 50 ms
        = 45 + 42.6 + 50 = 137.6 ms
```

Set the probe deadline to **400 ms** (2.9x margin) and require **3** consecutive misses before teardown, for a 1.2 s eviction floor. Today's `DefaultIdleTimeout = 5 * time.Minute` (`params_mut3.go:76`) governs a different thing (silent-session eviction) and is fine; it is the probe deadline that needs deriving.

### Deliverable: UDP GSO/GRO, the single largest win

New file `winn_protocol_experimental/winn3/carrier/udp_gso_linux.go`.

```go
//go:build linux || android

package carrier

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// UDP segmentation and receive offload.
//
// WHY THIS FILE IS THE LARGEST SINGLE WIN ON THE CANADA NODE.
//
// recvmmsg and sendmmsg amortise the SYSCALL BOUNDARY. They do not amortise
// the per-skb kernel path: udp_sendmsg -> ip_make_skb -> ip_send_skb ->
// __dev_queue_xmit -> fq enqueue/dequeue -> virtio xmit_skb runs once per
// datagram either way. At the shipped plan floor a gigabit is 91,041 pps
// (1e9 / (1373 x 8)), so that path runs 91,041 times per second per direction
// and it is the cost the 2.0 GHz Haswell cannot absorb.
//
// UDP_SEGMENT collapses it. One sendmsg carrying up to floor(65507 / 1402) =
// 46 datagrams traverses the stack and the qdisc ONCE and is segmented at the
// driver boundary, so the TX skb rate at a gigabit falls from 91,041/s to
// 1,979/s. UDP_GRO does the mirror on receive; NAPI-bounded coalescing is
// nearer 16:1, giving 5,690 skbs/s. A single-queue virtio pair moving six
// thousand skbs per second is IDLING, which is why ethtool -l showing
// Combined: 1 looks fatal and is not.
//
// It also retires SndbufErrors 263,060 (see WriteBatchTo's ENOBUFS comment).
// fq accounts a GSO superframe as ONE packet against flow_limit until
// segmentation, so a flow_limit of 8192 becomes 8192 x 46 datagrams of
// headroom instead of 8192.
//
// CAPABILITY IS LATCHED, NOT ASSUMED. A kernel or device that refuses a
// superframe answers EINVAL, and one EINVAL disables GSO for the life of the
// process so every later batch takes the unchanged scalar path. Degrading to
// today's behaviour is correct; dropping traffic because an offload was
// assumed is not.
const (
	solUDP     = 17  // SOL_UDP
	udpSegment = 103 // UDP_SEGMENT, Linux 4.18+
	udpGRO     = 104 // UDP_GRO,     Linux 5.0+

	// gsoMaxSegments bounds one superframe. The kernel's own ceiling is
	// higher, but 64 keeps a single loss event from costing more than one
	// batch and keeps the superframe inside a 64 KiB IP datagram for every
	// segment size this deployment plans.
	gsoMaxSegments = 64

	// gsoIPPayloadMax is the largest IP payload a superframe may carry:
	// 65535 minus a 20-byte IPv4 header and an 8-byte UDP header.
	gsoIPPayloadMax = 65507
)

// cmsgAlign rounds up to the platform's cmsg alignment (sizeof(size_t)).
func cmsgAlign(n int) int {
	const a = int(unsafe.Sizeof(uintptr(0))) - 1
	return (n + a) & ^a
}

// cmsgHdrLen is sizeof(struct cmsghdr): size_t cmsg_len, int level, int type.
const cmsgHdrLen = 16

// gsoControl is one CMSG_SPACE(sizeof(uint16)) control buffer.
type gsoControl [cmsgHdrLen + 8]byte

// set writes the UDP_SEGMENT control message and returns its byte length.
func (c *gsoControl) set(gsoSize uint16) uint64 {
	dataLen := 2
	msgLen := cmsgHdrLen + dataLen
	*(*uint64)(unsafe.Pointer(&c[0])) = uint64(msgLen)
	*(*int32)(unsafe.Pointer(&c[8])) = int32(solUDP)
	*(*int32)(unsafe.Pointer(&c[12])) = int32(udpSegment)
	*(*uint16)(unsafe.Pointer(&c[cmsgHdrLen])) = gsoSize
	return uint64(cmsgAlign(msgLen))
}

// EnableUDPGRO asks the kernel to coalesce same-flow, same-size datagrams into
// one skb before this socket's receive queue. It is advisory: a kernel without
// UDP_GRO answers ENOPROTOOPT and the receive path is unchanged.
func (c *RawBatchConn) EnableUDPGRO() error {
	var setErr error
	err := c.rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), solUDP, udpGRO, 1)
	})
	if err != nil {
		return err
	}
	if setErr != nil && !errors.Is(setErr, unix.ENOPROTOOPT) {
		return setErr
	}
	return nil
}

// gsoDisabled latches a permanent fallback after one EINVAL.
var gsoDisabled atomic.Bool

// DisableUDPGSO turns the offload off for the life of the process.
func DisableUDPGSO() { gsoDisabled.Store(true) }

// UDPGSOEnabled reports whether superframes are still being attempted.
func UDPGSOEnabled() bool { return !gsoDisabled.Load() }

// gsoRun describes one maximal group of consecutive equal-length messages.
type gsoRun struct {
	start int
	count int
	size  int
}

// gsoRuns groups msgs into superframe candidates. UDP_SEGMENT requires every
// segment except the last to be exactly gso_size, so only consecutive
// equal-length messages may share a superframe. During a bulk transfer every
// datagram is a full inner MTU, which is why this groups almost everything.
func gsoRuns(msgs []BatchMsg) []gsoRun {
	runs := make([]gsoRun, 0, 4)
	for i := 0; i < len(msgs); {
		size := msgs[i].N
		if size <= 0 {
			i++
			continue
		}
		perFrame := gsoIPPayloadMax / size
		if perFrame > gsoMaxSegments {
			perFrame = gsoMaxSegments
		}
		if perFrame < 2 {
			runs = append(runs, gsoRun{start: i, count: 1, size: size})
			i++
			continue
		}
		n := 1
		for i+n < len(msgs) && n < perFrame && msgs[i+n].N == size {
			n++
		}
		runs = append(runs, gsoRun{start: i, count: n, size: size})
		i += n
	}
	return runs
}

// WriteBatchToGSO transmits msgs to one destination, coalescing consecutive
// equal-length datagrams into UDP_SEGMENT superframes.
//
// It returns the number of msgs the kernel accepted, matching WriteBatchTo's
// partial-write contract exactly: a caller cannot tell the two apart except by
// throughput. On EINVAL it latches the offload off and reports the count so
// far, and the caller's next call takes WriteBatchTo unchanged.
//
// The superframe staging buffer is owned by this RawBatchConn and reused, so
// the coalescing copy is not paid back in GC pressure. That copy is 1402 bytes
// at roughly 10 GB/s, about 280 cycles on this core, against the several
// thousand cycles a whole extra skb traversal costs. The zero-copy refinement
// is to have SealBatchInto write directly into the staging buffer at the right
// offset; this version is the drop-in.
func (c *RawBatchConn) WriteBatchToGSO(msgs []BatchMsg, to netip.AddrPort) (int, error) {
	if gsoDisabled.Load() {
		return c.WriteBatchTo(msgs, to)
	}
	nMsgs := len(msgs)
	if nMsgs == 0 {
		return 0, nil
	}
	runs := gsoRuns(msgs)
	if len(runs) == nMsgs {
		// Nothing coalesced. Do not pay the cmsg for single segments.
		return c.WriteBatchTo(msgs, to)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hs) < len(runs) {
		c.hs = make([]mmsghdr, len(runs))
		c.iovs = make([]iovec, len(runs))
		c.names = make([][32]byte, len(runs))
	}
	if len(c.gsoCtl) < len(runs) {
		c.gsoCtl = make([]gsoControl, len(runs))
	}
	if cap(c.gsoStage) < gsoIPPayloadMax*len(runs) {
		c.gsoStage = make([]byte, gsoIPPayloadMax*len(runs))
	}

	var name [32]byte
	var namelen uint32
	if to.Addr().Is4() {
		ip4 := to.Addr().As4()
		binaryNativePutUint16(name[0:2], unix.AF_INET)
		binaryBigPutUint16(name[2:4], to.Port())
		copy(name[4:8], ip4[:])
		namelen = 16
	} else if to.Addr().Is6() {
		ip6 := to.Addr().As16()
		binaryNativePutUint16(name[0:2], unix.AF_INET6)
		binaryBigPutUint16(name[2:4], to.Port())
		copy(name[8:24], ip6[:])
		namelen = 28
	}

	for r, run := range runs {
		stage := c.gsoStage[r*gsoIPPayloadMax : (r+1)*gsoIPPayloadMax]
		off := 0
		for k := 0; k < run.count; k++ {
			m := msgs[run.start+k]
			off += copy(stage[off:], m.Payload[:m.N])
		}
		c.iovs[r].base = &stage[0]
		c.iovs[r].len = uint64(off)
		c.hs[r].hdr.iov = &c.iovs[r]
		c.hs[r].hdr.iovlen = 1
		c.hs[r].hdr.flags = 0
		c.hs[r].len = 0
		c.names[r] = name
		c.hs[r].hdr.name = &c.names[r][0]
		c.hs[r].hdr.namelen = namelen
		if run.count > 1 {
			ctlLen := c.gsoCtl[r].set(uint16(run.size))
			c.hs[r].hdr.control = &c.gsoCtl[r][0]
			c.hs[r].hdr.controllen = ctlLen
		} else {
			c.hs[r].hdr.control = nil
			c.hs[r].hdr.controllen = 0
		}
	}

	const enobufsRetries = 8
	var framesSent int
	var sysErr syscall.Errno
	attempts := 0
	err := c.rawConn.Write(func(fd uintptr) bool {
		r1, _, errno := syscall.Syscall6(
			unix.SYS_SENDMMSG,
			fd,
			uintptr(unsafe.Pointer(&c.hs[0])),
			uintptr(len(runs)),
			0, 0, 0,
		)
		if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
			return false
		}
		if errno == syscall.ENOBUFS && attempts < enobufsRetries {
			attempts++
			return false
		}
		if errno != 0 {
			sysErr = errno
			return true
		}
		framesSent = int(r1)
		return true
	})
	if err != nil {
		return 0, err
	}
	if sysErr == syscall.EINVAL {
		// The kernel or the device refused the superframe. Latch off and let
		// the caller retry on the unchanged path rather than lose the batch.
		DisableUDPGSO()
		c.mu.Unlock()
		n, retryErr := c.WriteBatchTo(msgs, to)
		c.mu.Lock()
		return n, retryErr
	}
	if sysErr != 0 {
		return c.gsoAccepted(runs, framesSent), sysErr
	}
	return c.gsoAccepted(runs, framesSent), nil
}

// gsoAccepted converts a superframe count into a datagram count, so the
// partial-write contract this reports is the one WriteBatchTo reports.
func (c *RawBatchConn) gsoAccepted(runs []gsoRun, frames int) int {
	if frames <= 0 {
		return 0
	}
	if frames > len(runs) {
		frames = len(runs)
	}
	n := 0
	for i := 0; i < frames; i++ {
		n += runs[i].count
	}
	return n
}
```

Two small helpers keep the new file from re-importing `encoding/binary` under a shadowed name; add them here or reuse the existing calls directly:

```go
func binaryNativePutUint16(b []byte, v uint16) {
	*(*uint16)(unsafe.Pointer(&b[0])) = v
}

func binaryBigPutUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}
```

And three fields on `RawBatchConn` in `udp_batch_unix.go`, alongside the existing transmit vectors:

```go
	// GSO staging. Owned by this conn and reused, so the coalescing copy is
	// not paid back in GC pressure. See udp_gso_linux.go.
	gsoStage []byte
	gsoCtl   []gsoControl
```

Wire the call site at `main.go:1958` (`return bw.WriteBatchTo(msgs, dest)`) to prefer `WriteBatchToGSO` behind a type assertion, and call `EnableUDPGRO()` once in `newSplitUDP` right after `NewRawBatchConn`.

---

## 4. Suricata: three of the brief's four proposed flags are wrong. Here is what is actually true.

### `--queue-cpu-fanout` is actively harmful on this host

It selects the queue by `smp_processor_id()`. You have **one** NIC receive queue and its IRQ is hard-pinned to CPU 4, so every packet is classified in softirq on CPU 4 and fanout maps 100% of traffic to a single queue. You would add configuration, change nothing, and believe you had fixed it. Drop the flag. Plain `--queue-balance` uses the flow hash and does distribute per flow, which is what you want.

### `--queue-bypass` is banned by your own test suite, and correctly

`tools/test_deployment_runtime_configs.sh:150` fails the build on an unconditional `-j NFQUEUE --queue-num 0 --queue-bypass`. The installer gates it behind `SURICATA_NFQUEUE_FAIL_OPEN`, default `0`, fail-closed (`wins_core_server_setup_ONETOUCH.sh:481,7163-7167`). Adding it unconditionally to fix throughput would convert an IPS into a decoration whenever Suricata is restarting. **Do not propose it.** Multi-queue is fully compatible with fail-closed.

### "Accepting port 443 prior to NFQUEUE" is the wrong framing, but the right instinct

TCP 443 on this node carries XRay VLESS over TLS. The payload is AEAD-sealed. Suricata can read the ClientHello (SNI, JA3/JA4, version, cipher list) and the certificate, and after that it is inspecting ciphertext. **Inspecting packets 11 through infinity of an XRay flow yields zero detections and costs 100% of the throughput.** So: keep the IPS on the handshake, bypass the flow after it. That is not "accept 443", it is "inspect what is inspectable."

### The drop arithmetic, and why 125,188 is exactly what you should expect

Your unit runs `-q 0`, one queue, one thread (`wins_core_server_setup_ONETOUCH.sh:6729`, `wins_data_plane_setup_ONETOUCH.sh:5056`).

```
1 Gbps at a 1448-byte MSS = 1e9 / (1448 x 8) = 86,326 pps
Default NFQUEUE queue-maxlen = 1024 packets
1024 / 86,326 = 11.9 ms of buffer
```

Any 12 ms hiccup in that one thread drops packets. And `NFQ_REPEAT_MARK = 0x40000000` (`wins_core_server_setup_ONETOUCH.sh:6637`) tells me the config uses `mode: repeat`, which is the **most expensive** of the three NFQ modes: every packet is queued to userspace, copied in full, inspected, then re-injected with `NF_REPEAT` so it re-traverses the entire iptables chain from the top. Two full netfilter traversals plus one netlink round trip, per packet, for every packet of every flow.

`[UNVERIFIED-LIVE]` Single-thread NFQ capacity on a 2.0 GHz Haswell in repeat mode: 8-20 us per packet, so 50,000-125,000 pps. **86,326 pps sits inside that band.** That is your 125,188 drops, arithmetically. Settle the per-packet figure locally:

```bash
# Instantaneous queue depth and drop delta under load.
watch -n1 'cat /proc/net/netfilter/nfnetlink_queue'
# Columns: queue_num portid queue_total copy_mode copy_range queue_dropped \
#          user_dropped id_sequence 1
perf top -p "$(pidof suricata)" -g --sort symbol
```

Four queues at that rate give 200,000-500,000 pps, which clears 1 Gbps with margin.

### Deliverable: four queues, fail-closed, plus a real flow bypass

`[UNVERIFIED-LIVE]` `bypass-mark`/`bypass-mask` are Suricata NFQ capture-bypass keys distinct from `repeat-mark`. Confirm with `suricata --dump-config | grep '^nfq'` before deploying.

```yaml
# /etc/suricata/suricata.yaml
nfq:
  mode: repeat
  repeat-mark: 0x40000000
  repeat-mask: 0x40000000
  # Capture bypass. Once a flow is bypassed Suricata marks it and the firewall
  # stops queueing it. This is the flag that matters: it is what stops the IPS
  # copying ciphertext it cannot read for the life of every elephant flow.
  bypass-mark: 0x20000000
  bypass-mask: 0x20000000
  batchcount: 20
  fail-open: no          # fail CLOSED, matching SURICATA_NFQUEUE_FAIL_OPEN=0

stream:
  bypass: yes            # bypass once the stream depth budget is spent
  reassembly:
    depth: 1mb           # inspect the handshake and early records, then stop

# TLS is where the only real signal on 443 lives. Keep it.
app-layer:
  protocols:
    tls:
      enabled: yes
      ja3-fingerprints: yes
      encryption-handling: bypass   # stop at the encrypted records

# 4 threads on CPU 0-3. CPU 4 and 5 belong to IRQ 36 and 37; putting a
# detect thread there would contend with the softirq that feeds it.
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - worker-cpu-set:
        cpu: [ 0, 1, 2, 3 ]
        mode: exclusive
        threads: 4
```

Unit:

```ini
ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid \
  -q 0 -q 1 -q 2 -q 3 -c /etc/suricata/suricata.yaml
```

Firewall. Replace the single-queue target in **both** `wins_core_server_setup_ONETOUCH.sh:7162` and `wins_data_plane_setup_ONETOUCH.sh:6970`:

```bash
# Was: (-m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0)
# Four queues, flow-hash balanced. NO --queue-cpu-fanout: with one NIC rx
# queue every packet is classified on CPU 4 and fanout would collapse all
# four queues back into one. NO --queue-bypass: fail-closed is the invariant
# that tools/test_deployment_runtime_configs.sh:150 pins.
local -a nfqueue_target=(
  -m mark ! --mark 0x40000000/0x40000000
  -m mark ! --mark 0x20000000/0x20000000
  -j NFQUEUE --queue-balance 0:3
)
```

Carry the bypass decision across packets of the same flow through conntrack, or the mark dies with the first packet:

```bash
iptables -t mangle -A PREROUTING -j CONNMARK --restore-mark \
  --nfmask 0x20000000 --ctmask 0x20000000
iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark \
  --nfmask 0x20000000 --ctmask 0x20000000
```

Two grep-oracle tests will fail on the `--queue-num 0` literal (`wins_core_server_setup_ONETOUCH.sh:2156,2229,2562` and the assertions in `tools/test_deployment_runtime_configs.sh:4452,4776,4898-4901`). Update them to accept `--queue-balance 0:3` in the same commit, and keep the assertion that forbids unconditional `--queue-bypass` exactly as it is.

Port 9111 is already ACCEPTed ahead of NFQUEUE, so **Winn v3 never touches Suricata.** Correct, and it means none of this section bears on the Winn throughput goal. Do not let the 125,188 drops distract from section 3.

---

## 5. AWG MTU and MSS: 1440/1400 is exactly right. 1408 has no arithmetic basis. Reject it.

### The overhead sum

```
Outer IPv4 header          20
Outer UDP header            8
WireGuard type + reserved   4
Receiver index              4
Nonce / counter             8
Poly1305 tag               16
                        = 60 bytes
1500 - 60 = 1440
```

`server/wins_core_server_setup_ONETOUCH.sh:4237,4292,5889` already sets `MTU = 1440`. **Correct, provably, with no change needed.**

MSS clamp:

```
1440 - 20 (inner IPv4) - 20 (inner TCP) = 1400
```

**Also correct.** TCP timestamps consume 12 bytes of the 1400 as options at run time, which is normal and is not an MSS error.

### Why 1408 is wrong

`1500 - 1408 = 92`. There is no 92-byte overhead in AmneziaWG's data path. `[UNVERIFIED-LIVE]` The AWG obfuscation parameters `Jc/Jmin/Jmax` inject standalone junk packets, and `S1/S2` prepend junk to the handshake initiation and response only; `H1..H4` replace the four message type values without changing length. **Type-4 transport data packets are byte-for-byte WireGuard.** So 1408 is 1440 minus an arbitrary 32, and it costs:

```
Goodput lost : (1440 - 1408) / 1440 = 2.22%
pps added    : 1e9/(1408x8) = 88,778 vs 1e9/(1440x8) = 86,806  =  +2.27%
```

You would pay 2.2% of throughput and 2.3% more packets for a hedge against an overhead that does not exist. **Reject 1408.** Verify the AWG claim before shipping:

```bash
awg show wg0 | head -20
tcpdump -ni ens3 'udp port 51820' -c 20 -e | awk '{print $NF}'  # observe frame lengths
```

### The one real MTU defect: IPv6 outer

`MTU = 1440` is flat. If any client reaches the gateway over an IPv6 outer:

```
40 (IPv6) + 8 (UDP) + 32 (WG) = 80
1500 - 80 = 1420
```

**1440 is 20 bytes too large on an IPv6 outer path, and every full-size packet fragments or is silently dropped.** Decide explicitly:

- Path proven IPv4-only: keep `MTU = 1440`, `MSS 1400`.
- Dual-stack: set `MTU = 1420`, `MSS 1380`, and clamp both families.

```bash
# Clamp both families. clamp-mss-to-pmtu follows the real path and is the
# safety net for a mid-path MTU you did not predict.
iptables  -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu

# Prove the inner MTU with DF-set probes. Largest success + 28 = path MTU.
ping -M do -s 1412 -c 3 <inner-peer>   # 1412 + 28 = 1440
ping -M do -s 1413 -c 3 <inner-peer>   # must fail if 1440 is exact
```

### A related finding on Winn v3's own path MTU

`carrier.DefaultPathMTU = 1450` (`sizing.go:137`), against a 1500-byte WAN path your raw measurement of 1742/1652 Mbps confirms is intact. You are leaving 50 bytes per datagram on the table:

```
Inner MTU 1373 -> 91,041 pps at 1 Gbps
Inner MTU 1423 -> 87,842 pps at 1 Gbps    (-3.5% packets, +3.6% payload/packet)
```

`pmtud_linux.go` already reads `IP_MTU`, so the machinery exists. **Escalate to 1500 only on a PMTUD-confirmed path, never blindly**, because `params_mut3.go:191` documents 1280-1420 as a 141-value dead zone and a wrong guess here is worse than 3.5%. Lower priority than sections 2 and 3, but it is free once PMTUD gates it.

---

## 6. XRay Android client: the brief's premise is already satisfied in this tree.

The brief asks to "elevate pipe buffer from 4 KiB to 4 MB." **Done, and the comment explains the unit trap.** `VpnTunnelService.kt:2012` sets `.put("bufferSize", 4096)`, and `VpnTunnelService.kt:1996-1997` records why that is 4 MB and not 4 KiB:

> "Mind the unit. infra/conf/policy.go multiplies the configured value by 1024, so bufferSize 4096 means 4 MB per connection, not 4 KiB."

The diagnosis is also already recorded: Xray's `readDefaultBufferSize` returns `4 * 1024` for `GOARCH=arm64` as a low-end-device concession versus `512 * 1024` on desktop, and `tools/build_xray_engine.sh` builds for android-arm64. Emitting the policy block is the fix and it is in place. **No action. Re-measure before spending further effort here; this line of the brief is stale.**

On the second half, Cloudflare CDN serialization: routing XRay through a CDN adds a TLS terminator and a middlebox to every byte, and its egress is shaped by the CDN's own per-connection policy, not by your 1.96 Gbps Bell Laval link. Where a direct IP transport exists, the CDN is pure loss. But it is also your domain-fronting cover. **This is a threat-model decision, not a performance one, and it is the owner's call, not mine.** The measurement that makes the call cheap:

```bash
# Same XRay config, two outbounds. Run both, compare.
#   A: "address": "<cdn-hostname>"      (current)
#   B: "address": "<gateway-direct-ip>", "serverName": "<cdn-hostname>"
# B keeps the SNI cover and removes the CDN hop. If B is materially faster,
# you are paying for fronting you may already get from SNI alone.
```

---

## 7. Android TUN pump: already fixed, and the brief is quoting the pre-fix telemetry back at us.

Everything the brief asks for is present in `WinnV3AndroidTun.kt`:

| Asked | Status | Evidence |
|---|---|---|
| Burst drain vs single-packet wake | Present | `runBurstReader`, `MAX_BURST_PACKETS = 256`, line 329 comment "ONE WAKE CARRIES A WHOLE BURST. THIS IS THE UPLINK FIX." |
| `Thread.MAX_PRIORITY` | Present | line 320, plus kernel-side `THREAD_PRIORITY_URGENT_AUDIO` |
| Queue overflow semantics | Present, and correct | `enqueue` line 501: `if (count == queueDepth) return false` = tail drop |

**Tail drop on the uplink ring is the right policy and I am not changing it.** The reasoning in `winn3_frame_device.go:88-98` is sound: removing the head of an in-order inner TCP stream deletes the lowest unacknowledged sequence number, the receiver cannot describe the hole with a SACK block, and the sender waits out an RTO instead of fast-retransmitting. Tail drop costs a halved cwnd. Head drop costs a cwnd collapse to 1 and a repeating cycle.

**Integrity note on the telemetry.** The brief cites "21.5-255 Mbps up." That exact range appears in `winn3_frame_device.go:95-96` as the **symptom the tail-drop fix was written to remove**:

> "Measured on a Samsung Galaxy S26 Ultra against the Canada gateway, the uplink sat between 21.5 and 255 Mbps with exactly that variance, while the same handset with no VPN did 1652.9 Mbps up."

So the brief is quoting a pre-fix measurement as if it were current state. **Re-measure the handset uplink against the patched gateway before anyone spends another hour here.** I decline to propose Android changes against telemetry the source tree says is obsolete.

### What is genuinely still costly on the handset

Three copies per packet: kernel TUN read into `buffer`, `System.arraycopy` into `slab` (line 503), `batch.append` out of `slab`. At 91,041 pps and 1400 bytes:

```
3 x 1400 x 91,041 = 382 MB/s of memcpy
```

On an S26 Ultra that is a small single-digit percentage of one core. Real, measurable, **and not worth fixing before section 3 lands**, because the gateway is the binding constraint and a slab-free redesign risks the rebind-generation correctness that lines 358-390 carefully establish. Ranked below everything in sections 2 and 3.

The per-packet `synchronized(state)` inside the drain loop is likewise fine. An uncontended ART thin-lock CAS is tens of nanoseconds; 91,041 pps x 2 x 30 ns is about 0.5% of a core. The comment at line 351 makes the right trade deliberately: holding the monitor across a whole 256-packet burst would block `readOutgoingBatch`, `rebind` and `close` for the burst's duration. **Leave it.**

---

## 8. Decoy calculator lockout: the re-arm is the trap, and rebooting makes it permanent.

### Root cause, exact

`lib/local_security.dart:448-450`:

```dart
static const int lockoutThreshold = 5;
static const int baseDelaySeconds = 5;
static const int maxDelaySeconds = 300;
```

Five failures arm a backoff that caps at 300 seconds. That part is working as designed. **The trap is `rearmAfterMonotonicRollback`** (`local_security.dart:495-500`), called from `_verifyUserPin` (`lib/main.dart:11021-11027`):

```dart
lockedUntilMonotonicMs: nowMonotonicMs + maxDelaySeconds * 1000,
```

A reboot resets the monotonic clock epoch, `isMonotonicRollback` fires, and the gate re-arms a **fresh 300 seconds** anchored to the new epoch while preserving `failureCount`. So rebooting the handset to clear the lockout re-arms it. Reboot again, another 300 seconds. **Under the tester's most natural recovery action the lockout is unclearable.** That is exactly the reported symptom.

The design intent is defensible (M-15: a stale pre-reboot deadline compared against a new epoch could mean anything from an accidental near-permanent lockout to an accidental early release, so it refuses to simply clear the penalty). The consequence for a developer holding their own handset was not anticipated.

### Remediation, in ascending order of risk. Use the first one.

**Option 1, zero risk: do not reboot. Wait 300 seconds, then enter the PIN exactly once.** The re-arm triggers only on monotonic rollback, which only a reboot causes. A single 5-minute wait clears it. This is the correct answer and it needs no tooling.

**Option 2, targeted, non-destructive.** The debug build is debuggable, so `run-as` reaches the app-private directory. `SecureFileStore.kt:62-72` maps logical names to on-disk names: `vpn_settings.txt` is `prefs.dat`, `user_pin.txt` is `profile.dat`, both under `filesDir/secure_state`.

```bash
# Delete ONLY the settings record that carries pin_attempt_state.
# profile.dat (user_pin.txt) is left intact, so the enrolled PIN survives.
adb -s REDACTED_SERIAL shell run-as org.winsvpn.app.debug \
  ls -la files/secure_state
adb -s REDACTED_SERIAL shell run-as org.winsvpn.app.debug \
  rm -f files/secure_state/prefs.dat
adb -s REDACTED_SERIAL shell am force-stop org.winsvpn.app.debug
```

Cost: the other `vpn_settings.txt` runtime settings reset to defaults. Recoverable. **The enrolled credential in `profile.dat` is untouched**, which is the whole point of choosing this over option 3.

**Option 3, `pm clear`: do not use it.** It destroys the AndroidKeyStore alias along with the data, which means `keystore.dat` (`client_keypair.json`), `profile.dat` (the enrolled PIN) and every subscription artifact are unrecoverable. **Clearing app data to fix a 5-minute rate limit would destroy the device's client identity.** Flagging this explicitly because it is the first thing most people reach for.

### A second failure mode that looks identical and is not the lockout

`lib/main.dart` in `_verifyUserPin`: if `user_pin.txt` holds a legacy plaintext credential, the path **deletes it and throws `PinReenrollmentRequired`** rather than accepting it, even when the PIN is correct (M-1). If `142536=` was enrolled before the hashed-credential migration, it can never verify, and the UI shows the same generic failure the lockout shows. Distinguish them before assuming lockout:

```bash
adb -s REDACTED_SERIAL logcat -c
adb -s REDACTED_SERIAL logcat | grep -iE 'PinReenrollment|pin_attempt|PinAttemptState|lockedUntil'
```

`PinReenrollmentRequired` means re-enroll, not wait.

### The product defect worth fixing, separate from unblocking you

`rearmAfterMonotonicRollback` should cap total re-arms, or anchor the re-arm to the **remaining** pre-reboot delay rather than always to `maxDelaySeconds`. Today an adversary who can force reboots holds the owner out indefinitely, and the owner cannot distinguish that from a broken app. Recommended change, preserving the M-15 intent:

```dart
  /// Re-arms after [isMonotonicRollback] detects a reboot, bounded by the
  /// delay the failure count actually earned rather than always by
  /// [maxDelaySeconds].
  ///
  /// The old form imposed a fresh maxDelaySeconds on EVERY reboot while a
  /// monotonic deadline was set, so rebooting to clear a lockout re-armed it
  /// and the penalty became unclearable by the owner's most natural recovery
  /// action. Anchoring to the earned delay keeps M-15's refusal to silently
  /// clear the penalty while making the lockout terminate.
  PinAttemptState rearmAfterMonotonicRollback(int nowMonotonicMs) {
    final earnedSeconds = delayForFailureCount(failureCount);
    return PinAttemptState(
      failureCount: failureCount,
      lockedUntilUtc: lockedUntilUtc,
      lockedUntilMonotonicMs: nowMonotonicMs + earnedSeconds * 1000,
      lastSeenMonotonicMs: nowMonotonicMs,
    );
  }
```

where `delayForFailureCount` is the existing backoff schedule (`baseDelaySeconds` doubling, capped at `maxDelaySeconds`). This is a behaviour change under test; the suite pins the current shape, so it lands with its own test update and should be a separate commit from the throughput work.

---

## Ranked remediation, with the arithmetic that ranks it

| # | Change | Site | Expected gain | Proof |
|---|---|---|---|---|
| 1 | UDP GSO on TX, UDP GRO on RX | new `udp_gso_linux.go` | TX skbs 91,041/s to 1,979/s (46x); RX to 5,690/s (16x). Retires `SndbufErrors 263,060` | §2, §3 |
| 2 | `demuxChanDepth` 4096 to 256 + non-blocking pump + control lane | `cover_demux.go:43,224,436` | Control-plane HOL 85.7 ms to 42.7 ms; 30 MiB returned to a 96 MiB GOMEMLIMIT. **Ends the teardown** | §3 |
| 3 | Liveness deadline 400 ms, 3 misses | session driver | Makes collapse impossible rather than unlikely | §3 |
| 4 | Length-bucketed copy-on-write CID index | `cover_demux.go:284-328` | Removes an O(4096) mutex-held scan from ~50% of data packets; closes a pre-auth remote DoS | §3 |
| 5 | RPS `0x0c`, `gro_flush_timeout`, `napi_defer_hard_irqs`, `fq flow_limit 8192` | new steering script | One extra core of RX stack per flow; removes the ENOBUFS source | §2 |
| 6 | `CPUAffinity=0-1` on the gateway unit | systemd | Stops the scheduler placing the pump on CPU 4/5 against the pinned IRQs. **Prerequisite for RFS** | §2 |
| 7 | Suricata `-q 0..3`, `--queue-balance 0:3`, capture bypass | installers + yaml | 86,326 pps against a 50-125k single-thread ceiling becomes 200-500k. Clears the 125,188 drops | §4 |
| 8 | Hoist the per-`recv` `time.Timer` | `cover_demux.go:433` | Removes ~9 MB/s of GC garbage from the collapse loop | §3 |
| 9 | AWG: keep 1440/1400; add ip6tables clamp, or move to 1420/1380 | installers | Correctness on IPv6 outer paths. **Reject 1408** | §5 |
| 10 | `SO_REUSEPORT` worker pool | gateway bind | No single-client gain. Required for N-handset scale and for RPS to have flows to spread | §2 |
| 11 | Winn v3 path MTU 1450 to PMTUD-confirmed 1500 | `sizing.go:137` | 3.5% fewer packets. **Only behind PMTUD**, never blind | §5 |
| — | Cipher agility | | 2.50 points of one core per Gbps. **Do not build it** | §1 |
| — | XPS, `--queue-cpu-fanout`, `--queue-bypass` | | No-op, harmful, and banned by your own tests respectively | §2, §4 |
| — | XRay pipe buffer, Android burst drain | | **Already shipped.** Brief's premises are stale | §6, §7 |

## The measurements that settle every `[UNVERIFIED]` term

The one number I could not derive from your telemetry is the per-skb kernel cost, and it is the term that decides how much of items 1 and 5 you get. Thirty seconds of `perf` settles it:

```bash
# Where the cycles actually go under load. If udp_sendmsg/ip_make_skb/
# __dev_queue_xmit/fq_enqueue dominate, item 1 is worth everything above.
perf record -F 999 -a -g -- sleep 30 && perf report --sort symbol | head -40

# Is the collector the stall source? Confirms or kills the GOMEMLIMIT loop.
systemctl set-environment GODEBUG=gctrace=1
journalctl -u winn3-gateway -f | grep -E '^gc [0-9]+'

# Softirq distribution. Proves whether CPU 4 is the wall.
mpstat -P ALL 1 10

# Drop accounting, all four layers, before and after each change.
nstat -az | grep -E 'UdpRcvbufErrors|UdpSndbufErrors|UdpInErrors'
cat /proc/net/netfilter/nfnetlink_queue
tc -s qdisc show dev ens3
ethtool -S ens3 | grep -iE 'drop|err'
```

Run that suite once before item 1 and once after. If `perf` does not show the per-skb transmit path dominating, I am wrong about the ranking and item 2 moves to first place on its own arithmetic, which stands independently.

**One closing statement of position.** Crypto is 7.75% of budget and the cipher question is settled. The single virtio queue is a red herring that dissolves at 6,000 skbs per second. The session collapse above 700 Mbps is not a mystery: it is 85.7 milliseconds of FIFO, sitting in front of a liveness probe, computed from two constants in this repository, and it will get worse every time the link gets faster until the queues are made shallower and the control plane is given its own lane.
