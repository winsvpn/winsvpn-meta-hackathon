# Turn 1 Submission: claude-opus5

# ROUND 43 PODIUM VERDICT: Claude Opus 5 (extra-high)

## 0. Disclosure of evidence basis

No tools were permitted for this turn, so I could not read `winn3/driver/loop.go`, `winn3/core/batch.go`, `cmd/winn-datapath/winn3_frame_device.go`, or `udp_batch_unix.go`. Every diff below is anchored to the exact text quoted in packet sections 2.1 through 2.3. Hunks that depend on lines the packet did not quote are marked CONTINGENT with the exact predicate that decides whether to apply them. Crypto throughput figures and syscall fixed costs are parametric with the assumed constant stated inline; those are marked `(unverified)` and do not change any vote, because every vote below survives across the full plausible range of those constants.

---

## 1. First-principles arithmetic

### 1.1 Target and observed budgets

Target: 1,000 Mbps = 125,000,000 B/s. At 1373 B inner MTU:

```
125,000,000 / 1373 = 91,041.51 pps
1 / 91,041.51      = 10.9840 µs per packet (aggregate wall clock)
```

Run 15 observed:

```
419,954,688 B / 8.000 s = 52,494,336 B/s = 419.955 Mbps
52,494,336 / 1373       = 38,233.31 pps
1 / 38,233.31           = 26.1552 µs per packet
```

Correction to the packet: section 1.1 states 38,255 pps and 26.14 µs. That figure implies an inner size of 1372.2 B, not 1373 B. The internal inconsistency is 0.057%. Using 1373 B consistently, the true figures are 38,233.31 pps and 26.1552 µs. The residual to retire is 26.1552 − 10.9840 = **15.1712 µs per packet**, and the required speedup is 91,041.51 / 38,233.31 = **2.3812x**.

### 1.2 The decisive refutation: syscall batching cannot retire 15.17 µs

Amortized per-packet cost of a vectored send is `F/B + M`, where F is the fixed per-`sendmmsg` cost (entry, exit, vector walk setup) and M is the per-message kernel cost (checksum, route lookup, qdisc enqueue, driver xmit). Widening B touches only the `F/B` term. M is invariant under batching.

Retirable time going from B=32 to B=256:

```
F * (1/32 - 1/256) = F * 0.02734375
```

Setting that equal to the 15.1712 µs gap:

```
F = 15.1712 / 0.02734375 = 554.83 µs per sendmmsg call
```

For B=512:

```
F = 15.1712 / 0.029296875 = 517.84 µs per sendmmsg call
```

A 554 µs syscall entry cost on an arm64 Oryon core at 3.63 GHz is roughly 2.0 million cycles. Measured arm64 syscall entry plus vector setup is under 10 µs even with Android's `xt_qtaguid` socket tagging in the path. At a generous F = 10 µs the actual retirement is:

```
10 µs * 0.02734375 = 0.2734 µs per packet (B=256)
10 µs * 0.029296875 = 0.2930 µs per packet (B=512)
```

That is 1.05% of the 26.1552 µs budget, not 58%. Packet section 2.1's claim of "slashing syscall context switching and core scheduling overhead by up to 93.8%" describes the reduction in call *count* (1 − 32/512 = 93.75%), which is correct, and then implicitly attributes a proportional reduction in *cost*, which is false because cost is dominated by the O(n) per-message term.

### 1.3 The 420.2 Mbps analytical bound already tells you where the constraint is

Section 1.1 reports the measured 420.0 Mbps matching a prior analytical bound of 420.2 Mbps to within 0.05%. A model that accurate is a model of the binding constraint. Check whether the transmit syscall path could have produced that bound:

```
38,233.31 pps / 32 = 1,194.79 sendmmsg calls/s
1 / 1,194.79       = 837.0 µs available per call
```

For `sendmmsg` at B=32 to be the binding constraint, each call would have to consume 837 µs. It does not. Alternatively, for the per-message kernel term M to bind, M would have to be 26.1552 µs per datagram; typical UDP transmit cost is 1 to 3 µs per datagram `(unverified)`. Neither branch is reachable.

Conclusion: the 420.2 Mbps bound was set upstream of the Go transmit loop, consistent with the packet's own narrative that the bound was derived from the Kotlin burst reader and batch pump after lock contention was removed. OI-1, OI-2, and OI-3 all operate downstream of that bound. **No combination of them can exceed a ceiling imposed upstream.**

### 1.4 Corroborating evidence in the telemetry

Run 15 reports `tx_dropped_sink=0`, zero socket errors, and all 32 HTTP streams completing with HTTP 200. `offerBatch` calls `d.push(d.toEngine, pkt, &d.droppedToEngine, false)` against a 65,536-deep channel with a drop counter. If that push is non-blocking (the `false` argument and the presence of a drop counter both indicate it is), then zero drops across 8 seconds means the 65,536-slot channel never filled. A queue that never fills is not the constraint, and the consumer behind it was never the constraint either. The producer side was throttled by something that never presented backpressure to this queue.

### 1.5 Bandwidth-delay product cross-check on the measurement harness

At 65 ms RTT across 32 concurrent HTTP streams:

```
Required in-flight at 1,000 Mbps: 125,000,000 * 0.065 = 8,125,000 B = 7.75 MiB
Per stream:                        8,125,000 / 32      = 253,906 B = 248 KiB

Observed in-flight at 420 Mbps:    52,494,336 * 0.065  = 3,412,132 B = 3.25 MiB
Per stream:                        3,412,132 / 32      = 106,629 B = 104.1 KiB
```

104.1 KiB per stream is within a few percent of common congestion window and receive window ceilings. This is a falsifiable alternative hypothesis for the 420 Mbps plateau that the packet does not consider, and it is consistent with the zero-drop telemetry. Before any of OI-1 through OI-3 is credited with a throughput change, the harness must be rerun with per-stream `tcp_info` capture (`snd_cwnd`, `snd_wnd`, `rcv_space`, `bytes_retrans`). If `snd_cwnd * mss` sits near 104 KiB with zero retransmits, the plateau is in the measurement harness, not the datapath.

### 1.6 Composite expected outcome of the round's proposals

| Change | Expected retirement (µs/pkt) | Optimistic bound (µs/pkt) |
|---|---|---|
| sendmmsg 32 to 256 (OI-1A, F = 5 to 10 µs) | 0.137 | 0.273 |
| toEngine batch carrier (OI-2) | 0.115 | 3.980 |
| Crypto batch 32 to 256 (OI-3 Option 1 only) | 0.328 | 0.328 |

Derivations for rows 2 and 3 appear in sections 3.2 and 3.3.

```
Option 2 path, expected:    26.1552 - 0.252 = 25.9032 µs -> 38,605 pps -> 424.0 Mbps
Option 2 path, optimistic:  26.1552 - 4.253 = 21.9022 µs -> 45,658 pps -> 501.5 Mbps
Option 1 path, optimistic:  26.1552 - 4.581 = 21.5742 µs -> 46,352 pps -> 509.1 Mbps
```

The best case across all four items reaches **50.9% of the 1,000 Mbps target**. The expected case reaches **42.4%**, a gain of 0.96% over Run 15.

### 1.7 What actually closes the gap

Per-packet serialized cost must fall to 10.9840 µs, or the transmit path must run on more than one core. With the batching changes applied (21.90 µs/pkt optimistic), lane sharding gives:

```
2 lanes: 21.9022 / 2 = 10.9511 µs -> 91,315 pps -> 1,003.0 Mbps
3 lanes: 21.9022 / 3 =  7.3007 µs -> 136,972 pps -> 1,504.5 Mbps
```

Two lanes clear the bar with 0.3% of margin, which is not a margin. Three lanes is the engineering answer. Two constraints attach:

- **Flow-hash sharding, not round robin**: lane selection must hash the inner packet 5-tuple. Round-robin distribution reorders segments within a TCP flow, and at 32 streams over 3 lanes the expected reordering would collapse every inner congestion window. Hashing 32 streams across 3 lanes gives ~10.7 streams per lane, adequate balance.
- **Separate UDP sockets per lane**: concurrent `sendmmsg` on a shared UDP fd serializes on the socket lock, which removes most of the parallelism benefit. Separate sockets mean separate source ports, which requires `cover_demux.go` and the gateway session demux to key on the WinnV3 session identifier rather than the 4-tuple. That is a gateway-side contract change and belongs in its own round.

### 1.8 Gateway assessment (packet section 2.4)

`main.go` `readLoopEntered` calls `ReadFromUDPAddrPort` one datagram at a time; `deliverSessionDatagram` pushes one `*[]byte` per datagram into `p.inbox`; `t.dev.WritePacket(p.body)` issues one `write()` to the Linux TUN per datagram. Per-packet serialized gateway cost, using 2 µs per `recvfrom`, ~0.12 µs for two channel operations, and ~3 µs per TUN `write()` `(unverified)`:

```
Floor estimate:  ~5.1 µs/pkt -> 196,078 pps -> 2,153 Mbps
Realistic:      ~10.0 µs/pkt -> 100,000 pps -> 1,098 Mbps
```

At Run 15's 38,233 pps the gateway consumes 0.20 to 0.38 of one core. **Answer: the gateway is not saturated at 420 Mbps.** It is also not the active bottleneck. But at the 1,000 Mbps target it has roughly 9% of headroom in the realistic case, so it is a co-bottleneck that must be fixed in the same program of work. Note the internal inconsistency the packet surfaces: `cover_demux.go` already uses `recvmmsg` at `demuxBatchSize = 64` while `main.go` uses single-datagram reads. The session ingress path is the unbatched one.

---

## 2. Votes

**OI-1: DISAGREE:** closing the 15.1712 µs/packet residual by widening the transmit batch from 32 to 256 requires a fixed per-`sendmmsg` cost of 554.83 µs (15.1712 ÷ (1/32 − 1/256)); arm64 syscall entry plus vector setup is under 10 µs, which bounds the retirement at 0.2734 µs/packet, or 1.05% of the budget.

**OI-2: AGREE**, subject to two recorded corrections: the post-change channel operation rate is 711.3/s, not 356/s, because the descriptor return path adds two operations per batch; and the expected retirement is 0.115 µs/packet (optimistic bound 3.98 µs/packet), so this item must not be credited with closing the gap.

**OI-3: AGREE (Option 2)**, on the arithmetic that Option 1's marginal advantage is 0.3281 µs/packet (1.25% of budget) and is purchased by mutating a constant the downlink receive path reads, which OI-4 forbids.

**OI-4: AGREE**, conditioned on the three enforceable guarantees in section 3.4. Option 1 of OI-3 violates the invariant; Option 2 plus the OI-1 and OI-2 diffs below do not.

**OI-5 (new item, proposed):** the item set OI-1 through OI-4 is arithmetically incapable of reaching 1,000 Mbps, topping out at 509.1 Mbps in the most optimistic case. I move that Round 43 add an item covering (a) instrumentation of the Kotlin TUN reader and LocalSocket transfer to locate the ~20 µs of unattributed per-packet serialized time, (b) per-stream `tcp_info` capture to exclude the harness BDP hypothesis in section 1.5, and (c) flow-hashed 3-lane uplink sharding with its gateway demux contract change.

---

## 3. Reasoning and exact diffs

### 3.1 OI-1: batch widening, memory, and the short-write finding

Memory per transmit slot on arm64 (64-bit), using 1500 B outer buffers:

```
unix.Mmsghdr        64 B   (msghdr 56 + msg_len 4 + 4 pad)
unix.Iovec          16 B
RawSockaddrInet6    28 B
outer buffer      1500 B
                 ------
                  1608 B per slot

 32 slots:    51,456 B =  50.25 KiB (current)
256 slots:   411,648 B = 402.00 KiB
512 slots:   823,296 B = 804.00 KiB
```

Adding Go slice headers for `writeBatchBufs` and the `BatchMsg` wrapper at ~48 B per slot: 256 slots total ≈ 414 KiB. The increase over the current allocation is 351.75 KiB per loop instance. That is unremarkable against an Android app heap.

The `wmem_max` question has a sharper answer than the packet expects. Socket send accounting charges `skb->truesize`, not payload length. For a 1500 B linear UDP skb on arm64: 2048 B kmalloc bucket + ~320 B `skb_shared_info` + ~240 B `sk_buff` ≈ 2,608 B `(unverified)`.

```
256 datagrams * 2,608 = 667,648 B = 652.0 KiB
512 datagrams * 2,608 = 1,335,296 B = 1.273 MiB
wmem_max = 8 MiB      = 8,388,608 B
```

Both fit inside `wmem_max` (7.96% and 15.92%). But `wmem_max` is the ceiling, not the socket's actual `sk_sndbuf`. If `SO_SNDBUF` was never raised, the socket carries `wmem_default`, typically 212,992 B:

```
212,992 / 2,608 = 81.67 -> 81 datagrams
```

**Falsifiable prediction: widening `writeBatchMsgs` to 256 without raising `SO_SNDBUF` will produce a short `sendmmsg` return at approximately 81 messages under sustained load, regardless of the array width.** The existing `l.writeBatchMsgs[sent:count]` resume logic makes this a performance defect rather than a correctness defect, but the 256-wide vector would never actually be transmitted as one call. The diff in 3.1.3 is therefore mandatory, not optional.

**Proposal B (`UDP_SEGMENT`) verdict:** reject for this round. GSO coalescing requires uniform segment sizes across the coalesced buffer, which the WinnV3 outer frame does not guarantee once the inner MTU varies. It also interacts with PMTU discovery and with Android's per-UID network tagging in ways that require their own validation round. The arithmetic in section 1.2 shows batching of any form retires under 0.3 µs/packet, so GSO's additional complexity buys nothing measurable against a 15.17 µs gap.

#### Diff 3.1.1: `winn3/core/batch.go`, new transmit-only constant

```diff
--- a/winn3/core/batch.go
+++ b/winn3/core/batch.go
@@
 // MaxBatchSize bounds a single crypto batch. Frozen under the Round 35 and
 // Round 38 downlink treaties: the receive path sizes its slot arrays and its
 // CryptoPool job array from this value. Do not change it without reopening
 // the downlink freeze invariant.
 const MaxBatchSize = 32
+
+// MaxTxBatchSize bounds one outer sendmmsg vector on the transmit path only.
+// It is read by driver/loop.go when sizing writeBatchBufs and writeBatchMsgs
+// and when accumulating crypto batches into a single SendBatch call. Nothing
+// on the receive path reads this constant.
+const MaxTxBatchSize = 256
+
+// TxBatchesPerSend is the number of whole crypto batches accumulated into one
+// SendBatch call. 256 / 32 = 8.
+const TxBatchesPerSend = MaxTxBatchSize / MaxBatchSize
+
+// Compile-time guard: MaxTxBatchSize must remain an exact multiple of
+// MaxBatchSize so the accumulation loop in driver.loop never leaves a partial
+// crypto window. A non-zero remainder makes the array length non-zero and the
+// assignment fails to typecheck.
+var _ [0]struct{} = [MaxTxBatchSize % MaxBatchSize]struct{}{}
```

The constant name `MaxBatchSize` keeps its value and its every existing reader. This is what makes OI-4 enforceable by `git diff` rather than by assertion.

#### Diff 3.1.2: `winn3/driver/loop.go`, buffer sizing

CONTINGENT on the packet's statement in section 2.1 that the allocation site reads `batchCapacity = session.MaxBatchSize`. Apply at that allocation site.

```diff
--- a/winn3/driver/loop.go
+++ b/winn3/driver/loop.go
@@
-	batchCapacity := session.MaxBatchSize
+	// Transmit vectors are sized from the transmit-only constant. The receive
+	// side keeps session.MaxBatchSize. See core.MaxTxBatchSize.
+	batchCapacity := core.MaxTxBatchSize
```

If `core` is not already imported in `loop.go`, add it to the import block in the existing group ordering.

#### Diff 3.1.3: transmit socket buffer sizing

CONTINGENT on the socket construction site in `udp_batch_unix.go`. Apply immediately after the fd is obtained and before the first `SendBatch`.

```diff
--- a/winn3/carrier/udp_batch_unix.go
+++ b/winn3/carrier/udp_batch_unix.go
@@
+// txSockBufBytes sizes the transmit socket buffer for a full
+// core.MaxTxBatchSize sendmmsg vector. Accounting charges skb truesize, not
+// payload: 256 datagrams at roughly 2,608 B truesize need 652 KiB. The default
+// wmem_default of 208 KiB admits only about 81 datagrams and would force a
+// short send on every call. The kernel doubles the requested value, so 4 MiB
+// requested yields 8 MiB accounted, matching net.core.wmem_max on the target
+// device. Failure to raise the buffer is not fatal: the batch simply sends
+// short and the caller's resume path handles the remainder.
+const txSockBufBytes = 4 << 20
+
+func setTxSockBuf(fd int) {
+	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, txSockBufBytes); err != nil {
+		logf("carrier: SO_SNDBUF %d failed, transmit batches will send short: %v", txSockBufBytes, err)
+	}
+}
```

Call `setTxSockBuf(fd)` at the socket construction site. Substitute the package's existing logging helper for `logf`; if the package has none, drop the message and discard the error, since the short-send path is already correct.

### 3.2 OI-2: inbound batch carrier, ownership, credit, and the exact retirement

**Question 1, memory ownership and recycling.** The existing contract is already a handoff: `d.push(d.toEngine, pkt, ...)` places a slice header on the channel and the producer must not touch that backing array again. The batch carrier preserves that contract exactly and adds a second contract for the descriptor itself. A descriptor ring plus a free list gives strict credit accounting: a producer that cannot obtain a descriptor drops, and a consumer that has finished a descriptor returns it. No `sync.Pool`, so no GC-timed descriptor churn and no possibility of the producer overwriting a descriptor still queued.

**Question 2, credit and drop policy.** Two semantic changes must be recorded. First, drop granularity moves from one packet to up to 512. A single drop event now discards a contiguous run of segments that may belong to one inner TCP flow, which collapses that flow's congestion window far harder than a scattered single-packet loss. The diff below mitigates by dropping only the remainder that does not fit rather than discarding the whole offered batch on the first failure. Second, `droppedToEngine` must be incremented by the packet count, not by 1, or the counter silently under-reports by up to 512x.

**Question 3, exact per-packet CPU retired.** At the 1,000 Mbps target:

```
Before: 91,041.51 sends + 91,041.51 receives      = 182,083.0 ops/s
After:  (91,041.51 / 512) batches = 177.82/s
        * 4 ops (toEngine send/recv, free send/recv) =    711.3 ops/s
Reduction: 99.61%
```

The packet's figure of 356/s counts only the forward direction and omits descriptor return. Per-packet:

```
(182,083.0 - 711.3) / 91,041.51 = 1.9922 channel ops retired per packet
```

A buffered Go channel operation on a 24 B element is a lock acquire, a memmove, a lock release: roughly 25 to 70 ns uncontended on arm64 `(unverified)`. At the 60 ns upper end:

```
1.9922 * 60 ns = 0.1195 µs retired
New cost added: 2 slice-header copies (48 B) at ~10 GB/s = 0.0048 µs
Net: 0.1147 µs per packet = 0.44% of the 26.1552 µs budget
```

Under heavy park/unpark contention a channel operation reaches 1 to 2 µs, which would give up to 3.98 µs per packet. Run 15's evidence argues against that regime: a 65,536-deep channel that never dropped a single packet was not a channel where the consumer repeatedly parked on empty under producer pressure. Treat 0.115 µs as expected and 3.98 µs as the optimistic bound.

**Bufferbloat finding.** A 65,536-packet queue is a latency defect independent of throughput:

```
65,536 / 91,041.51 = 719.85 ms of standing queue at 1,000 Mbps
65,536 / 38,233.31 = 1,714.2 ms at Run 15 rates
```

Any standing occupancy at those depths destroys inner TCP RTT estimation on a path whose real RTT is 65 ms. The ring below holds 8 descriptors of 512:

```
8 * 512 = 4,096 packets / 91,041.51 = 44.99 ms
```

That is 16x less queue while still carrying 8x the 512-packet arrival quantum as headroom. Setting `engineBatchRingLen = 4` halves it again to 22.50 ms if the team prefers a tighter latency target; 8 is the safer default against scheduler jitter.

**Descriptor memory:** `8 * 512 * 24 B = 98,304 B = 96.0 KiB` of slice headers.

#### Diff 3.2.1: `cmd/winn-datapath/winn3_frame_device.go`, descriptor type and ring

```diff
--- a/cmd/winn-datapath/winn3_frame_device.go
+++ b/cmd/winn-datapath/winn3_frame_device.go
@@
+// engineBatchSlots is the packet capacity of one toEngine descriptor. It
+// matches the 512-packet batch quantum delivered by the Kotlin inboundPump so
+// a full arrival fits one descriptor.
+const engineBatchSlots = 512
+
+// engineBatchRingLen is the descriptor count. 8 * 512 = 4,096 packets, which
+// is 44.99 ms of queue at the 91,041.51 pps wire-speed target, replacing the
+// 65,536-slot channel that held 719.85 ms at the same rate. Descriptor memory
+// is 8 * 512 * 24 B = 96.0 KiB of slice headers.
+const engineBatchRingLen = 8
+
+// engineBatch carries one uplink packet batch from the Kotlin frame reader to
+// the engine drain. Ownership rules:
+//
+//	1. offerBatch takes ownership of every packets[i] backing array handed to
+//	   it. The caller must not recycle or write those arrays afterwards. This
+//	   is the same contract the previous per-packet chan []byte carried.
+//	2. A descriptor obtained from freeEngine is owned exclusively by the
+//	   producer until it is sent on toEngine, and exclusively by the consumer
+//	   from receipt until it is returned to freeEngine.
+//	3. The consumer clears packets[0:count] before returning the descriptor so
+//	   a stale slice header cannot pin a recycled buffer.
+type engineBatch struct {
+	packets [][]byte
+	count   int
+}
```

#### Diff 3.2.2: device fields and construction

CONTINGENT on the existing struct field and constructor. Replace the `toEngine chan []byte` declaration and its `make` call.

```diff
--- a/cmd/winn-datapath/winn3_frame_device.go
+++ b/cmd/winn-datapath/winn3_frame_device.go
@@ type winn3FrameDevice struct {
-	toEngine        chan []byte
+	toEngine        chan *engineBatch
+	freeEngine      chan *engineBatch
 	droppedToEngine uint64
@@
-	d.toEngine = make(chan []byte, 65536)
+	d.toEngine = make(chan *engineBatch, engineBatchRingLen)
+	d.freeEngine = make(chan *engineBatch, engineBatchRingLen)
+	for i := 0; i < engineBatchRingLen; i++ {
+		d.freeEngine <- &engineBatch{packets: make([][]byte, engineBatchSlots)}
+	}
```

`fromEngine` and every downlink field are untouched. See section 3.4.

#### Diff 3.2.3: `offerBatch`

```diff
--- a/cmd/winn-datapath/winn3_frame_device.go
+++ b/cmd/winn-datapath/winn3_frame_device.go
@@
 func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
-	for _, pkt := range packets {
-		d.push(d.toEngine, pkt, &d.droppedToEngine, false)
-	}
-	return nil
+	if len(packets) == 0 {
+		return nil
+	}
+	for off := 0; off < len(packets); {
+		var b *engineBatch
+		select {
+		case b = <-d.freeEngine:
+		default:
+			// Ring exhausted. Drop the remainder rather than the whole offer so
+			// a single exhaustion event does not discard packets already staged.
+			atomic.AddUint64(&d.droppedToEngine, uint64(len(packets)-off))
+			return nil
+		}
+		n := copy(b.packets[:engineBatchSlots], packets[off:])
+		b.count = n
+		off += n
+		select {
+		case d.toEngine <- b:
+		default:
+			// toEngine full while freeEngine had credit: return the descriptor
+			// and account both this batch and the untouched remainder.
+			for i := 0; i < n; i++ {
+				b.packets[i] = nil
+			}
+			b.count = 0
+			d.freeEngine <- b
+			atomic.AddUint64(&d.droppedToEngine, uint64(n+(len(packets)-off)))
+			return nil
+		}
+	}
+	return nil
 }
```

The `d.freeEngine <- b` on the recovery path cannot block: the descriptor was just taken from `freeEngine`, so the ring has a free slot by construction.

#### Diff 3.2.4: consumer drain

CONTINGENT on the existing engine-side reader. This adds the batched read; the existing scalar read call site must be replaced with a call to it.

```diff
--- a/cmd/winn-datapath/winn3_frame_device.go
+++ b/cmd/winn-datapath/winn3_frame_device.go
@@
+// readBatchInto drains one descriptor into out and returns the packet count.
+// out must have length at least engineBatchSlots; a shorter slice would
+// silently discard the tail of a full descriptor, so the mismatch is an error
+// rather than a truncation.
+func (d *winn3FrameDevice) readBatchInto(out [][]byte) (int, error) {
+	if len(out) < engineBatchSlots {
+		return 0, fmt.Errorf("winn3FrameDevice: readBatchInto needs %d slots, got %d", engineBatchSlots, len(out))
+	}
+	var b *engineBatch
+	select {
+	case b = <-d.toEngine:
+	case <-d.closed:
+		return 0, io.EOF
+	}
+	n := copy(out, b.packets[:b.count])
+	for i := 0; i < b.count; i++ {
+		b.packets[i] = nil
+	}
+	b.count = 0
+	d.freeEngine <- b
+	return n, nil
+}
```

`d.freeEngine <- b` cannot block here either: the descriptor was in flight on `toEngine`, so its slot in the ring is free. Substitute the device's existing close signal for `d.closed` if it is named differently.

### 3.3 OI-3: why Option 2, with the arithmetic

**Cache locality.** One 256-packet batch touches `256 * 1373 = 351,488 B` of plaintext. AEAD reads plaintext and writes ciphertext, so ~703 KiB of traffic per batch. Spread across 8 workers that is 88 KiB per core of working set. Snapdragon 8 Elite carries 12 MiB of cluster L2 and 8 MiB of system cache. Locality does not forbid 256, and it does not forbid 512 (176 KiB per core). Cache is not the deciding factor.

**Crypto is not the bottleneck at all.** At an assumed 2.0 GB/s AEAD rate per core `(unverified)`:

```
1373 B / 2.0e9 B/s = 0.6865 µs per packet of crypto CPU
Total at 1,000 Mbps: 125,000,000 / 2.0e9 = 0.0625 core = 6.25% of one core
```

Even at a pessimistic 500 MB/s software ChaCha20 path, 1,000 Mbps costs 25% of one core. The 8-worker pool is sized far beyond the work.

**Fan-out signaling is comparable to the crypto itself.** Using 1.5 µs per worker wakeup `(unverified)`:

```
Batch 32:  8 workers * 1.5 µs + (4 pkts * 0.6865) = 12.000 + 2.746 = 14.746 µs
           14.746 / 32  = 0.4608 µs per packet
Batch 256: 8 workers * 1.5 µs + (32 pkts * 0.6865) = 12.000 + 21.968 = 33.968 µs
           33.968 / 256 = 0.1327 µs per packet
Option 1 advantage over Option 2: 0.4608 - 0.1327 = 0.3281 µs per packet
```

0.3281 µs is 1.25% of the 26.1552 µs budget. Option 1 buys that by editing a constant that `Session.DeliverBatch`, `RecvBatch`, and the `CryptoPool` job array all read, which is the downlink path (see 3.4). The risk-adjusted answer is Option 2.

**Crypto head-of-line latency, for completeness.** A 256-packet crypto batch adds `32 * 0.6865 = 21.97 µs` before the first datagram of that batch can leave, against `4 * 0.6865 = 2.75 µs` at batch 32. The 19.2 µs delta is 0.030% of a 65 ms RTT and does not affect throughput. Latency is not a reason to reject Option 1; the freeze invariant is.

**One fact to verify before finalizing.** The arithmetic above assumes `PollBatchInto` performs the AEAD fan-out, which packet section 2.3 implies (`CryptoPool.jobs [MaxBatchSize]cryptoJob`, and `PollBatchInto` rejecting `len(slots) > MaxBatchSize`). If encryption instead happens upstream and `PollBatchInto` is a pure ring drain, Option 2 carries no crypto penalty at all, Option 1's 0.3281 µs advantage vanishes entirely, and the case for Option 2 becomes unconditional. Either way Option 2 wins; the verification only determines the margin.

**Accumulation loop cost.** Option 2 calls `PollBatchInto` 8 times per 256 packets. A poll is a ring drain with no syscall, at roughly 0.5 µs of fixed cost `(unverified)`: `8 * 0.5 / 256 = 0.0156 µs per packet`. Negligible.

#### Diff 3.3.1: `winn3/driver/loop.go`, accumulate whole crypto batches into one SendBatch

Anchored to the exact block quoted in packet section 2.1.

```diff
--- a/winn3/driver/loop.go
+++ b/winn3/driver/loop.go
@@
 	if batchCarrier, isBatch := c.(carrier.BatchCarrier); isBatch {
-		batchLimit := len(l.writeBatchMsgs)
-		if batchLimit > session.MaxBatchSize {
-			batchLimit = session.MaxBatchSize
-		}
+		// Accumulate whole crypto batches of session.MaxBatchSize into one
+		// outer transmit vector of at most core.MaxTxBatchSize. The crypto
+		// batch width is unchanged, so core.MaxBatchSize and every receive-side
+		// reader of it are untouched. At the 91,041.51 pps wire-speed target
+		// this drops sendmmsg calls from 2,845.05/s to 355.63/s.
+		txLimit := len(l.writeBatchMsgs)
+		if txLimit > core.MaxTxBatchSize {
+			txLimit = core.MaxTxBatchSize
+		}
+		count := 0
+		var pollErr error
+		for count < txLimit {
+			window := txLimit - count
+			if window > session.MaxBatchSize {
+				window = session.MaxBatchSize
+			}
+			got, err := l.sess.PollBatchInto(l.writeBatchBufs[count : count+window])
+			if err != nil {
+				pollErr = err
+				break
+			}
+			if got == 0 {
+				// Outbox drained.
+				break
+			}
+			count += got
+			if got < window {
+				// Short poll means the outbox is drained; another poll would
+				// only burn a ring traversal.
+				break
+			}
+		}
@@
-		count, pollErr := l.sess.PollBatchInto(l.writeBatchBufs[:batchLimit])
@@
 		n, err := batchCarrier.SendBatch(cctx, l.writeBatchMsgs[sent:count])
 	}
```

The `PollBatchInto` call is moved into the accumulation loop, so the original standalone call line is deleted. `count` and `pollErr` are now declared before the loop rather than by the `:=` on the deleted line; every downstream reader of both names is unchanged, including the `l.writeBatchMsgs[sent:count]` resume path.

#### Diff 3.3.2 (CONTINGENT): iovec length resynchronization

Apply this hunk **only if** `l.writeBatchMsgs[i]`'s iovec length is not automatically derived from `len(l.writeBatchBufs[i])` at send time, that is, only if the previous single-poll code path contained an explicit length sync between the poll and the `SendBatch`. If such a sync already exists in the unquoted region, it must be moved inside the accumulation loop rather than duplicated. Insert immediately after `count += got`:

```diff
+			// Republish each slot's post-poll length into its iovec. The single
+			// poll this loop replaced covered slots [0:count]; the accumulation
+			// loop must cover [count-got:count] on each pass.
+			for i := count - got; i < count; i++ {
+				l.writeBatchMsgs[i].SetLen(len(l.writeBatchBufs[i]))
+			}
```

Substitute the carrier package's actual length setter for `SetLen`. If the packet's unquoted code sets `Iov.Len` directly, the body becomes `l.writeBatchMsgs[i].Iov.Base = &l.writeBatchBufs[i][0]; l.writeBatchMsgs[i].Iov.SetLen(len(l.writeBatchBufs[i]))`. This is the single point where the diff depends on code the packet did not quote, and it must be resolved by reading `loop.go` before the change is merged. A missed length sync here sends stale-length datagrams, which is a silent corruption bug, not a crash.

### 3.4 OI-4: downlink freeze, and how it is guaranteed rather than asserted

**Question 1: do the proposed changes touch the downlink?**

Option 1 of OI-3 does. `core.MaxBatchSize` is read by `Session.DeliverBatch` (receive), by `RecvBatch` slot sizing, and by `CryptoPool.jobs [MaxBatchSize]cryptoJob` plus `queue chan int`. If a single `CryptoPool` serves both encrypt and decrypt, changing the constant changes the decrypt fan-out granularity and the receive slot array sizing. Both are downlink datapath and downlink buffer allocation, which Rounds 35 and 38 froze. Option 1 therefore violates the invariant directly, and that is the primary reason for the OI-3 vote.

Option 2 plus diffs 3.1.1 through 3.3.2 do not. Every edit lands in one of three places: a new constant that no receive-path file reads, the transmit branch of `loop.drain`, or the `toEngine` uplink path. `RecvBatch`, `outboundPump`, `pumpOutboundBatch`, `fromEngine`, and `deliverReceiveBatch` receive zero characters of diff.

**Question 2: how is this guaranteed?** Three enforceable conditions, not assertions.

- **Distinct symbol, not a changed value**: `core.MaxBatchSize` keeps its value of 32 byte for byte. The transmit width lives in the new `core.MaxTxBatchSize`. A reviewer verifies the invariant with `git diff --stat` on the receive-path files rather than by reasoning about call graphs. Add a CI check: `git diff --exit-code -- winn3/core/session_recv.go winn3/session/batch.go cmd/winn-datapath/*outbound*` for the merge, adjusted to the repository's actual receive-path file set.
- **Dedicated transmit buffer ring, no shared pool**: if `toEngine` and `fromEngine` draw packet buffers from a common pool, holding uplink packets for longer inside a 512-slot descriptor changes pool residency and therefore changes downlink allocation behavior, which is an indirect breach of the frozen buffer allocations. The `engineBatch` ring in 3.2.1 allocates its own `[][]byte` backing at construction and never returns those slices to a shared pool. Verify before merge that `offerBatch`'s callers and `readBatchInto`'s consumers do not share an allocator with the downlink path. If they do, the uplink must be given its own allocator as part of this change.
- **Queue depth reduction is uplink only**: the 65,536 to 4,096 change in 3.2.2 applies to `toEngine`. `fromEngine`'s depth is untouched, so downlink queueing latency and downlink drop behavior are unchanged.

**Naming hazard worth recording in the treaty.** The packet's suggested type name `InboundBatchCarrier` describes the uplink (inbound to the Go engine, outbound on the wire). Under the Round 35 and 38 vocabulary, "inbound" reads as downlink. The diff above uses `engineBatch` and `toEngine` to avoid encoding that collision into a type name that a future reader will mistake for downlink machinery.

**Validation gate before the freeze is certified intact.** Rerun the downlink leg first, in isolation, before any uplink measurement, and require the downlink sustained and instantaneous figures to land within measurement noise of the Run 15 baselines of 663 Mbps sustained and 1,432.3 Mbps peak. A downlink regression of any size invalidates the merge regardless of the uplink result.

---

## 4. Closing position

The round's four items are individually correct engineering and collectively insufficient. Widening the transmit batch, batching the `toEngine` channel, and decoupling the crypto batch from the carrier batch together retire 0.252 µs per packet in the expected case and 4.253 µs in the optimistic case, against a 15.1712 µs requirement. That is 424.0 Mbps expected and 501.5 Mbps optimistic, against a 1,000 Mbps target.

The 15.17 µs is not in `sendmmsg`, because closing it there would require a 554.83 µs syscall. It is not in the Go channel, because a 65,536-deep queue that never dropped a packet was never the constraint. It is not in AEAD, because 1,000 Mbps costs 6.25% of one core at 2 GB/s. By the packet's own account the 420.2 Mbps analytical bound came from the Kotlin reader and pump, and the measured 420.0 Mbps matching it to 0.05% is the strongest single piece of evidence in the packet about where the remaining time lives. Instrument that layer, exclude the 104.1 KiB per-stream congestion window hypothesis with `tcp_info` capture, and plan on three flow-hashed uplink lanes. Merge the diffs above because they are cheap, correct, and reduce 720 ms of standing queue to 45 ms, not because they will produce wire speed.
