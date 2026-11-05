# Turn 2 Verdict: claude-opus5

# ROUND 43 TURN 2: CLAUDE OPUS 5 (extra-high)

## 0. Evidence basis for this turn

No tools again. Every diff below is anchored to source text quoted inside the packet: the `loop.go` drain block and the `NewRawBatchConn` allocation list come from Gemini's Turn 1 removal lines, the `winn3_frame_device.go` bodies come from Gemini's Turn 1 removal lines, and the lifecycle facts come from Arbiter ground truth item 3. Where a hunk still depends on text nobody quoted, it is marked CONTINGENT with the exact predicate. Constants I could not verify carry `(unverified)` inline and no vote turns on any of them.

---

## 1. Steelman of the opposing podiums

**Gemini on `sendMu` hold time.** The strongest thing in Gemini's submission is not the cache argument, it is the lock argument, and I underweighted it in Turn 1. My Turn 1 treated OI-3 Option 1 as costing only a freeze violation for a 0.3281 µs/packet gain. Gemini identified a second cost I did not price: `Session.SealBatchInto` holds `s.sendMu` across the whole crypto window, so Option 1 converts a 4.8 µs lock hold into a 30.4 µs hold, and every keepalive, control frame, and rekey transition queues behind it. That is an argument Option 2 wins on its own merits rather than winning on treaty compliance alone, and it repairs the weakest part of my Turn 1 OI-3 reasoning. Steelmanned fully: a datapath whose urgent control frames can be stalled 30 µs by bulk traffic has a rekey timing hazard that no throughput number compensates for.

**Gemini on cache locality.** The direction is right even though the number is wrong (section 3.1). Per worker, batch 256 grows the crypto working set from roughly 11 KiB to roughly 88 KiB, which is the difference between trivially L1-resident and marginal. Gemini reached the right verdict by the wrong path.

**Sol Pro on descriptor lifecycle.** Sol Pro's refusal to emit an OI-2 patch from the excerpt was correct discipline, and Arbiter ground truth item 3 proved it by disclosing the one fact that decides the design: `flushInboundBatch` executes `*batch = (*batch)[:0]` after `offerBatch` returns. That statement, read against the ground truth sentence "the producer never reuses the packet buffers or slice headers," is internally contradictory. Truncating to `[:0]` and appending again overwrites the same backing array. The packet buffers are not reused (each comes fresh from `allocPacket`), but the slice header array is. So Sol Pro's falsification test, run the producer with immediate reuse under the race detector and watch descriptors corrupt, would have fired against any design that enqueues `*batch` by reference. My Turn 1 `engineBatch` design happened to survive because it copies headers, but I did not name the producer reuse as the reason it must copy. Sol Pro did. His eight-clause ownership contract is the correct acceptance criterion for OI-2 and I adopt clauses 1 through 4, 6, and 8 verbatim in substance below.

**Sol Pro on artifact-scoped deployment.** `winn3/driver/loop.go` is shared code. Shipping the transmit widening in a gateway binary widens gateway-to-client transmit batches, which is a downlink behavior change even with `RecvBatch` untouched. I missed this in Turn 1; my OI-4 analysis checked the call graph and not the deployment target. Adopted.

**Gemini on drop granularity.** Gemini's per-packet tail drop beats my 512-packet descriptor drop on exactly the axis I flagged myself and then under-weighted: a contiguous discard of up to 512 datagrams lands mostly inside a small number of inner TCP flows and collapses their congestion windows, where scattered single losses are absorbed by SACK. This is the reason I abandon my own `engineBatch` descriptor design in favor of his lock-batched ring (section 4).

---

## 2. Position changes

Four changes, three of them against my own Turn 1 text.

- **OI-1 vote flips from DISAGREE to AGREE.** My DISAGREE attached to a sufficiency claim, not to Proposal A. Arbiter ground truth item 2 accepts the 554.83 µs refutation and restates OI-1 as a required foundational prerequisite with a stated benefit of about 0.27 µs/packet. Voting DISAGREE against text that now asserts exactly what my arithmetic proved would be a DISAGREE without a falsifiable reason attached, which under 13.2.3 counts as AGREE anyway. I vote it honestly.
- **Diff 3.1.3 from my Turn 1 is withdrawn in full.** It predicted a short `sendmmsg` at roughly 81 messages if `SO_SNDBUF` carried `wmem_default`. Arbiter ground truth item 2 verifies `carrier/udp_socket_buffers.go` sets `DefaultUDPSocketBufferBytes = 8 MiB` and that `getsockopt(SO_SNDBUF)` confirms the grant. 8,388,608 / 2,608 = 3,216 datagrams of skb headroom against a 256-datagram vector, so the prediction is retired and the `setTxSockBuf` helper would be duplicate code.
- **The transmit constant moves out of `core/batch.go` into the driver package.** Sol Pro's constraint ("no changes should be made to `core/batch.go` or `session/batch.go`") is the stronger form of OI-4 and two of three podiums placed the constant package-local. `git diff --exit-code -- winn3/core/batch.go winn3/session/batch.go` returning clean is a better invariant proof than any reasoning about who reads `MaxTxBatchSize`. My Turn 1 diff 3.1.1 is superseded by diff A1 below.
- **My CONTINGENT diff 3.3.2 (iovec length resync) is withdrawn.** Gemini's quoted original shows the population loop is `l.writeBatchMsgs[k].Payload = l.writeBatchBufs[k]; l.writeBatchMsgs[k].N = len(l.writeBatchBufs[k])` running over `[0:count]` after the poll. Leaving that loop untouched and letting `count` be the accumulated total covers every slot with no resync hunk and no silent stale-length hazard.

Unchanged: the composite arithmetic in section 1.6 of my Turn 1, the OI-3 Option 2 vote, and the OI-5 motion.

---

## 3. First-principles arithmetic, rechecked

### 3.0 Base figures (recomputed independently of Turn 1)

```
1373 / 125,000,000       = 1.09840e-5 s   = 10.98400 us/packet at 1,000 Mbps
125,000,000 / 1373       = 91,041.515 pps
419,954,688 / 8          = 52,494,336 B/s
52,494,336 / 1373        = 38,233.311 pps
1373 / 52,494,336        = 2.615520e-5 s  = 26.15520 us/packet observed
26.15520 - 10.98400      = 15.17120 us/packet residual
91,041.515 / 38,233.311  = 2.38116x required speedup
```

Sol Pro's independent derivation matches mine to six significant figures on all five lines. Two podiums have now rechecked this from first principles, satisfying 13.3.

### 3.1 Repair of Gemini's cache arithmetic

Gemini compares a 351.5 KiB aggregate batch working set against a 128 KiB L1 data cache `(unverified: published Oryon prime L1D is 96 KiB by my recollection, also unverified)`. That comparison mixes an aggregate against a per-core resource. The crypto pool fans out across 8 workers, so per worker:

```
Batch  32:  32/8 =  4 pkts  *1373 =  5,492 B in  + ~5,556 B out = 10.79 KiB
Batch 256: 256/8 = 32 pkts  *1373 = 43,936 B in  + ~44,448 B out = 86.51 KiB
Growth factor: 8.0x
```

86.51 KiB against a 96 KiB L1D is marginal; against 128 KiB it is resident. Gemini's conclusion holds at the per-core level but only barely, and it holds for a reason his number does not state. The OI-3 vote does not rest on this, so the unverified cache size is not escalated under 13.3.

### 3.2 Repair of Gemini's `sendMu` arithmetic

Gemini reports 4.8 µs held at batch 32 and 30.4 µs at batch 256, a 6.33x ratio. Per-packet crypto cost is invariant under batch width, so strict linear scaling of his own baseline gives:

```
4.8 * (256/32) = 38.4 us
```

His 30.4 µs implicitly amortizes roughly 8 µs of fan-out across the wider batch. Either figure supports the verdict, and the linear one supports it harder: the true Option 1 penalty is between 6.3x and 8.0x, not below 6.3x. Under Option 2 the hold stays at 4.8 µs and, because the accumulation loop issues eight sequential `PollBatchInto` calls, control frames get eight acquisition windows per 256 datagrams instead of one. Urgent-frame latency is held exactly at today's value rather than merely bounded.

### 3.3 Correction to Gemini's kernel transmit cost

Gemini computes total kernel socket transmit time as 355.631 calls/s times 18 µs = 6.40 ms/s, or 0.64% of one core, and derives an amortized 0.070 µs/packet for the entire kernel send. An 18 µs `sendmmsg` carrying 256 datagrams charges 0.070 µs of kernel work per 1400 B UDP datagram, which is below the cost of the checksum alone. Splitting the call into its fixed term `F` and its per-message term `M`, with `F` near 10 µs and `M` near 2 µs `(unverified)`:

```
Per call at B=256: 10 + 256*2       = 522 us
Total:             355.631 * 522 us = 185.6 ms/s = 18.56% of one 3.63 GHz core
```

That is 29x Gemini's figure. It does not change any vote, and it matters for one downstream reason only: the 3-lane sharding plan in my Turn 1 section 1.7 has to budget roughly 0.19 core for transmit kernel work at the target rate, which 3 lanes accommodate.

### 3.4 What OI-1 and OI-3 Option 2 are worth, restated for the record

```
F * (1/32 - 1/256) = F * 0.02734375
F = 10 us  ->  0.27344 us/packet retired  = 1.045% of the 26.15520 us budget
26.15520 - 0.27344 = 25.88176 us  ->  10,984 / 25.88176 = 424.4 Mbps
```

Gemini's Turn 1 projection of 1,080 to 1,220 Mbps for the full item set is not ratified. Reaching 1,080 Mbps requires 10.17 µs/packet, which is 15.98 µs below the observed figure, and the sum of every optimistic bound across OI-1, OI-2, and OI-3 is 4.253 µs. The projection exceeds its own optimistic ceiling by 3.8x. Section 7 converts this into a falsifiable prediction that settles the disagreement by measurement rather than by argument.

### 3.5 Socket buffer, recomputed against Arbiter ground truth

```
skb truesize per 1500 B linear UDP datagram (unverified): ~2,608 B
256 * 2,608      =   667,648 B = 652.0 KiB
667,648 / 8,388,608 = 7.96% of the verified 8 MiB grant
8,388,608 / 2,608   = 3,216 datagrams of headroom
```

The Arbiter states 7.8%; the difference is rounding on the truesize constant. Either figure clears the batch by a factor above 12.

---

## 4. Answer to the Arbiter's OI-2 staging question

Ship `loop.go` first, in its own commit and its own measurement run, and land the frame device ring second in the same round rather than in a later one.

The reason is attribution, not risk aversion. OI-1A plus OI-3 Option 2 is worth 0.27344 µs/packet by the arithmetic above; OI-2 is worth 0.1147 µs/packet expected with a 3.98 µs optimistic bound. Those two bounds differ by a factor of 35, and the only way to learn which regime the channel is actually in is to measure a run where it is the sole variable. Landing both together produces one delta that neither model can be tested against.

There is a second reason specific to this round. `loop.go` plus the carrier transmit arrays touch two files, no lifecycle contract, and no ownership handoff. The frame device ring rewrites `offer`, `offerBatch`, `ReadPacket`, `ReadBatch`, and `Close`, and it changes what happens to queued packets at close. Those belong to separate review surfaces.

Stage A and Stage B diffs are both ratified and both complete below. Nothing is deferred out of the round.

---

## 5. Final convergence votes

**OI-1: AGREE.** Proposal A at 256 datagrams is adopted as a prerequisite and not as a sufficiency claim, on the Arbiter's ground truth item 2 text; Proposal B is rejected because `UDP_SEGMENT` requires a uniform segment size across the coalesced buffer, which independently sealed ChaCha20-Poly1305 outer frames of varying length do not provide, and because the roughly 64 KiB GSO payload ceiling admits `floor(65,507 / 1,373) = 47` segments, so it cannot express a 256-datagram vector at all.

**OI-2: AGREE.** Ratified as Gemini's lock-batched ring with the four corrections in section 6.3, on the arithmetic that one mutex acquisition per 512-packet batch replaces 512 channel lock pairs, retiring 1.9922 channel operations per packet, and on the ownership ground that `flushInboundBatch` executes `*batch = (*batch)[:0]` and re-appends into the same backing array, so the ring must copy slice headers under the lock and no design enqueuing `*batch` by reference is admissible.

**OI-3: AGREE (Option 2).** `session.MaxBatchSize` stays at 32 byte for byte; the transmit vector is accumulated from eight sequential polls. Falsifiable by `strace -c -e trace=sendmmsg`: `SendBatch` call rate must fall from 2,845.047/s to 355.631/s at the 1,000 Mbps target proxy while `PollBatchInto` call rate stays at 2,845.047/s, and `sendMu` hold time measured by mutex profile must stay at the pre-change value rather than rising by the 6.3x to 8.0x factor Option 1 would produce.

**OI-4: AGREE.** Falsifiable by source hash: `winn3/core/batch.go`, `winn3/session/batch.go`, `tun.pumpOutboundBatch`, and the Kotlin `outboundPump` must hash identical before and after, `git diff --exit-code` on those paths must return 0, and the downlink leg rerun in isolation must land within measurement noise of 663 Mbps sustained and 1,432.3 Mbps peak before the uplink leg is run at all.

**Diff-level correction recorded against a peer hunk, not a vote.** Gemini's Turn 1 `udp_batch_unix.go` diff widens `c.rhs`, `c.riovs`, and `c.rnames` from 32 to 256. Those are the `recvmmsg` receive arrays. Widening them is a downlink buffer allocation change and Rounds 35 and 38 bar it. Ratified diff A3 widens the five transmit arrays only and leaves the three receive arrays at 32. This is detectable by `git diff` on three field names and must be checked before merge.

**OI-5 carried forward, not blocking.** The item set OI-1 through OI-4 tops out at 501.5 Mbps optimistic and 424.4 Mbps expected against a 1,000 Mbps target. I re-move an item covering instrumentation of the Kotlin TUN reader and LocalSocket transfer, per-stream `tcp_info` capture to exclude the 104.1 KiB per-stream congestion window hypothesis, and flow-hashed 3-lane uplink sharding with its gateway demux contract change. This motion does not condition any of the four votes above.

---

## 6. Final ratified diffs

### 6.1 Stage A, diff A1: `winn_protocol_experimental/winn3/driver/loop.go`, transmit constants

Place the const block with the package's existing top-level constants.

```diff
--- a/winn_protocol_experimental/winn3/driver/loop.go
+++ b/winn_protocol_experimental/winn3/driver/loop.go
@@
+// txCarrierBatchSize bounds one outer sendmmsg vector on the transmit path
+// only. It is deliberately package-local to the driver: session.MaxBatchSize
+// keeps its value of 32, core/batch.go and session/batch.go take zero diff, and
+// the Round 35 and Round 38 downlink freeze is provable by
+// `git diff --exit-code -- winn3/core/batch.go winn3/session/batch.go` rather
+// than by reasoning about who reads a new exported constant.
+//
+// At the 91,041.515 pps wire-speed target this moves SendBatch calls from
+// 2,845.047/s to 355.631/s, an 87.5 percent reduction in call count, worth
+// about 0.273 us per packet at a 10 us fixed per-call cost. It does not touch
+// the per-message kernel term, which is why it is a prerequisite and not a
+// sufficient change.
+const txCarrierBatchSize = 256
+
+// txBatchesPerSend is the number of whole crypto batches accumulated into one
+// SendBatch call: 256 / 32 = 8.
+const txBatchesPerSend = txCarrierBatchSize / session.MaxBatchSize
+
+// Compile-time guard: txCarrierBatchSize must stay an exact multiple of
+// session.MaxBatchSize so the accumulation loop never leaves a partial crypto
+// window. A non-zero remainder makes the array length non-zero and this
+// assignment fails to typecheck.
+var _ [0]struct{} = [txCarrierBatchSize % session.MaxBatchSize]struct{}{}
```

### 6.2 Stage A, diff A2: `loop.go`, buffer sizing and the accumulation loop

Anchored to Gemini's quoted original at the `newLoop` allocation site and at `func (l *Loop) drain`.

```diff
@@ func newLoop(cfg Config, build func(session.Config) (*session.Driver, error)) (*Loop, error) {
-	const batchCapacity = session.MaxBatchSize
-	writeBatchBufs := make([][]byte, batchCapacity)
-	writeBatchMsgs := make([]carrier.BatchMsg, batchCapacity)
+	const batchCapacity = txCarrierBatchSize
+	writeBatchBufs := make([][]byte, batchCapacity)
+	writeBatchMsgs := make([]carrier.BatchMsg, batchCapacity)
```

```diff
@@ func (l *Loop) drain(ctx context.Context) (int, error) {
 		if batchCarrier, isBatch := c.(carrier.BatchCarrier); isBatch {
 			batchLimit := len(l.writeBatchMsgs)
-			if batchLimit > session.MaxBatchSize {
-				batchLimit = session.MaxBatchSize
-			}
+			if batchLimit > txCarrierBatchSize {
+				batchLimit = txCarrierBatchSize
+			}
 			if remaining := maxDrainPerWake - i; remaining < batchLimit {
 				batchLimit = remaining
 			}
-			count, pollErr := l.sess.PollBatchInto(l.writeBatchBufs[:batchLimit])
-			l.syncGate()
+			// Accumulate whole crypto windows of session.MaxBatchSize into one
+			// outer transmit vector of at most txCarrierBatchSize. Each poll
+			// takes and releases sendMu on its own, so the lock hold stays at
+			// the current 32-packet duration and control frames keep eight
+			// acquisition windows per 256 datagrams. syncGate stays paired 1:1
+			// with PollBatchInto so gate observation cadence is unchanged.
+			count := 0
+			var pollErr error
+			for count < batchLimit {
+				window := batchLimit - count
+				if window > session.MaxBatchSize {
+					window = session.MaxBatchSize
+				}
+				got, err := l.sess.PollBatchInto(l.writeBatchBufs[count : count+window])
+				l.syncGate()
+				count += got
+				if err != nil {
+					pollErr = err
+					break
+				}
+				if got < window {
+					// Short poll means the outbox is drained. Another poll
+					// would only burn a ring traversal.
+					break
+				}
+			}
 			if count == 0 {
 				return moved, pollErr
 			}
 			for k := 0; k < count; k++ {
 				l.writeBatchMsgs[k].Payload = l.writeBatchBufs[k]
 				l.writeBatchMsgs[k].N = len(l.writeBatchBufs[k])
 			}
```

Everything below that population loop is untouched: the `for sent < count` resume loop, `l.c.messagesSent.Add`, `l.c.sendFailed.Add(uint64(count - sent))`, `moved += sent`, the `pollErr` and `sendErr` returns, `i += count`, and `if count < batchLimit { return moved, nil }`. Their semantics carry over exactly, because `count` is still the number of contiguous filled slots starting at index 0 and `count < batchLimit` still means the outbox drained.

Two behavior notes for the reviewer. The population loop now covers all accumulated slots because it iterates `[0:count]`, which is why no iovec resync hunk exists anywhere in this diff. And `l.syncGate()` was moved inside the accumulation loop rather than left after it: leaving it outside would cut gate observation frequency by up to 8x, which is a behavior change nobody voted on.

### 6.3 Stage A, diff A3: `winn_protocol_experimental/winn3/carrier/udp_batch_unix.go`, transmit arrays only

Without this hunk, diff A2 is inert or worse: the carrier's internal `hs`, `iovs`, `names`, `addrs`, and `addrIPs` arrays are 32 long, so a 256-message vector either truncates silently or indexes out of range.

```diff
--- a/winn_protocol_experimental/winn3/carrier/udp_batch_unix.go
+++ b/winn_protocol_experimental/winn3/carrier/udp_batch_unix.go
@@
+// txBatchSlots sizes the transmit-side mmsghdr, iovec, and address arrays. It
+// must be at least driver.txCarrierBatchSize or SendBatch truncates every
+// oversized vector. The value is duplicated rather than imported because
+// driver/loop.go builds on platforms this file excludes; the clamp in
+// SendBatch makes any future drift a short send that the caller's sent:count
+// resume loop already handles, never a panic.
+//
+// The receive-side arrays rhs, riovs, and rnames deliberately keep their
+// 32-slot width. Widening them is a downlink buffer allocation change and is
+// barred by the Round 35 and Round 38 freeze.
+const txBatchSlots = 256
+
@@ func NewRawBatchConn(conn *net.UDPConn) (*RawBatchConn, error) {
-		hs:      make([]mmsghdr, 32),
-		iovs:    make([]iovec, 32),
-		names:   make([][32]byte, 32),
-		addrs:   make([]net.UDPAddr, 32),
-		addrIPs: make([][16]byte, 32),
+		hs:      make([]mmsghdr, txBatchSlots),
+		iovs:    make([]iovec, txBatchSlots),
+		names:   make([][32]byte, txBatchSlots),
+		addrs:   make([]net.UDPAddr, txBatchSlots),
+		addrIPs: make([][16]byte, txBatchSlots),
 	}
```

`c.rhs`, `c.riovs`, and `c.rnames` keep `make(..., 32)` and take zero diff.

Memory delta, exact for the four sized types plus the address arrays `(unverified on mmsghdr padding)`:

```
224 extra slots * (64 mmsghdr + 16 iovec + 32 name + 16 addrIP) = 224 * 128 = 28,672 B
plus 224 * sizeof(net.UDPAddr) (24 B slice header + 16 B string header + 4 B port + pad)
Total carrier-side increase: well under 64 KiB
```

### 6.4 Stage A, diff A4 (CONTINGENT): `SendBatch` clamp

Apply only if `SendBatch` does not already bound its message count by `len(c.hs)`. Insert as the first statement of the method body, before any indexing of `c.hs`, `c.iovs`, or `c.names`.

```diff
@@ func (c *RawBatchConn) SendBatch(ctx context.Context, msgs []carrier.BatchMsg) (int, error) {
+	// Bound the vector by the preallocated header arrays. A caller that hands
+	// in more than txBatchSlots messages gets a short send and resumes from
+	// its own sent:count offset; without this the widened driver vector would
+	// index past len(c.hs).
+	if len(msgs) > len(c.hs) {
+		msgs = msgs[:len(c.hs)]
+	}
```

The predicate is verifiable by reading the first ten lines of `SendBatch`. If a clamp is already present, skip this hunk entirely.

### 6.5 Stage B, diff B1: `cmd/winn-datapath/winn3_frame_device.go`, ring state

Ratifies Gemini's structure. Corrections against his Turn 1 text: `sync.Cond` is constructed with `sync.NewCond` rather than assigned by field, `Signal` becomes `Broadcast` because the packet does not establish that exactly one goroutine consumes `toEngine`, the ring reuses `winn3FrameQueueDepth` so `toHost` and every downlink depth stays untouched, and a high water mark is added so the depth reduction from 65,536 can be argued from occupancy data in a later round instead of guessed at now.

```diff
--- a/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
+++ b/winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go
@@ type winn3FrameDevice struct {
-	toEngine chan []byte
+	// toEngine is a slice-header ring guarded by one mutex. offerBatch takes
+	// the lock once per batch instead of once per packet, which is the entire
+	// point: at a 512-packet arrival quantum this replaces 512 channel lock
+	// pairs with one acquire and one broadcast.
+	//
+	// The ring copies slice headers under the lock. flushInboundBatch runs
+	// *batch = (*batch)[:0] and re-appends into the same backing array after
+	// offerBatch returns, so any design that enqueued the caller's [][]byte by
+	// reference would hand the consumer headers the producer is about to
+	// overwrite. Packet buffers themselves come fresh from allocPacket and are
+	// owned by the device from enqueue until recycle.
+	toEngineMu    sync.Mutex
+	toEngineCond  *sync.Cond
+	toEngineRing  [][]byte
+	toEngineHead  int
+	toEngineCount int
+	toEngineHigh  atomic.Uint64
 	toHost   chan []byte
@@ func newWinn3FrameDevice(mtu int) (*winn3FrameDevice, error) {
-	return &winn3FrameDevice{
-		mtu:      mtu,
-		toEngine: make(chan []byte, winn3FrameQueueDepth),
-		toHost:   make(chan []byte, winn3FrameQueueDepth),
-		closed:   make(chan struct{}),
-	}, nil
+	dev := &winn3FrameDevice{
+		mtu:          mtu,
+		toEngineRing: make([][]byte, winn3FrameQueueDepth),
+		toHost:       make(chan []byte, winn3FrameQueueDepth),
+		closed:       make(chan struct{}),
+	}
+	dev.toEngineCond = sync.NewCond(&dev.toEngineMu)
+	return dev, nil
 }
+
+// pushEngineLocked enqueues one packet. The caller holds toEngineMu. A full
+// ring drops and recycles that one packet, preserving the current per-packet
+// tail-drop granularity: a contiguous multi-hundred-packet discard would land
+// inside a small number of inner TCP flows and collapse their congestion
+// windows, where scattered single losses are absorbed by SACK.
+func (d *winn3FrameDevice) pushEngineLocked(pkt []byte) {
+	if d.toEngineCount >= len(d.toEngineRing) {
+		d.droppedToEngine.Add(1)
+		d.recycle(pkt)
+		return
+	}
+	slot := d.toEngineHead + d.toEngineCount
+	if slot >= len(d.toEngineRing) {
+		slot -= len(d.toEngineRing)
+	}
+	d.toEngineRing[slot] = pkt
+	d.toEngineCount++
+	if uint64(d.toEngineCount) > d.toEngineHigh.Load() {
+		d.toEngineHigh.Store(uint64(d.toEngineCount))
+	}
+}
+
+// popEngineLocked removes the head packet. The caller holds toEngineMu and
+// must have verified toEngineCount > 0. The slot is cleared so a stale header
+// cannot pin a recycled buffer.
+func (d *winn3FrameDevice) popEngineLocked() []byte {
+	pkt := d.toEngineRing[d.toEngineHead]
+	d.toEngineRing[d.toEngineHead] = nil
+	d.toEngineHead++
+	if d.toEngineHead == len(d.toEngineRing) {
+		d.toEngineHead = 0
+	}
+	d.toEngineCount--
+	return pkt
+}
+
+// engineQueueHighWater reports peak toEngine occupancy. Run 15 recorded zero
+// drops against a 65,536-slot queue, which proves the queue never filled and
+// says nothing about how full it got. 65,536 packets is 719.85 ms of standing
+// queue at 91,041.515 pps and 1,714.2 ms at the Run 15 rate, so the depth is a
+// latency defect if occupancy is ever material. Measure first, then cut the
+// depth in a later round with data attached.
+func (d *winn3FrameDevice) engineQueueHighWater() uint64 {
+	return d.toEngineHigh.Load()
+}
```

CONTINGENT on two facts the packet did not quote. If `sync` is not already imported, add it. If `droppedToEngine` is a bare `uint64` rather than an `atomic.Uint64`, replace `d.droppedToEngine.Add(1)` with `atomic.AddUint64(&d.droppedToEngine, 1)` in `pushEngineLocked`; Gemini's Turn 1 text uses the method form and `&d.droppedToEngine` is passed to `push` elsewhere, which is consistent with `*atomic.Uint64`.

Memory: the ring is `65,536 * 24 B = 1,572,864 B` of slice headers, which is what `chan []byte` of the same depth already allocated. No net change.

### 6.6 Stage B, diff B2: producers

```diff
@@ func (d *winn3FrameDevice) offer(packet []byte) error {
 	copy(cp, packet)
-	d.push(d.toEngine, cp, &d.droppedToEngine, false)
+	d.toEngineMu.Lock()
+	d.pushEngineLocked(cp)
+	d.toEngineCond.Broadcast()
+	d.toEngineMu.Unlock()
 	return nil
 }
@@ func (d *winn3FrameDevice) offerBatch(packets [][]byte) error {
 	if d.isClosed() {
 		for _, pkt := range packets {
 			d.recycle(pkt)
 		}
 		return errWinn3DeviceClosed
 	}
+	d.toEngineMu.Lock()
 	for _, pkt := range packets {
 		if len(pkt) > d.mtu {
 			d.oversize.Add(1)
 			d.recycle(pkt)
 			continue
 		}
-		d.push(d.toEngine, pkt, &d.droppedToEngine, false)
+		d.pushEngineLocked(pkt)
 	}
+	d.toEngineCond.Broadcast()
+	d.toEngineMu.Unlock()
 	return nil
 }
```

`offer` pushes directly rather than wrapping its packet in a one-element `[][]byte`, which would heap-allocate on every scalar-path packet. `d.push` itself stays in the file: the `toHost` downlink path still uses it and must not be touched.

### 6.7 Stage B, diff B3: consumers

```diff
@@ func (d *winn3FrameDevice) ReadPacket(buf []byte) (int, error) {
-	var pkt []byte
-	select {
-	case pkt = <-d.toEngine:
-	case <-d.closed:
-		select {
-		case pkt = <-d.toEngine:
-		default:
-			return 0, errWinn3DeviceClosed
-		}
-	}
+	d.toEngineMu.Lock()
+	for d.toEngineCount == 0 {
+		if d.isClosed() {
+			d.toEngineMu.Unlock()
+			return 0, errWinn3DeviceClosed
+		}
+		d.toEngineCond.Wait()
+	}
+	pkt := d.popEngineLocked()
+	d.toEngineMu.Unlock()
 	defer d.recycle(pkt)
 	n := copy(buf, pkt)
```

```diff
@@ func (d *winn3FrameDevice) ReadBatch(bufs [][]byte) ([]int, error) {
 	if len(bufs) == 0 {
 		return nil, nil
 	}
-	var first []byte
-	select {
-	case pkt, ok := <-d.toEngine:
-		if !ok {
-			return nil, errWinn3DeviceClosed
-		}
-		first = pkt
-	case <-d.closed:
-		select {
-		case pkt := <-d.toEngine:
-			first = pkt
-		default:
-			return nil, errWinn3DeviceClosed
-		}
-	}
-
-	lengths := d.readLengths[:0]
-	if cap(lengths) < len(bufs) {
-		lengths = make([]int, 0, len(bufs))
-	}
-	if len(first) > len(bufs[0]) {
-		d.oversize.Add(1)
-		d.recycle(first)
-		return nil, errors.New("read batch buffer too small for first packet")
-	}
-	n0 := copy(bufs[0], first)
-	d.recycle(first)
-	lengths = append(lengths, n0)
-
-	for len(lengths) < len(bufs) {
-		select {
-		case pkt, ok := <-d.toEngine:
-			if !ok {
-				d.readLengths = lengths
-				return lengths, nil
-			}
-			idx := len(lengths)
-			if len(pkt) > len(bufs[idx]) {
-				d.oversize.Add(1)
-				d.recycle(pkt)
-				continue
-			}
-			ni := copy(bufs[idx], pkt)
-			d.recycle(pkt)
-			lengths = append(lengths, ni)
-		default:
-			if len(d.toEngine) > 0 && len(lengths) < len(bufs) {
-				continue
-			}
-			d.readLengths = lengths
-			return lengths, nil
-		}
-	}
-	d.readLengths = lengths
-	return lengths, nil
+	// One lock acquire drains up to len(bufs) packets. The old code took a
+	// channel receive per packet plus a non-blocking retry on the drain path.
+	for {
+		d.toEngineMu.Lock()
+		for d.toEngineCount == 0 {
+			if d.isClosed() {
+				d.toEngineMu.Unlock()
+				return nil, errWinn3DeviceClosed
+			}
+			d.toEngineCond.Wait()
+		}
+		lengths := d.readLengths[:0]
+		if cap(lengths) < len(bufs) {
+			lengths = make([]int, 0, len(bufs))
+		}
+		for len(lengths) < len(bufs) && d.toEngineCount > 0 {
+			pkt := d.popEngineLocked()
+			idx := len(lengths)
+			if len(pkt) > len(bufs[idx]) {
+				d.oversize.Add(1)
+				d.recycle(pkt)
+				continue
+			}
+			n := copy(bufs[idx], pkt)
+			d.recycle(pkt)
+			lengths = append(lengths, n)
+		}
+		d.toEngineMu.Unlock()
+		if len(lengths) == 0 {
+			// Every packet dequeued this pass was oversize. Do not hand the
+			// engine an empty batch with a nil error; wait for real data.
+			continue
+		}
+		d.readLengths = lengths
+		return lengths, nil
+	}
 }
```

One deliberate semantic change, recorded rather than buried: the old code returned `errors.New("read batch buffer too small for first packet")` when the first packet was oversize while skipping oversize packets at every other index. The ratified loop skips uniformly. An oversize packet is already counted in `d.oversize` and returning an error to the engine for a condition that is silently skipped one index later is an asymmetry no caller can depend on deliberately. If `errors` becomes unused in the file after this hunk, drop it from the import block.

### 6.8 Stage B, diff B4: `Close`

```diff
@@ func (d *winn3FrameDevice) Close() error {
 	if d.once.CompareAndSwap(false, true) {
 		close(d.closed)
+		d.toEngineMu.Lock()
+		for d.toEngineCount > 0 {
+			d.recycle(d.popEngineLocked())
+		}
+		d.toEngineCond.Broadcast()
+		d.toEngineMu.Unlock()
 	}
```

Behavior change to record: queued uplink packets are recycled at close instead of remaining readable by a post-close drain. The engine is going away at that point and recycling returns the buffers to `packetPool` rather than stranding up to 65,536 of them until GC.

Wakeup safety: `sync.Cond.Wait` registers on the notify list before releasing the lock, so a `Broadcast` issued by `Close` after it acquires the lock cannot be lost by a waiter that was mid-`Wait`. Every waiter rechecks `toEngineCount` and `isClosed` under the lock after waking, so there is no path that returns a packet from an emptied ring.

---

## 7. Falsifiable predictions and the measurement gate

Ordering is fixed. Downlink leg first, in isolation, before any uplink measurement. If downlink sustained or peak moves outside measurement noise against 663 Mbps and 1,432.3 Mbps, the merge is rejected regardless of the uplink result.

- **Prediction 1, Stage A alone.** Uplink lands between 420 and 435 Mbps. Derivation: `10,984 / (26.15520 - 0.27344) = 424.4 Mbps`, with the range covering unmodeled poll-loop savings. Falsified if the measured figure reaches 500 Mbps, in which case my fixed-syscall-cost model is wrong, Gemini's projection gains support, and I withdraw the OI-5 escalation.
- **Prediction 2, syscall counting.** `strace -c -f -e trace=sendmmsg` over a fixed-duration run shows call count falling by a factor near 8 while bytes sent stay flat. Falsified if the ratio is below 4, which would mean the outbox rarely holds 256 datagrams and the accumulation loop is exiting early on short polls.
- **Prediction 3, Stage B alone.** Incremental gain over Stage A is under 0.5 Mbps in the expected regime. Falsified if Stage B alone adds more than 40 Mbps, which would put channel operations in the 1 to 2 µs contended regime and would make the OI-2 optimistic bound of 3.98 µs/packet the operative number.
- **Prediction 4, occupancy.** `engineQueueHighWater` stays below 4,096 across an 8 second run. If it does, the depth cut from 65,536 to 4,096 is safe and should be proposed in a later round with the measurement attached. If it exceeds 4,096, my Turn 1 bufferbloat argument was overstated and the depth stays.
- **Prediction 5, freeze proof.** `git diff --exit-code` returns 0 on `winn3/core/batch.go`, `winn3/session/batch.go`, the Kotlin `outboundPump`, `tun.pumpOutboundBatch`, and the `rhs`, `riovs`, `rnames` fields of `udp_batch_unix.go`. Any non-zero exit falsifies the OI-4 vote and blocks the merge.

Deployment scope, adopted from Sol Pro: the Stage A commit ships in the Android datapath artifact only. The gateway keeps the current `loop.go` until gateway downlink latency is measured separately, because the widened transmit vector in shared driver code would otherwise widen gateway-to-client batches and change downlink behavior without any receive-side diff.
