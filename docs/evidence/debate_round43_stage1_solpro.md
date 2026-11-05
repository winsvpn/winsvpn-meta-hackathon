# Turn 1 Submission: solpro

1. **Arithmetic**

Using the delivered byte count rather than the rounded 420 Mbps figure:

```text
Delivered bytes             = 419,954,688 B
Duration                    = 8 s
Delivered byte rate         = 52,494,336 B/s
Delivered bit rate          = 419,954,688 bit/s
Full-size packet proxy      = 52,494,336 / 1,373
                             = 38,233.311 packets/s
Equivalent packet interval  = 1 / 38,233.311
                             = 26.155203 us
```

For 1,000 Mbps:

```text
Required byte rate          = 125,000,000 B/s
Required packet rate        = 125,000,000 / 1,373
                             = 91,041.515 packets/s
Required packet interval    = 1,373 / 125,000,000
                             = 10.984000 us
Required retirement         = 26.155203 - 10.984000
                             = 15.171203 us/packet
```

These packet rates are payload-derived proxies. They are exact only if every delivered packet carries 1,373 bytes of measured payload. HTTP and TCP framing usually make the real outer datagram rate higher.

Batch rates at the 1,000 Mbps proxy are:

| Batch size | Calls/s | Traffic represented per full batch |
|---:|---:|---:|
| 32 | 2,845.047 | 351.488 us |
| 64 | 1,422.524 | 702.976 us |
| 128 | 711.262 | 1.405952 ms |
| 256 | 355.631 | 2.811904 ms |
| 512 | 177.815 | 5.623808 ms |

At the measured rate, the equivalent call rates are 1,194.791/s for 32, 149.349/s for 256, and 74.674/s for 512.

The rate reduction alone cannot establish a throughput result. If `h` is the fixed cost in microseconds of one `sendmmsg` invocation, changing 32 to 256 saves:

```text
Delta_send = h * (1/32 - 1/256)
           = h * 7/256
           = 0.02734375h us/packet
```

For this change alone to retire 15.171203 us:

```text
h >= 15.171203 * 256 / 7
h >= 554.833 us per sendmmsg call
```

For 512:

```text
Delta_send = h * (1/32 - 1/512)
           = h * 15/512

h >= 15.171203 * 512 / 15
h >= 517.844 us per sendmmsg call
```

Unless profiling shows roughly 0.5 ms of fixed scheduler and syscall overhead per existing call, send widening alone cannot explain a 2.38x throughput increase.

The resulting throughput model is:

```text
Tnew_us = 26.155203 - Delta_us
Mbps    = 10,984 / Tnew_us
```

The implementation must produce `Tnew_us < 10.984` to exceed 1,000 Mbps.

2. **OI-1: Outer UDP transmit batching and GSO**

Proposal A is a valid optimization, but 256 is preferable to 512 for the first deployment.

A 256-entry carrier aggregation reduces `sendmmsg` calls by 87.5 percent relative to 32. Moving from 256 to 512 saves only another 177.816 calls/s at the target rate, while doubling descriptor memory and increasing the maximum represented traffic interval from 2.812 ms to 5.624 ms.

The session must still be polled in chunks of 32. Therefore:

```text
Session PollBatchInto calls at target = 91,041.515 / 32
                                      = 2,845.047/s

Carrier SendBatch calls at target     = 91,041.515 / 256
                                      = 355.631/s
```

The proposal reduces carrier calls. It does not reduce crypto-pool dispatches or `PollBatchInto` calls unless `core.MaxBatchSize` also changes.

Proposal B should not be introduced in this round:

* One `UDP_SEGMENT` super-packet is bounded by the roughly 64 KiB UDP/GSO payload ceiling.
* Even with zero protocol overhead, `floor(65,507 / 1,373) = 47` segments. Actual encrypted outer packets reduce that number.
* Segment sizes must be uniform except for the final segment.
* Variable tunnel framing, partial packets, PMTU transitions, and kernel feature probing add failure modes.
* It cannot combine 256 or 512 MTU-sized datagrams into one UDP super-packet.

Memory arithmetic on arm64 is:

```text
Go []byte header          = 24 bytes
Linux iovec               = 16 bytes
Linux mmsghdr             = 64 bytes
```

For arrays of slice headers, `mmsghdr`, and one `iovec` per packet:

```text
Per entry known metadata  = 24 + 64 + 16
                          = 104 bytes

256 entries               = 26,624 bytes
512 entries               = 53,248 bytes
```

Relative to 32 entries:

```text
256 increment             = (256 - 32) * 104
                          = 23,296 bytes

512 increment             = (512 - 32) * 104
                          = 49,920 bytes
```

This excludes `carrier.BatchMsg`, any `ipv4.Message` array, control buffers, socket addresses, and packet storage. Their exact sizes cannot be verified from the docket because their definitions are absent. For an actual `carrier.BatchMsg` size of `S`, the Go-side array cost is exactly:

```text
256 * S bytes
512 * S bytes
```

If packet buffers have capacity `C`, packet storage is exactly `256C` or `512C`.

For an upper packet-buffer example of 1,500 bytes:

```text
256 buffers = 384,000 bytes
512 buffers = 768,000 bytes
```

`wmem_max` does not account for userspace descriptor arrays. It limits kernel socket memory. An 8 MiB limit nominally exceeds one 512-packet batch, but it does not guarantee acceptance because socket accounting includes skb overhead and already queued packets. Correctness still depends on partial-send and `EAGAIN` handling. The existing `sent:count` loop appears intended for that requirement.

Recommended surgical diff:

```diff
diff --git a/winn3/driver/loop.go b/winn3/driver/loop.go
index 0000000..1111111 100644
--- a/winn3/driver/loop.go
+++ b/winn3/driver/loop.go
@@
 package driver
 
+const txCarrierBatchSize = 256
+
@@
-	batchCapacity := session.MaxBatchSize
+	batchCapacity := txCarrierBatchSize
 	writeBatchBufs := make([][]byte, batchCapacity)
 	writeBatchMsgs := make([]carrier.BatchMsg, batchCapacity)
@@
 	if batchCarrier, isBatch := c.(carrier.BatchCarrier); isBatch {
 		batchLimit := len(l.writeBatchMsgs)
-		if batchLimit > session.MaxBatchSize {
-			batchLimit = session.MaxBatchSize
+		if batchLimit > txCarrierBatchSize {
+			batchLimit = txCarrierBatchSize
 		}
-		count, pollErr := l.sess.PollBatchInto(l.writeBatchBufs[:batchLimit])
+		count := 0
+		var pollErr error
+		for count < batchLimit {
+			pollLimit := count + session.MaxBatchSize
+			if pollLimit > batchLimit {
+				pollLimit = batchLimit
+			}
+
+			requested := pollLimit - count
+			n, err := l.sess.PollBatchInto(
+				l.writeBatchBufs[count:pollLimit],
+			)
+			count += n
+
+			if err != nil {
+				pollErr = err
+				break
+			}
+			if n < requested {
+				break
+			}
+		}
 		// Existing pollErr handling remains unchanged.
 		// Existing message population remains unchanged.
 		// Existing partial SendBatch loop remains unchanged.
 		n, err := batchCarrier.SendBatch(
 			cctx,
 			l.writeBatchMsgs[sent:count],
 		)
```

The three comment lines shown in the context are not new executable code and should remain the existing code in the file. No change is required in `udp_batch_unix.go` if it already passes the complete input slice to `sendmmsg`. Any internal 32-entry truncation there must be removed before this patch has effect.

Vote OI-1:

`DISAGREE: send widening alone can retire the required 15.171203 us only if the fixed cost of each current sendmmsg call is at least 554.833 us for a 256-entry batch, and no measurement in the docket establishes that threshold.`

3. **OI-2: Inbound batch carrier channel**

The operation-count argument is valid, but an exact CPU-time claim is not derivable from operation counts.

At the target packet rate, the scalar channel performs approximately:

```text
Channel sends and receives = 2 * 91,041.515
                           = 182,083.030 operations/s
```

With full 512-packet descriptors:

```text
Batch descriptors/s        = 91,041.515 / 512
                           = 177.815

Channel operations/s       = 2 * 177.815
                           = 355.631
```

With 256-packet descriptors, it is 711.262 channel operations/s. The docket's 356 figure therefore corresponds to 512 packets, not 256.

If one scalar channel operation costs `q` microseconds, 512 batching saves:

```text
Delta_channel = 2q * (1 - 1/512)
              = 1.99609375q us/packet
```

For channel batching alone to retire 15.171203 us:

```text
q >= 15.171203 / 1.99609375
q >= 7.600 us per scalar channel operation
```

That is testable with `runtime/trace`, mutex profiles, block profiles, and a packet-channel microbenchmark. It cannot be asserted from throughput telemetry.

The required ownership contract is:

1. The LocalSocket reader owns every packet buffer and the batch slice before enqueue.
2. A successful enqueue transfers ownership of all accepted packet buffers to `winn3FrameDevice`.
3. The producer must not reuse either the packet storage or the slice-header array after transfer.
4. The consumer clears each descriptor slot before recycling the descriptor.
5. Descriptor recycling is safe after the final slot is extracted. Packet-buffer recycling is not safe until the engine exposes a release callback or copies the packet.
6. Queue credits are counted in packets, not descriptors.
7. Credits are released when a packet leaves the queue for the engine.
8. If only part of a batch fits, the accepted prefix is enqueued and the rejected suffix increments `droppedToEngine` by the exact rejected packet count.
9. If the descriptor channel send fails after credit reservation, all reserved credits are returned before recording drops.

A plain `chan [][]byte` does not encode this contract. It is unsafe if the LocalSocket parser reuses its slice-header array after `offerBatch` returns.

No compile-correct diff can be produced from the supplied excerpt because the following required definitions are absent:

* The `winn3FrameDevice` field declaration.
* The constructor and channel initialization.
* The consumer method that currently receives from `toEngine`.
* The concrete type and update API of `droppedToEngine`.
* The current ownership and release behavior of packet buffers.
* Whether more than one goroutine consumes `toEngine`.

Changing only the shown `offerBatch` method would either fail to compile or introduce an ownership race. The exact patch requires the complete file and its consumer interface.

Vote OI-2:

`DISAGREE: the supplied proposal does not define whether the producer reuses the [][]byte header or packet storage after offerBatch returns, so a direct chan [][]byte replacement can be falsified by running with immediate producer reuse under the race detector and observing corrupted packet descriptors.`

4. **OI-3: Crypto batch size versus carrier batch size**

Option 2 is the cleaner boundary.

`core.MaxBatchSize` controls cryptographic work and session API bounds. Carrier aggregation controls syscall amortization. They do not need the same constant.

With eight crypto workers:

```text
32-packet crypto batch   = 4 packets per worker
64-packet crypto batch   = 8 packets per worker
128-packet crypto batch  = 16 packets per worker
256-packet crypto batch  = 32 packets per worker
```

A 32-packet batch already exposes four independent packet operations per worker. Increasing it does not create additional hardware workers. It mainly amortizes queue setup while increasing queue residence, shared working set, and tail latency.

Approximate packet-data working sets, excluding tags, headers, jobs, and destination buffers:

| Batch | Input bytes at 1,373 B | Input plus equal-sized output |
|---:|---:|---:|
| 32 | 43,936 | 87,872 |
| 64 | 87,872 | 175,744 |
| 128 | 175,744 | 351,488 |
| 256 | 351,488 | 702,976 |
| 512 | 702,976 | 1,405,952 |

A 256-packet crypto operation therefore moves roughly 703 KiB before counting metadata and AEAD expansion. This is materially less cache-local than the existing 32-packet operation.

For the `queue chan int`, arm64 stores an 8-byte integer per buffered element:

```text
32 entries                = 256 bytes of element storage
256 entries               = 2,048 bytes
Increment                  = 1,792 bytes
```

For `jobs [MaxBatchSize]cryptoJob`, if `sizeof(cryptoJob) = J`:

```text
32 entries                = 32J
256 entries               = 256J
Increment                  = 224J
```

The exact `J` cannot be calculated without the omitted `cryptoJob` definition.

Option 2 gives:

* Eight nonblocking 32-packet polls to assemble at most 256 packets.
* One carrier `SendBatch` call.
* No change to cryptographic worker count.
* No change to `Session.DeliverBatch` limits.
* No change to the global meaning of `core.MaxBatchSize`.
* No increase in receive-side batch bounds.

The OI-1 diff implements this option. No changes should be made to `core/batch.go` or `session/batch.go`.

Vote OI-3:

`AGREE: Option 2 keeps every PollBatchInto call at the existing verified limit of 32 while reducing full-load SendBatch calls from 2,845.047/s to 355.631/s, which is directly falsifiable through syscall counting.`

5. **OI-4: Downlink freeze invariant**

The proposed Option 2 change touches only the driver transmit drain:

```text
Session outbox
    -> PollBatchInto in chunks of 32
    -> aggregate up to 256
    -> SendBatch
```

It does not require changes to:

* `RecvBatch`
* `DeliverBatch`
* `outboundPump`
* `pumpOutboundBatch`
* Android downlink buffer allocation
* Downlink byte accounting
* Downlink timing mathematics
* `core.MaxBatchSize`

Changing `core.MaxBatchSize` would not satisfy the strongest interpretation of the freeze because the same constant bounds both transmission and session batch APIs. Keeping it at 32 avoids that coupling.

The guarantee should be enforced by release scope:

1. Deploy the driver aggregation change only in the Android datapath artifact during the first experiment.
2. Do not deploy the same commit to the gateway until gateway downlink latency is tested.
3. Require an unchanged source hash for Android `outboundPump`, `pumpOutboundBatch`, and measurement files.
4. Compare downlink allocation counts with `testing.AllocsPerRun`.
5. Compare downlink packet and byte totals for identical replay input.
6. Compare `RecvBatch` invocation counts and batch-size histograms before and after.
7. Reject the release if downlink throughput, drop counters, or allocation counts differ outside the predeclared measurement tolerance.

Although the client receive path remains untouched, `winn3/driver/loop.go` is generic code. Deploying the changed binary on the gateway could widen gateway-to-client outer transmission batches. That would be a downlink behavior change even though `RecvBatch` is unchanged. Artifact-scoped deployment is therefore necessary for a literal 100 percent freeze.

Vote OI-4:

`AGREE: keeping core.MaxBatchSize at 32 and changing only the Android client's transmit drain leaves every named downlink receive function and allocation site byte-for-byte unchanged, which is falsifiable by source hashes and replay allocation tests.`

6. **Gateway assessment**

The evidence does not establish that the client is the sole active bottleneck.

At the measured payload proxy, a scalar gateway loop executes approximately 38,233 UDP reads/s. At the target it must execute at least 91,042 reads/s, and likely more after accounting for partial TCP packets and tunnel overhead.

Zero drops at 420 Mbps proves correctness at that load. It does not establish spare capacity at 1,000 Mbps.

The gateway must be measured for:

* Per-core utilization and run-queue delay.
* `SO_RXQ_OVFL`.
* UDP receive-queue occupancy.
* `perf` samples in `ReadFromUDPAddrPort`, `deliverSessionDatagram`, channel operations, AEAD, and TUN writes.
* Inbox depth and packet residence time.
* TUN write blocking time.
* Scalar read syscall rate.
* Whether production traffic actually enters `splitUDP.pumpBatch` or the scalar `server.readLoopEntered` path.

The scalar server read path and scalar inbox delivery are credible next bottlenecks once the client transmits above 420 Mbps. They should not be changed under the downlink freeze until client-side profiling demonstrates that the client reaches the gateway ingress limit.

7. **Adjudication summary**

| Item | Vote | Decision |
|---|---|---|
| OI-1 | DISAGREE | Merge a 256-entry carrier aggregator as an optimization, but do not claim it is sufficient for 1,000 Mbps. Do not add UDP GSO. |
| OI-2 | DISAGREE | The optimization is directionally useful, but the supplied source does not define a safe ownership and credit lifecycle. |
| OI-3 | AGREE | Keep crypto batches at 32 and aggregate up to eight polls into one 256-entry carrier send. |
| OI-4 | AGREE | Freeze all receive-side and measurement code, and deploy the transmit change only in the Android client artifact. |
