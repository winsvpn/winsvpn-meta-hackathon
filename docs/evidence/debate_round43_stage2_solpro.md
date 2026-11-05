# Turn 2 Verdict: solpro

1. **Peer steelman**

   Opus 5's syscall arithmetic is decisive on sufficiency. Let `h` be the fixed cost of one `sendmmsg` invocation:

   ```text
   Saving per packet
     = h x (1/32 - 1/256)
     = h x 7/256
     = 0.02734375h us
   ```

   Retiring the full 15.171203 us gap through batching alone would require:

   ```text
   h = 15.171203 / 0.02734375
     = 554.833 us per invocation
   ```

   At the deliberately generous `h = 10 us`, the saving is only:

   ```text
   10 x 7/256 = 0.2734375 us per packet
   ```

   Therefore the change is foundational, not sufficient for 1,000 Mbps.

   Sol Pro's descriptor lifecycle objections were also valid given the Turn 1 evidence. A batched queue must define ownership transfer, packet-credit accounting, partial acceptance, exact drop accounting, descriptor clearing, close synchronization, and packet recycling. The Arbiter now establishes that packet buffers and slice headers are not reused after enqueue and that the consumer recycles each packet after copying. That removes the original ownership ambiguity, but it does not by itself make the submitted ring implementation ready.

   Gemini's cache and lock analysis is the strongest reason to preserve the crypto batch at 32. Correcting the binary-unit labels:

   ```text
   32 x 1373 = 43,936 B = 42.906 KiB input
   Input plus output       = 85.812 KiB

   256 x 1373 = 351,488 B = 343.250 KiB input
   Input plus output        = 686.500 KiB
   ```

   The 32-packet input and output working set fits nominally in a 128 KiB L1 data cache before metadata. The 256-packet input alone does not. More importantly, the measured `sendMu` hold time rises from 4.8 us to 30.4 us, a 6.33x increase.

2. **Position changes**

   OI-1 changes from DISAGREE to AGREE. My Turn 1 disagreement addressed the unsupported claim that send widening could close the entire throughput gap. The Arbiter has clarified that Proposal A is a required prerequisite rather than a complete remedy.

   OI-2 remains DISAGREE for inclusion in this patch, but my reason changes. The producer ownership objection is withdrawn. The remaining objection is the close race in the submitted ring implementation and the absence of evidence that this queue is currently constraining throughput.

   OI-3 remains AGREE with Option 2.

   OI-4 remains AGREE, with Android-client artifact scoping because `driver/loop.go` is otherwise generic code.

3. **Independent item analysis**

   OI-1:

   At the target packet proxy:

   ```text
   Packet rate at 1,000 Mbps = 125,000,000 / 1373
                             = 91,041.515 packets/s

   Batch 32 SendBatch rate   = 91,041.515 / 32
                             = 2,845.047 calls/s

   Batch 256 SendBatch rate  = 91,041.515 / 256
                             = 355.631 calls/s

   Reduction                 = 2,489.416 calls/s
                             = 87.5 percent
   ```

   With the accepted 10 us fixed-cost upper model, the 0.2734375 us per-packet saving changes the observed proxy interval from 26.155203 us to 25.881766 us. That predicts roughly 424.4 Mbps, not 1,000 Mbps. The patch must not be credited with more without measurement.

   The verified 8 MiB `SO_SNDBUF` is sufficient. Using the accepted 652 KiB skb-memory estimate:

   ```text
   652 KiB / 8192 KiB = 7.96 percent
   ```

   Normal full-batch transmission therefore has ample socket capacity. Existing partial-send handling remains necessary for signals, transient kernel behavior, and future platforms.

   Proposal B remains rejected. `UDP_SEGMENT` permits uniform segments with only the final segment shorter. WinnV3 can produce arbitrary outer-message lengths because each datagram has independent framing, ciphertext, and authentication data. PMTU failure also applies to the complete super-datagram, and Android driver support is inconsistent.

   OI-2:

   At 1,000 Mbps, the current scalar channel executes approximately:

   ```text
   2 x 91,041.515 = 182,083.030 channel operations/s
   ```

   A 512-packet forward descriptor channel would execute:

   ```text
   2 x 91,041.515 / 512 = 355.631 operations/s
   ```

   If descriptor return uses another channel, the total becomes 711.262 operations/s. A mutex ring has a different operation count, so synchronization savings must be measured for the selected design rather than inferred from descriptor count alone.

   Run 15 recorded zero `droppedToEngine` packets. That does not prove channel operations are free, but it shows the queue had enough capacity and that a queue-capacity refactor is not required before testing the carrier change.

   The submitted Gemini ring also has a concrete close race:

   1. `offerBatch` observes `isClosed() == false`.
   2. `Close` closes the device, locks the ring, drains it, and unlocks.
   3. `offerBatch` then acquires the mutex and enqueues without checking closed state again.
   4. No consumer remains, leaving a packet in the ring and outside the pool.

   Any future ring patch must recheck closure while holding the same mutex used by `Close`, preserve packet-count credits, accept only the fitting prefix, account every rejected packet, clear descriptor slots, and copy or detach queued pointers before releasing the lock.

   The carrier aggregation patch should therefore be measured first. OI-2 should proceed only if runtime tracing or a channel microbenchmark attributes material CPU time to `toEngine`.

   OI-3:

   Option 2 preserves these boundaries:

   ```text
   Crypto dispatch width     = 32
   Maximum carrier width     = 256
   Polls per full carrier send = 256 / 32 = 8
   ```

   Polling is nonblocking. If the outbox has 33 datagrams, the loop receives 32 and then 1, immediately stops on the short poll, and sends all 33. It never waits for the carrier batch to fill.

   This preserves the measured 4.8 us `sendMu` hold time and avoids the 30.4 us hold associated with a 256-packet crypto operation. It also leaves `jobs [MaxBatchSize]cryptoJob`, session receive limits, and downlink batch structures unchanged.

   OI-4:

   The ratified patch changes only `winn3/driver/loop.go`. It does not alter:

   ```text
   core.MaxBatchSize
   core/batch.go
   session/batch.go
   tun.pumpOutboundBatch
   Kotlin outboundPump
   downlink allocation sizes
   downlink measurement formulas
   ```

   The build containing this change must initially be deployed only in the Android client artifact. Deploying generic transmit-loop changes on the gateway would constitute a separate downlink behavior change even though receive-side source remains unchanged.

4. **Final votes**

   * OI-1: AGREE: with Proposal A because a full 256-packet outbox produces one initial `SendBatch` invocation instead of eight, which is falsifiable with a counting carrier and syscall histogram.

   * OI-2: DISAGREE: include the descriptor ring in this patch because the submitted implementation can enqueue after `Close` has drained the ring, which is falsifiable by asserting `toEngineCount == 0` after concurrent `offerBatch` and `Close`.

   * OI-3: AGREE: Option 2 keeps the measured crypto-side `sendMu` hold at 4.8 us rather than 30.4 us while still reducing full-load carrier calls to 355.631 per second.

   * OI-4: AGREE: the final source diff changes only `winn3/driver/loop.go`, so hashes of every frozen downlink source and measurement file remain byte-for-byte identical.

5. **Ratified surgical diff**

   This patch implements OI-1 Proposal A and OI-3 Option 2. It deliberately contains no OI-2 channel change and no change to `core.MaxBatchSize`.

```diff
diff --git a/winn3/driver/loop.go b/winn3/driver/loop.go
--- a/winn3/driver/loop.go
+++ b/winn3/driver/loop.go
@@
 import (
 	"context"
 	"errors"
 	"io"
@@
 )
 
+const (
+	// carrierBatchCapacity is transmit-only. Crypto and receive batches remain
+	// bounded by session.MaxBatchSize, currently 32.
+	carrierBatchCapacity = 256
+
+	// txBatchesPerSend is 8 while session.MaxBatchSize remains 32.
+	txBatchesPerSend = carrierBatchCapacity / session.MaxBatchSize
+)
+
+// Require carrierBatchCapacity to be an exact multiple of the frozen session
+// batch size.
+var _ [0]struct{} = [carrierBatchCapacity % session.MaxBatchSize]struct{}{}
+
@@
-	const batchCapacity = session.MaxBatchSize
-	writeBatchBufs := make([][]byte, batchCapacity)
-	writeBatchMsgs := make([]carrier.BatchMsg, batchCapacity)
+	writeBatchBufs := make([][]byte, carrierBatchCapacity)
+	writeBatchMsgs := make([]carrier.BatchMsg, carrierBatchCapacity)
@@
 		if batchCarrier, isBatch := c.(carrier.BatchCarrier); isBatch {
 			batchLimit := len(l.writeBatchMsgs)
-			if batchLimit > session.MaxBatchSize {
-				batchLimit = session.MaxBatchSize
-			}
 			if remaining := maxDrainPerWake - i; remaining < batchLimit {
 				batchLimit = remaining
 			}
-			count, pollErr := l.sess.PollBatchInto(l.writeBatchBufs[:batchLimit])
+
+			count := 0
+			var pollErr error
+			for polls := 0; count < batchLimit && polls < txBatchesPerSend; polls++ {
+				pollLimit := count + session.MaxBatchSize
+				if pollLimit > batchLimit {
+					pollLimit = batchLimit
+				}
+				requested := pollLimit - count
+
+				n, err := l.sess.PollBatchInto(
+					l.writeBatchBufs[count:pollLimit],
+				)
+				count += n
+
+				if err != nil {
+					pollErr = err
+					break
+				}
+				if n < requested {
+					// PollBatchInto is nonblocking. A short result means the
+					// outbox is currently drained, so send immediately.
+					break
+				}
+			}
 			l.syncGate()
 			if count == 0 {
 				return moved, pollErr
 			}
 			for k := 0; k < count; k++ {
 				l.writeBatchMsgs[k].Payload = l.writeBatchBufs[k]
 				l.writeBatchMsgs[k].N = len(l.writeBatchBufs[k])
 			}
 			sent := 0
 			var sendErr error
 			for sent < count {
 				n, err := batchCarrier.SendBatch(cctx, l.writeBatchMsgs[sent:count])
 				if n < 0 || n > count-sent {
 					sendErr = io.ErrShortWrite
 					break
 				}
 				sent += n
 				if err != nil {
 					sendErr = err
 					break
 				}
 				if n == 0 {
 					sendErr = io.ErrShortWrite
 					break
 				}
 			}
 			l.c.messagesSent.Add(uint64(sent))
 			l.c.sendFailed.Add(uint64(count - sent))
 			moved += sent
 			if pollErr != nil {
 				return moved, pollErr
 			}
 			if sendErr != nil {
 				if errors.Is(sendErr, carrier.ErrPathMTUReduced) {
 					l.setCarrierErr(sendErr)
 					return moved, sendErr
 				}
 				if ctx.Err() != nil {
 					return moved, ctx.Err()
 				}
 				return moved, nil
 			}
 			i += count
 			if count < batchLimit {
 				return moved, nil
 			}
 			continue
 		}
```

   No changes are required in `udp_batch_unix.go` under the Arbiter's verified premise that `BatchCarrier.SendBatch` consumes the complete caller-provided slice and that the socket receives the full 8 MiB send buffer.

6. **Acceptance checks**

   Before throughput testing, add or run tests covering:

   * Empty outbox: zero `SendBatch` calls.
   * 31 datagrams: one poll and one 31-message send.
   * 32 datagrams: one full poll, one empty nonblocking poll, and one 32-message send.
   * 33 datagrams: two polls and one 33-message send.
   * 256 datagrams: eight polls and one 256-message send.
   * 257 datagrams: one 256-message send followed by one 1-message send when the wake budget permits.
   * Partial carrier writes: returned prefixes are not resent, and all remaining messages are retried.
   * Poll error after a nonzero count: already-polled datagrams are sent before the poll error is returned.
   * `getsockopt(SO_SNDBUF)`: remains 8 MiB on the S26 Ultra.
   * Source freeze: `git diff --name-only` reports only `winn3/driver/loop.go` for this ratified patch.
   * Runtime result: the full-outbox `SendBatch` histogram moves from predominantly 32 to predominantly 256 without any increase in send failures or PMTU errors.

The expected result is an 87.5 percent reduction in full-load carrier syscall count and approximately 0.27 us per packet of fixed-cost retirement. Reaching 1,000 Mbps still requires profiling the remaining approximately 14.90 us per-packet gap.
