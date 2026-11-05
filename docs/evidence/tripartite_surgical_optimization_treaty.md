# Winthos Tripartite Presidential Council Binding Treaty (v1.0)
## Multi-Gigabit Symmetrical Upload Optimization & End-to-End Vector Alignment

**Codified under Winthos Presidential Council Authority (September 2026)**

**Council Members**:
- **Supervisor & Orchestrator**: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking) -> AFFIRMATIVE
- **Podium 1**: GLM 5.3 Flash (Lead Datapath Architect, BaseTen fp8 Max Thinking) -> RATIFIED WITH AMENDMENTS
- **Podium 2**: GPT-5.6 Sol Pro (Principal Systems & Kernel Architect, OpenAI flex Extra High Thinking) -> RATIFIED WITH AMENDMENTS

**Result: 3-0 Unanimous Ratification on Codified Amendments.**

---

### 1. Mathematical Ground Truth & Root Cause Analysis

Telemetry on Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL) against local gateway `aicore` (192.168.4.36:9111) over 2000 Mbps symmetrical fiber:
- Download: 1,218 Mbps (Exceeded wire speed target).
- Upload: 117 Mbps (Run 1 baseline).
- Uplink packets: 425,857 packets over 217,026 outer messages = 1.96 packets per outer carrier message.
- At 117 Mbps and 1373-byte MTU, line rate is 10,648 pps = 5,432 messages per second, meaning 184 microseconds of serialized per-message overhead.
- To achieve 1,000+ Mbps upload, the message rate must reach 91,043 pps. With 64-packet carrier vectorization, message rate drops from 46,450 to ~1,422 messages per second, easily fitting within the hardware bandwidth envelope.

---

### 2. Codified Tripartite Technical Amendments

#### Amendment A: Per-Mini-Batch Concurrent Notification (`WinnV3AndroidTun.kt`)
1. In `runBurstReader`, maintain `miniBatchSize = 64`.
2. Move `notifyPending(generation)` to trigger immediately after each completed mini-batch enqueue outside the monitor lock. This unblocks the outbound pump concurrently while the reader continues draining subsequent packets.
3. Replace single-event drop reporting with packet-accurate accounting for every overflowed packet.
4. If drained is 0, execute `Thread.yield()` to prevent spinning.

#### Amendment B: Peek-Gated Frame Drain & Safe Shutdown (`datapath/duplex` & `cmd/winn-datapath/winn3_frame.go`)
1. Add `duplex.PayloadLength(hdr []byte) int` decoding `binary.LittleEndian.Uint32(hdr[8:12])`.
2. In `winn3FrameServer.serve`:
   - Inspect `bufInput.Buffered() < duplex.HeaderSize` and `bufInput.Peek(duplex.HeaderSize)`.
   - Compute `need := duplex.HeaderSize + duplex.PayloadLength(hdr)`.
   - Only invoke `reader.Read()` when `bufInput.Buffered() >= need` to guarantee zero-blocking userspace memory drain.
   - Surface all frame decode errors and guard both inner and outer loops with `s.closed.Load()`.

#### Amendment C: Retain 16-Slot Yield Budget & Bounds Check (`cmd/winn-datapath/winn3_frame_device.go`)
1. Maintain `const maxSpinSlots = 16`. Reject changing the yield threshold to 64: `i < 16` is a spin budget for a momentarily empty channel, not a batch size ceiling.
2. Add packet length validation against buffer capacity at slot 0 and throughout the loop to prevent memory corruption.
3. Retain zero-allocation `d.readLengths` scratch slice.

---

### 3. Binding Signatures & Ratification

```
SUPERVISOR: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED

PODIUM 1: GLM 5.3 Flash (BaseTen fp8, Max Thinking)
VOTE: AFFIRMATIVE (ON RATIFIED AMENDMENTS)
STATUS: RATIFIED & SIGNED

PODIUM 2: GPT-5.6 Sol Pro (OpenAI flex, Extra High Thinking)
VOTE: AFFIRMATIVE (ON RATIFIED AMENDMENTS)
STATUS: RATIFIED & SIGNED
```

---

### 4. Round 2 Codified Treaty (v2.0): Bounded Micro-Aggregation for Wire-Speed Carrier Saturation

**Empirical Diagnosis**:
- Post Round 1 speedtest: Download 1,225 Mbps (wire speed target reached), Upload 46.5 to 139 Mbps.
- Ratio: `tx_packets: 336,200`, `messages_sent: 151,173` = 2.22 packets per outer carrier message.
- Mechanism: In `winn3_frame_device.go:ReadBatch`, the non-blocking `default:` case with `runtime.Gosched()` yields for only ~1us. Because the TCP sender paces packets at 10 to 50us intervals, `ReadBatch` exits with only 1 or 2 packets. This fragments the outbound stream into single/dual packet outer UDP datagrams. At ~184us per-message serialization and Wi-Fi 7 airtime overhead, this physically caps throughput at ~140 Mbps.

**Tripartite Council Resolution**:
1. **Rejection of Option C (Kotlin)**: Unanimously rejected. Android lacks batched TUN read APIs; adding buffering in Kotlin would introduce IPC jitter and extra memory copies.
2. **Adoption of Option A (`cmd/winn-datapath/winn3_frame_device.go:ReadBatch`)**: Unanimously adopted.
   - `ReadBatch` is the earliest ingestion seam and isolates waiting to the dedicated outbound TUN pump goroutine.
   - The carrier loop, session ticks, rekeying, and inbound traffic remain completely unblocked.
3. **Micro-Aggregation Policy Constants**:
   - `readBatchMaxHold`: 1000 microseconds (1 millisecond backstop window).
   - `readBatchTargetBytes`: 32 KiB (32 << 10 bytes).
   - `readBatchMaxPackets`: 32 packets.
   - `readBatchLatencyCutoff`: 256 bytes (immediate zero-delay bypass for ICMP ping, TCP ACKs, and handshake control frames to preserve sub-15ms latency).
4. **Zero-Allocation Reusable Timer Architecture**:
   - Add `readBatchTimer *time.Timer` to `winn3FrameDevice`.
   - Implement `armTimer` and `stopTimer` helpers using `Stop()` / `Reset()` patterns to eliminate GC allocations on the hot path.
5. **Drain & Carrier Vectorization**:
   - Gathering 20 to 32 packets in `ReadBatch` allows `pumpOutboundBatch` to invoke `bSink.SendDataBatch` with full batches.
   - `Loop.drain` wakes once per batch, drains 20 to 32 packets via `PollBatchInto`, and transmits them in a single `sendmmsg` system call via `batchCarrier.SendBatch`.

```
ROUND 2 SUPERVISOR: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED

ROUND 2 PODIUM 1: GLM 5.3 Flash (BaseTen fp8, Max Thinking)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED

ROUND 2 PODIUM 2: GPT-5.6 Sol Pro (OpenAI flex, Extra High Thinking)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED
```

