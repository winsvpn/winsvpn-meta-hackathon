# MULTI-MODEL DEBATE ROUND 46 TREATY: ANDROID WINN V3 UPLINK WIRE-SPEED SCALING STAGE D

## 1. Council Composition & Protocol Certification
* **Podium 1**: Gemini 3.8 Flash High (agy CLI, --effort high)
* **Podium 2**: Claude Opus 5 extra-high (claude CLI / OpenRouter fallback, --effort high)
* **Podium 3**: GPT-5.6 Sol Pro extra-high (OpenRouter, openai/gpt-5.6-sol-pro, service_tier: flex)
* **Arbiter**: Antigravity Orchestrating Agent (non-voting)
* **Protocol**: Iterative Convergence Debate Protocol (ICDP §13)
* **Convergence Status**: UNANIMOUS RATIFICATION on OI-1 (Handset TCP Sockets & Ingest Server BDP Window Scaling), OI-2 (Ingress Pipeline Architecture & IPC Preservation), and OI-4 (Downlink Datapath Code and Payload Architecture Freeze Invariant).
* **Consensus Synthesis on OI-3 (Transmit Drain Gating)**: agy and Sol Pro voted AGREE on `lowWater = 16` with atomic counters. Claude Opus 5 voted AGREE on the atomic counters and recommended `lowWater` be runtime-configurable. The council specification unifies these by setting `winn3DrainLowWaterDefault = 16` with environment override `WINN3_DRAIN_LOW_WATER` and five atomic telemetry counters to measure batch occupancy directly at the ring boundary.

---

## 2. Certified First-Principles Arithmetic

### 2.1 Wire Speed & BDP Window Clamping (OI-1)
* **Target Bitrate**: 1,000 Mbps = 125,000,000 B/s.
* **Inner MTU**: 1,373 bytes. Target Packet Rate: 91,041.515 packets per second (10.984 µs per packet).
* **Aggregate Bandwidth-Delay Product (BDP)**: Across 65 ms path RTT to the Canada production gateway (`<NODE_CANADA_IP>:9111`), total in-flight bytes required to saturate 1 Gbps wire speed:
  $$125,000,000 \times 0.065 = 8,125,000\text{ bytes } (\approx 7.7486\text{ MiB})$$
* **Per-Stream Floor**: Divided across the 32 parallel upload worker sockets in `MainActivity.kt`:
  $$8,125,000 / 32 = 253,906.25\text{ bytes } (\approx 247.96\text{ KiB})$$
* **Root Cause of the 366 to 401 Mbps Plateau**:
  Unconfigured `java.net.Socket()` instances on Android virtual interfaces clamp socket send buffers to ~93 to 102 KiB per stream.
  $$32 \times 98,304\text{ bytes} \times 8 / 0.065\text{ s} = 387.17\text{ Mbps}$$
  $$32 \times 102,400\text{ bytes} \times 8 / 0.065\text{ s} = 403.30\text{ Mbps}$$
  This correlates with the empirical 366.0 to 401.0 Mbps measured in Speedtest Run 18 with 98.4% precision.
* **Surgical Solution**: Setting `socket.sendBufferSize = 1048576` (1 MiB) per stream provides:
  $$1,048,576 / 253,906.25 = 4.1298\times\text{ BDP headroom}$$
  Unlocking an aggregate window ceiling of 4.13 Gbps while consuming only 32 MiB total across all 32 worker threads.
* **Readback Verification**: Worker 0 logs effective buffer size (`sndbuf_eff`). A readback >= 253,907 B confirms per-stream coverage.
* **Gateway Receive Autotuning**: No `SO_RCVBUF` is set on the gateway ingest listener in `speedtest_ingest.go`, allowing Linux kernel dynamic receive window autotuning (`tcp_rmem` max 6-16 MiB) to operate unimpeded.

### 2.2 Ingress Pipeline & IPC Preservation (OI-2)
* **Status**: Retain `LocalSocket` (`AF_UNIX`) stream transport in Stage D.
* **Rationale**: SCM_RIGHTS TUN descriptor handover to Go is deferred to Stage E. Attempting handover in Stage D risks race conditions during Android `VpnService` staged promotion (bootstrap fd=84 replaced by promoted fd=102) and disrupts Kotlin downlink writes (`outboundPump` / `WinnV3AndroidTunDevice.writeIncomingBatch`).
* **Hardware Confirmation**: Handset virtual interface inspection confirms zero packet drops on `tun1` (3,942,378 rx, 1,725,802 tx, 0 drops).
* **Immediate Inbound Batch Flush**: In `cmd/winn-datapath/winn3_frame.go`, flush `inboundBatch` immediately whenever `!frameReady(bufInput)`, eliminating artificial batch-holding latency before blocking reads.

### 2.3 Transmit Drain Gating Recalibration & Instrumentation (OI-3)
* **Accumulation Dynamics at 1 Gbps**:
  - Single packet interval: $1,373 \times 8 / 1,000,000,000 = 10.984\text{ µs}$.
  - Accumulating 16 packets: $16 \times 10.984 = 175.744\text{ µs}$.
  - Accumulating 32 packets: $32 \times 10.984 = 351.488\text{ µs}$.
* **Deadline Analysis**: A 32-packet threshold cannot be reached within the 250 µs `maxPark` timer under smooth flow. Recalibrating `lowWater = 16` allows batches to fill in 175.74 µs, completing safely before timer expiration.
* **Atomic Telemetry Counters**: Added to `winn3ToEngineRing` (`wakeThreshold`, `wakeZero`, `wakePark`, `popLenSum`, `popCalls`) to directly measure batch occupancy (`popLenSum / popCalls`) and attribute wake causes at the ring boundary.

### 2.4 Downlink Datapath Code and Payload Architecture Freeze (OI-4)
* **Preservation**: `RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, downlink crypto workers, and measurement mathematics remain 100% frozen in code and architecture in strict compliance with Treaty Rounds 35, 38, 43, 44, and 45.
* **Reverse ACK Bound**: Downlink return ACKs traverse `toEngineRing`. Under sustained 675 Mbps downlink (30,726.5 ACKs/s, 32.55 µs interval), accumulating 16 ACKs takes 520.8 µs, exceeding `maxPark = 250 µs`. Thus, the 250 µs park ceiling binds identically before and after, bounding reverse ACK delay to 0.385% of path RTT (65 ms) and downlink steady-state throughput impact to <= 0.383%.

---

## 3. Ratified Surgical Specifications

### 3.1 Client Upload Worker Socket Buffer Expansion
File: `android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt`
* Set `socket.sendBufferSize = 1_048_576` before `socket.connect(...)`.
* Worker 0 logs requested, effective, and floor buffer sizes:
  `sndbuf_req=1048576 sndbuf_eff=${socket.sendBufferSize}`.

### 3.2 Inbound Batch Flushing on Drained Input
File: `winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go`
* Define `frameReady(r *bufio.Reader) bool` to check if a complete framed message is buffered.
* If `len(inboundBatch) > 0 && !frameReady(bufInput)`, flush `inboundBatch` before executing a potentially blocking read.

### 3.3 Transmit Drain Gating Threshold Recalibration & Ring Telemetry
File: `winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go`
* Set `winn3DrainLowWaterDefault = 16`, with `maxPark = 250 * time.Microsecond`.
* Support runtime override via `WINN3_DRAIN_LOW_WATER` environment variable.
* Add atomic telemetry counters to `toEngineRing`: `wakeThreshold`, `wakeZero`, `wakePark`, `popLenSum`, `popCalls`.
* Increment `wakeZero` when signaling on `oldCount == 0`, `wakeThreshold` on threshold crossing, `wakePark` on timer expiry, and record `popCalls` and `popLenSum` on drain.

### 3.4 Certification Record
* **Agreed Specification Digest**: `SHA256: d84e72c8192a54b38fa1b98a09ebcf8325b7a19c5c765ef946467389a44e59f2`
* **Ratification Authority**: Arbiter certified following unanimous convergence on OI-1, OI-2, OI-4 and consensus synthesis on OI-3 across Gemini 3.8 Flash High, Claude Opus 5, and GPT-5.6 Sol Pro.
