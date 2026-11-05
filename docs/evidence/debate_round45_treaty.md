# MULTI-MODEL DEBATE ROUND 45 TREATY: ANDROID WINN V3 UPLINK WIRE-SPEED SCALING STAGE C

## 1. Council Composition & Protocol Certification
* **Podium 1**: Gemini 3.8 Flash High (agy CLI, --effort high)
* **Podium 2**: Claude Opus 5 extra-high (claude CLI, --effort high)
* **Podium 3**: GPT-5.6 Sol Pro extra-high (OpenRouter, openai/gpt-5.6-sol-pro, service_tier: flex)
* **Arbiter**: Antigravity Orchestrating Agent (non-voting)
* **Protocol**: Iterative Convergence Debate Protocol (ICDP §13)
* **Convergence Status**: UNANIMOUS RATIFICATION on OI-1 (Transmit Coalescing Architecture & Layer Selection: Reject Mechanism A, Adopt Mechanism B UDP_SEGMENT paired with Transmit Drain Gating), OI-2 (Linux Kernel 6.12 Capability and Handset Safety), OI-3 (Gateway Demux Sizing and Zero-Truncation Invariant), and OI-4 (Downlink Freeze Invariant 100% Preservation).

---

## 2. Certified First-Principles Arithmetic

### 2.1 Wire Speed & S26 Ultra Telemetry Identities
* **Target Bitrate**: 1,000 Mbps = 125,000,000 B/s.
* **Inner MTU**: 1,373 bytes.
* **Target Packet Rate**: 125,000,000 / 1,373 = 91,041.515 packets per second.
* **Target Wall-Clock Budget**: 1 / 91,041.515 = 10.984000 µs per packet.
* **Run 17 Measured Uplink**: 426.0 Mbps sustained (~31,026 pps, 32.23 µs/packet). In-flight engine peak reached 872.7 to 883.3 Mbps (~64,000 pps, 15.6 µs/packet).
* **Downlink Symmetry Disproves Syscall Bottlenecks**: Run 17 recorded 686.0 Mbps sustained with an in-flight engine peak of 1,714.4 Mbps (156,073 pps, 6.41 µs/packet) across the same Snapdragon 8 Elite Oryon cores, JNI/TUN boundary, and ChaCha20-Poly1305 primitives. This proves that single-packet TUN read and crypto primitives are not the binding constraint (single-reader TUN capacity at 4.5 µs is 222,222 pps = 2,441 Mbps).

### 2.2 Carrier Batch Starvation Discovery & Accounting (OI-1 & OI-2)
* **Run 17 Empirical Telemetry**: 1,811,929 datagrams transmitted across 1,146,349 socket calls.
* **Batch Occupancy Ratio**: 1,811,929 / 1,146,349 = 1.5806 datagrams per `sendmmsg` call.
* **Root Cause**: The carrier drain thread was waking on single-packet signals from `toEngineRing`, finding only 1 or 2 datagrams queued and executing `sendmmsg` immediately, operating at only 0.617% of the configured 256-wide batch capacity.
* **Transmit Drain Gating (txDrainGate)**:
  - Low watermark: 32 packets.
  - Maximum parking delay: 250 µs.
  - Latency impact: 250 µs represents 0.385% of the 65 ms Canada gateway RTT, creating zero disruption to TCP congestion control.
  - Accumulation: At 91,041.5 pps wire speed, 250 µs accumulates 22.76 packets; at current sustained rates it accumulates 9.70 packets.
* **Kernel UDP Segmentation Offload (Mechanism B)**:
  - Linux kernel 6.12.30 supports `UDP_SEGMENT` (SOL_UDP=17, UDP_SEGMENT=103).
  - Emits runs of up to 45 equal-length datagrams (e.g. 1,402 bytes) via a single `sendmsg` call with control message headers.
  - Reduces socket syscalls from 1,146,349 down to ~40,000 to 56,000 across the entire test session (95.1% to 96.5% reduction).
  - Runtime capability probe with zero-drop fallback to `sendmmsg` ensures absolute safety on mobile Wi-Fi interfaces.

### 2.3 Rejection of Mechanism A (Super-Datagrams)
* **PMTU Overrun**: Packing 2 full 1,373-byte inner packets into an outer UDP datagram produces a 2,806 to 2,809-byte IP datagram against a 1,500-byte path MTU, causing PMTU drops or IP fragmentation.
* **Protocol Ground Truth**: Small-frame packing within `MaxMessageSize` (1,402 bytes) is already implemented in `driver.go:1980-1994` and requires no protocol modification.

### 2.4 Gateway Ingress Zero-Truncation Invariant (OI-3)
* **Status**: Under Mechanism B, every emitted datagram remains at or below 1,402 bytes over the wire.
* **Gateway Demux Sizing**: Gateway receive buffers (`cover_demux.go:127` allocating 4,096 bytes) receive individual datagrams well below capacity, guaranteeing zero truncation and zero slab memory bloat. Gateway requires zero code modifications.

### 2.5 Downlink Freeze Invariant 100% Preservation (OI-4)
* **Preservation**: `RecvBatch`, `outboundPump`, `toHost`, `fromEngine`, downlink crypto workers, and measurement mathematics remain 100% frozen.

---

## 3. Ratified Surgical Specifications

### 3.1 Kernel UDP Segmentation Offload (GSO) Carrier
File: `winn_protocol_experimental/winn3/carrier/udp_gso_linux.go`
* Probe `UDP_SEGMENT` at carrier socket initialization.
* Wrap existing `RawBatchConn` / batch writer.
* On transmit, coalesce runs of equal-sized datagrams (<= 45 segments, <= 65,535 bytes) and send via `unix.SendmsgN` with `SOL_UDP / UDP_SEGMENT` cmsg.
* If unsupported or rejected by kernel routing, permanently fall back to `sendmmsg` with zero dropped packets.

### 3.2 Transmit Drain Gating in Inbound Ring Buffer
File: `winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go`
* Add `lowWater = 32` and `maxPark = 250 * time.Microsecond` coalescing parameters to `toEngineRing`.
* In `pushBatch` and `pushOne`, signal consumer when ring depth reaches `lowWater` or transitions from empty.
* In `popBatch`, if ring holds between 1 and `lowWater - 1` packets, wait up to `maxPark` (250 µs) for additional burst packets before popping.
* Prevents carrier batch starvation while guaranteeing bounded delivery latency (maximum 250 µs) on light traffic.

### 3.3 Certification Record
* **Agreed Specification Digest**: `SHA256: 7d6c54e1957221448ebf5a8a7de40b0805c6dcb65b05888e252814b74f3e6a0d`
* **Ratification Authority**: Arbiter certified following unanimous affirmative convergence across all active podiums.
