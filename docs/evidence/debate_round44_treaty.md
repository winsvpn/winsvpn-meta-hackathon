# MULTI-MODEL DEBATE ROUND 44 TREATY: ANDROID WINN V3 UPLINK WIRE-SPEED SCALING STAGE B

## 1. Council Composition & Protocol Certification
* **Podium 1**: Gemini 3.8 Flash High (agy CLI, --effort high)
* **Podium 2**: Claude Opus 5 extra-high (claude CLI, --effort high)
* **Podium 3**: GPT-5.6 Sol Pro extra-high (OpenRouter, openai/gpt-5.6-sol-pro, service_tier: flex)
* **Arbiter**: Antigravity Orchestrating Agent (non-voting)
* **Protocol**: Iterative Convergence Debate Protocol (ICDP §13)
* **Convergence Status**: UNANIMOUS RATIFICATION on OI-1 (Lock-Batched Ring Buffer), OI-2 (Preserve packetPool in Stage B), OI-3 (Gateway 4-Tuple Hashing Verification), and OI-4 (Downlink Freeze Invariant).

---

## 2. Certified First-Principles Arithmetic

### 2.1 Wire Speed & S26 Ultra Telemetry Identities
* **Target Bitrate**: 1,000 Mbps = 125,000,000 B/s.
* **Inner MTU**: 1,373 bytes.
* **Target Packet Rate**: 125,000,000 / 1,373 = 91,041.515 packets per second.
* **Target Wall-Clock Budget**: 1 / 91,041.515 = 10.984000 µs per packet.
* **Run 16 Measured Uplink**: 389,677,056 bytes in 8.000 seconds = 48,709,632 B/s = 389.677 Mbps across 32 concurrent HTTP streams to gateway ingest (10.10.0.1:8455).
* **Run 16 Packet Rate**: 48,709,632 / 1,373 = 35,476.790 packets per second.
* **Run 16 Observed Wall-Clock Duration**: 1 / 35,476.790 = 28.187440 µs per packet.
* **Residual Wall-Clock Budget to Retire**: 28.187440 - 10.984000 = 17.203440 µs per packet (2.56623x speedup required).

### 2.2 Lock Acquisition Amortization (OI-1)
* **Scalar Channel Contention**:
  - Push operations: 91,041.515 pushes per second, each acquiring and releasing `hchan.lock`.
  - Pop operations: 91,041.515 pops per second, each acquiring and releasing `hchan.lock`.
  - Total channel synchronization entries: 2 * 91,041.515 = 182,083.030 acquisitions per second.
* **Batched Ring Buffer Synchronization**:
  - Push batching (512 packets): 91,041.515 / 512 = 177.816 acquisitions per second.
  - Pop batching (256 packets): 91,041.515 / 256 = 355.631 acquisitions per second.
  - Total ring synchronization entries: 177.816 + 355.631 = 533.446 acquisitions per second.
  - Acquisition reduction factor: 182,083.030 / 533.446 = 341.333x.
  - Synchronization frequency reduction: (182,083.030 - 533.446) / 182,083.030 = 99.707%.
* **Cache Line Invalidation Elimination**:
  - Reader goroutine (`serve`) and consumer goroutine (`pumpOutboundBatch`) execute on separate Snapdragon 8 Elite Oryon cores.
  - Moving 181,549 lock operations/second off the shared bus removes inter-core cache line bouncing and goroutine descheduling overhead.

### 2.3 Memory Lifecycle & Safety (OI-2)
* **Byte Copy Movement**:
  - 3 payload copies of 1,373 bytes = 4,119 bytes per packet.
  - Total bandwidth at line rate: 3 * 125 MB/s = 375 MB/s (under 0.6% of LPDDR5X DRAM bus capacity).
  - Effective copy time on Oryon L2/L3 cache: ~0.16 to 0.47 µs per packet.
* **Preservation of packetPool**:
  - Bypassing the copy into `bufs[idx]` would violate the frozen `tun.BatchDevice` contract (`ReadBatch(bufs [][]byte) ([]int, error)`).
  - Direct slice lending without a full loan/return protocol introduces memory aliasing and use-after-recycle bugs.
  - Council unanimously confirms: zero copy architecture refactoring in Stage B. Zero-allocation `packetPool` recycling is preserved.

### 2.4 Gateway Ingress Headroom Verification (OI-3)
* **Codebase Ground Truth**: `cmd/winn3-gateway/forward_linux.go` lines 272-286 hashes the TCP 4-tuple (`srcPort >> 2 ^ dstPort`), distributing the 32 streams evenly across all 4 TUN multi-queue descriptors.
* **Status**: Gateway requires zero modifications for Stage B.
* **Certification Caveat (§13.7.9)**: Gateway capacity above 48,709,632 B/s (38.97% of wire speed) is unverified by physical measurement and will be evaluated during wire-speed validation.

### 2.5 Downlink Freeze Invariant (OI-4)
* **Preservation**: `toHost chan []byte`, `take()`, `tryTake()`, `WritePacket()`, `pumpOutboundBatch`, `outboundPump`, and all downlink measurement parameters remain 100% frozen.
* **Baseline**: Measured 673 Mbps sustained in Run 16.

---

## 3. Ratified Surgical Specifications

### 3.1 New Ring Buffer Component
File: `winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go`
* Define `toEngineRing` struct with `sync.Mutex`, `sync.Cond`, circular slice storage of size `winn3FrameQueueDepth = 65536`, `mask = winn3FrameQueueDepth - 1`.
* `pushBatch(packets [][]byte)`: enqueues up to 512 slice headers under `mu.Lock()`, executes tail drop if capacity exceeded, unlocks, and signals `notify.Signal()`.
* `popBatch(dst [][]byte)`: waits while empty and open, drains up to `len(dst)` (256) slice headers under `mu.Lock()`, unlocks, and re-signals if remaining queued packets exist.
* Payload copying into `bufs[idx]` and `packetPool` recycling occur strictly outside the mutex lock.
* `close()`: sets `closed = true` under lock and broadcasts `notify.Broadcast()`.
* Graceful drain: `popBatch` returns remaining queued packets before reporting `errWinn3DeviceClosed`.

### 3.2 Frame Device Queue Binding
File: `winn_protocol_experimental/cmd/winn-datapath/winn3_frame_device.go`
* Replace `toEngine chan []byte` with `*toEngineRing`.
* Add reusable scratch slices `offerScratch [][]byte` and `readPackets [][]byte` to eliminate per-batch slice allocation.
* In `offerBatch`: filter oversize packets into `offerScratch`, call `d.toEngine.pushBatch(valid)`, record tail drops in `droppedToEngine`, recycle rejected packets to `packetPool`, and clear scratch pointers.
* In `ReadBatch`: drain slice headers into `readPackets` via `d.toEngine.popBatch(packets)`, copy into caller buffers `bufs[idx]`, and recycle pooled packets.
* `push(d.toHost, ...)` remains 100% untouched for downlink traffic.
