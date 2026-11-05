# Winn Protocol v3: Engineering Evolution from 200 Mbps to Symmetrical Gigabit (1.55 Gbps / 1.23 Gbps)

This technical reference documents the engineering journey, architectural bottlenecks, mathematical physics, kernel optimizations, and surgical fixes that advanced Winn Protocol v3 from an initial ceiling of ~200 Mbps to wire-speed symmetrical gigabit throughput (1,554 Mbps download / 1,228 Mbps upload) on the physical Samsung Galaxy S26 Ultra (SM-S948U1) over direct transport.

---

## 1. Executive Summary & Final Empirical Baseline

- **Hardware Platform**: Samsung Galaxy S26 Ultra (SM-S948U1, Qualcomm Snapdragon 8 Elite, serial REDACTED_SERIAL).
- **Gateway Node**: `aicore` (192.168.4.36:9111, Linux 6.8 kernel, 2.5 GbE physical uplink).
- **Cryptographic Suite**: Winn Protocol v3 post-quantum encapsulation (ML-KEM-768 key exchange, dual Ed25519 and ML-DSA-65 authentication, ChaCha20-Poly1305 AEAD).
- **Observed Throughput Progress**:
  - **Initial Implementation**: ~200 Mbps download, ~180 Mbps upload (CPU bound, single-packet syscalls, socket buffer constrained).
  - **Intermediate Batching & Buffer Tuning**: ~600 to 900 Mbps download, upload stalling and dropping.
  - **Final Tuned Datapath (S26 Ultra Verified)**:
    - **Download**: **1,554 Mbps**
    - **Upload**: **1,228 Mbps**
    - **Packet Drop Rate**: 0.003% (36 queue drops out of 1,060,324 packets).
    - **Cryptographic Unopenable Rate**: 0 packets.
    - **Session Posture**: 100% stable `SECURED` state without reconnection or token desynchronisation.

---

## 2. Key Bottlenecks Identified in the 200 Mbps Baseline

When Winn Protocol v3 was initially deployed, throughput plateaued around 200 Mbps despite running on top-tier silicon and gigabit wireless links. Systematic CPU profiling, packet capture, and kernel tracing identified six distinct bottlenecks:

### A. The Bandwidth-Delay Product (BDP) Socket Buffer Wall
- **The Physics**: The theoretical throughput of any reliable flow over a network is bounded by:
  $$\text{Max Throughput} = \frac{\text{Buffer Size}}{\text{RTT}}$$
- **The Defect**: Standard Linux, Android, and macOS kernel defaults set `SO_RCVBUF` and `SO_SNDBUF` to ~213 KiB (with `net.core.rmem_default` at 212,992 bytes).
- **The Impact**: Over a local Wi-Fi hop with an RTT of 8 ms, a 213 KiB buffer limits throughput to:
  $$\frac{213 \times 1024 \times 8 \text{ bits}}{0.008 \text{ s}} \approx 218 \text{ Mbps}$$
  Over WAN paths (such as gx10 to Spain at 132 ms RTT), a 213 KiB buffer collapses throughput to ~13 Mbps. The protocol was not CPU-bound at 200 Mbps; the kernel socket was discarding packets as soon as a single burst exceeded 145 packets.

### B. Syscall Overhead (One Syscall per Datagram)
- Transmitting 1.5 Gbps of standard 1,400-byte wire datagrams requires processing:
  $$\frac{1.5 \times 10^9 \text{ bps}}{1400 \times 8 \text{ bits}} \approx 133,928 \text{ datagrams/second}$$
- In the initial code, each datagram incurred separate system calls:
  1. `Read` from TUN interface.
  2. Encrypt in user space.
  3. `WriteToUDP` to socket.
  4. Corresponding `ReadFromUDP` and `Write` on the peer.
- With 134,000 packets per second, the process was issuing over 535,000 system calls per second. Context switching consumed more than 65% of all CPU time on the cores.

### C. Garbage Collection & Memory Allocation Escapes
- Memory profiling with Go's `alloc_objects` on the S26 Ultra showed that `sync.Pool.Put` in `recycleDataBuf` accounted for 30% of every object allocated by the entire datapath.
- Using slice headers (`*[]byte`) in `sync.Pool` caused `Put(&b)` to take the address of a local slice header on the stack. The Go compiler was forced to escape this 24-byte header to the heap on every packet, generating over 130,000 heap allocations per second.
- GC pause cycles occurred every 80 to 120 milliseconds, each causing a 3 to 15 millisecond stall. At line rate, a 10 ms stall backed up over 1,300 packets, overflowing userspace queues.

### D. Hot-Path Mutex Contention
- In `session.Driver`, `Enqueue` and `Deliver` held `d.mu.Lock()` per packet.
- When multiple goroutines (reader, writer, control loop) touched the session concurrently, thread contention on `d.mu` degraded multi-core scaling. Cores spent significant time spinning on lock acquisition rather than processing network frames.

### E. Sliding Token Window vs Queue Depth Mismatch
- Winn Protocol v3 uses a sliding token window (`core.DefaultTokenWindow` = 1024) to authenticate arriving packets and prevent replay attacks.
- The carrier pipe inbox depth was originally left at `carrier.DefaultPipeDepth` (256 slots).
- Because 256 was smaller than the reordering tolerance (511 slots), normal burst reordering caused packets to drop with `ErrQueueFull` before reaching `Session.Open`.

### F. Demultiplexer Scheduler Starvation on S26 Upload
- During multi-gigabit download bursts, the client sent tens of thousands of reverse TCP ACKs.
- The gateway UDP reader goroutine (`readLoopEntered`) drained the 32 MiB kernel buffer in a tight loop.
- When the 512-slot `ps.pipe.inbox` filled while `driver.Loop.readLoop` was writing to the TUN device, `readLoopEntered` dropped 2,800+ consecutive packets without yielding CPU time.
- Dropping 2,800 packets advanced the client's packet counter past the 1,024-token window. All future packets failed token lookup as `unopenable`, causing liveness timers to expire and tearing down the connection.

---

## 3. Systematic Architecture & Optimization Phases

To resolve these bottlenecks, the engineering team executed a series of architectural interventions:

### Phase 1: BDP Scaling & Kernel Buffer Floors
- **Changes**:
  - Set gateway socket buffer request to 16 MiB in `cmd/winn3-gateway/udp_socket_buffers.go`:
    ```go
    udpSocketBufferBytes = 16 << 20
    udpSocketBufferMinBytes = 8 << 20
    ```
  - Linux kernel automatically doubles `SO_RCVBUF` internally, granting 33,554,432 bytes (32 MiB) of kernel buffer.
  - Sized client socket buffer default to 8 MiB in `winn3/carrier/udp_socket_buffers.go`.
- **Result**: The kernel socket buffer can absorb up to 23,000 full-size datagrams during transient user-space scheduling delays without dropping a single packet.

### Phase 2: Vectorized Batching (mmsg I/O)
- **Changes**:
  - Implemented `RecvBatch` and `WriteBatchTo` across `winn3/carrier`.
  - On Linux and Android, replaced single `recvfrom`/`sendto` syscalls with `recvmmsg` and `sendmmsg`.
  - Tuned batch sizes to 64 datagrams per batch (`session.MaxBatchSize = 64`).
- **Result**: Reduced system calls by 98.4% (from 134,000 syscalls/sec down to ~2,100 batch syscalls/sec at 1.5 Gbps). Syscall CPU overhead dropped from 65% to under 7%.

### Phase 3: Zero-Allocation Slab Management
- **Changes**:
  - Refactored `session.Driver` buffer pool to use array pointers instead of slice headers:
    ```go
    const dataBufSize = 2048
    var dataBufPool = sync.Pool{
        New: func() any { return new([dataBufSize]byte) },
    }
    ```
  - An array pointer `*[2048]byte` is a single machine word. It fits into the interface container without heap boxing or allocation escapes.
  - Optimized buffer recycling in `recycleDataBuf` to clear only written bytes (`clear(b)`) instead of wiping untouched slab memory.
- **Result**: Completely eliminated 130,000 heap allocations per second. Datapath allocations dropped to zero during steady-state data transfer.

### Phase 4: Amortized Batch Locking
- **Changes**:
  - Added `EnqueueBatch(inners [][]byte) (int, error)` in `session.Driver`.
  - Added `DeliverBatch(slots []ReceiveSlot) (int, error)`.
  - The hot-path mutex `d.mu.Lock()` is acquired once per batch of up to 64 packets instead of 64 separate lock/unlock operations.
- **Result**: Eliminated lock contention between packet ingress and egress routines, unlocking true multi-core parallel processing.

### Phase 5: Multiqueue TUN Scaling
- **Changes**:
  - Configured 4 multiqueue TUN descriptors (`IFF_MULTI_QUEUE`) on the gateway forward device (`winn3gw0`).
  - Allowed multiple worker goroutines to read and write to the Linux network stack simultaneously without kernel serialization bottlenecks.

### Phase 6: Inbox Derivation & Scheduler Yielding
- **Changes**:
  - Pinned `Depth: core.DefaultTokenWindow / 2` (512 slots) in `newSession`.
  - Added `DeliverWithRetry(msg []byte, maxRetries int) error` in `winn3/carrier/pipe.go`:
    ```go
    for attempt := 0; attempt <= maxRetries; attempt++ {
        select {
        case p.inbox <- bp:
            // Delivered successfully
            return nil
        default:
            if attempt < maxRetries {
                runtime.Gosched()
                if attempt >= 3 {
                    time.Sleep(25 * time.Microsecond)
                }
            }
        }
    }
    ```
  - Called `ps.pipe.DeliverWithRetry(buf, 20)` in `cmd/winn3-gateway/main.go`.
- **Result**: When line-rate bursts occur, the demultiplexer yields CPU time to let `Loop.readLoop` drain batches of 64 packets into the TUN interface. Arriving packets wait safely in the 32 MiB kernel buffer rather than being dropped.

---

## 4. Performance Evolution Comparison Table

| Metric | Initial Winn v3 Baseline | Intermediate Architecture | Final Tuned S26 Implementation |
| :--- | :--- | :--- | :--- |
| **Download Throughput** | ~200 Mbps | ~750 Mbps | **1,554 Mbps** |
| **Upload Throughput** | ~180 Mbps | Dropped / Desynced | **1,228 Mbps** |
| **I/O Processing Model** | Single-datagram syscalls | Partial batching | Vectorized `recvmmsg` / `sendmmsg` (64 pkts) |
| **Gateway `SO_RCVBUF`** | 213 KiB (OS default) | 8 MiB | **32 MiB granted** (16 MiB requested) |
| **Client `SO_RCVBUF`** | 213 KiB (OS default) | 4 MiB | **8 MiB** |
| **Heap Allocations / sec** | ~130,000 allocs/s | ~40,000 allocs/s | **0 allocs/s (zero-alloc slabs)** |
| **Lock Acquisitions / sec** | 134,000 locks/s | 60,000 locks/s | **~2,100 locks/s (batch amortized)** |
| **Inbox Drop Rate** | Catastrophic on burst | 2,837 drops per burst | **36 drops per 1,060,000 pkts (0.003%)** |
| **Cryptographic Desync** | Frequent at high load | Occurred on upload start | **0 desyncs (100% stable connection)** |
| **TUN Concurrency** | Single queue descriptor | Single queue descriptor | **4 Multiqueue TUN queues** |

---

## 5. Architectural Lessons for AmneziaWG (AWG) and Future Protocols

The lessons learned from optimizing Winn Protocol v3 apply directly to AmneziaWG (AWG) and other UDP-based secure tunnels:

1. **Never Rely on Kernel Default Socket Buffers**:
   - Any high-speed UDP transport must explicitly configure `SO_RCVBUF` and `SO_SNDBUF` to 8 MiB or higher. The 213 KiB OS default is fundamentally incapable of multi-gigabit throughput.
2. **Batching is Mandatory for Gigabit Wire Speed**:
   - Vectorized I/O (`recvmmsg`, `sendmmsg`, GSO/GRO) must be integrated into the lowest layer of the carrier bind. Individual packet syscalls saturate CPU cores with context switching.
3. **Array Pointers for Object Pools**:
   - In Go, always pool `*[N]byte` array pointers rather than `*[]byte` slice headers to avoid 24-byte interface boxing escapes to the heap.
4. **Cooperative Yielding on Ingress Queues**:
   - A high-speed socket reader must never discard packets immediately on a full userspace queue without cooperative yielding (`runtime.Gosched()`). The kernel socket buffer exists specifically to absorb bursts while userspace worker threads catch up.
5. **Lock Once Per Batch**:
   - Move synchronization boundaries to the batch level. Holding mutexes per packet introduces severe thread contention on multi-core processors.
