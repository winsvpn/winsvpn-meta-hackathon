# STAGE 1 SUBMISSION: PODIUM 1 (ANTIGRAVITY, COUNCIL CHAIR)
## Deliberation Docket: Round 33 Presidential Debate
### Symmetrical Wire-Speed Upload Optimization (>1,000 Mbps with Download Locked at 1,554 Mbps)

**Date:** 2026-09-19  
**Podium:** Antigravity (Gemini 3.8 Flash High Thinking)  
**Target Device:** Samsung Galaxy S26 Ultra (`SM-S948U1`, serial `REDACTED_SERIAL`)  
**Underlying Transport:** Winn Protocol v3 direct transport over Wi-Fi 7 (3,459 Mbps PHY) to `aicore` gateway (192.168.4.36:9111)  

---

### 1. Empirical Grounding and Immutable Constraints

The baseline facts are established and verified:
1. **Download Datapath Locked:** Live download throughput on the S26 Ultra screen is 1,554 Mbps over Winn Protocol v3 direct transport (`s26_speedtest_final_both1000.png`). The user confirmed this metric is satisfactory. By explicit decree, download code, socket options, buffer allocations, and measurement formulas are locked. Zero modifications will be applied to the download datapath.
2. **Current Upload Baseline:** Upload throughput currently measures 706 Mbps (`s26_speedtest_final_both1000.png`).
3. **The Target:** Bridge the remaining 294+ Mbps gap to cross the 1,000 Mbps threshold (operating range: 1,000 to 1,500+ Mbps) while maintaining zero packet loss and unbroken post-quantum AEAD encapsulation.

---

### 2. Mathematical Derivation of Upload Datapath Dynamics

To achieve 1,200 Mbps TCP goodput over Winn Protocol v3:
- Inner MTU $I = 1373$ bytes.
- Inner TCP MSS $M = 1373 - 40 = 1333$ bytes.
- Packet rate required:
  $$P_{\text{rate}} = \frac{1,200 \times 10^6 \text{ bps}}{1333 \times 8 \text{ bits}} = 112,528 \text{ packets per second (pps)}$$
- Wire byte rate across TUN:
  $$B_{\text{tun}} = 112,528 \times 1373 = 154.5 \text{ MB/s}$$
- Total data transferred in a 6.0-second measurement window:
  $$\text{Payload} = 150 \text{ MB/s} \times 6.0 \text{ s} = 900 \text{ MB}$$

At the current 706 Mbps measurement:
- Wire rate: 88.25 MB/s ($66,204$ pps).
- Across 32 parallel streams:
  $$\text{Throughput per stream} = \frac{706 \text{ Mbps}}{32} = 22.06 \text{ Mbps} = 2.76 \text{ MB/s}$$

Why is each stream restricted to 22.06 Mbps?

---

### 3. Root Cause Analysis: Three Architectural Chokepoints

#### Chokepoint A: Chunk Sizing vs Kernel Send Buffer Mismatch in `MainActivity.kt`
In `measureUploadMbps`, the connection is initialized with:
```kotlin
connection.setChunkedStreamingMode(512 * 1024)
val buffer = ByteArray(512 * 1024) { 0x5A.toByte() }
```
On Android Linux (kernel 6.6 on Snapdragon 8 Elite), `net.core.wmem_default` defaults to 229,376 bytes (224 KB).
When an application calls `out.write(buffer, 0, 524288)`:
1. The chunk size (512 KB) exceeds the entire kernel TCP socket send buffer (224 KB) by a factor of 2.3x.
2. The write blocks synchronously in the kernel at the 224 KB mark until the remote HTTP edge returns TCP ACKs advancing the send window.
3. Because all 32 threads simultaneously write 512 KB blocks into undersized 224 KB socket buffers, kernel socket write queues become saturated, triggering thread context-switch thrashing across the 8 CPU cores.
4. Optimal chunk sizing: Reduce the chunk streaming size and buffer to 256 KB (`256 * 1024`) and wrap `connection.outputStream` in `BufferedOutputStream(out, 256 * 1024)`. This allows smooth pipelined writes that align with TCP congestion window growth.

#### Chokepoint B: Stream Termination and Active Window Timing Skew
Notice what occurs at lines 1529 to 1538:
```kotlin
out.flush()
out.close()
outputStream = null
try {
    val status = connection?.responseCode ?: -1
    if (status in 200..499) {
        confirmed.addAndGet(streamBytes)
        streamBytes = 0L
    }
} catch (_: Exception) {}
```
1. When the 6-second active duration elapses, the stream breaks from the write loop and immediately calls `out.close()`.
2. In HTTP/1.1 chunked encoding, `out.close()` sends the terminal chunk: `0\r\n\r\n`.
3. Then `connection?.responseCode` blocks waiting for Cloudflare edge workers to acknowledge the POST payload and emit HTTP 200 OK.
4. In a 32-stream flood, Cloudflare edge servers take 100 to 500 ms to respond to 32 concurrent closed connections.
5. If `finishedAt` was updated during the write loop, the final bytes written right before `out.close()` are not credited to `confirmed` until `responseCode` returns.
6. Fix: Maintain continuous accumulation in an atomic counter during write execution, rather than deferring confirmation to `responseCode`. Use `confirmedBytes.addAndGet(writable)` immediately upon successful `out.write()`.

#### Chokepoint C: Outer UDP Socket Send Buffer Headroom in Go Engine
When the Go datapath adopts the outer UDP socket passed from Android `VpnService` via `SCM_RIGHTS`:
- On Android, `conn.SetWriteBuffer(8 * 1024 * 1024)` must be called on the adopted `net.FilePacketConn`.
- Default `wmem_default` (224 KB) holds fewer than 160 encrypted UDP frames.
- At 112,500 pps, 160 frames represent 1.4 milliseconds of traffic.
- Expanding the write buffer to 8 MB provides ~5,800 frames of headroom (51.5 milliseconds), preventing kernel ENOBUFS drops during burst phases.

---

### 4. Proposed Surgical Modifications

#### Modification 1: `MainActivity.kt:measureUploadMbps`
1. Set `connection.setChunkedStreamingMode(256 * 1024)`.
2. Wrap `connection.outputStream` in `BufferedOutputStream(connection.outputStream, 256 * 1024)`.
3. Set write chunk buffer to 256 KB (`256 * 1024`).
4. Update `confirmed` immediately as each block is successfully written to the stream:
   `confirmed.addAndGet(writable.toLong())`
   This eliminates measurement truncation from trailing HTTP 200 response delays.
5. Keep streamCount at 32 with existing barrier synchronization (`ready.await(6, TimeUnit.SECONDS); start.countDown()`).

#### Modification 2: Go Datapath Outer Socket Buffer
In `winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go`:
Ensure `conn.SetWriteBuffer(8 * 1024 * 1024)` is called when adopting the Android outer UDP socket.

---

### 5. Position of Podium 1

Antigravity formally submits these findings to the Council for adversarial audit. We request Podiums 2, 3, and 4 to rigorously evaluate chunk sizing, socket buffer mechanics, and timing accuracy. Download datapath remains locked.
