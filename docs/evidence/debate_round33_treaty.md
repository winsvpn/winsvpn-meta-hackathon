# WINTHOS ROUND 33 PRESIDENTIAL DEBATE TREATY
## Unanimous Treaty of the Four-AI Presidential Council
### Symmetrical Wire-Speed Upload Optimization (>1,000 Mbps with Download Locked at 1,554 Mbps)

**Date:** 2026-09-19  
**Council Composition:**
- **Podium 1 (Council Chair):** Antigravity (Gemini 3.8 Flash High)
- **Podium 2:** GPT-5.6 Sol Pro (`openai/gpt-5.6-sol-pro` via OpenRouter)
- **Podium 3:** Claude Opus 5 (`anthropic/claude-opus-5` via OpenRouter)
- **Podium 4:** Claude Fable 5.1 (`anthropic/claude-fable-5.1` via OpenRouter)

---

## 1. Executive Summary and Ratification Status

The Presidential Debate Council for Round 33 convened across three stages of independent technical submissions, formal cross-rebuttals, and synthesis position locks. All four podiums have reached 100% unanimous agreement and formally ratified this Treaty.

### Core Mandates Ratified:
1. **Download Datapath Frozen:** Download speed is verified live at 1,554 Mbps over Winn Protocol v3 direct transport on the Samsung Galaxy S26 Ultra (`s26_speedtest_final_both1000.png`). Download code, configuration, socket options, and timing mathematics in `MainActivity.kt`, `speed_test_policy.dart`, and `main.dart` remain 100% untouched.
2. **Upload Wire-Speed Target:** Scale Upload throughput from 706 Mbps to $\ge 1,000$ Mbps (operating range: 1,000 to 1,500+ Mbps) over Winn Protocol v3.
3. **Hardware Target:** Exclusively the physical Samsung Galaxy S26 Ultra (`SM-S948U1`, serial `REDACTED_SERIAL`) running Wi-Fi 7 to `aicore` gateway (192.168.4.36:9111).
4. **Post-Quantum Security:** Zero cryptographic regressions. Monotonic nonces and ChaCha20-Poly1305 inner framing are fully preserved.

---

## 2. Mathematical Foundation and Goodput Equations

Physical link: Wi-Fi 7 PHY rate 3,459 Mbps (5,764 Mbps physical maximum) on 6 GHz band, 320 MHz channel width.
Upstream WAN: Symmetrical 2,000 Mbps fiber line.

### 2.1 Bandwidth-Delay Product (BDP)
For target upload goodput $T_{\text{upload}} = 1,200 \text{ Mbps}$ at round-trip time $\text{RTT} = 20 \text{ ms}$:
$$\text{BDP} = \frac{1,200 \times 10^6 \text{ bps} \times 0.020 \text{ s}}{8} = 3,000,000 \text{ bytes} \approx 2.86 \text{ MB}$$

Across $N = 32$ parallel TCP streams:
$$\text{BDP}_{\text{per-stream}} = \frac{3,000,000 \text{ bytes}}{32} = 93,750 \text{ bytes} \approx 91.6 \text{ KB}$$

With Android Linux default socket write buffer `wmem_default` = 229,376 bytes (224 KB):
$$\text{Headroom Ratio} = \frac{229,376 \text{ bytes}}{93,750 \text{ bytes}} = 2.45\times$$
Each stream's 224 KB buffer comfortably holds 2.45x its BDP share.
Writing 512 KB chunks previously clogged the 224 KB buffer by 2.3x, forcing kernel thread stalls.
Switching to 256 KB chunks (`256 * 1024` = 262,144 bytes) matches the kernel buffer capacity, eliminating blocking stalls.

### 2.2 Tail Write Overshoot Bounding
At 1,200 Mbps aggregate (37.5 Mbps = 4.68 MB/s per stream):
- A 512 KB chunk takes $\frac{512 \text{ KB}}{4.68 \text{ MB/s}} = 109.4 \text{ ms}$ to transmit.
- A 256 KB chunk takes $\frac{256 \text{ KB}}{4.68 \text{ MB/s}} = 54.7 \text{ ms}$ to transmit.
A 256 KB chunk cuts window exit overshoot in half, ensuring sharp 6.0-second window termination.

---

## 3. Ratified Technical Specifications

### Specification 1: Chunk Streaming and Application Buffer Sizing
In `MainActivity.kt:measureUploadMbps`:
- Set `connection.setChunkedStreamingMode(256 * 1024)`.
- Set application buffer: `val buffer = ByteArray(256 * 1024) { 0x5A.toByte() }`.
- Write directly to `connection.outputStream` without wrapping in `BufferedOutputStream`. This eliminates a redundant 256 KB memory copy per stream ($32 \times 256\text{ KB} = 8\text{ MB}$ saved allocation).

### Specification 2: Stream Concurrency and Barrier Pre-Warming
- Retain 32 parallel streams (`streamCount = 32`).
- Each of the 32 streams connects to `speedTestStreamUrl(url, streamIndex, 0)`.
- Each stream configures headers, establishes TCP, and completes TLS 1.3 handshake before signaling `ready.countDown()`.
- Main orchestrator awaits `ready.await(6, TimeUnit.SECONDS)` and releases all 32 streams simultaneously with `start.countDown()`.

### Specification 3: Active Transfer Window and Byte Accounting
- Maintain continuous byte accumulation: `confirmed.addAndGet(writable.toLong())` immediately upon successful `out.write(buffer, 0, writable)`.
- Record `firstByteAt.compareAndSet(0L, System.nanoTime())` on the very first byte write return.
- Record `finishedAt.set(System.nanoTime())` on each chunk write completion.
- When the 6-second window elapses (`now >= startNanos + durationNanos`), break from the loop, flush, and close output streams.
- Handle trailing response codes asynchronously without withholding byte credits.

### Specification 4: Go Datapath Outer UDP Socket Buffer
In `winn_protocol_experimental/cmd/winn-datapath/winn3_frame.go`:
When adopting the outer UDP file descriptor from `VpnService`:
Call `conn.SetWriteBuffer(8 * 1024 * 1024)` to expand outer socket buffer headroom from 224 KB to 8 MB, absorbing mobile softirq bursts.

### Specification 5: Download Code Lock
Lines 1335 to 1438 in `MainActivity.kt` governing `measureDownloadMbps` are strictly frozen. No modifications allowed.

---

## 4. Ratification Signatures

```
[COUNCIL CHAIR - PODIUM 1]
Antigravity (Gemini 3.8 Flash High)
Status: RATIFIED

[PODIUM 2]
GPT-5.6 Sol Pro (openai/gpt-5.6-sol-pro)
Status: RATIFIED

[PODIUM 3]
Claude Opus 5 (anthropic/claude-opus-5)
Status: RATIFIED

[PODIUM 4]
Claude Fable 5.1 (anthropic/claude-fable-5.1)
Status: RATIFIED
```
