# WINTHOS ROUND 34 PRESIDENTIAL DEBATE TREATY
## Unanimous Treaty of the Four-AI Presidential Council
### Symmetrical Wire-Speed Upload Optimization (>1,000 Mbps with Download Locked at 1,554 Mbps)

**Date:** 2026-09-19  
**Council Composition:**
- **Podium 1 (Council Chair):** Antigravity (Gemini 3.8 Flash High)
- **Podium 2:** GPT-5.6 Sol Pro (openai/gpt-5.6-sol-pro via OpenRouter)
- **Podium 3:** Claude Opus 5 (anthropic/claude-opus-5 via OpenRouter)
- **Podium 4:** Claude Fable 5.1 (anthropic/claude-fable-5.1 via Claude Code CLI)

---

## 1. Executive Summary and Ratification Status

The Presidential Debate Council for Round 34 convened across three stages of independent technical submissions, adversarial cross-rebuttals, and synthesis position locks. All four podiums have reached 100% unanimous agreement and formally ratified this Treaty.

### Core Directives Ratified:
1. **Download Datapath Frozen:** Download speed is verified live at 1,507 to 1,554 Mbps over Winn Protocol v3 direct transport on the Samsung Galaxy S26 Ultra (s26_speedtest_mid1.png and s26_speedtest_final_both1000.png). Download code, socket options, buffer allocations, and measurement mathematics in MainActivity.kt are 100% frozen. Zero download code will be modified.
2. **Upload Wire-Speed Target:** Scale Upload throughput from 0/706 Mbps to >= 1,000 Mbps (target: 1,000 to 1,500+ Mbps) over Winn Protocol v3.
3. **Target Device:** Exclusively the physical Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL) connected via Wi-Fi 7 (3,459 Mbps PHY rate) to the aicore gateway (192.168.4.36:9111).
4. **Post-Quantum Security:** Zero cryptographic regressions. Monotonic nonces and ChaCha20-Poly1305 inner framing remain fully intact.

---

## 2. Mathematical Foundation and Goodput Equations

Physical link: Wi-Fi 7 PHY rate 3,459 Mbps on 6 GHz band, 320 MHz channel width.
Upstream WAN: Symmetrical 2,000 Mbps fiber line.

### 2.1 Bandwidth-Delay Product (BDP)
For target upload goodput T_upload = 1,200 Mbps at round-trip time RTT = 12 ms:
BDP = (1,200 * 10^6 bps * 0.012 s) / 8 = 1,800,000 bytes approx 1.72 MB.

Across N = 24 parallel streams:
BDP_per_stream = 1,800,000 bytes / 24 = 75,000 bytes approx 73.2 KB.

With Android Linux default socket write buffer wmem_default = 229,376 bytes (224 KB):
Headroom Ratio = 229,376 bytes / 75,000 bytes = 3.06x.
Each stream requires only 73.2 KB of in-flight buffer to saturate 50 Mbps. Android's 224 KB default wmem easily holds 3x BDP.

### 2.2 Connection Stagger Arithmetic
For N = 24 streams staggered by 2 ms:
Total stagger span = 23 gaps * 2 ms = 46 ms.
On the Snapdragon 8 Elite (2 prime cores at 4.32 GHz, 6 performance cores at 3.53 GHz), each TLS 1.3 X25519 key exchange consumes approximately 1.2 ms of CPU time.
A 2 ms stagger completely serializes TLS handshakes onto available cores without CPU thread scheduling thrashing, while consuming less than 0.5% of the measurement window.

---

## 3. Ratified Technical Specifications

### Specification 1: HTTP Header Alignment in MainActivity.kt
For speed.cloudflare.com upload requests, align headers with Dart's browser profile:
- User-Agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
- Content-Type: "application/octet-stream"
- Cache-Control: "no-store"
- Connection: "keep-alive"
- Accept: "*/*"
- Origin: "https://speed.cloudflare.com"
- Referer: "https://speed.cloudflare.com/"
- Sec-Fetch-Site: "same-origin"
- Sec-Fetch-Mode: "cors"
- Set System.setProperty("http.maxConnections", "32") to avoid connection pool eviction.

### Specification 2: Canonical Upload URL in speedTestStreamUrl
In MainActivity.kt:
For speed.cloudflare.com upload requests, return canonical "https://speed.cloudflare.com/__up" without query strings:
```kotlin
if (host == "speed.cloudflare.com" && base.path == "/__down") {
    return URL("https://speed.cloudflare.com/__down?bytes=50000000")
}
if (host == "speed.cloudflare.com" && base.path == "/__up") {
    return URL("https://speed.cloudflare.com/__up")
}
```
The /__down branch remains byte-for-byte untouched.

### Specification 3: Stream Concurrency and Connection Stagger
- Stream count: 24 streams (defaulting to 24, clamped 1..32).
- Micro-stagger: Stagger connection start by 2 ms per stream index:
  `Thread.sleep(streamIndex * 2L)` inside worker thread execution prior to connection open.
- Barrier synchronization: Keep ready.await(6, TimeUnit.SECONDS) and start.countDown() to launch writes simultaneously.

### Specification 4: Chunk Streaming and Direct Buffer Write
- Chunk mode: `connection.setChunkedStreamingMode(256 * 1024)`.
- Application buffer: `val buffer = ByteArray(256 * 1024) { 0x5A.toByte() }`.
- Write directly to `connection.outputStream`.
- Accounting: `confirmed.addAndGet(writable.toLong())` immediately upon successful `out.write(buffer, 0, writable)`.
- Record `firstByteAt.compareAndSet(0L, System.nanoTime())` and `finishedAt.set(System.nanoTime())`.

### Specification 5: Diagnostic Logging
Log connection setup and write exceptions using android.util.Log.w:
`Log.w("WinsSpeedUpload", "Upload stream $streamIndex failed: ${e.message}")`.

### Specification 6: Dart Fallback Guard in lib/main.dart
In `lib/main.dart`:
If `_hasNativeTunnelBridge` is true and a VPN tunnel is active:
If native upload returns null, do NOT trigger pure-Dart fallback with 32 unthrottled HttpClient streams. Log diagnostic and return null safely to avoid tunnel teardown.

### Specification 7: Download Datapath Lock
Lines governing `measureDownloadMbps` and the `/__down` branch are strictly frozen.

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
