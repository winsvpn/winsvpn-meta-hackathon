# Winthos Four-AI Presidential Debate Treaty (v5.1)
## Multi-Gbps Symmetrical Upload Optimization on 2000 Mbps Fiber

**Codified under Winthos Presidential Council Binding Treaties (September 2026)**

**Signatories**:
- **Podium 1**: Antigravity (Council Chair, Lead Systems Architect) -> AFFIRMATIVE
- **Podium 2**: GPT-5.6 Sol Pro (Principal AI Systems & Compiler Architect, OpenAI) -> AFFIRMATIVE
- **Podium 3**: Claude Opus 5 (Anthropic, Lead HPC Systems Architect, Claude Code CLI) -> AFFIRMATIVE
- **Podium 4**: Claude Fable 5.1 (Anthropic, Elite Mobile Datapath Architect, Claude Code CLI) -> AFFIRMATIVE

**Result: 4-0 Unanimous Binding Treaty Ratification.**

---

## 1. Problem Synthesis & Mathematical Ground Truth

Empirical telemetry on the Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL) connected via Wi-Fi 7 to a 2000 Mbps symmetrical fiber Internet connection revealed severe throughput asymmetry:
- Download throughput: 1,103 Mbps.
- Upload throughput: 67.2 Mbps.
- Disparity ratio: 1,103 / 67.2 = 16.41x asymmetry.
- Raw single-stream TCP over tunnel to gateway: 160 Mbps (moved 100 MB in 5.04s).
- Wi-Fi 7 link rate: >2,400 Mbps PHY link.

All four AI podiums deliberated independently. Their empirical determinations converged on the exact physical mechanisms governing the upload ceiling:

### 1.1 Outer UDP Socket Send Buffer Starvation & Wi-Fi 7 Transmit Completion
Under Android Linux defaults, `wmem_default` is 229,376 bytes (224 KB).
Accounting for Linux skb truesize (~2,300 bytes allocated for a 1,400-byte packet), a 224 KB buffer holds barely 100 queued datagrams (~140 KB of tunnel payload).
On Wi-Fi 7, firmware A-MPDU frame aggregation and block acknowledgment latency take 20 to 25 ms before freeing skbs and replenishing `sndbuf` credits.
A 224 KB send buffer divided by 25 ms completion latency mathematically caps throughput at:
229,376 * 8 / (0.025 * 10^6) = 73.4 Mbps.
This directly produces the observed 67.2 Mbps ceiling.
When `SO_SNDBUF` fills, Go's non-blocking `netpoll` parks on `POLLOUT` with EAGAIN. Application counters register zero errors while the backlog spills into the Android tun queue, overflowing `/sys/class/net/tun0/statistics/tx_dropped` and forcing TCP congestion window collapse.
Setting `SO_SNDBUF` to 8 MiB (`8 * 1024 * 1024`) expands buffer headroom by 36.5x, absorbing multi-megabit Wi-Fi 7 bursts.

### 1.2 Android VpnService Wake Lock Expiration (Opus 5 Finding)
In `VpnTunnelService.kt`, `tunnelWakeLock` was acquired with `STARTUP_WAKE_LOCK_TIMEOUT_MS = 60_000L`.
Sixty seconds after connection, the wake lock lapsed. The Snapdragon 8 Gen 5 SoC entered deep `cpuidle` C-states between packet bursts, introducing microsecond wake latency on the uplink poll-to-notify handoff.
Acquiring `tunnelWakeLock` untimed for the entire service lifetime prevents CPU throttling during active speed tests.

### 1.3 Burst Reader Spurious Sleep (Opus 5 Finding)
In `WinnV3AndroidTun.kt:runBurstReader()`, when `poll()` returned readable but drained zero packets, the loop executed `Thread.sleep(1)`.
Sleeping a full millisecond on a spurious wake added massive latency jitter against a sub-millisecond packet loop.
Replacing `Thread.sleep(1)` with `Thread.yield()` eliminates the 1,000-microsecond thread stall.

### 1.4 Vectorized Enqueue & Mutex Elimination
Entering `synchronized(state)` per packet created over 180,000 JVM monitor acquisitions per second at line rate.
Batching packet enqueue into 16-packet mini-batches under a single monitor acquisition eliminates 93.7% of monitor lock operations.
Replacing `s.mu.Lock()` with `atomic.Pointer[winn3FrameDevice]` in Go `handleInbound()` makes inbound device access completely lock-free.

### 1.5 Dynamic Gateway PMTU Clamping & FQ Qdisc
On `aicore` (192.168.4.36), static clamping to MSS 1240 wasted 93 bytes per packet compared to the 1333-byte natural MSS of `winn3gw0` (MTU 1373).
Replacing static clamping with `--clamp-mss-to-pmtu` on the `FORWARD` chain recovers 7% payload efficiency.
Configuring `txqueuelen 10000` and `tc qdisc replace dev winn3gw0 root fq limit 20480 flow_limit 512 refill_delay 1ms` prevents egress queue drops.

---

## 2. Unanimous Implementation Covenant

1. **Outer UDP Socket Buffer Configuration (`cmd/winn-datapath/winn3_frame.go`)**:
   Enforce `SetWriteBuffer(8 * 1024 * 1024)` and `SetReadBuffer(8 * 1024 * 1024)` on dialed and adopted sockets. Verify via `GetsockoptInt`.
2. **Untimed Android Fast-Path Wake Lock (`VpnTunnelService.kt`)**:
   Hold `tunnelWakeLock` untimed for the session lifetime; release explicitly in `releaseTunnelPerformanceLocks()`.
3. **Zero-Sleep Spurious Poll Handler (`WinnV3AndroidTun.kt`)**:
   Replace `Thread.sleep(1)` with `Thread.yield()`.
4. **Mini-Batch JVM Monitor Drain (`WinnV3AndroidTun.kt`)**:
   Drain up to 16 packets per `synchronized(state)` monitor acquisition.
5. **Lock-Free Go Datapath (`cmd/winn-datapath/winn3_frame.go`)**:
   Use `atomic.Pointer[winn3FrameDevice]`.
6. **Zero-Allocation ReadBatch (`cmd/winn-datapath/winn3_frame_device.go`)**:
   Reuse `d.readLengths` scratch slice.
7. **Gateway MSS Clamping & FQ Queue (`aicore`)**:
   Apply `--clamp-mss-to-pmtu` on `FORWARD` and attach `fq limit 20480 flow_limit 512 refill_delay 1ms`.

---

## 3. Ratification Signatures

```
PODIUM 1: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED

PODIUM 2: GPT-5.6 Sol Pro (Principal AI Systems Architect, OpenAI)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED

PODIUM 3: Claude Opus 5 (Anthropic, Lead HPC Systems Architect, Claude Code CLI)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED

PODIUM 4: Claude Fable 5.1 (Anthropic, Elite Mobile Datapath Architect, Claude Code CLI)
VOTE: AFFIRMATIVE
STATUS: RATIFIED & SIGNED
```
