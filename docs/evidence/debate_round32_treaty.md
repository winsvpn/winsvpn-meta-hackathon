# WINTHOS ROUND 32 PRESIDENTIAL DEBATE TREATY
## Unanimous Treaty of the Four-AI Presidential Council
### Symmetrical Multi-Gbps Wire Speed Optimization for Single VPN and Fleet-Wide Double VPN

**Date:** 2026-09-19  
**Council Composition:**
- **Podium 1 (Council Chair):** Antigravity (Gemini 3.8 Flash High)
- **Podium 2:** GPT-5.6 Sol Pro (`openai/gpt-5.6-sol-pro` via OpenRouter flex xhigh)
- **Podium 3:** Claude Opus 5 (Anthropic Claude Code CLI `--model opus --effort xhigh`)
- **Podium 4:** Claude Fable 5.1 (Anthropic Claude Code CLI `--model claude-fable-5-1 --effort high`)

---

## 1. Executive Summary & Ratification Status

The Presidential Debate Council for Round 32 convened across four stages of adversarial technical debate, formal cross-rebuttals, and synthesis position locks. All four podiums have locked their positions and unanimously ratified this Treaty.

### Core Targets Ratified:
1. **Single VPN Wire Speed:** 1,000 to 2,000 Mbps line rate (1,800 Mbps certified application payload ceiling over 2.0 Gbps physical Ethernet).
2. **Double VPN Wire Speed:** 500 to 1,500 Mbps symmetrical goodput via `aicore` (192.168.4.36) 1st hop to any data plane node in the fleet (Canada `<NODE_CANADA_IP>`, Germany `<NODE_GERMANY_IP>`, Spain `<NODE_SPAIN_IP>`, Kansas Core `<KANSAS_HUB_IP>`).
3. **Gateway Ingress Multiprotocol:** `aicore` accepts all incoming client connections (Winn Protocol v3 on UDP 9111, Winn Protocol v1 AWG on UDP 51820 with XRay fallback). Outgoing hop from `aicore` to the selected Exit Node executes exclusively over Winn Protocol v3.
4. **Physical Device:** Samsung Galaxy S26 Ultra (`SM-S948U1`, serial `REDACTED_SERIAL`).

---

## 2. Mathematical Ceiling and Physical Wire Truth

All four podiums accept the derived mathematical ceiling over physical Ethernet.

### 2.1 The Framing Equation
Given physical line rate $R = 2.00 \times 10^9 \text{ bps}$ (2,000 Mbps):

$$T_{\text{tcp}} = \frac{R}{8(I + H_o + U + W + L)} \times (I - H_{\text{inner}} - 20) \times 8$$

Where:
- $I$: Inner IP packet size (current baseline 1373 bytes).
- $H_o$: Outer IP header (20 bytes IPv4, 40 bytes IPv6).
- $U$: Outer UDP header (8 bytes).
- $W$: Winn Protocol v3 record framing and AEAD authentication tag (32 bytes).
- $L$: Physical Ethernet framing (38 bytes: 14 header, 4 FCS, 8 preamble, 12 inter-frame gap).
- $H_{\text{inner}}$: Inner IP header (20 bytes IPv4).
- Inner TCP data payload $P = I - 40$.

### 2.2 Numerical Goodput Ceilings

| Framing Overhead $W$ | Inner MTU $I$ | Outer Family | Total Wire Bytes | Packet Rate (pps) | Inner TCP Payload $P$ | Maximum TCP Goodput $T_{\text{tcp}}$ |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 32 bytes | 1373 | IPv4 | 1471 | 169,952 | 1333 bytes | **1,812.6 Mbps** |
| 32 bytes | 1440 | IPv4 | 1538 | 162,548 | 1400 bytes | **1,820.5 Mbps** |
| 32 bytes | 1420 | IPv6 | 1538 | 162,548 | 1360 bytes | **1,768.5 Mbps** |

### 2.3 Ratified Rule on 2.0 Gbps Reporting
A 2.00 Gbps Ethernet WAN line cannot yield 2.00 Gbps of TCP application data payload due to immutable wire headers. The Council formally sets 1,800 Mbps as the 100% operational line saturation benchmark in the UI. Any speed between 1,000 Mbps and 1,812 Mbps satisfies the single VPN objective.

---

## 3. Specification A: Symmetrical UDP GSO and GRO

### 3.1 Directional Parity Contract
GSO and GRO operate symmetrically across the link:
- **Upload:** Handset performs UDP GSO transmit aggregation. Gateway (`aicore`) performs UDP GRO receive coalescing.
- **Download:** Gateway (`aicore`) performs UDP GSO transmit aggregation. Handset performs UDP GRO receive coalescing.

### 3.2 Cryptographic Isolation Contract
Each inner IP packet is sealed individually using ChaCha20-Poly1305 with its own monotonic nonce *prior* to batch insertion. The Linux kernel processes ciphertext only. Nonce assignment is never deferred to the network stack.

### 3.3 Socket Ancillary Constants and Type Widths
- `SOL_UDP`: 17
- `UDP_SEGMENT`: 103
- `UDP_GRO`: 104
- `UDP_MAX_SEGMENTS`: 64
- **Ancillary Data Width Rule:**
  - `UDP_SEGMENT` transmit cmsg passes host-order `uint16` (2 bytes).
  - `UDP_GRO` receive cmsg returns host-order Linux `int` (4 bytes).
  - Explicit size checks prevent buffer overruns and endianness bugs.
- **Batch Limits:** Contiguous byte slice capped at 64 segments or 61,440 bytes (providing a 4,095-byte safety margin under the 65,535-byte IP limit).

### 3.4 Fallback Handling
If `sendmsg` returns `EINVAL`, `EIO`, or `ENOPROTOOPT`, GSO is immediately disabled on that socket for the session. The batch degrades to serial unbatched transmission. Zero packets are dropped.

---

## 4. Specification B: Mobile Client Fast-Path and Descriptor Ownership

### 4.1 Direct Descriptor Transfer
Kotlin Android host code establishes the `VpnService` tunnel and immediately transfers ownership of the file descriptor to the Go runtime using `pfd.detachFd()`.
- The Kotlin `LocalSocket` 8 MB IPC relay is completely removed.
- The 1 MB Kotlin byte accumulator is completely removed.
- Kotlin is restricted strictly to lifecycle and UI monitoring.

### 4.2 Non-Blocking TUN Polling Engine
The 60-microsecond spin-wait on `EAGAIN` is abolished.
The Go TUN reader executes non-blocking `unix.Read`. Upon receiving `EAGAIN`, it parks on `unix.Poll` using a two-element poll descriptor array:
1. The TUN file descriptor (waiting for `POLLIN`).
2. A non-blocking `eventfd` cancel descriptor.
When the session terminates, writing 8 bytes to the cancel `eventfd` instantly unparks all waiting reader goroutines with clean zero-leak cleanup.

### 4.3 Multi-Writer Flow Sharding
Multiple TUN writers are sharded by hashing the inner IP 5-tuple:
`hash(src_ip, dst_ip, src_port, dst_port, protocol) % num_writers`
This preserves packet order within individual TCP flows and prevents reordering penalties while distributing kernel `netif_rx` softirq processing across multiple performance cores.

---

## 5. Specification C: Socket Buffers and Linux Kernel Tuning

### 5.1 Handset Buffer Sizing
The handset requests 16 MB (`16 << 20`) on `SO_RCVBUF` and `SO_SNDBUF`. Linux clamps to `rmem_max` and then doubles the assigned buffer.

### 5.2 Gateway Sysctl Tuning (`aicore`)
The gateway `/etc/sysctl.d/90-win-vpn.conf` is codified as:

```ini
# Maximum socket receive and send buffers (32 MB)
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432

# Default socket buffers (16 MB)
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216

# Minimum and maximum UDP buffer scaling
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Packet processing queues
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 8192

# IP forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Queue discipline and pacing
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

### 5.3 Interface Queue Length
Set `txqueuelen` to 10,000 on `winn3gw0` and the physical WAN interface (`enp2s0` / `eth0`):
```bash
ip link set dev winn3gw0 txqueuelen 10000
```

---

## 6. Specification D: Double VPN Terminated Tunnel Architecture

### 6.1 Terminated Tunnel Routing Model
Double VPN operates as two serial terminated tunnels, not nested encapsulation:
1. **Hop 1:** Handset (10.10.0.14) connects to `aicore` (192.168.4.36:9111).
2. `aicore` decapsulates the packet into cleartext IP on kernel interface `winn3gw0`.
3. Fast-path policy routing directs the packet into Hop 2.
4. **Hop 2:** `aicore` acts as a client to the selected fleet Exit Node (Canada `<NODE_CANADA_IP>`, Germany `<NODE_GERMANY_IP>`, Spain `<NODE_SPAIN_IP>`, Kansas Core `<KANSAS_HUB_IP>`) using Winn Protocol v3.
5. The Exit Node terminates Hop 2 and forwards to the public Internet.

### 6.2 MTU Budget and MSS Clamping
- Handset inner MTU: 1373 bytes.
- Hop 1 payload: $1373 + 32 + 28 = 1433 \text{ bytes} \le 1500 \text{ physical MTU}$.
- Hop 2 payload: $1373 + 32 + 28 = 1433 \text{ bytes} \le 1500 \text{ physical MTU}$.
Because `aicore` decapsulates between hops, inner packet MTU remains constant across both links. No double-subtraction occurs.
To eliminate fragmentation from downstream path MTU variations, `aicore` applies TCP MSS clamping:
```bash
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

### 6.3 Gateway Ingress Multiprotocol
`aicore` maintains listeners for all supported ingress protocols:
- **Winn Protocol v3:** UDP 9111 (`winn3gw0`, subnet 10.10.0.0/24).
- **Winn Protocol v1 AWG:** UDP 51820 (`wgcore0`, subnet 10.50.0.0/24).
- **XRay VLESS-WS Fallback:** TCP 443 / local bridge.
All decrypted ingress packets converge on the host kernel routing table and can be dispatched across any configured Hop 2 egress tunnel.

---

## 7. Verification Protocol & Acceptance Criteria

1. **Kernel Telemetry Verification:**
   During 16-stream SpeedBench runs, `ip -s link show dev <wan>` byte counters on `aicore` must increment proportionally to the transferred payload volume.
2. **Framing Verification ($W$):**
   Capture 200 outer packets during active transfer:
   `tcpdump -ni any -c 200 'udp and port 9111' -w /tmp/winn_verify.pcap`
   Verify that maximum UDP payload length is exactly $1373 + W$.
3. **Single VPN Target Acceptance:**
   Achieve $\ge 1,000 \text{ Mbps}$ download and $\ge 1,000 \text{ Mbps}$ upload on the physical Samsung Galaxy S26 Ultra (`SM-S948U1`).
4. **Double VPN Target Acceptance:**
   Achieve $\ge 500 \text{ Mbps}$ download and $\ge 500 \text{ Mbps}$ upload across Double VPN via `aicore` to remote fleet nodes.

---

## 8. Ratification Signatures

```
[COUNCIL CHAIR - PODIUM 1]
Antigravity (Gemini 3.8 Flash High)
Status: RATIFIED

[PODIUM 2]
GPT-5.6 Sol Pro (openai/gpt-5.6-sol-pro flex xhigh)
Status: RATIFIED

[PODIUM 3]
Claude Opus 5 (claude-code-cli opus xhigh)
Status: RATIFIED

[PODIUM 4]
Claude Fable 5.1 (claude-code-cli claude-fable-5-1 high)
Status: RATIFIED
```
