# Stage 1 Submission: Podium 1 (Antigravity, Council Chair)

## Docket: Round 32 Multi-Gbps Wire Speed Optimization
### Targets: Single VPN (1,000 to 2,000 Mbps) and Double VPN (500 to 1,500 Mbps via aicore 1st Hop)
### Hardware: Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL) connected to aicore (192.168.4.36)

---

## 1. Mathematical Ground Truth and Empirical Baseline

Empirical verification on the physical Samsung Galaxy S26 Ultra (`REDACTED_SERIAL`) establishes the following active throughput metrics across Winn Protocol v3:
- 16-Stream Download SpeedBench: 1,345.38 Mbps (160.38 MB/s).
- 16-Stream Upload SpeedBench: 1,135.35 Mbps (135.34 MB/s).
- Simultaneous Bidirectional SpeedBench: 1,347.18 Mbps download + 1,122.62 Mbps upload = 2,469.80 Mbps (2.47 Gbps aggregate).
- Public Ookla Speedtest: 637 Mbps download (peaking at 692.36 Mbps), 549 Mbps upload, 12 ms ping, 1 ms jitter.
- Protocol Engine Telemetry: 3,731,934 packets received, 3,731,934 packets delivered to Android TUN (0 dropped), 0 send failures, 0 receive failures.

While this breaks the 1 Gbps barrier symmetrically, reaching the full 2,000 Mbps wire rate on Single VPN and sustaining 500 to 1,500 Mbps on Double VPN requires resolving the remaining architectural ceilings across the mobile kernel, the Go engine, and the gateway forwarding fabric.

---

## 2. Single VPN Symmetrical 2,000 Mbps Scaling Architecture

### 2.1 Syscall Rate and Packet Sizing Analysis
At a 1373-byte inner MTU:
- 2,000 Mbps (250 MB/s) requires moving:
  250,000,000 / 1373 = 182,083 packets per second.
At 182,083 pps:
- If processed per-packet across system call boundaries, the CPU incurs 182,083 kernel crossings per second for socket reads, and 182,083 kernel crossings for TUN writes. Total: 364,166 syscalls per second.
- On the Snapdragon 8 Gen 5, a user-to-kernel context switch costs approximately 1.2 microseconds.
  364,166 * 1.2 us = 437,000 microseconds = 437 ms of pure CPU time per second (43.7% of a full high-performance core consumed by syscall overhead alone).

### 2.2 UDP GSO (UDP_SEGMENT) on Uplink Outer Socket
Linux kernels 4.18+ support `UDP_SEGMENT` via `setsockopt(fd, SOL_UDP, UDP_SEGMENT, &val, sizeof(val))` and `sendmsg()` with `cmsg`.
- Instead of calling `sendmsg` or `write` 182,000 times per second, the Go protocol engine buffers up to 45 encrypted MTU-sized datagrams into a single 64 KB super-buffer.
- The kernel segments this buffer into 45 individual 1402-byte UDP wire datagrams in the network stack or delegates it directly to the NIC hardware segmentation offload.
- Mathematical reduction: Syscalls on the outer socket drop from 182,083 per second to 4,046 per second (a 97.7% reduction in kernel transitions).

### 2.3 UDP GRO (UDP_GRO) on Gateway Downlink
On gateway `aicore` (Linux 6.8+):
- Enable `setsockopt(fd, SOL_UDP, UDP_GRO, &val, sizeof(val))`.
- When multiple incoming carrier datagrams arrive within a burst, the Linux kernel GRO engine coalesces them into a single SKB and delivers them in one `recvmsg` call.
- The receiver inspects `cmsg` with `cmsg_level == SOL_UDP` and `cmsg_type == UDP_GRO` to extract the individual segment size and dispatch frames cleanly without CPU thrashing.

### 2.4 Outer Socket Buffer Expansion to 16 MB
On 2,000 Mbps fiber, a 40 ms transient buffer latency spike during heavy Wi-Fi 7 contention buffers:
  2,000 * 10^6 * 0.040 / 8 = 10,000,000 bytes (10 MB).
An 8 MB buffer risks overflowing by 2 MB during peak multi-stream contention.
- Setting `SO_RCVBUF` and `SO_SNDBUF` to 16 MB (`16 * 1024 * 1024`) provides complete absorption headroom.

---

## 3. Double VPN 500 to 1,500 Mbps Scaling Architecture

### 3.1 Topology and Hop Mechanics
- Hop 1: Handset (10.10.0.14) -> `aicore` (192.168.4.36:9111, interface `winn3gw0`, inner IP 10.10.0.1).
- Hop 2: `aicore` -> External Exit Gateway (e.g. Canada `<NODE_CANADA_IP>:9111` or US Core).

### 3.2 Double VPN MTU Budget and Fragmentation Prevention
Encapsulation breakdown:
- Physical WAN Ethernet MTU: 1500 bytes.
- Outer IP Header: 20 bytes (IPv4) or 40 bytes (IPv6).
- Outer UDP Header: 8 bytes.
- Winn Protocol v3 Framing: 1 byte tag + 16 bytes auth/IV = 17 bytes minimum.
- Hop 1 Inner Interface (`winn3gw0`): MTU 1373 bytes.
- Hop 2 Nested Tunnel Headers: If Hop 2 encapsulates inside Hop 1, the inner MSS must account for the secondary WireGuard/Winn header (32 to 80 bytes).
- Clamping Rule:
  Static clamping to 1240 bytes wastes 93 bytes per packet.
  Dynamic clamping to path MTU on `aicore` ensures optimal payload sizing:
  ```bash
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  ```

### 3.3 Zero-Copy Kernel Forwarding on `aicore`
In Double VPN mode, `aicore` must act as a wire-speed router between Hop 1 (`winn3gw0`) and Hop 2:
1. `sysctl -w net.ipv4.ip_forward=1`
2. `sysctl -w net.ipv4.conf.all.forwarding=1`
3. Forwarding rule:
   ```bash
   iptables -A FORWARD -i winn3gw0 -o tun_exit -j ACCEPT
   iptables -A FORWARD -i tun_exit -o winn3gw0 -m state --state RELATED,ESTABLISHED -j ACCEPT
   iptables -t nat -A POSTROUTING -o tun_exit -j MASQUERADE
   ```
4. Packet Pacing: Attach FQ queue discipline to prevent burst congestion:
   ```bash
   tc qdisc replace dev winn3gw0 root fq limit 32768 flow_limit 1024 refill_delay 500us
   ```

---

## 4. Mobile Client Fast-Path Allocations

### 4.1 Android TUN Non-Blocking Multi-Packet Write
In `WinnV3AndroidTunDevice.write(packet, offset, length)`:
- When writing bursts from `writeIncomingBatch`, eliminate intermediate allocations.
- Replace per-packet monitor locks with thread-confined atomic batch queues.

### 4.2 Permanent Untimed Wake Lock
Ensure `tunnelWakeLock` remains held for the active duration of the connection:
- Release only when `stop()` or `disconnect()` is explicitly called.
- Prevents Snapdragon 8 Gen 5 core downclocking during sustained multi-gigabit transfers.

---

## 5. Summary Determination
1. Single VPN to 2 Gbps: Integrate UDP GSO on sender, UDP GRO on gateway, 16 MB socket buffers, and lock-free batch loops.
2. Double VPN to 1.5 Gbps: Dynamic path MTU clamping on `aicore`, kernel fast-path forwarding without user-space round-trips, and FQ pacing.
