# Stage 1: Independent Blind Deliberation (Blind Lock)
## Podium 1: Antigravity (Council Chair, Lead Systems Architect)

### 1. Cryptographic Feasibility on Canada VPS (Haswell Core)
The suspicion that the Intel Haswell CPU is mathematically unable to sustain wire-speed cryptography is disproven by Level 1 empirical benchmarks executed directly on the Canada VPS hardware.

Measured OpenSSL EVP throughput on the live Canada node (Linux 6.8.0-139, 2.0 GHz Haswell, 1024-byte blocks):
- ChaCha20-Poly1305: 1,218,911 kB/s (1.22 GB/s = 9.75 Gbps per core)
- AES-256-GCM: 1,611,681 kB/s (1.61 GB/s = 12.89 Gbps per core)

Mathematical Derivation (Level 3):
At 1.0 Gbps symmetrical wire speed (125 MB/s ingress plus 125 MB/s egress = 250 MB/s full duplex):
- ChaCha20-Poly1305 compute requirement: 250 MB/s / 1218 MB/s = 0.205 vCPU (20.5% of one core).
- AES-256-GCM compute requirement: 250 MB/s / 1611 MB/s = 0.155 vCPU (15.5% of one core).

Even under full duplex gigabit saturation, ChaCha20-Poly1305 consumes less than a quarter of a single Haswell core. The remaining 79.5% of that core and the other 5 vCPUs remain completely idle with respect to cipher arithmetic. Therefore, cipher exhaustion is not the cause of the 615-627 Mbps ceiling. 

Cipher agility to AES-GCM provides a modest 25% efficiency gain in cryptographic cycles (0.155 vs 0.205 vCPU), but does not unblock the transport barrier. Pinned protocol suite `winn3-x25519-mlkem768-chacha20poly1305-sha256` remains cryptographically sound and capable of multi-gigabit throughput.

### 2. The Real Ingress Bottleneck: VirtIO Single-Queue Serialization
The true throughput ceiling is architectural. It stems from hardware-level interrupt serialization combined with single-queue virtio limitations.

Empirical Telemetry:
- `ethtool -l ens3` reports `Combined: 1` with pre-set maximum `n/a`. The OVH KVM hypervisor provisions only a single virtio ring pair.
- `/proc/interrupts` demonstrates total pinning:
  - IRQ 36 (`virtio0-input.0`, 12,340,243 interrupts) is handled exclusively by CPU 4.
  - IRQ 37 (`virtio0-output.0`, 15,916,212 interrupts) is handled exclusively by CPU 5.
- Gateway posture log reveals `udp_rcvbuf_errors: 96200`.

Mechanics:
At 1 Gbps with a 1373-byte inner MTU, ingress wire rate is 91,041 packets per second. A single 2.0 GHz Haswell core executing hardware interrupts, softirq packet handling, IP stack validation, and socket queuing saturates at approximately 600-650 Mbps.

Required Kernel and Gateway Remediation:
1. Kernel Receive Packet Steering (RPS):
   Distribute packet processing across all 6 vCPUs post-interrupt:
   `echo 3f > /sys/class/net/ens3/queues/rx-0/rps_cpus`
   `echo 4096 > /sys/class/net/ens3/queues/rx-0/rps_flow_cnt`
   `sysctl -w net.core.rps_sock_flow_entries=32768`
2. Transmit Packet Steering (XPS):
   Map transmit processing across all cores:
   `echo 3f > /sys/class/net/ens3/queues/tx-0/xps_cpus`
3. Buffer Sizing to Eliminate `udp_rcvbuf_errors`:
   `sysctl -w net.core.rmem_max=67108864`
   `sysctl -w net.core.wmem_max=67108864`
   `sysctl -w net.core.rmem_default=33554432`
   `sysctl -w net.core.wmem_default=33554432`
4. Socket Multi-Worker Fanout:
   Replace the single-threaded UDP read loop in `cmd/winn3-gateway` with a `SO_REUSEPORT` socket listener pool matching `runtime.GOMAXPROCS(0)`. Each worker executes independent `recvmmsg` batches. This prevents lock contention on a single socket receive buffer.

### 3. Root Cause of Uplink Collapse Above 600-700 Mbps
When offered uplink load exceeds 600 Mbps, the session crashes completely. Two distinct failures interact here:

1. Liveness Probe Starvation:
   Control frames (keepalives, path MTU probes, session heartbeats) share the identical queue and socket buffer with high-throughput bulk data frames. Under queue saturation, control frames suffer tail drops or queue delays exceeding the handshake timeout threshold (typically 5 seconds). The gateway presumes the peer has disconnected and tears down the session.
   Fix: Introduce an out-of-band priority control ring for opcode 0x01/0x02 keepalives so that liveness packets bypass saturated data frame queues.

2. Mutex Contention in Gateway Ingress/Egress:
   In `cmd/winn3-gateway/cover_demux.go`, sharing a lock between the receive pump and session pipes introduced cross-thread blocking. Separating the read and write locks and isolating session vectors eliminates the 2,106 ms inner RTT latency spike.

3. Buffer Drop Semantics (`winn3_frame_device.go`):
   Dropping the oldest packet (`dropOldest = true`) on in-order TCP streams punches holes at the window head, forcing TCP into expensive Retransmission Timeouts (RTO) and collapsing congestion window `cwnd` to 1. Both `toEngine` and `toHost` carrying in-order TCP streams must utilize tail-drop (`dropOldest = false`). This preserves head sequence numbers and allows TCP SACK recovery without window collapse.

### 4. Suricata Inline IPS on TCP 443
Telemetry reveals 125,188 packets dropped on NFQUEUE 0.
Suricata runs in inline IPS mode on a single queue with full packet copy for TCP port 443. This is a fatal bottleneck for XRay. Every inbound TLS byte must cross kernel-userspace boundaries for inspection by Suricata before reaching XRay. Because XRay traffic is encrypted with TLS 1.3, Suricata cannot inspect application layer payloads anyway.

Resolution Contract:
1. Primary Recommendation: Accept inbound TCP 443 traffic for established XRay ports prior to the NFQUEUE rule, identical to how AWG UDP and Winn v3 port 9111 are handled.
2. Alternative Recommendation: If IPS policy mandates inspection, upgrade the rule to multi-queue CPU fanout with automatic bypass:
   `iptables -R WINVPN-INPUT <num> -p tcp -m tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-balance 0:5 --queue-cpu-fanout --queue-bypass`

### 5. AWG (Amnezia WireGuard) MTU and MSS Sizing
Current state: Inner MTU 1280, MSS clamp 1240.
Over a standard 1500-byte WAN link:
- IPv4 header (20 bytes) + UDP header (8 bytes) + WireGuard header (32 bytes) = 60 bytes overhead.
- Safe maximum inner MTU: 1500 - 60 = 1440 bytes.
- Corresponding TCP MSS clamp: 1440 - 40 = 1400 bytes.
- Payload efficiency gain: Raising MTU from 1280 to 1440 increases payload per frame by 160 bytes (12.5% increase), reducing packet processing rate from 102,400 pps to 86,805 pps at 1 Gbps.

### 6. XRay Android Client Optimization
Current state: Android XRay runs a 4 KiB pipe buffer default.
At gigabit line rates, a 4 KiB buffer requires 31,250 context switches per second between the XRay core and Android VPN service.
Action: Set `policy.levels.0.bufferSize = 4194304` (4 MB) in the generated XRay configuration.
Route direct IP traffic without Cloudflare CDN transit where unblocked paths exist, avoiding edge throttling.

### 7. Android TUN Pump Serialization (`WinnV3AndroidTun.kt`)
Current state: Handset achieved 21.5 to 255 Mbps uplink while raw WAN achieved 1,652.9 Mbps.
The cause was notifying the pump thread on the very first packet of every burst, resulting in single-packet batch processing (95,493 futex wakes and AF_UNIX writes per second).
Action:
- Set `O_NONBLOCK` on the tun descriptor via `Os.fcntlInt`.
- Read packets in a tight loop until `EAGAIN` (-1).
- Enqueue all packets without notifying.
- Issue a single `state.notifyAll()` once the kernel buffer is drained.
- Elevate pump thread priority to `Thread.MAX_PRIORITY` and `THREAD_PRIORITY_URGENT_AUDIO`.

### 8. Decoy Calculator Lockout Reset on S26 Ultra
The lockout gate in `lib/main.dart` (`_readPinAttemptState()`) reads from `vpn_settings.txt` in secure storage. Repeated failed attempts and device reboot monotonic resets have engaged the penalty timer.
Action:
Clear `pin_attempt_state` from `vpn_settings.txt` or wipe application secure storage via `pm clear org.winsvpn.app.debug`, re-seeding `user_pin.txt` with PIN `142536=`.
