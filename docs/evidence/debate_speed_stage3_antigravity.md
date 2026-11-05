# Stage 3: Synthesis and Position Lock
## Podium 1: Antigravity (Council Chair, Lead Systems Architect)

### 1. Absorbed Points
1. Root Cause of Gateway Stall and Session Collapse:
   Absorbed from Podium 3 (Claude Opus 5). The primary driver of `udp_rcvbuf_errors = 96,200` and the uplink collapse above 600 Mbps is the $O(n)$ locked linear scan in `routeQUIC()` (`cmd/winn3-gateway/cover_demux.go:284-299`).
   Derivation: Every v3 datagram matching `pkt[0]&0x80 == 0 && pkt[0]&0x40 != 0` (25% of all incoming high-entropy traffic) acquires `s.cidMu.Lock()` and linearly iterates over up to 4,096 learned CIDs doing string comparisons. At 85,150 pps (1 Gbps), 21,288 datagrams/sec enter this loop, requiring up to 8.72 x 10^7 string comparisons per second. On a 2.0 GHz Haswell core, this yields a budget of only 22.9 cycles per comparison, causing immediate CPU exhaustion and pump stalls. The pump stalling fills the 8 MiB socket buffer, drops packets in the kernel, and starves liveness probes.
   Action: Replace `routeQUIC()` with an `atomic.Pointer` to an immutable, lock-free $O(1)$ prefix map. Discontinue unauthenticated CID learning.

2. Elimination of Dead Allocations and Channel Unpacking:
   Absorbed from Podium 3. Remove `net.UDPAddrFromAddrPort(msgs[i].Addr)` in `cover_demux.go:217` (saving 5.45 MB/s of dead heap garbage under `GOMEMLIMIT=96MiB`). Batch datagram slice handoffs into `side.incoming` instead of pushing single elements through channel selects.

3. Core Steering Partitioning (RPS Mask `0f`):
   Absorbed from Podium 3 and Podium 2. Set RPS mask to `0f` (CPUs 0 through 3), isolating CPUs 4 and 5 exclusively for hardware IRQ 36 (`virtio0-input.0`) and IRQ 37 (`virtio0-output.0`). Omit `xps_cpus` as a no-op on a single transmit queue.

4. UDP GRO Unpacking Safety:
   Absorbed from Podium 2. When enabling `UDP_GRO` on Linux 6.8, parse the `SOL_UDP` ancillary control message (`gso_size`) and split coalesced superframes into discrete datagrams before submitting them to AEAD decryption.

5. Liveness Refresh on Any Authenticated Traffic:
   Absorbed from Podium 2 and Podium 3. Update `lastRx` timestamp upon receipt of any authenticated data or control frame. A session actively receiving 700 Mbps of authenticated payload must never be torn down due to delayed heartbeat probes.

6. Non-Destructive S26 Lockout Remediation:
   Absorbed from Podium 2. Do not execute `pm clear` (which wipes client keys and enrolled identities). Surgically delete `pin_attempt_state` from `vpn_settings.txt` or allow the penalty window to expire without rebooting.

### 2. Defended Grounds
1. Tail-Drop Policy for In-Order TCP Payloads:
   Maintained against Podium 2's initial Stage 1 proposal. In-order TCP payload queues (`toEngine` and `toHost`) must strictly use tail-drop. Dropping the oldest packet deletes the sequence head (`snd_una`), freezing the cumulative ACK pointer, blinding SACK recovery, and triggering repeated RTO timeouts that collapse throughput to 21.5 Mbps. Podium 2 has formally conceded this and adopted tail-drop in Stage 2.

2. Suricata Bypass for Established XRay Traffic:
   Maintained across all podiums. Inbound TCP 443 for XRay must be accepted prior to the inline NFQUEUE rule. This eliminates 125,188 packet drops and userspace copy overhead without sacrificing security, as TLS 1.3 payloads cannot be inspected inline by Suricata.

3. AWG MTU 1440 and MSS 1400 Alignment:
   Maintained across all podiums. Pinned MTU 1440 and MSS clamp 1400 eliminate 160 bytes of wasted payload per packet and prevent MTU black holes.

### 3. Irreconcilable Delta
Zero irreconcilable deltas remain. All three podiums have reached 100% technical convergence on the root causes, parameter values, kernel configurations, and architectural refactorings.
