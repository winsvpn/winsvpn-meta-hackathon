# Stage 2: Adversarial Cross-Podium Rebuttal
## Podium 1: Antigravity (Council Chair, Lead Systems Architect)

### 1. Challenge to Podium 2 (Sol Pro) on Buffer Drop Semantics
Disputed Claim:
> "For ordinary data, use drop-oldest on a bounded byte ring." (Sol Pro Stage 1, Line 240)

Level 1 Empirical and Level 3 Protocol Proof:
This claim is mathematically and empirically flawed for in-order TCP transport.

Dropping the oldest packet at the head of the queue deletes the lowest unacknowledged sequence number (`snd_una`). In TCP SACK (RFC 2018), SACK options report non-contiguous blocks strictly above the cumulative ACK pointer (`rcv_nxt`). A receiver that misses the queue head cannot advance `rcv_nxt` and cannot SACK the missing head itself. The cumulative ACK pointer freezes. 

The sender receives no duplicate ACKs with higher SACK blocks to trigger Fast Retransmit. The sender sits idle until the Retransmission Timeout (RTO) expires. Upon RTO expiry:
- Congestion window `cwnd` collapses to 1 MSS.
- Slow-start threshold `ssthresh` is cut to half of in-flight bytes.
- The pipeline drains, restarting from a single packet slow start.

Level 1 Empirical Proof:
Measured on the Samsung Galaxy S26 Ultra over real WAN against the Canada gateway:
- Drop-oldest: Uplink throughput collapsed to 21.5 Mbps, fluctuating between 21.5 and 255 Mbps across RTO collapse cycles.
- Tail-drop (`dropOldest = false`): Preserves head sequence numbers. The receiver issues duplicate ACKs with valid SACK blocks covering the dropped tail. Fast Retransmit fires within one RTT. Congestion window is halved, not collapsed to 1, and throughput stabilizes above 600-800 Mbps.

Podium 2 must formally concede drop-oldest and adopt tail-drop for all in-order TCP payload rings (`toEngine` and `toHost`).

### 2. Concession and Absorption of Podium 3 (Claude Opus 5) on RPS Mask `0f`
Disputed Claim Audited:
> "RPS mask `3f` is wrong, and not by a little... Two of those six are CPU 4 and CPU 5, which are hard-pinned to IRQ 36 and IRQ 37. So mask `3f` carries a 33% chance of steering your only flow onto a CPU that is already saturated with driver work... Use an explicit two-bit or four-bit mask that excludes the IRQ CPUs." (Opus 5 Stage 1, Lines 70-72)

Concession:
Podium 3's derivation is empirically and mathematically sound.
RPS computes the target CPU via `skb_get_hash`, hashing the UDP 4-tuple. For a single active tunnel session, all packets hash to one deterministic CPU index. Under mask `3f` (binary 111111 across CPUs 0-5), there is a 2 in 6 (33.3%) probability of mapping that tunnel's softirq processing directly onto CPU 4 (which is already 100% busy servicing IRQ 36 virtio0-input.0) or CPU 5 (servicing IRQ 37 virtio0-output.0).

Podium 1 formally accepts Podium 3's architecture. We replace mask `3f` with mask `0f` (binary 001111, CPUs 0 through 3):
- CPU 4: Dedicated to IRQ 36 (`virtio0-input.0`) hardware interrupts and NAPI driver polling.
- CPU 5: Dedicated to IRQ 37 (`virtio0-output.0`) hardware interrupts and TX reclamation.
- CPUs 0-3: Dedicated to RPS software protocol stack processing and `SO_REUSEPORT` application workers.

### 3. Concession and Absorption of Podium 3 on UDP GSO / GRO
Disputed Claim Audited:
> "Add UDP GSO on transmit and UDP GRO on receive... GSO superframe capacity = 46 segments... TX skb rate at 1 Gbps = 91,041 / 46 = 1,979 skbs/s. RX skb rate at 1 Gbps = 91,041 / 16 = 5,690 skbs/s. The queue was never the constraint. The 91,041 independent skb traversals per second were." (Opus 5 Stage 1, Lines 78-86)

Concession:
This is the single most decisive insight in the debate.
Verifying against the live Linux 6.8 kernel headers on Ubuntu 24.04:
- `SOL_UDP = 17`
- `UDP_SEGMENT = 103` (Generic Segmentation Offload)
- `UDP_GRO = 104` (Generic Receive Offload)
Traversing 91,041 discrete 1.4 kB skbs per second through the Linux networking stack consumes ~21,968 cycles per packet, exhausting the 2.0 GHz Haswell core. Coalescing packets into 64 kB superframes reduces stack traversals by 88% to 97%, allowing a single virtio ring pair to move 2 Gbps with ease.

Podium 1 formally incorporates `UDP_SEGMENT` and `UDP_GRO` into the binding treaty execution plan.

### 4. Challenge to Podium 2 on XPS Configuration
Disputed Claim:
> "for q in /sys/class/net/$IF/queues/tx-*; do printf '3f\n' > "$q/xps_cpus"; done" (Sol Pro Stage 1, Line 59)

Rebuttal:
As noted by Podium 3, `ens3` possesses exactly one transmit queue: `/sys/class/net/ens3/queues/tx-0`.
XPS (Transmit Packet Steering) maps CPU affinities across multiple transmit queues. When a network device possesses only a single hardware transmit queue, the kernel sends all outbound traffic through that single queue regardless of `xps_cpus`. Configuring XPS on a single-queue device is redundant and must be omitted from production scripts.

### 5. Alignment on Suricata NFQUEUE
All three podiums concur on the root cause of the XRay degradation:
- Suricata inline IPS on single NFQUEUE 0 with full packet copy has dropped 125,188 packets on inbound TCP 443.
- XRay carries TLS 1.3 payloads that cannot be inspected by Suricata without TLS interception proxies.
- Resolution: Add an explicit accept rule for established XRay TCP 443 preceding NFQUEUE, or deploy `--queue-balance 0:5 --queue-cpu-fanout --queue-bypass`. Accepting before NFQUEUE is ratified as the primary wire-speed configuration.
