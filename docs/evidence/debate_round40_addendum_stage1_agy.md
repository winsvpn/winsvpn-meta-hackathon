# Round 40 addendum stage1: agy

### Ingress Ceiling Candidate Re-ranking (Mandate 1)

Candidate (i), loss-limited TCP, ranks as the single most probable cause of the phone inner plateau. Fact 3a demonstrates that the WAN path from this residential LAN to Canada enters persistent packet loss once offered rates reach 400 Mbps, showing 8.27% loss at 400 Mbps and 7.40% at 550 Mbps. When 32 concurrent TCP flows encounter 5 to 8% random packet loss, standard TCP congestion control repeatedly cuts congestion windows. This collapse restricts aggregate inner goodput to the 358 to 445 Mbps plateau, even though unmanaged UDP reaches 560 to 580 Mbps. The falsification test requires running an inner UDP stream across the tunnel at 600 Mbps offered rate; if inner UDP reaches 550 Mbps while inner TCP remains pinned at 440 Mbps, candidate (i) is confirmed, whereas an inner UDP stall at 440 Mbps kills candidate (i).

1. **Candidate (i): Loss-limited TCP**. Upstream path packet loss of 5 to 8% at 400 to 600 Mbps triggers window backoff across 32 concurrent TCP flows, restricting aggregate inner goodput to 358 to 445 Mbps while raw unmanaged UDP delivers 560 to 580 Mbps.
2. **Candidate (iv): Token window 1024 pacing the carrier loop**. DefaultTokenWindow 1024 allows an inbox half-window of 512 frames with 511 reorder tolerance. At 1400 bytes per frame, 1024 outstanding frames represent 1.43 MB of inflight data. If the round-trip latency to Canada is 25 to 30 ms (UNVERIFIED-LIVE), the maximum unacknowledged throughput permitted by the token window equals (1024 * 1400 * 8) / 0.026 s = 441 Mbps, matching the observed 437 to 445 Mbps ceiling.
3. **Candidate (ii): Phone Wi-Fi radio uplink limitations**. While the phone achieved 1166 Mbps downlink, mobile Wi-Fi chipsets typically allocate fewer spatial streams and lower transmit power for uplink compared to a MacBook Wi-Fi 6E link rate of 1729 Mbps. Thermal limits or 2x2 MIMO uplink constraints on the handset could constrain physical airtime transfer to approximately 470 Mbps carrier rate.
4. **Candidate (iii): Winn client send path**. The Android userspace pipeline (TUN burst reader, cross-seam IPC, AF_UNIX batching, and AEAD encryption loop) demonstrated an instantaneous burst capacity of 644 Mbps inner offered rate in Fact 3e. Although processing could encounter thermal throttling during sustained runs, the demonstrated 644 Mbps burst rules out a hard architectural bottleneck at 445 Mbps.
5. **Candidate (v): Gateway side**. Ruled out and placed last. Fact 1 proves zero session inbox drops occurred during the 358 to 445 Mbps runs. Fact 3a confirms Canada drained 560 to 580 Mbps at 600 Mbps offered with zero UdpRcvbufErrors, zero UdpInErrors, and flat CPU utilization.

### Ruling on Round 41 Carrier Send Pacing (Mandate 2)

Carrier send pacing is ratified. Pacing plausibly recovers inner TCP throughput toward the 560 to 580 Mbps UDP knee by eliminating micro-burst queue saturation. When 32 inner TCP streams burst simultaneously, instantaneous packet bursts overwhelm intermediate access buffers, causing synchronized tail drops and subsequent window collapse. Metering carrier sends with a token bucket smooths packet departures, preventing buffer spills while allowing inner TCP flows to stabilize near the path UDP capacity. This approach aligns transmission rates with physical link constraints rather than contesting them.

* **Bucket rate source**: Derived dynamically from the path discriminator estimate, initialized to 90% of the measured UDP path capacity (520 Mbps to track the 560 to 580 Mbps knee).
* **Burst size**: Sized at 16 to 32 datagrams (approximately 22 KiB to 45 KiB), matching standard kernel batch boundaries without inducing buffer queue spikes at access hops.
* **Engine placement**: Positioned in the client carrier dispatch loop immediately following AEAD encryption and sequence allocation, directly governing carrier socket transmission calls.
* **Interaction with token window and D23 geometry**: The pacer operates downstream of token acquisition, releasing granted frames according to the bucket schedule without holding frames beyond token expiration. This ensures carrier bursts never exceed the gateway inbox drain capacity of 512 frames per RTT, maintaining D23 invariants.
* **Proof measurement**: Conduct an A/B benchmark of 32-stream inner TCP ingest with pacing active at 520 Mbps versus unpaced transmission; an increase from 445 Mbps toward 500+ Mbps alongside reduced TCP retransmissions validates the design.

### Ruling on the 1000/1000 Target (Mandate 3)

Sustaining 1000 Mbps upload is physically impossible on this specific residential access network. Fact 3a confirms that unencapsulated UDP to Canada caps at 560 to 580 Mbps with 5 to 8% packet loss under 600 Mbps offered load. Because raw UDP cannot cross 600 Mbps without loss over this WAN path, VPN encapsulation cannot attain 1000 Mbps. This limitation represents an owner-report item reflecting an asymmetrical residential internet subscription (such as 2000/500 Mbps). Demonstrating a 1000 Mbps symmetrical figure requires testing across a dedicated symmetrical fiber connection or high-capacity datacenter link.

* **2000/500-class home plan promise**: The product should guarantee line-rate saturation of provisioned uplink capacity, delivering 450 to 480 Mbps sustained upload (90 to 95% of the physical ISP cap) while mitigating bufferbloat.
* **2000/2000-class plan promise**: The product should target 1000+ Mbps symmetrical tunnel throughput, conditioned on symmetric fiber connectivity and client radios supporting link rates above 1.5 Gbps.

### Upstream Scrubber Impact on Winn v3 Design (Mandate 4)

Upstream dropping of constant-pattern UDP does not invalidate Winn v3 production design assumptions. Every production carrier packet, handshake, rekey, and session message is authenticated and encrypted via AEAD, producing pseudorandom ciphertexts with high entropy that pass scrubber filters. Fact 3c confirms that randomized UDP payloads traverse the path unobstructed. The finding imposes a strict architectural constraint prohibiting unencrypted static probes, zero-padded keepalives, or fixed-pattern ping frames anywhere in the datapath.

* **Production keepalives and probes**: Winn v3 ships zero constant-pattern carrier keepalives. Carrier sockets transmit opaque datagrams without native keepalive headers, while session keepalives are PING frames encapsulated inside AEAD messages with randomized silence timers and variable padding.
* **Vulnerable diagnostic tools**: Diagnostic utilities using static payloads, such as the constant-pattern UDP test ('x'*1400) or test fixtures in standalone tools, are dropped by upstream scrubbers and must be updated to emit cryptographically random bytes.

### Immediate Next Check Without Phone PIN (Mandate 5)

The single most valuable check available without the phone PIN is running the 32-stream ingest upload benchmark from the MacBook connected to the same Wi-Fi LAN. The MacBook operates on Wi-Fi 6E with a verified link rate of 1729 Mbps, ample processing capacity, and full diagnostic access. Executing both a direct 32-stream TCP upload to Canada and an in-tunnel ingest test from the MacBook provides immediate discrimination. If the MacBook achieves 550+ Mbps inner TCP through Winn v3, the 445 Mbps plateau is isolated to handset hardware or Android IPC; if the MacBook also plateaus at 440 Mbps, the ceiling is confirmed as WAN path loss dynamics.

### VERDICT

* **Item 1**: AGREE. Loss-limited TCP is the primary cause because 5 to 8% path loss above 400 Mbps forces 32 TCP congestion windows to contract below the measured 580 Mbps raw UDP capacity.
* **Item 2**: AGREE. Carrier send pacing at the bottleneck drain rate prevents queue overflow spikes at access buffers, reducing burst packet loss and allowing inner TCP goodput to approach the 560 to 580 Mbps UDP knee.
* **Item 3**: AGREE. A 1000 Mbps upload target is unachievable on this residential vantage because raw unencapsulated UDP caps at 560 to 580 Mbps with 5% loss, requiring symmetrical fiber access to demonstrate gigabit uplink speeds.
* **Item 4**: AGREE. Upstream scrubbing of constant-pattern UDP does not invalidate Winn v3 production design because all carrier packets are AEAD ciphertext, but all diagnostic probes and test fixtures must use high-entropy randomized payloads.
* **Item 5**: AGREE. Executing the 32-stream ingest upload benchmark from the MacBook on the same Wi-Fi LAN isolates phone radio and Android CPU constraints from WAN path limits without requiring the phone PIN.

Podium: Gemini 3.8 Flash High (Antigravity agy)
