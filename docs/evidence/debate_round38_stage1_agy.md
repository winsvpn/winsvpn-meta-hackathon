# Round 38 stage1: agy

### Verification of Packet State

* **Item 1 (Buffer Revert)**: VERIFIED. Reverting carrier buffers to 8 MiB across both DialUDP and adopted-descriptor dial paths restores baseline throughput parameters following empirical refutation of the 4 MiB bufferbloat hypothesis. Passing results across carrier, tun, and cmd/winn-datapath unit tests confirm datapath regression safety.
* **Item 2 (Warm-up Revert)**: VERIFIED. Removing the one-second warm-up eliminates artificial latency overhead. Retaining the complete experimental measurement matrix in MainActivity.kt preserves necessary engineering provenance.
* **Item 3 (Dynamic MTU)**: VERIFIED. Deriving the inner MTU from the underlying link with floor 1280, ceiling 1440, and IPv6 minus 32 adjustment prevents packet fragmentation across heterogeneous radio carriers. Hardware verification at 767/767 Mbps on Wi-Fi validates PMTUD kernel integration alongside fleet-wide 1280 defaults.
* **Item 4 (Spain Management Restoration)**: VERIFIED WITH RESIDUAL BLOCKER. LUKS volume unlocking and boot enablement of wg-quick@wghub0 restore local cryptographic readiness across endpoints. The IONOS infrastructure firewall drop of inbound UDP 51820 on kansas represents an external firewall policy blocker outside host OS control (UNVERIFIED-LIVE).
* **Item 5 (RV-2 Status)**: CONFIRMED. The policy fork between local-only routing and suppression persistence remains escalated for sovereign user adjudication.

### Attack on Endpoint-Selection Interpretation (Mandate 1)

* **Alternative Mechanism**: Client transport protocol and application layer flow control asymmetry. The speedtest target families differ in their primary upload destination: Global Backbone targets speed.cloudflare.com first, whereas North America Backbone targets cachefly first. Cloudflare endpoints enforce HTTP/2 or HTTP/3 stream multiplexing with strict stream-level receive window limits (typically 64 KB or 256 KB) and server-side connection pacing (UNVERIFIED-LIVE). Cachefly endpoints accept direct HTTP/1.1 POST streams with deep TCP receive windows and no stream-level flow control bottlenecks (UNVERIFIED-LIVE). In addition, client-side Dart HttpClient socket buffer boundaries under HTTP/2 stream multiplexing can restrict single-stream throughput to 230-300 Mbps, regardless of tunnel capacity. Alternatively, the Canada node exit IP may face upstream transit traffic shaping specifically on peering links to AS13335 (Cloudflare), while direct transit to AS33182 (Cachefly) remains unthrottled (UNVERIFIED-LIVE).
* **Discriminating Measurement**: Execute raw single-stream direct uploads via curl from the Canada gateway host directly to both targets, bypassing the VPN tunnel: compare `curl -4 --http1.1 -T /tmp/testfile https://speed.cloudflare.com/__up` against `curl -4 --http2 -T /tmp/testfile https://speed.cloudflare.com/__up` and `curl -4 --http1.1 -T /tmp/testfile https://cachefly.speedtest.net/upload`. If direct uploads to Cloudflare reach 700+ Mbps under HTTP/1.1 but collapse to 230-300 Mbps under HTTP/2, the root cause is transport protocol flow control rather than geographic anycast routing. If Cloudflare upload remains clamped at 230-300 Mbps across all protocols while showing packet loss, transit peering policing is the primary driver.

### Product Fix Vote (Mandate 2)

* **Vote**: Option C (ORDER-SWAP), with regional target generalization.
* **Reasoning**: Speedtests exist to measure physical tunnel forwarding capacity, which is empirically verified at 681-790 Mbps by North America runs and parallel socket transfers. High-threat users require predictable, deterministic operational feedback; presenting numbers that fluctuate threefold across successive runs erodes confidence and prompts false suspicions of tunnel degradation or interception. Option B (REPORT-BOTH) introduces dual-row interface clutter that confuses non-technical users about actual network performance. Option A (STICKY-BEST) incurs extra measurement latency and consumes unneeded cellular data by running duplicate test passes on connection setup. Reordering target lists to place the verified high-throughput regional endpoint first delivers a stable, accurate reflection of datapath capacity, while retaining Global Backbone as a resilient fallback.

### RV-2 Recommendation (Mandate 3)

* **RV-2 Recommendation**: Retain option (c) to keep guardrail suppression active, ensuring infrastructure tokens and internal network probes never reach external inference providers, while accepting the public unauthenticated enumeration residual as a known low-impact trade-off.

Podium: Gemini 3.8 Flash High (Antigravity agy)
