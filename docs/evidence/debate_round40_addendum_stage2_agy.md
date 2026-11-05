# Round 40 addendum stage2 (turn 2): agy

Turn 1 cross-examination centers on two opposing hypotheses. Opus argued that DefaultTokenWindow 1024 acts as a sender credit gate capping in-flight data to 1.43 MB, which produces a throughput ceiling of 358 to 441 Mbps across 26 to 32 ms WAN RTTs to match the observed plateau. Agy argued that 32 concurrent unpaced TCP streams cause micro-burst queue saturation at access buffers, causing packet drops that collapse congestion windows below the path's 580 Mbps UDP capability.

Because Fact A confirms that DefaultTokenWindow operates strictly on the receive side without send-side credit gates, the send-gate BDP hypothesis collapses. Fact B proves that pacing does not reduce packet loss at matched mean rates (5.83% paced versus 5.35 to 5.89% burst at 400 Mbps), eliminating the burst-queue mechanism. Handset telemetry in Fact C establishes the phone radio uplink envelope as the primary constraint, running at 470 Mbps carrier rate (68% of Calculated Tx) with 9.2% physical retries.

* **OI-1**: AGREE. Fact C measures the handset Calculated Tx at 692 Mbps with 9.2% retries capping carrier delivery near 470 Mbps, while Fact A and Fact D eliminate token-starvation and gateway-side bottlenecks.
* **OI-2**: AGREE. Fact B proves matched-rate pacing yields 5.83% loss compared to 5.35 to 5.89% for burst-32 UDP at 400 Mbps, falsifying pacing as an upload capacity recovery mechanism.
* **OI-3**: AGREE. Delivering 1000 Mbps inner throughput requires approximately 1070 Mbps carrier rate, which exceeds both the measured 560 to 580 Mbps path UDP capacity and the handset's 692 Mbps calculated Wi-Fi TX rate.
* **OI-4**: AGREE. Fact D confirms carrier/pmtud.go and carrier/doc.go emit zero unencrypted probes or fixed-pattern datagrams, guaranteeing all production wire frames are high-entropy AEAD ciphertexts.
* **OI-5**: AGREE. Pushing iperf3 via adb measures raw UDP throughput directly over the local Wi-Fi hop, isolating handset radio airtime limits from tunnel crypto and Android userspace IPC without requiring an app PIN.

NEXT: Run the adb iperf3 UDP sweep from 300 to 700 Mbps across the local LAN to isolate handset Wi-Fi airtime capacity from tunnel userspace processing.
