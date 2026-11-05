# Stage 1 Submission: stage1_opus5

I'm working through the technical determination, focusing on the HttpURLConnection setup with chunked streaming, header alignment, and stream count math against a 1000 Mbps target, factoring in RTT and bandwidth-delay product to figure out where the exception actually got thrown during connection setup.

The likely culprit is either setFixedLengthStreamingMode with an oversized content length, a missing setDoOutput call, main-thread network access, or a Cloudflare 403 tripping an IOException during getOutputStream write. I also need to check the VPN tunnel angle: with tx_packets frozen, no bytes are actually crossing the tun interface, so I need to figure out whether upload sockets are being protected or bypassed depending on whether the app itself is the VPN client.

But that frozen tx_packets count of 91,367 alongside a claimed 1.55 Gbps download is physically implausible, since download at that speed necessarily generates a large volume of ACK traffic that should register as tx. This points to either ACKs bypassing tun via a protected socket path, or the counter snapshot simply being stale :  a measurement artifact worth flagging as a strong differentiator, along with the packet-rate math (roughly 129k pps at 1500 MTU, with ACK ratios shifting under GRO).

Now I'm working through sizing for the upload target: at 1000 Mbps aggregate across 24 streams, each stream needs about 41.67 Mbps, and using an estimated RTT of ~15ms through the tunnel, the per-stream bandwidth-delay product comes to roughly 78 KB :  so SO_SNDBUF should be set well above 2x that, around 512 KB, with wmem_max sized to cover the aggregate BDP of about 1.875 MB.

For write chunking, 256 KB buffers keep syscall rates manageable (~480/s total across streams). Staggering stream starts by 3ms each keeps the ramp-up skew negligible relative to the measurement window, and I'm planning to discard the first 500ms of data to exclude TCP slow-start effects, since reaching the target cwnd takes roughly 2.4 RTTs.

A bigger concern is HTTP/2 connection coalescing on Android's HttpURLConnection: if all 24 "streams" collapse onto a single H2 connection, I'd lose the parallelism I'm trying to measure due to head-of-line blocking and single-flow limits. I think the safer approach is to bypass HttpURLConnection entirely and write raw HTTP/1.1 over SSLSocket directly, giving explicit control over separate TCP connections.

This raw socket approach also lets me tune SO_SNDBUF and TCP_NODELAY directly and guarantee 24 truly distinct TCP flows, which matches the mandate's request for exact socket configuration. I'll present both a minimal HttpURLConnection-based fix and the raw SSLSocket implementation as the stronger recommendation, since HttpURLConnection simply can't expose the socket-level controls needed here: and I should also use fixed-length or chunked streaming mode so the body isn't buffered entirely in memory.

Chunked encoding to Cloudflare's __up endpoint generally works, but I'm second-guessing whether some edges reject Transfer-Encoding: chunked, so a fixed-length approach with a defined content length feels safer. I'm working through the timing math: 25MB chunks take about 4.8s at the observed throughput, while 100MB chunks take too long, so I'm landing on a loop of moderate fixed-length POSTs sized to fit within each stream's time budget.

I also realize counting bytes written to the socket overstates actual throughput because of send-buffer buffering, but this only introduces roughly 1% error given typical buffer sizes and a 10s measurement window, which seems acceptable. In steady state, write() blocks once the buffer fills, so the write rate should converge to the actual wire rate.

For the Dart fallback, I want to gate it so it only triggers if native returns null, and even then have it retry native once rather than immediately spawning a fallback stream storm :  catch blocks should log failures and increment counters, requiring a confirmed quorum (like 16 of 24) before declaring failure.

I also need to provide the specific Linux sysctl settings for the gateway box to tune socket buffer sizes and backlog, since the mandate requires exact values.

Adding more sysctl parameters :  congestion control, queueing discipline, TCP tuning flags, and UDP buffer minimums since the tunnel protocol likely runs over UDP, plus IP forwarding and connection tracking limits.

I'm also thinking through MTU math for the Winn v3 protocol over UDP, landing on roughly 1440 for the tun interface and 1400 for TCP MSS, then calculating that gigabit throughput at that packet size means about 89k packets per second :  which pushes into territory where single-threaded UDP reads on the gateway CPU could bottleneck without recvmmsg/sendmmsg batching. I'm also flagging that Android's VpnService reading from the tun fd single-threaded faces a similarly tight per-packet time budget at that packet rate.

The upload path (phone reading from tun and encrypting) is likely slower than the download path (writing to tun), since Android's read path tends to lag. I'm weighing whether raising the tun MTU beyond 1440 could help throughput, but the fiber WAN's 1500 MTU means larger tunnel packets would need fragmentation, so I want to present this as an optional tradeoff with the underlying math rather than a firm recommendation.

I'm also working out the ideal number of parallel streams, landing on 24 based on a contention model balancing per-stream throughput against thread scheduling overhead :  factoring in the gateway's 8-core/16-thread CPU versus the phone's more limited big-core count.

The syscall overhead turns out trivial since crypto dominates: ChaCha20 at ~1.5 GB/s per core barely uses a fraction of one core for 1000 Mbps. The real contention comes from TLS handshake bursts :  32 simultaneous X25519 keygen + ECDSA verify operations at ~1.2ms CPU each would create a significant spike of concurrent load.
