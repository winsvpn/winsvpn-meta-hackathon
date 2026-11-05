# Stage 1 Submission: stage1_fable51

I need to work through the technical debate on fixing the upload speed test, covering the kernel datapath from the tun interface through the VPN engine and out over Wi-Fi, while keeping the writing style punchy and avoiding certain formatting conventions.

For the MTU math, I'm reasoning through a plausible overhead budget for the Winn protocol (outer IP/UDP headers plus a header and auth tag), landing on a tun MTU around 1440 and an inner TCP MSS near 1388-1400, while flagging that this needs verification against the actual interface config rather than assumed as fact.

Then I pivot to the root cause: since tx_packets on the tun never increments, nothing ever reaches the tunnel, which means the failure happens upstream at the socket connect stage, likely tied to DNS resolution or TLS handshake issues when the app calls getOutputStream().

Actually, I'm reconsidering the User-Agent blocking theory -- a Cloudflare 403 would only occur after a completed TLS handshake, which requires packets to have crossed the tun already. Since tx_packets is frozen at zero delta, that rules out an HTTP-level rejection and points instead to something failing before any network traffic occurs, like DNS resolution, socket binding/protection, or a malformed URL.

I'm also considering whether the speed test app's sockets might bypass the tun entirely via VpnService.protect, which would explain a frozen tx_packets count even if the connection technically succeeds elsewhere, though this seems to conflict with the reported download stats going through the tunnel.

My leading hypothesis now is a classic HttpURLConnection mistake: calling getOutputStream() without setting doOutput=true throws a ProtocolException immediately, before any network I/O occurs -- which would perfectly explain zero tun packets during the failed upload attempt.

Since the actual exception is being swallowed, I can't be certain of the true cause: it could be a ProtocolException from doOutput not being set, an IllegalStateException from header ordering, or something related to 32 concurrent connections exhausting resources locally before any packet is sent. Without seeing the actual code, my best move is to recommend logging the exception's class and message so the real cause becomes visible.

There's also the possibility this ties to the Dart HttpClient fallback: 32 concurrent uploads with large in-memory bodies could trigger low-memory conditions, causing the engine's frame loop to exit if the tunnel fd hit EOF or the VpnService got revoked under memory pressure.

I'm also weighing throughput math: hitting >1000 Mbps upload with 16-24 streams means each stream needs roughly 42-62 Mbps, and with an ~8ms RTT to the edge the BDP per stream stays small (tens of KB), so default socket buffers should be sufficient: the bottleneck is more likely elsewhere, like the engine's per-flow table overflowing from a burst of 32 simultaneous SYNs plus data.

I'm now checking CPU cost: at 1000 Mbps with 1400-byte inner packets that's about 89,286 packets/sec, giving roughly 11.2 µs per packet per core, and AES-GCM on a Snapdragon 8 Elite Gen 2 core should encrypt that payload in well under a microsecond thanks to ARMv8 crypto extensions, so raw crypto throughput shouldn't be the limiting factor either.

The real bottleneck is the tun read/write syscall overhead, since Android's VpnService doesn't support batched packet reads on tun, meaning it's one syscall per packet at roughly 2-4 µs, which still fits comfortably within a core or two. I'm also weighing the asymmetry between download and upload paths, since upload adds the app-side TLS encryption cost on top of the kernel segmentation and tun routing overhead.

Then there's the MTU question: if the tun MTU matches the outer transport's MTU too closely, full-size upload packets risk fragmentation at the outer layer, while download packets already get MSS-clamped by the gateway. That mismatch would manifest asymmetrically: upload breaking while download stays fine: which feels like a strong diagnostic clue worth pursuing.

accounts for uncertainty in outer IP family, giving 1420 either way. That yields about 91.2% payload efficiency (1368/1500), so at 2000 Mbps WAN the goodput ceiling is roughly 1824 Mbps, and Wi-Fi 7's real-world MAC throughput (~2250 Mbps) comfortably clears the 1000 Mbps upload target, with the Ryzen 7 8845HS's AES-NI handling decapsulation fine. Now I'm turning to comparing connection counts of 16, 24, and 32 streams and their per-connection handshake costs.

With 32 simultaneous handshakes, the CPU load from ECDHE and cert verification concentrates around 40 ms in the first 50 ms of the test, so staggering matters. Staggering 24 streams at 3 ms apart spreads that load over about 69 ms, which is negligible against a 10 s test, and TCP slow start reaches the needed cwnd within roughly 5 RTTs (~40 ms), giving a full ramp-up time to target rate of about 200 ms.

I'm settling on 24 connections since throughput gains diminish past roughly 16 streams -- Cloudflare's own speed test uses only a handful -- and extra streams beyond that mainly add contention rather than bandwidth, while 24 still provides margin against per-connection ceilings at some edge colos.
