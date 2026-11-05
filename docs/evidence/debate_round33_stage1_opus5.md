# Stage 1 Submission: stage1_opus5

I need to build a rigorous technical case, with math, code diffs, sysctls, and socket configs, avoiding em dashes and banned words. Looking at the numbers: 706 Mbps upload across 32 parallel HTTP/1.1 POST streams to speed.cloudflare.com/__up works out to about 22 Mbps per stream, which is a meaningful data point I want to build on.

Testing whether that per-stream figure is BDP-limited, I compute the window against an assumed RTT and find the bandwidth-delay product too small to explain it, so the real bottleneck looks like it's in the chunked write path instead: a 512 KB blind write against a 224 KB socket send buffer, combined with how HttpURLConnection's chunked streaming mode buffers and frames data before emission.

Tracing that further, OkHttp's chunked sink converts each app-level write into one chunk, copying it through 8 KB Okio buffer segments into the socket, which raises the question of whether per-chunk flush overhead is the real inefficiency versus the aggregate CPU cost of JNI calls and memcpy across 32 concurrent flows sharing one source IP to Cloudflare's anycast edge.

The more likely culprit is Cloudflare's per-connection shaping combined with congestion control across 32 competing flows causing loss and cwnd collapse, plus a measurement quirk where upload timing only counts bytes after flush/close and the response code returns: meaning connection setup, TLS handshake, and tail-drain time all get folded into the reported duration.

As for TLS overhead, the phone's crypto extensions handle AES-GCM fast enough that encryption itself isn't the bottleneck at these speeds, so it's not a hardware limitation.

Looking at the 22.06 Mbps per-stream figure more carefully, that seems to be the real clue: likely a combination of the per-stream congestion window capped by the phone's send buffer and head-of-line blocking from the write chunk size. Working out the bandwidth-delay product: to sustain 1,500 Mbps across 32 streams needs about 46.9 Mbps each, and at a 12ms RTT that means each stream only needs roughly 70 KB of buffer, well under the 224 KB allocated.

So the buffer theory doesn't actually explain the bottleneck at high stream counts, meaning something else is limiting things: likely Wi-Fi uplink asymmetry itself, since phones typically transmit with fewer spatial streams, lower power, and worse TXOP/OFDMA efficiency than they receive with, causing uplink goodput to lag well behind downlink even at the same PHY rate.

Handset A-MPDU sizes are often smaller on uplink, and sustained multi-gigabit 6 GHz uplink can trigger thermal MCS backoff on the modem/WLAN chip. Since download already hits 1,554 Mbps on the same link, the air interface clearly supports that speed in one direction, so the fix should focus on cutting per-packet overhead and eliminating the 512 KB write stalls to close the uplink gap, since uplink is typically 60-80% of downlink on comparable setups.

Applying that ratio (0.7 * 1,554 ≈ 1,088) suggests a realistic uplink ceiling of roughly 1,100-1,250 Mbps rather than parity with download, which is a useful target to engineer toward. I'm also considering the Winn Protocol v3 tunnel path itself: every uplink byte has to traverse app, TLS, TCP, the tun device read, Winn framing, and then the outer UDP socket before hitting Wi-Fi, and the runBurstReader's synchronized state lock during 64-packet mini-batch draining looks like the real serialization bottleneck, especially at ~134,000 packets/s implied by 1,500 Mbps over a 1,400-byte inner MTU.

If the lock is only acquired once per 64-packet batch that's a manageable ~2,000 acquisitions per second, but if it's held per-packet instead, that balloons to 134K lock ops/s with real contention, and a single-threaded tun reader at that packet rate with a synchronized monitor and slab copy is tight even on a fast core. For fixes, I'm thinking about the upload measurement layer in MainActivity.kt -- specifically reducing the chunked streaming size or switching to a fixed-length streaming mode with a large content length to avoid chunk framing overhead and let OkHttp handle the transfer more efficiently.

Actually the write granularity matters more: matching writes to 64 KB chunks aligned with the socket buffer, though wrapping this in a BufferedOutputStream backfires here since writes already meet or exceed the buffer size, so buffering just adds overhead instead of smoothing anything out.

On the concurrency question, if Cloudflare's edge shaping caps each stream near 22-25 Mbps, then hitting 706 Mbps implies needing roughly 32 concurrent streams, so scaling stream count is the other lever to test.

But more streams means more TLS handshakes, CPU load, Wi-Fi contention, and tunnel packet churn, plus ramp-up eating into the test window. I should extend the test duration to 10 seconds and discard the first 1.5 seconds of slow-start data, and pre-warm connections before measuring throughput.

For correctness, I want to sample steady-state bytes between t=2.0s and finish rather than counting from the start, avoiding TLS handshake and slow-start contamination. Checking the throughput formula confirms the units are right (bytes*8000/nanos = Mbps), but I notice `confirmed` only counts streams after they get a response code, so a stalled stream contributes zero and could skew the aggregate if streams don't all finish within the window.
