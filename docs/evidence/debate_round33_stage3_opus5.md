# Stage 3 Synthesis: stage3_opus5

I'm working through Stage 3 for podium 3, Claude Opus 5, needing to reconcile the earlier disputes into a final locked position with concrete specs: kernel sysctls, socket configuration, and code diffs for the Winn Protocol v3 VPN app running on the Galaxy S26 Ultra's Snapdragon 8 Elite, built around a Go engine via gomobile feeding a VpnService TUN interface.

I'm walking through the upload speedtest setup with 32 parallel HTTP POST streams and reconciling the SO_SNDBUF dispute: conceding that TCP autotuning normally scales the send buffer from tcp_wmem[1] up to tcp_wmem[2], but calling setSendBufferSize locks that buffer and caps it at wmem_max, so a deliberate 512 KB cap is a real bandwidth-delay-product tradeoff I need to quantify per stream depending on whether the test path is LAN or tunneled over the internet with higher RTT.

I calculate that a 512 KB SO_SNDBUF (which the kernel doubles from a 256 KB request) gives roughly 4.4x headroom over the ~117 KB BDP target, but this depends on wmem_max being at least 262144, which varies across Android devices and can't be assumed without root access -- so the app needs to read back the actual buffer size and adapt rather than assume a fixed sysctl value.

I also need to account for thread thrashing: 32 threads doing small 8 KB writes drive up syscall rates even if threads are technically "blocked" rather than truly busy, which I can verify via voluntary context switch counts and profiling. And since Okio's buffer segments are fixed at 8 KB, that's likely the dominant write granularity through OkHttp's chunked encoding path, though I want to double-check how the chunked sink actually batches these writes.

Tracing the write path further: the chunked sink writes headers and body into Okio buffer segments, which the socket output stream flushes 8 KB at a time, and under TLS each of those becomes a Conscrypt SSL record rather than getting batched into larger 16 KB records :  meaning the app-layer 8 KB granularity carries straight through to the wire.

At 150 MB/s throughput that works out to roughly 18,300 sends per second, which is cheap in syscall overhead (~0.1 core-seconds/s) and AES-GCM with hardware crypto extensions only costs a few percent of a core, so neither is the bottleneck :  the real question is how to get TLS records to coalesce into 16 KB chunks instead.

Since Okio caps segments at 8 KB, I need to decide how HttpURLConnection's setChunkedStreamingMode should be configured in MainActivity.kt to honestly reflect what chunk size OkHttp's bridge actually delivers underneath.

1 of chunkLength; the actual write buffer sink still uses Okio's 8192-byte segments underneath, so setting chunk length above 8192 doesn't change the underlying wire segment size, just how often chunk headers get inserted. So a larger chunkLength value like 16384 is essentially harmless but doesn't do much beyond reducing header frequency slightly, since the framing overhead per chunk is small regardless of alignment with Okio's internal buffering.

I'm now leaning toward picking a bigger chunk size like 65536 to match larger application write blocks, minimizing per-chunk overhead and JNI crossings while keeping syscall counts the same, and questioning whether OkHttp 2.x even requires writes to be bounded by the configured chunk length (it doesn't -- it handles arbitrary sizes).

With that settled, I'm sizing per-thread buffers at 64 KB each across 32 threads, totaling 2 MB instead of 8 MB, and wondering if I can push further by sharing a single read-only buffer across threads since writes don't mutate it.

Rather than sharing one array outright, I'm settling on a shared 256 KB random-filled buffer with each thread writing rotating 64 KB windows, which keeps heap usage tiny while avoiding cache contention and GC pressure. Compression isn't a factor here since there's no encoding on the POST payload. Next I want to weigh parallel stream counts: 32 vs 24 vs 16: against per-thread overhead.

Thinking through 32 streams across 8 cores with blocking IO, the real bottleneck isn't CPU but kernel buffer footprint (roughly 16 MB locked across all streams) and congestion control behavior: more streams ramp cwnd faster during slow start but risk more queueing and loss over shared Wi-Fi airtime. I'm leaning toward 24 streams as a reasonable compromise between fast ramp-up and avoiding contention, though I still need to firm up that decision.

Working out the aggregate BDP at 1200 Mbps and 25ms gives about 3.75 MB, and at 16 streams that's roughly 234 KB per stream, well within the 512 KB SO_SNDBUF limit and reaching full cwnd within about 4 RTTs (100ms) :  so 16 streams could suffice while cutting kernel memory overhead in half, though I'm weighing the risk of per-connection server-side limits on a single 5-tuple hash path. Given the debate between 32/24/16, I'm settling on 16 as the primary choice.

On uplink, the handset's TXOP determines its airtime share regardless of internal stream count :  the AP doesn't grant more airtime just because there are more TCP flows within a single station. So the flow count argument for uplink specifically doesn't hold the same weight as it might for downlink scheduling.

16 is settled. For pre-warming, I'll open all 16 connections upfront, finish the TLS handshake on each, then send a minimal priming request to avoid cold-start effects skewing the measurement.
