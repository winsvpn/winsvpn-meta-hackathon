# Stage 2 Rebuttal: stage2_fable51

I need to write Stage 2 as Podium 4, auditing Podiums 1, 2, 3, and my own Stage 1 honestly. I'll aim for high burstiness with short decisive claims mixed with compound proofs, avoiding dashes and the banned vocabulary list entirely.

Auditing Podium 1's core claim about wmem_default as the TCP buffer size, I'm noting the real mechanism is tcp_wmem with autotuning, not the static default, and that Android's HttpsURLConnection routes through OkHttp and Conscrypt before ever touching the raw socket, which undermines the described blocking behavior at 224 KB. I'm also flagging that blocked threads sleep rather than thrash the CPU, so the context switch claim under 32 threads doesn't hold up the way Podium 1 argues, and I'm checking how setChunkedStreamingMode behaves inside OkHttp's actual implementation.

Tracing chunk emission further...

Actually I realize the Okio OutputStreamSink loops over 8 KB segments, so each segment becomes its own SSLOutputStream write, producing 8 KB TLS records (roughly 8,221 bytes with overhead) and separate send() syscalls rather than 16 KB records as I assumed.

This means around 10,800 syscalls per second across 32 threads, which isn't the bottleneck, and it also means the chunked streaming mode size and BufferedOutputStream settings are largely irrelevant since Okio's fixed 8 KB granularity dominates. When writes are 256 KB or larger, BufferedOutputStream just bypasses its own buffer entirely, so wrapping the stream with a 256 KB buffer accomplishes nothing except wasting 8 MB of heap across 32 threads. I'm now turning to the timing concern around when streamBytes gets accumulated relative to when the response code is read.

If bytes are only credited to `confirmed` after responseCode succeeds, an exception or timeout there means lost accounting, but P1's proposed fix of crediting bytes on successful `out.write()` has its own flaw -- it counts bytes accepted into user-space and kernel buffers, not bytes actually delivered, which inflates throughput. I'm weighing whether to keep the response-code gate but measure duration to the last write time, possibly with mid-window sampling, or to credit bytes at write time while stopping the clock at the last write, accepting that in-flight unacked bytes introduce a small bounded error.

Estimating that worst case, with 32 concurrent connections each carrying up to ~4.5 MB of buffered-but-undelivered data across Okio and socket send buffers, the inflation could reach 128 MB over a 6-second window -- roughly 170 Mbps of phantom throughput, which is enough to falsely trigger a 1,000 Mbps threshold. That's a serious measurement integrity risk, so the better fix is to count bytes at write time but stop the stopwatch only when the final `responseCode` call returns, capturing the drain time rather than the write time.

I can bound the inflation by capping SO_SNDBUF at 512 KB per stream, which limits worst-case overcredit to about 21 Mbps over 6 seconds :  comfortably above the per-stream bandwidth-delay product of ~117 KB, so it won't throttle real throughput. This is settable by wrapping the SSLSocketFactory to call setSendBufferSize on the socket before connect, giving a concrete hardened fix.

Now I'm turning to Podium 1's Chokepoint C: setting a large write buffer on the outer UDP socket, though wmem_max will still clamp it as I noted earlier.

Since kernel doubles and clamps the socket buffer, I really need to verify via readback after setting it rather than assume. My earlier headroom math treated bytes literally, but the kernel counts skb truesize which includes overhead per UDP datagram, so the real capacity is likely closer to 100 frames, not 160. I also need to account for how a full send buffer causes blocking or ENOBUFS behavior on UDP sends.

Actually, I realize Go's UDP socket is nonblocking under the runtime poller, so a full sndbuf causes EAGAIN and the goroutine parks until writable rather than dropping the packet :  meaning "kernel drops due to ENOBUFS" was the wrong diagnosis. The actual drops would happen further downstream in the qdisc or Wi-Fi driver queue, especially if fq_codel is active and its latency target triggers drops under a large socket buffer.
