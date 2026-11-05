# Stage 2 Rebuttal: stage2_opus5

I need to build Stage 2 as an adversarial cross-rebuttal from Podium 3, auditing the other podiums and self-correcting my own Stage 1, backed by concrete technical details like code diffs, sysctl settings, and socket configurations, while keeping the prose varied and punchy.

Diving into the device specifics: a Samsung Galaxy S26 Ultra on Android with a ~6.6 kernel and Snapdragon 8 Elite, testing Winn Protocol v3 over Wi-Fi 7 at 1554 Mbps down and 706 Mbps up against a >1000 Mbps upload target, measured through 32 parallel HTTP POST streams.

My first attack targets Podium 1's Chokepoint A math. I'm arguing their wmem_default constant is likely misattributed (208 KB vs 224 KB confusion with rmem_default), and more fundamentally that TCP sockets don't rely on wmem_default at all since tcp_wmem autotuning overrides it, growing the buffer automatically under write pressure, so their claim that a 512 KB chunk overwhelms a 224 KB buffer rests on a flawed premise from the start.

My second point dismantles their "thread thrashing" claim: the 8 Elite has 8 cores with no little cores, and threads blocked on a full write buffer are sleeping, not runnable, so they can't be thrashing across cores :  this confuses blocked with runnable state, and real context-switch cost would only show up if writes completed too fast, which is verifiable through voluntary_ctxt_switches in /proc.

Third, I'm noting that their proposed fix :  shrinking chunks from 512 KB to 256 KB :  actually doubles syscalls per MB, adding more JNI transitions and chunk-header overhead, which can't help a throughput problem that's already backpressure-limited; the fix moves in the wrong direction entirely.

The real culprit is that HttpURLConnection on Android is OkHttp-backed, so its chunked-mode buffer just becomes an Okio segment allocation that still copies through 8 KB segments regardless of the size argument given.

For BufferedOutputStream, I have a solid rebuttal: its write() method explicitly bypasses the internal buffer when the write length exceeds the buffer size, flushing and writing directly :  so wrapping a 256 KB buffer around 256 KB writes adds zero benefit while costing 8 MB of heap across 32 threads. This is a fair concession point since Podium 4 and my own Stage 1 both caught the same issue.

Now I'm turning to Chokepoint B, which is genuinely the strongest argument in Podium 1's submission :  I should concede part of it while correcting where their reasoning goes wrong.

Crediting bytes at write() return time is still flawed, since a successful write only confirms bytes entered the socket send buffer, not that they left on the wire; at window's end, up to sndbuf-bytes-per-stream across 32 streams remain in flight and get mismeasured, and with autotuned 4 MB sndbuf that's 128 MB of phantom bytes translating to roughly 170 Mbps of error :  larger than the discrepancy being corrected. The right fix is steady-state sampling: take two snapshots inside the window at t1 and t2 so buffer fill/drain transients cancel out, rather than relying on cumulative totals, and I should also flag that TCP_INFO via getsockopt isn't fully accurate either.

On the SetWriteBuffer(8MB) claim, I need to concede to Podium 4: Go's SetWriteBuffer maps to setsockopt SO_SNDBUF, which the kernel clamps against net.core.wmem_max and doubles for bookkeeping, so 8 MB requested against a stock 212992 wmem_max actually yields 425984 bytes :  and since the clamping happens silently without an error return, checking the return value proves nothing; only getsockopt can verify the real value.

Also worth noting that raising wmem_max via SO_SNDBUFFORCE needs CAP_NET_ADMIN, unavailable to a non-root Android app, so the practical fix is sendmmsg batching with non-blocking sockets rather than chasing a bigger buffer. And for UDP specifically, SO_SNDBUF doesn't behave like it does for TCP since there's no retransmit queue :  it only gates what's queued before the driver, so a 425 KB buffer still holds roughly 300 frames at 1400 bytes each.

Now I'm double-checking the packet rate math: 1200e6 divided by (1333*8) works out to about 112,528 pps, and multiplying that by the tunnel overhead of 1373 bytes gives the tunneled bitrate :  confirming the earlier throughput and buffering assumptions hold. I'm also noting that ENOBUFS from UDP sends happens once sndbuf is exceeded, so sendmmsg batching helps amortize syscall overhead but doesn't eliminate ENOBUFS :  that still needs to be handled with retries rather than dropped packets.

I catch a small inconsistency where the payload rate silently shifts from 154.5 to 150 MB/s in a later calculation :  sloppy but not fatal. Working backward from the 1500-byte MTU constraint with 1373-byte inner payload, 20-byte IP header, and 8-byte UDP header, the tunnel header itself must be about 99 bytes, which is plausible given an AEAD tag, nonce, and counter/type fields, and this puts wire efficiency at roughly 88.9%.

But I realize the real correction needed is that the actual air-time cost should use the full 1500-byte outer frame, not the 1373-byte inner TUN size :  so the outer wire rate comes out to about 168.8 MB/s, or 1,350 Mbps of UDP/IP traffic on the air to deliver 1,200 Mbps of inner goodput, and I need to factor in the return-path TCP ACKs against the 1,554 Mbps already flowing in the download direction.

Actually, since Wi-Fi is half-duplex, download and upload aren't independent :  they share the same TXOP budget. If the download and upload numbers in that speedtest screenshot were measured simultaneously, then total medium occupancy is 1554 + 706 = 2,260 Mbps, which lines up almost exactly with the theoretical MAC-efficiency ceiling of roughly 1,900-2,250 Mbps at that PHY rate. That's the critical insight I was missing.

So this hinges on whether the test measured both directions at once or sequentially :  if simultaneous, upload physically cannot exceed 1,000 Mbps without download dropping, and this half-duplex TDD airtime accounting is something no other analysis raised. I want to flag this as the decisive unresolved question and lay out the math carefully: at 3459 Mbps PHY, that's consistent with 160 MHz channel width, 2 spatial streams, and 4K-QAM under EHT (Wi-Fi 7), while 2882 Mbps would correspond to 160 MHz/2SS/MCS13.

That leaves the case where 3459 Mbps maps to 320 MHz/2SS/MCS11 or similar. Applying realistic EHT MAC efficiency with A-MPDU aggregation, downlink runs 60-70% and uplink 50-60% due to handset TXOP limits and lack of uplink MU-MIMO, giving an aggregate goodput ceiling near 2,248 Mbps at 65% -- which matches the observed 2,260 Mbps almost exactly. Since simultaneous bidirectional traffic hitting a 1,000 Mbps upload target would require 2,554 Mbps total, exceeding the medium's capacity, the real choice is either running unidirectional upload tests (which should reach 1,300-1,500 Mbps) or accepting that the download lock and upload target are mutually exclusive on this half-duplex medium.

I'm working through the airtime-share equation, where downlink and uplink goodput each get divided by their PHY rate times an efficiency factor, summing to no more than the airtime left after beacon overhead. Testing eta_d=0.68 and eta_u=0.55 against the observed 1554/706 split slightly overshoots 100% utilization, so I adjust to eta_d=0.70 and eta_u=0.58, which brings the total airtime usage down to about 99%, matching expectations much better.

This confirms saturation: with download locked at 1554, pushing upload to 1000 would demand over 114% of available airtime, which is physically impossible. So the download lock must mean the code stays untouched, not that both streams run simultaneously at their peak values :  sequential measurement is the only consistent way to satisfy both the code constraint and the upload target.

Now I'm turning to evaluate the second submission, which appears to be largely empty or lacking substance.
