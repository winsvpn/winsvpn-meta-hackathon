# Stage 1 Submission: stage1_opus5

I'm working out the technical proposal for fixing the IPv6 black hole issue causing connect stalls across 24 parallel upload streams to speed.cloudflare.com, planning to include math modeling, sysctls, and socket configuration diffs.

The cleanest fix is filtering DNS resolution to IPv4 addresses only, since JVM system properties for preferring IPv4 aren't reliable post-init on Android. With OkHttp a custom Dns implementation that filters to Inet4Address is a small, high-value change, but the existing codebase relies on HttpURLConnection instead, which complicates pinning the connection to an IPv4 literal while preserving TLS SNI and certificate validation.

But there's actually a better root-cause fix: don't add the IPv6 default route on the VPN interface at all. Android's netd resolver checks per-network IPv6 reachability before querying AAAA records, so if the VPN network never advertises IPv6 connectivity, the system will naturally suppress IPv6 DNS lookups everywhere -- meaning the real solution is to remove the `::/0` route and pair it with the IPv4-only DNS filtering as a defensive second layer.

I'm also noting a fix for the connection lifecycle: adding per-stream deadlines, cooperative shutdown ordering, and atomic byte counting during writes rather than after.

If IPv6 routing has to stay for some reason, the alternative is making sure unreachable IPv6 destinations fail fast with an ICMPv6 unreachable response instead of hanging silently.

For the throughput math: tunnel efficiency runs around 83% of physical WAN speed based on the download benchmark, so applying that same ratio to the 1947 Mbps upload path gives roughly 1624 Mbps theoretical capacity :  comfortably above the 1000 Mbps target. I'm now checking whether Wi-Fi MAC efficiency at the measured PHY rate leaves enough headroom too.

Working through per-stream requirements, 1000 Mbps split across 24 connections needs about 42 Mbps per stream, and a single measured curl transfer hit roughly 206 Mbps :  so 24 parallel streams could theoretically demand nearly 5 Gbps, well beyond what any single link segment could sustain.

I'm calculating bandwidth-delay product to check buffer sizing: at ~1624 Mbps and roughly 12ms RTT through the tunnel, that's about 2.4 MB of data in flight, or roughly 100 KB per stream when split across 24 connections :  comfortably within typical Android TCP buffer limits, though I need to check if the app's chunk size matches this.

Chunked transfer framing overhead is negligible for 256 KB chunks (about 0.003%), so sticking with chunked encoding is fine and avoids needing to know the total upload length in advance. Fixed-length streaming would eliminate that framing overhead entirely, but requires knowing the exact byte count upfront, which doesn't work for a time-bounded upload where we don't know the total ahead of time.

Working through the timeout math: with a 5000 ms connect timeout and two AAAA addresses, that's 10,000 ms wasted before falling back to IPv4. With 24 streams staggered by roughly 40 ms each, the last stream starts around 920 ms in, pushing the IPv4 attempt to about 10,920 ms, which lines up with the observed 16-second timeout implying a 6-second measurement window.

With the fix applied, there's zero IPv6 waste, a single-RTT IPv4 connection, and TLS 1.3 completing in one RTT, giving a time-to-first-byte around 36 ms. Slow start ramp-up to line rate takes roughly 70 ms total, which is only about 1.2% loss over a 6-second window: so I'm recommending bumping durationMs to 10000.

I need to exclude a 1000 ms warmup period from the rate calculation, only measuring bytes transferred after that window. For the gateway-side sysctls, since download datapath code is completely frozen, I should limit changes to things that don't touch the IPv4 download path: sticking to IPv6-only ip6tables rules and socket buffer maxima rather than anything on the ingress/download side.

Now I'm writing a code diff that gates IPv6 tunnel routing behind a check for gateway IPv6 egress support, falling back with a warning log if the gateway doesn't support it.

I need to add an `ipv6_egress` flag to the Winn Protocol v3 handshake JSON, defaulting to false when absent, and explain the underlying Android mechanism: netd's per-network AAAA suppression uses `have_ipv6(netid)` to probe connectivity via a UDP connect, so removing the ::/0 route on the VPN network causes that probe to fail and the resolver to drop AAAA queries entirely.

For the DNS pinning diff, I'm setting up a custom OkHttp Dns implementation that filters lookups down to only IPv4 addresses, throwing if none exist, and for HttpURLConnection I need an equivalent IP-pinning approach that still respects SNI.

Since Android's HttpURLConnection can't have its DNS resolution overridden, I'm realizing the real fix is bypassing it entirely: build a raw SSLSocket connected directly to a chosen IPv4 address, then speak HTTP/1.1 chunked encoding manually over that socket.

This gives me direct control over SO_SNDBUF and TCP_NODELAY while writing bytes, and matches the curl behavior exactly. I'll propose this raw socket uploader as the primary solution.
