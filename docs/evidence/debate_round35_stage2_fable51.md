# Stage 2 Cross-Rebuttal: stage2_fable51

I need to build Podium 4's Stage 2 rebuttal with high burstiness, no dashes, no AI cliches, covering the kernel datapath, MTU encapsulation budget, and VpnService analysis.

Auditing Podium 1's claims: their suggested `java.net.preferIPv4Addresses` property doesn't actually exist, the real ones are `preferIPv4Stack` and `preferIPv6Addresses`, and Android's resolver goes through netd via getaddrinfo with RFC 6724 ordering rather than honoring Java properties the way HotSpot does. Their fallback of connecting to an IPv4 literal with a manual Host header also breaks SNI, since Conscrypt only sets SNI for hostnames, not IP literals.

Actually the real cause is zero confirmed bytes in round 34 since the socket was killed before the 200 OK was read: so connectTimeout was 6000ms, meaning shutdownNow fired before any response code was parsed. Reducing connectTimeout to 2000ms and extending the await window only reduces the penalty from dual AAAA lookups (4s wasted) but doesn't fix the underlying issue; fixing IPv6 resolution addresses the root cause, while timeout tuning is just a secondary mitigation.

Podium 1's stack trace approach of grabbing the first frame only captures the deepest libcore frame rather than the actual caller in MainActivity, so it's not useful without filtering by package name. And its suggestion to omit the ::/0 route needs scrutiny: Android's VpnService.Builder blocks an entire address family by default unless allowFamily is explicitly called for it, so simply omitting the route isn't equivalent to intentionally allowing or blocking IPv6 traffic.

This confirms my Stage 1 fix, and Podium 3 also converges on removing the IPv6 route as the cleanest solution. Podium 2's rejection based on "round scope" doesn't hold since the download datapath is entirely IPv4, so removing the v6 route wouldn't affect IPv4 forwarding :  though I need to figure out why download still succeeds at 1,580 Mbps despite the IPv6 black hole, maybe it resolves differently or connects via literal IPv4.

I'm considering whether OkHttp's Happy Eyeballs fallback lets download absorb the 10s IPv6 stall without freezing, meaning the route fix speeds connect setup but doesn't touch the frozen download datapath code at lines 1315-1437, which stays untouched either way.

Now checking Podium 2's proposal: it's correct on properties and SNI, but suggesting OkHttp Dns assumes the upload client already uses OkHttp rather than HttpURLConnection (which Podium 3 claims). Android's HttpURLConnection wrapper doesn't expose a Dns interface, so implementing this would require migrating to OkHttp as a new dependency, or falling back to Podium 3's raw SSLSocket approach instead.

On the VpnService route change, app-level pinning only patches the speed test while every other dual-stack app still eats AAAA stalls, and the black hole itself is a correctness defect worth fixing at the gateway level with a capability-gated route removal that leaves IPv4 untouched. Both keeping and removing the `::/0` route are leak-safe since v6 has no working exit either way, so there's no leak-based argument against removing it.

Podium 3 converges on removing the route plus DNS filtering, floats ICMPv6 unreachable synthesis as a fallback, and considers hand-rolling HTTP/1.1 over raw SSLSocket, though that adds risk around chunked parsing and connection handling. I'm noting that proper SNI requires the createSocket overload that takes a hostname string rather than an InetAddress, since the latter skips SNI entirely on Android.

I notice a discrepancy: Podium 3's stagger math uses 40 ms per stream while the mandate specifies 2 ms, making their "24 × 40ms = 920ms" figure inconsistent: a minor flaw. On warmup exclusion, I lean toward keeping the 6s measured window with the first second excluded as warmup, rather than extending total duration to 8s.

The 7s total transmission time (6s measured + 1s warmup) seems like an acceptable tradeoff. Their 83% tunnel efficiency figure checks out mathematically, and since ChaCha20-Poly1305 encryption/decryption costs are symmetric between upload and download paths, the 1,600 Mbps upload estimate against a 1,000 Mbps target seems reasonable. Now I want to work through my own analysis of the kernel datapath and MTU budget.

Calculating overhead: with a 1500-byte Wi-Fi MTU, subtracting outer IPv4/UDP headers and a WireGuard-style protocol header plus Poly1305 tag gives roughly 60 bytes of overhead, so setting the tunnel MTU to 1420 leaves some slack and yields an inner TCP MSS of 1380 bytes :  about 92% payload efficiency.

At 1 Gbps that translates to roughly 90,580 packets per second, meaning each read/encrypt/sendto cycle has to fit within about 11 µs on a single core.
