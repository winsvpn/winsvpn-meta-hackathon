# Stage 3 Synthesis: stage3_fable51

I'm putting together the Stage 3 write-up with working Kotlin for the upload speed measurement and streaming URL functions, plus the VPN tunnel routing tweak, aiming for a natural, varied writing style. I'm working through the design specifics, like using Cloudflare's upload endpoint with 24 parallel streams staggered by 2 milliseconds.

Now I'm reconciling a disagreement between the three review passes about IPv6 handling: one wants OkHttp with filtered DNS, another notes OkHttp isn't part of the codebase, so I'm deciding on a two-layer fix instead. One layer removes the IPv6 route conditionally at the VPN tunnel level to kill the root cause, and the other pins the upload path to IPv4 directly using a raw SSLSocket wrapped with proper SNI, since HttpURLConnection can't be forced onto a specific address family.

I'll settle on a synthesis: mandatory gateway fix at Layer 1, plus a dependency-free IPv4-pinned SSLSocket implementation at Layer 2 that captures OkHttp's proposed behavior (filtered IPv4 resolution, 2000ms connect timeout, graceful completion) without adding a library. For byte accounting, I need to confirm bytes only count once the server returns HTTP 200 after the full stream body is received, matching how Cloudflare's endpoint behaves.

For streams cut off at the deadline, I'll still finish sending the terminating chunk and read the response, counting the bytes if a 200 comes back, while streams that never got a response go uncounted. I'm defining a warmup period of 1000ms excluded from the measurement window, with the actual timing snapshot taken at warmup's end before the full duration begins.

But I realize the snapshot at deadline is tricky since bytes written to the OutputStream aren't necessarily delivered over the wire yet -- TCP send buffers could hold data, so with 24 concurrent streams over 6 seconds I need to think about how buffering affects the accuracy of what I'm measuring.

The 200 confirmation from the server ensures the bytes actually arrived, so I can accept a small bounded error from the send buffer (a few hundred KB, negligible against total throughput). Rather than the coordinator snapshotting all streams simultaneously, it's cleaner to have each stream record its own byte count the moment it observes the nanoTime crossing the warmup and deadline boundaries in its write loop, keeping the race window to about one write's worth of bytes.

The overshoot is bounded, roughly 0.7% at typical gigabit rates over a 6s window, which is acceptable to document. I decide to use the max stream end time as the window boundary for a conservative calculation, and I still need to configure sockets with TCP_NODELAY and proper buffer sizes, plus work out the chunked transfer encoding format for each write block.

For reading responses, I'll use Connection: close and read until EOF, ignoring early error responses since I only care about final completion. For DNS I need to resolve and filter for IPv4 addresses only, sharing the resolved list round-robin across streams, then handle socket connection and TLS setup for each stream.

Then I'm thinking through whether the speed test app's own sockets route through its VPN tunnel by default: yes, since VpnService captures all traffic from the app unless explicitly protected, which matters for how I structure the tunnel service logic.

For IPv6, I'm deciding to only add the IPv6 address, route, DNS server, and allowFamily(AF_INET6) to the VPN builder if the gateway actually advertises IPv6 egress, otherwise skip it entirely: recalling that on API 21+, VpnService blocks families by default unless a route or allowFamily explicitly permits them.

Actually, allowFamily lets that family's traffic bypass the tunnel entirely, so calling it without IPv6 egress would leak traffic. So I should not call it, and instead let IPv6 be blocked at the kernel level: connect() attempts return ENETUNREACH and the resolver stops issuing AAAA queries since the VPN network reports no IPv6, which is the correct, leak-safe behavior.

Now I'm checking the MTU budget for Winn Protocol v3: outer IPv4 header plus UDP plus protocol header plus tag adds up to about 60 bytes of overhead, giving an MSS of 1380 against a 1420 MTU, roughly 92% efficiency and about 90,580 packets per second at 1 Gbps. Since the download datapath is frozen, I'll leave the MTU as-is rather than changing setMtu, just noting the budget for reference.

I'm also tracing the uplink kernel path: app write() through TCP, into the tun fd, read by the VpnService loop, encrypted, then sent via UDP over Wi-Fi. Since Android's VpnService tun interface lacks IFF_VNET_HDR, GSO isn't available, but 90k pps on a single thread still fits within the ~11 µs per-packet budget.

ChaCha20-Poly1305 encryption at roughly 1.5 GB/s per core handles 1380 B blocks in about 1 µs, so that's not a bottleneck. Staggering 24 streams by 2 ms each only adds about 46 ms total spread, which is negligible against the 1 s warmup window.
