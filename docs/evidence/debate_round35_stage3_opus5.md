# Stage 3 Synthesis: stage3_opus5

I need to synthesize the final treaty: production Kotlin code for measuring upload speed and building the speed test URL in MainActivity.kt, plus routing fixes in VpnTunnelService.kt, along with exact sysctl values and socket settings, avoiding em dashes and AI-sounding phrasing. I'm working through the IPv6 black hole fix as a two-layer defense, starting with the transport layer approach.

For Layer A in VpnTunnelService, I avoid adding an IPv6 default route, avoid allowing the AF_INET6 family, and avoid assigning an IPv6 address, so the VPN's LinkProperties reports no IPv6 capability and AAAA lookups get suppressed via AI_ADDRCONFIG; I also set explicit IPv4-only DNS servers so resolution stays scoped to the VPN network id rather than inheriting the underlying Wi-Fi's IPv6 resolvers. For Layer B in MainActivity, I switch to OkHttp with a custom Dns implementation that filters resolved addresses down to Inet4Address only, which covers OEM builds like Samsung One UI that still return AAAA records, while keeping SNI correct since the hostname itself stays the same and OkHttp sends proper SNI and Host headers against the resolved address. This also resolves the earlier IP-literal SNI flaw and the concern about HttpURLConnection lacking DNS hooks, so I'm migrating just the upload path to OkHttp and specifying the gradle dependency line for it.

Now I'm settling on constants for the upload measurement: 24 concurrent streams staggered by 2ms, 256KB chunks, a 1 second warmup period, a 2 second connect timeout with one bounded retry, and a barrier timeout equal to the duration plus 12 seconds of padding. I confirm byte accounting only counts bytes from streams returning a 200-299 response code, tallied through a counting sink as bytes actually flush to the socket, with timing measured via a single monotonic nanoTime window captured after warmup :  and I'm leaving the download datapath completely untouched. Now I'm writing the upload measurement function itself, starting with the constants and then the URL-building helper for the speed test endpoint, keeping the exact `/__up` path intact.

I decide `speedTestStreamUrl` should return the upload endpoint constant exactly, since each stream gets its own connection anyway so no cache-busting query param is needed, and I need to make sure this function is scoped so it doesn't interfere with the frozen download URL logic elsewhere in the codebase.

Now I'm thinking through the byte-counting mechanism: a request body writer that emits 256 KiB blocks until the deadline hits, only incrementing the confirmed-byte counter after each block is fully written and flushed to the socket.

I need a two-tier accounting scheme where staged bytes track what's written per stream, then get promoted to confirmed bytes only once the response comes back 2xx. I also need to restrict counting to the measurement window itself, ignoring warmup bytes, by checking write timestamps against the window boundaries and accumulating only in-window totals.

Since kernel socket buffers can make writes appear complete before hitting the wire, I want to cap SO_SNDBUF per socket at 256 KiB to bound the overstatement -- with 24 streams that's at most 6 MiB of slack, which is under 0.5% error at the target throughput. The buffered bytes at window start and window end roughly cancel out, so the net bias stays small.

I'm configuring the socket factory with TCP_NODELAY enabled, a bounded send buffer, a small receive buffer since responses are tiny, keepalive disabled, linger disabled to avoid blocking on close, and a throughput-optimized traffic class flag.

Checking the bandwidth-delay product against buffer sizing, I bump the send buffer to 512 KiB per socket so the aggregate in-flight data covers RTTs up to roughly 60 ms at 1.6 Gbps, keeping the overstatement bound around 1% of total transfer, which the cancellation argument shrinks further.

I also weigh explicit buffer caps against relying on kernel autotuning, opting for the fixed 512 KiB value since it makes accounting error bounded and predictable rather than letting it grow toward tcp_wmem's max.

Now I'm listing out the sysctl tunables for the rooted device or gateway side: buffer sizes for rmem/wmem, enabling BBR congestion control with fq queueing, tuning tcp_notsent_lowat, disabling slow-start-after-idle, enabling MTU probing, bumping backlog and somaxconn limits, and setting UDP memory and IP forwarding parameters.

I'm realizing tcp_notsent_lowat is actually key here: it caps unsent bytes in the socket send buffer, which directly limits how much the accounting can overstate throughput. Setting it to 128 KiB means the socket becomes unwritable once unsent bytes exceed that threshold plus the in-flight congestion window, giving a clean bound on overstatement.

On Android I can't touch sysctl without root, but this is exposed as a per-socket option via TCP_NOTSENT_LOWAT, which Java doesn't natively support -- I'd need Os.setsockoptInt with a reflectively-extracted file descriptor from the Socket object. That's risky, so I'll gate it behind a try/catch as an optional enhancement with a safe fallback if it fails.

Now moving to MTU: the mandate specifies tunnel MTU 1420 with inner MSS 1380, so I need to configure the VpnService.Builder accordingly, accounting for the outer IPv4 and UDP overhead.

Setting up the tunnel interface builder...
