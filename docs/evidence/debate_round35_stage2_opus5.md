# Stage 2 Cross-Rebuttal: stage2_opus5

I need to audit Podiums 1, 2, and 4 as Podium 3, conceding where they're right and rebutting where they're wrong, then deliver hardened code diffs with exact sysctls and socket configs. I'm aiming for a punchy, decisive tone with no em dashes and no filler language.

On IPv6 resolution: Android's DNS lookups go through bionic's getaddrinfo which handles RFC 6724 sorting at the OS level, so JVM properties like preferIPv4Stack have no real effect here. Podium 1's proposed property name doesn't actually exist, so I'm siding with Podium 2 on that point, but I'm flagging that both Podium 2 and 4's OkHttp Dns proposal doesn't fit since the codebase runs on HttpURLConnection, not OkHttp.

I'm also noting that OkHttp's URLConnection-compatible factory was removed in 4.x, so bridging custom DNS into HttpURLConnection isn't straightforward without dropping to raw sockets or switching to OkHttp's Call API entirely. I need to defend my earlier raw SSLSocket proposal while acknowledging it requires manually handling SNI and hostname verification.

Digging further, I confirm that HttpsURLConnection's socket factory only wraps an already-connected raw socket, meaning the TCP destination is fixed by the internal DNS resolver before the SSL layer ever gets involved -- so there's no injection point to pin the IPv4 address through the standard API on Android.

Actually, using an IP literal in the URL means no SNI gets sent since RFC 6066 forbids IP literals there, and Cloudflare requires SNI on shared anycast IPs -- so the handshake would fail or return the wrong cert. This is a fatal flaw that kills Podium 1's IPv4-literal-plus-Host-header approach entirely.

So I'm weighing the remaining viable options: OkHttp with a custom Dns implementation, raw SSLSocket with manual SNI configuration and hand-rolled HTTP/1.1, or removing the `::/0` route so netd suppresses AAAA queries. There's also the possibility of keeping HttpURLConnection but forcing IPv6 to fail fast, which is Podium 4's ICMPv6 sink idea -- I need to scrutinize whether Android's HttpURLConnection implementation actually supports that.

Since HttpURLConnection on Android doesn't implement Happy Eyeballs and tries addresses serially, an ICMPv6 unreachable response delivered through the tun fd would trigger a fast connect failure and move to the next address, which works in principle. But I'm noting the complications: ICMPv6 checksums require the pseudo-header unlike ICMPv4, generating these responses in the VpnService read loop adds per-packet CPU overhead, and Android's AI_ADDRCONFIG check will still return AAAA records since a route exists -- so this only achieves fast failure rather than avoiding the attempt entirely.

My actual verdict is a cleaner fix: strip the `::/0` route and skip `allowFamily(AF_INET6)` when the gateway lacks IPv6 egress, so the VPN network reports no IPv6 capability and netd suppresses AAAA queries at the resolver level, avoiding any IPv6 attempts. I want to double check this doesn't leak IPv6 traffic outside the tunnel -- need to think through VpnService's exact behavior when no IPv6 route or address is configured.

So removing the IPv6 route from a non-bypassable VPN should make connect() return ENETUNREACH for IPv6, matching the "VPN blackholes IPv6 unless routed" behavior. And since Android 5, if the VPN's LinkProperties has no IPv6 address, ConnectivityManager reports no IPv6 support, which means getaddrinfo with AI_ADDRCONFIG will suppress AAAA lookups entirely.

I want to flag a caveat though: some OEM builds like Samsung's One UI may still return AAAA if the underlying Wi-Fi network has IPv6, since DNS resolution is per-network and tied to the netid. If the app's socket is bound to the VPN's netid, suppression should still apply, but I need to consider what happens if the VPN doesn't explicitly set its own DNS servers and instead inherits from the underlying network through netd.

On timeouts: Podium 1 wants to drop connectTimeout to 2000, but I need to check whether that timeout applies per socket connect attempt in Android's OkHttp implementation, since serial address attempts would multiply that value across all addresses tried.

Once IPv6 is out of the picture, the exact connect timeout matters less. Linux's SYN retransmit schedule means even 2000 ms allows two attempts, which is enough margin under typical loss rates, so 4000 ms is just extra safety for Wi-Fi roaming. I'll settle on 2000 ms being acceptable as long as it's paired with one bounded retry rather than a hard failure :  a concession with hardening attached.

The parent barrier timeout should also be computed from the child deadline via a formula, not hardcoded as a magic constant. Now I'm weighing 24 versus 32 concurrent streams with a 2 ms stagger between them.
