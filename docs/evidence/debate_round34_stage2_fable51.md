# Stage 2 Rebuttal: stage2_fable51

I need to audit Podium 1, 2, and 3's submissions, evaluating their claims and building rebuttals, concessions, and hardened code diffs, keeping the style sharp and varied while focusing on kernel datapath, MTU budget, and VpnService analysis. I'm starting to break down specific technical issues in Podium 1's approach.

Their Discovery 1 explanation for the Cloudflare 403 clashes with a frozen tx_packets counter, since a 403 response requires a completed TLS handshake, which itself requires packets traversing the tun interface. Since VPN apps route their own traffic through tun by default unless a socket is explicitly protected, a frozen counter would mean no SYN or ClientHello could have gone out, undermining the 403 hypothesis unless the counter snapshot is stale or the sockets bypass tun somehow, which is where Podium 3's argument becomes relevant.

I'm also questioning whether tx_packets at 91,367 is even plausible alongside a 1.55 Gbps download, since heavy download traffic generates a large volume of ACKs that would need to flow outbound through the same interface -- so a frozen or low tx count during that period seems inconsistent unless I'm misreading which direction (phone vs. gateway) the tun tx counter actually represents.

This suggests the telemetry itself may be unreliable, echoing what Podium 3 raised, and I want to concede that point while sharpening it further. Alternatively, if download sockets bypassed the tun interface via a "direct transport" mode, that could explain the discrepancy, but that's speculative -- I need to demand the exact sysfs path and two timestamped samples rather than assume.

Turning to Podium 1's second discovery about query string pollution on Cloudflare's /__up endpoint, I recall Cloudflare's own speedtest client actually uses measId query parameters for uploads, so their claim that arbitrary query strings are suspicious is false -- I should rebut it. Cache busting or stripping the query string is harmless either way, not a root cause, so I'll keep canonical URL formatting for cleanliness but won't claim it fixes anything causally.

More critically, Podium 1's rewrite touching /__down with a bytes=50000000 branch inside speedTestStreamUrl violates the download-path freeze since that function is shared between upload and download flows -- I need to push back hard and require any upload URL logic to live in a separate function entirely, leaving the download branch byte-for-byte untouched.

Testing whether curl works against Cloudflare's /__up endpoint confirms browser headers aren't required, so header spoofing isn't the root cause of the failure -- though mirroring the Dart client's known-working header profile is harmless for parity, I shouldn't frame it as a WAF fix since Sec-Fetch-* and CORS/Origin headers are irrelevant for a native client outside a browser context.

Given the frozen tx_packets telemetry, I'm considering root causes where failure happens before any packet leaves: missing setDoOutput(true) could throw a ProtocolException when getOutputStream is called without a body-supporting method, or setFixedLengthStreamingMode being called after connect or with a mismatched size could trigger an IllegalStateException from setting headers post-connection.

I'm also weighing whether DNS resolution matters -- likely not, since the host was already resolved during the download phase and the cache should be warm -- versus the possibility that upload traffic bypasses the tunnel entirely if the app binds the socket to a specific network via ConnectivityManager or opens the connection through a Network object, which would explain frozen tx counts even while upload proceeds normally over the underlying interface.

Another angle: maybe measureUploadMbps runs on the main thread and silently throws NetworkOnMainThreadException, caught by the generic exception handler, though that seems inconsistent if download uses the same code structure successfully. I'm also considering whether calling getOutputStream() with chunked streaming mode is what actually triggers the connection and header transmission.

If getOutputStream() completes, packets should have crossed the wire; a frozen tx count means it either failed or was never reached. The 403 theory requires enough packets for SYN, TLS, and requests across 32 streams to move the counter meaningfully, so a truly frozen counter contradicts that unless the telemetry itself is stale :  which means I need to instrument directly: log the exception class, message, and stack trace, and read tx_packets from the network statistics before and after the transfer to verify ground truth.

On the Android statistics restriction issue, I should fall back to TrafficStats.getUidTxBytes(uid) or the engine's own tun fd counters. Looking at stream concurrency across the reports, everyone converges on roughly 24 concurrent streams with a few milliseconds of stagger between them, so I want to check how OkHttp's connection pooling handles that load, since idle connection limits differ from active connection limits.

I'm now digging into whether the real bottleneck is Dispatcher's maxRequestsPerHost, which only applies to async calls, not synchronous HttpURLConnection -- and whether Android's built-in OkHttp actually negotiates HTTP/2 via ALPN, since that would change how connections get coalesced.

Now I recall more specifically: libcore's HttpsHandler defines a static HTTP_1_1_ONLY list and configures the client to use only that protocol, confirming Android's platform HttpURLConnection is restricted to HTTP/1.1. This undercuts the HTTP/2 coalescing concern for the platform implementation, though I still need to consider whether the app bundles its own OkHttp library instead.
