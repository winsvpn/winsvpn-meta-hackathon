# Stage 1 Submission: Podium 1 (Antigravity Council Chair)
## Round 35 Presidential Debate: Symmetrical Wire-Speed Upload (>1,000 Mbps with Download Locked at 1,580 Mbps)

### 1. Executive Position and Empirical Ground Truth

Physical hardware capabilities are definitively established. On the physical Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL) connected via Wi-Fi 7 to the 2,000 Mbps symmetrical fiber gateway, unprotected throughput reaches 1,895 Mbps Download and 1,947 Mbps Upload (s26_current_status.png). The hardware, radio PHY layer (3,459 Mbps), Snapdragon 8 Elite CPU, and upstream ISP line are capable of wire-speed saturation exceeding 1.9 Gbps in both directions.

Under active Winn Protocol v3 encapsulation to the aicore gateway (192.168.4.36:9111), Download throughput is verified live on screen at 1,575 to 1,580 Mbps (s26_speedtest_finished_round34b.png). Per user directive, the download datapath code and configuration remain 100% frozen.

In Round 34, the upload leg displayed `-- Mbps`. Empirical analysis of logcat telemetry and network probing revealed two distinct bottlenecks:
1. Dual-Stack IPv6 Black Hole:
   VpnTunnelService.kt configures `builder.addRoute("::", 0)` on the TUN interface. However, the aicore gateway lacks IPv6 masquerading and outbound IPv6 routing (ip6tables NAT table contains only Docker rules; IPv6 ping to 2606:4700:7::da shows 100% packet loss). When Android resolves speed.cloudflare.com, Java/OkHttp places IPv6 AAAA records at the top of the route candidate list. HttpURLConnection attempts connection to 2606:4700:7::da:443. The SYN packet enters tun0, arrives at aicore, and is dropped without RST. The client socket hangs for `connectTimeout = 5000` ms per IPv6 address. Across two AAAA records, each stream wastes 10 seconds before attempting IPv4.
2. Parent Timeout Premature Execution:
   With 24 streams staggered by 2 ms and stalled on IPv6 timeouts, `done.await(durationMs + 10_000L)` timed out at exactly 16 seconds (13:19:44.636). The parent thread executed `executor.shutdownNow()` and called `connection.disconnect()`, abruptly terminating all 24 sockets with `SocketException: Socket closed` before any payload byte could be confirmed.
3. Successful Proof-of-Concept:
   A direct curl command executing inside the S26 Ultra over the active Winn Protocol v3 tunnel using IPv4 forced routing (`curl -4 -H "Transfer-Encoding: chunked" ... https://speed.cloudflare.com/__up`) transmitted 10 MB in 389 ms (21.7 MB/s on a single stream) with 200 OK. The tunnel and gateway carry chunked upload traffic cleanly when IPv6 black-holing is eliminated.

---

### 2. Architectural Root Causes and Mathematical Models

#### 2.1 The Dual-Stack Latency Penalty
Let T_connect be the TCP and TLS connection establishment time.
On dual-stack Android with a black-holed IPv6 route:
T_connect = N_ipv6 * connectTimeout + T_ipv4_handshake
With N_ipv6 = 2 and connectTimeout = 5.0 s:
T_connect = 2 * 5.0 s + 0.015 s = 10.015 seconds.
Given measurement duration D = 6.0 s and total barrier timeout B = D + 10.0 s = 16.0 s:
Available transfer window = B - T_connect = 16.0 s - 10.015 s = 5.985 s.
If connection stagger and thread pool queueing introduce an additional 0.5 s delay, worker threads fail to complete before parent thread shutdown, yielding 0 confirmed bytes.

#### 2.2 Symmetrical Wire-Speed Saturation Arithmetic
To achieve T_upload = 1,400 Mbps over 24 streams:
Aggregate throughput required = 175 MB/s.
Per-stream throughput = 175 MB/s / 24 = 7.29 MB/s (58.3 Mbps).
With RTT = 12 ms, each stream requires:
In-flight window = 58.3 Mbps * 0.012 s / 8 = 87.45 KB.
With 256 KB chunk buffers and Android wmem_default = 224 KB, each stream sustains 100+ Mbps when socket writes proceed without blocking.

---

### 3. Surgical Proposals for Ratification

#### Proposal 1: Direct IPv4 Pinning or DNS Resolution in MainActivity.kt
In `measureUploadMbps` and `speedTestStreamUrl`:
Ensure HttpURLConnection resolves speed.cloudflare.com exclusively via IPv4, or resolve the hostname to its IPv4 address (162.159.140.220 / 172.66.0.218) with `Host: speed.cloudflare.com` header, or configure `System.setProperty("java.net.preferIPv4Addresses", "true")` before socket creation.
Even more robustly: In `measureUploadMbps`, resolve the target URL host to IPv4 using `InetAddress.getAllByName(targetUrl.host).firstOrNull { it is Inet4Address }?.hostAddress`. Connect to the IPv4 address while preserving the `Host: speed.cloudflare.com` header and SNI hostname via HttpsURLConnection default or custom HostnameVerifier.
Alternatively, in `VpnTunnelService.kt`: Check whether IPv6 is supported by the selected node. If aicore has no IPv6 outbound routing, omit `builder.addRoute("::", 0)` to prevent the Android system resolver from attempting IPv6.

#### Proposal 2: Immediate Connect Timeout Optimization
Reduce `connection.connectTimeout` from 5,000 ms to 2,000 ms, and extend parent `done.await(durationMs + 12_000L)`. This guarantees that even if a fallback occurs, the transfer loop has at least 8 seconds of active transmit time.

#### Proposal 3: Detailed Stack Trace Diagnostic Logging
Update the catch block in `measureUploadMbps`:
```kotlin
catch (e: Exception) {
    val line = e.stackTrace.firstOrNull()?.lineNumber ?: -1
    android.util.Log.w("WinsSpeedUpload", "Upload stream $streamIndex error at line $line: ${e.javaClass.simpleName}: ${e.message}")
}
```

#### Proposal 4: Retain 24 Streams and Direct Chunked Streaming
Retain 24 streams with 2 ms stagger and 256 KB chunked streaming mode.
Ensure `out.flush()` and response status reading are handled cleanly.

#### Proposal 5: Download Datapath 100% Frozen
Lines 1315-1437 of MainActivity.kt and download targets in lib/main.dart remain untouched.
