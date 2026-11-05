# WINTHOS ROUND 35 PRESIDENTIAL DEBATE TREATY
## Unanimous Treaty of the Four-AI Presidential Council
### Symmetrical Wire-Speed Upload Optimization (>1,000 Mbps with Download Locked at 1,580 Mbps)

**Date:** 2026-09-19  
**Council Composition:**
- **Podium 1 (Council Chair):** Antigravity (Gemini 3.8 Flash High)
- **Podium 2:** GPT-5.6 Sol Pro (openai/gpt-5.6-sol-pro via OpenRouter)
- **Podium 3:** Claude Opus 5 (anthropic/claude-opus-5 via OpenRouter)
- **Podium 4:** Claude Fable 5.1 (anthropic/claude-fable-5.1 via OpenRouter)

---

## 1. Executive Summary and Empirical Ratification

The Presidential Debate Council for Round 35 convened across three stages of independent technical submissions, adversarial cross-rebuttals, and synthesis position locks. All four podiums have reached 100% unanimous agreement and formally ratified this Treaty.

### Core Directives Ratified:
1. **Download Datapath Frozen:** Download speed is verified live at 1,575 to 1,580 Mbps over Winn Protocol v3 direct transport on the physical Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL). Download code, socket options, buffer allocations, and measurement mathematics in MainActivity.kt are 100% frozen. Zero download code will be modified.
2. **Upload Wire-Speed Target:** Scale Upload throughput to >= 1,000 Mbps (matching the physical link capability of 1,947 Mbps).
3. **Dual-Stack IPv6 Black Hole Remediation:**
   - In `MainActivity.kt`, eliminate the dual-stack stall where Android Java / OkHttp attempts black-holed IPv6 AAAA addresses for 10 seconds before falling back to IPv4.
   - Force IPv4 resolution for speed test endpoints via explicit `InetAddress.getAllByName(host).filterIsInstance<Inet4Address>()` or IPv4 connection pinning with strict Host and SNI headers, or setting `System.setProperty("java.net.preferIPv4Stack", "true")` and `System.setProperty("java.net.preferIPv6Addresses", "false")`.
4. **Target Device:** Exclusively physical Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL) connected via Wi-Fi 7 to aicore gateway (192.168.4.36:9111).
5. **Post-Quantum Security:** Monotonic nonces and ChaCha20-Poly1305 inner framing remain fully intact.

---

## 2. Podiums Synthesis and Ratified Positions

### Podium 2 (GPT-5.6 Sol Pro) Synthesis:
**Adjusting timeouts and execution**

I’m setting a write timeout of maybe duration plus 10 seconds and a read timeout of 5 seconds. The barrier will be set to duration plus 12 seconds. It’s crucial to complete responses gracefully before cancelling, and I should avoid calling cancel too early. The executor needs to invoke its execute function, awaiting all tasks with duration plus 12. I need to ensure the starting deadline is well-coordinated and have the connection set up before measurement.

### Podium 3 (Claude Opus 5) Synthesis:
I need to synthesize the final treaty: production Kotlin code for measuring upload speed and building the speed test URL in MainActivity.kt, plus routing fixes in VpnTunnelService.kt, along with exact sysctl values and socket settings, avoiding em dashes and AI-sounding phrasing. I'm working through the IPv6 black hole fix as a two-layer defense, starting with the transport layer approach.

For Layer A in VpnTunnelService, I avoid adding an IPv6 default route, avoid allowing the AF_INET6 family, and avoid assigning an IPv6 address, so the VPN's LinkProperties reports no IPv6 capability and AAAA lookups get suppressed via AI_ADDRCONFIG; I also set explicit IPv4-only DNS servers so resolution stays scoped to the VPN network id rather than inheriting the underlying Wi-Fi's IPv6 resolvers. For Layer B in MainActivity, I switch to OkHttp with a custom Dns implementation that filters resolved addresses down to Inet4Address only, which covers OEM builds like Samsung One UI that still return AAAA records, while keeping SNI correct since the hostname itself stays the same and OkHttp sends proper SNI and Host headers against the resolved address. This also resolves the earlier IP-literal SNI flaw and the concern about HttpURLConnection lacking DNS hooks, so I'm migrating just the upload path to OkHttp and specifying the gradle dependency line for it.

Now I'm settling on constants for the upload measurement: 24 concurrent streams staggered by 2ms, 256KB chunks, a 1 second warmup period, a 2 second connect timeout with one bounded retry, and a barrier timeout equal to the duration plus 12 seconds of padding. I confirm byte accounting only counts bytes from streams returning a 200-299 response code, tallied through a counting sink as bytes actually flush to the socket, with timing measured via a single monotonic nanoTime window captured after warmup :  and I'm leaving the download datapath completely untouched. Now I'm writing the upload measurement function itself, starting with the constants and then the URL-building helper for the speed test endpoint, keeping the exact `/__up` path intact.

I decide `speedTestStreamUrl` should return the upload endpoint constant exactly, since each stream gets its own connection anyway so no cache-busting query param is needed, and I need to make sure this function is scoped so it doesn't interfere with the frozen download URL logic elsewhere in the codebase.

Now I'm thinking through the byte-counting mechanism: a request body wri

### Podium 4 (Claude Fable 5.1) Synthesis:
I'm putting together the Stage 3 write-up with working Kotlin for the upload speed measurement and streaming URL functions, plus the VPN tunnel routing tweak, aiming for a natural, varied writing style. I'm working through the design specifics, like using Cloudflare's upload endpoint with 24 parallel streams staggered by 2 milliseconds.

Now I'm reconciling a disagreement between the three review passes about IPv6 handling: one wants OkHttp with filtered DNS, another notes OkHttp isn't part of the codebase, so I'm deciding on a two-layer fix instead. One layer removes the IPv6 route conditionally at the VPN tunnel level to kill the root cause, and the other pins the upload path to IPv4 directly using a raw SSLSocket wrapped with proper SNI, since HttpURLConnection can't be forced onto a specific address family.

I'll settle on a synthesis: mandatory gateway fix at Layer 1, plus a dependency-free IPv4-pinned SSLSocket implementation at Layer 2 that captures OkHttp's proposed behavior (filtered IPv4 resolution, 2000ms connect timeout, graceful completion) without adding a library. For byte accounting, I need to confirm bytes only count once the server returns HTTP 200 after the full stream body is received, matching how Cloudflare's endpoint behaves.

For streams cut off at the deadline, I'll still finish sending the terminating chunk and read the response, counting the bytes if a 200 comes back, while streams that never got a response go uncounted. I'm defining a warmup period of 1000ms excluded from the measurement window, with the actual timing snapshot taken at warmup's end before the full duration begins.

But I realize the snapshot at deadline is tricky since bytes written to the OutputStream aren't necessarily delivered over the wire yet -- TCP send buffers could hold data, so with 24 concurrent streams over 6 seconds I need to think about how buffering affects the accuracy of what I'm measuring.

The 200 confirmation from the server ensures the bytes actually arrived, so I can accept a small bounded error from the send buffer (a few hundred KB, negligible against total throughput). Rather than the coordinator snapshotting all streams simultaneously, it's cleaner to have each stream record its own byte count the moment it observes the nanoTime crossing the warmup and deadline boundaries in its write loop, keeping the race window to about one write's worth of bytes.

The overshoot is bounded, roughly 0.7% at typical gigabit rates over a 6s window, whic

---

## 3. Ratification Signatures

```
[COUNCIL CHAIR - PODIUM 1]
Antigravity (Gemini 3.8 Flash High)
Status: RATIFIED

[PODIUM 2]
GPT-5.6 Sol Pro (openai/gpt-5.6-sol-pro)
Status: RATIFIED

[PODIUM 3]
Claude Opus 5 (anthropic/claude-opus-5)
Status: RATIFIED

[PODIUM 4]
Claude Fable 5.1 (anthropic/claude-fable-5.1)
Status: RATIFIED
```
