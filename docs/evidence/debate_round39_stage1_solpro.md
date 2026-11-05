# Round 39 stage1: solpro

Packet-only audit: source, test output, host state, and reboot persistence were not independently inspected. `[UNVERIFIED-LIVE]` marks assertions not demonstrated by the reported physical-phone run.

1. **Gateway verdict:** The design is internally coherent. A default port of 0 suppresses the listener, construction after `newSharedGatewayTun` ties it to forwarding mode, and binding `assign.V4` avoids the cover listener. The reported tests exercise counting, serving, caps, methods, and concurrency. `[UNVERIFIED-LIVE]` Listener scope was not confirmed with a live socket listing or an outer-interface connection attempt.

   The phrase “byte-for-byte unchanged” is not supportable for an upgraded binary containing a new file and flag. The defensible claim is default-off behavioral compatibility. `[UNVERIFIED-LIVE]` No flag-off regression run is reported.

   The JSON count is server-observed application bytes. It is stronger than client socket-write totals because `io.Copy` counted bytes delivered to the handler, but it is not a TCP ACK count in the protocol sense.

2. **Upload Content-Length:** The budget is sufficient at the stated target. Four GiB is 4,294,967,296 bytes, and division by 32 gives exactly 134,217,728 bytes, or 128 MiB, per stream. At 1 Gbps for 8 seconds, the aggregate body is:

   `1,000,000,000 x 8 / 8 = 1,000,000,000 bytes`

   With equal distribution, that is 31,250,000 bytes per stream, only 23.3 percent of the 128 MiB allowance. The aggregate budget is exhausted only near:

   `4,294,967,296 x 8 / 8 = 4.295 Gbps`

   At the live 358.5 Mbps result, the expected aggregate is 358.5 MB in 8 seconds, matching the reported 358 MB.

   Ending during the declared body is safe for the measurement but not clean HTTP framing. `shutdownOutput` places TCP FIN after queued bytes, the server reads until EOF, and the resulting `io.Copy` count is final for bytes delivered before that EOF. All 32 streams returning HTTP 200 is live evidence that this server accepted the short bodies and returned their counts.

   The request is still shorter than its declared Content-Length, so EOF is an incomplete-body condition. The packet does not state whether the handler checks the `io.Copy` error. `[UNVERIFIED-LIVE]` Chunked request encoding with a terminating zero chunk, or a small custom framed protocol, would end the window without relying on malformed Content-Length semantics.

   Uneven streams can individually reach 128 MiB before 8 seconds even when the aggregate remains below 4 GiB. One stream at 1 Gbps would consume 128 MiB in about `134,217,728 x 8 / 1,000,000,000 = 1.07 seconds`. `[UNVERIFIED-LIVE]` No per-stream budget-exhaustion test is reported.

3. **Semaphore:** A 64-request semaphore does not constrain one 32-stream upload because 32 permits remain. It can admit two complete 32-stream tests, while request 65 waits. The live result, with all 32 requests receiving 200, proves capacity for one test, not for 64 simultaneous active requests.

   Stream reuse does not change the active-request arithmetic if each completed handler releases its permit. The raw upload itself shuts down each socket, so it is not persistent HTTP reuse.

   The semaphore also creates an inner-network denial mechanism. Sixty-four slow requests can occupy all permits for up to the 120 second read timeout, and the firewall admits the whole `10.10.0.0/24` source range. `[UNVERIFIED-LIVE]` Authentication, per-session quotas, semaphore wait limits, and overload status behavior are not reported.

4. **Timeout and cap defects:** The 8 second upload window fits comfortably inside the 120 second read timeout. The larger advertised limits do not always fit. Sending 1 GiB inside 120 seconds requires about:

   `1,073,741,824 x 8 / 120 = 71.6 Mbps`

   A slower maximum-size upload will time out. This does not affect the current 128 MiB per-stream client budget, but it means the 1 GiB API cap is not reachable at all supported rates.

   `[UNVERIFIED-LIVE]` The packet does not say whether an oversized POST returns 413 or returns 200 with a capped count after `MaxBytesReader` reports an error. It also does not state native connect, write, and response-read deadlines. The shared 8 second send window alone cannot stop a response read from hanging.

5. **Port discovery:** The gateway port is configurable, while Dart hardcodes 8455 and the signed descriptor supplies only the address. Canada works because both sides use 8455. Any node using another nonzero port will fail and fall back. `[UNVERIFIED-LIVE]` A signed ingest capability and port field would avoid probing old nodes and eliminate configuration divergence.

6. **Latch and stale Dart state:** Clearing only the native latch prevents a stale upload from reaching a different latched address:

   * Native latch null plus stale Dart address results in rejection.
   * Native latch for node B plus stale node A address results in `A != B`, hence rejection.
   * Fresh Dart B plus native B permits the request.

   The stale field still creates an availability defect. The Dart download path is not described as having the native equality gate, so a reconnect can prepend the old target before the new descriptor updates Dart state. If both nodes use the same inner address, address equality also cannot distinguish session identity, although routing would normally deliver that address to the current tunnel.

   `[UNVERIFIED-LIVE]` Clear the Dart field during teardown and bind both the Dart target and native latch to a session generation. This also blocks late callbacks from an earlier connection.

7. **Deployment evidence:** The live phone result proves that a listener was reachable through the tunnel and that at least 32 uploads completed with HTTP 200. The upload arithmetic is consistent: 358 MB over 8 seconds is about 358 Mbps. The directional ratio is `1166 / 358.5 = 3.25`, which supports the stated rounded 3.3x asymmetry.

   The phone run does not prove reboot persistence, exact installed binary identity, outer-interface nonreachability, or the relative claim “highest ever.” `[UNVERIFIED-LIVE]` Those require a reboot check, binary hash or version, socket binding inspection, firewall listing, and an outer-address negative probe.

   The literal backslash incident and wrong-filename incident are consistent with the need for those checks. The current live listener proves the corrected unit parsed far enough to enable port 8455, but it does not prove the saved firewall survives reboot.

8. **Ingress premise:** The ingest test removes public Internet transit after the gateway, but it does not by itself prove the ceiling is Winn software. Client radio uplink, carrier path directionality, client encryption, gateway decryption, and gateway TUN writes remain in the measured path. `[UNVERIFIED-LIVE]` No direct carrier UDP baseline or stage counters are supplied.

9. **Rank 1, pipe inbox overflow:** This is the strongest listed loss candidate because it is explicitly lossy and its depth equals the current AF_UNIX batch size. At 1500 bytes per packet, 358.5 Mbps is about 29,875 packets per second, so 256 packets represent only 8.6 ms. At 1 Gbps, 256 packets represent 3.1 ms. A scheduler or driver stall of those durations can fill the inbox.

   Cheapest discriminator: count demux attempts, successful enqueues, full-inbox drops, and occupancy high-water marks once per second. Any nonzero full-inbox count directly proves this loss site.

10. **Rank 2, single driver loop:** At 1500-byte packets, the loop has about 33.5 microseconds per packet at 358.5 Mbps, but only 12 microseconds at 1 Gbps. If dequeue plus decrypt, forwarding, and TUN write consumes near 33 microseconds, the observed ceiling follows.

   Cheapest discriminator: measure packets, bytes, and elapsed processing nanoseconds around the loop and each major stage. Increasing depth from 256 to 2048 raises buffering from 8.6 to 68.6 ms at the current rate, but it cannot fix a sustained consumer-rate deficit. A short improvement followed by renewed drops identifies burst absorption rather than added service capacity.

11. **Rank 3, AF_UNIX batch 256:** At 358.5 Mbps and 1500-byte packets, a full 256-packet batch implies about `29,875 / 256 = 117` batch dispatches per second. Moving to 512 lowers that to about 58 dispatches per second but does not halve packet encryption, UDP sends, demux, driver work, or TUN writes.

   `[UNVERIFIED-LIVE]` A 256 to 512 change is therefore unlikely to double sustained ingress unless batch dispatch itself consumes close to half the processing time. It can also increase burst pressure against a 256-frame inbox. Test 128, 256, and 512 only while collecting inbox occupancy and drop counters.

12. **Rank 4, demux contention:** The gateway demux is shared, so lock or scheduling contention is possible, but the packet provides no session count, CPU profile, mutex wait, or block time. That leaves less evidence than the explicit lossy inbox and serial consumer. `[UNVERIFIED-LIVE]` A one-session run with mutex and block timing is the cheapest discriminator.

13. **Rank 5, client SO_SNDBUF:** Eight MiB holds about 187 ms of traffic at 358.5 Mbps and 67 ms at 1 Gbps:

   `8 x 1,048,576 x 8 / 358,500,000 = 0.187 seconds`

   That capacity is large relative to the 3.1 ms target-rate inbox window, so buffer size alone is a weaker candidate. `[UNVERIFIED-LIVE]` Record actual `SO_SNDBUF`, UDP send duration, and `EAGAIN` or `ENOBUFS`, then compare 8 MiB with 32 MiB. A throughput change without gateway inbox drops would move this candidate upward.

**NEXT:** Add per-second counters for client carrier UDP sends, gateway UDP receives, inbox accepted and dropped frames, driver dequeues, and TUN-written bytes, then repeat the same 8 second 32-stream phone upload. This single stage ladder identifies the first rate collapse and directly separates carrier arrival, inbox loss, and driver or TUN limitation.
