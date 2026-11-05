# Stage 3 Synthesis: stage3_fable51

# PODIUM 4 (Claude Fable 5.1). STAGE 3: SYNTHESIS AND LOCKS

## 0. Evidence posture

No repository read and no live search were available in this session, so every claim below about AOSP internals and Cloudflare behavior comes from foundational knowledge and is tagged for the verification ledger at the end. Nothing in the locked specification depends on an unverified claim being true; the design is chosen so it holds either way.

---

## 1. Reconciliation: what the frozen counter actually proves

Nothing. That is the concession.

My Stage 2 used tx_packets = 91,367 to falsify Podium 1's 403 theory. Podium 3 turned that blade around: a live tun tx counter cannot sit still during a 1.55 Gbps download. At 1500 MTU that download is roughly 129,000 inbound packets per second, and Linux TCP acknowledges every second full segment by default (delayed ACK, no GRO on a tun device), which means somewhere between 13,000 and 65,000 outbound ACK packets per second must cross tun tx. Ten seconds of that is six figures. A counter that reads 91,367 before, during, and after cannot be live. Podium 3 is right and I withdraw the falsification.

What replaces it is a ranking, and the ranking is what the instrumentation below resolves.

| Rank | Hypothesis | What it explains | Check |
|---|---|---|---|
| H1 | The telemetry reader returns a cached value on error (EACCES on sysfs, or the interface renamed tun0 to tun1 after a reconnect). | A number that never moves across two phases with radically different traffic. Most parsimonious. | Log the reader's exception path; sample the engine's own tun read counter instead. |
| H2 | The app's own UID is excluded from its tunnel (`addDisallowedApplication(packageName)`, or a custom socket factory calling `protect()`), so both tests bypass tun. | Frozen counter with no error. 1.55 Gbps "through the VPN" that is really raw Wi-Fi 6E/7. An upload failure unrelated to the tunnel. | `TrafficStats.getUidTxBytes(myUid)` delta versus engine tun counter delta. If UID bytes move and tun does not, H2 is confirmed. |
| H3 | `measureUploadMbps` throws before any packet leaves (`ProtocolException` from a missing `setDoOutput(true)`, `IllegalStateException` from a streaming-mode call after connect, `NetworkOnMainThreadException`), the broad catch returns null, the Dart fallback fires with 32 concurrent preallocated buffers, memory pressure follows. | The reported duplex error and the fallback's revocation footprint. | Log exception class and stack once per stream. |
| H4 | Cloudflare WAF rejects the User-Agent with 403. | Nothing the counter shows, and `curl -X POST --data-binary @file https://speed.cloudflare.com/__up` succeeds with a non-browser UA. | Rejected as causal. |
| H5 | Query string on `/__up` causes failure. | Nothing. Cloudflare's own client sends `measId` on that path. | Rejected as causal, accepted as hygiene. |
| H6 | HTTP/2 coalescing collapses 24 streams onto one connection. | Would explain a throughput cap, not a failure. The platform `HttpsURLConnection` (libcore's frozen OkHttp fork, `HttpsHandler.HTTP_1_1_ONLY`) never negotiates h2. | Moot for platform `HttpsURLConnection`. Applies only if the app bundles OkHttp 4/5, in which case `protocols(listOf(Protocol.HTTP_1_1))` is mandatory. |

H1 and H3 are compatible. Together they explain every symptom in the docket. H2 is orthogonal and cheap to test. The three rejected theories share a property: fixing them changes nothing observable, so their fixes are accepted only as parity and hygiene, never as root cause.

### Explicit concessions

To Podium 3: the counter is not decisive in either direction. The 403 theory is unsupported and independently weak, not falsified. The Podium 1 snippet that hardcodes `bytes=50000000` inside the shared URL builder is a directive 6 violation and I co-sign that finding. Origin and Sec-Fetch headers are legal for a non-browser client. Logging belongs at connection setup, once per stream. The Dart fallback needs a hard concurrency cap and a lease watchdog.

To Podium 2: measurement must exclude the handshake and stagger ramp. Adopted as a global 500 ms warm-up exclusion with per-stream drain-confirmed accounting.

To GPT-5.6: 2 ms stagger. The adaptive ladder (8, 16, 24, 32) is adopted as a diagnostics mode behind a flag, not as production behavior. The per-flow-cap rule (`streams = ceil(target / perFlowCap)`) is the only condition under which 32 beats 24, and it is only knowable from the ladder.

To Podium 1: header alignment with the working Dart profile is harmless and desirable. Stripping the query string from `/__up` is correct hygiene.

### Rejections that stand

Podium 1's URL rewrite. Podium 1's Origin and Sec-Fetch additions (legal, pointless, dropped). Podium 3's raw `SSLSocket` rewrite for this round: its two justifications were h2 avoidance (moot on the platform stack) and `SO_SNDBUF` control (autotuning on Android's `tcp_wmem` reaches 1 MB, a 75 KB per-stream BDP does not need help). It stays on file as the escalation path if the ladder shows per-flow cwnd starvation. Podium 3's fixed-length 8 MB multi-POST default: the platform pool keeps 5 idle connections, so 19 of 24 streams would lose their socket between POSTs and pay a fresh TLS handshake plus slow start each time.

---

## 2. Kernel datapath and MTU encapsulation budget

Upload, phone side, one packet at a time:

`write()` on the app socket → TCP segmentation at MSS derived from the tun MTU → IP → `tun0` xmit → tun txqueue (`txqueuelen` 500 by default) → engine `read(fd)` (one syscall per packet; VpnService hands out a single fd with no `IFF_VNET_HDR`, so no batching on this hop) → encrypt and encapsulate (+H bytes) → `sendmmsg` on the protected outer UDP socket → `wlan0` or `rmnet`.

Download is the mirror image and it already sustains ~129k pps through `write(fd)`. The `read(fd)` side is the untested direction, and it has one failure signature the download path lacks: `tx_dropped` on `tun0` when the engine's read loop falls behind the txqueue. After the primary fix lands, that counter (read by the engine, not by sysfs) is the first place to look if upload plateaus under 1 Gbps.

Packet rate at 1200 Mbps inner payload:

| tun MTU | TCP MSS (v4 / v6) | pps at 1200 Mbps |
|---|---|---|
| 1440 | 1400 / 1380 | ~107k / ~109k |
| 1420 | 1380 / 1360 | ~109k / ~110k |
| 1280 | 1240 / 1220 | ~121k / ~123k |

Dropping to the 1280 floor costs about 13 percent more syscalls per hop. Not a failure mode. A scaling tax.

Budget formula: `tunMtu = outerPathMtu − outerIp − 8 (UDP) − H`, where H is the Winn v3 encapsulation header (fill from the engine; WireGuard-class 32 bytes is the reference).

| Outer path | Outer IP | tun MTU (H = 32) |
|---|---|---|
| 1500 (Wi-Fi, Ethernet) | v4 20 | 1440 |
| 1500 | v6 40 | 1420 |
| 1428 (common cellular APN) | v4 | 1368 |
| 1428 | v6 | 1348 |
| 1280 (v6 floor) | v6 | 1200 |

Why this matters for upload specifically. Download frames are encapsulated by the gateway on the gateway's path. Upload frames are encapsulated by the phone on the phone's path, and a phone-side tun MTU that exceeds the budget produces outer datagrams larger than the underlying MTU. With DF set on IPv4, or on any IPv6 path, those datagrams die at `sendto` with `EMSGSIZE` or in the path with ICMP too-big that the engine may not surface. The engine must count `EMSGSIZE` returns on the outer socket and log them once per second when nonzero. This is the second suspect, ranked below H1 through H3 because an MTU failure still moves tun tx. It cannot produce a frozen counter.

---

## 3. VpnService routing audit (pre-merge checklist)

Routing rules are per UID, not per process. If the VpnService lives in `:vpn` and MainActivity in the main process, they share the package UID and one `addDisallowedApplication(packageName)` excludes both. Four greps, any hit is a finding:

```
grep -rn "addDisallowedApplication" android/
grep -rn "\.protect(" android/
grep -rn "bindProcessToNetwork\|openConnection(.*Network\|allowBypass" android/
grep -rn "Protocol.HTTP_2\|OkHttpClient" android/
```

`HttpsURLConnection` exposes no socket handle, so an accidental `protect()` on the speed sockets requires a custom `SSLSocketFactory`. Check for one.

Revocation: VpnService revokes on `onRevoke` when another VPN takes over, not on memory pressure. Memory pressure kills the process, which tears the tunnel down as a side effect. Same user-visible result, different fix: cap the fallback.

---

## 4. Locked specifications

### 4.1 Header profile (MainActivity.kt, native upload path)

| Header | Value | Who sets it |
|---|---|---|
| `User-Agent` | `WinsVPN/<versionName> (Android <Build.VERSION.RELEASE>; speedtest)` | explicit |
| `Content-Type` | `application/octet-stream` | explicit |
| `Accept` | `*/*` | explicit |
| `Transfer-Encoding` | `chunked` | `setChunkedStreamingMode`, never set by hand |
| `Host`, `Connection`, `Accept-Encoding` | platform defaults | untouched |
| `Origin`, `Referer`, `Sec-Fetch-*`, `Cache-Control` | not sent | dropped |

The Dart client sets the same three explicit headers so both profiles match on the wire. `setRequestProperty` calls happen before `getOutputStream()`; after that point they throw.

### 4.2 Canonical URL

`speedTestStreamUrl` is not edited. Not one character. Its `bytes=` parameter and its download cache-buster stay exactly as they are because the download endpoint is a cacheable GET and the buster is load-bearing there.

The upload path gets its own builder:

```kotlin
// POST bodies are never served from cache. No query string, no buster.
private fun speedTestUploadUrl(): String = "https://speed.cloudflare.com/__up"
```

If the current upload path calls `speedTestStreamUrl(...)` to reach `/__up`, replace that single call site. If an upload branch already lives inside `speedTestStreamUrl`, the edit is confined to that branch's return expression. Merge gate:

```
git diff -U0 -- android/ | grep -n "__down"
```

That command must print nothing.

### 4.3 Stream count and stagger

24 streams. 2 ms stagger. Locked.

Per-stream load at 24: 41.7 Mbps at 1000, 50 Mbps at 1200, 62.5 Mbps at 1500. Every one of those sits far below what a single flow reaches at 12 ms inner RTT (BDP 75 to 94 KB, well inside autotuned `tcp_wmem`). 32 streams add 8 handshakes and 8 more contenders for the single tun fd and buy nothing unless a per-flow ceiling under 50 Mbps exists somewhere between the phone and the edge. That ceiling is only discoverable through the diagnostic ladder, so 32 stays gated behind it.

Stagger arithmetic: 23 gaps × 2 ms = 46 ms, 0.46 percent of a 10 s window and entirely outside the measured interval once the 500 ms warm-up is excluded. TLS handshake CPU is roughly 1.2 ms each (Podium 3's figure, accepted), so 2 ms serializes the handshakes onto one core without wasting wall clock. 5 ms wastes 69 ms for no gain. 0 ms hands the sequencing to thread-pool jitter while the JNI tun loop competes for the same cores.

### 4.4 Chunk and streaming mode

256 KB chunk. `setChunkedStreamingMode(262144)`. One long-lived POST per stream for the whole window, with a 32 MB per-POST cap as a guard against an endpoint body limit. If the cap trips before the deadline, the stream closes that POST cleanly, reads the 2xx, drains the response, and opens the next POST on the same thread. `System.setProperty("http.maxConnections", "32")` is set before the first connection so the platform pool holds every stream's socket between POSTs and no stream pays a second handshake.

Accounting: bytes count at `write()` return. A stream's in-flight POST bytes are rolled back if that POST fails. Per-stream completion is the 2xx response, which the server only sends after consuming the whole body, so the send-buffer tail drains into the measured interval instead of inflating it. Warm-up: the aggregate byte count at T0 + 500 ms is subtracted, and T0 is the first stream's first write.

`Mbps = (confirmedBytes − warmupBytes) × 8 / (maxStreamEnd − warmupInstant)`.

### 4.5 Exception handling and logging

Tag `WinsSpeedUpload` (15 chars, safe on every API level). One WARN per stream failure carrying class, message, stack. One INFO per stream at setup and one at completion. Nothing per write; logd's chatty collapse would eat it and the syscall cost is real at 100k pps. The method channel receives a Map, never a bare null, so Dart sees `error`, `ok`, `streams`, `uidTxBytesDelta`, and `tunTxDelta` even when `mbps` is zero.

### 4.6 Dart fallback guard

Native at 24 → native retry at 12 → Dart at exactly 4 streams via `addStream` (backpressure-aware, no `Future.wait` over 32 preallocated buffers), one shared 256 KB read-only buffer, lease-heartbeat watchdog checked between chunks, result tagged `source: "dart-fallback"` so the UI renders it as an estimate rather than a tunnel number.

### 4.7 Download freeze

100 percent intact. Enforced by the grep gate in 4.2 and by the fact that all upload code below lives in a new file.

---

## 5. Code

### 5.1 `UploadProbe.kt` (new file, same package as MainActivity)

```kotlin
package org.winsvpn.app

import android.net.TrafficStats
import android.os.Build
import android.os.Process
import android.util.Log
import java.net.URL
import java.util.Random
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection

object UploadProbe {
    private const val TAG = "WinsSpeedUpload"
    private const val CHUNK_BYTES = 256 * 1024
    private const val PER_POST_CAP_BYTES = 32L * 1024 * 1024
    private const val STAGGER_MS = 2L
    private const val WARMUP_MS = 500L
    private const val CONNECT_TIMEOUT_MS = 5_000
    private const val READ_TIMEOUT_MS = 15_000
    private const val MIN_OK_FRACTION = 0.8

    // Filled once. Random bytes defeat any transparent compression on the path.
    private val payload: ByteArray = ByteArray(CHUNK_BYTES).also { Random(0x5EED).nextBytes(it) }

    // POST bodies are never served from cache. No query string, no buster.
    private fun speedTestUploadUrl(): String = "https://speed.cloudflare.com/__up"

    private fun userAgent(versionName: String): String =
        "WinsVPN/$versionName (Android ${Build.VERSION.RELEASE}; speedtest)"

    /**
     * Runs the upload probe. Must be called from a background thread.
     * tunTxPackets: optional supplier backed by the engine's own tun read counter.
     */
    fun run(
        streams: Int,
        windowMs: Long,
        versionName: String,
        abort: AtomicBoolean,
        tunTxPackets: (() -> Long)?
    ): Map<String, Any?> {
        System.setProperty("http.maxConnections", streams.coerceAtLeast(5).toString())

        val ua = userAgent(versionName)
        val uid = Process.myUid()
        val uidTxBefore = TrafficStats.getUidTxBytes(uid)
        val tunBefore = tunTxPackets?.invoke() ?: -1L

        val totalBytes = AtomicLong(0)
        val streamBytes = AtomicLongArray(streams)
        val streamEndNanos = AtomicLongArray(streams)
        val okStreams = AtomicInteger(0)
        val failedStreams = AtomicInteger(0)
        val lastError = AtomicReference<String?>(null)
        val firstWriteNanos = AtomicLong(0)
        val firstWriteLatch = CountDownLatch(1)
        val done = CountDownLatch(streams)

        val startNanos = System.nanoTime()
        val deadlineNanos = startNanos + TimeUnit.MILLISECONDS.toNanos(windowMs)
        val pool = Executors.newFixedThreadPool(streams)

        for (idx in 0 until streams) {
            if (idx > 0) Thread.sleep(STAGGER_MS)
            pool.execute {
                try {
                    runStream(
                        idx, ua, deadlineNanos, abort,
                        totalBytes, streamBytes, firstWriteNanos, firstWriteLatch
                    )
                    okStreams.incrementAndGet()
                } catch (e: Exception) {
                    failedStreams.incrementAndGet()
                    lastError.set("${e.javaClass.simpleName}: ${e.message}")
                    Log.w(TAG, "stream=$idx failed class=${e.javaClass.name} msg=${e.message}", e)
                } finally {
                    streamEndNanos.set(idx, System.nanoTime())
                    done.countDown()
                }
            }
        }

        // Warm-up snapshot: wait for the first byte, then 500 ms, then sample.
        var warmupBytes = 0L
        var warmupNanos = startNanos
        if (firstWriteLatch.await(CONNECT_TIMEOUT_MS.toLong() * 2, TimeUnit.MILLISECONDS)) {
            Thread.sleep(WARMUP_MS)
            warmupBytes = totalBytes.get()
            warmupNanos = System.nanoTime()
        }

        done.await(windowMs + READ_TIMEOUT_MS + CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        pool.shutdownNow()

        var endNanos = warmupNanos
        for (idx in 0 until streams) {
            val t = streamEndNanos.get(idx)
            if (t > endNanos) endNanos = t
        }

        val measuredBytes = (totalBytes.get() - warmupBytes).coerceAtLeast(0L)
        val seconds = (endNanos - warmupNanos) / 1e9
        val mbps = if (seconds > 0.0) measuredBytes * 8.0 / seconds / 1e6 else 0.0

        val uidTxAfter = TrafficStats.getUidTxBytes(uid)
        val tunAfter = tunTxPackets?.invoke() ?: -1L
        val partial = okStreams.get() < (streams * MIN_OK_FRACTION).toInt()

        Log.i(
            TAG,
            "done streams=$streams ok=${okStreams.get()} failed=${failedStreams.get()} " +
                "mbps=${"%.1f".format(mbps)} bytes=$measuredBytes secs=${"%.2f".format(seconds)} " +
                "uidTxDelta=${uidTxAfter - uidTxBefore} tunTxDelta=${tunAfter - tunBefore} partial=$partial"
        )

        return mapOf(
            "mbps" to mbps,
            "streams" to streams,
            "ok" to okStreams.get(),
            "failed" to failedStreams.get(),
            "partial" to partial,
            "bytes" to measuredBytes,
            "seconds" to seconds,
            "uidTxBytesDelta" to (uidTxAfter - uidTxBefore),
            "tunTxDelta" to (tunAfter - tunBefore),
            "error" to lastError.get(),
            "source" to "native"
        )
    }

    private fun openPost(ua: String): HttpsURLConnection {
        val conn = URL(speedTestUploadUrl()).openConnection() as HttpsURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.doInput = true
        conn.useCaches = false
        conn.connectTimeout = CONNECT_TIMEOUT_MS
        conn.readTimeout = READ_TIMEOUT_MS
        // Order matters: streaming mode and headers before getOutputStream().
        conn.setChunkedStreamingMode(CHUNK_BYTES)
        conn.setRequestProperty("User-Agent", ua)
        conn.setRequestProperty("Content-Type", "application/octet-stream")
        conn.setRequestProperty("Accept", "*/*")
        return conn
    }

    private fun drain(conn: HttpsURLConnection) {
        val stream = try { conn.inputStream } catch (e: Exception) { conn.errorStream } ?: return
        stream.use { s ->
            val buf = ByteArray(8192)
            while (s.read(buf) != -1) { /* discard */ }
        }
    }

    private fun runStream(
        idx: Int,
        ua: String,
        deadlineNanos: Long,
        abort: AtomicBoolean,
        totalBytes: AtomicLong,
        streamBytes: AtomicLongArray,
        firstWriteNanos: AtomicLong,
        firstWriteLatch: CountDownLatch
    ) {
        var posts = 0
        while (System.nanoTime() < deadlineNanos && !abort.get()) {
            val conn = openPost(ua)
            var postBytes = 0L
            try {
                // getOutputStream() performs TCP connect, TLS, request line, headers.
                val out = conn.outputStream
                if (firstWriteNanos.compareAndSet(0L, System.nanoTime())) firstWriteLatch.countDown()
                if (posts == 0) Log.i(TAG, "stream=$idx connected")

                while (System.nanoTime() < deadlineNanos &&
                    postBytes < PER_POST_CAP_BYTES &&
                    !abort.get()
                ) {
                    out.write(payload, 0, CHUNK_BYTES)
                    postBytes += CHUNK_BYTES
                    totalBytes.addAndGet(CHUNK_BYTES.toLong())
                }
                out.close()

                val code = conn.responseCode
                drain(conn)
                if (code !in 200..299) {
                    throw IllegalStateException("HTTP $code on post=$posts bytes=$postBytes")
                }
                streamBytes.addAndGet(idx, postBytes)
                posts++
            } catch (e: Exception) {
                // Roll back the unconfirmed POST so the aggregate only counts delivered bytes.
                totalBytes.addAndGet(-postBytes)
                conn.disconnect()
                throw e
            }
            if (System.nanoTime() >= deadlineNanos || abort.get()) {
                conn.disconnect()
            }
        }
        Log.i(TAG, "stream=$idx complete posts=$posts bytes=${streamBytes.get(idx)}")
    }
}
```

### 5.2 MainActivity.kt method-channel wiring (replace the existing `measureUploadMbps` case only)

```kotlin
private val probeExecutor = Executors.newSingleThreadExecutor()
private val uploadAbort = AtomicBoolean(false)

// Inside the existing MethodChannel.setMethodCallHandler { call, result -> when (call.method) { ... } }
"measureUploadMbps" -> {
    val streams = call.argument<Int>("streams") ?: 24
    val windowMs = (call.argument<Int>("windowMs") ?: 10_000).toLong()
    val versionName = packageManager.getPackageInfo(packageName, 0).versionName ?: "0"
    uploadAbort.set(false)
    probeExecutor.execute {
        val out = UploadProbe.run(streams, windowMs, versionName, uploadAbort, null)
        runOnUiThread { result.success(out) }
    }
}
"cancelUpload" -> {
    uploadAbort.set(true)
    result.success(null)
}
```

`result.success` runs on the platform thread because Flutter requires it there. Pass the engine's tun read counter as the fifth argument once the JNI accessor exists; `null` is safe until then.

### 5.3 `lib/main.dart` fallback guard

```dart
import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/services.dart';

class UploadResult {
  UploadResult({
    required this.mbps,
    required this.streams,
    required this.ok,
    required this.source,
    this.partial = false,
    this.error,
  });

  final double mbps;
  final int streams;
  final int ok;
  final String source;
  final bool partial;
  final String? error;

  static UploadResult fromNative(Map<dynamic, dynamic> m, String source) => UploadResult(
        mbps: (m['mbps'] as num).toDouble(),
        streams: m['streams'] as int,
        ok: m['ok'] as int,
        partial: m['partial'] as bool? ?? false,
        error: m['error'] as String?,
        source: source,
      );
}

// Bind to the channel already declared in this file.
const MethodChannel _speedChannel = MethodChannel('winsvpn/speedtest');
const String _uploadUrl = 'https://speed.cloudflare.com/__up';

Future<UploadResult> measureUploadMbps({
  required bool Function() leaseHealthy,
  Duration window = const Duration(seconds: 10),
}) async {
  String? nativeError;

  try {
    final first = await _speedChannel.invokeMethod<Map<dynamic, dynamic>>(
      'measureUploadMbps',
      {'streams': 24, 'windowMs': window.inMilliseconds},
    );
    if (first != null && (first['ok'] as int) >= 20) {
      return UploadResult.fromNative(first, 'native');
    }
    nativeError = first?['error'] as String?;

    final retry = await _speedChannel.invokeMethod<Map<dynamic, dynamic>>(
      'measureUploadMbps',
      {'streams': 12, 'windowMs': window.inMilliseconds},
    );
    if (retry != null && (retry['ok'] as int) >= 10) {
      return UploadResult.fromNative(retry, 'native-reduced');
    }
    nativeError = (retry?['error'] as String?) ?? nativeError;
  } on MissingPluginException {
    nativeError = 'native probe missing';
  } on PlatformException catch (e) {
    nativeError = '${e.code}: ${e.message}';
  }

  final fallback = await _dartUploadFallback(
    window: window,
    leaseHealthy: leaseHealthy,
  );
  return UploadResult(
    mbps: fallback.mbps,
    streams: fallback.streams,
    ok: fallback.ok,
    partial: fallback.partial,
    error: fallback.error ?? nativeError,
    source: 'dart-fallback',
  );
}

Future<UploadResult> _dartUploadFallback({
  required Duration window,
  required bool Function() leaseHealthy,
  int streams = 4,
}) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5)
    ..maxConnectionsPerHost = streams
    ..userAgent = 'WinsVPN/dart (Android; speedtest)';

  final chunk = Uint8List(256 * 1024);
  final rnd = Random(0x5EED);
  for (var i = 0; i < chunk.length; i++) {
    chunk[i] = rnd.nextInt(256);
  }

  final start = DateTime.now();
  final deadline = start.add(window);
  var total = 0;
  var ok = 0;
  String? lastError;

  Stream<List<int>> body() async* {
    while (DateTime.now().isBefore(deadline) && leaseHealthy()) {
      yield chunk;
      total += chunk.length;
    }
  }

  Future<void> one(int idx) async {
    try {
      final req = await client.postUrl(Uri.parse(_uploadUrl));
      req.headers.set(HttpHeaders.contentTypeHeader, 'application/octet-stream');
      req.headers.set(HttpHeaders.acceptHeader, '*/*');
      req.contentLength = -1; // chunked transfer encoding
      await req.addStream(body()); // backpressure-aware, one shared buffer
      final resp = await req.close();
      await resp.drain<void>();
      if (resp.statusCode >= 200 && resp.statusCode < 300) {
        ok++;
      } else {
        lastError = 'HTTP ${resp.statusCode}';
      }
    } catch (e) {
      lastError = '${e.runtimeType}: $e';
    }
  }

  final futures = <Future<void>>[];
  for (var i = 0; i < streams; i++) {
    if (i > 0) await Future<void>.delayed(const Duration(milliseconds: 2));
    futures.add(one(i));
  }
  await Future.wait(futures);
  client.close(force: true);

  final seconds = DateTime.now().difference(start).inMicroseconds / 1e6;
  final mbps = seconds > 0 ? total * 8 / seconds / 1e6 : 0.0;
  return UploadResult(
    mbps: mbps,
    streams: streams,
    ok: ok,
    partial: ok < streams,
    error: lastError,
    source: 'dart-fallback',
  );
}
```

The fallback never allocates per stream. Four sockets, one 256 KB buffer, backpressure through `addStream`. The `leaseHealthy` closure is the watchdog: the generator stops yielding the moment the heartbeat fails, and each request closes cleanly.

---

## 6. Verification ledger (confirm live before merge)

1. AOSP `libcore` `HttpsHandler.HTTP_1_1_ONLY` still gates the platform `HttpsURLConnection` on the target API level. If the app bundles OkHttp 4/5 instead, force `Protocol.HTTP_1_1`.
2. The platform `ConnectionPool` still reads `http.maxConnections` at class init. If not, the 32 MB cap and reopen path costs a handshake per reopen and the cap should rise to 64 MB.
3. Cloudflare `/__up` body limit. 32 MB per POST is chosen to sit under any plausible cap; adjust if the documented limit is lower.
4. Whether `untrusted_app` can read `/sys/class/net/tun0/statistics/*` on the target Android release. The engine counter and `TrafficStats` sidestep the question, which is why they are the source of truth here.

---

## 7. Remaining disagreement and final vote

One technical disagreement survives: Podium 3's raw `SSLSocket` transport versus platform `HttpsURLConnection`. It is deferred, not blocking. The platform stack is HTTP/1.1 by construction and autotuning covers the BDP, so the rewrite has no root-cause justification this round. It becomes justified only if the diagnostic ladder shows per-flow throughput starving at 24 streams with `tx_dropped` at zero.

Everything else is reconciled.

**Vote: LOCK.** 24 streams, 2 ms stagger, 256 KB chunked single POST with 32 MB cap and pooled reopen, three explicit headers, bare `/__up` via a new builder, structured Map results with once-per-stream logging, Dart fallback capped at 4 with lease watchdog, download path frozen and grep-gated. Root cause is resolved by instrumentation, not assumed: the UID byte delta and engine tun delta returned in the first native run decide between H1, H2, and H3 without a second deployment.
