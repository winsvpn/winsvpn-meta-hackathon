import 'dart:async';
import 'dart:io';
import 'dart:math';

class ThroughputMeasurement {
  const ThroughputMeasurement({
    required this.bytes,
    required this.elapsed,
  });

  final int bytes;
  final Duration elapsed;

  double get mbps => throughputMbps(bytes, elapsed);
}

double throughputMbps(int bytes, Duration elapsed) {
  if (bytes <= 0 || elapsed.inMicroseconds <= 0) return 0;
  // One bit per microsecond is one megabit per second.
  return (bytes * 8) / elapsed.inMicroseconds;
}

class ThroughputSpeedTest {
  ThroughputSpeedTest({
    required this.userAgent,
    HttpClient Function()? clientFactory,
  }) : _clientFactory = clientFactory ?? HttpClient.new;

  final String userAgent;
  final HttpClient Function() _clientFactory;

  Future<ThroughputMeasurement?> measureDownload(
    String url, {
    required Duration duration,
    required int parallelStreams,
    required int maximumBytes,
    int minimumBytes = 256 * 1024,
  }) async {
    if (parallelStreams < 1 || maximumBytes < 1 || duration <= Duration.zero) {
      return null;
    }

    final baseUri = Uri.tryParse(url);
    if (baseUri == null || !baseUri.hasScheme || baseUri.host.isEmpty) {
      return null;
    }

    final watch = Stopwatch()..start();
    var measuredBytes = 0;
    var requestSequence = 0;

    bool hasBudget() =>
        watch.elapsed < duration && measuredBytes < maximumBytes;

    Future<void> worker(int workerId) async {
      final client = _configuredClient(1);
      try {
        while (hasBudget()) {
          final sequence = requestSequence++;
          final requestUri = _cacheBustedUri(baseUri, workerId, sequence);
          StreamSubscription<List<int>>? subscription;
          Timer? timer;
          try {
            final request = await client.getUrl(requestUri);
            request.headers.set(HttpHeaders.cacheControlHeader, 'no-store');
            request.headers.set(HttpHeaders.acceptEncodingHeader, 'identity');
            request.headers.set(HttpHeaders.userAgentHeader, userAgent);
            final response = await request.close().timeout(
                  const Duration(seconds: 6),
                );
            if (response.statusCode < 200 || response.statusCode >= 400) break;

            final completer = Completer<void>();
            final remaining = duration - watch.elapsed;
            if (remaining <= Duration.zero) break;

            void finish() {
              if (!completer.isCompleted) completer.complete();
            }

            timer = Timer(remaining, finish);
            subscription = response.listen(
              (chunk) {
                if (!hasBudget()) {
                  finish();
                  return;
                }
                final remainingBudget = maximumBytes - measuredBytes;
                measuredBytes += min(chunk.length, remainingBudget);
                if (!hasBudget()) finish();
              },
              onDone: finish,
              onError: (_) => finish(),
              cancelOnError: true,
            );
            await completer.future;
            await subscription.cancel();
            subscription = null;
            timer.cancel();
            timer = null;
          } catch (_) {
            break;
          } finally {
            timer?.cancel();
            await subscription?.cancel();
          }
        }
      } finally {
        client.close(force: true);
      }
    }

    try {
      await Future.wait(
        List.generate(parallelStreams, (index) => worker(index)),
      ).timeout(duration + const Duration(seconds: 8));
    } catch (_) {
      // Keep successfully transferred bytes when one stream times out.
    } finally {
      watch.stop();
    }

    if (measuredBytes < minimumBytes || watch.elapsed <= Duration.zero) {
      return null;
    }
    return ThroughputMeasurement(bytes: measuredBytes, elapsed: watch.elapsed);
  }

  Future<ThroughputMeasurement?> measureUpload(
    String url, {
    required Duration duration,
    required int parallelStreams,
    required int maximumBytes,
    int minimumBytes = 256 * 1024,
  }) async {
    if (parallelStreams < 1 || maximumBytes < 1 || duration <= Duration.zero) {
      return null;
    }

    final baseUri = Uri.tryParse(url);
    if (baseUri == null || !baseUri.hasScheme || baseUri.host.isEmpty) {
      return null;
    }

    final watch = Stopwatch()..start();
    final chunk = List<int>.filled(64 * 1024, 0x5A, growable: false);
    var reservedBytes = 0;
    var confirmedBytes = 0;
    var transferElapsed = Duration.zero;

    bool hasBudget() =>
        watch.elapsed < duration && reservedBytes < maximumBytes;

    Future<void> worker(int workerId) async {
      var requestBytes = 0;
      final client = _configuredClient(1);
      try {
        final request = await client.postUrl(
          _cacheBustedUri(baseUri, workerId, 0),
        );
        request.bufferOutput = false;
        request.headers.set(
          HttpHeaders.contentTypeHeader,
          'application/octet-stream',
        );
        request.headers.set(HttpHeaders.cacheControlHeader, 'no-store');
        request.headers.set(HttpHeaders.userAgentHeader, userAgent);

        var bytesSinceFlush = 0;
        while (hasBudget()) {
          final remainingBudget = maximumBytes - reservedBytes;
          if (remainingBudget <= 0) break;
          final size = min(chunk.length, remainingBudget);
          reservedBytes += size;
          requestBytes += size;
          bytesSinceFlush += size;
          request.add(size == chunk.length ? chunk : chunk.sublist(0, size));
          if (bytesSinceFlush >= 256 * 1024) {
            await request.flush().timeout(const Duration(seconds: 4));
            if (watch.elapsed > transferElapsed) {
              transferElapsed = watch.elapsed;
            }
            bytesSinceFlush = 0;
          }
        }

        await request.flush().timeout(const Duration(seconds: 4));
        if (watch.elapsed > transferElapsed) transferElapsed = watch.elapsed;
        final response = await request.close().timeout(
              const Duration(seconds: 8),
            );
        await response.drain<void>().timeout(
              const Duration(seconds: 3),
              onTimeout: () {},
            );
        if (response.statusCode >= 200 && response.statusCode < 500) {
          confirmedBytes += requestBytes;
        }
      } catch (_) {
        // Another parallel stream may still produce a valid measurement.
      } finally {
        client.close(force: true);
      }
    }

    try {
      await Future.wait(
        List.generate(parallelStreams, (index) => worker(index)),
      ).timeout(duration + const Duration(seconds: 12));
    } catch (_) {
      // Keep bytes confirmed by streams that completed successfully.
    } finally {
      watch.stop();
    }

    if (confirmedBytes < minimumBytes || transferElapsed <= Duration.zero) {
      return null;
    }
    return ThroughputMeasurement(
      bytes: confirmedBytes,
      elapsed: transferElapsed,
    );
  }

  HttpClient _configuredClient(int parallelStreams) {
    return _clientFactory()
      ..connectionTimeout = const Duration(seconds: 5)
      ..idleTimeout = const Duration(seconds: 4)
      ..maxConnectionsPerHost = parallelStreams;
  }

  Uri _cacheBustedUri(Uri uri, int workerId, int sequence) {
    if (uri.host == 'speed.cloudflare.com' && uri.path == '/__down') {
      // Cloudflare rejects unknown query parameters on this endpoint. The
      // response is generated for each request and is not a cacheable asset.
      return uri;
    }
    final query = <String, String>{
      ...uri.queryParameters,
      '_wins_speedtest':
          '${DateTime.now().microsecondsSinceEpoch}-$workerId-$sequence',
    };
    return uri.replace(queryParameters: query);
  }
}
