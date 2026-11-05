import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/throughput_speed_test.dart';

void main() {
  test('throughputMbps converts bytes and time to decimal Mbps', () {
    expect(
      throughputMbps(125000000, const Duration(seconds: 1)),
      closeTo(1000, 0.001),
    );
    expect(throughputMbps(0, const Duration(seconds: 1)), 0);
    expect(throughputMbps(1024, Duration.zero), 0);
  });

  test('download measurement aggregates concurrent HTTP streams', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    var requestCount = 0;
    var activeRequests = 0;
    var maximumActiveRequests = 0;
    final serverTask = server.forEach((request) async {
      requestCount++;
      activeRequests++;
      if (activeRequests > maximumActiveRequests) {
        maximumActiveRequests = activeRequests;
      }
      request.response.statusCode = HttpStatus.ok;
      request.response.headers.contentType = ContentType.binary;
      try {
        for (var i = 0; i < 12; i++) {
          request.response.add(List<int>.filled(64 * 1024, i));
          await request.response.flush();
          await Future<void>.delayed(const Duration(milliseconds: 4));
        }
      } finally {
        await request.response.close();
        activeRequests--;
      }
    });

    final tester = ThroughputSpeedTest(userAgent: 'WinsVPN-Test');
    final result = await tester.measureDownload(
      'http://${server.address.host}:${server.port}/download',
      duration: const Duration(milliseconds: 350),
      parallelStreams: 3,
      maximumBytes: 6 * 1024 * 1024,
      minimumBytes: 64 * 1024,
    );

    expect(result, isNotNull);
    expect(result!.bytes, greaterThan(64 * 1024));
    expect(result.mbps, greaterThan(0));
    expect(requestCount, greaterThanOrEqualTo(3));
    expect(maximumActiveRequests, greaterThanOrEqualTo(2));

    await server.close(force: true);
    await serverTask;
  });

  test('upload measurement combines completed parallel requests', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    var uploadedBytes = 0;
    var requestCount = 0;
    final serverTask = server.forEach((request) async {
      requestCount++;
      await for (final chunk in request) {
        uploadedBytes += chunk.length;
      }
      request.response.statusCode = HttpStatus.ok;
      await request.response.close();
    });

    final tester = ThroughputSpeedTest(userAgent: 'WinsVPN-Test');
    final result = await tester.measureUpload(
      'http://${server.address.host}:${server.port}/upload',
      duration: const Duration(milliseconds: 300),
      parallelStreams: 3,
      maximumBytes: 3 * 1024 * 1024,
      minimumBytes: 64 * 1024,
    );

    expect(result, isNotNull);
    expect(result!.bytes, uploadedBytes);
    expect(result.mbps, greaterThan(0));
    expect(requestCount, 3);

    await server.close(force: true);
    await serverTask;
  });
}
