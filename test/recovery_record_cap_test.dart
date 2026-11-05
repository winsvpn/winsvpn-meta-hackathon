// The gateway-recovery record is fetched over the device trust store from
// raw.githubusercontent.com, so a CA the network operator installed can
// answer it. The body is capped while it streams (fetchWithoutRedirectsCapped,
// kMaxGatewayRecoveryRecordBytes), the way the signed update notice beside
// it already is; a `.timeout` alone only stops the wait, not the download.
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/gateway_failover.dart';
import 'package:wins_vpn/no_redirect_http.dart';

void main() {
  test('_fetchGatewayRecordBody caps the record body while it streams', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<String?> _fetchGatewayRecordBody(Uri url)');
    final end = source.indexOf(
        'Future<Map<String, String>> _resolveDynamicEndpoints()', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body, contains('await fetchWithoutRedirectsCapped('));
    expect(body, contains('maxBytes: kMaxGatewayRecoveryRecordBytes'));
    expect(body, isNot(contains('fetchWithoutRedirects(url)')));
  });

  test('the cap is small and leaves room for every compiled gateway line', () {
    final longest = primaryStealthGateways
        .map((gateway) => gateway.length + 1)
        .fold<int>(0, (sum, length) => sum + length);
    expect(kMaxGatewayRecoveryRecordBytes, greaterThan(longest * 4));
    expect(kMaxGatewayRecoveryRecordBytes, lessThanOrEqualTo(65536));
  });

  test('a 32 MiB body is refused past the cap instead of being buffered',
      () async {
    const totalBytes = 32 * 1024 * 1024;
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      request.response.statusCode = 200;
      request.response.headers.contentType = ContentType.text;
      final chunk = Uint8List(64 * 1024);
      for (var i = 0; i < chunk.length; i++) {
        chunk[i] = 0x61;
      }
      var sent = 0;
      try {
        while (sent < totalBytes) {
          request.response.add(chunk);
          sent += chunk.length;
          if (sent % (4 * 1024 * 1024) == 0) await request.response.flush();
        }
        await request.response.close();
      } catch (_) {
        // The client closed its connection at the cap.
      }
    });
    try {
      final url = Uri.parse('http://127.0.0.1:${server.port}/record.txt');
      Object? failure;
      try {
        await fetchWithoutRedirectsCapped(
          url,
          maxBytes: kMaxGatewayRecoveryRecordBytes,
          deadline: const Duration(seconds: 4),
        );
      } catch (e) {
        failure = e;
      }
      expect(failure, isA<ResponseBodyTooLargeException>());
    } finally {
      await server.close(force: true);
    }
  });
}
