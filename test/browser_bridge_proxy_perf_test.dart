// Seat C audit: C-extension upstream connect fallback and relay backpressure.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:wins_vpn/browser_bridge_proxy.dart';
import 'package:flutter_test/flutter_test.dart';

class OpenGate implements TunnelGate {
  @override
  bool get admitsTraffic => true;
  @override
  Stream<bool> get changes => const Stream<bool>.empty();
}

Future<Socket> _connectThrough(BridgeProxyServer proxy, String token) async {
  final s = await Socket.connect(InternetAddress.loopbackIPv4, proxy.port);
  final auth = base64.encode(utf8.encode('extension:$token'));
  s.write('CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n'
      'Proxy-Authorization: Basic $auth\r\n\r\n');
  await s.flush();
  return s;
}

void main() {
  test('a failing first (IPv6) address falls back to the next one', () async {
    final upstream = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    upstream.listen((s) {});
    final attempts = <String>[];
    final cred = ProxyCredential.generate();
    final proxy = BridgeProxyServer(
      gate: OpenGate(),
      credential: cred,
      resolver: (_) async => <InternetAddress>[
        InternetAddress('2001:4860::1'),
        InternetAddress('192.0.2.1'),
      ],
      connector: (host, port) async {
        attempts.add(host);
        if (host.contains(':')) throw const SocketException('unreachable');
        return Socket.connect(InternetAddress.loopbackIPv4, upstream.port);
      },
    );
    await proxy.start();
    final c = await _connectThrough(proxy, cred.token);
    final head = await c.first.timeout(const Duration(seconds: 5));
    expect(utf8.decode(head), startsWith('HTTP/1.1 200'));
    expect(attempts, <String>['2001:4860::1', '192.0.2.1']);
    c.destroy();
    await proxy.stop();
    await upstream.close();
  });

  test('client upload is not buffered without bound when upstream stalls', () async {
    // Upstream accepts and does not read for the measurement window.
    final upstream = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final held = <StreamSubscription<Uint8List>>[];
    upstream.listen((s) {
      final sub = s.listen((_) {});
      sub.pause();
      held.add(sub);
    });
    final cred = ProxyCredential.generate();
    final proxy = BridgeProxyServer(
      gate: OpenGate(),
      credential: cred,
      resolver: (_) async => <InternetAddress>[InternetAddress('192.0.2.1')],
      connector: (host, port) =>
          Socket.connect(InternetAddress.loopbackIPv4, upstream.port),
    );
    await proxy.start();
    final c = await _connectThrough(proxy, cred.token);
    final reply = Completer<void>();
    c.listen((_) { if (!reply.isCompleted) reply.complete(); });
    await reply.future.timeout(const Duration(seconds: 5));
    final rssBefore = ProcessInfo.currentRss;
    final chunk = Uint8List(1 << 20);
    var sent = 0;
    final deadline = DateTime.now().add(const Duration(seconds: 4));
    while (DateTime.now().isBefore(deadline) && sent < (512 << 20)) {
      c.add(chunk);
      var stalled = false;
      await c.flush().timeout(const Duration(milliseconds: 500),
          onTimeout: () { stalled = true; });
      sent += chunk.length;
      // A stalled flush means the proxy stopped reading: backpressure held.
      if (stalled) break;
    }
    final growthMiB = (ProcessInfo.currentRss - rssBefore) >> 20;
    // ignore: avoid_print
    print('sent=${sent >> 20} MiB rss growth=$growthMiB MiB');
    expect(growthMiB, lessThan(64));
    c.destroy();
    await proxy.stop();
    await upstream.close();
  }, timeout: const Timeout(Duration(seconds: 60)));
}
