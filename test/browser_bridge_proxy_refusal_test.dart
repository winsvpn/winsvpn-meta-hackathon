import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// The standalone native host runs lib/browser_bridge_proxy.dart with no root
// error zone, so an unhandled asynchronous socket error ends the process. A
// refusal (407, 503, 400, 403, 501, 502) is written before the relay attaches
// its `done` handlers; a client that resets while it flushes must not raise
// one. The child program runs the shipping library verbatim: once with a
// socket double whose write fails on `done` (deterministic), once with real
// loopback clients that send a head and reset (SO_LINGER 0).
void main() {
  test('refused clients that reset never raise an unhandled error', () async {
    final source = File('lib/browser_bridge_proxy.dart').readAsStringSync();
    final temporary =
        await Directory.systemTemp.createTemp('wins-proxy-refusal-');
    try {
      final program = File('${temporary.path}/probe.dart');
      await program.writeAsString('$source$_harness');
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        [program.path],
      ).timeout(const Duration(seconds: 90));
      expect(result.exitCode, 0, reason: '${result.stderr}');
      final output = '${result.stdout}';
      expect(output, contains('double_reset: unhandled=0 destroyed=true'));
      expect(output, contains('loopback_reset: unhandled=0'));
    } finally {
      await temporary.delete(recursive: true);
    }
  });
}

const _harness = r'''

class ResetOnWriteSocket extends Stream<Uint8List> implements Socket {
  final Completer<Socket> completion = Completer<Socket>();
  bool destroyed = false;
  @override
  Future<Socket> get done => completion.future;
  @override
  void write(Object? value) {
    scheduleMicrotask(() => completion.completeError(
        const SocketException('synthetic peer reset during refusal write')));
  }
  @override
  void destroy() { destroyed = true; }
  @override
  StreamSubscription<Uint8List> listen(void Function(Uint8List)? onData,
          {Function? onError, void Function()? onDone, bool? cancelOnError}) =>
      const Stream<Uint8List>.empty().listen(onData,
          onError: onError, onDone: onDone, cancelOnError: cancelOnError);
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Future<void> main() async {
  final doubled = <Object>[];
  final peers = <ResetOnWriteSocket>[];
  await runZonedGuarded<Future<void>>(() async {
    final proxy = BridgeProxyServer(
        gate: ClosedTunnelGate(), credential: ProxyCredential.generate());
    for (final status in [407, 503]) {
      final client = ResetOnWriteSocket();
      peers.add(client);
      proxy._refuse(client, status, 'Refused');
    }
    await Future<void>.delayed(const Duration(milliseconds: 60));
  }, (Object error, StackTrace stack) { doubled.add(error); });
  print('double_reset: unhandled=${doubled.length} '
      'destroyed=${peers.every((peer) => peer.destroyed)}');

  final looped = <Object>[];
  await runZonedGuarded<Future<void>>(() async {
    final proxy = BridgeProxyServer(
        gate: ClosedTunnelGate(), credential: ProxyCredential.generate());
    await proxy.start();
    // struct linger { l_onoff = 1, l_linger = 0 }: close sends a reset.
    final linger = Uint8List(8)
      ..buffer.asByteData().setInt32(0, 1, Endian.host);
    final soLinger = Platform.isLinux ? 13 : 0x0080;
    for (var i = 0; i < 120; i++) {
      final peer =
          await Socket.connect(InternetAddress.loopbackIPv4, proxy.port);
      peer.setRawOption(
          RawSocketOption(RawSocketOption.levelSocket, soLinger, linger));
      peer.write('CONNECT example.org:443 HTTP/1.1\r\n'
          'Host: example.org:443\r\n\r\n');
      await peer.flush();
      peer.destroy();
      unawaited(peer.done.catchError((Object _) => peer));
      if (i % 10 == 0) {
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
    }
    await Future<void>.delayed(const Duration(milliseconds: 500));
    await proxy.stop();
  }, (Object error, StackTrace stack) { looped.add(error); });
  print('loopback_reset: unhandled=${looped.length}');
}
''';
