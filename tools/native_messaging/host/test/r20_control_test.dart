import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:wins_bridge_host/browser_bridge_app_ipc.dart';
import 'package:wins_bridge_host/browser_bridge_protocol.dart';

void check(bool value, String message) {
  if (!value) throw StateError(message);
}
Future<Map<String, dynamic>> raw(int port, String token, String id, String type) async {
  final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
  final bytes = <int>[];
  final done = Completer<Map<String, dynamic>>();
  socket.listen((chunk) {
    bytes.addAll(chunk);
    if (bytes.length < 4) return;
    final n = bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24;
    if (bytes.length >= n + 4 && !done.isCompleted) {
      done.complete(jsonDecode(utf8.decode(bytes.sublist(4, n + 4))) as Map<String, dynamic>);
    }
  }, onError: done.completeError);
  socket.add(encodeBrowserBridgeAppIpcFrame(<String, Object?>{
    'v': 1, 'id': id, 'token': token, 'type': type,
  }));
  try {
    return await done.future.timeout(const Duration(seconds: 5));
  } finally {
    socket.destroy();
  }
}
Future<void> main() async {
  final dir = Directory.systemTemp.createTempSync('r20-control-');
  final discovery = File('${dir.path}/ipc.json');
  final trust = BrowserBridgeAppIpcTrust.authenticated(
    secretHex: generateBrowserBridgeAppIpcToken(),
    expectedIdentity: BrowserBridgeAppIpcProcessIdentity.currentProcess(),
  );
  var calls = 0;
  final server = BrowserBridgeAppIpcServer(
    discoveryFile: discovery, trust: trust,
    snapshot: () => BridgeStatus.appNotRunning(winn: BridgeWinnState.unavailableOnThisPlatform),
    onCommand: (_) async { calls++; },
  );
  try {
    await server.start();
    final token = (jsonDecode(discovery.readAsStringSync()) as Map)['token'] as String;
    for (final type in <String>['request_connect', 'request_disconnect']) {
      check((await raw(server.port, token, type, type))['ok'] == false,
          'read-only bridge admitted $type');
    }
    check(calls == 0, 'read-only bridge invoked control handler');
    check((await raw(server.port, token, 'status', 'get_status'))['ok'] == true,
        'read-only bridge denied status');
    stdout.writeln('PASS: raw same-user controls denied; status remains available');
  } finally {
    await server.stop();
    dir.deleteSync(recursive: true);
  }
}
