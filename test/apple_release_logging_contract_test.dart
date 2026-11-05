import 'dart:io';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('_debugLog has no unconditional print', () {
    final src = File('lib/main.dart').readAsStringSync();
    final start = src.indexOf('void _debugLog(String message)');
    expect(start, greaterThan(0));
    final body = src.substring(start, src.indexOf('\n  }\n', start));
    expect(body.contains("print('[WINS-DEBUG]"), isFalse);
  });

  test('Apple release builds have no public tunnel log sink', () {
    final audit = File('macos/Runner/RouteAudit.swift').readAsStringSync();
    final at = audit.indexOf('os_log("%{public}@", log: log, type: .default, line)');
    expect(at, greaterThan(0));
    expect(audit.substring(at - 40, at), contains('#if DEBUG'));
    for (final path in const [
      'ios/PacketTunnel/PacketTunnelProvider.swift',
      'macos/PacketTunnel/PacketTunnelProvider.swift',
      'macos/Runner/AppDelegate.swift',
    ]) {
      expect(File(path).readAsStringSync(), contains('OSLog.disabled'), reason: path);
    }
    expect(File('apple/EngineWrappers/WinsWinnPacketEngine.m').readAsStringSync(),
        contains('return OS_LOG_DISABLED;'));
  });
}
