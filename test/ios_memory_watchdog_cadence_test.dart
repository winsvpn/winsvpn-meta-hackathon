import 'dart:io';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('the watchdog keeps strict startup sampling and relaxes after promotion', () {
    final provider = File('ios/PacketTunnel/PacketTunnelProvider.swift').readAsStringSync();
    expect(provider, contains('winnMemoryWatchdogPromotedIntervalSeconds = 5.0'));
    expect(provider, contains('leeway: .seconds(2)'));
    expect(provider, contains('leeway: .milliseconds(100)'));
  });
}
