import 'dart:io';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('watch commands are never queued', () {
    final phone = File('ios/WinsWatch Watch App/PhoneLink.swift').readAsStringSync();
    expect(phone, isNot(contains('transferUserInfo(')));
    final bridge = File('ios/Runner/WatchSessionBridge.swift').readAsStringSync();
    final start = bridge.indexOf('  func session(_ session: WCSession, didReceiveUserInfo');
    expect(start, greaterThanOrEqualTo(0));
    final end = bridge.indexOf('\n  }', start);
    expect(bridge.substring(start, end), isNot(contains('handle(')));
  });
}
