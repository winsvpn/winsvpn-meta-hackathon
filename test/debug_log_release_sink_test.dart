import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('debug log sink has no unconditional print call', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(source, contains('void _debugLog(String message) {'));
    final body = source.split('void _debugLog(String message) {')[1]
        .split('String _redactedTunnelFailureText')[0];
    expect(body, isNot(contains('print(')));
    expect(body, contains('assert(() {'));
    expect(body, contains('redactLogSecrets(message)'));
  });
}
