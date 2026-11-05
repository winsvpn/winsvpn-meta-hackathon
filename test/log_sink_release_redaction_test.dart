import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/diagnostic_redaction.dart';

void main() {
  test('redactLogSecrets strips bare hostnames, plain accounts, email, install ids', () {
    final out = redactLogSecrets(
      "SocketException: Failed host lookup: 'e.app-cloud-sync.net' "
      'refused for node7.example.net account 123456789012 '
      'mail user@example.com device INSTALL-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf',
    );
    expect(out, isNot(contains('app-cloud-sync.net')));
    expect(out, isNot(contains('node7.example.net')));
    expect(out, isNot(contains('123456789012')));
    expect(out, isNot(contains('user@example.com')));
    expect(out, isNot(contains('INSTALL-')));
  });

  test('redactLogSecrets keeps stack-frame file names readable', () {
    const input = 'at _VpnDashboardBodyState._connect (package:wins_vpn/main.dart)';
    expect(redactLogSecrets(input), contains('main.dart'));
  });

  test('the debug log sink writes nothing in a release build', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('  void _debugLog(String message) {');
    expect(start, greaterThanOrEqualTo(0), reason: 'anti-vacuity: the sink exists');
    final body = source.substring(start, source.indexOf('\n  }\n', start));
    final guardAt = body.indexOf('if (kReleaseMode || !_diagnosticsEnabled) return;');
    expect(guardAt, greaterThanOrEqualTo(0));
    expect(guardAt, lessThan(body.indexOf('redactLogSecrets(')));
    expect(body, isNot(contains('print(')),
        reason: 'only debugPrint inside the assert may write');
    expect(body, contains('debugPrint(clean)'));
  });
}
