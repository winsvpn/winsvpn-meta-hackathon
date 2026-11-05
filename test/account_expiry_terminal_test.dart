import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('trusted expired status stops and settles before disconnected state',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<void> _handleTrustedExpiredAccount(');
    final end = source.indexOf('Future<bool> _refreshAccountStatus(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    var cursor = 0;
    for (final step in <String>[
      '_accountExpiredTerminal = true',
      "accountTerminalStatus: 'expired'",
      '_stopAndProveTunnelInactive()',
      'if (settled)',
      '_isConnected = false',
    ]) {
      final index = body.indexOf(step, cursor);
      expect(index, greaterThanOrEqualTo(cursor), reason: step);
      cursor = index + step.length;
    }
  });

  test('expired is terminal rather than an ordinary sync-success status', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _refreshAccountStatus(');
    final end = source.indexOf('void _showAnnouncementWindow(', start);
    final body = source.substring(start, end);
    final terminal = body.indexOf("if (status == 'expired')");
    final ordinary = body.indexOf("if (status == 'ok' ||", terminal);
    expect(terminal, greaterThanOrEqualTo(0));
    expect(ordinary, greaterThan(terminal));
    expect(body.substring(terminal, ordinary),
        contains('_handleTrustedExpiredAccount(operationEpoch, token)'));
    expect(
      body.substring(ordinary),
      isNot(contains("status == 'expired'")),
    );
  });

  test('expired state blocks reconnect and exposes persistent renewal UI', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(source, contains('if (_accountExpiredTerminal && !_isConnected)'));
    expect(source, contains("'expired_renewal_banner'"));
    expect(source, contains("'Renew access'"));
    expect(source,
        contains("settingsData['account_terminal_status'] == 'expired'"));
  });
}
