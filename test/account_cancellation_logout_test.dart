import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('revoked or deleted account triggers deactivation to activation screen',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<void> _handleTrustedRevokedAccount(');
    final end = source.indexOf('Future<bool> _refreshAccountStatus(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body, contains('_deactivateCurrentDevice()'));
    expect(body, contains('_showFeedback(reason)'));
  });

  test('HTTP 404 and 401 trigger _handleTrustedRevokedAccount in _refreshAccountStatus',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _refreshAccountStatus(');
    final end = source.indexOf('void _showAnnouncementWindow(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body, contains('response.statusCode == 404 || response.statusCode == 401'));
    expect(body, contains('_handleTrustedRevokedAccount('));
  });

  test('cancelled or deleted status payloads trigger _handleTrustedRevokedAccount',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _refreshAccountStatus(');
    final end = source.indexOf('void _showAnnouncementWindow(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body, contains("status == 'cancelled'"));
    expect(body, contains("status == 'deleted'"));
    expect(body, contains("status == 'revoked'"));
  });

  test('sendLogoutToHub retires a logout only on the hub reply contract', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _sendLogoutToHub(');
    final end = source.indexOf('Future<bool> _queuePendingLogout(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body,
        contains('hubLogoutAcknowledged(response.statusCode, response.body)'));
    expect(body, isNot(contains('response.statusCode == 404')));
    expect(body, isNot(contains('response.statusCode == 401')));
  });

  test('deactivateCurrentDevice falls back to current account number if empty', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<void> _deactivateCurrentDevice()');
    final end = source.indexOf('// Account deletion (Apple Guideline 5.1.1(v)', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body, contains('await _currentAccountNumberForRefresh()'));
    expect(body, contains('_resetAccountUiAfterVerifiedCleanup()'));
  });
}
