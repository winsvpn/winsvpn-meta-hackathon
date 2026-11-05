import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Runs the shipping pending-logout methods (extracted verbatim from
// lib/main.dart) over an in-memory secure store and a scripted hub reply.
// The single pending_logout.json slot must never lose one account's queued
// revocation to another account's logout, cleanup or late retry.
void main() {
  test('cleanup wiring removes only the departing account\'s queued logout',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('  Future<bool> _deleteCleanupArtifact(');
    final end = source.indexOf("      case 'vpn_settings':", start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body, contains('return _deletePendingLogoutForScope(scopeToken);'));
    expect(body,
        isNot(contains("_deleteSensitiveArtifactVerified('pending_logout.json')")));
  });

  test('pending logout survives another account and a late retry', () async {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('  Future<bool> _queuePendingLogout(');
    final end = source.indexOf(
      '\n  // ====================================================================\n'
      '  // Duress (panic)',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final queue = File('lib/account_session_lifecycle.dart').absolute.uri;
    final temporary =
        await Directory.systemTemp.createTemp('wins-logout-isolation-');
    try {
      final program = File('${temporary.path}/probe.dart');
      await program.writeAsString(
        "import '$queue';\n$_harness${source.substring(start, end)}\n$_end",
      );
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        [program.path],
      ).timeout(const Duration(seconds: 60));
      expect(result.exitCode, 0, reason: '${result.stderr}');
      final output = '${result.stdout}';
      for (final line in <String>[
        'conflicting_enqueue: accepted=false prior_retained=true',
        'same_device_newer_token: accepted=true token=second',
        'formatted_account_same_row: accepted=true',
        'other_account_cleanup: success=true prior_retained=true',
        'own_cleanup: success=true removed=true',
        'damaged_slot_cleanup: success=true removed=true',
        'late_acknowledgment: newer_retained=true',
        'acknowledged_retry: removed=true',
        'lost_write: accepted=false',
        'damaged_slot_enqueue: accepted=true',
      ]) {
        expect(output, contains(line));
      }
    } finally {
      await temporary.delete(recursive: true);
    }
  });
}

const _harness = r'''
import 'dart:async';
import 'dart:convert';

class Harness {
  String? stored;
  bool discardWrites = false;
  bool _privacyConsentGranted = true;
  static const String _freeAccessAccountNumber = '9999-9999-9999';
  Completer<void>? entered;
  Completer<bool>? reply;
  final ClientKeyOperationQueue _pendingLogoutOperations =
      ClientKeyOperationQueue();
  void _debugLog(String message) {}
  String _clientKeyScopeToken(String account) => 'scope:$account';
  Future<String?> _readSensitiveText(String name) async => stored;
  Future<void> _writeSensitiveText(String name, String value) async {
    if (!discardWrites) stored = value;
  }
  Future<void> _deleteSensitiveText(String name) async { stored = null; }
  Future<bool> _deleteSensitiveArtifactVerified(String name) async {
    await _deleteSensitiveText(name);
    return await _readSensitiveText(name) == null;
  }
  Future<bool> _sendLogoutToHub({required bool freeAccess,
      required String accountNumber, required String deviceId,
      required String? deviceAuthToken}) {
    entered?.complete();
    return reply?.future ?? Future<bool>.value(false);
  }
  Future<bool> queue(String account, [String token = 'first']) =>
      _queuePendingLogout(freeAccess: false, accountNumber: account,
          deviceId: 'install-1', deviceAuthToken: token);
  Map get record => jsonDecode(stored!) as Map;
  bool holds(String account) =>
      stored != null && record['account_number'] == account;
''';

const _end = r'''
}

Future<void> main() async {
  final first = Harness();
  await first.queue('1111-1111-1111');
  final second = await first.queue('2222-2222-2222');
  print('conflicting_enqueue: accepted=$second '
      'prior_retained=${first.holds('1111-1111-1111')}');

  final rotated = Harness();
  await rotated.queue('1111-1111-1111', 'first');
  final replaced = await rotated.queue('1111-1111-1111', 'second');
  print('same_device_newer_token: accepted=$replaced '
      'token=${rotated.record['device_auth_token']}');

  final formatted = Harness();
  await formatted.queue('1111-1111-1111');
  print('formatted_account_same_row: '
      'accepted=${await formatted.queue('111111111111')}');

  final other = Harness();
  await other.queue('1111-1111-1111');
  final otherCleanup =
      await other._deletePendingLogoutForScope('scope:2222-2222-2222');
  print('other_account_cleanup: success=$otherCleanup '
      'prior_retained=${other.holds('1111-1111-1111')}');

  final own = Harness();
  await own.queue('1111-1111-1111');
  final ownCleanup =
      await own._deletePendingLogoutForScope('scope:1111-1111-1111');
  print('own_cleanup: success=$ownCleanup removed=${own.stored == null}');

  final damaged = Harness()..stored = 'not json';
  final damagedCleanup =
      await damaged._deletePendingLogoutForScope('scope:2222-2222-2222');
  print('damaged_slot_cleanup: success=$damagedCleanup '
      'removed=${damaged.stored == null}');

  final race = Harness();
  await race.queue('1111-1111-1111');
  race.entered = Completer<void>();
  race.reply = Completer<bool>();
  final pending = race._retryPendingLogout();
  await race.entered!.future;
  await race._deletePendingLogoutForScope('scope:1111-1111-1111');
  await race.queue('2222-2222-2222');
  race.reply!.complete(true);
  await pending;
  print('late_acknowledgment: '
      'newer_retained=${race.holds('2222-2222-2222')}');

  final acknowledged = Harness();
  await acknowledged.queue('1111-1111-1111');
  acknowledged.reply = Completer<bool>()..complete(true);
  await acknowledged._retryPendingLogout();
  print('acknowledged_retry: removed=${acknowledged.stored == null}');

  final lost = Harness()..discardWrites = true;
  print('lost_write: accepted=${await lost.queue('1111-1111-1111')}');

  final garbage = Harness()..stored = '[1, 2]';
  print('damaged_slot_enqueue: '
      'accepted=${await garbage.queue('1111-1111-1111')}');
}
''';
