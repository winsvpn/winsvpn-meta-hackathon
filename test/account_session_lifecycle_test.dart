import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/account_session_lifecycle.dart';

void main() {
  test('account epoch invalidates every captured operation synchronously', () {
    final epoch = AccountSessionEpoch();
    final accountA = epoch.bump();
    expect(epoch.isCurrent(accountA), isTrue);

    final teardown = epoch.bump();
    expect(epoch.isCurrent(accountA), isFalse);
    expect(epoch.isCurrent(teardown), isTrue);

    final accountB = epoch.bump();
    expect(epoch.isCurrent(teardown), isFalse);
    expect(epoch.isCurrent(accountB), isTrue);
  });

  test('cleanup journal round-trips phase and independently pending artifacts',
      () {
    const record = AccountCleanupJournal(
      intent: AccountCleanupIntent.deactivate,
      scopeToken: 'scope-token',
      phase: 'purge',
      pendingArtifacts: <String>{'pin', 'keys'},
    );
    final decoded = AccountCleanupJournal.fromJson(record.toJson());
    expect(decoded.intent, AccountCleanupIntent.deactivate);
    expect(decoded.scopeToken, 'scope-token');
    expect(decoded.phase, 'purge');
    expect(decoded.pendingArtifacts, <String>{'pin', 'keys'});
  });

  test('cleanup journal rejects an unknown or incomplete record', () {
    expect(
      () => AccountCleanupJournal.fromJson(<String, dynamic>{
        'v': 1,
        'intent': 'duress',
        'scope': 'scope-token',
        'phase': 'purge',
        'pending': <String>[],
      }),
      throwsFormatException,
    );
  });

  test('teardown requires a continuous native-inactive proof before purge', () {
    final source = File('lib/main.dart').readAsStringSync();
    final proofStart =
        source.indexOf('Future<bool> _stopAndProveTunnelInactive() async {');
    final proofEnd =
        source.indexOf('Future<bool> _deleteCleanupArtifact(', proofStart);
    final proof = source.substring(proofStart, proofEnd);
    expect(proof, contains('_nativeTunnelActivityForStopSettlement()'));
    expect(proof, contains('inactiveSamples >= 3'));
    expect(proof, contains('const Duration(milliseconds: 750)'));
    expect(proof, contains('if (activity == true)'));
    expect(proof, contains('_cancelAndStopNativeTunnel'));

    final teardownStart =
        source.indexOf('Future<void> _deactivateCurrentDevice() async {');
    final teardownEnd = source.indexOf('// Account deletion', teardownStart);
    final teardown = source.substring(teardownStart, teardownEnd);
    expect(
      teardown.indexOf('_stopAndProveTunnelInactive()'),
      lessThan(teardown.indexOf('_runAccountCleanup(journal, epoch)')),
    );
    expect(teardown, isNot(contains('bool tunnelStopped = true')));
  });

  test('cleanup is independently verified and remains journaled on residue',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final deleteStart = source.indexOf('Future<bool> _deleteCleanupArtifact(');
    final runEnd = source.indexOf(
        'void _resetAccountUiAfterVerifiedCleanup()', deleteStart);
    final cleanup = source.substring(deleteStart, runEnd);
    for (final artifact in <String>[
      'vpn_config',
      'user_pin',
      'pending_logout',
      'vpn_settings',
      'restart_config',
      'activation_marker',
      'client_keys',
    ]) {
      expect(cleanup, contains("case '$artifact':"), reason: artifact);
    }
    expect(
        cleanup, contains('for (final artifact in _accountCleanupArtifacts)'));
    expect(cleanup, contains('} catch (_) {'));
    expect(cleanup, contains('_writeAccountCleanupJournal(current'));
    expect(cleanup, contains('current.pendingArtifacts.isNotEmpty'));
    expect(cleanup, contains('_clearOrdinaryCamouflageLatchVerified()'));
    expect(cleanup,
        contains("_deleteSensitiveArtifactVerified('calc_session.json')"));
  });

  test('epoch fences late account sync and queued settings commits', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(source,
        contains('final scheduledEpoch = _accountSessionEpoch.current;'));
    expect(
      RegExp(r'_settingsWritesSealed \|\|\s*!_accountSessionEpoch\.isCurrent\(scheduledEpoch\)')
          .allMatches(source)
          .length,
      greaterThanOrEqualTo(3),
    );
    expect(
        source, contains('await _deleteSensitiveText(\'vpn_settings.txt\');'));
    expect(
        source,
        contains(
            '_applyAccountSyncData(\n      Map<String, dynamic> data, int expectedEpoch)'));
    expect(source, contains('final epoch = _beginAccountTeardown();'));
    expect(source,
        contains('final activationEpoch = await _beginAccountActivation();'));
  });

  test('activation marker is last durable commit before success UI', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<void> _onAuthSuccess(');
    final end = source.indexOf('Future<bool> _refreshFreeVpnConfig(', start);
    final body = source.substring(start, end);
    var cursor = 0;
    for (final step in <String>[
      '_persistDeviceAuthTokenRequired(deviceAuthToken)',
      '_storeUserPin(pin)',
      '_persistVpnConfigRequired(normalizedConfig)',
      '_saveActivationSettingsRequired(',
      '_loadExistingClientKeyPair(',
      '_writeActivationCompleteMarker(',
      '_isLoggedIn = true',
    ]) {
      final index = body.indexOf(step, cursor);
      expect(index, greaterThanOrEqualTo(cursor), reason: step);
      cursor = index + step.length;
    }
    expect(source, contains("settings['lifecycle_schema'] == 2"));
    expect(source, contains('_activationCompleteForScope(accountScope)'));
  });

  test('ordinary latch clearing requires a journal and duress removes it', () {
    final source = File('lib/main.dart').readAsStringSync();
    final clearStart =
        source.indexOf('Future<bool> _clearOrdinaryCamouflageLatchVerified()');
    final clearEnd =
        source.indexOf('Future<bool> _runAccountCleanup(', clearStart);
    final clear = source.substring(clearStart, clearEnd);
    expect(
        clear,
        contains(
            'if (await _readAccountCleanupJournal() == null) return false;'));
    expect(clear, contains('await latch.delete()'));
    final latchStart = source.indexOf('Future<void> _latchCamouflage()');
    final latchEnd =
        source.indexOf('Future<String?> _readDuressCredential()', latchStart);
    expect(source.substring(latchStart, latchEnd),
        contains('if (await _readAccountCleanupJournal() != null) return;'));
    expect(source, contains("'calc_session.json',\n      'calc_state.json',"));
  });
}
