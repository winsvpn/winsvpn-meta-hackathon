// _mutateVpnRuntimeSettings: an account epoch bump that is NOT a teardown
// seal (an activation) landing while a write is in flight must not delete
// the settings document. Only a seal may erase it, because only a seal is
// followed by the cleanup that erases storage anyway.
//
// The method under test is the shipping text, extracted from lib/main.dart
// and asserted verbatim before it runs against an in-memory store whose
// write can be held open.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/account_session_lifecycle.dart';

class _Store {
  String? document = jsonEncode(<String, dynamic>{
    'privacy_policy_accepted_version': '2026-10-04.v5',
    'legal_accepted_version': '2026-08-31.v4',
    'pin_attempt_state': <String, dynamic>{'failureCount': 4},
    'announcement_seq_floor': 17,
    'discovery_seq_floor': 12,
  });
  Completer<void>? holdWrite;
  int deletes = 0;
}

class _Harness {
  _Harness(this.store);
  final _Store store;
  final AccountSessionEpoch _accountSessionEpoch = AccountSessionEpoch();
  bool _settingsWritesSealed = false;
  Future<void> _settingsMutationQueue = Future<void>.value();

  Future<Map<String, dynamic>> _readSensitiveJsonMap(String name) async {
    final raw = (store.document)?.trim() ?? '';
    if (raw.isEmpty) return <String, dynamic>{};
    final decoded = jsonDecode(raw);
    if (decoded is Map) return Map<String, dynamic>.from(decoded);
    throw const FormatException('Sensitive state payload is not a JSON object');
  }

  Future<void> _writeSensitiveText(String name, String value) async {
    final hold = store.holdWrite;
    if (hold != null) await hold.future;
    store.document = value;
  }

  Future<void> _deleteSensitiveText(String name) async {
    store.deletes += 1;
    store.document = null;
  }

  // ---- verbatim from lib/main.dart (asserted by the first test) ----
  Future<void> _mutateVpnRuntimeSettings(
    void Function(Map<String, dynamic> data) mutation, {
    bool Function()? skipWriteWhen,
  }) {
    final scheduledEpoch = _accountSessionEpoch.current;
    final operation = _settingsMutationQueue.then((_) async {
      if (_settingsWritesSealed ||
          !_accountSessionEpoch.isCurrent(scheduledEpoch)) {
        throw StateError(
            'Account settings write superseded by lifecycle change');
      }
      final data = await _readSensitiveJsonMap('vpn_settings.txt');
      if (_settingsWritesSealed ||
          !_accountSessionEpoch.isCurrent(scheduledEpoch)) {
        throw StateError(
            'Account settings write superseded by lifecycle change');
      }
      mutation(data);
      if (skipWriteWhen?.call() == true) return;
      await _writeSensitiveText('vpn_settings.txt', jsonEncode(data));
      if (_settingsWritesSealed ||
          !_accountSessionEpoch.isCurrent(scheduledEpoch)) {
        // Only a teardown SEAL erases the document: the write repopulated
        // storage the teardown is erasing, so erase it again. An activation
        // bumps the epoch without sealing or erasing anything; its own writes
        // are queued behind this one and replace its values, and deleting the
        // whole document here threw away the privacy consent, the legal
        // acceptance, the PIN lockout ledger, both replay floors and every
        // preference.
        if (_settingsWritesSealed) {
          await _deleteSensitiveText('vpn_settings.txt');
        }
        throw StateError(
            'Account settings write superseded by lifecycle change');
      }
    });
    _settingsMutationQueue = operation.then<void>(
      (_) {},
      onError: (_, __) {},
    );
    return operation;
  }
  // ---- end verbatim ----

  // lib/main.dart _beginAccountActivation: unseal, then bump.
  int beginAccountActivation() {
    _settingsWritesSealed = false;
    return _accountSessionEpoch.bump();
  }

  // lib/main.dart _beginAccountTeardown: seal, then bump.
  int beginAccountTeardown() {
    _settingsWritesSealed = true;
    return _accountSessionEpoch.bump();
  }
}

void main() {
  test('the extracted _mutateVpnRuntimeSettings is the shipping text', () {
    final main = File('lib/main.dart').readAsStringSync();
    final start = main.indexOf('  Future<void> _mutateVpnRuntimeSettings(');
    final end = main.indexOf('  Future<void> _writeVpnRuntimeSetting(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final shipping = main.substring(start, end).trimRight();
    final here = File('test/settings_epoch_bump_test.dart').readAsStringSync();
    final hStart = here.indexOf('  Future<void> _mutateVpnRuntimeSettings(');
    final hEnd = here.indexOf('  // ---- end verbatim ----', hStart);
    expect(here.substring(hStart, hEnd).trimRight(), shipping);
  });

  test('an activation bump during an in-flight write keeps the document',
      () async {
    final store = _Store();
    final h = _Harness(store);
    store.holdWrite = Completer<void>();
    // The unawaited write _resolveAnnouncement issues after a /nodes reply.
    final inFlight = h._mutateVpnRuntimeSettings((data) {
      data['announcement_seq_floor'] = 18;
    });
    Object? failure;
    final settled = inFlight.catchError((Object e) {
      failure = e;
    });
    await Future<void>.delayed(Duration.zero);
    // The user taps Activate while the native write has not returned.
    h.beginAccountActivation();
    store.holdWrite!.complete();
    await settled;
    expect(failure, isA<StateError>());
    expect(store.deletes, 0);
    expect(store.document, isNotNull);
    final kept = jsonDecode(store.document!) as Map;
    expect(kept['privacy_policy_accepted_version'], '2026-10-04.v5');
    expect(kept['legal_accepted_version'], '2026-08-31.v4');
    expect(kept['pin_attempt_state'], {'failureCount': 4});
    expect(kept['discovery_seq_floor'], 12);
  });

  test('a teardown seal during an in-flight write still erases it', () async {
    final store = _Store();
    final h = _Harness(store);
    store.holdWrite = Completer<void>();
    final inFlight = h._mutateVpnRuntimeSettings((data) {
      data['announcement_seq_floor'] = 18;
    });
    Object? failure;
    final settled = inFlight.catchError((Object e) {
      failure = e;
    });
    await Future<void>.delayed(Duration.zero);
    h.beginAccountTeardown();
    store.holdWrite!.complete();
    await settled;
    expect(failure, isA<StateError>());
    expect(store.deletes, 1);
    expect(store.document, isNull);
  });

  test('a write queued after the bump lands on the kept document', () async {
    final store = _Store();
    final h = _Harness(store);
    store.holdWrite = Completer<void>();
    final inFlight = h._mutateVpnRuntimeSettings((data) {
      data['announcement_seq_floor'] = 18;
    }).catchError((_) {});
    await Future<void>.delayed(Duration.zero);
    h.beginAccountActivation();
    // The activation's own write, queued behind the superseded one.
    final activationWrite = h._mutateVpnRuntimeSettings((data) {
      data['device_auth_token'] = 'token-token-token-token';
    });
    store.holdWrite!.complete();
    store.holdWrite = null;
    await inFlight;
    await activationWrite;
    final kept = jsonDecode(store.document!) as Map;
    expect(kept['device_auth_token'], 'token-token-token-token');
    expect(kept['privacy_policy_accepted_version'], '2026-10-04.v5');
    expect(store.deletes, 0);
  });
}
