// Sol's two continuation paths, run verbatim from lib/main.dart: a flow that
// awaits and then shows UI must stop, not just stop drawing, when the app
// relocked during the await.
//
// * _promptDuressEnrollment awaits the native SMS capability, then opens the
//   enrollment dialog.
// * _issueAndShowRecoveryCode awaits the credential write, then shows the code
//   once; a relock keeps the code pending, in memory, for the next unlock.
//
// The harness runs those methods verbatim with the technique of
// connected_server_switch_transaction_test.dart. A relock is what production's
// _clearProductSurfacesForDecoy does before it arms the decoy (one more decoy
// generation) plus the flag; the unlock is the decoy cleared and
// _showPendingRecoveryCode called, as the PIN unlock does. Both call sites are
// pinned in decoy_cover_test.dart and below.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production code: $start');
  }
  return source.substring(first, last);
}

void main() {
  late Directory temporary;
  late File executable;
  late String source;

  setUpAll(() async {
    source = File('lib/main.dart').readAsStringSync();
    final duress = _between(
        source,
        '  Future<void> _promptDuressEnrollment({String? knownRealPin}) async {',
        '  Future<void> _showDuressEnrollmentDialog(');
    final recovery = _between(
        source,
        '  Future<void> _issueAndShowRecoveryCode() async {',
        '  /// After a recovery-code unlock the user has proved possession');
    temporary = await Directory.systemTemp.createTemp('l91-decoy-continuation-');
    executable = File('${temporary.path}/continuation.dart');
    await executable.writeAsString('''
import 'dart:async';

class H {
  H(this.storage);
  // vpn_settings.txt; shared by two H objects to model a process restart.
  final Map<String, dynamic> storage;
  bool mounted = true;
  bool _showDecoyCalculator = false;
  int _decoyGeneration = 0;
  String? _pendingRecoveryCode;
  bool _recoveryCodeMissing = true;
  bool _supportsDeviceNativeSms = true;
  final List<String> events = <String>[];
  final List<String> feedback = <String>[];
  Completer<Map<String, dynamic>>? capability;
  Completer<String>? issue;
  void Function()? whileCodeDialogOpen;
  void setState(void Function() fn) => fn();
  String _t(String value) => value;
  void _debugLog(String message) {}
  void _showFeedback(String message) => feedback.add(message);
  Future<Map<String, dynamic>> _duressSmsCapability() => capability!.future;
  Future<void> _showDuressEnrollmentDialog(
      {String? knownRealPin, required bool canOfferSms}) async {
    events.add('duress-dialog canOfferSms=\$canOfferSms');
  }
  int mints = 0;
  Future<String> _issueRecoveryCode() {
    mints++;
    return issue!.future;
  }
  Future<Map<String, dynamic>> _readVpnRuntimeSettings() async =>
      Map<String, dynamic>.from(storage);
  Future<void> _mutateVpnRuntimeSettings(
      void Function(Map<String, dynamic> data) mutation) async {
    mutation(storage);
  }
  // The real dialog answers true only on "I have saved it"; a dialog the
  // relock removed answers null (false here).
  Future<bool> _showRecoveryCodeOnce(String code) async {
    events.add('code-dialog \$code');
    whileCodeDialogOpen?.call();
    return !_showDecoyCalculator;
  }
  // What production does when it arms the decoy, and when the PIN unlocks.
  void relock() {
    _decoyGeneration++;
    _showDecoyCalculator = true;
  }
  void unlock() => _showDecoyCalculator = false;

$duress
$recovery
}

void check(bool ok, String message) {
  if (!ok) throw StateError(message);
}

Future<void> settle() async {
  for (var i = 0; i < 10; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

Future<void> main(List<String> args) async {
  final scenario = args.single;
  final storage = <String, dynamic>{};
  final h = H(storage);
  switch (scenario) {
    case 'duress_control':
      h.capability = Completer<Map<String, dynamic>>();
      final prompt = h._promptDuressEnrollment();
      h.capability!.complete(<String, dynamic>{'can_offer_sms': true});
      await prompt;
      check(h.events.single == 'duress-dialog canOfferSms=true',
          'control: the unlocked prompt did not open: \${h.events}');
    case 'duress_relock_during_capability':
      // Sol: relock during _duressSmsCapability, then it completes.
      h.capability = Completer<Map<String, dynamic>>();
      final prompt = h._promptDuressEnrollment();
      await settle();
      h.relock();
      h.capability!.complete(<String, dynamic>{'can_offer_sms': true});
      await prompt;
      check(h.events.isEmpty, 'the dialog opened over the calculator: \${h.events}');
    case 'duress_relock_and_unlock_during_capability':
      // The generation token: relocked and unlocked again during the await is
      // a different session, and the prompt that belonged to the old one ends.
      h.capability = Completer<Map<String, dynamic>>();
      final prompt = h._promptDuressEnrollment();
      await settle();
      h.relock();
      h.unlock();
      h.capability!.complete(<String, dynamic>{'can_offer_sms': false});
      await prompt;
      check(h.events.isEmpty, 'a prompt from before the relock acted: \${h.events}');
    case 'recovery_control':
      h.issue = Completer<String>();
      final flow = h._issueAndShowRecoveryCode();
      h.issue!.complete('ABCD-1234');
      await flow;
      check(h.events.single == 'code-dialog ABCD-1234', 'control: \${h.events}');
      check(h._pendingRecoveryCode == null && !h._recoveryCodeMissing, 'control state');
      check(!storage.containsKey('recovery_code_unconfirmed'),
          'the flag survived a confirmed showing');
      await h._showPendingRecoveryCode();
      check(h.events.length == 1, 'the code was shown twice');
    case 'recovery_relock_during_issue':
      // Sol: relock during _issueRecoveryCode. No dialog; the minted code is
      // kept and shown once after the unlock.
      h.issue = Completer<String>();
      final flow = h._issueAndShowRecoveryCode();
      await settle();
      h.relock();
      h.issue!.complete('ABCD-1234');
      await flow;
      check(h.events.isEmpty, 'the code dialog opened over the calculator: \${h.events}');
      check(h._pendingRecoveryCode == 'ABCD-1234', 'the minted code was lost');
      check(storage['recovery_code_unconfirmed'] == true, 'the flag was not persisted');
      await h._showPendingRecoveryCode();
      check(h.events.isEmpty, 'shown while the decoy is still up');
      h.unlock();
      await h._showPendingRecoveryCode();
      check(h.events.single == 'code-dialog ABCD-1234', 'not shown after unlock: \${h.events}');
      check(h._pendingRecoveryCode == null, 'still pending after it was seen');
      check(!storage.containsKey('recovery_code_unconfirmed'), 'flag kept after confirmation');
      check(h.mints == 1, 'a remembered code was re-minted');
      await h._showPendingRecoveryCode();
      check(h.events.length == 1, 'shown more than once');
    case 'recovery_lost_to_process_restart':
      // F1: minted, its dialog removed by a relock, then the process dies.
      // Only the flag survives; the next unlock mints a NEW code (which
      // invalidates the unseen one) and shows it once.
      h.issue = Completer<String>();
      h.whileCodeDialogOpen = h.relock;
      final flow = h._issueAndShowRecoveryCode();
      h.issue!.complete('CODE-ONE');
      await flow;
      check(h._pendingRecoveryCode == 'CODE-ONE' &&
              storage['recovery_code_unconfirmed'] == true,
          'precondition: pending and flagged');
      check(!storage.values.any((v) => '\$v'.contains('CODE-ONE')),
          'the code itself reached storage');
      final restarted = H(storage); // new process: memory is empty
      restarted.issue = Completer<String>()..complete('CODE-TWO');
      restarted._showDecoyCalculator = true;
      await restarted._showPendingRecoveryCode();
      check(restarted.events.isEmpty && restarted.mints == 0,
          'acted behind the decoy after the restart');
      restarted.unlock();
      await restarted._showPendingRecoveryCode();
      check(restarted.mints == 1, 'no new code was minted after the restart');
      check(restarted.events.single == 'code-dialog CODE-TWO',
          'the new code was not shown once: \${restarted.events}');
      check(!storage.containsKey('recovery_code_unconfirmed'),
          'the flag survived the confirmed showing');
      await restarted._showPendingRecoveryCode();
      check(restarted.mints == 1 && restarted.events.length == 1,
          'minted or shown again after confirmation');
    case 'recovery_relock_during_dialog':
      // The relock removes the open code dialog (the route clear); the code
      // stays pending instead of counting as seen.
      h.issue = Completer<String>();
      h.whileCodeDialogOpen = h.relock;
      final flow = h._issueAndShowRecoveryCode();
      h.issue!.complete('ABCD-1234');
      await flow;
      check(h._pendingRecoveryCode == 'ABCD-1234', 'an interrupted showing counted as seen');
      h.whileCodeDialogOpen = null;
      h.unlock();
      await h._showPendingRecoveryCode();
      check(h.events.length == 2 && h._pendingRecoveryCode == null,
          'not shown again after unlock: \${h.events}');
  }
  print('PASS \$scenario');
}
''');
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'duress_control',
    'duress_relock_during_capability',
    'duress_relock_and_unlock_during_capability',
    'recovery_control',
    'recovery_relock_during_issue',
    'recovery_relock_during_dialog',
    'recovery_lost_to_process_restart',
  ]) {
    test('continuation: $scenario', () async {
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[executable.path, scenario],
        workingDirectory: temporary.path,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }

  test('a launch with no decoy offers a lost recovery code', () {
    final onboarding = _between(source,
        '  Future<void> _determineSecurityOnboardingLayer() async {',
        '  Future<void> _onCalculatorButtonPressed(');
    expect(onboarding,
        contains('      if (_isLoggedIn && !_showDecoyCalculator) {\n'
            '        unawaited(_showPendingRecoveryCode());'));
  });

  test('the PIN unlock shows a pending recovery code', () {
    final unlock = _between(source,
        '  Future<void> _onCalculatorButtonPressed(String buttonText) async {',
        '  /// Before a user connect to a manual choice');
    final reset = unlock.indexOf('await _promptForMandatoryPinReset();');
    final pending = unlock.indexOf('await _showPendingRecoveryCode();');
    expect(reset, greaterThan(0));
    expect(pending, greaterThan(reset));
  });
}
