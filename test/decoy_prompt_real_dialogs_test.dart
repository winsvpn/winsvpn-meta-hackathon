// The REAL dialog bodies of the prompts the decoy can block, pumped on a real
// widget tree with the real DecoyRouteGuard, through the real deferred offer.
//
// decoy_prompt_deferral_test.dart runs the logic around each dialog with the
// dialog itself scripted. That leaves the presenters and the button wiring
// unexecuted, and two production mutants survived it (a presenter that turns
// a removed dialog into a plain "no", and a Save that pops false). This file
// closes that: it copies the production functions out of lib/main.dart at test
// time, UNMODIFIED (the presenters, their builders, the ensure function, the
// unlock offer, both PIN prompts, their commit methods, the PIN-unlock block,
// and the privacy, terms, secure-state and package-visibility dialogs), into a
// widget test, and runs that test with `flutter test`. A
// mutation of any of those functions in main.dart changes what runs here.
//
// Only what the functions read is stubbed: colours and copy constants, the
// storage writes, the legal-text fetch and the platform flag. The stubs are
// listed in the template below.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Runs [command] in its own process group with a hard timeout that kills the
/// whole group (the dart launcher, its VM and any child), so a hung scenario
/// cannot outlive the test that started it.
Future<ProcessResult> _runGrouped(
  List<String> command, {
  required String workingDirectory,
  required Duration timeout,
}) async {
  final process = await Process.start(
    'perl',
    <String>['-e', 'setpgrp(0,0); exec @ARGV', ...command],
    workingDirectory: workingDirectory,
  );
  final out = process.stdout.transform(utf8.decoder).join();
  final err = process.stderr.transform(utf8.decoder).join();
  var timedOut = false;
  final code = await process.exitCode.timeout(timeout, onTimeout: () async {
    timedOut = true;
    await Process.run('kill', <String>['-TERM', '--', '-${process.pid}']);
    await Future<void>.delayed(const Duration(seconds: 2));
    await Process.run('kill', <String>['-KILL', '--', '-${process.pid}']);
    return -9;
  });
  // Nothing of the group may remain, whatever the exit path.
  await Process.run('kill', <String>['-KILL', '--', '-${process.pid}']);
  final stdout = await out;
  final stderr = await err;
  return ProcessResult(process.pid, code,
      stdout, timedOut ? '$stderr\nTIMEOUT after ${timeout.inSeconds}s' : stderr);
}

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  if (first < 0) throw StateError('Could not extract production code: $start');
  final last = source.indexOf(end, first + start.length);
  if (last <= first) throw StateError('Could not find the end of: $start');
  return source.substring(first, last);
}

const List<String> _expected = <String>[
  'legal_agree_needs_the_checkbox_and_cancel_refuses',
  'legal_behind_the_decoy_then_the_unlock_shows_the_real_dialog_once',
  'legal_removed_by_a_relock_is_deferred_not_refused',
  'legal_two_callers_share_the_one_real_dialog',
  'disclosure_real_dialog_accept_and_not_now',
  'disclosure_removed_by_a_relock_is_deferred_not_refused',
  'pin_upgrade_real_dialog_save_pops_true_and_not_now_pops_false',
  'pin_upgrade_save_then_relock_leaves_a_working_keypad',
  'pin_reset_real_dialog_save_then_relock_retires_the_code',
  'pin_reset_cannot_be_dismissed_and_saves',
  'pin_upgrade_save_is_disabled_while_the_write_runs',
  'pin_reset_save_is_disabled_while_the_write_runs',
  'pin_upgrade_second_dialog_during_the_write_waits_and_asks_nothing',
  'pin_upgrade_save_after_not_now_never_answers_the_legal_dialog',
  'pin_upgrade_save_after_back_never_answers_the_disclosure_dialog',
  'pin_upgrade_save_under_a_newer_dialog_ends_only_its_own',
  'pin_reset_save_under_a_newer_dialog_ends_only_its_own',
  'pin_reset_save_after_its_removal_never_answers_a_newer_dialog',
  'late_privacy_buttons_never_answer_a_newer_dialog',
  'late_terms_close_never_answers_a_newer_dialog',
  'late_secure_state_ok_never_answers_a_newer_dialog',
  'late_package_buttons_never_answer_a_newer_dialog',
  'late_legal_buttons_never_answer_a_newer_dialog',
  'late_disclosure_buttons_never_answer_a_newer_dialog',
  'late_pin_upgrade_not_now_and_escape_never_answer_a_newer_dialog',
  'pin_upgrade_failed_write_after_a_relock_touches_nothing',
  'pin_reset_failed_write_after_a_relock_touches_nothing',
];

const String _template = r'''
// A hung dialog (a Save that never re-enables) fails in 90 s, not after the default 30 s per test plus the outer run.
@Timeout(Duration(seconds: 90))
library;

import 'dart:async';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/camouflage_policy.dart' show kCamouflagePinLength;
import 'package:wins_vpn/decoy_cover.dart';
import 'package:wins_vpn/decoy_prompt_gate.dart';
import 'package:wins_vpn/end_own_route.dart';
import 'package:wins_vpn/owned_keyboard_listener.dart';
import 'package:wins_vpn/tv_dpad_support.dart';

const String _androidVpnServiceDisclosureVersion = 'disclosure-v1';
const String _androidPackageVisibilityDisclosureVersion = 'pkg-v1';
const String _legalDocumentVersion = 'legal-v2';
const String _bundledLegalDocumentHash = 'h2';
const String _legalFallbackBody = 'body';
const String _privacyPolicyVersion = 'pp-v1';
const String _privacyPolicyUrl = 'https://example.invalid/privacy';
const String _termsUrl = 'https://example.invalid/terms';
const String _billingTermsUrl = 'https://example.invalid/billing';
const String _trustedContactUrl = 'https://example.invalid/contact';
const String _vulnerabilityDisclosureUrl = 'https://example.invalid/vuln';
const String _privacyPolicyBody = 'Privacy policy body.';
const String _androidVpnServiceDisclosure = 'Disclosure body.';
const Color _surfaceText = Color(0xFF111827);
const Color _surfaceMutedText = Color(0xFF4B5563);
const Color _surfacePanel = Color(0xFFFDFDFD);
const Color _surfaceLegalBox = Color(0xFFFFFFFF);
const Color _surfaceBorder = Color(0x26000000);
const String account = '111122223333';

String nativeTunnelErrorSummary(Object error) => 'native:$error';

String? pinPolicyRejectionReason(String pin) {
  if (pin.length != kCamouflagePinLength) return 'Please choose a 6-digit code.';
  if (pin == '123456') return 'That code is too easy to guess.';
  return null;
}

class _Epoch {
  int current = 1;
  int bump() => ++current;
  bool isCurrent(int epoch) => epoch == current;
}

class _PinEntry {
  int pinLength = 4;
  void reset() {}
}

@@LEGAL_STALE@@

class _HostW extends StatefulWidget {
  const _HostW({required this.guard});
  final DecoyRouteGuard guard;
  @override
  State<_HostW> createState() => H();
}

class H extends State<_HostW> {
  bool isAndroid = false;
  bool _showDecoyCalculator = false;
  int _decoyGeneration = 0;
  final _Epoch _accountSessionEpoch = _Epoch();
  final DeferredPrompt _deferredLegalConsent = DeferredPrompt();
  bool _privacyConsentGranted = true;
  bool _privacyConsentPromptOpen = false;
  String _androidPackageVisibilityConsentVersion = '';
  bool _isLoggedIn = true;
  bool _isFreeAccessSession = false;
  bool _isLoading = false;
  final String _freeAccessAccountNumber = 'FREE-ACCESS-1';
  String _legalAcceptedVersion = '';
  String _legalAcceptedHash = '';
  String _androidVpnServiceDisclosureConsentVersion = '';
  String _androidVpnServiceDisclosureAcceptedAtUtc = '';
  Future<bool>? _androidVpnServiceDisclosureConsentRequest;
  Future<bool>? _legalAcceptanceDialogRequest;
  String _legalAcceptanceDialogKey = '';
  bool _pinResetWriting = false;
  bool _pinResetPromptWaiting = false;
  bool _pinUpgradePromptWaiting = false;
  bool _pinUpgradeDialogOpen = false;
  bool _pinResetDialogOpen = false;
  Future<String?>? _pinUpgradeInFlight;
  bool _pinUpgradeAvailable = true;
  bool _pinResetRequired = false;
  bool _pinResetCommitted = false;
  Future<String?>? _pinResetInFlight;
  bool _recoveryUnlockPending = false;
  String _calcDisplayString = '0';
  final _PinEntry _calculatorPinEntry = _PinEntry();
  final TextEditingController _pinUpgradeController = TextEditingController();

  final List<String> saved = <String>[];
  final List<String> feedback = <String>[];
  int replaced = 0;
  int issued = 0;
  Future<void> Function()? replaceHook;

  void _debugLog(String message) {}
  String _t(String value) => value;
  void _showFeedback(String message) {
    if (_showDecoyCalculator) return;
    feedback.add(message);
  }

  bool _accountEpochIsCurrent(int epoch) => _accountSessionEpoch.isCurrent(epoch);
  ThemeData _lightSurfaceTheme(BuildContext context) => Theme.of(context);
  String _localeCode() => 'en';
  String _localizedLegalBody(String body) => body;

  void relock() {
    _decoyGeneration++;
    clearProductSurfacesForDecoy(context, guard: widget.guard);
    setState(() => _showDecoyCalculator = true);
  }

  void unlockOnly() => setState(() => _showDecoyCalculator = false);

  Future<void> _saveVpnRuntimeSettings({
    String? accountNumber,
    String? legalAcceptedVersion,
    String? legalAcceptedHash,
    String? androidVpnServiceDisclosureConsentVersion,
    String? androidVpnServiceDisclosureAcceptedAtUtc,
    String? androidPackageVisibilityConsentVersion,
  }) async {
    if (legalAcceptedVersion != null) saved.add('legal:$legalAcceptedVersion');
    if (androidVpnServiceDisclosureConsentVersion != null) {
      saved.add('disclosure:$androidVpnServiceDisclosureConsentVersion');
    }
    if (androidPackageVisibilityConsentVersion != null) {
      saved.add('package:$androidPackageVisibilityConsentVersion');
    }
  }

  Future<Map<String, String>> _loadLegalDocumentForAcceptance() async =>
      <String, String>{
        'version': 'legal-v2',
        'hash': 'h2',
        'body': 'b',
        'display_body': 'Legal display body.',
      };
  Map<String, dynamic> _legalAcceptancePayload(Map<String, String> doc) =>
      <String, dynamic>{'legal_version': doc['version']};
  Future<bool> _ensurePrivacyConsentForNetworkUse() async => _privacyConsentGranted;
  Future<String> _currentAccountNumberForRefresh() async => account;
  Future<void> _replaceUserPin(String pin) async {
    final hook = replaceHook;
    if (hook != null) await hook();
    replaced++;
  }

  Future<void> _issueAndShowRecoveryCode() async => issued++;
  Future<void> _persistPrivacyConsent() async {}
  void _startPostPrivacyConsentInitialization() {}
  Future<void> _setLauncherCamouflage({required bool enabled}) async {}
  Future<void> _reconcileNativeTunnelState({bool refreshNetworkLabel = false}) async {}
  void _runPendingSettingsRestart() {}
  // Round UN: queues a tunnel-name restore; it raises no dialog.
  void _scheduleTunnelDisplayRestore() {}
  Future<void> _showPendingRecoveryCode() async {}

  Future<void> pinUnlockAccepted() async {
@@UNLOCK@@
  }

  @override
  Widget build(BuildContext context) => Scaffold(
      body: Center(child: Text(_showDecoyCalculator ? '7 8 9 = 0' : "Win's VPN")));

  // ---- production code, unmodified ------------------------------------
@@LABELS@@
@@PRIVACY@@
@@PACKAGE@@
@@LEGAL@@
@@GLUE@@
@@PIN_UPGRADE@@
@@PIN_RESET@@
}

Future<H> pump(WidgetTester tester) async {
  late H host;
  final guard = DecoyRouteGuard(decoyShowing: () => host._showDecoyCalculator);
  await tester.pumpWidget(MaterialApp(
    navigatorObservers: <NavigatorObserver>[guard],
    home: _HostW(guard: guard),
  ));
  host = tester.state<H>(find.byType(_HostW));
  return host;
}

Future<void> settle(WidgetTester tester) async {
  for (var i = 0; i < 6; i++) {
    await tester.pump(const Duration(milliseconds: 60));
  }
}

const String legalTitle = 'Privacy Policy and Legal Acceptance Required';

void noDialog() {
  expect(find.byType(AlertDialog, skipOffstage: false), findsNothing);
  expect(find.byType(Dialog, skipOffstage: false), findsNothing);
}

/// Lets microtasks run with no frame in between (no element is rebuilt).
Future<void> microtasks() async {
  for (var i = 0; i < 50; i++) {
    await Future<void>.value();
  }
}

/// The button's own callback, kept to be called after its dialog has ended.
VoidCallback lateTap<B extends ButtonStyleButton>(WidgetTester tester, String label) {
  final callback = tester.widget<B>(find.widgetWithText(B, label)).onPressed;
  expect(callback, isNotNull, reason: '$label is disabled');
  return callback!;
}

/// Ends the open dialog titled [oldTitle] with [end], lets its exit animation
/// start, presents a newer legal dialog through the real ensure function while
/// the old one is still mounted, then calls each [late] callback of the old
/// dialog. The newer dialog must stay open, unanswered, with nothing stored.
Future<void> lateAnswersLeaveTheNewerDialog(
  WidgetTester tester,
  H h, {
  required String oldTitle,
  required Future<void> Function() end,
  required List<VoidCallback> late,
}) async {
  await end();
  await tester.pump();
  h._legalAcceptedVersion = '';
  h._legalAcceptedHash = '';
  var legalEnded = false;
  final legal = h._ensureLegalAcceptanceForActivation(account)
    ..then((_) => legalEnded = true);
  await tester.pump();
  await tester.pump();
  final shown = oldTitle == legalTitle ? 2 : 1;
  expect(find.text(legalTitle), findsNWidgets(shown), reason: 'no newer legal dialog');
  expect(find.text(oldTitle), findsWidgets,
      reason: 'the old dialog was unmounted already: no window');
  for (final callback in late) {
    callback();
    await tester.pump();
    expect(legalEnded, isFalse,
        reason: 'a late answer of "$oldTitle" ended the newer legal dialog');
  }
  await settle(tester);
  expect(find.text(legalTitle), findsOneWidget,
      reason: 'a late answer of "$oldTitle" closed the newer legal dialog');
  if (oldTitle != legalTitle) expect(find.text(oldTitle), findsNothing);
  expect(legalEnded, isFalse);
  expect(h.saved, isEmpty, reason: 'a late answer recorded consent');
  await tester.tap(find.text('Cancel'));
  await settle(tester);
  expect(await legal, isNull);
  expect(h.saved, isEmpty);
  noDialog();
  expect(tester.takeException(), isNull);
}

void main() {
  testWidgets('legal_agree_needs_the_checkbox_and_cancel_refuses', (tester) async {
    final h = await pump(tester);
    var done = h._ensureLegalAcceptanceForActivation(account);
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget);
    // Agree is disabled until the box is ticked.
    await tester.tap(find.text('Agree'));
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget, reason: 'Agree worked unticked');
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    await tester.tap(find.text('Agree'));
    await settle(tester);
    expect(await done, isNotNull);
    expect(h.saved, <String>['legal:legal-v2']);
    noDialog();
    // Cancel is a refusal: nothing stored, nothing kept.
    h._legalAcceptedVersion = '';
    h.saved.clear();
    done = h._ensureLegalAcceptanceForActivation(account);
    await settle(tester);
    await tester.tap(find.text('Cancel'));
    await settle(tester);
    expect(await done, isNull);
    expect(h.saved, isEmpty);
    expect(h._deferredLegalConsent.isPending, isFalse);
    expect(h.feedback.last, 'Legal acceptance is required before activation.');
    print('REAL_OK legal_agree_needs_the_checkbox_and_cancel_refuses');
  });

  testWidgets('legal_behind_the_decoy_then_the_unlock_shows_the_real_dialog_once',
      (tester) async {
    final h = await pump(tester);
    h.relock();
    await settle(tester);
    final blocked = await h._ensureLegalAcceptanceForActivation(account);
    await settle(tester);
    expect(blocked, isNull);
    noDialog();
    expect(find.text('7 8 9 = 0'), findsOneWidget);
    expect(h._deferredLegalConsent.isPending, isTrue);
    final unlock = h.pinUnlockAccepted();
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget, reason: 'not offered at the unlock');
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    await tester.tap(find.text('Agree'));
    await settle(tester);
    await unlock;
    expect(h.saved, <String>['legal:legal-v2']);
    noDialog();
    // Once: another relock and unlock asks nothing.
    h.relock();
    await settle(tester);
    await h.pinUnlockAccepted();
    await settle(tester);
    noDialog();
    expect(h.saved, hasLength(1));
    print('REAL_OK legal_behind_the_decoy_then_the_unlock_shows_the_real_dialog_once');
  });

  testWidgets('legal_removed_by_a_relock_is_deferred_not_refused', (tester) async {
    final h = await pump(tester);
    final done = h._ensureLegalAcceptanceForActivation(account);
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget);
    h.relock();
    await settle(tester);
    noDialog();
    expect(await done, isNull);
    expect(h.saved, isEmpty);
    expect(h._deferredLegalConsent.isPending, isTrue,
        reason: 'a removed dialog was read as a refusal');
    final unlock = h.pinUnlockAccepted();
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget);
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    await tester.tap(find.text('Agree'));
    await settle(tester);
    await unlock;
    expect(h.saved, <String>['legal:legal-v2']);
    print('REAL_OK legal_removed_by_a_relock_is_deferred_not_refused');
  });

  testWidgets('legal_two_callers_share_the_one_real_dialog', (tester) async {
    final h = await pump(tester);
    final a = h._ensureLegalAcceptanceForActivation(account);
    final b = h._ensureLegalAcceptanceForActivation(account);
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget, reason: 'the dialogs stacked');
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    await tester.tap(find.text('Agree'));
    await settle(tester);
    expect(await a, isNotNull);
    expect(await b, isNotNull);
    noDialog();
    print('REAL_OK legal_two_callers_share_the_one_real_dialog');
  });

  testWidgets('disclosure_real_dialog_accept_and_not_now', (tester) async {
    final h = await pump(tester);
    h.isAndroid = true;
    h._legalAcceptedVersion = 'legal-v2';
    h._legalAcceptedHash = 'h2';
    var done = h._ensureLegalAcceptanceForActivation(account);
    await settle(tester);
    expect(find.text('Android VPN disclosure'), findsOneWidget);
    await tester.tap(find.text('Accept and continue'));
    await settle(tester);
    expect(find.text('Android VPN disclosure'), findsOneWidget, reason: 'accepted unticked');
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    await tester.tap(find.text('Accept and continue'));
    await settle(tester);
    expect(await done, isNotNull);
    expect(h.saved, <String>['disclosure:disclosure-v1']);
    // Not now is a refusal.
    h._androidVpnServiceDisclosureConsentVersion = '';
    h._androidVpnServiceDisclosureAcceptedAtUtc = '';
    h.saved.clear();
    done = h._ensureLegalAcceptanceForActivation(account);
    await settle(tester);
    await tester.tap(find.text('Not now'));
    await settle(tester);
    expect(await done, isNull);
    expect(h.saved, isEmpty);
    expect(h._deferredLegalConsent.isPending, isFalse);
    print('REAL_OK disclosure_real_dialog_accept_and_not_now');
  });

  testWidgets('disclosure_removed_by_a_relock_is_deferred_not_refused', (tester) async {
    final h = await pump(tester);
    h.isAndroid = true;
    h._legalAcceptedVersion = 'legal-v2';
    h._legalAcceptedHash = 'h2';
    final done = h._ensureLegalAcceptanceForActivation(account);
    await settle(tester);
    expect(find.text('Android VPN disclosure'), findsOneWidget);
    h.relock();
    await settle(tester);
    noDialog();
    expect(await done, isNull);
    expect(h._deferredLegalConsent.isPending, isTrue,
        reason: 'a removed disclosure was read as a refusal');
    final unlock = h.pinUnlockAccepted();
    await settle(tester);
    expect(find.text('Android VPN disclosure'), findsOneWidget);
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    await tester.tap(find.text('Accept and continue'));
    await settle(tester);
    await unlock;
    expect(h.saved, <String>['disclosure:disclosure-v1']);
    print('REAL_OK disclosure_removed_by_a_relock_is_deferred_not_refused');
  });

  testWidgets('pin_upgrade_real_dialog_save_pops_true_and_not_now_pops_false',
      (tester) async {
    final h = await pump(tester);
    var done = h._promptForPinUpgrade();
    await settle(tester);
    expect(find.text('Set a longer unlock code'), findsOneWidget);
    Finder saveButton() => find.widgetWithText(TextButton, 'Save');
    // A rejected code shows its message and leaves Save usable again.
    for (final rejected in <String>['123456', '48']) {
      await tester.enterText(find.byType(TextField), rejected);
      await tester.tap(saveButton());
      await settle(tester);
      expect(find.text('Set a longer unlock code'), findsOneWidget,
          reason: 'a rejected code closed the dialog');
      expect(h.replaced, 0);
      expect(tester.widget<TextButton>(saveButton()).onPressed, isNotNull,
          reason: 'Save stayed dead after a rejected code');
    }
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await settle(tester);
    await done;
    noDialog();
    expect(h.replaced, 1);
    expect(h._calculatorPinEntry.pinLength, 6);
    expect(h._pinUpgradeAvailable, isFalse);
    expect(h.feedback, contains('Unlock code updated.'),
        reason: 'Save did not answer true');
    // Not now pops false: nothing stored, the notice stays.
    h._pinUpgradeAvailable = true;
    h._calculatorPinEntry.pinLength = 4;
    h.feedback.clear();
    done = h._promptForPinUpgrade();
    await settle(tester);
    await tester.tap(find.text('Not now'));
    await settle(tester);
    await done;
    noDialog();
    expect(h.replaced, 1);
    expect(h._pinUpgradeAvailable, isTrue);
    expect(h.feedback, isEmpty);
    print('REAL_OK pin_upgrade_real_dialog_save_pops_true_and_not_now_pops_false');
  });

  testWidgets('pin_upgrade_save_then_relock_leaves_a_working_keypad', (tester) async {
    final h = await pump(tester);
    // The write outlives the dialog: the relock removes it, frames pump and
    // dispose its elements, and only then does the write finish.
    final gate = Completer<void>();
    h.replaceHook = () async {
      h.relock();
      await gate.future;
    };
    final done = h._promptForPinUpgrade();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await settle(tester);
    noDialog();
    gate.complete();
    await settle(tester);
    await done;
    noDialog();
    expect(h.replaced, 1);
    expect(h._calculatorPinEntry.pinLength, 6,
        reason: 'the keypad kept expecting the old length');
    expect(h._pinUpgradeAvailable, isFalse);
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_upgrade_save_then_relock_leaves_a_working_keypad');
  });

  testWidgets('pin_reset_real_dialog_save_then_relock_retires_the_code', (tester) async {
    final h = await pump(tester);
    h._pinResetRequired = true;
    final gate = Completer<void>();
    h.replaceHook = () async {
      h.relock();
      await gate.future;
    };
    final done = h._promptForMandatoryPinReset();
    await settle(tester);
    expect(find.text('Choose a new unlock code'), findsOneWidget);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await settle(tester);
    noDialog();
    gate.complete();
    await settle(tester);
    await done;
    noDialog();
    expect(h.replaced, 1);
    expect(h._calculatorPinEntry.pinLength, 6);
    expect(h._pinResetRequired, isFalse);
    expect(h.issued, 1, reason: 'the typed recovery code was not retired');
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_reset_real_dialog_save_then_relock_retires_the_code');
  });

  testWidgets('pin_reset_cannot_be_dismissed_and_saves', (tester) async {
    final h = await pump(tester);
    h._pinResetRequired = true;
    final done = h._promptForMandatoryPinReset();
    await settle(tester);
    // Back does not dismiss it.
    await tester.binding.handlePopRoute();
    await settle(tester);
    expect(find.text('Choose a new unlock code'), findsOneWidget);
    await tester.enterText(find.byType(TextField), '123456');
    await tester.tap(find.text('Save'));
    await settle(tester);
    expect(find.text('Choose a new unlock code'), findsOneWidget, reason: 'a weak code closed it');
    expect(h.replaced, 0);
    expect(tester.widget<TextButton>(find.widgetWithText(TextButton, 'Save')).onPressed, isNotNull,
        reason: 'Save stayed dead after a rejected code');
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await settle(tester);
    await done;
    noDialog();
    expect(h.replaced, 1);
    expect(h._pinResetRequired, isFalse);
    expect(h.issued, 1);
    print('REAL_OK pin_reset_cannot_be_dismissed_and_saves');
  });

  testWidgets('pin_upgrade_save_is_disabled_while_the_write_runs', (tester) async {
    final h = await pump(tester);
    final gate = Completer<void>();
    h.replaceHook = () async => gate.future;
    final done = h._promptForPinUpgrade();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    Finder save() => find.widgetWithText(TextButton, 'Save');
    expect(tester.widget<TextButton>(save()).onPressed, isNotNull);
    await tester.tap(save());
    await settle(tester);
    expect(tester.widget<TextButton>(save()).onPressed, isNull,
        reason: 'Save stayed live during the write');
    await tester.tap(save(), warnIfMissed: false);
    await settle(tester);
    gate.complete();
    await settle(tester);
    await done;
    expect(h.replaced, 1, reason: 'a second tap started a second write');
    noDialog();
    print('REAL_OK pin_upgrade_save_is_disabled_while_the_write_runs');
  });

  testWidgets('pin_reset_save_is_disabled_while_the_write_runs', (tester) async {
    final h = await pump(tester);
    h._pinResetRequired = true;
    final gate = Completer<void>();
    h.replaceHook = () async => gate.future;
    final done = h._promptForMandatoryPinReset();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    Finder save() => find.widgetWithText(TextButton, 'Save');
    await tester.tap(save());
    await settle(tester);
    expect(tester.widget<TextButton>(save()).onPressed, isNull,
        reason: 'Save stayed live during the write');
    await tester.tap(save(), warnIfMissed: false);
    await settle(tester);
    gate.complete();
    await settle(tester);
    await done;
    expect(h.replaced, 1, reason: 'a second tap started a second write');
    expect(h.issued, 1);
    noDialog();
    print('REAL_OK pin_reset_save_is_disabled_while_the_write_runs');
  });

  testWidgets('pin_upgrade_second_dialog_during_the_write_waits_and_asks_nothing',
      (tester) async {
    final h = await pump(tester);
    final gate = Completer<void>();
    h.replaceHook = () async {
      h.relock();
      await gate.future;
    };
    final first = h._promptForPinUpgrade();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await settle(tester);
    noDialog();
    // The user unlocks with the old code before the write commits and taps the
    // notice again: the second prompt waits for the write and asks nothing.
    h.replaceHook = null;
    h.unlockOnly();
    final second = h._promptForPinUpgrade();
    await settle(tester);
    noDialog();
    gate.complete();
    await settle(tester);
    await first;
    await second;
    await settle(tester);
    noDialog();
    expect(h.replaced, 1, reason: 'a second write was started');
    expect(h._pinUpgradeAvailable, isFalse);
    expect(h._calculatorPinEntry.pinLength, 6);
    print('REAL_OK pin_upgrade_second_dialog_during_the_write_waits_and_asks_nothing');
  });

  // ---- Turn 7: a dialog's late answer ends that dialog, never a newer one ----
  //
  // Navigator.pop ends whatever route is on top. A dialog that was popped stays
  // mounted while it animates out, and a Save whose write outlived its dialog
  // still holds a mounted context in that window. Each test below presents a
  // newer consent dialog in such a window and checks that the late answer
  // leaves it open, unanswered, with nothing stored.

  testWidgets('pin_upgrade_save_after_not_now_never_answers_the_legal_dialog',
      (tester) async {
    final h = await pump(tester);
    final gate = Completer<void>();
    h.replaceHook = () async => gate.future;
    final upgrade = h._promptForPinUpgrade();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await tester.pump();
    // "Not now" stays live while the write runs.
    await tester.tap(find.text('Not now'));
    await tester.pump();
    await upgrade;
    var legalEnded = false;
    final legal = h._ensureLegalAcceptanceForActivation(account)
      ..then((_) => legalEnded = true);
    await tester.pump();
    await tester.pump();
    expect(find.text(legalTitle), findsOneWidget);
    expect(find.text('Set a longer unlock code'), findsOneWidget,
        reason: 'the upgrade dialog was gone before the write ended: no window');
    gate.complete();
    await tester.pump();
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget,
        reason: 'the dismissed upgrade dialog\'s Save answered the legal dialog');
    expect(legalEnded, isFalse);
    expect(h.saved, isEmpty);
    expect(h.replaced, 1);
    expect(h._calculatorPinEntry.pinLength, 6);
    expect(find.text('Set a longer unlock code'), findsNothing);
    // The legal dialog still asks for itself.
    await tester.tap(find.text('Cancel'));
    await settle(tester);
    expect(await legal, isNull);
    expect(h.saved, isEmpty);
    noDialog();
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_upgrade_save_after_not_now_never_answers_the_legal_dialog');
  });

  testWidgets('pin_upgrade_save_after_back_never_answers_the_disclosure_dialog',
      (tester) async {
    final h = await pump(tester);
    h.isAndroid = true;
    h._legalAcceptedVersion = 'legal-v2';
    h._legalAcceptedHash = 'h2';
    final gate = Completer<void>();
    h.replaceHook = () async => gate.future;
    final upgrade = h._promptForPinUpgrade();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await tester.pump();
    // The system back gesture pops the upgrade dialog during its write.
    await tester.binding.handlePopRoute();
    await tester.pump();
    await upgrade;
    var ended = false;
    final consent = h._ensureLegalAcceptanceForActivation(account)
      ..then((_) => ended = true);
    await tester.pump();
    await tester.pump();
    expect(find.text('Android VPN disclosure'), findsOneWidget);
    expect(find.text('Set a longer unlock code'), findsOneWidget,
        reason: 'the upgrade dialog was gone before the write ended: no window');
    gate.complete();
    await tester.pump();
    await settle(tester);
    expect(find.text('Android VPN disclosure'), findsOneWidget,
        reason: 'the popped upgrade dialog\'s Save answered the disclosure');
    expect(ended, isFalse);
    expect(h.saved, isEmpty);
    expect(h.replaced, 1);
    await tester.tap(find.text('Not now'));
    await settle(tester);
    expect(await consent, isNull);
    expect(h.saved, isEmpty);
    noDialog();
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_upgrade_save_after_back_never_answers_the_disclosure_dialog');
  });

  testWidgets('pin_upgrade_save_under_a_newer_dialog_ends_only_its_own',
      (tester) async {
    final h = await pump(tester);
    final gate = Completer<void>();
    h.replaceHook = () async => gate.future;
    var upgradeEnded = false;
    final upgrade = h._promptForPinUpgrade()..then((_) => upgradeEnded = true);
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await tester.pump();
    // A connect flow presents the legal dialog over the open upgrade dialog.
    var legalEnded = false;
    final legal = h._ensureLegalAcceptanceForActivation(account)
      ..then((_) => legalEnded = true);
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget);
    expect(find.text('Set a longer unlock code'), findsOneWidget);
    gate.complete();
    await tester.pump();
    await settle(tester);
    // The upgrade dialog ends with its own answer; the legal dialog is untouched.
    expect(upgradeEnded, isTrue, reason: 'the covered upgrade dialog never ended');
    await upgrade;
    expect(find.text('Set a longer unlock code'), findsNothing);
    expect(h.feedback, contains('Unlock code updated.'));
    expect(find.text(legalTitle), findsOneWidget,
        reason: 'the upgrade dialog\'s Save answered the legal dialog');
    expect(legalEnded, isFalse);
    expect(h.saved, isEmpty);
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    await tester.tap(find.text('Agree'));
    await settle(tester);
    expect(await legal, isNotNull);
    expect(h.saved, <String>['legal:legal-v2']);
    noDialog();
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_upgrade_save_under_a_newer_dialog_ends_only_its_own');
  });

  testWidgets('pin_reset_save_under_a_newer_dialog_ends_only_its_own',
      (tester) async {
    final h = await pump(tester);
    h._pinResetRequired = true;
    final gate = Completer<void>();
    h.replaceHook = () async => gate.future;
    var resetEnded = false;
    final reset = h._promptForMandatoryPinReset()..then((_) => resetEnded = true);
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await tester.pump();
    var legalEnded = false;
    final legal = h._ensureLegalAcceptanceForActivation(account)
      ..then((_) => legalEnded = true);
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget);
    expect(find.text('Choose a new unlock code'), findsOneWidget);
    gate.complete();
    await tester.pump();
    await settle(tester);
    expect(resetEnded, isTrue, reason: 'the covered reset dialog never ended');
    await reset;
    expect(find.text('Choose a new unlock code'), findsNothing);
    expect(h._pinResetRequired, isFalse);
    expect(h.issued, 1);
    expect(find.text(legalTitle), findsOneWidget,
        reason: 'the reset dialog\'s Save answered the legal dialog');
    expect(legalEnded, isFalse);
    expect(h.saved, isEmpty);
    await tester.tap(find.text('Cancel'));
    await settle(tester);
    expect(await legal, isNull);
    noDialog();
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_reset_save_under_a_newer_dialog_ends_only_its_own');
  });

  testWidgets('pin_reset_save_after_its_removal_never_answers_a_newer_dialog',
      (tester) async {
    final h = await pump(tester);
    h._pinResetRequired = true;
    final gate = Completer<void>();
    h.replaceHook = () async => gate.future;
    final reset = h._promptForMandatoryPinReset();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await tester.pump();
    // Inside one frame: a relock removes the reset dialog (its elements stay
    // mounted until the next frame), the app is unlocked, a legal dialog is
    // presented, and the write ends.
    h.relock();
    h.unlockOnly();
    var legalEnded = false;
    final legal = h._ensureLegalAcceptanceForActivation(account)
      ..then((_) => legalEnded = true);
    await microtasks();
    expect(h._legalAcceptanceDialogRequest, isNotNull, reason: 'no legal dialog was presented');
    expect(find.text('Choose a new unlock code'), findsOneWidget,
        reason: 'the removed dialog was unmounted already: no window');
    gate.complete();
    await microtasks();
    await settle(tester);
    expect(find.text(legalTitle), findsOneWidget,
        reason: 'the removed reset dialog\'s Save answered the legal dialog');
    expect(legalEnded, isFalse);
    expect(h.saved, isEmpty);
    await reset;
    expect(h.issued, 1);
    expect(h._pinResetRequired, isFalse);
    await tester.tap(find.text('Cancel'));
    await settle(tester);
    expect(await legal, isNull);
    noDialog();
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_reset_save_after_its_removal_never_answers_a_newer_dialog');
  });

  testWidgets('late_privacy_buttons_never_answer_a_newer_dialog', (tester) async {
    final h = await pump(tester);
    final done = h._showPrivacyPolicyDialog(requireConsent: true);
    await settle(tester);
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    final late = <VoidCallback>[
      lateTap<TextButton>(tester, 'Not now'),
      lateTap<ElevatedButton>(tester, 'Accept Privacy Policy'),
    ];
    await lateAnswersLeaveTheNewerDialog(tester, h,
        oldTitle: 'Privacy Policy and Legal Consent',
        end: () => tester.tap(find.text('Not now')),
        late: late);
    await done;
    print('REAL_OK late_privacy_buttons_never_answer_a_newer_dialog');
  });

  testWidgets('late_terms_close_never_answers_a_newer_dialog', (tester) async {
    final h = await pump(tester);
    final done = h._showTermsAndLegalDialog();
    await settle(tester);
    final late = <VoidCallback>[lateTap<ElevatedButton>(tester, 'Close')];
    await lateAnswersLeaveTheNewerDialog(tester, h,
        oldTitle: 'Terms and Legal',
        end: () => tester.tap(find.text('Close')),
        late: late);
    await done;
    print('REAL_OK late_terms_close_never_answers_a_newer_dialog');
  });

  testWidgets('late_secure_state_ok_never_answers_a_newer_dialog', (tester) async {
    final h = await pump(tester);
    final done = h._showSecureStateFailureDialog(title: 'Not saved', error: 'e');
    await settle(tester);
    final late = <VoidCallback>[lateTap<ElevatedButton>(tester, 'OK')];
    await lateAnswersLeaveTheNewerDialog(tester, h,
        oldTitle: 'Not saved', end: () => tester.tap(find.text('OK')), late: late);
    await done;
    print('REAL_OK late_secure_state_ok_never_answers_a_newer_dialog');
  });

  testWidgets('late_package_buttons_never_answer_a_newer_dialog', (tester) async {
    final h = await pump(tester);
    final done = h._promptForAndroidPackageVisibilityConsent();
    await settle(tester);
    final late = <VoidCallback>[
      lateTap<TextButton>(tester, 'Not now'),
      lateTap<ElevatedButton>(tester, 'Continue'),
    ];
    await lateAnswersLeaveTheNewerDialog(tester, h,
        oldTitle: 'Installed app access',
        end: () => tester.tap(find.text('Not now')),
        late: late);
    expect(await done, isFalse);
    print('REAL_OK late_package_buttons_never_answer_a_newer_dialog');
  });

  testWidgets('late_legal_buttons_never_answer_a_newer_dialog', (tester) async {
    final h = await pump(tester);
    final done = h._presentLegalAcceptanceDialog(<String, String>{
      'version': 'legal-v2',
      'hash': 'h2',
      'body': 'b',
      'display_body': 'Legal display body.',
    });
    await settle(tester);
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    final late = <VoidCallback>[
      lateTap<TextButton>(tester, 'Cancel'),
      lateTap<ElevatedButton>(tester, 'Agree'),
    ];
    await lateAnswersLeaveTheNewerDialog(tester, h,
        oldTitle: legalTitle,
        end: () => tester.tap(find.text('Cancel')),
        late: late);
    expect(await done, isFalse);
    print('REAL_OK late_legal_buttons_never_answer_a_newer_dialog');
  });

  testWidgets('late_disclosure_buttons_never_answer_a_newer_dialog', (tester) async {
    final h = await pump(tester);
    h.isAndroid = true;
    final done = h._presentAndroidVpnServiceDisclosureDialog();
    await settle(tester);
    await tester.tap(find.byType(Checkbox));
    await settle(tester);
    final late = <VoidCallback>[
      lateTap<TextButton>(tester, 'Not now'),
      lateTap<ElevatedButton>(tester, 'Accept and continue'),
    ];
    h.isAndroid = false;
    await lateAnswersLeaveTheNewerDialog(tester, h,
        oldTitle: 'Android VPN disclosure',
        end: () => tester.tap(find.text('Not now')),
        late: late);
    expect(await done, isFalse);
    print('REAL_OK late_disclosure_buttons_never_answer_a_newer_dialog');
  });

  testWidgets('late_pin_upgrade_not_now_and_escape_never_answer_a_newer_dialog',
      (tester) async {
    final h = await pump(tester);
    final done = h._promptForPinUpgrade();
    await settle(tester);
    final titleContext = tester.element(find.text('Set a longer unlock code'));
    final late = <VoidCallback>[
      lateTap<TextButton>(tester, 'Not now'),
      () => Actions.invoke(titleContext, const DismissIntent()),
    ];
    await lateAnswersLeaveTheNewerDialog(tester, h,
        oldTitle: 'Set a longer unlock code',
        end: () => tester.tap(find.text('Not now')),
        late: late);
    await done;
    expect(h.replaced, 0);
    print('REAL_OK late_pin_upgrade_not_now_and_escape_never_answer_a_newer_dialog');
  });

  // The Save's own mounted check, not _endOwnDialog's, is what keeps a failed
  // write from updating a dialog a relock has disposed.
  testWidgets('pin_upgrade_failed_write_after_a_relock_touches_nothing', (tester) async {
    final h = await pump(tester);
    final gate = Completer<void>();
    h.replaceHook = () async {
      h.relock();
      await gate.future;
      throw StateError('the store refused the write');
    };
    final done = h._promptForPinUpgrade();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await settle(tester);
    noDialog();
    gate.complete();
    await settle(tester);
    await done;
    noDialog();
    expect(h.replaced, 0);
    expect(h._calculatorPinEntry.pinLength, 4);
    expect(h._pinUpgradeAvailable, isTrue);
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_upgrade_failed_write_after_a_relock_touches_nothing');
  });

  testWidgets('pin_reset_failed_write_after_a_relock_touches_nothing', (tester) async {
    final h = await pump(tester);
    h._pinResetRequired = true;
    final gate = Completer<void>();
    h.replaceHook = () async {
      h.relock();
      await gate.future;
      throw StateError('the store refused the write');
    };
    final done = h._promptForMandatoryPinReset();
    await settle(tester);
    await tester.enterText(find.byType(TextField), '482915');
    await tester.tap(find.text('Save'));
    await settle(tester);
    noDialog();
    gate.complete();
    await settle(tester);
    await done;
    noDialog();
    expect(h.replaced, 0);
    expect(h._pinResetRequired, isTrue);
    expect(h.issued, 0);
    expect(tester.takeException(), isNull);
    print('REAL_OK pin_reset_failed_write_after_a_relock_touches_nothing');
  });
}
''';

void main() {
  late Directory genDir;
  late File generated;

  setUpAll(() async {
    final source = File('lib/main.dart').readAsStringSync();
    final chunks = <String, String>{
      'LEGAL_STALE': _between(
          source,
          'bool legalAcceptanceIsStale({',
          '/// Returns the location value sent to the control plane'),
      'UNLOCK': _between(
          source,
          '        final viaRecoveryCode = _recoveryUnlockPending;',
          '      } else {\n'
              '        // For camouflage purposes'),
      'PRIVACY': _between(
          source,
          '  Future<bool> _showPrivacyPolicyDialog({required bool requireConsent}) async {',
          '  Future<bool> _ensurePrivacyConsentForNetworkUse() async {'),
      'PACKAGE': _between(
          source,
          '  Future<bool> _promptForAndroidPackageVisibilityConsent() async {',
          '  Future<void> _toggleSplitTunnelPanel() async {'),
      'LABELS': _between(
          source,
          '  Map<String, String> _localizedLegalLabels() {',
          '  Future<Map<String, String>> _loadLegalDocumentForAcceptance() async {'),
      'LEGAL': _between(
          source,
          '  /// Shows the legal dialog for [doc], alone. A caller joins an open dialog',
          '  Future<bool> _fetchAvailableNodes('),
      'GLUE': _between(
              source,
              '  bool _decoyStillAway(int decoyGeneration) =>',
              '  Future<void> _showDuressEnrollmentDialog(') +
          _between(
              source,
              '  /// Runs one legal-terms or Android VPN-disclosure dialog under the decoy',
              '  Future<void> _promptForPinUpgrade() async {'),
      'PIN_UPGRADE': _between(
          source,
          '  Future<void> _promptForPinUpgrade() async {',
          '  Widget _buildVpnDashboard('),
      'PIN_RESET': _between(
          source,
          '  Future<void> _promptForMandatoryPinReset() async {',
          '  /// Offer to create a recovery code on an install that predates them.'),
    };
    var text = _template;
    for (final entry in chunks.entries) {
      text = text.replaceAll('@@${entry.key}@@', entry.value);
    }
    text = text.replaceAll('Platform.isAndroid', 'isAndroid');
    // Two rewrites, both listed in the header of the generated file's stubs:
    // the platform flag becomes a field, and the legal text box's
    // Scrollbar(thumbVisibility: true), which asserts in debug builds inside a
    // dialog (no PrimaryScrollController there), is switched off. Nothing else
    // in the copied text is touched.
    genDir = Directory('.dart_tool/l97_real_dialogs')..createSync(recursive: true);
    generated = File('${genDir.path}/real_dialogs_test.dart');
    await generated.writeAsString(text);
  });

  tearDownAll(() async {
    if (genDir.existsSync()) genDir.deleteSync(recursive: true);
  });

  test('the real dialog bodies, pumped through the real deferred offer',
      () async {
    final flutter = '${Platform.environment['FLUTTER_ROOT']}/bin/flutter';
    final result = await _runGrouped(
      <String>[flutter, 'test', '--no-pub', generated.path],
      workingDirectory: Directory.current.path,
      timeout: const Duration(minutes: 10),
    );
    final out = '${result.stdout}\n${result.stderr}';
    expect(result.exitCode, 0, reason: out);
    for (final name in _expected) {
      expect(out, contains('REAL_OK $name'), reason: 'did not run: $name\n$out');
    }
  }, timeout: const Timeout(Duration(minutes: 12)));
}
