import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/account_session_lifecycle.dart';

String _methodBody(String source, String signature, String nextSignature) {
  final start = source.indexOf(signature);
  final end = source.indexOf(nextSignature, start);
  expect(start, greaterThanOrEqualTo(0), reason: signature);
  expect(end, greaterThan(start), reason: nextSignature);
  return source.substring(start, end);
}

void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('crash restart with a stop-failure journal blocks onboarding', () {
    final startup = _methodBody(
      source,
      'Future<void> _initializePrivacyConsentGate() async {',
      'Future<void> _armCamouflageBeforeConsent() async {',
    );
    expect(startup, contains('AccountCleanupResumeOutcome.pending'));
    expect(startup, contains('_accountCleanupStartupBlocked = true'));
    expect(
      startup.indexOf('AccountCleanupResumeOutcome.pending'),
      lessThan(startup.indexOf('_readVpnRuntimeSettings()')),
    );
  });

  test('crash restart with artifact residue blocks and schedules a retry', () {
    final resume = _methodBody(
      source,
      'Future<AccountCleanupResumeOutcome> _resumePendingAccountCleanup()',
      'Future<void> _deactivateCurrentDevice() async {',
    );
    expect(resume, contains('_accountCleanupStartupBarrier.resume()'));
    expect(source, contains('onPending: _forcePendingAccountCleanupUi'));
    expect(source, contains('onRetryCompleted:'));
  });

  test('completed restart cleanup is distinguished so onboarding proceeds', () {
    final startup = _methodBody(
      source,
      'Future<void> _initializePrivacyConsentGate() async {',
      'Future<void> _armCamouflageBeforeConsent() async {',
    );
    expect(startup, contains('final cleanupOutcome ='));
    final lifecycleSource =
        File('lib/account_session_lifecycle.dart').readAsStringSync();
    expect(
      lifecycleSource,
      contains('AccountCleanupResumeOutcome { none, completed, pending }'),
    );
    expect(
      startup.indexOf('final cleanupOutcome ='),
      lessThan(startup.indexOf('_readVpnRuntimeSettings()')),
    );
  });

  test('activation is refused while an ordinary cleanup journal is open', () {
    final activation = _methodBody(
      source,
      'Future<int?> _beginAccountActivation() async {',
      'int _beginAccountTeardown() {',
    );
    expect(activation,
        contains('_accountCleanupStartupBarrier.activationAllowed'));
    expect(activation, contains('return null'));
    expect(activation.indexOf('activationAllowed'),
        lessThan(activation.indexOf('_settingsWritesSealed = false')));
  });

  test('stop-failure journal remains a fail-closed restart barrier', () async {
    var journalPresent = true;
    var cleanupAttempts = 0;
    var pendingUi = false;
    final barrier = AccountCleanupStartupBarrier(
      journalExists: () async => journalPresent,
      attemptCleanup: () async {
        cleanupAttempts += 1;
        // Native stop proof failed. The durable journal survives unchanged.
      },
      onPending: () => pendingUi = true,
      onCompleted: () {},
      onRetryCompleted: () {},
      retryDelay: const Duration(days: 1),
    );
    addTearDown(barrier.dispose);

    final outcome = await barrier.resume();

    expect(outcome, AccountCleanupResumeOutcome.pending);
    expect(journalPresent, isTrue);
    expect(cleanupAttempts, 1);
    expect(pendingUi, isTrue);
  });

  test('artifact-residue restart barrier retries on the real event loop',
      () async {
    var journalPresent = true;
    var cleanupAttempts = 0;
    var pendingUi = false;
    final retryCompleted = Completer<void>();
    final barrier = AccountCleanupStartupBarrier(
      journalExists: () async => journalPresent,
      attemptCleanup: () async {
        cleanupAttempts += 1;
        if (cleanupAttempts == 2) journalPresent = false;
      },
      onPending: () => pendingUi = true,
      onCompleted: () => pendingUi = false,
      onRetryCompleted: retryCompleted.complete,
      retryDelay: const Duration(milliseconds: 5),
    );
    addTearDown(barrier.dispose);

    final firstOutcome = await barrier.resume();
    expect(firstOutcome, AccountCleanupResumeOutcome.pending);
    expect(pendingUi, isTrue);

    await retryCompleted.future.timeout(const Duration(milliseconds: 500));
    expect(cleanupAttempts, 2);
    expect(journalPresent, isFalse);
    expect(pendingUi, isFalse);
  });

  test('restart cleanup completion permits onboarding', () async {
    var journalPresent = true;
    var completionCount = 0;
    final barrier = AccountCleanupStartupBarrier(
      journalExists: () async => journalPresent,
      attemptCleanup: () async => journalPresent = false,
      onPending: () {},
      onCompleted: () => completionCount += 1,
      onRetryCompleted: () {},
    );
    addTearDown(barrier.dispose);

    final outcome = await barrier.resume();

    expect(outcome, AccountCleanupResumeOutcome.completed);
    expect(completionCount, 1);
    expect(outcome != AccountCleanupResumeOutcome.pending, isTrue);
  });

  test('open journal refuses activation without advancing the account epoch',
      () async {
    var journalPresent = true;
    final epoch = AccountSessionEpoch();
    final barrier = AccountCleanupStartupBarrier(
      journalExists: () async => journalPresent,
      attemptCleanup: () async {},
      onPending: () {},
      onCompleted: () {},
      onRetryCompleted: () {},
      retryDelay: const Duration(days: 1),
    );
    addTearDown(barrier.dispose);

    if (await barrier.activationAllowed()) epoch.bump();
    expect(epoch.current, 0);

    journalPresent = false;
    if (await barrier.activationAllowed()) epoch.bump();
    expect(epoch.current, 1);
  });
}
