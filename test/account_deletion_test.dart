import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:wins_vpn/account_deletion.dart';
import 'package:wins_vpn/main.dart';

/// Builds a sheet inside a real modal route so `Navigator.pop` behaves exactly
/// as it does in the app, and the popped value can be asserted on.
Future<SheetHarness> pumpDeletionSheet(
  WidgetTester tester, {
  required AccountDeletionState initialState,
  Future<AccountDeletionState?> Function()? onRequest,
  Future<AccountDeletionState?> Function(String requestId)? onConfirm,
  Future<AccountDeletionState?> Function()? onCancel,
  Future<AccountDeletionState?> Function()? onRefresh,
}) async {
  final harness = SheetHarness();
  await tester.pumpWidget(
    MaterialApp(
      home: Scaffold(
        body: Builder(
          builder: (context) => ElevatedButton(
            key: const Key('open_sheet'),
            onPressed: () async {
              harness.result = await showModalBottomSheet<bool>(
                context: context,
                // Matches the app: the policy + warning copy is taller than the
                // default half-screen sheet, so it must be scroll-controlled or
                // the action buttons sit off-screen.
                isScrollControlled: true,
                builder: (_) => AccountDeletionSheet(
                  initialState: initialState,
                  autoRefresh: false,
                  onRequest: onRequest ??
                      () async {
                        harness.requestCalls++;
                        return null;
                      },
                  onConfirm: onConfirm ??
                      (id) async {
                        harness.confirmCalls.add(id);
                        return null;
                      },
                  onCancel: onCancel ??
                      () async {
                        harness.cancelCalls++;
                        return null;
                      },
                  onRefresh: onRefresh ??
                      () async {
                        harness.refreshCalls++;
                        return null;
                      },
                ),
              );
              harness.closed = true;
            },
            child: const Text('open'),
          ),
        ),
      ),
    ),
  );
  await tester.tap(find.byKey(const Key('open_sheet')));
  await tester.pumpAndSettle();
  return harness;
}

/// Records what the sheet asked the hub to do, and what it popped.
class SheetHarness {
  int requestCalls = 0;
  int cancelCalls = 0;
  int refreshCalls = 0;
  List<String> confirmCalls = <String>[];
  bool? result;
  bool closed = false;
}

String textOf(WidgetTester tester, String key) =>
    tester.widget<Text>(find.byKey(Key(key))).data ?? '';

/// The primary action is a Text in terminal states and an ElevatedButton in
/// actionable ones; read its label either way.
String primaryActionLabel(WidgetTester tester) {
  final widget =
      tester.widget(find.byKey(const Key('account_deletion_primary_action')));
  if (widget is Text) return widget.data ?? '';
  if (widget is ElevatedButton && widget.child is Text) {
    return (widget.child as Text).data ?? '';
  }
  return '';
}

/// Scrolls the control into view before tapping. The sheet is a scroll view, so
/// a control can be laid out below the fold on a small test surface.
Future<void> tapKey(WidgetTester tester, String key) async {
  final finder = find.byKey(Key(key));
  await tester.ensureVisible(finder);
  await tester.pumpAndSettle();
  await tester.tap(finder);
  await tester.pumpAndSettle();
}

void main() {
  group('deletion quorum policy', () {
    test('required confirmations derive from the live active-device count', () {
      // Never hardcoded to 2 or 3: an account below the quorum needs unanimity
      // of what it has, an account at or above it never needs unanimity.
      expect(requiredDeletionConfirmations(0), 0);
      expect(requiredDeletionConfirmations(1), 1);
      expect(requiredDeletionConfirmations(2), 2);
      expect(requiredDeletionConfirmations(3), 2);
      expect(requiredDeletionConfirmations(4), 2);
      expect(requiredDeletionConfirmations(10), kAccountDeletionQuorum);
    });

    test('three devices never require all three', () {
      expect(requiredDeletionConfirmations(3), lessThan(3));
    });

    test('only a single-device account uses the waiting period', () {
      expect(deletionUsesWaitingPeriod(0), isFalse);
      expect(deletionUsesWaitingPeriod(1), isTrue);
      expect(deletionUsesWaitingPeriod(2), isFalse);
      expect(deletionUsesWaitingPeriod(3), isFalse);
    });

    test('idle state for zero devices is unavailable, not none', () {
      expect(
          AccountDeletionState.idle(0).stage, AccountDeletionStage.unavailable);
      expect(AccountDeletionState.idle(1).stage, AccountDeletionStage.none);
    });

    test('status payload parses each stage the hub can return', () {
      for (final entry in <String, AccountDeletionStage>{
        'awaiting_confirmations': AccountDeletionStage.awaitingConfirmations,
        'awaiting_delay': AccountDeletionStage.awaitingDelay,
        'completed': AccountDeletionStage.completed,
        'cancelled': AccountDeletionStage.cancelled,
        'unavailable': AccountDeletionStage.unavailable,
      }.entries) {
        final parsed = AccountDeletionState.fromStatusPayload({
          'stage': entry.key,
          'active_device_count': 3,
          'confirmed_device_count': 1,
        });
        expect(parsed.stage, entry.value, reason: entry.key);
      }
    });

    test('an unrecognised or truncated payload degrades safely', () {
      // This transport can be intercepted or truncated by a censor; a garbled
      // body must never read as "deletion in progress".
      final garbled = AccountDeletionState.fromStatusPayload(
          {'stage': 'nonsense', 'active_device_count': 2});
      expect(garbled.stage, AccountDeletionStage.none);
      final empty = AccountDeletionState.fromStatusPayload({});
      expect(empty.stage, AccountDeletionStage.unavailable);
      expect(empty.activeDeviceCount, 0);
    });

    test('remaining confirmations never goes negative', () {
      const state = AccountDeletionState(
        stage: AccountDeletionStage.awaitingConfirmations,
        activeDeviceCount: 3,
        confirmedDeviceCount: 5,
      );
      expect(state.remainingConfirmations, 0);
    });

    test('a device that already confirmed cannot confirm again', () {
      const confirmed = AccountDeletionState(
        stage: AccountDeletionStage.awaitingConfirmations,
        activeDeviceCount: 3,
        confirmedDeviceCount: 1,
        thisDeviceConfirmed: true,
      );
      expect(confirmed.canConfirmOnThisDevice, isFalse,
          reason: 'one device must not be able to supply a whole quorum');
      const fresh = AccountDeletionState(
        stage: AccountDeletionStage.awaitingConfirmations,
        activeDeviceCount: 3,
        confirmedDeviceCount: 1,
        thisDeviceConfirmed: false,
      );
      expect(fresh.canConfirmOnThisDevice, isTrue);
    });

    test('any pending request is cancellable, a settled one is not', () {
      expect(
          const AccountDeletionState(
                  stage: AccountDeletionStage.awaitingConfirmations,
                  activeDeviceCount: 3,
                  confirmedDeviceCount: 1)
              .canCancel,
          isTrue);
      expect(
          const AccountDeletionState(
                  stage: AccountDeletionStage.awaitingDelay,
                  activeDeviceCount: 1,
                  confirmedDeviceCount: 1)
              .canCancel,
          isTrue);
      expect(
          const AccountDeletionState(
                  stage: AccountDeletionStage.completed,
                  activeDeviceCount: 0,
                  confirmedDeviceCount: 2)
              .canCancel,
          isFalse);
    });
  });

  group('policy copy states the applicable rule', () {
    test('three devices: says two of three, and that not all are needed', () {
      final copy = accountDeletionPolicyCopy(3);
      expect(copy, contains('3 active devices'));
      expect(copy, contains('2 different devices'));
      expect(copy, contains('You do not need every device'));
    });

    test('two devices: both must confirm', () {
      final copy = accountDeletionPolicyCopy(2);
      expect(copy, contains('2 active devices'));
      expect(copy, contains('2 different devices'));
    });

    test('one device: states the waiting period and the cancel escape hatch',
        () {
      final copy = accountDeletionPolicyCopy(1);
      expect(copy, contains('1 active device'));
      expect(copy, contains('7 days'));
      expect(copy, contains('cancel'));
    });

    test('zero devices: tells the user how to become able to delete', () {
      final copy = accountDeletionPolicyCopy(0);
      expect(copy, contains('no active devices'));
      expect(copy, contains('Activate a device'));
    });

    test('irreversibility warning names the forfeiture of paid time', () {
      final warning = accountDeletionIrreversibleWarningCopy();
      expect(warning, contains('permanent'));
      expect(warning, contains('remaining paid time'));
      expect(warning, contains('forfeited'));
      expect(warning, contains('not'));
      expect(warning.toLowerCase(), contains('refunded'));
      expect(warning, contains('VPN keys'));
    });
  });

  group('AccountDeletionSheet UI states', () {
    testWidgets('3-device idle shows the two-of-three rule and a delete action',
        (tester) async {
      await pumpDeletionSheet(tester,
          initialState: AccountDeletionState.idle(3));
      expect(textOf(tester, 'account_deletion_policy'),
          contains('2 different devices'));
      expect(textOf(tester, 'account_deletion_status'),
          contains('No deletion is pending'));
      expect(find.byKey(const Key('account_deletion_primary_action')),
          findsOneWidget);
      expect(find.text('Delete Account'), findsWidgets);
      // Nothing pending, so no cancel and no progress bar.
      expect(find.byKey(const Key('account_deletion_cancel')), findsNothing);
      expect(find.byKey(const Key('account_deletion_progress')), findsNothing);
    });

    testWidgets('2-device idle states both devices must confirm',
        (tester) async {
      await pumpDeletionSheet(tester,
          initialState: AccountDeletionState.idle(2));
      final copy = textOf(tester, 'account_deletion_policy');
      expect(copy, contains('2 active devices'));
      expect(copy, contains('2 different devices'));
    });

    testWidgets('1-device idle states the 7-day waiting period',
        (tester) async {
      await pumpDeletionSheet(tester,
          initialState: AccountDeletionState.idle(1));
      final copy = textOf(tester, 'account_deletion_policy');
      expect(copy, contains('1 active device'));
      expect(copy, contains('7 days'));
    });

    testWidgets('0-device account is told deletion is unavailable',
        (tester) async {
      await pumpDeletionSheet(tester,
          initialState: AccountDeletionState.idle(0));
      expect(textOf(tester, 'account_deletion_status'),
          contains('no active devices'));
      expect(primaryActionLabel(tester), 'Deletion Unavailable');
    });

    testWidgets('deletion is never requested from the first tap',
        (tester) async {
      final harness = await pumpDeletionSheet(tester,
          initialState: AccountDeletionState.idle(3));
      await tapKey(tester, 'account_deletion_primary_action');
      // Step 2 of 2 is now on screen and the hub has NOT been called yet.
      expect(harness.requestCalls, 0);
      expect(find.byKey(const Key('account_deletion_warning')), findsOneWidget);
      expect(textOf(tester, 'account_deletion_warning'),
          contains('cannot be undone'));
      expect(find.byKey(const Key('account_deletion_final_confirm')),
          findsOneWidget);
    });

    testWidgets('the second step is what calls the hub', (tester) async {
      final harness = await pumpDeletionSheet(tester,
          initialState: AccountDeletionState.idle(3));
      await tapKey(tester, 'account_deletion_primary_action');
      await tapKey(tester, 'account_deletion_final_confirm');
      expect(harness.requestCalls, 1);
    });

    testWidgets('going back from the warning cancels the attempt',
        (tester) async {
      final harness = await pumpDeletionSheet(tester,
          initialState: AccountDeletionState.idle(3));
      await tapKey(tester, 'account_deletion_primary_action');
      await tapKey(tester, 'account_deletion_back');
      expect(harness.requestCalls, 0);
      expect(find.byKey(const Key('account_deletion_policy')), findsOneWidget);
    });

    testWidgets('partially confirmed shows received vs required and a cancel',
        (tester) async {
      await pumpDeletionSheet(
        tester,
        initialState: const AccountDeletionState(
          stage: AccountDeletionStage.awaitingConfirmations,
          activeDeviceCount: 3,
          confirmedDeviceCount: 1,
          thisDeviceConfirmed: true,
          requestId: 'req-1',
        ),
      );
      expect(textOf(tester, 'account_deletion_progress'),
          'Confirmations received: 1 of 2');
      expect(textOf(tester, 'account_deletion_status'),
          contains('This device has confirmed'));
      expect(find.byKey(const Key('account_deletion_cancel')), findsOneWidget);
      // This device already voted, so its action is inert.
      final button = tester.widget<ElevatedButton>(
          find.byKey(const Key('account_deletion_primary_action')));
      expect(button.onPressed, isNull);
      expect(button.child, isA<Text>());
      expect((button.child as Text).data, 'Waiting For Another Device');
    });

    testWidgets('a second device that has not confirmed can confirm',
        (tester) async {
      final harness = await pumpDeletionSheet(
        tester,
        initialState: const AccountDeletionState(
          stage: AccountDeletionStage.awaitingConfirmations,
          activeDeviceCount: 3,
          confirmedDeviceCount: 1,
          thisDeviceConfirmed: false,
          requestId: 'req-42',
        ),
      );
      final button = tester.widget<ElevatedButton>(
          find.byKey(const Key('account_deletion_primary_action')));
      expect(button.onPressed, isNotNull);
      await tapKey(tester, 'account_deletion_primary_action');
      await tapKey(tester, 'account_deletion_final_confirm');
      // The confirmation is bound to the specific request the device saw.
      expect(harness.confirmCalls, ['req-42']);
    });

    testWidgets('quorum met closes the sheet and reports the deletion',
        (tester) async {
      final harness = await pumpDeletionSheet(
        tester,
        initialState: const AccountDeletionState(
          stage: AccountDeletionStage.awaitingConfirmations,
          activeDeviceCount: 2,
          confirmedDeviceCount: 1,
          thisDeviceConfirmed: false,
          requestId: 'req-9',
        ),
        onConfirm: (id) async => const AccountDeletionState(
          stage: AccountDeletionStage.completed,
          activeDeviceCount: 0,
          confirmedDeviceCount: 2,
        ),
      );
      await tapKey(tester, 'account_deletion_primary_action');
      await tapKey(tester, 'account_deletion_final_confirm');
      // Popping true is the signal the caller uses to wipe local credentials.
      expect(harness.result, isTrue);
      expect(harness.closed, isTrue);
    });

    testWidgets('single-device pending shows the scheduled delay and a cancel',
        (tester) async {
      await pumpDeletionSheet(
        tester,
        initialState: AccountDeletionState(
          stage: AccountDeletionStage.awaitingDelay,
          activeDeviceCount: 1,
          confirmedDeviceCount: 1,
          thisDeviceConfirmed: true,
          scheduledFor: DateTime.utc(2026, 8, 10),
          requestId: 'req-solo',
        ),
      );
      final status = textOf(tester, 'account_deletion_status');
      expect(status, contains('waiting period'));
      expect(status, contains('2026-08-10'));
      expect(status, contains('cancelling stops it'));
      expect(find.byKey(const Key('account_deletion_cancel')), findsOneWidget);
      expect(primaryActionLabel(tester), 'Deletion Scheduled');
    });

    testWidgets(
        'cancelling a pending request calls the hub and shows the result',
        (tester) async {
      final harness = await pumpDeletionSheet(
        tester,
        initialState: const AccountDeletionState(
          stage: AccountDeletionStage.awaitingConfirmations,
          activeDeviceCount: 3,
          confirmedDeviceCount: 1,
          thisDeviceConfirmed: true,
          requestId: 'req-c',
        ),
        onCancel: () async => AccountDeletionState.idle(3).copyWith(
          stage: AccountDeletionStage.cancelled,
        ),
      );
      await tapKey(tester, 'account_deletion_cancel');
      expect(harness.cancelCalls, 0, reason: 'the injected onCancel is used');
      expect(textOf(tester, 'account_deletion_status'), contains('cancelled'));
      expect(textOf(tester, 'account_deletion_status'),
          contains('No data was erased'));
      // Cancelled is a restartable state, not a dead end.
      expect(primaryActionLabel(tester), 'Delete Account');
      expect(harness.result, isNull, reason: 'cancelling must not pop true');
    });

    testWidgets('cancelled state offers a fresh delete, not a stuck screen',
        (tester) async {
      await pumpDeletionSheet(
        tester,
        initialState: const AccountDeletionState(
          stage: AccountDeletionStage.cancelled,
          activeDeviceCount: 3,
          confirmedDeviceCount: 0,
        ),
      );
      expect(textOf(tester, 'account_deletion_status'),
          contains('No data was erased'));
      final button = tester.widget<ElevatedButton>(
          find.byKey(const Key('account_deletion_primary_action')));
      expect(button.onPressed, isNotNull);
    });

    testWidgets('completed state reports the account is gone', (tester) async {
      await pumpDeletionSheet(
        tester,
        initialState: const AccountDeletionState(
          stage: AccountDeletionStage.completed,
          activeDeviceCount: 0,
          confirmedDeviceCount: 2,
        ),
      );
      expect(textOf(tester, 'account_deletion_status'),
          contains('has been deleted'));
      expect(primaryActionLabel(tester), 'Account Deleted');
    });

    testWidgets('an unreachable hub reports an unknown deletion state',
        (tester) async {
      final harness = await pumpDeletionSheet(
        tester,
        initialState: AccountDeletionState.idle(3),
        onRequest: () async => null,
      );
      await tapKey(tester, 'account_deletion_primary_action');
      await tapKey(tester, 'account_deletion_final_confirm');
      expect(textOf(tester, 'account_deletion_error'),
          contains('deletion state is unknown'));
      expect(harness.result, isNull);
      // Still on the overview, still able to retry.
      expect(find.byKey(const Key('account_deletion_policy')), findsOneWidget);
    });

    testWidgets('a thrown request restores deletion sheet actions',
        (tester) async {
      final harness = await pumpDeletionSheet(
        tester,
        initialState: AccountDeletionState.idle(3),
        onRequest: () async => throw StateError('transport failure'),
      );
      await tapKey(tester, 'account_deletion_primary_action');
      await tapKey(tester, 'account_deletion_final_confirm');
      expect(textOf(tester, 'account_deletion_error'),
          contains('deletion state is unknown'));
      expect(tester.widget<ElevatedButton>(
        find.byKey(const Key('account_deletion_primary_action')),
      ).onPressed, isNotNull);
      await tapKey(tester, 'account_deletion_close');
      expect(harness.result, isFalse);
    });

    testWidgets('refresh re-reads status while a request is pending',
        (tester) async {
      var polled = 0;
      await pumpDeletionSheet(
        tester,
        initialState: const AccountDeletionState(
          stage: AccountDeletionStage.awaitingConfirmations,
          activeDeviceCount: 3,
          confirmedDeviceCount: 1,
          thisDeviceConfirmed: true,
          requestId: 'req-r',
        ),
        onRefresh: () async {
          polled++;
          return const AccountDeletionState(
            stage: AccountDeletionStage.awaitingConfirmations,
            activeDeviceCount: 3,
            confirmedDeviceCount: 2,
            thisDeviceConfirmed: true,
            requestId: 'req-r',
          );
        },
      );
      await tapKey(tester, 'account_deletion_refresh');
      expect(polled, 1);
      expect(textOf(tester, 'account_deletion_progress'),
          'Confirmations received: 2 of 2');
    });

    testWidgets('closing the sheet without acting reports no deletion',
        (tester) async {
      final harness = await pumpDeletionSheet(tester,
          initialState: AccountDeletionState.idle(3));
      await tapKey(tester, 'account_deletion_close');
      expect(harness.result, isFalse);
    });
  });

  group('the sheet answers only its own route (N-9)', () {
    // The confirm that completes the deletion awaits the hub, then hands true
    // back to the caller, which wipes local credentials. That answer must end
    // THIS sheet's route only. A bare pop ends whatever is on top when the
    // hub answers: a bool consent dialog presented over (or after) the sheet
    // was answered true, consent that nobody gave.
    for (final dismissed in <bool>[false, true]) {
      testWidgets(
          'a confirm that completes after the sheet was '
          '${dismissed ? 'dismissed' : 'covered'} never answers the newer '
          'bool dialog', (tester) async {
        final hub = Completer<AccountDeletionState?>();
        var confirms = 0;
        final sheetResult = <bool?>[];
        late BuildContext page;
        await tester.pumpWidget(MaterialApp(
          home: Scaffold(
            body: Builder(builder: (context) {
              page = context;
              return const SizedBox();
            }),
          ),
        ));
        unawaited(showModalBottomSheet<bool>(
          context: page,
          isScrollControlled: true,
          builder: (_) => AccountDeletionSheet(
            initialState: const AccountDeletionState(
              stage: AccountDeletionStage.awaitingConfirmations,
              activeDeviceCount: 2,
              confirmedDeviceCount: 1,
              thisDeviceConfirmed: false,
              requestId: 'req-9',
            ),
            autoRefresh: false,
            onRequest: () async => null,
            onConfirm: (id) {
              confirms++;
              return hub.future;
            },
            onCancel: () async => null,
            onRefresh: () async => null,
          ),
        ).then(sheetResult.add));
        await tester.pumpAndSettle();
        for (final key in const <String>[
          'account_deletion_primary_action',
          'account_deletion_final_confirm',
        ]) {
          final finder = find.byKey(Key(key));
          await tester.ensureVisible(finder);
          await tester.pumpAndSettle();
          await tester.tap(finder);
          await tester.pump();
        }
        expect(confirms, 1,
            reason: 'precondition: the confirm is held at the hub');
        if (dismissed) {
          // The barrier tap dismisses the sheet while the request is out; the
          // newer dialog arrives while the sheet is still animating out.
          await tester.tapAt(const Offset(400, 20));
          await tester.pump(const Duration(milliseconds: 20));
          expect(sheetResult, <bool?>[null],
              reason: 'precondition: the barrier tap dismissed the sheet');
        }
        bool? consent;
        var consentDone = false;
        unawaited(showDialog<bool>(
          context: page,
          builder: (dialogContext) => AlertDialog(
            title: const Text('CONSENT'),
            actions: <Widget>[
              TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(false),
                  child: const Text('Decline')),
              TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(true),
                  child: const Text('Agree')),
            ],
          ),
        ).then((v) {
          consent = v;
          consentDone = true;
        }));
        await tester.pump(const Duration(milliseconds: 20));
        expect(find.text('CONSENT'), findsOneWidget);
        hub.complete(const AccountDeletionState(
          stage: AccountDeletionStage.completed,
          activeDeviceCount: 0,
          confirmedDeviceCount: 2,
        ));
        await tester.idle();
        await tester.pump(const Duration(milliseconds: 20));
        expect(tester.takeException(), isNull);
        expect(consentDone, isFalse,
            reason: 'the sheet answered the newer bool dialog (true = Agree)');
        expect(find.text('CONSENT'), findsOneWidget,
            reason: 'the newer dialog was ended by the sheet');
        if (dismissed) {
          expect(sheetResult, <bool?>[null]);
        } else {
          // Covered: the sheet is removed alone, with its own answer, so the
          // caller still wipes the credentials of the account that is gone.
          expect(sheetResult, <bool?>[true]);
        }
        // The newer dialog still answers for itself, once.
        await tester.pump(const Duration(milliseconds: 400));
        await tester.tap(find.text('Decline'));
        await tester.pumpAndSettle();
        expect(consentDone, isTrue);
        expect(consent, isFalse);
        expect(tester.takeException(), isNull);
      });
    }
  });

  group('in-app discoverability and transport contract', () {
    // Apple Guideline 5.1.1(v) requires the deletion flow to be initiable from
    // inside the app. These guard the wiring that a widget test of the full
    // dashboard cannot reach without a live hub.
    final source = File('lib/main.dart').readAsStringSync();

    test('the account screen carries a Delete Account entry point', () {
      expect(source, contains("Key('account_deletion_entry')"));
      expect(source, contains('"Delete Account"'));
      expect(source, contains('unawaited(_openAccountDeletionSheet())'));
    });

    test('the entry point is hidden for the shared free-access identity', () {
      final start = source.indexOf("Key('account_deletion_entry')");
      expect(start, greaterThanOrEqualTo(0));
      // The guard must sit immediately before the tile, not somewhere vague.
      final preceding = source.substring(start - 400, start);
      expect(preceding, contains('if (!_isFreeAccessSession)'));
    });

    test('every deletion call is authenticated with this device\'s own token',
        () {
      final start =
          source.indexOf('Future<AccountDeletionState?> _postAccountDeletion(');
      final end = source.indexOf(
          'Future<AccountDeletionState?> _fetchAccountDeletionStatus()', start);
      expect(start, greaterThanOrEqualTo(0));
      expect(end, greaterThan(start));
      final body = source.substring(start, end);
      expect(body, contains("headers['Authorization'] = 'Bearer \$token';"));
      // A missing token must degrade, never send an unauthenticated call.
      expect(body, contains('if (token.isEmpty)'));
      expect(body, contains('return null;'));
      // The raw token is only ever interpolated into the Authorization header.
      expect('\$token'.allMatches(body).length, 1);
    });

    test('all four hub routes are reachable through gateway failover', () {
      for (final fn in [
        'accountDeletionRequestGateways',
        'accountDeletionConfirmGateways',
        'accountDeletionCancelGateways',
        'accountDeletionStatusGateways',
      ]) {
        expect(source, contains(fn), reason: fn);
      }
    });

    test('a completed deletion wipes local credentials for the dead account',
        () {
      final start =
          source.indexOf('Future<bool> _clearLocalStateAfterAccountDeletion()');
      expect(start, greaterThanOrEqualTo(0));
      final end =
          source.indexOf('Future<void> _openAccountDeletionSheet()', start);
      final body = source.substring(start, end);
      expect(body, contains('_beginAccountTeardown()'));
      expect(body, contains('_writeAccountCleanupJournal(journal, epoch)'));
      expect(body, contains('_stopAndProveTunnelInactive()'));
      expect(body, contains('_runAccountCleanup(journal, epoch)'));
      expect(body, contains('_resetAccountUiAfterVerifiedCleanup()'));
      expect(body, contains('return false;'));
      expect(body, contains('return true;'));

      final cleanupStart =
          source.indexOf('Future<bool> _deleteCleanupArtifact(');
      final cleanupEnd = source.indexOf(
          'Future<bool> _clearOrdinaryCamouflageLatchVerified()', cleanupStart);
      final cleanupBody = source.substring(cleanupStart, cleanupEnd);
      for (final wiped in [
        "_deleteSensitiveArtifactVerified('user_pin.txt')",
        '_deletePendingLogoutForScope(scopeToken)',
        "_deleteSensitiveArtifactVerified('vpn_settings.txt')",
        '_deleteClientKeyPairForScopeTokenUnlocked(scopeToken)',
      ]) {
        expect(cleanupBody, contains(wiped), reason: wiped);
      }
    });

    test('an already completed deletion cleans up before opening the sheet',
        () {
      final start = source.indexOf('Future<void> _openAccountDeletionSheet()');
      final end = source.indexOf('Future<String> _loadOrCreateInstallId()', start);
      expect(start, greaterThanOrEqualTo(0));
      expect(end, greaterThan(start));
      final body = source.substring(start, end);
      final completed = body.indexOf(
          'if (initial.stage == AccountDeletionStage.completed)');
      final cleanup = body.indexOf(
          'await _clearLocalStateAfterAccountDeletion()', completed);
      final sheet = body.indexOf('showModalBottomSheet<bool>');
      expect(completed, greaterThanOrEqualTo(0));
      expect(cleanup, greaterThan(completed));
      expect(sheet, greaterThan(cleanup));
    });
  });
}
