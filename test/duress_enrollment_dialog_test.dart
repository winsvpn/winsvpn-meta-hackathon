// The REAL duress enrollment dialog (lib/duress_enrollment_dialog.dart, the
// body main.dart's _showDuressEnrollmentDialog calls), pumped on a real widget
// tree with the platform work faked. Rule: a flow whose dialog a relock
// removed never commits. Each await inside the dialog's submit (the
// credential read, the SMS permission, the enrollment itself) is held, the
// app relocks through the production relock clear and the route guard, the
// await completes, and nothing may be written and no dialog state touched
// (setState on the removed dialog would throw, and the test would fail).
import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/decoy_cover.dart';
import 'package:wins_vpn/duress_enrollment_dialog.dart';

const _realPin = '482915';
const _duressPin = '739264';

class _Fakes {
  bool decoy = false;
  Completer<bool>? verify;
  Completer<bool>? sms;
  Completer<void>? enrollGate;
  // Held after the write, as the real commit's read-backs are awaited.
  Completer<void>? readbackGate;
  Object? enrollError;
  final List<String> enrolled = <String>[];
  int verifies = 0;
  int smsRequests = 0;
  bool Function()? handedStillAway;
  int enrollCalls = 0;

  DuressEnrollmentHooks hooks() => DuressEnrollmentHooks(
        translate: (s) => s,
        verifyRealPin: (pin) {
          verifies++;
          return verify?.future ?? Future<bool>.value(pin == _realPin);
        },
        requestSmsPermission: () {
          smsRequests++;
          return sms?.future ?? Future<bool>.value(true);
        },
        // Models main.dart _enrollDuress: after its await it checks the
        // stillAway it was handed and writes nothing on a relock (the real
        // commit is executed in duress_enroll_commit_test).
        enroll: ({
          required String realPin,
          required String duressPin,
          String? trustedPhone,
          String? trustedEmail,
          bool Function()? stillAway,
        }) async {
          enrollCalls++;
          handedStillAway = stillAway;
          if (enrollGate != null) await enrollGate!.future;
          if (enrollError != null) throw enrollError!;
          if (stillAway != null && !stillAway()) return false;
          enrolled.add('$duressPin phone=$trustedPhone');
          if (readbackGate != null) await readbackGate!.future;
          return true;
        },
        isPhoneShapedContact: (c) => c.replaceAll(RegExp(r'\D'), '').length >= 7,
        debugLog: (_) {},
        stillAway: () => !decoy,
      );
}

class _Page extends StatelessWidget {
  const _Page();
  @override
  Widget build(BuildContext context) =>
      const Scaffold(body: Center(child: Text('home')));
}

class _Harness {
  _Harness(this.tester, this.fakes);
  final WidgetTester tester;
  final _Fakes fakes;
  late DecoyRouteGuard guard;
  late BuildContext page;
  Future<String?>? outcome;
  Object? outcomeValue = 'pending';

  Future<void> pump() async {
    guard = DecoyRouteGuard(decoyShowing: () => fakes.decoy);
    await tester.pumpWidget(MaterialApp(
      navigatorObservers: <NavigatorObserver>[guard],
      home: const _Page(),
    ));
    page = tester.element(find.byType(_Page));
  }

  Future<void> open({required bool canOfferSms, String? knownRealPin}) async {
    outcome = showDuressEnrollmentDialog(page,
        knownRealPin: knownRealPin,
        canOfferSms: canOfferSms,
        hooks: fakes.hooks());
    outcome!.then((v) => outcomeValue = v);
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsOneWidget);
  }

  Future<void> fill(List<String> values) async {
    final fields = find.byType(TextField);
    expect(fields, findsNWidgets(values.length));
    for (var i = 0; i < values.length; i++) {
      await tester.enterText(fields.at(i), values[i]);
    }
    await tester.pump();
  }

  // The production relock: clear the surfaces, then the decoy is up.
  Future<void> relock() async {
    clearProductSurfacesForDecoy(page, guard: guard);
    fakes.decoy = true;
    await tester.pump();
    expect(find.byType(AlertDialog), findsNothing,
        reason: 'the relock must remove the dialog');
  }

  Future<void> settle() async {
    for (var i = 0; i < 5; i++) {
      await tester.pump(const Duration(milliseconds: 50));
    }
  }
}

void main() {
  testWidgets('control: an unlocked wipe-only enrollment commits once',
      (tester) async {
    final fakes = _Fakes();
    final h = _Harness(tester, fakes);
    await h.pump();
    await h.open(canOfferSms: false);
    await h.fill(const <String>[_realPin, _duressPin, _duressPin]);
    await tester.tap(find.text('Save'));
    await tester.pumpAndSettle();
    expect(fakes.enrolled, <String>['$_duressPin phone=null']);
    expect(h.outcomeValue, 'wipe');
    expect(tester.takeException(), isNull);
  });

  testWidgets('control: an unlocked text-alert enrollment stores the contact',
      (tester) async {
    final fakes = _Fakes();
    final h = _Harness(tester, fakes);
    await h.pump();
    await h.open(canOfferSms: true, knownRealPin: _realPin);
    await h.fill(const <String>['+1 555 010 2030', '', _duressPin, _duressPin]);
    await tester.tap(find.text('Allow text alert'));
    await tester.pumpAndSettle();
    expect(fakes.enrolled, <String>['$_duressPin phone=+1 555 010 2030']);
    expect(h.outcomeValue, 'sms');
  });

  for (final verified in <bool>[true, false]) {
    testWidgets(
        'relock during the credential read (verified=$verified): no commit, '
        'no dialog state', (tester) async {
      final fakes = _Fakes()..verify = Completer<bool>();
      final h = _Harness(tester, fakes);
      await h.pump();
      await h.open(canOfferSms: false);
      await h.fill(const <String>[_realPin, _duressPin, _duressPin]);
      await tester.tap(find.text('Save'));
      await tester.pump();
      expect(fakes.verifies, 1);
      await h.relock();
      fakes.verify!.complete(verified);
      await h.settle();
      expect(fakes.enrolled, isEmpty, reason: 'committed behind the calculator');
      expect(tester.takeException(), isNull,
          reason: 'dialog state was touched after the relock');
      expect(h.outcomeValue, isNull);
    });
  }

  testWidgets('relock during the SMS permission: no credential, no contact',
      (tester) async {
    final fakes = _Fakes()..sms = Completer<bool>();
    final h = _Harness(tester, fakes);
    await h.pump();
    await h.open(canOfferSms: true, knownRealPin: _realPin);
    await h.fill(const <String>['+1 555 010 2030', 'a@b.example', _duressPin, _duressPin]);
    await tester.tap(find.text('Allow text alert'));
    await tester.pump();
    expect(fakes.smsRequests, 1);
    await h.relock();
    fakes.sms!.complete(true);
    await h.settle();
    expect(fakes.enrolled, isEmpty, reason: 'committed behind the calculator');
    // The dialog stops at its own check: the commit is not even started (no
    // credential encoding behind the calculator), the commit's own check
    // being the second line.
    expect(fakes.enrollCalls, 0, reason: 'the commit was started after the relock');
    expect(tester.takeException(), isNull);
    expect(h.outcomeValue, isNull);
  });

  testWidgets('relock during a failing enrollment: no dialog state',
      (tester) async {
    final fakes = _Fakes()
      ..enrollGate = Completer<void>()
      ..enrollError = StateError('storage');
    final h = _Harness(tester, fakes);
    await h.pump();
    await h.open(canOfferSms: false, knownRealPin: _realPin);
    await h.fill(const <String>[_duressPin, _duressPin]);
    await tester.tap(find.text('Save'));
    await tester.pump();
    await h.relock();
    fakes.enrollGate!.complete();
    await h.settle();
    expect(tester.takeException(), isNull,
        reason: 'the failure path touched a removed dialog');
    expect(h.outcomeValue, isNull);
  });

  testWidgets(
      'relock while the enrollment is in flight: zero writes, and the removed '
      'dialog pops nothing, before or after the next frame', (tester) async {
    // The commit gets the dialog's stillAway and writes nothing after a
    // relock. And the removed dialog's pop must not land on the route below
    // it: between the route removal and the next frame the dialog's context
    // is still mounted.
    final fakes = _Fakes()..enrollGate = Completer<void>();
    final h = _Harness(tester, fakes);
    await h.pump();
    await h.open(canOfferSms: false, knownRealPin: _realPin);
    await h.fill(const <String>[_duressPin, _duressPin]);
    await tester.tap(find.text('Save'));
    await tester.pump();
    // Relock with no frame in between, then let the write finish.
    clearProductSurfacesForDecoy(h.page, guard: h.guard);
    fakes.decoy = true;
    fakes.enrollGate!.complete();
    await tester.idle();
    await tester.pump();
    expect(fakes.handedStillAway, isNotNull,
        reason: 'the dialog did not hand its relock check to the commit');
    expect(fakes.handedStillAway!(), isFalse);
    expect(fakes.enrolled, isEmpty, reason: 'committed behind the calculator');
    expect(find.text('home'), findsOneWidget,
        reason: 'the removed dialog popped the page below it');
    expect(h.guard.routes.length, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
      'relock after the write, during its read-back: the removed dialog pops '
      'nothing', (tester) async {
    // The write happened while unlocked; the relock lands while the commit
    // reads it back. The commit then reports enrolled, and between the route
    // removal and the next frame the dialog's context is still mounted, so
    // only the stillAway check before the pop keeps it off the page below.
    final fakes = _Fakes()..readbackGate = Completer<void>();
    final h = _Harness(tester, fakes);
    await h.pump();
    await h.open(canOfferSms: false, knownRealPin: _realPin);
    await h.fill(const <String>[_duressPin, _duressPin]);
    await tester.tap(find.text('Save'));
    await tester.pump();
    expect(fakes.enrolled.length, 1, reason: 'precondition: written while unlocked');
    clearProductSurfacesForDecoy(h.page, guard: h.guard);
    fakes.decoy = true;
    fakes.readbackGate!.complete();
    await tester.idle();
    await tester.pump();
    expect(find.text('home'), findsOneWidget,
        reason: 'the removed dialog popped the page below it');
    expect(h.guard.routes.length, 1);
    expect(tester.takeException(), isNull);
  });

  // N-9 (a): the Save awaits the enrollment, then answers with the outcome.
  // The answer must end THIS dialog's route only. A bare pop ends whatever
  // route is on top when the write completes: a newer bool dialog (the legal
  // or disclosure consent) got a String and the navigator threw inside its
  // own flush.
  for (final dismissed in <bool>[false, true]) {
    testWidgets(
        'a Save whose write ends after the dialog was '
        '${dismissed ? 'dismissed' : 'covered'} never answers the newer bool '
        'dialog', (tester) async {
      final fakes = _Fakes()..enrollGate = Completer<void>();
      final h = _Harness(tester, fakes);
      await h.pump();
      await h.open(canOfferSms: false, knownRealPin: _realPin);
      await h.fill(const <String>[_duressPin, _duressPin]);
      await tester.tap(find.text('Save'));
      await tester.pump();
      expect(fakes.enrollCalls, 1, reason: 'precondition: the write is held');
      if (dismissed) {
        // The barrier tap dismisses the duress dialog during the write; the
        // newer dialog arrives while the old one is still animating out.
        await tester.tapAt(const Offset(4, 4));
        await tester.pump(const Duration(milliseconds: 20));
        expect(h.outcomeValue, isNull,
            reason: 'precondition: the barrier tap dismissed the dialog');
      }
      bool? consent;
      var consentDone = false;
      showDialog<bool>(
        context: h.page,
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
      });
      await tester.pump(const Duration(milliseconds: 20));
      expect(find.text('CONSENT'), findsOneWidget);
      fakes.enrollGate!.complete();
      await tester.idle();
      await tester.pump(const Duration(milliseconds: 20));
      expect(tester.takeException(), isNull,
          reason: 'the Save answered the newer dialog with its String');
      expect(consentDone, isFalse,
          reason: 'the Save answered the newer bool dialog');
      expect(find.text('CONSENT'), findsOneWidget,
          reason: 'the newer dialog was ended by the Save');
      expect(fakes.enrolled, <String>['$_duressPin phone=null']);
      if (dismissed) {
        expect(h.outcomeValue, isNull);
      } else {
        // Covered: the duress dialog is removed alone, with its own outcome.
        await tester.pump(const Duration(milliseconds: 400));
        expect(h.outcomeValue, 'wipe');
        expect(find.byType(AlertDialog), findsOneWidget);
      }
      // The newer dialog still answers for itself, once.
      await tester.pump(const Duration(milliseconds: 400));
      await tester.tap(find.text('Decline'));
      await tester.pumpAndSettle();
      expect(consentDone, isTrue);
      expect(consent, isFalse);
      expect(find.byType(AlertDialog), findsNothing);
      expect(tester.takeException(), isNull);
    });
  }

  test('the dialog keeps the dashboard surface colours', () {
    final main = File('lib/main.dart').readAsStringSync();
    final dialog = File('lib/duress_enrollment_dialog.dart').readAsStringSync();
    for (final pair in const <List<String>>[
      <String>['_flagRed', '_duressError'],
      <String>['_surfaceText', '_duressText'],
      <String>['_surfacePanel', '_duressPanel'],
    ]) {
      final m = RegExp('static const Color ${pair[0]} = (Color\\(0x[0-9A-F]+\\));')
          .firstMatch(main);
      final d = RegExp('const Color ${pair[1]} = (Color\\(0x[0-9A-F]+\\));')
          .firstMatch(dialog);
      expect(m?.group(1), isNotNull, reason: pair[0]);
      expect(d?.group(1), m?.group(1), reason: pair.join(' vs '));
    }
  });

  test('main.dart binds the dialog to its decoy generation', () {
    final main = File('lib/main.dart').readAsStringSync();
    final start = main.indexOf('  Future<void> _showDuressEnrollmentDialog(');
    expect(start, greaterThan(0));
    final body = main.substring(start, main.indexOf('\n  }\n', start));
    expect(body, contains('final decoyGeneration = _decoyGeneration;'));
    expect(body, contains('stillAway: () => _decoyStillAway(decoyGeneration),'));
    expect(body, contains('enroll: _enrollDuress,'));
  });
}
