// lib/decoy_prompt_gate.dart on a real widget tree, with the real
// DecoyRouteGuard and the real showDialog: a consent dialog that a flow raises
// while the decoy calculator covers the app is not drawn, one the relock
// removes is not read as a refusal, and either way the question is kept, once,
// for the next unlock. The host relocks exactly as main.dart's
// didChangeAppLifecycleState does (clear the surfaces, then set the decoy) and
// registers the guard the way MyApp registers decoyRouteGuard.
//
// decoy_prompt_deferral_test.dart runs the six production dialogs' own
// functions around this gate; this file pins the gate itself against the
// engine that removes the routes.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/decoy_cover.dart';
import 'package:wins_vpn/decoy_prompt_gate.dart';

const _legalTitle = 'Privacy Policy and Legal Acceptance Required';
const _disclosureTitle = 'Android VPN disclosure';

class _Host extends StatefulWidget {
  const _Host({required this.guard});
  final DecoyRouteGuard guard;
  @override
  State<_Host> createState() => _HostState();
}

class _HostState extends State<_Host> with WidgetsBindingObserver {
  bool decoy = false;
  bool mounted_ = true;
  int epoch = 1;
  int generation = 0;
  int presented = 0;
  final DeferredPrompt deferral = DeferredPrompt();
  late BuildContext pageContext;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.inactive) return;
    generation++;
    clearProductSurfacesForDecoy(context, guard: widget.guard);
    setState(() => decoy = true);
  }

  void unlock() => setState(() => decoy = false);

  Future<bool> ask(String title) => runGatedConsentPrompt(
        deferral: deferral,
        mounted: () => mounted_ && mounted,
        decoyShowing: () => decoy,
        accountEpoch: () => epoch,
        present: () {
          presented++;
          return showDialog<bool>(
            context: pageContext,
            barrierDismissible: false,
            builder: (dialogContext) => AlertDialog(
              title: Text(title),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(false),
                  child: const Text('Cancel'),
                ),
                ElevatedButton(
                  onPressed: () => Navigator.of(dialogContext).pop(true),
                  child: const Text('Agree'),
                ),
              ],
            ),
          );
        },
      );

  @override
  Widget build(BuildContext context) {
    pageContext = context;
    return Scaffold(
        body: Center(child: Text(decoy ? '7 8 9 = 0' : "Win's VPN")));
  }
}

Future<_HostState> _pump(WidgetTester tester) async {
  late _HostState host;
  final guard = DecoyRouteGuard(decoyShowing: () => host.decoy);
  await tester.pumpWidget(MaterialApp(
    navigatorObservers: <NavigatorObserver>[guard],
    home: _Host(guard: guard),
  ));
  host = tester.state<_HostState>(find.byType(_Host));
  return host;
}

Future<void> _relock(WidgetTester tester) async {
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
  await tester.pump();
}

void _expectNoDialog() {
  expect(find.byType(AlertDialog, skipOffstage: false), findsNothing);
  expect(find.byType(Dialog, skipOffstage: false), findsNothing);
  expect(find.text(_legalTitle, skipOffstage: false), findsNothing);
  expect(find.text(_disclosureTitle, skipOffstage: false), findsNothing);
}

void main() {
  tearDown(() {
    TestWidgetsFlutterBinding.instance
        .handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });

  group('DeferredPrompt', () {
    test('a record is consumed once', () {
      final p = DeferredPrompt();
      expect(p.isPending, isFalse);
      p.defer(accountEpoch: 3);
      p.defer(accountEpoch: 3);
      expect(p.isPending, isTrue);
      expect(p.take(accountEpoch: 3), isTrue);
      expect(p.isPending, isFalse);
      expect(p.take(accountEpoch: 3), isFalse);
    });

    test('a record from another account session is dropped, not carried', () {
      final p = DeferredPrompt();
      p.defer(accountEpoch: 3);
      expect(p.take(accountEpoch: 4), isFalse);
      expect(p.isPending, isFalse);
      expect(p.take(accountEpoch: 3), isFalse);
    });

    test('answered drops the record for its epoch and counts, and only then', () {
      final p = DeferredPrompt();
      p.defer(accountEpoch: 2);
      p.answered(accountEpoch: 2);
      expect(p.isPending, isFalse);
      expect(p.answerCount, 1);
      p.answered(accountEpoch: 2);
      expect(p.answerCount, 2);
    });

    test('nothing pending takes false', () {
      final p = DeferredPrompt();
      expect(p.take(accountEpoch: 1), isFalse);
      expect(p.isPendingFor(1), isFalse);
    });

    test('isPendingFor looks without consuming, and only for its epoch', () {
      final p = DeferredPrompt();
      p.defer(accountEpoch: 5);
      expect(p.isPendingFor(6), isFalse);
      expect(p.isPendingFor(5), isTrue);
      expect(p.isPendingFor(5), isTrue, reason: 'looking must not consume');
      expect(p.take(accountEpoch: 5), isTrue);
      expect(p.isPendingFor(5), isFalse);
    });
  });

  group('runGatedConsentPrompt on a real tree', () {
    testWidgets('control: unlocked, the user agrees', (tester) async {
      final host = await _pump(tester);
      final answer = host.ask(_legalTitle);
      await tester.pump();
      expect(find.text(_legalTitle), findsOneWidget);
      await tester.tap(find.text('Agree'));
      await tester.pump();
      expect(await answer, isTrue);
      expect(host.deferral.isPending, isFalse);
      _expectNoDialog();
    });

    testWidgets('the user refuses: false, nothing kept', (tester) async {
      final host = await _pump(tester);
      final answer = host.ask(_legalTitle);
      await tester.pump();
      await tester.tap(find.text('Cancel'));
      await tester.pump();
      expect(await answer, isFalse);
      expect(host.deferral.isPending, isFalse);
    });

    testWidgets('the system back gesture while unlocked is a refusal',
        (tester) async {
      final host = await _pump(tester);
      final answer = host.ask(_legalTitle);
      await tester.pump();
      Navigator.of(host.pageContext).pop();
      await tester.pump();
      expect(await answer, isFalse);
      expect(host.deferral.isPending, isFalse,
          reason: 'a back press is not a blocked prompt');
    });

    testWidgets('behind the decoy: not drawn, not asked, deferred',
        (tester) async {
      final host = await _pump(tester);
      await _relock(tester);
      expect(host.decoy, isTrue);
      final answer = await host.ask(_legalTitle);
      await tester.pump();
      expect(answer, isFalse, reason: 'never an acceptance');
      expect(host.presented, 0, reason: 'the dialog code must not run');
      _expectNoDialog();
      expect(find.text('7 8 9 = 0'), findsOneWidget);
      expect(host.deferral.isPending, isTrue);
    });

    testWidgets('the relock removes an open dialog: no refusal, kept',
        (tester) async {
      final host = await _pump(tester);
      final answer = host.ask(_disclosureTitle);
      await tester.pump();
      expect(find.text(_disclosureTitle), findsOneWidget);
      await _relock(tester);
      _expectNoDialog();
      expect(await answer, isFalse);
      expect(host.deferral.isPending, isTrue,
          reason: 'a removed dialog is a question still owed');
    });

    testWidgets('an answer given before the relock stands', (tester) async {
      final host = await _pump(tester);
      final answer = host.ask(_legalTitle);
      await tester.pump();
      await tester.tap(find.text('Agree'));
      await _relock(tester);
      expect(await answer, isTrue);
      expect(host.deferral.isPending, isFalse);
    });

    testWidgets('after the unlock it is offered once, only in its own session',
        (tester) async {
      final host = await _pump(tester);
      await _relock(tester);
      await host.ask(_legalTitle);
      // A second trip to the background re-arms the decoy: still kept.
      await _relock(tester);
      host.unlock();
      await tester.pump();
      expect(host.deferral.take(accountEpoch: host.epoch), isTrue);
      final answer = host.ask(_legalTitle);
      await tester.pump();
      expect(find.text(_legalTitle), findsOneWidget);
      await tester.tap(find.text('Agree'));
      await tester.pump();
      expect(await answer, isTrue);
      expect(host.deferral.take(accountEpoch: host.epoch), isFalse,
          reason: 'offered once');
    });

    testWidgets('a record from another account session is not offered',
        (tester) async {
      final host = await _pump(tester);
      await _relock(tester);
      await host.ask(_legalTitle);
      host.epoch++;
      host.unlock();
      await tester.pump();
      expect(host.deferral.take(accountEpoch: host.epoch), isFalse);
      _expectNoDialog();
    });

    testWidgets(
        'a session that ended while the dialog was open is not kept for the '
        'next one', (tester) async {
      final host = await _pump(tester);
      final answer = host.ask(_legalTitle);
      await tester.pump();
      host.epoch++; // logged out and in again while the dialog is open
      await _relock(tester);
      expect(await answer, isFalse);
      expect(host.deferral.isPending, isFalse,
          reason: 'the question belonged to the session that ended');
    });

    testWidgets('the record keeps the epoch the dialog opened in',
        (tester) async {
      final host = await _pump(tester);
      host.epoch = 7;
      final answer = host.ask(_legalTitle);
      await tester.pump();
      await _relock(tester);
      expect(await answer, isFalse);
      expect(host.deferral.isPendingFor(7), isTrue);
    });

    testWidgets('a real answer drops the record; a removal and a back press do not',
        (tester) async {
      final host = await _pump(tester);
      // Refused in the dialog: the record is decided.
      host.deferral.defer(accountEpoch: host.epoch);
      var answer = host.ask(_legalTitle);
      await tester.pump();
      await tester.tap(find.text('Cancel'));
      await tester.pump();
      expect(await answer, isFalse);
      expect(host.deferral.isPending, isFalse, reason: 'a refusal left the record');
      expect(host.deferral.answerCount, 1);
      // Accepted: also decided.
      host.deferral.defer(accountEpoch: host.epoch);
      answer = host.ask(_legalTitle);
      await tester.pump();
      await tester.tap(find.text('Agree'));
      await tester.pump();
      expect(await answer, isTrue);
      expect(host.deferral.isPending, isFalse);
      expect(host.deferral.answerCount, 2);
      // A back press is not an answer.
      host.deferral.defer(accountEpoch: host.epoch);
      answer = host.ask(_legalTitle);
      await tester.pump();
      Navigator.of(host.pageContext).pop();
      await tester.pump();
      expect(await answer, isFalse);
      expect(host.deferral.isPending, isTrue);
      expect(host.deferral.answerCount, 2);
    });

    testWidgets('an answer given after the session changed drops nothing',
        (tester) async {
      final host = await _pump(tester);
      host.deferral.defer(accountEpoch: host.epoch + 1);
      final answer = host.ask(_legalTitle);
      await tester.pump();
      host.epoch++;
      await tester.tap(find.text('Agree'));
      await tester.pump();
      expect(await answer, isTrue);
      expect(host.deferral.answerCount, 0, reason: 'an answer for an ended session counted');
    });

    testWidgets('a relock and unlock with nothing pending shows nothing',
        (tester) async {
      final host = await _pump(tester);
      await _relock(tester);
      host.unlock();
      await tester.pump();
      await _relock(tester);
      host.unlock();
      await tester.pump();
      expect(host.deferral.take(accountEpoch: host.epoch), isFalse);
      expect(host.presented, 0);
      _expectNoDialog();
    });

    testWidgets('not mounted: not asked, nothing kept', (tester) async {
      final host = await _pump(tester);
      host.mounted_ = false;
      final unmounted = host.ask(_legalTitle);
      await tester.pump();
      // Checked before the answer is awaited: a dialog that was wrongly asked would never be answered.
      expect(host.presented, 0, reason: 'a prompt was presented by an unmounted host');
      expect(await unmounted, isFalse);
      expect(host.deferral.isPending, isFalse);
    });
  });
}
