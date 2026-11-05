// The decoy calculator is a body swap, so surfaces outside the body (the root
// ScaffoldMessenger's snack bars and banners, and routes above the first)
// survive it unless something removes them, and a route pushed later by an
// async continuation lands on top of it. These widget tests execute
// lib/decoy_cover.dart on a real widget tree:
// * the relock: a Product surface is up, the inactive lifecycle callback
//   relocks, and after ONE pump nothing of the Product is left (no exit
//   transition either);
// * the route guard: a route pushed while the decoy shows is gone after one
//   pump, and only a decoy/ route stays.
// The host relocks exactly as main.dart's didChangeAppLifecycleState does
// (clear the surfaces, then set the decoy), and its MaterialApp registers a
// DecoyRouteGuard the way MyApp registers decoyRouteGuard. The whole app
// cannot be relocked in a host test: in-app camouflage is not supported on the
// test platform; the app-wiring tests pin the call sites and pump MyApp to
// check the guard is registered.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/decoy_cover.dart';
import 'package:wins_vpn/main.dart' show MyApp;

const _settingsMessage =
    'The new settings apply as soon as the server list has loaded.';
const _product = <String>[
  _settingsMessage,
  'Free server changed.',
  "Win's VPN",
  'Release held traffic?',
  'Choose a server',
  'Emergency alert',
  'Save this recovery code',
];

class _Host extends StatefulWidget {
  const _Host({required this.clearsSurfaces, required this.guard});
  final bool clearsSurfaces;
  final DecoyRouteGuard guard;
  @override
  State<_Host> createState() => _HostState();
}

class _HostState extends State<_Host> with WidgetsBindingObserver {
  bool decoy = false;
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
    if (widget.clearsSurfaces) {
      clearProductSurfacesForDecoy(context, guard: widget.guard);
    }
    setState(() => decoy = true);
  }

  @override
  Widget build(BuildContext context) {
    pageContext = context;
    if (decoy) {
      return const Scaffold(body: Center(child: Text('7 8 9 = 0')));
    }
    return const Scaffold(body: Center(child: Text("Win's VPN")));
  }
}

Future<_HostState> _pumpHost(WidgetTester tester,
    {bool clearsSurfaces = true}) async {
  late _HostState host;
  final guard = DecoyRouteGuard(decoyShowing: () => host.decoy);
  await tester.pumpWidget(MaterialApp(
    navigatorObservers: <NavigatorObserver>[guard],
    home: _Host(clearsSurfaces: clearsSurfaces, guard: guard),
  ));
  host = tester.state<_HostState>(find.byType(_Host));
  return host;
}

Future<void> _relock(WidgetTester tester) async {
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
  await tester.pump();
}

void _expectOnlyTheCalculator() {
  expect(find.text('7 8 9 = 0'), findsOneWidget);
  for (final text in _product) {
    expect(find.textContaining(text, skipOffstage: false), findsNothing,
        reason: text);
  }
  expect(find.byType(SnackBar, skipOffstage: false), findsNothing);
  expect(find.byType(MaterialBanner, skipOffstage: false), findsNothing);
  expect(find.byType(Dialog, skipOffstage: false), findsNothing);
  expect(find.byType(AlertDialog, skipOffstage: false), findsNothing);
  expect(find.byType(BottomSheet, skipOffstage: false), findsNothing);
}

void main() {
  tearDown(() {
    // Leave the binding resumed for the next test.
    TestWidgetsFlutterBinding.instance
        .handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });

  group('relock', () {
    testWidgets(
        'control: without the clear, a snack bar shown before the relock '
        'stays over the calculator (the leak is real)', (tester) async {
      final host = await _pumpHost(tester, clearsSurfaces: false);
      ScaffoldMessenger.of(host.pageContext)
          .showSnackBar(const SnackBar(content: Text(_settingsMessage)));
      await tester.pump(const Duration(milliseconds: 300));
      await _relock(tester);
      expect(find.text('7 8 9 = 0'), findsOneWidget);
      expect(find.text(_settingsMessage), findsOneWidget);
    });

    testWidgets('a snack bar shown just before the relock is gone at once',
        (tester) async {
      final host = await _pumpHost(tester);
      ScaffoldMessenger.of(host.pageContext)
          .showSnackBar(const SnackBar(content: Text(_settingsMessage)));
      await tester.pump(const Duration(milliseconds: 300));
      expect(find.text(_settingsMessage), findsOneWidget);
      await _relock(tester);
      _expectOnlyTheCalculator();
      await tester.pump(const Duration(seconds: 10));
      _expectOnlyTheCalculator();
    });

    testWidgets('queued snack bars never surface after the relock',
        (tester) async {
      final host = await _pumpHost(tester);
      final messenger = ScaffoldMessenger.of(host.pageContext);
      messenger.showSnackBar(const SnackBar(content: Text(_settingsMessage)));
      messenger.showSnackBar(const SnackBar(content: Text('Free server changed.')));
      await tester.pump(const Duration(milliseconds: 300));
      await _relock(tester);
      _expectOnlyTheCalculator();
      await tester.pump(const Duration(seconds: 10));
      await tester.pump(const Duration(seconds: 10));
      _expectOnlyTheCalculator();
    });

    testWidgets('a material banner is gone at once', (tester) async {
      final host = await _pumpHost(tester);
      ScaffoldMessenger.of(host.pageContext).showMaterialBanner(
        MaterialBanner(
          content: const Text("Win's VPN announcement"),
          actions: <Widget>[TextButton(onPressed: () {}, child: const Text('OK'))],
        ),
      );
      await tester.pump(const Duration(milliseconds: 300));
      expect(find.byType(MaterialBanner), findsOneWidget);
      await _relock(tester);
      _expectOnlyTheCalculator();
    });

    testWidgets(
        'R1: an open dialog and bottom sheet are gone after ONE frame, with '
        'no exit transition', (tester) async {
      final host = await _pumpHost(tester);
      showModalBottomSheet<void>(
        context: host.pageContext,
        builder: (_) => const SizedBox(height: 200, child: Text('Choose a server')),
      );
      await tester.pumpAndSettle();
      showDialog<void>(
        context: host.pageContext,
        builder: (_) => const Dialog(child: Text('Release held traffic?')),
      );
      await tester.pumpAndSettle();
      expect(find.text('Release held traffic?'), findsOneWidget);
      expect(find.text('Choose a server'), findsOneWidget);
      await _relock(tester);
      // One pump, not pumpAndSettle: a pop would still be fading the dialog
      // (about 150 ms) and sliding the sheet (about 200 ms) here.
      _expectOnlyTheCalculator();
    });
  });

  group('route guard', () {
    testWidgets(
        'a dialog pushed while the decoy shows is gone after one pump, and '
        'its future answers null', (tester) async {
      final host = await _pumpHost(tester);
      await _relock(tester);
      Object? answered = 'pending';
      showDialog<String>(
        context: host.pageContext,
        builder: (_) => const AlertDialog(title: Text('Emergency alert')),
      ).then((value) => answered = value);
      await tester.pump();
      _expectOnlyTheCalculator();
      await tester.pump(const Duration(seconds: 2));
      _expectOnlyTheCalculator();
      expect(answered, isNull, reason: 'the caller must read it as dismissed');
    });

    testWidgets('a bottom sheet and a page pushed while the decoy shows go too',
        (tester) async {
      final host = await _pumpHost(tester);
      await _relock(tester);
      showModalBottomSheet<void>(
        context: host.pageContext,
        builder: (_) => const Text('Choose a server'),
      );
      Navigator.of(host.pageContext).push(MaterialPageRoute<void>(
          builder: (_) => const Scaffold(body: Text('Save this recovery code'))));
      await tester.pump();
      _expectOnlyTheCalculator();
    });

    testWidgets('a decoy/ route stays over the calculator', (tester) async {
      final host = await _pumpHost(tester);
      await _relock(tester);
      showDialog<void>(
        context: host.pageContext,
        routeSettings: const RouteSettings(name: '${kDecoyRoutePrefix}entry-failure'),
        builder: (_) => const AlertDialog(title: Text('Calculation error')),
      );
      await tester.pump();
      await tester.pump(const Duration(seconds: 1));
      expect(find.text('Calculation error'), findsOneWidget);
    });

    testWidgets('control: routes pushed while unlocked are left alone',
        (tester) async {
      final host = await _pumpHost(tester);
      showDialog<void>(
        context: host.pageContext,
        builder: (_) => const AlertDialog(title: Text('Emergency alert')),
      );
      await tester.pumpAndSettle();
      expect(find.text('Emergency alert'), findsOneWidget);
    });

    testWidgets('MyApp registers the guard on its root navigator',
        (tester) async {
      await tester.pumpWidget(const MyApp());
      await tester.pump();
      final navigator = tester.state<NavigatorState>(find.byType(Navigator).first);
      expect(navigator.widget.observers, contains(decoyRouteGuard));
      expect(decoyRouteGuard.navigator, same(navigator));
    });

    testWidgets(
        'F2: the guard is the root navigator\'s one DecoyRouteGuard and stays '
        'registered across MaterialApp rebuilds', (tester) async {
      await tester.pumpWidget(const MyApp());
      await tester.pump();
      final navigator = tester.state<NavigatorState>(find.byType(Navigator).first);
      void expectRegistered(String when) {
        final current =
            tester.state<NavigatorState>(find.byType(Navigator).first);
        expect(current, same(navigator), reason: '$when: navigator replaced');
        final guards =
            current.widget.observers.whereType<DecoyRouteGuard>().toList();
        expect(guards, <DecoyRouteGuard>[decoyRouteGuard], reason: when);
        expect(decoyRouteGuard.navigator, same(current), reason: when);
      }

      expectRegistered('first build');
      // A new MyApp widget (a parent rebuild).
      await tester.pumpWidget(const MyApp());
      await tester.pump();
      expectRegistered('new MyApp widget');
      // The MaterialApp element itself rebuilt.
      tester.element(find.byType(MaterialApp)).markNeedsBuild();
      await tester.pump();
      expectRegistered('MaterialApp rebuild');
      // A locale change rebuilds the app from the platform.
      tester.binding.platformDispatcher.localesTestValue = const <Locale>[
        Locale('my'),
      ];
      await tester.pump();
      expectRegistered('locale change');
      tester.binding.platformDispatcher.clearLocalesTestValue();
      await tester.pump();
      expectRegistered('locale restored');
      // And it still guards: a dialog pushed while the decoy is up goes.
      decoyCoverActive = true;
      showDialog<void>(
        context: tester.element(find.byType(Scaffold).first),
        builder: (_) => const AlertDialog(title: Text('Emergency alert')),
      );
      await tester.pump();
      expect(find.text('Emergency alert'), findsNothing);
      decoyCoverActive = false;
    });
  });

  group('app wiring', () {
    late String source;
    setUpAll(() => source = File('lib/main.dart').readAsStringSync());

    int index(String needle, [int from = 0]) {
      final at = source.indexOf(needle, from);
      expect(at, greaterThanOrEqualTo(0), reason: needle);
      return at;
    }

    test('every write that can set the decoy clears the surfaces first', () {
      // Each decoy-arming write, with the clear in the same synchronous turn.
      const clear = '_clearProductSurfacesForDecoy();';
      for (final pair in const <List<String>>[
        // pre-consent probe
        <String>[clear, '    setState(() {\n      _showDecoyCalculator = true;\n      _calcDisplayString = "0";'],
        // duress
        <String>['      if (_supportsInAppCamouflage) $clear', '        _showDecoyCalculator = _supportsInAppCamouflage;'],
        // lifecycle relock: anchored after its own camouflageRelevant test,
        // so the confirmed-disconnect site (same text) cannot stand in for it
        <String>['final camouflageRelevant = _supportsInAppCamouflage &&', '      $clear\n      setState(() => _showDecoyCalculator = true);\n    } else {\n      _showDecoyCalculator = true;'],
        // confirmed disconnect
        <String>['      $clear\n      setState(() => _showDecoyCalculator = true);\n    }\n    unawaited(_latchCamouflage());', ''],
        // activation
        <String>['        $clear\n        setState(() => _showDecoyCalculator = true);', ''],
        // user disconnect
        <String>['        if (showCamouflageAfterDisconnect) $clear', '          _showDecoyCalculator = showCamouflageAfterDisconnect;'],
      ]) {
        final at = index(pair[0]);
        if (pair[1].isNotEmpty) {
          final write = index(pair[1], at);
          expect(write - at, lessThan(1400), reason: pair[1]);
        }
      }
      // Onboarding decides inside a setState, then clears in the same turn.
      final decide = index('          _showDecoyCalculator = decoyCalculatorShouldArm(');
      final cleared = index('      if (_showDecoyCalculator) $clear', decide);
      expect(cleared - decide, lessThan(900));
      // Every write of the decoy flag is one of those 7, a false, the
      // initState first-frame value (nothing is on screen yet), or the
      // unmounted branch of the lifecycle relock (no tree to clear).
      final writes = RegExp(r'_showDecoyCalculator = (?!false)')
          .allMatches(source)
          .length;
      expect(writes, 9);
      // The first-frame value, set first thing in initState (before any
      // build, so there is nothing to clear).
      expect(source, contains('    super.initState();\n    _showDecoyCalculator = calculatorCoversFirstFrame('));
      // Each arming starts a new decoy generation.
      final bump = index('  void _clearProductSurfacesForDecoy() {');
      expect(source.substring(bump, bump + 120), contains('    _decoyGeneration++;'));
      expect(
          source,
          contains('    } else {\n      _showDecoyCalculator = true;\n    }\n'
              '    unawaited(() async {\n      await _setLauncherCamouflage(enabled: true);'));
      final helper = index('  void _clearProductSurfacesForDecoy() {');
      expect(source.substring(helper, helper + 200),
          contains('clearProductSurfacesForDecoy(context);'));
    });

    test('a fresh install drops the first-frame surface before its consent dialog',
        () {
      // The guard removes a push over the decoy; a never-activated, unlatched
      // install's consent dialog is not one (onboarding shows it the real app).
      final gate = index('  Future<void> _initializePrivacyConsentGate() async {');
      final arm = index('      await _armCamouflageBeforeConsent();\n      return;\n    }', gate);
      final drop = index('    if (mounted && _showDecoyCalculator) {\n'
          '      setState(() => _showDecoyCalculator = false);\n    }\n'
          '    await _showPrivacyPolicyDialog(requireConsent: true);', arm);
      expect(drop - arm, lessThan(700));
    });

    test('the recovery-code and release dialogs have no async action inside',
        () {
      // Their buttons only pop; everything after the dialog re-checks the
      // relock (consentStillOwned, _showRecoveryCodeUntilSeen). The duress
      // dialog, the one with in-dialog awaits, is duress_enrollment_dialog_test.
      // The release dialog returns showDialog's future (0 awaits); the
      // recovery dialog awaits only its showDialog (1).
      for (final entry in const <String, int>{
        '  Future<bool> _showRecoveryCodeOnce(String code) async {': 1,
        '  Future<bool?> _confirmWinn3HoldRelease(String serverName) async {': 0,
      }.entries) {
        final start = index(entry.key);
        final body = source.substring(start, source.indexOf('\n  }\n', start));
        expect(RegExp(r'\bawait\b').allMatches(body).length, entry.value,
            reason: '${entry.key} gained an await');
        expect(body, isNot(contains('async =>')), reason: entry.key);
        expect(RegExp(r'onPressed: \(\) async').hasMatch(body), isFalse,
            reason: '${entry.key} gained an async button');
      }
    });

    test('the keypad popup is the decoy route the guard keeps', () {
      final popup = index('  void _showEntryFailurePopup() {');
      expect(source.substring(popup, popup + 900),
          contains("routeSettings: const RouteSettings(name: '\${kDecoyRoutePrefix}entry-failure'),"));
      // The only decoy/ route in the app.
      expect(RegExp(r'kDecoyRoutePrefix').allMatches(source).length, 1);
    });

    test('no snack bar, sheet or release dialog is raised behind the decoy', () {
      final feedback = index('  void _showFeedback(String message) {');
      expect(source.substring(feedback, feedback + 160),
          contains('    if (_showDecoyCalculator) return;'));
      expect(RegExp(r'showSnackBar\(').allMatches(source).length, 1,
          reason: 'every snack bar goes through _showFeedback');
      final picker = index('  Future<void> _showLocationPicker({bool freeOnly = false}) async {');
      final sheet = index('    _showLocationPickerSheet(freeOnly: freeOnly);\n  }', picker);
      expect(source.substring(picker, sheet),
          contains('    if (!mounted || _showDecoyCalculator) return;'));
      final consent = index('    bool consentStillOwned() =>');
      expect(source.substring(consent, consent + 260),
          contains('        !_showDecoyCalculator;'));
      final automatic = index("                          ? 'Automatic server selection enabled.'");
      expect(source.substring(automatic - 80, automatic),
          contains('_showSelectionFeedback(refreshed'));
    });
  });
}
