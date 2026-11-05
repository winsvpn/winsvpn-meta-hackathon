import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/l10n/app_localizations.dart';
import 'package:wins_vpn/server_load.dart';
import 'package:wins_vpn/server_load_bar.dart';

/// Freshness clock bound to the test's fake time. testWidgets runs inside a
/// FakeAsync zone: `tester.pump(d)` advances `tester.binding.clock` and fires
/// due timers, so no test here sleeps for real.
class _TesterClock extends ServerLoadClock {
  _TesterClock(this.tester)
      : _startMs = tester.binding.clock.now().millisecondsSinceEpoch;

  final WidgetTester tester;
  final int _startMs;

  /// The binding's fake clock starts in 2015, outside the epoch window the
  /// load code accepts, so the wall clock here is fake ELAPSED time on top of
  /// a present-day base.
  static const int wallBaseMs = 1790480000123;

  /// Simulated suspend: the monotonic clock lags fake time by this much.
  int monoLagMs = 0;

  /// Simulated wall-clock change.
  int wallOffsetMs = 0;

  int get _elapsedMs =>
      tester.binding.clock.now().millisecondsSinceEpoch - _startMs;

  @override
  int monotonicMs() => 1000 + _elapsedMs - monoLagMs;

  @override
  int wallMs() => wallBaseMs + _elapsedMs + wallOffsetMs;
}

/// Widget contract for the shared Flutter load bar.
void main() {
  late ServerLoadClock savedClock;
  setUp(() => savedClock = serverLoadClock);
  tearDown(() => serverLoadClock = savedClock);

  _TesterClock useFakeClock(WidgetTester tester) {
    final clock = _TesterClock(tester);
    serverLoadClock = clock;
    return clock;
  }

  /// A node as the app holds it after a live /nodes reply received now.
  Map<String, dynamic> freshNode(Object? raw) {
    final rx = serverLoadReceiptNow();
    return <String, dynamic>{
      'slug': 'x',
      kServerLoadPctKey: raw,
      kServerLoadReceivedMonoKey: rx.mono,
      kServerLoadReceivedWallKey: rx.wall,
    };
  }

  Widget app(Widget child,
          {Brightness brightness = Brightness.light,
          Locale locale = const Locale('en')}) =>
      MaterialApp(
        locale: locale,
        supportedLocales: AppLocalizations.supportedLocales,
        localizationsDelegates: const [
          AppLocalizations.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        theme: ThemeData(brightness: brightness),
        home: Scaffold(body: Center(child: child)),
      );

  Future<void> pumpBar(
    WidgetTester tester,
    Object? node, {
    Brightness brightness = Brightness.light,
    Locale locale = const Locale('en'),
  }) =>
      tester.pumpWidget(app(ServerLoadBar(node: node),
          brightness: brightness, locale: locale));

  Finder fill() => find.byKey(const ValueKey<String>('server-load-fill'));

  Color? fillColor(WidgetTester tester) {
    if (fill().evaluate().isEmpty) return null;
    return tester
        .widget<ColoredBox>(
            find.descendant(of: fill(), matching: find.byType(ColoredBox)))
        .color;
  }

  double fillWidth(WidgetTester tester) =>
      fill().evaluate().isEmpty ? 0 : tester.getSize(fill()).width;

  // The brief's cases, as raw values. `missing` is what a node without the
  // key yields for node['load_pct'].
  final missing = <String, dynamic>{'slug': 'x'}[kServerLoadPctKey];

  final knownCases = <String, (Object?, int, Color)>{
    '0': (0, 0, ServerLoadPalette.light.low),
    '55': (55, 55, ServerLoadPalette.light.low),
    '60': (60, 60, ServerLoadPalette.light.elevated),
    '85': (85, 85, ServerLoadPalette.light.high),
    '100': (100, 100, ServerLoadPalette.light.high),
  };

  final unknownCases = <String, Object?>{
    'null': null,
    'missing': missing,
    'string "45"': '45',
    'float 45.5': 45.5,
    'integral float 45.0': 45.0,
    'negative -5': -5,
    'over 100 (105)': 105,
    'off-step 47': 47,
    'bool': true,
    'map': <String, int>{'v': 45},
    'list': <int>[45],
  };

  group('known values', () {
    for (final entry in knownCases.entries) {
      testWidgets('${entry.key}%: coloured fill, label and tooltip',
          (tester) async {
        useFakeClock(tester);
        final (raw, pct, colour) = entry.value;
        final handle = tester.ensureSemantics();
        await pumpBar(tester, freshNode(raw));

        expect(tester.takeException(), isNull);
        expect(fillColor(tester), colour);
        // 36 px bar; a known value always draws at least the 6% nub.
        expect(fillWidth(tester),
            closeTo(36 * math.max(pct / 100, 0.06), 0.01));
        expect(find.bySemanticsLabel('Server load $pct%'), findsOneWidget);
        expect(tester.widget<Tooltip>(find.byType(Tooltip)).message,
            'Server load $pct%');
        handle.dispose();
        // Unmount: the expiry timer must be cancelled, or testWidgets fails
        // with "A Timer is still pending".
        await tester.pumpWidget(const SizedBox());
      });
    }

    testWidgets('known 0% is visibly different from unknown', (tester) async {
      useFakeClock(tester);
      await pumpBar(tester, freshNode(0));
      final zero = fillWidth(tester);
      await pumpBar(tester, freshNode(null));
      expect(zero, greaterThan(0));
      expect(fillWidth(tester), 0);
    });
  });

  group('unknown and malformed values render the empty neutral track', () {
    for (final entry in unknownCases.entries) {
      testWidgets(entry.key, (tester) async {
        useFakeClock(tester);
        final handle = tester.ensureSemantics();
        // A FRESH stamp: only the malformed figure makes it unknown.
        await pumpBar(tester, freshNode(entry.value));

        expect(tester.takeException(), isNull,
            reason: 'a malformed value must never throw');
        expect(find.byType(ServerLoadBar), findsOneWidget);
        expect(fill(), findsNothing);
        expect(find.bySemanticsLabel('Server load unknown'), findsOneWidget);
        expect(tester.widget<Tooltip>(find.byType(Tooltip)).message,
            'Server load unknown');
        // The track is still drawn, same size as a known bar.
        expect(tester.getSize(find.byType(ServerLoadBar)), const Size(36, 6));
        handle.dispose();
      });
    }

    testWidgets('a valid figure without a receipt stamp is unknown',
        (tester) async {
      useFakeClock(tester);
      for (final node in <Object?>[
        <String, dynamic>{kServerLoadPctKey: 45},
        null,
        'not a map',
      ]) {
        await pumpBar(tester, node);
        expect(tester.takeException(), isNull);
        expect(fill(), findsNothing, reason: '$node');
      }
    });
  });

  group('expiry at 60 s (fake time)', () {
    testWidgets('the bar turns grey on its own at 60 s and re-announces',
        (tester) async {
      useFakeClock(tester);
      final handle = tester.ensureSemantics();
      await pumpBar(tester, freshNode(45));
      expect(find.bySemanticsLabel('Server load 45%'), findsOneWidget);

      await tester.pump(const Duration(seconds: 59, milliseconds: 999));
      expect(fill(), findsOneWidget, reason: 'still fresh at 59.999 s');

      // Nothing rebuilds the parent: only the bar's own timer can do this.
      await tester.pump(const Duration(milliseconds: 1));
      expect(fill(), findsNothing, reason: 'unknown at 60 s');
      expect(find.bySemanticsLabel('Server load unknown'), findsOneWidget);
      expect(find.bySemanticsLabel('Server load 45%'), findsNothing,
          reason: 'a stale figure must never be announced');
      expect(tester.widget<Tooltip>(find.byType(Tooltip)).message,
          'Server load unknown');
      handle.dispose();
    });

    testWidgets('an unmounted bar leaves no timer behind', (tester) async {
      useFakeClock(tester);
      await pumpBar(tester, freshNode(45));
      await tester.pumpWidget(const SizedBox());
      // Deliberately no further pump: testWidgets fails the test with "A
      // Timer is still pending even after the widget tree was disposed" if
      // dispose() did not cancel the 60 s expiry timer.
      expect(tester.takeException(), isNull);
    });

    testWidgets('replacing the node re-arms the timer from the new receipt',
        (tester) async {
      useFakeClock(tester);
      await pumpBar(tester, freshNode(45));
      await tester.pump(const Duration(seconds: 50));
      await pumpBar(tester, freshNode(80)); // a new listing arrives
      await tester.pump(const Duration(seconds: 50));
      expect(fillColor(tester), ServerLoadPalette.light.elevated,
          reason: '50 s after the NEW receipt: still fresh');
      await tester.pump(const Duration(seconds: 10));
      expect(fill(), findsNothing);
    });

    testWidgets('after a suspend, resume re-evaluates even if the timer lags',
        (tester) async {
      final clock = useFakeClock(tester);
      await pumpBar(tester, freshNode(45));
      expect(fill(), findsOneWidget);
      // Device slept for 5 minutes: the wall clock moved, the monotonic clock
      // (and therefore the pending timer) did not.
      clock.wallOffsetMs = 5 * 60 * 1000;
      tester.binding
          .handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump();
      expect(fill(), findsNothing);
    });

    testWidgets('an old copy stays grey even when the live list is newer',
        (tester) async {
      // The picker bug this design avoids: the copy carries its OWN stamp, so
      // nothing newer can make its old figure look fresh.
      useFakeClock(tester);
      final oldCopy = freshNode(90);
      await tester.pump(const Duration(seconds: 61));
      final live = freshNode(20);
      expect(freshServerLoadPct(live), 20);
      await pumpBar(tester, oldCopy);
      expect(fill(), findsNothing);
    });
  });

  group('LiveServerLoadBar (open picker follows the live listing)', () {
    testWidgets('a fetch that lands while the picker is open updates the bar',
        (tester) async {
      useFakeClock(tester);
      final revision = ValueNotifier<int>(0);
      addTearDown(revision.dispose);
      final pickerCopy = freshNode(90); // what the sheet copied when it opened
      Map<String, dynamic>? liveRow = pickerCopy;
      await tester.pumpWidget(app(LiveServerLoadBar(
        listing: revision,
        resolve: () => liveRow ?? pickerCopy,
      )));
      expect(fillColor(tester), ServerLoadPalette.light.high);

      await tester.pump(const Duration(seconds: 30));
      liveRow = freshNode(20); // _parseNodesResponse replaced the list
      revision.value++;
      await tester.pump();
      expect(fillColor(tester), ServerLoadPalette.light.low);
      expect(fillWidth(tester), closeTo(36 * 0.20, 0.01));

      // The new figure gets its own full 60 s.
      await tester.pump(const Duration(seconds: 59));
      expect(fill(), findsOneWidget);
      await tester.pump(const Duration(seconds: 1));
      expect(fill(), findsNothing);
    });

    testWidgets('a slug that left the listing falls back to the expiring copy',
        (tester) async {
      useFakeClock(tester);
      final revision = ValueNotifier<int>(0);
      addTearDown(revision.dispose);
      final pickerCopy = freshNode(45);
      Map<String, dynamic>? liveRow;
      await tester.pumpWidget(app(LiveServerLoadBar(
        listing: revision,
        resolve: () => liveRow ?? pickerCopy,
      )));
      revision.value++;
      await tester.pump();
      expect(fill(), findsOneWidget);
      await tester.pump(const Duration(seconds: 60));
      expect(fill(), findsNothing);
    });
  });

  group('published bands (hub Round LD: 25/60/90/100)', () {
    // Busy (60) sits exactly on the amber threshold: a future `>` in place of
    // `>=` would turn it green, and this test must catch that.
    final bands = <int, Color>{
      25: ServerLoadPalette.light.low,
      60: ServerLoadPalette.light.elevated,
      90: ServerLoadPalette.light.high,
      100: ServerLoadPalette.light.high,
    };
    for (final entry in bands.entries) {
      testWidgets('${entry.key}% renders the right colour', (tester) async {
        useFakeClock(tester);
        await pumpBar(tester, freshNode(entry.key));
        expect(fillColor(tester), entry.value);
        await tester.pumpWidget(const SizedBox());
      });
    }
  });

  group('theme', () {
    testWidgets('dark theme uses the dark palette', (tester) async {
      useFakeClock(tester);
      await pumpBar(tester, freshNode(55), brightness: Brightness.dark);
      expect(fillColor(tester), ServerLoadPalette.dark.low);
      await pumpBar(tester, freshNode(60), brightness: Brightness.dark);
      expect(fillColor(tester), ServerLoadPalette.dark.elevated);
      await pumpBar(tester, freshNode(85), brightness: Brightness.dark);
      expect(fillColor(tester), ServerLoadPalette.dark.high);
    });

    test('dark amber is the app colour it claims to be', () {
      expect(ServerLoadPalette.dark.elevated.toARGB32(),
          Colors.orangeAccent.toARGB32());
    });

    // WCAG 1.4.11 non-text contrast: 3:1 for every fill and the outline,
    // against the track and against the ACTUAL colour behind the bar. The
    // app's light panels are translucent (main.dart _surfacePanel 0xD8FDFDFD,
    // _surfacePanelSoft 0xB8FFFFFF) over the 0xFF0B0B0F scaffold, so the
    // surface is their alpha-blended composite, not the panel colour.
    const scaffold = Color(0xFF0B0B0F);
    const surfacePanel = Color(0xD8FDFDFD);
    const surfacePanelSoft = Color(0xB8FFFFFF);
    final panelOverScaffold = Color.alphaBlend(surfacePanel, scaffold);
    final lightSurfaces = <String, Color>{
      'panel over scaffold': panelOverScaffold,
      'soft panel over scaffold': Color.alphaBlend(surfacePanelSoft, scaffold),
      // The home tile: soft tile colour inside the main panel.
      'soft tile inside panel':
          Color.alphaBlend(surfacePanelSoft, panelOverScaffold),
    };
    final darkSurfaces = <String, Color>{'scaffold': scaffold};

    test('composites are what the review computed', () {
      expect(_hex(lightSurfaces['panel over scaffold']!), 'D8D8D9');
      expect(_hex(lightSurfaces['soft panel over scaffold']!), 'BBBBBC');
    });

    for (final (name, palette, surfaces) in [
      ('light', ServerLoadPalette.light, lightSurfaces),
      ('dark', ServerLoadPalette.dark, darkSurfaces),
    ]) {
      test('$name palette keeps 3:1 against the track and every composite',
          () {
        final fills = <String, Color>{
          'low': palette.low,
          'elevated': palette.elevated,
          'high': palette.high,
        };
        for (final f in fills.entries) {
          expect(_contrast(f.value, palette.track), greaterThanOrEqualTo(3.0),
              reason: '$name ${f.key} vs track');
          for (final s in surfaces.entries) {
            expect(_contrast(f.value, s.value), greaterThanOrEqualTo(3.0),
                reason: '$name ${f.key} vs ${s.key} (${_hex(s.value)})');
          }
        }
        for (final s in surfaces.entries) {
          expect(_contrast(palette.outline, s.value), greaterThanOrEqualTo(3.0),
              reason: '$name outline vs ${s.key} (${_hex(s.value)})');
        }
      });
    }

    test('the Turn 1 light palette fails the composite check (control)', () {
      const oldAmber = Color(0xFFE65100);
      final soft = lightSurfaces['soft panel over scaffold']!;
      expect(_contrast(oldAmber, soft), lessThan(3.0),
          reason: 'the check must be able to fail');
    });
  });

  group('localisation', () {
    // Owner-approved wording (Round LC OI-8, RESOLVED-BY-USER):
    // .agent/debates/_decisions/owner_ruling_load_bar_burmese_20260927.md
    const burmesePercentTemplate = "ဆာဗာ အသုံးပြုမှုနှုန်း {percent}%";
    const burmeseUnknown = "ဆာဗာ ဝန် မရရှိပါ";

    testWidgets('Burmese labels render with the percentage substituted',
        (tester) async {
      useFakeClock(tester);
      final handle = tester.ensureSemantics();
      for (final pct in <int>[25, 45, 60, 90, 100]) {
        await pumpBar(tester, freshNode(pct), locale: const Locale('my'));
        final expected =
            burmesePercentTemplate.replaceFirst('{percent}', '$pct');
        expect(find.bySemanticsLabel(expected), findsOneWidget, reason: '$pct');
        final label = tester.widget<Tooltip>(find.byType(Tooltip)).message!;
        expect(label, expected);
        expect(label.contains('\uFFFD'), isFalse, reason: 'no U+FFFD');
        expect(label.contains('{'), isFalse, reason: 'placeholder substituted');
        expect(label.endsWith('$pct%'), isTrue, reason: 'keeps the % form');
      }
      await pumpBar(tester, freshNode(null), locale: const Locale('my'));
      expect(find.bySemanticsLabel(burmeseUnknown), findsOneWidget);
      expect(burmeseUnknown.contains('\uFFFD'), isFalse);
      handle.dispose();
      await tester.pumpWidget(const SizedBox());
    });

    test('the generated Burmese localisation carries the ruled bytes', () {
      final my = lookupAppLocalizations(const Locale('my'));
      expect(my.serverLoadPercent(90),
          burmesePercentTemplate.replaceFirst('{percent}', '90'));
      expect(my.serverLoadUnknown, burmeseUnknown);
    });

    testWidgets('no localisation delegate: English fallback, no throw',
        (tester) async {
      useFakeClock(tester);
      final handle = tester.ensureSemantics();
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(body: Center(child: ServerLoadBar(node: freshNode(45)))),
      ));
      expect(tester.takeException(), isNull);
      expect(find.bySemanticsLabel('Server load 45%'), findsOneWidget);
      handle.dispose();
      await tester.pumpWidget(const SizedBox());
    });

    test('serverLoadLabel without l10n', () {
      expect(serverLoadLabel(null, null), 'Server load unknown');
      expect(serverLoadLabel(null, 5), 'Server load 5%');
    });
  });

  testWidgets('inside a ListTile the load joins the row label', (tester) async {
    useFakeClock(tester);
    final handle = tester.ensureSemantics();
    await tester.pumpWidget(MaterialApp(
      localizationsDelegates: const [AppLocalizations.delegate],
      home: Material(
        child: ListTile(
          title: Row(children: [
            const Expanded(child: Text('Spain (Madrid)')),
            ServerLoadBar(node: freshNode(70)),
          ]),
          onTap: () {},
        ),
      ),
    ));
    expect(tester.getSemantics(find.byType(ListTile)).label,
        contains('Server load 70%'));
    handle.dispose();
    await tester.pumpWidget(const SizedBox());
  });
}

String _hex(Color c) => c
    .toARGB32()
    .toRadixString(16)
    .padLeft(8, '0')
    .substring(2)
    .toUpperCase();

double _luminance(Color c) {
  double ch(double v) =>
      v <= 0.03928 ? v / 12.92 : math.pow((v + 0.055) / 1.055, 2.4).toDouble();
  return 0.2126 * ch(c.r) + 0.7152 * ch(c.g) + 0.0722 * ch(c.b);
}

double _contrast(Color a, Color b) {
  final la = _luminance(a);
  final lb = _luminance(b);
  return (math.max(la, lb) + 0.05) / (math.min(la, lb) + 0.05);
}
