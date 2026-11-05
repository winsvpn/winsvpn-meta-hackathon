import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/main.dart';

/// The home header is one widget on the one home panel, so it is the same
/// before and after activation. This pins the two things the owner asked for
/// (2026-09-29): a "Part of Winthos AI" line directly under the "Win's VPN"
/// wordmark, and less empty space above and below the logo. The owner also
/// ruled that the logo sentences stay in English in every language.
void main() {
  const originalLogoHeight = 124.0; // the old fixed Image height
  const subtitleKey = Key('home_brand_subtitle');

  // flutter_test draws every font as the wide Ahem square face, which makes
  // the size measurement meaningless. Load the real Roboto the app uses from
  // the Flutter SDK cache (the tool sets FLUTTER_ROOT); without it the
  // font-size tests are skipped rather than measured wrongly.
  final flutterRoot = Platform.environment['FLUTTER_ROOT'];
  final robotoDir = flutterRoot == null
      ? null
      : '$flutterRoot/bin/cache/artifacts/material_fonts';
  final robotoFiles = <File>[
    for (final w in ['Regular', 'Medium', 'Bold'])
      if (robotoDir != null) File('$robotoDir/Roboto-$w.ttf'),
  ];
  final haveRoboto = robotoFiles.isNotEmpty && robotoFiles.every((f) => f.existsSync());
  setUpAll(() async {
    if (!haveRoboto) return;
    final loader = FontLoader('Roboto');
    for (final f in robotoFiles) {
      loader.addFont(Future.value(ByteData.sublistView(f.readAsBytesSync())));
    }
    await loader.load();
  });

  Widget host({Locale? locale, double textScale = 1.0}) => MaterialApp(
        locale: locale,
        supportedLocales: const [Locale('en'), Locale('de'), Locale('my')],
        localizationsDelegates: const [
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        builder: (context, child) => MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: TextScaler.linear(textScale)),
          child: child!,
        ),
        home: const Scaffold(
          body: Center(child: WinsHomeBrandHeader()),
        ),
      );

  /// Font size the subtitle is actually drawn at: its style size, times the
  /// system text scale, times the FittedBox shrink factor (never above 1).
  double renderedFontPx(WidgetTester tester, double textScale) {
    final text = tester.widget<Text>(find.byKey(subtitleKey));
    final laidOut = tester.getSize(find.byKey(subtitleKey));
    final box = tester.getSize(find
        .ancestor(of: find.byKey(subtitleKey), matching: find.byType(FittedBox))
        .first);
    final fit = [1.0, box.width / laidOut.width, box.height / laidOut.height]
        .reduce((a, b) => a < b ? a : b);
    return text.style!.fontSize! * textScale * fit;
  }

  testWidgets('header is shorter than the old 124px logo box and shows the '
      'subtitle under the wordmark', (tester) async {
    await tester.pumpWidget(host());

    final header = tester.getRect(find.byType(WinsHomeBrandHeader));
    expect(header.height, WinsHomeBrandHeader.bandHeight);
    expect(header.height, lessThan(originalLogoHeight - 30),
        reason: 'the transparent margins must be cropped, not kept');
    expect(header.width, WinsHomeBrandHeader.logoWidth,
        reason: 'the logo itself is not resized');

    expect(find.text('Part of Winthos AI'), findsOneWidget);
    final sub = tester.getRect(find.byKey(subtitleKey));
    expect(header.contains(sub.topLeft) && header.contains(sub.bottomRight),
        isTrue, reason: 'subtitle must sit inside the header, adding no height');
    // Under the wordmark (drawn at x 91..234 of the 250px logo), not under the
    // shield, and in the lower half of the band where the wordmark ends.
    final wordmarkLeft = header.left + 91;
    final wordmarkRight = header.left + 234;
    expect(sub.left, greaterThanOrEqualTo(wordmarkLeft - 0.5));
    expect(sub.right, lessThanOrEqualTo(wordmarkRight + 0.5));
    expect(sub.top - header.top, greaterThan(50),
        reason: 'below the wordmark baseline (y=72 minus 20px band offset)');
  });

  for (final locale in const [Locale('en'), Locale('de'), Locale('my')]) {
    testWidgets('shows exactly "Part of Winthos AI" under ${locale.languageCode}',
        (tester) async {
      await tester.pumpWidget(host(locale: locale));
      final text = tester.widget<Text>(find.byKey(subtitleKey));
      expect(text.data, 'Part of Winthos AI');
      expect(find.text('Part of Winthos AI'), findsOneWidget);
    });
  }

  // HD-2: the subtitle lives in a fixed box inside a FittedBox, so pin the
  // smallest size it may be drawn at instead of trusting the box.
  for (final scale in const [1.0, 2.0]) {
    testWidgets('subtitle is not drawn below 10 logical px at text scale $scale',
        skip: !haveRoboto,
        (tester) async {
      await tester.pumpWidget(host(textScale: scale));
      expect(tester.takeException(), isNull);
      expect(renderedFontPx(tester, scale), greaterThanOrEqualTo(10.0));
      // English keeps its designed size at the default scale.
      if (scale == 1.0) {
        expect(renderedFontPx(tester, scale), 11.0);
      }
      final header = tester.getRect(find.byType(WinsHomeBrandHeader));
      final box = tester.getRect(find
          .ancestor(
              of: find.byKey(subtitleKey), matching: find.byType(FittedBox))
          .first);
      expect(header.contains(box.bottomRight), isTrue,
          reason: 'must not grow the header');
    });
  }

  // HD-2 (narrow windows): the home panel hands the header
  // min(window - 24, 460) - 2 * horizontal padding (12 under 380 dp, else 18)
  // - 2 for the border. A 270 dp window leaves 220 dp, less than the 250 dp
  // logo, so the whole header must scale down instead of clipping.
  double availableFor(double window) {
    final panel = window - 24 < 460 ? window - 24 : 460.0;
    final pad = window < 380 ? 12.0 : 18.0;
    return panel - 2 * pad - 2;
  }

  for (final window in const [240.0, 270.0, 320.0, 411.0]) {
    for (final scale in const [1.0, 2.0]) {
      testWidgets('header fits and stays whole at $window dp, text scale $scale',
          (tester) async {
        tester.view.physicalSize = Size(window * 3, 800 * 3);
        tester.view.devicePixelRatio = 3;
        addTearDown(tester.view.reset);
        final avail = availableFor(window);
        await tester.pumpWidget(MaterialApp(
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(context)
                .copyWith(textScaler: TextScaler.linear(scale)),
            child: child!,
          ),
          home: Scaffold(
            body: Align(
              alignment: Alignment.topCenter,
              child: SizedBox(
                width: avail,
                child: const Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [WinsHomeBrandHeader()],
                ),
              ),
            ),
          ),
        ));
        expect(tester.takeException(), isNull);

        final header = tester.getRect(find.byType(WinsHomeBrandHeader));
        final expectedScale = avail < 250 ? avail / 250 : 1.0;
        // Nothing clipped: the header itself fits the room it is given.
        expect(header.width, lessThanOrEqualTo(avail + 0.01));
        expect(header.width, closeTo(250 * expectedScale, 0.01));
        expect(header.height, closeTo(WinsHomeBrandHeader.bandHeight * expectedScale, 0.01),
            reason: 'aspect ratio is kept');
        if (avail >= 250) {
          expect(header.width, 250, reason: 'unchanged at 250 dp or wider');
          expect(header.height, WinsHomeBrandHeader.bandHeight);
        }
        // The subtitle is fully inside the header (so not clipped by the
        // Stack) and still under the wordmark span, scaled with the header.
        final sub = tester.getRect(find.byKey(subtitleKey));
        expect(header.inflate(0.01).contains(sub.topLeft), isTrue);
        expect(header.inflate(0.01).contains(sub.bottomRight), isTrue);
        expect(sub.left, greaterThanOrEqualTo(header.left + 91 * expectedScale - 0.5));
        expect(sub.right, lessThanOrEqualTo(header.left + 234 * expectedScale + 0.5));
        expect(sub.top - header.top, greaterThan(50 * expectedScale),
            reason: 'below the wordmark baseline');
        // The wordmark (drawn to x = 234 of 250) also ends inside the header.
        expect(header.left + 234 * expectedScale, lessThanOrEqualTo(header.right));
      });
    }
  }

  // HD-2 (map button): the header now starts higher than the old 124 dp logo
  // box, so on a narrow window its box would run under the floating map
  // button. Real home, real layout: the header box must never intersect the
  // button, at every width and text scale, and must stay exactly where it was
  // where there was no overlap (384 dp and wider).
  for (final window in const [270.0, 320.0, 360.0, 384.0, 411.0]) {
    for (final scale in const [1.0, 2.0]) {
      testWidgets(
          'header box clears the map button at $window dp, text scale $scale',
          (tester) async {
        tester.view.physicalSize = Size(window * 3, 832 * 3);
        tester.view.devicePixelRatio = 3;
        addTearDown(tester.view.reset);
        await tester.pumpWidget(MediaQuery(
          data: MediaQueryData(
              size: Size(window, 832), textScaler: TextScaler.linear(scale)),
          child: const MyApp(),
        ));
        await tester.pump();
        final notNow = find.text('Not now');
        if (notNow.evaluate().isNotEmpty) {
          await tester.tap(notNow);
          await tester.pumpAndSettle();
        }
        await tester.pump(const Duration(milliseconds: 500));

        final button = tester.getRect(find.descendant(
            of: find.byTooltip('Explore map'), matching: find.byType(IconButton)));
        final header = tester.getRect(find.byType(WinsHomeBrandHeader));
        expect(header.overlaps(button), isFalse,
            reason: 'header $header runs under the map button $button');
        // The real button box is inside the box the layout reserved for it.
        final reserved = Rect.fromLTWH(
            WinsHomeBrandHeader.mapButtonLeft,
            WinsHomeBrandHeader.mapButtonTop,
            WinsHomeBrandHeader.mapButtonSize + 2 * WinsHomeBrandHeader.mapButtonBorder,
            WinsHomeBrandHeader.mapButtonSize + 2 * WinsHomeBrandHeader.mapButtonBorder);
        expect(reserved.inflate(0.01).contains(button.topLeft), isTrue);
        expect(reserved.inflate(0.01).contains(button.bottomRight), isTrue);

        if (window >= 384) {
          // No overlap: nothing pushes the header, and the card has no
          // padding above it: card top edge, 1 dp border, then the header
          // (whose band keeps 1 dp above the artwork), so the shield sits 2 dp
          // below the card's top edge (it was 22).
          final card = tester.getRect(find
              .ancestor(
                  of: find.byType(WinsHomeBrandHeader),
                  matching: find.byWidgetPredicate((w) =>
                      w is Container &&
                      w.decoration is BoxDecoration &&
                      (w.decoration as BoxDecoration).borderRadius ==
                          BorderRadius.circular(14)))
              .first);
          expect(header.top - card.top, closeTo(1, 0.01));
          expect(
              header.top -
                  card.top +
                  (23 - WinsHomeBrandHeader.bandTop),
              lessThanOrEqualTo(3),
              reason: 'shield within a few dp of the card top');
          final panel = window - 24 < 460 ? window - 24 : 460.0;
          final inner = panel - 2 - 36;
          expect(header.left,
              closeTo((window - panel) / 2 + 1 + 18 + (inner - 250) / 2, 0.01));
          expect(header.width, 250);
        }
      });
    }
  }

  test('clearance: nothing to do when the header is already clear', () {
    final move = WinsHomeBrandHeader.clearance(
      header: const Rect.fromLTWH(67, 37, 250, 84),
      obstacles: const [Rect.fromLTWH(10, 8, 50, 50)],
      spareRight: 36,
    );
    expect(move, (dx: 0.0, dy: 0.0));
  });

  test('clearance: shifts right when there is room, otherwise moves down', () {
    // About 360 dp: overlaps the map button by a few dp and has 30 dp spare.
    final shift = WinsHomeBrandHeader.clearance(
      header: const Rect.fromLTWH(55, 26, 250, 84),
      obstacles: const [Rect.fromLTWH(10, 8, 50, 50)],
      spareRight: 30,
    );
    expect(shift.dy, 0);
    expect(shift.dx, closeTo(60 - 55, 0.01));
    // About 320 dp: only 10 dp spare, so it goes down past the button.
    final down = WinsHomeBrandHeader.clearance(
      header: const Rect.fromLTWH(35, 23, 250, 84),
      obstacles: const [Rect.fromLTWH(10, 8, 50, 50)],
      spareRight: 10,
    );
    expect(down.dx, 0);
    expect(down.dy, closeTo(58 - 23, 0.01));
  });

  test('clearance: the share button on the right also clears the header', () {
    for (final window in const [270.0, 320.0, 360.0, 384.0, 411.0]) {
      final panel = window - 24 < 460 ? window - 24 : 460.0;
      final pad = window < 380 ? 12.0 : 18.0;
      final inner = panel - 2 - 2 * pad;
      final width = inner < 250 ? inner : 250.0;
      final header = Rect.fromLTWH(
          (window - panel) / 2 + 1 + pad + (inner - width) / 2,
          (window < 380 ? 10 : 18) + 1,
          width,
          84 * width / 250);
      final buttons = <Rect>[
        const Rect.fromLTWH(10, 8, 50, 50),
        Rect.fromLTWH(window - 10 - 56, 8, 56, 56),
      ];
      final move = WinsHomeBrandHeader.clearance(
        header: header,
        obstacles: buttons,
        spareRight: (inner - width) / 2,
      );
      final moved = header.shift(Offset(move.dx, move.dy));
      for (final b in buttons) {
        expect(moved.overlaps(b), isFalse, reason: 'window $window: $moved vs $b');
      }
      if (window >= 384) {
        expect(move, (dx: 0.0, dy: 0.0), reason: 'unchanged at $window dp');
      }
    }
  });

  group('source contract', () {
    final source = File('lib/main.dart').readAsStringSync();

    test('the home panel uses the header, English only, no _t()', () {
      expect(source, contains('const header = WinsHomeBrandHeader();'));
      expect(source, contains('_buildHomeBrandHeader('));
      expect(source.contains("_t('Part of Winthos AI')"), isFalse);
      expect(source.contains('_t("Part of Winthos AI")'), isFalse);
      expect(source.contains("'assets/icon/app_icon.webp'"), isTrue);
      // The old inline 124px logo must be gone from the panel.
      expect(source.contains('height: 124,\n'), isFalse);
    });

    test('no locale table carries a translation of the subtitle', () {
      // Only the constant itself may hold the English text.
      expect(source.contains("'Part of Winthos AI':"), isFalse);
      expect(source.contains('"Part of Winthos AI":'), isFalse);
      expect(source, contains("static const String subtitle = 'Part of Winthos AI';"));
    });
  });
}
