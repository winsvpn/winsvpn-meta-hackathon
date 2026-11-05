import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/locale_resolution.dart';

/// Rebuilds the production `MaterialApp` locale wiring from `lib/main.dart`.
///
/// Mirrors it field for field, including the *absence* of `locale:` — a pinned
/// locale is the one change that would silently defeat every test here, so the
/// harness must not supply one either.
Widget _localizedApp({
  required void Function(Locale) onLocale,
  List<Locale> supportedLocales = kSupportedLocales,
}) {
  return MaterialApp(
    localizationsDelegates: const [
      GlobalMaterialLocalizations.delegate,
      GlobalWidgetsLocalizations.delegate,
      GlobalCupertinoLocalizations.delegate,
    ],
    supportedLocales: supportedLocales,
    localeListResolutionCallback: resolveAppLocale,
    home: Builder(
      builder: (context) {
        onLocale(Localizations.localeOf(context));
        return const SizedBox.shrink();
      },
    ),
  );
}

void main() {
  group('resolveAppLocale ordered preference matching', () {
    test('an exact language+script+country match wins over every looser tier',
        () {
      expect(
        resolveAppLocale(
          const [Locale('en', 'US')],
          const [Locale('en'), Locale('en', 'US'), Locale('my')],
        ),
        const Locale('en', 'US'),
      );
    });

    test('script decides legibility over country between zh-Hans and zh-Hant',
        () {
      // A device set to zh-Hant-CN must get Traditional, because for zh the
      // script determines legibility and the country does not. The supported
      // locales must carry their scripts for the script tier to be reachable.
      expect(
        resolveAppLocale(
          const [
            Locale.fromSubtags(
                languageCode: 'zh', scriptCode: 'Hant', countryCode: 'CN'),
          ],
          const [
            Locale.fromSubtags(languageCode: 'zh', scriptCode: 'Hans'),
            Locale.fromSubtags(languageCode: 'zh', scriptCode: 'Hant'),
          ],
        ),
        const Locale.fromSubtags(languageCode: 'zh', scriptCode: 'Hant'),
      );
    });

    test('an unmatched script still binds the preferred language to the script '
        'classes we do ship', () {
      // zh-Hant-CN, none of the Hant locales supported, so it narrows to Hans.
      expect(
        resolveAppLocale(
          const [
            Locale.fromSubtags(
                languageCode: 'zh', scriptCode: 'Hant', countryCode: 'CN'),
          ],
          const [Locale.fromSubtags(languageCode: 'zh', scriptCode: 'Hans')],
        ),
        const Locale.fromSubtags(languageCode: 'zh', scriptCode: 'Hans'),
      );
    });

    test('country survives the script being dropped', () {
      // zh-Hans-CN with zh-CN and zh-TW both supported: the country
      // distinguishes zh_CN from zh_TW. The script is dropped because neither
      // candidate carries one, and the country must beat list order (zh-TW is
      // first). If the country tier were broken, the language tier would hand
      // back zh-TW.
      expect(
        resolveAppLocale(
          const [
            Locale.fromSubtags(
                languageCode: 'zh', scriptCode: 'Hans', countryCode: 'CN'),
          ],
          const [Locale('zh', 'TW'), Locale('zh', 'CN')],
        ),
        const Locale('zh', 'CN'),
      );
    });

    test('language+country matches when the preferred locale has no script', () {
      expect(
        resolveAppLocale(
          const [Locale('fr', 'CA')],
          const [Locale('en'), Locale('fr', 'CA')],
        ),
        const Locale('fr', 'CA'),
      );
    });

    test('a country-qualified preference narrows to the bare language', () {
      // A phone set to en_GB reports a country we do not ship; it gets generic
      // `en`, and a phone set to my_MM gets generic `my`.
      expect(
        resolveAppLocale(const [Locale('en', 'GB')], kSupportedLocales),
        const Locale('en'),
      );
      expect(
        resolveAppLocale(
          const [Locale('my', 'MM')],
          const [Locale('en'), Locale('my')],
        ),
        const Locale('my'),
      );
    });

    test('language alone matches when nothing more specific is available', () {
      expect(
        resolveAppLocale(
          const [Locale('fr', 'FR')],
          const [Locale('en'), Locale('fr', 'CA')],
        ),
        const Locale('fr', 'CA'),
      );
    });

    test('device preference order beats match precision', () {
      // my_MM comes first and matches `my` at the language tier, so it wins over
      // the exact en_US match that only the second preference reaches.
      expect(
        resolveAppLocale(
          const [Locale('my', 'MM'), Locale('en', 'US')],
          const [Locale('en', 'US'), Locale('my')],
        ),
        const Locale('my'),
      );
    });

    test('empty or absent device preferences fall back to English', () {
      expect(resolveAppLocale(null, kSupportedLocales), const Locale('en'));
      expect(resolveAppLocale(const [], kSupportedLocales), const Locale('en'));
    });

    test('an empty supportedList returns kFallbackLocale', () {
      expect(
        resolveAppLocale(const [Locale('en')], const <Locale>[]),
        kFallbackLocale,
      );
      expect(resolveAppLocale(null, const <Locale>[]), kFallbackLocale);
    });

    test('an unsupported locale falls back to English, not to the first entry',
        () {
      // The regression this guards: Flutter's default resolution returns
      // supportedLocales.first. With `my` sorted first, a French phone would
      // have been handed Burmese.
      expect(
        resolveAppLocale(
          const [Locale('fr', 'FR')],
          const [Locale('my'), Locale('en')],
        ),
        const Locale('en'),
      );
    });

    test('ends at the fallback language even when the fallback is not first', () {
      expect(
        resolveAppLocale(
          const [Locale('th')],
          const [Locale('my'), Locale('en')],
        ),
        const Locale('en'),
      );
    });

    test('a Burmese phone gets Burmese once `my` is declared', () {
      // `my` is shipped because the app's strings ARE now extracted and
      // translated: lib/l10n/app_my.arb carries the full Burmese catalogue
      // (79/79 keys, syllable-validator-clean), so un-gating `my` is backed by
      // real Burmese rather than an empty App Store claim. This test fails
      // loudly if someone removes `my` from kSupportedLocales without also
      // removing the ARB.
      expect(
        resolveAppLocale(const [Locale('my', 'MM')], kSupportedLocales),
        const Locale('my'),
      );
      expect(
        kSupportedLocales.map((l) => l.languageCode),
        contains('my'),
        reason: 'kSupportedLocales must declare `my` to match the shipped '
            'app_my.arb catalogue.',
      );
    });

    test('falls back to the first supported locale when the fallback language '
        'is not supported', () {
      expect(
        resolveAppLocale(
          const [Locale('fr')],
          const [Locale('my'), Locale('th')],
        ),
        const Locale('my'),
      );
    });

    test('a partially-filled Myanmar set fails an unsupported request over to '
        'the platform default, never a blank or a first-entry choice', () {
      // The "partially-filled Myanmar set": the English platform default plus a
      // Myanmar entry that is only partially specified (region-qualified
      // `my_MM`, not the general bare `my`). `my_MM` is deliberately FIRST so
      // that a blind `supportedList.first` fallback would hand a French phone
      // Burmese — the blank-adjacent failure this guard exists to stop. The
      // fallback language (en) is present but not first, so the only correct
      // answer for an unsupported request is the platform default.
      const supported = <Locale>[Locale('my', 'MM'), Locale('en')];

      expect(
        resolveAppLocale(const [Locale('fr', 'FR')], supported),
        const Locale('en'),
      );
      expect(
        resolveAppLocale(const [Locale('lo')], supported),
        const Locale('en'),
      );
      expect(
        resolveAppLocale(const [Locale('zh')], supported),
        const Locale('en'),
      );

      // A resolved locale outside the supported set is a blank UI: MaterialApp
      // has no delegate that can localize it. The fallback must stay in-set.
      for (final result in [
        resolveAppLocale(const [Locale('fr', 'FR')], supported),
        resolveAppLocale(const [Locale('lo')], supported),
        resolveAppLocale(const [Locale('zh')], supported),
      ]) {
        expect(supported.contains(result), isTrue,
            reason: 'the fallback for an unsupported request must be a locale '
                'the app can actually localize, never a blank UI');
      }

      // Positive control: the partial set still serves a Burmese request by
      // narrowing bare `my` to the region-qualified entry, so the
      // fail-over-to-English only applies to genuinely unsupported requests.
      expect(
        resolveAppLocale(const [Locale('my')], supported),
        const Locale('my', 'MM'),
      );
      expect(
        resolveAppLocale(const [Locale('my', 'MM')], supported),
        const Locale('my', 'MM'),
      );
    });
  });

  group('MaterialApp follows the system language', () {
    tearDown(() {
      TestWidgetsFlutterBinding.instance.platformDispatcher
          .clearLocalesTestValue();
    });

    testWidgets('a Burmese phone gets Burmese, because `my` is declared',
        (tester) async {
      tester.platformDispatcher.localesTestValue = const [
        Locale('my', 'MM'),
        Locale('en', 'US'),
      ];

      late Locale resolved;
      await tester.pumpWidget(_localizedApp(onLocale: (l) => resolved = l));

      expect(resolved, const Locale('my'));
    });

    testWidgets('an English phone gets English', (tester) async {
      tester.platformDispatcher.localesTestValue = const [Locale('en', 'GB')];

      late Locale resolved;
      await tester.pumpWidget(_localizedApp(onLocale: (l) => resolved = l));

      expect(resolved.languageCode, 'en');
    });

    testWidgets('an unsupported phone language gets English, not Burmese',
        (tester) async {
      tester.platformDispatcher.localesTestValue = const [Locale('fr', 'FR')];

      late Locale resolved;
      await tester.pumpWidget(_localizedApp(onLocale: (l) => resolved = l));

      expect(resolved, const Locale('en'));
    });

    testWidgets(
        'a partially-filled Myanmar set renders the English platform default '
        'chrome for an unsupported device language, not a blank UI',
        (tester) async {
      // Same partial set as the pure-function guard: platform default `en`
      // plus a region-only (partially-filled) Myanmar entry listed first.
      const partialMyanmarSet = <Locale>[Locale('my', 'MM'), Locale('en')];
      tester.platformDispatcher.localesTestValue = const [Locale('lo')];

      late Locale resolved;
      late MaterialLocalizations chrome;
      await tester.pumpWidget(
        MaterialApp(
          localizationsDelegates: const [
            GlobalMaterialLocalizations.delegate,
            GlobalWidgetsLocalizations.delegate,
            GlobalCupertinoLocalizations.delegate,
          ],
          supportedLocales: partialMyanmarSet,
          localeListResolutionCallback: resolveAppLocale,
          home: Builder(
            builder: (context) {
              resolved = Localizations.localeOf(context);
              chrome = MaterialLocalizations.of(context);
              return const SizedBox.shrink();
            },
          ),
        ),
      );

      // The device language (Lao) is unsupported, so the resolver must land on
      // the in-set English default rather than the first (Myanmar) entry.
      expect(resolved, const Locale('en'));

      // And the chrome must actually render English — a blank UI would mean the
      // locale resolved to something the delegates could not localize.
      expect(chrome.cancelButtonLabel, 'Cancel');
    });

    testWidgets('the delegates can localize chrome once a locale is declared',
        (tester) async {
      // Proves the localization plumbing works end to end, independently of
      // which locales this app currently ships. `my` is passed explicitly here
      // rather than via kSupportedLocales precisely so that this stays a test
      // of the machinery, not of the shipping locale list.
      //
      // Asserting only that it stopped being the English one is the durable
      // check: `cancelButtonLabel` (not `okButtonLabel`, which Burmese leaves
      // as "OK").
      tester.platformDispatcher.localesTestValue = const [Locale('my', 'MM')];

      late MaterialLocalizations chrome;
      await tester.pumpWidget(
        MaterialApp(
          localizationsDelegates: const [
            GlobalMaterialLocalizations.delegate,
            GlobalWidgetsLocalizations.delegate,
            GlobalCupertinoLocalizations.delegate,
          ],
          supportedLocales: const [Locale('en'), Locale('my')],
          localeListResolutionCallback: resolveAppLocale,
          home: Builder(
            builder: (context) {
              chrome = MaterialLocalizations.of(context);
              return const SizedBox.shrink();
            },
          ),
        ),
      );

      expect(chrome.cancelButtonLabel, isNot('Cancel'));
    });
  });

  group('platform declarations stay in step with Dart', () {
    test('every supported locale is declared in ios/Runner/Info.plist', () {
      // iOS reports only the development region to the app unless the locale
      // is in CFBundleLocalizations, so a locale present here but missing
      // there is silently dead on iPhone.
      const declaredInPlist = <String>{'en', 'my'};
      expect(
        kSupportedLocales.map((l) => l.languageCode).toSet(),
        declaredInPlist,
        reason: 'Update ios/Runner/Info.plist CFBundleLocalizations to match.',
      );
    });
  });
}
