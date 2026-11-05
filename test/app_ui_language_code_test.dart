import 'dart:ui';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/locale_resolution.dart';

void main() {
  test('Burmese anywhere in the ordered list wins over an unsupported first', () {
    expect(appUiLanguageCode(const [Locale('th'), Locale('my')]), 'my');
  });
  test('first supported language in device order decides', () {
    expect(appUiLanguageCode(const [Locale('en'), Locale('my')]), 'en');
    expect(appUiLanguageCode(const [Locale('my', 'MM')]), 'my');
  });
  test('German is not a supported locale: [de, my] is Burmese, [de] English', () {
    expect(appUiLanguageCode(const [Locale('de'), Locale('my')]), 'my');
    expect(appUiLanguageCode(const [Locale('de', 'DE')]), 'en');
  });
  test('always the language resolveAppLocale picks', () {
    for (final list in const <List<Locale>>[
      [Locale('de'), Locale('my')],
      [Locale('fr'), Locale('en')],
      [Locale('my', 'MM'), Locale('en')],
      [],
    ]) {
      expect(appUiLanguageCode(list),
          resolveAppLocale(list, kSupportedLocales).languageCode);
    }
  });
  test('empty or unknown lists fall back to English', () {
    expect(appUiLanguageCode(null), 'en');
    expect(appUiLanguageCode(const [Locale('fr')]), 'en');
  });
}
