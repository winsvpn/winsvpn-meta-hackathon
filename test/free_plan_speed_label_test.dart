import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/l10n/app_localizations.dart';
import 'package:wins_vpn/locale_resolution.dart';

void main() {
  test('every supported language states the directional free-plan limit',
      () async {
    for (final locale in kSupportedLocales) {
      final strings = await AppLocalizations.delegate.load(locale);
      expect(strings.tryFreeServerLimited, contains('100 Mbps'),
          reason: '${locale.languageCode} activation label');
      expect(strings.freeServerLimited, contains('100 Mbps'),
          reason: '${locale.languageCode} server label');
      expect(strings.tryFreeServerLimited, isNot(strings.tryFreeServer));
    }
  });
}
