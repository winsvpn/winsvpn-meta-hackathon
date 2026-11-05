import 'dart:ui' show Locale;

/// The locale the app falls back to when the device asks for nothing we can
/// serve.
const Locale kFallbackLocale = Locale('en');

/// Locales this app declares support for, most-authoritative first.
///
/// IMPORTANT: this list is the single source of truth for what the app
/// declares it localizes. Keep it in step with `CFBundleLocalizations` in
/// `ios/Runner/Info.plist` (the `tools/ios_localization_gate.py --update`
/// regenerates the plist from this list).
///
/// `my` is now declared because the app's strings ARE extracted and translated:
/// `lib/l10n/app_en.arb` is the template and `lib/l10n/app_my.arb` carries the
/// full Burmese translation (79/79 keys, syllable-validator-clean, and the
/// duress SMS/alert strings dual-family model-verified). Declaring `my` makes
/// both the ARB output and Flutter's Material/Cupertino chrome render in
/// Burmese for a Burmese device.
const List<Locale> kSupportedLocales = <Locale>[
  Locale('en'),
  Locale('my'),
];

/// Picks the app locale from the device's ordered language preferences.
///
/// Flutter's built-in resolution is *almost* right, but its last step is to
/// return `supportedLocales.first` when nothing matches — an arbitrary choice
/// driven by list order rather than by anything a user decided. This resolver
/// ends at [kFallbackLocale] instead, which is always a language the strings
/// were actually authored in.
///
/// [preferred] is the device's language list, most-preferred first — the value
/// Flutter passes to `localeListResolutionCallback`. It is null or empty before
/// the platform has reported anything, in which case the fallback applies.
///
/// Each preferred locale is tried in turn, and for each one the match is
/// narrowed step by step, so the user's *ordering* always beats the precision
/// of a later match:
///   1. language + script + country (an exact match)
///   2. language + script
///   3. language + country
///   4. language alone
Locale resolveAppLocale(
  List<Locale>? preferred,
  Iterable<Locale> supported,
) {
  final supportedList = supported.toList(growable: false);
  if (supportedList.isEmpty) return kFallbackLocale;

  for (final locale in preferred ?? const <Locale>[]) {
    for (final candidate in supportedList) {
      if (candidate.languageCode == locale.languageCode &&
          candidate.scriptCode == locale.scriptCode &&
          candidate.countryCode == locale.countryCode) {
        return candidate;
      }
    }

    // Script before country: for zh-Hans vs zh-Hant the script decides
    // legibility, the country does not.
    if (locale.scriptCode != null) {
      for (final candidate in supportedList) {
        if (candidate.languageCode == locale.languageCode &&
            candidate.scriptCode == locale.scriptCode) {
          return candidate;
        }
      }
    }

    if (locale.countryCode != null) {
      for (final candidate in supportedList) {
        if (candidate.languageCode == locale.languageCode &&
            candidate.countryCode == locale.countryCode) {
          return candidate;
        }
      }
    }

    // Turns a device set to `my_MM` into our generic `my`.
    for (final candidate in supportedList) {
      if (candidate.languageCode == locale.languageCode) {
        return candidate;
      }
    }
  }

  for (final candidate in supportedList) {
    if (candidate.languageCode == kFallbackLocale.languageCode) {
      return candidate;
    }
  }

  return supportedList.first;
}

/// The language code of the in-file `_t` table in lib/main.dart: exactly the
/// app locale [resolveAppLocale] picks from the same ordered device list, so
/// `_t` strings and the ARB and Material strings on one screen are always the
/// same language (`en` or `my`), never a third.
String appUiLanguageCode(List<Locale>? deviceLocales) =>
    resolveAppLocale(deviceLocales, kSupportedLocales).languageCode;
