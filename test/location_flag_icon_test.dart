import 'dart:io';

import 'package:country_flags/country_flags.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/location_flag_icon.dart';

void main() {
  test('accepts country codes and regional-indicator flags', () {
    expect(countryCodeFromFlagValue(' es '), 'ES');
    expect(countryCodeFromFlagValue('🇪🇸'), 'ES');
    expect(countryCodeFromFlagValue('US'), 'US');
    expect(countryCodeFromFlagValue('🇲🇲'), 'MM');
  });

  test('rejects unsupported values instead of rendering letter glyphs', () {
    expect(countryCodeFromFlagValue(null), isNull);
    expect(countryCodeFromFlagValue(''), isNull);
    expect(countryCodeFromFlagValue('🌐'), isNull);
    expect(countryCodeFromFlagValue('ZZ'), isNull);
    expect(countryCodeFromFlagValue('ES\nUS'), isNull);
  });

  test('all canonical location surfaces use the image flag widget', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(
      RegExp(r'LocationFlagIcon\(').allMatches(source).length,
      3,
      reason:
          'The picker, free-server selector, and dashboard selector must share the Windows-safe renderer.',
    );
    expect(source, isNot(contains('leading: Text(_normalizeFlag(')));
    expect(source, isNot(contains("? _normalizeFlag(selectedFree['flag'])")));
  });

  testWidgets('renders Spain as a local image flag with an accessible label',
      (tester) async {
    final semantics = tester.ensureSemantics();
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: LocationFlagIcon(
            flagValue: 'ES',
            locationName: 'Spain',
          ),
        ),
      ),
    );

    expect(find.byType(CountryFlag), findsOneWidget);
    expect(find.text('ES'), findsNothing);
    expect(find.text('🇪🇸'), findsNothing);
    expect(find.bySemanticsLabel('Spain flag'), findsOneWidget);
    semantics.dispose();
  });

  testWidgets('uses an accessible globe for unknown locations', (tester) async {
    final semantics = tester.ensureSemantics();
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: LocationFlagIcon(
            flagValue: '🌐',
            locationName: 'Automatic',
          ),
        ),
      ),
    );

    expect(find.byIcon(Icons.public), findsOneWidget);
    expect(find.byType(CountryFlag), findsNothing);
    expect(find.bySemanticsLabel('Automatic location'), findsOneWidget);
    semantics.dispose();
  });

  test('overrides bogus GL flag with deterministic slug and name fallback', () {
    expect(
      countryCodeFromFlagValue('GL', locationName: 'Canada', slug: 'canada-ca1'),
      'CA',
    );
    expect(
      countryCodeFromFlagValue('🇬🇱', locationName: 'Germany', slug: 'germany-de1'),
      'DE',
    );
    expect(
      countryCodeFromFlagValue('GL', locationName: 'Spain', slug: 'spain-madrid'),
      'ES',
    );
    expect(
      countryCodeFromFlagValue('GL', locationName: 'Nuuk', slug: 'greenland-01'),
      'GL',
    );
    expect(
      countryCodeFromFlagValue(null, slug: 'canada-ca1'),
      'CA',
    );
    expect(
      countryCodeFromFlagValue('🌐', locationName: 'Germany'),
      'DE',
    );
  });
}

