import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _body(String source, String startMarker, String endMarker) {
  final start = source.indexOf(startMarker);
  final end = source.indexOf(endMarker, start + startMarker.length);
  expect(start, greaterThanOrEqualTo(0), reason: 'missing $startMarker');
  expect(end, greaterThan(start), reason: 'missing $endMarker');
  return source.substring(start, end);
}

void main() {
  final root = Platform.environment['WINS_SOURCE_ROOT'] ?? '.';
  final mainSource = File('$root/lib/main.dart').readAsStringSync();
  final securitySource =
      File('$root/lib/local_security.dart').readAsStringSync();

  test('APP-08 local-state reset is debug-mode only', () {
    final init = _body(
      mainSource,
      'void initState() {',
      'void _startBrowserBridgeAppIpc()',
    );
    expect(init, contains('const resetLocalState = kDebugMode &&'));
    expect(init, contains("bool.fromEnvironment('WINS_RESET_LOCAL_STATE'"));
    expect(init, isNot(contains('flutter build ios --release')));
  });

  test('APP-12 payment origins are independent of gateway defines', () {
    expect(
      securitySource,
      contains(
          "const String kReviewedPaymentBase = 'https://sync.winsvpn.org';"),
    );
    expect(securitySource, contains('compiledTrustedPaymentHosts('));
    expect(
        securitySource, contains('isReleaseBuild ? releaseCsv : overrideCsv'));

    final tracked = _body(
      mainSource,
      'String _trackedPaymentUrl(',
      'String _extractReferralCodeFromLink(',
    );
    expect(tracked, contains('validatedPaymentUrl('));
    expect(tracked, contains('kReviewedPaymentBase'));

    final launch = _body(
      mainSource,
      'Future<void> _launchPaymentURL(',
      'Future<void> _promptAppUpdateRequired()',
    );
    expect(launch, contains('validatedPaymentUrl(url)'));
    expect(
      RegExp(r'_launchPaymentURL\(\s*_trackedPaymentUrl\(')
          .allMatches(mainSource)
          .length,
      5,
    );
  });
}
