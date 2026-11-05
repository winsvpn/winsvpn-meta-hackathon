import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// A-03 (audits 2026-08-28): the live-test smoke defines and the cleartext
/// route-probe User-Agent must be structurally inert in release builds.
///
/// These are const expressions over `kReleaseMode`, so the control itself is
/// compile-time. A test cannot evaluate `kReleaseMode == true` (tests run
/// debug), so this suite pins the SOURCE SHAPE that produces that evaluation:
/// each define's initializer must carry the `!kReleaseMode &&` (bool) or
/// `kReleaseMode ? '' :` (string) guard. If a refactor drops the guard, this
/// fails and the release artifact cannot be built until it is restored.
void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('live smoke defines are release-locked', () {
    for (final name in [
      'WINS_APPLE_LIVE_TUNNEL_SMOKE',
      'WINS_APPLE_LIVE_TUNNEL_SMOKE_DOUBLE_VPN',
      'WINS_APPLE_EXTERNAL_LEAK_AUDIT',
      'WINS_SPEED_TEST_SMOKE',
    ]) {
      final guard = '!kReleaseMode &&\n      bool.fromEnvironment(\n        \'$name\'';
      final guardAlt = '!kReleaseMode &&\n      bool.fromEnvironment(\'$name\'';
      expect(
        source.contains(guard) || source.contains(guardAlt),
        isTrue,
        reason: '$name lost its !kReleaseMode guard: a stale build define '
            'could arm automatic connect/probe/speed traffic in a release '
            'artifact (A-03)',
      );
    }
  });

  test('route probe user agent is forced empty in release', () {
    expect(
      source.contains(
        "static const String _routeProbeUserAgent = kReleaseMode\n      ? ''"),
      isTrue,
      reason: 'WINS_ROUTE_PROBE_USER_AGENT lost its kReleaseMode empty-string '
          'force: a release build could re-arm a product-identifying '
          'cleartext header (A-03)',
    );
  });

  test('speed test user agent carries no product identity', () {
    // A-02 (Daybreak): the speed-test UA names the product to third-party
    // measurement servers. It must stay brand-free.
    expect(source.contains("User-Agent', 'WinsVPN-Speedtest"), isFalse,
        reason: 'the speed test must not send a product-identifying '
            'User-Agent to third-party servers (A-02)');
    expect(source.contains('"WinsVPN-Speedtest/1.0"'), isFalse,
        reason: 'the speed test must not send a product-identifying '
            'User-Agent to third-party servers (A-02)');
  });

  /// The full body of the first declaration whose text starts with
  /// [signature], from its opening `{` to the matching `}`. Brace-balanced,
  /// so a nested block inside the method cannot end the slice early. String
  /// literals in lib/main.dart that contain braces are interpolations like
  /// `'$x'`, never bare `{`/`}` characters, so a character walk is sufficient.
  String balancedBody(String source, String signature) {
    final start = source.indexOf(signature);
    expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
    final open = source.indexOf('{', start);
    var depth = 0;
    for (var i = open; i < source.length; i++) {
      final c = source[i];
      if (c == '{') depth++;
      if (c == '}') {
        depth--;
        if (depth == 0) return source.substring(start, i + 1);
      }
    }
    fail('unbalanced braces after $signature');
  }

  test('pre-VPN geo is user-triggered, never automatic (A-01)', () {
    final initBody = balancedBody(
        source, 'void _startPostPrivacyConsentInitialization() {');
    expect(initBody.trim().endsWith('}'), isTrue,
        reason: 'the slice must be the whole method, not a prefix of it');
    expect(initBody.contains('_fetchPreVpnCountryCode()'), isFalse,
        reason: 'the post-consent startup path must NOT launch the pre-VPN '
            'geo lookup automatically (A-01): it leaves the device from the '
            'user\'s real IP to branded hosts on every launch.');
    expect(initBody.contains('_preVpnGeoUserRequested = true'), isFalse,
        reason: 'startup must not pre-arm the user-request flag either');
    final fetchStart = source.indexOf('Future<void> _fetchPreVpnCountryCode()');
    final fetchBody = source.substring(
        fetchStart, source.indexOf('Future<void> _fetchPreVpnCountryCodeNow'));
    expect(fetchBody.contains('if (!_preVpnGeoUserRequested) return;'), isTrue,
        reason: 'the geo fetch must be gated on an explicit user request '
            '(A-01)');
  });
}
