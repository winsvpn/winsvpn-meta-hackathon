// Android AmneziaWG handshake timing: a source contract across Dart, Kotlin
// and the Android JNI UAPI adapter.
//
// Why this file exists. WireGuard retries a lost handshake after a fixed 5 s
// (RekeyTimeout), so on a lossy cellular path one lost initiation or response
// pushes a cold connect past the 4 s tap-to-traffic target. The L30 lab
// (awg-hardening-20260924, pinned amneziawg-go v3.1.20260828 on both ends)
// measured the effect of RekeyTimeout = 3 with MaxHandshakeAttempts = 30.
// Both keys are client-only in AmneziaWG 3: no gateway parity, no hub change.
//
// The emission is Android-only on purpose. The Android converters
// (AwgUserspaceConfig.kt and tools/amneziawg_android_official_jni) map both
// keys to UAPI; the Windows and Linux INI allowlists and the Apple parser do
// not know them and would refuse the whole config. So this test pins three
// facts together: main.dart emits the keys only under Platform.isAndroid,
// both Android converters understand them, and the product of the two keeps
// WireGuard's 90 s give-up window (18 attempts x 5 s).

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _read(String path) => File(path).readAsStringSync();

/// The body of `_buildRawAmneziaConfig`, up to the INI's `[Peer]` header.
String _rawConfigWriter(String main) {
  final start = main.indexOf('String _buildRawAmneziaConfig(');
  expect(start, greaterThanOrEqualTo(0),
      reason: 'lib/main.dart no longer defines _buildRawAmneziaConfig');
  final peer = main.indexOf('\n[Peer]\n', start);
  expect(peer, greaterThan(start),
      reason: '_buildRawAmneziaConfig no longer writes a [Peer] section');
  return main.substring(start, peer);
}

void main() {
  group('Android AWG handshake timing', () {
    late String writer;
    setUpAll(() => writer = _rawConfigWriter(_read('lib/main.dart')));

    test(
        'main.dart emits RekeyTimeout and MaxHandshakeAttempts on Android only',
        () {
      final decl = RegExp(
        r"final String awgHandshakeTimingLines =\s*Platform\.isAndroid\s*"
        r"\?\s*'RekeyTimeout = (\d+)\\nMaxHandshakeAttempts = (\d+)'\s*"
        r":\s*'';",
      ).firstMatch(writer);
      expect(decl, isNotNull,
          reason: 'expected an Android-gated RekeyTimeout/MaxHandshakeAttempts '
              'declaration in _buildRawAmneziaConfig; any other platform must get ""');
      final rekey = int.parse(decl!.group(1)!);
      final attempts = int.parse(decl.group(2)!);
      expect(rekey, inInclusiveRange(1, 4),
          reason: 'a retry interval of 5 s or more cannot recover a lost '
              'handshake packet inside the 4 s connect target');
      expect(rekey * attempts, greaterThanOrEqualTo(90),
          reason: 'keep WireGuard\'s 90 s give-up window (18 x 5 s)');
    });

    test('the lines land inside [Interface], after H4 and before [Peer]', () {
      final h4 = writer.lastIndexOf('H4 = ');
      final use = writer.lastIndexOf(r'$awgHandshakeTimingLines');
      expect(h4, greaterThan(0));
      expect(use, greaterThan(h4),
          reason: 'the timing keys must be written into the [Interface] block');
    });

    test('both Android UAPI converters map the two keys', () {
      final kotlin = _read(
          'android/app/src/main/kotlin/org/winsvpn/app/AwgUserspaceConfig.kt');
      expect(kotlin, contains('"rekeytimeout" to "rekey_timeout"'));
      expect(kotlin,
          contains('"maxhandshakeattempts" to "max_handshake_attempts"'));
      final jni = _read('tools/amneziawg_android_official_jni/uapi_adapt.go');
      expect(jni, matches(RegExp(r'"rekeytimeout":\s*"rekey_timeout"')));
      expect(
          jni,
          matches(
              RegExp(r'"maxhandshakeattempts":\s*"max_handshake_attempts"')));
    });
  });
}
