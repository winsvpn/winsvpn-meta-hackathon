import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Direct decode of the desktop/Apple release injection lists for
/// `WINS_WINN3_DUAL_AUTH`. Mirrors `android_winn3_dual_auth_define_test.dart`:
/// Flutter keeps the LAST `NAME=` occurrence, so a duplicate or a debug leak
/// has to fail here instead of shipping.
///
/// Windows and Linux parsers consume `auth_ed25519` / `auth_mldsa65` and bind
/// both paths into the engine document, so Release may flip the define.
/// Windows flips it in the Release-only CMake enabled blob; Linux flips it
/// only through the canonical release producer after AOT capability proof.
/// Apple cdatapath has no DualAuth fields; iOS and macOS stay BLOCKED.
void main() {
  const dualAuthTrue = 'WINS_WINN3_DUAL_AUTH=true';
  const dualAuthTrueBlob = 'V0lOU19XSU5OM19EVUFMX0FVVEg9dHJ1ZQ==';

  List<String> decodeCsvBlobs(String csv) {
    return csv
        .split(',')
        .map((token) => token.trim())
        .where(
          (token) =>
              token.isNotEmpty &&
              !token.contains(r'${') &&
              !token.startsWith(r'$('),
        )
        .map((token) {
          try {
            return utf8.decode(base64Decode(token));
          } on FormatException {
            return '';
          }
        })
        .where((entry) => entry.startsWith('WINS_WINN3_'))
        .toList();
  }

  List<String> cmakeQuotedSets(String source, String name) {
    final pattern = RegExp('set\\(\\s*${RegExp.escape(name)}\\s+"([^"]*)"\\s*\\)');
    return pattern.allMatches(source).map((match) => match.group(1)!).toList();
  }

  test('the compiled dual-auth true blob is exactly Android C-8 encoding', () {
    expect(base64Encode(utf8.encode(dualAuthTrue)), dualAuthTrueBlob);
    final gradle = File('android/app/build.gradle.kts').readAsStringSync();
    expect(gradle.split(dualAuthTrueBlob).length - 1, 1);
  });

  test('Windows Release ENABLED_BLOB emits WINS_WINN3_DUAL_AUTH=true once', () {
    final cmake =
        File('windows/flutter/Winn3DescriptorRing.cmake').readAsStringSync();
    final enabled = cmakeQuotedSets(cmake, 'WINN3_WINDOWS_ENABLED_BLOB');
    expect(enabled, hasLength(1));
    final decoded = decodeCsvBlobs(enabled.single);
    expect(
      decoded.where((entry) => entry.startsWith('WINS_WINN3_DUAL_AUTH=')),
      [dualAuthTrue],
    );
    expect(
      decoded.where((entry) => entry.startsWith('WINS_WINN3_ENABLED_PLATFORMS=')),
      ['WINS_WINN3_ENABLED_PLATFORMS=windows'],
    );
  });

  test('Windows Debug ring cannot advertise WINS_WINN3_DUAL_AUTH', () {
    final cmake =
        File('windows/flutter/Winn3DescriptorRing.cmake').readAsStringSync();
    final ring = cmakeQuotedSets(cmake, 'WINN3_RING_DART_DEFINES');
    expect(ring, hasLength(1));
    final decoded = decodeCsvBlobs(ring.single);
    expect(
      decoded.where((entry) => entry.startsWith('WINS_WINN3_DUAL_AUTH=')),
      isEmpty,
      reason: 'WINN3_RING_DART_DEFINES is compiled for Debug/Profile',
    );
    expect(ring.single.contains(dualAuthTrueBlob), isFalse);
    final backend =
        File('windows/flutter/winn3_tool_backend.cmd').readAsStringSync();
    expect(backend.contains(dualAuthTrueBlob), isFalse);
    expect(backend.contains('if /I "%~2"=="Release"'), isTrue);
  });

  test('Linux dual-auth is producer-owned and absent from direct builds', () {
    final cmake =
        File('linux/flutter/Winn3DescriptorRing.cmake').readAsStringSync();
    expect(
      cmake.split(dualAuthTrueBlob).length - 1,
      0,
      reason: 'Linux dual-auth is deliberately absent from CMake: direct '
          'Flutter/CMake builds must not advertise the release-only '
          'capability',
    );
    final ring = cmakeQuotedSets(cmake, 'WINN3_RING_DART_DEFINES');
    expect(ring, isNotEmpty);
    final decoded = decodeCsvBlobs(ring.first);
    expect(
      decoded.where((entry) => entry.startsWith('WINS_WINN3_DUAL_AUTH=')),
      isEmpty,
    );

    final producer = File('tools/build_linux_release.sh').readAsStringSync();
    expect(
      producer,
      contains(
        'WINS_WINN3_DUAL_AUTH is producer-owned for Linux release builds',
      ),
      reason: 'The producer must refuse environment overrides so the single '
          'audited argv entry cannot be duplicated or forged',
    );
    expect(
      producer,
      contains('"winsvpn-linux-compiled-capability-proof-v3"'),
      reason: 'The define must stay bound to the compiled capability proof',
    );
    expect(producer, contains('"define": "WINS_WINN3_DUAL_AUTH=true"'));
  });

  test('Linux Debug/Profile unconditional ring cannot advertise dual-auth', () {
    final cmake =
        File('linux/flutter/Winn3DescriptorRing.cmake').readAsStringSync();
    final ring = cmakeQuotedSets(cmake, 'WINN3_RING_DART_DEFINES');
    expect(ring, isNotEmpty);
    expect(ring.first.contains(r'${'), isFalse);
    final decoded = decodeCsvBlobs(ring.first);
    expect(
      decoded.where((entry) => entry.startsWith('WINS_WINN3_DUAL_AUTH=')),
      isEmpty,
    );
    expect(
      decoded.where((entry) => entry.startsWith('WINS_WINN3_ENABLED_PLATFORMS=')),
      ['WINS_WINN3_ENABLED_PLATFORMS=linux'],
    );
    final backend =
        File('linux/flutter/winn3_tool_backend.sh').readAsStringSync();
    expect(backend.contains(dualAuthTrueBlob), isFalse);
  });

  test('iOS and macOS release rings stay BLOCKED / fail-closed', () {
    for (final spec in <(String, String)>[
      ('ios/Flutter/Winn3DescriptorRing.xcconfig', 'ios'),
      ('macos/Flutter/Winn3DescriptorRing.xcconfig', 'macos'),
    ]) {
      final source = File(spec.$1).readAsStringSync();
      final lines = source
          .split('\n')
          .where((line) => line.startsWith('DART_DEFINES='))
          .toList();
      expect(lines, hasLength(1), reason: spec.$1);
      final decoded = decodeCsvBlobs(lines.single.split('=').sublist(1).join('='));
      expect(
        decoded.where((entry) => entry.startsWith('WINS_WINN3_DUAL_AUTH=')),
        isEmpty,
        reason: '${spec.$1} is BLOCKED: Apple cdatapath cannot ingest DualAuth',
      );
      expect(
        decoded.where((entry) => entry.startsWith('WINS_WINN3_ENABLED_PLATFORMS=')),
        ['WINS_WINN3_ENABLED_PLATFORMS=${spec.$2}'],
      );
      expect(source.contains(dualAuthTrueBlob), isFalse, reason: spec.$1);
    }
  });

  test('Debug xcconfigs cannot accidentally advertise dual-auth', () {
    for (final path in <String>[
      'ios/Flutter/Debug.xcconfig',
      'macos/Flutter/Flutter-Debug.xcconfig',
    ]) {
      final source = File(path).readAsStringSync();
      expect(source.contains('Winn3DescriptorRing.xcconfig'), isFalse,
          reason: path);
      expect(source.contains(dualAuthTrueBlob), isFalse, reason: path);
      expect(
        decodeCsvBlobs(source)
            .where((entry) => entry.startsWith('WINS_WINN3_DUAL_AUTH=')),
        isEmpty,
        reason: path,
      );
    }
  });
}
