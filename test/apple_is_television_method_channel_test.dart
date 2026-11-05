import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Apple has no TV form factor in this product. The method-channel contract
/// still requires an `isTelevision` handler because Dart names the method, so
/// iOS and macOS must answer `false` instead of `FlutterMethodNotImplemented`.
void main() {
  const bridges = <String>[
    'ios/Runner/AppDelegate.swift',
    'macos/Runner/MainFlutterWindow.swift',
  ];

  String caseBody(String source, String method) {
    final start = source.indexOf('case "$method":');
    expect(start, greaterThanOrEqualTo(0), reason: 'missing case "$method"');
    final next = source.indexOf('\n    case ', start + 1);
    expect(next, greaterThan(start), reason: 'unterminated case "$method"');
    return source.substring(start, next);
  }

  for (final sourcePath in bridges) {
    test('$sourcePath answers isTelevision with false', () {
      final source = File(sourcePath).readAsStringSync();
      final body = caseBody(source, 'isTelevision');
      expect(body, contains('result(false)'));
      expect(body, isNot(contains('result(true)')));
      expect(body, isNot(contains('FlutterMethodNotImplemented')));
    });
  }

  test('Dart never treats Apple as TV and only probes Android', () {
    final dart = File('lib/main.dart').readAsStringSync();

    expect(dart, contains('On iOS/macOS it'));
    expect(dart, contains('stays phone (no TV form factor in this product).'));

    final earlyStart = dart.indexOf('if (Platform.isAndroid) {');
    final earlyCall = dart.indexOf("invokeMethod('isTelevision')");
    expect(earlyStart, greaterThanOrEqualTo(0));
    expect(earlyCall, greaterThan(earlyStart));
    expect(earlyCall, lessThan(dart.indexOf('registerNativeComponentLicenses();')));

    final refreshStart = dart.indexOf('Future<void> _refreshFormFactor() async {');
    final refreshEnd = dart.indexOf('\n  }', refreshStart);
    expect(refreshStart, greaterThanOrEqualTo(0));
    expect(refreshEnd, greaterThan(refreshStart));
    final refresh = dart.substring(refreshStart, refreshEnd);
    expect(refresh, contains('if (!Platform.isAndroid) return;'));
    expect(refresh, contains("invokeMethod('isTelevision')"));
  });
}
