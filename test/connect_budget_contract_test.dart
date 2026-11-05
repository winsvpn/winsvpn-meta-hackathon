import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/hub_request_window.dart';

int _integerDefault(String signature, String name) {
  final match = RegExp(
    '${RegExp.escape(name)}\\s*[:=]\\s*(\\d+)',
  ).firstMatch(signature);
  expect(match, isNotNull, reason: '$name default not found');
  return int.parse(match!.group(1)!);
}

String _readinessSignature(String source) {
  final match = RegExp(
    r'Future<bool> _waitForTunnelReady\(\s*\{([\s\S]*?)\}\) async \{',
  ).firstMatch(source);
  expect(match, isNotNull, reason: 'readiness declaration not found');
  return match!.group(1)!;
}

void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('source request deadlines do not grow', () {
    expect(
      kHubVerifyTotalDeadline.inMilliseconds,
      lessThanOrEqualTo(12000),
    );
    expect(
      kFreeStatusPreflightDeadline.inMilliseconds,
      lessThanOrEqualTo(6000),
    );
    expect(
      kNodeDiscoveryDeadline.inMilliseconds,
      lessThanOrEqualTo(10000),
    );
  });

  test('readiness defaults come from the complete signature', () {
    final signature = _readinessSignature(source);
    expect(_integerDefault(signature, 'attempts'), 18);
    expect(_integerDefault(signature, 'milliseconds'), 150);
    expect(_integerDefault(signature, 'minimumEngineReadyMs'), 1200);
    expect(_integerDefault(signature, 'stableReadySamples'), 2);

    final delayTotal =
        (_integerDefault(signature, 'attempts') - 1) *
            _integerDefault(signature, 'milliseconds');
    expect(delayTotal, 2550);
  });

  test('Android production retains its native proof window', () {
    final start = source.indexOf(
      'final defaultReadinessAttempts = _isApplePlatform',
    );
    expect(start, greaterThanOrEqualTo(0));
    final end = source.indexOf('} on PlatformException {', start);
    expect(end, greaterThan(start));
    final production = source.substring(start, end);

    expect(production, matches(RegExp(r'\?\s*128\b')));
    expect(production, contains('effectiveReadinessAttempts'));
    expect(production, contains('attempts: effectiveReadinessAttempts'));
    expect(
      production,
      contains('delay: const Duration(milliseconds: 250)'),
    );
    expect(
      production,
      contains('minimumEngineReadyMs: stealthActive ? 2200 : 200'),
    );
    expect(
      production,
      contains('stableReadySamples: stealthActive ? 2 : 1'),
    );
  });

  test('helper readiness read has the agreed timeout', () {
    final start = source.indexOf(
      'Future<Map<dynamic, dynamic>?> _latestTunnelReadiness()',
    );
    expect(start, greaterThanOrEqualTo(0));
    final end = source.indexOf(
      'Future<bool> _nativeWinn3SecurityRefusalReported',
      start,
    );
    expect(end, greaterThan(start));
    final helper = source.substring(start, end);

    expect(helper, contains(".invokeMethod('getTunnelReadiness')"));
    expect(helper, contains('.timeout(const Duration(seconds: 2))'));
  });
}
