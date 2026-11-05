import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _functionBody(String source, String signature, String nextSignature) {
  final start = source.indexOf(signature);
  final end = source.indexOf(nextSignature, start);
  expect(start, greaterThanOrEqualTo(0));
  expect(end, greaterThan(start));
  return source.substring(start, end);
}

void main() {
  // The refreshes share the walk already in flight (L91). The shared walk is
  // a plain discovery walk: no forced latency probe.
  test('the shared discovery walk does not wait for latency telemetry', () {
    final source = File('lib/main.dart').readAsStringSync();
    final body = _functionBody(
      source,
      'Future<bool> _sharedNodeDiscovery() {',
      '  /// A settings restart deferred because the listing had not loaded',
    );
    expect(body, contains('walk = _fetchAvailableNodes().whenComplete('));
    expect(body, isNot(contains('forceLive')));
  });

  test('account config refresh does not wait for node latency telemetry', () {
    final source = File('lib/main.dart').readAsStringSync();
    final body = _functionBody(
      source,
      'Future<bool> _refreshVpnConfigForCurrentSelection(',
      'Future<bool> _waitForTunnelState(',
    );

    expect(
      body,
      contains(
        '_lastConfigRefreshHadLiveNodeListing = await _sharedNodeDiscovery();',
      ),
    );
    expect(body, isNot(contains('_fetchAvailableNodes(forceLive: true)')));
  });

  test('free config refresh does not wait for node latency telemetry', () {
    final source = File('lib/main.dart').readAsStringSync();
    final body = _functionBody(
      source,
      'Future<bool> _refreshFreeVpnConfig(',
      'Future<bool> _refreshVpnConfigForCurrentSelection(',
    );

    expect(
      body,
      contains(
        '_lastConfigRefreshHadLiveNodeListing = await _sharedNodeDiscovery();',
      ),
    );
    expect(body, isNot(contains('_fetchAvailableNodes(forceLive: true)')));
  });
}
