import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Apple native sampling claims one published handle lifetime', () {
    final source = File(
      'apple/WinsTunnelCore/WinsPacketTunnelEngine.swift',
    ).readAsStringSync();
    final sampleStart = source.indexOf(
        'func seamObservabilityStatusFields() -> [String: Any] {',
        source.indexOf('private final class WinsNativePacketTunnelEngine'));
    final sampleEnd =
        source.indexOf('private static func sampleDocument(', sampleStart);
    final sample = source.substring(sampleStart, sampleEnd);
    expect(sample, contains('lifetime.claim({ winnSamplePublication })'));
    expect(sample, contains('defer { lifetime.releaseClaim() }'));
    expect(sample, contains('publication.seamStats'));
    expect(sample, contains('publication.engineStatus'));
    expect(sample, isNot(contains('let seamHandle = winnSeamHandle')));
    expect(sample, isNot(contains('loadedComponents.first')));
  });

  test('stop rejects new claims and drains before native destroy', () {
    final source = File(
      'apple/WinsTunnelCore/WinsPacketTunnelEngine.swift',
    ).readAsStringSync();
    final stopStart = source.indexOf('func stop() {',
        source.indexOf('private final class WinsNativePacketTunnelEngine'));
    final stopEnd =
        source.indexOf('private func stopUnpublishedNativeState()', stopStart);
    final stop = source.substring(stopStart, stopEnd);
    expect(stop, contains('lifetime.beginStopAndWaitForSamplers()'));
    expect(stop, contains('winnSamplePublication = nil'));
    expect(
      stop.indexOf('beginStopAndWaitForSamplers()'),
      lessThan(stop.indexOf('stopUnpublishedNativeState()')),
    );

    final gateStart = source.indexOf('final class WinsNativeSamplerLifetime');
    final gateEnd =
        source.indexOf('struct WinsPacketTunnelEngineStartResult', gateStart);
    final gate = source.substring(gateStart, gateEnd);
    expect(gate, contains('phase = .stopping'));
    expect(gate, contains('while inFlightSamplers > 0'));
    expect(gate, contains('condition.wait()'));
    expect(gate, contains('precondition(inFlightSamplers == 0)'));
  });

  test('Apple runner stress tests hold 32 samples across concurrent stop', () {
    for (final runnerTests in <String>[
      'macos/RunnerTests/RunnerTests.swift',
      'ios/RunnerTests/RunnerTests.swift',
    ]) {
      final source = File(runnerTests).readAsStringSync();
      final start = source.indexOf(
          'func testNativeSamplerLifetimeDrainsConcurrentClaimsBeforeStop()');
      expect(start, greaterThanOrEqualTo(0), reason: runnerTests);
      final body = source.substring(start);
      expect(body, contains('for _ in 0..<32'), reason: runnerTests);
      expect(body, contains('beginStopAndWaitForSamplers()'),
          reason: runnerTests);
      expect(body, contains('.timedOut'), reason: runnerTests);
      expect(body, contains('releaseSamplers.signal()'), reason: runnerTests);
    }
  });
}
