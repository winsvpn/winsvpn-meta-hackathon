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
  final androidSource = File(
    '$root/android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt',
  ).readAsStringSync();
  final iosSource =
      File('$root/ios/Runner/AppDelegate.swift').readAsStringSync();
  final macosSource =
      File('$root/macos/Runner/MainFlutterWindow.swift').readAsStringSync();

  test('APP-09 reserves before await and gates every published result', () {
    final run = _body(
      mainSource,
      'Future<void> _runSpeedTest() async {',
      'void _maybeRunSpeedTestSmoke()',
    );
    expect(run, contains('_speedTestLifecycle.tryBegin'));
    expect(
      run.indexOf('_speedTestLifecycle.tryBegin'),
      lessThan(run.indexOf('await _latestTunnelReadiness()')),
    );
    expect(
      run.indexOf('_speedTestRunning = true'),
      lessThan(run.indexOf('await _latestTunnelReadiness()')),
    );
    expect(run, contains('_requireCurrentSpeedTestLease(lease)'));
    expect(run, contains('_speedTestLifecycle.complete(lease)'));
    expect(
      run,
      contains('_speedTestRouteLabel(startedConnected: startedConnected)'),
    );
  });

  test('APP-09 lifecycle edges synchronously invalidate transports', () {
    final cancel = _body(
      mainSource,
      'void _cancelSpeedTest({bool updateUi = true})',
      'bool _requireCurrentSpeedTestLease(',
    );
    expect(cancel, contains('_speedTestLifecycle.cancel()'));
    expect(cancel, contains('_closeSpeedTestTransports()'));
    expect(mainSource, contains('client.close(force: true)'));
    expect(mainSource, contains("invokeMethod('cancelSpeedTestMeasurements')"));

    final stop = _body(
      mainSource,
      'Future<bool> _cancelAndStopNativeTunnel({',
      'Future<bool> _settleWindowsTunnelStop(',
    );
    expect(stop, contains('_cancelSpeedTest();'));
    final teardown = _body(
      mainSource,
      'int _beginAccountTeardown()',
      'Future<void> _applyAccountSyncData(',
    );
    expect(teardown, contains('_cancelSpeedTest();'));
    final dispose = _body(
        mainSource, 'void dispose() {', 'void didChangeAppLifecycleState(');
    expect(dispose, contains('_cancelSpeedTest(updateUi: false)'));
    final lifecycle = _body(
      mainSource,
      'void didChangeAppLifecycleState(AppLifecycleState state)',
      'void _startStatusHeartbeat()',
    );
    expect(lifecycle, contains('state == AppLifecycleState.paused'));
    expect(lifecycle, contains('_cancelSpeedTest();'));
  });

  test('APP-09 Android native transfers honor cancellation generation', () {
    expect(androidSource, contains('"cancelSpeedTestMeasurements" ->'));
    expect(androidSource, contains('speedTestGeneration.incrementAndGet()'));
    expect(androidSource, contains('activeSpeedTestConnections'));
    expect(androidSource, contains('connection.disconnect()'));
    expect(
      RegExp(r'speedTestGeneration\.get\(\) == measurementGeneration')
          .allMatches(androidSource)
          .length,
      greaterThanOrEqualTo(3),
    );
  });

  test('APP-09 Apple native sessions are registered and canceled', () {
    for (final source in <String>[iosSource, macosSource]) {
      expect(source, contains('private enum WinsAppleSpeedTestRegistry'));
      expect(source, contains('case "cancelSpeedTestMeasurements":'));
      expect(source, contains('WinsAppleSpeedTestRegistry.cancelAll()'));
      expect(
        source,
        contains(r'activeSessions.forEach { $0.invalidateAndCancel() }'),
      );
      expect(
        RegExp(r'WinsAppleSpeedTestRegistry\.register\(')
            .allMatches(source)
            .length,
        2,
      );
      expect(
          source, contains('isCurrent(cancellationGeneration) ? mbps : nil'));
    }
  });
}
