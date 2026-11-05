import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tunnel_stop_settlement.dart';
import 'dart:io';

void main() {
  test('Windows stop settlement outlasts the observed late-start race', () {
    expect(windowsTunnelStopQuietWindow, const Duration(seconds: 6));
    expect(
      windowsTunnelStopSettlementTimeout,
      greaterThan(windowsTunnelStopQuietWindow),
    );
    expect(
      windowsTunnelStopPollInterval,
      lessThanOrEqualTo(const Duration(milliseconds: 500)),
    );
    expect(
      windowsTunnelActivitySnapshotTimeout,
      greaterThan(const Duration(seconds: 12)),
      reason: 'the Dart activity query must outlast native pipe I/O',
    );
    expect(windowsTunnelNativeStopTimeout, const Duration(seconds: 35));
  });

  test('Windows settlement budget outlasts the service stop-watchdog recovery',
      () {
    final serviceSource = File('windows/runner/windows_tunnel_service_main.cpp')
        .readAsStringSync();
    final protocolSource =
        File('windows/runner/windows_tunnel_service_protocol.h')
            .readAsStringSync();
    final watchdogMatch =
        RegExp(r'kStopOverallWatchdogMilliseconds = (\d+)')
            .firstMatch(protocolSource);
    expect(watchdogMatch, isNotNull,
        reason: 'the native stop watchdog bound must be discoverable');
    final watchdogMs = int.parse(watchdogMatch!.group(1)!);

    final restartMatch =
        RegExp(r'\{SC_ACTION_RESTART, (\d+)\}').firstMatch(serviceSource);
    expect(restartMatch, isNotNull,
        reason: 'the first SCM restart delay must be discoverable');
    final restartDelayMs = int.parse(restartMatch!.group(1)!);

    final worstCaseRecovery =
        Duration(milliseconds: watchdogMs + restartDelayMs);
    expect(
      windowsTunnelStopSettlementTimeout,
      greaterThan(worstCaseRecovery + windowsTunnelStopQuietWindow),
      reason:
          'settlement must survive a watchdog-triggered manager restart and '
          'still have time left afterward to observe a full quiet window',
    );
  });

  test('Windows internal failover settles before the next transport starts',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(
      source,
      contains("Platform.isWindows\n              ? windowsTunnelNativeStopTimeout"),
      reason:
          'the Dart stop budget must exceed the native 25-second stop-pipe bound',
    );
    expect(source, contains('Future<bool> _stopNativeTunnelForFailover()'));
    expect(
      RegExp(r'if \(!await _stopNativeTunnelForFailover\(\)\)')
          .allMatches(source)
          .length,
      6,
      reason: 'exactly the cover-node pre-settlement, the pre-fallback stop, '
          'the Double VPN handover stop after a failed single-hop restore, '
          'the failed-candidate cleanup, the stale-plan retry settlement and '
          'the relay path failure retry settlement remain; the demoted-direct '
          'tail must not stop-then-retry an explicitly disabled direct '
          'transport',
    );
    // The sixth site is the ciphertext relay retry: it settles the failed
    // relay lead before the one full retry that no longer asks for the relay
    // (winn3_relay_test.dart), never a transport the settings excluded.
    final relayRetryStart = source.indexOf(
        'if (relayFailure == Winn3RelayFailureAction.suppressAndRetry) {');
    final relayRetryEnd =
        source.indexOf('await _connectWithSmartProtocol();', relayRetryStart);
    expect(relayRetryStart, greaterThanOrEqualTo(0));
    expect(relayRetryEnd, greaterThan(relayRetryStart));
    expect(
      RegExp(r'if \(!await _stopNativeTunnelForFailover\(\)\)')
          .allMatches(source.substring(relayRetryStart, relayRetryEnd))
          .length,
      1,
    );
    // The fourth site is the stale-plan retry: it settles the failed v3 lead
    // before the one fresh-config retry of the same node, never a transport
    // the settings excluded (winn3_stale_cached_config_test.dart).
    final staleRetryStart =
        source.indexOf('winn3TerminalFailureMayRetryWithFreshConfig(');
    final staleRetryEnd =
        source.indexOf('await _markCachedVpnConfigStale();', staleRetryStart);
    expect(staleRetryStart, greaterThanOrEqualTo(0));
    expect(staleRetryEnd, greaterThan(staleRetryStart));
    expect(
      RegExp(r'if \(!await _stopNativeTunnelForFailover\(\)\)')
          .allMatches(source.substring(staleRetryStart, staleRetryEnd))
          .length,
      1,
    );
    expect(
      source,
      contains('_settleWindowsTunnelStop(keepVpnLauncher: true)'),
    );
    expect(source, contains('_nativeTunnelActivityForStopSettlement()'));
    final stopStart = source.indexOf('Future<bool> _stopNativeTunnel({');
    final stopEnd = source.indexOf(
      'Future<bool?> _nativeTunnelActivityForStopSettlement()',
      stopStart,
    );
    final stop = source.substring(stopStart, stopEnd);
    expect(
      stop.indexOf('if (Platform.isWindows)'),
      lessThan(stop.indexOf('final stopped = await _waitForTunnelState(false')),
      reason:
          'Windows must skip the legacy boolean state loop and use the authoritative tri-state settlement',
    );
    expect(
      stop,
      contains(
          'Windows callers verify the manager, Xray process, and interface'),
    );
    final failoverStart = source.indexOf(
      'Future<bool> _stopNativeTunnelForFailover()',
    );
    final failoverEnd = source.indexOf(
      'Future<void> _setLauncherCamouflage',
      failoverStart,
    );
    final failover = source.substring(failoverStart, failoverEnd);
    expect(failover, contains('if (!Platform.isWindows) return stopped'));
    expect(
      failover,
      isNot(contains('if (!stopped || !Platform.isWindows)')),
      reason:
          'Windows failover must verify concrete quiet state after an inconclusive stop RPC',
    );
    expect(failover, contains('_settleWindowsTunnelStop('));
  });

  test('Windows cancellation settles after an inconclusive stop RPC', () {
    final source = File('lib/main.dart').readAsStringSync();
    final cancelStart = source.indexOf(
      'Future<bool> _cancelAndStopNativeTunnel(',
    );
    final cancelEnd = source.indexOf(
      'Future<bool> _settleWindowsTunnelStop(',
      cancelStart,
    );
    final cancel = source.substring(cancelStart, cancelEnd);
    expect(cancel, contains('if (!Platform.isWindows) return stopped'));
    expect(
      cancel,
      isNot(contains('if (!stopped || !Platform.isWindows) return stopped')),
    );
    expect(cancel, contains('if (!stopped)'));
    expect(cancel, contains('return _settleWindowsTunnelStop('));
  });

  test('Windows settlement treats a busy status pipe as unknown', () {
    final source = File('lib/main.dart').readAsStringSync();
    final helperStart = source.indexOf(
      'Future<bool?> _nativeTunnelActivityForStopSettlement()',
    );
    final helperEnd = source.indexOf(
      'Future<bool> _cancelAndStopNativeTunnel(',
      helperStart,
    );
    expect(helperStart, greaterThanOrEqualTo(0));
    expect(helperEnd, greaterThan(helperStart));
    final helper = source.substring(helperStart, helperEnd);
    expect(helper, contains('return null;'));
    expect(helper, contains("'getTunnelActivitySnapshot'"));
    expect(helper, contains('windowsTunnelActivitySnapshotTimeout'));
    expect(helper, contains("snapshot['known'] != true"));

    final settlementStart = source.indexOf(
      'Future<bool> _settleWindowsTunnelStop(',
    );
    final settlementEnd = source.indexOf(
      'Future<bool> _stopNativeTunnelForFailover()',
      settlementStart,
    );
    final settlement = source.substring(settlementStart, settlementEnd);
    expect(settlement, contains('if (activity == null)'));
    expect(settlement, contains('final settlementClock = Stopwatch()..start();'));
    expect(settlement, contains('quietWindow.observe(activity, settlementClock.elapsed)'));
    expect(settlement, isNot(contains('DateTime.now()')));
    expect(
      settlement,
      isNot(contains('if (!stoppedAgain) return false')),
      reason: 'a transiently busy service pipe must not strand TCP fallback',
    );
  });

  int quietWindowSamples() {
    return windowsTunnelStopQuietWindow.inMilliseconds ~/
        windowsTunnelStopPollInterval.inMilliseconds;
  }

  test('a delayed first quiet snapshot starts the observed quiet window', () {
    final window = TunnelStopQuietWindow(windowsTunnelStopQuietWindow);
    expect(window.observe(false, const Duration(seconds: 7)), isFalse);
    expect(window.observe(false, const Duration(seconds: 12)), isFalse);
    expect(window.observe(false, const Duration(seconds: 13)), isTrue);
  });

  test('an unknown or active snapshot resets the observed quiet window', () {
    final window = TunnelStopQuietWindow(windowsTunnelStopQuietWindow);
    expect(window.observe(false, const Duration(seconds: 1)), isFalse);
    expect(window.observe(null, const Duration(seconds: 6)), isFalse);
    expect(window.observe(false, const Duration(seconds: 7)), isFalse);
    expect(window.observe(true, const Duration(seconds: 10)), isFalse);
    expect(window.observe(false, const Duration(seconds: 11)), isFalse);
    expect(window.observe(false, const Duration(seconds: 17)), isTrue);
  });

  test('Windows settlement: in-flight traffic drains before a true stop', () {
    final window = quietWindowSamples();
    final samples = <TunnelActivitySample>[
      for (var i = 0; i < 3; i++) TunnelActivitySample.active,
      for (var i = 0; i < window; i++) TunnelActivitySample.quiet,
      TunnelActivitySample.active,
    ];
    final result = tunnelStopSettlement(samples, window);
    expect(result.settled, isTrue,
        reason: 'traffic that finishes must settle once the full quiet window '
            'has elapsed uninterrupted');
    expect(result.settledAtIndex, greaterThanOrEqualTo(3 + window - 1),
        reason: 'settlement must be reached inside the trailing quiet run, '
            'never while the leading traffic was still in flight');
    expect(
      result.settledAtIndex,
      lessThan(samples.length),
      reason: 'a later re-injected active sample must not retroactively '
          'extend or cancel the already-earned quiet window',
    );
  });

  test('Windows settlement: persistent in-flight traffic is refused, not '
      'silently stopped', () {
    final window = quietWindowSamples();
    final samples = <TunnelActivitySample>[
      for (var i = 0; i < 4 * window; i++) TunnelActivitySample.active,
    ];
    final result = tunnelStopSettlement(samples, window);
    expect(result.settled, isFalse,
        reason: 'a tunnel still carrying traffic the whole shutdown must '
            'never be reported stopped — that is a silent false "stopped"');
    expect(result.settledAtIndex, -1);
  });

  test('Windows settlement: an active sample mid-quiet forfeits the window',
      () {
    final window = quietWindowSamples();
    expect(window, greaterThan(1));
    final samples = <TunnelActivitySample>[
      for (var i = 0; i < window - 1; i++) TunnelActivitySample.quiet,
      TunnelActivitySample.active,
      for (var i = 0; i < window; i++) TunnelActivitySample.quiet,
    ];
    final result = tunnelStopSettlement(samples, window);
    expect(result.settled, isTrue);
    expect(result.settledAtIndex, greaterThanOrEqualTo(window + 1),
        reason: 'the interrupted first quiet run must not count; only the '
            'uninterrupted run after the active sample may earn settlement');
  });

  test('Windows settlement: a short quiet run cannot earn a stop', () {
    final window = quietWindowSamples();
    expect(window, greaterThan(1));
    final samples = <TunnelActivitySample>[
      for (var i = 0; i < window - 1; i++) TunnelActivitySample.quiet,
    ];
    final result = tunnelStopSettlement(samples, window);
    expect(result.settled, isFalse,
        reason: 'quiet must persist for the full window, never an abbreviated '
            'one');
  });

  test('Windows settlement: a busy/unknown pipe is not quiet evidence', () {
    final window = quietWindowSamples();
    final samples = <TunnelActivitySample>[
      for (var i = 0; i < 4 * window; i++) TunnelActivitySample.unknown,
    ];
    final result = tunnelStopSettlement(samples, window);
    expect(result.settled, isFalse,
        reason: 'an unavailable status pipe must not be read as a quiet tunnel'
            ' — the caller keeps waiting rather than trusting a false stop');
  });
}
