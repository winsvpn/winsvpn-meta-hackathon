import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tunnel_transition_gate.dart';

void main() {
  test('power button cancels an in-flight tunnel transition', () {
    final source = File('lib/main.dart').readAsStringSync();
    final toggleStart = source.indexOf(
      'Future<void> _toggleVpnConnection() async',
    );
    final toggleEnd = source.indexOf(
      'void _showFeedback(String message)',
      toggleStart,
    );
    expect(toggleStart, greaterThanOrEqualTo(0));
    expect(toggleEnd, greaterThan(toggleStart));
    final toggle = source.substring(toggleStart, toggleEnd);

    expect(toggle, contains('if (_isLoading)'));
    expect(toggle, contains('if (!_isVpnConnectInFlight) return'));
    expect(toggle, contains('final operationEpoch = ++_vpnUiOperationEpoch'));
    expect(
      toggle.indexOf('_isVpnConnectInFlight = false'),
      lessThan(toggle.indexOf('_cancelAndStopNativeTunnel')),
      reason: 'cancel must become single-shot before asynchronous teardown',
    );
    expect(
      toggle,
      contains('keepVpnLauncher: true, releaseKillSwitchBlock: true);'),
    );
    expect(toggle, contains("_ipAfterVpn = stopped"));

    expect(
      source,
      contains('_isVpnConnectInFlight &&'),
      reason: 'only an active VPN connect may expose its cancel view',
    );
    expect(
      source,
      contains('VpnConnectTransitionView('),
    );
  });

  test('Windows cancellation waits through a late native restart', () {
    final source = File('lib/main.dart').readAsStringSync();
    final settlementStart = source.indexOf(
      'Future<bool> _cancelAndStopNativeTunnel(',
    );
    final settlementEnd = source.indexOf(
      'Future<bool> _settleWindowsTunnelStop(',
      settlementStart,
    );
    expect(settlementStart, greaterThanOrEqualTo(0));
    expect(settlementEnd, greaterThan(settlementStart));
    final settlement = source.substring(settlementStart, settlementEnd);

    expect(settlement, contains('_tunnelTransitionGate.cancel()'));
    expect(settlement, contains('_settleWindowsTunnelStop('));
    expect(
      RegExp(r'_stopNativeTunnel\(').allMatches(settlement).length,
      1,
    );

    final helperEnd = source.indexOf(
      'Future<bool> _stopNativeTunnelForFailover()',
      settlementEnd,
    );
    final helper = source.substring(settlementEnd, helperEnd);
    expect(helper, contains('windowsTunnelStopQuietWindow'));
    expect(helper, contains('_nativeTunnelActivityForStopSettlement()'));
    expect(RegExp(r'_stopNativeTunnel\(').allMatches(helper).length, 1);
  });

  test('smart-connect propagates cancellation through native wait loops', () {
    final source = File('lib/main.dart').readAsStringSync();
    final connectStart = source.indexOf(
      'Future<void> _connectWithSmartProtocol(',
    );
    final connectEnd = source.indexOf(
      'Future<void> _toggleVpnConnection() async',
      connectStart,
    );
    expect(connectStart, greaterThanOrEqualTo(0));
    expect(connectEnd, greaterThan(connectStart));
    final connect = source.substring(connectStart, connectEnd);

    expect(connect, contains('_tunnelTransitionGate.begin()'));
    expect(connect, isNot(contains('stopIfTransitionCancelled')));
    expect(connect, contains('shouldCancel: transitionCancelled'));

    final readinessStart = source.indexOf('Future<bool> _waitForTunnelReady(');
    final candidateStart =
        source.indexOf('Future<bool> _startTunnelCandidate(');
    expect(readinessStart, greaterThanOrEqualTo(0));
    expect(candidateStart, greaterThan(readinessStart));
    final readiness = source.substring(readinessStart, candidateStart);
    expect(readiness, contains('bool Function()? shouldCancel'));
    expect(readiness, contains('shouldCancel?.call() == true'));
  });

  test('smart-connect persists the exact pre-fallback failure boundary', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(source, contains('failover_stop_settlement_failed_before_tcp'));
    expect(source, contains('tcp_fallback_candidate_preflight_failed'));
    expect(source, contains('failed_tcp_stop_settlement_failed'));
  });

  test('pre-native smart-connect failures settle the dashboard state', () {
    final source = File('lib/main.dart').readAsStringSync();
    final connectStart = source.indexOf(
      'Future<void> _connectWithSmartProtocol(',
    );
    final connectEnd = source.indexOf(
      'Future<void> _toggleVpnConnection() async',
      connectStart,
    );
    expect(connectStart, greaterThanOrEqualTo(0));
    expect(connectEnd, greaterThan(connectStart));
    final connect = source.substring(connectStart, connectEnd);

    // These remain genuine terminal failures: the connection attempt is
    // aborted, so the dashboard must reset via _finishTunnelConnectFailure.
    for (final message in <String>[
      'Could not refresh VPN config. Check hub connection and try again.',
      'VPN config missing. Deactivate and activate again.',
      'TCP fallback is not registered for this server yet.',
    ]) {
      final messageIndex = connect.indexOf(message);
      expect(messageIndex, greaterThanOrEqualTo(0));
      final helperIndex = connect.lastIndexOf(
        'failConnect(',
        messageIndex,
      );
      expect(
        helperIndex,
        greaterThanOrEqualTo(0),
        reason: 'Failure "$message" must reset the visible dashboard status.',
      );
      expect(
        messageIndex - helperIndex,
        lessThan(100),
        reason: 'Failure "$message" must be passed directly to the helper.',
      );
    }

    // An unavailable Double VPN core is deliberately NOT a terminal failure:
    // directConfig/stealthBase already passed _hasUsableVpnConfig, so the
    // connection proceeds single-hop instead of aborting. It must still
    // "settle the dashboard state" -- just via a direct status setState
    // rather than the full-disconnect _finishTunnelConnectFailure helper,
    // since the connection is succeeding, not failing.
    const fallbackMessage =
        'Double VPN core is offline for maintenance. Connecting with standard VPN instead...';
    expect(
      RegExp(r'failConnect\([^)]*\)').allMatches(connect).any(
            (m) => m.group(0)?.contains(fallbackMessage) ?? false,
          ),
      isFalse,
      reason:
          'Double VPN unavailability must not be routed through the terminal failure helper.',
    );
    final fallbackOccurrences =
        RegExp(RegExp.escape(fallbackMessage)).allMatches(connect).length;
    expect(
      fallbackOccurrences,
      2,
      reason:
          'Both the direct and stealth/TCP Double VPN gates must surface the same fallback status.',
    );
  });

  test('rapid connect cancel reconnect preserves the newest owner', () {
    final gate = TunnelTransitionGate();
    final firstConnect = gate.begin();
    expect(gate.isCurrent(firstConnect), isTrue);

    final cancelOwner = gate.cancel();
    expect(gate.isCurrent(firstConnect), isFalse);
    expect(gate.isCurrent(cancelOwner), isTrue);

    final reconnect = gate.begin();
    expect(gate.isCurrent(firstConnect), isFalse);
    expect(gate.isCurrent(cancelOwner), isFalse);
    expect(gate.isCurrent(reconnect), isTrue);
  });
}
