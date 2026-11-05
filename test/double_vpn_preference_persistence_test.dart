import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Double VPN switch becomes visible only after durable preference write',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf(
      'Future<void> _setDoubleVpnRequested(bool requested) async',
    );
    final end = source.indexOf(
      'void _scheduleTunnelSettingsReconnect',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));

    final handler = source.substring(start, end);
    final durableEnable = handler.indexOf(
      'if (!await _persistDoubleVpnRequested(true))',
    );
    final visibleEnable = handler.indexOf('_isDoubleVpnRequested = true;');
    final durableDisable = handler.indexOf(
      'if (!await _persistDoubleVpnRequested(false))',
    );
    final visibleDisable = handler.indexOf('_isDoubleVpnRequested = false;');

    expect(durableEnable, greaterThanOrEqualTo(0));
    expect(visibleEnable, greaterThan(durableEnable));
    expect(durableDisable, greaterThanOrEqualTo(0));
    expect(visibleDisable, greaterThan(durableDisable));
    expect(
      handler,
      isNot(contains('unawaited(_saveVpnRuntimeSettings())')),
    );

    final broadSaveStart = source.indexOf(
      'Future<void> _saveVpnRuntimeSettings({',
    );
    final broadSaveEnd = source.indexOf(
      'Future<bool> _readNativeTunnelActive()',
      broadSaveStart,
    );
    expect(broadSaveStart, greaterThanOrEqualTo(0));
    expect(broadSaveEnd, greaterThan(broadSaveStart));
    expect(
      source.substring(broadSaveStart, broadSaveEnd),
      isNot(contains("data['double_vpn_requested'] =")),
      reason:
          'A queued broad settings snapshot must not overwrite the dedicated durable Double VPN preference.',
    );
  });

  test(
      'Double VPN falls back to single-hop (not a hard failure) when the censorship TCP path core is unavailable',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('final stealthRefreshed =');
    final boundedCandidates = source.indexOf(
      'final boundedCandidates = boundedXrayTransportOptions(',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(boundedCandidates, greaterThan(start));

    final fallbackGate = source.substring(start, boundedCandidates);
    final gateStart = fallbackGate.indexOf(
      // FAST-CONNECT (2026-10-24): the gate reads the route THIS connect
      // asked for, which is the user's choice unless it went one hop first.
      "requestDoubleRoute &&\n        !_boolValue(stealthBase['double_vpn_active'])",
    );
    expect(
      gateStart,
      greaterThanOrEqualTo(0),
      reason:
          'The app must still detect when an explicitly requested Double VPN route is unavailable.',
    );
    final candidatesMarker = fallbackGate.indexOf('var candidates =');
    expect(candidatesMarker, greaterThan(gateStart));
    // AICORE (the Core relay) is a shared, non-dedicated box the owner also
    // uses for other purposes and that can go offline for reasons unrelated
    // to the VPN service. Per explicit product decision, an unavailable
    // core must fail over to the already-validated single-hop stealthBase
    // config instead of blocking the connection with
    // _finishTunnelConnectFailure -- stranding the user on a resource that
    // was never meant to be a dedicated, always-on node.
    expect(
      fallbackGate.substring(gateStart, candidatesMarker),
      isNot(contains('_finishTunnelConnectFailure(')),
      reason:
          'An unavailable Double VPN core must fail over to single-hop, not block the connection.',
    );
    expect(
      source.substring(boundedCandidates),
      contains('for (final candidate in boundedCandidates)'),
      reason:
          'Single and Double VPN must retain at least one reachable candidate for every advertised Xray route within the bounded retry budget.',
    );
  });

  test(
      'Double VPN unavailability falls back to single-hop without ever clearing the saved preference',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<void> _connectWithSmartProtocol');
    final end = source.indexOf(
      'Future<void> _toggleVpnConnection()',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));

    final connect = source.substring(start, end);
    final availabilityGate = connect.indexOf(
      // FAST-CONNECT (2026-10-24): the route this connect asked for, and not
      // the background upgrade's own attempt (that one is Double by
      // construction and stays silent while the single-hop session runs).
      "if (requestDoubleRoute &&\n        upgradeAttempt == null &&\n        (!_boolValue(directConfig['double_vpn_active']) ||\n            !_doubleVpnAvailable)) {",
    );
    expect(availabilityGate, greaterThanOrEqualTo(0));
    final gateEnd = connect.indexOf('\n    }', availabilityGate);
    expect(gateEnd, greaterThan(availabilityGate));
    final gate = connect.substring(availabilityGate, gateEnd);
    // Same reasoning as the censorship/TCP fallback test above: AICORE is
    // shared and non-dedicated, so an unavailable core must fail over to
    // the already-validated single-hop directConfig rather than block the
    // connection -- and it must do so without ever touching the user's
    // saved preference, so Double VPN resumes automatically once the core
    // relay is healthy again instead of requiring the user to re-enable it.
    expect(gate, isNot(contains('_finishTunnelConnectFailure(')));
    expect(gate, isNot(contains('_persistDoubleVpnRequested(false)')));
    expect(gate, isNot(contains('_isDoubleVpnRequested = false')));

    // Became `Future<void> ... async` when announcement signature verification
    // was added; the leading space keeps this matching the declaration rather
    // than a call site, whichever return type it carries.
    final parseStart = source.indexOf(' _parseNodesResponse(String body)');
    final parseEnd = source.indexOf(
      'Future<void> _saveCachedNodes()',
      parseStart,
    );
    expect(parseStart, greaterThanOrEqualTo(0));
    expect(parseEnd, greaterThan(parseStart));
    final parseNodes = source.substring(parseStart, parseEnd);
    expect(
      parseNodes,
      isNot(contains('_persistDoubleVpnRequested(false)')),
      reason:
          'A transient or stale node response must not erase the durable Double VPN preference.',
    );
    expect(
      parseNodes,
      isNot(contains('_isDoubleVpnRequested = false')),
    );
  });
}
