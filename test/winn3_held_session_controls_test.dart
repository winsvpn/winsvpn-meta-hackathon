import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/vpn_power_control.dart';

// Device findings 2026-09-23 (S26, Winn v3 to UK, blocked after promotion):
// the capture was held fail-closed, a server pick then hung in "Switching VPN
// server..." because its preparation ran through the held blackhole, and the
// "Cancel connection" label under the round cancel control did nothing.

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production source: $start');
  }
  return source.substring(first, last);
}

void main() {
  group('a server pick over a held Winn v3 session', () {
    late String source;
    setUpAll(() => source = File('lib/main.dart').readAsStringSync());

    // What the gate DOES is executed in winn3_held_switch_transaction_test.dart.
    // This only pins that nothing reaches the retained-route switch around it.
    test('every user server pick goes through the held-session gate', () {
      final gate = _between(
        source,
        '  Future<void> _switchServerFromUserSelection(',
        '  Future<void> _reconnectHeldWinn3Session(',
      );
      expect(gate, contains('await _switchConnectedServer(serverName'));
      final dialog = _between(
        source,
        '  Future<bool?> _confirmWinn3HoldRelease(',
        '  Future<Map<dynamic, dynamic>?> _readTunnelReadinessForRelease(',
      );
      expect(dialog, contains('winn3ServerSwitchReleaseDisclosure'));

      final outside = source.replaceFirst(gate, '');
      final callers = RegExp(r'await _switchConnectedServer\(')
          .allMatches(outside)
          .length;
      expect(callers, 0,
          reason: 'a server pick bypasses the held-session gate');
      expect(
          RegExp(r'await _switchServerFromUserSelection\(')
              .allMatches(source)
              .length,
          2,
          reason: 'the picker\'s Automatic row, and _onServerRowTapped, '
              'which every node row and the watch call');
      final watch = _between(
        source,
        '  Future<void> _selectWatchCountry(String slug) async {',
        '  /// State as the watch should see it',
      );
      expect(watch, contains('await _onServerRowTapped('));
      expect(watch, isNot(contains('_selectedLocationIndex =')));
    });

    test('the headline names a held session instead of UNPROTECTED', () {
      final headline = _between(
        source,
        'Text(_rendersConnected ? _t("SECURED")',
        '// Round A3: a held Winn v3 session says what it is doing',
      );
      expect(headline, contains('_t("TRAFFIC HELD")'));
      expect(headline, contains('_rendersHeldSession'));
      final held = _between(
        source,
        '  bool get _rendersHeldSession =>',
        '  static const Duration _tunnelProofMaxFreshness',
      );
      // Held, never connected: the green claim still needs its proof.
      expect(held, contains('!_rendersConnected'));
      expect(held, contains('_winn3HostLifecycle.holdsSession'));
    });
  });

  group('the connect transition', () {
    testWidgets('the "Cancel connection" label cancels too', (tester) async {
      var cancels = 0;
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: VpnConnectTransitionView(
            status: 'Switching VPN server...',
            connectedColor: Colors.green,
            disconnectedColor: Colors.red,
            onCancel: () => cancels += 1,
          ),
        ),
      ));

      await tester.tap(find.text('Cancel connection'));
      expect(cancels, 1);

      // One "Cancel VPN connection" semantics label remains and no TextButton
      // was added. This does not exercise a screen reader or a D-pad.
      expect(find.bySemanticsLabel('Cancel VPN connection'), findsOneWidget);
      expect(find.byType(TextButton), findsNothing);
    });
  });
}
