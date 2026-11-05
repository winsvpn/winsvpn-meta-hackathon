import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/double_vpn_assignment_retry.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

// 2026-10-23 live finding: Double VPN was requested, the connect-time refresh
// failed, and a cached standalone winn/3 document started a single-hop tunnel
// while the only notice was a status line that the connected state replaced.
// The single-hop fallback stays (a decided product behaviour), but it may
// never be silent: the connect says so once, and the dashboard says so for as
// long as the tunnel is up.

Map<String, dynamic> _standaloneV3() => <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'node_slug': 'canada-ca1',
      'double_vpn_active': false,
    };

Map<String, dynamic> _twoHop() => <String, dynamic>{
      'protocol_version': kWinnProtocolV1,
      'node_slug': 'canada-ca1',
      'double_vpn_active': true,
      'double_vpn_core_id': 'north-america-core',
      'double_vpn_exit_slug': 'canada-ca1',
    };

void main() {
  group('doubleVpnRequestedButSingleHop', () {
    test('only a Double VPN request can be undercut', () {
      for (final config in <Map<String, dynamic>?>[
        null,
        <String, dynamic>{},
        _standaloneV3(),
        _twoHop(),
      ]) {
        expect(
          doubleVpnRequestedButSingleHop(
            doubleVpnRequested: false,
            config: config,
          ),
          isFalse,
        );
      }
    });

    test('a requested Double VPN on a single-hop config is flagged', () {
      expect(
        doubleVpnRequestedButSingleHop(
          doubleVpnRequested: true,
          config: _standaloneV3(),
        ),
        isTrue,
      );
    });

    test('a missing or empty config cannot prove two hops', () {
      for (final config in <Map<String, dynamic>?>[null, <String, dynamic>{}]) {
        expect(
          doubleVpnRequestedButSingleHop(
            doubleVpnRequested: true,
            config: config,
          ),
          isTrue,
        );
      }
    });

    test('an incomplete two-hop marker is still flagged', () {
      expect(
        doubleVpnRequestedButSingleHop(
          doubleVpnRequested: true,
          config: <String, dynamic>{
            ..._standaloneV3(),
            'double_vpn_active': true,
          },
        ),
        isTrue,
      );
    });

    test('a complete two-hop config is not flagged', () {
      expect(
        doubleVpnRequestedButSingleHop(
          doubleVpnRequested: true,
          config: _twoHop(),
        ),
        isFalse,
      );
    });
  });

  group('route and latch helpers', () {
    test('a config is two-hop only when it passes the Double VPN check', () {
      expect(doubleVpnRouteOf(_twoHop()), doubleVpnRouteTwoHop);
      expect(doubleVpnRouteOf(_standaloneV3()), doubleVpnRouteSingleHop);
      expect(doubleVpnRouteOf(null), doubleVpnRouteSingleHop);
      expect(doubleVpnRouteOf(<String, dynamic>{}), doubleVpnRouteSingleHop);
      expect(
        doubleVpnRouteOf(<String, dynamic>{
          'double_vpn_active': true,
          'double_vpn_core_id': 'core',
        }),
        doubleVpnRouteSingleHop,
        reason: 'no exit slug',
      );
      expect(doubleVpnRouteTwoHop, 'two-hop');
      expect(doubleVpnRouteSingleHop, 'single-hop');
    });

    test('the service answer wins when it is a real boolean', () {
      for (final reported in <bool>[true, false]) {
        expect(
          doubleVpnCommittedSingleHop(
            doubleVpnRequested: reported,
            config: reported ? _twoHop() : _standaloneV3(),
            nativeReported: reported,
          ),
          reported,
        );
      }
      // Wanted + one hop by the config, but the service says otherwise: the
      // notification was posted from the service's answer, so it is used.
      expect(
        doubleVpnCommittedSingleHop(
          doubleVpnRequested: true,
          config: _standaloneV3(),
          nativeReported: false,
        ),
        isFalse,
      );
      expect(
        doubleVpnCommittedSingleHop(
          doubleVpnRequested: false,
          config: _twoHop(),
          nativeReported: true,
        ),
        isTrue,
      );
    });

    test('without a boolean from the service the rule is applied here', () {
      for (final reported in <Object?>[null, 'true', 1, <String, bool>{}]) {
        expect(
          doubleVpnCommittedSingleHop(
            doubleVpnRequested: true,
            config: _standaloneV3(),
            nativeReported: reported,
          ),
          isTrue,
        );
        expect(
          doubleVpnCommittedSingleHop(
            doubleVpnRequested: true,
            config: _twoHop(),
            nativeReported: reported,
          ),
          isFalse,
        );
        expect(
          doubleVpnCommittedSingleHop(
            doubleVpnRequested: false,
            config: _standaloneV3(),
            nativeReported: reported,
          ),
          isFalse,
        );
      }
    });
  });

  group('main.dart wiring', () {
    late final String source;

    setUpAll(() {
      source = File('lib/main.dart').readAsStringSync();
    });

    test('every tunnel commit says so when it is single hop', () {
      final start = source.indexOf('Future<bool> _startTunnelCandidate(');
      final end = source.indexOf(
        '  Future<void> _connectWithSmartProtocol({',
        start,
      );
      expect(start, greaterThanOrEqualTo(0));
      expect(end, greaterThan(start));
      final candidate = source.substring(start, end);
      final commit = candidate.indexOf('_isConnected = true;');
      expect(commit, greaterThanOrEqualTo(0));
      // The answer is asked for before the state change (it awaits) and
      // latched inside it, in the same setState as the connected flag.
      final asked = candidate.indexOf(
        'await _routeIsSingleHopAtCommit(configForPersistence);',
      );
      expect(asked, inInclusiveRange(0, commit));
      final latched = candidate.indexOf(
        '_committedDoubleVpnSingleHop = committedSingleHop;',
        commit,
      );
      expect(latched, greaterThan(commit));
      final notice = candidate.indexOf('if (committedSingleHop) {', latched);
      expect(notice, greaterThan(latched));
      // FAST-CONNECT (2026-10-24): a session that went one hop first while
      // Double VPN is prepared says so; every other single-hop commit keeps
      // the "unavailable" message. Either way the commit is never silent.
      final shown = candidate.indexOf(
        '_showFeedback(_t(\n'
        '              _doubleVpnUpgradePhase == DoubleVpnUpgradePhase.preparing\n'
        '                  ? doubleVpnSingleHopPreparingMessage\n'
        '                  : doubleVpnSingleHopConnectedMessage));',
        notice,
      );
      expect(shown, greaterThan(notice));
      final success = candidate.indexOf('return true;', shown);
      expect(success, greaterThan(shown),
          reason: 'the notice belongs to the commit that returns success');
    });

    test('the dashboard keeps the notice up while the session lasts', () {
      // Bound to the session through a latch, with the restored config only
      // as the fallback before anything has spoken. The runtime behaviour is
      // in tunnel_display_restore_production_test.dart.
      expect(source, contains('bool? _committedDoubleVpnSingleHop;'));
      expect(
        source,
        contains('bool get _doubleVpnSingleHopSession =>\n'
            '      _isConnected &&\n'
            '      (_committedDoubleVpnSingleHop ??\n'
            '          doubleVpnRequestedButSingleHop('),
      );
      final protocolLine = source.indexOf('Selected Protocol (Automatic):');
      expect(protocolLine, greaterThanOrEqualTo(0));
      final indicator = source.indexOf(
        'if (_rendersConnected && _doubleVpnSingleHopSession) ...[',
      );
      expect(indicator, greaterThan(protocolLine));
      final block = source.substring(indicator, indicator + 400);
      expect(block, contains("key: const Key('double_vpn_single_hop_notice')"));
      // FAST-CONNECT: worded "connecting Double VPN" only while the upgrade
      // of a deliberate one-hop-first session has not failed yet.
      expect(
          block,
          contains('_t(_doubleVpnUpgradePhase == DoubleVpnUpgradePhase.preparing\n'
              '                  ? doubleVpnSingleHopPreparingNotice\n'
              '                  : doubleVpnSingleHopSessionNotice)'));
    });

    test('the single-hop fallback itself is unchanged and never silent', () {
      // Both gates still continue on one hop (not a hard failure) ...
      expect(
        RegExp(RegExp.escape(
          'Double VPN core is offline for maintenance. Connecting with standard VPN instead...',
        )).allMatches(source).length,
        2,
      );
    });

    test('the cached document that led in the incident is now flagged', () {
      final cached = <String, dynamic>{
        ..._standaloneV3(),
        'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
      };
      // The offline lead is kept (explicit product decision) ...
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: cached,
          listingNode: null,
          automaticMode: true,
          coverExactTarget: false,
        ),
        isTrue,
      );
      // ... and the connect that it starts is recognised as single hop under
      // a Double VPN request, which is what drives both notices.
      expect(
        doubleVpnRequestedButSingleHop(
          doubleVpnRequested: true,
          config: cached,
        ),
        isTrue,
      );
    });

    test('notice texts name the problem and the way out', () {
      expect(doubleVpnSingleHopSessionNotice,
          startsWith('Single hop: Double VPN unavailable'));
      expect(doubleVpnSingleHopConnectedMessage, contains('Double VPN is unavailable'));
      expect(doubleVpnSingleHopConnectedMessage, contains('turn Double VPN off'));
    });
  });
}
