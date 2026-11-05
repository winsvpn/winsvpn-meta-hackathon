import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/location_flag_icon.dart';
import 'package:wins_vpn/tunnel_display_identity.dart';

// 2026-09-22 S26 Ultra, free tier: the card read "Canada / Status: online"
// and SECURED while the Winn v3 session ran on uk-gb1. The card rendered the
// picker position; nothing tied it to the node the tunnel was started for.
// Lifecycle through real switch transactions is covered by the production
// switch harness in connected_server_switch_transaction_test.dart.
void main() {
  Map<String, dynamic> canada() => <String, dynamic>{
        'slug': 'ca-tor1',
        'name': 'Canada',
        'status': 'online',
        'latency_ms': 22,
      };
  Map<String, dynamic> uk() => <String, dynamic>{
        'slug': 'uk-gb1',
        'name': 'United Kingdom',
        'flag': 'GB',
        'status': 'online',
        'latency_ms': 35,
      };

  DashboardNodeDisplay show(
    TunnelDisplayLedger ledger,
    List<Map<String, dynamic>> locations, {
    int selectedIndex = 0,
    bool rendersConnected = true,
    int accountEpoch = 1,
  }) =>
      dashboardNodeForDisplay(
        locations: locations,
        selectedIndex: selectedIndex,
        rendersConnected: rendersConnected,
        ledger: ledger,
        accountEpoch: accountEpoch,
      );

  CommittedTunnelNode? commit(
    TunnelDisplayLedger ledger,
    String slug, {
    List<Map<String, dynamic>> locations = const <Map<String, dynamic>>[],
    int accountEpoch = 1,
  }) =>
      ledger.commit(
        servedIdentity: slug,
        callerIdentity: slug,
        coverFallbackInProgress: false,
        accountEpoch: accountEpoch,
        locations: locations,
      );

  group('display rule', () {
    test('a secured tunnel names its committed node, not the picker', () {
      final ledger = TunnelDisplayLedger();
      final locations = [canada(), uk()];
      commit(ledger, 'uk-gb1', locations: locations);
      final shown = show(ledger, locations, selectedIndex: 0);
      expect(shown.source, DashboardNodeSource.committedTunnel);
      expect(shown.node?['slug'], 'uk-gb1');
    });

    test('a secured tunnel with no committed identity is an unknown node', () {
      final ledger = TunnelDisplayLedger();
      final shown = show(ledger, [canada(), uk()]);
      expect(shown.source, DashboardNodeSource.unknownTunnel);
      expect(shown.node, isNull);
      for (final slug in ['', '  ', 'auto', 'AUTO']) {
        final blank = TunnelDisplayLedger();
        expect(commit(blank, slug), isNull, reason: slug);
        expect(
            show(blank, [canada()]).source, DashboardNodeSource.unknownTunnel,
            reason: slug);
      }
    });

    test('not secured keeps the picker position and its clamp', () {
      final ledger = TunnelDisplayLedger();
      commit(ledger, 'ca-tor1', locations: [canada(), uk()]);
      final picker = show(ledger, [canada(), uk()],
          selectedIndex: 1, rendersConnected: false);
      expect(picker.source, DashboardNodeSource.picker);
      expect(picker.node?['slug'], 'uk-gb1');
      expect(
          show(ledger, [canada(), uk()],
                  selectedIndex: 9, rendersConnected: false)
              .node?['slug'],
          'ca-tor1');
      final empty = show(ledger, const [], rendersConnected: false);
      expect(empty.source, DashboardNodeSource.picker);
      expect(empty.node, isNull);
    });

    test('a normalized served slug still finds its listing row', () {
      final ledger = TunnelDisplayLedger();
      final locations = [
        <String, dynamic>{'slug': 'UK-GB1', 'name': 'UK', 'status': 'online'},
      ];
      commit(ledger, 'uk-gb1', locations: locations);
      expect(show(ledger, locations).node, same(locations.single));
    });
  });

  group('health honesty', () {
    test('a listed committed node shows the CURRENT listing health', () {
      final ledger = TunnelDisplayLedger();
      final locations = [canada(), uk()];
      commit(ledger, 'uk-gb1', locations: locations);
      // A later listing refresh replaces the row with new health.
      final refreshed = [
        canada(),
        uk()
          ..['status'] = 'offline'
          ..['latency_ms'] = 180,
      ];
      final shown = show(ledger, refreshed).node!;
      expect(shown['status'], 'offline');
      expect(shown['latency_ms'], 180);
    });

    test('a delisted committed node shows identity only, status unknown', () {
      final ledger = TunnelDisplayLedger();
      commit(ledger, 'uk-gb1', locations: [canada(), uk()]);
      final shown = show(ledger, [canada()]);
      expect(shown.source, DashboardNodeSource.committedTunnel);
      expect(shown.node, <String, dynamic>{
        'slug': 'uk-gb1',
        'name': 'United Kingdom',
        'status': 'unknown',
        'flag': 'GB',
      });
      expect(shown.node!.containsKey('latency_ms'), isFalse);
    });

    test('a node never listed gets the bare unknown-status placeholder', () {
      final ledger = TunnelDisplayLedger();
      commit(ledger, 'uk-gb1');
      expect(show(ledger, [canada()]).node, <String, dynamic>{
        'slug': 'uk-gb1',
        'name': 'uk-gb1',
        'status': 'unknown',
      });
    });

    test('the unknown-node label infers no country flag', () {
      expect(
        countryCodeFromFlagValue(null, locationName: 'Unknown node', slug: ''),
        isNull,
      );
    });
  });

  group('lifecycle', () {
    test('a change of account epoch hides the record', () {
      final ledger = TunnelDisplayLedger();
      commit(ledger, 'uk-gb1', locations: [uk()], accountEpoch: 1);
      expect(show(ledger, [uk()], accountEpoch: 1).node?['slug'], 'uk-gb1');
      expect(show(ledger, [uk()], accountEpoch: 2).source,
          DashboardNodeSource.unknownTunnel);
    });

    test('native adoption without identity renders unknown', () {
      final ledger = TunnelDisplayLedger();
      commit(ledger, 'uk-gb1', locations: [uk()]);
      // The session ended, then native reconciliation found a tunnel again.
      expect(ledger.settle(wasConnected: true, isConnected: false), isTrue);
      expect(ledger.settle(wasConnected: false, isConnected: true), isTrue);
      expect(show(ledger, [uk()]).source, DashboardNodeSource.unknownTunnel);
    });

    test('an unchanged connected flag keeps the retained session', () {
      final ledger = TunnelDisplayLedger();
      commit(ledger, 'uk-gb1', locations: [uk()]);
      final generation = ledger.generation;
      expect(ledger.settle(wasConnected: true, isConnected: true), isFalse);
      expect(ledger.generation, generation);
      expect(show(ledger, [uk()]).node?['slug'], 'uk-gb1');
    });

    test('an obsolete completion cannot end a newer session', () {
      final ledger = TunnelDisplayLedger();
      commit(ledger, 'ca-tor1', locations: [canada(), uk()]);
      final observed = ledger.generation;
      // While the obsolete operation waited, a newer tunnel committed.
      commit(ledger, 'uk-gb1', locations: [canada(), uk()]);
      expect(ledger.endSession(observedGeneration: observed), isFalse);
      expect(
          ledger.settle(
              wasConnected: true,
              isConnected: false,
              observedGeneration: observed),
          isFalse);
      expect(show(ledger, [canada(), uk()]).node?['slug'], 'uk-gb1');
      // The current owner can still end it.
      expect(ledger.endSession(observedGeneration: ledger.generation), isTrue);
      expect(ledger.recordFor(accountEpoch: 1), isNull);
    });

    test('a record from an earlier generation is never shown', () {
      final ledger = TunnelDisplayLedger();
      final first = commit(ledger, 'uk-gb1', locations: [uk()])!;
      ledger.endSession();
      expect(first.sessionGeneration, lessThan(ledger.generation));
      expect(ledger.recordFor(accountEpoch: 1), isNull);
    });
  });

  group('committed slug', () {
    test('the served identity wins over the caller slug', () {
      expect(
        committedTunnelNodeSlug(
          servedIdentity: 'uk-gb1',
          callerIdentity: 'ca-tor1',
          coverFallbackInProgress: false,
        ),
        'uk-gb1',
      );
    });

    test('a cover successor names itself, not the failed picker node', () {
      final ledger = TunnelDisplayLedger();
      final locations = [canada(), uk()];
      ledger.commit(
        servedIdentity: 'uk-gb1',
        callerIdentity: 'ca-tor1',
        coverFallbackInProgress: true,
        accountEpoch: 1,
        locations: locations,
      );
      expect(show(ledger, locations, selectedIndex: 0).node?['slug'], 'uk-gb1');
      // During cover the caller is the FAILED node; without a served identity
      // the successor stays unknown rather than naming the failed node.
      expect(
        committedTunnelNodeSlug(
          servedIdentity: '',
          callerIdentity: 'ca-tor1',
          coverFallbackInProgress: true,
        ),
        '',
      );
    });

    test('outside cover fallback the caller slug is the fallback', () {
      expect(
        committedTunnelNodeSlug(
          servedIdentity: '',
          callerIdentity: 'ca-tor1',
          coverFallbackInProgress: false,
        ),
        'ca-tor1',
      );
      expect(
        committedTunnelNodeSlug(
          servedIdentity: 'auto',
          callerIdentity: 'auto',
          coverFallbackInProgress: false,
        ),
        '',
      );
    });
  });

  group('app wiring', () {
    late String source;

    setUpAll(() {
      source = File('lib/main.dart').readAsStringSync();
    });

    String body(String startMarker, String endMarker) {
      final start = source.indexOf(startMarker);
      expect(start, greaterThanOrEqualTo(0), reason: startMarker);
      final end = source.indexOf(endMarker, start);
      expect(end, greaterThan(start), reason: endMarker);
      return source.substring(start, end);
    }

    test('the card renders the display rule and never the cached config', () {
      final dashboard = body(
        'Widget _buildVpnDashboard(',
        'Text(_rendersConnected ? _t("SECURED")',
      );
      expect(dashboard, contains('dashboardNodeForDisplay('));
      expect(dashboard, contains('rendersConnected: _rendersConnected,'));
      expect(dashboard, contains('ledger: _tunnelDisplayLedger,'));
      expect(
          dashboard, contains('accountEpoch: _accountSessionEpoch.current,'));
      expect(dashboard, isNot(contains('_cachedVpnConfig')));
      expect(dashboard, isNot(contains('_locations[safeLocationIndex]')));
      // Unknown identity is explicit, not "Searching..." / "Status: offline".
      expect(
          dashboard,
          contains(
              "nameOverride: tunnelNodeUnknown ? _t('Unknown node') : null"));
      expect(
          dashboard, contains("(tunnelNodeUnknown ? 'unknown' : 'offline')"));
    });

    test('the commit records the served node without moving the selection', () {
      final start = body(
        'Future<bool> _startTunnelCandidate(',
        'Future<bool> _loadPowerProtectionPromptSeen(',
      );
      final lastCancel = start.lastIndexOf(
          'if (shouldCancel?.call() == true) return false;',
          start.indexOf('_tunnelDisplayLedger.commit('));
      final connected = start.indexOf('_isConnected = true;');
      final record = start.indexOf('_tunnelDisplayLedger.commit(');
      expect(lastCancel, greaterThanOrEqualTo(0));
      expect(connected, greaterThan(lastCancel));
      expect(record, greaterThan(connected));
      expect(
        start.substring(record),
        startsWith('_tunnelDisplayLedger.commit(\n'
            '            servedIdentity: winn3SelectedNodeIdentity(configForPersistence),'),
      );
      expect(start.substring(record, record + 400),
          contains('accountEpoch: _accountSessionEpoch.current,'));
      expect('_tunnelDisplayLedger.commit('.allMatches(source).length, 1);
      // The v3 caller identity still comes from the independent selection.
      expect(
        start,
        contains('independentlySelectedSlug: _currentSelectedSlug(),'),
      );
    });

    test('every connected-flag write keeps the display session in step', () {
      final writes = RegExp(r'_isConnected = (?!=)')
          .allMatches(source)
          .where((write) => !source
              .substring(write.start - 20, write.start)
              .contains('bool '))
          .toList();
      // Anti-vacuity: the known write sites are all still found.
      expect(writes.length, greaterThanOrEqualTo(20));
      for (final write in writes) {
        final start = write.start;
        final window = source.substring((start - 400).clamp(0, source.length),
            (start + 400).clamp(0, source.length));
        final lineStart = source.lastIndexOf('\n', start);
        expect(
          window.contains('_settleTunnelDisplaySession(') ||
              window.contains('_tunnelDisplayLedger.'),
          isTrue,
          reason: source.substring(lineStart + 1, source.indexOf('\n', start)),
        );
      }
    });

    test('teardown owners capture the display generation before awaiting', () {
      final toggle = body(
        'Future<void> _toggleVpnConnection() async {',
        'void _showFeedback(String message) {',
      );
      final captures =
          'final displayGeneration = _tunnelDisplayLedger.generation;'
              .allMatches(toggle)
              .length;
      expect(captures, 2);
      expect(
          'observedGeneration: displayGeneration'.allMatches(toggle).length, 3);
      final reconcile = body(
        'Future<void> _reconcileNativeTunnelState(',
        'void _armCalculatorAfterConfirmedDisconnect() {',
      );
      expect(reconcile.indexOf('_tunnelDisplayLedger.generation'),
          lessThan(reconcile.indexOf('await _readNativeTunnelActive()')));
    });

    test('account cleanup ends the display session', () {
      for (final marker in [
        'void _resetAccountUiAfterVerifiedCleanup() {',
        'void _forcePendingAccountCleanupUi() {',
      ]) {
        final cleanup = body(marker, '\n  }\n');
        expect(cleanup, contains('_tunnelDisplayLedger.endSession();'),
            reason: marker);
      }
    });
  });
}
