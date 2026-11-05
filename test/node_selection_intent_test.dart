import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/main.dart';

void main() {
  group('node request intent', () {
    test('automatic intent ignores the displayed active node', () {
      expect(
        nodeLocationForRequest(
          automatic: true,
          displayedNodeSlug: 'hub-selected-node',
        ),
        'auto',
      );
    });

    test('cover exact slug wins over automatic routing', () {
      expect(
        nodeLocationForRequest(
          automatic: true,
          displayedNodeSlug: 'hub-selected-node',
          exactCoverTargetSlug: 'france-winn1',
        ),
        'france-winn1',
      );
      expect(
        () => nodeLocationForRequest(
          automatic: true,
          displayedNodeSlug: 'hub-selected-node',
          exactCoverTargetSlug: 'auto',
        ),
        throwsStateError,
      );
    });

    test('explicit intent always returns a concrete node', () {
      expect(
        nodeLocationForRequest(
          automatic: false,
          displayedNodeSlug: 'user-selected-node',
        ),
        'user-selected-node',
      );
    });

    test('invalid explicit intent fails instead of entering automatic routing',
        () {
      expect(
        () => nodeLocationForRequest(
          automatic: false,
          displayedNodeSlug: 'auto',
        ),
        throwsStateError,
      );
      expect(
        () => nodeLocationForRequest(
          automatic: false,
          displayedNodeSlug: 'AUTO',
        ),
        throwsStateError,
      );
      expect(
        () => nodeLocationForRequest(
          automatic: false,
          displayedNodeSlug: '  ',
        ),
        throwsStateError,
      );
    });
  });

  group('app integration contract', () {
    late String source;

    setUpAll(() {
      source = File('lib/main.dart').readAsStringSync();
    });

    String methodBody(String startMarker, String endMarker) {
      final start = source.indexOf(startMarker);
      final end = source.indexOf(endMarker, start);
      expect(start, greaterThanOrEqualTo(0), reason: startMarker);
      expect(end, greaterThan(start), reason: endMarker);
      return source.substring(start, end);
    }

    test('activation, free refresh, and paid reconnect use routing intent', () {
      final activation = methodBody(
        'Future<void> _loginWithAccountNumber() async',
        'Map<String, dynamic> _freeAccessPayload(',
      );
      final freePayload = methodBody(
        'Map<String, dynamic> _freeAccessPayload(',
        'Future<void> _loginWithFreeAccess() async',
      );
      final reconnect = methodBody(
        'Future<bool> _refreshVpnConfigForCurrentSelection(',
        'Future<bool> _waitForTunnelState(',
      );

      expect(activation, contains('"location": _requestedLocationSlug(),'));
      expect(freePayload, contains('"location": _requestedLocationSlug(),'));
      expect(
          reconnect,
          contains(
              "final requestLocation = requestedLocation ?? _requestedLocationSlug();"));
      expect(reconnect, contains("'location': requestLocation,"));
    });

    test('automatic initiation reaches backend before cached fallback', () {
      final connect = methodBody(
        'Future<void> _connectWithSmartProtocol(',
        'Future<void> _toggleVpnConnection() async',
      );
      final cacheRead = connect.indexOf(
        'final cachedDirectConfig = _cachedDirectConfigForFastConnect();',
      );
      final skipGate = connect.indexOf(
        'maySkipControlPlaneRefreshWithCachedConfig(',
      );
      final backendRefresh = connect.indexOf(
        'await _refreshVpnConfigForCurrentSelection(',
        skipGate,
      );
      final cachedFallback = connect.indexOf(
        'mayLeadWithCachedConfigAfterRefreshFailure(',
        backendRefresh,
      );

      expect(cacheRead, greaterThanOrEqualTo(0));
      expect(skipGate, greaterThan(cacheRead));
      expect(backendRefresh, greaterThan(skipGate));
      expect(cachedFallback, greaterThan(backendRefresh));
    });

    test('node discovery and auth responses update display only', () {
      final authApply = methodBody(
        'void _applySelectedNodeFromAuth(',
        'Map<String, dynamic> _normalizeVpnConfig(',
      );
      final discovery = methodBody(
        'Future<void> _parseNodesResponse(String body) async',
        'Future<void> _saveCachedNodes() async',
      );

      expect(authApply, contains('_selectedLocationIndex ='));
      expect(authApply, contains('_winn3CoverExactTargetSlug'));
      // Discovery re-binds the selection through _rebindSelection, which
      // writes the index and the unlisted record but never the intent mode.
      final rebind = methodBody(
        'void _rebindSelection(String intendedSlug,',
        'void _applySelectedNodeFromAuth(',
      );
      expect(discovery, contains('_rebindSelection(selectedSlug'));
      expect(rebind, contains('_selectedLocationIndex ='));
      expect(authApply, isNot(contains('_automaticNodeSelection =')));
      expect(discovery, isNot(contains('_automaticNodeSelection =')));
      expect(rebind, isNot(contains('_automaticNodeSelection =')));
    });

    test('automatic versus explicit intent is durable', () {
      final save = methodBody(
        'Future<void> _saveVpnRuntimeSettings({',
        'Future<bool> _readNativeTunnelActive()',
      );
      expect(
        save,
        contains("data['automatic_node_selection'] = "
            '_automaticNodeSelection;'),
      );
      expect(
        source,
        contains("settingsData['automatic_node_selection'] != false;"),
      );
    });

    test('picker and watch selections explicitly bypass AI', () {
      final watch = methodBody(
        'Future<void> _selectWatchCountry(String slug) async',
        'void _publishWatchState()',
      );
      final picker = methodBody(
        'void _showLocationPickerSheet({bool freeOnly = false})',
        'Widget _buildFreeServerSelector()',
      );

      // Both the watch and a phone row go through one tap handler, which
      // makes the pick explicit (behaviour: selected_node_rebind_test).
      final row = methodBody(
        'Future<void> _onServerRowTapped(',
        'void _showLocationPickerSheet({bool freeOnly = false})',
      );
      expect(watch, contains('await _onServerRowTapped('));
      expect(picker, contains('await _onServerRowTapped(location'));
      expect(row, contains('_automaticNodeSelection = false;'));
      expect(picker, contains('_automaticNodeSelection = true'));
    });
  });
}
