import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production method: $start');
  }
  return source.substring(first, last);
}

void main() {
  late Directory temporary;
  late File executable;
  late String source;

  setUpAll(() async {
    source = File('lib/main.dart').readAsStringSync();
    final switchMethod = _between(
      source,
      '  Future<void> _switchConnectedServer(',
      '  Future<void> _showLocationPicker(',
    );
    // The display-ownership helpers the switch consults, verbatim.
    final displayOwnership = _between(
      source,
      "  /// Keeps the dashboard's committed-node record in step",
      '  void _finishTunnelConnectFailure(',
    );
    // The selection re-bind the switch's restore calls, verbatim.
    final selectionRebind = _between(
      source,
      '  /// A manual choice that the listing does not carry, so no row is selected.',
      '  void _applySelectedNodeFromAuth(',
    );
    temporary =
        await Directory.systemTemp.createTemp('wins-switch-transaction-');
    executable = File('${temporary.path}/switch_transaction.dart');
    // The dashboard's display ledger is production code too, imported as-is.
    final displayLedger =
        File('lib/tunnel_display_identity.dart').absolute.uri;
    // Execute the production method verbatim. Only its external dependencies
    // are replaced: native operations, connector preparation, widget state,
    // and persistence. This is transaction coverage, not device VPN proof.
    final rebind = File('lib/node_selection_rebind.dart').absolute.uri;
    await executable.writeAsString(
        "import '$displayLedger';\nimport '$rebind';\n"
        '$_harnessBefore\n$displayOwnership\n$selectionRebind\n'
        '$switchMethod\n$_harnessAfter');
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'prepare_false',
    'prepare_throw',
    'prepare_timeout',
    'prepared_start',
    'cancel_prepare',
    'cancel_stop',
    'stop_failed_active',
    'stop_failed_inactive',
    'old_node_removed',
    'target_removed_before_switch',
    'prepare_failed_native_died',
    'account_changed',
    'cancel_prepare_newer_record',
    'cancel_stop_newer_record',
    'cold_start_prepared_rejected',
    'persist_failed_then_adopted',
    'cover_successor',
    'committed_node_delisted',
  ]) {
    test('production connected-server transaction: $scenario', () async {
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[executable.path, scenario],
        workingDirectory: temporary.path,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }

  test('staged refresh returns before durable config publication', () {
    for (final boundaries in const <List<String>>[
      <String>[
        '  Future<bool> _refreshFreeVpnConfig(',
        '  Future<bool> _refreshVpnConfigForCurrentSelection(',
      ],
      <String>[
        '  Future<bool> _refreshVpnConfigForCurrentSelection(',
        '  Future<bool> _waitForTunnelState(',
      ],
    ]) {
      final refresh = _between(source, boundaries[0], boundaries[1]);
      final preparedBlocks = RegExp(
        r'if \(onPrepared != null\)\s*\{\s*'
        r'onPrepared\(normalized, responseData\);\s*return true;\s*\}',
      ).allMatches(refresh).toList();
      expect(preparedBlocks, isNotEmpty, reason: boundaries[0]);
      expect(
          preparedBlocks.length,
          RegExp(r'await _persistVpnConfigBestEffort\(')
              .allMatches(refresh)
              .length,
          reason: 'every refresh publication must offer the staged return');
      for (final block in preparedBlocks) {
        final followingWrite =
            refresh.indexOf('await _persistVpnConfigBestEffort(', block.end);
        expect(followingWrite, greaterThan(block.end));
      }
    }
    expect(source, isNot(contains('_lastConfigRefreshTime')));
  });

  test('native cutover follows config construction and precedes native start',
      () {
    final candidate = _between(source, '  Future<bool> _startTunnelCandidate(',
        '  Future<bool> _loadPowerProtectionPromptSeen(');
    final construct = candidate.indexOf('final rawTunnelConfig =');
    final cutover = candidate.indexOf('await beforeTunnelStart()');
    final start = candidate.indexOf("'startTunnel',");
    expect(construct, greaterThanOrEqualTo(0));
    expect(cutover, greaterThan(construct));
    expect(start, greaterThan(cutover));
    expect(candidate.substring(cutover, start),
        contains('shouldCancel?.call() == true'));
  });

  test('cancellation owner clears server-switch transition flag', () {
    final cancellation = _between(
        source,
        '  Future<void> _toggleVpnConnection() async {',
        '    if (_appUpdateRequired && !_isConnected) {');
    final stop = cancellation.indexOf('await _cancelAndStopNativeTunnel(');
    final clear = cancellation.indexOf('_isTunnelTransitioning = false');
    expect(stop, greaterThanOrEqualTo(0));
    expect(clear, greaterThan(stop));
  });
}

const _harnessBefore = r'''
import 'dart:async';

class _Epoch {
  int current = 0;
}

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

class Harness {
  bool mounted = true;
  bool _isConnected = true;
  bool _isLoading = false;
  bool _automaticNodeSelection = false;
  bool _isVpnConnectInFlight = false;
  bool _isTunnelTransitioning = false;
  bool _supportsNativeTunnelReadiness = true;
  // C-core-17 (ruling A2) fence members the extracted consumers read.
  bool _appInBackground = false;
  int _resumeProofGeneration = 0;
  int _selectedLocationIndex = 0;
  Map<String, dynamic>? _unlistedSelection;
  DateTime? _liveListingReceivedAt;
  bool _showDecoyCalculator = false;
  int _vpnUiOperationEpoch = 0;
  String _ipAfterVpn = 'France secured';
  String _activeProtocolLabel = 'Winn';
  String _activeProtocolVersion = 'winn/1';
  String? _winn3IngestRouterV4;
  final String _defaultProtocolLabel = 'Winn';
  final _accountSessionEpoch = _Epoch();
  List<Map<String, dynamic>> _locations = <Map<String, dynamic>>[
    <String, dynamic>{'slug': 'france', 'name': 'France'},
    <String, dynamic>{'slug': 'germany', 'name': 'Germany'},
  ];
  Map<String, dynamic> _cachedVpnConfig = <String, dynamic>{'node_slug': 'france'};
  final _tunnelDisplayLedger = TunnelDisplayLedger();
  // Round UN: adoption asks for a persisted-record restore. The restore
  // itself runs verbatim in tunnel_display_restore_production_test.dart;
  // here only the request is counted.
  int restoreSchedules = 0;
  void _scheduleTunnelDisplayRestore() => restoreSchedules++;
  // The durable copy a process restart would load; _cachedVpnConfig is the
  // in-memory one production also uses as preparation state.
  Map<String, dynamic> persistedConfig = <String, dynamic>{'node_slug': 'france'};
  final List<String> events = <String>[];
  final List<String> feedback = <String>[];
  String preparation = 'success';
  bool nativeActive = true;
  bool stopResult = true;
  bool removePreviousNode = false;
  // Production staged refresh writes the prepared config into
  // _cachedVpnConfig before onPrepared returns (main.dart
  // _refreshVpnConfigForCurrentSelection / _refreshFreeVpnConfig).
  bool stagePreparedConfig = false;
  bool persistFails = false;
  String? servedSlug;
  bool coverFallback = false;
  int stagedWrites = 0;
  int stops = 0;
  int starts = 0;
  int cacheWrites = 0;
  int settingsWrites = 0;
  int nativeReads = 0;
  Completer<void>? prepareGate;
  Completer<void>? stopGate;
  final prepared = Completer<void>();
  final stopping = Completer<void>();

  void setState(void Function() update) => update();
  String _t(String value) => value;
  void _debugLog(String message) {}
  void _showFeedback(String message) => feedback.add(message);
  bool _accountEpochIsCurrent(int epoch) =>
      _accountSessionEpoch.current == epoch;
  String _currentSelectedSlug() =>
      _locations[_selectedLocationIndex]['slug'] as String;
  int _indexForNodeSlug(String? slug) {
    final index = _locations.indexWhere((node) => node['slug'] == slug);
    return index < 0 ? 0 : index;
  }
  List<Map<String, dynamic>> _sortedNodeItems(
      Iterable<Map<String, dynamic>> nodes) => nodes.toList();
  Future<void> _saveVpnRuntimeSettings() async {
    settingsWrites++;
    events.add('settings');
  }
  Future<bool> _readNativeTunnelActive() async {
    nativeReads++;
    events.add('read');
    return nativeActive;
  }
  void _finishTunnelConnectFailure(String message) {
    feedback.add(message);
    final wasConnected = _isConnected;
    _isConnected = false;
    _tunnelDisplayLedger.settle(
        wasConnected: wasConnected, isConnected: _isConnected);
    _activeProtocolLabel = _defaultProtocolLabel;
    _activeProtocolVersion = '';
    _ipAfterVpn = 'Disconnected';
  }
  Future<bool> _stopNativeTunnel({bool keepVpnLauncher = false}) async {
    stops++;
    events.add('stop');
    if (!stopping.isCompleted) stopping.complete();
    if (stopGate != null) await stopGate!.future;
    if (stopResult) nativeActive = false;
    return stopResult;
  }
  Future<void> _connectWithSmartProtocol({
    Future<bool> Function()? beforeTunnelStart,
  }) async {
    events.add('prepare');
    check(nativeActive, 'old native route must be active during preparation');
    if (!prepared.isCompleted) prepared.complete();
    if (prepareGate != null) await prepareGate!.future;
    if (removePreviousNode) {
      _locations.removeWhere((node) => node['slug'] == 'france');
      _selectedLocationIndex = 0;
    }
    final served = servedSlug ?? _currentSelectedSlug();
    if (stagePreparedConfig) {
      stagedWrites++;
      _cachedVpnConfig = <String, dynamic>{'node_slug': served};
    }
    if (preparation == 'false') return;
    if (preparation == 'throw') throw StateError('preparation rejected');
    if (preparation == 'timeout') throw TimeoutException('hub timed out');
    check(beforeTunnelStart != null, 'switch must supply the native cutover');
    if (!await beforeTunnelStart!()) return;
    check(!nativeActive, 'native start must follow confirmed old-route stop');
    check(!_isConnected, 'old connection cannot remain secured during cutover');
    check(_tunnelDisplayLedger.recordFor(
                accountEpoch: _accountSessionEpoch.current) ==
            null,
        'confirmed cutover must end the retained display session');
    starts++;
    events.add('start');
    nativeActive = true;
    cacheWrites++;
    _cachedVpnConfig = <String, dynamic>{'node_slug': served};
    // _persistVpnConfigBestEffort swallows a failed write; the commit below
    // still happens, exactly as in production.
    if (!persistFails) persistedConfig = Map<String, dynamic>.from(_cachedVpnConfig);
    events.add('persist');
    _isConnected = true;
    // Mirrors the production commit in _startTunnelCandidate.
    _tunnelDisplayLedger.commit(
      servedIdentity: served,
      callerIdentity: _currentSelectedSlug(),
      coverFallbackInProgress: coverFallback,
      accountEpoch: _accountSessionEpoch.current,
      locations: _locations,
    );
    _ipAfterVpn = 'Germany secured';
    events.add('secured');
  }

  // A tunnel committed in this process before the scenario starts.
  void commitInitialTunnel() {
    _tunnelDisplayLedger.commit(
      servedIdentity: 'france',
      callerIdentity: 'france',
      coverFallbackInProgress: false,
      accountEpoch: _accountSessionEpoch.current,
      locations: _locations,
    );
  }

  // Mirrors production native adoption (_restoreSession / reconcile): the
  // tunnel is live but nothing in this process committed it.
  void adoptNativeTunnel() {
    final wasConnected = _isConnected;
    _isConnected = true;
    _tunnelDisplayLedger.settle(
        wasConnected: wasConnected, isConnected: _isConnected);
  }

  DashboardNodeDisplay display() => dashboardNodeForDisplay(
        locations: _locations,
        selectedIndex: _selectedLocationIndex,
        rendersConnected:
            _isConnected && !_isVpnConnectInFlight && !_isTunnelTransitioning,
        ledger: _tunnelDisplayLedger,
        accountEpoch: _accountSessionEpoch.current,
      );

  void checkDisplays(String? slug, String message) {
    final shown = display();
    if (slug == null) {
      check(shown.source == DashboardNodeSource.unknownTunnel &&
              shown.node == null,
          '$message (got ${shown.source} ${shown.node})');
    } else {
      check(shown.source == DashboardNodeSource.committedTunnel &&
              shown.node?['slug'] == slug,
          '$message (got ${shown.source} ${shown.node})');
    }
  }

  void claimNewUiOwner() {
    _vpnUiOperationEpoch++;
    _isLoading = true;
    _isVpnConnectInFlight = true;
    _isTunnelTransitioning = true;
    _ipAfterVpn = 'new owner';
  }

  void checkRetainedRoute() {
    check(stops == 0, 'failed preparation stopped the native tunnel');
    check(starts == 0, 'failed preparation started another tunnel');
    check(cacheWrites == 0, 'failed preparation published a VPN config');
    check(_cachedVpnConfig['node_slug'] == 'france', 'old config changed');
    check(nativeActive && _isConnected, 'old route was not retained');
    check(nativeReads > 0, 'restored secured state requires fresh native proof');
    check(_currentSelectedSlug() == 'france', 'old node selection not restored');
    check(_ipAfterVpn == 'France secured', 'old connected status not restored');
    check(!_isLoading && !_isVpnConnectInFlight && !_isTunnelTransitioning,
        'failed switch did not settle its own UI flags');
    checkDisplays('france', 'retained route must keep naming its own node');
  }

  void checkNewOwnerUntouched() {
    check(_isLoading && _isVpnConnectInFlight && _isTunnelTransitioning,
        'obsolete switch cleared the current owner UI flags');
    check(_ipAfterVpn == 'new owner', 'obsolete switch overwrote current status');
    check(starts == 0 && cacheWrites == 0, 'obsolete switch started or published');
    check(settingsWrites == 0, 'obsolete switch wrote current owner settings');
  }
''';

const _harnessAfter = r'''
}

Future<void> main(List<String> arguments) async {
  final scenario = arguments.single;
  final h = Harness();
  final coldStart = scenario == 'cold_start_prepared_rejected';
  if (coldStart) {
    h._isConnected = false;
    h.adoptNativeTunnel();
  } else {
    h.commitInitialTunnel();
    h.checkDisplays('france', 'initial committed tunnel must be named');
  }
  final initialDisplayGeneration = h._tunnelDisplayLedger.generation;
  switch (scenario) {
    case 'prepare_false':
    case 'prepare_throw':
    case 'prepare_timeout':
      h.preparation = scenario.substring('prepare_'.length);
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      h.checkRetainedRoute();
    case 'prepared_start':
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      check(h.stops == 1 && h.starts == 1 && h.cacheWrites == 1,
          'successful switch must stop/start/persist exactly once');
      check(h.events.indexOf('prepare') < h.events.indexOf('stop') &&
          h.events.indexOf('stop') < h.events.indexOf('start') &&
          h.events.indexOf('start') < h.events.indexOf('secured'),
          'successful switch violated preparation/cutover/commit ordering');
      check(h._isConnected && h.nativeActive, 'new route did not commit');
      check(h._currentSelectedSlug() == 'germany', 'new node not selected');
      check(!h._isLoading && !h._isTunnelTransitioning && !h._isVpnConnectInFlight,
          'successful switch did not settle UI');
      check(h._tunnelDisplayLedger.generation > initialDisplayGeneration + 1,
          'replacement commit must start a new display session after cutover');
      h.checkDisplays('germany', 'replacement commit must name its own node');
    case 'cancel_prepare':
    case 'account_changed':
    case 'cancel_prepare_newer_record':
      h.prepareGate = Completer<void>();
      final pending = h._switchConnectedServer('Germany', targetSlug: 'germany');
      await h.prepared.future;
      // Beginning a switch does not end the retained display session.
      check(h._tunnelDisplayLedger.generation == initialDisplayGeneration,
          'switch start cleared the retained display session');
      if (scenario == 'account_changed') {
        h._accountSessionEpoch.current++;
        h._ipAfterVpn = 'new owner';
      } else {
        h.claimNewUiOwner();
      }
      if (scenario == 'cancel_prepare_newer_record') {
        // The newer owner commits its own tunnel while the obsolete switch
        // is still waiting on preparation.
        h._tunnelDisplayLedger.commit(
          servedIdentity: 'germany',
          callerIdentity: 'germany',
          coverFallbackInProgress: false,
          accountEpoch: h._accountSessionEpoch.current,
          locations: h._locations,
        );
      }
      final ownerGeneration = h._tunnelDisplayLedger.generation;
      h.prepareGate!.complete();
      await pending;
      check(h.stops == 0, 'cancelled preparation stopped the native tunnel');
      h.checkNewOwnerUntouched();
      check(h._tunnelDisplayLedger.generation == ownerGeneration,
          'obsolete switch changed the display session');
      if (scenario == 'cancel_prepare_newer_record') {
        check(h._tunnelDisplayLedger
                    .recordFor(accountEpoch: h._accountSessionEpoch.current)
                    ?.slug ==
                'germany',
            'obsolete switch cleared or overwrote the newer display record');
      } else if (scenario == 'account_changed') {
        // The record belongs to the previous account: a secured card for the
        // current account must not name it.
        final secured = dashboardNodeForDisplay(
          locations: h._locations,
          selectedIndex: h._selectedLocationIndex,
          rendersConnected: true,
          ledger: h._tunnelDisplayLedger,
          accountEpoch: h._accountSessionEpoch.current,
        );
        check(secured.source == DashboardNodeSource.unknownTunnel,
            'account change must not keep naming the previous account node');
      } else {
        check(h._tunnelDisplayLedger
                    .recordFor(accountEpoch: h._accountSessionEpoch.current)
                    ?.slug ==
                'france',
            'obsolete switch cleared the display record it did not own');
      }
    case 'cancel_stop':
    case 'cancel_stop_newer_record':
      h.stopGate = Completer<void>();
      final pending = h._switchConnectedServer('Germany', targetSlug: 'germany');
      await h.stopping.future;
      h.claimNewUiOwner();
      if (scenario == 'cancel_stop_newer_record') {
        h._tunnelDisplayLedger.commit(
          servedIdentity: 'germany',
          callerIdentity: 'germany',
          coverFallbackInProgress: false,
          accountEpoch: h._accountSessionEpoch.current,
          locations: h._locations,
        );
      }
      final ownerGeneration = h._tunnelDisplayLedger.generation;
      h.stopGate!.complete();
      await pending;
      check(h.stops == 1, 'cancellation caused a second native stop');
      h.checkNewOwnerUntouched();
      check(h._tunnelDisplayLedger.generation == ownerGeneration,
          'obsolete cutover changed the display session');
      if (scenario == 'cancel_stop_newer_record') {
        check(h._tunnelDisplayLedger
                    .recordFor(accountEpoch: h._accountSessionEpoch.current)
                    ?.slug ==
                'germany',
            'obsolete cutover cleared or overwrote the newer display record');
      }
    case 'stop_failed_active':
    case 'stop_failed_inactive':
      h.stopResult = false;
      if (scenario == 'stop_failed_inactive') {
        h.stopGate = Completer<void>();
        final pending = h._switchConnectedServer('Germany', targetSlug: 'germany');
        await h.stopping.future;
        h.nativeActive = false;
        h.stopGate!.complete();
        await pending;
      } else {
        await h._switchConnectedServer('Germany', targetSlug: 'germany');
      }
      check(h.stops == 1 && h.starts == 0 && h.cacheWrites == 0,
          'inconclusive teardown must not start or publish replacement');
      check(h._isConnected == h.nativeActive,
          'stop failure must reflect native state, not optimistic green');
      check(h._currentSelectedSlug() == 'france', 'old selection not restored');
      check(!h._isLoading && !h._isTunnelTransitioning && !h._isVpnConnectInFlight,
          'stop failure did not settle its UI');
      if (h.nativeActive) {
        h.checkDisplays('france', 'still-active retained tunnel must keep its node');
      } else {
        check(
            h._tunnelDisplayLedger
                    .recordFor(accountEpoch: h._accountSessionEpoch.current) ==
                null,
            'a retained tunnel that died kept its display record');
      }
    case 'target_removed_before_switch':
      // A refresh removed Germany after the row was tapped: the switch is
      // refused before anything is prepared or stopped, never row 0.
      h._locations.removeWhere((node) => node['slug'] == 'germany');
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      check(!h.events.contains('prepare'), 'a removed target was prepared');
      check(h.stops == 0 && h.starts == 0, 'a removed target touched the tunnel');
      check(h._currentSelectedSlug() == 'france' && !h._automaticNodeSelection,
          'the selection moved to ${h._currentSelectedSlug()}');
      check(h._isConnected && !h._isLoading, 'the retained route was disturbed');
      check(h.feedback.any((m) => m.contains('Germany is no longer in the server list')),
          'the refusal was not explained: ${h.feedback}');
    case 'old_node_removed':
      h.preparation = 'false';
      h.removePreviousNode = true;
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      h.checkRetainedRoute();
    case 'prepare_failed_native_died':
      h.preparation = 'false';
      h.prepareGate = Completer<void>();
      final pending = h._switchConnectedServer('Germany', targetSlug: 'germany');
      await h.prepared.future;
      h.nativeActive = false;
      h.prepareGate!.complete();
      await pending;
      check(h.stops == 0 && h.starts == 0 && h.cacheWrites == 0,
          'failed preparation must not alter tunnel or config');
      check(h.nativeReads > 0 && !h._isConnected,
          'failed preparation restored stale green after old tunnel died');
      check(h._ipAfterVpn == 'Disconnected', 'native-down status not reflected');
      check(
          h._tunnelDisplayLedger
                  .recordFor(accountEpoch: h._accountSessionEpoch.current) ==
              null,
          'failed preparation kept a record after the retained tunnel died');
      // A later native reconciliation that finds a tunnel again cannot
      // resurrect the dead session's node.
      h.nativeActive = true;
      h.adoptNativeTunnel();
      h.checkDisplays(null, 'native adoption must render an unknown node');
    case 'cold_start_prepared_rejected':
      // Restart with tunnel A live: nothing in this process committed it.
      h.checkDisplays(null, 'cold-start adoption must render an unknown node');
      h.stagePreparedConfig = true;
      h.preparation = 'false';
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      check(h.stagedWrites == 1 && h._cachedVpnConfig['node_slug'] == 'germany',
          'model must stage prepared B into the cache like production');
      check(h.stops == 0 && h.starts == 0 && h.cacheWrites == 0,
          'rejected B must not alter the tunnel or publish a config');
      check(h.nativeActive && h._isConnected, 'retained A was not kept');
      check(h._currentSelectedSlug() == 'france', 'old selection not restored');
      h.checkDisplays(null,
          'retained cold-start tunnel must stay unknown, never the prepared B');
    case 'persist_failed_then_adopted':
      h.persistFails = true;
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      check(h.starts == 1 && h._isConnected, 'switch did not commit');
      check(h.persistedConfig['node_slug'] == 'france',
          'model must leave the stale durable config after a failed write');
      h.checkDisplays('germany',
          'a failed best-effort write must not change the committed node');
      // Process restart: the stale persisted config is loaded and the live
      // tunnel is adopted without identity.
      final restarted = Harness();
      restarted._cachedVpnConfig =
          Map<String, dynamic>.from(h.persistedConfig);
      restarted._isConnected = false;
      restarted.adoptNativeTunnel();
      restarted.checkDisplays(null,
          'adopted tunnel must be unknown, not the stale persisted node');
    case 'cover_successor':
      h._locations.add(<String, dynamic>{
        'slug': 'spain',
        'name': 'Spain',
        'status': 'online',
        'latency_ms': 48,
      });
      h.servedSlug = 'spain';
      h.coverFallback = true;
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      check(h.starts == 1 && h._isConnected, 'cover successor did not commit');
      check(h._currentSelectedSlug() == 'germany',
          'cover successor must not move the picker selection');
      h.checkDisplays('spain', 'card must name the cover successor it dials');
      check(h.display().node?['latency_ms'] == 48,
          'a listed committed node must show its current listing health');
    case 'committed_node_delisted':
      h._locations[1]['flag'] = 'DE';
      h._locations[1]['status'] = 'online';
      h._locations[1]['latency_ms'] = 31;
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      h.checkDisplays('germany', 'replacement commit must name its own node');
      // A later listing refresh no longer carries the committed node.
      h._locations.removeWhere((node) => node['slug'] == 'germany');
      h._selectedLocationIndex = 0;
      final shown = h.display().node!;
      check(shown['status'] == 'unknown',
          'a delisted node must not keep its cached status');
      check(!shown.containsKey('latency_ms'),
          'a delisted node must not keep its cached latency');
      check(shown['name'] == 'Germany' && shown['flag'] == 'DE',
          'a delisted node keeps its committed identity');
    default:
      throw StateError('Unknown scenario: $scenario');
  }
  print('PASS $scenario');
}
''';
