// The saved server choice survives listing changes, and the server list's
// check marks the node in use.
//
// Seen on an S26 on 2026-09-27 (lane L83): a free session carried on
// us-chicago1 while the card read "Unknown node" and the list's check sat on
// Canada, the first row by name once Canada was listed again. A cold start
// filtered every cached row out of the free listing, the choice became row 0,
// and the check followed the saved choice rather than the carrying node.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/node_selection_rebind.dart';
import 'package:wins_vpn/tunnel_display_identity.dart';

Map<String, dynamic> _node(String slug, String name) =>
    <String, dynamic>{'slug': slug, 'name': name, 'status': 'online'};

final _ca = _node('canada-ca1', 'Canada');
final _de = _node('germany-de1', 'Germany');
final _nl = _node('netherlands-nl1', 'Netherlands');
final _uk = _node('uk-gb1', 'United Kingdom');
final _us = _node('us-chicago1', 'United States (Chicago)');

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production code: $start');
  }
  return source.substring(first, last);
}

DashboardNodeDisplay _picker(List<Map<String, dynamic>> locations, int index,
        {Map<String, dynamic>? unlisted}) =>
    dashboardNodeForDisplay(
      locations: locations,
      selectedIndex: index,
      rendersConnected: false,
      ledger: TunnelDisplayLedger(),
      accountEpoch: 1,
      unlistedSelection: unlisted,
    );

DashboardNodeDisplay _connected(
    List<Map<String, dynamic>> locations, String? committedSlug) {
  final ledger = TunnelDisplayLedger();
  if (committedSlug == null) {
    // Native adoption after a restart: connected, no verified identity.
    ledger.settle(wasConnected: false, isConnected: true);
  } else {
    ledger.commit(
      servedIdentity: committedSlug,
      callerIdentity: committedSlug,
      coverFallbackInProgress: false,
      accountEpoch: 1,
      locations: locations,
    );
  }
  return dashboardNodeForDisplay(
    locations: locations,
    selectedIndex: 0,
    rendersConnected: true,
    ledger: ledger,
    accountEpoch: 1,
  );
}

void main() {
  group('rebindSelection', () {
    test('a listed choice binds to its row in either mode', () {
      for (final automatic in [false, true]) {
        final r = rebindSelection(
          locations: [_ca, _de, _us],
          intendedSlug: 'us-chicago1',
          automatic: automatic,
        );
        expect(r.index, 2);
        expect(r.unlisted, isNull);
      }
    });

    test('an unlisted manual choice stays the choice, never row 0', () {
      final r = rebindSelection(
        locations: [_nl, _uk, _us],
        intendedSlug: 'canada-ca1',
        automatic: false,
        knownRows: [_ca],
      );
      expect(r.index, kUnlistedSelectionIndex);
      expect(r.unlisted, <String, dynamic>{
        'slug': 'canada-ca1',
        'name': 'Canada',
      });
    });

    test('an empty listing keeps a manual choice unlisted, not row 0', () {
      final r = rebindSelection(
        locations: const [],
        intendedSlug: 'us-chicago1',
        automatic: false,
      );
      expect(r.index, kUnlistedSelectionIndex);
      expect(r.unlisted?['slug'], 'us-chicago1');
      expect(r.unlisted?['name'], 'us-chicago1',
          reason: 'identity without a known row falls back to the slug');
    });

    test('automatic and slug-less choices keep the row-0 display default', () {
      for (final slug in ['canada-ca1', '', 'auto', 'AUTO', '  ']) {
        final automatic = slug == 'canada-ca1';
        final r = rebindSelection(
          locations: [_nl, _us],
          intendedSlug: slug,
          automatic: automatic,
        );
        expect(r.index, 0, reason: slug);
        expect(r.unlisted, isNull, reason: slug);
      }
    });

    test('an empty flag is not carried as identity', () {
      final r = rebindSelection(
        locations: const [],
        intendedSlug: 'canada-ca1',
        automatic: false,
        knownRows: [
          <String, dynamic>{'slug': 'canada-ca1', 'name': 'Canada', 'flag': ' '}
        ],
      );
      expect(r.unlisted!.containsKey('flag'), isFalse);
    });
  });

  group('fresh live listing', () {
    final now = DateTime.utc(2026, 9, 27, 21);
    test('only a live listing within the window is fresh', () {
      expect(listingIsFresh(liveListingAt: null, now: now), isFalse);
      expect(listingIsFresh(liveListingAt: now, now: now), isTrue);
      expect(
          listingIsFresh(
              liveListingAt: now.subtract(kFreshListingMaxAge), now: now),
          isTrue);
      expect(
          listingIsFresh(
              liveListingAt: now
                  .subtract(kFreshListingMaxAge)
                  .subtract(const Duration(seconds: 1)),
              now: now),
          isFalse);
      expect(
          listingIsFresh(
              liveListingAt: now.add(const Duration(seconds: 5)), now: now),
          isFalse,
          reason: 'a clock that went backwards is no evidence');
    });

    test('an omission counts only in a fresh, nonempty listing', () {
      bool omits(List<Map<String, dynamic>> l, String slug, DateTime? at) =>
          freshListingOmits(
              locations: l, slug: slug, liveListingAt: at, now: now);
      expect(omits([_nl, _us], 'canada-ca1', now), isTrue);
      expect(omits([_nl, _us], 'us-chicago1', now), isFalse);
      expect(omits([_nl, _us], 'canada-ca1', null), isFalse);
      expect(
          omits([_nl, _us], 'canada-ca1',
              now.subtract(const Duration(minutes: 10))),
          isFalse);
      expect(omits(const [], 'canada-ca1', now), isFalse);
      expect(omits([_nl], 'auto', now), isFalse);
      expect(omits([_nl], '  ', now), isFalse);
    });
  });

  group('dashboard card, not secured', () {
    test('an unlisted choice is named as unavailable, not as row 0', () {
      final d = _picker([_nl, _uk, _us], kUnlistedSelectionIndex,
          unlisted: <String, dynamic>{'slug': 'canada-ca1', 'name': 'Canada'});
      expect(d.source, DashboardNodeSource.picker);
      expect(d.node?['name'], 'Canada');
      expect(d.node?['status'], 'unavailable');
    });

    test('before any listing the unlisted choice is status unknown', () {
      final d = _picker(const [], kUnlistedSelectionIndex,
          unlisted: <String, dynamic>{'slug': 'canada-ca1', 'name': 'Canada'});
      expect(d.node?['status'], 'unknown');
    });

    test('a status the caller computed wins', () {
      final d = _picker([_nl, _us], kUnlistedSelectionIndex,
          unlisted: <String, dynamic>{
            'slug': 'canada-ca1',
            'name': 'Canada',
            'status': 'unknown',
          });
      expect(d.node?['status'], 'unknown');
    });

    test('without an unlisted record the old clamp is unchanged', () {
      expect(_picker([_nl, _us], kUnlistedSelectionIndex).node, same(_nl));
      expect(_picker([_nl, _us], 1).node, same(_us));
    });
  });

  group('server list check and tap', () {
    test('secured: the check marks the carrying node, not the saved choice',
        () {
      final d = _connected([_ca, _de, _us], 'us-chicago1');
      expect(
          pickerCheckedSlug(
              dashboard: d, automatic: false, selectedSlug: 'canada-ca1'),
          'us-chicago1');
      expect(
          pickerTapChangesServer(
              dashboard: d,
              automatic: false,
              selectedSlug: 'canada-ca1',
              tappedSlug: 'us-chicago1'),
          isFalse,
          reason: 'already carrying there: no reconnect');
      expect(
          pickerTapChangesServer(
              dashboard: d,
              automatic: false,
              selectedSlug: 'canada-ca1',
              tappedSlug: 'canada-ca1'),
          isTrue,
          reason: 'the saved choice is not the carrying node: switch');
    });

    test('secured in automatic mode: a tap on the carrying row only saves it',
        () {
      final d = _connected([_ca, _de, _us], 'us-chicago1');
      expect(
          pickerTapChangesServer(
              dashboard: d,
              automatic: true,
              selectedSlug: 'canada-ca1',
              tappedSlug: 'us-chicago1'),
          isFalse,
          reason: 'already carrying there: no teardown for nothing');
      expect(
          pickerTapChangesServer(
              dashboard: d,
              automatic: true,
              selectedSlug: 'canada-ca1',
              tappedSlug: 'germany-de1'),
          isTrue);
    });

    test('secured, node not known: no row is checked and every tap switches',
        () {
      final d = _connected([_ca, _de, _us], null);
      expect(d.source, DashboardNodeSource.unknownTunnel);
      expect(
          pickerCheckedSlug(
              dashboard: d, automatic: false, selectedSlug: 'canada-ca1'),
          '');
      for (final slug in ['canada-ca1', 'us-chicago1']) {
        expect(
            pickerTapChangesServer(
                dashboard: d,
                automatic: false,
                selectedSlug: 'canada-ca1',
                tappedSlug: slug),
            isTrue,
            reason: slug);
      }
    });

    test('not secured: the saved manual choice, no row in automatic mode', () {
      final d = _picker([_ca, _us], 1);
      expect(
          pickerCheckedSlug(
              dashboard: d, automatic: false, selectedSlug: 'us-chicago1'),
          'us-chicago1');
      expect(
          pickerCheckedSlug(
              dashboard: d, automatic: true, selectedSlug: 'us-chicago1'),
          '');
      expect(
          pickerTapChangesServer(
              dashboard: d,
              automatic: false,
              selectedSlug: 'us-chicago1',
              tappedSlug: 'us-chicago1'),
          isFalse);
      expect(
          pickerTapChangesServer(
              dashboard: d,
              automatic: true,
              selectedSlug: 'us-chicago1',
              tappedSlug: 'us-chicago1'),
          isTrue,
          reason: 'automatic taps keep their old meaning');
    });

    test('an unlisted saved choice checks no listed row', () {
      final d = _picker([_nl, _us], kUnlistedSelectionIndex,
          unlisted: <String, dynamic>{'slug': 'canada-ca1', 'name': 'Canada'});
      final checked = pickerCheckedSlug(
          dashboard: d, automatic: false, selectedSlug: 'canada-ca1');
      expect([_nl, _us].where((n) => n['slug'] == checked), isEmpty);
    });
  });

  group('production selection code, run verbatim', () {
    late Directory temporary;
    late File executable;

    setUpAll(() async {
      final source = File('lib/main.dart').readAsStringSync();
      final requestSlug = _between(
          source, 'String nodeLocationForRequest({', '\n/// The one dialog');
      final sorting = _between(
          source,
          '  String _nodeSortKey(Map<String, dynamic> node) {',
          '  int? _nodeLatencyMs(');
      // _isFreeNode .. _indexForNodeSlug, then _manualSelectionUnlisted,
      // _rebindSelection, _freshListingOmits, _unlistedSelectionForDisplay
      // and _refuseUnlistedSwitchTarget.
      final freeIndexAndRebind = _between(
          source,
          '  bool _isFreeNode(Map<String, dynamic> node) {',
          '  void _applySelectedNodeFromAuth(');
      final currentSlug = _between(source, '  String _currentSelectedSlug() {',
          '  bool _cachedConfigMatchesCurrentSelection(');
      final watchPick = _between(
          source,
          "  /// The phone's own country-picker tap handler, for a listed row.",
          '  /// State as the watch should see it');
      // _nodeInUse, _pickerCheckedSlugNow, _watchSelectedSlug,
      // _speedTestRegionNode and _onServerRowTapped.
      final inUse = _between(
          source,
          "  /// The node in use, by the card's rule: the carrying node while secured.",
          '  void _showLocationPickerSheet({bool freeOnly = false}) {');
      final cacheRestoreAndBootstrap = _between(
          source,
          '  Future<void> _loadCachedNodesFromDisk() async {',
          '  @override\n  void dispose() {');
      final listingRebind = _between(
          source,
          '        if (fetchedNodes.isNotEmpty) {\n          final selectedSlug',
          '\n      });\n      if (fetchedNodes.isNotEmpty) {\n'
              '        _nodeListingRevision');
      final settingsRestore = _between(
          source,
          "        _selectedLocationIndex = settingsData['selected_index'] ?? 0;",
          '        final sessionFieldsCurrent = restoreOwnsSession();');
      final settingsSave = _between(
          source,
          '        // Never the negative sentinel.',
          "        data['stealth_active'] = _isCensorshipModeActive;");

      temporary = await Directory.systemTemp.createTemp('l91-selection-');
      executable = File('${temporary.path}/selection.dart');
      final display = File('lib/tunnel_display_identity.dart').absolute.uri;
      final rebind = File('lib/node_selection_rebind.dart').absolute.uri;
      final cover = File('lib/winn3_cover_fallback.dart').absolute.uri;
      await executable.writeAsString('''
import 'dart:async';
import 'dart:convert';
import '$display';
import '$rebind';
import '$cover';

$requestSlug

class _Epoch {
  int current = 1;
}

class H {
  List<Map<String, dynamic>> _locations = [];
  int _selectedLocationIndex = 0;
  Map<String, dynamic>? _unlistedSelection;
  DateTime? _liveListingReceivedAt;
  bool _automaticNodeSelection = true;
  bool _isFreeAccessSession = false;
  final Set<String> _freeNodeSlugs = <String>{};
  bool _freeNodeSnapshotLive = false;
  String? _winn3CoverExactTargetSlug;
  List<Map<String, dynamic>> _bootstrapNodes = [];
  bool mounted = true;
  bool _isConnected = false;
  bool _isLoading = false;
  bool _isLoggedIn = true;
  bool _isCensorshipModeActive = false;
  bool _rendersConnected = false;
  bool _showDecoyCalculator = false;
  final _tunnelDisplayLedger = TunnelDisplayLedger();
  final _accountSessionEpoch = _Epoch();
  String? cacheText;
  Completer<void>? cacheReadGate;
  final List<String> feedback = <String>[];
  final List<String> switches = <String>[];
  int settingsSaves = 0;
  void setState(void Function() fn) => fn();
  void _debugLog(String message) {}
  void _showFeedback(String message) => feedback.add(message);
  String _displayNodeName(dynamic value, {String fallback = 'Unknown'}) =>
      (value ?? fallback).toString();
  bool _boolValue(dynamic v) => v == true || v?.toString() == 'true';
  Map<String, dynamic> _normalizeNodeItem(Map<String, dynamic> item) =>
      Map<String, dynamic>.from(item);
  void stripServerLoad(Map<String, dynamic> node) {}
  Future<String?> _readSensitiveText(String name) async {
    if (cacheReadGate != null) await cacheReadGate!.future;
    return cacheText;
  }
  Future<void> _saveVpnRuntimeSettings() async => settingsSaves++;
  // Runs inside the free-config refresh (the app backgrounding, for example).
  void Function()? duringFreeRefresh;
  Future<bool> _refreshFreeVpnConfig(
      {bool stealthMode = false, bool Function()? shouldCancel}) async {
    duringFreeRefresh?.call();
    return true;
  }
  Future<void> _switchServerFromUserSelection(String serverName,
      {String? targetSlug}) async {
    switches.add(targetSlug ?? 'auto');
  }

$sorting
$freeIndexAndRebind
$currentSlug
$watchPick
$inUse
$cacheRestoreAndBootstrap

  void restoreSettings(Map<String, dynamic> settingsData) {
$settingsRestore
    // Production restores this a few lines later in the same block.
    _isFreeAccessSession = settingsData['free_access_session'] == true;
  }

  Map<String, dynamic> saveSettings() {
    final data = <String, dynamic>{};
$settingsSave
    return data;
  }

  void applyListing(List<dynamic> fetchedNodes, Set<String> freeSlugs) {
    final mapped = fetchedNodes
        .whereType<Map>()
        .map((item) => _normalizeNodeItem(Map<String, dynamic>.from(item)))
        .toList();
    // The same setState in _parseNodesResponse sets these first.
    _freeNodeSlugs
      ..clear()
      ..addAll(freeSlugs);
    _freeNodeSnapshotLive = true;
$listingRebind
  }

  void connectOn(String slug) {
    _isConnected = true;
    _rendersConnected = true;
    _tunnelDisplayLedger.commit(
      servedIdentity: slug,
      callerIdentity: slug,
      coverFallbackInProgress: false,
      accountEpoch: _accountSessionEpoch.current,
      locations: _locations,
    );
  }

  void adoptUnknown() {
    _isConnected = true;
    _rendersConnected = true;
    _tunnelDisplayLedger.settle(wasConnected: false, isConnected: true);
  }

  String card() {
    final d = _nodeInUse();
    if (d.source == DashboardNodeSource.unknownTunnel) return 'Unknown node';
    return '\${d.node?['name']} / \${d.node?['status']}';
  }

  String request() {
    try {
      return _requestedLocationSlug();
    } catch (_) {
      return 'THROWS';
    }
  }
}

Map<String, dynamic> node(String slug, String name) =>
    <String, dynamic>{'slug': slug, 'name': name, 'status': 'online'};
final ca = node('canada-ca1', 'Canada');
final de = node('germany-de1', 'Germany');
final nl = node('netherlands-nl1', 'Netherlands');
final uk = node('uk-gb1', 'United Kingdom');
final us = node('us-chicago1', 'United States (Chicago)');
Set<String> slugs(List<Map<String, dynamic>> n) =>
    n.map((e) => e['slug'] as String).toSet();

void check(bool ok, String message) {
  if (!ok) throw StateError(message);
}

Future<void> main(List<String> args) async {
  final scenario = args.single;
  final h = H();
  switch (scenario) {
    case 'phone':
    case 'phone_upgrade':
      // Chicago picked on 2026-09-26 while Canada and Germany were closed.
      // phone_upgrade: settings written by the old build (no slug).
      h.restoreSettings(<String, dynamic>{
        'selected_index': 2,
        if (scenario == 'phone') 'selected_slug': 'us-chicago1',
        'automatic_node_selection': false,
        'free_access_session': true,
      });
      h.cacheText = jsonEncode(<String, dynamic>{
        'selected_index': 2,
        'selected_slug': 'us-chicago1',
        'nodes': [nl, uk, us],
      });
      await h._loadCachedNodesFromDisk();
      // FREE-CAP t5 (owner ruling: all servers for free users, landed in
      // 44af32e): a free session lists every server, so the cached rows stay.
      check(h._locations.length == 3 &&
              slugs(h._locations).containsAll(slugs([nl, uk, us])),
          'free cache rows should be kept: \${slugs(h._locations)}');
      check(h._currentSelectedSlug() == 'us-chicago1',
          'cold start lost the choice: \${h._currentSelectedSlug()}');
      // Adopted tunnel on Chicago, then the listing with Canada back.
      h.adoptUnknown();
      h.applyListing([ca, de, nl, uk, us], slugs([ca, de, nl, uk, us]));
      check(h.card() == 'Unknown node', 'adoption has no verified identity');
      check(h._pickerCheckedSlugNow() == '', 'a row was checked for an unknown tunnel');
      check(h._watchSelectedSlug() == '', 'the watch marked a row for an unknown tunnel');
      check(h._currentSelectedSlug() == 'us-chicago1', 'choice moved');
      check(h.request() == 'us-chicago1', 'next connect would not be Chicago');
    case 'closed':
      h._automaticNodeSelection = false;
      h.applyListing([ca, nl, uk, us], const <String>{});
      h._selectedLocationIndex = 0; // the user's tap on Canada
      h.applyListing([nl, uk, us], const <String>{});
      check(h.card() == 'Canada / unavailable', 'card: \${h.card()}');
      check(!h._locations.any((n) => n['slug'] == h._pickerCheckedSlugNow()),
          'a listed row was checked for a closed choice');
      check(h.request() == 'canada-ca1',
          'a closed choice must be requested as itself, never row 0');
      h._selectFirstUsableNode();
      check(h._manualSelectionUnlisted, 'first-usable fallback replaced it');
      h._liveListingReceivedAt =
          DateTime.now().subtract(const Duration(minutes: 30));
      check(h.card() == 'Canada / unknown',
          'an old listing is no evidence of closure: \${h.card()}');
      h.applyListing([ca, de, nl, uk, us], const <String>{});
      check(h.card() == 'Canada / online' &&
              h._pickerCheckedSlugNow() == 'canada-ca1',
          'the choice did not come back with its node');
      check(!h._manualSelectionUnlisted, 'still unlisted');
    case 'listing_before_cache':
      h.restoreSettings(<String, dynamic>{
        'selected_index': 4,
        'selected_slug': 'us-chicago1',
        'automatic_node_selection': false,
      });
      h.applyListing([ca, de, nl, uk, us], const <String>{});
      check(h._pickerCheckedSlugNow() == 'us-chicago1' &&
              h.request() == 'us-chicago1',
          'listing before cache moved the choice');
    case 'cache_read_straddles_live_listing':
      // D4: /nodes lands while the cache read awaits; the cache must not
      // overwrite the newer live listing.
      h._isFreeAccessSession = true;
      h._automaticNodeSelection = false;
      h.cacheText = jsonEncode(<String, dynamic>{
        'selected_slug': 'us-chicago1',
        'nodes': [nl, uk, us],
      });
      h.cacheReadGate = Completer<void>();
      final restoring = h._loadCachedNodesFromDisk();
      h.applyListing([ca, us], slugs([ca, us]));
      h._selectedLocationIndex = 1;
      h.cacheReadGate!.complete();
      await restoring;
      check(h._locations.length == 2 && h._freeNodeSnapshotLive,
          'the cache overwrote the live listing');
      check(h._currentSelectedSlug() == 'us-chicago1', 'selection moved');
    case 'automatic':
      h.restoreSettings(<String, dynamic>{
        'selected_index': 1,
        'selected_slug': 'canada-ca1',
        'automatic_node_selection': true,
      });
      h.applyListing([nl, uk, us], const <String>{});
      check(h._selectedLocationIndex == 0 && h._pickerCheckedSlugNow() == '' &&
              h.request() == 'auto',
          'automatic behaviour changed');
    case 'switch_to_automatic':
      h._automaticNodeSelection = false;
      h.applyListing([ca, nl], const <String>{});
      h.applyListing([nl], const <String>{});
      check(h._manualSelectionUnlisted, 'not unlisted');
      h._automaticNodeSelection = true; // Automatic row tapped
      check(h.request() == 'auto' && h.card() == 'Netherlands / online',
          'automatic after an unlisted choice');
    case 'bootstrap':
      h.restoreSettings(<String, dynamic>{
        'selected_slug': 'us-chicago1',
        'automatic_node_selection': false,
      });
      h._bootstrapNodes = [ca, nl];
      h._useBootstrapNodesIfEmpty();
      check(h._manualSelectionUnlisted && h.request() == 'us-chicago1',
          'bootstrap replaced the choice with row 0');
      h.applyListing([ca, us], const <String>{});
      check(h._pickerCheckedSlugNow() == 'us-chicago1',
          'did not re-bind after bootstrap');
    case 'settings_save_by_slug':
      h._automaticNodeSelection = false;
      h.applyListing([ca, us], const <String>{});
      h.applyListing([us], const <String>{});
      h._selectedLocationIndex = kUnlistedSelectionIndex;
      final saved = h.saveSettings();
      check(saved['selected_slug'] == 'canada-ca1',
          'saved \${saved['selected_slug']}, not the unlisted choice');
      check(saved['selected_index'] == 0, 'the negative sentinel was persisted');
      final restored = H()
        ..restoreSettings(<String, dynamic>{...saved})
        ..applyListing([ca, us], const <String>{});
      check(restored._currentSelectedSlug() == 'canada-ca1',
          'the saved slug did not re-bind after a restart');
    case 'secured_committed':
      h._automaticNodeSelection = false;
      h.applyListing([ca, de, us], const <String>{});
      h._selectedLocationIndex = 0; // saved choice Canada
      h.connectOn('us-chicago1');
      check(h.card() == 'United States (Chicago) / online' &&
              h._pickerCheckedSlugNow() == 'us-chicago1',
          'secured card or check does not name the carrying node');
      check(h._watchSelectedSlug() == 'us-chicago1',
          'the watch does not mark the carrying node');
      check(h._speedTestRegionNode()?['slug'] == 'us-chicago1',
          'the speed test does not target the carrying node');
    case 'tap_disconnected_after_resort':
      // D1: the sheet was built from [nl, uk, us]; a refresh re-sorted the
      // listing (Canada re-promoted) before the tap on Chicago.
      h._automaticNodeSelection = false;
      h.applyListing([nl, uk, us], const <String>{});
      final tappedRow = Map<String, dynamic>.from(h._locations[2]);
      h.applyListing([ca, nl, uk, us], const <String>{});
      await h._onServerRowTapped(tappedRow);
      check(h._currentSelectedSlug() == 'us-chicago1',
          'the tap chose \${h._currentSelectedSlug()}, not Chicago');
      check(h.switches.isEmpty && h.settingsSaves == 1, 'tap side effects');
    case 'tap_disconnected_after_removal':
      h._automaticNodeSelection = false;
      h.applyListing([nl, uk, us], const <String>{});
      final tappedRow = Map<String, dynamic>.from(h._locations[2]);
      h.applyListing([nl, uk], const <String>{});
      await h._onServerRowTapped(tappedRow);
      check(h._currentSelectedSlug() == 'us-chicago1' &&
              h._manualSelectionUnlisted,
          'a removed tapped row became \${h._currentSelectedSlug()}');
      check(h.card() == 'United States (Chicago) / unavailable',
          'card: \${h.card()}');
    case 'tap_secured_carrying_automatic':
      // OI-UI-2: automatic, carrying Chicago; a tap on Chicago saves it as the
      // manual choice and does not reconnect.
      h.applyListing([ca, us], const <String>{});
      h.connectOn('us-chicago1');
      await h._onServerRowTapped(Map<String, dynamic>.from(us));
      check(h.switches.isEmpty, 'the carrying row reconnected: \${h.switches}');
      check(!h._automaticNodeSelection &&
              h._currentSelectedSlug() == 'us-chicago1' &&
              h.settingsSaves == 1,
          'the carrying row was not saved as the manual choice');
      await h._onServerRowTapped(Map<String, dynamic>.from(ca));
      check(h.switches.single == 'canada-ca1', 'another row did not switch');
    case 'tap_secured_unknown':
      h._automaticNodeSelection = false;
      h.applyListing([ca, us], const <String>{});
      h._selectedLocationIndex = 1; // saved Chicago
      h.adoptUnknown();
      await h._onServerRowTapped(Map<String, dynamic>.from(us));
      check(h.switches.single == 'us-chicago1',
          'a tap with an unknown carrying node did not reconnect');
      check(h._speedTestRegionNode() == null,
          'the speed test targeted a region for an unknown node');
    case 'watch_pick_saved_row_while_unknown':
      // D5: the watch used to ignore a pick of the saved row.
      h._automaticNodeSelection = false;
      h.applyListing([ca, us], const <String>{});
      h._selectedLocationIndex = 1;
      h.adoptUnknown();
      await h._selectWatchCountry('us-chicago1');
      check(h.switches.single == 'us-chicago1',
          'the watch pick of the saved row was ignored');
      await h._selectWatchCountry('not-listed');
      check(h.switches.length == 1, 'an unlisted watch pick acted');
    case 'watch_disconnected':
      h._automaticNodeSelection = false;
      h.applyListing([ca, us], const <String>{});
      h._selectedLocationIndex = 1;
      check(h._watchSelectedSlug() == 'us-chicago1', 'watch: saved choice');
      await h._selectWatchCountry('canada-ca1');
      check(h._currentSelectedSlug() == 'canada-ca1' && h.switches.isEmpty,
          'a disconnected watch pick did not save the choice');
    case 'speed_test_unlisted':
      // Not secured: an unlisted saved choice has no region.
      h._automaticNodeSelection = false;
      h.applyListing([ca, us], const <String>{});
      h.applyListing([us], const <String>{});
      check(h._manualSelectionUnlisted, 'not unlisted');
      check(h._speedTestRegionNode() == null,
          'row 0 region used for an unlisted choice: \${h._speedTestRegionNode()}');
      // Secured: the committed node leaves the listing. The card still names
      // it by identity, but its region is not used.
      h.applyListing([ca, us], const <String>{});
      h.connectOn('canada-ca1');
      check(h._speedTestRegionNode()?['slug'] == 'canada-ca1',
          'a listed carrying node lost its region');
      h.applyListing([us], const <String>{});
      final shown = h._nodeInUse();
      check(shown.source == DashboardNodeSource.committedTunnel &&
              shown.node?['slug'] == 'canada-ca1',
          'precondition: the card names the delisted carrying node');
      check(h._speedTestRegionNode() == null,
          'a delisted carrying node picked the region: \${h._speedTestRegionNode()}');
    case 'free_tap_message_dropped_behind_decoy':
      // Seat C P1: the free-config refresh is a network wait; the decoy can
      // come back during it, and "Free server changed." must not follow.
      h.applyListing([ca, us], const <String>{});
      h._automaticNodeSelection = false;
      await h._onServerRowTapped(Map<String, dynamic>.from(us), freeOnly: true);
      check(h.feedback.single == 'Free server changed.',
          'control: the unlocked message was not shown: \${h.feedback}');
      h.feedback.clear();
      h.duringFreeRefresh = () => h._showDecoyCalculator = true;
      await h._onServerRowTapped(Map<String, dynamic>.from(ca), freeOnly: true);
      check(h._currentSelectedSlug() == 'canada-ca1', 'the choice was not saved');
      check(h.feedback.isEmpty, 'feedback over the decoy: \${h.feedback}');
    case 'tap_switch_keeps_deferred_restart':
      // N2: a tap that asks for a switch does not clear a deferred settings
      // restart; only a switch that commits replaces its display session.
      h.applyListing([ca, us], const <String>{});
      h.connectOn('us-chicago1');
      h._settingsRestartPending = true;
      h._settingsRestartGeneration = h._tunnelDisplayLedger.generation;
      await h._onServerRowTapped(Map<String, dynamic>.from(ca));
      check(h.switches.single == 'canada-ca1', 'the tap did not ask to switch');
      check(h._settingsRestartPending,
          'a switch that has not committed cleared the deferred restart');
    case 'switch_refusal':
      h.applyListing([ca, us], const <String>{});
      check(!h._refuseUnlistedSwitchTarget('us-chicago1', 'Chicago'),
          'a listed target was refused');
      check(!h._refuseUnlistedSwitchTarget(null, 'Automatic'),
          'automatic was refused');
      check(h._refuseUnlistedSwitchTarget('germany-de1', 'Germany') &&
              h.feedback.single.contains('Germany is no longer'),
          'a removed target was not refused');
      // T1 audit: behind the decoy it still refuses, but says nothing.
      h._showDecoyCalculator = true;
      check(h._refuseUnlistedSwitchTarget('germany-de1', 'Germany'),
          'behind the decoy a removed target was not refused');
      check(h.feedback.length == 1, 'feedback over the decoy: \${h.feedback}');
  }
  print('PASS \$scenario');
}
''');
    });

    tearDownAll(() async {
      if (await temporary.exists()) await temporary.delete(recursive: true);
    });

    for (final scenario in const <String>[
      'phone',
      'phone_upgrade',
      'closed',
      'listing_before_cache',
      'cache_read_straddles_live_listing',
      'automatic',
      'switch_to_automatic',
      'bootstrap',
      'settings_save_by_slug',
      'secured_committed',
      'tap_disconnected_after_resort',
      'tap_disconnected_after_removal',
      'tap_secured_carrying_automatic',
      'tap_secured_unknown',
      'watch_pick_saved_row_while_unknown',
      'watch_disconnected',
      'speed_test_unlisted',
      'switch_refusal',
      'tap_switch_keeps_deferred_restart',
      'free_tap_message_dropped_behind_decoy',
    ]) {
      test('selection scenario: $scenario', () async {
        final result = await Process.run(
          Platform.environment['DART_EXECUTABLE'] ?? 'dart',
          <String>[
            '--packages=${File('.dart_tool/package_config.json').absolute.path}',
            executable.path,
            scenario,
          ],
          workingDirectory: temporary.path,
        );
        expect(result.exitCode, 0,
            reason: '${result.stdout}\n${result.stderr}');
        expect(result.stdout.toString(), contains('PASS $scenario'));
      });
    }
  });

  // Behaviour is covered above and in the switch, held-switch and
  // reconciliation harnesses. What remains is wiring that only a widget pump
  // of the whole app could execute: that each surface calls the tested
  // method.
  group('app wiring', () {
    late String source;
    setUpAll(() => source = File('lib/main.dart').readAsStringSync());

    test('each surface calls the tested in-use methods', () {
      final sheet = _between(source, '  void _showLocationPickerSheet(',
          '  Widget _buildFreeServerSelector(');
      expect(sheet, contains('final checkedSlug = _pickerCheckedSlugNow();'));
      expect(sheet,
          contains('final selected = slug.isNotEmpty && slug == checkedSlug;'));
      expect(sheet,
          contains('await _onServerRowTapped(location, freeOnly: freeOnly);'));
      expect(sheet, isNot(contains('_selectedLocationIndex =')),
          reason: 'the sheet must not bind a tap by index');
      final card = _between(source, '  Widget _buildVpnDashboard(',
          '    final Widget commandCenter = Column(');
      expect(card, contains('unlistedSelection: _unlistedSelectionForDisplay(),'));
      final watch = _between(source, '  void _publishWatchState() {',
          '  Future<void> _loadInstalledAppsForSplitTunnel(');
      expect(watch, contains("selectedSlug: locked ? '' : _watchSelectedSlug(),"));
      expect(source, contains('    final selectedNode = _speedTestRegionNode();'));
      // A deferred settings restart runs after each live listing; the
      // reconciliation harness executes _runPendingSettingsRestart itself.
      final parse = _between(source,
          'Future<void> _parseNodesResponse(String body) async',
          'Future<void> _saveCachedNodes() async');
      expect(parse, contains('        _runPendingSettingsRestart();'));
      // T1: the PIN unlock and the TV self-heal run a restart held behind
      // the decoy (the reconciliation harness executes the runner itself).
      final unlock = _between(source,
          '  Future<void> _onCalculatorButtonPressed(String buttonText) async {',
          '  /// Before a user connect to a manual choice');
      expect(
          unlock,
          contains('        unawaited(_reconcileNativeTunnelState(refreshNetworkLabel: true));\n'
              '        // A settings restart held behind the decoy runs now, if its tunnel\n'
              '        // is still the one it was deferred for.\n'
              '        _runPendingSettingsRestart();'));
      expect(
          source,
          contains('          unawaited(_setLauncherCamouflage(enabled: false));\n'
              '          _runPendingSettingsRestart();'));
      // Startup and the picker share the walk a connect waits on.
      expect(source, contains('      unawaited(_sharedNodeDiscovery());'));
      expect(RegExp(r'unawaited\(_sharedNodeDiscovery\(\)\);')
              .allMatches(source).length, 3);
      // N4: the connect's config refreshes and the auth success share it too.
      expect(RegExp(r'_lastConfigRefreshHadLiveNodeListing = '
              r'await _sharedNodeDiscovery\(\);')
          .allMatches(source).length, 2);
      final auth = _between(source, '  Future<void> _onAuthSuccess(Map<String, dynamic> data',
          '  Future<bool> _refreshFreeVpnConfig({');
      expect(auth, isNot(contains('_fetchAvailableNodes(')));
      expect(auth, contains('      await _sharedNodeDiscovery();'));
    });

    test('a user pick is never resolved through the row-0 fallback', () {
      final callers = RegExp(r'_indexForNodeSlug\(').allMatches(source).length;
      // The declaration and the auth apply, which binds a slug it has just
      // merged into the listing.
      expect(callers, 2);
      final auth = _between(source, '  void _applySelectedNodeFromAuth(',
          '  Map<String, dynamic> _normalizeVpnConfig(');
      expect(auth, contains('_selectedLocationIndex = _indexForNodeSlug(slug);'));
      final restoreSelection = _between(source, '    void restoreSelection() {',
          '    setState(() {\n      _automaticNodeSelection = targetSlug == null;');
      expect(restoreSelection, contains('_rebindSelection(previousSlug);'));
    });
  });
}
