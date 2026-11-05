import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Round L (OI-L3, OI-L4): the held-session server switch and held Reconnect,
// executed. The production methods from `_switchServerFromUserSelection`
// through the REAL retained-route `_switchConnectedServer`, the settings
// restart, and the display-ownership helpers they call, are run verbatim in a
// separate Dart process. Only their external dependencies are replaced: the
// dialog, the native readiness reads, the native stop, the monotonic clock and
// pauses (virtual time), connector preparation, and widget state. Preparation
// fails the scenario unless the marked hold's release was acknowledged, so a
// path that reaches preparation early, the retained-route switch included, is
// caught where it happens. This is transaction coverage, not device proof.

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production source: $start');
  }
  return source.substring(first, last);
}

void main() {
  late Directory temporary;
  late File executable;

  setUpAll(() async {
    final source = File('lib/main.dart').readAsStringSync();
    final held = _between(
      source,
      '  /// Every server the user picks while a session exists comes here',
      '  Future<void> _showLocationPicker(',
    );
    final displayOwnership = _between(
      source,
      "  /// Keeps the dashboard's committed-node record in step",
      '  void _finishTunnelConnectFailure(',
    );
    // The production current-slug getter, which knows an unlisted choice.
    final currentSlug = _between(
      source,
      '  String _currentSelectedSlug() {',
      '  String _requestedLocationSlug()',
    );
    // The ungated settings restart, verbatim: it is what an ungated held
    // switch would call, so a regression to it fails behaviourally here.
    final restart = _between(
      source,
      '  Future<void> _restartTunnelForSettingsChange() async {',
      '  void _bringSplitTunnelPanelIntoView() {',
    );
    // What the banner's Reconnect really calls, so the banner scenario runs
    // the production wiring rather than a name this test assumes.
    final bannerReconnect = RegExp(
            r'onReconnect: \(\) => unawaited\((_[A-Za-z0-9]+)\(\)\)')
        .firstMatch(source)
        ?.group(1);
    if (bannerReconnect == null) {
      throw StateError('the held banner has no Reconnect wiring');
    }
    // The selection re-bind the switch's restore calls, verbatim.
    final selectionRebind = _between(
      source,
      '  /// A manual choice that the listing does not carry, so no row is selected.',
      '  void _applySelectedNodeFromAuth(',
    );
    temporary = await Directory.systemTemp.createTemp('wins-held-switch-');
    executable = File('${temporary.path}/held_switch.dart');
    final ledger = File('lib/tunnel_display_identity.dart').absolute.uri;
    final barrier = File('lib/winn3_release_barrier.dart').absolute.uri;
    final rebind = File('lib/node_selection_rebind.dart').absolute.uri;
    await executable.writeAsString(
        "import '$ledger';\nimport '$barrier';\nimport '$rebind';\n"
        '$_harnessBefore\n$displayOwnership\n$selectionRebind\n$currentSlug\n'
        '$restart\n$held\n'
        '${_harnessAfter.replaceAll('BANNER_RECONNECT', bannerReconnect)}');
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'decline',
    'dismiss',
    'missing_lifecycle_after_dialog',
    'lifecycle_cleared_before_interface_closes',
    'recovered_during_dialog',
    'replaced_by_another_held_session',
    'replaced_by_a_committed_session',
    'account_changed_during_dialog',
    'ui_operation_changed_during_dialog',
    'delayed_teardown',
    'teardown_never_acknowledged',
    'kill_switch_keeps_block',
    'readiness_fails_while_waiting',
    'stale_acknowledgement_for_another_hold',
    'no_release_ledger',
    'banner_reconnect_waits_for_release',
    'slow_native_reads_respect_the_deadline',
    'a_slow_stop_counts_against_the_deadline',
    'not_held_uses_the_retained_switch',
    'target_removed_during_dialog',
    'target_removed_before_dialog',
    'target_removed_during_release',
    'decoy_returns_during_readiness_read',
    'decoy_returns_during_dialog',
  ]) {
    test('held switch transaction: $scenario', () async {
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[executable.path, scenario],
        workingDirectory: temporary.path,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }
}

const _harnessBefore = r'''
import 'dart:async';

class _Epoch {
  int current = 0;
}

class FakeLifecycle {
  const FakeLifecycle(this.holdsSession);
  final bool holdsSession;
}

// The production one-liner (lib/winn3_host_lifecycle.dart) over the fake
// lifecycle; winn3_held_switch_gate_test.dart covers the real one.
bool winn3ServerSwitchMustReleaseHold(FakeLifecycle lifecycle) =>
    lifecycle.holdsSession;

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

class Harness {
  bool mounted = true;
  bool _isConnected = true;
  bool _isLoading = false;
  bool _isVpnConnectInFlight = false;
  bool _isTunnelTransitioning = false;
  bool _supportsNativeTunnelReadiness = true;
  // C-core-17 (ruling A2) fence members the extracted consumers read.
  bool _appInBackground = false;
  int _resumeProofGeneration = 0;
  String _activeProtocolLabel = 'Winn';
  String _activeProtocolVersion = 'winn/3';
  final String _defaultProtocolLabel = 'Winn';
  String? _winn3IngestRouterV4;
  bool _automaticNodeSelection = false;
  int _selectedLocationIndex = 0;
  Map<String, dynamic>? _unlistedSelection;
  DateTime? _liveListingReceivedAt;
  bool _showDecoyCalculator = false;
  final bool _isApplePlatform = false;
  String _displayNodeName(Object? value) => (value ?? '').toString();
  int _vpnUiOperationEpoch = 0;
  String _ipAfterVpn = 'held';
  final _accountSessionEpoch = _Epoch();
  final _tunnelDisplayLedger = TunnelDisplayLedger();
  // Round UN: adoption asks for a persisted-record restore. The restore
  // itself runs verbatim in tunnel_display_restore_production_test.dart;
  // here only the request is counted.
  int restoreSchedules = 0;
  void _scheduleTunnelDisplayRestore() => restoreSchedules++;
  FakeLifecycle _winn3HostLifecycle = const FakeLifecycle(true);
  List<Map<String, dynamic>> _locations = <Map<String, dynamic>>[
    <String, dynamic>{'slug': 'uk', 'name': 'United Kingdom'},
    <String, dynamic>{'slug': 'france', 'name': 'France'},
  ];

  // The native side, as getTunnelReadiness publishes it.
  bool ledger = true;
  // The lifecycle board's keys (winn3_lifecycle, winn3_capture_held). The
  // board clears them at the START of a teardown pass, before the interface
  // closes, and an older host never publishes them.
  bool boardPublished = true;
  String lifecycle = 'blocked';
  int holdId = 1;
  int sequence = 7;
  int lastHoldId = 0;
  String lastDisposition = 'none';
  bool captureHeld = true;
  bool interfaceOpen = true;
  bool readinessFails = false;
  bool failEveryOtherRead = false;

  // How the teardown the stop requests ends.
  int acknowledgeAfterReads = 0;
  String releaseDisposition = 'closed';
  bool staleAcknowledgement = false;
  bool stopRequested = false;
  int readsSinceStop = 0;
  bool acknowledged = false;
  int? stopAtSelection;

  // The dialog.
  bool? consent = true;
  void Function()? whileDialogOpen;

  final List<String> events = <String>[];
  final List<String> feedback = <String>[];

  void setState(void Function() update) => update();
  String _t(String value) => value;
  void _showFeedback(String message) => feedback.add(message);
  bool _accountEpochIsCurrent(int epoch) =>
      _accountSessionEpoch.current == epoch;
  int _indexForNodeSlug(String? slug) {
    final index = _locations.indexWhere((node) => node['slug'] == slug);
    return index < 0 ? 0 : index;
  }

  Map<String, dynamic> readiness() => <String, dynamic>{
        'interface_open': interfaceOpen,
        'active': lifecycle == 'connected',
        if (boardPublished) 'winn3_lifecycle': lifecycle,
        if (boardPublished) 'winn3_capture_held': captureHeld,
        if (ledger) 'winn3_hold_id': holdId,
        if (ledger) 'winn3_release_sequence': sequence,
        if (ledger) 'winn3_release_hold_id': lastHoldId,
        if (ledger) 'winn3_release_disposition': lastDisposition,
      };

  void completeTeardown() {
    acknowledged = true;
    sequence++;
    lastHoldId = holdId;
    lastDisposition = releaseDisposition;
    holdId = 0;
    captureHeld = false;
    interfaceOpen = releaseDisposition == 'kill_switch_block';
  }

  // Virtual monotonic time.
  Duration now = Duration.zero;
  Duration readLatency = Duration.zero;
  Duration stopLatency = Duration.zero;
  Duration longestReadTimeout = Duration.zero;
  Duration? stopStartedAt;
  Duration? gaveUpAt;
  Duration Function() _winn3ReleaseClock() {
    final start = now;
    return () => now - start;
  }

  int readinessReads = 0;
  // Runs inside every readiness read (the app backgrounding, for example).
  void Function()? whileReadingReadiness;
  Future<Map<dynamic, dynamic>?> _readTunnelReadinessForRelease(
      {Duration timeout = const Duration(seconds: 3)}) async {
    if (timeout > longestReadTimeout) longestReadTimeout = timeout;
    whileReadingReadiness?.call();
    // Once the teardown is under way, a slow native side answers after
    // readLatency, or the read times out first.
    if (stopRequested && readLatency > Duration.zero) {
      if (readLatency >= timeout) {
        now += timeout;
        events.add('readiness-timeout');
        return null;
      }
      now += readLatency;
    }
    readinessReads++;
    events.add('readiness');
    if (stopRequested && !acknowledged) {
      readsSinceStop++;
      if (staleAcknowledgement && readsSinceStop == 1) {
        // Another hold's release lands first, with the interface closed.
        sequence++;
        lastHoldId = 99;
        lastDisposition = 'closed';
      }
      if (readsSinceStop > acknowledgeAfterReads) completeTeardown();
    }
    if (readinessFails) return null;
    if (failEveryOtherRead && readinessReads.isEven) return null;
    return readiness();
  }

  Future<void> _winn3ReleasePause(
      [Duration pause = const Duration(milliseconds: 250)]) async {
    now += pause;
    events.add('pause');
  }

  // dynamic, not bool?: the production signature is Future<bool?>, and a
  // dynamic fake also lets an older bool-returning caller compile.
  Future<dynamic> _confirmWinn3HoldRelease(String serverName) async {
    events.add('dialog');
    whileDialogOpen?.call();
    return consent;
  }

  // winn3HostLifecycleFromReadiness's Android rules: no winn3_lifecycle key
  // is `none`; held needs the capture flag AND an open interface, in a
  // recovering or blocked (or unknown, read as blocked) state.
  bool _observeWinn3HostLifecycle(Map<dynamic, dynamic>? readiness) {
    final held = readiness != null &&
        readiness.containsKey('winn3_lifecycle') &&
        readiness['winn3_lifecycle'] != 'connected' &&
        readiness['winn3_capture_held'] == true &&
        readiness['interface_open'] == true;
    _winn3HostLifecycle = FakeLifecycle(held);
    return held;
  }

  // Dependencies of the REAL retained-route switch.
  void _debugLog(String message) {}
  List<Map<String, dynamic>> _sortedNodeItems(
          Iterable<Map<String, dynamic>> nodes) =>
      nodes.toList();
  Future<void> _saveVpnRuntimeSettings() async => events.add('settings');
  void _finishTunnelConnectFailure(String message) {
    feedback.add(message);
    _isConnected = false;
  }

  // Runs while the held tunnel is being released (a listing refresh).
  void Function()? whileReleasing;
  String? requestedAtPrepare;
  Future<bool> _stopNativeTunnel({bool keepVpnLauncher = false}) async {
    events.add('stop');
    whileReleasing?.call();
    stopStartedAt = now;
    now += stopLatency;
    stopAtSelection = _selectedLocationIndex;
    stopRequested = true;
    return true;
  }

  Future<bool> _readNativeTunnelActive() async {
    events.add('read-active');
    gaveUpAt ??= now;
    return captureHeld && interfaceOpen;
  }

  int markedHold = 1;
  Future<void> _connectWithSmartProtocol({
    Future<bool> Function()? beforeTunnelStart,
  }) async {
    events.add('prepare');
    requestedAtPrepare = _currentSelectedSlug();
    check(lastDisposition == 'closed' && lastHoldId == markedHold,
        'preparation started without the marked hold released');
    check(!interfaceOpen, 'preparation started with the capture interface open');
    if (beforeTunnelStart != null && !await beforeTunnelStart()) return;
    events.add('start');
  }

  void commitInitialTunnel() {
    _tunnelDisplayLedger.commit(
      servedIdentity: 'uk',
      callerIdentity: 'uk',
      coverFallbackInProgress: false,
      accountEpoch: _accountSessionEpoch.current,
      locations: _locations,
    );
  }

  bool get stopped => events.contains('stop');
  bool get switchedRetained => events.contains('settings');
  bool get prepared => events.contains('prepare');

  void checkNothingHappened(String why) {
    check(!stopped, '$why: the held tunnel was stopped');
    check(!prepared, '$why: preparation started');
    check(!switchedRetained, '$why: the retained-route switch ran');
    check(_selectedLocationIndex == 0 && !_automaticNodeSelection,
        '$why: the selection changed');
    check(!_isLoading, '$why: left loading');
  }
''';

const _harnessAfter = r'''
}

Future<void> main(List<String> arguments) async {
  final scenario = arguments.single;
  final h = Harness();
  h.commitInitialTunnel();
  Future<void> pick() => h._switchServerFromUserSelection('France', targetSlug: 'france');
  switch (scenario) {
    case 'decline':
      h.consent = false;
      await pick();
      h.checkNothingHappened('declined');
      check(h.feedback.isEmpty, 'a decline is not an error');
      break;
    case 'dismiss':
      h.consent = null;
      await pick();
      h.checkNothingHappened('dismissed');
      break;
    case 'missing_lifecycle_after_dialog':
      // The reading after the dialog carries no lifecycle board keys at all.
      h.whileDialogOpen = () => h.boardPublished = false;
      await pick();
      h.checkNothingHappened('a missing lifecycle');
      check(h.feedback.single.contains('changed while you were deciding'),
          '${h.feedback}');
      break;
    case 'lifecycle_cleared_before_interface_closes':
      // A teardown pass has started: the board is cleared and the capture
      // flag is gone, but the interface is still open and the ledger's hold
      // is still outstanding.
      h.whileDialogOpen = () {
        h.boardPublished = false;
        h.captureHeld = false;
      };
      await pick();
      h.checkNothingHappened('a lifecycle cleared mid-teardown');
      break;
    case 'recovered_during_dialog':
      // An apparent recovery is not the session consent was given for: no
      // token binds it to that session, and a blocked hold does not recover
      // in place. Nothing runs; the user picks again from a fresh state.
      h.whileDialogOpen = () {
        h.captureHeld = false;
        h.lifecycle = 'connected';
        h.holdId = 0;
      };
      await pick();
      h.checkNothingHappened('an apparent recovery');
      check(h.feedback.single.contains('changed while you were deciding'),
          '${h.feedback}');
      break;
    case 'target_removed_during_dialog':
      // A listing refresh while the consent dialog is open removes France.
      h.whileDialogOpen = () =>
          h._locations.removeWhere((node) => node['slug'] == 'france');
      await pick();
      h.checkNothingHappened('target removed during the dialog');
      check(h.feedback.any((m) => m.contains('France is no longer in the server list')),
          'the refusal was not explained: ${h.feedback}');
      break;
    case 'decoy_returns_during_readiness_read':
      // P2: the decoy comes back while the first readiness read is out. No
      // release dialog, no message, no release.
      h.whileReadingReadiness = () => h._showDecoyCalculator = true;
      await pick();
      h.checkNothingHappened('decoy returned before the dialog');
      check(!h.events.contains('dialog'), 'the release dialog opened over the decoy');
      check(h.feedback.isEmpty, 'feedback over the decoy: ${h.feedback}');
      break;
    case 'decoy_returns_during_dialog':
      // P2: the decoy comes back while the consent dialog is open (the
      // relock pops the dialog; its future answers). Nothing is released.
      h.whileDialogOpen = () => h._showDecoyCalculator = true;
      await pick();
      h.checkNothingHappened('decoy returned during the dialog');
      check(h.feedback.isEmpty, 'feedback over the decoy: ${h.feedback}');
      break;
    case 'target_removed_during_release':
      // A refresh removes France after the checks, while the held tunnel is
      // being released. The replacement must request France exactly, never
      // row 0 (United Kingdom).
      h.whileReleasing = () =>
          h._locations.removeWhere((node) => node['slug'] == 'france');
      await pick();
      check(h.stopped && h.events.contains('prepare'),
          'the release did not run to preparation: ${h.events}');
      check(h.requestedAtPrepare == 'france',
          'the replacement requested ${h.requestedAtPrepare}, not France');
      check(h._selectedLocationIndex == kUnlistedSelectionIndex &&
              !h._automaticNodeSelection,
          'the removed target was bound to row ${h._selectedLocationIndex}');
      break;
    case 'target_removed_before_dialog':
      h._locations.removeWhere((node) => node['slug'] == 'france');
      await pick();
      h.checkNothingHappened('target removed before the dialog');
      check(!h.events.contains('dialog'), 'asked to release for a removed target');
      break;
    case 'not_held_uses_the_retained_switch':
      // A session that was never held keeps the retained-route switch, which
      // here runs for real up to its preparation boundary.
      h._winn3HostLifecycle = const FakeLifecycle(false);
      h.ledger = false;
      h.boardPublished = false;
      h.captureHeld = false;
      h.interfaceOpen = false;
      h.lastDisposition = 'closed';
      h.lastHoldId = 1;
      await pick();
      check(h.prepared && h.switchedRetained, 'the ordinary switch did not run');
      check(!h.events.contains('dialog'), 'an ordinary switch asked for release');
      break;
    case 'replaced_by_another_held_session':
      h.whileDialogOpen = () {
        h.holdId = 2;
        h.sequence++;
      };
      await pick();
      h.checkNothingHappened('another hold');
      check(h.feedback.single.contains('changed while you were deciding'),
          'the user is told why nothing happened: ${h.feedback}');
      break;
    case 'replaced_by_a_committed_session':
      h.whileDialogOpen = () {
        h._tunnelDisplayLedger.commit(
          servedIdentity: 'france',
          callerIdentity: 'france',
          coverFallbackInProgress: false,
          accountEpoch: h._accountSessionEpoch.current,
          locations: h._locations,
        );
      };
      await pick();
      h.checkNothingHappened('a new display session');
      break;
    case 'account_changed_during_dialog':
      h.whileDialogOpen = () => h._accountSessionEpoch.current++;
      await pick();
      h.checkNothingHappened('another account');
      break;
    case 'ui_operation_changed_during_dialog':
      h.whileDialogOpen = () => h._vpnUiOperationEpoch++;
      await pick();
      h.checkNothingHappened('another UI operation');
      break;
    case 'delayed_teardown':
      h.acknowledgeAfterReads = 6;
      await pick();
      check(h.stopped && h.prepared, 'the confirmed switch did not connect');
      check(h.stopAtSelection == 0, 'the selection changed before the stop');
      final stop = h.events.indexOf('stop');
      final prepare = h.events.indexOf('prepare');
      check(h.events.sublist(stop, prepare).where((e) => e == 'pause').length >= 6,
          'preparation did not wait for the delayed acknowledgement');
      check(h._selectedLocationIndex == 1, 'the picked server was not selected');
      check(!h._isLoading, 'left loading');
      break;
    case 'teardown_never_acknowledged':
      h.acknowledgeAfterReads = 1 << 30;
      await pick();
      check(h.stopped, 'the stop was never requested');
      check(!h.prepared, 'preparation started without an acknowledgement');
      check(h.feedback.single.contains('Could not confirm'), '${h.feedback}');
      check(h._isConnected, 'a still-held session must still read as a session');
      check(h._selectedLocationIndex == 0, 'the selection changed without a release');
      check(!h._isLoading, 'left loading');
      break;
    case 'kill_switch_keeps_block':
      h.releaseDisposition = 'kill_switch_block';
      await pick();
      check(!h.prepared, 'preparation started behind a kill-switch block');
      check(h.feedback.single.contains('kill switch'), '${h.feedback}');
      break;
    case 'readiness_fails_while_waiting':
      h.acknowledgeAfterReads = 1 << 30;
      h.failEveryOtherRead = true;
      await pick();
      check(!h.prepared, 'failed readings were taken as a release');
      break;
    case 'stale_acknowledgement_for_another_hold':
      h.staleAcknowledgement = true;
      h.acknowledgeAfterReads = 3;
      await pick();
      check(h.prepared, 'the real acknowledgement was not honoured');
      check(h.lastHoldId == 1, 'preparation followed the stale acknowledgement');
      break;
    case 'no_release_ledger':
      h.ledger = false;
      await pick();
      h.checkNothingHappened('no ledger');
      check(!h.events.contains('dialog'), 'consent was asked for a release that cannot be proven');
      check(h.feedback.single.contains('Could not confirm'), '${h.feedback}');
      break;
    case 'banner_reconnect_waits_for_release':
      h.acknowledgeAfterReads = 4;
      await h.BANNER_RECONNECT();
      check(h.stopped && h.prepared, 'the held Reconnect did not reconnect');
      check(h._selectedLocationIndex == 0, 'a plain Reconnect changed the selection');
      break;
    case 'slow_native_reads_respect_the_deadline':
      h.acknowledgeAfterReads = 1 << 30;
      h.readLatency = const Duration(seconds: 10);
      await pick();
      check(!h.prepared, 'preparation started without an acknowledgement');
      final spent = h.gaveUpAt! - h.stopStartedAt!;
      check(spent <= const Duration(seconds: 20),
          'the barrier ran ${spent.inMilliseconds} ms past its start');
      check(h.longestReadTimeout <= const Duration(seconds: 3),
          'a reading was allowed ${h.longestReadTimeout}');
      break;
    case 'a_slow_stop_counts_against_the_deadline':
      h.acknowledgeAfterReads = 1 << 30;
      h.stopLatency = const Duration(seconds: 18);
      h.readLatency = const Duration(seconds: 1);
      await pick();
      check(!h.prepared, 'preparation started without an acknowledgement');
      final spent = h.gaveUpAt! - h.stopStartedAt!;
      check(spent <= const Duration(seconds: 20),
          'stop plus wait took ${spent.inMilliseconds} ms');
      break;
    default:
      throw ArgumentError(scenario);
  }
  print('PASS $scenario');
}
''';
