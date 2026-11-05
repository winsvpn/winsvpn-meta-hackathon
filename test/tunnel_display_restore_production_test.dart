import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production code: $start');
  }
  return source.substring(first, last);
}

// Round UN, 2026-09-29 owner report: "Unknown node" replaced the connected
// server after the Calculator relock and PIN unlock, and after background and
// reopen. The committed-node record lived only in the Dart isolate: one
// flapping native reading ended it, and a killed app or destroyed Flutter
// engine never had it. The fix persists it inside the encrypted runtime
// settings record, bound to the account scope and to the native session.
//
// These scenarios run the production code verbatim, with the technique of
// connected_server_switch_transaction_test.dart: the Round UN methods, the
// settle funnel, native reconciliation, the lifecycle handler, the native
// stop funnel, the runtime-settings queue, the account-scope helpers, the
// readiness read, and the exact PIN-unlock, commit and account-activation
// snippets. Only native I/O, the encrypted store and widget state are
// replaced. This is state-machine coverage, not device proof.
void main() {
  late Directory temporary;
  late File executable;
  late String source;

  setUpAll(() async {
    source = File('lib/main.dart').readAsStringSync();
    final pieces = <String>[
      _between(source, '  static const String _tunnelDisplayRecordKey',
          '  // User intent, not a mirror of the node currently displayed.'),
      _between(
          source,
          "  /// Round UN: asks, once the current frame's state change is done",
          "  /// Keeps the dashboard's committed-node record in step"),
      _between(source, "  /// Keeps the dashboard's committed-node record in step",
          '  void _finishTunnelConnectFailure('),
      _between(source, '  Future<void> _reconcileNativeTunnelState(',
          '  Future<void> _fetchLiveNetworkIp() async {'),
      _between(
          source,
          '  @override\n  void didChangeAppLifecycleState(AppLifecycleState state) {',
          '  void _startStatusHeartbeat() {'),
      _between(source, '  Future<bool> _stopNativeTunnel({',
          '  Future<bool?> _nativeTunnelActivityForStopSettlement() async {'),
      _between(
          source,
          '  Future<Map<String, dynamic>> _readVpnRuntimeSettings() async {',
          '  // M-14: the legacy Apple file -> Keychain migration'),
      _between(source, '  Future<Map<String, dynamic>> _readSensitiveJsonMap(',
          '  // Derives a stable, non-reversible per-account scope token'),
      _between(
          source,
          '  Future<String> _currentAccountNumberForRefresh() async {',
          '  // The identifier every _loadOrCreateClientKeyPair call site must agree on'),
      _between(
          source,
          '  Future<String> _effectiveAccountScopeForKeyPair() async {',
          '  @override\n  void initState() {'),
      _between(
          source,
          '  Future<Map<dynamic, dynamic>?> _latestTunnelReadiness() async {',
          '  Future<bool> _nativeWinn3SecurityRefusalReported('),
      // The dashboard's Double VPN single-hop latch: the getter, the commit
      // answer and the service-reading adoption, verbatim.
      _between(source, '  bool get _doubleVpnSingleHopSession =>',
          '  String get _winnSessionDetailLine'),
    ];
    final unlock = _between(
        source,
        '        final viaRecoveryCode = _recoveryUnlockPending;\n',
        '        // A camouflage-latched launch defers the privacy-consent prompt');
    final commit = _between(
        source,
        '      if (mounted) {\n        setState(() {\n          _isConnected = true;\n'
            '          // A new display session for the node this tunnel dials',
        '      await _saveVpnRuntimeSettings(\n'
            '        accountNumber: await _currentAccountNumberForRefresh(),');
    final auth = _between(
        source,
        '    if (mounted) {\n      setState(applyAuthSuccessState);',
        '    if (freeAccess) {\n      unawaited(_sharedNodeDiscovery());');
    final startAttempt = _between(
        source,
        '    // Round UN (OI-UN-1): a start attempt replaces the native session',
        '    _lastTunnelCandidateWasSecurityRefusal = false;\n'
            '    _lastWinn3FailureShape = Winn3FailureShape.unclassified;');
    temporary = await Directory.systemTemp.createTemp('round-un-restore-');
    executable = File('${temporary.path}/round_un_restore.dart');
    final ledger = File('lib/tunnel_display_identity.dart').absolute.uri;
    final doubleVpn =
        File('lib/double_vpn_assignment_retry.dart').absolute.uri;
    final fastConnect =
        File('lib/double_vpn_fast_connect.dart').absolute.uri;
    await executable.writeAsString("import '$ledger';\n"
        "import '$doubleVpn';\nimport '$fastConnect';\n$_harnessBefore\n"
        '${pieces.join('\n')}\n'
        '  // The PIN unlock success branch of _onCalculatorButtonPressed.\n'
        '  void unlockVerbatim() {\n    if (!mounted) return;\n$unlock  }\n\n'
        '  // The commit in _startTunnelCandidate, up to its settings save.\n'
        '  void commitVerbatim({\n'
        '    required Map<String, dynamic> config,\n'
        '    required Map<String, dynamic> configForPersistence,\n'
        '    required _Caller selectedNodeCaller,\n'
        '    required String protocolLabel,\n'
        '    required int? winn3StartToken,\n'
        '    bool committedSingleHop = false,\n'
        '  }) {\n$commit  }\n\n'
        '  // _onAuthSuccess applying its state, then the Round UN reconcile.\n'
        '  void authSuccessVerbatim(int expectedEpoch,\n'
        '      {required bool freeAccess}) {\n'
        '    void applyAuthSuccessState() {\n'
        '      _isLoggedIn = true;\n'
        '      _isFreeAccessSession = freeAccess;\n'
        '    }\n\n$auth  }\n\n'
        '  // The head of _startTunnelCandidate, before any native call.\n'
        '  void startAttemptVerbatim() {\n$startAttempt  }\n'
        '$_harnessAfter');
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'trigger_relock_flap_then_unlock_restores',
    'trigger_relock_without_flap_keeps_commit',
    'trigger_background_resume_flap_restores',
    'background_reading_never_disconnects',
    'trigger_relaunch_apple_restores_after_unlock',
    'trigger_relaunch_android_engine_restores',
    'trigger_relaunch_android_process_death_stays_unknown',
    'trigger_relogin_same_account_restores',
    'trigger_relogin_other_account_clears_record',
    'trigger_relogin_other_account_while_disconnected_clears_record',
    'negative_other_account_record_never_shown',
    'negative_other_session_record_never_shown',
    'negative_record_cleared_by_disconnect',
    'negative_android_v1_after_v3_not_persisted',
    'negative_android_foreign_token_not_persisted',
    'negative_decoy_up_reads_nothing',
    'negative_desktop_never_reads',
    'race_commit_during_restore_read',
    'race_death_during_restore_read',
    'race_relock_during_restore_read',
    'race_account_change_during_restore_read',
    'race_stop_during_persist',
    'race_death_while_persist_queued',
    'restore_retries_until_status_current',
    'restore_attempts_are_bounded',
    'resume_asks_again_after_inconclusive',
    'no_account_single_attempt',
    'commit_outranks_restore',
    'oi1_failed_save_then_no_options_restart_stays_unknown',
    'oi1_no_options_restart_is_never_named',
    'oi1_failed_start_attempt_clears_record',
    'oi1_start_attempt_drops_inflight_persist',
    'oi6_android_persist_rereads_until_lifecycle',
    'oi6_android_persist_rereads_are_bounded',
    'oi6_android_persist_reread_cancelled_by_stop',
    'oi6_android_persist_reread_survives_relock',
    'oi6_android_persist_reread_survives_relock_during_read',
    'oi6_android_persist_reread_cancelled_by_death',
    'oi6_android_persist_reread_stops_on_other_start',
    'oi6_apple_and_v1_persist_read_once',
    'oi11_stop_while_persist_reads_drops_write',
    'un2_android_connect_behind_decoy_persists_then_relaunch_restores',
    'un2_android_flap_behind_decoy_resumes_without_a_record',
    'un2_android_foreground_handover_flap_resumes_without_a_record',
    'un2_android_resumed_session_flaps_again',
    'un2_android_resume_retries_until_lifecycle',
    'un2_negative_other_start_never_resumed',
    'un2_negative_stop_forgets_the_commit',
    'un2_negative_other_account_epoch_never_resumed',
    'un2_negative_decoy_up_resumes_nothing',
    'un2_negative_apple_commit_is_not_remembered',
    'un2_negative_v1_commit_is_not_remembered',
    'marker_commit_one_hop_latches_and_announces',
    'marker_commit_two_hop_clears_it',
    'marker_commit_double_off_clears_it',
    'marker_server_switch_staging_does_not_move_it',
    'marker_failed_switch_keeps_the_retained_session_marker',
    'marker_genuine_double_session_not_labelled_by_staging',
    'marker_native_adoption_takes_the_service_marker',
    'marker_native_adoption_drops_obsolete_and_switching_readings',
    'marker_android_commit_takes_the_service_answer',
  ]) {
    test('production Round UN restore: $scenario', () async {
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[executable.path, scenario],
        workingDirectory: temporary.path,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }

  group('storage and clearing contract', () {
    test('the record lives only in the encrypted runtime settings record', () {
      final roundUn = _between(
          source,
          "  /// Round UN: asks, once the current frame's state change is done",
          "  /// Keeps the dashboard's committed-node record in step");
      expect(roundUn, contains('_readVpnRuntimeSettings()'));
      expect(roundUn, contains('_mutateVpnRuntimeSettings('));
      for (final forbidden in <String>[
        'File(',
        'writeAsString',
        '_appDocumentsDirectory',
        '_writeSensitiveText(',
        '_readSensitiveText(',
        'SharedPreferences',
        'crypto.',
      ]) {
        expect(roundUn, isNot(contains(forbidden)), reason: forbidden);
      }
      // vpn_settings.txt is an existing sensitive name: the native stores
      // encrypt it (Android Keystore AES-GCM, Apple Keychain, DPAPI,
      // libsecret). Round UN adds no name, so no native allowlist changes.
      final names = _between(
          source,
          '  static const Set<String> _sensitiveStateFileNames = <String>{',
          '  };');
      expect(names, contains("'vpn_settings.txt',"));
      expect(RegExp(r"'[a-z_]+\.(json|txt|conf)',").allMatches(names).length,
          11);
    });

    test('logout, account deletion and the duress wipe delete the container',
        () {
      final artifacts = _between(source,
          '  static const Set<String> _accountCleanupArtifacts = <String>{', '  };');
      expect(artifacts, contains("'vpn_settings',"));
      final cleanup = _between(
          source,
          '  Future<bool> _deleteCleanupArtifact(String artifact, String scopeToken) {',
          '  Future<bool> _clearOrdinaryCamouflageLatchVerified() async {');
      expect(
          cleanup,
          contains("case 'vpn_settings':\n        return () async {\n"
              '          await _settingsMutationQueue;\n'
              "          return _deleteSensitiveArtifactVerified('vpn_settings.txt');"));
      final duress = _between(
          source,
          '  Future<void> _wipeIncriminatingStateForDuress({',
          '  /// Deletes everything in the app');
      expect(duress, contains("await _deleteSensitiveText('vpn_settings.txt');"));
      // The alert-preserving branch keeps only the queued alert.
      expect(
          duress,
          contains("final record = data['pending_emergency'];\n"
              '          data.clear();'));
    });

    test('every app-initiated stop clears the record before stopping', () {
      final stop = _between(source, '  Future<bool> _stopNativeTunnel({',
          '  Future<bool?> _nativeTunnelActivityForStopSettlement() async {');
      final clear = stop.indexOf('unawaited(_clearPersistedTunnelDisplay());');
      final native = stop.indexOf("invokeMethod('stopTunnel'");
      expect(clear, greaterThanOrEqualTo(0));
      expect(native, greaterThan(clear));
      // The only direct stops outside that funnel are the duress path (whose
      // wipe deletes vpn_settings.txt) and free activation (followed by
      // _onAuthSuccess, which reconciles the record). A new direct stop must
      // be reviewed for Round UN.
      expect(
          RegExp(r"invokeMethod\(\s*'stopTunnel'").allMatches(source).length,
          3);
      // OI-UN-11: the stop generation moves before the clear is queued.
      final bump = stop.indexOf('_tunnelDisplayStopGeneration++;');
      expect(bump, greaterThanOrEqualTo(0));
      expect(bump, lessThan(clear));
    });

    test('every start attempt clears the record before any native call', () {
      final start = _between(source, '  Future<bool> _startTunnelCandidate(',
          '  /// Round UN: asks, once the current frame');
      final bump = start.indexOf('_tunnelDisplayStopGeneration++;');
      final clear = start.indexOf('unawaited(_clearPersistedTunnelDisplay());');
      expect(bump, greaterThanOrEqualTo(0));
      expect(clear, greaterThan(bump));
      // Ahead of every early return and every native side effect: the iOS v3
      // config delivery, the pre-start hook, and the native start itself.
      for (final later in <String>[
        'return false;',
        'deliverWinnIosServedTunnelConfig(',
        'beforeTunnelStart()',
        "'startTunnel',",
      ]) {
        final at = start.indexOf(later);
        expect(at, greaterThan(clear), reason: later);
      }
      // Exactly one clear in the start path: a later one would erase this
      // start's own record.
      expect('unawaited(_clearPersistedTunnelDisplay());'.allMatches(start).length,
          1);
    });

    test('every app-initiated stop forgets what the commit remembered', () {
      final stop = _between(source, '  Future<bool> _stopNativeTunnel({',
          '  Future<bool?> _nativeTunnelActivityForStopSettlement() async {');
      final clear = stop.indexOf('unawaited(_clearPersistedTunnelDisplay());');
      final forget = stop.indexOf('_tunnelDisplayLedger.forget();');
      final native = stop.indexOf("invokeMethod('stopTunnel'");
      expect(forget, greaterThan(clear));
      expect(native, greaterThan(forget));
      // A start attempt keeps it: a retained route is still the same session,
      // and a replaced one names another token. Only a stop ends the session.
      final start = _between(source, '  Future<bool> _startTunnelCandidate(',
          '  /// Round UN: asks, once the current frame');
      expect(start, isNot(contains('_tunnelDisplayLedger.forget();')));
    });

    test('the commit names its own start and the restore resumes it', () {
      final commit = _between(
          source,
          '          _tunnelDisplayLedger.commit(\n',
          '          _isCensorshipModeActive = _boolValue(config[');
      expect(
          commit,
          contains('nativeSession: startedNativeTunnelSession(\n'
              '              operatingSystem: Platform.operatingSystem,\n'
              '              dartStartToken: winn3StartToken,'));
      final restore = _between(
          source,
          '  Future<void> _restoreTunnelDisplayFromRecord() async {',
          '  /// Round UN: persists the node a tunnel that just committed');
      // The decoy gate precedes the first read, and the memory is consulted
      // only after the platform named a session.
      final gate = restore.indexOf('_showDecoyCalculator) return;');
      final read = restore.indexOf('await _readVpnRuntimeSettings()');
      final resume = restore.indexOf('_tunnelDisplayLedger.resume(');
      final named = restore.indexOf('if (remembered && session != null) {');
      expect(gate, greaterThanOrEqualTo(0));
      expect(read, greaterThan(gate));
      expect(named, greaterThan(read));
      expect(resume, greaterThan(named));
      // Only the commit's session may name it: the resume receives the
      // session the platform named and the display generation it observed.
      expect(restore, contains('nativeSession: session,'));
      expect(restore, contains('observedGeneration: displayGeneration,'));
    });

    test('a relock does not end the persist wait', () {
      final persist = _between(
          source,
          '  Future<void> _persistCommittedTunnelDisplay({',
          '  /// Round UN: removes the persisted committed-node record');
      expect(persist, contains('bool rereadCancelled() => !stillCurrent();'));
      expect(persist, isNot(contains('_showDecoyCalculator')));
    });

    test('every restore trigger is wired', () {
      final settle = _between(
          source,
          "  /// Keeps the dashboard's committed-node record in step",
          '  void _finishTunnelConnectFailure(');
      expect(settle,
          contains('if (changed && !wasConnected && _isConnected) {\n'
              '      _scheduleTunnelDisplayRestore();'));
      final lifecycle = _between(
          source,
          '  @override\n  void didChangeAppLifecycleState(AppLifecycleState state) {',
          '  void _startStatusHeartbeat() {');
      final resumed = lifecycle.indexOf('if (state == AppLifecycleState.resumed)');
      final resumeRestore =
          lifecycle.indexOf('_scheduleTunnelDisplayRestore();', resumed);
      expect(resumeRestore, greaterThan(resumed));
      expect(resumeRestore, lessThan(lifecycle.indexOf('return;', resumed) + 40));
      final auth = _between(source, '  Future<void> _onAuthSuccess(',
          '  Future<bool> _refreshFreeVpnConfig(');
      expect(auth,
          contains('unawaited(_reconcileTunnelDisplayAfterAuth(expectedEpoch));'));
    });
  });
}

const _harnessBefore = r'''
import 'dart:async';
import 'dart:convert';
import 'dart:io' hide Platform;

// Replaces dart:io Platform so a scenario can run as Android, iOS or desktop.
class Platform {
  static String operatingSystem = 'ios';
  static bool get isAndroid => operatingSystem == 'android';
  static bool get isIOS => operatingSystem == 'ios';
  static bool get isMacOS => operatingSystem == 'macos';
  static bool get isWindows => operatingSystem == 'windows';
  static bool get isLinux => operatingSystem == 'linux';
}

enum AppLifecycleState { resumed, inactive, hidden, paused, detached }

const Duration windowsTunnelNativeStopTimeout = Duration(seconds: 12);

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

class _Epoch {
  int current = 0;
  bool isCurrent(int captured) => captured == current;
}

class _Barrier {
  int resumes = 0;
  Future<void> resume() async => resumes++;
}

class _Gate {
  int get supersededFloor => 1;
}

class _Text {
  String text = '';
}

class _PinEntry {
  void reset() {}
}

class _Caller {
  const _Caller(this.exactSlug);
  final String exactSlug;
  bool get isPresent => exactSlug.isNotEmpty;
}

String winn3SelectedNodeIdentity(Map<String, dynamic> config) =>
    (config['node_slug'] ?? '').toString();
String normalizedWinnProtocolVersion(Object? raw) =>
    (raw ?? 'winn/1').toString();

const String appleGenerationA = '11111111-AAAA-4AAA-8AAA-111111111111';
const String appleGenerationB = '22222222-BBBB-4BBB-8BBB-222222222222';
const String accountA = '1111-2222-3333';
const String accountB = '4444-5555-6666';

// The app's own start hands the provider its config as transient start
// options; a Settings or menu toggle restarts it from the shared config.
Map<String, dynamic> appleReadiness(String generation,
        {bool available = true,
        String configSource = 'transient_start_options'}) =>
    <String, dynamic>{
      'active': true,
      'provider_status_available': available,
      'provider_status_generation': generation,
      'provider_config_source': configSource,
    };

Map<String, dynamic> androidReadiness(int token, {bool lifecycle = true}) =>
    <String, dynamic>{
      'active': true,
      'winn3_start_token': token,
      if (lifecycle) 'winn3_lifecycle': 'connected',
    };

class _Channel {
  _Channel(this.h);
  final Harness h;
  Future<T?> invokeMethod<T>(String method, [Object? arguments]) async {
    switch (method) {
      case 'getTunnelReadiness':
        h.readinessReads++;
        final gate = h.readinessGate;
        if (gate != null) {
          h.readinessGate = null;
          await gate.future;
        }
        if (h.readinessQueue.isNotEmpty) {
          return h.readinessQueue.removeAt(0) as T?;
        }
        return h.readiness as T?;
      case 'stopTunnel':
        h.stops++;
        final gate = h.stopGate;
        if (gate != null) {
          h.stopGate = null;
          await gate.future;
        }
        h.nativeActive = false;
        return null;
    }
    throw StateError('unexpected native method $method');
  }
}

class _LifecycleBase {
  void didChangeAppLifecycleState(AppLifecycleState state) {}
}

class Harness extends _LifecycleBase {
  Harness(this.secure) {
    _methodChannel = _Channel(this);
  }

  // The native encrypted store (Android Keystore file, Apple Keychain) by
  // logical name. Shared by two Harness objects to model a relaunch.
  final Map<String, String> secure;
  final List<String> secureReads = <String>[];
  Completer<void>? settingsReadGate;

  late final _Channel _methodChannel;
  static const String _freeAccessAccountNumber = '9999-9999-9999';
  bool mounted = true;
  bool _isConnected = false;
  bool _isLoggedIn = true;
  bool _isFreeAccessSession = false;
  bool _isLoading = false;
  bool _isTunnelTransitioning = false;
  bool _showDecoyCalculator = false;
  bool _supportsNativeTunnelReadiness = true;
  bool _supportsInAppCamouflage = true;
  bool _hasNativeTunnelBridge = true;
  bool get _isApplePlatform => Platform.isIOS || Platform.isMacOS;
  bool _accountCleanupPending = false;
  bool _preVpnGeoUserRequested = false;
  bool _settingsWritesSealed = false;
  bool _recoveryUnlockPending = false;
  bool _pinResetRequired = false;
  bool _winn3CoverFallbackInProgress = false;
  bool _isCensorshipModeActive = false;
  String _calcDisplayString = '0';
  String _ipAfterVpn = 'Disconnected';
  String _activeProtocolLabel = 'Winn';
  String _activeProtocolVersion = '';
  String _preVpnCountryCode = '';
  String _preVpnRegionCode = '';
  double? _preVpnLatitude;
  double? _preVpnLongitude;
  Map<String, dynamic>? _cachedVpnConfig;
  Future<void> _settingsMutationQueue = Future<void>.value();
  final _accountCleanupStartupBarrier = _Barrier();
  final _accountSessionEpoch = _Epoch();
  final _tunnelTransitionGate = _Gate();
  bool _desktopNetworkBlockMayBeLatched = true;
  final _accountController = _Text();
  final _calculatorPinEntry = _PinEntry();
  final _tunnelDisplayLedger = TunnelDisplayLedger();
  List<Map<String, dynamic>> _locations = <Map<String, dynamic>>[
    <String, dynamic>{
      'slug': 'uk-gb1',
      'name': 'United Kingdom',
      'flag': 'GB',
      'status': 'online',
    },
    <String, dynamic>{'slug': 'ca-tor1', 'name': 'Canada', 'status': 'online'},
    <String, dynamic>{'slug': 'de-fra1', 'name': 'Germany', 'status': 'online'},
  ];

  // Native tunnel state.
  bool nativeActive = false;
  final List<bool> activeQueue = <bool>[];
  Map<String, dynamic>? readiness;
  final List<Map<String, dynamic>?> readinessQueue = <Map<String, dynamic>?>[];
  Completer<void>? readinessGate;
  Completer<void>? stopGate;
  int readinessReads = 0;
  int nativeReads = 0;
  int stops = 0;
  int decoyGenerations = 0;
  final List<String> debugLog = <String>[];

  void setState(void Function() fn) => fn();
  bool _isDoubleVpnRequested = false;
  // Production keeps this beside _cachedVpnConfig; the getter and the helpers
  // extracted above read it.
  bool? _committedDoubleVpnSingleHop;
  // FAST-CONNECT: the commit words its one-time notice from this phase.
  DoubleVpnUpgradePhase _doubleVpnUpgradePhase = DoubleVpnUpgradePhase.none;
  final List<String> feedback = <String>[];
  void _showFeedback(String message) => feedback.add(message);
  String _t(String value) => value;
  void _debugLog(String message) => debugLog.add(message);
  bool _accountEpochIsCurrent(int expectedEpoch) =>
      _accountSessionEpoch.isCurrent(expectedEpoch);
  // Production hashes this; the harness needs only its equality.
  String _clientKeyScopeToken(String accountScope) => 'scope-v1:$accountScope';
  bool _boolValue(Object? value) => value == true;
  String _normalizeProtocolLabel(String label) => label;
  void _cancelSpeedTest() {}
  // C-core-17 (ruling A2) lifecycle members the extracted observer touches.
  bool _appInBackground = false;
  int _resumeProofGeneration = 0;
  // Production's return also voids the proof and starts the bounded resume
  // read; the restore paths here depend only on these two effects.
  void _leaveBackground() {
    _appInBackground = false;
    _resumeProofGeneration++;
  }
  void _startBackgroundHeartbeat() {}
  void _clearProductSurfacesForDecoy() => decoyGenerations++;
  // Production bumps _decoyGeneration in _clearProductSurfacesForDecoy; the
  // copied unlock block reads it (Round F3: the deferred offer's generation).
  int get _decoyGeneration => decoyGenerations;
  Future<void> _setLauncherCamouflage({required bool enabled}) async {}
  Future<void> _latchCamouflage() async {}
  Future<void> _fetchLiveNetworkIp() async {}
  Future<void> _fetchPreVpnCountryCode() async {}
  void _runPendingSettingsRestart() {}

  Future<bool> _readNativeTunnelActive() async {
    nativeReads++;
    if (activeQueue.isNotEmpty) return activeQueue.removeAt(0);
    return nativeActive;
  }

  Future<bool> _waitForTunnelState(bool expected,
          {int attempts = 15, Duration delay = const Duration(seconds: 1)}) async =>
      nativeActive == expected;

  Future<String?> _readSensitiveText(String name) async {
    secureReads.add(name);
    final gate = settingsReadGate;
    if (gate != null && name == 'vpn_settings.txt') {
      settingsReadGate = null;
      await gate.future;
    }
    return secure[name];
  }

  Future<void> _writeSensitiveText(String name, String value) async {
    secure[name] = value;
  }

  Future<void> _deleteSensitiveText(String name) async {
    secure.remove(name);
  }

  int settingsReads() =>
      secureReads.where((name) => name == 'vpn_settings.txt').length;

  Map<String, dynamic>? persistedRecord() {
    final raw = secure['vpn_settings.txt'];
    if (raw == null) return null;
    final record = (jsonDecode(raw) as Map)['tunnel_display_record'];
    return record == null ? null : Map<String, dynamic>.from(record as Map);
  }

  String card() {
    final shown = dashboardNodeForDisplay(
      locations: _locations,
      selectedIndex: 1,
      rendersConnected: _isConnected,
      ledger: _tunnelDisplayLedger,
      accountEpoch: _accountSessionEpoch.current,
    );
    if (shown.source == DashboardNodeSource.unknownTunnel) return 'Unknown node';
    return '${shown.source.name}:${shown.node?['name']}';
  }

  Future<void> signIn(String account) async {
    _accountController.text = account;
    await _mutateVpnRuntimeSettings((data) => data['account_number'] = account);
  }

  // The commit as _startTunnelCandidate performs it: the route is asked for
  // first (verbatim helper, which awaits), then the verbatim state change.
  Future<void> commitWithRoute(String slug, Map<String, dynamic> config) async {
    nativeActive = true;
    final committedSingleHop = await _routeIsSingleHopAtCommit(config);
    commitVerbatim(
      config: config,
      configForPersistence: config,
      selectedNodeCaller: _Caller(slug),
      protocolLabel: 'Winn',
      winn3StartToken: null,
      committedSingleHop: committedSingleHop,
    );
  }

  // A tunnel the connector committed in this process, through the verbatim
  // commit snippet (which persists the record).
  void commitNode(String slug, {int? winn3StartToken}) {
    nativeActive = true;
    final config = <String, dynamic>{
      'node_slug': slug,
      'protocol_version': 'winn/3',
    };
    commitVerbatim(
      config: config,
      configForPersistence: config,
      selectedNodeCaller: _Caller(slug),
      protocolLabel: 'Winn',
      winn3StartToken: winn3StartToken,
    );
  }
''';

const _harnessAfter = r'''
}

Future<void> settle() async {
  for (var i = 0; i < 40; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

const String ukShown = 'committedTunnel:United Kingdom';

Future<Harness> relaunch(Map<String, String> secure, {required bool decoy}) async {
  final h = Harness(secure);
  // A cold start: empty ledger, epoch 0, no typed account (restored from the
  // settings record), the decoy armed where camouflage applies.
  h._showDecoyCalculator = decoy;
  return h;
}

Map<String, dynamic> oneHopConfig(String slug) =>
    <String, dynamic>{'node_slug': slug, 'protocol_version': 'winn/1'};

Map<String, dynamic> twoHopConfig(String slug) => <String, dynamic>{
      'node_slug': slug,
      'protocol_version': 'winn/1',
      'double_vpn_active': true,
      'double_vpn_core_id': 'north-america-core',
      'double_vpn_exit_slug': slug,
    };

Future<void> main(List<String> args) async {
  final scenario = args.single;
  final secure = <String, String>{};
  final h = Harness(secure);
  switch (scenario) {
    case 'trigger_relock_flap_then_unlock_restores':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      check(h.card() == ukShown, 'commit: ${h.card()}');
      check(h.persistedRecord()?['slug'] == 'uk-gb1', 'commit did not persist');
      // Leaving the foreground: the decoy arms on `inactive`, and that
      // relock's own reconciliation, still in the foreground, reads one "not
      // active" (the provider probe lagging). Ruling A2: a reading taken in
      // the background never reaches reconciliation.
      h.activeQueue.add(false);
      h.didChangeAppLifecycleState(AppLifecycleState.inactive);
      await settle();
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      check(h._showDecoyCalculator, 'relock did not arm the decoy');
      check(!h._isConnected, 'the flap did not disconnect');
      // Reopen: the tunnel is adopted again behind the calculator.
      h.nativeActive = true;
      final readsBehindDecoy = h.settingsReads();
      final readinessBehindDecoy = h.readinessReads;
      h.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await settle();
      check(h._isConnected, 'resume did not adopt the tunnel');
      check(h.card() == 'Unknown node', 'behind the decoy: ${h.card()}');
      check(h.settingsReads() == readsBehindDecoy &&
              h.readinessReads == readinessBehindDecoy,
          'the record was read behind the calculator');
      // PIN unlock.
      h.unlockVerbatim();
      await settle();
      check(!h._showDecoyCalculator, 'unlock kept the decoy');
      check(h.card() == ukShown, 'after unlock: ${h.card()}');
    case 'trigger_relock_without_flap_keeps_commit':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      h.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await settle();
      final readsBeforeUnlock = h.settingsReads();
      h.unlockVerbatim();
      await settle();
      check(h.card() == ukShown, 'no flap: ${h.card()}');
      check(h.settingsReads() == readsBeforeUnlock,
          'a live commit record was re-read from storage');
    case 'background_reading_never_disconnects':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.activeQueue.add(false);
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      check(h._showDecoyCalculator, 'relock did not arm the decoy');
      check(h._isConnected, 'a background reading disconnected the tunnel');
      check(h.activeQueue.length == 1, 'a native read ran in the background');
    case 'trigger_background_resume_flap_restores':
      // No in-app disguise here (a TV, or camouflage not applicable).
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      check(!h._showDecoyCalculator, 'no disguise applies here');
      // Reopen: the first reading lost its handshake proof, the next has it.
      h.activeQueue.add(false);
      h.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await settle();
      check(!h._isConnected, 'the flap did not disconnect');
      h.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await settle();
      check(h.card() == ukShown, 'after the flap: ${h.card()}');
    case 'trigger_relaunch_apple_restores_after_unlock':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      // iOS terminates the suspended app; the Packet Tunnel keeps running.
      h.mounted = false;
      final next = await relaunch(secure, decoy: true);
      next.readiness = appleReadiness(appleGenerationA);
      next.nativeActive = true;
      next._locations = <Map<String, dynamic>>[];
      await next._reconcileNativeTunnelState();
      await settle();
      check(next._isConnected, 'relaunch did not adopt');
      check(next.card() == 'Unknown node', 'behind the decoy: ${next.card()}');
      next.unlockVerbatim();
      await settle();
      // No listing yet: the record's own identity, with no health claimed.
      check(next.card() == ukShown, 'after unlock: ${next.card()}');
      final shown = dashboardNodeForDisplay(
        locations: next._locations,
        selectedIndex: 0,
        rendersConnected: true,
        ledger: next._tunnelDisplayLedger,
        accountEpoch: next._accountSessionEpoch.current,
      );
      check(shown.node?['status'] == 'unknown' && shown.node?['flag'] == 'GB',
          'restored row: ${shown.node}');
    case 'trigger_relaunch_android_engine_restores':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      // The Flutter engine is destroyed; the VpnService process survives.
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = androidReadiness(4242);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await settle();
      check(next.card() == ukShown, 'engine relaunch: ${next.card()}');
    case 'trigger_relaunch_android_process_death_stays_unknown':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      // Process death: native Always-on restarts the service in a new
      // process from its restart config. The token and lifecycle are gone.
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = <String, dynamic>{'active': true, 'winn3_start_token': -1};
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await settle();
      await Future<void>.delayed(const Duration(milliseconds: 4500));
      await settle();
      check(next.card() == 'Unknown node', 'process death: ${next.card()}');
    case 'trigger_relogin_same_account_restores':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      // Activation of the same account while the tunnel keeps running.
      final epoch = ++h._accountSessionEpoch.current;
      check(h.card() == 'Unknown node', 'new epoch: ${h.card()}');
      h.authSuccessVerbatim(epoch, freeAccess: false);
      await settle();
      check(h.persistedRecord() != null, 'same-account record was removed');
      check(h.card() == ukShown, 'same-account re-login: ${h.card()}');
    case 'trigger_relogin_other_account_clears_record':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      final epoch = ++h._accountSessionEpoch.current;
      h._accountController.text = accountB;
      h.authSuccessVerbatim(epoch, freeAccess: false);
      await settle();
      check(h.persistedRecord() == null, 'account change kept the record');
      check(h.card() == 'Unknown node', 'other account: ${h.card()}');
      // Free access is another account scope too.
      final free = Harness(<String, String>{});
      Platform.operatingSystem = 'ios';
      await free.signIn(accountA);
      free.readiness = appleReadiness(appleGenerationA);
      free.commitNode('uk-gb1');
      await settle();
      final freeEpoch = ++free._accountSessionEpoch.current;
      free.authSuccessVerbatim(freeEpoch, freeAccess: true);
      await settle();
      check(free.persistedRecord() == null, 'free access kept a paid record');
      check(free.card() == 'Unknown node', 'free access: ${free.card()}');
    case 'trigger_relogin_other_account_while_disconnected_clears_record':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      // The tunnel dies on its own (no app stop), so the record stays.
      h.nativeActive = false;
      await h._reconcileNativeTunnelState();
      await settle();
      check(!h._isConnected, 'death was not applied');
      check(h.persistedRecord() != null, 'a native death cleared the record');
      // Another account activates while nothing is connected: no restore
      // runs, so the activation itself must remove the old account's record.
      final epoch = ++h._accountSessionEpoch.current;
      h._accountController.text = accountB;
      h.authSuccessVerbatim(epoch, freeAccess: false);
      await settle();
      check(h.persistedRecord() == null, 'account change kept the record');
    case 'negative_other_account_record_never_shown':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      // Relaunch with another account's settings: same live session.
      final next = await relaunch(secure, decoy: false);
      await next.signIn(accountB);
      next.readiness = appleReadiness(appleGenerationA);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await settle();
      check(next.card() == 'Unknown node', 'other account: ${next.card()}');
      check(next.persistedRecord() == null, 'stale record kept');
    case 'negative_other_session_record_never_shown':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = appleReadiness(appleGenerationB);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await settle();
      check(next.card() == 'Unknown node', 'other session: ${next.card()}');
      check(next.persistedRecord() == null, 'stale record kept');
    case 'negative_record_cleared_by_disconnect':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      check(h.persistedRecord() != null, 'commit did not persist');
      final stopped = await h._stopNativeTunnel(keepVpnLauncher: true);
      await settle();
      check(stopped && h.stops == 1, 'the stop did not run');
      check(h.persistedRecord() == null, 'disconnect kept the record');
      // Even a session with the same native identity (the snapshot keeps
      // it) is not named after that disconnect.
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = androidReadiness(4242);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await settle();
      check(next.card() == 'Unknown node', 'after disconnect: ${next.card()}');
    case 'negative_android_v1_after_v3_not_persisted':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      // The readiness snapshot still names the earlier v3 start; this commit
      // is a v1 start that minted no token.
      h.readiness = androidReadiness(4242);
      h.commitNode('ca-tor1');
      await settle();
      check(h.card() == 'committedTunnel:Canada', 'commit: ${h.card()}');
      check(h.persistedRecord() == null, 'a v1 commit was bound to v3');
    case 'negative_android_foreign_token_not_persisted':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('ca-tor1', winn3StartToken: 777);
      await settle();
      check(h.persistedRecord() == null, 'another start token was bound');
    case 'negative_decoy_up_reads_nothing':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: true);
      next.readiness = appleReadiness(appleGenerationA);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      next._scheduleTunnelDisplayRestore();
      next.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await settle();
      check(next.settingsReads() == 0 && next.readinessReads == 0,
          'read behind the decoy: ${next.secureReads} ${next.readinessReads}');
      check(next.card() == 'Unknown node', 'named behind the decoy');
    case 'negative_desktop_never_reads':
      Platform.operatingSystem = 'linux';
      h._isConnected = false;
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      check(h._isConnected && h.card() == 'Unknown node', 'desktop adoption');
      check(h.settingsReads() == 0 && h.readinessReads == 0,
          'desktop read a record it can never bind');
    case 'race_commit_during_restore_read':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = appleReadiness(appleGenerationA);
      next.nativeActive = true;
      next.settingsReadGate = Completer<void>();
      final gate = next.settingsReadGate!;
      await next._reconcileNativeTunnelState();
      await settle();
      // A user switch commits Germany while the restore waits on storage.
      next.readiness = appleReadiness(appleGenerationB);
      next.commitNode('de-fra1');
      gate.complete();
      await settle();
      check(next.card() == 'committedTunnel:Germany', 'race: ${next.card()}');
    case 'race_death_during_restore_read':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      // No disguise re-arms on the death, so the later restore really runs.
      next._supportsInAppCamouflage = false;
      next.readiness = appleReadiness(appleGenerationA);
      next.nativeActive = true;
      next.readinessGate = Completer<void>();
      final gate = next.readinessGate!;
      await next._reconcileNativeTunnelState();
      await settle();
      next.nativeActive = false;
      await next._reconcileNativeTunnelState();
      gate.complete();
      await settle();
      check(!next._isConnected, 'death was not applied');
      check(next.card() == 'Unknown node' || !next._isConnected,
          'the obsolete restore named a dead session');
      // Another session comes up (a new profile generation).
      next.nativeActive = true;
      next.readiness = appleReadiness(appleGenerationB);
      await next._reconcileNativeTunnelState();
      await settle();
      check(next.card() == 'Unknown node', 'after death: ${next.card()}');
      check(next.persistedRecord() == null, 'the dead session record stayed');
    case 'race_relock_during_restore_read':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = appleReadiness(appleGenerationA);
      next.nativeActive = true;
      next.readinessGate = Completer<void>();
      final gate = next.readinessGate!;
      await next._reconcileNativeTunnelState();
      await settle();
      next.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      gate.complete();
      await settle();
      check(next._showDecoyCalculator, 'relock did not arm');
      check(next.card() == 'Unknown node', 'named behind the decoy');
      next.unlockVerbatim();
      await settle();
      check(next.card() == ukShown, 'after unlock: ${next.card()}');
    case 'race_account_change_during_restore_read':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = appleReadiness(appleGenerationA);
      next.nativeActive = true;
      next.readinessGate = Completer<void>();
      final gate = next.readinessGate!;
      await next._reconcileNativeTunnelState();
      await settle();
      next._accountSessionEpoch.current++;
      gate.complete();
      await settle();
      check(next.card() == 'Unknown node', 'account change: ${next.card()}');
      check(next._tunnelDisplayLedger.recordFor(accountEpoch: 0) == null,
          'the superseded epoch was named');
    case 'race_stop_during_persist':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.readinessGate = Completer<void>();
      final gate = h.readinessGate!;
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      // The user disconnects before the persist's readiness read returns.
      await h._stopNativeTunnel(keepVpnLauncher: true);
      h.setState(() {
        final wasConnected = h._isConnected;
        h._isConnected = false;
        h._settleTunnelDisplaySession(wasConnected);
      });
      gate.complete();
      await settle();
      check(h.persistedRecord() == null, 'a stopped session was persisted');
    case 'race_death_while_persist_queued':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      // An earlier settings write holds the queue.
      h.settingsReadGate = Completer<void>();
      final gate = h.settingsReadGate!;
      unawaited(h._writeVpnRuntimeSetting('unrelated', 1));
      await settle();
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      // The committed session dies before its queued write runs.
      h.nativeActive = false;
      await h._reconcileNativeTunnelState();
      check(!h._isConnected, 'death was not applied');
      gate.complete();
      await settle();
      check(h.persistedRecord() == null, 'a dead session was persisted');
    case 'resume_asks_again_after_inconclusive':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next._supportsInAppCamouflage = false;
      next.readiness = appleReadiness(appleGenerationA, available: false);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await Future<void>.delayed(const Duration(milliseconds: 4500));
      await settle();
      check(next.card() == 'Unknown node', 'unverified: ${next.card()}');
      // The provider status document is current by the next resume.
      next.readiness = appleReadiness(appleGenerationA);
      next.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await settle();
      check(next.card() == ukShown, 'after resume: ${next.card()}');
    case 'no_account_single_attempt':
      Platform.operatingSystem = 'ios';
      // A record is on file, but no account can be read for this process.
      secure['vpn_settings.txt'] = jsonEncode(<String, dynamic>{
        'tunnel_display_record': <String, dynamic>{
          'schema': 1,
          'slug': 'uk-gb1',
          'account_scope': 'scope-v1:$accountA',
          'native_session': 'apple-status:$appleGenerationA',
        },
      });
      h.readiness = appleReadiness(appleGenerationA, available: false);
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await Future<void>.delayed(const Duration(milliseconds: 2000));
      await settle();
      check(h.readinessReads == 1, 'attempts: ${h.readinessReads}');
      check(h.card() == 'Unknown node', 'no account: ${h.card()}');
      check(h.persistedRecord() != null, 'no account proved it stale');
    case 'restore_retries_until_status_current':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = appleReadiness(appleGenerationA);
      next.readinessQueue.add(appleReadiness(appleGenerationA, available: false));
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await settle();
      check(next.card() == 'Unknown node', 'first attempt named it');
      check(next.persistedRecord() != null, 'a lagging status removed it');
      await Future<void>.delayed(const Duration(milliseconds: 2600));
      await settle();
      check(next.card() == ukShown, 'second attempt: ${next.card()}');
    case 'restore_attempts_are_bounded':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = appleReadiness(appleGenerationA, available: false);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await Future<void>.delayed(const Duration(milliseconds: 5000));
      await settle();
      check(next.readinessReads == 3, 'attempts: ${next.readinessReads}');
      check(next.card() == 'Unknown node', 'unverified: ${next.card()}');
    case 'commit_outranks_restore':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      final reads = h.settingsReads();
      final readinessReads = h.readinessReads;
      h._scheduleTunnelDisplayRestore();
      await settle();
      check(h.settingsReads() == reads && h.readinessReads == readinessReads,
          'a committed session was re-read');
      check(h.card() == ukShown, 'commit: ${h.card()}');
    case 'oi1_failed_save_then_no_options_restart_stays_unknown':
      // Both Turn 1 seats (OI-UN-1): node A committed; a flap shows the
      // tunnel disconnected while provider A keeps running; the user connects
      // B; the host rewrites the shared config to B, then saveToPreferences
      // fails, so the profile keeps generation A. A Settings or menu toggle
      // later restarts the provider without options: B under generation A.
      for (final os in const <String>['ios', 'macos']) {
        Platform.operatingSystem = os;
        final run = Harness(<String, String>{});
        run._supportsInAppCamouflage = false;
        await run.signIn(accountA);
        run.readiness = appleReadiness(appleGenerationA);
        run.commitNode('uk-gb1');
        await settle();
        check(run.persistedRecord()?['slug'] == 'uk-gb1',
            '$os: commit did not persist');
        run.activeQueue.add(false);
        await run._reconcileNativeTunnelState();
        await settle();
        check(!run._isConnected, '$os: the flap did not disconnect');
        // The connect for B: the start attempt, then the failed profile save.
        // Native is unchanged (provider A still runs) and nothing commits.
        run.startAttemptVerbatim();
        await settle();
        run.readiness = appleReadiness(appleGenerationA,
            configSource: 'shared_config_path');
        await run._reconcileNativeTunnelState();
        await Future<void>.delayed(const Duration(milliseconds: 3200));
        await settle();
        check(run._isConnected, '$os: the restart was not adopted');
        check(run.card() == 'Unknown node', '$os: named ${run.card()}');
        check(run.persistedRecord() == null,
            '$os: the record outlived the start attempt');
      }
    case 'oi1_no_options_restart_is_never_named':
      // Seat C's guard alone (OI-UN-1): the start attempt's clear never
      // reached storage (the app was killed first, or the removal failed),
      // so record A survives. A provider restarted without options is still
      // never named from it.
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.settingsReadGate = Completer<void>();
      h.startAttemptVerbatim();
      await settle();
      h.mounted = false;
      check(h.persistedRecord()?['slug'] == 'uk-gb1', 'the clear was not held');
      final next = await relaunch(secure, decoy: false);
      next._supportsInAppCamouflage = false;
      next.readiness = appleReadiness(appleGenerationA,
          configSource: 'shared_config_path');
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await Future<void>.delayed(const Duration(milliseconds: 3200));
      await settle();
      check(next._isConnected, 'the restart was not adopted');
      check(next.card() == 'Unknown node', 'no-options restart: ${next.card()}');
      check(next.readinessReads == 3, 'attempts: ${next.readinessReads}');
      check(next.persistedRecord() != null,
          'a reading that names no session proved the record stale');
      // Control: the only difference is the config source.
      next.readiness = appleReadiness(appleGenerationA);
      next.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await settle();
      check(next.card() == ukShown, 'control: ${next.card()}');
    case 'oi1_failed_start_attempt_clears_record':
      // Fable's guard alone (OI-UN-1): a start attempt that never commits
      // removes record A, even while the running provider still reports A's
      // own start options. No later reading can pair A with a generation
      // whose shared config that attempt may have rewritten.
      Platform.operatingSystem = 'ios';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      h.activeQueue.add(false);
      await h._reconcileNativeTunnelState();
      await settle();
      check(!h._isConnected, 'the flap did not disconnect');
      h.startAttemptVerbatim();
      await settle();
      check(h.persistedRecord() == null, 'the start attempt kept the record');
      await h._reconcileNativeTunnelState();
      await settle();
      check(h._isConnected, 'not adopted');
      check(h.card() == 'Unknown node', 'after a start attempt: ${h.card()}');
    case 'oi1_start_attempt_drops_inflight_persist':
      // A commit's record write still in flight when another start attempt
      // begins must not land after that attempt's clear.
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.readinessGate = Completer<void>();
      final gate = h.readinessGate!;
      h.commitNode('uk-gb1');
      await settle();
      h.startAttemptVerbatim();
      await settle();
      gate.complete();
      await settle();
      check(h.persistedRecord() == null,
          'an earlier commit landed after a start attempt');
    case 'oi6_android_persist_rereads_until_lifecycle':
      // Fable (OI-UN-6): the commit lands before the engine publishes its
      // lifecycle; a later reading names the session.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.readinessQueue.add(androidReadiness(4242, lifecycle: false));
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      check(h.persistedRecord() == null, 'written before the lifecycle');
      check(h.readinessReads == 1, 'reads: ${h.readinessReads}');
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(h.readinessReads == 2, 'reads: ${h.readinessReads}');
      check(h.persistedRecord()?['native_session'] == 'android-winn3:4242',
          'record: ${h.persistedRecord()}');
      // The engine-relaunch trigger now restores.
      h.mounted = false;
      final next = await relaunch(secure, decoy: false);
      next.readiness = androidReadiness(4242);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await settle();
      check(next.card() == ukShown, 'engine relaunch: ${next.card()}');
    case 'oi6_android_persist_rereads_are_bounded':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242, lifecycle: false);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      // The last re-read is due at 4.5 s; a fourth would be due at 6 s.
      await Future<void>.delayed(const Duration(milliseconds: 7000));
      await settle();
      check(h.readinessReads == 4, 'reads: ${h.readinessReads}');
      check(h.persistedRecord() == null, 'an unnamed session was persisted');
      check(h.card() == ukShown, 'the commit itself: ${h.card()}');
    case 'oi6_android_persist_reread_cancelled_by_stop':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.readinessQueue.add(androidReadiness(4242, lifecycle: false));
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      // The user disconnects while the persist waits for the lifecycle. The
      // ledger is left as it is, so only the stop itself can end the wait.
      await h._stopNativeTunnel(keepVpnLauncher: true);
      await settle();
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(h.readinessReads == 1, 'read after the stop: ${h.readinessReads}');
      check(h.persistedRecord() == null, 'a stopped session was persisted');
    case 'oi6_android_persist_reread_survives_relock':
      // Round UN-2: a relock leaves the session standing, so it no longer
      // ends the wait. The write shows nothing, and a connect that finishes
      // as the user leaves the app is still named after the next adoption.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.readinessQueue.add(androidReadiness(4242, lifecycle: false));
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      // Backgrounded: the decoy arms while the tunnel stays up.
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      check(h._showDecoyCalculator && h._isConnected, 'relock state');
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(h.readinessReads == 2, 'second read: ${h.readinessReads}');
      check(h.persistedRecord()?['native_session'] == 'android-winn3:4242',
          'record: ${h.persistedRecord()}');
    case 'oi6_android_persist_reread_survives_relock_during_read':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.readinessQueue.add(androidReadiness(4242, lifecycle: false));
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      // The second reading is slow; the relock lands while it is in flight.
      h.readinessGate = Completer<void>();
      final gate = h.readinessGate!;
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(h.readinessReads == 2, 'second read: ${h.readinessReads}');
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      gate.complete();
      await settle();
      check(h._showDecoyCalculator && h._isConnected, 'relock state');
      check(h.persistedRecord()?['native_session'] == 'android-winn3:4242',
          'record: ${h.persistedRecord()}');
    case 'oi6_android_persist_reread_cancelled_by_death':
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.readinessQueue.add(androidReadiness(4242, lifecycle: false));
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      h.nativeActive = false;
      await h._reconcileNativeTunnelState();
      await settle();
      check(!h._isConnected, 'death was not applied');
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(h.readinessReads == 1, 'read after the death: ${h.readinessReads}');
      check(h.persistedRecord() == null, 'a dead session was persisted');
    case 'oi6_android_persist_reread_stops_on_other_start':
      // The token now names another start: the wait ends at once and nothing
      // is bound to this commit.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(9999, lifecycle: false);
      h.readinessQueue.add(androidReadiness(4242, lifecycle: false));
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await Future<void>.delayed(const Duration(milliseconds: 6000));
      await settle();
      check(h.readinessReads == 2, 'reads: ${h.readinessReads}');
      check(h.persistedRecord() == null, 'another start was bound');
    case 'oi6_apple_and_v1_persist_read_once':
      // Only an Android v3 start waits for its lifecycle.
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = <String, dynamic>{
        ...appleReadiness(appleGenerationA, available: false),
        'winn3_start_token': 4242,
      };
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(h.readinessReads == 1, 'Apple reads: ${h.readinessReads}');
      check(h.persistedRecord() == null, 'an unverified session was persisted');
      final v1 = Harness(<String, String>{});
      Platform.operatingSystem = 'android';
      await v1.signIn(accountA);
      v1.readiness = <String, dynamic>{'active': true};
      v1.commitNode('ca-tor1');
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(v1.readinessReads == 1, 'v1 reads: ${v1.readinessReads}');
      check(v1.persistedRecord() == null, 'a v1 session was persisted');
    case 'oi11_stop_while_persist_reads_drops_write':
      // Seat C F2 (OI-UN-11): the persist's readiness read returns while the
      // user's stop RPC is still pending. The stop's clear has already run
      // and the ledger has not changed yet, so only the stop generation can
      // drop the write that would otherwise land after the clear.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.readinessGate = Completer<void>();
      final readGate = h.readinessGate!;
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      h.stopGate = Completer<void>();
      final stopGate = h.stopGate!;
      final stopping = h._stopNativeTunnel(keepVpnLauncher: true);
      await settle();
      check(h.stops == 1, 'the stop RPC was not sent');
      readGate.complete();
      await settle();
      check(h.persistedRecord() == null,
          'the persist landed after the stop cleared the record');
      stopGate.complete();
      final stopped = await stopping;
      h.setState(() {
        final wasConnected = h._isConnected;
        h._isConnected = false;
        h._settleTunnelDisplaySession(wasConnected);
      });
      await settle();
      check(stopped, 'the stop failed');
      check(h.persistedRecord() == null, 'a stopped session was persisted');
    case 'un2_android_connect_behind_decoy_persists_then_relaunch_restores':
      // 2026-10-23 owner report, first half. The user taps Connect and leaves
      // the app at once: the decoy is armed when the commit lands, and the
      // engine has not published its lifecycle yet. Before Round UN-2 the
      // relock ended the persist's wait, so no record was ever written and the
      // next adoption (here a recreated Flutter engine) stayed unknown.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.readinessQueue.add(androidReadiness(4242, lifecycle: false));
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      check(h._showDecoyCalculator, 'the decoy did not arm');
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(h.persistedRecord()?['slug'] == 'uk-gb1',
          'no record behind the decoy: ${h.persistedRecord()}');
      // The Flutter engine is recreated in the same process; the VpnService
      // keeps its token and lifecycle.
      h.mounted = false;
      final next = await relaunch(secure, decoy: true);
      next.readiness = androidReadiness(4242);
      next.nativeActive = true;
      await next._reconcileNativeTunnelState();
      await settle();
      check(next.card() == 'Unknown node', 'behind the decoy: ${next.card()}');
      next.unlockVerbatim();
      await settle();
      check(next.card() == ukShown, 'after unlock: ${next.card()}');
    case 'un2_android_flap_behind_decoy_resumes_without_a_record':
      // 2026-10-23 owner report, second half, with no stored record at all:
      // the relock's reading flaps, the tunnel is adopted again behind the
      // calculator, and the PIN unlock names it from the commit this process
      // remembers, because the platform still names that commit's session.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      await h._mutateVpnRuntimeSettings(
          (data) => data.remove('tunnel_display_record'));
      check(h.persistedRecord() == null, 'the record was not removed');
      h.activeQueue.add(false);
      h.didChangeAppLifecycleState(AppLifecycleState.inactive);
      await settle();
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      check(h._showDecoyCalculator, 'relock did not arm the decoy');
      check(!h._isConnected, 'the flap did not disconnect');
      h.nativeActive = true;
      final readsBehindDecoy = h.settingsReads();
      final readinessBehindDecoy = h.readinessReads;
      h.didChangeAppLifecycleState(AppLifecycleState.resumed);
      await settle();
      check(h._isConnected, 'resume did not adopt the tunnel');
      check(h.card() == 'Unknown node', 'behind the decoy: ${h.card()}');
      check(h.settingsReads() == readsBehindDecoy &&
              h.readinessReads == readinessBehindDecoy,
          'the commit was resumed behind the calculator');
      h.unlockVerbatim();
      await settle();
      check(!h._showDecoyCalculator, 'unlock kept the decoy');
      check(h.card() == ukShown, 'after unlock: ${h.card()}');
      check(h.persistedRecord() == null, 'a stored record was involved');
    case 'un2_android_foreground_handover_flap_resumes_without_a_record':
      // A network handover in the foreground: one reading reports the tunnel
      // not active while the engine rebuilds its session, the next sees it
      // again. The session, its token and its lifecycle never changed.
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      await h._mutateVpnRuntimeSettings(
          (data) => data.remove('tunnel_display_record'));
      h.activeQueue.add(false);
      await h._reconcileNativeTunnelState();
      await settle();
      check(!h._isConnected, 'the flap did not disconnect');
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      check(h._isConnected, 'the tunnel was not adopted again');
      check(h.card() == ukShown, 'after the handover: ${h.card()}');
    case 'un2_android_resumed_session_flaps_again':
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      await h._mutateVpnRuntimeSettings(
          (data) => data.remove('tunnel_display_record'));
      for (var flap = 0; flap < 3; flap++) {
        h.activeQueue.add(false);
        await h._reconcileNativeTunnelState();
        await settle();
        check(!h._isConnected, 'flap $flap did not disconnect');
        h.nativeActive = true;
        await h._reconcileNativeTunnelState();
        await settle();
        check(h.card() == ukShown, 'flap $flap: ${h.card()}');
      }
    case 'un2_android_resume_retries_until_lifecycle':
      // The reading that follows the flap has no lifecycle yet. The session is
      // not nameable from it, so the tunnel stays unknown, and the bounded
      // retry names it once the lifecycle is back.
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      await h._mutateVpnRuntimeSettings(
          (data) => data.remove('tunnel_display_record'));
      h.activeQueue.add(false);
      await h._reconcileNativeTunnelState();
      await settle();
      h.nativeActive = true;
      h.readinessQueue.add(androidReadiness(4242, lifecycle: false));
      await h._reconcileNativeTunnelState();
      await settle();
      check(h.card() == 'Unknown node', 'unnamed session: ${h.card()}');
      await Future<void>.delayed(const Duration(milliseconds: 1700));
      await settle();
      check(h.card() == ukShown, 'second attempt: ${h.card()}');
    case 'un2_negative_other_start_never_resumed':
      // The flap was a death: the service came back with another start's
      // token. That session was not started by this commit.
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      h.activeQueue.add(false);
      await h._reconcileNativeTunnelState();
      await settle();
      h.readiness = androidReadiness(5151);
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      check(h._isConnected, 'the other start was not adopted');
      check(h.card() == 'Unknown node', 'other start: ${h.card()}');
      check(h.persistedRecord() == null, 'the other start kept the record');
    case 'un2_negative_stop_forgets_the_commit':
      // An app-initiated stop ends the session the commit started. A later
      // reading that still carries its token (the native snapshot keeps it)
      // does not bring the node back.
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      final stopped = await h._stopNativeTunnel(keepVpnLauncher: true);
      check(stopped, 'the stop failed');
      h.setState(() {
        final wasConnected = h._isConnected;
        h._isConnected = false;
        h._settleTunnelDisplaySession(wasConnected);
      });
      await settle();
      check(!h._tunnelDisplayLedger.remembers(accountEpoch: 0),
          'the stop kept the commit');
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      check(h._isConnected, 'the tunnel was not adopted');
      check(h.card() == 'Unknown node', 'after the stop: ${h.card()}');
    case 'un2_negative_other_account_epoch_never_resumed':
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      await h._mutateVpnRuntimeSettings(
          (data) => data.remove('tunnel_display_record'));
      h.activeQueue.add(false);
      await h._reconcileNativeTunnelState();
      await settle();
      // Another activation while the tunnel keeps running.
      h._accountSessionEpoch.current++;
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      check(h._isConnected, 'the tunnel was not adopted');
      check(h.card() == 'Unknown node', 'other epoch: ${h.card()}');
    case 'un2_negative_decoy_up_resumes_nothing':
      // The same gate as the stored record: behind the calculator nothing is
      // read and nothing is named, even from memory.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h.readiness = androidReadiness(4242);
      h.commitNode('uk-gb1', winn3StartToken: 4242);
      await settle();
      await h._mutateVpnRuntimeSettings(
          (data) => data.remove('tunnel_display_record'));
      h.activeQueue.add(false);
      h.didChangeAppLifecycleState(AppLifecycleState.inactive);
      await settle();
      h.didChangeAppLifecycleState(AppLifecycleState.paused);
      await settle();
      h.nativeActive = true;
      final readsBefore = h.settingsReads();
      final readinessBefore = h.readinessReads;
      h.didChangeAppLifecycleState(AppLifecycleState.resumed);
      h._scheduleTunnelDisplayRestore();
      await settle();
      check(h._showDecoyCalculator && h._isConnected, 'state behind the decoy');
      check(h.settingsReads() == readsBefore &&
              h.readinessReads == readinessBefore,
          'read behind the decoy');
      check(h.card() == 'Unknown node', 'named behind the decoy');
    case 'un2_negative_apple_commit_is_not_remembered':
      // Apple names its session only in a provider reading, so an Apple
      // commit is not remembered and behaves exactly as before.
      Platform.operatingSystem = 'ios';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h.commitNode('uk-gb1');
      await settle();
      check(!h._tunnelDisplayLedger.remembers(accountEpoch: 0),
          'an Apple commit was remembered');
      await h._mutateVpnRuntimeSettings(
          (data) => data.remove('tunnel_display_record'));
      h.activeQueue.add(false);
      await h._reconcileNativeTunnelState();
      await settle();
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      check(h._isConnected, 'the tunnel was not adopted');
      check(h.card() == 'Unknown node', 'Apple without a record: ${h.card()}');
    case 'un2_negative_v1_commit_is_not_remembered':
      Platform.operatingSystem = 'android';
      h._supportsInAppCamouflage = false;
      await h.signIn(accountA);
      // A v1 start mints no token; the snapshot may still name an older v3.
      h.readiness = androidReadiness(4242);
      h.commitNode('ca-tor1');
      await settle();
      check(!h._tunnelDisplayLedger.remembers(accountEpoch: 0),
          'a v1 commit was remembered');
      h.activeQueue.add(false);
      await h._reconcileNativeTunnelState();
      await settle();
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      check(h.card() == 'Unknown node', 'v1 after a flap: ${h.card()}');
    case 'marker_commit_one_hop_latches_and_announces':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h._isDoubleVpnRequested = true;
      await h.commitWithRoute('uk-gb1', oneHopConfig('uk-gb1'));
      await settle();
      check(h._committedDoubleVpnSingleHop == true, 'the latch was not set');
      check(h._doubleVpnSingleHopSession, 'the dashboard would show nothing');
      check(h.feedback.length == 1 &&
              h.feedback.single == doubleVpnSingleHopConnectedMessage,
          'the one-time message: ${h.feedback}');
    case 'marker_commit_two_hop_clears_it':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h._isDoubleVpnRequested = true;
      await h.commitWithRoute('uk-gb1', oneHopConfig('uk-gb1'));
      check(h._doubleVpnSingleHopSession, 'precondition: marked');
      h.feedback.clear();
      h._isConnected = false;
      await h.commitWithRoute('uk-gb1', twoHopConfig('uk-gb1'));
      await settle();
      check(h._committedDoubleVpnSingleHop == false, 'the latch stayed set');
      check(!h._doubleVpnSingleHopSession, 'a genuine Double VPN is labelled');
      check(h.feedback.isEmpty, 'a genuine Double VPN announced one hop');
    case 'marker_commit_double_off_clears_it':
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h._isDoubleVpnRequested = true;
      await h.commitWithRoute('uk-gb1', oneHopConfig('uk-gb1'));
      check(h._doubleVpnSingleHopSession, 'precondition: marked');
      h.feedback.clear();
      h._isConnected = false;
      h._isDoubleVpnRequested = false;
      await h.commitWithRoute('uk-gb1', oneHopConfig('uk-gb1'));
      await settle();
      check(h._committedDoubleVpnSingleHop == false, 'the latch stayed set');
      check(!h._doubleVpnSingleHopSession, 'Double VPN off still labelled');
      check(h.feedback.isEmpty, 'Double VPN off announced one hop');
    case 'marker_server_switch_staging_does_not_move_it':
      // DV-01. A one-hop session is live. A server switch stages the prepared
      // TWO-hop replacement in the cached config (production does exactly
      // this before the cutover) and holds beforeTunnelStart. The retained
      // tunnel is still one hop, so the marker must stay until the commit.
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h._isDoubleVpnRequested = true;
      await h.commitWithRoute('uk-gb1', oneHopConfig('uk-gb1'));
      check(h._doubleVpnSingleHopSession, 'precondition: marked');
      final heldCutover = Completer<void>();
      final switching = () async {
        h._isTunnelTransitioning = true;
        h._cachedVpnConfig = twoHopConfig('de-fra1');
        await heldCutover.future;
        h._isConnected = false;
        h._isTunnelTransitioning = false;
        await h.commitWithRoute('de-fra1', twoHopConfig('de-fra1'));
      }();
      await settle();
      check(h._doubleVpnSingleHopSession,
          'the staged two-hop config cleared the marker while the one-hop tunnel still carries');
      check(h._committedDoubleVpnSingleHop == true, 'the latch moved early');
      heldCutover.complete();
      await switching;
      await settle();
      check(!h._doubleVpnSingleHopSession,
          'the committed two-hop session is still labelled');
    case 'marker_failed_switch_keeps_the_retained_session_marker':
      // DV-01, failure leg: the preparation fails, the old route is kept, the
      // transition flags settle, and the cache still holds the staged config.
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h._isDoubleVpnRequested = true;
      await h.commitWithRoute('uk-gb1', oneHopConfig('uk-gb1'));
      h._isTunnelTransitioning = true;
      h._cachedVpnConfig = twoHopConfig('de-fra1');
      h._isTunnelTransitioning = false;
      await settle();
      check(h._isConnected, 'precondition: the old route is kept');
      check(h._doubleVpnSingleHopSession,
          'a failed switch cleared the marker of the retained one-hop tunnel');
    case 'marker_genuine_double_session_not_labelled_by_staging':
      // The reverse staging: a genuine Double VPN session is live and the
      // cache is replaced by a one-hop document. It must not be labelled.
      Platform.operatingSystem = 'ios';
      await h.signIn(accountA);
      h.readiness = appleReadiness(appleGenerationA);
      h._isDoubleVpnRequested = true;
      await h.commitWithRoute('uk-gb1', twoHopConfig('uk-gb1'));
      check(!h._doubleVpnSingleHopSession, 'precondition: not marked');
      h._isTunnelTransitioning = true;
      h._cachedVpnConfig = oneHopConfig('de-fra1');
      h._isTunnelTransitioning = false;
      await settle();
      check(!h._doubleVpnSingleHopSession,
          'staging a one-hop config labelled a genuine Double VPN session');
    case 'marker_native_adoption_takes_the_service_marker':
      // DV-01, adoption: a service this process did not start (restarted by
      // the system, or adopted after an app restart). The cached config says
      // two hops; the service says marked. The service wins, and a later
      // reading that says otherwise clears it.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h._isDoubleVpnRequested = true;
      h._isConnected = true;
      h._cachedVpnConfig = twoHopConfig('uk-gb1');
      check(!h._doubleVpnSingleHopSession, 'precondition: no marker yet');
      final generation = h._tunnelDisplayLedger.generation;
      final epoch = h._accountSessionEpoch.current;
      h._adoptNativeDoubleVpnMarker(<String, dynamic>{
        'double_vpn_single_hop': true,
      }, displayGeneration: generation, accountEpoch: epoch);
      check(h._doubleVpnSingleHopSession,
          'the service marker was not adopted');
      h._adoptNativeDoubleVpnMarker(<String, dynamic>{
        'double_vpn_single_hop': false,
      }, displayGeneration: generation, accountEpoch: epoch);
      check(!h._doubleVpnSingleHopSession,
          'the service clearing its marker was not adopted');
      h._adoptNativeDoubleVpnMarker(<String, dynamic>{
        'double_vpn_single_hop': true,
      }, displayGeneration: generation, accountEpoch: epoch);
      // A reading with no boolean says nothing and changes nothing.
      for (final silent in <Object?>[null, 'true', 1]) {
        h._adoptNativeDoubleVpnMarker(<String, dynamic>{
          'double_vpn_single_hop': silent,
          'active': true,
        }, displayGeneration: generation, accountEpoch: epoch);
        check(h._doubleVpnSingleHopSession,
            'a non-boolean reading moved the marker: $silent');
      }
    case 'marker_native_adoption_drops_obsolete_and_switching_readings':
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h._isDoubleVpnRequested = true;
      h._isConnected = true;
      h._cachedVpnConfig = oneHopConfig('uk-gb1');
      h._committedDoubleVpnSingleHop = true;
      final oldGeneration = h._tunnelDisplayLedger.generation;
      final oldEpoch = h._accountSessionEpoch.current;
      // A reading issued before a newer session committed.
      h._tunnelDisplayLedger.commit(
        servedIdentity: 'de-fra1',
        callerIdentity: 'de-fra1',
        coverFallbackInProgress: false,
        accountEpoch: h._accountSessionEpoch.current,
        locations: h._locations,
      );
      h._adoptNativeDoubleVpnMarker(<String, dynamic>{
        'double_vpn_single_hop': false,
      }, displayGeneration: oldGeneration, accountEpoch: oldEpoch);
      check(h._committedDoubleVpnSingleHop == true,
          'an obsolete reading moved the marker');
      // A reading for an account that has since been replaced.
      final currentGeneration = h._tunnelDisplayLedger.generation;
      h._accountSessionEpoch.current++;
      h._adoptNativeDoubleVpnMarker(<String, dynamic>{
        'double_vpn_single_hop': false,
      }, displayGeneration: currentGeneration, accountEpoch: oldEpoch);
      check(h._committedDoubleVpnSingleHop == true,
          'a reading for another account moved the marker');
      // A reading that arrives while a switch is preparing.
      h._isTunnelTransitioning = true;
      h._adoptNativeDoubleVpnMarker(<String, dynamic>{
        'double_vpn_single_hop': false,
      },
          displayGeneration: h._tunnelDisplayLedger.generation,
          accountEpoch: h._accountSessionEpoch.current);
      check(h._committedDoubleVpnSingleHop == true,
          'a reading during a switch moved the marker');
    case 'marker_android_commit_takes_the_service_answer':
      // Dashboard and notification read one fact: at commit the answer is the
      // service's own, whatever the Dart rule would have said.
      Platform.operatingSystem = 'android';
      await h.signIn(accountA);
      h._isDoubleVpnRequested = false;
      h.readiness = <String, dynamic>{
        'active': true,
        'double_vpn_single_hop': true,
      };
      await h.commitWithRoute('uk-gb1', twoHopConfig('uk-gb1'));
      await settle();
      check(h._committedDoubleVpnSingleHop == true,
          'the service said marked and the latch disagreed');
      h._isConnected = false;
      h._isDoubleVpnRequested = true;
      h.readiness = <String, dynamic>{
        'active': true,
        'double_vpn_single_hop': false,
      };
      await h.commitWithRoute('uk-gb1', oneHopConfig('uk-gb1'));
      await settle();
      check(h._committedDoubleVpnSingleHop == false,
          'the service said not marked and the latch disagreed');
      // No boolean from the service: the same rule is applied here.
      h._isConnected = false;
      h.readiness = <String, dynamic>{'active': true};
      await h.commitWithRoute('uk-gb1', oneHopConfig('uk-gb1'));
      await settle();
      check(h._committedDoubleVpnSingleHop == true,
          'with no service answer the rule was not applied');
    default:
      throw StateError('Unknown scenario: $scenario');
  }
  print('PASS $scenario');
  exit(0);
}
''';
