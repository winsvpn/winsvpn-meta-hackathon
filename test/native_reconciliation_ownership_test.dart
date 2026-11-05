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

// Round C turn 2: an obsolete native reading assigned _isConnected before its
// generation-guarded ledger call, and a rejected ledger call did not undo the
// assignment. A fresh identity-free reading then ended the newer committed
// session's record, so the secured card showed an unknown node although that
// tunnel never ended. These scenarios execute the production reconciliation,
// heartbeat and network-label methods verbatim with controllable native-read
// completions.
void main() {
  late Directory temporary;
  late File executable;
  late File smartConnectExecutable;

  setUpAll(() async {
    final source = File('lib/main.dart').readAsStringSync();
    final methods = <String>[
      _between(
        source,
        "  /// Keeps the dashboard's committed-node record in step",
        '  void _finishTunnelConnectFailure(',
      ),
      _between(
        source,
        '  Future<void> _reconcileNativeTunnelState(',
        '  /// Restores the owner-selected post-activation surface',
      ),
      _between(
        source,
        '  Future<void> _fetchLiveNetworkIp() async {',
        '  Future<void> _storeUserPin(',
      ),
      _between(
        source,
        '  Future<void> _runStatusHeartbeat() async {',
        '  Future<void> _refreshAnnouncementsAfterConnect({',
      ),
      // CORE-36: the account-only sync and the foreground tick that runs it
      // while the heartbeat's top gate is shut.
      _between(
        source,
        '  Future<void> _runBackgroundSecurityHeartbeat() async {',
        '  /// Reads the native tunnel backend purely to keep the display liveness',
      ),
      // CORE-36: the single-flight entry every account status caller goes
      // through, verbatim. Only the request behind it is a stub here.
      _between(
        source,
        '  Future<bool> _refreshAccountStatus({',
        '  Future<bool> _refreshAccountStatusOnce({',
      ),
      _between(
        source,
        '  Future<void> _determineSecurityOnboardingLayer() async {',
        '  Future<void> _onCalculatorButtonPressed(',
      ),
      _between(
        source,
        '  Future<void> _restartTunnelForSettingsChange() async {',
        '  void _bringSplitTunnelPanelIntoView() {',
      ),
      _between(
        source,
        '  Future<void> _toggleVpnConnection() async {',
        '  void _showFeedback(String message) {',
      ),
      _between(
        source,
        '  Future<void> _switchConnectedServer(',
        '  Future<void> _showLocationPicker(',
      ),
      _between(
        source,
        '  void _finishTunnelConnectFailure(String fallbackMessage) {',
        '  Future<void> _connectWithSmartProtocol({',
      ),
      _between(
        source,
        '  Future<void> _handleTrustedExpiredAccount(',
        '  Future<void> _handleTrustedRevokedAccount(',
      ),
      _between(
        source,
        '  Future<void> _recordAppleTunnelFailure(',
        '  Future<Map<String, int>> _currentTunCounters() async {',
      ),
      _between(
        source,
        '  Future<bool> _waitForTunnelReady(',
        '  Future<bool> _stopNativeTunnel({',
      ),
      _between(
        source,
        '  Future<bool> _confirmTunnelUsable(',
        '  /// Resolves the Xray carrier to public IPv4 literals',
      ),
      _between(
        source,
        '  /// A terminal v3 failure ends the fast path for this cache:',
        '  Future<void> _persistVpnConfigRequired(',
      ),
    ];
    // The production smart connect, run verbatim in its own program so the
    // other scenarios keep their controllable connect stub.
    final smartConnect = _between(
      source,
      '  Future<void> _connectWithSmartProtocol({',
      '  Future<void> _toggleVpnConnection() async {',
    );
    // The production current-slug getter, which knows the unlisted choice.
    methods.add(_between(
      source,
      '  String _currentSelectedSlug() {',
      '  String _requestedLocationSlug()',
    ));
    // The connect confirmation _toggleVpnConnection calls, verbatim.
    methods.add(_between(
      source,
      '  /// Before a user connect to a manual choice the listing does not carry:',
      '  Widget _buildShareShortcut() {',
    ));
    // The selection re-bind the restore, switch and toggle call, verbatim.
    final selectionRebind = _between(
      source,
      '  /// A manual choice that the listing does not carry, so no row is selected.',
      '  void _applySelectedNodeFromAuth(',
    );
    temporary =
        await Directory.systemTemp.createTemp('wins-native-reconciliation-');
    executable = File('${temporary.path}/native_reconciliation.dart');
    smartConnectExecutable =
        File('${temporary.path}/native_reconciliation_smart_connect.dart');
    final imports = <String>[
      "import '${File('lib/tunnel_display_identity.dart').absolute.uri}';",
      "import '${File('lib/tunnel_transition_gate.dart').absolute.uri}';",
      "import '${File('lib/node_selection_rebind.dart').absolute.uri}';",
      "import '${File('lib/double_vpn_fast_connect.dart').absolute.uri}';",
    ].join('\n');
    await executable.writeAsString('$imports\n$_harnessBefore\n'
        '$_connectStub\n${methods.join('\n')}\n$selectionRebind\n'
        '$_harnessAfter');
    await smartConnectExecutable.writeAsString('$imports\n$_harnessBefore\n'
        '${methods.join('\n')}\n$selectionRebind\n$smartConnect\n'
        '$_harnessAfter');
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'reconcile_stale_false_then_fresh_true',
    'reconcile_two_completions_keep_b_record',
    'reconcile_stale_true_after_disconnect',
    'reconcile_stale_account_epoch',
    'reconcile_current_death_then_adoption',
    'heartbeat_stale_false_then_fresh_true',
    'heartbeat_current_death_then_adoption',
    'heartbeat_background_reading_dropped',
    'heartbeat_pre_return_reading_dropped',
    'network_label_background_reading_dropped',
    'heartbeat_background_true_reading_dropped',
    'heartbeat_pre_return_true_reading_dropped',
    'heartbeat_unanswered_read_reaches_account_sync',
    'loading_session_keeps_account_sync',
    'free_session_keeps_account_sync',
    'foreground_tick_one_status_request_per_minute',
    'account_syncs_never_overlap',
    'account_sync_epoch_replacement',
    'account_sync_callers_share_one_flight',
    'network_label_stale_false_then_fresh_true',
    'network_label_current_death_then_adoption',
    'restore_stale_false_commit_b_after_read',
    'restore_stale_false_commit_b_during_settings',
    'restore_stale_account_epoch',
    'restore_genuine_startup_adoption',
    'restore_current_death_clears_record',
    'settings_restart_stale_stop_failed_reading',
    'settings_restart_stop_failed_still_active',
    'settings_restart_stop_failed_inactive',
    'settings_restart_stale_stop_result',
    'toggle_stale_failed_stop_reading',
    'toggle_stale_stop_result',
    'toggle_stale_cancel_stop_result',
    'toggle_failed_stop_still_active',
    'toggle_failed_stop_inactive',
    'toggle_disconnect_current',
    'toggle_gated_by_maintenance_and_update',
    'toggle_unlisted_fresh_listing_refuses',
    'toggle_unlisted_refresh_relists_connects',
    'toggle_unlisted_refresh_fails_attempts_exact',
    'toggle_unlisted_refresh_fails_recent_listing_refuses',
    'restart_unlisted_keeps_tunnel',
    'restart_unlisted_stale_defers_then_runs',
    'restart_deferred_retries_after_picker_load',
    'restart_deferred_dropped_after_reconnect',
    'restart_deferred_dropped_after_account_change',
    'toggle_unlisted_wait_keeps_adopted_status',
    'restart_deferred_waits_behind_decoy',
    'restart_under_decoy_defers_silently',
    'toggle_unlisted_refusal_silent_behind_decoy',
    'toggle_unlisted_shares_inflight_walk',
    'toggle_unlisted_wait_is_bounded',
    'toggle_unlisted_wait_is_a_connect_and_a_tap_abandons_it',
    'held_disconnect_bypasses_maintenance_and_update',
    'held_disconnect_never_connects',
    'network_label_held_session_untouched',
    'switch_stale_failed_stop_reading',
    'switch_stale_failed_preparation_reading',
    'switch_stale_cutover_stop_result',
    'switch_failed_stop_still_active',
    'switch_failed_preparation_native_died',
    'expiry_stale_inactivity_proof',
    'expiry_current_inactivity_proof',
    'network_label_stale_http_response',
    'network_label_current_http_disconnected',
    'network_label_current_http_after_own_settlement',
    'smart_connect_stale_failover_stop_before_tcp',
    'smart_connect_stale_diagnostic_before_tcp',
    'smart_connect_stale_failover_stop_before_cover',
    'smart_connect_stale_failover_stop_after_tcp_candidate',
    'smart_connect_stale_key_preflight_exception',
    'smart_connect_current_failure',
    'smart_connect_terminal_changed_plan_retries_once',
    'smart_connect_terminal_unchanged_plan_fails_once',
    'smart_connect_terminal_hub_unreachable_keeps_cache',
    'smart_connect_terminal_retry_fails_again_no_loop',
    'smart_connect_terminal_fresh_hub_config_no_retry',
    'readiness_wait_stale_label',
    'readiness_wait_current_label',
    'apple_readiness_wait_stale_failure',
    'apple_readiness_wait_current_failure',
    'apple_failure_recorder_stale_read',
    'apple_failure_recorder_current_read',
    'tunnel_usable_stale_label',
    'tunnel_usable_current_label',
  ]) {
    test('production native reconciliation: $scenario', () async {
      final program = scenario.startsWith('smart_connect_')
          ? smartConnectExecutable
          : executable;
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[program.path, scenario],
        workingDirectory: temporary.path,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }
}

const _harnessBefore = r'''
import 'dart:async';
import 'dart:io';

class _Epoch {
  int current = 0;
}

class _Response {
  int statusCode = 0;
  String body = '';
}

// The public-IP refresh: unreachable unless a scenario holds a response.
Completer<_Response>? httpGate;
bool httpRequested = false;
Future<_Response> fetchWithoutRedirects(Uri uri) {
  httpRequested = true;
  final gate = httpGate;
  if (gate == null) return Future<_Response>.error(StateError('offline'));
  return gate.future;
}

// Top-level policy stubs the production smart connect calls. They route it
// to the failure branch a scenario names in [smartRoute].
String smartRoute = 'tcp';
// Whether the cached config is fresh enough to lead without the hub.
bool cacheIsFresh = true;
enum Winn3LeadPolicy { standard, diagnosticForceXrayOverride }
enum Winn3NativeVerdict { pending }

class _HubCancellationsStub {
  void notifyGenerationChanged() {}
}

enum Winn3FailureShape { unclassified, unconfirmedTerminal, securityRefusal }

class _XrayOption {
  const _XrayOption(this.host, this.port, this.security);
  final String host;
  final int port;
  final String security;
}

void synchronizeWinn1FallbackDispatchGeneration({
  required String selectionGeneration,
  required bool ordinaryConnectivityAuthorized,
}) {}
bool maySkipControlPlaneRefreshWithCachedConfig({
  Map<String, dynamic>? cachedConfig,
  required bool automaticMode,
  required bool coverExactTarget,
  DateTime? now,
}) =>
    cacheIsFresh;
bool cachedConfigIsExplicitWinn3FastPathCandidate({
  Map<String, dynamic>? cachedConfig,
  required bool automaticMode,
  required bool coverExactTarget,
}) =>
    true;
bool doubleVpnRequestedButSingleHop({
  required bool doubleVpnRequested,
  required Map<String, dynamic>? config,
}) =>
    false;
bool mayLeadWithCachedConfigAfterRefreshFailure({
  Map<String, dynamic>? cachedConfig,
  Map<String, dynamic>? listingNode,
  required bool automaticMode,
  required bool coverExactTarget,
  bool explicitFastPathCandidate = false,
}) =>
    false;
// Mirrors lib/winn3_cover_fallback.dart; its own semantics are unit-tested in
// winn3_stale_cached_config_test.dart. Here the plan is its path MTU.
const String kVpnConfigFetchedAtKey = 'config_fetched_at_ms';
Map<String, dynamic> markVpnConfigStale(Map<String, dynamic> config) =>
    Map<String, dynamic>.from(config)..remove(kVpnConfigFetchedAtKey);
bool winn3ServedPlanChanged({
  required Map<String, dynamic> previous,
  required Map<String, dynamic> current,
}) =>
    previous['winn3_path_mtu'] != current['winn3_path_mtu'];
bool winn3TerminalFailureMayRetryWithFreshConfig({
  required bool configFromFastPath,
  required bool retryAlreadyUsed,
}) =>
    configFromFastPath && !retryAlreadyUsed;
String? strictWinnProtocolVersion(Map<String, dynamic> config) => 'winn/3';
bool armWinn1PrimaryHubDispatchAuthorization({
  required Map<String, dynamic> config,
  required String selectionGeneration,
}) =>
    true;
bool cachedConfigMayAuthorizeAwgOrXray({
  required Map<String, dynamic> config,
  required bool hasFreshHubConfig,
  Map<String, dynamic>? listingNode,
}) =>
    true;
Winn3LeadPolicy winn3LeadPolicy({
  required Map<String, dynamic> config,
  required bool userTcpOnly,
  required bool forceXrayForDiagnostics,
}) =>
    Winn3LeadPolicy.standard;
bool shouldAttemptServedLeadCandidate({
  required Winn3LeadPolicy policy,
  required bool directAwgEnabled,
}) =>
    true;
bool maySelectLegacyRouteAfterWinn3Lead({
  required Winn3LeadPolicy policy,
  required bool primaryAttempted,
  required Winn3NativeVerdict primaryVerdict,
  required bool securityRefused,
  required bool servedConfigNeedsLegacyNode,
}) =>
    smartRoute == 'cover';
bool servedConfigNeedsCoverNodeFallback(Map<String, dynamic> config) =>
    smartRoute == 'cover';
int? indexOfCoverBearingWinn1Fallback({
  required List<Map<String, dynamic>> locations,
  required String failedSlug,
  required Set<String> alreadyTriedSlugs,
}) =>
    1;
bool winn3CoverFallbackBudgetRemains(Set<String> alreadyTriedSlugs) => true;
// Mirrors lib/winn3_cover_fallback.dart. No scenario here serves a Core relay
// route, so the relay failure action is always none; its semantics are
// unit-tested in winn3_relay_test.dart.
enum Winn3RelayFailureAction { none, suppressOnly, suppressAndRetry }
Winn3RelayFailureAction winn3RelayFailureAction({
  required Map<String, dynamic> config,
  required bool isUpgradeAttempt,
  required bool retryAlreadyUsed,
  required Winn3NativeVerdict verdict,
  required Winn3FailureShape shape,
}) =>
    Winn3RelayFailureAction.none;
DateTime winn3RelaySuppressionUntil(DateTime now) =>
    now.add(const Duration(minutes: 5));
// No scenario here serves a relay, so a config never carries one; the real
// guard (a failed relay-led attempt does not strike the direct UDP memory) and
// the same-sample failure shape merge are pinned in winn3_relay_test.dart.
bool winn3ConfigCarriesRelay(Map<String, dynamic> config) => false;
// Mirrors lib/winn3_cover_fallback.dart: a refusal seen once is never
// relabelled as silence.
Winn3FailureShape mergeWinn3FailureShape(
  Winn3FailureShape previous,
  Winn3FailureShape observed,
) {
  if (previous == Winn3FailureShape.securityRefusal ||
      observed == Winn3FailureShape.securityRefusal) {
    return Winn3FailureShape.securityRefusal;
  }
  return observed == Winn3FailureShape.unclassified ? previous : observed;
}

// The harness readiness maps carry no typed verdict string, so the shape read
// from a sample is always unclassified here; winn3_failure_shape_test.dart
// covers the real reader.
Winn3FailureShape nativeWinn3FailureShape(
  Map<dynamic, dynamic>? readiness, {
  required int? startToken,
}) =>
    Winn3FailureShape.unclassified;
String winn3SelectedNodeIdentity(Map<String, dynamic> config) =>
    (config['node_slug'] ?? '').toString();
List<_XrayOption> boundedXrayTransportOptions(
  List<_XrayOption> candidates, {
  required int maximumCandidates,
}) =>
    candidates;

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

// Stubs for the restore's independent onboarding dependencies.
class _HeldLifecycle {
  bool holdsSession = false;
}

const int kCamouflagePinLength = 6;
const String kWinnProtocolV1 = 'winn/1';
const String kWinnProtocolV3 = 'winn/3';

class PinCredentialCodec {
  static int storedPinLength(String credential) => 6;
}

class _PinEntry {
  int pinLength = 6;
  int recoveryLength = 0;
}

class _Text {
  String text = '';
}

class _Channel {
  // A held method completes only when the scenario says so.
  final Map<String, Completer<Object?>> held = <String, Completer<Object?>>{};
  final Map<String, Object?> replies = <String, Object?>{};
  Future<T?> invokeMethod<T>(String method, [Object? arguments]) async {
    final gate = held.remove(method);
    if (gate != null) return (await gate.future) as T?;
    return replies[method] as T?;
  }
}

// Readiness and Apple-diagnostic stubs for _waitForTunnelReady and
// _recordAppleTunnelFailure.
String appleReadinessString(Map<dynamic, dynamic>? readiness, String key) =>
    (readiness?[key] ?? '').toString();
bool appleReadinessBool(Map<dynamic, dynamic>? readiness, String key) =>
    readiness?[key] == true;
bool appleTunnelReady(Map<dynamic, dynamic>? readiness) =>
    readiness?['ready'] == true;
bool appleTunnelNeedsVpnConfigurationPermission(
        Map<dynamic, dynamic>? readiness,
        [Object? error]) =>
    false;
String appleTunnelUserFailureStatus(
        Map<dynamic, dynamic>? readiness, Object? error) =>
    'Apple tunnel failed';
String appleTunnelDebugFailureSummary(
        Map<dynamic, dynamic>? readiness, Object? error) =>
    'summary';
Winn3NativeVerdict mergeWinn3NativeVerdict(
        Winn3NativeVerdict previous, Winn3NativeVerdict next) =>
    next;
Winn3NativeVerdict nativeWinn3ReadinessVerdict(
  Map<dynamic, dynamic> readiness, {
  int? startToken,
  int? startGeneration,
  String? selectionGeneration,
  String? failedNode,
}) =>
    Winn3NativeVerdict.pending;
bool nativeWinn3VerdictAllowsReadyState(Winn3NativeVerdict verdict) => true;
// tunnel_readiness.dart imports Flutter, so its proof predicates are stubbed
// with their production rules.
bool hasAwgPeerHandshakeProof({
  required bool handshakeRecent,
  required int rxBytes,
  required int txBytes,
}) =>
    handshakeRecent && rxBytes >= 80 && txBytes >= 80;
bool hasTunnelDataPathProof({
  required bool active,
  required bool engineReady,
  required bool vpnPresent,
  required bool vpnValidated,
  required int rxDelta,
  required int txDelta,
  required bool boundVpnProbeSucceeded,
  required bool encryptedPeerHandshakeSucceeded,
}) =>
    active && engineReady && vpnPresent && boundVpnProbeSucceeded;
bool hasUserVisibleTunnelProtectionProof({
  required bool active,
  required bool engineReady,
  required bool vpnPresent,
  required bool boundVpnProbeSucceeded,
}) =>
    active && engineReady && vpnPresent && boundVpnProbeSucceeded;

class DiscoveryIntakeState {
  const DiscoveryIntakeState({this.seqFloor = 0});
  final int seqFloor;
  static DiscoveryIntakeState restore(Map<String, dynamic> settings) =>
      const DiscoveryIntakeState();
}

class _DiscoveryOperationsStub {
  Future<T> run<T>(String key, Future<T> Function() operation) => operation();
}

bool stealthFlagForTransportMode(String mode) => mode == 'tcp';

List<String> normalizeExcludedIpv4Cidrs(Iterable<String> values) =>
    values.toList();

int onboardingDecisions = 0;

bool decoyCalculatorShouldArm({
  required bool supportsInAppCamouflage,
  required bool appIsActivated,
  required bool freeAccessSession,
  required bool camouflageLatched,
  required bool openedByDialer,
  required bool unlockedThisSession,
}) {
  onboardingDecisions++;
  return false;
}

class Harness {
  bool mounted = true;
  bool _isConnected = true;
  bool _isLoggedIn = true;
  bool _isLoading = false;
  bool _isTunnelTransitioning = false;
  bool _supportsNativeTunnelReadiness = true;
  // C-core-17 (ruling A2) fence members the extracted reconciliation reads.
  bool _appInBackground = false;
  int _resumeProofGeneration = 0;
  bool _resumeProofPending = false;
  bool _privacyConsentGranted = true;
  bool _isApplePlatform = false;
  bool _statusHeartbeatRunning = false;
  // CORE-36 (O9) members the extracted heartbeat reads. The production bound
  // is the 8 s proof window; a short one keeps the scenario fast.
  bool _heartbeatNativeReadPending = false;
  static const Object _heartbeatProofGateZoneKey = #winsHeartbeatProofGate;
  static const Duration _heartbeatNativeReadBound = Duration(milliseconds: 50);
  int? _accountStatusRefreshEpoch;
  Future<bool>? _accountStatusRefreshInFlight;
  int? _accountStatusThrottleEpoch;
  bool _preVpnGeoUserRequested = false;
  String _ipAfterVpn = 'Traffic Secured & Obfuscated';
  String _ipBeforeVpn = 'Fetching...';
  String _preVpnCountryCode = '';
  String _preVpnRegionCode = '';
  double? _preVpnLatitude;
  double? _preVpnLongitude;
  DateTime _lastAnnouncementSync = DateTime.now();
  DateTime _lastAccountStatusSync = DateTime.now();
  final _accountSessionEpoch = _Epoch();
  final _tunnelDisplayLedger = TunnelDisplayLedger();
  // Round UN: adoption asks for a persisted-record restore. The restore
  // itself runs verbatim in tunnel_display_restore_production_test.dart;
  // here only the request is counted.
  int restoreSchedules = 0;
  void _scheduleTunnelDisplayRestore() => restoreSchedules++;
  List<Map<String, dynamic>> _locations = <Map<String, dynamic>>[
    <String, dynamic>{'slug': 'france', 'name': 'France', 'status': 'online'},
    <String, dynamic>{'slug': 'germany', 'name': 'Germany', 'status': 'online'},
    <String, dynamic>{'slug': 'spain', 'name': 'Spain', 'status': 'online'},
  ];

  // Native reads: held ones complete only when the scenario says so; the
  // rest answer [nativeActive] at once.
  bool nativeActive = true;
  int holdReads = 0;
  final List<Completer<bool>> heldReads = <Completer<bool>>[];
  int nativeReads = 0;
  int announcementRefreshes = 0;

  void setState(void Function() update) => update();
  String _t(String value) => value;
  bool _accountEpochIsCurrent(int epoch) =>
      _accountSessionEpoch.current == epoch;
  Future<bool> _readNativeTunnelActive() {
    nativeReads++;
    if (holdReads > 0) {
      holdReads--;
      final read = Completer<bool>();
      heldReads.add(read);
      return read.future;
    }
    return Future<bool>.value(nativeActive);
  }
  void _armCalculatorAfterConfirmedDisconnect() {}
  Future<void> _fetchPreVpnCountryCode() async {}
  Future<void> _saveVpnRuntimeSettings({
    String? accountNumber,
    String? announcement,
    String? expiration,
    String? referralCode,
    String? referralLink,
    String? referralBackupLink,
    String? accountTerminalStatus,
  }) async {}
  // Both announcement syncs ride one forced status call, as in production.
  Future<void> _refreshAnnouncementsAfterConnect({
    bool forcePopup = false,
    int? expectedEpoch,
  }) async {
    announcementRefreshes++;
    await _refreshAccountStatus(force: true, expectedEpoch: expectedEpoch);
  }
  Future<void> _refreshAnnouncementsWhileDisconnected(
      {int? expectedEpoch}) async {
    await _refreshAccountStatus(force: true, expectedEpoch: expectedEpoch);
  }
  // One account status request per call, behind the production
  // single-flight entry. [syncGate] holds it open BEFORE it stamps the sync
  // clock: the account branch stamps only after its two credential reads
  // (Sol, CORE-36), so a held gate is the window in which every caller sees
  // the clock unstamped.
  int accountSyncs = 0;
  int syncsInFlight = 0;
  int maxSyncsInFlight = 0;
  final Map<int?, int> syncsInFlightByEpoch = <int?, int>{};
  int maxSyncsInFlightPerEpoch = 0;
  final List<int?> syncEpochs = <int?>[];
  Completer<void>? syncGate;
  Future<bool> _refreshAccountStatusOnce(
      {int? expectedEpoch, bool force = false}) async {
    accountSyncs++;
    syncEpochs.add(expectedEpoch);
    syncsInFlight++;
    if (syncsInFlight > maxSyncsInFlight) maxSyncsInFlight = syncsInFlight;
    final perEpoch = (syncsInFlightByEpoch[expectedEpoch] ?? 0) + 1;
    syncsInFlightByEpoch[expectedEpoch] = perEpoch;
    if (perEpoch > maxSyncsInFlightPerEpoch) {
      maxSyncsInFlightPerEpoch = perEpoch;
    }
    try {
      final gate = syncGate;
      if (gate != null) await gate.future;
      _lastAccountStatusSync = DateTime.now();
    } finally {
      syncsInFlight--;
      syncsInFlightByEpoch[expectedEpoch] = perEpoch - 1;
    }
    return true;
  }

  // Restore's own dependencies. Settings and activation reads can be held so
  // a commit can land after the native reading was taken.
  final _methodChannel = _Channel();
  final _calculatorPinEntry = _PinEntry();
  final _splitTunnelRoutesController = _Text();
  final _accountController = _Text();
  bool _pinUpgradeAvailable = false;
  bool _recoveryCodeMissing = false;
  bool _duressSetupAvailable = false;
  bool _launcherUnlocked = false;
  bool _showDecoyCalculator = false;
  bool _supportsInAppCamouflage = false;
  int _selectedLocationIndex = 0;
  Map<String, dynamic>? _unlistedSelection;
  DateTime? _liveListingReceivedAt;
  // The one live /nodes refresh a connect to an unlisted choice runs. A
  // non-null listing is a live listing that is applied through the
  // production re-bind; null is a refresh that failed.
  // decoy_cover.dart needs a widget tree; decoy_cover_test executes it.
  int decoyClears = 0;
  void _clearProductSurfacesForDecoy() => decoyClears++;
  // The onboarding restore offers a lost recovery code where no decoy shows
  // (decoy_continuation_test executes it).
  int pendingRecoveryOffers = 0;
  Future<void> _showPendingRecoveryCode() async => pendingRecoveryOffers++;
  List<Map<String, dynamic>>? liveListing;
  int nodeFetches = 0;
  // Holds the walk open: a slow or blocked discovery.
  Completer<void>? fetchGate;
  Future<bool> _fetchAvailableNodes({bool forceLive = false}) async {
    nodeFetches++;
    await Future<void>.delayed(Duration.zero);
    if (fetchGate != null) await fetchGate!.future;
    final listing = liveListing;
    if (listing == null) return false;
    final intended = _currentSelectedSlug();
    _locations = listing;
    _liveListingReceivedAt = DateTime.now();
    _rebindSelection(intended);
    // _parseNodesResponse runs this after every live listing.
    _runPendingSettingsRestart();
    return true;
  }
  void chooseUnlisted(String slug, String name) {
    _automaticNodeSelection = false;
    _selectedLocationIndex = kUnlistedSelectionIndex;
    _unlistedSelection = <String, dynamic>{'slug': slug, 'name': name};
  }
  bool _automaticNodeSelection = true;
  bool _isCensorshipModeActive = false;
  bool _isDoubleVpnRequested = false;
  bool _isStealthTransportOnly = false;
  String _transportMode = 'auto';
  bool _alwaysOnEnabled = false;
  bool _diagnosticsEnabled = true;
  String _userSelectedProtocolVersion = '';
  final Set<String> _excludedVpnPackages = <String>{};
  final Set<String> _excludedVpnCidrs = <String>{};
  bool _isFreeAccessSession = false;
  bool _accountExpiredTerminal = false;
  String _activeProtocolLabel = 'Winn';
  String _activeProtocolVersion = '';
  final String _defaultProtocolLabel = 'Winn';
  int _announcementSeqFloor = 0;
  String _serverAnnouncement = '';
  DiscoveryIntakeState _discoveryState = const DiscoveryIntakeState();
  final _discoveryOperations = _DiscoveryOperationsStub();
  String _expirationDate = '';
  String _referralCode = '';
  String _referralLink = '';
  String _referralBackupLink = '';
  String _legalAcceptedVersion = '';
  String _legalAcceptedHash = '';
  String _androidVpnServiceDisclosureConsentVersion = '';
  String _androidVpnServiceDisclosureAcceptedAtUtc = '';
  String _androidPackageVisibilityConsentVersion = '';
  final List<String> debugLog = <String>[];
  Map<String, dynamic> settings = <String, dynamic>{};
  Completer<void>? settingsGate;
  Completer<void>? activationGate;
  bool settingsRead = false;
  bool activationStarted = false;

  void _debugLog(String message) => debugLog.add(message);
  Future<String?> _readSensitiveText(String name) async => 'credential';
  Future<bool> _camouflageLatched() async => false;
  Future<Map<String, dynamic>> _readVpnRuntimeSettings() async {
    settingsRead = true;
    if (settingsGate != null) await settingsGate!.future;
    return settings;
  }
  String _normalizeProtocolLabel(dynamic value) =>
      (value ?? 'Winn').toString();
  Future<String> _restoreAnnouncementForDisplay(
          Map<String, dynamic> settingsData) async =>
      '';
  String _localizedAnnouncement(String value) => value;
  Future<void> _applyDiscoveredEndpointsToSweep() async {}
  Future<void> _loadCachedVpnConfigFromDisk() async {}
  Future<bool> _activationCompleteOrMigrateLegacy(
      String? storedPinCredential, Map<String, dynamic> settingsData) async {
    activationStarted = true;
    if (activationGate != null) await activationGate!.future;
    return true;
  }
  Future<void> _latchCamouflage() async {}
  Future<void> _setLauncherCamouflage({required bool enabled}) async {}

  // Settings-restart dependencies.
  bool stopResult = true;
  int stops = 0;
  int connects = 0;
  final List<String> feedback = <String>[];
  void _showFeedback(String message) => feedback.add(message);
  // A held stop completes only when the scenario says so.
  Completer<bool>? heldStop;
  bool holdNextStop = false;
  Future<bool> _stopNativeTunnel({bool keepVpnLauncher = false}) {
    stops++;
    if (holdNextStop) {
      holdNextStop = false;
      heldStop = Completer<bool>();
      return heldStop!.future;
    }
    return Future<bool>.value(stopResult);
  }
  Future<bool> _cancelAndStopNativeTunnel(
          {bool keepVpnLauncher = false,
          bool releaseKillSwitchBlock = false}) =>
      _stopNativeTunnel(keepVpnLauncher: keepVpnLauncher);

  // Connect-stub controls (the stub itself is _connectStub below).
  String preparation = 'release';
  Completer<void>? prepareGate;
  bool prepareStarted = false;

  // Production smart-connect dependencies, controllable per scenario.
  final _tunnelTransitionGate = TunnelTransitionGate();
  bool _desktopNetworkBlockMayBeLatched = true;
  Map<String, dynamic> _cachedVpnConfig = <String, dynamic>{
    'node_slug': 'france',
  };
  bool _winn3CoverFallbackInProgress = false;
  final Set<String> _winn3CoverFallbackTriedSlugs = <String>{};
  String _winn3SelectionGeneration = '';
  bool _winn3OrdinaryConnectivityAuthorized = false;
  String? _winn3CoverExactTargetSlug;
  String _winn3CoverFailedNode = '';
  int? _winn3CoverAuthorizationToken;
  int _winn3CoverStartGeneration = 0;
  bool _hasCurrentAndroidVpnServiceDisclosureConsent = true;
  bool _lastAppleTunnelNeedsPermissionApproval = false;
  bool _androidNeedsVpnPermission = false;
  Object? _lastAppleInternetProbeFailure;
  Object? _lastAppleConnectedReadinessSnapshot;
  bool _lastConfigRefreshHadLiveNodeListing = false;
  bool _lastTunnelCandidateWasSecurityRefusal = false;
  final _hubCancellations = _HubCancellationsStub();
  Winn3NativeVerdict _lastWinn3NativeVerdict = Winn3NativeVerdict.pending;
  Winn3FailureShape _lastWinn3FailureShape = Winn3FailureShape.unclassified;
  bool _forceXrayForDiagnostics = false;
  bool _doubleVpnAvailable = true;
  final int _maximumTcpFallbackCandidates = 4;
  final List<String> diagnostics = <String>[];
  Completer<void>? diagnosticGate;
  String diagnosticGateReason = '';
  Completer<bool>? failoverStopGate;
  int failoverStopGateAt = 1;
  int failoverStops = 0;
  bool failoverStopResult = false;
  Completer<void>? keyGate;
  bool keyThrows = false;
  int candidateStarts = 0;

  void _cancelSpeedTest() {}
  Completer<Map<dynamic, dynamic>?>? readinessGate;
  Future<Map<dynamic, dynamic>?> _latestTunnelReadiness() {
    final gate = readinessGate;
    readinessGate = null;
    return gate?.future ??
        Future<Map<dynamic, dynamic>?>.value(<dynamic, dynamic>{});
  }
  void _rememberWinn3OrdinaryAuthorization(int? startToken) {}
  Future<bool> _probeVpnInternet() async => false;
  int _readinessInt(Map<dynamic, dynamic> readiness, String key) => 0;
  Future<bool> _waitForTunnelState(bool expected,
          {int attempts = 15, Duration delay = const Duration(seconds: 1)}) async =>
      false;
  String _newWinn3SelectionGeneration() => 'generation';
  Future<bool> _blockIfUpdateRequired() async => false;
  Future<String> _currentAccountNumberForRefresh() async => 'acct';
  Future<Object?> _ensureLegalAcceptanceForActivation(String account) async =>
      Object();
  // Off by default: every older scenario keeps its fixed France cache.
  bool fastConnectFromCache = false;
  Map<String, dynamic>? _cachedDirectConfigForFastConnect() =>
      fastConnectFromCache
          ? Map<String, dynamic>.from(_cachedVpnConfig)
          : <String, dynamic>{'node_slug': 'france'};
  bool _boolValue(Object? value) => value == true;
  bool _boolDefaultTrue(Object? value) => value != false;
  // What a direct (non-stealth) hub refresh serves, and whether it answers.
  Map<String, dynamic>? hubServes;
  bool hubAnswers = true;
  int directRefreshes = 0;
  Future<bool> _refreshVpnConfigForCurrentSelection({
    required bool stealthMode,
    bool Function()? shouldCancel,
    String? requestedLocation,
    void Function(Map<String, dynamic>, Map<String, dynamic>)? onPrepared,
    bool? doubleVpnRoute,
  }) async {
    if (stealthMode) return true;
    directRefreshes++;
    if (!hubAnswers) return false;
    final served = hubServes;
    if (served != null) _cachedVpnConfig = Map<String, dynamic>.from(served);
    return true;
  }
  final List<String> persisted = <String>[];
  Future<void> _persistVpnConfigBestEffort(
      Map<String, dynamic> config, String reason) async {
    persisted.add(reason);
  }
  bool _winn3FreshConfigRetryInProgress = false;
  DateTime? _winn3RelaySuppressedUntil;
  bool _winn3RelayRetryInProgress = false;
  Map<String, dynamic>? _protocolListingNodeForConfig(
          Map<String, dynamic>? config) =>
      null;
  String _capacityAwareConnectFailureMessage(String message) => message;
  Map<String, dynamic> _configForTransport(
    Map<String, dynamic> config, {
    required bool stealthMode,
    String? xrayHost,
    int? xrayPort,
    String? xraySecurity,
  }) =>
      Map<String, dynamic>.from(config);
  Future<String> _effectiveAccountScopeForKeyPair() async => 'scope';
  bool keyRequested = false;
  Future<Object?> _loadExistingClientKeyPair(String scope) async {
    keyRequested = true;
    if (keyGate != null) await keyGate!.future;
    if (keyThrows) throw StateError('client key preflight failed');
    return Object();
  }
  bool _configMatchesLocalClientKeys(
          Map<String, dynamic>? config, Object keys) =>
      true;
  Future<Object?> _loadExistingWinn3KeyPair(String scope) async => null;
  bool winn3ConfigKeyUsable(Map<String, dynamic>? config, Object? local,
          {bool freshFromHub = false}) =>
      true;
  bool _hasUsableVpnConfig(Map<String, dynamic>? config) => config != null;
  Future<void> _applyAccountSyncData(
      Map<String, dynamic> data, int expectedEpoch) async {}
  void _applySelectedNodeFromAuth(Map<String, dynamic> data,
      {bool freeAccess = false}) {}
  Future<String> _directUdpNetworkScope() async => 'network';
  Future<bool> _startTunnelCandidate(
    Map<String, dynamic> config,
    String protocolLabel, {
    bool requireConnectivityProof = true,
    int? readinessAttempts,
    required int transitionGeneration,
    bool Function()? shouldCancel,
    Future<bool> Function()? beforeTunnelStart,
    bool? awaitNativeDoubleVpnSingleHop,
    Stopwatch? nativeStartSpacingClock,
  }) async {
    candidateStarts++;
    startedPathMtus.add('${config['winn3_path_mtu']}');
    final working = gatewayPathMtu;
    if (working == null) return false;
    if (config['winn3_path_mtu'] == working) return true;
    // The engine's ErrPathMTUMismatch reaches Dart as this typed terminal.
    _lastTunnelCandidateWasSecurityRefusal = true;
    _lastWinn3FailureShape = Winn3FailureShape.unconfirmedTerminal;
    return false;
  }
  // When set, a start carries only at this path MTU; any other is refused.
  String? gatewayPathMtu;
  final List<String> startedPathMtus = <String>[];
  Future<void> _recordDirectUdpOutcome(
      {required String scope, required bool reachable}) async {}
  void _refreshAnnouncementsAfterConnectInBackground() {}
  String _displayNodeName(Object? value) => (value ?? '').toString();
  Future<void> _persistTunnelFailureDiagnostic(
      Object protocolLabel, Object reason) async {
    diagnostics.add('$reason');
    if (diagnosticGate != null && '$reason' == diagnosticGateReason) {
      await diagnosticGate!.future;
    }
  }
  Future<bool> _stopNativeTunnelForFailover() {
    failoverStops++;
    if (failoverStopGate != null && failoverStops == failoverStopGateAt) {
      return failoverStopGate!.future;
    }
    return Future<bool>.value(failoverStops < failoverStopGateAt
        ? true
        : failoverStopResult);
  }
  List<String> _xrayHostCandidates(Map<String, dynamic> config) =>
      <String>['cdn.example'];
  Future<List<_XrayOption>> _reachableTcpFallbackOptions(
          Map<String, dynamic> config, List<String> hosts) async =>
      <_XrayOption>[const _XrayOption('cdn.example', 443, 'tls')];
  List<_XrayOption> _windowsBlindTcpFallbackOptions(
          Map<String, dynamic> config) =>
      const <_XrayOption>[];

  // The Double VPN choice is never being saved in these scenarios; the guard
  // itself runs in double_vpn_preference_runtime_test.dart. The marker and the
  // service's copy of the choice are exercised in
  // tunnel_display_restore_production_test.dart and
  // double_vpn_preference_runtime_test.dart; here they only have to compile.
  bool _refuseConnectWhileDoubleVpnSaving() => false;
  bool _doubleVpnPreferenceChanging = false;
  int _doubleVpnPreferenceRevision = 0;
  bool? _committedDoubleVpnSingleHop;
  Future<bool> _writeDoubleVpnIntentRecord(bool requested) async => true;
  // FAST-CONNECT: the harness host is never Android, so no connect here is
  // fast-connect eligible; these only have to compile. The state machine
  // runs in double_vpn_fast_connect_test.dart.
  DoubleVpnUpgradePhase _doubleVpnUpgradePhase = DoubleVpnUpgradePhase.none;
  int doubleVpnUpgradeCancels = 0;
  void _cancelDoubleVpnUpgrade() => doubleVpnUpgradeCancels++;
  void _armDoubleVpnUpgrade(Map<String, dynamic> singleHopConfig,
      {Duration initialDelay = Duration.zero}) {}
  Future<DoubleVpnDirectRaceOutcome> _attemptDoubleVpnRouteWithinBudget({
    required bool Function() shouldCancel,
    required void Function(Map<String, dynamic>, Map<String, dynamic>)
        onPrepared,
  }) async =>
      DoubleVpnDirectRaceOutcome.timedOut;
  Future<void> _restoreSingleHopAfterDoubleVpnHandover(
    DoubleVpnUpgradeAttempt attempt, {
    required int transitionGeneration,
    required bool Function() shouldCancel,
    required void Function(String message) failConnect,
  }) async {}

  // Toggle and switch dependencies.
  int _vpnUiOperationEpoch = 0;
  bool _isVpnConnectInFlight = false;
  bool _appUpdateRequired = false;
  bool _isUnderMaintenance = false;
  // Round A3: the held Winn v3 session's lifecycle and Disconnect latch.
  final _HeldLifecycle _winn3HostLifecycle = _HeldLifecycle();
  bool _winn3HeldDisconnectPending = false;
  String? _winn3IngestRouterV4;
  String _lastAppleTunnelFailureStatus = '';
  Future<void> _promptAppUpdateRequired() async {}
  int _indexForNodeSlug(String? slug) {
    final index = _locations.indexWhere((node) => node['slug'] == slug);
    return index < 0 ? 0 : index;
  }
  List<Map<String, dynamic>> _sortedNodeItems(
          Iterable<Map<String, dynamic>> nodes) =>
      nodes.toList();

  // Expiry dependency: the inactivity proof can be held.
  Completer<bool>? heldProof;
  Future<bool> _stopAndProveTunnelInactive() {
    heldProof = Completer<bool>();
    return heldProof!.future;
  }

  // A direct _connectWithSmartProtocol() commit (the Apple live-tunnel smoke
  // path): the transition gate advances and B commits, while the UI
  // operation epoch does not change.
  void directCommit(String slug) {
    final uiEpoch = _vpnUiOperationEpoch;
    _tunnelTransitionGate.begin();
    commitTunnel(slug);
    nativeActive = true;
    check(_vpnUiOperationEpoch == uiEpoch,
        'model error: a direct commit must not advance the UI epoch');
  }

  int get _displayEpoch => _accountSessionEpoch.current;

  // Mirrors the production commit in _startTunnelCandidate.
  void commitTunnel(String slug) {
    _isConnected = true;
    _activeProtocolLabel = 'Winn Protocol';
    _activeProtocolVersion = 'winn/3';
    _isCensorshipModeActive = false;
    _tunnelDisplayLedger.commit(
      servedIdentity: slug,
      callerIdentity: slug,
      coverFallbackInProgress: false,
      accountEpoch: _displayEpoch,
      locations: _locations,
    );
    _ipAfterVpn = 'Traffic Secured & Obfuscated';
  }

  // Mirrors _switchConnectedServer: confirmed cutover, replacement commit,
  // settled flags.
  void cutoverAndCommit(String slug) {
    final retained = _tunnelDisplayLedger.generation;
    _isConnected = false;
    _tunnelDisplayLedger.endSession(observedGeneration: retained);
    commitTunnel(slug);
    _isLoading = false;
    _isTunnelTransitioning = false;
  }

  // Mirrors the toggle's confirmed disconnect.
  void disconnect() {
    final wasConnected = _isConnected;
    _isConnected = false;
    _tunnelDisplayLedger.settle(
        wasConnected: wasConnected, isConnected: _isConnected);
    _ipAfterVpn = 'Disconnected';
  }

  String? recordSlug() =>
      _tunnelDisplayLedger.recordFor(accountEpoch: _displayEpoch)?.slug;

  DashboardNodeDisplay display() => dashboardNodeForDisplay(
        locations: _locations,
        selectedIndex: 0,
        rendersConnected: _isConnected &&
            !_isVpnConnectInFlight &&
            !_isTunnelTransitioning,
        ledger: _tunnelDisplayLedger,
        accountEpoch: _displayEpoch,
      );

  void checkSecuredOn(String slug, String message) {
    final shown = display();
    check(_isConnected, '$message: connected state was flipped');
    check(recordSlug() == slug, '$message: record is ${recordSlug()}');
    check(
        shown.source == DashboardNodeSource.committedTunnel &&
            shown.node?['slug'] == slug,
        '$message: card shows ${shown.source} ${shown.node}');
  }

  void checkSecuredUnknown(String message) {
    final shown = display();
    check(_isConnected, '$message: not connected');
    check(recordSlug() == null, '$message: record is ${recordSlug()}');
    check(shown.source == DashboardNodeSource.unknownTunnel,
        '$message: card shows ${shown.source} ${shown.node}');
  }
''';

// The controllable connect used by every scenario except smart_connect_*.
const _connectStub = r'''
  Future<void> _connectWithSmartProtocol({
    Future<bool> Function()? beforeTunnelStart,
  }) async {
    connects++;
    if (beforeTunnelStart == null) return;
    prepareStarted = true;
    if (prepareGate != null) await prepareGate!.future;
    if (preparation == 'fail') return;
    await beforeTunnelStart();
  }
''';

const _harnessAfter = r'''
}

Future<void> settle() async {
  for (var i = 0; i < 20; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

Future<void> staleFalseThenFreshTrue(
  Harness h,
  Future<void> Function() observe, {
  required String label,
  bool checkBetweenCompletions = true,
}) async {
  h.commitTunnel('france');
  // 1. An old reading captures A's generation and waits on native.
  h.holdReads = 1;
  final old = observe();
  await settle();
  check(h.heldReads.length == 1, '$label: old reading was not held');
  // 2. A cutover happens, B commits, and its flags settle.
  h.cutoverAndCommit('germany');
  h.checkSecuredOn('germany', '$label: B commit');
  // 3. The old reading returns false (A is gone). It must be dropped.
  h.heldReads.single.complete(false);
  await old;
  await settle();
  if (checkBetweenCompletions) {
    h.checkSecuredOn('germany', '$label: after the obsolete false');
    check(h._ipAfterVpn == 'Traffic Secured & Obfuscated',
        '$label: obsolete false rewrote the status label to ${h._ipAfterVpn}');
  }
  // 4-5. A fresh reading of B's generation finds B active.
  h.nativeActive = true;
  await observe();
  await settle();
  h.checkSecuredOn('germany', '$label: after the fresh true');
  // Round UN: B was committed here, never adopted; nothing asks to restore.
  check(h.restoreSchedules == 0,
      '$label: a committed session asked for a restore');
}

Future<void> currentDeathThenAdoption(
  Harness h,
  Future<void> Function() observe, {
  required String label,
}) async {
  h.commitTunnel('france');
  // A current-generation death still disconnects and clears the record.
  h.holdReads = 1;
  final death = observe();
  await settle();
  h.heldReads.single.complete(false);
  await death;
  await settle();
  check(!h._isConnected, '$label: current-session death was not detected');
  check(h.recordSlug() == null, '$label: death kept the record');
  check(h.restoreSchedules == 0, '$label: a death asked for a restore');
  // A later identity-free adoption stays unknown until a verified persisted
  // record names it (Round UN): the adoption asks for that restore once.
  h.nativeActive = true;
  await observe();
  await settle();
  h.checkSecuredUnknown('$label: adoption after death');
  check(h.restoreSchedules == 1,
      '$label: adoption asked for ${h.restoreSchedules} restores');
}

void checkRestoreCompleted(Harness h, String label) {
  check(
      !h.debugLog.any((line) => line.contains('restore failed')),
      '$label: restore threw: ${h.debugLog}');
  check(onboardingDecisions == 1,
      '$label: the onboarding-layer decision did not run');
}

// A commit lands after restore took its native reading (false), at the
// awaited step [pause]; restore then resumes.
Future<void> restoreWithCommitDuring(Harness h, String pause) async {
  h._isConnected = false;
  h.nativeActive = false;
  final gate = Completer<void>();
  if (pause == 'settings') {
    h.settingsGate = gate;
    h.settings = <String, dynamic>{
      'active_protocol_label': 'Persisted label',
      'active_protocol_version': 'winn/1',
      'stealth_active': true,
      'free_access_session': true,
    };
  } else {
    h.activationGate = gate;
  }
  final restore = h._determineSecurityOnboardingLayer();
  await settle();
  check(h.nativeReads == 1, 'restore did not take its native reading');
  check(pause == 'settings' ? h.settingsRead : h.activationStarted,
      'restore did not reach the $pause await');
  // The browser bridge's connect commits B meanwhile.
  h.commitTunnel('germany');
  h.nativeActive = true;
  gate.complete();
  await restore;
  await settle();
  checkRestoreCompleted(h, 'restore ($pause)');
  h.checkSecuredOn('germany', 'restore ($pause) resumed after B committed');
  check(h._activeProtocolLabel == 'Winn Protocol' &&
          h._activeProtocolVersion == 'winn/3' &&
          !h._isCensorshipModeActive,
      'restore ($pause) overwrote B session fields: '
      '${h._activeProtocolLabel} ${h._activeProtocolVersion} '
      '${h._isCensorshipModeActive}');
  check(h._isLoggedIn, 'restore ($pause) left the connected app logged out');
  // A fresh reconciliation of B's generation must not end B either.
  await h._reconcileNativeTunnelState();
  await settle();
  h.checkSecuredOn('germany', 'restore ($pause) then fresh reconciliation');
}

void checkRestartSettled(Harness h, String label) {
  check(h.stops == 1 && h.connects == 0,
      '$label: a failed stop must not start a replacement');
  check(!h._isLoading, '$label: restart did not clear its loading flag');
  check(h.feedback.isNotEmpty, '$label: stop failure was not reported');
}

// A direct smart connect A (no switch) reaches the failure branch a scenario
// holds; B commits under a newer transition with the UI epoch unchanged; the
// obsolete step is released. B must keep everything, then survive a fresh
// reconciliation.
Future<void> staleSmartConnect(
  Harness h,
  String label, {
  required bool Function() pending,
  required void Function() release,
}) async {
  h._isConnected = false;
  final attempt = h._connectWithSmartProtocol();
  await settle();
  check(pending(), '$label: the failure step was not held');
  final uiEpoch = h._vpnUiOperationEpoch;
  h.directCommit('spain');
  release();
  await attempt;
  await settle();
  check(h._vpnUiOperationEpoch == uiEpoch, '$label: UI epoch moved');
  h.checkSecuredOn('spain', '$label: after the obsolete failure');
  check(h._ipAfterVpn == 'Traffic Secured & Obfuscated',
      '$label: obsolete failure rewrote B label to ${h._ipAfterVpn}');
  check(h._activeProtocolLabel == 'Winn Protocol' &&
          h._activeProtocolVersion == 'winn/3',
      '$label: obsolete failure reset B protocol fields');
  check(h.feedback.isEmpty, '$label: obsolete failure reported ${h.feedback}');
  await h._reconcileNativeTunnelState();
  await settle();
  h.checkSecuredOn('spain', '$label: then fresh reconciliation');
}

void checkUiSettled(Harness h, String label, int uiEpoch) {
  check(!h._isLoading && !h._isVpnConnectInFlight && !h._isTunnelTransitioning,
      '$label: the operation did not settle its own UI flags '
      '(loading=${h._isLoading} inFlight=${h._isVpnConnectInFlight} '
      'transitioning=${h._isTunnelTransitioning})');
  check(h._vpnUiOperationEpoch == uiEpoch,
      '$label: UI epoch moved unexpectedly');
}

// B commits (direct connect, UI epoch unchanged) while [operation]'s native
// observation is outstanding; the obsolete result is then released, and a
// fresh reconciliation follows. B must keep its connection and identity.
Future<void> staleOperationKeepsB(
  Harness h,
  String label,
  Future<void> Function() operation,
  void Function() release, {
  required bool Function() observationPending,
}) async {
  h.commitTunnel('france');
  final pending = operation();
  await settle();
  check(observationPending(), '$label: observation was not held');
  final uiEpoch = h._vpnUiOperationEpoch;
  h.directCommit('spain');
  release();
  await pending;
  await settle();
  checkUiSettled(h, label, uiEpoch);
  h.checkSecuredOn('spain', '$label: after the obsolete result');
  check(h._ipAfterVpn != 'Disconnected',
      '$label: obsolete result rewrote the status label');
  check(h._activeProtocolVersion == 'winn/3',
      '$label: obsolete result reset B protocol fields');
  await h._reconcileNativeTunnelState();
  await settle();
  h.checkSecuredOn('spain', '$label: then fresh reconciliation');
}

// The 2026-09-26 Chicago case: an explicit-node cache planned at 1450 while
// the gateway was moved to 1400. The production smart connect must spend one
// hub refresh after the terminal failure and retry only on a changed plan,
// never loop, and leave the failed cache stale but usable offline.
Future<void> staleCachedPlan(Harness h, String scenario) async {
  const stamp = 1758895200000;
  Map<String, dynamic> served(String mtu, {bool stamped = true}) =>
      <String, dynamic>{
        'node_slug': 'france',
        'winn3_path_mtu': mtu,
        if (stamped) kVpnConfigFetchedAtKey: stamp,
      };
  h._isConnected = false;
  h.fastConnectFromCache = true;
  h.failoverStopResult = true;
  h._cachedVpnConfig = served('1450');
  h.gatewayPathMtu = '1400';
  h.hubServes = served('1400');
  switch (scenario) {
    case 'smart_connect_terminal_unchanged_plan_fails_once':
      h.gatewayPathMtu = '1300';
      h.hubServes = served('1450');
    case 'smart_connect_terminal_hub_unreachable_keeps_cache':
      h.hubAnswers = false;
    case 'smart_connect_terminal_retry_fails_again_no_loop':
      h.gatewayPathMtu = '1300';
    case 'smart_connect_terminal_fresh_hub_config_no_retry':
      cacheIsFresh = false;
      h.gatewayPathMtu = '1300';
  }
  await h._connectWithSmartProtocol();
  await settle();
  final failed = h.feedback
      .where((line) => line.contains('could not be established'))
      .length;
  check(!h._winn3FreshConfigRetryInProgress,
      '$scenario: the retry latch was left set');
  switch (scenario) {
    case 'smart_connect_terminal_changed_plan_retries_once':
      check(h.directRefreshes == 1,
          'changed plan: expected one hub refresh, got ${h.directRefreshes}');
      check(h.startedPathMtus.join(',') == '1450,1400',
          'changed plan: starts were ${h.startedPathMtus}');
      check(h.failoverStops == 1,
          'changed plan: the failed start was not stopped before the retry');
      check(failed == 0 && h.feedback.isEmpty,
          'changed plan: the retry that carried reported ${h.feedback}');
      check(h._cachedVpnConfig[kVpnConfigFetchedAtKey] == stamp,
          'changed plan: the fresh config lost its fetch stamp');
    case 'smart_connect_terminal_unchanged_plan_fails_once':
      check(h.directRefreshes == 1,
          'unchanged plan: expected one hub refresh, got ${h.directRefreshes}');
      check(h.startedPathMtus.join(',') == '1450',
          'unchanged plan: a same-plan retry ran: ${h.startedPathMtus}');
      check(failed == 1, 'unchanged plan: failure not reported once');
      check(!h._cachedVpnConfig.containsKey(kVpnConfigFetchedAtKey),
          'unchanged plan: the failed cache was not marked stale');
      check(h.persisted.contains('winn3_terminal_failure_stale'),
          'unchanged plan: the stale mark was not persisted');
    case 'smart_connect_terminal_hub_unreachable_keeps_cache':
      check(h.directRefreshes == 1,
          'hub unreachable: expected one hub attempt, got ${h.directRefreshes}');
      check(h.startedPathMtus.join(',') == '1450',
          'hub unreachable: retried without a fresh plan');
      check(failed == 1, 'hub unreachable: failure not reported once');
      check(h._cachedVpnConfig['winn3_path_mtu'] == '1450' &&
              !h._cachedVpnConfig.containsKey(kVpnConfigFetchedAtKey),
          'hub unreachable: the cache must stay usable, only stale: '
          '${h._cachedVpnConfig}');
      check(h.persisted.contains('winn3_terminal_failure_stale'),
          'hub unreachable: the stale mark was not persisted');
    case 'smart_connect_terminal_retry_fails_again_no_loop':
      check(h.directRefreshes == 1,
          'no loop: the retry refreshed again (${h.directRefreshes})');
      check(h.startedPathMtus.join(',') == '1450,1400',
          'no loop: starts were ${h.startedPathMtus}');
      check(failed == 1, 'no loop: expected one failure report, got $failed');
      check(!h._cachedVpnConfig.containsKey(kVpnConfigFetchedAtKey),
          'no loop: the second failure did not mark the cache stale');
    case 'smart_connect_terminal_fresh_hub_config_no_retry':
      check(h.directRefreshes == 1,
          'fresh hub config: only the leading refresh may run, got '
          '${h.directRefreshes}');
      check(h.startedPathMtus.join(',') == '1400',
          'fresh hub config: starts were ${h.startedPathMtus}');
      check(failed == 1, 'fresh hub config: failure not reported once');
      check(!h._cachedVpnConfig.containsKey(kVpnConfigFetchedAtKey),
          'fresh hub config: the failed config was not marked stale');
  }
}

Future<void> main(List<String> arguments) async {
  final scenario = arguments.single;
  final h = Harness();
  switch (scenario) {
    case 'network_label_stale_http_response':
      // Disconnected, no record; the label refresh's request is held.
      h._isConnected = false;
      h._ipAfterVpn = 'Disconnected';
      h.nativeActive = false;
      await h._fetchLiveNetworkIp();
      await settle();
      check(!httpRequested, 'a public-IP request was issued');
      h.directCommit('spain');
      await settle();
      h.checkSecuredOn('spain', 'network label: after the refresh');
      check(h._ipAfterVpn == 'Traffic Secured & Obfuscated',
          'delayed public-IP response rewrote B label to ${h._ipAfterVpn}');
      await h._reconcileNativeTunnelState();
      await settle();
      h.checkSecuredOn('spain', 'network label: then fresh reconciliation');
    case 'network_label_current_http_disconnected':
      h._isConnected = false;
      h._ipAfterVpn = 'Traffic Secured & Obfuscated';
      h.nativeActive = false;
      await h._fetchLiveNetworkIp();
      await settle();
      check(!httpRequested, 'a public-IP request was issued');
      check(h._ipAfterVpn == 'Disconnected',
          'current disconnected response was not applied');
    case 'network_label_current_http_after_own_settlement':
      // Apple: the method itself ends the dead session, then its own
      // response must still apply.
      h._isApplePlatform = true;
      h.commitTunnel('france');
      h.nativeActive = false;
      await h._fetchLiveNetworkIp();
      await settle();
      check(!h._isConnected && h.recordSlug() == null,
          'own disconnect settlement did not run');
      check(!httpRequested, 'a public-IP request was issued');
      check(h._ipAfterVpn == 'Disconnected',
          'response after the own settlement was dropped');
    case 'smart_connect_stale_failover_stop_before_tcp':
      h.failoverStopGate = Completer<bool>();
      await staleSmartConnect(h, 'failover stop before TCP',
          pending: () => h.failoverStops == 1,
          release: () => h.failoverStopGate!.complete(false));
    case 'smart_connect_stale_diagnostic_before_tcp':
      h.failoverStopResult = false;
      h.diagnosticGate = Completer<void>();
      h.diagnosticGateReason = 'failover_stop_settlement_failed_before_tcp';
      await staleSmartConnect(h, 'diagnostic before TCP',
          pending: () => h.diagnostics.contains(h.diagnosticGateReason),
          release: () => h.diagnosticGate!.complete());
    case 'smart_connect_stale_failover_stop_before_cover':
      smartRoute = 'cover';
      h.failoverStopGate = Completer<bool>();
      await staleSmartConnect(h, 'failover stop before cover',
          pending: () => h.failoverStops == 1,
          release: () => h.failoverStopGate!.complete(false));
    case 'smart_connect_stale_failover_stop_after_tcp_candidate':
      // The stop before TCP succeeds; the stop after the failed TCP
      // candidate is held.
      h.failoverStopGateAt = 2;
      h.failoverStopGate = Completer<bool>();
      await staleSmartConnect(h, 'failover stop after TCP candidate',
          pending: () => h.failoverStops == 2 && h.candidateStarts == 2,
          release: () => h.failoverStopGate!.complete(false));
    case 'smart_connect_stale_key_preflight_exception':
      h.keyGate = Completer<void>();
      h.keyThrows = true;
      await staleSmartConnect(h, 'key preflight exception',
          pending: () => h.keyRequested && h.failoverStops == 0,
          release: () => h.keyGate!.complete());
    case 'smart_connect_current_failure':
      // No newer owner: the attempt's own failed stop is still a failure.
      h._isConnected = false;
      h.failoverStopResult = false;
      await h._connectWithSmartProtocol();
      await settle();
      check(!h._isConnected && h._ipAfterVpn == 'Disconnected',
          'current-owner failure did not settle the dashboard');
      check(
          h.feedback.any((line) => line.contains('could not be removed safely')),
          'current-owner failure was not reported: ${h.feedback}');
      check(h.diagnostics.contains('failover_stop_settlement_failed_before_tcp'),
          'model error: the pre-TCP failover branch was not reached');
    case 'smart_connect_terminal_changed_plan_retries_once':
    case 'smart_connect_terminal_unchanged_plan_fails_once':
    case 'smart_connect_terminal_hub_unreachable_keeps_cache':
    case 'smart_connect_terminal_retry_fails_again_no_loop':
    case 'smart_connect_terminal_fresh_hub_config_no_retry':
      await staleCachedPlan(h, scenario);
    case 'readiness_wait_stale_label':
    case 'readiness_wait_current_label':
      // Attempt A waits for readiness; its native reading is held.
      final stale = scenario.endsWith('stale_label');
      h.commitTunnel('france');
      final attemptA = h._tunnelTransitionGate.begin();
      final readiness = Completer<Object?>();
      h._methodChannel.held['getTunnelReadiness'] = readiness;
      final waiting = h._waitForTunnelReady(
        attempts: 1,
        shouldCancel: () => !h._tunnelTransitionGate.isCurrent(attemptA),
      );
      await settle();
      if (stale) h.directCommit('spain');
      readiness.complete(<String, dynamic>{'active': false});
      final ready = await waiting;
      await settle();
      check(!ready, 'model error: readiness must not be reported');
      if (stale) {
        h.checkSecuredOn('spain', 'readiness wait: after the obsolete reading');
        check(h._ipAfterVpn == 'Traffic Secured & Obfuscated',
            'obsolete readiness reading rewrote B label to ${h._ipAfterVpn}');
      } else {
        check(h._ipAfterVpn == 'Securing VPN route...',
            'current attempt progress label was not written');
      }
    case 'apple_readiness_wait_stale_failure':
    case 'apple_readiness_wait_current_failure':
      final stale = scenario.contains('stale');
      h._isApplePlatform = true;
      h.commitTunnel('france');
      final attemptA = h._tunnelTransitionGate.begin();
      final readiness = Completer<Map<dynamic, dynamic>?>();
      h.readinessGate = readiness;
      final waiting = h._waitForTunnelReady(
        attempts: 1,
        shouldCancel: () => !h._tunnelTransitionGate.isCurrent(attemptA),
      );
      await settle();
      if (stale) h.directCommit('spain');
      readiness.complete(<dynamic, dynamic>{'status': 'connecting'});
      final ready = await waiting;
      await settle();
      check(!ready, 'model error: readiness must not be reported');
      if (stale) {
        h.checkSecuredOn('spain', 'Apple readiness: after the obsolete reading');
        check(h._ipAfterVpn == 'Traffic Secured & Obfuscated',
            'obsolete Apple reading rewrote B label to ${h._ipAfterVpn}');
        check(h._lastAppleTunnelFailureStatus.isEmpty,
            'obsolete Apple failure status was recorded');
      } else {
        check(h._ipAfterVpn == 'Apple tunnel failed' &&
                h._lastAppleTunnelFailureStatus == 'Apple tunnel failed',
            'current Apple failure was not recorded: ${h._ipAfterVpn}');
      }
    case 'apple_failure_recorder_stale_read':
    case 'apple_failure_recorder_current_read':
      // The production recorder alone, with A's cancellation callback; its
      // own readiness read is the one held.
      final stale = scenario.contains('stale');
      h._isApplePlatform = true;
      h.commitTunnel('france');
      final attemptA = h._tunnelTransitionGate.begin();
      final readiness = Completer<Map<dynamic, dynamic>?>();
      h.readinessGate = readiness;
      final recording = h._recordAppleTunnelFailure(
        'Winn',
        shouldCancel: () => !h._tunnelTransitionGate.isCurrent(attemptA),
      );
      await settle();
      check(h.readinessGate == null, 'recorder did not issue its own read');
      check(h._lastAppleTunnelFailureStatus.isEmpty,
          'recorder wrote before its read completed');
      if (stale) h.directCommit('spain');
      readiness.complete(<dynamic, dynamic>{'status': 'disconnected'});
      await recording;
      await settle();
      if (stale) {
        h.checkSecuredOn('spain', 'Apple recorder: after the obsolete read');
        check(h._ipAfterVpn == 'Traffic Secured & Obfuscated',
            'obsolete Apple failure rewrote B label to ${h._ipAfterVpn}');
        check(h._activeProtocolLabel == 'Winn Protocol' &&
                h._activeProtocolVersion == 'winn/3',
            'obsolete Apple failure reset B protocol fields');
        check(h._lastAppleTunnelFailureStatus.isEmpty,
            'obsolete Apple failure status was recorded: '
            '${h._lastAppleTunnelFailureStatus}');
        check(!h._lastAppleTunnelNeedsPermissionApproval,
            'obsolete Apple permission diagnosis was recorded');
        await h._reconcileNativeTunnelState();
        await settle();
        h.checkSecuredOn('spain', 'Apple recorder: then fresh reconciliation');
      } else {
        check(h._lastAppleTunnelFailureStatus == 'Apple tunnel failed' &&
                h._ipAfterVpn == 'Apple tunnel failed',
            'current Apple failure was not recorded: '
            '${h._lastAppleTunnelFailureStatus} / ${h._ipAfterVpn}');
      }
    case 'tunnel_usable_stale_label':
    case 'tunnel_usable_current_label':
      final stale = scenario.contains('stale');
      h.commitTunnel('france');
      final attemptA = h._tunnelTransitionGate.begin();
      final readiness = Completer<Object?>();
      h._methodChannel.held['getTunnelReadiness'] = readiness;
      final confirming = h._confirmTunnelUsable(
        baselineTunRxBytes: 0,
        baselineTunTxBytes: 0,
        attempts: 1,
        shouldCancel: () => !h._tunnelTransitionGate.isCurrent(attemptA),
      );
      await settle();
      if (stale) h.directCommit('spain');
      readiness.complete(<String, dynamic>{'active': false});
      final usable = await confirming;
      await settle();
      check(!usable, 'model error: usability must not be reported');
      if (stale) {
        h.checkSecuredOn('spain', 'usability probe: after the obsolete reading');
        check(h._ipAfterVpn == 'Traffic Secured & Obfuscated',
            'obsolete usability reading rewrote B label to ${h._ipAfterVpn}');
      } else {
        check(h._ipAfterVpn == 'Finalizing secure route...',
            'current attempt progress label was not written');
      }
    case 'settings_restart_stale_stop_result':
      h.commitTunnel('france');
      h.holdNextStop = true;
      final pending = h._restartTunnelForSettingsChange();
      await settle();
      check(h.heldStop != null, 'restart stop was not held');
      h.directCommit('spain');
      h.heldStop!.complete(true);
      await pending;
      await settle();
      check(!h._isLoading, 'restart did not clear its loading flag');
      check(h.connects == 0, 'restart reconnected over the newer session');
      h.checkSecuredOn('spain', 'restart: after the obsolete stop result');
      await h._reconcileNativeTunnelState();
      await settle();
      h.checkSecuredOn('spain', 'restart: then fresh reconciliation');
    case 'toggle_stale_failed_stop_reading':
      h.stopResult = false;
      h.holdReads = 1;
      await staleOperationKeepsB(
        h,
        'toggle failed stop',
        () => h._toggleVpnConnection(),
        () => h.heldReads.single.complete(false),
        observationPending: () => h.heldReads.length == 1,
      );
    case 'toggle_stale_stop_result':
      h.holdNextStop = true;
      await staleOperationKeepsB(
        h,
        'toggle stop result',
        () => h._toggleVpnConnection(),
        () => h.heldStop!.complete(true),
        observationPending: () => h.heldStop != null,
      );
    case 'toggle_stale_cancel_stop_result':
      // Cancelling an in-flight connect: the toggle's cancel owner stops.
      h._isLoading = true;
      h._isVpnConnectInFlight = true;
      h._isTunnelTransitioning = true;
      h.holdNextStop = true;
      h.commitTunnel('france');
      final pending = h._toggleVpnConnection();
      await settle();
      check(h.heldStop != null, 'cancel stop was not held');
      final uiEpoch = h._vpnUiOperationEpoch;
      h.directCommit('spain');
      h.heldStop!.complete(true);
      await pending;
      await settle();
      checkUiSettled(h, 'toggle cancel', uiEpoch);
      h.checkSecuredOn('spain', 'toggle cancel: after the obsolete result');
      await h._reconcileNativeTunnelState();
      await settle();
      h.checkSecuredOn('spain', 'toggle cancel: then fresh reconciliation');
    case 'toggle_failed_stop_still_active':
      h.commitTunnel('france');
      h.stopResult = false;
      h.nativeActive = true;
      await h._toggleVpnConnection();
      await settle();
      checkUiSettled(h, 'toggle current still active', h._vpnUiOperationEpoch);
      h.checkSecuredOn('france', 'toggle: still-active tunnel keeps its node');
      check(h.feedback.isNotEmpty, 'failed stop was not reported');
    case 'toggle_failed_stop_inactive':
      h.commitTunnel('france');
      h.stopResult = false;
      h.nativeActive = false;
      await h._toggleVpnConnection();
      await settle();
      checkUiSettled(h, 'toggle current inactive', h._vpnUiOperationEpoch);
      check(!h._isConnected && h._ipAfterVpn == 'Disconnected',
          'toggle: a dead tunnel stayed connected');
      check(h.recordSlug() == null, 'toggle: a dead tunnel kept its record');
    case 'toggle_disconnect_current':
      h.commitTunnel('france');
      h.stopResult = true;
      h.nativeActive = false;
      await h._toggleVpnConnection();
      await settle();
      checkUiSettled(h, 'toggle disconnect', h._vpnUiOperationEpoch);
      check(!h._isConnected, 'toggle: disconnect did not disconnect');
      check(h.recordSlug() == null, 'toggle: disconnect kept the record');
      check(h._activeProtocolLabel == 'Winn' && h._activeProtocolVersion == '',
          'toggle: disconnect kept protocol fields');
    case 'toggle_unlisted_fresh_listing_refuses':
    case 'toggle_unlisted_refresh_relists_connects':
    case 'toggle_unlisted_refresh_fails_attempts_exact':
    case 'toggle_unlisted_refresh_fails_recent_listing_refuses':
      // Disconnected, the saved manual choice Canada is not listed.
      h._isConnected = false;
      h.nativeActive = false;
      h.chooseUnlisted('canada', 'Canada');
      final base = <Map<String, dynamic>>[...h._locations];
      switch (scenario) {
        case 'toggle_unlisted_fresh_listing_refuses':
          h.liveListing = base;
        case 'toggle_unlisted_refresh_relists_connects':
          h.liveListing = <Map<String, dynamic>>[
            <String, dynamic>{'slug': 'canada', 'name': 'Canada', 'status': 'online'},
            ...base,
          ];
        case 'toggle_unlisted_refresh_fails_attempts_exact':
          // No live listing ever, or only an old one: not evidence.
          h.liveListing = null;
          h._liveListingReceivedAt =
              DateTime.now().subtract(const Duration(minutes: 30));
        case 'toggle_unlisted_refresh_fails_recent_listing_refuses':
          h.liveListing = null;
          h._liveListingReceivedAt =
              DateTime.now().subtract(const Duration(seconds: 20));
      }
      await h._toggleVpnConnection();
      await settle();
      check(h.nodeFetches == 1, 'connect ran ${h.nodeFetches} refreshes, not one');
      check(!h._isLoading, 'the refresh left the power control loading');
      final refused = scenario.endsWith('refuses');
      if (refused) {
        check(h.connects == 0, 'a fresh omission still connected');
        check(h.feedback.any((m) => m.contains('Canada is not in the server list')),
            'the refusal did not name the server: ${h.feedback}');
        check(h._currentSelectedSlug() == 'canada', 'the refusal moved the choice');
      } else {
        check(h.connects == 1, 'the connect was not attempted');
        check(h._currentSelectedSlug() == 'canada',
            'the connect would request ${h._currentSelectedSlug()}, not Canada');
        check(!h.feedback.any((m) => m.contains('not in the server list')),
            'refused without a fresh omission: ${h.feedback}');
      }
    case 'restart_unlisted_keeps_tunnel':
      h.commitTunnel('france');
      h.chooseUnlisted('canada', 'Canada');
      // A fresh live listing omits Canada.
      h._liveListingReceivedAt = DateTime.now();
      await h._restartTunnelForSettingsChange();
      await settle();
      check(h.stops == 0 && h.connects == 0,
          'a settings restart tore down the carrying tunnel for an unlisted choice');
      check(h._isConnected && h.recordSlug() == 'france',
          'the carrying tunnel was not kept');
      check(h.feedback.any((m) => m.contains('your current connection was kept')),
          'the restart did not say why: ${h.feedback}');
      check(!h._isLoading, 'restart left the UI loading');
    case 'restart_unlisted_stale_defers_then_runs':
      // E3: the listing has not loaded, so an omission is no evidence. The
      // restart waits for the next live listing, then runs.
      h.commitTunnel('france');
      h.chooseUnlisted('canada', 'Canada');
      await h._restartTunnelForSettingsChange();
      await settle();
      check(h.stops == 0 && h.connects == 0, 'deferred restart tore down');
      check(h._settingsRestartPending, 'the restart was not deferred');
      check(h.feedback.any((m) => m.contains('as soon as the server list has loaded')),
          'the deferral was not explained: ${h.feedback}');
      check(!h.feedback.any((m) => m.contains('your current connection was kept')),
          'claimed a closure without a fresh listing');
      h.liveListing = <Map<String, dynamic>>[
        <String, dynamic>{'slug': 'canada', 'name': 'Canada', 'status': 'online'},
        ...h._locations,
      ];
      await h._fetchAvailableNodes();
      await settle();
      check(!h._settingsRestartPending, 'the deferred restart stayed pending');
      check(h.stops == 1 && h.connects == 1,
          'the deferred restart did not run: stops ${h.stops} connects ${h.connects}');
    case 'restart_deferred_retries_after_picker_load':
      // Sol Turn 3: the listing lands while the picker holds _isLoading. The
      // runner must try again once it clears.
      h.commitTunnel('france');
      h.chooseUnlisted('canada', 'Canada');
      await h._restartTunnelForSettingsChange();
      await settle();
      check(h._settingsRestartPending, 'the restart was not deferred');
      h._isLoading = true; // the picker's own discovery
      h.liveListing = <Map<String, dynamic>>[
        <String, dynamic>{'slug': 'canada', 'name': 'Canada', 'status': 'online'},
        ...h._locations,
      ];
      await h._fetchAvailableNodes();
      await settle();
      check(h.stops == 0 && h._settingsRestartPending,
          'the restart ran under the picker, or was dropped');
      h._isLoading = false; // the picker's finally
      await Future<void>.delayed(
          kSettingsRestartRetryInterval + const Duration(milliseconds: 300));
      await settle();
      check(!h._settingsRestartPending, 'the deferred restart stayed pending');
      check(h.stops == 1 && h.connects == 1,
          'the restart never ran after the picker: stops ${h.stops} connects ${h.connects}');
    case 'restart_deferred_dropped_after_reconnect':
    case 'restart_deferred_dropped_after_account_change':
      // N1: the deferred restart belongs to the tunnel it was deferred for.
      h.commitTunnel('france');
      h.chooseUnlisted('canada', 'Canada');
      await h._restartTunnelForSettingsChange();
      await settle();
      check(h._settingsRestartPending, 'the restart was not deferred');
      if (scenario.endsWith('reconnect')) {
        // Disconnect, then a new tunnel built with the new settings.
        h._tunnelDisplayLedger.endSession();
        h.commitTunnel('france');
      } else {
        h._accountSessionEpoch.current++;
      }
      h.liveListing = <Map<String, dynamic>>[
        <String, dynamic>{'slug': 'canada', 'name': 'Canada', 'status': 'online'},
        ...h._locations,
      ];
      await h._fetchAvailableNodes();
      await Future<void>.delayed(
          kSettingsRestartRetryInterval + const Duration(milliseconds: 300));
      await settle();
      check(h.stops == 0 && h.connects == 0,
          'a stale deferred restart tore down the newer tunnel');
      check(!h._settingsRestartPending, 'the stale restart was not dropped');
    case 'toggle_unlisted_wait_keeps_adopted_status':
      // N3: reconciliation adopts a tunnel during the wait; its status line
      // must survive the wait's own cleanup.
      h._isConnected = false;
      h.nativeActive = false;
      h._ipAfterVpn = 'Disconnected';
      h.chooseUnlisted('canada', 'Canada');
      h.fetchGate = Completer<void>();
      final tap = h._toggleVpnConnection();
      await settle();
      check(h._ipAfterVpn == 'Checking the server list...', 'status: ${h._ipAfterVpn}');
      // The production reconciliation adopts the tunnel during the wait. It
      // rewrites only an empty or "disconnected" line, so the checking line
      // is still there when the wait ends.
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      check(h._isConnected, 'precondition: reconciliation did not adopt');
      check(h._ipAfterVpn == 'Checking the server list...',
          'precondition: reconciliation rewrote the checking line');
      h.fetchGate!.complete();
      await tap;
      await settle();
      check(h._ipAfterVpn == 'Traffic Secured & Obfuscated',
          'the wait left "${h._ipAfterVpn}" under an adopted tunnel');
      check(h.connects == 0 && h._isConnected, 'the adopted tunnel was toggled');
    case 'restart_deferred_waits_behind_decoy':
      // T1: backgrounding brings the decoy back with the tunnel up. A listing
      // and the retry interval must neither restart nor say anything.
      h.commitTunnel('france');
      h.chooseUnlisted('canada', 'Canada');
      await h._restartTunnelForSettingsChange();
      await settle();
      check(h._settingsRestartPending, 'the restart was not deferred');
      h._showDecoyCalculator = true;
      h.feedback.clear();
      h.liveListing = <Map<String, dynamic>>[
        <String, dynamic>{'slug': 'canada', 'name': 'Canada', 'status': 'online'},
        ...h._locations,
      ];
      await h._fetchAvailableNodes();
      await Future<void>.delayed(
          kSettingsRestartRetryInterval + const Duration(milliseconds: 300));
      await settle();
      check(h.stops == 0 && h.connects == 0, 'restarted behind the decoy');
      check(h.feedback.isEmpty, 'feedback over the decoy: ${h.feedback}');
      check(h._settingsRestartPending, 'the restart was dropped behind the decoy');
      check(h._settingsRestartRetry == null, 'a retry timer was armed behind the decoy');
      // Behind the decoy with another operation holding _isLoading, the
      // runner must still not arm its retry timer (the decoy wins).
      h._isLoading = true;
      await h._fetchAvailableNodes();
      await settle();
      check(h._settingsRestartRetry == null,
          'a retry timer was armed behind the decoy while loading');
      h._isLoading = false;
      // The PIN unlock (_onCalculatorButtonPressed) clears the decoy and runs
      // the runner; the wiring is pinned in selected_node_rebind_test.
      h._showDecoyCalculator = false;
      h._runPendingSettingsRestart();
      await settle();
      await Future<void>.delayed(
          kSettingsRestartRetryInterval + const Duration(milliseconds: 300));
      await settle();
      check(h.stops == 1 && h.connects == 1,
          'unlock did not run exactly one restart: stops ${h.stops} connects ${h.connects}');
      check(!h._settingsRestartPending, 'still pending after the unlock');
    case 'restart_under_decoy_defers_silently':
      // T1: a settings restart that starts behind the decoy (the 900 ms
      // settings timer) tears nothing down and says nothing.
      h.commitTunnel('france');
      h._showDecoyCalculator = true;
      await h._restartTunnelForSettingsChange();
      await settle();
      check(h.stops == 0 && h.connects == 0, 'restarted behind the decoy');
      check(h.feedback.isEmpty && h._settingsRestartPending,
          'not deferred silently: ${h.feedback}');
      h._showDecoyCalculator = false;
      h._runPendingSettingsRestart();
      await settle();
      check(h.stops == 1 && h.connects == 1, 'the unlock did not apply it');
    case 'toggle_unlisted_refusal_silent_behind_decoy':
      // T1 audit: the connect refusal can complete after the app went to the
      // background; it refuses, silently.
      h._isConnected = false;
      h.nativeActive = false;
      h.chooseUnlisted('canada', 'Canada');
      h.liveListing = <Map<String, dynamic>>[...h._locations];
      h.fetchGate = Completer<void>();
      final tap = h._toggleVpnConnection();
      await settle();
      h._showDecoyCalculator = true;
      h.fetchGate!.complete();
      await tap;
      await settle();
      check(h.connects == 0, 'a fresh omission connected');
      check(h.feedback.isEmpty, 'feedback over the decoy: ${h.feedback}');
    case 'toggle_unlisted_shares_inflight_walk':
      // E1: a walk already running (startup) is awaited, not repeated.
      h._isConnected = false;
      h.nativeActive = false;
      h.chooseUnlisted('canada', 'Canada');
      h.fetchGate = Completer<void>();
      h.liveListing = <Map<String, dynamic>>[
        <String, dynamic>{'slug': 'canada', 'name': 'Canada', 'status': 'online'},
        ...h._locations,
      ];
      final startup = h._sharedNodeDiscovery();
      final tap = h._toggleVpnConnection();
      await settle();
      h.fetchGate!.complete();
      await startup;
      await tap;
      await settle();
      check(h.nodeFetches == 1, 'the connect started a second walk (${h.nodeFetches})');
      check(h.connects == 1 && h._currentSelectedSlug() == 'canada',
          'the connect did not go on to Canada');
    case 'toggle_unlisted_wait_is_bounded':
      // E1: a walk that never ends is waited on for the bound only, and then
      // the exact choice is attempted.
      h._isConnected = false;
      h.nativeActive = false;
      h.chooseUnlisted('canada', 'Canada');
      h.fetchGate = Completer<void>();
      final watch = Stopwatch()..start();
      await h._toggleVpnConnection();
      await settle();
      watch.stop();
      check(watch.elapsed < kUnlistedChoiceRefreshBound + const Duration(seconds: 2),
          'the wait took ${watch.elapsed}');
      check(watch.elapsed >= kUnlistedChoiceRefreshBound - const Duration(milliseconds: 50),
          'did not wait for the walk at all (${watch.elapsed})');
      check(h.connects == 1 && h._currentSelectedSlug() == 'canada',
          'after the bound the exact choice was not attempted');
      h.fetchGate!.complete();
    case 'toggle_unlisted_wait_is_a_connect_and_a_tap_abandons_it':
      // E2: while it waits, the power control reads as a connect in flight,
      // and a second tap abandons it.
      h._isConnected = false;
      h.nativeActive = false;
      h.stopResult = true;
      h.chooseUnlisted('canada', 'Canada');
      h.fetchGate = Completer<void>();
      h.liveListing = <Map<String, dynamic>>[
        <String, dynamic>{'slug': 'canada', 'name': 'Canada', 'status': 'online'},
        ...h._locations,
      ];
      final first = h._toggleVpnConnection();
      await settle();
      check(h._isLoading && h._isVpnConnectInFlight,
          'the wait is not a connect in flight (the watch would say disconnecting)');
      check(h._ipAfterVpn == 'Checking the server list...', 'status: ${h._ipAfterVpn}');
      await h._toggleVpnConnection();
      await settle();
      h.fetchGate!.complete();
      await first;
      await settle();
      check(h.connects == 0, 'an abandoned wait still connected');
      check(!h._isLoading && !h._isVpnConnectInFlight, 'the abandon left flags set');
    case 'toggle_gated_by_maintenance_and_update':
      h.commitTunnel('france');
      h.stopResult = true;
      h.nativeActive = false;
      h._isUnderMaintenance = true;
      h._appUpdateRequired = true;
      // Sol-core-7: the gates exist to stop CONNECTING; an ordinary connected
      // session can still be disconnected under them.
      await h._toggleVpnConnection();
      await settle();
      check(!h._isConnected, 'toggle: the gates blocked an ordinary disconnect');
      final connectsBeforeGatedTap = h.connects;
      await h._toggleVpnConnection();
      await settle();
      check(h.connects == connectsBeforeGatedTap && !h._isConnected,
          'toggle: the gates no longer stop a connect');
    case 'held_disconnect_bypasses_maintenance_and_update':
      h.commitTunnel('france');
      h.stopResult = true;
      h.nativeActive = false;
      h._winn3HostLifecycle.holdsSession = true;
      h._isUnderMaintenance = true;
      h._appUpdateRequired = true;
      await h._disconnectHeldWinn3Session();
      await settle();
      checkUiSettled(h, 'held disconnect', h._vpnUiOperationEpoch);
      check(!h._isConnected, 'held disconnect: blocked by a required update or maintenance');
      check(h.recordSlug() == null, 'held disconnect: kept the record');
      check(!h._winn3HeldDisconnectPending, 'held disconnect: the latch was left set');
      // The latch is one-shot: a later connect is gated again.
      final connectsAfterHeld = h.connects;
      await h._toggleVpnConnection();
      await settle();
      check(h.connects == connectsAfterHeld && !h._isConnected,
          'held disconnect: the latch leaked into a later toggle');
    case 'held_disconnect_never_connects':
      h._isConnected = false;
      final connectsBefore = h.connects;
      await h._disconnectHeldWinn3Session();
      await settle();
      check(h.connects == connectsBefore, 'held disconnect: started a connect');
      check(!h._winn3HeldDisconnectPending, 'held disconnect: latch left set');
    case 'network_label_held_session_untouched':
      h.commitTunnel('france');
      h._winn3HostLifecycle.holdsSession = true;
      h.nativeActive = true;
      h._ipAfterVpn = 'held banner owns the dashboard';
      final before = h._ipBeforeVpn;
      await h._fetchLiveNetworkIp();
      await settle();
      check(h._isConnected, 'label: a held session was disconnected');
      check(h._ipAfterVpn == 'held banner owns the dashboard',
          'label: a held session was given a label (${h._ipAfterVpn})');
      check(h._ipBeforeVpn == before, 'label: a public address was fetched through the hold');
    case 'switch_stale_failed_stop_reading':
      h.stopResult = false;
      h.holdReads = 1;
      await staleOperationKeepsB(
        h,
        'switch failed stop',
        () => h._switchConnectedServer('Germany', targetSlug: 'germany'),
        () => h.heldReads.single.complete(false),
        observationPending: () => h.heldReads.length == 1,
      );
    case 'switch_stale_failed_preparation_reading':
      h.preparation = 'fail';
      h.holdReads = 1;
      await staleOperationKeepsB(
        h,
        'switch failed preparation',
        () => h._switchConnectedServer('Germany', targetSlug: 'germany'),
        () => h.heldReads.single.complete(false),
        observationPending: () => h.heldReads.length == 1,
      );
    case 'switch_stale_cutover_stop_result':
      h.holdNextStop = true;
      await staleOperationKeepsB(
        h,
        'switch cutover',
        () => h._switchConnectedServer('Germany', targetSlug: 'germany'),
        () => h.heldStop!.complete(true),
        observationPending: () => h.heldStop != null,
      );
    case 'switch_failed_stop_still_active':
      h.commitTunnel('france');
      h.stopResult = false;
      h.nativeActive = true;
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      await settle();
      checkUiSettled(h, 'switch current still active', h._vpnUiOperationEpoch);
      h.checkSecuredOn('france', 'switch: still-active tunnel keeps its node');
      check(h._currentSelectedSlug() == 'france', 'switch: selection not restored');
    case 'switch_failed_preparation_native_died':
      h.commitTunnel('france');
      h.preparation = 'fail';
      h.nativeActive = false;
      await h._switchConnectedServer('Germany', targetSlug: 'germany');
      await settle();
      checkUiSettled(h, 'switch current death', h._vpnUiOperationEpoch);
      check(!h._isConnected && h._ipAfterVpn == 'Disconnected',
          'switch: retained tunnel death not applied');
      check(h.recordSlug() == null, 'switch: dead retained tunnel kept record');
      check(h._currentSelectedSlug() == 'france', 'switch: selection not restored');
    case 'expiry_stale_inactivity_proof':
      h.commitTunnel('france');
      final pending = h._handleTrustedExpiredAccount(0, 'acct');
      await settle();
      check(h.heldProof != null, 'expiry proof was not held');
      h.directCommit('spain');
      h.heldProof!.complete(true);
      await pending;
      await settle();
      h.checkSecuredOn('spain', 'expiry: after the obsolete proof');
      await h._reconcileNativeTunnelState();
      await settle();
      h.checkSecuredOn('spain', 'expiry: then fresh reconciliation');
    case 'expiry_current_inactivity_proof':
      h.commitTunnel('france');
      final pending = h._handleTrustedExpiredAccount(0, 'acct');
      await settle();
      h.nativeActive = false;
      h.heldProof!.complete(true);
      await pending;
      await settle();
      check(!h._isConnected && h._ipAfterVpn == 'Disconnected',
          'expiry: proven teardown did not disconnect');
      check(h.recordSlug() == null, 'expiry: proven teardown kept the record');
      check(h._accountExpiredTerminal, 'expiry: terminal flag not set');
    case 'settings_restart_stale_stop_failed_reading':
      h.commitTunnel('france');
      h.stopResult = false;
      h.holdReads = 1;
      final restart = h._restartTunnelForSettingsChange();
      await settle();
      check(h.heldReads.length == 1, 'restart did not read native state');
      // A connect that does not take _isLoading (the Apple live-tunnel smoke
      // path) commits B while the restart's reading is outstanding.
      h.commitTunnel('germany');
      h.nativeActive = true;
      h.heldReads.single.complete(false);
      await restart;
      await settle();
      checkRestartSettled(h, 'stale stop-failed reading');
      h.checkSecuredOn('germany', 'restart resumed after B committed');
      check(h._ipAfterVpn != 'Disconnected',
          'obsolete reading rewrote the status label');
      await h._reconcileNativeTunnelState();
      await settle();
      h.checkSecuredOn('germany', 'restart then fresh reconciliation');
    case 'settings_restart_stop_failed_still_active':
      h.commitTunnel('france');
      h.stopResult = false;
      h.nativeActive = true;
      await h._restartTunnelForSettingsChange();
      await settle();
      checkRestartSettled(h, 'current stop failure, still active');
      h.checkSecuredOn('france', 'retained tunnel must keep its node');
    case 'settings_restart_stop_failed_inactive':
      h.commitTunnel('france');
      h.stopResult = false;
      h.nativeActive = false;
      await h._restartTunnelForSettingsChange();
      await settle();
      checkRestartSettled(h, 'current stop failure, inactive');
      check(!h._isConnected, 'a dead tunnel stayed connected');
      check(h._ipAfterVpn == 'Disconnected', 'dead tunnel label not updated');
      check(h.recordSlug() == null, 'a dead tunnel kept its record');
    case 'restore_stale_false_commit_b_after_read':
      await restoreWithCommitDuring(h, 'activation');
    case 'restore_stale_false_commit_b_during_settings':
      await restoreWithCommitDuring(h, 'settings');
      check(h._isFreeAccessSession,
          'independent onboarding restore was skipped');
    case 'restore_stale_account_epoch':
      h._isConnected = false;
      h.nativeActive = true;
      h.activationGate = Completer<void>();
      final restore = h._determineSecurityOnboardingLayer();
      await settle();
      check(h.activationStarted, 'restore did not reach activation');
      // Account teardown or activation moved the epoch meanwhile.
      h._accountSessionEpoch.current++;
      // Hold the network-label reading restore issues on its way out, so the
      // restore's own result is judged alone.
      h.holdReads = 1;
      h.activationGate!.complete();
      await restore;
      await settle();
      checkRestoreCompleted(h, 'stale account');
      check(!h._isConnected,
          'a reading taken for the previous account set connected state');
      check(h.heldReads.length == 1, 'restore did not refresh the label');
      // That later reading is fresh for the current account: a live tunnel
      // is adopted, without identity.
      h.heldReads.single.complete(true);
      await settle();
      h.checkSecuredUnknown('fresh reading after the account change');
    case 'restore_genuine_startup_adoption':
      h._isConnected = false;
      h.nativeActive = true;
      await h._determineSecurityOnboardingLayer();
      await settle();
      checkRestoreCompleted(h, 'startup adoption');
      h.checkSecuredUnknown('identity-free startup adoption');
      check(h._isLoggedIn, 'adopted tunnel did not log the app in');
      // Round UN: the relaunch adoption asks the persisted record once.
      check(h.restoreSchedules == 1,
          'startup adoption asked for ${h.restoreSchedules} restores');
    case 'restore_current_death_clears_record':
      // Restore reruns (PIN re-enrollment failure) while A is committed.
      h.commitTunnel('france');
      h.nativeActive = false;
      await h._determineSecurityOnboardingLayer();
      await settle();
      checkRestoreCompleted(h, 'current death');
      check(!h._isConnected, 'current-session death was not applied');
      check(h.recordSlug() == null, 'current-session death kept the record');
      check(h._activeProtocolLabel == 'Winn' && h._activeProtocolVersion == '',
          'down tunnel kept its protocol fields');
      h.nativeActive = true;
      await h._reconcileNativeTunnelState();
      await settle();
      h.checkSecuredUnknown('adoption after the restore-observed death');
    case 'reconcile_stale_false_then_fresh_true':
      await staleFalseThenFreshTrue(h, () => h._reconcileNativeTunnelState(),
          label: 'reconcile');
    case 'reconcile_two_completions_keep_b_record':
      // The verdict's exact sequence, judged only on the final state: B's
      // record must survive both completions.
      await staleFalseThenFreshTrue(h, () => h._reconcileNativeTunnelState(),
          label: 'reconcile', checkBetweenCompletions: false);
    case 'reconcile_stale_true_after_disconnect':
      h.commitTunnel('france');
      h.holdReads = 1;
      final old = h._reconcileNativeTunnelState();
      await settle();
      // The user disconnects while the old read (taken before the stop) waits.
      h.disconnect();
      h.heldReads.single.complete(true);
      await old;
      await settle();
      check(!h._isConnected,
          'obsolete true re-secured a tunnel the user disconnected');
      check(h._ipAfterVpn == 'Disconnected',
          'obsolete true rewrote the status label to ${h._ipAfterVpn}');
    case 'reconcile_stale_account_epoch':
      h.commitTunnel('france');
      h.holdReads = 1;
      final old = h._reconcileNativeTunnelState();
      await settle();
      // Account teardown owns connection state from here.
      h._accountSessionEpoch.current++;
      h.heldReads.single.complete(false);
      await old;
      await settle();
      check(h._isConnected && h._ipAfterVpn == 'Traffic Secured & Obfuscated',
          'a reading from the previous account mutated connection state');
    case 'heartbeat_background_reading_dropped':
    case 'heartbeat_pre_return_reading_dropped':
    case 'network_label_background_reading_dropped':
      // Ruling A2: a native reading that lands in the background, or that
      // was issued before the last return to the foreground, describes an
      // older moment and writes no connection state.
      if (scenario.startsWith('network_label_')) h._isApplePlatform = true;
      h.commitTunnel('france');
      h.holdReads = 1;
      final old = scenario.startsWith('network_label_')
          ? h._fetchLiveNetworkIp()
          : h._runStatusHeartbeat();
      await settle();
      if (scenario == 'heartbeat_pre_return_reading_dropped') {
        h._resumeProofGeneration++;
      } else {
        h._appInBackground = true;
      }
      h.heldReads.single.complete(false);
      await old;
      await settle();
      check(h._isConnected && h._ipAfterVpn == 'Traffic Secured & Obfuscated',
          'an out-of-lifecycle reading mutated connection state');
      check(h.recordSlug() == 'france',
          'an out-of-lifecycle reading ended the committed record');
    case 'heartbeat_background_true_reading_dropped':
    case 'heartbeat_pre_return_true_reading_dropped':
      // The same fence for a stale "up": a disconnected app whose heartbeat
      // read lands in the background, or straddles a return, adopts nothing.
      h._isConnected = false;
      h._ipAfterVpn = 'Disconnected';
      h.holdReads = 1;
      final old = h._runStatusHeartbeat();
      await settle();
      if (scenario == 'heartbeat_pre_return_true_reading_dropped') {
        h._resumeProofGeneration++;
      } else {
        h._appInBackground = true;
      }
      h.heldReads.single.complete(true);
      await old;
      await settle();
      check(!h._isConnected && h._ipAfterVpn == 'Disconnected',
          'an out-of-lifecycle "up" reading adopted a tunnel');
      check(h.restoreSchedules == 0,
          'an out-of-lifecycle "up" reading asked for a restore');
    case 'heartbeat_unanswered_read_reaches_account_sync':
      // O9: a native read that never answers must not hold the heartbeat, so
      // the account sync (status, revocation) still runs, and later
      // heartbeats issue no second read while the first is pending.
      h.commitTunnel('france');
      h._lastAnnouncementSync = DateTime.now();
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      h.holdReads = 1;
      final readsBefore = h.nativeReads;
      await h._runStatusHeartbeat();
      check(!h._statusHeartbeatRunning, 'the heartbeat stayed running');
      check(h.accountSyncs == 1, 'an unanswered read blocked the account sync');
      // A minute later, with that read still unanswered.
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      await h._runStatusHeartbeat();
      check(h.accountSyncs == 2, 'the next heartbeat skipped the account sync');
      check(h.nativeReads == readsBefore + 1,
          'a second native read was issued while the first was pending');
      h.heldReads.single.complete(false);
      await settle();
      check(h._isConnected && h.recordSlug() == 'france',
          'a reading that answered after the bound was applied');
      h.nativeActive = true;
      await h._runStatusHeartbeat();
      check(h.nativeReads == readsBefore + 2,
          'the answered read did not clear the pending state');
      check(h._isConnected && h.recordSlug() == 'france',
          'a fresh reading after the pending one moved the session');
    case 'loading_session_keeps_account_sync':
    case 'free_session_keeps_account_sync':
      // Sol (CORE-36-T9C-sol): the heartbeat's top gate shuts for a loading
      // session and for a free session that is not logged in, before any
      // read or sync. The account duty must still run, on its 60 s clock,
      // with every native read held for good.
      if (scenario == 'loading_session_keeps_account_sync') {
        h._isLoading = true;
      } else {
        h._isLoggedIn = false;
        h._isFreeAccessSession = true;
      }
      h.holdReads = 1000;
      h._lastAnnouncementSync = DateTime.fromMillisecondsSinceEpoch(0);
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 1, 'a gated session skipped the account sync');
      check(h.syncEpochs.single == h._accountSessionEpoch.current,
          'the sync did not carry the current account epoch');
      check(h.nativeReads == 0, 'the gated heartbeat issued a native read');
      for (var i = 0; i < 5; i++) {
        h._onForegroundStatusTick();
        await settle();
      }
      check(h.accountSyncs == 1, 'the sync repeated inside its 60 s clock');
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 2, 'the sync stopped after its first minute');
      check(h.maxSyncsInFlight == 1, 'two account syncs overlapped');
    case 'foreground_tick_one_status_request_per_minute':
      // Steady foreground: the heartbeat can run, so it makes the minute's
      // status call and the tick adds none (T9C-sol's tick made two).
      h.commitTunnel('france');
      h._lastAnnouncementSync = DateTime.fromMillisecondsSinceEpoch(0);
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 1,
          'a due minute issued ${h.accountSyncs} status requests, not 1');
      check(h.nativeReads == 1, 'the tick did not run the heartbeat read');
      for (var i = 0; i < 5; i++) {
        h._onForegroundStatusTick();
        await settle();
      }
      check(h.accountSyncs == 1, 'a status request repeated inside the minute');
    case 'account_syncs_never_overlap':
      // A sync the tick started while loading is still in flight when the
      // gate opens; the heartbeat joins it and issues no second call.
      h.commitTunnel('france');
      h._isLoading = true;
      h._lastAnnouncementSync = DateTime.fromMillisecondsSinceEpoch(0);
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      h.syncGate = Completer<void>();
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 1 && h.syncsInFlight == 1,
          'the gated tick did not start the account sync');
      h._isLoading = false;
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 1, 'the heartbeat overlapped the account sync');
      h.syncGate!.complete();
      h.syncGate = null;
      await settle();
      check(!h._statusHeartbeatRunning,
          'the heartbeat outlived the sync it joined');
      // The reverse: a heartbeat sync in flight when loading starts.
      h._lastAnnouncementSync = DateTime.fromMillisecondsSinceEpoch(0);
      h.syncGate = Completer<void>();
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 2 && h._statusHeartbeatRunning,
          'the heartbeat did not start its own sync');
      h._isLoading = true;
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 2,
          'the tick overlapped the heartbeat sync in flight');
      h.syncGate!.complete();
      h.syncGate = null;
      await settle();
      check(h.maxSyncsInFlight == 1, 'two account syncs overlapped');
    case 'account_sync_epoch_replacement':
      // Sol (CORE-36): the account is replaced while a sync for the old one
      // is held. The replacement's sync starts at once, not after the old
      // one; the old completion does not release the new sync's slot; and
      // nothing more is issued for the old epoch.
      h._isLoading = true;
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      final oldGate = Completer<void>();
      h.syncGate = oldGate;
      final oldEpoch = h._accountSessionEpoch.current;
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 1, 'the gated tick did not start the sync');
      h._accountSessionEpoch.current++;
      final newEpoch = h._accountSessionEpoch.current;
      final newGate = Completer<void>();
      h.syncGate = newGate;
      h._onForegroundStatusTick();
      await settle();
      check(h.accountSyncs == 2 && h.syncEpochs.last == newEpoch,
          'the replacement account waited on the old account sync');
      oldGate.complete();
      await settle();
      final joined =
          h._refreshAccountStatus(force: true, expectedEpoch: newEpoch);
      await settle();
      check(h.accountSyncs == 2,
          'the old completion released the replacement sync');
      check(await h._refreshAccountStatus(expectedEpoch: oldEpoch) == false,
          'a call for the replaced account was admitted');
      check(h.accountSyncs == 2, 'a request was issued for the old account');
      newGate.complete();
      h.syncGate = null;
      check(await joined, 'the joined caller lost the sync result');
      await settle();
      check(h.syncEpochs.length == 2 &&
              h.syncEpochs.first == oldEpoch &&
              h.syncEpochs.last == newEpoch,
          'sync epochs were ${h.syncEpochs}');
      check(h.maxSyncsInFlightPerEpoch == 1,
          'two syncs for one account epoch overlapped');
    case 'account_sync_callers_share_one_flight':
      // Sol (CORE-36): the 45 s throttle is checked before the credential
      // reads and the clock is stamped after them, so callers that arrive in
      // that window all see an unstamped clock. Every caller kind arrives in
      // it here: the background helper, the heartbeat's account branch, both
      // forced announcement syncs, and a forced direct call (onboarding,
      // referral share). One request is made, and every caller gets its
      // result.
      h._lastAnnouncementSync = DateTime.now();
      h._lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
      h.syncGate = Completer<void>();
      final epoch = h._accountSessionEpoch.current;
      final callers = <Future<Object?>>[
        h._runBackgroundSecurityHeartbeat(),
        h._runStatusHeartbeat(),
        h._refreshAnnouncementsAfterConnect(expectedEpoch: epoch),
        h._refreshAnnouncementsWhileDisconnected(expectedEpoch: epoch),
        h._refreshAccountStatus(force: true),
        h._refreshAccountStatus(expectedEpoch: epoch),
      ];
      await settle();
      check(h.accountSyncs == 1,
          '${h.accountSyncs} requests for one account epoch, not 1');
      h.syncGate!.complete();
      h.syncGate = null;
      await Future.wait(callers);
      check(h.maxSyncsInFlight == 1, 'two account syncs overlapped');
      // After it lands: an unforced caller inside 45 s makes no request, a
      // forced one makes exactly one.
      check(await h._refreshAccountStatus(expectedEpoch: epoch),
          'the throttled caller reported failure');
      check(h.accountSyncs == 1, 'the 45 s throttle let a request through');
      check(await h._refreshAccountStatus(force: true, expectedEpoch: epoch),
          'the forced caller reported failure');
      check(h.accountSyncs == 2, 'a forced caller after the sync was dropped');
    case 'reconcile_current_death_then_adoption':
      await currentDeathThenAdoption(h, () => h._reconcileNativeTunnelState(),
          label: 'reconcile');
    case 'heartbeat_stale_false_then_fresh_true':
      await staleFalseThenFreshTrue(h, () => h._runStatusHeartbeat(),
          label: 'heartbeat');
    case 'heartbeat_current_death_then_adoption':
      await currentDeathThenAdoption(h, () => h._runStatusHeartbeat(),
          label: 'heartbeat');
      check(h.announcementRefreshes > 0,
          'heartbeat adoption no longer refreshes announcements');
    case 'network_label_stale_false_then_fresh_true':
      // Apple is the platform whose network-label path clears _isConnected.
      h._isApplePlatform = true;
      await staleFalseThenFreshTrue(h, () => h._fetchLiveNetworkIp(),
          label: 'network label');
    case 'network_label_current_death_then_adoption':
      h._isApplePlatform = true;
      await currentDeathThenAdoption(h, () => h._fetchLiveNetworkIp(),
          label: 'network label');
    default:
      throw StateError('Unknown scenario: $scenario');
  }
  print('PASS $scenario');
}
''';
