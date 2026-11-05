// Ruling A2 (CORE-36): what a return from the background may claim. The
// proof recorder, the resume void, the held-lifecycle observer, the resume
// check and the read-issue tag run VERBATIM from lib/main.dart in a
// subprocess against scripted native replies, so a change to a fence is a
// red test, not a surviving substring.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _between(String source, String start, String end) {
  final a = source.indexOf(start);
  expect(a, greaterThanOrEqualTo(0), reason: 'missing $start');
  final b = source.indexOf(end, a + start.length);
  expect(b, greaterThan(a), reason: 'missing $end after $start');
  return source.substring(a, b);
}

void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('hidden, paused and detached start the background; inactive is visible',
      () {
    final lifecycle = _between(source,
        '  void didChangeAppLifecycleState(AppLifecycleState state) {',
        '  void _startStatusHeartbeat() {');
    final resumed = lifecycle.indexOf('if (state == AppLifecycleState.resumed)');
    expect(lifecycle.indexOf('if (_appInBackground) _leaveBackground();', resumed),
        greaterThan(resumed));
    expect(
        lifecycle,
        contains('    if (state == AppLifecycleState.inactive) {\n'
            '      if (_appInBackground) _leaveBackground();\n'
            '    } else if (!_appInBackground) {\n'
            '      _appInBackground = true;\n'
            '      _startBackgroundHeartbeat();\n'
            '    }\n'));
    expect(lifecycle, contains('        state != AppLifecycleState.hidden &&\n'));
    expect(lifecycle,
        contains('    if (state == AppLifecycleState.hidden) return;\n'));
    final leave = _between(source, '  void _leaveBackground() {', '\n  }\n');
    expect(leave.indexOf('_beginResumeProofCheck();'),
        lessThan(leave.indexOf('_startStatusHeartbeat();')));
  });

  test('reconciliation never applies a background or pre-return reading', () {
    final reconcile = _between(source,
        '  Future<void> _reconcileNativeTunnelState(', '    if (active) {');
    expect(
        reconcile,
        contains('    if (!_supportsNativeTunnelReadiness || !mounted || '
            '_appInBackground) {\n'));
    expect(reconcile,
        contains('    final lifecycleGeneration = _resumeProofGeneration;\n'));
    expect(
        reconcile,
        contains('    if (_appInBackground ||\n'
            '        lifecycleGeneration != _resumeProofGeneration ||\n'
            '        !_nativeReadingIsCurrent(displayGeneration, accountEpoch)) {\n'));
  });

  test('every native read is tagged with its issue generation', () {
    final read = _between(source, '  Future<bool> _readNativeTunnelActive() async {',
        '    if (_isApplePlatform) {');
    expect(read, contains('if (Zone.current[_proofIssueZoneKey] == null) {'));
    expect(read, contains('_proofIssueZoneKey: _resumeProofGeneration,'));
  });

  test('every state-writing native-read consumer drops out-of-lifecycle readings',
      () {
    for (final start in const <String>[
      '  Future<bool> _readNativeTunnelConnectedProof() async {',
      '  Future<void> _restartTunnelForSettingsChange() async {',
      '  Future<void> _fetchPreVpnCountryCode() async {',
      '  Future<void> _reconnectHeldWinn3Session({',
      '  Future<void> _switchConnectedServer(String serverName,',
      '  Future<void> _runStatusHeartbeat() async {',
      '  Future<void> _fetchLiveNetworkIp() async {',
      '  Future<void> _determineSecurityOnboardingLayer() async {',
      '  Future<void> _toggleVpnConnection() async {',
    ]) {
      final body = _between(source, start, '\n  }\n');
      expect(body, contains('_appInBackground'), reason: start);
      expect(body, contains('_resumeProofGeneration'), reason: start);
    }
  });

  test('the background heartbeat is the account sync alone', () {
    final background = _between(source, '  void _startBackgroundHeartbeat() {',
        '  /// Ruling A2: the background duty');
    expect(background, contains('Duration(seconds: 60)'));
    expect(background, contains('_proofTimer = null;'));
    expect(
        'unawaited(_runBackgroundSecurityHeartbeat());'
            .allMatches(background)
            .length,
        2,
        reason: 'the periodic tick and the immediate sync');
    final run = _between(source,
        '  Future<void> _runBackgroundSecurityHeartbeat() async {', '\n  }\n');
    expect(run, contains('_refreshAccountStatus(expectedEpoch: accountEpoch)'));
    expect(run, isNot(contains('force: true')));
    expect(run, isNot(contains('_readNativeTunnelActive')));
    expect(run, isNot(contains('invokeMethod')));
    expect(run, isNot(contains('_isLoading')));
  });

  test('headline, status line and held banner wait for the check', () {
    expect(source,
        contains('(_rendersResumeCheck ? _t("CHECKING") : _t("UNPROTECTED"))'));
    final held = _between(source, '  bool get _rendersHeldSession =>',
        '  static const Duration _tunnelProofMaxFreshness');
    expect(held, contains('!_resumeProofPending &&'));
    final line = _between(source, '  String get _statusLineText {', '\n  }\n');
    expect(line.indexOf("if (_rendersResumeCheck) return _t('Checking connection...');"),
        lessThan(line.indexOf('final value = _ipAfterVpn.trim();')));
    expect(
        source,
        contains('        if (!_resumeProofPending &&\n'
            '            !_rendersConnected &&\n'
            '            ((_isConnected && _winn3HostLifecycle.holdsSession) ||'));
  });

  group('behaviour', () {
    late Directory temporary;
    late File executable;

    setUpAll(() async {
      final record = _between(source, '  void _recordNativeTunnelProof(bool active) {',
          '  /// A connected session waiting on its first post-resume proof.');
      final observe = _between(source,
          '  bool _observeWinn3HostLifecycle(Map<dynamic, dynamic>? readiness) {',
          '  /// Current connected proof, read fresh');
      final heldRecord = _between(source, '  bool _recordedHeldSession() {',
          '\n  }\n');
      final checkBody = _between(source, '  void _beginResumeProofCheck() {',
          '  /// Background cadence (C-core-17, ruling A2)');
      final readPrelude = _between(source,
          '  Future<bool> _readNativeTunnelActive() async {',
          '    if (_isApplePlatform) {');
      temporary = await Directory.systemTemp.createTemp('resume-proof-claim-');
      executable = File('${temporary.path}/resume.dart');
      await executable.writeAsString('''
import 'dart:async';

class TunnelLivenessProof {
  TunnelLivenessProof({required this.active, required this.probedAt});
  final bool active;
  final DateTime probedAt;
}

class Winn3HostLifecycleView {
  const Winn3HostLifecycleView._(this.holdsSession);
  final bool holdsSession;
  static const Winn3HostLifecycleView none = Winn3HostLifecycleView._(false);
  static const Winn3HostLifecycleView held = Winn3HostLifecycleView._(true);
}

Winn3HostLifecycleView winn3HostLifecycleFromReadiness(
        Map<dynamic, dynamic>? readiness,
        {required bool apple}) =>
    readiness != null && readiness['held'] == true
        ? Winn3HostLifecycleView.held
        : Winn3HostLifecycleView.none;

class H {
  bool mounted = true;
  final bool _isApplePlatform = false;
  bool _appInBackground = false;
  bool _resumeProofPending = false;
  int _resumeProofGeneration = 0;
  static const Object _proofIssueZoneKey = #winsNativeProofIssue;
  static const Object _heartbeatProofGateZoneKey = #winsHeartbeatProofGate;
  Winn3HostLifecycleView _winn3HostLifecycle = Winn3HostLifecycleView.none;
  DateTime _winn3LifecycleObservedAt = DateTime.fromMillisecondsSinceEpoch(0);
  TunnelLivenessProof _latestTunnelProof = TunnelLivenessProof(
      active: false, probedAt: DateTime.fromMillisecondsSinceEpoch(0));
  final List<Completer<Object>> replies = <Completer<Object>>[];
  void setState(void Function() fn) => fn();
  bool _recordedTunnelProof(bool active) {
    _recordNativeTunnelProof(active);
    return active;
  }
  bool get fresh => _latestTunnelProof.probedAt.millisecondsSinceEpoch > 0;
  bool get held => _winn3HostLifecycle.holdsSession;
  bool get observed => _winn3LifecycleObservedAt.millisecondsSinceEpoch > 0;

$record
$observe
$heldRecord
  }

$checkBody
$readPrelude
    final reply = Completer<Object>();
    replies.add(reply);
    final value = await reply.future;
    if (value is Map) {
      if (_observeWinn3HostLifecycle(value)) return _recordedHeldSession();
      return _recordedTunnelProof(false);
    }
    return _recordedTunnelProof(value as bool);
  }
}

void check(bool ok, String message) {
  if (!ok) throw StateError(message);
}

Future<void> settle() => Future<void>.delayed(Duration.zero);

const Map<String, Object> heldReading = <String, Object>{'held': true};

Future<void> main(List<String> args) async {
  final scenario = args.single;
  final h = H();
  switch (scenario) {
    case 'pending_read_shows_no_claim':
      h._recordNativeTunnelProof(true);
      check(h._latestTunnelProof.active, 'setup');
      h._beginResumeProofCheck();
      check(h._resumeProofPending, 'the check must be pending');
      check(!h._latestTunnelProof.active && !h.fresh, 'the old proof must be void');
    case 'old_success_after_new_failure':
      final a = h._readNativeTunnelActive();
      await settle();
      h._appInBackground = true;
      h._appInBackground = false;
      h._beginResumeProofCheck();
      await settle();
      h.replies[1].complete(false);
      await settle();
      check(!h._resumeProofPending, 'the resume read ends the check');
      h.replies[0].complete(true);
      await a;
      await settle();
      check(!h._latestTunnelProof.active, 'a pre-pause reply must not write');
    case 'old_reply_while_pending_is_dropped':
      final a = h._readNativeTunnelActive();
      await settle();
      h._beginResumeProofCheck();
      await settle();
      h.replies[0].complete(true);
      await a;
      await settle();
      check(h._resumeProofPending && !h.fresh, 'a pre-pause reply cannot end the check');
    case 'timed_out_resume_read_publishes_nothing':
      h._beginResumeProofCheck();
      await Future<void>.delayed(const Duration(milliseconds: 2100));
      check(!h._resumeProofPending, 'a timeout ends the check');
      check(!h.fresh, 'the proof stays void after a timeout');
      final c = h._readNativeTunnelActive();
      await settle();
      h.replies[1].complete(false);
      await c;
      h.replies[0].complete(true);
      await settle();
      check(!h._latestTunnelProof.active, 'the late reply must publish nothing');
    case 'background_reply_writes_nothing':
      final a = h._readNativeTunnelActive();
      await settle();
      h._appInBackground = true;
      h.replies[0].complete(true);
      await a;
      check(!h.fresh, 'a reply landing in the background must not write');
    case 'direct_write_waits_for_a_read':
      h._beginResumeProofCheck();
      h._recordNativeTunnelProof(true);
      check(h._resumeProofPending && !h.fresh, 'an untagged write cannot end the check');
      await settle();
      h.replies[0].complete(true);
      await settle();
      await settle();
      check(!h._resumeProofPending && h._latestTunnelProof.active, 'the resume read writes');
      h._recordNativeTunnelProof(false);
      check(!h._latestTunnelProof.active, 'after the check, direct writes count again');
    case 'resume_clears_old_held_lifecycle':
      h._winn3HostLifecycle = Winn3HostLifecycleView.held;
      h._winn3LifecycleObservedAt = DateTime.now();
      h._beginResumeProofCheck();
      check(!h.held, 'the pre-pause held claim must be void during the check');
      check(!h.observed, 'the pre-pause observation time must be void too');
      await Future<void>.delayed(const Duration(milliseconds: 2100));
      check(!h._resumeProofPending, 'a timeout ends the check');
      check(!h.held, 'a timed-out check must not bring the old held claim back');
    case 'stale_held_reading_is_not_stored':
      final a = h._readNativeTunnelActive();
      await settle();
      h._beginResumeProofCheck();
      await settle();
      h.replies[1].complete(false);
      await settle();
      check(!h._resumeProofPending, 'the resume read ends the check');
      h.replies[0].complete(heldReading);
      check(await a, 'the caller still sees the session it read');
      await settle();
      check(!h.held, 'a pre-pause held reading must not be stored');
      check(!h.observed, 'nor may it stamp an observation time');
      check(!h._latestTunnelProof.active, 'nor may it write a proof');
    case 'background_held_reading_is_not_stored':
      final a = h._readNativeTunnelActive();
      await settle();
      h._appInBackground = true;
      h.replies[0].complete(heldReading);
      await a;
      check(!h.held, 'a held reading landing in the background must not be stored');
      check(!h.observed, 'nor may it stamp an observation time');
    case 'fresh_held_reading_ends_check_as_held':
      h._beginResumeProofCheck();
      await settle();
      h.replies[0].complete(heldReading);
      await settle();
      await settle();
      check(!h._resumeProofPending, 'a fresh held reading ends the check');
      check(h.held, 'a fresh held reading is stored');
      check(h.observed, 'a stored held reading stamps its observation time');
      check(h.fresh && !h._latestTunnelProof.active, 'a held session records a down proof');
    case 'untagged_observation_is_stored':
      h._beginResumeProofCheck();
      h._observeWinn3HostLifecycle(heldReading);
      check(h.held, 'the held-release flow observes outside the read path');
      check(h.observed, 'and that stored observation is stamped');
    default:
      throw StateError('unknown scenario \$scenario');
  }
  print('PASS \$scenario');
}
''');
    });

    tearDownAll(() async {
      if (await temporary.exists()) await temporary.delete(recursive: true);
    });

    for (final scenario in const <String>[
      'pending_read_shows_no_claim',
      'old_success_after_new_failure',
      'old_reply_while_pending_is_dropped',
      'timed_out_resume_read_publishes_nothing',
      'background_reply_writes_nothing',
      'direct_write_waits_for_a_read',
      'resume_clears_old_held_lifecycle',
      'stale_held_reading_is_not_stored',
      'background_held_reading_is_not_stored',
      'fresh_held_reading_ends_check_as_held',
      'untagged_observation_is_stored',
    ]) {
      test('resume proof: $scenario', () async {
        final result = await Process.run(
          Platform.environment['DART_EXECUTABLE'] ?? 'dart',
          <String>[executable.path, scenario],
          workingDirectory: temporary.path,
        );
        expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
        expect(result.stdout.toString(), contains('PASS $scenario'));
      });
    }
  });
}
