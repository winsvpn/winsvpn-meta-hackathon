// CORE-36 (Sol-core-T11-2): a heartbeat native read that answers after the
// heartbeat's bound has been retired. Its late "up", "down" or held-session
// reply must not replace the liveness proof, the held-session lifecycle or the
// heartbeat's display state, with the lifecycle generation unchanged, and the
// account sync must run while that read is still pending. A reply inside the
// bound still publishes. The heartbeat, the proof recorder, the lifecycle
// observer and the read-issue tag run VERBATIM from lib/main.dart in a
// subprocess against scripted native replies.
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
  late Directory temporary;
  late File executable;

  setUpAll(() async {
    final source = File('lib/main.dart').readAsStringSync();
    final record = _between(source, '  void _recordNativeTunnelProof(bool active) {',
        '  /// A connected session waiting on its first post-resume proof.');
    final observe = _between(source,
        '  bool _observeWinn3HostLifecycle(Map<dynamic, dynamic>? readiness) {',
        '  /// Current connected proof, read fresh');
    final heldRecord =
        _between(source, '  bool _recordedHeldSession() {', '\n  }\n');
    final readPrelude = _between(source,
        '  Future<bool> _readNativeTunnelActive() async {',
        '    if (_isApplePlatform) {');
    final heartbeat = _between(source,
        '  Future<void> _runStatusHeartbeat() async {',
        '  Future<void> _refreshAnnouncementsAfterConnect({');
    temporary = await Directory.systemTemp.createTemp('heartbeat-late-reply-');
    executable = File('${temporary.path}/late.dart');
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

class _Epoch {
  int current = 1;
}

class _Ledger {
  int generation = 0;
}

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

  // The heartbeat's own members. The production bound is the 8 s proof
  // window; a short one keeps the scenario fast.
  bool _statusHeartbeatRunning = false;
  bool _isLoggedIn = true;
  bool _isLoading = false;
  final _accountSessionEpoch = _Epoch();
  final _tunnelDisplayLedger = _Ledger();
  bool get _supportsNativeTunnelReadiness => true;
  bool _heartbeatNativeReadPending = false;
  static const Duration _heartbeatNativeReadBound = Duration(milliseconds: 200);
  bool _isConnected = true;
  String _ipAfterVpn = 'Traffic Secured & Obfuscated';
  DateTime _lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
  DateTime _lastAnnouncementSync = DateTime.now();
  int accountSyncs = 0;
  int displaySettles = 0;

  void setState(void Function() fn) => fn();
  String _t(String value) => value;
  bool _accountEpochIsCurrent(int epoch) => _accountSessionEpoch.current == epoch;
  bool _nativeReadingIsCurrent(int displayGeneration, int accountEpoch) =>
      mounted &&
      _tunnelDisplayLedger.generation == displayGeneration &&
      _accountEpochIsCurrent(accountEpoch);
  void _settleTunnelDisplaySession(bool wasConnected,
      {int? observedGeneration}) {
    displaySettles++;
  }
  Future<void> _fetchLiveNetworkIp() async {}
  Future<void> _refreshAnnouncementsAfterConnect(
      {bool forcePopup = false, int? expectedEpoch}) async {}
  Future<void> _refreshAnnouncementsWhileDisconnected(
      {int? expectedEpoch}) async {}
  Future<bool> _refreshAccountStatus(
      {bool force = false, int? expectedEpoch}) async {
    accountSyncs++;
    _lastAccountStatusSync = DateTime.now();
    return true;
  }
  Future<void> _saveVpnRuntimeSettings() async {}
  bool _recordedTunnelProof(bool active) {
    _recordNativeTunnelProof(active);
    return active;
  }

$record
$observe
$heldRecord
  }

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

$heartbeat
}

void check(bool ok, String message) {
  if (!ok) throw StateError(message);
}

Future<void> settle() async {
  for (var i = 0; i < 5; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

const Map<String, Object> heldReading = <String, Object>{'held': true};

Future<void> main(List<String> args) async {
  final scenario = args.single;
  final h = H();
  switch (scenario) {
    case 'late_down_after_bound_publishes_nothing':
    case 'late_up_after_bound_publishes_nothing':
    case 'late_held_after_bound_publishes_nothing':
      final up = scenario != 'late_up_after_bound_publishes_nothing';
      h._isConnected = up;
      h._ipAfterVpn = up ? 'Traffic Secured & Obfuscated' : 'Disconnected';
      h._recordNativeTunnelProof(up);
      final proof = h._latestTunnelProof;
      final ip = h._ipAfterVpn;
      final generation = h._resumeProofGeneration;
      await h._runStatusHeartbeat();
      check(h.replies.length == 1, 'the heartbeat issued no native read');
      check(h._heartbeatNativeReadPending, 'the read was not left pending');
      check(h.accountSyncs == 1,
          'the account sync did not run while the read was pending');
      final Object late = scenario == 'late_held_after_bound_publishes_nothing'
          ? heldReading
          : !up;
      h.replies.single.complete(late);
      await settle();
      check(h._resumeProofGeneration == generation, 'the lifecycle moved');
      check(!h._heartbeatNativeReadPending, 'the late reply left the read pending');
      check(identical(h._latestTunnelProof, proof),
          'a late reply replaced the liveness proof');
      check(!h._winn3HostLifecycle.holdsSession,
          'a late reply stored a held-session lifecycle');
      check(h._winn3LifecycleObservedAt.millisecondsSinceEpoch == 0,
          'a late reply refreshed the held-session observation time');
      check(h._isConnected == up && h._ipAfterVpn == ip && h.displaySettles == 0,
          'a late reply moved the heartbeat display state');
    case 'reply_inside_bound_publishes':
      h._recordNativeTunnelProof(true);
      final proof = h._latestTunnelProof;
      final beat = h._runStatusHeartbeat();
      await settle();
      h.replies.single.complete(false);
      await beat;
      check(!identical(h._latestTunnelProof, proof) &&
              !h._latestTunnelProof.active,
          'a reply inside the bound did not publish its proof');
      check(!h._isConnected && h._ipAfterVpn == 'Disconnected' &&
              h.displaySettles == 1,
          'a reply inside the bound did not move the display');
    case 'held_reply_inside_bound_is_stored':
      h._recordNativeTunnelProof(true);
      final beat = h._runStatusHeartbeat();
      await settle();
      h.replies.single.complete(heldReading);
      await beat;
      check(h._winn3HostLifecycle.holdsSession,
          'a held reply inside the bound was not stored');
      check(
          DateTime.now().difference(h._winn3LifecycleObservedAt) <
              const Duration(seconds: 5),
          'a stored held reply did not stamp its observation time');
      check(!h._latestTunnelProof.active, 'a held session kept a connected proof');
      check(h._isConnected, 'a held session ended the connected session');
    default:
      throw ArgumentError(scenario);
  }
  print('PASS \$scenario');
}
''');
  });

  tearDownAll(() async {
    await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'late_down_after_bound_publishes_nothing',
    'late_up_after_bound_publishes_nothing',
    'late_held_after_bound_publishes_nothing',
    'reply_inside_bound_publishes',
    'held_reply_inside_bound_is_stored',
  ]) {
    test('heartbeat late reply: $scenario', () async {
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
