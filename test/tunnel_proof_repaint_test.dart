import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Runs the shipping proof getter, held-session getter, repaint check,
// heartbeat start and proof pump (extracted verbatim from lib/main.dart) under
// a scripted timer and a scripted setState/build boundary. The painted SECURED
// claim must follow the logical claim when a native read disproves it, and
// when the last proof expires while the next read never answers, with no other
// setState. The painted TRAFFIC HELD claim must expire the same way: a held
// lifecycle observed longer ago than the proof window (or in the future) paints
// nothing, and a healthy held bridge that keeps observing never flickers.
String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) throw StateError('Missing $start');
  return source.substring(first, last);
}

void main() {
  test('a disproved or expired tunnel proof repaints the headline', () async {
    final source = File('lib/main.dart').readAsStringSync();
    final getter = _between(source, '  bool get _rendersConnected {',
        '  /// A held Winn v3 session (Round A3)');
    final held = _between(source, '  bool get _rendersHeldSession =>',
        '  /// Maximum age of a native liveness proof');
    final claims = _between(source, '  int _paintedProofClaims = -1;',
        '  Timer? _settingsReconnectTimer;');
    final start = _between(source, '  void _startStatusHeartbeat() {',
        '  /// Ruling A2: the app is visible again');
    final pump = _between(source, '  Future<void> _pumpTunnelProof() async {',
        '  Future<void> _runStatusHeartbeat() async {');
    final proof = File('lib/tunnel_liveness_proof.dart').absolute.uri;
    final temporary =
        await Directory.systemTemp.createTemp('wins-proof-repaint-');
    try {
      final program = File('${temporary.path}/probe.dart');
      await program.writeAsString("import '$proof';\n"
          '$_harness$getter$held$claims$start$pump$_end');
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        [program.path],
      ).timeout(const Duration(seconds: 60));
      expect(result.exitCode, 0, reason: '${result.stderr}');
      final output = '${result.stdout}';
      expect(output, contains('native_down: logical=false painted=false'));
      expect(output, contains('expired_and_hung: logical=false painted=false'));
      expect(output, contains('steady: rebuilds=0'));
      expect(output, contains('held_fresh: logical=true'));
      expect(output, contains('held_stale: logical=false'));
      expect(output, contains('held_future: logical=false'));
      expect(output,
          contains('held_expired_and_hung: before=true logical=false painted=false'));
      expect(output, contains('held_steady: rebuilds=0 painted=true'));
    } finally {
      await temporary.delete(recursive: true);
    }
  });
}

const _harness = r'''
import 'dart:async';

class ControlledTimer implements Timer {
  ControlledTimer(this.callback);
  final void Function(Timer) callback;
  @override
  bool isActive = true;
  @override
  int tick = 0;
  @override
  void cancel() { isActive = false; }
  void fire() { if (isActive) { tick++; callback(this); } }
}

class Winn3HostLifecycleView {
  const Winn3HostLifecycleView._(this.holdsSession);
  final bool holdsSession;
  static const Winn3HostLifecycleView none = Winn3HostLifecycleView._(false);
  static const Winn3HostLifecycleView held = Winn3HostLifecycleView._(true);
}

class Harness {
  bool _privacyConsentGranted = true;
  bool _isApplePlatform = false;
  bool _supportsNativeTunnelReadiness = true;
  bool _proofPumpRunning = false;
  bool mounted = true;
  bool _isConnected = true;
  bool _isVpnConnectInFlight = false;
  bool _isTunnelTransitioning = false;
  bool _resumeProofPending = false;
  Winn3HostLifecycleView _winn3HostLifecycle = Winn3HostLifecycleView.none;
  DateTime _winn3LifecycleObservedAt = DateTime.fromMillisecondsSinceEpoch(0);
  bool get _rendersResumeCheck => false;
  Timer? _statusTimer, _proofTimer;
  static const _tunnelProofMaxFreshness = Duration(seconds: 8);
  TunnelLivenessProof _latestTunnelProof =
      TunnelLivenessProof(active: true, probedAt: DateTime.now());
  bool paintedConnected = false;
  bool paintedHeld = false;
  int rebuilds = 0;
  bool hang = false;
  bool nativeActive = false;
  // A healthy held bridge: every read lands as a stored held observation,
  // which is what _observeWinn3HostLifecycle stamps.
  bool nativeHeld = false;
  void build() {
    _paintedProofClaims = _proofClaims;
    paintedConnected = _rendersConnected;
    paintedHeld = _rendersHeldSession;
  }
  void setState(void Function() update) {
    update();
    rebuilds++;
    build();
  }
  // The account heartbeat may be parked in its serial front walk.
  void _onForegroundStatusTick() {}
  Future<bool> _readNativeTunnelActive() async {
    if (hang) return Completer<bool>().future;
    if (nativeHeld) _winn3LifecycleObservedAt = DateTime.now();
    _latestTunnelProof =
        TunnelLivenessProof(active: nativeActive, probedAt: DateTime.now());
    return nativeActive || nativeHeld;
  }
''';

const _end = r'''
}
Future<void> settle() async {
  for (var i = 0; i < 4; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}
Future<void> main() async {
  await runZoned(() async {
    final steady = Harness()..nativeActive = true;
    steady.build();
    steady._startStatusHeartbeat();
    (steady._proofTimer as ControlledTimer).fire();
    await settle();
    (steady._proofTimer as ControlledTimer).fire();
    await settle();
    print('steady: rebuilds=${steady.rebuilds} painted=${steady.paintedConnected}');

    final down = Harness();
    down.build();
    down._startStatusHeartbeat();
    (down._proofTimer as ControlledTimer).fire();
    await settle();
    print('native_down: logical=${down._rendersConnected} '
        'painted=${down.paintedConnected} rebuilds=${down.rebuilds}');

    final hung = Harness()..hang = true;
    hung.build();
    hung._latestTunnelProof = TunnelLivenessProof(active: true,
        probedAt: DateTime.now().subtract(const Duration(seconds: 10)));
    hung._startStatusHeartbeat();
    (hung._proofTimer as ControlledTimer).fire();
    await settle();
    (hung._proofTimer as ControlledTimer).fire();
    await settle();
    print('expired_and_hung: logical=${hung._rendersConnected} '
        'painted=${hung.paintedConnected} rebuilds=${hung.rebuilds}');

    Harness heldAt(Duration age) => Harness()
      .._latestTunnelProof = TunnelLivenessProof(
          active: false, probedAt: DateTime.now())
      .._winn3HostLifecycle = Winn3HostLifecycleView.held
      .._winn3LifecycleObservedAt = DateTime.now().subtract(age);
    print('held_fresh: logical='
        '${heldAt(const Duration(seconds: 1))._rendersHeldSession}');
    print('held_stale: logical='
        '${heldAt(const Duration(seconds: 120))._rendersHeldSession}');
    print('held_future: logical='
        '${heldAt(const Duration(seconds: -60))._rendersHeldSession}');

    // Painted while fresh, then the bridge hangs and the observation ages
    // past the window: the next pump tick must repaint it away.
    final heldHung = heldAt(const Duration(milliseconds: 7800))..hang = true;
    heldHung.build();
    final before = heldHung.paintedHeld;
    await Future<void>.delayed(const Duration(milliseconds: 400));
    heldHung._startStatusHeartbeat();
    (heldHung._proofTimer as ControlledTimer).fire();
    await settle();
    print('held_expired_and_hung: before=$before '
        'logical=${heldHung._rendersHeldSession} '
        'painted=${heldHung.paintedHeld} rebuilds=${heldHung.rebuilds}');

    final heldSteady = heldAt(const Duration(seconds: 1))..nativeHeld = true;
    heldSteady.build();
    heldSteady._startStatusHeartbeat();
    (heldSteady._proofTimer as ControlledTimer).fire();
    await settle();
    (heldSteady._proofTimer as ControlledTimer).fire();
    await settle();
    print('held_steady: rebuilds=${heldSteady.rebuilds} '
        'painted=${heldSteady.paintedHeld}');
  }, zoneSpecification: ZoneSpecification(
    createPeriodicTimer: (self, parent, zone, duration, callback) =>
        ControlledTimer(callback),
  ));
}
''';
