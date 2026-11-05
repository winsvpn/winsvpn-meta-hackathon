import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/apple_tunnel_diagnostics.dart';
import 'package:wins_vpn/tunnel_readiness.dart';
import 'package:wins_vpn/winn3_host_lifecycle.dart';

/// Round A3: the Android and Apple hosts CONSUME the Winn v3 engine's
/// lifecycle status (Round A2), and the app renders it.
///
/// Native behaviour is pinned natively (the Gradle suite's
/// `WinnV3LifecycleWatchTest`, `WinnV3CaptureCustodyTest`,
/// `WinnV3RecoveryProberTest`, `WinnV3StatusStallTest` and
/// `WinnV3HostReadinessTest`, and `tools/verify_apple_winn3_lifecycle.sh`).
/// This suite owns what no native suite can see:
///   * the Dart status consumer, fed the exact `getTunnelReadiness` maps the
///     native bridges were proven to produce
///     (`test/fixtures/winn3_host_lifecycle_readiness.json`), including
///     blocked and a later recovery;
///   * the dashboard banner and its two controls;
///   * that the Kotlin, Swift and Go spellings and constants agree, and where
///     in each host the lifecycle is read.
void main() {

  testWidgets('an Apple held session exposes manual recovery only', (tester) async {
    var disconnects = 0;
    var reconnects = 0;
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: Winn3HostLifecycleBanner(
      lifecycle: const Winn3HostLifecycleView(
        state: Winn3HostLifecycleState.blocked, captureHeld: true),
      translate: (s) => s, enabled: true, reconnectAvailable: false,
      onDisconnect: () => disconnects++, onReconnect: () => reconnects++,
    ))));
    expect(find.byKey(const Key('winn3_host_lifecycle_reconnect')), findsNothing);
    expect(find.textContaining('Disconnecting releases the hold'), findsWidgets);
    await tester.tap(find.byKey(const Key('winn3_host_lifecycle_disconnect')));
    expect(disconnects, 1);
    expect(reconnects, 0);
  });
  String read(String path) => File(path).readAsStringSync();

  const kotlinService =
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt';
  const kotlinActivity =
      'android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt';
  const kotlinGate =
      'android/app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt';
  const kotlinLifecycle =
      'android/app/src/main/kotlin/org/winsvpn/app/WinnV3HostLifecycle.kt';
  const swiftEngine = 'apple/WinsTunnelCore/WinsPacketTunnelEngine.swift';
  const swiftContract = 'apple/WinsTunnelCore/WinsWinn3HostContract.swift';
  const swiftDatapath = 'apple/WinsTunnelCore/WinsWinn3Datapath.swift';
  const goReconnect = 'winn_protocol_experimental/winn3/driver/reconnect.go';
  const goFrameStatus =
      'winn_protocol_experimental/cmd/winn-datapath/winn3_status.go';
  const goCdatapath =
      'winn_protocol_experimental/cdatapath/winn_datapath_winn3.go';
  const goDial = 'winn_protocol_experimental/winn3/carrier/dial.go';
  const goSessionConfig = 'winn_protocol_experimental/winn3/session/config.go';
  const fixturePath = 'test/fixtures/winn3_host_lifecycle_readiness.json';

  Map<String, dynamic> fixture() =>
      jsonDecode(read(fixturePath)) as Map<String, dynamic>;

  /// `Name = "value"` constants of a Go const block, by name prefix.
  Map<String, String> goStringConsts(String source, String prefix) {
    final out = <String, String>{};
    for (final m in RegExp('^\\s*($prefix\\w*)\\s*=\\s*"([^"]*)"',
            multiLine: true)
        .allMatches(source)) {
      out[m.group(1)!] = m.group(2)!;
    }
    return out;
  }

  /// A Go duration or integer constant, in milliseconds (or as a plain count).
  int goConst(String source, String name) {
    final m = RegExp('^\\s*$name\\s*=\\s*([^\\n/]+)', multiLine: true)
        .firstMatch(source);
    expect(m, isNotNull, reason: '$name is not declared where it was');
    final text = m!.group(1)!.trim();
    final duration =
        RegExp(r'^(\d+)\s*\*\s*time\.(Millisecond|Second)$').firstMatch(text);
    if (duration != null) {
      final n = int.parse(duration.group(1)!);
      return duration.group(2) == 'Second' ? n * 1000 : n;
    }
    return int.parse(text);
  }

  /// The body of the first declaration whose signature starts with [signature].
  String body(String source, String signature) {
    final start = source.indexOf(signature);
    expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
    final open = source.indexOf('{', start);
    var depth = 0;
    for (var i = open; i < source.length; i++) {
      final c = source[i];
      if (c == '{') depth++;
      if (c == '}') {
        depth--;
        if (depth == 0) return source.substring(open, i + 1);
      }
    }
    fail('unbalanced $signature');
  }

  /// The literal of the first Swift array whose declaration is [signature].
  String arrayBody(String source, String signature) {
    final start = source.indexOf(signature);
    expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
    final open = source.indexOf('[', start);
    return source.substring(open, source.indexOf(']', open) + 1);
  }

  /// The platform proof the app computes today, before the lifecycle: the
  /// Android composite main.dart feeds `hasPersistedAndroidTunnelProof`.
  bool androidProof(Map<String, dynamic> readiness) =>
      hasPersistedAndroidTunnelProof(
        active: readiness['active'] == true,
        engineReady: readiness['engine_ready'] == true,
        interfaceOpen: readiness['interface_open'] == true,
        vpnPresent: readiness['vpn_present'] == true,
        handshakeRecent: readiness['awg_handshake_recent'] == true,
        awgRxBytes:
            int.tryParse((readiness['awg_rx_bytes'] ?? '0').toString()) ?? 0,
        awgTxBytes:
            int.tryParse((readiness['awg_tx_bytes'] ?? '0').toString()) ?? 0,
      );

  /// What `_readNativeTunnelActive` returns and records for one reading:
  /// a held session is live with no proof; otherwise the proof is both.
  ({bool sessionUp, bool proof}) readNativeTunnelActive(
      Winn3HostLifecycleView lifecycle, bool platformProof) {
    if (lifecycle.holdsSession) return (sessionUp: true, proof: false);
    return (sessionUp: platformProof, proof: platformProof);
  }

  /// The release explanation the app must show for each native limitation.
  const releaseExplanation = <String, String>{
    'disguise_refused_notification': 'The disguise could not show the notification',
    'vpn_permission_revoked': 'VPN permission was withdrawn.',
    'service_destroyed': 'The VPN service was closed.',
  };

  /// The full Android map MainActivity returns for one fixture step.
  Map<String, dynamic> androidReadiness(Map<String, dynamic> step) {
    final composite = (step['composite'] as List).cast<bool>();
    return <String, dynamic>{
      ...(step['readiness'] as Map<String, dynamic>),
      'service_active': composite[0],
      'interface_open': composite[2],
      'vpn_present': composite[2],
      'awg_handshake_recent': true,
      'awg_rx_bytes': 4096,
      'awg_tx_bytes': 4096,
      'winn3_verdict': 'connected',
      'winn3_start_state': 'connected',
    };
  }

  /// The Apple map the app bridge returns for one fixture step.
  Map<String, dynamic> appleReadiness(Map<String, dynamic> step) => <String, dynamic>{
        ...(step['forwarded'] as Map<String, dynamic>),
        'active': true,
        'provider_status_available': true,
        'provider_status_schema_supported': true,
      };

  void expectApp(String name, Winn3HostLifecycleView view,
      Map<String, dynamic> app) {
    expect(view.state.name, app['state'], reason: '$name: state');
    expect(view.holdsSession, app['holds_session'],
        reason: '$name: holds the session');
    expect(view.actionRequired, app['action_required'],
        reason: '$name: action required');
    expect(view.observer, app['observer'] ?? '', reason: '$name: observer');
    expect(view.cause, app['cause'] ?? '', reason: '$name: cause');
    expect(view.limitation, app['limitation'] ?? '',
        reason: '$name: limitation');
    expect(view.releasedWithLimitation, app['released'] ?? false,
        reason: '$name: released with a limitation');
    if (view.releasedWithLimitation) {
      final line = view.statusLine((s) => s)!;
      expect(line, contains('traffic is no longer held'), reason: name);
      expect(line, contains(releaseExplanation[view.limitation]!),
          reason: '$name: the app explains ${view.limitation}');
    }
  }

  group('the Dart status consumer, fed what the native bridges publish', () {
    test('Android: connected, recovering, a later recovery, blocked and held',
        () {
      final steps = (fixture()['android'] as List).cast<Map<String, dynamic>>();
      expect(steps.length, greaterThanOrEqualTo(10),
          reason: 'the fixture was not read; this would be vacuous');
      for (final step in steps) {
        final name = step['step'] as String;
        // The whole map MainActivity returns: the proven claim and lifecycle
        // keys, plus the platform keys the proof reads, set as a live v3
        // session sets them.
        final readiness = androidReadiness(step);
        final view = winn3HostLifecycleFromReadiness(readiness, apple: false);
        final app = step['app'] as Map<String, dynamic>;
        expectApp(name, view, app);
        final reading = readNativeTunnelActive(view, androidProof(readiness));
        expect(reading.proof, app['proof'],
            reason: '$name: connected is painted only when the engine proved it');
        if (view.holdsSession) {
          expect(reading.sessionUp, isTrue,
              reason: '$name: a held session keeps its disconnect control');
        }
        if (reading.proof) {
          expect(view.state,
              anyOf(Winn3HostLifecycleState.connected,
                  Winn3HostLifecycleState.none),
              reason: '$name: proof only for engine-proven connected or legacy');
        }
      }
    });

    test('Apple: connected, recovering, the host ceiling, a later recovery, '
        'engine blocked, present-invalid', () {
      final steps = (fixture()['apple'] as List).cast<Map<String, dynamic>>();
      expect(steps.length, greaterThanOrEqualTo(8));
      for (final step in steps) {
        final name = step['step'] as String;
        final readiness = appleReadiness(step);
        expect(appleTunnelProviderStatusCurrent(readiness), isTrue);
        final view = winn3HostLifecycleFromReadiness(readiness, apple: true);
        expectApp(name, view, step['app'] as Map<String, dynamic>);
      }
    });

    test('Apple: a stale provider document or a down system tunnel holds nothing',
        () {
      final held = <String, dynamic>{
        'active': true,
        'provider_status_available': true,
        'provider_status_schema_supported': true,
        'provider_winn3_recovery_state': 'recovering',
        'provider_winn3_recovery_capture_held': true,
      };
      expect(winn3HostLifecycleFromReadiness(held, apple: true).holdsSession,
          isTrue);
      expect(
          winn3HostLifecycleFromReadiness(
                  {...held, 'provider_status_stale': true},
                  apple: true)
              .holdsSession,
          isFalse);
      expect(
          winn3HostLifecycleFromReadiness({...held, 'active': false},
                  apple: true)
              .holdsSession,
          isFalse);
    });

    test('an unknown lifecycle is blocked, never connected', () {
      final android = winn3HostLifecycleFromReadiness({
        'winn3_lifecycle': 'a-state-nobody-defined',
        'winn3_capture_held': true,
        'interface_open': true,
      }, apple: false);
      expect(android.state, Winn3HostLifecycleState.blocked);
      final apple = winn3HostLifecycleFromReadiness({
        'active': true,
        'provider_status_available': true,
        'provider_status_schema_supported': true,
        'provider_winn3_recovery_state': 7,
        'provider_winn3_recovery_capture_held': true,
      }, apple: true);
      expect(apple.state, Winn3HostLifecycleState.blocked);
      expect(winn3HostLifecycleFromReadiness(null, apple: false),
          Winn3HostLifecycleView.none);
    });

    test('the lifecycle never touches the cover-fallback inputs', () {
      final fallback = read('lib/winn3_cover_fallback.dart');
      for (final key in [
        'winn3_lifecycle',
        'winn3_capture_held',
        'winn3_recovery',
        'winn3_host_lifecycle',
        'Winn3HostLifecycle',
      ]) {
        expect(fallback, isNot(contains(key)),
            reason: 'cover fallback must never read the lifecycle ($key)');
      }
      final consumer = read('lib/winn3_host_lifecycle.dart');
      for (final key in [
        'winn3_verdict',
        'winn3_start_state',
        'winn3_awg_xray_authorization_token',
      ]) {
        expect(consumer, isNot(contains("'$key'")),
            reason: 'the lifecycle consumer must never read $key');
      }
    });
  });

  group('Apple promotion records its proof before exposure', () {
    test('both providers promote through the WinsTunnelCore handoff, before '
        'publishing the datapath', () {
      for (final path in [
        'ios/PacketTunnel/PacketTunnelProvider.swift',
        'macos/PacketTunnel/PacketTunnelProvider.swift',
      ]) {
        final source = read(path);
        final gate = source.indexOf('if datapath.promotionConverged(');
        expect(gate, greaterThan(0), reason: '$path: the shared handoff');
        expect(source,
            isNot(contains('WinsWinn3PromotionGate.converged(engineStatusFields: engineFields)')),
            reason: '$path: no inline static gate left to bypass the handoff');
        final begin = source.indexOf('beginPromotion(engineFields: engineFields)', gate);
        expect(begin, greaterThan(gate), reason: '$path: promotion begins after the handoff');
        expect(source, contains('self.winn3Datapath = datapath'),
            reason: '$path: the publication the handoff precedes');
      }
      final datapath = read(swiftDatapath);
      final wrapper = body(datapath, 'func promotionConverged(');
      expect(wrapper, contains('history: lifecycleHistory'));
      final contract = read(swiftContract);
      final handoff = body(contract, 'static func promotionConverged(');
      expect(handoff, contains('WinsWinn3PromotionGate.converged(engineStatusFields: fields)'));
      expect(handoff, contains('history.recordPromotion('));
    });
  });

  group('the Dart control, driven by every fixture step', () {
    Future<void> expectControls(WidgetTester tester, String name,
        Winn3HostLifecycleView view, Map<String, dynamic> app) async {
      var disconnects = 0;
      var reconnects = 0;
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: Winn3HostLifecycleBanner(
            lifecycle: view,
            translate: (s) => s,
            enabled: true,
            onDisconnect: () => disconnects++,
            onReconnect: () => reconnects++,
          ),
        ),
      ));
      final held = app['holds_session'] == true;
      expect(find.byKey(const Key('winn3_host_lifecycle_disconnect')),
          held ? findsOneWidget : findsNothing,
          reason: '$name: Disconnect');
      expect(find.byKey(const Key('winn3_host_lifecycle_reconnect')),
          held ? findsOneWidget : findsNothing,
          reason: '$name: Reconnect');
      if (held) {
        await tester.tap(find.byKey(const Key('winn3_host_lifecycle_disconnect')));
        await tester.tap(find.byKey(const Key('winn3_host_lifecycle_reconnect')));
        expect(disconnects, 1, reason: name);
        expect(reconnects, 1, reason: name);
      }
      final shown = find.byKey(const Key('winn3_host_lifecycle_status'));
      final showsLine = held || (app['released'] == true);
      expect(shown, showsLine ? findsOneWidget : findsNothing,
          reason: '$name: status line');
    }

    testWidgets('Android steps, sampler through readiness to the controls',
        (tester) async {
      for (final step
          in (fixture()['android'] as List).cast<Map<String, dynamic>>()) {
        final view = winn3HostLifecycleFromReadiness(androidReadiness(step), apple: false);
        await expectControls(tester, step['step'] as String, view,
            step['app'] as Map<String, dynamic>);
      }
    });

    testWidgets('Apple steps, sampler through host fields to the controls, '
        'including recovery after stopped, connecting and disappearance',
        (tester) async {
      final steps = (fixture()['apple'] as List).cast<Map<String, dynamic>>();
      final names = steps.map((s) => s['step']).toList();
      for (final required in [
        'stopped_after_proof',
        'connected_after_stopped',
        'connecting_after_proof',
        'lifecycle_disappears',
        'connected_after_disappearance',
        // Promotion by the providers' own gate, with NO connected health
        // sample, then each first sample, then recovery.
        for (final tag in [
          'stopped',
          'connecting',
          'missing_lifecycle',
          'unavailable_sample'
        ]) ...[
          'promoted_by_gate_then_$tag',
          'first_sample_after_promotion_$tag',
          'recovered_after_promotion_$tag',
        ],
      ]) {
        expect(names, contains(required));
      }
      for (final step in steps) {
        final view = winn3HostLifecycleFromReadiness(appleReadiness(step), apple: true);
        await expectControls(tester, step['step'] as String, view,
            step['app'] as Map<String, dynamic>);
      }
    });
  });

  group('the dashboard banner', () {
    String t(String s) => s;

    Future<void> pump(WidgetTester tester, Winn3HostLifecycleView view,
        {required VoidCallback onDisconnect,
        required VoidCallback onReconnect,
        bool enabled = true}) {
      return tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: Winn3HostLifecycleBanner(
            lifecycle: view,
            translate: t,
            enabled: enabled,
            onDisconnect: onDisconnect,
            onReconnect: onReconnect,
          ),
        ),
      ));
    }

    testWidgets('recovering says so and keeps both controls usable',
        (tester) async {
      var disconnects = 0;
      var reconnects = 0;
      await pump(
        tester,
        const Winn3HostLifecycleView(
            state: Winn3HostLifecycleState.recovering, captureHeld: true),
        onDisconnect: () => disconnects++,
        onReconnect: () => reconnects++,
      );
      expect(find.textContaining('Reconnecting...'), findsOneWidget);
      final disclosure = tester
          .widget<Text>(find.byKey(const Key('winn3_host_lifecycle_reconnect_disclosure')))
          .data!;
      expect(disclosure, winn3ReconnectReleaseDisclosure);
      expect(disclosure, contains('no longer held'));
      for (final claim in ['brief', 'bounded', 'moment', 'second']) {
        expect(disclosure.toLowerCase(), isNot(contains(claim)),
            reason: 'the release interval is not measured: $claim');
      }
      await tester.tap(find.byKey(const Key('winn3_host_lifecycle_disconnect')));
      await tester.tap(find.byKey(const Key('winn3_host_lifecycle_reconnect')));
      expect(disconnects, 1);
      expect(reconnects, 1);
    });

    testWidgets('blocked is action-required and names who observed it',
        (tester) async {
      for (final entry in {
        'engine': 'Could not reconnect.',
        'recovery_ceiling': 'Reconnecting is taking too long.',
        'session_ended': 'The tunnel stopped.',
        'invalid_status': 'does not recognise',
        'invalid_transition': 'does not accept',
      }.entries) {
        await pump(
          tester,
          Winn3HostLifecycleView(
              state: Winn3HostLifecycleState.blocked,
              captureHeld: true,
              observer: entry.key),
          onDisconnect: () {},
          onReconnect: () {},
        );
        final text = tester
            .widget<Text>(find.byKey(const Key('winn3_host_lifecycle_status')))
            .data!;
        expect(text, contains(entry.value), reason: entry.key);
        expect(text, contains('Reconnect or disconnect.'));
        for (final claim in ['censor', 'revoked', 'banned', 'Connected']) {
          expect(text, isNot(contains(claim)), reason: '${entry.key}: $claim');
        }
        expect(find.byKey(const Key('winn3_host_lifecycle_disconnect')),
            findsOneWidget);
        expect(find.byKey(const Key('winn3_host_lifecycle_reconnect')),
            findsOneWidget);
        expect(find.byKey(const Key('winn3_host_lifecycle_reconnect_disclosure')),
            findsOneWidget);
      }
    });

    testWidgets('a hold the platform could not keep is said out loud',
        (tester) async {
      await pump(
        tester,
        const Winn3HostLifecycleView(
            state: Winn3HostLifecycleState.blocked,
            captureHeld: false,
            observer: 'session_ended',
            limitation: 'disguise_refused_notification'),
        onDisconnect: () {},
        onReconnect: () {},
      );
      expect(find.textContaining('may now leave outside the VPN'),
          findsOneWidget);
      expect(find.textContaining('disguise'), findsOneWidget);
      expect(find.byKey(const Key('winn3_host_lifecycle_disconnect')),
          findsNothing);
      await pump(
        tester,
        const Winn3HostLifecycleView(
            state: Winn3HostLifecycleState.blocked,
            captureHeld: true,
            observer: 'session_ended',
            limitation: 'foreground_refresh_failed'),
        onDisconnect: () {},
        onReconnect: () {},
      );
      expect(find.textContaining('Android may end the hold'), findsOneWidget);
    });

    testWidgets('connected and none render nothing', (tester) async {
      for (final view in [
        Winn3HostLifecycleView.none,
        const Winn3HostLifecycleView(state: Winn3HostLifecycleState.connected),
      ]) {
        await pump(tester, view, onDisconnect: () {}, onReconnect: () {});
        expect(find.byKey(const Key('winn3_host_lifecycle_status')),
            findsNothing);
      }
    });
  });

  group('where the app reads it', () {
    test('main.dart reads the lifecycle on both platforms and holds, never '
        'paints, a held session', () {
      final source = read('lib/main.dart');
      final nativeRead =
          body(source, 'Future<bool> _readNativeTunnelActive()');
      expect(
          'if (_observeWinn3HostLifecycle(readiness)) return _recordedHeldSession();'
              .allMatches(nativeRead)
              .length,
          1,
          reason: 'the Apple branch');
      expect(nativeRead, contains('if (_observeWinn3HostLifecycle(readiness)) {'),
          reason: 'the Android branch');
      final held = body(source, 'bool _recordedHeldSession()');
      expect(held, contains('_recordNativeTunnelProof(false)'),
          reason: 'a held session records NO proof');
      expect(held, contains('return true'));
      final dashboardStart = source.indexOf('Widget _buildVpnDashboard(');
      final dashboard = source.substring(dashboardStart,
          source.indexOf('final Widget settingsCenter', dashboardStart));
      expect(dashboard, contains('Winn3HostLifecycleBanner('));
      expect(dashboard,
          contains('onDisconnect: () => unawaited(_disconnectHeldWinn3Session())'));
      expect(dashboard,
          // Round L (OI-L4): a held Reconnect waits for the release
          // acknowledgement before it prepares anything; the settings
          // restart it used before does not.
          contains('onReconnect: () => unawaited(_reconnectHeldWinn3Session())'));
    });
  });

  group('Round A3 v3: session existence, capture custody and connected proof',
      () {
    test('the three readings are kept apart', () {
      const held = Winn3NativeTunnelReading(sessionExists: true, heldSession: true);
      expect(held.sessionExists, isTrue);
      expect(held.connectedProof, isFalse,
          reason: 'a held session is a session, never connected proof');
      const live = Winn3NativeTunnelReading(sessionExists: true, heldSession: false);
      expect(live.connectedProof, isTrue);
      const none = Winn3NativeTunnelReading(sessionExists: false, heldSession: false);
      expect(none.connectedProof, isFalse);
    });

    test('Apple smoke diagnostics require connected proof and report a held '
        'session separately', () {
      final source = read('lib/main.dart');
      final start = source.indexOf("'phase': 'connected_probe_complete'");
      expect(start, greaterThan(0));
      final smoke = source.substring(source.lastIndexOf('final probeSnapshot', start), start);
      expect(smoke, contains('final connected = await _readNativeTunnelConnectedProof();'));
      expect(smoke, isNot(contains('await _readNativeTunnelActive()')));
      expect(smoke, contains('final passed = ready &&\n        connected &&'));
      final payload = source.substring(start, source.indexOf('};', start));
      expect(payload, contains("'connected': connected,"));
      expect(payload, contains("'winn3_held_session': heldSession,"));
      final proof = body(source, 'Future<bool> _readNativeTunnelConnectedProof()');
      expect(proof, contains('heldSession: _winn3HostLifecycle.holdsSession'));
      expect(proof, contains('.connectedProof'));
    });

    test('the "secured" label never describes a held session', () {
      final source = read('lib/main.dart');
      final fetch = body(source, 'Future<void> _fetchLiveNetworkIp()');
      final held = fetch.indexOf(
          'if (_supportsNativeTunnelReadiness && _winn3HostLifecycle.holdsSession) return;');
      expect(held, greaterThan(0));
      expect(held, lessThan(fetch.indexOf('Traffic Secured & Obfuscated')));
    });

    test('every _readNativeTunnelActive() caller is on the audited list', () {
      final source = read('lib/main.dart');
      final callers = RegExp(r'_readNativeTunnelActive\(\)')
          .allMatches(source)
          .length;
      // The definition, the proof reader, and the eleven session-existence
      // callers classified in the contract comment above it. A new caller
      // must be classified there first. Round L added the held reconnect's
      // reading after an unproven release (session existence).
      expect(callers, 13,
          reason: 'classify a new caller as session existence or connected proof');
    });

    test('the held Disconnect is its own action that skips the update and '
        'maintenance gates (executed in native_reconciliation_ownership_test)',
        () {
      final source = read('lib/main.dart');
      final held = body(source, 'Future<void> _disconnectHeldWinn3Session()');
      expect(held, contains('_winn3HeldDisconnectPending = true;'));
      expect(held, contains('await _toggleVpnConnection();'));
      final toggle = body(source, 'Future<void> _toggleVpnConnection()');
      final latch = toggle.indexOf('final heldDisconnect = _winn3HeldDisconnectPending;');
      expect(latch, greaterThanOrEqualTo(0));
      expect(latch, lessThan(toggle.indexOf('_appUpdateRequired')),
          reason: 'the latch is read before the first gate');
      final update = toggle.indexOf('if (_appUpdateRequired && !_isConnected) {');
      final maintenance = toggle.indexOf('if (_isUnderMaintenance && !_isConnected) {');
      expect(toggle.indexOf('if (!heldDisconnect) {', update),
          lessThan(toggle.indexOf('_promptAppUpdateRequired()', update)));
      expect(toggle.indexOf('if (!heldDisconnect) {', maintenance),
          lessThan(toggle.indexOf('Maintenance in progress', maintenance)));
      expect(toggle, contains('if (heldDisconnect && !_isConnected) return;'),
          reason: 'the held Disconnect can never start a connect');
    });
  });

  group('one vocabulary', () {
    test('Kotlin and Swift spell every Go lifecycle state', () {
      final go = read(goReconnect);
      final states = goStringConsts(go, 'Lifecycle')
        ..removeWhere((k, _) => k.startsWith('LifecycleCause'));
      final causes = goStringConsts(go, 'LifecycleCause');
      expect(states.values.toSet(),
          {'connecting', 'connected', 'recovering', 'blocked', 'stopped'});
      expect(causes.values.toSet(),
          {'never_established', 'budget_spent', 'terminal'});

      final kotlinEnum =
          body(read(kotlinGate), 'internal enum class WinnV3Lifecycle(');
      for (final state in states.values) {
        expect(kotlinEnum, contains('("$state")'));
      }
      final swift = read(swiftContract);
      final swiftEnum = body(swift, 'enum State: String, CaseIterable');
      for (final state in states.values) {
        expect(swiftEnum, contains('case $state'));
      }
      // The Apple sampler's vocabulary is the Go vocabulary, exactly.
      final engine = read(swiftEngine);
      final vocab = engine.substring(
          engine.indexOf('static let engineVocabularyFields'),
          engine.indexOf('static let invalidVocabularySuffix'));
      for (final value in [...states.values, ...causes.values]) {
        expect(vocab, contains('"$value"'), reason: 'Apple sampler: $value');
      }
    });

    test('the key names are the engine json tags', () {
      final frame = read(goFrameStatus);
      expect(frame, contains('`json:"lifecycle,omitempty"`'));
      expect(frame, contains('`json:"lifecycle_cause,omitempty"`'));
      final kotlin = read(kotlinGate);
      expect(kotlin, contains('const val KEY_LIFECYCLE = "lifecycle"'));
      expect(kotlin,
          contains('const val KEY_LIFECYCLE_CAUSE = "lifecycle_cause"'));
      final cdatapath = read(goCdatapath);
      expect(cdatapath, contains('`json:"winn3_lifecycle,omitempty"`'));
      expect(cdatapath, contains('`json:"winn3_lifecycle_cause,omitempty"`'));
    });

    test('every published Apple key clears the sampler denylist', () {
      final engine = read(swiftEngine);
      final deny = arrayBody(
          engine, 'private static let deniedRuntimeStatusFragments = [');
      final denied = RegExp(r'"([a-z0-9]+)"')
          .allMatches(deny)
          .map((m) => m.group(1)!)
          .toSet();
      expect(denied, contains('host'),
          reason: 'the denylist was not parsed; this guard would be vacuous');
      final prefix = RegExp(r'static let engineFieldPrefix = "([a-z0-9_]+)"')
          .firstMatch(engine)!
          .group(1)!;
      for (final key in [
        'winn3_lifecycle',
        'winn3_lifecycle_cause',
        'winn3_lifecycle_invalid',
        'winn3_lifecycle_cause_invalid',
      ]) {
        final tokens = '$prefix$key'.split(RegExp(r'[_-]'));
        expect(tokens.where(denied.contains), isEmpty,
            reason: '$prefix$key is eaten by deniedRuntimeStatusFragments');
      }
      final hostKeys = arrayBody(read(swiftContract), 'static let hostStatusKeys = [');
      for (final m in RegExp(r'"([a-z0-9_]+)"').allMatches(hostKeys)) {
        expect(m.group(1)!.split('_').where(denied.contains), isEmpty,
            reason: '${m.group(1)} carries a denied token');
      }
      for (final value in [
        'never_established',
        'budget_spent',
        'terminal',
        'recovery_ceiling',
        'invalid_status',
        'not_live',
        'unreported'
      ]) {
        expect(value.split('_').where(denied.contains), isEmpty,
            reason: 'the value $value is eaten by the value filter');
      }
    });

    test('both app forwarders derive their list from publishedStatusKeys', () {
      for (final path in [
        'ios/Runner/AppDelegate.swift',
        'macos/Runner/MainFlutterWindow.swift',
      ]) {
        final source = read(path);
        expect(source,
            contains('for source in WinsWinnSeamObservability.publishedStatusKeys {'),
            reason: path);
        expect(source, contains('fields["provider_" + source] = mappedValue'),
            reason: path);
      }
      final engine = read(swiftEngine);
      final published = body(engine, 'static var publishedStatusKeys: [String]');
      expect(published, contains('WinsWinn3Lifecycle.hostStatusKeys'));
      expect(published, contains('engineVocabularyFields'));
    });
  });

  group('the host ceiling is the engine constants', () {
    test('Kotlin and Swift carry the Go constants the model is built on', () {
      final dial = read(goDial);
      final session = read(goSessionConfig);
      final rounds = goConst(dial, 'DefaultBackoffAttempts');
      final backoffCapMs = goConst(dial, 'DefaultBackoffCap');
      final retryBaseMs = goConst(session, 'DefaultRetryBase');
      final retryCapMs = goConst(session, 'DefaultRetryCap');
      final retryAttempts = goConst(session, 'DefaultRetryAttempts');

      var total = 0;
      var window = retryBaseMs;
      for (var i = 0; i < retryAttempts; i++) {
        total += window;
        if (window < retryCapMs) {
          window = window * 2 > retryCapMs ? retryCapMs : window * 2;
        }
      }
      final handshakeBudgetMs = total + retryCapMs;
      expect(handshakeBudgetMs, 23500);
      expect(rounds * handshakeBudgetMs + rounds * backoffCapMs, 157500);

      final kotlin = read(kotlinLifecycle);
      expect(kotlin, contains('const val SUPERVISOR_ROUNDS = $rounds'));
      expect(kotlin,
          contains('const val SUPERVISOR_BACKOFF_CAP_MS = ${_ms(backoffCapMs)}'));
      expect(kotlin,
          contains('const val SESSION_RETRY_BASE_MS = ${_ms(retryBaseMs)}'));
      expect(
          kotlin, contains('const val SESSION_RETRY_CAP_MS = ${_ms(retryCapMs)}'));
      expect(kotlin,
          contains('const val SESSION_RETRY_ATTEMPTS = $retryAttempts'));

      final swift = read(swiftContract);
      expect(swift, contains('static let supervisorRounds = $rounds'));
      expect(
          swift,
          contains(
              'supervisorBackoffCapSeconds: TimeInterval = ${backoffCapMs ~/ 1000}'));
      expect(swift,
          contains('sessionRetryBaseSeconds: TimeInterval = ${retryBaseMs / 1000}'));
      expect(swift,
          contains('sessionRetryCapSeconds: TimeInterval = ${retryCapMs ~/ 1000}'));
      expect(swift, contains('static let sessionRetryAttempts = $retryAttempts'));
    });

    test('the ceiling is described as a host policy, never a proven bound', () {
      for (final path in [kotlinLifecycle, swiftContract]) {
        final source = read(path).toLowerCase();
        expect(source, isNot(contains('can only ever fire late')), reason: path);
        expect(source, isNot(contains('never early')), reason: path);
        expect(source, contains('not a proven upper bound'), reason: path);
      }
    });

    test('the Apple recovery clock reads no wall clock', () {
      final swift = read(swiftContract);
      final clock = body(swift, 'final class WinsWinn3RecoveryClock');
      expect(clock, isNot(contains('Date')));
      expect(clock, contains('DispatchTime.now()'));
      final datapath = read(swiftDatapath);
      final snapshot = body(datapath, 'func healthSnapshot()');
      expect(snapshot, isNot(contains('Date()')));
      expect(snapshot, contains('WinsWinn3Lifecycle.hostStatus('));
    });
  });

  group('Android wiring', () {
    test('the readiness map and isTunnelHealthy share the lifecycle claim', () {
      final activity = read(kotlinActivity);
      final readiness = body(activity, 'private fun buildTunnelReadiness()');
      expect(readiness,
          contains('VpnTunnelService.currentReadinessClaimFields()'));
      expect(readiness, isNot(contains('"active" to')));
      expect(readiness, isNot(contains('"tunnel_healthy" to')));
      expect(readiness, isNot(contains('"engine_ready" to')));
      final service = read(kotlinService);
      final healthy = service.substring(service.indexOf('fun isTunnelHealthy()'),
          service.indexOf('fun isTunnelHealthy()') + 300);
      expect(healthy, contains('winn3HostLifecycle.snapshot()'));
    });

    test('the post-promotion loop publishes only while it owns the tunnel', () {
      final thread =
          body(read(kotlinService), 'private fun startWinnV3EngineThread(');
      final loop = thread.substring(thread.indexOf('Thread.sleep(1000)'));
      final publish = loop.indexOf('WinnV3PostPromotionStep.publish(');
      final ownership = loop.indexOf(
          'stillOwner = !tearingDown && lifecycleBinding.owner == tunnelGeneration', publish);
      expect(publish, greaterThan(0));
      expect(ownership, greaterThan(publish),
          reason: 'ownership is re-checked after the sleep, in the publication');
      expect(loop.indexOf('synchronized(winnEngineLock)'), lessThan(publish),
          reason: 'under the teardown lock');
      expect(loop, contains('prober.onVerdict(verdict)'));
      expect(thread, isNot(contains('RECOVERY_PROBE_INTERVAL_MS')));
    });
  });
}

/// A Kotlin Long literal for [ms], spelled the way the source spells it.
String _ms(int ms) {
  final text = ms.toString();
  final grouped = text.length > 3
      ? '${text.substring(0, text.length - 3)}_${text.substring(text.length - 3)}'
      : text;
  return '${grouped}L';
}
