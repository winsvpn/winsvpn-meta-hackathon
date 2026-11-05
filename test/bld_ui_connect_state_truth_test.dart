/// Exercises the connect/disconnect UI truth contract: the green "connected"
/// claim on every native platform must be impossible while the tunnel is down.
///
/// Two kinds of tests live here:
///   * source-structure tests that read `lib/main.dart` as text, so a future
///     edit that untethers a display site from the verified-live proof fails
///     here even if it compiles;
///   * widget tests for the power control, and a compile gate (the import of
///     `package:wins_vpn/main.dart`) that makes this whole file proof that the
///     app still compiles, since `flutter analyze` cannot be trusted in this
///     tree.
///
/// Failure direction matters: every assertion here must FAIL when a lane
/// reconnects a green claim to a stale `_isConnected` or to an in-flight
/// optimistic write. The negative `isNot` assertions are the ones with teeth.
library;

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
// Compile gate by design: importing the app's entry point forces lib/main.dart
// to compile in this test's batch, which the header above documents as the
// only trustworthy compile check in this tree. The analyzer cannot see that
// intent, so the unused-import warning is suppressed rather than removed.
// ignore: unused_import
import 'package:wins_vpn/main.dart';
import 'package:wins_vpn/vpn_power_control.dart';

String _normalizeSourceWhitespace(String source) => source
    .replaceAll(RegExp(r'\s+'), ' ')
    .replaceAll(RegExp(r'\(\s+'), '(')
    .replaceAll(RegExp(r'\s+\)'), ')')
    .trim();

/// Extracts the body of a method starting at the first occurrence of
/// [signature], walking to the first `{` after the parameter list and then to
/// brace depth 0. Named-parameter blocks (`{ ... }`) would otherwise balance
/// on their own and truncate the extract.
String _functionBody(String source, String signature) {
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: 'could not find $signature');

  var cursor = start;
  var parenDepth = 0;
  var sawParen = false;
  while (cursor < source.length) {
    final ch = source[cursor];
    if (ch == '(') {
      parenDepth++;
      sawParen = true;
    } else if (ch == ')') {
      parenDepth--;
      if (sawParen && parenDepth == 0) break;
    }
    cursor++;
  }
  expect(sawParen && parenDepth == 0, isTrue,
      reason: 'unterminated parameter list for $signature');

  final bodyOpen = source.indexOf('{', cursor);
  expect(bodyOpen, greaterThan(cursor), reason: 'no body for $signature');

  var depth = 0;
  for (var i = bodyOpen; i < source.length; i++) {
    if (source[i] == '{') depth++;
    if (source[i] == '}') {
      depth--;
      if (depth == 0) return source.substring(start, i + 1);
    }
  }
  fail('unterminated function for signature: $signature');
}

void main() {
  test('the app still compiles (compile gate)', () {
    // Importing package:wins_vpn/main.dart above already compiled the whole
    // app; this test pins that a _fresh_ build of the file under test succeeds.
    expect(File('lib/main.dart').existsSync(), isTrue);
  });

  group('_readNativeTunnelActive is a live truth source on every platform', () {
    test('Windows and Linux consult their native backend, never self-mirror',
        () {
      final source = File('lib/main.dart').readAsStringSync();
      final read =
          _functionBody(source, 'Future<bool> _readNativeTunnelActive()');
      final windowsMarker =
          read.indexOf('Platform.isWindows || Platform.isLinux');
      expect(windowsMarker, greaterThanOrEqualTo(0),
          reason: 'desktop platforms must have a dedicated live branch');
      final desktop = read.substring(windowsMarker);
      expect(desktop, contains('getTunnelReadiness'));
      expect(desktop, contains('active'));
      // No code path may self-mirror the prior boolean: the desktop branch
      // must not fall back to _isConnected (e.g. `active ?? _isConnected`).
      expect(read, isNot(contains('active ?? _isConnected')));
      // Exactly one `return _isConnected;` (the web fallback) is allowed.
      expect(RegExp(r'return _isConnected;').allMatches(read).length, 1);
    });

    test('an unreadable bridge fails CLOSED on every native platform', () {
      final source = File('lib/main.dart').readAsStringSync();
      final read =
          _functionBody(source, 'Future<bool> _readNativeTunnelActive()');
      // Every native result -- including a failed fallback read -- must be
      // pushed through the proof recorder, so a future green can never reuse a
      // pre-failure stale proof. A thrown/absent read is recorded as down.
      expect(read, contains('_recordedTunnelProof(active ?? false)'));
      expect(read, contains('_recordedTunnelProof(false)'));
      expect(read, contains('_recordedTunnelProof(active)'));
      // The test's own legacy phrasing must not survive: a bare
      // `return active ?? false;` bypasses the proof recorder entirely.
      expect(read, isNot(contains('return active ?? false;')));
      // The only path that may keep the previous boolean is the web fallback.
      expect(RegExp(r'return _isConnected;').allMatches(read).length, 1);
    });
  });

  group('the heartbeat polls real tunnel state on every native platform', () {
    test('the poll gate covers all native platforms and the read is scoped',
        () {
      final source = File('lib/main.dart').readAsStringSync();
      final heartbeat =
          _functionBody(source, 'Future<void> _runStatusHeartbeat()');
      expect(heartbeat, contains('pollsNativeTunnelState'));
      expect(heartbeat, contains('_supportsNativeTunnelReadiness'));
      expect(
        heartbeat,
        isNot(contains('Platform.isAndroid || _isApplePlatform')),
      );
      final gate = heartbeat.indexOf('pollsNativeTunnelState');
      final nativeRead = heartbeat.indexOf('_readNativeTunnelActive()');
      expect(nativeRead, greaterThan(gate));
    });
  });

  group('a dedicated proof pump keeps the display proof fresh unconditionally',
      () {
    test('the pump exists, is native-scoped, and never writes session state',
        () {
      final source = File('lib/main.dart').readAsStringSync();
      final pump = _functionBody(source, 'Future<void> _pumpTunnelProof()');
      expect(pump, contains('_readNativeTunnelActive()'));
      expect(pump, contains('_supportsNativeTunnelReadiness'));
      expect(pump, contains('_proofPumpRunning'));
      // The pump only freshens the display proof. It must NEVER flip
      // _isConnected/_isLoggedIn, or a logged-out or loading UI could be
      // walked into a session it never started.
      expect(pump, isNot(contains('_isConnected')));
      expect(pump, isNot(contains('_isLoggedIn')));
    });

    test('the heartbeat start also arms the proof pump', () {
      final source = File('lib/main.dart').readAsStringSync();
      final start = _functionBody(source, 'void _startStatusHeartbeat()');
      expect(start, contains('_proofTimer = Timer.periodic'));
      expect(start, contains('_pumpTunnelProof'));
    });
  });

  group('no optimistic green is ever painted from an in-flight claim', () {
    test('_switchConnectedServer never writes _isConnected = true', () {
      final source = File('lib/main.dart').readAsStringSync();
      final fn = _functionBody(source, 'Future<void> _switchConnectedServer(');
      expect(fn, isNot(contains('_isConnected = true')));
      expect(fn, contains('_readNativeTunnelActive()'));
      expect(fn, contains('_isVpnConnectInFlight = true'));
      expect(fn, contains('_supportsNativeTunnelReadiness'));
    });

    test('the toggle teardown-failure path reflects the live backend', () {
      final source = File('lib/main.dart').readAsStringSync();
      final toggle =
          _functionBody(source, 'Future<void> _toggleVpnConnection() async');
      final failureSite =
          toggle.indexOf('Still disconnecting. Try again in a moment.');
      expect(failureSite, greaterThanOrEqualTo(0));
      final after = toggle.substring(failureSite);
      expect(after, contains('_readNativeTunnelActive()'));
      expect(after, isNot(contains('_isConnected = true')));
    });
  });

  group('the green claim is gated to verified, fresh, non-transition state',
      () {
    test('_rendersConnected requires a fresh native liveness proof', () {
      final source = File('lib/main.dart').readAsStringSync();
      final normalizedSource = _normalizeSourceWhitespace(source);
      expect(source, contains('bool get _rendersConnected {'));
      expect(
        normalizedSource,
        contains(
            '_latestTunnelProof.activeWithin(DateTime.now(), _tunnelProofMaxFreshness)'),
      );
      expect(source, contains('_supportsNativeTunnelReadiness'));
      expect(
        source,
        isNot(contains('bool get _rendersConnected =>')),
        reason: '_rendersConnected must not be a bare bool equality -- the '
            'freshness proof cannot be bypassed by an early `=>`',
      );
      expect(
        normalizedSource,
        contains(
            '_isConnected && !_isVpnConnectInFlight && !_isTunnelTransitioning'),
      );
    });

    test('only _recordNativeTunnelProof may advance the proof timestamp', () {
      final source = File('lib/main.dart').readAsStringSync();
      final writes =
          RegExp(r'_latestTunnelProof\s*=').allMatches(source).length;
      expect(writes, greaterThanOrEqualTo(1));
      final recordBody =
          _functionBody(source, 'void _recordNativeTunnelProof(bool active)');
      expect(recordBody, contains('probedAt: DateTime.now()'));
      expect(recordBody, contains('active: active'));
    });

    test('the connect commit records a native proof, not an optimistic flag',
        () {
      final source = File('lib/main.dart').readAsStringSync();
      final proofSite = source.indexOf('_recordNativeTunnelProof(stillActive)');
      expect(proofSite, greaterThanOrEqualTo(0),
          reason: 'the connector commit site must record a fresh native proof');
      // The backend answer becomes a fresh proof BEFORE the optimistic
      // _isConnected = true lands, so the green can never be painted by a flag
      // whose proof is older than the tunnel it describes.
      final region = source.substring(proofSite, proofSite + 4000);
      final flagSite = region.indexOf('_isConnected = true');
      expect(flagSite,
          greaterThan(region.indexOf('_recordNativeTunnelProof(stillActive)')),
          reason: 'the proof must be recorded before the green flag is set');
    });

    test('the secured status line cannot be repainted from a stale claim', () {
      final source = File('lib/main.dart').readAsStringSync();
      // The render site must interpolate the guarded line, never the raw
      // _ipAfterVpn that a stale reconcile could leave claiming "secured".
      // Brace style ($x vs ${x}) is not part of the contract; WHICH variable
      // is rendered is.
      final statusSite = source.indexOf('"Status:")}');
      expect(statusSite, greaterThanOrEqualTo(0),
          reason: 'the Status: render site must still exist');
      final statusLine = source.substring(statusSite, statusSite + 120);
      expect(statusLine, contains('_statusLineText'));
      expect(statusLine, isNot(contains('_ipAfterVpn')));
      final lineBody = _functionBody(source, 'String get _statusLineText');
      expect(lineBody, contains('_rendersConnected'));
      expect(lineBody, contains('secured'));
      expect(lineBody, contains('obfuscated'));
    });

    test('the watch state mirrors the display gate, not the raw bool', () {
      final source = File('lib/main.dart').readAsStringSync();
      final publish = _functionBody(source, 'void _publishWatchState()');
      expect(publish, contains('_rendersConnected'));
      expect(publish, isNot(contains('else if (_isConnected)')),
          reason: 'the watch must not report connected off the raw cached '
              'bool; it must require the same display gate the screen uses');
      expect(publish, contains('_lastAppleTunnelNeedsPermissionApproval'));
    });
  });

  group(
      'VpnPowerControl widget never shows the connected color while in '
      'flight', () {
    const green = Color(0xFF046A38);
    const red = Color(0xFFDE2910);

    Widget harness(bool isConnected, bool isConnectInFlight) {
      return MaterialApp(
        home: Scaffold(
          body: VpnPowerControl(
            isConnected: isConnected,
            isConnectInFlight: isConnectInFlight,
            connectedColor: green,
            disconnectedColor: red,
            onPressed: () {},
          ),
        ),
      );
    }

    testWidgets('connected + in-flight renders disconnected (never green)',
        (tester) async {
      await tester.pumpWidget(harness(true, true));
      final icon = tester.widget<Icon>(find.byType(Icon));
      expect(icon.color, red,
          reason: 'a connection in flight must never render the green claim');
      expect(icon.icon, Icons.close);
    });

    testWidgets('connected + settled renders green', (tester) async {
      await tester.pumpWidget(harness(true, false));
      final icon = tester.widget<Icon>(find.byType(Icon));
      expect(icon.color, green);
      expect(icon.icon, Icons.power_settings_new);
    });

    testWidgets('disconnected renders red', (tester) async {
      await tester.pumpWidget(harness(false, false));
      final icon = tester.widget<Icon>(find.byType(Icon));
      expect(icon.color, red);
    });
  });
}
