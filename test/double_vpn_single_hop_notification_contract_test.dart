// Android ongoing notification and its restart: a wanted Double VPN that is
// running on one hop is never silent. A source contract across Dart and Kotlin.
//
// The dashboard line (double_vpn_single_hop_visible_test.dart) is not on screen
// while the app is closed, and the notification is the one surface that is. The
// Android service has no idea Double VPN exists, so the app hands it two facts
// it keeps for itself:
//
//   * the ROUTE of the config it is starting, `DoubleVpnRoute = two-hop |
//     single-hop` in the [WinsApp] section, written on every Android start. It
//     travels inside the config, so the saved restart config carries it;
//   * the user's CURRENT CHOICE, in a record of its own (`route_intent.txt`,
//     "1" or "0"), written whenever the choice changes, when settings load and
//     at every start, and removed with the rest of the restart state.
//
// At every start AND every system restart (START_STICKY, always-on) the service
// combines them: marked when the route says single hop and the user has not
// said no. A genuine Double VPN config is never marked; an older config with no
// route is never marked; an unreadable choice counts as wanted. The service
// reports the result in `getTunnelReadiness` and the dashboard takes it from
// there, so both surfaces read one fact. A disguised notification is the
// ordinary one whatever the route is (owner ruling 2026-10-23).

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _read(String path) => File(path).readAsStringSync();

const String _service =
    'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt';

String _constant(String kotlin, String name) {
  final match = RegExp('const val $name = "([^"]*)"').firstMatch(kotlin);
  expect(match, isNotNull, reason: '$name is not declared in $_service');
  return match!.group(1)!;
}

String _method(String source, String start, String end) {
  final first = source.indexOf(start);
  expect(first, greaterThanOrEqualTo(0), reason: start);
  final last = source.indexOf(end, first + start.length);
  expect(last, greaterThan(first), reason: end);
  return source.substring(first, last);
}

void main() {
  late final String mainSource;
  late final String kotlin;

  setUpAll(() {
    mainSource = _read('lib/main.dart');
    kotlin = _read(_service);
  });

  group('Dart hands the service the route and the choice', () {
    test('Android canonical settings writes await native completion', () {
      final writer = _method(
        mainSource,
        'Future<void> _writeSensitiveText(',
        'Future<void> _deleteSensitiveText(',
      );
      expect(writer,
          contains("Platform.isAndroid && name == 'vpn_settings.txt'"));
      expect(writer, contains('? await write'));
      expect(writer, contains(': await write.timeout(const Duration(seconds: 4))'));
    });

    test('the raw config carries the route on Android only, two values only',
        () {
      final writer = _method(
        mainSource,
        'String _buildRawAmneziaConfig(',
        '\n[Peer]\n',
      );
      final decl = RegExp(
        r"final String doubleVpnRouteLine = Platform\.isAndroid &&\s*"
        r"\(config\['double_vpn_route'\] == doubleVpnRouteTwoHop \|\|\s*"
        r"config\['double_vpn_route'\] == doubleVpnRouteSingleHop\)\s*"
        r"\?\s*'\\nDoubleVpnRoute = \$\{config\['double_vpn_route'\]\}'\s*"
        r":\s*'';",
      ).firstMatch(writer);
      expect(decl, isNotNull,
          reason: 'expected an Android-gated, whitelisted DoubleVpnRoute line');
      final section = writer.indexOf('[WinsApp]');
      final use = writer.indexOf(r'$windowsTunnelGatewayLine$doubleVpnRouteLine');
      expect(section, greaterThanOrEqualTo(0));
      expect(use, greaterThan(section),
          reason: 'the key is written inside the [WinsApp] section');
      expect(use, lessThan(writer.indexOf('return """')),
          reason: 'it is part of the section text, not of the AWG sections');
      expect(writer, isNot(contains('DoubleVpnSingleHop')),
          reason: 'the previous candidate\'s start-time marker is gone');
    });

    test('every Android start refreshes the choice and states its route', () {
      final candidate = _method(
        mainSource,
        'Future<bool> _startTunnelCandidate(',
        '  Future<void> _connectWithSmartProtocol({',
      );
      final record = candidate.indexOf(
          'await _writeDoubleVpnIntentRecord(_isDoubleVpnRequested);');
      final canonical = candidate.indexOf(
          "data['double_vpn_requested'] = _isDoubleVpnRequested;");
      final route = candidate.indexOf(
          "..['double_vpn_route'] = doubleVpnRouteOf(config);");
      final raw = candidate.indexOf('_buildRawAmneziaConfig(');
      final native = candidate.indexOf("'startTunnel',");
      expect(record, greaterThanOrEqualTo(0));
      expect(canonical, greaterThanOrEqualTo(0));
      expect(record, greaterThan(canonical),
          reason: 'the canonical setting is durable before native start');
      expect(route, greaterThan(record));
      expect(raw, greaterThan(route),
          reason: 'the route is set before the native text is built');
      expect(native, greaterThan(raw));
      final gate = candidate.lastIndexOf('if (Platform.isAndroid) {', record);
      expect(gate, greaterThanOrEqualTo(0));
      // Unconditional on the route and on the choice: a non-Double start and
      // a Double-off start state their route too.
      final head = candidate.substring(gate, record);
      expect(head, isNot(contains('doubleVpnRequestedButSingleHop(')));
      expect(head, isNot(contains('_isDoubleVpnRequested &&')));
      expect(
        candidate.indexOf("'double_vpn_route'", route + 10),
        -1,
        reason: 'the route is never written into the persisted document',
      );
    });

    test('the choice record: registered, Android only, on-disk name neutral',
        () {
      expect(mainSource,
          contains("static const String _doubleVpnIntentRecord = 'route_intent.txt';"));
      // NOT in the shared set: that set is pinned against the Apple allowlist
      // and walked by erase loops that run on every platform. The Android-only
      // name is accepted by the validator and erased explicitly.
      final names = _method(
        mainSource,
        'static const Set<String> _sensitiveStateFileNames = <String>{',
        '  };',
      );
      expect(names, isNot(contains('route_intent')));
      expect(names, isNot(contains('_doubleVpnIntentRecord')));
      expect(
        mainSource,
        contains('!_sensitiveStateFileNames.contains(name) &&\n'
            '        !(Platform.isAndroid && name == _doubleVpnIntentRecord)'),
      );
      final erase = _method(
        mainSource,
        'Future<bool> _eraseLocalAccountDataKeepingDevice(int epoch) async {',
        '  Future<void> _deactivateCurrentDevice() async {',
      );
      expect(
        erase,
        contains('if (Platform.isAndroid &&\n'
            '        !await _deleteSensitiveArtifactVerified(_doubleVpnIntentRecord)) {'),
        reason: 'the local account erase removes the choice on Android',
      );
      final writer = _method(
        mainSource,
        'Future<bool> _writeDoubleVpnIntentRecord(bool requested) {',
        '  Future<bool> _persistDoubleVpnRequested(bool requested) async {',
      );
      expect(writer, contains('if (!Platform.isAndroid) return Future<bool>.value(true);'));
      expect(writer, contains("requested ? '1' : '0'"));
      // A failed write that would leave a stale "0" behind for a wanted
      // Double VPN removes the record, so it reads as unknown (= wanted).
      expect(writer, contains('if (requested && !_doubleVpnIntentWritesSealed &&'));
      expect(writer, contains('_deleteSensitiveText(_doubleVpnIntentRecord)'));
      final store = _read(
          'android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt');
      expect(store, contains('"route_intent.txt",'));
      expect(store, contains('"route_intent.txt" to "layout.dat"'));
    });

    test('turning it on records the service copy first, off records it after',
        () {
      final persist = _method(
        mainSource,
        'Future<bool> _persistDoubleVpnRequested(bool requested) async {',
        '  Future<void> _setDoubleVpnRequested(bool requested)',
      );
      final first = persist.indexOf(
          'if (requested && !await _writeDoubleVpnIntentRecord(true)) return false;');
      final settings = persist.indexOf('_mutateVpnRuntimeSettings(');
      final after = persist.indexOf(
          'if (!requested) await _writeDoubleVpnIntentRecord(false);');
      expect(first, greaterThanOrEqualTo(0));
      expect(settings, greaterThan(first));
      expect(after, greaterThan(settings));
      expect(persist,
          contains('if (requested) await _writeDoubleVpnIntentRecord(false);'),
          reason: 'a failed settings write undoes the service copy');
    });

    test('settings load, account cleanup and the duress wipe all reach it', () {
      expect(
        mainSource,
        contains(
            'await _writeDoubleVpnIntentRecord(_isDoubleVpnRequested);'),
        reason: 'the load re-syncs the service copy',
      );
      final cleanup = _method(
        mainSource,
        "      case 'restart_config':",
        "      case 'activation_marker':",
      );
      expect(cleanup, contains("'wins_vpn_restart_config.conf'"));
      expect(cleanup, contains('await _doubleVpnIntentRecordQueue;'));
      expect(mainSource, contains('_doubleVpnIntentWritesSealed = true;\n    await _doubleVpnIntentRecordQueue;'));
      expect(
        mainSource,
        contains('if (!_doubleVpnPreferenceChanging &&\n'
            '            preferenceRevisionAtRead == _doubleVpnPreferenceRevision) {'),
        reason: 'a restore read taken during a toggle must not write old intent',
      );
      expect(
          cleanup,
          contains(
              '!Platform.isAndroid ||\n              await _deleteSensitiveArtifactVerified(_doubleVpnIntentRecord)'),
          reason: 'account change: the choice goes with the restart state');
      final duress = _method(
        mainSource,
        'Future<void> _wipeIncriminatingStateForDuress({',
        'Future<void> _sweepAppStorageForDuress(',
      );
      expect(
          duress,
          contains('if (Platform.isAndroid) {\n'
              '      try {\n'
              '        await _deleteSensitiveText(_doubleVpnIntentRecord);'));
      // No new cleanup-journal artifact name: a journal written by this build
      // stays readable by every build that knows the existing ones.
      final artifacts = _method(
        mainSource,
        'static const Set<String> _accountCleanupArtifacts = <String>{',
        '  };',
      );
      expect(artifacts, isNot(contains('intent')));
    });
  });

  group('Kotlin decides, reports and keeps the disguise', () {
    test('both sides agree on every name and value', () {
      expect(_constant(kotlin, 'DOUBLE_VPN_ROUTE_KEY'), 'doublevpnroute');
      expect('DoubleVpnRoute'.toLowerCase(), 'doublevpnroute',
          reason: 'parseConfigSection lowercases keys');
      expect(_constant(kotlin, 'DOUBLE_VPN_ROUTE_SINGLE_HOP'), 'single-hop');
      expect(_constant(kotlin, 'DOUBLE_VPN_ROUTE_TWO_HOP'), 'two-hop');
      expect(_constant(kotlin, 'DOUBLE_VPN_INTENT_RECORD'), 'route_intent.txt');
      expect(_constant(kotlin, 'DOUBLE_VPN_READINESS_KEY'),
          'double_vpn_single_hop');
      expect(mainSource, contains("readiness['double_vpn_single_hop']"));
      expect(mainSource, contains("?['double_vpn_single_hop']"));
      expect(mainSource, contains('DoubleVpnRoute = '));
    });

    test('there is no disguised single-hop text, and the text order is fixed',
        () {
      expect(kotlin, isNot(contains('DISGUISED_SINGLE_HOP_TEXT')));
      expect(kotlin, isNot(contains('Running in background (limited)')));
      final text = _method(
        kotlin,
        'internal fun tunnelForegroundTextFor(',
        '/// The importance the tunnel channel will settle at',
      );
      final disguised = text.indexOf('disguised -> "Running in background."');
      final marked = text.indexOf(
          'state == TunnelForegroundState.CONNECTED && doubleVpnSingleHop ->');
      expect(disguised, greaterThanOrEqualTo(0));
      expect(marked, greaterThan(disguised),
          reason: 'the disguised case is decided first, whatever the route');
    });

    test('a restart restores the route and reads the canonical saved choice',
        () {
      expect(kotlin, contains('persistRestartConfig(config)'));
      expect(kotlin, contains('secureFileStore.read("vpn_settings.txt", legacy)'));
      expect(kotlin,
          isNot(contains('secureFileStore.read(DOUBLE_VPN_INTENT_RECORD)')));
      expect(kotlin, isNot(contains('persistRestartDoubleVpn')));
    });

    test('the single-hop text is the ruled one, on the non-disguised path only',
        () {
      expect(_constant(kotlin, 'SINGLE_HOP_TEXT'),
          'Single hop: Double VPN unavailable.');
    });
  });
}
