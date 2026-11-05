import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Seat C finding A-1 (2026-09-29), made a real test. In the transition case
// (new app, hub not yet upgraded) the hub serves this device a winn/3 private
// key for ONE session. The marker that described it was dropped by
// `_configForTransport`, so the started config was persisted as
// `connected_tunnel_config` and kept in memory with the served key.
//
// These scenarios execute the PRODUCTION methods of lib/main.dart verbatim
// (normalization, key attach, transport projection, both config writers, the
// Apple config channel, the tunnel stop) in their own program, with only the
// platform edges stubbed: the secure state store, the method channel and the
// native stop. `_startTunnelCandidate` is too large to run here; its two
// statements that persist and keep the started config are replayed, and a
// source check below pins that production still does exactly that.

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production method: $start');
  }
  return source.substring(first, last);
}

void main() {
  late Directory temporary;
  late File program;
  final source = File('lib/main.dart').readAsStringSync();

  setUpAll(() async {
    final methods = <String>[
      _between(source, '  String? _stringValue(Map<String, dynamic> data',
          '  /// Verifier built from the compiled-in public key set'),
      _between(source, '  Map<String, dynamic> _mapValue(',
          '  String _normalizeProtocolLabel('),
      _between(source, '  String _hostnameOnly(String value) {',
          '  ({String host, int port})? _hostPortValue('),
      _between(source, '  Map<String, dynamic> _attachLocalClientKeys(',
          '  Future<Directory> _appDocumentsDirectory() async {'),
      _between(source, '  Future<void> _persistVpnConfigBestEffort(',
          '  /// A terminal v3 failure ends the fast path'),
      _between(source, '  Future<void> _persistVpnConfigRequired(',
          '  Future<void> _deleteVpnConfigOnApple() async {'),
      _between(source, '  Map<String, dynamic> _normalizeVpnConfig(',
          '  List<String> _xrayHostCandidates('),
      _between(source, '  Future<bool> _cancelAndStopNativeTunnel({',
          '  Future<bool> _settleWindowsTunnelStop({'),
    ];
    temporary = await Directory.systemTemp.createTemp('wins-winn3-session-');
    program = File('${temporary.path}/winn3_session_key_lifecycle.dart');
    await program.writeAsString(
        '$_harnessBefore\n${methods.join('\n')}\n$_harnessAfter');
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'transition_key_never_persisted_and_dropped_at_stop',
    'transition_key_stripped_even_without_marker',
    'adopted_local_key_persists_and_survives_stop',
    'adopted_key_known_only_from_store_after_restart',
    'adopted_key_kept_when_store_read_fails',
    'late_collision_for_account_a_leaves_account_b_key',
    'non_apple_stop_never_calls_the_keychain_clear',
  ]) {
    test('production session-key lifecycle: $scenario', () async {
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[
          '--packages=${File('.dart_tool/package_config.json').absolute.path}',
          program.path,
          scenario,
        ],
        workingDirectory: temporary.path,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }

  test(
      'production _startTunnelCandidate persists and keeps the started config '
      'exactly as the harness replays it', () {
    final start = _between(source, '  Future<bool> _startTunnelCandidate(',
        '  void _settleTunnelDisplaySession(');
    final normalized = start.replaceAll(RegExp(r'\s+'), ' ');
    expect(
        normalized,
        contains("await _persistVpnConfigBestEffort( configForPersistence, "
            "'connected_tunnel_config');"));
    expect(normalized, contains('_cachedVpnConfig = configForPersistence;'));
  });
}

const _harnessBefore = r'''
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:wins_vpn/server_load.dart';
import 'package:wins_vpn/vpn_config_validation.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn3_device_key.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';
import 'package:wins_vpn/xray_transport_options.dart';

const served = 'VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=';

// Every failed check is collected and reported, so one broken rule never
// hides another.
final List<String> failures = <String>[];

void check(bool condition, String what) {
  if (!condition && !failures.contains(what)) failures.add(what);
}

class FakeChannel {
  final Map<String, String> apple = <String, String>{};
  final List<Map<String, dynamic>> secretClears = <Map<String, dynamic>>[];
  Future<T?> invokeMethod<T>(String method, [dynamic arguments]) async {
    if (method == 'persistVpnConfig') {
      apple['vpn_config'] = (arguments as Map)['config'] as String;
      return true as T;
    }
    if (method == 'readVpnConfig') return apple['vpn_config'] as T?;
    if (method == 'clearWinnSessionSecret') {
      secretClears.add(Map<String, dynamic>.from(arguments as Map));
      return true as T;
    }
    throw StateError('unexpected channel call $method');
  }
}

class FakeGate {
  int generation = 0;
  int cancel() => ++generation;
}

class FakeCancellations {
  void notifyGenerationChanged() {}
}

class Harness {
  static final FakeChannel _methodChannel = FakeChannel();
  final Map<String, String> secureState = <String, String>{};
  bool _isApplePlatform = false;
  static const int _directAwgMtu = 1280;
  static const int _stealthTransportMtu = 1280;
  Map<String, dynamic> _cachedVpnConfig = <String, dynamic>{};
  final FakeGate _tunnelTransitionGate = FakeGate();
  final FakeCancellations _hubCancellations = FakeCancellations();
  Map<String, bool> get _winnCapabilityFlags =>
      <String, bool>{'supports_winn3': true};

  void _debugLog(String message) {}
  Future<String> _effectiveAccountScopeForKeyPair() async => 'acct';
  String _clientKeyScopeToken(String accountScope) => 'scope-$accountScope';
  Future<T> _serializeClientKeyOperationForScopeToken<T>(
          String scopeToken, Future<T> Function() operation) =>
      operation();
  Future<bool> _deleteClientKeyPairForScopeTokenUnlocked(
          String scopeToken) async =>
      true;
  bool failKeyReads = false;
  Future<String?> _readSensitiveText(String name) async {
    if (failKeyReads && name == kWinn3KeyPairFileName) {
      throw StateError('secure store unavailable');
    }
    return secureState[name];
  }
  Future<void> _writeSensitiveText(String name, String value) async {
    secureState[name] = value;
  }
  Future<void> _deleteSensitiveText(String name) async {
    secureState.remove(name);
  }
  void _cancelSpeedTest() {}
  // FAST-CONNECT: ending a background Double VPN upgrade touches no key.
  void _cancelDoubleVpnUpgrade() {}
  Future<bool> _stopNativeTunnel(
          {bool keepVpnLauncher = false,
          int? cancellationGeneration,
          bool releaseKillSwitchBlock = false}) async =>
      true;
  Future<bool> _settleWindowsTunnelStop(
          {required bool keepVpnLauncher, int? cancellationGeneration}) async =>
      true;

  Iterable<String> everythingStored() sync* {
    yield* secureState.values;
    yield* _methodChannel.apple.values;
  }

  void noServedKeyStored(String when) {
    for (final value in everythingStored()) {
      check(!value.contains(served), 'served key persisted ($when)');
    }
  }

  Map<String, dynamic> legacyServedConfig({String echo = ''}) =>
      <String, dynamic>{
        'client_ip': '10.8.1.3',
        'client_private_key': '',
        'client_public_key': 'AWG_PUBLIC_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAA=',
        'server_public_key': 'U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M=',
        'server_endpoint': '203.0.113.7:51820',
        'dns': '10.8.1.1',
        'node_slug': 'lab-alpha',
        'protocol_version': kWinnProtocolV3,
        'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
        'winn3_descriptor': <String, dynamic>{'payload': 'eA==', 'sig': 'eA=='},
        'winn3_inner_v4': '10.10.4.9',
        'winn3_static_private': echo.isEmpty ? served : '',
        'winn3staticprivate': echo.isEmpty ? served : '',
        if (echo.isNotEmpty) 'winn3_static_public': echo,
      };

  /// What one transition connect does to the config, in production order:
  /// refresh (normalize + attach, cache, persist), transport projection,
  /// start (persist as connected_tunnel_config, keep in memory).
  Future<Map<String, dynamic>> connect(
      Map<String, dynamic> raw, Winn3DeviceKeyPair local,
      {bool dropMarker = false}) async {
    final clientKeys = clientKeysWithWinn3(<String, String>{
      'private_key': 'AWG_PRIVATE_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAA=',
      'public_key': 'AWG_PUBLIC_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAA=',
    }, local);
    final normalized =
        _attachLocalClientKeys(_normalizeVpnConfig(raw), clientKeys);
    _cachedVpnConfig = normalized;
    await _persistVpnConfigBestEffort(normalized, 'account_config_refresh');
    var directConfig = _configForTransport(_cachedVpnConfig, stealthMode: false);
    if (dropMarker) {
      directConfig = Map<String, dynamic>.from(directConfig)
        ..remove(kWinn3StaticPrivateOriginField);
    }
    // The connect preflight: a config fetched for this session needs no
    // second /verify.
    check(winn3ConfigKeyUsable(directConfig, local, freshFromHub: true),
        'fresh session config needs an extra /verify');
    // _startTunnelCandidate, replayed (pinned by the source check):
    final configForPersistence = directConfig;
    await _persistVpnConfigBestEffort(
        configForPersistence, 'connected_tunnel_config');
    _cachedVpnConfig = configForPersistence;
    _isApplePlatform = false;
    await _persistVpnConfigRequired(configForPersistence);
    _isApplePlatform = true;
    await _persistVpnConfigRequired(configForPersistence);
    return directConfig;
  }
''';

const _harnessAfter = r'''
}

Future<void> main(List<String> args) async {
  final scenario = args.single;
  final h = Harness();
  final local = (await h._winn3KeyPairForRequest('acct'))!;
  final keyRecord = h.secureState[kWinn3KeyPairFileName] ?? '';
  switch (scenario) {
    case 'transition_key_never_persisted_and_dropped_at_stop':
    case 'transition_key_stripped_even_without_marker':
      final started = await h.connect(h.legacyServedConfig(), local,
          dropMarker: scenario == 'transition_key_stripped_even_without_marker');
      check(servedWinn3StaticPrivate(started) == served,
          'the session did not run on the served key');
      check(jsonEncode(h._cachedVpnConfig).contains(served),
          'the live session lost its key before stop');
      h.noServedKeyStored('after start');
      check(h.secureState['vpn_config.txt'] != null, 'vpn_config.txt written');
      check(Harness._methodChannel.apple['vpn_config'] != null,
          'Apple config store written');
      await h._cancelAndStopNativeTunnel(keepVpnLauncher: true);
      check(!jsonEncode(h._cachedVpnConfig).contains(served),
          'served key still in memory after stop');
      h.noServedKeyStored('after stop');
      // OI-KEYSAPP-13: the Apple tunnel-secret Keychain copy is cleared at
      // stop, keeping only the device's own key for this scope.
      final clears = Harness._methodChannel.secretClears;
      check(clears.length == 1, 'Apple tunnel secret not cleared at stop');
      check(clears.isNotEmpty && clears.single['accountScope'] == 'scope-acct',
          'Apple tunnel secret cleared for the wrong scope');
      check(
          clears.isNotEmpty &&
              clears.single['keepStaticPrivate'] == local.privateKey,
          'Apple clear does not keep exactly the local key');
      check(
          clears.isEmpty ||
              !clears.single['keepStaticPrivate'].toString().contains(served),
          'Apple clear was told to keep the served key');
      check(h.secureState[kWinn3KeyPairFileName] == keyRecord,
          'device key record changed');
      check(!keyRecord.contains(served), 'served key in device key record');
      // The next session never reuses a cached copy: it refreshes.
      final next =
          h._configForTransport(h._cachedVpnConfig, stealthMode: false);
      check(!winn3ConfigKeyUsable(next, local, freshFromHub: false),
          'a later session would start without asking the hub');
      break;
    case 'adopted_local_key_persists_and_survives_stop':
      final started =
          await h.connect(h.legacyServedConfig(echo: local.publicKey), local);
      check(servedWinn3StaticPrivate(started) == local.privateKey,
          'local key not attached');
      check((h.secureState['vpn_config.txt'] ?? '').contains(local.privateKey),
          'local key was stripped from vpn_config.txt');
      await h._cancelAndStopNativeTunnel(keepVpnLauncher: true);
      check(servedWinn3StaticPrivate(h._cachedVpnConfig) == local.privateKey,
          'local key dropped at stop');
      check(
          winn3ConfigKeyUsable(
              h._configForTransport(h._cachedVpnConfig, stealthMode: false),
              local,
              freshFromHub: false),
          'cached local-key config should not need a refresh');
      break;
    case 'adopted_key_known_only_from_store_after_restart':
      // A new app run: nothing in memory, the key only in the store.
      final restarted = Harness()..secureState.addAll(h.secureState);
      await restarted.connect(
          restarted.legacyServedConfig(echo: local.publicKey), local);
      check(
          (restarted.secureState['vpn_config.txt'] ?? '')
              .contains(local.privateKey),
          'a stored local key was stripped from vpn_config.txt');
      break;
    case 'adopted_key_kept_when_store_read_fails':
      // The store cannot be read now; the key seen this run still counts.
      h.failKeyReads = true;
      await h.connect(h.legacyServedConfig(echo: local.publicKey), local);
      check((h.secureState['vpn_config.txt'] ?? '').contains(local.privateKey),
          'a local key seen this run was stripped on a store read failure');
      await h._cancelAndStopNativeTunnel(keepVpnLauncher: true);
      check(servedWinn3StaticPrivate(h._cachedVpnConfig) == local.privateKey,
          'local key dropped at stop on a store read failure');
      break;
    case 'late_collision_for_account_a_leaves_account_b_key':
      // OI-KEYSAPP-7 (Sol): the account switches to B while A's /verify is
      // still in flight; A's 409 arrives after the switch.
      final keyA = local; // account 'acct'
      final keyB = (await h._winn3KeyPairForRequest('other'))!;
      final bodyA = jsonEncode(<String, dynamic>{
        'winn3_static_public': keyA.publicKey,
        'supports_winn3_client_key': true,
      });
      h._noteWinn3KeyCollision(
          http.Response('{"detail":"in use"}', 409, headers: <String, String>{
            'x-wins-error-code': 'winn3_static_public_in_use',
          }),
          bodyA);
      final bNext = (await h._winn3KeyPairForRequest('other'))!;
      check(bNext.privateKey == keyB.privateKey,
          "a late 409 for account A rotated account B's key");
      final aNext = (await h._winn3KeyPairForRequest('acct'))!;
      check(aNext.publicKey != keyA.publicKey,
          "account A's refused key was not rotated");
      final aAfter = (await h._winn3KeyPairForRequest('acct'))!;
      check(aAfter.publicKey == aNext.publicKey, 'account A rotated twice');
      break;
    case 'non_apple_stop_never_calls_the_keychain_clear':
      await h.connect(h.legacyServedConfig(), local);
      h._isApplePlatform = false;
      await h._cancelAndStopNativeTunnel(keepVpnLauncher: true);
      check(Harness._methodChannel.secretClears.isEmpty,
          'the Apple Keychain clear ran on a non-Apple host');
      check(!jsonEncode(h._cachedVpnConfig).contains(served),
          'served key still in memory after stop');
      break;
    default:
      throw StateError('unknown scenario $scenario');
  }
  if (failures.isNotEmpty) {
    for (final failure in failures) {
      print('FAILED: $failure');
    }
    exitCode = 1;
    return;
  }
  print('PASS $scenario');
}
''';
