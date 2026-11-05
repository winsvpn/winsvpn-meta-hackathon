import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/main.dart';

// Round UN at widget level: the real app, cold-started with a tunnel the
// previous process committed and a persisted record in the encrypted settings
// store. The dashboard card must name that node when the record belongs to
// this account and to the running native session, and "Unknown node"
// otherwise. The host is the Apple path (the test runs on macOS, which has no
// in-app disguise, so the card is reachable without a PIN); the native layer
// is a mocked method channel over an in-memory Keychain stand-in.
void main() {
  const tunnelChannel = MethodChannel('wins_vpn/tunnel');
  const account = '1111-2222-3333';
  const generation = '11111111-AAAA-4AAA-8AAA-111111111111';
  final source = File('lib/main.dart').readAsStringSync();
  final policyVersion = RegExp(r"_privacyPolicyVersion = '([^']+)'")
      .firstMatch(source)!
      .group(1)!;
  String scopeToken(String accountScope) => crypto.sha256
      .convert(utf8.encode('wins-client-keypair-scope-v1\n$accountScope'))
      .toString();

  late Directory documents;
  late Map<String, String> keychain;
  late List<String> calls;
  late Map<String, dynamic> readiness;

  Map<String, dynamic> readyApple(String providerGeneration) => <String, dynamic>{
        'active': true,
        'status': 'connected',
        'platform': Platform.operatingSystem,
        'provider_status_available': true,
        'provider_status_schema_supported': true,
        'provider_status_generation': providerGeneration,
        'provider_config_source': 'transient_start_options',
        'provider_stage': 'running',
        'provider_engine_ready': true,
        'provider_network_settings_applied': true,
        'provider_healthy': true,
      };

  void seedSettings({required Map<String, Object>? record}) {
    keychain['vpn_settings.txt'] = jsonEncode(<String, Object>{
      'privacy_policy_accepted_version': policyVersion,
      'account_number': account,
      if (record != null) 'tunnel_display_record': record,
    });
  }

  Map<String, Object> record({String? scope, String session = generation}) =>
      <String, Object>{
        'schema': 1,
        'slug': 'uk-gb1',
        'name': 'United Kingdom',
        'flag': 'GB',
        'account_scope': scope ?? scopeToken(account),
        'native_session': 'apple-status:$session',
      };

  setUp(() async {
    documents = await Directory.systemTemp.createTemp('round-un-widget-');
    keychain = <String, String>{};
    calls = <String>[];
    readiness = readyApple(generation);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(tunnelChannel, (call) async {
      calls.add(call.method);
      final arguments = call.arguments is Map
          ? Map<String, dynamic>.from(call.arguments as Map)
          : const <String, dynamic>{};
      final name = (arguments['name'] ?? '').toString();
      switch (call.method) {
        case 'getAppDocumentsDirectory':
          return documents.path;
        case 'secureStateRead':
        case 'readSecureText':
          return keychain[name];
        case 'secureStateWrite':
        case 'writeSecureText':
          keychain[name] = (arguments['value'] ?? '').toString();
          return true;
        case 'secureStateDelete':
        case 'deleteSecureText':
          keychain.remove(name);
          return true;
        case 'getTunnelReadiness':
          return readiness;
        case 'getTunnelState':
          return readiness['active'] == true;
      }
      return null;
    });
  });

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(tunnelChannel, null);
    if (await documents.exists()) await documents.delete(recursive: true);
  });

  // The secured dashboard trips one debug-only paint advisory in existing
  // UI (a ListTile inside a coloured DecoratedBox), which no other widget
  // test reaches because they stop at activation. Exactly that message is
  // dropped; every other error still fails the test.
  const knownAdvisory =
      'ListTile background color or ink splashes may be invisible.';
  FlutterExceptionHandler? testHandler;
  void dropKnownAdvisory() {
    testHandler = FlutterError.onError;
    FlutterError.onError = (details) {
      if (details.exceptionAsString().contains(knownAdvisory)) return;
      testHandler?.call(details);
    };
  }

  Future<void> coldStart(WidgetTester tester,
      {required bool Function() until}) async {
    dropKnownAdvisory();
    await tester.pumpWidget(const MyApp());
    for (var attempt = 0; attempt < 160 && !until(); attempt++) {
      await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 25)));
      await tester.pump(const Duration(milliseconds: 100));
    }
  }

  Future<void> shutDown(WidgetTester tester) async {
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(minutes: 5));
    FlutterError.onError = testHandler;
  }

  bool shows(String text) => find.text(text).evaluate().isNotEmpty;
  Map<String, dynamic>? persisted() {
    final raw = keychain['vpn_settings.txt'];
    if (raw == null) return null;
    final value = (jsonDecode(raw) as Map)['tunnel_display_record'];
    return value == null ? null : Map<String, dynamic>.from(value as Map);
  }

  // Round UN binds the Apple provider status generation here; any other
  // host takes another native path and skips these.
  final notApplePath = !(Platform.isMacOS || Platform.isIOS);

  testWidgets('relaunch with the tunnel up names the committed node',
      (tester) async {
    seedSettings(record: record());
    await coldStart(tester, until: () => shows('United Kingdom'));
    expect(calls, contains('getTunnelReadiness'));
    expect(find.text('United Kingdom'), findsOneWidget);
    expect(find.text('Unknown node'), findsNothing);
    expect(persisted()?['slug'], 'uk-gb1');
    await shutDown(tester);
  }, skip: notApplePath);

  testWidgets('another native session stays an unknown node, record removed',
      (tester) async {
    seedSettings(record: record(session: '22222222-BBBB-4BBB-8BBB-222222222222'));
    await coldStart(tester,
        until: () => shows('Unknown node') && persisted() == null);
    expect(find.text('Unknown node'), findsOneWidget);
    expect(find.text('United Kingdom'), findsNothing);
    expect(persisted(), isNull);
    await shutDown(tester);
  }, skip: notApplePath);

  testWidgets('another account stays an unknown node, record removed',
      (tester) async {
    seedSettings(record: record(scope: scopeToken('4444-5555-6666')));
    await coldStart(tester,
        until: () => shows('Unknown node') && persisted() == null);
    expect(find.text('Unknown node'), findsOneWidget);
    expect(find.text('United Kingdom'), findsNothing);
    expect(persisted(), isNull);
    await shutDown(tester);
  }, skip: notApplePath);

  testWidgets(
      'a provider restarted without start options stays an unknown node',
      (tester) async {
    // Round UN, OI-UN-1: same generation, but a Settings or menu toggle
    // restarted the provider from the shared config, which a failed save may
    // have left holding another node.
    seedSettings(record: record());
    readiness = <String, dynamic>{
      ...readyApple(generation),
      'provider_config_source': 'shared_config_path',
    };
    await coldStart(tester, until: () => shows('Unknown node'));
    for (var i = 0; i < 40; i++) {
      await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 25)));
      await tester.pump(const Duration(milliseconds: 200));
    }
    expect(calls, contains('getTunnelReadiness'));
    expect(find.text('Unknown node'), findsOneWidget);
    expect(find.text('United Kingdom'), findsNothing);
    // A reading that names no session proves nothing stale.
    expect(persisted()?['slug'], 'uk-gb1');
    await shutDown(tester);
  }, skip: notApplePath);

  testWidgets('no persisted record stays an unknown node', (tester) async {
    seedSettings(record: null);
    await coldStart(tester, until: () => shows('Unknown node'));
    // Let every bounded restore attempt run out.
    for (var i = 0; i < 40; i++) {
      await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 25)));
      await tester.pump(const Duration(milliseconds: 200));
    }
    expect(find.text('Unknown node'), findsOneWidget);
    expect(find.text('United Kingdom'), findsNothing);
    await shutDown(tester);
  }, skip: notApplePath);
}
