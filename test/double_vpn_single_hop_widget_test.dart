import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/main.dart';

// The Double VPN single-hop notice at widget level: the real app, cold-started
// with a tunnel the previous process committed (an ADOPTED session) and the
// config that committed in the persisted store. The dashboard must carry the
// persistent notice when Double VPN is wanted and that config is not two-hop,
// and must not carry it for a genuine Double VPN config or when Double VPN is
// off. The host is the Apple path (macOS has no in-app disguise, so the
// dashboard is reachable without a PIN); the native layer is a mocked method
// channel over an in-memory Keychain stand-in. The Android service reading
// (readiness `double_vpn_single_hop`) is covered at harness level in
// tunnel_display_restore_production_test.dart: this host cannot be Android.
void main() {
  const tunnelChannel = MethodChannel('wins_vpn/tunnel');
  const account = '1111-2222-3333';
  const generation = '11111111-AAAA-4AAA-8AAA-111111111111';
  final source = File('lib/main.dart').readAsStringSync();
  final policyVersion = RegExp(r"_privacyPolicyVersion = '([^']+)'")
      .firstMatch(source)!
      .group(1)!;

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

  void seedSettings({required bool doubleVpnWanted}) {
    keychain['vpn_settings.txt'] = jsonEncode(<String, Object>{
      'privacy_policy_accepted_version': policyVersion,
      'account_number': account,
      'double_vpn_requested': doubleVpnWanted,
    });
  }

  // The config that committed, as the persisted private config holds it.
  String? persistedConfig;
  String config({required bool twoHop}) => jsonEncode(<String, Object>{
        'protocol_version': 'winn/1',
        'node_slug': 'uk-gb1',
        'client_ip': '10.9.1.2',
        'double_vpn_active': twoHop,
        'double_vpn_core_id': twoHop ? 'north-america-core' : '',
        'double_vpn_exit_slug': twoHop ? 'uk-gb1' : '',
      });

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
        case 'readVpnConfig':
          return persistedConfig;
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
  // Round UN binds the Apple provider status generation here; any other
  // host takes another native path and skips these.
  final notApplePath = !(Platform.isMacOS || Platform.isIOS);

  const notice = Key('double_vpn_single_hop_notice');

  Future<void> settleDashboard(WidgetTester tester) async {
    for (var i = 0; i < 40; i++) {
      await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 25)));
      await tester.pump(const Duration(milliseconds: 200));
    }
  }

  testWidgets(
      'an adopted one-hop session under a wanted Double VPN shows the notice',
      (tester) async {
    seedSettings(doubleVpnWanted: true);
    persistedConfig = config(twoHop: false);
    await coldStart(tester, until: () => shows('SECURED'));
    await settleDashboard(tester);
    expect(shows('SECURED'), isTrue);
    expect(find.byKey(notice), findsOneWidget);
    expect(
      find.textContaining('Single hop: Double VPN unavailable'),
      findsOneWidget,
    );
    await shutDown(tester);
  }, skip: notApplePath);

  testWidgets('an adopted genuine Double VPN session shows no notice',
      (tester) async {
    seedSettings(doubleVpnWanted: true);
    persistedConfig = config(twoHop: true);
    await coldStart(tester, until: () => shows('SECURED'));
    await settleDashboard(tester);
    expect(shows('SECURED'), isTrue);
    expect(find.byKey(notice), findsNothing);
    await shutDown(tester);
  }, skip: notApplePath);

  testWidgets('with Double VPN off a one-hop session shows no notice',
      (tester) async {
    seedSettings(doubleVpnWanted: false);
    persistedConfig = config(twoHop: false);
    await coldStart(tester, until: () => shows('SECURED'));
    await settleDashboard(tester);
    expect(shows('SECURED'), isTrue);
    expect(find.byKey(notice), findsNothing);
    await shutDown(tester);
  }, skip: notApplePath);
}
