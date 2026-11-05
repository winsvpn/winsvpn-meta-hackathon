import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_ios_raw_config_main.dart';

const String _validLabIni = '''
[Interface]
PrivateKey = __WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__
Address = 10.8.0.2/32
MTU = 1280
DNS = 10.64.0.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 16
S2 = 80
S3 = 16
S4 = 0
H1 = 11
H2 = 22
H3 = 33
H4 = 44

[Peer]
PublicKey = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[WinsDebug]
ClientPublicKey = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS

[WinsApp]
ExcludedPackages =
ExcludedPathsB64 = W10=

[WinsDevContainment]
Enabled = true

[winn]
enabled = true
carrier = winn3
endpoint = 192.0.2.20:51844
inner_v4 = 10.64.0.2
inner_router_v4 = 10.64.0.254
static_private = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
gateway_static = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
gateway_id = bGFiLWdhdGV3YXk=
admission_key = MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm
path_mtu = 1280
carrier_classes = udp
session_id = iosraw-lab-test
''';

void main() {
  testWidgets('lab AppBar title is winn/3 raw config lab', (tester) async {
    await tester.pumpWidget(RawConfigLabApp(
      activeOverride: false,
      invokeOverride: (method, args) async => true,
    ));
    await tester.pumpAndSettle();
    expect(find.text('winn/3 raw config lab'), findsOneWidget);
    expect(find.byType(AppBar), findsOneWidget);
  });

  testWidgets('pumps with stub valid raw config and shows emitted INI',
      (tester) async {
    String? emittedMethod;
    Map<String, dynamic>? emittedArgs;

    await tester.pumpWidget(RawConfigLabApp(
      operatingSystemOverride: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(_validLabIni),
      invokeOverride: (method, arguments) async {
        emittedMethod = method;
        emittedArgs = arguments as Map<String, dynamic>?;
        return true;
      },
    ));

    // Auto-run on init + allow async _run to complete.
    await tester.pump(); // post-frame callback scheduled
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();

    expect(emittedMethod, 'startIosRawConfigLabTunnel');
    expect(emittedArgs, isNotNull);
    expect(emittedArgs!['configTemplate'], _validLabIni);

    // Status line for accepted path.
    expect(find.textContaining('native start requested'), findsOneWidget);

    // Emitted INI is shown verbatim in the UI (SelectableText with key).
    final emittedFinder = find.byKey(const Key('emitted_ini'));
    expect(emittedFinder, findsOneWidget);
    final emittedWidget = tester.widget<SelectableText>(emittedFinder);
    expect(emittedWidget.data, contains('[winn]'));
    expect(emittedWidget.data, contains('carrier = winn3'));
    expect(emittedWidget.data, contains('endpoint = 192.0.2.20:51844'));
    expect(emittedWidget.data, contains(_validLabIni.trim().split('\n').first.trim()));
    // The full stub is displayed.
    expect(emittedWidget.data, _validLabIni);

    // No error detail on the accepted path.
    expect(find.byKey(const Key('error_detail')), findsNothing);
  });

  testWidgets('surfaces preflight errors and shows no INI', (tester) async {
    final relay = _validLabIni.replaceFirst('carrier = winn3', 'carrier = direct-awg');
    var invoked = false;

    await tester.pumpWidget(RawConfigLabApp(
      operatingSystemOverride: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(relay),
      invokeOverride: (method, arguments) async {
        invoked = true;
        return true;
      },
    ));

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();

    expect(invoked, isFalse, reason: 'preflight must block before native invoke');

    // Blocked status is shown in both status and error_detail (they share text).
    final statusWidget = tester.widget<Text>(find.byKey(const Key('lab_status')));
    expect(statusWidget.data, contains('blocked at preflight'));
    expect(statusWidget.data, contains('carrier_not_winn3'));
    expect(find.textContaining('carrier_not_winn3'), findsWidgets);

    // Error detail widget surfaces the structured reason.
    final errorFinder = find.byKey(const Key('error_detail'));
    expect(errorFinder, findsOneWidget);
    final errorWidget = tester.widget<Text>(errorFinder);
    expect(errorWidget.data, contains('carrier_not_winn3'));
    expect(errorWidget.data, contains('preflight'));

    // No INI on the refused path.
    expect(find.byKey(const Key('emitted_ini')), findsNothing);
  });

  testWidgets('surfaces malformed endpoint error', (tester) async {
    final bad = _validLabIni.replaceFirst(
      'endpoint = 192.0.2.20:51844',
      'endpoint = not-an-endpoint',
    );

    await tester.pumpWidget(RawConfigLabApp(
      operatingSystemOverride: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(bad),
      invokeOverride: (method, arguments) async => true,
    ));

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();

    final statusWidget2 = tester.widget<Text>(find.byKey(const Key('lab_status')));
    expect(statusWidget2.data, contains('blocked at preflight'));
    expect(statusWidget2.data, contains('winn_endpoint_malformed'));
    expect(find.textContaining('winn_endpoint_malformed'), findsWidgets);
    expect(find.byKey(const Key('emitted_ini')), findsNothing);
    expect(find.byKey(const Key('error_detail')), findsOneWidget);
  });

  testWidgets('surfaces native start refusal without showing INI',
      (tester) async {
    String? emittedMethod;
    var invokeCalled = false;

    await tester.pumpWidget(RawConfigLabApp(
      operatingSystemOverride: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(_validLabIni),
      invokeOverride: (method, arguments) async {
        invokeCalled = true;
        emittedMethod = method;
        return false;
      },
    ));

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();

    expect(invokeCalled, isTrue,
        reason: 'a preflight-valid stub must reach the native invoke seam');
    expect(emittedMethod, 'startIosRawConfigLabTunnel');

    final statusWidget = tester.widget<Text>(find.byKey(const Key('lab_status')));
    expect(statusWidget.data, contains('blocked at native_start'));
    expect(statusWidget.data, contains('not_accepted'));

    final errorWidget = tester.widget<Text>(find.byKey(const Key('error_detail')));
    expect(errorWidget.data, contains('blocked at native_start'));
    expect(errorWidget.data, contains('not_accepted'));
    expect(find.byKey(const Key('emitted_ini')), findsNothing);
  });

  testWidgets('native invoke exception surfaces native_refused',
      (tester) async {
    await tester.pumpWidget(RawConfigLabApp(
      operatingSystemOverride: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(_validLabIni),
      invokeOverride: (method, arguments) async {
        throw StateError('native channel down');
      },
    ));

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();

    final statusWidget = tester.widget<Text>(find.byKey(const Key('lab_status')));
    expect(statusWidget.data, contains('blocked at native_start'));
    expect(statusWidget.data, contains('native_refused'));

    final errorWidget = tester.widget<Text>(find.byKey(const Key('error_detail')));
    expect(errorWidget.data, contains('blocked at native_start: native_refused'));
    expect(find.byKey(const Key('emitted_ini')), findsNothing);
  });

  testWidgets('inactive gate shows inactive message and no INI or error',
      (tester) async {
    var invoked = false;
    await tester.pumpWidget(RawConfigLabApp(
      activeOverride: false,
      invokeOverride: (method, args) async {
        invoked = true;
        return true;
      },
    ));

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();

    expect(invoked, isFalse);
    expect(find.textContaining('inactive: use a Debug build'), findsOneWidget);
    expect(find.byKey(const Key('emitted_ini')), findsNothing);
    expect(find.byKey(const Key('error_detail')), findsNothing);
  });

  testWidgets('Run once button re-invokes with current stub', (tester) async {
    var calls = 0;
    await tester.pumpWidget(RawConfigLabApp(
      operatingSystemOverride: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(_validLabIni),
      invokeOverride: (method, arguments) async {
        calls++;
        return true;
      },
    ));

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();
    expect(calls, 1);

    await tester.ensureVisible(find.text('Run once'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Run once'), warnIfMissed: false);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();
    expect(calls, 2);
    expect(find.byKey(const Key('emitted_ini')), findsOneWidget);
  });

  testWidgets('accepted run shows a schema-valid redacted summary',
      (tester) async {
    await tester.pumpWidget(RawConfigLabApp(
      operatingSystemOverride: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(_validLabIni),
      invokeOverride: (method, arguments) async => true,
    ));

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();

    final summaryFinder = find.byKey(const Key('schema_summary'));
    expect(summaryFinder, findsOneWidget);
    final summaryWidget = tester.widget<SelectableText>(summaryFinder);
    final text = summaryWidget.data!;
    expect(text, contains('schema valid: true'));
    expect(text, contains('protocol: winn/3, carrier: winn3'));
    expect(text, contains('endpoint: 192.0.2.20:51844'));
    expect(text, contains('path mtu: 1280'));
    expect(text, contains('static_private'),
        reason: 'the summary names secret fields present (redacted)');
    // The summary must be key-material free: no secret VALUE may appear.
    expect(text.contains('AAAAA'), isFalse,
        reason: 'summary must never print a secret value');
    expect(text.contains('MDEyMzQ'), isFalse,
        reason: 'summary must never print the admission key value');
  });

  testWidgets('preflight refusal shows no schema summary', (tester) async {
    final relay = _validLabIni.replaceFirst('carrier = winn3', 'carrier = direct-awg');
    await tester.pumpWidget(RawConfigLabApp(
      operatingSystemOverride: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(relay),
      invokeOverride: (method, arguments) async => true,
    ));

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('schema_summary')), findsNothing,
        reason: 'a refused doc must not present a schema-valid summary');
    expect(find.byKey(const Key('emitted_ini')), findsNothing);
  });

  test('summary reports schema-valid for a winn3 document', () {
    final summary = summarizeWinnIosControlPlaneDocument(_validLabIni);
    expect(summary.schemaValid, isTrue, reason: summary.errors.join(','));
    expect(summary.protocolVersion, 'winn/3');
    expect(summary.carrier, 'winn3');
    expect(summary.endpoint, '192.0.2.20:51844');
    expect(summary.innerV4, '10.64.0.2');
    expect(summary.innerRouterV4, '10.64.0.254');
    expect(summary.pathMtu, '1280');
    // Secret-shaped fields are named but never valued.
    expect(summary.redactedSecretKeys, contains('static_private'));
    expect(summary.redactedSecretKeys, contains('admission_key'));
    final redactedJson =
        const JsonEncoder().convert(summary.toJsonRedacted());
    expect(redactedJson.contains('AAAAAA'), isFalse,
        reason: 'redacted summary JSON must not contain a secret value');
    expect(redactedJson.contains('MDEyMzQ'), isFalse,
        reason: 'redacted summary JSON must not contain the admission key');
    expect(redactedJson, contains('secret_fields_redacted'));
  });

  test('summary refuses a non-winn3 carrier', () {
    final relay = _validLabIni.replaceFirst(
        'carrier = winn3', 'carrier = direct-awg');
    final summary = summarizeWinnIosControlPlaneDocument(relay);
    expect(summary.schemaValid, isFalse);
    expect(summary.errors, contains('carrier_not_winn3'));
    expect(summary.redactedSecretKeys, isEmpty);
  });

  test('summary refuses a document smuggling a protocol key', () {
    // Insert a protocol key into the emitted [winn] section.
    final smuggled = _validLabIni.replaceFirst(
      'carrier_classes = udp',
      'carrier_classes = udp\nprotocol = winn/3',
    );
    final summary = summarizeWinnIosControlPlaneDocument(smuggled);
    expect(summary.schemaValid, isFalse);
    expect(summary.errors, contains('winn_protocol_key_forbidden'));
  });
}
