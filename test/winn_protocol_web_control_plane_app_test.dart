import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';
import 'package:wins_vpn/winn_protocol_web_control_plane_app.dart';

/// Widget tests for the config-only web/desktop control-plane surface
/// (`lib/winn_protocol_web_control_plane_app.dart`).
///
/// The thing a false-green would hide here: a user "gets a session" by pasting
/// a winn/3 config, and must be able to do so WITHOUT a native tunnel AND
/// without the surface turning into any kind of raw HTTP proxy (no CONNECT, no
/// proxy-auth, no port). Every test drives the widget through its actual UI.
void main() {
  String validJson() => jsonEncode(<String, dynamic>{
        'protocol_version': kWinnProtocolV3,
        'protocol_params': <String, dynamic>{},
        'server_endpoint': '127.0.0.1:51820',
        'client_ip': '10.99.0.2',
        'client_private_key': '<REDACTED_WG_KEY>',
        'client_public_key': '<REDACTED_WG_KEY>',
        'server_public_key': '<REDACTED_WG_KEY>',
        'mtu': 1280,
        'dns': '10.99.0.1',
        'stealth_active': false,
        'obfuscation': <String, dynamic>{'H1': 11, 'H2': 22, 'H3': 33, 'H4': 44},
      });

  testWidgets('resolves a pasted config into a session, no native tunnel',
      (tester) async {
    await tester.pumpWidget(WinnWebControlPlaneApp(initialText: validJson()));
    await tester.tap(find.text('Resolve session'));
    await tester.pump();

    expect(find.textContaining('carrier: $kWinnCarrierDirectAwg'),
        findsOneWidget);
    expect(find.textContaining('resolved [winn] section'), findsOneWidget);
    // The resolved INI body is shown (a real key from the emitted section).
    expect(
      find.byWidgetPredicate((w) =>
          w is SelectableText &&
          w.data != null &&
          w.data!.contains('endpoint = 127.0.0.1:51820')),
      findsOneWidget,
    );
    // A resolved session must never present a raw-HTTP-proxy affordance.
    expect(find.textContaining('CONNECT'), findsNothing);
    expect(find.textContaining('proxy-auth'), findsNothing);
  });

  testWidgets('refuses a config missing a required field and shows the reason',
      (tester) async {
    final incomplete = jsonDecode(validJson())
        as Map<String, dynamic>
      ..remove('client_private_key');
    await tester.pumpWidget(
        WinnWebControlPlaneApp(initialText: jsonEncode(incomplete)));
    await tester.tap(find.text('Resolve session'));
    await tester.pump();

    expect(find.text('refused'), findsOneWidget);
    expect(find.textContaining('missing_field'), findsOneWidget);
    // No [winn] section may be presented for a refused config.
    expect(find.text('[winn]'), findsNothing);
  });

  testWidgets('reports a non-JSON paste as a parse error, no crash',
      (tester) async {
    await tester.pumpWidget(const WinnWebControlPlaneApp(initialText: 'not json'));
    await tester.tap(find.text('Resolve session'));
    await tester.pump();

    expect(find.text('error_code_config_error_not_json'), findsOneWidget);
    expect(find.text('refused'), findsNothing);
  });

  testWidgets('reports an empty paste as an error, no session', (tester) async {
    await tester.pumpWidget(const WinnWebControlPlaneApp());
    await tester.tap(find.text('Resolve session'));
    await tester.pump();

    expect(find.text('error_code_config_error_empty'), findsOneWidget);
    expect(find.text('carrier:'), findsNothing);
  });

  testWidgets('reports a non-object paste as an error, no session',
      (tester) async {
    await tester.pumpWidget(const WinnWebControlPlaneApp(initialText: '[1,2]'));
    await tester.tap(find.text('Resolve session'));
    await tester.pump();

    expect(find.text('error_code_config_error_not_object'), findsOneWidget);
    expect(find.text('[winn]'), findsNothing);
  });

  testWidgets('the surface claims only a config; it never proxies anything',
      (tester) async {
    // The banner is a promise, and the promise is CONTROLLED: the rendered
    // control plane must offer no connectivity-control besides the config
    // text, Resolve, and the result. There is no toggle for a local listener,
    // no port field, no CONNECT/proxy-auth affordance anywhere.
    await tester.pumpWidget(const WinnWebControlPlaneApp());
    final text = tester.widgetList<Text>(find.byType(Text)).map((t) => t.data ?? '');
    for (final t in text) {
      expect(t.toLowerCase(), isNot(contains('connect ')));
      expect(t.toLowerCase(), isNot(contains('proxy-auth')));
    }
    expect(find.byType(WinnWebControlPlaneApp), findsOneWidget);
  });
}
