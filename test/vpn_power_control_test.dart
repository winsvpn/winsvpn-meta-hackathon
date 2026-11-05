import 'dart:ui' show SemanticsAction;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/vpn_power_control.dart';
import 'package:wins_vpn/l10n/app_localizations.dart';

void main() {
  testWidgets('Burmese power and cancellation controls are localized', (tester) async {
    final semantics = tester.ensureSemantics();
    try {
    var cancels = 0;
    Widget localized(Widget body) => MaterialApp(
      locale: const Locale('my'),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: Scaffold(body: body));
    for (final connected in [false, true]) {
      await tester.pumpWidget(localized(VpnPowerControl(
        isConnected: connected, isConnectInFlight: false,
        connectedColor: Colors.green, disconnectedColor: Colors.red,
        onPressed: () {})));
      await tester.pump();
      expect(find.bySemanticsLabel(connected
        ? 'VPN ချိတ်ဆက်မှု ဖြတ်ပါ' : 'VPN ချိတ်ဆက်ပါ'), findsOneWidget);
    }
    await tester.pumpWidget(localized(VpnConnectTransitionView(
      status: 'fixture', connectedColor: Colors.green,
      disconnectedColor: Colors.red, onCancel: () => cancels++)));
    await tester.pump();
    expect(find.bySemanticsLabel('VPN ချိတ်ဆက်မှုကို ပယ်ဖျက်ပါ'), findsOneWidget);
    expect(find.bySemanticsLabel('VPN ချိတ်ဆက်နေသည်'), findsOneWidget);
    await tester.tap(find.bySemanticsLabel('VPN ချိတ်ဆက်မှုကို ပယ်ဖျက်ပါ'));
    await tester.tap(find.text('ချိတ်ဆက်မှုကို ပယ်ဖျက်ပါ'));
    expect(cancels, 2);
    } finally {
      semantics.dispose();
    }
  });

  Widget buildControl({
    required bool isConnected,
    required bool isConnectInFlight,
    required VoidCallback onPressed,
  }) {
    return MaterialApp(
      home: Scaffold(
        body: VpnPowerControl(
          isConnected: isConnected,
          isConnectInFlight: isConnectInFlight,
          connectedColor: Colors.green,
          disconnectedColor: Colors.red,
          onPressed: onPressed,
        ),
      ),
    );
  }

  testWidgets('in-flight power control is a reachable semantic cancel button',
      (tester) async {
    var taps = 0;
    await tester.pumpWidget(buildControl(
      isConnected: false,
      isConnectInFlight: true,
      onPressed: () => taps += 1,
    ));

    final cancel = find.bySemanticsLabel('Cancel VPN connection');
    expect(cancel, findsOneWidget);
    expect(
      tester
          .getSemantics(cancel)
          .getSemanticsData()
          .hasAction(SemanticsAction.tap),
      isTrue,
    );
    expect(find.byIcon(Icons.close), findsOneWidget);
    await tester.tap(cancel);
    expect(taps, 1);
  });

  testWidgets('connect transition exposes only progress and cancel controls',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: VpnConnectTransitionView(
          status: 'Trying Winn Protocol',
          connectedColor: Colors.green,
          disconnectedColor: Colors.red,
          onCancel: () {},
        ),
      ),
    ));

    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    expect(find.bySemanticsLabel('Cancel VPN connection'), findsOneWidget);
    expect(find.byType(Switch), findsNothing);
    expect(find.byType(Checkbox), findsNothing);
    expect(find.byType(DropdownButton<dynamic>), findsNothing);
  });

  testWidgets('idle power labels distinguish connect and disconnect',
      (tester) async {
    await tester.pumpWidget(buildControl(
      isConnected: false,
      isConnectInFlight: false,
      onPressed: () {},
    ));
    expect(find.bySemanticsLabel('Connect VPN'), findsOneWidget);

    await tester.pumpWidget(buildControl(
      isConnected: true,
      isConnectInFlight: false,
      onPressed: () {},
    ));
    expect(find.bySemanticsLabel('Disconnect VPN'), findsOneWidget);
  });
}
