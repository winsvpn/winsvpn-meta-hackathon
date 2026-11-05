import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_status_surface_widget.dart';

Widget _surface(Future<Object?> Function() reader) => MaterialApp(
      home: Scaffold(
        body: WinnStatusSurface(
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
          readinessReader: reader,
          translate: (s) => s,
        ),
      ),
    );

void main() {
  testWidgets('no reads while off screen; reads resume at once on return',
      (tester) async {
    var reads = 0;
    await tester.pumpWidget(_surface(() async {
      reads++;
      return <String, Object?>{'service_active': true};
    }));
    await tester.pump(const Duration(seconds: 1));
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    final before = reads;
    await tester.pump(const Duration(seconds: 30));
    expect(reads, before);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(reads, before + 1, reason: 'one immediate read on return');
  });

  testWidgets('an unfocused but visible window keeps reading', (tester) async {
    var reads = 0;
    await tester.pumpWidget(_surface(() async {
      reads++;
      return <String, Object?>{'service_active': true};
    }));
    await tester.pump(const Duration(seconds: 1));
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    final before = reads;
    await tester.pump(const Duration(seconds: 10));
    expect(reads, greaterThan(before));
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });
}
