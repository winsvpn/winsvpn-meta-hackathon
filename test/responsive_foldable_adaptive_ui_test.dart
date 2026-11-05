import 'dart:io';
import 'dart:ui' show DisplayFeature, DisplayFeatureState, DisplayFeatureType;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:wins_vpn/main.dart';

void main() {
  const tunnelChannel = MethodChannel('wins_vpn/tunnel');
  late Directory testDocumentsDirectory;

  setUp(() async {
    testDocumentsDirectory =
        await Directory.systemTemp.createTemp('winsvpn-responsive-test-');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(tunnelChannel, (call) async {
      switch (call.method) {
        case 'getAppDocumentsDirectory':
          return testDocumentsDirectory.path;
        case 'readSecureText':
        case 'secureStateRead':
          return null;
        case 'writeSecureText':
        case 'deleteSecureText':
        case 'secureStateWrite':
        case 'secureStateDelete':
          return true;
        case 'getInstalledApps':
          return const <Map<String, dynamic>>[];
        case 'monotonicMilliseconds':
          return null;
        default:
          return null;
      }
    });
  });

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(tunnelChannel, null);
    if (await testDocumentsDirectory.exists()) {
      await testDocumentsDirectory.delete(recursive: true);
    }
  });

  Future<void> dismissPrivacyPolicyIfPresent(WidgetTester tester) async {
    await tester.pump();
    final notNow = find.text('Not now');
    if (notNow.evaluate().isNotEmpty) {
      await tester.tap(notNow);
      await tester.pumpAndSettle();
    }
  }

  group('Responsive and Foldable Adaptive UI', () {
    testWidgets('portrait phone renders compact bounded layout without overflow',
        (WidgetTester tester) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      await tester.pumpWidget(const MyApp());
      await dismissPrivacyPolicyIfPresent(tester);

      expect(find.text('Enter Secure Account Number'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('compact landscape phone adapts without vertical overflow',
        (WidgetTester tester) async {
      tester.view.physicalSize = const Size(844, 390);
      tester.view.devicePixelRatio = 1;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      await tester.pumpWidget(const MyApp());
      await dismissPrivacyPolicyIfPresent(tester);

      expect(find.text('Enter Secure Account Number'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('foldable unfolded wide display expands card width cleanly',
        (WidgetTester tester) async {
      tester.view.physicalSize = const Size(880, 900);
      tester.view.devicePixelRatio = 1;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      await tester.pumpWidget(const MyApp());
      await dismissPrivacyPolicyIfPresent(tester);

      expect(find.text('Enter Secure Account Number'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('foldable with vertical hinge feature renders cleanly',
        (WidgetTester tester) async {
      tester.view.physicalSize = const Size(800, 800);
      tester.view.devicePixelRatio = 1;
      tester.view.displayFeatures = const <DisplayFeature>[
        DisplayFeature(
          bounds: Rect.fromLTWH(390, 0, 20, 800),
          type: DisplayFeatureType.hinge,
          state: DisplayFeatureState.postureFlat,
        ),
      ];
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
        tester.view.resetDisplayFeatures();
      });

      await tester.pumpWidget(const MyApp());
      await dismissPrivacyPolicyIfPresent(tester);

      expect(find.text('Enter Secure Account Number'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  });
}
