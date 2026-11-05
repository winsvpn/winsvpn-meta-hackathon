import 'dart:io';
import 'dart:ui' show Tristate;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:wins_vpn/main.dart';
import 'package:wins_vpn/offline_world_map_backdrop.dart';
import 'package:wins_vpn/public_ip_map_backdrop.dart';

class _TestTileProvider extends TileProvider {
  @override
  ImageProvider getImage(TileCoordinates coordinates, TileLayer options) =>
      const AssetImage('assets/wallpaper/offline_world_map.webp');
}

void expectNativeAppleMap(
  WidgetTester tester, {
  required double latitude,
  required double longitude,
}) {
  final dynamic platformView = Platform.isIOS
      ? tester.widget<UiKitView>(find.byType(UiKitView))
      : tester.widget<AppKitView>(find.byType(AppKitView));
  expect(platformView.viewType, 'winsvpn/apple-map');
  expect(
    platformView.creationParams,
    <String, dynamic>{
      'latitude': latitude,
      'longitude': longitude,
      'radiusMeters': PublicIpMapBackdrop.targetRadiusMiles *
          OfflineWorldMapBackdrop.metersPerMile,
    },
  );
  expect(find.byType(InteractiveViewer), findsNothing);
}

Future<void> declineFirstRunPrivacyPolicy(WidgetTester tester) async {
  await tester.pump();
  final notNow = find.text('Not now');
  if (notNow.evaluate().isNotEmpty) {
    await tester.tap(notNow);
    await tester.pumpAndSettle();
  }
}

void main() {
  group('WINS_MAP_TILE_URL release gate (F-07)', () {
    test('a release build ignores the define and keeps the compiled endpoint',
        () {
      expect(
        PublicIpMapBackdrop.compiledMapTileUrlTemplate(
          isReleaseBuild: true,
          definePresent: true,
          defineValue: 'https://tiles.evil.example/{z}/{x}/{y}.png',
        ),
        PublicIpMapBackdrop.defaultTileUrlTemplate,
      );
    });

    test('an unset define keeps the compiled endpoint in any mode', () {
      expect(
        PublicIpMapBackdrop.compiledMapTileUrlTemplate(
          isReleaseBuild: false,
          definePresent: false,
          defineValue: '',
        ),
        PublicIpMapBackdrop.defaultTileUrlTemplate,
      );
    });

    test('debug/profile builds honour the define for testing', () {
      expect(
        PublicIpMapBackdrop.compiledMapTileUrlTemplate(
          isReleaseBuild: false,
          definePresent: true,
          defineValue: 'https://maps.staging.example.net/{z}/{x}/{y}.png',
        ),
        'https://maps.staging.example.net/{z}/{x}/{y}.png',
      );
      // An empty define value is indistinguishable from an unset one and
      // falls back to the compiled endpoint, never to an empty URL.
      expect(
        PublicIpMapBackdrop.compiledMapTileUrlTemplate(
          isReleaseBuild: false,
          definePresent: true,
          defineValue: '   ',
        ),
        PublicIpMapBackdrop.defaultTileUrlTemplate,
      );
    });
  });

  const tunnelChannel = MethodChannel('wins_vpn/tunnel');
  late Set<String> unexpectedTunnelMethods;
  // External browser launches requested by the app, in order.
  late List<String> launchedExternalUrls;
  late Directory testDocumentsDirectory;
  setUp(() async {
    unexpectedTunnelMethods = <String>{};
    launchedExternalUrls = <String>[];
    testDocumentsDirectory =
        await Directory.systemTemp.createTemp('winsvpn-widget-test-');
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
        case 'launchExternalUrl':
          launchedExternalUrls.add(
              ((call.arguments as Map?)?['url'] ?? '').toString());
          return true;
        case 'monotonicMilliseconds':
          // M-15: no platform implements this native handler yet, so tests
          // exercise (and must keep exercising) the documented fallback:
          // a null result routes PIN-lockout enforcement back to
          // wall-clock-only checking instead of crashing.
          return null;
        default:
          unexpectedTunnelMethods.add(call.method);
          throw PlatformException(
            code: 'UNEXPECTED_TEST_METHOD',
            message: 'Unexpected wins_vpn/tunnel method: ${call.method}',
          );
      }
    });
  });
  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(tunnelChannel, null);
    if (await testDocumentsDirectory.exists()) {
      await testDocumentsDirectory.delete(recursive: true);
    }
    expect(
      unexpectedTunnelMethods,
      isEmpty,
      reason: 'Every native bridge call must have an explicit test contract.',
    );
  });

  // Owner ruling 2026-10-24: one label in every build.
  const premiumAccessLabel = 'Premium Access Info';

  testWidgets('VPN activation screen renders', (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());
    for (var attempt = 0;
        attempt < 40 &&
            find.text('Privacy Policy and Legal Consent').evaluate().isEmpty;
        attempt += 1) {
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 25)),
      );
      await tester.pump();
    }
    await tester.pumpAndSettle();

    expect(find.text('Privacy Policy and Legal Consent'), findsOneWidget);
    expect(find.text('Accept Privacy Policy'), findsOneWidget);
    expect(find.text('Not now'), findsOneWidget);
    // The consent sheet must show *a* policy URL, not a specific one: the URL
    // moved behind WINS_PRIVACY_POLICY_URL so a neutral-domain build can name a
    // neutral copy, and pinning the literal here would make that migration
    // present as a UI test failure.
    expect(
      find.textContaining(const String.fromEnvironment(
        'WINS_PRIVACY_POLICY_URL',
        defaultValue: 'https://www.winsvpn.org/privacy/',
      )),
      findsOneWidget,
    );

    expect(find.text('Enter Secure Account Number'), findsOneWidget);
    expect(find.text('Activate Device'), findsOneWidget);
    expect(find.text(premiumAccessLabel), findsOneWidget);
    if (Platform.isIOS || Platform.isMacOS) {
      expect(find.text('Buy Premium Access'), findsNothing);
    }
  });

  testWidgets('activation screen frames the threat model honestly',
      (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());
    await declineFirstRunPrivacyPolicy(tester);

    expect(
      find.text(
        'Before you start - what this protects, and what it cannot',
      ),
      findsOneWidget,
    );
    expect(
      find.textContaining('Until the tunnel is up, your network can see'),
      findsOneWidget,
    );
    expect(
      find.textContaining('not the fact of a VPN connection'),
      findsOneWidget,
    );
    expect(
      find.textContaining('it does not make you untraceable'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('activation controls remain bounded at accessibility text sizes',
      (WidgetTester tester) async {
    tester.view.physicalSize = const Size(2064, 2752);
    tester.view.devicePixelRatio = 2;
    tester.platformDispatcher.textScaleFactorTestValue = 3.2;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
      tester.platformDispatcher.clearTextScaleFactorTestValue();
    });

    await tester.pumpWidget(const MyApp());
    await declineFirstRunPrivacyPolicy(tester);

    expect(find.text('Enter Secure Account Number'), findsOneWidget);
    expect(find.text('Create 6-Digit PIN'), findsOneWidget);
    expect(find.text('Activate Device'), findsOneWidget);
    expect(find.text('Try Free Server (100 Mbps upload and download)'), findsOneWidget);
    expect(find.text(premiumAccessLabel), findsOneWidget);
    expect(tester.takeException(), isNull);

    final activateRect = tester.getRect(find.text('Activate Device'));
    final freeRect =
        tester.getRect(find.text('Try Free Server (100 Mbps upload and download)'));
    final premiumRect = tester.getRect(find.text(premiumAccessLabel));
    expect(activateRect.bottom, lessThanOrEqualTo(freeRect.top));
    expect(freeRect.bottom, lessThanOrEqualTo(premiumRect.top));
  });

  testWidgets('activation workflow exposes semantic names and control roles',
      (WidgetTester tester) async {
    final semantics = tester.ensureSemantics();

    await tester.pumpWidget(const MyApp());
    await declineFirstRunPrivacyPolicy(tester);

    expect(find.bySemanticsLabel('Activate Device'), findsOneWidget);
    expect(
      find.bySemanticsLabel('Try Free Server (100 Mbps upload and download)'),
      findsOneWidget,
    );
    expect(find.bySemanticsLabel(premiumAccessLabel), findsOneWidget);

    final textFields = find.byType(EditableText);
    expect(textFields, findsNWidgets(3));
    for (var index = 0; index < 3; index++) {
      final node = tester.getSemantics(textFields.at(index));
      expect(node.flagsCollection.isTextField, isTrue);
      expect(node.flagsCollection.isFocused, isNot(Tristate.none));
    }
    semantics.dispose();
  });

  testWidgets('activation validation provides text guidance beyond color',
      (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());
    await declineFirstRunPrivacyPolicy(tester);

    await tester.tap(find.text('Activate Device'));
    await tester.pump();

    expect(
      find.text('Type the 12-digit Account Number here.'),
      findsOneWidget,
    );
    expect(find.text('Set your 6-digit PIN here.'), findsOneWidget);
    expect(
      find.textContaining(
        'Please type your 12-digit Account Number and set a 6-digit PIN',
      ),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('all builds render a local real-world map before connection',
      (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());
    await declineFirstRunPrivacyPolicy(tester);

    expect(find.byType(OfflineWorldMapBackdrop), findsOneWidget);
    expect(find.byTooltip('Explore map'), findsOneWidget);
    expect(find.byType(InteractiveViewer), findsOneWidget);

    final image = tester.widget<Image>(
      find.descendant(
        of: find.byType(OfflineWorldMapBackdrop),
        matching: find.byType(Image),
      ),
    );
    expect(
      (image.image as AssetImage).assetName,
      'assets/wallpaper/offline_world_map.webp',
    );
    expect(find.text('Natural Earth (public domain)'), findsOneWidget);

    await tester.tap(find.byTooltip('Explore map'));
    await tester.pump();

    expect(find.byTooltip('Close map'), findsOneWidget);
    expect(find.text('Enter Secure Account Number'), findsNothing);

    await tester.tap(find.byTooltip('Close map'));
    await tester.pump();

    expect(find.byTooltip('Explore map'), findsOneWidget);
    expect(find.text('Enter Secure Account Number'), findsOneWidget);
  });

  testWidgets('offline map centers locally and remains interactive',
      (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: SizedBox(
          width: 400,
          height: 800,
          child: OfflineWorldMapBackdrop(countryCode: 'US'),
        ),
      ),
    );
    await tester.pump();

    expect(
      find.bySemanticsLabel('Your approximate network location'),
      findsOneWidget,
    );
    expect(
      tester.getSize(find.byKey(const Key('approximate-location-marker'))),
      const Size(26, 26),
    );
    final viewer = tester.widget<InteractiveViewer>(
      find.byType(InteractiveViewer),
    );
    final controller = viewer.transformationController!;
    expect(controller.value.getMaxScaleOnAxis(), closeTo(2.75, 0.001));
    final beforeDrag = List<double>.from(controller.value.storage);

    await tester.drag(find.byType(InteractiveViewer), const Offset(-48, 0));
    await tester.pumpAndSettle();

    expect(controller.value.storage, isNot(orderedEquals(beforeDrag)));
    expect(tester.takeException(), isNull);
  });

  testWidgets('offline map uses a tighter user-location frame',
      (WidgetTester tester) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(400, 800);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    await tester.pumpWidget(
      MaterialApp(
        home: SizedBox(
          width: 400,
          height: 800,
          child: OfflineWorldMapBackdrop(
            countryCode: 'US',
            regionCode: 'FL',
            latitude: 27.8,
            longitude: -81.7,
          ),
        ),
      ),
    );
    await tester.pump();

    if (Platform.isIOS || Platform.isMacOS) {
      expectNativeAppleMap(tester, latitude: 27.8, longitude: -81.7);
    } else {
      final viewer = tester.widget<InteractiveViewer>(
        find.byType(InteractiveViewer),
      );
      expect(
        viewer.transformationController!.value.getMaxScaleOnAxis(),
        closeTo(2.65, 0.01),
      );
      expect(
        find.bySemanticsLabel('Your approximate network location'),
        findsOneWidget,
      );
      expect(
        tester.getSize(find.byKey(const Key('approximate-location-marker'))),
        const Size(26, 26),
      );
    }
    expect(tester.takeException(), isNull);
  });

  testWidgets('public IP map frames approximately a 50-mile radius',
      (WidgetTester tester) async {
    const viewport = Size(400, 800);
    final zoom = PublicIpMapBackdrop.targetZoomForRadius(
      viewport: viewport,
      latitude: 40.71,
    );
    final visibleRadius = PublicIpMapBackdrop.visibleRadiusMiles(
      viewport: viewport,
      latitude: 40.71,
      zoom: zoom,
    );
    expect(visibleRadius, closeTo(50, 0.1));

    await tester.pumpWidget(
      MaterialApp(
        home: SizedBox(
          width: 400,
          height: 800,
          child: PublicIpMapBackdrop(
            countryCode: 'US',
            regionCode: 'FL',
            latitude: 40.71,
            longitude: -74.01,
            tileProvider: _TestTileProvider(),
          ),
        ),
      ),
    );
    await tester.pump();

    expect(find.byKey(const Key('public-ip-local-map')), findsOneWidget);
    expect(
      find.bySemanticsLabel('Your approximate network location'),
      findsOneWidget,
    );
    if (Platform.isIOS || Platform.isMacOS) {
      expect(find.text('Natural Earth (public domain)'), findsNothing);
      expectNativeAppleMap(tester, latitude: 40.71, longitude: -74.01);
    } else {
      expect(find.byType(FlutterMap), findsOneWidget);
      expect(
        find.byKey(
          const ValueKey('public-ip-city-label-tiles-primary'),
        ),
        findsOneWidget,
      );
      expect(find.text('Approximate IP location'), findsOneWidget);
      expect(find.text('© OpenStreetMap contributors'), findsOneWidget);
      expect(
        PublicIpMapBackdrop.tileRequestIdentity,
        contains('support@winsvpn.org'),
      );
      expect(
        Uri.parse(
          PublicIpMapBackdrop.defaultTileUrlTemplate
              .replaceAll('{z}', '8')
              .replaceAll('{x}', '128')
              .replaceAll('{y}', '127'),
        ).host,
        'www.winsvpn.org',
      );
      expect(
        PublicIpMapBackdrop.fallbackTileUrlTemplate(
          'https://maps.example/tiles/{z}/{x}/{y}.png',
        ),
        PublicIpMapBackdrop.defaultTileUrlTemplate,
      );
      expect(
        PublicIpMapBackdrop.fallbackTileUrlTemplate(
          PublicIpMapBackdrop.defaultTileUrlTemplate,
        ),
        isNull,
      );
      expect(find.text('Natural Earth (public domain)'), findsNothing);
      final tiles = tester.widget<TileLayer>(
        find.byKey(
          const ValueKey('public-ip-city-label-tiles-primary'),
        ),
      );
      expect(tiles.urlTemplate, PublicIpMapBackdrop.defaultTileUrlTemplate);
      expect(tiles.fallbackUrl, isNull);
      expect(tiles.errorTileCallback, isNotNull);
      final circleLayer = tester.widget<CircleLayer>(find.byType(CircleLayer));
      expect(
        circleLayer.circles.single.key,
        const Key('public-ip-50-mile-radius'),
      );
      expect(circleLayer.circles.single.useRadiusInMeter, isTrue);
      expect(
        circleLayer.circles.single.radius,
        closeTo(80467.2, 0.01),
      );
    }
    expect(
      find.byWidgetPredicate(
        (widget) => widget is Image && widget.image is NetworkImage,
      ),
      findsNothing,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('public IP map displays dynamic provider attribution',
      (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: SizedBox(
          width: 400,
          height: 800,
          child: PublicIpMapBackdrop(
            countryCode: 'US',
            regionCode: 'FL',
            latitude: 40.71,
            longitude: -74.01,
            tileUrlTemplate: 'https://maps.winsvpn.org/tiles/{z}/{x}/{y}.png',
            attributionText:
                '© Managed map provider • © OpenStreetMap contributors',
            tileProvider: _TestTileProvider(),
          ),
        ),
      ),
    );
    await tester.pump();

    if (!Platform.isIOS && !Platform.isMacOS) {
      expect(
        find.text('© Managed map provider • © OpenStreetMap contributors'),
        findsOneWidget,
      );
      final tiles = tester.widget<TileLayer>(
        find.byKey(
          const ValueKey('public-ip-city-label-tiles-primary'),
        ),
      );
      expect(
        tiles.urlTemplate,
        'https://maps.winsvpn.org/tiles/{z}/{x}/{y}.png',
      );
      expect(tiles.fallbackUrl, isNull);
      expect(tiles.errorTileCallback, isNotNull);
    }
    expect(tester.takeException(), isNull);
  });

  testWidgets('offline map uses the iPad reference location span',
      (WidgetTester tester) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1024, 1366);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    await tester.pumpWidget(
      const MaterialApp(
        home: SizedBox(
          width: 1024,
          height: 1366,
          child: OfflineWorldMapBackdrop(
            countryCode: 'US',
            regionCode: 'FL',
            latitude: 27.8,
            longitude: -81.7,
          ),
        ),
      ),
    );
    await tester.pump();

    if (Platform.isIOS || Platform.isMacOS) {
      expectNativeAppleMap(tester, latitude: 27.8, longitude: -81.7);
    } else {
      final viewer = tester.widget<InteractiveViewer>(
        find.byType(InteractiveViewer),
      );
      expect(
        viewer.transformationController!.value.getMaxScaleOnAxis(),
        closeTo(3.97, 0.01),
      );
      expect(
        tester.getSize(find.byKey(const Key('approximate-location-marker'))),
        const Size(26, 26),
      );
    }
    expect(tester.takeException(), isNull);
  });

  testWidgets('offline map keeps a tight location span on wide desktops',
      (WidgetTester tester) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1280, 768);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    await tester.pumpWidget(
      const MaterialApp(
        home: SizedBox(
          width: 1280,
          height: 768,
          child: OfflineWorldMapBackdrop(
            countryCode: 'US',
            regionCode: 'FL',
            latitude: 27.8,
            longitude: -81.7,
          ),
        ),
      ),
    );
    await tester.pump();

    if (Platform.isIOS || Platform.isMacOS) {
      expectNativeAppleMap(tester, latitude: 27.8, longitude: -81.7);
    } else {
      final viewer = tester.widget<InteractiveViewer>(
        find.byType(InteractiveViewer),
      );
      expect(
        viewer.transformationController!.value.getMaxScaleOnAxis(),
        closeTo(8.82, 0.02),
      );
    }
    expect(tester.takeException(), isNull);
  });

  testWidgets('premium access opens the website home page in every build',
      (WidgetTester tester) async {
    // Owner ruling 2026-10-24 ("Home page everywhere"). The host platforms
    // that launch through the native channel are asserted; on a Windows or
    // Linux host the same tap would spawn a real browser process.
    await tester.pumpWidget(const MyApp());
    await declineFirstRunPrivacyPolicy(tester);

    expect(find.text('Buy Premium Access'), findsNothing);
    expect(find.text('Premium Access Options'), findsNothing);
    if (!(Platform.isAndroid || Platform.isIOS || Platform.isMacOS)) return;
    await tester.ensureVisible(find.text(premiumAccessLabel).first);
    await tester.pump();
    await tester.tap(find.text(premiumAccessLabel).first);
    await tester.pumpAndSettle();

    expect(launchedExternalUrls, <String>['https://www.winsvpn.org']);
    // No sheet, no store notice, no purchase or redemption offer in the app.
    expect(find.textContaining('For the Apple App Store build'), findsNothing);
    expect(find.textContaining('For this Google Play build'), findsNothing);
    expect(find.text("Open Win's VPN Website"), findsNothing);
    expect(find.text('1 Month Subscription'), findsNothing);
    expect(find.byKey(const Key('prepaid_redemption_entry')), findsNothing,
        reason: 'test builds do not enable external payment links');
  });
}
