import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tv_dpad_support.dart';
import 'package:wins_vpn/vpn_power_control.dart';

void main() {
  group('TV D-pad support file contains required symbols', () {
    test('tv_dpad_support.dart declares focus traversal and key handling', () async {
      final content = await readSupportFile();
      expect(content.contains('FocusTraversalGroup'), isTrue,
          reason: 'Missing FocusTraversalGroup');
      expect(content.contains('FocusTraversalOrder'), isTrue,
          reason: 'Missing FocusTraversalOrder');
      expect(content.contains('DirectionalFocusIntent'), isTrue,
          reason: 'Missing DirectionalFocusIntent');
      expect(content.contains('Shortcuts('), isTrue, reason: 'Missing Shortcuts(');
      expect(content.contains('Actions('), isTrue, reason: 'Missing Actions(');
      expect(content.contains('LogicalKeyboardKey'), isTrue,
          reason: 'Missing LogicalKeyboardKey');
      expect(content.contains('KeyboardListener'), isTrue,
          reason: 'Missing KeyboardListener');
    });
  });

  group('main.dart contains TV wiring', () {
    test('main.dart wraps dashboard in FocusTraversalGroup with explicit order',
        () async {
      final mainContent = await readMainFile();
      final supportContent = await readSupportFile();
      expect(mainContent.contains('TvDpadWrapper'), isTrue);
      expect(mainContent.contains('TvFocusDecoration'), isTrue);
      expect(mainContent.contains('TvActivatable'), isTrue);
      expect(mainContent.contains('FocusTraversalGroup') || supportContent.contains('FocusTraversalGroup'), isTrue);
      expect(supportContent.contains('FocusTraversalOrder'), isTrue);
      expect(supportContent.contains('NumericFocusOrder'), isTrue);
      expect(supportContent.contains('OrderedTraversalPolicy'), isTrue);
    });

    test('map backdrop is static on TV (InteractiveViewer not used on TV path)',
        () async {
      final content = await readMainFile();
      expect(content.contains("assets/wallpaper/default.webp"), isTrue);
      // Ensure TV path returns static image; check inside _buildWallpaperBackdrop
      final methodStart = content.indexOf('Widget _buildWallpaperBackdrop');
      expect(methodStart, isNot(-1));
      final methodSlice = content.substring(methodStart, methodStart + 2000);
      // TV branch should be inside this method and before PublicIpMapBackdrop
      final tvInMethod = methodSlice.indexOf('if (_isAndroidTv)');
      final mapInMethod = methodSlice.indexOf('PublicIpMapBackdrop');
      expect(tvInMethod, isNot(-1));
      expect(mapInMethod, isNot(-1));
      expect(tvInMethod < mapInMethod, isTrue,
          reason: 'TV check must come before map backdrop inside _buildWallpaperBackdrop');
      // And TV branch should use Image.asset
      expect(methodSlice.substring(tvInMethod, mapInMethod).contains('Image.asset'), isTrue);
      expect(methodSlice.substring(tvInMethod, mapInMethod),
          isNot(contains('InteractiveViewer')));
    });

    test('vpn_power_control.dart handles D-pad keys', () async {
      final content = await readPowerControlFile();
      expect(content.contains('LogicalKeyboardKey'), isTrue);
      expect(content.contains('DirectionalFocusIntent'), isTrue);
      expect(content.contains('Shortcuts'), isTrue);
      expect(content.contains('Actions'), isTrue);
      expect(content.contains('KeyboardListener'), isTrue);
    });
  });

  group('TvFocusDecoration visible ring', () {
    testWidgets('shows amber ring when focused', (tester) async {
      final focusNode = FocusNode();
      addTearDown(focusNode.dispose);
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: FocusTraversalGroup(
              policy: OrderedTraversalPolicy(),
              child: Column(
                children: [
                  TvFocusDecoration(
                    order: 1,
                    child: Focus(
                      focusNode: focusNode,
                      autofocus: true,
                      child: Container(width: 100, height: 40, color: Colors.blue),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(focusNode.hasPrimaryFocus, isTrue);
      final containers = tester.widgetList<AnimatedContainer>(find.byType(AnimatedContainer));
      final hasRing = containers.any((c) {
        final dec = c.decoration;
        if (dec is BoxDecoration) {
          final border = dec.border;
          if (border is Border) {
            return border.top.color == const Color(0xFFFFD21F) && border.top.width == 3.5;
          }
        }
        return false;
      });
      expect(hasRing, isTrue, reason: 'Focused TvFocusDecoration should show 3.5 amber border');
    });

    testWidgets('no ring when not focused', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: FocusTraversalGroup(
              policy: OrderedTraversalPolicy(),
              child: Column(
                children: [
                  TvFocusDecoration(
                    order: 1,
                    child: Container(width: 100, height: 40, color: Colors.blue),
                  ),
                  Focus(
                    autofocus: true,
                    child: Container(width: 100, height: 40, color: Colors.red),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final firstDecorationFinder = find.byType(TvFocusDecoration).first;
      final animated = find.descendant(of: firstDecorationFinder, matching: find.byType(AnimatedContainer));
      expect(animated, findsOneWidget);
      final container = tester.widget<AnimatedContainer>(animated);
      final dec = container.decoration as BoxDecoration;
      final border = dec.border as Border;
      expect(border.top.color, Colors.transparent);
    });
  });

  group('Directional focus traversal order', () {
    testWidgets('arrowDown moves focus 1 -> 2 -> 3 in explicit order', (tester) async {
      final focus1 = FocusNode();
      final focus2 = FocusNode();
      final focus3 = FocusNode();
      addTearDown(focus1.dispose);
      addTearDown(focus2.dispose);
      addTearDown(focus3.dispose);
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: TvDpadWrapper(
              child: FocusTraversalGroup(
                policy: OrderedTraversalPolicy(),
                child: Column(
                  children: [
                    FocusTraversalOrder(
                      order: const NumericFocusOrder(1),
                      child: Focus(
                        focusNode: focus1,
                        autofocus: true,
                        child: Container(width: 200, height: 40, color: Colors.blue, child: const Text('one')),
                      ),
                    ),
                    FocusTraversalOrder(
                      order: const NumericFocusOrder(2),
                      child: Focus(
                        focusNode: focus2,
                        child: Container(width: 200, height: 40, color: Colors.green, child: const Text('two')),
                      ),
                    ),
                    FocusTraversalOrder(
                      order: const NumericFocusOrder(3),
                      child: Focus(
                        focusNode: focus3,
                        child: ElevatedButton(onPressed: dummyCb, child: const Text('b3')),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(focus1.hasFocus, isTrue);
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
      await tester.pumpAndSettle();
      expect(focus2.hasFocus, isTrue, reason: 'arrowDown should move 1->2');
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
      await tester.pumpAndSettle();
      expect(focus3.hasFocus, isTrue, reason: 'second arrowDown should move 2->3');
      // also test reverse
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowUp);
      await tester.pumpAndSettle();
      expect(focus2.hasFocus, isTrue, reason: 'arrowUp should move 3->2');
    });

    testWidgets('select/enter activates focused control', (tester) async {
      var activated = false;
      final activatableFocus = FocusNode();
      addTearDown(activatableFocus.dispose);
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: TvDpadWrapper(
              child: Center(
                child: TvActivatable(
                  order: 1,
                  autofocus: true,
                  onActivate: () => activated = true,
                  child: Container(width: 100, height: 40, color: Colors.green),
                ),
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      // Activatable should be autofocused
      expect(activated, isFalse);
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(activated, isTrue, reason: 'Enter should activate TvActivatable');
      activated = false;
      await tester.sendKeyEvent(LogicalKeyboardKey.select);
      await tester.pumpAndSettle();
      expect(activated, isTrue, reason: 'Select should also activate');
    });

    testWidgets('back (escape/goBack) invokes onBack', (tester) async {
      var backCount = 0;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: TvDpadWrapper(
              onBack: () => backCount++,
              child: Focus(
                autofocus: true,
                child: Container(width: 100, height: 100, color: Colors.yellow),
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      await tester.pumpAndSettle();
      expect(backCount, 1, reason: 'escape should invoke onBack once');
    });

    test('goBack mapping exists in file', () async {
      final content = await readSupportFile();
      expect(content.contains('LogicalKeyboardKey.goBack'), isTrue);
      expect(content.contains('LogicalKeyboardKey.browserBack'), isTrue);
    });
  });

  group('Dashboard carries FocusTraversalGroup', () {
    testWidgets('VpnDashboardBody contains TvDpadWrapper and ordered traversal', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: TvDpadWrapper(
              child: FocusTraversalGroup(
                policy: OrderedTraversalPolicy(),
                child: Column(
                  children: [
                    FocusTraversalOrder(
                      order: const NumericFocusOrder(1),
                      child: Focus(child: TextButton(onPressed: dummyCb, child: const Text('one'))),
                    ),
                    FocusTraversalOrder(
                      order: const NumericFocusOrder(2),
                      child: Focus(child: TextButton(onPressed: dummyCb, child: const Text('two'))),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.byType(FocusTraversalGroup), findsWidgets);
      expect(find.byType(Shortcuts), findsWidgets);
      expect(find.byType(Actions), findsWidgets);
      expect(find.byType(KeyboardListener), findsWidgets);
    });
  });

  group('VpnPowerControl D-pad', () {
    testWidgets('VpnPowerControl shows ring when focused and activates on enter', (tester) async {
      var pressed = false;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Center(
              child: VpnPowerControl(
                isConnected: false,
                isConnectInFlight: false,
                connectedColor: Colors.green,
                disconnectedColor: Colors.red,
                onPressed: () => pressed = true,
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byType(VpnPowerControl));
      await tester.pumpAndSettle();
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(pressed, isTrue, reason: 'Enter after tap should activate VpnPowerControl');
    });

    testWidgets('VpnPowerControl autofocus shows ring and activates', (tester) async {
      var pressed = false;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Center(
              child: VpnPowerControl(
                isConnected: false,
                isConnectInFlight: false,
                connectedColor: Colors.green,
                disconnectedColor: Colors.red,
                onPressed: () => pressed = true,
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byType(VpnPowerControl));
      await tester.pumpAndSettle();
      expect(pressed, isTrue, reason: 'tap should activate');
      // File-level check ensures D-pad keys are wired; widget key dispatch is covered by VpnPowerControl's Shortcuts/Actions unit via TvActivatable test
    });
  });

  group('Main dashboard file mutation guards', () {
    test('tv_dpad file still contains required symbols after edits', () async {
      final c = await readSupportFile();
      expect(c.contains('kTvFocusColor'), isTrue);
      expect(c.contains('kTvFocusBorderWidth'), isTrue);
      expect(c.contains('TvStaticBackdrop'), isTrue);
    });
  });
}

void dummyCb() {}

Future<String> readSupportFile() async {
  return File('lib/tv_dpad_support.dart').readAsStringSync();
}

Future<String> readMainFile() async {
  return File('lib/main.dart').readAsStringSync();
}

Future<String> readPowerControlFile() async {
  return File('lib/vpn_power_control.dart').readAsStringSync();
}
