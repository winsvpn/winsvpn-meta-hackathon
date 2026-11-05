import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tv_dpad_support.dart';

// Real behaviour tests for the TV D-pad support file. No fake source reads:
// every assertion drives an actual widget tree and a real key event, and
// focus is observed through the visible focus ring, not a synthetic probe.

bool _decorationHasRing(WidgetTester tester, int order) {
  final decos = tester
      .widgetList<TvFocusDecoration>(find.byType(TvFocusDecoration))
      .where((d) => d.order == order);
  for (final d in decos) {
    final f = find.byWidgetPredicate((w) => identical(w, d));
    final inner = find.descendant(
        of: f, matching: find.byType(AnimatedContainer));
    for (int i = 0; i < inner.evaluate().length; i++) {
      final c = tester.widget<AnimatedContainer>(inner.at(i));
      final dec = c.decoration;
      if (dec is BoxDecoration && dec.border is Border &&
          (dec.border as Border).top.color == kTvFocusColor) {
        return true;
      }
    }
  }
  return false;
}

void main() {
  group('TvFocusDecoration visible ring', () {
    testWidgets('shows amber ring when focused', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: FocusTraversalGroup(
            policy: OrderedTraversalPolicy(),
            child: Column(children: [
              TvFocusDecoration(
                order: 1,
                autofocus: true,
                child: ElevatedButton(onPressed: () {}, child: const Text('one')),
              ),
            ]),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 1), isTrue,
          reason: 'focused decoration must show amber ring');
    });

    testWidgets('exactly one ring among focused and unfocused', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: FocusTraversalGroup(
            policy: OrderedTraversalPolicy(),
            child: Column(children: [
              TvFocusDecoration(
                order: 1,
                child: ElevatedButton(onPressed: () {}, child: const Text('one')),
              ),
              TvFocusDecoration(
                order: 2,
                autofocus: true,
                child:
                    ElevatedButton(onPressed: () {}, child: const Text('two')),
              ),
            ]),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 1), isFalse,
          reason: 'unfocused decoration must be transparent');
      expect(_decorationHasRing(tester, 2), isTrue,
          reason: 'focused decoration must show ring');
    });
  });

  group('Directional focus traversal', () {
    testWidgets('arrowDown moves 1 -> 2 -> 3, arrowUp goes back', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: TvDpadWrapper(
            child: FocusTraversalGroup(
              policy: OrderedTraversalPolicy(),
              child: Column(children: [
                TvFocusDecoration(
                  order: 1,
                  autofocus: true,
                  child: ElevatedButton(
                      onPressed: () {}, child: const Text('btn 1')),
                ),
                TvFocusDecoration(
                  order: 2,
                  child: ElevatedButton(
                      onPressed: () {}, child: const Text('btn 2')),
                ),
                TvFocusDecoration(
                  order: 3,
                  child: ElevatedButton(
                      onPressed: () {}, child: const Text('btn 3')),
                ),
              ]),
            ),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 1), isTrue);

      await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 2), isTrue, reason: 'after down -> 2');

      await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 3), isTrue, reason: 'after down -> 3');

      await tester.sendKeyEvent(LogicalKeyboardKey.arrowUp);
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 2), isTrue, reason: 'after up -> 2');
    });

    testWidgets('arrowRight moves to right neighbour', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: TvDpadWrapper(
            child: FocusTraversalGroup(
              policy: OrderedTraversalPolicy(),
              child: Row(children: [
                TvFocusDecoration(
                  order: 1,
                  autofocus: true,
                  child: ElevatedButton(
                      onPressed: () {}, child: const Text('L')),
                ),
                TvFocusDecoration(
                  order: 2,
                  child: ElevatedButton(
                      onPressed: () {}, child: const Text('R')),
                ),
              ]),
            ),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 1), isTrue);
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowRight);
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 2), isTrue, reason: 'move right -> 2');
    });

    testWidgets('arrowLeft moves to left neighbour', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: TvDpadWrapper(
            child: FocusTraversalGroup(
              policy: OrderedTraversalPolicy(),
              child: Row(children: [
                TvFocusDecoration(
                  order: 1,
                  autofocus: true,
                  child: ElevatedButton(
                      onPressed: () {}, child: const Text('L')),
                ),
                TvFocusDecoration(
                  order: 2,
                  child: ElevatedButton(
                      onPressed: () {}, child: const Text('R')),
                ),
              ]),
            ),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      // move right first, then left back to 1
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowRight);
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 2), isTrue);
      await tester.sendKeyEvent(LogicalKeyboardKey.arrowLeft);
      await tester.pumpAndSettle();
      expect(_decorationHasRing(tester, 1), isTrue, reason: 'left returns to 1');
    });
  });

  group('TvActivatable activation', () {
    testWidgets('enter and select call onActivate', (tester) async {
      var activated = 0;
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: TvDpadWrapper(
            child: Center(
              child: TvActivatable(
                order: 1,
                autofocus: true,
                onActivate: () => activated++,
                child: const SizedBox(
                    width: 120, height: 50, child: Placeholder()),
              ),
            ),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(activated, 1, reason: 'enter should activate');
      await tester.sendKeyEvent(LogicalKeyboardKey.select);
      await tester.pumpAndSettle();
      expect(activated, 2, reason: 'select should activate');
    });

    testWidgets('TvActivatable shows ring when focused', (tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: TvDpadWrapper(
            child: Center(
              child: TvActivatable(
                order: 1,
                autofocus: true,
                onActivate: () {},
                child: const SizedBox(width: 120, height: 50),
              ),
            ),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      final f = find.byType(TvActivatable);
      final inner =
          find.descendant(of: f, matching: find.byType(AnimatedContainer));
      var hasRing = false;
      for (int i = 0; i < inner.evaluate().length; i++) {
        final c = tester.widget<AnimatedContainer>(inner.at(i));
        final dec = c.decoration;
        if (dec is BoxDecoration && dec.border is Border &&
            (dec.border as Border).top.color == kTvFocusColor) {
          hasRing = true;
        }
      }
      expect(hasRing, isTrue);
    });
  });

  group('TvDpadWrapper back handling', () {
    testWidgets('escape invokes onBack', (tester) async {
      var back = 0;
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: TvDpadWrapper(
            onBack: () => back++,
            child: TvFocusDecoration(
              order: 1,
              autofocus: true,
              child: ElevatedButton(onPressed: () {}, child: const Text('x')),
            ),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      await tester.pumpAndSettle();
      expect(back, 1, reason: 'escape maps to DismissIntent -> onBack once');
    });
  });
}
