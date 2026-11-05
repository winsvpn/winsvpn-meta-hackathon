import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tv_focus.dart';

void main() {
  testWidgets('arrow keys move selection up and down', (tester) async {
    await tester.pumpWidget(_harness(itemCount: 6));

    await tester.pumpAndSettle();
    expect(_primaryTvFocus(tester), isNotNull);
    expect(_selectedTrail(tester), [0]);

    await _press(tester, LogicalKeyboardKey.arrowDown);
    await tester.pump();
    expect(_selectedTrail(tester), [0, 1]);

    await _press(tester, LogicalKeyboardKey.arrowDown);
    await tester.pump();
    expect(_selectedTrail(tester), [0, 1, 2]);

    await _press(tester, LogicalKeyboardKey.arrowUp);
    await tester.pump();
    expect(_selectedTrail(tester), [0, 1, 2, 1]);
  });

  testWidgets('select / enter / gameButtonA invoke onSelected', (tester) async {
    final tap = <int>[];
    await tester.pumpWidget(_harness(itemCount: 4, onSelectedCalls: tap));
    await tester.pumpAndSettle();

    await _press(tester, LogicalKeyboardKey.arrowDown);
    await tester.pump();
    await _press(tester, LogicalKeyboardKey.enter);
    await tester.pump();
    expect(tap, [1]);

    await _press(tester, LogicalKeyboardKey.arrowDown);
    await tester.pump();
    await _press(tester, LogicalKeyboardKey.select);
    await tester.pump();
    expect(tap, [1, 2]);

    await _press(tester, LogicalKeyboardKey.arrowUp);
    await tester.pump();
    await _press(tester, LogicalKeyboardKey.gameButtonA);
    await tester.pump();
    expect(tap, [1, 2, 1]);
  });

  testWidgets('selection clamps at the ends of the list', (tester) async {
    await tester.pumpWidget(_harness(itemCount: 3));
    await tester.pumpAndSettle();

    for (var i = 0; i < 6; i++) {
      await _press(tester, LogicalKeyboardKey.arrowDown);
      await tester.pump();
    }
    expect(_lastSelected(tester), 2);

    for (var i = 0; i < 6; i++) {
      await _press(tester, LogicalKeyboardKey.arrowUp);
      await tester.pump();
    }
    expect(_lastSelected(tester), 0);
  });

  testWidgets('a long list scrolls the selection into view', (tester) async {
    // Small viewport, many items: the 7th item cannot be visible until the
    // list scrolls.
    final trail = <int>[];
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: Center(
          child: SizedBox(
            width: 400,
            height: 200,
            child: TvFocusList(
              autofocus: true,
              itemCount: 12,
              itemExtent: 72,
              onSelectionChanged: trail.add,
              itemBuilder: (context, i) =>
                  Center(child: Text('Item $i')),
            ),
          ),
        ),
      ),
    ));
    await tester.pumpAndSettle();

    for (var i = 0; i < 7; i++) {
      await _press(tester, LogicalKeyboardKey.arrowDown);
      await tester.pump();
    }
    expect(trail.last, 7);
    await tester.pumpAndSettle();
    final scrollOffset = tester
        .widget<Scrollable>(find.byType(Scrollable))
        .controller
        ?.offset ??
        0;
    expect(scrollOffset, greaterThan(0),
        reason: 'selection at index 5 must have scrolled the list past 0');
  });

  testWidgets('arrowRight does not move selection (single-column list)',
      (tester) async {
    await tester.pumpWidget(_harness(itemCount: 3));
    await tester.pumpAndSettle();

    await _press(tester, LogicalKeyboardKey.arrowRight);
    await tester.pump();
    await _press(tester, LogicalKeyboardKey.arrowLeft);
    await tester.pump();

    expect(_selectedTrail(tester), [0]);
  });
}

Future<void> _press(WidgetTester tester, LogicalKeyboardKey key) {
  return tester.sendKeyEvent(key);
}

FocusNode? _primaryTvFocus(WidgetTester tester) {
  return FocusManager.instance.primaryFocus;
}

List<int> _selectedTrail(WidgetTester tester) {
  final state = tester.state<_FixtureState>(find.byType(_SelectionProbeMarker));
  return List.of(state.selectionTrail);
}

int _lastSelected(WidgetTester tester) {
  final trail = _selectedTrail(tester);
  return trail.last;
}

Widget _harness({required int itemCount, List<int>? onSelectedCalls}) {
  return _SelectionProbeMarker(itemCount: itemCount, onSelectedCalls: onSelectedCalls);
}

/// Builds the [TvFocusList] under a [MaterialApp] in a tall viewport so all
/// short fixtures are visible, and records every selection change.
class _SelectionProbeMarker extends StatefulWidget {
  const _SelectionProbeMarker({required this.itemCount, this.onSelectedCalls});

  final int itemCount;
  final List<int>? onSelectedCalls;

  @override
  State<_SelectionProbeMarker> createState() => _FixtureState();
}

class _FixtureState extends State<_SelectionProbeMarker> {
  final List<int> selectionTrail = [];

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: Center(
          child: SizedBox(
            width: 600,
            height: 900,
            child: TvFocusList(
              autofocus: true,
              itemCount: widget.itemCount,
              itemExtent: 72,
              onSelectionChanged: selectionTrail.add,
              onSelected: widget.onSelectedCalls?.add,
              itemBuilder: (context, i) => Center(child: Text('Item $i')),
            ),
          ),
        ),
      ),
    );
  }
}
