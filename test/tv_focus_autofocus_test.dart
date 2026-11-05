import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tv_focus.dart';

// Machine-written assertion (lane gen_tv_focus_widget_auto, 2026-08-11).
//
// Question under test: is the first focusable widget auto-focused after launch
// for a D-pad remote? The list's Focus node is the "first focusable" element a
// D-pad lands on. Two controls, so the positive assertion has a negative
// counterpart to fail against:
//   * autofocus=true  -> primary focus lands on the list node after launch.
//   * autofocus=false -> the list is reachable but does NOT steal focus.
void main() {
  testWidgets(
      'first focusable list is auto-focused after launch when autofocus is set',
      (tester) async {
    final focusNode = FocusNode(debugLabel: 'first-focusable-list');
    addTearDown(focusNode.dispose);

    await tester.pumpWidget(_harness(autofocus: true, focusNode: focusNode));
    await tester.pumpAndSettle();

    expect(
      focusNode.hasFocus,
      isTrue,
      reason: 'the first focusable widget must be auto-focused for a '
          'D-pad remote after launch',
    );
    expect(
      FocusManager.instance.primaryFocus,
      same(focusNode),
      reason: 'the list must hold the primary focus, not an unrelated node',
    );
  });

  testWidgets(
      'without autofocus the list is focusable but does not steal focus',
      (tester) async {
    final focusNode = FocusNode(debugLabel: 'first-focusable-list');
    addTearDown(focusNode.dispose);

    await tester.pumpWidget(_harness(autofocus: false, focusNode: focusNode));
    await tester.pumpAndSettle();

    expect(
      focusNode.hasFocus,
      isFalse,
      reason: 'autofocus=false must NOT grab focus on launch; this is the '
          'negative control that keeps the positive assertion honest',
    );
  });
}

Widget _harness({required bool autofocus, required FocusNode focusNode}) {
  return MaterialApp(
    home: Scaffold(
      body: Center(
        child: SizedBox(
          width: 600,
          height: 900,
          child: TvFocusList(
            autofocus: autofocus,
            focusNode: focusNode,
            itemCount: 3,
            itemExtent: 72,
            onSelected: (_) {},
            itemBuilder: (context, i) => Center(child: Text('Item $i')),
          ),
        ),
      ),
    ),
  );
}
