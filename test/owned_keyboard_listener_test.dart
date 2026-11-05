import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/owned_keyboard_listener.dart';

void main() {
  testWidgets(
      'node survives rebuild, dispatches current callback and is disposed', (
    tester,
  ) async {
    final first = <KeyEvent>[];
    final second = <KeyEvent>[];
    Widget build(ValueChanged<KeyEvent> onKeyEvent) => MaterialApp(
          home: OwnedKeyboardListener(
            autofocus: true,
            includeSemantics: false,
            onKeyEvent: onKeyEvent,
            child: const Text('TV control'),
          ),
        );

    await tester.pumpWidget(build(first.add));
    await tester.pump();
    final listener =
        tester.widget<KeyboardListener>(find.byType(KeyboardListener));
    final node = listener.focusNode;
    expect(node.skipTraversal, isTrue);
    expect(node.hasFocus, isTrue);
    expect(listener.includeSemantics, isFalse);
    await tester.sendKeyEvent(LogicalKeyboardKey.select);
    expect(first.whereType<KeyDownEvent>(), hasLength(1));

    await tester.pumpWidget(build(second.add));
    expect(
      tester.widget<KeyboardListener>(find.byType(KeyboardListener)).focusNode,
      same(node),
    );
    expect(node.hasFocus, isTrue);
    await tester.sendKeyEvent(LogicalKeyboardKey.select);
    expect(first.whereType<KeyDownEvent>(), hasLength(1));
    expect(second.whereType<KeyDownEvent>(), hasLength(1));

    await tester.pumpWidget(const SizedBox.shrink());
    expect(node.parent, isNull);
    expect(() => node.addListener(() {}), throwsFlutterError);
    expect(tester.takeException(), isNull);
  });
}
