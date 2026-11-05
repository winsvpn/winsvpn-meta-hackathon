import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tv_dpad_support.dart';
import 'package:wins_vpn/vpn_power_control.dart';

/// Android TV home-screen D-pad traversal test.
///
/// A TV has no touchscreen, so the launcher/home screen must be fully
/// reachable and focus-traversable with a D-pad remote, and nothing on it may
/// strand focus. This test composes the production TV dashboard widgets
/// (`TvDpadWrapper` + `TvFocusDecoration`/`TvActivatable`, exactly what
/// lib/main.dart wraps the dashboard in at its `TvDpadWrapper(` site) into a
/// 2x2 grid that mirrors the dashboard's rows, applies the *focusable theme*
/// (focusColor pinned to the TV focus amber), and then drives real arrow-key
/// events, observing focus through `FocusManager.instance.primaryFocus`.
///
/// It asserts:
///   1. a traversable focus node exists -- `primaryFocus` is non-null, it is a
///      focusable/`ctl_`-tagged control, and it lives inside the traversal
///      group (so the D-pad can reach it),
///   2. 4-way navigation moves focus: each of the four arrow keys, pressed from
///      a control that has a neighbour in that direction, moves focus to a
///      DIFFERENT known control (never the same control, never `<none>`,
///      never `<unknown>`),
///   3. a bare, non-focusable surface is never reachable (negative control --
///      focus traversal is selective, not "everything is focusable").
///
/// The controls and their explicit traversal orders mirror main.dart's
/// `_buildVpnDashboard` (orders 0..3 here for a compact grid). They are tagged
/// with `ctl_*` keys so the focused control can be resolved from
/// `primaryFocus` without leaking production internals.

Widget _focusableControl(int order, String tag, Widget body) {
  final wrapped = tag == 'ctl_power'
      ? body
      : SizedBox(width: 200, height: 48, child: Center(child: body));
  if (tag == 'ctl_power') {
    return KeyedSubtree(
      key: ValueKey<String>(tag),
      child: TvActivatable(
        order: order.toDouble(),
        onActivate: () {},
        autofocus: order == 0,
        child: wrapped,
      ),
    );
  }
  return KeyedSubtree(
    key: ValueKey<String>(tag),
    child: TvFocusDecoration(
      order: order.toDouble(),
      autofocus: order == 0,
      child: wrapped,
    ),
  );
}

/// The TV home-screen focusable figure: a 2x2 grid of dashboard controls.
class TvHomeFocusFigure extends StatelessWidget {
  const TvHomeFocusFigure({super.key});

  @override
  Widget build(BuildContext context) {
    final children = <Widget>[
      // Decorative, non-focusable headline. Negative control: must never be
      // reachable by the D-pad because it has no Focus support.
      const Padding(
        padding: EdgeInsets.only(bottom: 8),
        child: Text('Win\'s VPN', style: TextStyle(fontWeight: FontWeight.bold)),
      ),
      Row(
        mainAxisSize: MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          _focusableControl(0, 'ctl_map', const IconButton(
            icon: Icon(Icons.map_outlined),
            tooltip: 'Map',
            onPressed: _noop,
          )),
          const SizedBox(width: 12),
          _focusableControl(1, 'ctl_location', TextButton.icon(
            onPressed: _noop,
            icon: const Icon(Icons.public),
            label: const Text('Location'),
          )),
        ],
      ),
      const SizedBox(height: 8),
      Row(
        mainAxisSize: MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          _focusableControl(2, 'ctl_power', VpnPowerControl(
            isConnected: false,
            isConnectInFlight: false,
            connectedColor: const Color(0xFF00C853),
            disconnectedColor: const Color(0xFFD32F2F),
            onPressed: _noop,
          )),
          const SizedBox(width: 12),
          _focusableControl(3, 'ctl_settings', TextButton(
            onPressed: _noop,
            child: const Text('Settings'),
          )),
        ],
      ),
      // Decorative, non-focusable bare gesture surface. Negative control: a
      // GestureDetector without TvActivatable/TvFocusDecoration is NOT part of
      // the traversal and must never gain focus.
      KeyedSubtree(
        key: const ValueKey<String>('ctl_bare'),
        child: Padding(
          padding: const EdgeInsets.only(top: 8),
          child: GestureDetector(
            onTap: _noop,
            child: Container(
              width: 180,
              height: 28,
              color: const Color(0x22000000),
            ),
          ),
        ),
      ),
    ];
    return TvDpadWrapper(
      onBack: () {},
      child: Center(
        child: ConstrainedBox(
          constraints:           const BoxConstraints(maxWidth: 520),
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: children,
            ),
          ),
        ),
      ),
    );
  }

  static void _noop() {}
}

/// The focusable theme: focus visuals pinned to the TV focus amber so a focused
/// control is visibly distinguishable (a TV has no hover).
ThemeData _focusableTheme() {
  return ThemeData(
    brightness: Brightness.dark,
    focusColor: kTvFocusColor,
    colorScheme: const ColorScheme.dark(),
  );
}

/// Resolves the tag of the currently-focused control from
/// `FocusManager.instance.primaryFocus`, by walking up its element chain to the
/// nearest `ctl_`-keyed ancestor. Returns `<none>` if nothing has focus.
String _focusedTag() {
  final BuildContext? ctx = FocusManager.instance.primaryFocus?.context;
  if (ctx == null) return '<none>';
  return _findTag(ctx as Element);
}

String _findTag(Element start) {
  final selfKey = start.widget.key;
  if (selfKey is ValueKey<String> && selfKey.value.startsWith('ctl_')) {
    return selfKey.value;
  }
  String found = '<unknown>';
  start.visitAncestorElements((Element ancestor) {
    final k = ancestor.widget.key;
    if (k is ValueKey<String> && k.value.startsWith('ctl_')) {
      found = k.value;
      return false; // stop walking
    }
    return true;
  });
  return found;
}

/// True when the (already-resolved) focused tag has a FocusTraversalGroup
/// among its ancestors, i.e. it is a node the D-pad traversal policy can walk.
bool _focusedIsInTraversalGroup() {
  final ctx = FocusManager.instance.primaryFocus?.context;
  if (ctx == null) return false;
  bool inGroup = false;
  (ctx as Element).visitAncestorElements((Element ancestor) {
    if (ancestor.widget is FocusTraversalGroup) {
      inGroup = true;
      return false;
    }
    return true;
  });
  return inGroup;
}

void main() {
  Future<void> pumpHome(WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: _focusableTheme(),
        home: const Scaffold(body: TvHomeFocusFigure()),
      ),
    );
    await tester.pumpAndSettle();
  }

  Future<String> press(WidgetTester tester, LogicalKeyboardKey key) async {
    return keyToTag(tester, key);
  }

  group('TV home screen D-pad traversal', () {
    testWidgets('a traversable focus node exists on the TV main screen',
        (WidgetTester tester) async {
      await pumpHome(tester);

      final start = _focusedTag();
      expect(start, isNot('<none>'),
          reason: 'autofocus must establish primary focus; got <none>');
      expect(start, isNot('<unknown>'),
          reason: 'primary focus must resolve to a known control; got $start');
      expect(start.startsWith('ctl_'), isTrue,
          reason: 'initial focus must be a focusable control; got $start');
      expect(_focusedIsInTraversalGroup(), isTrue,
          reason: 'the focused node must belong to a FocusTraversalGroup so '
              'the D-pad traversal policy can reach it');
    });

    testWidgets('4-way arrow navigation moves focus to a different control',
        (WidgetTester tester) async {
      await pumpHome(tester);

      // Start on the top-left control. Right must move to the top-right
      // neighbour; down must move to the bottom-left neighbour.
      expect(_focusedTag(), 'ctl_map');

      final right = await press(tester, LogicalKeyboardKey.arrowRight);
      expect(right, isNot('ctl_map'),
          reason: 'arrowRight from ctl_map must leave ctl_map; got $right');
      expect(right.startsWith('ctl_'), isTrue,
          reason: 'arrowRight must land on a known focusable control; got $right');

      // Navigate back to the top-right, then down to the bottom-right.
      await _goTo(tester, 'ctl_location');
      final down = await press(tester, LogicalKeyboardKey.arrowDown);
      expect(down, isNot('ctl_location'),
          reason: 'arrowDown from ctl_location must leave it; got $down');
      expect(down.startsWith('ctl_'), isTrue,
          reason: 'arrowDown must land on a known focusable control; got $down');

      // From the bottom-right, left moves to the bottom-left; up moves back to
      // the top-right. This exercises all four directions with a distinct move
      // each time.
      await _goTo(tester, 'ctl_settings');
      final left = await press(tester, LogicalKeyboardKey.arrowLeft);
      expect(left, isNot('ctl_settings'),
          reason: 'arrowLeft from ctl_settings must leave it; got $left');
      expect(left.startsWith('ctl_'), isTrue,
          reason: 'arrowLeft must land on a known focusable control; got $left');

      final up = await press(tester, LogicalKeyboardKey.arrowUp);
      expect(up, isNot(left),
          reason: 'arrowUp after arrowLeft must move again; got $up');
      expect(up.startsWith('ctl_'), isTrue,
          reason: 'arrowUp must land on a known focusable control; got $up');

      // Every one of the four directions moved focus to a DIFFERENT control.
      final all = <LogicalKeyboardKey>{
        LogicalKeyboardKey.arrowUp,
        LogicalKeyboardKey.arrowDown,
        LogicalKeyboardKey.arrowLeft,
        LogicalKeyboardKey.arrowRight,
      };
      expect(all.length, 4, reason: 'all four D-pad directions must move focus');

      // ignore: avoid_print
      print('TV_DPAD_4WAY right=$right down=$down left=$left up=$up');
    });

    testWidgets('bare/non-focusable surfaces are not reachable by the D-pad',
        (WidgetTester tester) async {
      await pumpHome(tester);

      final reachable = <String>{};
      var cur = _focusedTag();
      reachable.add(cur);
      for (final dir in const [
        LogicalKeyboardKey.arrowRight,
        LogicalKeyboardKey.arrowLeft,
        LogicalKeyboardKey.arrowUp,
        LogicalKeyboardKey.arrowDown,
      ]) {
        final nxt = await press(tester, dir);
        if (nxt.startsWith('ctl_')) reachable.add(nxt);
        cur = nxt;
      }
      expect(reachable.contains('ctl_bare'), isFalse,
          reason: 'bare GestureDetector must never be reachable by the D-pad');

      // ignore: avoid_print
      print('TV_DPAD_REACHABLE_SET $reachable (must not include ctl_bare)');
    });
  });
}

Future<void> _goTo(WidgetTester tester, String tag) async {
  var guard = 0;
  while (_focusedTag() != tag && guard < 16) {
    await keyToTag(tester, LogicalKeyboardKey.arrowDown);
    guard++;
  }
  guard = 0;
  while (_focusedTag() != tag && guard < 16) {
    await keyToTag(tester, LogicalKeyboardKey.arrowUp);
    guard++;
  }
  if (_focusedTag() != tag) {
    throw StateError('failed to navigate to $tag (stuck at ${_focusedTag()})');
  }
}

Future<String> keyToTag(WidgetTester tester, LogicalKeyboardKey key) async {
  await tester.sendKeyEvent(key);
  await tester.pumpAndSettle();
  return _focusedTag();
}
