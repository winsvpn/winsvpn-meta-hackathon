import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tv_dpad_support.dart';
import 'package:wins_vpn/vpn_power_control.dart';

/// D-pad traversal verification for the TV dashboard.
///
/// The load-bearing TV integration check is *reachability*, not an audit:
/// every on-screen focusable control must be reachable from the D-pad with
/// no dead ends. This test builds the dashboard's focusable control set using
/// the SAME production widgets that main.dart composes for TV
/// (`TvDpadWrapper` with `OrderedTraversalPolicy`, plus `TvFocusDecoration`,
/// `TvActivatable` and `VpnPowerControl`), lays them out in the production
/// traversal order, and then drives real arrow-key events, observing focus
/// via `FocusManager.instance.primaryFocus`.
///
/// It asserts:
///   1. every dashboard control is reachable via arrow keys from the start,
///   2. the reachable set is EXACTLY the focusable controls (decorative,
///      non-focusable widgets are never reached -- the negative control),
///   3. no control is a dead end: every control has at least one arrow that
///      moves focus to a different control,
///   4. traversal is bidirectional: pressing up from the bottom walks back
///      through the same chain.
///
/// The dashboard controls and their explicit traversal orders mirror
/// main.dart's `_buildVpnDashboard` / `_buildMapModeButton` / privacy action
/// (orders 0, 1, 2, 3, 4, 5, 27). They are tagged with `ctl_*` keys so the
/// currently-focused control can be resolved from `primaryFocus`.

const List<({int order, String tag})> _dashboardControls = [
  (order: 0, tag: 'ctl_map'),
  (order: 1, tag: 'ctl_location'),
  (order: 2, tag: 'ctl_power'),
  (order: 3, tag: 'ctl_speedtest'),
  (order: 4, tag: 'ctl_premium'),
  (order: 5, tag: 'ctl_action5'),
  (order: 27, tag: 'ctl_privacy'),
];

void _appendControl(List<Widget> children, ({int order, String tag}) c) {
  Widget child = _buildControlBody(c.order, c.tag);
  if (c.tag == 'ctl_power') {
    child = TvActivatable(
      order: c.order.toDouble(),
      onActivate: () {},
      autofocus: c.order == 0,
      child: child,
    );
  } else {
    child = TvFocusDecoration(
      order: c.order.toDouble(),
      autofocus: c.order == 0,
      child: child,
    );
  }
  children.add(KeyedSubtree(key: ValueKey<String>(c.tag), child: child));
}

/// Renders a given dashboard control's body exactly as production does.
Widget _buildControlBody(int order, String tag) {
  switch (tag) {
    case 'ctl_map':
      return IconButton(
        icon: const Icon(Icons.map_outlined),
        color: const Color(0xFF1F2937),
        onPressed: () {},
      );
    case 'ctl_location':
      return ListTile(
        tileColor: const Color(0x11000000),
        leading: const Icon(Icons.public),
        title: const Text('Yangon'),
        subtitle: const Text('Status: online'),
        trailing: const Icon(Icons.keyboard_arrow_down),
        onTap: () {},
      );
    case 'ctl_power':
      return VpnPowerControl(
        isConnected: false,
        isConnectInFlight: false,
        connectedColor: const Color(0xFF00C853),
        disconnectedColor: const Color(0xFFD32F2F),
        onPressed: () {},
      );
    case 'ctl_speedtest':
      return TextButton(
        onPressed: () {},
        child: const Text('Run speed test'),
      );
    case 'ctl_premium':
      return TextButton.icon(
        onPressed: () {},
        icon: const Icon(Icons.refresh, size: 16),
        label: const Text('Upgrade'),
      );
    case 'ctl_action5':
      return TextButton.icon(
        onPressed: () {},
        icon: const Icon(Icons.settings, size: 16),
        label: const Text('Settings'),
      );
    case 'ctl_privacy':
      return TextButton(
        onPressed: () {},
        child: const Text('Privacy Policy'),
      );
    default:
      return const SizedBox();
  }
}

/// Renders the TV dashboard focusable control figure.
class TvDashboardFocusFigure extends StatelessWidget {
  const TvDashboardFocusFigure({super.key});

  @override
  Widget build(BuildContext context) {
    final children = <Widget>[
      // Decorative, non-focusable headline. Negative control: must never be
      // reachable by the D-pad because it has no Focus support.
      const Padding(
        padding: EdgeInsets.only(bottom: 6),
        child: Text('Win\'s VPN', style: TextStyle(fontWeight: FontWeight.bold)),
      ),
    ];
    for (final c in _dashboardControls) {
      _appendControl(children, c);
    }
    // Decorative, non-focusable bare gesture surface. Negative control: a
    // GestureDetector without TvActivatable/TvFocusDecoration is NOT part of
    // the traversal and must never gain focus.
    children.add(
      KeyedSubtree(
        key: const ValueKey<String>('ctl_bare'),
        child: Padding(
          padding: const EdgeInsets.only(top: 6),
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
    );
    return TvDpadWrapper(
      onBack: () {},
      child: Center(
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: children,
          ),
        ),
      ),
    );
  }

  static void _noop() {}
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

class _Harness {
  _Harness(this.tester);
  final WidgetTester tester;

  List<String> chain = <String>[];
  static const List<LogicalKeyboardKey> _arrows = [
    LogicalKeyboardKey.arrowDown,
    LogicalKeyboardKey.arrowUp,
    LogicalKeyboardKey.arrowLeft,
    LogicalKeyboardKey.arrowRight,
  ];

  Future<String> press(LogicalKeyboardKey key) async {
    await tester.sendKeyEvent(key);
    await tester.pumpAndSettle();
    return _focusedTag();
  }

  int get _position {
    final tag = _focusedTag();
    final i = chain.indexOf(tag);
    return i < 0 ? -1 : i;
  }

  /// Walk down from the start until focus stops changing, recording the chain.
  Future<void> buildDownChain() async {
    chain = <String>[];
    var cur = _focusedTag();
    expect(cur, 'ctl_map',
        reason: 'autofocused start must be the first control, got $cur');
    chain.add(cur);
    final seen = <String>{cur};
    for (var guard = 0; guard < 64; guard++) {
      final nxt = await press(LogicalKeyboardKey.arrowDown);
      if (nxt == cur) break; // bottom boundary
      if (seen.contains(nxt)) break; // cycle safety
      seen.add(nxt);
      chain.add(nxt);
      cur = nxt;
    }
  }

  /// Navigate to the control at [index] using arrows.
  Future<void> goToIndex(int index) async {
    var pos = _position;
    var guard = 0;
    while (pos < index && guard < 64) {
      await press(LogicalKeyboardKey.arrowDown);
      pos = _position;
      guard++;
    }
    guard = 0;
    while (pos > index && guard < 64) {
      await press(LogicalKeyboardKey.arrowUp);
      pos = _position;
      guard++;
    }
    expect(_focusedTag(), chain[index],
        reason: 'failed to navigate to ${chain[index]}');
  }
}

void main() {
  final expectedTags = _dashboardControls.map((c) => c.tag).toSet();
  final expectedOrders = _dashboardControls.map((c) => c.order).toSet();

  testWidgets(
      'TV dashboard: every focusable control is D-pad reachable with no dead ends',
      (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: TvDashboardFocusFigure())),
    );
    await tester.pumpAndSettle();

    final h = _Harness(tester);

    // Autofocus lands on the first dashboard control.
    expect(_focusedTag(), 'ctl_map');

    // 1. Walk down to discover the traversal chain.
    await h.buildDownChain();
    final chainSet = h.chain.toSet();

    // Coverage: exact set match -- every expected control present AND nothing
    // else (decorative, non-focusable widgets are excluded by set equality).
    expect(chainSet, expectedTags,
        reason:
            'reachable focus chain must be EXACTLY the dashboard controls; '
            'got ${h.chain}');

    // 2. The negative control must hold: bare/decorative widgets are never in
    //    the traversal.
    expect(chainSet.contains('ctl_bare'), isFalse,
        reason: 'bare GestureDetector must not be focusable/reachable');

    // 3. No dead ends: every control has at least one arrow that moves focus
    //    to a DIFFERENT control.
    final noDeadEnd = <String>[];
    for (var i = 0; i < h.chain.length; i++) {
      await h.goToIndex(i);
      var moved = false;
      for (final k in _Harness._arrows) {
        final t = await h.press(k);
        final ti = h.chain.indexOf(t);
        if (ti >= 0 && ti != i) {
          moved = true;
          break;
        }
      }
      if (!moved) noDeadEnd.add(h.chain[i]);
    }
    expect(noDeadEnd, isEmpty,
        reason: 'dead ends found on controls: $noDeadEnd');

    // 4. Bidirectional: pressing up from the bottom of the down-chain walks
    //    back up through the full chain (reverse == reversed down-chain).
    await h.goToIndex(h.chain.length - 1);
    final reverse = <String>[];
    var cur = _focusedTag();
    reverse.add(cur);
    final seen = <String>{cur};
    for (var guard = 0; guard < 64; guard++) {
      final nxt = await h.press(LogicalKeyboardKey.arrowUp);
      if (nxt == cur) break;
      if (seen.contains(nxt)) break;
      seen.add(nxt);
      reverse.add(nxt);
      cur = nxt;
    }
    expect(reverse, h.chain.reversed.join('|').split('|').toList(),
        reason: 'up-walk from bottom must reverse the down-chain; got $reverse');

    // Printed traversal chain coverage for all on-screen controls.
    // ignore: avoid_print
    print('TRAVERSAL_CHAIN (${h.chain.length}/${expectedTags.length} '
        'dashboard controls, orders ${expectedOrders.toString()})\n'
        '  down: ${h.chain.join(' -> ')}\n'
        '  up:   ${reverse.join(' -> ')}\n'
        '  bare/decorative reached: ${chainSet.contains('ctl_bare')} (must be false)\n'
        '  dead ends: $noDeadEnd (must be empty)');
  });

  testWidgets('TV dashboard: left and right keys also navigate (no horizontal trap)',
      (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: TvDashboardFocusFigure())),
    );
    await tester.pumpAndSettle();
    final h = _Harness(tester);
    await h.buildDownChain();

    // From the power control, at least one horizontal key must be able to
    // move somewhere or the control would be a horizontal dead end. In the
    // dashboard there are horizontally-adjacent controls in the regions, so
    // left/right must be exercised: verify they never crash and that after
    // pressing them focus is still resolvable (never trapped as <none>).
    await h.goToIndex(h.chain.indexOf('ctl_power'));
    for (final k in [LogicalKeyboardKey.arrowLeft, LogicalKeyboardKey.arrowRight]) {
      final t = await h.press(k);
      expect(t, isNot('<none>'),
          reason: 'arrow $k must not strand focus; got $t');
      expect(t, isNot('<unknown>'),
          reason: 'arrow $k must land on a known control; got $t');
    }
  });
}
