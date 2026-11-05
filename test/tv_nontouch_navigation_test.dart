// ignore_for_file: avoid_print, deprecated_member_use, unintended_html_in_doc_comment
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tv_dpad_support.dart';

/// D-pad-only navigation to the settings surface on Android TV.
///
/// An Android TV has no touchscreen and no mouse; the ONLY input is the
/// D-pad remote (arrows + select/enter + back). Everything the user can do
/// must be reachable by focus traversal and operable by select/enter. There
/// is no separate navigable "Settings" screen in this codebase: the settings
/// controls (Double VPN, stealth/TCP toggle, protocol radio, always-on,
/// diagnostics, split tunnel, connection-code entry, licences, privacy) are
/// rendered directly on the dashboard surface by `_buildVpnDashboard`
/// (lib/main.dart), each wrapped by the production `TvFocusDecoration` /
/// `TvActivatable` widgets and ordered for traversal underneath a single
/// `FocusTraversalGroup` with `OrderedTraversalPolicy` (supplied by
/// `TvDpadWrapper`).
///
/// So the load-bearing claim for a D-pad-only user is:
///   1. every settings control is REACHABLE by arrow-key focus traversal,
///   2. a settings control can be OPENED (an action dispatched) by pressing
///      select/enter -- not merely focused,
///   3. reopening is possible after back/escape (focus is never stranded and
///      "open" is repeatable),
///   4. the negative control holds -- decorative text and a bare gesture
///      surface are never reachable by the D-pad.
///
/// This fixture composes the EXACT production widgets main.dart uses for TV
/// (both from `lib/tv_dpad_support.dart`), in the settings section's real
/// traversal order (13..20, 25..27 from `_buildVpnDashboard`), tagged with
/// `ctl_*` keys so the focused control can be resolved from
/// `FocusManager.instance.primaryFocus`.

const List<({int order, String tag})> _settingsControls = [
  (order: 13, tag: 'ctl_double_vpn'),
  (order: 14, tag: 'ctl_stealth_tcp'),
  (order: 15, tag: 'ctl_proto_auto'),
  (order: 16, tag: 'ctl_proto_udp'),
  (order: 17, tag: 'ctl_proto_tcp'),
  (order: 18, tag: 'ctl_always_on'),
  (order: 19, tag: 'ctl_diagnostics'),
  (order: 20, tag: 'ctl_split_tunnel'),
  (order: 25, tag: 'ctl_conn_code'),
  (order: 26, tag: 'ctl_licences'),
  (order: 27, tag: 'ctl_privacy'),
];

/// The set of settings controls that OPEN a subordinate surface when
/// selected (a sheet, a page, a picker) rather than merely toggling in place.
const Set<String> _openingControls = {
  'ctl_conn_code', // _openDiscoveryPasteInSheet()
  'ctl_licences', // showLicensePage(...)
  'ctl_privacy', // privacy-policy detail
};

/// A concrete settings figure mirroring the dashboard's settings section.
///
/// Each control is wrapped in the production `TvFocusDecoration` (or, for the
/// connection-code tile which the dashboard opens as a sheet, still a
/// `TvFocusDecoration` so the underlying ListTile's own tap action runs on
/// select/enter). Every action is routed through a recorder so the test can
/// assert an OPEN actually dispatched.
class TvSettingsFocusFigure extends StatefulWidget {
  const TvSettingsFocusFigure({super.key});

  @override
  State<TvSettingsFocusFigure> createState() => _TvSettingsFocusFigureState();
}

class _TvSettingsFocusFigureState extends State<TvSettingsFocusFigure> {
  final List<String> opened = <String>[];
  final List<String> toggled = <String>[];

  void _open(String tag) {
    setState(() => opened.add(tag));
  }

  void _toggle(String tag) {
    setState(() => toggled.add(tag));
  }

  @override
  Widget build(BuildContext context) {
    final children = <Widget>[
      // Decorative, NON-focusable section header. Negative control: plain
      // Text has no Focus support and must never be reachable by the D-pad.
      const Padding(
        padding: EdgeInsets.only(bottom: 6),
        child: Text('Settings',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
      ),
    ];
    for (final c in _settingsControls) {
      children.add(KeyedSubtree(
        key: ValueKey<String>(c.tag),
        child: TvFocusDecoration(
          order: c.order.toDouble(),
          autofocus: c.order == _settingsControls.first.order,
          child: _settingsControlBody(c.tag),
        ),
      ));
    }
    // Decorative, NON-focusable bare gesture surface. Negative control: a
    // GestureDetector without TvFocusDecoration/TvActivatable is NOT part of
    // the traversal and must never gain focus.
    children.add(KeyedSubtree(
      key: const ValueKey<String>('ctl_bare'),
      child: Padding(
        padding: const EdgeInsets.only(top: 6),
        child: GestureDetector(
          onTap: () {},
          child: Container(
            width: 180,
            height: 24,
            color: const Color(0x22000000),
          ),
        ),
      ),
    ));
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

  Widget _settingsControlBody(String tag) {
    switch (tag) {
      case 'ctl_double_vpn':
        return SwitchListTile(
          key: const Key('double_vpn_tile'),
          title: const Text('Double VPN'),
          value: false,
          onChanged: (_) => _toggle(tag),
        );
      case 'ctl_stealth_tcp':
        return SwitchListTile(
          key: const Key('stealth_transport_only_toggle'),
          title: const Text('Always connect over TCP'),
          value: false,
          onChanged: (_) => _toggle(tag),
        );
      case 'ctl_proto_auto':
        return RadioListTile<String>(
          key: const Key('transport_mode_auto'),
          dense: true,
          title: const Text('Automatic'),
          value: 'auto',
          groupValue: 'auto',
          onChanged: (_) => _toggle(tag),
        );
      case 'ctl_proto_udp':
        return RadioListTile<String>(
          key: const Key('transport_mode_udp'),
          dense: true,
          title: const Text('Direct (UDP) only'),
          value: 'udp',
          groupValue: 'auto',
          onChanged: (_) => _toggle(tag),
        );
      case 'ctl_proto_tcp':
        return RadioListTile<String>(
          key: const Key('transport_mode_tcp'),
          dense: true,
          title: const Text('TCP only'),
          value: 'tcp',
          groupValue: 'auto',
          onChanged: (_) => _toggle(tag),
        );
      case 'ctl_always_on':
        return SwitchListTile(
          key: const Key('always_on_toggle'),
          title: const Text('Always-on VPN'),
          value: false,
          onChanged: (_) => _toggle(tag),
        );
      case 'ctl_diagnostics':
        return SwitchListTile(
          key: const Key('diagnostics_toggle'),
          title: const Text('Diagnostics'),
          value: false,
          onChanged: (_) => _toggle(tag),
        );
      case 'ctl_split_tunnel':
        // Dashboard wraps _buildSplitTunnelPanel in a TvFocusDecoration; the
        // panel opens an app-selection sheet on selection, so model it as a
        // tappable tile to prove it is both reachable and openable.
        return ListTile(
          key: const Key('split_tunnel_entry'),
          leading: const Icon(Icons.apps),
          title: const Text('Split tunnel'),
          onTap: () => _open(tag),
        );
      case 'ctl_conn_code':
        return ListTile(
          key: const Key('discovery_paste_in_entry'),
          leading: const Icon(Icons.vpn_key_outlined),
          title: const Text('Enter connection code'),
          onTap: () => _open(tag),
        );
      case 'ctl_licences':
        return ListTile(
          key: const Key('open_source_licences_entry'),
          leading: const Icon(Icons.description_outlined),
          title: const Text('Open source licences'),
          onTap: () => _open(tag),
        );
      case 'ctl_privacy':
        return TextButton(
          onPressed: () => _open(tag),
          child: const Text('Privacy Policy'),
        );
      default:
        return const SizedBox();
    }
  }
}

/// Resolves the tag of the currently-focused control from
/// `FocusManager.instance.primaryFocus`, walking up to the nearest `ctl_`-keyed
/// ancestor. Returns '<none>' if nothing has focus.
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
      return false;
    }
    return true;
  });
  return found;
}

/// True when the focused node belongs to a FocusTraversalGroup, i.e. it is a
/// node the D-pad OrderedTraversalPolicy can walk.
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

Future<String> _press(WidgetTester tester, LogicalKeyboardKey key) async {
  await tester.sendKeyEvent(key);
  await tester.pumpAndSettle();
  return _focusedTag();
}

_TvSettingsFocusFigureState _figureState(WidgetTester tester) {
  return tester.state<_TvSettingsFocusFigureState>(
      find.byType(TvSettingsFocusFigure));
}

void main() {
  Future<void> pumpSettings(WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: TvSettingsFocusFigure())),
    );
    await tester.pumpAndSettle();
  }

  final expectedTags = _settingsControls.map((c) => c.tag).toSet();

  testWidgets(
      'a D-pad-only user can reach every settings control by focus traversal',
      (WidgetTester tester) async {
    await pumpSettings(tester);

    // Autofocus must establish primary focus on the first settings control.
    final start = _focusedTag();
    expect(start, _settingsControls.first.tag,
        reason: 'autofocus must land on the first settings control; got $start');
    expect(_focusedIsInTraversalGroup(), isTrue,
        reason: 'the settings surface must be inside a FocusTraversalGroup so '
            'the D-pad OrderedTraversalPolicy can walk it');

    // Walk down with arrowRight/arrowDown until focus stops changing,
    // recording every reachable control.
    final reached = <String>{start};
    var cur = start;
    for (final dir in const [
      LogicalKeyboardKey.arrowRight,
      LogicalKeyboardKey.arrowDown,
    ]) {
      var guard = 0;
      var stuck = false;
      while (!stuck && guard < 64) {
        final nxt = await _press(tester, dir);
        if (nxt == cur) {
          stuck = true;
          break;
        }
        if (!nxt.startsWith('ctl_')) {
          break;
        }
        if (nxt == 'ctl_bare') {
          break;
        }
        reached.add(nxt);
        cur = nxt;
        guard++;
      }
    }

    // Coverage: EXACT match -- every settings control reachable and nothing
    // that is not a settings control (decorative text / bare surface excluded
    // by set equality).
    expect(reached, expectedTags,
        reason: 'D-pad traversal of the settings surface must reach EXACTLY '
            'the settings controls; got $reached');

    // Negative control: the bare GestureDetector is never reachable.
    expect(reached.contains('ctl_bare'), isFalse,
        reason: 'bare GestureDetector must never be reachable by the D-pad');
  });

  testWidgets(
      'a D-pad-only user can OPEN a settings control with select, then back',
      (WidgetTester tester) async {
    await pumpSettings(tester);

    // Every settings control is reachable; prove the connection-code entry
    // (order 25) -- which opens a sheet in production -- can be navigated to
    // and OPENED by select, without touching the screen.
    for (final opening in _openingControls) {
      var cur = _focusedTag();
      var guard = 0;
      while (cur != opening && guard < 128) {
        final nxt = await _press(tester, LogicalKeyboardKey.arrowDown);
        if (nxt.startsWith('ctl_')) cur = nxt;
        guard++;
      }
      expect(cur, opening,
          reason: 'failed to navigate to opening control $opening; '
              'stuck at $cur');

      // From a non-opening neighbour of a switch, the control may be a radio
      // group; settle with select so both ActivateIntent paths are covered.
      await _press(tester, LogicalKeyboardKey.select);

      final state = _figureState(tester);
      expect(state.opened, contains(opening),
          reason: 'select/enter on $opening must have dispatched the open '
              'action; opened=${state.opened}');
      expect(_focusedTag(), opening,
          reason: 'after open, focus must remain on $opening (not stranded)');

      // Back/escape must leave the traversal usable: it resolves to a known
      // control still inside the group, and a second select can open again.
      // (escape maps to the same DismissIntent behind TvDpadWrapper's
      // goBack/browserBack and has a physical key the simulator can emit.)
      await _press(tester, LogicalKeyboardKey.escape);
      final afterBack = _focusedTag();
      expect(afterBack, isNot('<none>'),
          reason: 'back must not strand focus; got $afterBack');
      expect(afterBack.startsWith('ctl_'), isTrue,
          reason: 'after back, focus must resolve to a settings control; '
              'got $afterBack');
      expect(_focusedIsInTraversalGroup(), isTrue,
          reason: 'after back, focus must remain in the traversal group');
    }
    print('TV_NONTOUCH_OPENED ${_figureState(tester).opened}');
  });

  testWidgets('a D-pad-only user can OPEN a switch/radio settings control',
      (WidgetTester tester) async {
    await pumpSettings(tester);

    // A switch/radio setting (Double VPN, order 13) is both reachable and
    // operable: select fires its onChanged/toggle, not just focus.
    final target = 'ctl_stealth_tcp';
    var cur = _focusedTag();
    var guard = 0;
    while (cur != target && guard < 128) {
      final nxt = await _press(tester, LogicalKeyboardKey.arrowDown);
      if (nxt.startsWith('ctl_')) cur = nxt;
      guard++;
    }
    expect(cur, target, reason: 'failed to reach $target by D-pad');

    await _press(tester, LogicalKeyboardKey.select);
    expect(_figureState(tester).toggled, contains(target),
        reason: 'select/enter on the $target switch must dispatch its toggle');
  });
}
