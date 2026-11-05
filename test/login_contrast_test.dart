import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/main.dart';

const deepBlue = Color(0xFF1B5BC4);
const darkAmber = Color(0xFF6D4C00);
const amberAccent = Color(0xFFFFC107);
const white70 = Color(0xB3FFFFFF);
const muted = Color(0xFF4B5563);
const panelComp = Color(0xFFD7D7D8);

double _lin(double c) {
  c /= 255;
  return c <= 0.03928 ? c / 12.92 : math.pow((c + 0.055) / 1.055, 2.4).toDouble();
}
double _lum(Color c) =>
    0.2126 * _lin(c.r * 255) + 0.7152 * _lin(c.g * 255) + 0.0722 * _lin(c.b * 255);
double _ratio(Color fg, Color bg) {
  final l1 = _lum(fg), l2 = _lum(bg);
  final hi = math.max(l1, l2), lo = math.min(l1, l2);
  return (hi + 0.05) / (lo + 0.05);
}

Finder _byText(String s) => find.byWidgetPredicate(
    (w) => w is Text && (w.data == s || (w.textSpan?.toPlainText() == s)));

Color? _nearestBg(WidgetTester t, String s) {
  final e = t.element(_byText(s));
  Color? acc;
  e.visitAncestorElements((a) {
    final w = a.widget;
    if (w is ColoredBox) { acc = w.color; return false; }
    if (w is Material && w.color != null) { acc = w.color; return false; }
    if (w is Container && w.decoration is BoxDecoration) {
      final c = (w.decoration as BoxDecoration).color;
      if (c != null) { acc = c; return false; }
    }
    return true;
  });
  return acc;
}

void main() {
  testWidgets('login action button label clears WCAG AA 4.5:1', (tester) async {
    await tester.pumpWidget(const MyApp());
    await tester.pump(const Duration(seconds: 1));
    expect(tester.takeException(), isNull);

    final btn = _byText('Activate Device');
    expect(btn, findsOneWidget);
    final painted = tester.widget<Text>(btn).style?.color;
    expect(painted, Colors.white);
    final bg = _nearestBg(tester, 'Activate Device');
    expect(bg, isNotNull);
    // WCAG AA for normal text: 4.5:1 of the ACTUAL painted pair.
    expect(_ratio(Colors.white, bg!), greaterThanOrEqualTo(4.5),
        reason: 'white on $bg must clear 4.5:1 (was 3.32:1 on blueAccent)');
    expect(bg, deepBlue, reason: 'and the button background is pinned deep blue');
  });

  testWidgets('login input hint and helpers are light-theme-readable',
      (tester) async {
    await tester.pumpWidget(const MyApp());
    await tester.pump(const Duration(seconds: 1));

    final accountField = find.text('XXXX-XXXX-XXXX');
    expect(accountField, findsOneWidget);
    final theme = Theme.of(tester.element(accountField));
    final hint = theme.inputDecorationTheme.hintStyle?.color;
    expect(hint, isNotNull);
    // Must not be the 72%-alpha muted that could not clear 4.5 on light panels.
    expect(hint!.a, greaterThanOrEqualTo(0.95),
        reason: 'hint must be near-opaque to clear 4.5:1 on light panels');
    expect(hint, muted,
        reason: 'hint pinned to full-strength muted text');
    expect(_ratio(hint, panelComp), greaterThanOrEqualTo(4.5));

    // Every login TextField: no dark-theme-only helper foregrounds.
    for (final tf in tester.widgetList<TextField>(find.byType(TextField))) {
      final hs = tf.decoration?.helperStyle?.color;
      if (hs == null) continue;
      expect(hs, isNot(amberAccent), reason: 'no bright yellow on light panel');
      expect(hs, isNot(white70), reason: 'no near-white helper on light panel');
      expect(_ratio(hs, panelComp), greaterThanOrEqualTo(4.5),
          reason: 'helper $hs must clear 4.5:1 on the light panel');
    }
  });
}
