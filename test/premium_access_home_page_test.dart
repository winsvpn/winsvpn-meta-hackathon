import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/local_security.dart';
import 'package:wins_vpn/premium_access_link.dart';

// Owner ruling 2026-10-24 ("Home page everywhere"): in every build the
// premium access button opens https://www.winsvpn.org in the external
// browser. The runtime tap is covered in widget_test.dart; these pins keep
// the decoy, Google Play (release gate S14A) and redemption rules in place.

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production source: $start');
  }
  return source.substring(first, last);
}

void main() {
  late final String source;

  setUpAll(() {
    source = File('lib/main.dart').readAsStringSync();
  });

  test('the target is the home page, with no anchor or payment route', () {
    expect(kPremiumAccessHomePageUrl, 'https://www.winsvpn.org');
    final uri = validatedHttpsUrl(kPremiumAccessHomePageUrl);
    expect(uri.host, 'www.winsvpn.org');
    expect(uri.path, isEmpty);
    expect(uri.hasFragment, isFalse);
    expect(uri.hasQuery, isFalse);
  });

  test('the label does not describe a purchase', () {
    expect(kPremiumAccessActionLabel, 'Premium Access Info');
    expect(kPremiumAccessActionLabel.toLowerCase(), isNot(contains('buy')));
    expect(source,
        contains('String get _premiumAccessActionLabel => kPremiumAccessActionLabel;'));
  });

  test('every premium button opens the home page, never the sheet', () {
    expect(
      RegExp(r'_openPremiumAccessHomePage\(\)\)').allMatches(source).length,
      3,
      reason: 'the activation button, the settings button and Renew access',
    );
    expect(
      RegExp(r'_showPaymentOptions\(').allMatches(source).length,
      1,
      reason: 'only the retained, unreachable definition remains',
    );
  });

  test('nothing opens behind the calculator decoy', () {
    final open = _between(source,
        '  Future<void> _openPremiumAccessHomePage() async {', '\n  }\n');
    final decoy = open.indexOf('if (_showDecoyCalculator) return;');
    final launch = open.indexOf('await _launchURL(');
    expect(decoy, greaterThanOrEqualTo(0));
    expect(launch, greaterThan(decoy));
    // The shared validated launcher: HTTPS validation, the native scheme
    // allowlist, and a message when no browser opens (TV devices).
    expect(open, contains('kPremiumAccessHomePageUrl'));
    expect(open, contains('failureMessage: kPremiumAccessOpenFailedMessage'));
    expect(open, contains('dismissCurrentView: false'));
    expect(open, isNot(contains('_openExternalUrl(')));
  });

  test('prepaid redemption keeps its own reachable entry', () {
    final entries = _between(source,
        '  List<Widget> _prepaidRedemptionEntries({required double tvOrder}) {',
        '\n  }\n');
    final play = entries.indexOf('if (_googlePlayBuild) return const <Widget>[];');
    final gate = entries.indexOf('if (!_canRedeemPrepaidInApp) return const <Widget>[];');
    final label = entries.indexOf('_t("Redeem a Prepaid Card")');
    expect(play, greaterThanOrEqualTo(0),
        reason: 'a constant first return drops the R2 text from Play builds');
    expect(gate, greaterThan(play));
    expect(label, greaterThan(gate));
    expect(entries, contains('_showPrepaidRedemption()'));
    final decoy = entries.indexOf('if (_showDecoyCalculator) return;');
    expect(decoy, inExclusiveRange(gate, entries.indexOf('_showPrepaidRedemption()')));
    expect(
      RegExp(r'\.\.\._prepaidRedemptionEntries\(tvOrder: ').allMatches(source).length,
      2,
      reason: 'the activation screen and the settings panel',
    );
  });

  test('release gate S14A treats the new entry as an R2 source', () {
    final gate = File('tools/android_play_redemption_gate.py').readAsStringSync();
    expect(gate,
        contains('"  List<Widget> _prepaidRedemptionEntries({required double tvOrder}) {",'));
    expect(gate, contains('"  Future<void> _showPrepaidRedemption() async {",'));
  });
}
