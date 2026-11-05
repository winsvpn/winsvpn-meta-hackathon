import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:wins_vpn/prepaid_redemption.dart';

// Round R2 Burmese guard for the app. Fails if a new R2 string, or a hub
// refusal the redemption dialog shows verbatim, has no Burmese entry in
// main.dart's `_t` map, or if the dialog or the payment sheet stops routing
// its text through that lookup.
//
// main.dart cannot be compiled here, so the `_t` map literal is run verbatim
// in a `dart` subprocess (as other main.dart tests do); that also proves the
// const map still compiles, which a duplicate key would break.
// test/web_r2_burmese_test.py binds the hub refusals below to the installer.

const _sheetStrings = <String>[
  'Referral code (optional)',
  'You and the friend who referred you each get 20% extra VPN time.',
  'Redeem a Prepaid Card',
  'Create an account or add time to one',
  "Opens the Win's VPN website",
];

const _dialogStrings = <String>[
  'Redeem a prepaid card',
  'Prepaid code',
  'Add the time to my account ({account})',
  'Turn off to create a new account instead',
  'Existing account number (optional)',
  'Referral code (optional)',
  'Promo code (optional)',
  'Email (optional, for setup key delivery)',
  'That code looks incomplete. It should be 27 characters (shown as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX).',
  'Enter the account number as 12 digits (1234-5678-9012), or leave it empty to create a new account.',
  'That promo code is not valid. Check it or leave the field empty.',
  'Too many attempts. Please wait a few minutes and try again.',
  'Redeeming...',
  'That code is not valid, or has already been redeemed.',
  'Account extended. Your existing credentials and devices are unchanged.',
  'Redeemed. Save your account number and setup key now: the setup key is shown only once.',
  'Redemption could not be confirmed. Retry with the same details: it may already have been accepted.',
  'Confirmed. Keep your saved credentials safe; the setup key will not be shown again.',
  'Could not confirm yet. Your credentials above are still valid; try again in a moment.',
  'Account number: {account}',
  'Setup key: {setup_key}',
  'Expires: {date}',
  'Referral bonus days added: {days}',
  'Promo bonus days added: {days}',
  'Copy',
  'Copy failed: select and copy manually',
  'I have saved my account number and setup key securely',
  'Close',
  'Redeem Code',
  'Retry unchanged request',
  'Confirm I have saved these',
];

// REDEMPTION_REFUSAL_MESSAGES in server/wins_control_plane_setup_ONETOUCH.sh.
const _hubRefusals = <String>[
  'That account number was not found. Check it, or leave the field empty to create a new account. Your code has not been used.',
  'That account is not active. Redeem the code for a new account instead, or contact support. Your code has not been used.',
  'That account renews through a PayPal subscription and cannot be extended with a prepaid code. Redeem it for a new account, or contact support. Your code has not been used.',
  'That account cannot be extended with a prepaid code. Contact support. Your code has not been used.',
  'That referral code cannot be used. Check it or leave the field empty. Your code has not been used.',
  'Referral codes cannot be used with this card. Leave the field empty. Your code has not been used.',
  'This account has already received its one referral bonus. Leave the referral field empty. Your code has not been used.',
  'That promo code is not valid or has expired. Check it or leave the field empty. Your code has not been used.',
  'That promo code cannot be combined with a referral code. Remove one of them. Your code has not been used.',
  'This account has already used that promo code. Leave the field empty. Your code has not been used.',
];

const _keepVerbatim = <String>[
  'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX',
  '1234-5678-9012',
  '20%',
  "Win's VPN",
  'PayPal',
];

const _code = 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-234';

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production code: $start');
  }
  return source.substring(first, last);
}

Future<Map<String, String>> _burmeseLookup({bool googlePlayBuild = false}) async {
  final source = File('lib/main.dart').readAsStringSync();
  final map = _between(
      source,
      '    const localized = <String, Map<String, String>>{',
      '    return localized[_languageCode]?[english] ?? english;');
  final temporary = await Directory.systemTemp.createTemp('wins-r2-l10n-');
  try {
    final program = File('${temporary.path}/lookup.dart');
    await program.writeAsString("import 'dart:convert';\nimport 'dart:io';\n"
        // The R2 block is a collection-if on main.dart's private
        // `_googlePlayBuild`, which this slice does not carry, so bind it
        // here or the slice stops compiling. The default keeps this guard
        // on the direct-distribution view, which is the one that must hold
        // every R2 string; gate S14A checks the Play AABs for the text the
        // Play build compiles out.
        'const bool _googlePlayBuild = $googlePlayBuild;\n'
        'void main() {\n$map'
        "  stdout.write(jsonEncode(localized['my']));\n}\n");
    final result = await Process.run(
      Platform.environment['DART_EXECUTABLE'] ?? 'dart',
      <String>[program.path],
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );
    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
    return (jsonDecode(result.stdout as String) as Map<String, dynamic>)
        .map((key, value) => MapEntry(key, value as String));
  } finally {
    await temporary.delete(recursive: true);
  }
}

List<String> _problems(String english, String? burmese) {
  if (burmese == null || burmese.trim().isEmpty) {
    return ['no Burmese entry: $english'];
  }
  final placeholders = RegExp(r'\{\w+\}');
  List<String> names(String s) =>
      placeholders.allMatches(s).map((m) => m.group(0)!).toList()..sort();
  return [
    if (!RegExp('[\u1000-\u109F]').hasMatch(burmese))
      'no Myanmar script: $english',
    if (burmese == english) 'Burmese equals English: $english',
    if (RegExp('[\u2012-\u2015]').hasMatch(burmese)) 'en or em dash: $english',
    // Myanmar Unicode stores the vowel sign E after its consonant; Zawgyi
    // stores it first.
    if (RegExp('(?<![\u1000-\u102A\u103B-\u103E])\u1031').hasMatch(burmese))
      'looks like Zawgyi, not Unicode: $english',
    if (names(english).join() != names(burmese).join())
      'placeholders differ: $english',
    for (final token in _keepVerbatim)
      if (english.contains(token) && !burmese.contains(token))
        '"$token" not kept: $english',
  ];
}

Future<void> _pump(WidgetTester tester, PrepaidRedemptionDialog dialog) async {
  await tester.pumpWidget(MaterialApp(home: Scaffold(body: dialog)));
}

// A lookup that marks whatever passed through it.
String _mark(String english) => '<<$english>>';

/// Every non-empty text the dialog shows, except TextField counters.
List<String> _visibleText(WidgetTester tester) => [
      for (final t in tester.widgetList<Text>(find.byType(Text)))
        t.data ?? t.textSpan?.toPlainText() ?? '',
      for (final t
          in tester.widgetList<SelectableText>(find.byType(SelectableText)))
        t.data ?? '',
    ].where((s) => s.isNotEmpty && !RegExp(r'^\d+/\d+$').hasMatch(s)).toList();

void _expectAllRouted(WidgetTester tester, String stage) {
  final bare = _visibleText(tester)
      .where((s) => !(s.startsWith('<<') && s.endsWith('>>')))
      .toList();
  expect(bare, isEmpty, reason: 'shown without the lookup ($stage)');
}

http.Response _json(Object body, [int status = 200]) =>
    http.Response(jsonEncode(body), status);

void main() {
  late Map<String, String> my;
  setUpAll(() async => my = await _burmeseLookup());

  test('every new R2 app string and hub refusal has Burmese in _t', () {
    final keys = {..._sheetStrings, ..._dialogStrings, ..._hubRefusals};
    final problems = [for (final key in keys) ..._problems(key, my[key])];
    expect(problems, isEmpty, reason: problems.join('\n'));
    for (final key in keys) {
      expect(RegExp(r'\s-\s').hasMatch(key), isFalse,
          reason: 'spaced hyphen as a dash: $key');
    }
  });

  test('the Play view of _t compiles out exactly the R2 entries', () async {
    final play = await _burmeseLookup(googlePlayBuild: true);
    expect(
        my.keys.toSet().difference(play.keys.toSet()),
        {..._sheetStrings, ..._dialogStrings, ..._hubRefusals}
            .difference({'Copy', 'Close'}),
        reason: 'the Play-excluded block must drop exactly the R2 entries',
    );
    expect(play.keys.toSet().difference(my.keys.toSet()), isEmpty);
    for (final shared in ['Copy', 'Close']) {
      expect(play[shared], my[shared],
          reason: '$shared is shared with other screens and stays in Play builds');
    }
  });

  test('the dialog source routes every literal through _tr', () {
    final source = File('lib/prepaid_redemption.dart').readAsStringSync();
    final routed = RegExp(r"""_tr\(\s*(?:'([^']*)'|"([^"]*)")""")
        .allMatches(source)
        .map((m) => m.group(1) ?? m.group(2)!)
        .toSet();
    expect(routed, _dialogStrings.toSet(),
        reason: 'a _tr key without an entry in _dialogStrings, or the reverse');
    for (final bare in [
      RegExp(r"""Text\(\s*['"]"""),
      RegExp(r"""labelText:\s*['"]"""),
      RegExp(r"""_message\s*=\s*(?:'[^']|"[^"])"""),
      RegExp(r"""return\s+'[A-Z]"""),
    ]) {
      expect(bare.hasMatch(source), isFalse, reason: 'bare literal: $bare');
    }
  });

  test('main.dart routes the payment sheet and passes _t to the dialog', () {
    final source = File('lib/main.dart').readAsStringSync();
    final sheet = _between(
            source,
            '  void _showPaymentOptions(BuildContext context) {',
            '  void _showAppleStorePremiumAccessNotice(')
        .replaceAll(RegExp(r'\(\s+'), '(');
    for (final english in _sheetStrings) {
      expect(sheet, contains('_t("$english")'));
    }
    final show = _between(
        source,
        'Future<void> _showPrepaidRedemption() async {',
        'String _extractReferralCodeFromLink(');
    expect(show, contains('PrepaidRedemptionDialog('));
    expect(show, contains('translate: _t,'));
  });

  testWidgets('every visible dialog string goes through translate',
      (tester) async {
    final posts = <String>[];
    await _pump(
      tester,
      PrepaidRedemptionDialog(
        translate: _mark,
        post: (path, request) async {
          posts.add(path);
          if (path.endsWith('/ack')) return http.Response('{"ok":true}', 200);
          if (posts.length == 1) return http.Response('{}', 503);
          if (posts.length == 2) {
            return _json(
                {'ok': false, 'status': 'x', 'message': 'Hub said no.'});
          }
          return _json({
            'ok': true,
            'mode': 'new',
            'account_number': '1234-5678-9012',
            'setup_key': 'save-this-key',
            'expiration_date': '2027-01-01T00:00:00+00:00',
            'referral_bonus_days': 6,
            'promo_bonus_days': 7,
          });
        },
      ),
    );
    _expectAllRouted(tester, 'signed out');
    await tester.enterText(find.byType(TextField).at(0), 'ABCD');
    await tester.tap(find.text(_mark('Redeem Code')));
    await tester.pumpAndSettle();
    _expectAllRouted(tester, 'incomplete code');
    await tester.enterText(find.byType(TextField).at(0), _code);
    await tester.tap(find.text(_mark('Redeem Code')));
    await tester.pumpAndSettle();
    expect(find.text(_mark('Retry unchanged request')), findsOneWidget);
    _expectAllRouted(tester, 'unconfirmed');
    await tester.tap(find.text(_mark('Retry unchanged request')));
    await tester.pumpAndSettle();
    expect(find.text(_mark('Hub said no.')), findsOneWidget);
    _expectAllRouted(tester, 'refusal');
    await tester.tap(find.text(_mark('Redeem Code')));
    await tester.pumpAndSettle();
    expect(find.text('<<Account number: 1234-5678-9012>>'), findsOneWidget);
    expect(find.text('<<Setup key: save-this-key>>'), findsOneWidget);
    expect(find.text('<<Promo bonus days added: 7>>'), findsOneWidget);
    _expectAllRouted(tester, 'new account');
    await tester.ensureVisible(find.byType(CheckboxListTile));
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    await tester.tap(find.text(_mark('Confirm I have saved these')));
    await tester.pumpAndSettle();
    expect(posts.last, '/api/redeem/ack');
    _expectAllRouted(tester, 'acknowledged');
  });

  testWidgets('signed-in extension renders in Burmese from _t', (tester) async {
    String lookup(String english) => my[english] ?? english;
    await _pump(
      tester,
      PrepaidRedemptionDialog(
        account: '1234-5678-9012',
        translate: lookup,
        post: (path, request) async => _json({
          'ok': true,
          'mode': 'extend',
          'account_number': '1234-5678-9012',
          'setup_key': '',
          'expiration_date': '2027-03-01T00:00:00+00:00',
          'referral_bonus_days': 3,
          'promo_bonus_days': 7,
        }),
      ),
    );
    expect(find.text(my['Redeem a prepaid card']!), findsOneWidget);
    expect(find.text('Redeem a prepaid card'), findsNothing);
    expect(
        find.text(my['Add the time to my account ({account})']!
            .replaceAll('{account}', '1234-5678-9012')),
        findsOneWidget);
    await tester.enterText(find.byType(TextField).at(0), _code);
    await tester.tap(find.text(my['Redeem Code']!));
    await tester.pumpAndSettle();
    expect(
        find.text(my[
            'Account extended. Your existing credentials and devices are unchanged.']!),
        findsOneWidget);
    expect(find.text(my['Expires: {date}']!.replaceAll('{date}', '2027-03-01')),
        findsOneWidget);
    expect(
        find.text(
            my['Referral bonus days added: {days}']!.replaceAll('{days}', '3')),
        findsOneWidget);
    expect(
        find.text(
            my['Promo bonus days added: {days}']!.replaceAll('{days}', '7')),
        findsOneWidget);
  });

  testWidgets('a hub refusal is shown in Burmese', (tester) async {
    String lookup(String english) => my[english] ?? english;
    for (final refusal in _hubRefusals) {
      await _pump(
        tester,
        PrepaidRedemptionDialog(
          key: UniqueKey(),
          translate: lookup,
          post: (path, request) async =>
              _json({'ok': false, 'status': 'refused', 'message': refusal}),
        ),
      );
      await tester.enterText(find.byType(TextField).at(0), _code);
      await tester.tap(find.text(my['Redeem Code']!));
      await tester.pumpAndSettle();
      expect(find.text(my[refusal]!), findsOneWidget, reason: refusal);
      expect(find.text(refusal), findsNothing);
    }
  });
}
