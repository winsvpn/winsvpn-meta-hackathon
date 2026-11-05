import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:wins_vpn/prepaid_redemption.dart';

// Round R2: in-app prepaid redemption dialog and its store gating in main.dart.
const _code = 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-234';
const _canonical = 'ABCDEFGHJKMNPQRSTVWXYZ01234';

Future<void> _pump(WidgetTester tester, PrepaidRedemptionDialog dialog) async {
  await tester.pumpWidget(MaterialApp(home: Scaffold(body: dialog)));
}

void main() {
  testWidgets('new account: lost reply retries the identical request, then ack',
      (tester) async {
    final calls = <(String, PrepaidRedemptionRequest)>[];
    String? filled;
    await _pump(
      tester,
      PrepaidRedemptionDialog(
        onNewCredentials: (account, key) => filled = '$account/$key',
        post: (path, request) async {
          calls.add((path, request));
          if (calls.length == 1) return http.Response('{}', 503);
          if (path.endsWith('/ack')) return http.Response('{"ok":true}', 200);
          return http.Response(
              jsonEncode({
                'ok': true,
                'mode': 'new',
                'account_number': '1234-5678-9012',
                'setup_key': 'save-this-key',
                'expiration_date': '2027-01-01T00:00:00+00:00',
                'referral_bonus_days': 6,
                'promo_bonus_days': 0,
              }),
              200);
        },
      ),
    );
    await tester.enterText(find.byType(TextField).at(0), _code.toLowerCase());
    await tester.enterText(find.byType(TextField).at(2), 'friend_01');
    await tester.tap(find.text('Redeem Code'));
    await tester.pumpAndSettle();
    expect(find.text('Retry unchanged request'), findsOneWidget);
    await tester.tap(find.text('Retry unchanged request'));
    await tester.pumpAndSettle();
    expect(identical(calls[0].$2, calls[1].$2), isTrue);
    final body = jsonDecode(calls[0].$2.body) as Map<String, dynamic>;
    expect(body, {'code': _canonical, 'referral_code': 'friend_01'});
    expect(find.text('Setup key: save-this-key'), findsOneWidget);
    expect(find.text('Referral bonus days added: 6'), findsOneWidget);
    final confirm = tester.widget<FilledButton>(
        find.widgetWithText(FilledButton, 'Confirm I have saved these'));
    expect(confirm.onPressed, isNull);
    await tester.ensureVisible(find.byType(CheckboxListTile));
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    await tester.tap(find.text('Confirm I have saved these'));
    await tester.pumpAndSettle();
    expect(calls.last.$1, '/api/redeem/ack');
    expect(jsonDecode(calls.last.$2.body), {'code': _canonical});
    expect(filled, '1234-5678-9012/save-this-key');
  });

  testWidgets('signed-in extension sends the device bearer and shows no key',
      (tester) async {
    PrepaidRedemptionRequest? sent;
    await _pump(
      tester,
      PrepaidRedemptionDialog(
        account: '1234-5678-9012',
        deviceId: 'this-device',
        deviceToken: 'scoped-token',
        post: (path, request) async {
          sent = request;
          return http.Response(
              jsonEncode({
                'ok': true,
                'mode': 'extend',
                'account_number': '1234-5678-9012',
                'setup_key': '',
                'expiration_date': '2027-03-01T00:00:00+00:00',
                'promo_bonus_days': 7,
              }),
              200);
        },
      ),
    );
    await tester.enterText(find.byType(TextField).at(0), _code);
    await tester.enterText(find.byType(TextField).at(2), 'welcome7');
    await tester.tap(find.text('Redeem Code'));
    await tester.pumpAndSettle();
    expect(sent!.headers['Authorization'], 'Bearer scoped-token');
    expect(jsonDecode(sent!.body), {
      'code': _canonical,
      'account_number': '1234-5678-9012',
      'device_id': 'this-device',
      'promo_code': 'WELCOME7',
    });
    expect(find.textContaining('Setup key:'), findsNothing);
    expect(find.text('Expires: 2027-03-01'), findsOneWidget);
    expect(find.text('Promo bonus days added: 7'), findsOneWidget);
    expect(find.text('Confirm I have saved these'), findsNothing);
  });

  testWidgets('a refusal shows the hub message and lets the user edit',
      (tester) async {
    final requests = <PrepaidRedemptionRequest>[];
    await _pump(
      tester,
      PrepaidRedemptionDialog(
        post: (path, request) async {
          requests.add(request);
          return http.Response(
              jsonEncode({
                'ok': false,
                'status': 'promo_invalid',
                'message': 'That promo code is not valid or has expired.',
              }),
              200);
        },
      ),
    );
    await tester.enterText(find.byType(TextField).at(0), _code);
    await tester.enterText(find.byType(TextField).at(3), 'OLDPROMO');
    await tester.tap(find.text('Redeem Code'));
    await tester.pumpAndSettle();
    expect(find.text('That promo code is not valid or has expired.'), findsOneWidget);
    expect(tester.widget<TextField>(find.byType(TextField).at(3)).enabled, isTrue);
    await tester.enterText(find.byType(TextField).at(3), '');
    await tester.tap(find.text('Redeem Code'));
    await tester.pumpAndSettle();
    expect(requests.length, 2);
    expect(jsonDecode(requests.last.body), {'code': _canonical});
  });

  testWidgets('local validation never sends a malformed request',
      (tester) async {
    var posts = 0;
    await _pump(
      tester,
      PrepaidRedemptionDialog(post: (path, request) async {
        posts++;
        return http.Response('{}', 500);
      }),
    );
    await tester.enterText(find.byType(TextField).at(0), 'ABCD');
    await tester.tap(find.text('Redeem Code'));
    await tester.pumpAndSettle();
    expect(find.textContaining('looks incomplete'), findsOneWidget);
    await tester.enterText(find.byType(TextField).at(0), _code);
    await tester.enterText(find.byType(TextField).at(1), '1234');
    await tester.tap(find.text('Redeem Code'));
    await tester.pumpAndSettle();
    expect(find.textContaining('12 digits'), findsOneWidget);
    await tester.enterText(find.byType(TextField).at(1), '');
    await tester.enterText(find.byType(TextField).at(3), 'x');
    await tester.tap(find.text('Redeem Code'));
    await tester.pumpAndSettle();
    expect(find.textContaining('promo code is not valid'), findsOneWidget);
    expect(posts, 0);
    expect(normalizePrepaidCode('abcd-efgh-jkmn-pqrs-tvwx-yzol-234'), 'ABCDEFGHJKMNPQRSTVWXYZ01234');
    expect(formatAccountNumberForRedemption('1234 5678 9012'), '1234-5678-9012');
    expect(formatAccountNumberForRedemption('1234567890123456'), '');
  });

  testWidgets('R2-AUDIT-07: the email field follows the account field',
      (tester) async {
    await _pump(
      tester,
      PrepaidRedemptionDialog(post: (path, request) async => http.Response('{}', 500)),
    );
    const email = 'Email (optional, for setup key delivery)';
    expect(find.widgetWithText(TextField, email), findsOneWidget);
    await tester.enterText(find.byType(TextField).at(1), '1234-5678-9012');
    await tester.pump();
    expect(find.widgetWithText(TextField, email), findsNothing);
    await tester.enterText(find.byType(TextField).at(1), '');
    await tester.pump();
    expect(find.widgetWithText(TextField, email), findsOneWidget);
  });

  testWidgets('R2-AUDIT-09: a signed-in extension reports its new expiry',
      (tester) async {
    String? reported;
    await _pump(
      tester,
      PrepaidRedemptionDialog(
        account: '1234-5678-9012',
        onAccountExtended: (expiry) => reported = expiry,
        post: (path, request) async => http.Response(
            jsonEncode({
              'ok': true,
              'mode': 'extend',
              'account_number': '1234-5678-9012',
              'setup_key': '',
              'expiration_date': '2027-03-01T00:00:00+00:00',
            }),
            200),
      ),
    );
    await tester.enterText(find.byType(TextField).at(0), _code);
    await tester.tap(find.text('Redeem Code'));
    await tester.pumpAndSettle();
    expect(reported, '2027-03-01T00:00:00+00:00');
  });

  test('R2-AUDIT-09: main.dart forgets the buyer referral and refreshes expiry',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final cleanup = source
        .split('void _resetAccountUiAfterVerifiedCleanup() {')[1]
        .split('void _forcePendingAccountCleanupUi()')[0];
    expect(cleanup, contains("_purchaseReferralCode = '';"));
    final show = source.split('Future<void> _showPrepaidRedemption() async {')[1]
        .split('String _extractReferralCodeFromLink(')[0];
    expect(show, contains('onAccountExtended:'));
    expect(show, contains('_refreshAccountStatusOnce('));
  });

  test('main.dart offers in-app redemption only on direct builds', () {
    final source = File('lib/main.dart').readAsStringSync();
    final gate = RegExp(r'bool get _canRedeemPrepaidInApp =>([^;]+);')
        .firstMatch(source)!
        .group(1)!;
    expect(gate, contains('_externalPaymentLinksEnabled'));
    expect(gate, contains('!_googlePlayBuild'));
    expect(gate, contains('!Platform.isIOS'));
    final show = source.split('Future<void> _showPrepaidRedemption() async {')[1]
        .split('String _extractReferralCodeFromLink(')[0];
    expect(show, contains('if (!_canRedeemPrepaidInApp) return;'));
    expect(show, contains('Uri.parse(kReviewedPaymentBase)'));
    expect(show, isNot(contains('verifyGateways')));
    final query = source.split('String _purchaseReferralQuery(String optionKey) {')[1]
        .split('}')[0];
    expect(query, contains("optionKey == 'donation'"));
    expect(
        RegExp(r'_launchPaymentURL\(\s*_trackedPaymentUrl\(')
            .allMatches(source)
            .length,
        5);
  });
}
