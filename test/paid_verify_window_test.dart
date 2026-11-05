import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _body(String source, String signature, String nextSignature) {
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
  final end = source.indexOf(nextSignature, start + signature.length);
  expect(end, greaterThan(start), reason: 'missing $nextSignature');
  return source.substring(start, end);
}

void main() {
  final source = File('lib/main.dart').readAsStringSync();
  late final refresh = _body(
    source,
    'Future<bool> _refreshVpnConfigForCurrentSelection(',
    'Future<bool> _waitForTunnelState(',
  );
  late final attemptStart = refresh.indexOf('attempt: (url, abort) async {');
  // The attempt closure ends where the walk's result is first examined.
  late final windowEnd = refresh.indexOf(
      'if (verifyOutcome.signals.contains(kHubSignalServerAtCapacity))',
      attemptStart);
  late final attempt = refresh.substring(attemptStart, windowEnd);

  test('the paid /verify refresh walks the window with abortable requests '
      'under the verify deadline', () {
    expect(refresh, contains('runHubRequestWindow<Map<String, dynamic>>('));
    expect(refresh, contains('totalDeadline: kHubVerifyTotalDeadline'));
    expect(refresh, contains('shouldCancel: refreshCancelled,'));
    expect(refresh, isNot(contains('for (final url in gateways) {')));
    expect(attempt, contains('sendHubRequest('));
    expect(attempt, isNot(contains('.timeout(')));
  });

  test('an authenticated reply is validated inside its attempt, before it '
      'can win', () {
    final authenticated =
        attempt.indexOf("if (responseData['status'] == 'authenticated')");
    final validation = attempt.indexOf('await _hubVerifyRejection(');
    final accepted = attempt.indexOf('HubAttemptResult<Map<String, dynamic>>.accepted(');
    expect(authenticated, greaterThan(0));
    expect(validation, greaterThan(authenticated));
    expect(accepted, greaterThan(validation));
    expect(attempt, contains('if (rejection == null) {'));
    // Nothing is persisted inside an attempt.
    expect(attempt, isNot(contains('_persistVpnConfig')));
    expect(attempt, isNot(contains('_cachedVpnConfig =')));
  });

  test('paid attempts validate against requirements captured from the paid '
      'payload, and the walk is cancellable by notification', () {
    expect(refresh, contains('final Map<String, dynamic> paidPayload = <String, dynamic>{'));
    expect(refresh,
        contains('final paidRequirements = HubVerifyRequirements.fromRequestPayload(paidPayload);'));
    expect(refresh,
        contains('final String requestBodyPayload = jsonEncode(paidPayload);'));
    expect(attempt, contains('requirements: paidRequirements,'));
    final track = refresh.indexOf(
        'final paidCancellation = _hubCancellations.track(refreshCancelled);');
    final pass = refresh.indexOf('cancellation: paidCancellation,');
    final release = refresh.indexOf('_hubCancellations.release(paidCancellation);');
    expect(track, greaterThan(0));
    expect(pass, greaterThan(track));
    expect(release, greaterThan(pass));
  });

  test('the capacity flag is a signal committed after the walk, only while '
      'the refresh is current', () {
    expect(attempt, isNot(contains('_lastVerifyServerAtCapacity')));
    expect(attempt, contains('signals: <String>{kHubSignalServerAtCapacity}'));
    final after = refresh.substring(refresh.indexOf('final verifyOutcome ='));
    final cancelCheck = after.indexOf('if (refreshCancelled()) return false;');
    final commit = after.indexOf(
        'if (verifyOutcome.signals.contains(kHubSignalServerAtCapacity)) {');
    expect(cancelCheck, greaterThan(0));
    expect(commit, greaterThan(cancelCheck));
  });
}
