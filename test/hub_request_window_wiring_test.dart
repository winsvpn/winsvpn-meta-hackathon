import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _body(String source, String signature, String nextSignature) {
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
  final end = source.indexOf(nextSignature, start + signature.length);
  expect(end, greaterThan(start), reason: 'missing $nextSignature');
  return source.substring(start, end);
}

int _count(String haystack, String needle) =>
    needle.allMatches(haystack).length;

/// The full argument text of every call to [name] in [body].
List<String> _calls(String body, String name) {
  final calls = <String>[];
  var from = 0;
  while (true) {
    final start = body.indexOf('$name(', from);
    if (start < 0) return calls;
    var depth = 0;
    var i = start + name.length;
    for (; i < body.length; i++) {
      if (body[i] == '(') depth++;
      if (body[i] == ')') {
        depth--;
        if (depth == 0) break;
      }
    }
    calls.add(body.substring(start, i + 1));
    from = i + 1;
  }
}

void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('Double VPN assignment accepts the first authenticated reply and '
      'aborts losing requests', () {
    final race = _body(
      source,
      'Future<DoubleVpnAssignmentAttempt<Map<String, dynamic>?>>',
      'Future<Map<String, dynamic>?> _postDoubleVpnAssignmentWithRetry(',
    );
    // One attempt walks the fronts through the staggered window (at most three
    // open, the window aborts the losers). It must never post to every front
    // at the same instant again: that was 29 duplicate Double VPN requests per
    // attempt against one hub.
    expect(race, contains('runHubRequestWindow<http.Response>('));
    expect(race, contains('sendHubRequest('));
    expect(race, contains('abort: abort,'));
    expect(race, contains('HubRequestWindowPolicy('));
    expect(race, isNot(contains('firstAcceptedOrAll<http.Response>(')));
    expect(race, isNot(contains('List<Completer<void>>.generate(')));
    expect(race, isNot(contains('Future.wait(candidates.map(')));
  });

  test('the free-verify walk validates inside each attempt, aborts through '
      'the transport and commits flags only after the walk', () {
    final walk = _body(
      source,
      'Future<Map<String, dynamic>?> _postAuthenticatedBatchedFallback(',
      'Future<DoubleVpnAssignmentAttempt<Map<String, dynamic>?>>',
    );
    expect(walk, contains('runHubRequestWindow<Map<String, dynamic>>('));
    expect(walk, contains('sendHubRequest('));
    expect(walk, contains('abort: abort,'));
    expect(walk, contains('final rejection = await rejectionOf(candidate);'));
    expect(walk, contains('alreadyAttempted?.addAll(outcome.started);'));
    expect(walk, isNot(contains('.timeout(')));
    // The rate-limit flag is set from the finished outcome, not from inside
    // an attempt, and only when the operation is still current.
    final attemptStart = walk.indexOf('attempt: (url, abort) async {');
    final attemptEnd = walk.indexOf('alreadyAttempted?.addAll(');
    expect(walk.substring(attemptStart, attemptEnd),
        isNot(contains('_lastGatewayRateLimited')));
    final cancelled = walk.indexOf(
        'if (outcome.cancelled || shouldCancel?.call() == true) return null;');
    final commit = walk.indexOf('_lastGatewayRateLimited = true;');
    expect(cancelled, greaterThan(attemptEnd));
    expect(commit, greaterThan(cancelled));
    expect(source, isNot(contains('_postAuthenticatedRace(')));
  });

  test('both free-verify operations share one absolute budget across both '
      'passes and the resolution between them, and are cancellable', () {
    final activation = _body(
      source,
      'Future<void> _loginWithFreeAccess() async {',
      'Future<void> _onAuthSuccess(',
    );
    final refresh = _body(
      source,
      'Future<bool> _refreshFreeVpnConfig(',
      'Future<bool> _refreshVpnConfigForCurrentSelection(',
    );
    for (final body in <String>[activation, refresh]) {
      expect(body,
          contains('final verifyBudget = HubOperationBudget(kHubVerifyTotalDeadline);'));
      expect(_count(body, '_postAuthenticatedBatchedFallback('), 2);
      expect(_count(body, 'budget: verifyBudget,'), 2);
      expect(_count(body, 'alreadyAttempted: attemptedFronts,'), 2);
      expect(
        body,
        contains(
            'await _resolveDynamicEndpointsWithin(verifyBudget.remaining);'),
      );
      expect(body, contains('!verifyBudget.spent'));
    }
    for (final call
        in _calls(activation, '_postAuthenticatedBatchedFallback')) {
      expect(call, contains('shouldCancel: activationSuperseded,'));
      expect(call, contains('rejectionOf: activationRejection,'));
    }
    for (final call in _calls(refresh, '_postAuthenticatedBatchedFallback')) {
      expect(call, contains('shouldCancel: refreshCancelled,'));
      expect(call, contains('rejectionOf: refreshRejection,'));
    }
  });

  test('the free Double VPN assignment poll is fenced by the account epoch',
      () {
    // The server picker calls _refreshFreeVpnConfig with no shouldCancel, so
    // passing the caller's callback through left the up-to-90 s poll running
    // across a logout or deletion.
    final refresh = _body(
      source,
      'Future<bool> _refreshFreeVpnConfig(',
      'Future<bool> _refreshVpnConfigForCurrentSelection(',
    );
    final polls = _calls(refresh, '_postDoubleVpnAssignmentWithRetry');
    expect(polls, hasLength(1));
    expect(polls.single, contains('shouldCancel: refreshCancelled,'));
    expect(refresh,
        contains('shouldCancel?.call() == true || !_accountEpochIsCurrent(refreshEpoch);'));
  });

  test('every account-epoch and transition-generation change notifies live '
      'hub walks', () {
    final bumps = 'final epoch = _accountSessionEpoch.bump();\n'
        '    _hubCancellations.notifyGenerationChanged();';
    expect(_count(source, bumps), 2);
    expect(_count(source, '_accountSessionEpoch.bump()'), 2);
    expect(
      source,
      contains('final cancellationGeneration = _tunnelTransitionGate.cancel();\n'
          '    _hubCancellations.notifyGenerationChanged();'),
    );
    expect(
      source,
      contains('final transitionGeneration = _tunnelTransitionGate.begin();\n'
          '    _hubCancellations.notifyGenerationChanged();'),
    );
    expect(_count(source, '_tunnelTransitionGate.begin()'), 1);
    expect(_count(source, '_tunnelTransitionGate.cancel()'), 1);
  });

  test('the free-verify walk tracks, passes and releases its cancellation',
      () {
    final walk = _body(
      source,
      'Future<Map<String, dynamic>?> _postAuthenticatedBatchedFallback(',
      'Future<DoubleVpnAssignmentAttempt<Map<String, dynamic>?>>',
    );
    final track = walk.indexOf(
        'final cancellation = _hubCancellations.track(shouldCancel ?? () => false);');
    final pass = walk.indexOf('cancellation: cancellation,');
    final release = walk.indexOf('_hubCancellations.release(cancellation);');
    expect(track, greaterThan(0));
    expect(pass, greaterThan(track));
    expect(release, greaterThan(pass));
  });

  test('activation and refresh validate against requirements captured from '
      'the payload they send', () {
    final activation = _body(
      source,
      'Future<void> _loginWithFreeAccess() async {',
      'Future<void> _onAuthSuccess(',
    );
    final refresh = _body(
      source,
      'Future<bool> _refreshFreeVpnConfig(',
      'Future<bool> _refreshVpnConfigForCurrentSelection(',
    );
    expect(activation, contains('final activationPayload = _freeAccessPayload('));
    expect(activation, contains('HubVerifyRequirements.fromRequestPayload(\n'
        '        activationPayload,'));
    expect(activation,
        contains('final requestBodyPayload = jsonEncode(activationPayload);'));
    expect(activation, contains('requirements: activationRequirements,'));
    expect(refresh,
        contains('HubVerifyRequirements.fromRequestPayload(refreshPayload);'));
    expect(refresh,
        contains('final requestBodyPayload = jsonEncode(refreshPayload);'));
    expect(refresh, contains('requirements: refreshRequirements,'));
    final helper = _body(
      source,
      'Future<String?> _hubVerifyRejection(',
      'Future<Map<String, String>> _resolveDynamicEndpointsWithin(',
    );
    expect(helper, contains('requirements: requirements,'));
    expect(helper, isNot(contains('_winn3CoverExactTargetSlug')));
  });

  test('bounded endpoint resolution is skipped when no budget remains', () {
    final helper = _body(
      source,
      'Future<Map<String, String>> _resolveDynamicEndpointsWithin(',
      '  /// ',
    );
    expect(helper, contains('runWithinBudget<Map<String, String>>('));
    expect(helper, contains('_resolveDynamicEndpoints,'));
  });

  test('the pinned client never outlives the window attempt that owns its permit', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('late final http.Client _controlPlaneClient');
    expect(start, greaterThanOrEqualTo(0), reason: 'anti-vacuity');
    final decl = source.substring(start, source.indexOf(';', start));
    expect(decl, contains('connectionVerificationTimeout:'));
    expect(decl, contains('HubRequestWindowPolicy().perRequestTimeout'));
  });
}
