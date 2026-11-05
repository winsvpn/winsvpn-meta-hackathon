import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/double_vpn_assignment_retry.dart';

const _pendingBody =
    '{"detail":"Double VPN Core assignment is still being prepared. Please try again."}';

DoubleVpnAssignmentAttempt<String> _attempt(
  int status,
  String body, {
  Map<String, String> headers = const {},
  String value = '',
}) {
  return DoubleVpnAssignmentAttempt<String>(
    statusCode: status,
    body: body,
    headers: headers,
    value: value,
  );
}

void main() {
  test('first accepted reply returns before a stalled peer', () async {
    final stalled = Completer<String?>();
    final fast = Completer<String?>();
    final race = firstAcceptedOrAll<String>(
      <Future<String?>>[stalled.future, fast.future],
      (value) => value == 'accepted',
    );
    fast.complete('accepted');
    final result = await race.timeout(const Duration(seconds: 1));
    expect(result.winner, 'accepted');
    expect(result.completed, <String?>[null, 'accepted']);
    expect(stalled.isCompleted, isFalse);
    stalled.complete(null);
  });

  test('without a winner replies retain input order', () async {
    final first = Completer<String?>();
    final second = Completer<String?>();
    final race = firstAcceptedOrAll<String>(
      <Future<String?>>[first.future, second.future],
      (value) => value == 'accepted',
    );
    second.complete('pending');
    first.complete('terminal');
    final result = await race.timeout(const Duration(seconds: 1));
    expect(result.winner, isNull);
    expect(result.completed, <String?>['terminal', 'pending']);
  });

  test('default polling budget covers Core recovery plus request margin', () {
    expect(
      defaultDoubleVpnAssignmentMaximumElapsed,
      const Duration(seconds: 120),
    );
    expect(
      defaultDoubleVpnAssignmentMaximumElapsed,
      greaterThan(const Duration(seconds: 90)),
    );
  });

  test('trusted pending response polls to Double success', () async {
    var calls = 0;
    final clock = Stopwatch();
    final outcome = await pollDoubleVpnAssignment<String, Object>(
      doubleVpnRequested: true,
      requestIdentity: Object(),
      stopwatch: clock,
      sleep: (_) async {},
      request: (_, __) async {
        calls += 1;
        return calls == 1
            ? _attempt(503, _pendingBody)
            : _attempt(200, '{"status":"authenticated"}', value: 'double');
      },
    );

    expect(calls, 2);
    expect(outcome.attempt?.value, 'double');
    expect(outcome.cancelled, isFalse);
    expect(outcome.deadlineReached, isFalse);
  });

  test('stable header is exact and incompatible code is terminal', () {
    expect(
      isDoubleVpnAssignmentPreparing(
        statusCode: 503,
        body: '{}',
        headers: const {'X-Wins-Error-Code': doubleVpnAssignmentPreparingCode},
      ),
      isTrue,
    );
    expect(
      isDoubleVpnAssignmentPreparing(
        statusCode: 503,
        body: _pendingBody,
        headers: const {'X-Wins-Error-Code': 'double_vpn_core_unavailable'},
      ),
      isFalse,
    );
  });

  test(
    'deadline is monotonic and no request starts without its full budget',
    () async {
      final clock = Stopwatch()..start();
      var calls = 0;
      final outcome = await pollDoubleVpnAssignment<String, String>(
        doubleVpnRequested: true,
        requestIdentity: 'identity',
        maximumElapsed: const Duration(milliseconds: 10),
        requestTimeout: const Duration(milliseconds: 11),
        stopwatch: clock,
        request: (_, __) async {
          calls += 1;
          return _attempt(503, _pendingBody);
        },
      );

      expect(calls, 0);
      expect(outcome.deadlineReached, isTrue);
    },
  );

  test('repeated pending responses stop at the monotonic deadline', () async {
    var elapsed = Duration.zero;
    var calls = 0;
    final outcome = await pollDoubleVpnAssignment<String, String>(
      doubleVpnRequested: true,
      requestIdentity: 'identity',
      maximumElapsed: const Duration(milliseconds: 8250),
      requestTimeout: const Duration(seconds: 7),
      elapsed: () => elapsed,
      sleep: (duration) async => elapsed += duration,
      request: (_, __) async {
        calls += 1;
        return _attempt(503, _pendingBody);
      },
    );

    expect(calls, 2);
    expect(elapsed, const Duration(seconds: 1));
    expect(outcome.deadlineReached, isTrue);
  });

  test('generic 503 core unavailable and maintenance do not retry', () async {
    for (final detail in <String>[
      'Double VPN core is not available yet.',
      'Server is offline or in maintenance.',
    ]) {
      var calls = 0;
      final outcome = await pollDoubleVpnAssignment<String, String>(
        doubleVpnRequested: true,
        requestIdentity: 'same',
        request: (_, __) async {
          calls += 1;
          return _attempt(503, '{"detail":"$detail"}');
        },
      );
      expect(calls, 1);
      expect(outcome.deadlineReached, isFalse);
    }
  });

  test('cancellation stops polling before another request', () async {
    var cancelled = false;
    var calls = 0;
    final outcome = await pollDoubleVpnAssignment<String, String>(
      doubleVpnRequested: true,
      requestIdentity: 'same',
      shouldCancel: () => cancelled,
      sleep: (_) async => cancelled = true,
      request: (_, __) async {
        calls += 1;
        return _attempt(503, _pendingBody);
      },
    );

    expect(calls, 1);
    expect(outcome.cancelled, isTrue);
  });

  test('cancellation stops an in-flight polling request promptly', () async {
    var cancelled = false;
    final neverCompletes = Completer<DoubleVpnAssignmentAttempt<String>>();
    Timer(const Duration(milliseconds: 15), () => cancelled = true);
    final outcome = await pollDoubleVpnAssignment<String, String>(
      doubleVpnRequested: true,
      requestIdentity: 'same',
      shouldCancel: () => cancelled,
      cancellationPollInterval: const Duration(milliseconds: 5),
      request: (_, __) => neverCompletes.future,
    );

    expect(outcome.attemptCount, 1);
    expect(outcome.cancelled, isTrue);
  });

  test('every retry receives the identical request identity object', () async {
    final identity = Object();
    final seen = <Object>[];
    final outcome = await pollDoubleVpnAssignment<String, Object>(
      doubleVpnRequested: true,
      requestIdentity: identity,
      sleep: (_) async {},
      request: (received, __) async {
        seen.add(received);
        return seen.length < 3
            ? _attempt(503, _pendingBody)
            : _attempt(200, '{"status":"authenticated"}', value: 'double');
      },
    );

    expect(outcome.attempt?.value, 'double');
    expect(seen, hasLength(3));
    expect(seen.every((item) => identical(item, identity)), isTrue);
  });

  test('single preference never enters the pending retry path', () async {
    var calls = 0;
    final outcome = await pollDoubleVpnAssignment<String, String>(
      doubleVpnRequested: false,
      requestIdentity: 'explicit-single',
      request: (_, __) async {
        calls += 1;
        return _attempt(503, _pendingBody);
      },
    );

    expect(calls, 1);
    expect(outcome.attempt?.statusCode, 503);
  });

  test('requested Double response can never downgrade to Single', () {
    expect(
      acceptsRequestedDoubleVpnConfig(
        doubleVpnRequested: true,
        config: const {
          'double_vpn_active': true,
          'double_vpn_core_id': 'core-1',
          'double_vpn_exit_slug': 'france',
        },
      ),
      isTrue,
    );
    expect(
      acceptsRequestedDoubleVpnConfig(
        doubleVpnRequested: true,
        config: const {'double_vpn_active': false},
      ),
      isFalse,
    );
    expect(
      acceptsRequestedDoubleVpnConfig(
        doubleVpnRequested: true,
        config: const {'double_vpn_active': true},
      ),
      isFalse,
    );
  });

  test('Retry-After is bounded', () {
    expect(
      doubleVpnAssignmentRetryDelay(const {'Retry-After': '4'}),
      const Duration(seconds: 4),
    );
    expect(
      doubleVpnAssignmentRetryDelay(const {'retry-after': '999'}),
      const Duration(seconds: 10),
    );
  });

  test('Retry-After zero or absent never polls faster than once a second',
      () async {
    expect(
      doubleVpnAssignmentRetryDelay(const {'Retry-After': '0'}),
      const Duration(seconds: 1),
    );
    expect(
      doubleVpnAssignmentRetryDelay(const <String, String>{}),
      const Duration(seconds: 1),
    );
    var elapsed = Duration.zero;
    var calls = 0;
    final outcome = await pollDoubleVpnAssignment<String, String>(
      doubleVpnRequested: true,
      requestIdentity: 'identity',
      maximumElapsed: const Duration(minutes: 2),
      requestTimeout: const Duration(seconds: 7),
      elapsed: () => elapsed,
      sleep: (duration) async => elapsed += duration,
      request: (_, __) async {
        calls += 1;
        return calls < 4
            ? _attempt(503, _pendingBody, headers: const {'retry-after': '0'})
            : _attempt(200, '{"status":"authenticated"}', value: 'double');
      },
    );
    expect(outcome.attempt?.value, 'double');
    expect(calls, 4);
    expect(elapsed, const Duration(seconds: 3));
  });
}
