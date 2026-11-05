import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:wins_vpn/hub_request_window.dart';

// testWidgets runs the body in a fake-time zone: Timer and Future.delayed
// advance only when the test pumps, so every duration below is exact.

List<String> _fronts(int count) =>
    List<String>.generate(count, (i) => 'https://f$i.example/free/verify');

int _index(String url) =>
    int.parse(RegExp(r'f(\d+)\.').firstMatch(url)!.group(1)!);

/// How one front behaves at the transport.
class _Front {
  const _Front.silent() : kind = 'silent', delayMs = 0, status = 0, body = '';
  const _Front.failFast() : kind = 'fail', delayMs = 0, status = 0, body = '';
  const _Front.reply(this.status, this.body, {this.delayMs = 0})
      : kind = 'reply';

  final String kind;
  final int delayMs;
  final int status;
  final String body;
}

const _ok = '{"status":"authenticated","vpn_config":{}}';

/// A transport that counts sends still open, honours `abortTrigger` after
/// [abortLagMs] (0 models an abort that ends the request at once; a lag models
/// the pinned client, whose abort takes effect only when connection setup
/// finishes), and records every start and abort.
class _FakeTransport extends http.BaseClient {
  _FakeTransport(this.tester, this.fronts, {this.abortLagMs = 0, this.shared})
      : origin = tester.binding.clock.now();

  /// When several windows share one transport count (consecutive walks).
  final _SharedCount? shared;

  final WidgetTester tester;
  final _Front Function(int index) fronts;
  final int abortLagMs;
  final DateTime origin;
  final List<(int, int)> starts = <(int, int)>[];
  final List<int> aborted = <int>[];
  final List<int> abortedAt = <int>[];
  int outstanding = 0;
  int maxOutstanding = 0;

  int get nowMs => tester.binding.clock.now().difference(origin).inMilliseconds;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final index = _index(request.url.toString());
    starts.add((index, nowMs));
    outstanding += 1;
    if (outstanding > maxOutstanding) maxOutstanding = outstanding;
    shared?.open(nowMs);
    final done = Completer<http.StreamedResponse>();
    Timer? replyTimer;
    Timer? lagTimer;
    final abort = request is http.Abortable ? request.abortTrigger : null;
    abort?.whenComplete(() {
      aborted.add(index);
      abortedAt.add(nowMs);
      lagTimer = Timer(Duration(milliseconds: abortLagMs), () {
        if (!done.isCompleted) {
          done.completeError(http.RequestAbortedException(request.url));
        }
      });
    });
    final front = fronts(index);
    switch (front.kind) {
      case 'fail':
        scheduleMicrotask(() {
          if (!done.isCompleted) {
            done.completeError(http.ClientException('reset', request.url));
          }
        });
        break;
      case 'reply':
        replyTimer = Timer(Duration(milliseconds: front.delayMs), () {
          if (!done.isCompleted) {
            done.complete(http.StreamedResponse(
              Stream<List<int>>.value(utf8.encode(front.body)),
              front.status,
            ));
          }
        });
        break;
      default:
        break;
    }
    try {
      return await done.future;
    } finally {
      outstanding -= 1;
      shared?.close();
      replyTimer?.cancel();
      lagTimer?.cancel();
    }
  }
}

class _SharedCount {
  int outstanding = 0;
  int max = 0;
  void open(int _) {
    outstanding += 1;
    if (outstanding > max) max = outstanding;
  }

  void close() => outstanding -= 1;
}

/// The production attempt shape: send through the transport with the
/// window's abort, classify, and let [validate] reject a candidate.
HubAttempt<Map<String, dynamic>> _attempt(
  _FakeTransport transport, {
  Future<bool> Function(String url, Map<String, dynamic> data)? validate,
  Set<String> Function(int status)? signalsFor,
}) {
  return (url, abort) async {
    try {
      final response = await sendHubRequest(
        transport,
        'POST',
        Uri.parse(url),
        abort: abort,
        body: '{}',
      );
      final result =
          classifyFreeVerifyAttempt(response.statusCode, response.body);
      if (result.verdict == HubAttemptVerdict.accepted &&
          validate != null &&
          !await validate(url, result.value!)) {
        return const HubAttemptResult<Map<String, dynamic>>.rejected();
      }
      final signals = signalsFor?.call(response.statusCode);
      if (signals != null && signals.isNotEmpty &&
          result.verdict == HubAttemptVerdict.rejected) {
        return HubAttemptResult<Map<String, dynamic>>.rejected(
            signals: signals);
      }
      return result;
    } catch (_) {
      return const HubAttemptResult<Map<String, dynamic>>.rejected();
    }
  };
}

class _Run {
  HubRequestWindowOutcome<Map<String, dynamic>>? outcome;
  int? finishedAtMs;
}

_Run _start(
  _FakeTransport transport, {
  int fronts = 29,
  HubRequestWindowPolicy policy = const HubRequestWindowPolicy(),
  Future<bool> Function(String url, Map<String, dynamic> data)? validate,
  bool Function()? shouldCancel,
  Set<String> Function(int status)? signalsFor,
  HubCancellation? cancellation,
  HubTransportPermits? permits,
}) {
  final run = _Run();
  runHubRequestWindow<Map<String, dynamic>>(
    urls: _fronts(fronts),
    policy: policy,
    shouldCancel: shouldCancel,
    cancellation: cancellation,
    // Each window gets its own pool unless a test shares one on purpose.
    permits: permits ?? HubTransportPermits(3),
    attempt: _attempt(transport, validate: validate, signalsFor: signalsFor),
  ).then((value) {
    run.outcome = value;
    run.finishedAtMs = transport.nowMs;
  });
  return run;
}

Future<void> _advance(WidgetTester tester, int ms, {int step = 50}) async {
  for (var done = 0; done < ms; done += step) {
    await tester.pump(Duration(milliseconds: step));
  }
}

void main() {
  group('timing and the in-flight cap', () {
    testWidgets('during silence the next front starts 500 ms after the last',
        (tester) async {
      final t = _FakeTransport(tester, (_) => const _Front.silent());
      _start(t, fronts: 6);
      await _advance(tester, 1200);
      expect(t.starts.map((s) => s.$2).toList(), <int>[0, 500, 1000]);
      // Full: nothing starts until the first front is aborted at 4 s and its
      // operation has actually ended.
      await _advance(tester, 2700);
      expect(t.starts.length, 3);
      await _advance(tester, 200);
      expect(t.starts.length, 4);
      expect(t.starts[3].$2, 4000);
      await _advance(tester, 20000);
    });

    testWidgets('after an outright failure the next front starts sooner, never '
        'less than 100 ms after the previous start: all 29 in under 3 s',
        (tester) async {
      final t = _FakeTransport(tester, (_) => const _Front.failFast());
      final run = _start(t);
      await _advance(tester, 4000, step: 10);
      final starts = t.starts.map((s) => s.$2).toList();
      expect(starts.length, 29);
      for (var i = 1; i < starts.length; i++) {
        expect(starts[i] - starts[i - 1], greaterThanOrEqualTo(100));
        expect(starts[i] - starts[i - 1], lessThan(500));
      }
      expect(starts.last, lessThan(3000));
      expect(run.outcome!.exhaustive, isTrue);
    });

    testWidgets('the transport never holds more than 3 open operations, and '
        'none is left open after the deadline', (tester) async {
      final t = _FakeTransport(tester, (_) => const _Front.silent());
      final run = _start(t);
      await _advance(tester, 12100);
      expect(t.maxOutstanding, 3);
      expect(run.outcome!.deadlineReached, isTrue);
      expect(run.outcome!.outstandingAtFinish, 3);
      await _advance(tester, 100);
      expect(t.outstanding, 0);
      expect(t.aborted.length, t.starts.length);
    });

    testWidgets('a slot is held until the aborted operation has really ended',
        (tester) async {
      // The pinned client's abort takes effect only after connection setup:
      // model it as a 3 s lag. The fourth front must wait for that, not for
      // the 4 s timeout alone.
      final t = _FakeTransport(tester, (_) => const _Front.silent(),
          abortLagMs: 3000);
      _start(t);
      await _advance(tester, 6900);
      expect(t.starts.length, 3);
      expect(t.maxOutstanding, 3);
      await _advance(tester, 200);
      expect(t.starts.length, 4);
      expect(t.starts[3].$2, 7000);
      expect(t.maxOutstanding, 3);
      await _advance(tester, 20000);
    });

    testWidgets('a winner aborts every other open operation', (tester) async {
      final t = _FakeTransport(
        tester,
        (i) => i == 2
            ? const _Front.reply(200, _ok, delayMs: 200)
            : const _Front.silent(),
      );
      final run = _start(t);
      await _advance(tester, 1300);
      expect(run.outcome!.acceptedUrl, 'https://f2.example/free/verify');
      expect(run.finishedAtMs, 1200);
      expect(run.outcome!.outstandingAtFinish, 2);
      await _advance(tester, 100);
      expect(t.aborted, containsAll(<int>[0, 1]));
      expect(t.outstanding, 0);
    });

    testWidgets('cancellation aborts every open operation', (tester) async {
      var cancelled = false;
      final t = _FakeTransport(tester, (_) => const _Front.silent());
      final run = _start(t, shouldCancel: () => cancelled);
      await _advance(tester, 600);
      cancelled = true;
      await _advance(tester, 500);
      expect(run.outcome!.cancelled, isTrue);
      expect(run.outcome!.exhaustive, isFalse);
      await _advance(tester, 100);
      expect(t.outstanding, 0);
      expect(t.aborted.length, t.starts.length);
    });
  });

  group('cancellation', () {
    // The counterexample from review: launches at 0, 0.5 and 1 s, the last
    // stagger event at 1.5 s, cancellation at 1.6 s, an accepted reply at 1.7 s.
    _Front counterexample(int i) => i == 0
        ? const _Front.reply(200, _ok, delayMs: 1700)
        : const _Front.silent();

    testWidgets('cancellation after the last stagger event, by predicate '
        'only: the accepted reply at 1.7 s is NOT accepted', (tester) async {
      var cancelled = false;
      final t = _FakeTransport(tester, counterexample);
      final run = _start(t, fronts: 3, shouldCancel: () => cancelled);
      await _advance(tester, 1600, step: 10);
      expect(t.starts.map((s) => s.$2).toList(), <int>[0, 500, 1000]);
      cancelled = true;
      await _advance(tester, 200, step: 10);
      expect(run.outcome!.cancelled, isTrue);
      expect(run.outcome!.value, isNull);
      expect(run.finishedAtMs, 1700);
      await _advance(tester, 100);
      expect(t.outstanding, 0);
    });

    testWidgets('explicit cancellation completes the window and signals every '
        'abort at once, with no further scheduling event', (tester) async {
      final cancellation = HubCancellation();
      final t = _FakeTransport(tester, counterexample);
      final run = _start(t, fronts: 3, cancellation: cancellation);
      await _advance(tester, 1600, step: 10);
      cancellation.cancel();
      await tester.pump(Duration.zero);
      expect(run.outcome!.cancelled, isTrue);
      expect(run.finishedAtMs, 1600);
      expect(t.abortedAt, <int>[1600, 1600, 1600]);
      await _advance(tester, 300, step: 10);
      expect(run.outcome!.value, isNull);
    });

    testWidgets('an accepted result that arrives after cancellation is not '
        'accepted', (tester) async {
      var cancelled = false;
      HubRequestWindowOutcome<String>? outcome;
      runHubRequestWindow<String>(
        urls: _fronts(1),
        shouldCancel: () => cancelled,
        permits: HubTransportPermits(3),
        attempt: (url, abort) async {
          // The transport ignores the abort and answers anyway.
          await Future<void>.delayed(const Duration(milliseconds: 300));
          return const HubAttemptResult<String>.accepted('late');
        },
      ).then((value) => outcome = value);
      await tester.pump(const Duration(milliseconds: 100));
      cancelled = true;
      await tester.pump(const Duration(milliseconds: 300));
      expect(outcome!.cancelled, isTrue);
      expect(outcome!.value, isNull);
    });

    testWidgets('the registry cancels exactly the operations its generation '
        'change made stale', (tester) async {
      var epoch = 1;
      final registry = HubCancellationRegistry();
      final stale = registry.track(() => epoch != 1);
      final current = registry.track(() => false);
      final t = _FakeTransport(tester, (_) => const _Front.silent());
      final run = _start(t, fronts: 3, cancellation: stale);
      await _advance(tester, 700);
      epoch = 2;
      registry.notifyGenerationChanged();
      await tester.pump(Duration.zero);
      expect(run.outcome!.cancelled, isTrue);
      expect(run.finishedAtMs, 700);
      expect(stale.isCancelled, isTrue);
      expect(current.isCancelled, isFalse);
      await _advance(tester, 100);
    });
  });

  group('shared transport permits across windows', () {
    testWidgets('consecutive windows never hold more than 3 operations '
        'between them, and waiting consumes the later window\'s deadline',
        (tester) async {
      // Status-like window: 6 s deadline, 3 s per-request timeout, and an
      // abort that ends the operation only after 7 s (connection setup).
      // Its operations are still open when it returns; the next window must
      // wait for their permits.
      final pool = HubTransportPermits(3);
      final count = _SharedCount();
      final status = _FakeTransport(tester, (_) => const _Front.silent(),
          abortLagMs: 7000, shared: count);
      final first = _start(status,
          permits: pool,
          policy: const HubRequestWindowPolicy(
              perRequestTimeout: Duration(seconds: 3),
              totalDeadline: Duration(seconds: 6)));
      await _advance(tester, 6100);
      expect(first.outcome!.deadlineReached, isTrue);
      expect(status.outstanding, 3);
      expect(pool.inUse, 3);
      final discovery = _FakeTransport(tester, (_) => const _Front.silent(),
          shared: count);
      final second = _start(discovery,
          permits: pool,
          policy: const HubRequestWindowPolicy(
              perRequestTimeout: Duration(seconds: 5),
              totalDeadline: Duration(seconds: 10)));
      await _advance(tester, 3500);
      expect(discovery.starts, isEmpty);
      expect(count.max, 3);
      // The first status operation ends at 3 s + 7 s = 10 s.
      await _advance(tester, 700);
      expect(discovery.starts.length, 1);
      expect(discovery.starts.first.$2, greaterThanOrEqualTo(3900));
      await _advance(tester, 12000);
      expect(second.outcome!.deadlineReached, isTrue);
      expect(count.max, 3);
      await _advance(tester, 10000);
      expect(pool.inUse, 0);
    });

    testWidgets('a superseded refresh keeps its permits until its operations '
        'really end', (tester) async {
      final pool = HubTransportPermits(3);
      final count = _SharedCount();
      final cancellation = HubCancellation();
      final old = _FakeTransport(tester, (_) => const _Front.silent(),
          abortLagMs: 3000, shared: count);
      final superseded =
          _start(old, permits: pool, cancellation: cancellation);
      await _advance(tester, 1100);
      cancellation.cancel();
      await tester.pump(Duration.zero);
      expect(superseded.outcome!.cancelled, isTrue);
      final fresh = _FakeTransport(tester,
          (_) => const _Front.reply(200, _ok, delayMs: 200),
          shared: count);
      final replacement = _start(fresh, permits: pool);
      await _advance(tester, 2800);
      expect(fresh.starts, isEmpty);
      expect(count.max, 3);
      await _advance(tester, 600);
      expect(fresh.starts, isNotEmpty);
      await _advance(tester, 400);
      expect(replacement.outcome!.value, isNotNull);
      expect(count.max, 3);
      expect(pool.inUse, 0);
    });
  });

  group('deadline and reachability', () {
    testWidgets('silent fronts: the walk ends at 12 s having started 9',
        (tester) async {
      final t = _FakeTransport(tester, (_) => const _Front.silent());
      final run = _start(t);
      await _advance(tester, 11950);
      expect(run.outcome, isNull);
      await _advance(tester, 100);
      expect(run.finishedAtMs, 12000);
      expect(run.outcome!.deadlineReached, isTrue);
      expect(run.outcome!.exhaustive, isFalse);
      // 0, .5, 1, then a slot at each abort: 4, 4.5, 5, 8, 8.5, 9.
      expect(run.outcome!.started.length, 9);
    });

    for (final position in <int>[10, 20, 29]) {
      testWidgets('a reachable front at position $position is reached when the '
          'fronts before it fail outright', (tester) async {
        final t = _FakeTransport(
          tester,
          (i) => i == position - 1
              ? const _Front.reply(200, _ok, delayMs: 300)
              : const _Front.failFast(),
        );
        final run = _start(t);
        await _advance(tester, 4000, step: 10);
        expect(run.outcome!.acceptedUrl,
            'https://f${position - 1}.example/free/verify');
        expect(run.finishedAtMs, lessThan(3500));
      });

      testWidgets('a reachable front at position $position is NOT reached '
          'within 12 s when the fronts before it are silent', (tester) async {
        final t = _FakeTransport(
          tester,
          (i) => i == position - 1
              ? const _Front.reply(200, _ok, delayMs: 300)
              : const _Front.silent(),
        );
        final run = _start(t);
        await _advance(tester, 12100);
        expect(run.outcome!.value, isNull);
        expect(run.outcome!.deadlineReached, isTrue);
        expect(t.starts.map((s) => s.$1), isNot(contains(position - 1)));
      });
    }

    testWidgets('a slow but valid reply inside the per-request timeout wins',
        (tester) async {
      final t = _FakeTransport(tester,
          (i) => i == 0 ? const _Front.reply(200, _ok, delayMs: 3900)
              : const _Front.silent());
      final run = _start(t);
      await _advance(tester, 4000, step: 10);
      expect(run.outcome!.acceptedUrl, 'https://f0.example/free/verify');
      expect(run.finishedAtMs, 3900);
    });

    testWidgets('a reply after the per-request timeout is aborted, not '
        'accepted', (tester) async {
      final t = _FakeTransport(tester,
          (i) => i == 0 ? const _Front.reply(200, _ok, delayMs: 4100)
              : const _Front.silent());
      final run = _start(t);
      await _advance(tester, 12100);
      expect(t.aborted, contains(0));
      expect(run.outcome!.value, isNull);
      expect(run.outcome!.deadlineReached, isTrue);
    });

    testWidgets('a reply that would land after the total deadline is ignored',
        (tester) async {
      // The 9th front starts at 9 s; its answer would come at 12.5 s.
      final t = _FakeTransport(tester,
          (i) => i == 8 ? const _Front.reply(200, _ok, delayMs: 3500)
              : const _Front.silent());
      final run = _start(t);
      await _advance(tester, 13000);
      expect(t.starts.map((s) => s.$1), contains(8));
      expect(run.outcome!.value, isNull);
      expect(run.finishedAtMs, 12000);
      expect(t.aborted, contains(8));
    });
  });

  group('winners, invalid candidates, terminal refusals', () {
    testWidgets('the first valid reply by arrival wins, not by list order',
        (tester) async {
      final t = _FakeTransport(tester, (i) => i == 0
          ? const _Front.reply(200, _ok, delayMs: 3000)
          : const _Front.reply(200, _ok, delayMs: 500));
      final run = _start(t, fronts: 3);
      await _advance(tester, 1100);
      expect(run.outcome!.acceptedUrl, 'https://f1.example/free/verify');
      expect(run.finishedAtMs, 1000);
    });

    testWidgets('a candidate the validator rejects loses, and a later valid '
        'one still wins', (tester) async {
      final t = _FakeTransport(
          tester, (_) => const _Front.reply(200, _ok, delayMs: 100));
      final validated = <int>[];
      final run = _start(t, fronts: 4, validate: (url, _) async {
        validated.add(_index(url));
        return _index(url) == 3;
      });
      await _advance(tester, 1000, step: 10);
      expect(validated, <int>[0, 1, 2, 3]);
      expect(run.outcome!.acceptedUrl, 'https://f3.example/free/verify');
    });

    testWidgets('HTML and unauthenticated replies are rejected', (tester) async {
      final t = _FakeTransport(tester, (i) => switch (i) {
            0 => const _Front.reply(200, '<!DOCTYPE html><p>portal</p>'),
            1 => const _Front.reply(200, '{"status":"pending"}'),
            _ => const _Front.reply(200, _ok),
          });
      final run = _start(t, fronts: 3);
      await _advance(tester, 400, step: 10);
      expect(run.outcome!.acceptedUrl, 'https://f2.example/free/verify');
    });

    testWidgets('a terminal refusal stops new fronts, but an in-flight valid '
        'reply still wins', (tester) async {
      final t = _FakeTransport(tester, (i) => i == 0
          ? const _Front.reply(200, _ok, delayMs: 2000)
          : const _Front.reply(503, '{"detail":"System Maintenance underway."}',
              delayMs: 100));
      final run = _start(t, fronts: 10);
      await _advance(tester, 3000);
      expect(t.starts.length, 2);
      expect(run.outcome!.acceptedUrl, 'https://f0.example/free/verify');
    });

    testWidgets('a terminal refusal with nothing in flight is reported, and is '
        'not an exhaustive sweep', (tester) async {
      final t = _FakeTransport(tester, (_) => const _Front.reply(429, ''));
      final run = _start(t, fronts: 10);
      await _advance(tester, 600);
      expect(t.starts.length, 1);
      expect(run.outcome!.terminalKinds, <String>{'rate_limited'});
      expect(run.outcome!.exhaustive, isFalse);
    });

    testWidgets('duplicate and blank fronts start once', (tester) async {
      final starts = <String>[];
      runHubRequestWindow<String>(
        urls: <String>['https://a/x', ' ', 'https://a/x', 'https://b/x '],
        attempt: (url, _) async {
          starts.add(url);
          return const HubAttemptResult<String>.rejected();
        },
      );
      await _advance(tester, 500, step: 10);
      expect(starts, <String>['https://a/x', 'https://b/x']);
    });
  });

  group('signals and late results', () {
    Set<String> capacity(int status) => status == 503
        ? const <String>{kHubSignalServerAtCapacity}
        : const <String>{};

    testWidgets('a signal from a reply that settled in time is reported',
        (tester) async {
      final t = _FakeTransport(tester, (i) => i == 0
          ? const _Front.reply(503, '{}', delayMs: 100)
          : const _Front.failFast());
      final run = _start(t, fronts: 3, signalsFor: capacity);
      await _advance(tester, 1000, step: 10);
      expect(run.outcome!.signals, <String>{kHubSignalServerAtCapacity});
    });

    testWidgets('a late 503 cannot reach the next refresh', (tester) async {
      // Refresh 1 ends at its 1 s deadline. Its front ignores the abort for
      // 5 s and then answers 503, while refresh 2 is running. Neither
      // outcome may carry the signal: refresh 1 had finished, and refresh 2
      // never saw that reply.
      final first = _FakeTransport(tester,
          (_) => const _Front.reply(503, '{}', delayMs: 1500),
          abortLagMs: 5000);
      final run1 = _start(first,
          fronts: 1,
          signalsFor: capacity,
          policy: const HubRequestWindowPolicy(
              totalDeadline: Duration(seconds: 1)));
      await _advance(tester, 1100);
      expect(run1.outcome!.deadlineReached, isTrue);
      final second = _FakeTransport(tester,
          (_) => const _Front.reply(200, _ok, delayMs: 800));
      final run2 = _start(second, fronts: 1, signalsFor: capacity);
      await _advance(tester, 1500);
      expect(run2.outcome!.acceptedUrl, isNotNull);
      // The late 503 from refresh 1 has now arrived (at 1.5 s after its
      // start), after refresh 1 finished and while refresh 2 ran.
      expect(first.outstanding, 0);
      expect(run1.outcome!.signals, isEmpty);
      expect(run2.outcome!.signals, isEmpty);
    });
  });

  group('one budget for the whole operation', () {
    testWidgets('resolution between passes is skipped when the budget is '
        'spent, and bounded when it is not', (tester) async {
      final origin = tester.binding.clock.now();
      final budget = HubOperationBudget(kHubVerifyTotalDeadline,
          elapsed: () => tester.binding.clock.now().difference(origin));
      final attempted = <String>{};
      var resolveCalls = 0;
      Future<String> slowResolve() async {
        resolveCalls += 1;
        await Future<void>.delayed(const Duration(seconds: 30));
        return 'recovered';
      }

      String? resolved;
      int? doneAt;
      () async {
        final pass1 = await runHubRequestWindow<String>(
          urls: _fronts(29).take(5).toList(),
          policy: HubRequestWindowPolicy(totalDeadline: budget.remaining),
          attempt: (url, abort) => abort.then(
              (_) => const HubAttemptResult<String>.rejected()),
        );
        attempted.addAll(pass1.started);
        resolved = await runWithinBudget(slowResolve,
            budget: budget.remaining, onExhausted: () => 'compiled');
        await runHubRequestWindow<String>(
          urls: _fronts(29).where((u) => !attempted.contains(u)).toList(),
          policy: HubRequestWindowPolicy(totalDeadline: budget.remaining),
          attempt: (url, abort) => abort.then(
              (_) => const HubAttemptResult<String>.rejected()),
        );
        doneAt = tester.binding.clock.now().difference(origin).inMilliseconds;
      }();
      await _advance(tester, 12100);
      expect(doneAt, lessThanOrEqualTo(12000));
      expect(resolved, 'compiled');
      expect(resolveCalls, 1);
      expect(budget.spent, isTrue);
      // Spent: the next operation is never started.
      var calledAgain = false;
      expect(
        await runWithinBudget(() async {
          calledAgain = true;
          return 'x';
        }, budget: budget.remaining, onExhausted: () => 'skipped'),
        'skipped',
      );
      expect(calledAgain, isFalse);
      await _advance(tester, 30000, step: 1000);
    });
  });

  test('classifier: only an authenticated JSON object is a candidate', () {
    expect(classifyFreeVerifyAttempt(200, '{"status":"authenticated"}').verdict,
        HubAttemptVerdict.accepted);
    for (final body in <String>[
      '<!DOCTYPE html><p>blocked</p>',
      '{"status":"pending"}',
      '["authenticated"]',
      'not json',
      '',
    ]) {
      expect(classifyFreeVerifyAttempt(200, body).verdict,
          HubAttemptVerdict.rejected,
          reason: body);
    }
    expect(classifyFreeVerifyAttempt(500, '{"detail":"boom"}').verdict,
        HubAttemptVerdict.rejected);
    final maintenance =
        classifyFreeVerifyAttempt(503, '{"detail":"Under maintenance"}');
    expect(maintenance.terminalKind, 'maintenance');
    expect(classifyFreeVerifyAttempt(429, '').terminalKind, 'rate_limited');
  });

  test('terminal priority matches the paired race', () {
    expect(freeVerifyTerminalByPriority(<String>{}), isNull);
    expect(freeVerifyTerminalByPriority(<String>{'unavailable', 'maintenance'}),
        'maintenance');
    expect(
        freeVerifyTerminalByPriority(<String>{'rejected', 'identity_collision'}),
        'identity_collision');
  });
}
