import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/hub_request_window.dart';

void main() {
  const urls = <String>[
    'https://sync.winsvpn.org/nodes',
    'https://sync.winsvpn.com/nodes',
    'https://a.app-cloud-sync.net/nodes',
    'https://b.app-cloud-sync.net/nodes',
  ];

  test('an empty preference keeps the compiled order', () {
    expect(HubOriginPreference().order(urls), orderedEquals(urls));
  });

  test('the accepted origin moves first; the rest keep their order', () {
    final preference = HubOriginPreference()
      ..recordAccepted('https://A.App-Cloud-Sync.net:443/verify');
    expect(preference.origin, 'https://a.app-cloud-sync.net:443');
    expect(
      preference.order(urls),
      orderedEquals(<String>[
        'https://a.app-cloud-sync.net/nodes',
        'https://sync.winsvpn.org/nodes',
        'https://sync.winsvpn.com/nodes',
        'https://b.app-cloud-sync.net/nodes',
      ]),
    );
  });

  test('a preference never adds or drops a candidate', () {
    final preference = HubOriginPreference()
      ..recordAccepted('https://not-compiled.example/nodes');
    expect(preference.order(urls), orderedEquals(urls));
  });

  test('a second walk starts on the front that answered the first', () async {
    final preference = HubOriginPreference();
    final firstWalk = <String>[];
    final first = await runHubRequestWindow<String>(
      urls: urls,
      preference: preference,
      permits: HubTransportPermits(3),
      policy: const HubRequestWindowPolicy(
        stagger: Duration(milliseconds: 20),
        minSpacing: Duration.zero,
      ),
      attempt: (url, abort) async {
        firstWalk.add(url);
        return url.contains('a.app-cloud-sync.net')
            ? HubAttemptResult<String>.accepted(url)
            : const HubAttemptResult<String>.rejected();
      },
    );
    expect(first.acceptedUrl, 'https://a.app-cloud-sync.net/nodes');
    expect(firstWalk.first, 'https://sync.winsvpn.org/nodes');

    final second = await runHubRequestWindow<String>(
      urls: urls.map((u) => u.replaceAll('/nodes', '/verify')).toList(),
      preference: preference,
      permits: HubTransportPermits(3),
      attempt: (url, abort) async => HubAttemptResult<String>.accepted(url),
    );
    expect(second.started.first, 'https://a.app-cloud-sync.net/verify');
    expect(second.started, hasLength(1),
        reason: 'no blocked front is launched before the known-good one');
  });

  // ARBITER-COMPOSED (Turn 5, PERF-CHOICE). Walks with two or three silent
  // fronts ahead of the reachable one, under the free preflight's policy
  // (3 s per request, 6 s budget) and node discovery's (5 s, 10 s), both with
  // the default 500 ms stagger and 3 in flight. A silent front is modelled as
  // a connect that ignores the abort until the pinned client's 10 s
  // connection timeout (kControlPlanePinConnectionTimeout), which is when
  // sendHubRequest's doc comment says the abort takes effect during
  // connection setup.
  group('walks with silent fronts ahead of the reachable one', () {
    const fronts = <String>[
      'https://sync.winsvpn.org/free/status',
      'https://sync.winsvpn.com/free/status',
      'https://a.app-cloud-sync.net/free/status',
      'https://b.app-cloud-sync.net/free/status',
    ];
    const reachable = 'https://a.app-cloud-sync.net/free/status';

    const preflight = HubRequestWindowPolicy(
      perRequestTimeout: Duration(seconds: 3),
      totalDeadline: kFreeStatusPreflightDeadline,
    );

    Future<(HubRequestWindowOutcome<String>?, Duration?)> walk(
        WidgetTester tester, List<String> order,
        {HubRequestWindowPolicy policy = preflight,
        HubOriginPreference? preference}) async {
      HubRequestWindowOutcome<String>? outcome;
      Duration? at;
      // The end of the fake-time step in progress; an outcome that arrives
      // during a step is stamped with that step's end.
      var now = Duration.zero;
      runHubRequestWindow<String>(
        urls: order,
        preference: preference,
        permits: HubTransportPermits(3),
        policy: policy,
        attempt: (url, abort) => url == reachable
            ? Future<HubAttemptResult<String>>.value(
                const HubAttemptResult<String>.accepted(''))
            : Future<HubAttemptResult<String>>.delayed(
                const Duration(seconds: 10),
                () => const HubAttemptResult<String>.rejected()),
      ).then((value) {
        outcome = value;
        at = now;
      });
      await tester.pump();
      const step = Duration(milliseconds: 100);
      while (outcome == null && now < const Duration(seconds: 12)) {
        now += step;
        await tester.pump(step);
      }
      // Let the silent attempts end so no timer outlives the test.
      await tester.pump(const Duration(seconds: 12));
      return (outcome, at);
    }

    testWidgets('P1S order: two silent fronts delay the reachable one by '
        '2 x 500 ms', (tester) async {
      final (outcome, at) = await walk(tester, fronts);
      expect(outcome!.acceptedUrl, reachable);
      expect(outcome.started, fronts.sublist(0, 3));
      expect(at, const Duration(seconds: 1));
    });

    testWidgets('C-2 order with the reachable front preferred: it starts '
        'first', (tester) async {
      final preference = HubOriginPreference()..recordAccepted(reachable);
      final (outcome, at) = await walk(tester, preference.order(fronts));
      expect(outcome!.acceptedUrl, reachable);
      expect(outcome.started, <String>[reachable]);
      expect(at, Duration.zero);
    });

    testWidgets('C-2 order with a stale preference for a now-silent front: '
        'the reachable front never starts inside the 6 s budget',
        (tester) async {
      final preference = HubOriginPreference()..recordAccepted(fronts[3]);
      final order = preference.order(fronts);
      expect(order.first, fronts[3]);
      final (outcome, at) = await walk(tester, order);
      expect(outcome!.value, isNull);
      expect(outcome.deadlineReached, isTrue);
      expect(outcome.started, <String>[fronts[3], fronts[0], fronts[1]]);
      expect(at, kFreeStatusPreflightDeadline);
    });

    testWidgets('either variant: node discovery, which is given the '
        'preference, with the same stale preference never starts the '
        'reachable front inside its 10 s budget', (tester) async {
      final preference = HubOriginPreference()..recordAccepted(fronts[3]);
      final (outcome, at) = await walk(
        tester,
        fronts,
        preference: preference,
        policy: const HubRequestWindowPolicy(
          perRequestTimeout: Duration(seconds: 5),
          totalDeadline: kNodeDiscoveryDeadline,
        ),
      );
      expect(outcome!.value, isNull);
      expect(outcome.deadlineReached, isTrue);
      expect(outcome.started, <String>[fronts[3], fronts[0], fronts[1]]);
      expect(at, kNodeDiscoveryDeadline);
    });
  });

  // ARBITER-COMPOSED (Turn 6, PERF-CHOICE). Sol's Turn 5 regression checks
  // for its rule: when the preferred origin observed at window entry reaches
  // its per-request timeout, the walk forgets that preference unless a newer
  // acceptance has refreshed it (a revision compare, including a refresh
  // that names the same origin). Same silent-front premise as the group
  // above. D = b, A = org, B = com, C = a.
  group('a timed-out preferred origin is forgotten unless refreshed', () {
    const org = 'https://sync.winsvpn.org/x';
    const com = 'https://sync.winsvpn.com/x';
    const a = 'https://a.app-cloud-sync.net/x';
    const b = 'https://b.app-cloud-sync.net/x';
    const fronts = <String>[org, com, a, b];
    const preflight = HubRequestWindowPolicy(
      perRequestTimeout: Duration(seconds: 3),
      totalDeadline: kFreeStatusPreflightDeadline,
    );
    const discovery = HubRequestWindowPolicy(
      perRequestTimeout: Duration(seconds: 5),
      totalDeadline: kNodeDiscoveryDeadline,
    );
    const step = Duration(milliseconds: 100);

    Future<HubAttemptResult<String>> silentFor10s() =>
        Future<HubAttemptResult<String>>.delayed(
          const Duration(seconds: 10),
          () => const HubAttemptResult<String>.rejected(),
        );

    // _freeAccessPreflightTerminalKind's wiring: the walk reads the
    // preference, the closure teaches it on a 200, and the window may only
    // forget it.
    Future<HubRequestWindowOutcome<String>> preflightWalk(
      HubOriginPreference preference,
      HubTransportPermits pool,
      HubAttempt<String> attempt, {
      List<String> urls = fronts,
      HubCancellation? cancellation,
    }) =>
        runHubRequestWindow<String>(
          urls: preference.order(urls),
          timeoutPreference: preference,
          cancellation: cancellation,
          permits: pool,
          policy: preflight,
          attempt: attempt,
        );

    // The wiring of node discovery and of paid and free verify.
    Future<HubRequestWindowOutcome<String>> discoveryWalk(
      HubOriginPreference preference,
      HubTransportPermits pool,
      HubAttempt<String> attempt, {
      List<String> urls = fronts,
      HubCancellation? cancellation,
    }) =>
        runHubRequestWindow<String>(
          urls: urls,
          preference: preference,
          cancellation: cancellation,
          permits: pool,
          policy: discovery,
          attempt: attempt,
        );

    // Pumps in 100 ms steps until [walk] completes; returns its outcome and
    // the fake time it took.
    Future<(HubRequestWindowOutcome<String>, Duration)> timed(
        WidgetTester tester,
        Future<HubRequestWindowOutcome<String>> walk) async {
      HubRequestWindowOutcome<String>? outcome;
      walk.then((value) => outcome = value);
      var at = Duration.zero;
      await tester.pump();
      while (outcome == null && at < const Duration(seconds: 30)) {
        at += step;
        await tester.pump(step);
      }
      return (outcome!, at);
    }

    for (final wiring in <String>['preflight', 'discovery']) {
      final timeout = wiring == 'preflight'
          ? preflight.perRequestTimeout
          : discovery.perRequestTimeout;
      testWidgets(
          '$wiring: an unchanged stale preference is forgotten at its '
          '${timeout.inSeconds} s timeout while the silent transports still '
          'hold their permits; after they settle the next walk takes the '
          'compiled order and reaches C after two 500 ms staggers',
          (tester) async {
        final pool = HubTransportPermits(3);
        final preference = HubOriginPreference()..recordAccepted(b);
        Future<HubAttemptResult<String>> attempt(String url, Future<void> _) =>
            url == a
                ? Future<HubAttemptResult<String>>.value(
                    const HubAttemptResult<String>.accepted(''))
                : silentFor10s();
        HubRequestWindowOutcome<String>? first;
        (wiring == 'preflight'
                ? preflightWalk(preference, pool, attempt)
                : discoveryWalk(preference, pool, attempt))
            .then((value) => first = value);
        await tester.pump(timeout - step);
        expect(preference.origin, 'https://b.app-cloud-sync.net:443');
        await tester.pump(step);
        expect(preference.origin, isNull,
            reason: 'D timed out with the revision this walk observed');
        expect(pool.inUse, 3,
            reason: 'D, A and B still hold their permits after the timeout');
        await tester.pump(const Duration(seconds: 11) - timeout);
        expect(first, isNotNull);
        expect(first!.started, <String>[b, org, com]);
        expect(first!.value, isNull);
        expect(pool.inUse, 0);
        final (next, at) = await timed(tester, discoveryWalk(preference, pool,
            (url, abort) => url == a
                ? Future<HubAttemptResult<String>>.value(
                    const HubAttemptResult<String>.accepted(''))
                : silentFor10s()));
        expect(next.started, <String>[org, com, a]);
        expect(next.acceptedUrl, a);
        expect(at, const Duration(seconds: 1));
        expect(preference.origin, 'https://a.app-cloud-sync.net:443');
        await tester.pump(const Duration(seconds: 12));
      });

      testWidgets(
          '$wiring: an acceptance during the walk keeps the refreshed '
          'preference, for another origin and for D again', (tester) async {
        for (final refresh in <String>[a, b]) {
          final preference = HubOriginPreference()..recordAccepted(b);
          final revision = preference.revision;
          Timer(const Duration(seconds: 1),
              () => preference.recordAccepted(refresh));
          final walk = wiring == 'preflight'
              ? preflightWalk(preference, HubTransportPermits(3),
                  (url, abort) => silentFor10s())
              : discoveryWalk(preference, HubTransportPermits(3),
                  (url, abort) => silentFor10s());
          final (outcome, _) = await timed(tester, walk);
          expect(outcome.started.first, b);
          expect(preference.revision, revision + 1,
              reason: 'only the refresh changed the preference');
          expect(preference.origin, hubOriginOf(refresh));
          await tester.pump(const Duration(seconds: 12));
        }
      });

      testWidgets(
          '$wiring: a timeout on a front that is not the preferred one, and '
          'a cancellation, keep the preference', (tester) async {
        final notInWalk = HubOriginPreference()..recordAccepted(b);
        final (o1, _) = await timed(
            tester,
            wiring == 'preflight'
                ? preflightWalk(notInWalk, HubTransportPermits(3),
                    (url, abort) => silentFor10s(),
                    urls: const <String>[org, com, a])
                : discoveryWalk(notInWalk, HubTransportPermits(3),
                    (url, abort) => silentFor10s(),
                    urls: const <String>[org, com, a]));
        expect(o1.started, <String>[org, com, a]);
        expect(notInWalk.origin, 'https://b.app-cloud-sync.net:443');
        await tester.pump(const Duration(seconds: 12));

        final cancelled = HubOriginPreference()..recordAccepted(b);
        final cancellation = HubCancellation();
        Timer(const Duration(seconds: 1), cancellation.cancel);
        final (o2, _) = await timed(
            tester,
            wiring == 'preflight'
                ? preflightWalk(cancelled, HubTransportPermits(3),
                    (url, abort) => silentFor10s(),
                    cancellation: cancellation)
                : discoveryWalk(cancelled, HubTransportPermits(3),
                    (url, abort) => silentFor10s(),
                    cancellation: cancellation));
        expect(o2.cancelled, isTrue);
        await tester.pump(const Duration(seconds: 12));
        expect(cancelled.origin, 'https://b.app-cloud-sync.net:443');
      });
    }

    testWidgets(
        "Sol's D, A, B launch sequence on one free connect (preflight, then "
        'node discovery, one shared pool): D is forgotten at 3 s, discovery '
        'reaches C at 5 s, and the next connect starts on C', (tester) async {
      const silent = <String>{org, com, b};
      final pool = HubTransportPermits(3);
      final preference = HubOriginPreference()..recordAccepted(b);
      Future<HubAttemptResult<String>> attempt(String url,
          {required bool closureTeaches}) {
        if (silent.contains(url)) return silentFor10s();
        // A 200, which only the preflight closure records itself.
        if (closureTeaches) preference.recordAccepted(url);
        return Future<HubAttemptResult<String>>.value(
            const HubAttemptResult<String>.accepted(''));
      }

      final walks = <(String, HubRequestWindowOutcome<String>, Duration)>[];
      var now = Duration.zero;
      Duration? forgotAt;
      Future<void> connect() async {
        var start = now;
        final p = await preflightWalk(preference, pool,
            (url, abort) => attempt(url, closureTeaches: true));
        walks.add(('preflight', p, now - start));
        start = now;
        final d = await discoveryWalk(preference, pool,
            (url, abort) => attempt(url, closureTeaches: false));
        walks.add(('discovery', d, now - start));
      }

      var done = false;
      () async {
        await connect();
        await Future<void>.delayed(const Duration(seconds: 30));
        await connect();
      }()
          .whenComplete(() => done = true);
      await tester.pump();
      for (var i = 0; i < 700 && !done; i++) {
        now += step;
        await tester.pump(step);
        if (forgotAt == null && preference.origin == null) forgotAt = now;
      }
      await tester.pump(const Duration(seconds: 15));
      expect(done, isTrue);
      expect(walks.map((w) => w.$1).toList(),
          <String>['preflight', 'discovery', 'preflight', 'discovery']);
      final (_, p1, p1At) = walks[0];
      expect(p1.started, <String>[b, org, com],
          reason: 'D, A, B hold the three permits');
      expect(p1.deadlineReached, isTrue);
      expect(p1At, kFreeStatusPreflightDeadline);
      expect(forgotAt, const Duration(seconds: 3));
      final (_, d1, d1At) = walks[1];
      expect(d1.started, <String>[org, com, a]);
      expect(d1.acceptedUrl, a);
      expect(d1At, const Duration(seconds: 5));
      expect(walks[2].$2.started, <String>[a]);
      expect(walks[3].$2.started, <String>[a]);
      expect(preference.origin, 'https://a.app-cloud-sync.net:443');
    });
  });
}
