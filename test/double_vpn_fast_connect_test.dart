import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/double_vpn_assignment_retry.dart';
import 'package:wins_vpn/double_vpn_fast_connect.dart';

// FAST-CONNECT FOR DOUBLE VPN (owner-approved 2026-10-24). A Double VPN
// connect must be protected in under 3 s from the tap, every time: a warm
// assignment connects Double directly, a cold one connects one hop first
// (marked) and upgrades make-before-break in the background.

/// A virtual clock for the upgrade loop: sleeps advance it instead of waiting.
class _VirtualClock {
  Duration now = Duration.zero;
  final List<Duration> sleeps = <Duration>[];
  Future<void> sleep(Duration delay) async {
    sleeps.add(delay);
    now += delay;
  }
}

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production method: $start');
  }
  return source.substring(first, last);
}

void main() {
  group('eligibility', () {
    test('only a fresh Android connect that wants Double VPN', () {
      expect(
        doubleVpnFastConnectEligible(
            operatingSystem: 'android',
            doubleVpnRequested: true,
            freshConnect: true),
        isTrue,
      );
      expect(
        doubleVpnFastConnectEligible(
            operatingSystem: 'android',
            doubleVpnRequested: false,
            freshConnect: true),
        isFalse,
        reason: 'single hop is not marked when Double VPN is not wanted',
      );
      expect(
        doubleVpnFastConnectEligible(
            operatingSystem: 'android',
            doubleVpnRequested: true,
            freshConnect: false),
        isFalse,
        reason: 'a server switch keeps its retained tunnel and asks for Double',
      );
      for (final os in <String>['ios', 'macos', 'windows', 'linux']) {
        expect(
          doubleVpnFastConnectEligible(
              operatingSystem: os,
              doubleVpnRequested: true,
              freshConnect: true),
          isFalse,
          reason: '$os has no in-place handover; it keeps the old behaviour',
        );
        expect(doubleVpnHandoverCutoverSupported(os), isFalse);
      }
      expect(doubleVpnHandoverCutoverSupported('android'), isTrue);
    });
  });

  group('timing', () {
    test('a cold connect stays under the 3 s owner bound', () {
      // Measured on the S26 release build: single hop tap -> validated.
      const singleHopConnect = Duration(milliseconds: 1380);
      expect(doubleVpnDirectConnectBudget + singleHopConnect,
          lessThan(const Duration(seconds: 3)));
    });

    test('a warm connect fits inside the budget', () {
      // Measured: a warm Double connect, refresh AND tunnel proof, 1.10 s.
      expect(doubleVpnDirectConnectBudget,
          greaterThan(const Duration(milliseconds: 1100)));
    });

    test('the handover respects the native start spacing', () {
      // MainActivity refuses a start within 1.5 s of the previous one.
      expect(doubleVpnHandoverMinimumSpacing,
          greaterThan(const Duration(milliseconds: 1500)));
      expect(doubleVpnHandoverSpacingRemaining(Duration.zero),
          doubleVpnHandoverMinimumSpacing);
      expect(
          doubleVpnHandoverSpacingRemaining(
              const Duration(milliseconds: 600)),
          const Duration(milliseconds: 1000));
      expect(doubleVpnHandoverSpacingRemaining(const Duration(seconds: 5)),
          Duration.zero);
    });
  });

  group('backoff', () {
    test('doubles from 10 s and is capped at five minutes', () {
      expect(
        <Duration>[for (var i = 0; i <= 9; i++) doubleVpnUpgradeBackoff(i)],
        <Duration>[
          const Duration(seconds: 10),
          const Duration(seconds: 10),
          const Duration(seconds: 20),
          const Duration(seconds: 40),
          const Duration(seconds: 80),
          const Duration(seconds: 160),
          const Duration(minutes: 5),
          const Duration(minutes: 5),
          const Duration(minutes: 5),
          const Duration(minutes: 5),
        ],
      );
      expect(doubleVpnUpgradeBackoff(1 << 20), const Duration(minutes: 5));
    });
  });

  group('upgrade loop', () {
    test('a served Double config upgrades on the first attempt', () async {
      final clock = _VirtualClock();
      final phases = <DoubleVpnUpgradePhase>[];
      var attempts = 0;
      final exit = await runDoubleVpnUpgradeLoop(
        attempt: () async {
          attempts++;
          return DoubleVpnCutoverResult.upgraded;
        },
        isCurrent: () => true,
        mayAttemptNow: () => true,
        onPhase: phases.add,
        sleep: clock.sleep,
      );
      expect(exit, DoubleVpnUpgradeExit.upgraded);
      expect(attempts, 1);
      expect(phases, <DoubleVpnUpgradePhase>[DoubleVpnUpgradePhase.none],
          reason: 'the marker wording clears only when Double commits');
      expect(clock.now, Duration.zero,
          reason: 'the first attempt starts as soon as single hop commits');
    });

    test('Core unavailable: stays single hop, marked, bounded retries',
        () async {
      final clock = _VirtualClock();
      final phases = <DoubleVpnUpgradePhase>[];
      final attemptTimes = <Duration>[];
      const horizon = Duration(minutes: 30);
      final exit = await runDoubleVpnUpgradeLoop(
        attempt: () async {
          attemptTimes.add(clock.now);
          return DoubleVpnCutoverResult.keptSingleHop;
        },
        isCurrent: () => clock.now < horizon,
        mayAttemptNow: () => true,
        onPhase: phases.add,
        sleep: clock.sleep,
      );
      expect(exit, DoubleVpnUpgradeExit.cancelled);
      expect(phases, isNotEmpty);
      expect(phases.toSet(), <DoubleVpnUpgradePhase>{
        DoubleVpnUpgradePhase.unavailable,
      }, reason: 'never claims Double while the Core is down');
      // No storm: 10+20+40+80+160 s, then one attempt per five minutes.
      expect(attemptTimes.length, lessThanOrEqualTo(12));
      for (var i = 1; i < attemptTimes.length; i++) {
        expect(attemptTimes[i] - attemptTimes[i - 1],
            greaterThanOrEqualTo(const Duration(seconds: 10)));
      }
      expect(attemptTimes.take(4).toList(), <Duration>[
        Duration.zero,
        const Duration(seconds: 10),
        const Duration(seconds: 30),
        const Duration(seconds: 70),
      ]);
    });

    test('one assignment poll per attempt keeps the request rate bounded', () {
      // Each attempt is one pollDoubleVpnAssignment, itself bounded.
      expect(defaultDoubleVpnAssignmentMaximumElapsed,
          lessThanOrEqualTo(const Duration(minutes: 2)));
      expect(
        doubleVpnAssignmentRetryDelay(const <String, String>{
          'Retry-After': '0',
        }),
        const Duration(seconds: 1),
        reason: 'the existing one-second floor still applies',
      );
    });

    test('disconnect during the backoff wait ends the loop at once', () async {
      final clock = _VirtualClock();
      var current = true;
      var attempts = 0;
      final exit = await runDoubleVpnUpgradeLoop(
        attempt: () async {
          attempts++;
          return DoubleVpnCutoverResult.keptSingleHop;
        },
        isCurrent: () => current,
        mayAttemptNow: () => true,
        onPhase: (_) {},
        sleep: (delay) async {
          await clock.sleep(delay);
          // The user taps Disconnect two seconds into the first wait.
          if (clock.now >= const Duration(seconds: 2)) current = false;
        },
      );
      expect(exit, DoubleVpnUpgradeExit.cancelled);
      expect(attempts, 1, reason: 'no attempt after the disconnect');
      expect(clock.now, lessThan(const Duration(seconds: 3)),
          reason: 'the wait is sliced, so it ends promptly');
    });

    test('disconnect during an attempt sends no further attempt', () async {
      var current = true;
      var attempts = 0;
      final exit = await runDoubleVpnUpgradeLoop(
        attempt: () async {
          attempts++;
          current = false;
          return DoubleVpnCutoverResult.keptSingleHop;
        },
        isCurrent: () => current,
        mayAttemptNow: () => true,
        onPhase: (_) => fail('a cancelled loop reports no phase'),
        sleep: _VirtualClock().sleep,
      );
      expect(exit, DoubleVpnUpgradeExit.cancelled);
      expect(attempts, 1);
    });

    test('a busy tunnel defers attempts without counting failures', () async {
      final clock = _VirtualClock();
      var busyChecks = 0;
      final attemptTimes = <Duration>[];
      final exit = await runDoubleVpnUpgradeLoop(
        attempt: () async {
          attemptTimes.add(clock.now);
          return attemptTimes.length < 2
              ? DoubleVpnCutoverResult.keptSingleHop
              : DoubleVpnCutoverResult.upgraded;
        },
        isCurrent: () => true,
        // Busy for the first three looks (another connect owns the tunnel).
        mayAttemptNow: () => ++busyChecks > 3,
        onPhase: (_) {},
        sleep: clock.sleep,
      );
      expect(exit, DoubleVpnUpgradeExit.upgraded);
      expect(attemptTimes.first, doubleVpnUpgradeBusyRecheck * 3);
      expect(attemptTimes[1] - attemptTimes[0], doubleVpnUpgradeBackoff(1),
          reason: 'busy looks did not inflate the failure count');
    });

    test('a refused Double route is not asked for again at once', () async {
      final clock = _VirtualClock();
      final attemptTimes = <Duration>[];
      await runDoubleVpnUpgradeLoop(
        initialDelay: doubleVpnUpgradeBackoff(1),
        attempt: () async {
          attemptTimes.add(clock.now);
          return DoubleVpnCutoverResult.upgraded;
        },
        isCurrent: () => true,
        mayAttemptNow: () => true,
        onPhase: (_) {},
        sleep: clock.sleep,
      );
      expect(attemptTimes, <Duration>[const Duration(seconds: 10)]);
    });

    test('a restored single hop counts as a failure and keeps retrying',
        () async {
      final clock = _VirtualClock();
      final results = <DoubleVpnCutoverResult>[
        DoubleVpnCutoverResult.restoredSingleHop,
        DoubleVpnCutoverResult.upgraded,
      ];
      final phases = <DoubleVpnUpgradePhase>[];
      final exit = await runDoubleVpnUpgradeLoop(
        attempt: () async => results.removeAt(0),
        isCurrent: () => true,
        mayAttemptNow: () => true,
        onPhase: phases.add,
        sleep: clock.sleep,
      );
      expect(exit, DoubleVpnUpgradeExit.upgraded);
      expect(phases, <DoubleVpnUpgradePhase>[
        DoubleVpnUpgradePhase.unavailable,
        DoubleVpnUpgradePhase.none,
      ]);
    });

    test('a lost session ends the loop without another attempt', () async {
      var attempts = 0;
      final exit = await runDoubleVpnUpgradeLoop(
        attempt: () async {
          attempts++;
          return DoubleVpnCutoverResult.lost;
        },
        isCurrent: () => true,
        mayAttemptNow: () => true,
        onPhase: (_) {},
        sleep: _VirtualClock().sleep,
      );
      expect(exit, DoubleVpnUpgradeExit.lost);
      expect(attempts, 1);
    });

    test('attempts never overlap', () async {
      var inFlight = 0;
      var maxInFlight = 0;
      var attempts = 0;
      await runDoubleVpnUpgradeLoop(
        attempt: () async {
          inFlight++;
          if (inFlight > maxInFlight) maxInFlight = inFlight;
          await Future<void>.delayed(Duration.zero);
          inFlight--;
          return ++attempts < 4
              ? DoubleVpnCutoverResult.keptSingleHop
              : DoubleVpnCutoverResult.upgraded;
        },
        isCurrent: () => true,
        mayAttemptNow: () => true,
        onPhase: (_) {},
        sleep: _VirtualClock().sleep,
      );
      expect(maxInFlight, 1);
    });
  });

  group('handover witness', () {
    test('only a real boolean of the expected value counts', () {
      expect(
          nativeDoubleVpnRouteObserved(
              <String, Object?>{'double_vpn_single_hop': false},
              expectSingleHop: false),
          isTrue);
      expect(
          nativeDoubleVpnRouteObserved(
              <String, Object?>{'double_vpn_single_hop': true},
              expectSingleHop: false),
          isFalse,
          reason: 'still the old single-hop session');
      expect(
          nativeDoubleVpnRouteObserved(
              <String, Object?>{'double_vpn_single_hop': true},
              expectSingleHop: true),
          isTrue);
      for (final reading in <Map<String, Object?>?>[
        null,
        <String, Object?>{},
        <String, Object?>{'double_vpn_single_hop': 'false'},
        <String, Object?>{'double_vpn_single_hop': 0},
      ]) {
        expect(nativeDoubleVpnRouteObserved(reading, expectSingleHop: false),
            isFalse);
        expect(nativeDoubleVpnRouteObserved(reading, expectSingleHop: true),
            isFalse);
      }
    });

    test('a matching route from a different start is stale', () {
      expect(nativeDoubleVpnRouteObserved(
        {'double_vpn_single_hop': false, 'double_vpn_handover_token': 41},
        expectSingleHop: false,
        handoverToken: 42,
      ), isFalse);
      expect(nativeDoubleVpnRouteObserved(
        {'double_vpn_single_hop': false, 'double_vpn_handover_token': 42},
        expectSingleHop: false,
        handoverToken: 42,
      ), isTrue);
    });
  });

  group('marker wording', () {
    test('the in-progress wording is distinct and still says single hop', () {
      expect(doubleVpnSingleHopPreparingNotice, startsWith('Single hop:'));
      expect(doubleVpnSingleHopPreparingNotice,
          isNot(equals(doubleVpnSingleHopSessionNotice)));
      expect(doubleVpnSingleHopPreparingNotice, contains('one server'));
      expect(doubleVpnSingleHopPreparingMessage, contains('one server'));
      expect(doubleVpnSingleHopPreparingNotice.toLowerCase(),
          isNot(contains('protected')));
      expect(doubleVpnUpgradedMessage, 'Double VPN is on.');
    });
  });

  group('main.dart wiring', () {
    late final String source;
    late final String connect;

    setUpAll(() {
      source = File('lib/main.dart').readAsStringSync();
      connect = _between(source, '  Future<void> _connectWithSmartProtocol({',
          '  Future<void> _toggleVpnConnection() async {');
    });

    test('the Kill Switch toggle is named Kill Switch', () {
      expect(source, contains('title: Text(_t("Kill Switch")),'));
      expect(source, isNot(contains('Block traffic after tunnel failure')));
      final toggle = source.indexOf("key: const Key('always_on_toggle')");
      final title = source.indexOf('_t("Kill Switch")', toggle);
      expect(title - toggle, inInclusiveRange(1, 600));
    });

    test('the bounded Double attempt runs before any single-hop request', () {
      final race = connect.indexOf('_attemptDoubleVpnRouteWithinBudget(');
      final singleRefresh = connect.indexOf(
          'doubleVpnRoute: requestDoubleRoute,', race);
      expect(race, greaterThan(0));
      expect(singleRefresh, greaterThan(race));
      final decided = connect.substring(race, singleRefresh);
      expect(decided, contains('DoubleVpnDirectRaceOutcome.served'));
      expect(decided, contains('requestDoubleRoute = false;'));
      final helper = _between(source,
          '  Future<DoubleVpnDirectRaceOutcome> _attemptDoubleVpnRouteWithinBudget({',
          '  /// FAST-CONNECT handover witness');
      expect(helper, contains('doubleVpnRoute: true'));
      expect(helper, contains('.timeout(doubleVpnDirectConnectBudget'));
      expect(helper, contains('abandoned = true;'),
          reason: 'a late Double reply must not follow a single-hop /verify');
    });

    test('a fresh Android Double request cannot reuse a cached route', () {
      expect(connect, contains(
          'var directConfig = !fastConnectEligible && beforeTunnelStart == null &&'));
      expect(connect, contains(
          "_boolValue(cachedDirectConfig['double_vpn_active']) ==\n"
          '                requestDoubleRoute &&'));
    });

    test('the upgrade is armed only after the single-hop commit', () {
      final started = connect.indexOf('if (directStarted) {');
      final armed = connect.indexOf('_armDoubleVpnUpgrade(', started);
      expect(started, greaterThan(0));
      expect(armed, greaterThan(started));
      expect(connect.substring(started, armed),
          contains('} else if (singleHopFirst) {'));
    });

    test('the cutover hands over in place, never through a stop', () {
      final handover = _between(source,
          '  Future<bool> _beginDoubleVpnHandover(',
          '  /// FAST-CONNECT: the Double start of an upgrade was handed over');
      expect(handover, isNot(contains('_stopNativeTunnel')));
      expect(handover, isNot(contains('stopTunnel')));
      expect(handover,
          contains('nativeDoubleVpnRouteObserved(readiness, expectSingleHop: true)'));
      expect(connect, contains(
          'awaitNativeDoubleVpnSingleHop: upgradeAttempt == null ? null : false,'));
      final restore = _between(source,
          '  Future<void> _restoreSingleHopAfterDoubleVpnHandover(',
          '  /// FAST-CONNECT: the bounded Double attempt of a fresh connect.');
      final restart = restore.indexOf('awaitNativeDoubleVpnSingleHop: true,');
      final stop = restore.indexOf('_stopNativeTunnelForFailover()');
      expect(restart, greaterThan(0));
      expect(stop, greaterThan(restart),
          reason: 'the restore starts in place first; a stop only follows '
              'a failed restore, and it keeps the Kill Switch block');
      expect(restore, isNot(contains('releaseKillSwitchBlock: true')));
    });

    test('restore spacing starts after MainActivity acknowledges the start', () {
      final candidate = _between(source,
          '  Future<bool> _startTunnelCandidate(',
          '  Future<void> _connectWithSmartProtocol({');
      final nativeCall = candidate.indexOf("'startTunnel',");
      final clockReset = candidate.indexOf('nativeStartSpacingClock?');
      expect(clockReset, greaterThan(nativeCall));
      // A start that throws also restarts the clock (conservative).
      final failure = candidate.indexOf('    } catch (e) {', nativeCall);
      expect(candidate.indexOf('nativeStartSpacingClock?', clockReset + 1),
          greaterThan(failure));
      expect(connect, contains(
          'nativeStartSpacingClock: upgradeAttempt?.sinceLastStart,'));
      final restore = _between(source,
          '  Future<void> _restoreSingleHopAfterDoubleVpnHandover(',
          '  /// FAST-CONNECT: the bounded Double attempt of a fresh connect.');
      expect(restore, contains(
          'nativeStartSpacingClock: attempt.sinceLastStart,'));
    });

    test('a failed handover never falls into the TCP or cover legs', () {
      final restore = connect.indexOf(
          'await _restoreSingleHopAfterDoubleVpnHandover(');
      final returned = connect.indexOf('return;', restore);
      final securityBranch =
          connect.indexOf('if (_lastTunnelCandidateWasSecurityRefusal) {');
      expect(restore, greaterThan(0));
      expect(returned, lessThan(securityBranch));
      expect(connect,
          contains('if (upgradeAttempt != null && !attemptLeadCandidate) return;'));
    });

    test('every disconnect and newer connect ends the upgrade', () {
      final cancel = _between(source,
          '  Future<bool> _cancelAndStopNativeTunnel({',
          '  Future<bool> _settleWindowsTunnelStop({');
      expect(cancel, contains('_cancelDoubleVpnUpgrade();'));
      expect(connect,
          contains('if (upgradeAttempt == null) _cancelDoubleVpnUpgrade();'));
      expect(connect,
          contains('(upgradeAttempt != null && !upgradeAttempt.stillWanted())'));
    });

    test('a silent upgrade failure keeps the single-hop session untouched', () {
      expect(connect,
          contains('if (upgradeAttempt != null && !previousTunnelReleased) return;'));
    });

    test('the upgrade defers to any operation that owns the tunnel', () {
      final arm = _between(source, '  void _armDoubleVpnUpgrade(',
          '  /// FAST-CONNECT: the upgrade\'s beforeTunnelStart.');
      for (final flag in <String>[
        '!_isLoading',
        '!_isTunnelTransitioning',
        '!_isVpnConnectInFlight',
        '!_doubleVpnPreferenceChanging',
        '!_appUpdateRequired',
        '!_accountCleanupPending',
      ]) {
        expect(arm, contains(flag));
      }
      expect(arm, contains('_isDoubleVpnRequested &&'));
      expect(arm, contains('_accountEpochIsCurrent(accountEpoch)'));
      expect(arm, contains('_winn3CoverFallbackInProgress'),
          reason: 'a cover successor is never upgraded');
    });

    test('Double VPN still cannot be toggled while connected', () {
      final toggle = _between(source,
          '  Future<void> _setDoubleVpnRequested(bool requested) async {',
          '  // STEALTH-TRANSPORT-ONLY LANE (2026-08-06). Own key, own writer.');
      expect(toggle, contains('if (_isConnected) {'));
      expect(toggle, contains('_isTunnelTransitioning ||'));
    });
  });

  group('race helper, executed verbatim', () {
    late Directory temporary;
    late File executable;

    setUpAll(() async {
      final source = File('lib/main.dart').readAsStringSync();
      final helper = _between(source,
          '  Future<DoubleVpnDirectRaceOutcome> _attemptDoubleVpnRouteWithinBudget({',
          '  /// FAST-CONNECT handover witness');
      temporary = await Directory.systemTemp.createTemp('wins-fast-connect-');
      executable = File('${temporary.path}/fast_connect_race.dart');
      final module = File('lib/double_vpn_fast_connect.dart').absolute.uri;
      await executable.writeAsString('''
import 'dart:async';
import 'dart:io';
import '$module';

class Harness {
  Harness(this.delay, this.served);
  final Duration delay;
  final bool served;
  bool cancelSeen = false;
  bool? routeAsked;
  final List<String> log = <String>[];
  void _debugLog(String message) => log.add(message);
  Future<bool> _refreshVpnConfigForCurrentSelection({
    bool stealthMode = false,
    bool Function()? shouldCancel,
    String? requestedLocation,
    void Function(Map<String, dynamic>, Map<String, dynamic>)? onPrepared,
    bool? doubleVpnRoute,
  }) async {
    routeAsked = doubleVpnRoute;
    final clock = Stopwatch()..start();
    while (clock.elapsed < delay) {
      if (shouldCancel?.call() == true) {
        cancelSeen = true;
        return false;
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    if (!served) return false;
    onPrepared?.call(<String, dynamic>{'double_vpn_active': true},
        <String, dynamic>{'status': 'authenticated'});
    return true;
  }
$helper}

Future<void> main(List<String> args) async {
  final h = Harness(Duration(milliseconds: int.parse(args[0])), args[1] == 'served');
  Map<String, dynamic>? prepared;
  final clock = Stopwatch()..start();
  final outcome = await h._attemptDoubleVpnRouteWithinBudget(
    shouldCancel: () => false,
    onPrepared: (config, response) => prepared = config,
  );
  final decidedMs = clock.elapsedMilliseconds;
  await Future<void>.delayed(const Duration(milliseconds: 300));
  stdout.writeln([outcome.name, decidedMs, h.routeAsked, prepared != null,
      h.cancelSeen].join(','));
}
''');
    });

    tearDownAll(() async {
      if (await temporary.exists()) await temporary.delete(recursive: true);
    });

    Future<List<String>> run(int delayMs, String mode) async {
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[executable.path, '$delayMs', mode],
      );
      expect(result.exitCode, 0, reason: '${result.stderr}');
      return (result.stdout as String).trim().split(',');
    }

    test('warm: a Double config inside the budget connects Double', () async {
      final r = await run(400, 'served');
      expect(r[0], 'served');
      expect(int.parse(r[1]), lessThan(1100));
      expect(r[2], 'true', reason: 'it asks for the Double route');
      expect(r[3], 'true', reason: 'the config is handed over');
      expect(r[4], 'false');
    });

    test('cold: past the budget it is abandoned and cancelled', () async {
      final r = await run(6000, 'served');
      expect(r[0], 'timedOut');
      expect(int.parse(r[1]),
          inInclusiveRange(doubleVpnDirectConnectBudget.inMilliseconds, 1700));
      expect(r[3], 'false', reason: 'a late config is never handed over');
      expect(r[4], 'true', reason: 'the poll saw its cancellation');
    });

    test('refused: a quick non-Double answer goes one hop at once', () async {
      final r = await run(100, 'refused');
      expect(r[0], 'refused');
      expect(int.parse(r[1]), lessThan(800));
      expect(r[3], 'false');
    });
  });
}
