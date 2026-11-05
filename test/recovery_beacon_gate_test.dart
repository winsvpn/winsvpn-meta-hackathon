import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/bootstrap_resilience.dart';
import 'package:wins_vpn/recovery_beacon_gate.dart';

/// The gate that decides whether the GitHub gateway-recovery beacon may fire.
///
/// The property under test throughout is asymmetric on purpose: a false
/// negative costs a censored user one connect timeout per API call, while a
/// false positive re-creates the recurring `raw.githubusercontent.com` ->
/// gateway -> ICMP-burst signature on every launch of every healthy client.
/// So the tests that matter most are the ones asserting the gate stays SHUT.
void main() {
  final t0 = DateTime.utc(2026, 8, 6, 12);
  const gateways = <String>[
    'https://sync.example.org',
    'https://sync.example.com',
    'https://hub.example.org',
  ];

  RecoveryBeaconGate gate() => RecoveryBeaconGate(compiledGateways: gateways);

  group('the happy path never beacons', () {
    test('a fresh gate makes no fetch', () {
      expect(gate().shouldFetchRecoveryRecord(t0), isFalse);
    });

    test('a cold start with no observations at all makes no fetch', () {
      // The regression this guards: the old code fetched unconditionally on
      // every launch. A cold start has no failure history and the record can
      // only re-order gateways the client is about to try anyway, so silence
      // is correct rather than merely cheap.
      final g = gate();
      for (var i = 0; i < 50; i++) {
        expect(
          g.shouldFetchRecoveryRecord(t0.add(Duration(minutes: i * 7))),
          isFalse,
        );
      }
    });

    test('repeated successes never open the gate', () {
      final g = gate();
      for (var i = 0; i < 20; i++) {
        g.recordGatewaySuccess(
          gateway: 'https://sync.example.org/nodes',
          now: t0.add(Duration(seconds: i * 5)),
        );
        expect(
          g.shouldFetchRecoveryRecord(t0.add(Duration(seconds: i * 5))),
          isFalse,
        );
      }
    });

    test('a success after a failure closes the gate again', () {
      final g = gate();
      g.recordGatewaySweepFailure(now: t0);
      expect(g.shouldFetchRecoveryRecord(t0), isTrue);
      g.recordGatewaySuccess(gateway: 'https://sync.example.org', now: t0);
      expect(g.shouldFetchRecoveryRecord(t0), isFalse);
    });
  });

  group('a failed sweep opens the gate', () {
    test('one exhausted sweep is enough', () {
      // Looser than bootstrap_resilience's 3-strike block threshold, and
      // deliberately so: that threshold protects scarce fallback DOMAINS from
      // being burned. This record is a static file on a high-collateral host
      // that can only re-order hosts already in the binary, so the expensive
      // error here is the false negative.
      final g = gate();
      g.recordGatewaySweepFailure(now: t0);
      expect(g.shouldFetchRecoveryRecord(t0), isTrue);
    });

    test('a success observation passed to the failure recorder is ignored', () {
      final g = gate();
      g.recordGatewaySweepFailure(
        now: t0,
        observation: BootstrapObservation.succeeded,
      );
      expect(g.shouldFetchRecoveryRecord(t0), isFalse);
    });
  });

  group('the throttle bounds the beacon under a sustained block', () {
    test('a second fetch inside the interval is refused', () {
      final g = gate();
      g.recordGatewaySweepFailure(now: t0);
      expect(g.shouldFetchRecoveryRecord(t0), isTrue);
      g.recordRecoveryRecordFetched(t0);
      expect(g.shouldFetchRecoveryRecord(t0), isFalse);
      expect(
        g.shouldFetchRecoveryRecord(
          t0.add(kRecoveryBeaconMinimumInterval - const Duration(seconds: 1)),
        ),
        isFalse,
      );
    });

    test('the heartbeat cannot outrun the throttle', () {
      // /nodes and /account/status ride a 3-5s heartbeat. Without the throttle
      // a blocked client would re-fetch the record on every beat and rebuild
      // exactly the periodic signature this gate exists to remove.
      final g = gate();
      var fetches = 0;
      for (var beat = 0; beat < 240; beat++) {
        final now = t0.add(Duration(seconds: beat * 5));
        g.recordGatewaySweepFailure(now: now);
        if (g.shouldFetchRecoveryRecord(now)) {
          g.recordRecoveryRecordFetched(now);
          fetches++;
        }
      }
      // 20 minutes of continuous failure at 5s intervals.
      expect(fetches, lessThanOrEqualTo(5));
    });

    test('a fetch is allowed again once the interval elapses', () {
      final g = gate();
      g.recordGatewaySweepFailure(now: t0);
      g.recordRecoveryRecordFetched(t0);
      final later = t0.add(kRecoveryBeaconMinimumInterval);
      g.recordGatewaySweepFailure(now: later);
      expect(g.shouldFetchRecoveryRecord(later), isTrue);
    });

    test('the throttle starts on attempt, not on success', () {
      // A fetch that fails still emitted the DNS query and the handshake, which
      // is the observable cost being bounded.
      final g = gate();
      g.recordGatewaySweepFailure(now: t0);
      g.recordRecoveryRecordFetched(t0);
      expect(g.shouldFetchRecoveryRecord(t0), isFalse);
    });
  });

  group('stale evidence stops beaconing', () {
    test('the gate closes once the failure window elapses', () {
      final g = gate();
      g.recordGatewaySweepFailure(now: t0);
      expect(
        g.shouldFetchRecoveryRecord(
          t0.add(kRecoveryBeaconFailureWindow - const Duration(minutes: 1)),
        ),
        isTrue,
      );
      expect(
        g.shouldFetchRecoveryRecord(t0.add(kRecoveryBeaconFailureWindow)),
        isFalse,
      );
    });

    test('a clock that jumps backwards does not open the gate', () {
      // Mobile clocks in this user population are unreliable, and a negative
      // interval must not read as "recently failed".
      final g = gate();
      g.recordGatewaySweepFailure(now: t0);
      expect(
        g.shouldFetchRecoveryRecord(t0.subtract(const Duration(hours: 5))),
        isFalse,
      );
    });
  });

  group('network scoping', () {
    test('changing network discards evidence from the old path', () {
      // Blocking is a property of the path. A gateway censored on hotel Wi-Fi
      // says nothing about the same user's mobile data, and carrying the
      // failure over would beacon on a network that never failed.
      final g = gate();
      g.recordGatewaySweepFailure(now: t0, networkScope: 'wifi-a');
      expect(g.shouldFetchRecoveryRecord(t0), isTrue);
      g.recordGatewaySweepFailure(now: t0, networkScope: 'cell-b');
      // The new scope recorded its own failure, so the gate is open on ITS
      // evidence -- but the old scope's health is gone.
      expect(g.compiledGateways, gateways);
      g.recordGatewaySuccess(
        gateway: 'https://sync.example.org',
        now: t0,
        networkScope: 'wifi-a',
      );
      expect(g.shouldFetchRecoveryRecord(t0), isFalse);
    });

    test('an empty scope token is normalised, not treated as a new network',
        () {
      final g = gate();
      g.recordGatewaySweepFailure(now: t0);
      g.recordGatewaySweepFailure(now: t0, networkScope: '   ');
      expect(g.shouldFetchRecoveryRecord(t0), isTrue);
      expect(g.lastKnownGoodGateway, isNull);
    });
  });

  group('endpoint health feeds a real bootstrap plan', () {
    test('the last working gateway is planned first', () {
      final g = gate();
      g.recordGatewaySuccess(
        gateway: 'https://hub.example.org/account/status',
        now: t0,
      );
      expect(g.lastKnownGoodGateway, 'https://hub.example.org');
      expect(g.plannedGatewayOrder(t0).first, 'https://hub.example.org');
    });

    test('route suffixes are stripped before health is keyed', () {
      final g = gate();
      g.recordGatewaySuccess(
        gateway: 'https://sync.example.org/free/status',
        now: t0,
      );
      expect(g.lastKnownGoodGateway, 'https://sync.example.org');
    });

    test('discovery is not required until every gateway is blocked', () {
      final g = gate();
      expect(g.discoveryRequired(t0), isFalse);
      g.recordGatewaySweepFailure(now: t0);
      // One ambiguous timeout with no control probe is transient, not a block:
      // a phone in a lift must not spend anything scarce.
      expect(g.discoveryRequired(t0), isFalse);
    });

    test('a self-evidencing observation blocks every compiled gateway at once',
        () {
      final g = gate();
      g.recordGatewaySweepFailure(
        now: t0,
        observation: BootstrapObservation.tlsResetAfterClientHello,
      );
      expect(g.discoveryRequired(t0), isTrue);
      // And the plan is still non-empty, so hysteresis cannot strand a client
      // whose block was lifted.
      expect(g.plannedGatewayOrder(t0), isNotEmpty);
    });

    test('the plan never strands a client, even fully blocked', () {
      final g = gate();
      for (var i = 0; i < 10; i++) {
        g.recordGatewaySweepFailure(
          now: t0.add(Duration(minutes: i)),
          observation: BootstrapObservation.dnsAnswerUnroutable,
        );
      }
      expect(g.plannedGatewayOrder(t0.add(const Duration(minutes: 10))),
          isNotEmpty);
    });
  });

  test('the default gate reasons about the compiled gateway set', () {
    // No argument means the real compiled set, so a build that re-points
    // WINS_GATEWAY_BASE re-points the gate with it and no second list of
    // hostnames exists to drift.
    expect(RecoveryBeaconGate().compiledGateways, isNotEmpty);
  });
}
