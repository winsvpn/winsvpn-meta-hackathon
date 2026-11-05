import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_status_surface.dart';
import 'package:wins_vpn/winn_status_surface_widget.dart';

// TWO HALVES, on the pattern test/winn_session_descriptor_test.dart
// established: a BEHAVIOURAL half over the pure library and the widget, plus a
// SOURCE-GUARD half over lib/main.dart, because the state this surface reads
// lives in private members of a State class and Dart privacy is per-library.
//
// The ruling discipline is stated in the library's own comment and enforced
// here in both directions: every branch that could go green by being deleted
// is asserted on the ABSENCE side too. "No probe" is never carrying, "one
// sample" is never flowing, a wrapped counter is never flowing, a zero delta
// is idle (carrying but silent -- the exact fact the user needs).
void main() {
  DateTime t0() => DateTime.fromMillisecondsSinceEpoch(1700000000000);

  group('winnGateState', () {
    test('no session and no probe is disconnected', () {
      expect(
        winnGateState(
          snapshot: null,
          connected: false,
          connectInFlight: false,
          probeAvailable: false,
        ),
        WinnGateState.disconnected,
      );
    });

    test('a connect in flight with no probe is connecting, not carrying', () {
      expect(
        winnGateState(
          snapshot: null,
          connected: false,
          connectInFlight: true,
          probeAvailable: false,
        ),
        WinnGateState.connecting,
      );
    });

    test('connected but no probe is unprobed, NEVER carrying', () {
      expect(
        winnGateState(
          snapshot: null,
          connected: true,
          connectInFlight: false,
          probeAvailable: false,
        ),
        WinnGateState.unprobed,
        reason: 'a platform with no readiness read cannot assert carrying',
      );
      expect(
        winnGateState(
          snapshot: null,
          connected: true,
          connectInFlight: false,
          probeAvailable: false,
        ),
        isNot(WinnGateState.carrying),
      );
    });

    test('a missing snapshot is no probe even when the channel exists', () {
      expect(
        winnGateState(
          snapshot: null,
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
        ),
        WinnGateState.unprobed,
        reason: 'a readiness read that failed must not become carrying',
      );
    });

    test('service inactive is disconnected even if engine/interface claim true',
        () {
      // The negative half of the carrying ladder.
      expect(
        winnGateState(
          snapshot: WinnReadinessSnapshot(
            serviceActive: false,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: 0,
            txBytes: 0,
            sampledAt: t0(),
          ),
          connected: false,
          connectInFlight: false,
          probeAvailable: true,
        ),
        WinnGateState.disconnected,
      );
    });

    test('engine not ready is establishing, never carrying', () {
      expect(
        winnGateState(
          snapshot: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: false,
            interfaceOpen: true,
            rxBytes: 0,
            txBytes: 0,
            sampledAt: t0(),
          ),
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
        ),
        WinnGateState.establishing,
      );
      expect(
        winnGateState(
          snapshot: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: false,
            rxBytes: 0,
            txBytes: 0,
            sampledAt: t0(),
          ),
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
        ),
        WinnGateState.establishing,
      );
    });

    test('carrying requires the full composite', () {
      expect(
        winnGateState(
          snapshot: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: 0,
            txBytes: 0,
            sampledAt: t0(),
          ),
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
        ),
        WinnGateState.carrying,
      );
    });

    test('a full composite is vetoed by transport_observed_both_ways=false',
        () {
      // The transfer-proven veto: every readiness bit true but the engine
      // explicitly reports transport NOT observed both ways. This is the false
      // "Connected" shape -- the gate must NOT say carrying.
      expect(
        winnGateState(
          snapshot: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: 0,
            txBytes: 0,
            sampledAt: t0(),
            transportProvenBothWays: false,
          ),
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
        ),
        WinnGateState.establishing,
      );
      expect(
        winnGateState(
          snapshot: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: 0,
            txBytes: 0,
            sampledAt: t0(),
            transportProvenBothWays: false,
          ),
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
        ),
        isNot(WinnGateState.carrying),
      );
    });

    test('absent transport_observed_both_ways does not fail closed', () {
      // A platform that does not expose the field must keep the old composite
      // behaviour -- vetoing every session because the field is missing would
      // be "never works", not "fails closed" (see the Android convergence
      // note). Absence is not a veto.
      expect(
        winnGateState(
          snapshot: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: 0,
            txBytes: 0,
            sampledAt: t0(),
          ),
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
        ),
        WinnGateState.carrying,
      );
    });

    test('transport_observed_both_ways=true with full composite is carrying',
        () {
      expect(
        winnGateState(
          snapshot: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: 0,
            txBytes: 0,
            sampledAt: t0(),
            transportProvenBothWays: true,
          ),
          connected: true,
          connectInFlight: false,
          probeAvailable: true,
        ),
        WinnGateState.carrying,
      );
    });
  });

  group('winnTrafficFlow', () {
    WinnReadinessSnapshot sample(int rx, int tx, DateTime at) =>
        WinnReadinessSnapshot(
          serviceActive: true,
          engineReady: true,
          interfaceOpen: true,
          rxBytes: rx,
          txBytes: tx,
          sampledAt: at,
        );

    test('one sample is never enough to prove flow', () {
      expect(
        winnTrafficFlow(
          prior: null,
          current: sample(100, 100, t0()),
          now: t0(),
          maxSampleAge: const Duration(seconds: 10),
          minimumAdvanceBytes: 1,
        ),
        WinnTrafficFlow.unknown,
        reason: 'a single sample is a moment, not a flow',
      );
    });

    test('a stale latest sample is unknown, never flowing', () {
      final now = t0();
      final stale = now.subtract(const Duration(seconds: 30));
      expect(
        winnTrafficFlow(
          prior: sample(100, 100, stale.subtract(const Duration(seconds: 3))),
          current: sample(200, 200, stale),
          now: now,
          maxSampleAge: const Duration(seconds: 10),
          minimumAdvanceBytes: 1,
        ),
        WinnTrafficFlow.unknown,
        reason: 'a counter not being read is not evidence of anything',
      );
    });

    test('a wrapped or reset counter is unknown, never flowing', () {
      final current = t0();
      final prior = current.subtract(const Duration(seconds: 3));
      expect(
        winnTrafficFlow(
          prior: sample(1000, 1000, prior),
          current: sample(10, 10, current),
          now: current,
          maxSampleAge: const Duration(seconds: 10),
          minimumAdvanceBytes: 1,
        ),
        WinnTrafficFlow.unknown,
        reason: 'a negative delta is a reset, not a measurement',
      );
    });

    test('platforms with no byte counters can never be flowing', () {
      final current = t0();
      final prior = current.subtract(const Duration(seconds: 3));
      expect(
        winnTrafficFlow(
          prior: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: null,
            txBytes: null,
            sampledAt: prior,
          ),
          current: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: null,
            txBytes: null,
            sampledAt: current,
          ),
          now: current,
          maxSampleAge: const Duration(seconds: 10),
          minimumAdvanceBytes: 1,
        ),
        WinnTrafficFlow.unknown,
      );
    });

    test('a zero delta is idle -- carrying but silent', () {
      final current = t0();
      final prior = current.subtract(const Duration(seconds: 3));
      expect(
        winnTrafficFlow(
          prior: sample(500, 500, prior),
          current: sample(500, 500, current),
          now: current,
          maxSampleAge: const Duration(seconds: 10),
          minimumAdvanceBytes: 1,
        ),
        WinnTrafficFlow.idle,
      );
    });

    test('a delta below the minimum is idle, not flowing', () {
      final current = t0();
      final prior = current.subtract(const Duration(seconds: 3));
      expect(
        winnTrafficFlow(
          prior: sample(500, 500, prior),
          current: sample(501, 500, current),
          now: current,
          maxSampleAge: const Duration(seconds: 10),
          minimumAdvanceBytes: 10,
        ),
        WinnTrafficFlow.idle,
      );
    });

    test('a real positive delta is flowing', () {
      final current = t0();
      final prior = current.subtract(const Duration(seconds: 3));
      expect(
        winnTrafficFlow(
          prior: sample(500, 500, prior),
          current: sample(5000, 2000, current),
          now: current,
          maxSampleAge: const Duration(seconds: 10),
          minimumAdvanceBytes: 1,
        ),
        WinnTrafficFlow.flowing,
      );
    });
  });

  group('winnTrafficRateBytesPerSecond', () {
    test('computes the rate across the two samples', () {
      final current = t0();
      final prior = current.subtract(const Duration(seconds: 2));
      final rate = winnTrafficRateBytesPerSecond(
        prior: WinnReadinessSnapshot(
          serviceActive: true,
          engineReady: true,
          interfaceOpen: true,
          rxBytes: 0,
          txBytes: 0,
          sampledAt: prior,
        ),
        current: WinnReadinessSnapshot(
          serviceActive: true,
          engineReady: true,
          interfaceOpen: true,
          rxBytes: 2000,
          txBytes: 2000,
          sampledAt: current,
        ),
      );
      expect(rate, 2000.0);
    });

    test('returns 0 for a wrapped counter', () {
      final current = t0();
      final prior = current.subtract(const Duration(seconds: 2));
      expect(
        winnTrafficRateBytesPerSecond(
          prior: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: 9000,
            txBytes: 0,
            sampledAt: prior,
          ),
          current: WinnReadinessSnapshot(
            serviceActive: true,
            engineReady: true,
            interfaceOpen: true,
            rxBytes: 100,
            txBytes: 0,
            sampledAt: current,
          ),
        ),
        0.0,
      );
    });
  });

  group('byte formatting', () {
    test('winnBytesHuman switches units at the right thresholds', () {
      expect(winnBytesHuman(0), '0 B');
      expect(winnBytesHuman(1023), '1023 B');
      expect(winnBytesHuman(1024), '1 KB');
      expect(winnBytesHuman(1536), '1.5 KB');
      expect(winnBytesHuman(5 * 1024 * 1024), '5 MB');
      expect(winnBytesHuman(2 * 1024 * 1024 * 1024), '2 GB');
    });

    test('winnRateHuman renders Mbps rates', () {
      expect(winnRateHuman(0), '0 Mbps');
      expect(winnRateHuman(512), '< 0.01 Mbps');
      expect(winnRateHuman(1250), '0.01 Mbps');
      expect(winnRateHuman(125000), '1 Mbps');
      expect(winnRateHuman(187500), '1.5 Mbps');
      expect(winnRateHuman(2.5 * 1000 * 1000 / 8), '2.5 Mbps');
      expect(winnRateHuman(725 * 1000 * 1000 / 8), '725 Mbps');
    });
  });

  group('winnReadinessSnapshot parses only real values', () {
    test('bool fields read true only from exactly true', () {
      final snap = winnReadinessSnapshot(
        sampledAt: t0(),
        serviceActive: true,
        engineReady: 'true',
        interfaceOpen: 1,
        rxBytes: 1000,
        txBytes: 2000,
      );
      expect(snap.serviceActive, isTrue);
      expect(snap.engineReady, isFalse,
          reason: 'a non-bool must not be coerced to true');
      expect(snap.interfaceOpen, isFalse);
      expect(snap.rxBytes, 1000);
      expect(snap.txBytes, 2000);
    });

    test('non-numeric counters are absent, so flow is unknown', () {
      final snap = winnReadinessSnapshot(
        sampledAt: t0(),
        serviceActive: true,
        engineReady: true,
        interfaceOpen: true,
        rxBytes: 'nonsense',
        txBytes: null,
      );
      expect(snap.counterPresent, isFalse);
    });

    test('transport_observed_both_ways is read as true/false/absent', () {
      expect(
        winnReadinessSnapshot(sampledAt: t0(), transportProvenBothWays: true)
            .transportProvenBothWays,
        isTrue,
      );
      expect(
        winnReadinessSnapshot(sampledAt: t0(), transportProvenBothWays: false)
            .transportProvenBothWays,
        isFalse,
      );
      expect(
        winnReadinessSnapshot(sampledAt: t0(), transportProvenBothWays: 'true')
            .transportProvenBothWays,
        isNull,
        reason: 'a string must not be coerced into a transfer verdict',
      );
      expect(
        winnReadinessSnapshot(sampledAt: t0()).transportProvenBothWays,
        isNull,
        reason: 'an absent key is not a veto on carrying',
      );
    });

    test('falls back to awg peer counters when tun counters are 0 or null', () {
      final snapNullTun = winnReadinessSnapshot(
        sampledAt: t0(),
        serviceActive: true,
        engineReady: true,
        interfaceOpen: true,
        rxBytes: null,
        txBytes: null,
        awgRxBytes: 15400,
        awgTxBytes: 8200,
      );
      expect(snapNullTun.rxBytes, 15400);
      expect(snapNullTun.txBytes, 8200);

      final snapZeroTun = winnReadinessSnapshot(
        sampledAt: t0(),
        serviceActive: true,
        engineReady: true,
        interfaceOpen: true,
        rxBytes: 0,
        txBytes: 0,
        awgRxBytes: 250000,
        awgTxBytes: 120000,
      );
      expect(snapZeroTun.rxBytes, 250000);
      expect(snapZeroTun.txBytes, 120000);

      final snapExplicitTraffic = winnReadinessSnapshot(
        sampledAt: t0(),
        serviceActive: true,
        engineReady: true,
        interfaceOpen: true,
        trafficRxBytes: 99999,
        trafficTxBytes: 88888,
        rxBytes: null,
        txBytes: null,
        awgRxBytes: 100,
        awgTxBytes: 100,
      );
      expect(snapExplicitTraffic.rxBytes, 99999);
      expect(snapExplicitTraffic.txBytes, 88888);
    });
  });

  group('WinnStatusSurface widget', () {
    testWidgets('shows gate and traffic for a carrying, flowing tunnel',
        (tester) async {
      var reads = 0;
      final surface = WinnStatusSurface(
        connected: true,
        connectInFlight: false,
        probeAvailable: true,
        readinessReader: () async {
          reads++;
          return <Object?, Object?>{
            'service_active': true,
            'engine_ready': true,
            'interface_open': true,
            'tun_rx_bytes': 500 + reads * 100,
            'tun_tx_bytes': 300 + reads * 100,
          };
        },
        translate: (value) => value,
      );
      await tester.pumpWidget(MaterialApp(home: Scaffold(body: surface)));
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 1));
      // First poll arrived: gate carrying, traffic still unknown (one sample).
      expect(find.textContaining('Carrying traffic'), findsOneWidget);
      // Second sample: counters advanced, so flow is proved.
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 1));
      expect(reads, greaterThanOrEqualTo(2));
      expect(find.textContaining('Flowing'), findsOneWidget);
    });

    testWidgets('a tunnel with no byte movement is idle, not flowing',
        (tester) async {
      final surface = WinnStatusSurface(
        connected: true,
        connectInFlight: false,
        probeAvailable: true,
        readinessReader: () async => <Object?, Object?>{
          'service_active': true,
          'engine_ready': true,
          'interface_open': true,
          'tun_rx_bytes': 50000,
          'tun_tx_bytes': 40000,
        },
        translate: (value) => value,
      );
      await tester.pumpWidget(MaterialApp(home: Scaffold(body: surface)));
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 1));
      expect(find.textContaining('Idle'), findsOneWidget);
      expect(find.textContaining('Flowing'), findsNothing);
    });

    testWidgets('no readiness channel renders unprobed, never carrying',
        (tester) async {
      final surface = WinnStatusSurface(
        connected: true,
        connectInFlight: false,
        probeAvailable: false,
        readinessReader: null,
        translate: (value) => value,
      );
      await tester.pumpWidget(MaterialApp(home: Scaffold(body: surface)));
      await tester.pump(const Duration(seconds: 1));
      expect(find.textContaining('no live probe'), findsOneWidget);
      expect(find.textContaining('Carrying traffic'), findsNothing);
    });

    testWidgets('a failing readiness read degrades to unknown, not flowing',
        (tester) async {
      final surface = WinnStatusSurface(
        connected: true,
        connectInFlight: false,
        probeAvailable: true,
        readinessReader: () async => throw Exception('native read failed'),
        translate: (value) => value,
      );
      await tester.pumpWidget(MaterialApp(home: Scaffold(body: surface)));
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 1));
      expect(find.textContaining('Flowing'), findsNothing);
    });

    testWidgets('disconnected shows Not connected, not Carrying',
        (tester) async {
      final surface = WinnStatusSurface(
        connected: false,
        connectInFlight: false,
        probeAvailable: true,
        readinessReader: () async => <Object?, Object?>{
          'service_active': false,
          'engine_ready': false,
          'interface_open': false,
          'tun_rx_bytes': 0,
          'tun_tx_bytes': 0,
        },
        translate: (value) => value,
      );
      await tester.pumpWidget(MaterialApp(home: Scaffold(body: surface)));
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 1));
      expect(find.textContaining('Not connected'), findsOneWidget);
      expect(find.textContaining('Carrying traffic'), findsNothing);
    });

    testWidgets(
        'transport_observed_both_ways=false is shown not up, never carrying',
        (tester) async {
      // The false-"Connected" shape in full: every readiness bit true and the
      // counters advancing, but the engine explicitly reports transport NOT
      // observed both ways. The gate row must refuse "Carrying traffic" and
      // report the secure route as still establishing instead.
      var reads = 0;
      final surface = WinnStatusSurface(
        connected: true,
        connectInFlight: false,
        probeAvailable: true,
        readinessReader: () async {
          reads++;
          return <Object?, Object?>{
            'service_active': true,
            'engine_ready': true,
            'interface_open': true,
            'transport_observed_both_ways': false,
            'tun_rx_bytes': 500 + reads * 100,
            'tun_tx_bytes': 300 + reads * 100,
          };
        },
        translate: (value) => value,
      );
      await tester.pumpWidget(MaterialApp(home: Scaffold(body: surface)));
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 1));
      await tester.pump(const Duration(seconds: 3));
      await tester.pump(const Duration(seconds: 1));
      expect(find.textContaining('Establishing secure route...'),
          findsOneWidget);
      expect(find.textContaining('Carrying traffic'), findsNothing,
          reason: 'a transfer-unproven engine must never report as connected');
    });
  });

  // -------------------------------------------------------------------------
  // Source-guard half: lib/main.dart.
  // -------------------------------------------------------------------------
  group('lib/main.dart', () {
    late String source;

    setUpAll(() {
      source = File('lib/main.dart').readAsStringSync();
    });

    test('imports and instantiates the honest status surface', () {
      expect(
        source.contains("import 'winn_status_surface_widget.dart';"),
        isTrue,
        reason: 'the dashboard must mount WinnStatusSurface',
      );
      expect(source.contains('WinnStatusSurface('), isTrue,
          reason: 'the widget must actually be placed in the app');
      expect(
        source.contains('connected: _isConnected'),
        isTrue,
        reason: 'the surface must be fed the app\u2019s true connected state',
      );
    });

    test('the surface is fed a native readiness reader, not a constant', () {
      final mount = _slice(
        source,
        start: 'WinnStatusSurface(',
        end: ');',
      );
      expect(mount, isNotEmpty, reason: 'the widget mount is gone');
      expect(mount.contains('readinessReader:'), isTrue,
          reason: 'the widget must poll a native readiness source');
      expect(mount.contains('probeAvailable:'), isTrue,
          reason: 'the widget must know whether a probe exists at all');
      // The widget must never be handed a fabricated gate/traffic verdict.
      for (final hardcoded in <String>[
        "gateState: WinnGateState.carrying",
        "flow: WinnTrafficFlow.flowing",
        "'Carrying traffic'",
        "'Flowing'",
      ]) {
        expect(mount.contains(hardcoded), isFalse,
            reason: 'the surface may not hardcode a status claim: '
                '$hardcoded');
      }
    });

    test('every status-surface phrase is translated in my and de', () {
      final my = _slice(source, start: "      'my': {", end: "\n      },");
      final de = _slice(source, start: "      'de': {", end: "\n      },");
      expect(my, isNotEmpty, reason: 'the my block is gone; test is blind');
      expect(de, isNotEmpty, reason: 'the de block is gone; test is blind');
      for (final phrase in kWinnStatusSurfacePhrases) {
        expect(my.contains("'$phrase':"), isTrue,
            reason: 'Burmese translation missing for status phrase "$phrase"');
        expect(de.contains("'$phrase':"), isTrue,
            reason: 'German translation missing for status phrase "$phrase"');
      }
    });
  });
}

/// The text between the first [start] and the next [end] after it, or `''`.
String _slice(String source, {required String start, required String end}) {
  final from = source.indexOf(start);
  if (from < 0) return '';
  final to = source.indexOf(end, from + start.length);
  if (to < 0) return '';
  return source.substring(from, to + end.length);
}