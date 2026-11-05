import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/direct_udp_transport_memory.dart';

void main() {
  final base = DateTime.utc(2026, 8, 6, 12);

  group('network scope derivation', () {
    test('is order independent and hides the underlying addresses', () {
      final a =
          directUdpNetworkScope(<String>['wlan0/192.168.1', 'rmnet0/10.4.5']);
      final b =
          directUdpNetworkScope(<String>['rmnet0/10.4.5', 'wlan0/192.168.1']);
      expect(a, b);
      expect(a, isNot(contains('192.168')));
      expect(a, isNot(contains('10.4')));
      expect(a.length, 16);
    });

    test('different networks land in different scopes', () {
      expect(
        directUdpNetworkScope(<String>['wlan0/192.168.1']),
        isNot(directUdpNetworkScope(<String>['wlan0/192.168.8'])),
      );
    });

    test('an unfingerprintable network gets the shared unknown scope', () {
      expect(directUdpNetworkScope(<String>[]), kDirectUdpUnknownScope);
      expect(
          directUdpNetworkScope(<String>['', '   ']), kDirectUdpUnknownScope);
    });
  });

  group('per-network demotion', () {
    test('a single failure does not cost the fast path', () {
      final memory = DirectUdpTransportMemory.empty
          .recordDirectUdpUnreachable(scope: 'net-a', now: base);
      expect(
        memory.shouldDemoteDirectUdp(scope: 'net-a', now: base),
        isFalse,
        reason: 'one transient failure must not flip the order',
      );
    });

    test('two consecutive failures on one network flip the order', () {
      final memory = DirectUdpTransportMemory.empty
          .recordDirectUdpUnreachable(scope: 'net-a', now: base)
          .recordDirectUdpUnreachable(
              scope: 'net-a', now: base.add(const Duration(minutes: 1)));
      expect(
        memory.shouldDemoteDirectUdp(
            scope: 'net-a', now: base.add(const Duration(minutes: 2))),
        isTrue,
      );
    });

    test('a demotion does not follow the user to a different network', () {
      final memory = DirectUdpTransportMemory.empty
          .recordDirectUdpUnreachable(scope: 'net-a', now: base)
          .recordDirectUdpUnreachable(
              scope: 'net-a', now: base.add(const Duration(minutes: 1)));
      expect(
        memory.shouldDemoteDirectUdp(scope: 'net-b', now: base),
        isFalse,
      );
    });

    test('a working direct tunnel clears that network outright', () {
      final memory = DirectUdpTransportMemory.empty
          .recordDirectUdpUnreachable(scope: 'net-a', now: base)
          .recordDirectUdpUnreachable(
              scope: 'net-a', now: base.add(const Duration(minutes: 1)))
          .recordDirectUdpReachable(
              scope: 'net-a', now: base.add(const Duration(minutes: 2)));
      expect(memory.shouldDemoteDirectUdp(scope: 'net-a', now: base), isFalse);
      expect(memory.isEmpty, isTrue);
    });
  });

  group('global demotion tier', () {
    // Mobile data hands out a fresh carrier-NAT address per session, so the
    // per-network scope can rotate and never accumulate its own strikes. This
    // tier is what covers that user.
    DirectUdpTransportMemory failAcrossRotatingScopes(int count) {
      var memory = DirectUdpTransportMemory.empty;
      for (var i = 0; i < count; i++) {
        memory = memory.recordDirectUdpUnreachable(
          scope: 'rotating-$i',
          now: base.add(Duration(minutes: i)),
        );
      }
      return memory;
    }

    test('a run of failures across rotating scopes eventually demotes', () {
      final short =
          failAcrossRotatingScopes(kDirectUdpGlobalStrikeThreshold - 1);
      expect(
        short.shouldDemoteDirectUdp(scope: 'rotating-new', now: base),
        isFalse,
      );

      final long = failAcrossRotatingScopes(kDirectUdpGlobalStrikeThreshold);
      expect(
        long.shouldDemoteDirectUdp(
          scope: 'rotating-new',
          now: base.add(const Duration(minutes: 30)),
        ),
        isTrue,
      );
    });

    test('any working direct tunnel resets the global run', () {
      final memory = failAcrossRotatingScopes(kDirectUdpGlobalStrikeThreshold)
          .recordDirectUdpReachable(
              scope: 'rotating-new', now: base.add(const Duration(hours: 1)));
      expect(
        memory.shouldDemoteDirectUdp(
            scope: 'rotating-new', now: base.add(const Duration(hours: 1))),
        isFalse,
      );
      expect(memory.global, isNull);
    });
  });

  group('recovery and clock behaviour', () {
    DirectUdpTransportMemory demoted() => DirectUdpTransportMemory.empty
        .recordDirectUdpUnreachable(scope: 'net-a', now: base)
        .recordDirectUdpUnreachable(
            scope: 'net-a', now: base.add(const Duration(minutes: 1)));

    test('the direct leg is allowed to lead again once the demotion is stale',
        () {
      final memory = demoted();
      expect(
        memory.shouldDemoteDirectUdp(
            scope: 'net-a',
            now:
                base.add(kDirectUdpReprobeInterval - const Duration(hours: 1))),
        isTrue,
      );
      expect(
        memory.shouldDemoteDirectUdp(
            scope: 'net-a',
            now:
                base.add(kDirectUdpReprobeInterval + const Duration(hours: 1))),
        isFalse,
        reason: 'a lifted block must recover the fast path without a reinstall',
      );
    });

    test('a re-probe that fails again refreshes the demotion', () {
      final reprobeAt = base.add(kDirectUdpReprobeInterval * 2);
      final memory =
          demoted().recordDirectUdpUnreachable(scope: 'net-a', now: reprobeAt);
      expect(
        memory.shouldDemoteDirectUdp(
            scope: 'net-a', now: reprobeAt.add(const Duration(hours: 1))),
        isTrue,
      );
    });

    test('a clock jumped far forward degrades to shipping order, not silence',
        () {
      expect(
        demoted().shouldDemoteDirectUdp(
            scope: 'net-a', now: base.add(const Duration(days: 4000))),
        isFalse,
        reason: 'the worst a fast clock can do is lead with the direct leg, '
            'which is exactly what ships today',
      );
    });

    test('a clock jumped far backward holds the demotion rather than crashing',
        () {
      expect(
        demoted().shouldDemoteDirectUdp(
            scope: 'net-a', now: base.subtract(const Duration(days: 4000))),
        isTrue,
        reason: 'a slow clock leaves the user on the CDN-fronted transports, '
            'which still connect',
      );
    });
  });

  group('persistence', () {
    test('a round trip preserves the decision', () {
      final memory = DirectUdpTransportMemory.empty
          .recordDirectUdpUnreachable(scope: 'net-a', now: base)
          .recordDirectUdpUnreachable(
              scope: 'net-a', now: base.add(const Duration(minutes: 1)));
      final restored = DirectUdpTransportMemory.fromJson(
        jsonDecode(jsonEncode(memory.toJson())),
        now: base.add(const Duration(minutes: 2)),
      );
      expect(
        restored.shouldDemoteDirectUdp(
            scope: 'net-a', now: base.add(const Duration(minutes: 2))),
        isTrue,
      );
    });

    test('the persisted document carries no address material', () {
      final memory = DirectUdpTransportMemory.empty.recordDirectUdpUnreachable(
        scope: directUdpNetworkScope(<String>['wlan0/192.168.1']),
        now: base,
      );
      final encoded = jsonEncode(memory.toJson());
      expect(encoded, isNot(contains('192.168')));
      expect(encoded, isNot(contains('wlan0')));
    });

    test('corrupt, foreign or future documents degrade to shipping order', () {
      for (final raw in <Object?>[
        null,
        'not-a-map',
        <String, dynamic>{},
        <String, dynamic>{
          'schema_version': 999,
          'networks': <String, dynamic>{}
        },
        <String, dynamic>{
          'schema_version': kDirectUdpMemorySchemaVersion,
          'networks': <String, dynamic>{
            'net-a': <String, dynamic>{
              'strikes': 'lots',
              'updated_at_utc': 'x'
            },
          },
        },
      ]) {
        final memory = DirectUdpTransportMemory.fromJson(raw, now: base);
        expect(
            memory.shouldDemoteDirectUdp(scope: 'net-a', now: base), isFalse);
      }
    });

    test('stale entries are pruned so the document stays bounded', () {
      final memory = DirectUdpTransportMemory.empty
          .recordDirectUdpUnreachable(scope: 'net-a', now: base)
          .recordDirectUdpUnreachable(
              scope: 'net-a', now: base.add(const Duration(minutes: 1)));
      final restored = DirectUdpTransportMemory.fromJson(
        jsonDecode(jsonEncode(memory.toJson())),
        now: base.add(kDirectUdpMemoryTtl + const Duration(days: 1)),
      );
      expect(restored.isEmpty, isTrue);
    });

    test('the tracked-network count is capped', () {
      var memory = DirectUdpTransportMemory.empty;
      for (var i = 0; i < kDirectUdpMaxTrackedNetworks * 3; i++) {
        memory = memory.recordDirectUdpUnreachable(
          scope: 'net-$i',
          now: base.add(Duration(minutes: i)),
        );
      }
      expect(
        memory.networks.length,
        lessThanOrEqualTo(kDirectUdpMaxTrackedNetworks),
      );
    });
  });

  group('the connect path honours the never-remove-a-transport contract', () {
    late String connect;

    setUpAll(() {
      final source = File('lib/main.dart').readAsStringSync();
      final start =
          source.indexOf('Future<void> _connectWithSmartProtocol(');
      final end =
          source.indexOf('Future<void> _toggleVpnConnection() async', start);
      expect(start, greaterThanOrEqualTo(0));
      expect(end, greaterThan(start));
      connect = source.substring(start, end);
    });

    test('network memory cannot reorder the v1 AWG then Xray pair', () {
      final boundedCandidates = connect
          .indexOf('final boundedCandidates = boundedXrayTransportOptions(');
      final directAttempt = connect.indexOf(
        'final directStarted = await attemptDirectAwgCandidate();',
      );
      expect(boundedCandidates, greaterThanOrEqualTo(0));
      expect(directAttempt, greaterThanOrEqualTo(0));
      expect(directAttempt, lessThan(boundedCandidates));
      expect(connect, isNot(contains('directUdpDemotedThisConnect')));
    });

    test('the AWG lead remains gated on the control-plane disable', () {
      expect(
        connect,
        contains('shouldAttemptServedLeadCandidate('),
      );
      expect(connect, contains('directAwgEnabled: directAwgEnabled'));
    });

    test('a platform VPN permission refusal is not a network failure', () {
      final record = connect.indexOf('await _recordDirectUdpOutcome(');
      expect(record, greaterThanOrEqualTo(0));
      final gateStart = connect.lastIndexOf('if (', record);
      expect(gateStart, greaterThanOrEqualTo(0));
      final gate = connect.substring(gateStart, record);
      expect(gate, contains('!_androidNeedsVpnPermission'));
      expect(gate, contains('!_lastTunnelCandidateWasSecurityRefusal'));
      expect(
        gate,
        contains('!_lastAppleTunnelNeedsPermissionApproval'),
      );
    });
  });

  test('the node latency probe never TCP-probes the direct UDP endpoint', () {
    // A per-node AmneziaWG listen port removes the fleet-wide `udp dport 9110`
    // that one national rule can block. Nothing on the client may key off the
    // literal 9110 to decide what a port IS, or that change quietly turns the
    // node picker into a TCP scanner aimed at the gateway's real address.
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<int?> _probeNodeLatencyMs(');
    expect(start, greaterThanOrEqualTo(0));
    final probe = source.substring(start, source.indexOf('\n  }', start));
    expect(
      probe,
      isNot(contains('direct.port != 9110')),
      reason: 'the direct endpoint is UDP whatever its port number is',
    );
    expect(
      probe,
      isNot(contains('_probeTcpLatencyMs(direct.host')),
      reason: 'a TCP connect to the AmneziaWG port can only time out',
    );
    expect(probe, contains('_probePingLatencyMs(direct.host)'));
  });
}
