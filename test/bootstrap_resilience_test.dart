import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/bootstrap_resilience.dart';

/// A record body must never yield endpoints. The discovery channel is the one
/// place where a *new* host can enter the client, so this list is the entire
/// security boundary: every one of these has to be rejected.
const Map<String, String> _hostileRecords = <String, String>{
  'scheme smuggled into the host': 'v1|2|4102444800|https://evil.example|c2ln',
  'path smuggled into the host': 'v1|2|4102444800|good.example/evil|c2ln',
  'port smuggled into the host': 'v1|2|4102444800|good.example:8443|c2ln',
  'userinfo in the host': 'v1|2|4102444800|user@evil.example|c2ln',
  'query in the host': 'v1|2|4102444800|good.example?next=evil|c2ln',
  'fragment in the host': 'v1|2|4102444800|good.example#evil|c2ln',
  'uppercase host': 'v1|2|4102444800|Good.Example|c2ln',
  'IPv4 literal': 'v1|2|4102444800|203.0.113.10|c2ln',
  'IPv6 literal': 'v1|2|4102444800|[2001:db8::1]|c2ln',
  'empty host list': 'v1|2|4102444800||c2ln',
  'wrong field count': 'v1|2|4102444800|c2ln',
  'unknown format': 'v9|2|4102444800|good.example|c2ln',
  'zero sequence': 'v1|0|4102444800|good.example|c2ln',
  'negative sequence': 'v1|-1|4102444800|good.example|c2ln',
  'non-numeric sequence': 'v1|abc|4102444800|good.example|c2ln',
  'non-numeric expiry': 'v1|2|soon|good.example|c2ln',
  'no signature separator': 'v1',
  'empty body': '',
  'whitespace only': '   \n  ',
  'html error page': '<!doctype html><html></html>',
};

/// 2030-01-01T00:00:00Z, comfortably inside the lifetime ceiling relative to
/// [_now] below.
const int _validExpiry = 1893456000;
final DateTime _now = DateTime.utc(2029, 12, 25);

String _record({
  int sequence = 2,
  int expiry = _validExpiry,
  String hosts = 'alpha.example,beta.example',
}) =>
    'v1|$sequence|$expiry|$hosts';

Future<bool> _acceptAll(List<int> message, List<int> signature) async => true;
Future<bool> _rejectAll(List<int> message, List<int> signature) async => false;

void main() {

  test('out-of-range discovery expiry is rejected before signature verification', () async {
    var verifications = 0;
    for (final expiry in [-8640000000001, 8640000000001]) {
      final result = await verifyDiscoveryRecord(
        '${_record(expiry: expiry)}|c2lnbmF0dXJl',
        lastAcceptedSequence: 1, now: _now,
        verifier: (_, __) async { verifications++; return true; });
      expect(result.rejection, DiscoveryRejection.malformed);
    }
    expect(verifications, 0);
  });
  group('failure classification', () {
    test('self-evidencing interference is confirmed without a control probe',
        () {
      const selfEvidencing = <BootstrapObservation>[
        BootstrapObservation.dnsNameNotFound,
        BootstrapObservation.dnsAnswerUnroutable,
        BootstrapObservation.tcpConnectResetInjected,
        BootstrapObservation.tlsResetAfterClientHello,
        BootstrapObservation.tlsCertificateRejected,
        BootstrapObservation.httpInterceptionPage,
        BootstrapObservation.httpBlockStatus,
      ];
      for (final observation in selfEvidencing) {
        expect(
          classifyBootstrapAttempt(observation: observation),
          BootstrapSignal.blockConfirmed,
          reason: '$observation',
        );
        expect(requiresControlProbe(observation), isFalse,
            reason: '$observation should not spend a probe');
      }
    });

    test('ambiguous failures need the control probe to mean anything', () {
      const ambiguous = <BootstrapObservation>[
        BootstrapObservation.dnsResolutionFailed,
        BootstrapObservation.tcpConnectTimedOut,
        BootstrapObservation.tlsHandshakeTimedOut,
        BootstrapObservation.requestTimedOut,
      ];
      for (final observation in ambiguous) {
        expect(requiresControlProbe(observation), isTrue,
            reason: '$observation');
        expect(
          classifyBootstrapAttempt(
            observation: observation,
            control: ControlProbeOutcome.reachable,
          ),
          BootstrapSignal.blockSuspected,
          reason: '$observation with working internet',
        );
        // No internet, or no probe run: cannot be attributed to the gateway.
        for (final control in [
          ControlProbeOutcome.unreachable,
          ControlProbeOutcome.notAttempted,
        ]) {
          expect(
            classifyBootstrapAttempt(
              observation: observation,
              control: control,
            ),
            BootstrapSignal.transient,
            reason: '$observation with $control',
          );
        }
      }
    });

    test('our own backend having an outage is never a block', () {
      // The most expensive false positive available: a 5xx behind a valid
      // certificate that gets read as censorship burns every fallback for the
      // whole user base during a routine incident.
      for (final control in ControlProbeOutcome.values) {
        expect(
          classifyBootstrapAttempt(
            observation: BootstrapObservation.httpServerError,
            control: control,
          ),
          BootstrapSignal.transient,
        );
        expect(
          classifyBootstrapAttempt(
            observation: BootstrapObservation.tcpConnectRefused,
            control: control,
          ),
          BootstrapSignal.transient,
        );
      }
    });

    test('the control probe can veto but never promote', () {
      // A reachable control must not turn a benign observation hostile.
      expect(
        classifyBootstrapAttempt(
          observation: BootstrapObservation.succeeded,
          control: ControlProbeOutcome.reachable,
        ),
        BootstrapSignal.none,
      );
      expect(
        classifyBootstrapAttempt(
          observation: BootstrapObservation.httpServerError,
          control: ControlProbeOutcome.reachable,
        ),
        BootstrapSignal.transient,
      );
    });
  });

  group('hysteresis', () {
    const scope = 'net-a';
    const fresh = EndpointHealth(networkScope: scope);

    test('one ambiguous failure does not spend anything', () {
      final after = recordBootstrapAttempt(
        fresh,
        signal: BootstrapSignal.blockSuspected,
        networkScope: scope,
        now: _now,
      );
      expect(after.blocked, isFalse);
      expect(after.strikes, 1);
    });

    test('three corroborating suspicions block; two do not', () {
      var state = fresh;
      for (var i = 0; i < kBlockStrikeThreshold - 1; i++) {
        state = recordBootstrapAttempt(
          state,
          signal: BootstrapSignal.blockSuspected,
          networkScope: scope,
          now: _now,
        );
      }
      expect(state.blocked, isFalse);
      state = recordBootstrapAttempt(
        state,
        signal: BootstrapSignal.blockSuspected,
        networkScope: scope,
        now: _now,
      );
      expect(state.blocked, isTrue);
      expect(state.blockedAt, isNotNull);
    });

    test('one confirmed observation blocks immediately', () {
      final state = recordBootstrapAttempt(
        fresh,
        signal: BootstrapSignal.blockConfirmed,
        networkScope: scope,
        now: _now,
      );
      expect(state.blocked, isTrue);
      expect(state.confirmed, isTrue);
    });

    test('transient failures never accumulate toward a block', () {
      var state = fresh;
      for (var i = 0; i < 20; i++) {
        state = recordBootstrapAttempt(
          state,
          signal: BootstrapSignal.transient,
          networkScope: scope,
          now: _now,
        );
      }
      expect(state.blocked, isFalse);
      expect(state.strikes, 0);
    });

    test('changing network discards evidence about the old path', () {
      // A gateway censored on a hotel Wi-Fi is usually fine on mobile data.
      // Carrying the verdict across would let one hostile network permanently
      // poison the primary gateway everywhere.
      final blocked = recordBootstrapAttempt(
        fresh,
        signal: BootstrapSignal.blockConfirmed,
        networkScope: scope,
        now: _now,
      );
      expect(blocked.blocked, isTrue);

      final elsewhere = recordBootstrapAttempt(
        blocked,
        signal: BootstrapSignal.blockSuspected,
        networkScope: 'net-b',
        now: _now,
      );
      expect(elsewhere.confirmed, isFalse);
      expect(elsewhere.strikes, 1);
      expect(elsewhere.blocked, isFalse);
    });

    test('a success clears the verdict', () {
      final blocked = recordBootstrapAttempt(
        fresh,
        signal: BootstrapSignal.blockConfirmed,
        networkScope: scope,
        now: _now,
      );
      final recovered = recordBootstrapAttempt(
        blocked,
        signal: BootstrapSignal.none,
        networkScope: scope,
        now: _now,
      );
      expect(recovered.blocked, isFalse);
      expect(recovered.strikes, 0);
      expect(recovered.confirmed, isFalse);
    });

    test('a blocked endpoint is rechecked, with backoff, and is capped', () {
      final blocked = recordBootstrapAttempt(
        fresh,
        signal: BootstrapSignal.blockConfirmed,
        networkScope: scope,
        now: _now,
      );
      expect(blocked.isDueForRecheck(_now), isFalse);
      expect(
        blocked.isDueForRecheck(_now.add(kMinimumRecheckInterval)),
        isTrue,
        reason: 'a false positive that is never rechecked is permanent',
      );

      var state = blocked;
      for (var i = 0; i < 12; i++) {
        state = recordBootstrapAttempt(
          state,
          signal: BootstrapSignal.blockConfirmed,
          networkScope: scope,
          now: _now,
        );
      }
      expect(state.recheckInterval, kMaximumRecheckInterval);
    });
  });

  group('discovery record', () {
    test('a well-formed signed record yields endpoints', () async {
      final result = await verifyDiscoveryRecord(
        '${_record()}|c2lnbmF0dXJl',
        now: _now,
        lastAcceptedSequence: 1,
        verifier: _acceptAll,
      );
      expect(result.accepted, isTrue);
      expect(result.record!.endpoints, [
        'https://alpha.example',
        'https://beta.example',
      ]);
      expect(result.record!.sequence, 2);
    });

    test('a hostile record can never introduce an endpoint', () async {
      for (final entry in _hostileRecords.entries) {
        final result = await verifyDiscoveryRecord(
          entry.value,
          now: _now,
          lastAcceptedSequence: 0,
          // Signature deliberately accepted: structural validation must stand
          // on its own, so that a compromised signing key still cannot inject
          // a malformed or unsafe endpoint.
          verifier: _acceptAll,
        );
        expect(result.accepted, isFalse, reason: entry.key);
        expect(result.record, isNull, reason: entry.key);
      }
    });

    test('a bad signature yields nothing, however well-formed the record',
        () async {
      final result = await verifyDiscoveryRecord(
        '${_record()}|c2lnbmF0dXJl',
        now: _now,
        lastAcceptedSequence: 1,
        verifier: _rejectAll,
      );
      expect(result.accepted, isFalse);
      expect(result.rejection, DiscoveryRejection.badSignature);
    });

    test('a throwing verifier fails closed', () async {
      final result = await verifyDiscoveryRecord(
        '${_record()}|c2lnbmF0dXJl',
        now: _now,
        lastAcceptedSequence: 1,
        verifier: (_, __) async => throw StateError('verifier unavailable'),
      );
      expect(result.accepted, isFalse);
      expect(result.rejection, DiscoveryRejection.badSignature);
    });

    test('replaying an old record cannot steer a client back', () async {
      // Anti-rollback is the primary control, because it does not depend on
      // the device knowing what time it is.
      for (final sequence in [1, 5, 9]) {
        final result = await verifyDiscoveryRecord(
          '${_record(sequence: sequence)}|c2lnbmF0dXJl',
          now: _now,
          lastAcceptedSequence: 9,
          verifier: _acceptAll,
        );
        expect(result.accepted, isFalse, reason: 'sequence $sequence');
        expect(result.rejection, DiscoveryRejection.replayedSequence);
      }
    });

    test('expiry is enforced, with tolerance for a wrong device clock',
        () async {
      final expiry = DateTime.utc(2030, 1, 1);
      final wellAfter = expiry.add(const Duration(days: 3));
      final result = await verifyDiscoveryRecord(
        '${_record()}|c2lnbmF0dXJl',
        now: wellAfter,
        lastAcceptedSequence: 1,
        verifier: _acceptAll,
      );
      expect(result.rejection, DiscoveryRejection.expired);

      // A device whose clock is a few hours off is not an edge case here.
      final justAfter = expiry.add(const Duration(hours: 1));
      final tolerated = await verifyDiscoveryRecord(
        '${_record()}|c2lnbmF0dXJl',
        now: justAfter,
        lastAcceptedSequence: 1,
        verifier: _acceptAll,
      );
      expect(tolerated.accepted, isTrue);
    });

    test('an absurd lifetime is refused', () async {
      final result = await verifyDiscoveryRecord(
        '${_record(expiry: 4102444800)}|c2lnbmF0dXJl',
        now: _now,
        lastAcceptedSequence: 1,
        verifier: _acceptAll,
      );
      expect(result.rejection, DiscoveryRejection.lifetimeTooLong);
    });

    test('oversized records and overlong endpoint lists are refused', () async {
      final tooMany = List.generate(
        kMaxDiscoveryEndpoints + 1,
        (i) => 'host$i.example',
      ).join(',');
      final many = await verifyDiscoveryRecord(
        '${_record(hosts: tooMany)}|c2lnbmF0dXJl',
        now: _now,
        lastAcceptedSequence: 1,
        verifier: _acceptAll,
      );
      expect(many.rejection, DiscoveryRejection.tooManyEndpoints);

      final huge = 'v1|2|$_validExpiry|${'a' * 600}.example|c2ln';
      final big = await verifyDiscoveryRecord(
        huge,
        now: _now,
        lastAcceptedSequence: 1,
        verifier: _acceptAll,
      );
      expect(big.rejection, DiscoveryRejection.tooLarge);
    });

    test('signed bytes are domain-separated and taken from the raw input', () {
      const raw = 'v1|2|$_validExpiry|alpha.example|c2lnbmF0dXJl';
      final split = splitDiscoveryRecord(raw)!;
      expect(split.signedPortion, 'v1|2|$_validExpiry|alpha.example');

      final signed = discoverySigningBytes(split.signedPortion);
      final domain = utf8.encode(kDiscoverySignatureDomain);
      expect(signed.sublist(0, domain.length), domain);
      expect(signed[domain.length], 0,
          reason: 'domain || 0x00 || message, as internal/pqauth does it');
      expect(
        utf8.decode(signed.sublist(domain.length + 1)),
        split.signedPortion,
      );
    });

    test('the verifier sees exactly the bytes that arrived', () async {
      const raw = 'v1|2|$_validExpiry|alpha.example|c2lnbmF0dXJl';
      List<int>? seenMessage;
      List<int>? seenSignature;
      await verifyDiscoveryRecord(
        raw,
        now: _now,
        lastAcceptedSequence: 1,
        verifier: (message, signature) async {
          seenMessage = message;
          seenSignature = signature;
          return true;
        },
      );
      expect(
        seenMessage,
        discoverySigningBytes('v1|2|$_validExpiry|alpha.example'),
      );
      expect(seenSignature, base64.decode('c2lnbmF0dXJl'));
    });

    test('the format fits one 255-byte TXT string', () {
      // Sizing claim from the design doc: an Ed25519 signature (64 bytes, 88
      // base64 chars) leaves room for a realistic endpoint set. An ML-DSA-65
      // signature (3309 bytes) does not fit and is why the record is a
      // locator rather than the authorisation itself.
      final realistic = 'v1|1024|$_validExpiry|'
          'alpha-example-host.net,beta-example-host.org,gamma-example.com|'
          '${base64.encode(List<int>.filled(64, 0))}';
      expect(utf8.encode(realistic).length, lessThan(255));
    });
  });

  group('ordering and budget', () {
    const compiled = [
      'https://one.example',
      'https://two.example',
      'https://three.example',
    ];
    const scope = 'net-a';

    test('a healthy launch tries the compiled set and spends no discovery', () {
      final plan = planBootstrapAttempts(
        compiledEndpoints: compiled,
        networkScope: scope,
        now: _now,
      );
      expect(plan.endpoints, compiled);
      expect(plan.shouldQueryDiscovery, isFalse,
          reason: 'an ordinary launch must cost nothing extra');
    });

    test('the endpoint that last worked on this network is tried first', () {
      final plan = planBootstrapAttempts(
        compiledEndpoints: compiled,
        networkScope: scope,
        now: _now,
        lastKnownGoodEndpoint: 'https://three.example',
      );
      expect(plan.endpoints.first, 'https://three.example');
      expect(plan.endpoints.toSet(), compiled.toSet());
    });

    test('blocked endpoints are skipped but not duplicated', () {
      final health = {
        'https://one.example': recordBootstrapAttempt(
          const EndpointHealth(networkScope: scope),
          signal: BootstrapSignal.blockConfirmed,
          networkScope: scope,
          now: _now,
        ),
      };
      final plan = planBootstrapAttempts(
        compiledEndpoints: compiled,
        networkScope: scope,
        now: _now,
        health: health,
      );
      expect(plan.endpoints, [
        'https://two.example',
        'https://three.example',
      ]);
      expect(plan.shouldQueryDiscovery, isFalse);
    });

    test('discovery is requested only once the compiled set is exhausted', () {
      final blocked = <String, EndpointHealth>{
        for (final endpoint in compiled)
          endpoint: recordBootstrapAttempt(
            const EndpointHealth(networkScope: scope),
            signal: BootstrapSignal.blockConfirmed,
            networkScope: scope,
            now: _now,
          ),
      };
      final plan = planBootstrapAttempts(
        compiledEndpoints: compiled,
        networkScope: scope,
        now: _now,
        health: blocked,
      );
      expect(plan.shouldQueryDiscovery, isTrue);
    });

    test('at most one new endpoint is revealed per launch', () {
      final blocked = <String, EndpointHealth>{
        for (final endpoint in compiled)
          endpoint: recordBootstrapAttempt(
            const EndpointHealth(networkScope: scope),
            signal: BootstrapSignal.blockConfirmed,
            networkScope: scope,
            now: _now,
          ),
      };
      final plan = planBootstrapAttempts(
        compiledEndpoints: compiled,
        networkScope: scope,
        now: _now,
        health: blocked,
        discoveredEndpoints: const [
          'https://fallback-a.example',
          'https://fallback-b.example',
          'https://fallback-c.example',
        ],
      );
      // A false positive must cost exactly one endpoint, not the whole reserve.
      expect(plan.endpoints, ['https://fallback-a.example']);
      expect(plan.shouldQueryDiscovery, isFalse);
    });

    test('hysteresis can never strand a client with nothing to try', () {
      final blocked = <String, EndpointHealth>{
        for (final endpoint in compiled)
          endpoint: recordBootstrapAttempt(
            const EndpointHealth(networkScope: scope),
            signal: BootstrapSignal.blockConfirmed,
            networkScope: scope,
            now: _now,
          ),
      };
      final plan = planBootstrapAttempts(
        compiledEndpoints: compiled,
        networkScope: scope,
        now: _now,
        health: blocked,
      );
      expect(plan.endpoints, isNotEmpty);
    });

    test('block state from another network does not suppress an endpoint', () {
      final elsewhere = <String, EndpointHealth>{
        for (final endpoint in compiled)
          endpoint: recordBootstrapAttempt(
            const EndpointHealth(networkScope: 'hotel-wifi'),
            signal: BootstrapSignal.blockConfirmed,
            networkScope: 'hotel-wifi',
            now: _now,
          ),
      };
      final plan = planBootstrapAttempts(
        compiledEndpoints: compiled,
        networkScope: 'mobile-data',
        now: _now,
        health: elsewhere,
      );
      expect(plan.endpoints, compiled);
      expect(plan.shouldQueryDiscovery, isFalse);
    });

    test('a blocked endpoint returns to the plan once recheck falls due', () {
      final health = {
        'https://one.example': recordBootstrapAttempt(
          const EndpointHealth(networkScope: scope),
          signal: BootstrapSignal.blockConfirmed,
          networkScope: scope,
          now: _now,
        ),
      };
      final later = _now.add(kMinimumRecheckInterval);
      final plan = planBootstrapAttempts(
        compiledEndpoints: compiled,
        networkScope: scope,
        now: later,
        health: health,
      );
      expect(plan.endpoints.first, 'https://one.example');
    });
  });
}
