import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/control_plane_pinning.dart';
import 'package:wins_vpn/gateway_failover.dart';
import 'package:wins_vpn/recovery_beacon_gate.dart';
import 'package:wins_vpn/signed_discovery_admission.dart';

void main() {
  tearDown(() => setSignedDiscoveryAdmission(const <String, DateTime>{}));

  test('an admitted host reaches every sweep after the compiled set', () {
    setSignedDiscoveryAdmission(<String, DateTime>{
      'https://fresh-front.example':
          DateTime.now().toUtc().add(const Duration(hours: 1)),
    });
    expect(nodeDiscoveryUrls(const GatewayEndpoints(gateway: '')).last,
        'https://fresh-front.example/nodes');
    expect(verifyGateways(const GatewayEndpoints(gateway: '')).last,
        'https://fresh-front.example/verify');
  });

  test('the pinned client admits an unexpired lease and nothing else', () {
    final uri = Uri.parse('https://fresh-front.example/nodes');
    expect(controlPlaneRequestTargetAllowed(uri), isFalse);
    setSignedDiscoveryAdmission(<String, DateTime>{
      'https://fresh-front.example':
          DateTime.now().toUtc().add(const Duration(hours: 1)),
    });
    expect(controlPlaneRequestTargetAllowed(uri), isTrue);
    expect(controlPlaneRequestTargetAllowed(Uri.parse('https://other.example/')),
        isFalse);
    expect(
        controlPlaneRequestTargetAllowed(
            Uri.parse('https://fresh-front.example:8443/nodes')),
        isFalse);
  });

  test('an expired lease is refused at URL build and at request time', () {
    setSignedDiscoveryAdmission(<String, DateTime>{
      'https://stale-front.example':
          DateTime.now().toUtc().subtract(const Duration(seconds: 1)),
    });
    expect(signedDiscoveryGatewayTail, isEmpty);
    expect(
        controlPlaneRequestTargetAllowed(
            Uri.parse('https://stale-front.example/nodes')),
        isFalse);
  });

  test('a shaped-wrong lease key is dropped', () {
    final until = DateTime.now().toUtc().add(const Duration(hours: 1));
    setSignedDiscoveryAdmission(<String, DateTime>{
      'http://plain.example': until,
      'https://port.example:8443': until,
      'https://path.example/x': until,
      'https://user@info.example': until,
    });
    expect(signedDiscoveryGatewayTail, isEmpty);
  });

  test('a discovered last-known-good cannot lead while compiled gateways work',
      () {
    final gate = RecoveryBeaconGate(
        compiledGateways: const <String>['https://compiled.example']);
    gate.adoptDiscoveredEndpoints(const <String>['https://fresh-front.example']);
    gate.recordGatewaySuccess(
        gateway: 'https://fresh-front.example/nodes', now: DateTime.now());
    expect(gate.plannedGatewayOrder(DateTime.now()),
        isNot(contains('https://fresh-front.example')));
  });
}
