import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/gateway_failover.dart';

void main() {
  test('a sweep starts at the compiled front that last answered', () {
    expect(
      preferredSweepGateway(
        activeGateway: primaryStealthGateways.first,
        lastKnownGoodGateway: 'https://c.app-cloud-sync.net/nodes',
      ),
      'https://c.app-cloud-sync.net',
    );
  });

  test('a non-compiled or absent last-known-good never becomes the start', () {
    expect(
      preferredSweepGateway(
        activeGateway: primaryStealthGateways.first,
        lastKnownGoodGateway: 'https://evil.example',
      ),
      primaryStealthGateways.first,
    );
    expect(
      preferredSweepGateway(activeGateway: primaryStealthGateways.first),
      primaryStealthGateways.first,
    );
  });
}
