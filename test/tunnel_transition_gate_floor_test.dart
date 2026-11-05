import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tunnel_transition_gate.dart';

// DESKTOP-4: every stop carries a positive cancellation floor. This pins the
// generation arithmetic only; the native channel contract is covered where the
// production start and stop calls are extracted (connect_transition_cancellation_test).
void main() {
  test('a stop before the first start already carries a positive floor', () {
    final gate = TunnelTransitionGate();
    expect(gate.supersededFloor, 1);
    expect(gate.supersededFloor, greaterThan(0));
  });

  test('failover within one generation keeps one floor', () {
    final gate = TunnelTransitionGate();
    final first = gate.begin();
    final floor = gate.supersededFloor;
    expect(gate.isCurrent(first), isTrue);
    expect(gate.supersededFloor, floor);
    expect(first, greaterThan(floor));
  });

  test('explicit cancellation supersedes the cancelled generation', () {
    final gate = TunnelTransitionGate();
    final first = gate.begin();
    gate.cancel();
    expect(gate.isCurrent(first), isFalse);
    expect(gate.supersededFloor, greaterThanOrEqualTo(first));
  });

  test('a later new connection is current and the cancelled one stays superseded',
      () {
    final gate = TunnelTransitionGate();
    final first = gate.begin();
    gate.cancel();
    final second = gate.begin();
    expect(gate.isCurrent(second), isTrue);
    expect(gate.isCurrent(first), isFalse);
    expect(gate.supersededFloor, greaterThanOrEqualTo(first));
    expect(gate.supersededFloor, lessThan(second));
  });
}
