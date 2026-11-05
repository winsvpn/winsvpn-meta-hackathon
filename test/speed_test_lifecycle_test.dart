import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/speed_test_lifecycle.dart';

void main() {
  test('a second start cannot cross the synchronous reservation', () {
    final lifecycle = SpeedTestLeaseController();
    final first = lifecycle.tryBegin('connected:node-a');

    expect(first, isNotNull);
    expect(lifecycle.isRunning, isTrue);
    expect(lifecycle.tryBegin('connected:node-a'), isNull);
  });

  test('cancellation invalidates the active lease', () {
    final lifecycle = SpeedTestLeaseController();
    final lease = lifecycle.tryBegin('connected:node-a')!;

    expect(lifecycle.cancel(), isTrue);
    expect(lifecycle.isCurrent(lease, 'connected:node-a'), isFalse);
    expect(lifecycle.complete(lease), isFalse);
    expect(lifecycle.isRunning, isFalse);
  });

  test('route identity change makes a result stale', () {
    final lifecycle = SpeedTestLeaseController();
    final lease = lifecycle.tryBegin('connected:node-a')!;

    expect(lifecycle.isCurrent(lease, 'connected:node-b'), isFalse);
    expect(lifecycle.cancelLease(lease), isTrue);
  });

  test('late completion cannot clear a replacement run', () {
    final lifecycle = SpeedTestLeaseController();
    final stale = lifecycle.tryBegin('device')!;
    expect(lifecycle.cancelLease(stale), isTrue);
    final replacement = lifecycle.tryBegin('connected:node-b')!;

    expect(lifecycle.complete(stale), isFalse);
    expect(lifecycle.isRunning, isTrue);
    expect(lifecycle.isCurrent(replacement, 'connected:node-b'), isTrue);
    expect(lifecycle.complete(replacement), isTrue);
    expect(lifecycle.isRunning, isFalse);
  });
}
