import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_host_lifecycle.dart';

// Device findings 2026-09-23: a server pick over a held Winn v3 session hung,
// because the retained-route switch prepares the new server through the held
// blackhole. The pick must release the hold first, as an owner action.

void main() {
  group('winn3ServerSwitchMustReleaseHold', () {
    const blockedHeld = Winn3HostLifecycleView(
      state: Winn3HostLifecycleState.blocked,
      captureHeld: true,
      observer: 'engine',
      cause: 'terminal',
    );
    const recoveringHeld = Winn3HostLifecycleView(
      state: Winn3HostLifecycleState.recovering,
      captureHeld: true,
    );

    test('must release the hold first, and only while a session is held', () {
      expect(winn3ServerSwitchMustReleaseHold(blockedHeld), isTrue);
      expect(winn3ServerSwitchMustReleaseHold(recoveringHeld), isTrue);
      expect(winn3ServerSwitchMustReleaseHold(Winn3HostLifecycleView.none),
          isFalse);
      expect(
          winn3ServerSwitchMustReleaseHold(const Winn3HostLifecycleView(
              state: Winn3HostLifecycleState.connected)),
          isFalse);
      // Released with a limitation: nothing is held, the ordinary switch runs.
      expect(
          winn3ServerSwitchMustReleaseHold(const Winn3HostLifecycleView(
              state: Winn3HostLifecycleState.blocked,
              limitation: 'service_destroyed')),
          isFalse);
    });

    test('the release is disclosed, never silent', () {
      expect(winn3ServerSwitchReleaseDisclosure,
          contains('traffic is no longer held'));
      expect(winn3ServerSwitchReleaseDisclosure,
          contains('may leave outside the VPN'));
    });

  });
}
