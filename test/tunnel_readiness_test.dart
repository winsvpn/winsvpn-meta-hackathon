import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tunnel_readiness.dart';

void main() {
  test('does not trust Android validation without return traffic', () {
    expect(
      hasTunnelDataPathProof(
        active: true,
        engineReady: true,
        vpnPresent: true,
        vpnValidated: true,
        rxDelta: 0,
        txDelta: 105000,
        boundVpnProbeSucceeded: false,
        encryptedPeerHandshakeSucceeded: false,
      ),
      isFalse,
    );
  });

  test('accepts a successful probe explicitly bound to the VPN network', () {
    expect(
      hasTunnelDataPathProof(
        active: true,
        engineReady: true,
        vpnPresent: true,
        vpnValidated: false,
        rxDelta: 0,
        txDelta: 0,
        boundVpnProbeSucceeded: true,
        encryptedPeerHandshakeSucceeded: false,
      ),
      isTrue,
    );
  });

  test('accepts validated bidirectional TUN traffic', () {
    expect(
      hasTunnelDataPathProof(
        active: true,
        engineReady: true,
        vpnPresent: true,
        vpnValidated: true,
        rxDelta: 512,
        txDelta: 512,
        boundVpnProbeSucceeded: false,
        encryptedPeerHandshakeSucceeded: false,
      ),
      isTrue,
    );
  });

  test('requires an active complete native tunnel', () {
    expect(
      hasTunnelDataPathProof(
        active: false,
        engineReady: true,
        vpnPresent: true,
        vpnValidated: true,
        rxDelta: 4096,
        txDelta: 4096,
        boundVpnProbeSucceeded: true,
        encryptedPeerHandshakeSucceeded: true,
      ),
      isFalse,
    );
  });

  test('accepts a recent bidirectional encrypted peer handshake', () {
    expect(
      hasTunnelDataPathProof(
        active: true,
        engineReady: true,
        vpnPresent: true,
        vpnValidated: false,
        rxDelta: 0,
        txDelta: 0,
        boundVpnProbeSucceeded: false,
        encryptedPeerHandshakeSucceeded: true,
      ),
      isTrue,
    );
  });

  test('AWG proof requires a recent peer handshake and both directions', () {
    expect(
      hasAwgPeerHandshakeProof(
        handshakeRecent: true,
        rxBytes: 96,
        txBytes: 96,
      ),
      isTrue,
    );
    expect(
      hasAwgPeerHandshakeProof(
        handshakeRecent: false,
        rxBytes: 500000,
        txBytes: 500000,
      ),
      isFalse,
    );
    expect(
      hasAwgPeerHandshakeProof(
        handshakeRecent: true,
        rxBytes: 0,
        txBytes: 500000,
      ),
      isFalse,
    );
  });

  test('user-visible protection always requires a VPN-bound Internet probe',
      () {
    expect(
      hasUserVisibleTunnelProtectionProof(
        active: true,
        engineReady: true,
        vpnPresent: true,
        boundVpnProbeSucceeded: false,
      ),
      isFalse,
    );
    expect(
      hasUserVisibleTunnelProtectionProof(
        active: true,
        engineReady: true,
        vpnPresent: true,
        boundVpnProbeSucceeded: true,
      ),
      isTrue,
    );
  });

  test('resume does not trust an engine-only Android tunnel', () {
    expect(
      hasPersistedAndroidTunnelProof(
        active: true,
        engineReady: true,
        interfaceOpen: true,
        vpnPresent: true,
        handshakeRecent: false,
        awgRxBytes: 0,
        awgTxBytes: 500000,
      ),
      isFalse,
    );
  });

  test('resume accepts a recent bidirectional Android peer session', () {
    expect(
      hasPersistedAndroidTunnelProof(
        active: true,
        engineReady: true,
        interfaceOpen: true,
        vpnPresent: true,
        handshakeRecent: true,
        awgRxBytes: 2048,
        awgTxBytes: 4096,
      ),
      isTrue,
    );
  });

  test('verdict label reports secured for a proven Android peer session', () {
    expect(
      tunnelReadinessVerdictLabel(
        active: true,
        engineReady: true,
        interfaceOpen: true,
        vpnPresent: true,
        handshakeRecent: true,
        awgRxBytes: 2048,
        awgTxBytes: 4096,
      ),
      'secured',
    );
  });

  test('verdict label reports unprotected when the handshake is stale', () {
    expect(
      tunnelReadinessVerdictLabel(
        active: true,
        engineReady: true,
        interfaceOpen: true,
        vpnPresent: true,
        handshakeRecent: false,
        awgRxBytes: 500000,
        awgTxBytes: 500000,
      ),
      'unprotected',
    );
  });

  test('verdict label reports unprotected when the interface is missing',
      () {
    expect(
      tunnelReadinessVerdictLabel(
        active: true,
        engineReady: true,
        interfaceOpen: false,
        vpnPresent: true,
        handshakeRecent: true,
        awgRxBytes: 4096,
        awgTxBytes: 8192,
      ),
      'unprotected',
    );
  });

  test('probe spends the Android budget and stops if never ready', () {
    var calls = 0;
    final result = probeTunnelReadiness(
      platform: 'android',
      isApplePlatform: false,
      stealthActive: false,
      sampleReady: () {
        calls++;
        return false;
      },
    );
    expect(result.ready, isFalse);
    expect(result.attemptsUsed, 3);
    expect(calls, 3);
  });

  test('probe stops early on the first ready sample', () {
    var calls = 0;
    final result = probeTunnelReadiness(
      platform: 'android',
      isApplePlatform: false,
      stealthActive: false,
      sampleReady: () {
        calls++;
        return calls == 2;
      },
    );
    expect(result.ready, isTrue);
    expect(result.attemptsUsed, 2);
    expect(calls, 2);
  });

  test('probe reports ready immediately when the first sample is ready', () {
    final result = probeTunnelReadiness(
      platform: 'android',
      isApplePlatform: false,
      stealthActive: false,
      sampleReady: () => true,
    );
    expect(result.ready, isTrue);
    expect(result.attemptsUsed, 1);
  });

  test('probe respects the Windows non-stealth budget of two', () {
    var calls = 0;
    final result = probeTunnelReadiness(
      platform: 'windows',
      isApplePlatform: false,
      stealthActive: false,
      sampleReady: () {
        calls++;
        return false;
      },
    );
    expect(result.ready, isFalse);
    expect(result.attemptsUsed, 2);
    expect(calls, 2);
  });

  test('probe respects the Apple budget of eight regardless of stealth', () {
    var calls = 0;
    final result = probeTunnelReadiness(
      platform: 'ios',
      isApplePlatform: true,
      stealthActive: false,
      sampleReady: () {
        calls++;
        return false;
      },
    );
    expect(result.ready, isFalse);
    expect(result.attemptsUsed, 8);
    expect(calls, 8);
  });

  test('probe does not let stealth widen the Apple budget', () {
    var calls = 0;
    final result = probeTunnelReadiness(
      platform: 'ios',
      isApplePlatform: true,
      stealthActive: true,
      sampleReady: () {
        calls++;
        return false;
      },
    );
    expect(result.ready, isFalse);
    expect(result.attemptsUsed, 8);
    expect(calls, 8);
  });

  test('probe widens the stealth Linux budget from four to six', () {
    var calls = 0;
    final result = probeTunnelReadiness(
      platform: 'linux',
      isApplePlatform: false,
      stealthActive: true,
      sampleReady: () {
        calls++;
        return false;
      },
    );
    expect(result.ready, isFalse);
    expect(result.attemptsUsed, 6);
    expect(calls, 6);
  });

  test('probe caps the unknown-platform stealth budget at twelve', () {
    var calls = 0;
    final result = probeTunnelReadiness(
      platform: 'other',
      isApplePlatform: false,
      stealthActive: true,
      sampleReady: () {
        calls++;
        return false;
      },
    );
    expect(result.ready, isFalse);
    expect(result.attemptsUsed, 12);
    expect(calls, 12);
  });
}
