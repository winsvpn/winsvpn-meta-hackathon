import 'package:flutter/foundation.dart';

import 'connectivity_probe_budget.dart';

/// Outcome of a budget-capped readiness probe sweep.
///
/// [ready] is whether a sample reported ready within the platform's attempt
/// budget. [attemptsUsed] is the number of probe samples actually taken, which
/// is exactly [budget] when the tunnel never became ready and strictly less
/// when it did, since the sweep stops on the first ready sample. The budget
/// comes from [tunnelConnectivityAttempts], so the same probe logic respects
/// a platform that can afford three attempts and one that can afford eight.
class TunnelReadinessProbeResult {
  const TunnelReadinessProbeResult({
    required this.ready,
    required this.attemptsUsed,
  });

  final bool ready;
  final int attemptsUsed;
}

/// Runs a readiness probe up to the platform's connectivity attempt budget and
/// no further.
///
/// [sampleReady] is expected to take a fresh readiness sample (an encrypted
/// peer session, a VPN-bound Internet probe, a TUN byte delta) and report
/// whether the tunnel is proven usable. The sweep consults the budget from
/// [tunnelConnectivityAttempts] exactly once, so the caller never chooses the
/// attempt count itself and a platform's cap cannot drift silently. A sample
/// that never reports ready costs exactly [budget] attempts and yields
/// [TunnelReadinessProbeResult.ready] == false; a sample that does costs only
/// the attempts it took, because the loop stops on the first positive.
TunnelReadinessProbeResult probeTunnelReadiness({
  required String platform,
  required bool isApplePlatform,
  required bool stealthActive,
  required bool Function() sampleReady,
}) {
  final budget = tunnelConnectivityAttempts(
    platform: platform,
    isApplePlatform: isApplePlatform,
    stealthActive: stealthActive,
  );
  var attemptsUsed = 0;
  for (var i = 0; i < budget; i++) {
    attemptsUsed = i + 1;
    if (sampleReady()) {
      return TunnelReadinessProbeResult(
        ready: true,
        attemptsUsed: attemptsUsed,
      );
    }
  }
  return TunnelReadinessProbeResult(ready: false, attemptsUsed: attemptsUsed);
}

/// The one-word verdict the Android connect screen surfaces for a persisted
/// (resume / relaunch) tunnel, derived from the process-/interface-level
/// readback reported by VpnTunnelService.
///
/// [secured] means the readback proves a recent bidirectional encrypted peer
/// session on top of an open, engine-backed, VPN-present interface. Everything
/// else -- a stale handshake, a missing interface, an engine that never went
/// ready -- is [unprotected]. There is deliberately no third state: a tunnel
/// that reports connected but cannot prove return traffic reads as
/// [unprotected] rather than "unknown", because on a resume path a green that
/// cannot be defended is a green the user must not trust.
enum TunnelReadinessVerdict { secured, unprotected }

/// Human-inspectable summary of the persisted-proof inputs, emitted to logcat
/// on Android so the connect screen's readiness decision is observable without
/// trusting a silent boolean. The enum is a stable, tested ARTIFACT; this
/// string is its debug serialisation.
String tunnelReadinessVerdictLabel({
  required bool active,
  required bool engineReady,
  required bool interfaceOpen,
  required bool vpnPresent,
  required bool handshakeRecent,
  required int awgRxBytes,
  required int awgTxBytes,
}) {
  final verdict = hasPersistedAndroidTunnelProof(
    active: active,
    engineReady: engineReady,
    interfaceOpen: interfaceOpen,
    vpnPresent: vpnPresent,
    handshakeRecent: handshakeRecent,
    awgRxBytes: awgRxBytes,
    awgTxBytes: awgTxBytes,
  );
  return verdict ? TunnelReadinessVerdict.secured.name
                  : TunnelReadinessVerdict.unprotected.name;
}

bool hasTunnelDataPathProof({
  required bool active,
  required bool engineReady,
  required bool vpnPresent,
  required bool vpnValidated,
  required int rxDelta,
  required int txDelta,
  required bool boundVpnProbeSucceeded,
  required bool encryptedPeerHandshakeSucceeded,
}) {
  if (!active || !engineReady || !vpnPresent) return false;
  if (boundVpnProbeSucceeded) return true;
  if (encryptedPeerHandshakeSucceeded) return true;

  final received = rxDelta < 0 ? 0 : rxDelta;
  final transmitted = txDelta < 0 ? 0 : txDelta;
  final bidirectional = received >= 96 && transmitted >= 96;
  final strongInbound = received >= 1024 && transmitted >= 96;

  // Android can label a VPN validated before an inner data path is usable.
  // Validation therefore only counts when the TUN interface also proves
  // bidirectional traffic. A large inbound delta is independently useful.
  return (vpnValidated && bidirectional) || strongInbound;
}

bool hasAwgPeerHandshakeProof({
  required bool handshakeRecent,
  required int rxBytes,
  required int txBytes,
}) {
  // Process/UID counters also include DNS, control-plane, and underlying
  // transport traffic. Only the encrypted peer counters prove that the AWG
  // session itself exchanged packets with the selected server.
  return handshakeRecent && rxBytes >= 80 && txBytes >= 80;
}

bool hasUserVisibleTunnelProtectionProof({
  required bool active,
  required bool engineReady,
  required bool vpnPresent,
  required bool boundVpnProbeSucceeded,
}) {
  // A peer handshake proves encryption to the selected server, but it does
  // not prove that the server can carry customer Internet traffic. The green
  // SECURED state therefore requires a request explicitly bound to the VPN
  // in addition to the native engine/interface state on every platform.
  return active && engineReady && vpnPresent && boundVpnProbeSucceeded;
}

bool hasPersistedAndroidTunnelProof({
  required bool active,
  required bool engineReady,
  required bool interfaceOpen,
  required bool vpnPresent,
  required bool handshakeRecent,
  required int awgRxBytes,
  required int awgTxBytes,
}) {
  // This check is used when the app resumes or is relaunched. Android may
  // report the VpnService and TUN interface as connected while the selected
  // peer is unreachable. Never restore the green "secured" state from those
  // process/interface flags alone.
  final secured = active &&
      engineReady &&
      interfaceOpen &&
      vpnPresent &&
      hasAwgPeerHandshakeProof(
        handshakeRecent: handshakeRecent,
        rxBytes: awgRxBytes,
        txBytes: awgTxBytes,
      );
  // Debug-only: surface the connect screen's readiness verdict to adb logcat
  // (assert-stripped in release builds, so this never ships a per-state log).
  assert(() {
    debugPrint(
      'WINS_TUNNEL_READINESS_VERDICT '
      '${secured ? TunnelReadinessVerdict.secured.name : TunnelReadinessVerdict.unprotected.name} '
      'secured=$secured active=$active engineReady=$engineReady '
      'interfaceOpen=$interfaceOpen vpnPresent=$vpnPresent '
      'handshakeRecent=$handshakeRecent awgRx=$awgRxBytes awgTx=$awgTxBytes',
    );
    return true;
  }());
  return secured;
}
