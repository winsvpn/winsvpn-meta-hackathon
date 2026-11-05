/// The dashboard's honest status surface: gate state, and whether traffic is
/// actually flowing.
///
/// ---------------------------------------------------------------------------
/// WHAT THIS FILE DOES NOT DO.
///
/// It does NOT report the Winn Protocol version. That fact is already owned by
/// lib/winn_session_descriptor.dart, whose whole reason for existing is that
/// the version must come from the NEGOTIATED `protocol_version` of a committed
/// session and never from a build flag or a default. This file stays out of
/// that decision; the dashboard composes the two surfaces.
///
/// It does NOT assert that a gate reporting "carrying" is carrying anything.
/// That is the silent-refusal shape the continuity brief calls #3: a session
/// can reach `gate=carrying` while the kernel admits zero bytes, and both ends
/// keep reporting carrying. The whole reason the traffic-flow fact exists as a
/// SEPARATE row is so the user can see the two disagree. A gate row and a
/// traffic row that are derived from the same signal would simply restate each
/// other and never surface that discrepancy.
///
/// ---------------------------------------------------------------------------
/// WHAT IT ACTUALLY DOES, AND WHAT IT NEEDS TO STAY HONEST.
///
/// Two facts, each derived only from what the platform's tunnel actually
/// reported into this process:
///
///   * GATE STATE. A ladder that can only reach `carrying` when the platform's
///     own carrying composite is all true -- on Android
///     `service_active && engine_ready && interface_open` (that is exactly
///     `VpnTunnelService.isTunnelHealthy()`), on Apple
///     `active && provider_engine_ready && interface_open`. Every other
///     combination is reported as a distinct, dimmer state (`connecting`,
///     `establishing`, or not connected) -- never as carrying.
///
///   * TRAFFIC FLOW. A measurement, not a label: the sum of the tun device's
///     rx+tx byte counters ADVANCED between two samples taken in the same
///     poll cadence. One sample is not enough and yields `unknown`; a stale
///     sample yields `unknown`; a wrapped/reset counter yields `unknown`.
///     Only a genuine positive delta proves `flowing`.
///
/// Every codepath above that could go green by being deleted was deliberately
/// written so that "no data" yields `unknown` rather than `flowing` -- the
/// same absence-vs-empty rule the antivirus lane uses for unreadable sources,
/// and the reason test/winn_status_surface_test.dart asserts both directions
/// on every branch.
library;

/// The gate lifecycle, as far as this process is able to observe it.
enum WinnGateState {
  /// No live tunnel session.
  disconnected,

  /// A connect is in flight; the tunnel has not yet reported active.
  connecting,

  /// A live session exists but has not yet reported the platform's full
  /// carrying composite (engine ready AND interface open), or the engine
  /// explicitly reports its own transfer as unproven
  /// (`transport_observed_both_ways=false`). Never rendered as carrying.
  establishing,

  /// The platform's own composite for a healthy carrying tunnel is all true.
  /// On Android this is `VpnTunnelService.isTunnelHealthy()`. It is NOT a
  /// claim that traffic is moving -- that is [WinnTrafficFlow]'s job.
  carrying,

  /// The app believes a session is up but this platform exposes no native
  /// tunnel readiness probe, so no carrying composite can be asserted.
  /// Reported as its own state so "we cannot tell" is never rendered as
  /// "carrying".
  unprobed,
}

/// Whether the tunnel byte counters actually moved between two samples.
enum WinnTrafficFlow {
  /// No measurement exists: fewer than two samples, a stale latest sample, or
  /// a counter that reset. Deliberately the default -- absence of proof is
  /// not `idle`, and it is certainly not `flowing`.
  unknown,

  /// rx+tx advanced by at least [winnTrafficFlow]'s minimum.
  flowing,

  /// rx+tx did not advance at all across the observation window. The gate may
  /// still be carrying; this row exists precisely to say so.
  idle,
}

/// One read of the native tunnel's readiness, with its byte counters.
///
/// [counterPresent] describes whether this platform actually handed us byte
/// counters at all. A platform that reports no counters can never produce
/// `flowing` -- the traffic row degrades to [WinnTrafficFlow.unknown].
class WinnReadinessSnapshot {
  const WinnReadinessSnapshot({
    required this.serviceActive,
    required this.engineReady,
    required this.interfaceOpen,
    required this.rxBytes,
    required this.txBytes,
    required this.sampledAt,
    this.transportProvenBothWays,
  });

  /// The platform's raw "a session is running" bit. Android: `service_active`.
  /// Apple: `active`.
  final bool serviceActive;

  /// The engine is loaded. Android: `engine_ready`. Apple:
  /// `provider_engine_ready` (or `engine_ready`).
  final bool engineReady;

  /// The tun interface is open. Both platforms: `interface_open`.
  final bool interfaceOpen;

  /// The engine's OWN transfer-proven signal (`transport_observed_both_ways`):
  /// at least one payload-carrying transport datagram has crossed in each
  /// direction. This is the gate field the rest of the tree promotes routes
  /// on, and it is stronger than the byte counters: handshakes and keepalives
  /// cannot raise it.
  ///
  /// `null` means the platform did not expose it at all. Absence is NOT
  /// treated as false -- a gate that cannot observe must not fail every
  /// session (see the Android convergence note). Only an explicit `false` is
  /// allowed to hold the gate below `carrying`.
  final bool? transportProvenBothWays;

  /// Bytes received through the tunnel, or null when the platform exposed no
  /// counter for them.
  final int? rxBytes;

  /// Bytes sent through the tunnel, or null when the platform exposed no
  /// counter for them.
  final int? txBytes;

  /// When this snapshot was read.
  final DateTime sampledAt;

  bool get counterPresent => rxBytes != null && txBytes != null;

  int get totalBytes => (rxBytes ?? 0) + (txBytes ?? 0);
}

/// Parses one native readiness map into a snapshot used by the two honest
/// derivations below. Unknown keys are read as false/absent -- a platform that
/// omits a field makes carrying and flowing equally unreachable, which is the
/// fail-closed direction.
WinnReadinessSnapshot winnReadinessSnapshot({
  required DateTime sampledAt,
  Object? serviceActive,
  Object? engineReady,
  Object? interfaceOpen,
  Object? rxBytes,
  Object? txBytes,
  Object? awgRxBytes,
  Object? awgTxBytes,
  Object? trafficRxBytes,
  Object? trafficTxBytes,
  Object? transportProvenBothWays,
}) {
  final parsedTrafficRx = _intValue(trafficRxBytes);
  final parsedTrafficTx = _intValue(trafficTxBytes);
  final parsedTunRx = _intValue(rxBytes);
  final parsedTunTx = _intValue(txBytes);
  final parsedAwgRx = _intValue(awgRxBytes);
  final parsedAwgTx = _intValue(awgTxBytes);

  int? finalRx;
  int? finalTx;

  if (parsedTrafficRx != null && parsedTrafficTx != null) {
    finalRx = parsedTrafficRx;
    finalTx = parsedTrafficTx;
  } else if (parsedTunRx != null &&
      parsedTunTx != null &&
      (parsedTunRx > 0 ||
          parsedTunTx > 0 ||
          (parsedAwgRx == null && parsedAwgTx == null) ||
          (parsedAwgRx == 0 && parsedAwgTx == 0))) {
    finalRx = parsedTunRx;
    finalTx = parsedTunTx;
  } else if (parsedAwgRx != null || parsedAwgTx != null) {
    finalRx = parsedAwgRx ?? parsedTunRx;
    finalTx = parsedAwgTx ?? parsedTunTx;
  } else {
    finalRx = parsedTunRx;
    finalTx = parsedTunTx;
  }

  return WinnReadinessSnapshot(
    serviceActive: _boolValue(serviceActive),
    engineReady: _boolValue(engineReady),
    interfaceOpen: _boolValue(interfaceOpen),
    rxBytes: finalRx,
    txBytes: finalTx,
    transportProvenBothWays: _nullableBool(transportProvenBothWays),
    sampledAt: sampledAt,
  );
}

/// The gate state derivable from the readiness snapshot and the app's own
/// connect flags.
///
/// [probeAvailable] is false on platforms that expose no native readiness
/// read; there the only honest answers are `connecting` (a connect is in
/// flight), `unprobed` (the app says a session is up but nothing in the
/// process can verify it), and `disconnected`.
WinnGateState winnGateState({
  required WinnReadinessSnapshot? snapshot,
  required bool connected,
  required bool connectInFlight,
  required bool probeAvailable,
}) {
  if (!probeAvailable || snapshot == null) {
    if (connectInFlight) return WinnGateState.connecting;
    if (connected) return WinnGateState.unprobed;
    return WinnGateState.disconnected;
  }
  if (connectInFlight && !snapshot.serviceActive) {
    return WinnGateState.connecting;
  }
  if (!snapshot.serviceActive) return WinnGateState.disconnected;
  if (snapshot.engineReady && snapshot.interfaceOpen) {
    // The composite is all true, but the engine's OWN transfer-proven gate
    // can still veto it. `transport_observed_both_ways=false` is the measured
    // false-"Connected" shape (2026-08-07): every readiness bit true while a
    // path drops every datagram. The engine cannot have proved a carrying
    // session it explicitly reports as unproven, so the gate stays
    // `establishing` -- never `carrying`. Only an explicit false vetoes;
    // absence (null) falls through to the composite, because a platform that
    // does not expose the field cannot be judged on it.
    if (snapshot.transportProvenBothWays == false) {
      return WinnGateState.establishing;
    }
    return WinnGateState.carrying;
  }
  return WinnGateState.establishing;
}

/// Whether traffic actually flowed, measured from two byte-counter samples.
///
/// Returns [WinnTrafficFlow.unknown] unless it can prove a positive delta:
/// two samples, a fresh latest sample, and no counter wrap. A zero delta is
/// [WinnTrafficFlow.idle] -- "carrying but nothing moved", the exact fact the
/// user needs when the gate row and the traffic row disagree.
WinnTrafficFlow winnTrafficFlow({
  required WinnReadinessSnapshot? prior,
  required WinnReadinessSnapshot current,
  required DateTime now,
  required Duration maxSampleAge,
  required int minimumAdvanceBytes,
}) {
  if (prior == null || !prior.counterPresent || !current.counterPresent) {
    return WinnTrafficFlow.unknown;
  }
  if (now.difference(current.sampledAt) > maxSampleAge) {
    return WinnTrafficFlow.unknown;
  }
  if (prior.sampledAt.isAtSameMomentAs(current.sampledAt)) {
    return WinnTrafficFlow.unknown;
  }
  final rxDelta = current.rxBytes! - prior.rxBytes!;
  final txDelta = current.txBytes! - prior.txBytes!;
  if (rxDelta < 0 || txDelta < 0) {
    return WinnTrafficFlow.unknown;
  }
  if (rxDelta + txDelta >= minimumAdvanceBytes) {
    return WinnTrafficFlow.flowing;
  }
  return WinnTrafficFlow.idle;
}

/// Bytes-per-second between two samples, or 0 when fewer than two samples
/// exist or the counter wrapped. Only used to render a rate when flow was
/// otherwise proven; a rate computed from a wrapped counter is misleading.
double winnTrafficRateBytesPerSecond({
  required WinnReadinessSnapshot? prior,
  required WinnReadinessSnapshot? current,
}) {
  if (prior == null ||
      current == null ||
      !prior.counterPresent ||
      !current.counterPresent) {
    return 0;
  }
  final rxDelta = current.rxBytes! - prior.rxBytes!;
  final txDelta = current.txBytes! - prior.txBytes!;
  if (rxDelta < 0 || txDelta < 0) return 0;
  final elapsed = current.sampledAt.difference(prior.sampledAt).inMilliseconds;
  if (elapsed <= 0) return 0;
  return (rxDelta + txDelta) * 1000.0 / elapsed;
}

/// Human-readable byte count, e.g. `1.2 MB`. Unit-only, so it is not part of
/// the translation surface; a `fromBytes(1)` name kept short for the row.
String winnBytesHuman(int bytes) {
  if (bytes < 0) return '0 B';
  if (bytes < 1024) return '$bytes B';
  final kb = bytes / 1024;
  if (kb < 1024) return '${_trim(kb)} KB';
  final mb = kb / 1024;
  if (mb < 1024) return '${_trim(mb)} MB';
  return '${_trim(mb / 1024)} GB';
}

/// Human-readable rate in Mbps (megabits per second), e.g. `12.5 Mbps`.
String winnRateHuman(double bytesPerSecond) {
  final value = bytesPerSecond < 0 ? 0.0 : bytesPerSecond;
  final bitsPerSecond = value * 8.0;
  final mbps = bitsPerSecond / 1000000.0;
  if (mbps >= 1.0) return '${_trim(mbps)} Mbps';
  if (mbps >= 0.1) return '${_trim(mbps)} Mbps';
  if (mbps >= 0.01) return '${mbps.toStringAsFixed(2)} Mbps';
  if (mbps > 0) return '< 0.01 Mbps';
  return '0 Mbps';
}

/// The English source strings this file can put on screen. The widget composes
/// its rows from these plus [WinnGateState] / [WinnTrafficFlow] phrase helpers.
/// Any phrase here MUST have an entry in `main.dart`'s `my` and `de`
/// translation blocks; the translation-coverage half of
/// test/winn_status_surface_test.dart fails if one is missing.
const List<String> kWinnStatusSurfacePhrases = <String>[
  'Gate:',
  'Traffic:',
  'Not connected',
  'Connecting...',
  'Establishing secure route...',
  'Carrying traffic',
  'Connected, no live probe on this device',
  'Flowing',
  'Idle',
  'Standby',
  'Not available',
  'Received',
  'Sent',
  'Received (Download)',
  'Sent (Upload)',
];

/// English source phrase for a gate state.
String winnGateStatePhrase(WinnGateState state) {
  switch (state) {
    case WinnGateState.disconnected:
      return 'Not connected';
    case WinnGateState.connecting:
      return 'Connecting...';
    case WinnGateState.establishing:
      return 'Establishing secure route...';
    case WinnGateState.carrying:
      return 'Carrying traffic';
    case WinnGateState.unprobed:
      return 'Connected, no live probe on this device';
  }
}

/// English source phrase for a traffic-flow state.
String winnTrafficFlowPhrase(WinnTrafficFlow flow) {
  switch (flow) {
    case WinnTrafficFlow.unknown:
      return 'Standby';
    case WinnTrafficFlow.flowing:
      return 'Flowing';
    case WinnTrafficFlow.idle:
      return 'Idle';
  }
}

bool _boolValue(Object? value) => value == true;

bool? _nullableBool(Object? value) {
  if (value is bool) return value;
  return null;
}

int? _intValue(Object? value) {
  if (value is int) return value;
  final parsed = int.tryParse((value ?? '').toString().trim());
  return parsed == null || parsed < 0 ? null : parsed;
}

/// One decimal digit, no trailing zero.
String _trim(double value) {
  final rounded = (value * 10).roundToDouble() / 10;
  if (rounded == rounded.roundToDouble()) {
    return rounded.toInt().toString();
  }
  return rounded.toStringAsFixed(1);
}