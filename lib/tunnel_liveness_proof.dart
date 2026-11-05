/// The freshness-bounded native liveness proof that may paint a green
/// "connected" claim on the connect/disconnect dashboard.
///
/// ---------------------------------------------------------------------------
/// WHY THIS TYPE EXISTS.
///
/// A bool is not a proof. A bool that reflected the tunnel yesterday, or even
/// a second before the engine died behind the UI, is a booby-trapped legacy
/// green: under this threat model a false "connected" is a safety defect. So
/// the only thing allowed to turn the headline UNPROTECTED/SECURED text, the
/// green power button, and the "Disconnect VPN" affordance green is a native
/// readiness read that (a) ANSWERED, and (b) answered "active", and (c)
/// answered it recently enough that the claim cannot outlive the tunnel that
/// produced it.
///
/// Every [activeWithin] branch FAILS CLOSED: a missing proof, a proof that
/// said "down", a staleness past [maxFreshness], a clock moved backwards so
/// the proof looks like it comes from the future, and an unreadable bridge
/// all yield `false`, which the dashboard renders as UNPROTECTED rather than
/// reusing a possibly-stale green.
library;

/// The result of one native tunnel liveness read, with the moment it was read.
class TunnelLivenessProof {
  const TunnelLivenessProof({required this.active, required this.probedAt});

  /// What the native backend answered. `false` is also a recorded proof --
  /// it is the strongest possible invalidation of a green claim.
  final bool active;

  /// Wall-clock instant the read was taken.
  final DateTime probedAt;

  /// True only when the proof is positive AND fresh. A positive answer older
  /// than [maxFreshness], or dated in the future (a backwards clock jump),
  /// is no proof at all.
  bool activeWithin(DateTime now, Duration maxFreshness) {
    if (!active) return false;
    final elapsed = now.difference(probedAt);
    if (elapsed.isNegative) return false;
    return elapsed <= maxFreshness;
  }
}