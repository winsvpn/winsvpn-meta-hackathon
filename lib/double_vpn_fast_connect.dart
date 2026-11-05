import 'dart:async';

/// FAST-CONNECT FOR DOUBLE VPN (owner-approved 2026-10-24).
///
/// Measured on a Samsung S26 release build: a single-hop connect is validated
/// 1.38 s after the tap, while a Double VPN connect took 7-8 s, because the
/// hub holds the first /verify up to ~5 s while the Core assignment is
/// prepared (503 `double_vpn_assignment_preparing`, Retry-After) and the client
/// then retries. Owner requirement: protected in under 3 s from the tap.
///
/// Live follow-up (same day, same device): a WARM Double connect (assignment
/// already active, the hub answers at once) validates in 1.10 s, and only a
/// COLD one (fresh assignment) is slow (18.33 s observed). So a connect that
/// wants Double VPN still asks for the Double route first, and gives that
/// request [doubleVpnDirectConnectBudget]. A genuine Double config within the
/// budget connects Double directly, exactly as before. Otherwise the request
/// is abandoned and the connect takes the ordinary single-hop route (the
/// existing fast path), marked as single hop for as long as it is one, and
/// prepares the Double assignment in the background. A genuine Double
/// config then replaces the single-hop session make-before-break: the native
/// host starts the new tunnel while the old interface is still installed, so
/// the device's traffic is never routed outside a tunnel during the cutover.
/// The marker clears only when the Double session itself commits. While the
/// Core is unavailable the session stays single hop, marked, and the upgrade
/// is retried with a bounded backoff on top of the existing bounded fan-out
/// and Retry-After rules (double_vpn_assignment_retry.dart).
///
/// Pure Dart with no Flutter import: the state machine is exercised directly
/// by test/double_vpn_fast_connect_test.dart.

/// Where the background upgrade of a single-hop session stands. The dashboard
/// words the single-hop marker from it; the marker itself (whether the running
/// session is one hop) is decided elsewhere and is never cleared from here.
enum DoubleVpnUpgradePhase {
  /// No upgrade belongs to the running session: Double VPN is off, the
  /// session is already two-hop, or the session was not started by this
  /// process (a native restart or an adopted tunnel).
  none,

  /// The session was connected single hop on purpose and its first upgrade
  /// attempt has not failed yet.
  preparing,

  /// An upgrade attempt failed (the Core is unavailable or did not become
  /// ready), or no upgrade can run for this session. The session stays one
  /// hop and says so.
  unavailable,
}

/// The platforms whose native host replaces a running tunnel in place.
///
/// Android: an `ACTION_CONNECT` that arrives while a session runs stops the old
/// engines, keeps the old interface installed as a blocking interface
/// (`resetTunnelBeforeConnect` -> `retainedKillSwitchInterface`), and closes it
/// only after the new `Builder.establish()` has returned; a Winn v3 start that
/// replaces a protecting posture builds a fail-closed bootstrap. Every other
/// host stops one session before it starts the next, so the fast path is not
/// used there and those platforms keep the previous behaviour (they wait for
/// the Double config, and a refused Double connect is reported, never silent).
bool doubleVpnHandoverCutoverSupported(String operatingSystem) =>
    operatingSystem == 'android';

/// Whether a connect that wants Double VPN may fall back to one hop first when
/// the Double route is not served within [doubleVpnDirectConnectBudget]. Only a
/// fresh connect may: a server switch keeps its retained tunnel while it
/// prepares, and the upgrade's own cutover asks for the Double route.
bool doubleVpnFastConnectEligible({
  required String operatingSystem,
  required bool doubleVpnRequested,
  required bool freshConnect,
}) =>
    doubleVpnRequested &&
    freshConnect &&
    doubleVpnHandoverCutoverSupported(operatingSystem);

/// How long a fast-connect-eligible connect waits for the Double route before
/// it takes one hop first. A warm assignment is served well inside it (the
/// whole warm connect, refresh plus tunnel proof, validated in 1.10 s); a cold
/// one is held by the hub for up to ~5 s per request while the Core prepares,
/// far outside it. 1.2 s rather than 1.5 s: a cold connect costs this budget
/// plus the single-hop connect (1.38 s from the tap, measured), and the owner
/// bound is under 3 s from the tap. Abandoning
/// the request is deliberate: the single-hop /verify that follows deactivates
/// the Double assignment on the hub, so a Double reply still in flight could
/// name an assignment that no longer exists. The upgrade polls afresh after
/// the single-hop session has committed, when that ordering is settled.
const Duration doubleVpnDirectConnectBudget = Duration(milliseconds: 1200);

/// How the bounded Double attempt of a fast-connect-eligible connect ended.
enum DoubleVpnDirectRaceOutcome {
  /// A genuine Double config was served in time: connect Double directly.
  served,

  /// The hub answered in time, but not with a Double config (for example the
  /// Core is not available). One hop first, marked unavailable, and the first
  /// upgrade attempt waits one backoff interval.
  refused,

  /// Nothing in time (a cold assignment). One hop first, marked as preparing,
  /// and the upgrade starts as soon as the single-hop session commits.
  timedOut,
}

/// How one upgrade attempt ended.
enum DoubleVpnCutoverResult {
  /// Nothing was handed over: the Double config was not served, was refused
  /// before the native start, or another operation owned the tunnel. The
  /// single-hop session is untouched.
  keptSingleHop,

  /// The Double session committed.
  upgraded,

  /// The Double start was handed over but did not commit, and the single-hop
  /// session was started again in its place.
  restoredSingleHop,

  /// Neither the Double start nor the single-hop restart committed. The
  /// connect failure was reported through the ordinary failure path.
  lost,
}

/// One upgrade attempt, handed to the connect path that runs it. The connect
/// writes [result]; [singleHopConfig] is the exact config the single-hop
/// session committed with, used to start it again if the handover fails.
class DoubleVpnUpgradeAttempt {
  DoubleVpnUpgradeAttempt({
    required this.singleHopConfig,
    required this.stillWanted,
    required this.sinceLastStart,
  });

  final Map<String, dynamic> singleHopConfig;

  /// Running since the session's latest start request (the single-hop commit,
  /// then each handover or restore); see [doubleVpnHandoverMinimumSpacing].
  final Stopwatch sinceLastStart;

  /// The UI operation the handover raised the transition flags under, or null
  /// while nothing was handed over. Whoever still owns that operation when the
  /// attempt ends lowers the flags.
  int? handoverOperationEpoch;

  /// False once the upgrade no longer belongs to the running session (it was
  /// cancelled, the account changed, the tunnel went away, or Double VPN is no
  /// longer wanted). The connect treats it as a cancellation.
  final bool Function() stillWanted;

  DoubleVpnCutoverResult result = DoubleVpnCutoverResult.keptSingleHop;
}

/// The wait before the next upgrade attempt after [consecutiveFailures]
/// failed ones: 10 s, doubling, capped at five minutes. Each attempt is itself
/// one bounded assignment poll (pollDoubleVpnAssignment: at most 90 s, at most
/// three fronts open, Retry-After honoured with a one-second floor), so a
/// session whose Core stays down sends at most one poll per interval.
Duration doubleVpnUpgradeBackoff(int consecutiveFailures) {
  const base = Duration(seconds: 10);
  const cap = Duration(minutes: 5);
  if (consecutiveFailures <= 1) return base;
  final exponent = consecutiveFailures - 1 > 5 ? 5 : consecutiveFailures - 1;
  final delay = base * (1 << exponent);
  return delay > cap ? cap : delay;
}

/// How often the loop looks again while another operation (a connect, a
/// switch, a disconnect, a pending setting) owns the tunnel. Looking sends
/// nothing.
const Duration doubleVpnUpgradeBusyRecheck = Duration(milliseconds: 500);

/// The least time between a tunnel start and the next start request on the
/// same session. The Android host refuses a start request that arrives within
/// 1.5 s of the previous one (CONNECT_IN_PROGRESS), so a handover waits out
/// this spacing after the single-hop commit, and a restore waits it out after
/// the Double start.
const Duration doubleVpnHandoverMinimumSpacing = Duration(milliseconds: 1600);

/// The upper bound on waiting for the native host to take a handover start
/// (its route marker changes when it does).
const Duration doubleVpnHandoverObservationBound = Duration(seconds: 4);

/// The time still to wait before a start request, given how long ago the
/// previous one was made.
Duration doubleVpnHandoverSpacingRemaining(Duration sincePreviousStart) =>
    sincePreviousStart >= doubleVpnHandoverMinimumSpacing
        ? Duration.zero
        : doubleVpnHandoverMinimumSpacing - sincePreviousStart;

/// Whether a native route reading shows that the host has taken the start it
/// was handed. The single-hop session reports `double_vpn_single_hop: true`
/// (Double is wanted and its route is one hop); the host resets that value as
/// soon as it processes a new start, before any engine of the new session
/// runs. So for a Double start, `false` proves the reading is no longer the
/// single-hop session's; for a single-hop restart, `true` is expected. Any
/// non-boolean proves nothing.
bool nativeDoubleVpnRouteObserved(
  Map<dynamic, dynamic>? readiness, {
  required bool expectSingleHop,
  int? handoverToken,
}) {
  if (handoverToken != null &&
      readiness?['double_vpn_handover_token'] != handoverToken) {
    return false;
  }
  final reported = readiness?['double_vpn_single_hop'];
  return reported is bool && reported == expectSingleHop;
}

/// How the background upgrade loop ended.
enum DoubleVpnUpgradeExit {
  /// The Double session committed.
  upgraded,

  /// The upgrade stopped belonging to the session (disconnect, account
  /// switch, a newer connect or switch, the tunnel went away).
  cancelled,

  /// The session was lost during a cutover and was reported as a failure.
  lost,
}

/// Runs the upgrade of one single-hop session to Double VPN.
///
/// [attempt] runs one complete attempt: one bounded assignment poll and, if a
/// genuine Double config is served, the make-before-break cutover. Attempts
/// never overlap, and nothing is sent between them: the loop only waits.
/// [isCurrent] ends the loop as soon as it turns false, including during a
/// wait. [mayAttemptNow] defers an attempt (without counting a failure) while
/// another operation owns the tunnel. [onPhase] reports `unavailable` after a
/// failed attempt and `none` after the Double session commits; the caller set
/// `preparing` when it connected single hop.
Future<DoubleVpnUpgradeExit> runDoubleVpnUpgradeLoop({
  required Future<DoubleVpnCutoverResult> Function() attempt,
  required bool Function() isCurrent,
  required bool Function() mayAttemptNow,
  required void Function(DoubleVpnUpgradePhase phase) onPhase,
  Duration Function(int consecutiveFailures) backoff = doubleVpnUpgradeBackoff,
  Duration busyRecheck = doubleVpnUpgradeBusyRecheck,
  Duration cancellationSlice = const Duration(milliseconds: 250),
  Duration initialDelay = Duration.zero,
  Future<void> Function(Duration delay)? sleep,
}) async {
  final pause = sleep ?? Future<void>.delayed;

  // Waits [delay] in slices so a cancellation ends the wait promptly.
  Future<bool> waitWhileCurrent(Duration delay) async {
    var remaining = delay;
    while (remaining > Duration.zero) {
      if (!isCurrent()) return false;
      final slice =
          remaining < cancellationSlice ? remaining : cancellationSlice;
      await pause(slice);
      remaining -= slice;
    }
    return isCurrent();
  }

  // A Double route the hub has just refused is not asked for again at once.
  if (!await waitWhileCurrent(initialDelay)) {
    return DoubleVpnUpgradeExit.cancelled;
  }
  var failures = 0;
  while (true) {
    if (!isCurrent()) return DoubleVpnUpgradeExit.cancelled;
    if (!mayAttemptNow()) {
      if (!await waitWhileCurrent(busyRecheck)) {
        return DoubleVpnUpgradeExit.cancelled;
      }
      continue;
    }
    final result = await attempt();
    switch (result) {
      case DoubleVpnCutoverResult.upgraded:
        onPhase(DoubleVpnUpgradePhase.none);
        return DoubleVpnUpgradeExit.upgraded;
      case DoubleVpnCutoverResult.lost:
        return DoubleVpnUpgradeExit.lost;
      case DoubleVpnCutoverResult.keptSingleHop:
      case DoubleVpnCutoverResult.restoredSingleHop:
        break;
    }
    if (!isCurrent()) return DoubleVpnUpgradeExit.cancelled;
    failures++;
    onPhase(DoubleVpnUpgradePhase.unavailable);
    if (!await waitWhileCurrent(backoff(failures))) {
      return DoubleVpnUpgradeExit.cancelled;
    }
  }
}

/// Shown on the dashboard while a session connected single hop on purpose and
/// its upgrade has not failed yet.
const String doubleVpnSingleHopPreparingNotice =
    'Single hop: connecting Double VPN... Your traffic goes through one '
    'server until it is ready.';

/// Shown once when a Double VPN connect commits on one hop first.
const String doubleVpnSingleHopPreparingMessage =
    'Connected through one server for now. Double VPN switches on '
    'automatically when it is ready.';

/// Shown once when the background upgrade commits the Double session.
const String doubleVpnUpgradedMessage = 'Double VPN is on.';
