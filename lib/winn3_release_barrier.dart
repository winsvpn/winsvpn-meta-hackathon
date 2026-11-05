/// Round L (OI-L4): the release-completion barrier for a held Winn v3 session.
///
/// A held reconnect or held server switch stops the held tunnel and then
/// prepares a new one. Preparation needs the control plane, and the held
/// capture is a blackhole for this app's own requests as well, so nothing may
/// be prepared until the old capture is known to be gone. The only evidence
/// accepted is the native host's release acknowledgement (Android:
/// `WinnV3ReleaseLedger`, published in `getTunnelReadiness`), bound to the
/// hold this app saw before it asked for the stop:
///
/// - `winn3_hold_id` names the outstanding hold, and a mark is taken only
///   while that hold is published as held;
/// - `winn3_release_sequence` must have advanced past the mark, so an
///   acknowledgement from before the request cannot count;
/// - `winn3_release_hold_id` must be the marked hold, so another hold's
///   release cannot count;
/// - `winn3_release_disposition` must be `closed`, with `interface_open`
///   false in the same reading.
///
/// A false `active` flag, a missing field, a failed query, an `incomplete`
/// pass and a timeout are all NOT a release. A configured kill switch that
/// keeps its block is a known outcome, and it is not a release either.
///
/// Pure Dart on purpose: the transaction tests execute the production code
/// that uses it outside Flutter.
library;

/// The hold a release must end, taken from one readiness reading before the
/// stop is requested.
class Winn3ReleaseMark {
  const Winn3ReleaseMark({required this.holdId, required this.sequence});

  final int holdId;
  final int sequence;

  @override
  bool operator ==(Object other) =>
      other is Winn3ReleaseMark &&
      other.holdId == holdId &&
      other.sequence == sequence;

  @override
  int get hashCode => Object.hash(holdId, sequence);

  @override
  String toString() => 'Winn3ReleaseMark(hold=$holdId, sequence=$sequence)';
}

enum Winn3ReleaseOutcome {
  /// The marked hold's interface was closed.
  released,

  /// The owner's kill switch kept the interface as a block. Not a release.
  killSwitchBlock,

  /// The hold ended some other way (a new connect took it over), or no
  /// acknowledgement arrived in time. Not a release.
  notReleased,
}

/// The stop request plus the release polling, measured on a monotonic clock:
/// nothing is prepared after this has passed without a proven release. It is
/// not a bound on the whole UI operation: the reconciliation read that follows
/// an unproven release, and the connect that follows a proven one, come after
/// it. It leaves room for a teardown pass that waits out its bridge closes
/// (up to 6 s each) and the native engine-retirement wait (5 s); a pass that
/// takes longer simply ends as not released.
const Duration winn3ReleaseDeadline = Duration(seconds: 20);

/// One readiness reading is cut to this, or to the time left if less.
const Duration winn3ReleaseReadTimeout = Duration(seconds: 3);

/// The pause between readings, or the time left if less.
const Duration winn3ReleasePollInterval = Duration(milliseconds: 250);

/// A mark for the hold [readiness] describes, or null when there is nothing
/// to bind a release to (no ledger fields, no outstanding hold, capture not
/// published as held, or no reading at all).
Winn3ReleaseMark? winn3ReleaseMarkFromReadiness(Map<dynamic, dynamic>? readiness) {
  if (readiness == null) return null;
  final holdId = readiness['winn3_hold_id'];
  final sequence = readiness['winn3_release_sequence'];
  if (holdId is! int || sequence is! int || holdId <= 0) return null;
  if (readiness['winn3_capture_held'] != true) return null;
  return Winn3ReleaseMark(holdId: holdId, sequence: sequence);
}

/// The outcome [readiness] proves for [mark], or null while it proves nothing
/// yet (keep waiting).
Winn3ReleaseOutcome? winn3ReleaseOutcome(
  Winn3ReleaseMark mark,
  Map<dynamic, dynamic>? readiness,
) {
  if (readiness == null) return null;
  final sequence = readiness['winn3_release_sequence'];
  final lastHold = readiness['winn3_release_hold_id'];
  final disposition = readiness['winn3_release_disposition'];
  if (sequence is! int || lastHold is! int || disposition is! String) {
    return null;
  }
  if (sequence <= mark.sequence || lastHold != mark.holdId) return null;
  switch (disposition) {
    case 'closed':
      return readiness['interface_open'] == false
          ? Winn3ReleaseOutcome.released
          : null;
    case 'kill_switch_block':
      return Winn3ReleaseOutcome.killSwitchBlock;
    case 'superseded':
      return Winn3ReleaseOutcome.notReleased;
    default:
      // `incomplete`, or a second holding pass over the same interface: a
      // later pass may still close it.
      return null;
  }
}

const String winn3ReleaseUnconfirmedMessage =
    'Could not confirm that the held tunnel was released, so nothing new was '
    'started. Traffic may still be held. Disconnect, then connect again.';

const String winn3ReleaseKillSwitchMessage =
    'Your kill switch is keeping traffic blocked, so nothing new was started. '
    'Disconnect, then connect again.';

const String winn3HeldSwitchChangedMessage =
    'The tunnel changed while you were deciding. Pick the server again.';
