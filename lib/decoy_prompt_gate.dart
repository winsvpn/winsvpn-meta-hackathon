/// Consent prompts that a flow can raise after an await, a timer or a
/// callback, while the decoy calculator may be covering the app.
///
/// [DecoyRouteGuard] (decoy_cover.dart) removes any route the decoy does not
/// own, and a removed dialog completes with null, which every caller reads as
/// "dismissed". For a consent the user never saw, that reading is wrong: the
/// flow that asked was cancelled, and nothing says the question is still
/// owed. This file keeps that question. A prompt the decoy blocked is
/// remembered, in memory only, and offered once after the next PIN unlock,
/// while it is still owed and still the same account session.
///
/// Pure Dart on purpose: the tests run it, and the main.dart glue that calls
/// it, without a widget tree.
library;

/// One prompt the decoy blocked, waiting for the next unlock.
///
/// Holds only the account session it was blocked in, never the prompt's
/// content: what to ask, and whether it is still owed, is decided again at
/// unlock time from live state. A remembered answer or a remembered error
/// would be a replay of stale state.
///
/// The decoy generation is deliberately not part of the record. A lifecycle
/// callback re-arms the decoy (one more generation) each time the app goes
/// inactive, including while the calculator is already showing, so equality
/// with the generation at blocking time would lose the prompt to an ordinary
/// second trip to the background. The generation binds the OFFER instead (see
/// main.dart, _offerDeferredLegalConsent): an offer stops the moment the
/// decoy comes back.
class DeferredPrompt {
  int? _accountEpoch;

  /// Whether a blocked prompt is waiting.
  bool get isPending => _accountEpoch != null;

  /// Remembers that a prompt was blocked in [accountEpoch]. Asking twice in
  /// one session leaves one record: the prompt is offered once.
  void defer({required int accountEpoch}) => _accountEpoch = accountEpoch;

  /// Whether a record is waiting for exactly [accountEpoch]. Does not consume
  /// it: an offer looks first, and consumes only when it goes ahead.
  bool isPendingFor(int accountEpoch) =>
      _accountEpoch != null && _accountEpoch == accountEpoch;

  /// Consumes the record. True only when one was waiting and it belongs to
  /// [accountEpoch]; a record from another account session is dropped, not
  /// carried over. Either way nothing is pending afterwards, so an offer is
  /// made once.
  bool take({required int accountEpoch}) {
    final held = _accountEpoch;
    _accountEpoch = null;
    return held != null && held == accountEpoch;
  }

  int _answers = 0;

  /// How many real answers (accept or refuse) a gated dialog has been given.
  /// An offer reads it before and after asking: it puts its record back after
  /// a lapse only when nothing was answered in between.
  int get answerCount => _answers;

  /// A dialog was really answered in [accountEpoch]. Whatever was blocked in
  /// that session has been decided by the user, in the connect's own dialog
  /// or the offer's, so nothing is owed any more: the record is dropped.
  void answered({required int accountEpoch}) {
    _answers++;
    take(accountEpoch: accountEpoch);
  }
}

/// Runs [present], the code that shows one consent dialog, so that it never
/// draws over the decoy and never reads a removal as a refusal.
///
/// * While [decoyShowing] holds, [present] is not called at all: nothing is
///   pushed, nothing is persisted, and the answer is false. The prompt is
///   deferred.
/// * A null answer from [present] while the decoy shows now is a dialog the
///   route guard (or the relock's own clear) removed, not a choice: deferred,
///   under the account session the dialog OPENED in. If the session changed
///   while it was open, the question belonged to a session that has ended and
///   is not deferred. A null with the app still unlocked is the system back
///   gesture on a dialog with no barrier dismissal, an ordinary refusal: not
///   deferred.
/// * A real answer (true or false) in the session the dialog opened in drops
///   any record: the user has decided, so the next unlock must not ask again.
/// * The answer is true only when the user pressed the accepting button.
///   Nothing here ever answers true for the user.
///
/// [present] returns true, false, or null for "removed or backed out".
Future<bool> runGatedConsentPrompt({
  required DeferredPrompt deferral,
  required bool Function() mounted,
  required bool Function() decoyShowing,
  required int Function() accountEpoch,
  required Future<bool?> Function() present,
}) async {
  if (!mounted()) return false;
  final openedIn = accountEpoch();
  if (decoyShowing()) {
    deferral.defer(accountEpoch: openedIn);
    return false;
  }
  final answer = await present();
  if (answer == null &&
      mounted() &&
      decoyShowing() &&
      accountEpoch() == openedIn) {
    deferral.defer(accountEpoch: openedIn);
  }
  if (answer != null && accountEpoch() == openedIn) {
    deferral.answered(accountEpoch: openedIn);
  }
  return answer == true;
}
