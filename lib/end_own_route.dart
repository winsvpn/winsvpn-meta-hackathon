/// Ends the dialog or bottom sheet a context was built in, and never any other
/// route.
///
/// Moved from main.dart's _endOwnDialog (Round F3) so the duress enrollment
/// dialog, which lives in its own library, and the account-deletion sheet end
/// through the same route-bound rule as the eight consent and PIN dialogs.
/// main.dart's _endOwnDialog delegates here.
library;

import 'package:flutter/widgets.dart';

/// Ends the route that [routeContext] was built in, with [result], and never
/// any other route. An answer that arrives after an await goes through this,
/// never through a bare Navigator.pop, which ends whatever route is on top
/// when it runs.
///
/// `routeContext.mounted` does not show that the route is still the one on
/// screen: a popped route stays mounted until its exit animation ends, and
/// its future has already completed. A Save whose write outlived the dialog's
/// "Not now" (or a back gesture) would otherwise pop a consent dialog
/// presented in that window, with true, and record consent that nobody gave.
/// So the route is checked, not the context:
/// * still the top route: popped with [result], as before;
/// * still on the navigator, under a newer route: removed alone, with
///   [result]; the route above is not touched;
/// * already ended (popped, removed, or animating out): nothing at all.
///
/// [T] must be the type argument the route was shown with (`showDialog<T>`,
/// `showModalBottomSheet<T>`); any other type throws a TypeError from
/// `ModalRoute.of`. Returns whether the route was ended here.
bool endOwnRoute<T>(BuildContext routeContext, [T? result]) {
  if (!routeContext.mounted) return false;
  final route = ModalRoute.of<T>(routeContext);
  if (route == null || !route.isActive) return false;
  final navigator = Navigator.of(routeContext);
  if (route.isCurrent) {
    navigator.pop<T>(result);
  } else {
    navigator.removeRoute<T>(route, result);
  }
  return true;
}
