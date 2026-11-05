/// What must go before the decoy calculator covers the app, and what may not
/// appear while it does.
///
/// The decoy is a body swap: `_showDecoyCalculator` makes the dashboard's
/// build return the calculator view. Anything that lives outside that body
/// survives the swap and stays on top of the calculator: the root
/// [ScaffoldMessenger]'s snack bars and material banners (a shown snack bar
/// stays until its duration ends or it is removed), and every route above the
/// root navigator's first one (dialogs, bottom sheets, pickers, pushed
/// pages). A Win's VPN message over a calculator gives the disguise away.
///
/// Two halves:
/// * [clearProductSurfacesForDecoy] removes what exists when the decoy is
///   armed, with no exit animation;
/// * [DecoyRouteGuard], the root navigator's observer, removes any route
///   pushed while the decoy shows, whichever continuation, timer or callback
///   pushed it. Only routes the decoy itself owns ([kDecoyRoutePrefix]) stay.
library;

import 'dart:async';

import 'package:flutter/material.dart';

/// Whether the decoy calculator is covering the app. The dashboard's
/// `_showDecoyCalculator` reads and writes exactly this, so the route guard
/// sees each change the moment it is made, not a frame later.
bool decoyCoverActive = false;

/// Route names under this prefix belong to the decoy itself (the keypad's own
/// popup) and are never removed.
const String kDecoyRoutePrefix = 'decoy/';

/// Whether [route] is one the decoy owns.
bool isDecoyOwnedRoute(Route<dynamic> route) =>
    (route.settings.name ?? '').startsWith(kDecoyRoutePrefix);

/// The root navigator's route choke point while the decoy shows.
///
/// A route pushed above the navigator's first route while [decoyShowing]
/// holds, and not owned by the decoy, is removed with
/// [NavigatorState.removeRoute]: no transition runs, and the future returned
/// by the push completes with null (read by every caller as dismissed). The
/// removal runs in a microtask queued from [didPush], because the navigator
/// is still flushing that push and [NavigatorState.removeRoute] asserts
/// against re-entry; a microtask runs before the engine can deliver another
/// frame.
///
/// It also keeps the navigator's current routes, so
/// [clearProductSurfacesForDecoy] can remove the ones above the first with no
/// exit transition.
class DecoyRouteGuard extends NavigatorObserver {
  DecoyRouteGuard({bool Function()? decoyShowing})
      : decoyShowing = decoyShowing ?? (() => decoyCoverActive);

  final bool Function() decoyShowing;
  final List<Route<dynamic>> _routes = <Route<dynamic>>[];

  /// The navigator's current routes, bottom first.
  List<Route<dynamic>> get routes => List<Route<dynamic>>.unmodifiable(_routes);

  @override
  void didPush(Route<dynamic> route, Route<dynamic>? previousRoute) {
    _routes.add(route);
    if (previousRoute == null) return; // the navigator's first route
    if (!decoyShowing() || isDecoyOwnedRoute(route)) return;
    scheduleMicrotask(() {
      if (decoyShowing() && _routes.contains(route)) _remove(route);
    });
  }

  @override
  void didPop(Route<dynamic> route, Route<dynamic>? previousRoute) {
    _routes.remove(route);
  }

  @override
  void didRemove(Route<dynamic> route, Route<dynamic>? previousRoute) {
    _routes.remove(route);
  }

  @override
  void didReplace({Route<dynamic>? newRoute, Route<dynamic>? oldRoute}) {
    final at = oldRoute == null ? -1 : _routes.indexOf(oldRoute);
    if (at >= 0 && newRoute != null) {
      _routes[at] = newRoute;
    } else {
      if (oldRoute != null) _routes.remove(oldRoute);
      if (newRoute != null) _routes.add(newRoute);
    }
  }

  /// Removes every route above the first, topmost first, with no exit
  /// transition. Returns false when the guard is not attached to a
  /// navigator.
  bool removeRoutesAboveFirst() {
    if (navigator == null) return false;
    for (final route in _routes.skip(1).toList().reversed) {
      _remove(route);
    }
    return true;
  }

  void _remove(Route<dynamic> route) {
    final nav = navigator;
    if (nav == null || !nav.mounted || !route.isActive) return;
    nav.removeRoute(route);
  }
}

/// The app's root navigator observer (MaterialApp.navigatorObservers).
final DecoyRouteGuard decoyRouteGuard = DecoyRouteGuard();

/// Removes those surfaces, immediately and with no exit animation. Every
/// path that sets the decoy calls this first.
void clearProductSurfacesForDecoy(BuildContext context,
    {DecoyRouteGuard? guard}) {
  final messenger = ScaffoldMessenger.maybeOf(context);
  if (messenger != null) {
    // clearSnackBars drops the queue and keeps only the current snack bar,
    // hiding it; removeCurrentSnackBar then removes that one at once. The
    // same pair for material banners.
    messenger.clearSnackBars();
    messenger.removeCurrentSnackBar();
    messenger.clearMaterialBanners();
    messenger.removeCurrentMaterialBanner();
  }
  // Routes go with no exit transition. Without an attached guard (never the
  // app, which registers decoyRouteGuard) the fallback pops, which animates.
  if (!(guard ?? decoyRouteGuard).removeRoutesAboveFirst()) {
    Navigator.maybeOf(context, rootNavigator: true)
        ?.popUntil((route) => route.isFirst);
  }
}
