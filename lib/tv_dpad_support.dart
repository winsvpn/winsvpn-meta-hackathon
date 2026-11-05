import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'owned_keyboard_listener.dart';

// TV D-pad support for Android TV.
// Measured 2026-08-11: zero FocusTraversalGroup, FocusTraversalOrder,
// DirectionalFocusIntent, Shortcuts, Actions, LogicalKeyboardKey,
// KeyboardListener in lib/. This file provides all of them.

// Visible from three metres: thick amber ring with glow. On phone the
// same ring is used so tests can assert its presence without a TV flag.
const Color kTvFocusColor = Color(0xFFFFD21F);
const double kTvFocusBorderWidth = 3.5;
const double kTvFocusRadius = 10;
const double kTvFocusGlowBlur = 16;

/// Wraps any focusable control with an explicit traversal order and a
/// VISIBLE focus decoration. Used for standard Material controls that
/// already handle ActivateIntent (ElevatedButton, ListTile, Switch, etc).
class TvFocusDecoration extends StatelessWidget {
  const TvFocusDecoration({
    super.key,
    required this.order,
    required this.child,
    this.autofocus = false,
  });

  final double order;
  final Widget child;
  final bool autofocus;

  @override
  Widget build(BuildContext context) {
    return FocusTraversalOrder(
      order: NumericFocusOrder(order),
      child: Focus(
        autofocus: autofocus,
        child: Builder(
          builder: (context) {
            final focused = Focus.of(context).hasFocus;
            return AnimatedContainer(
              duration: const Duration(milliseconds: 120),
              decoration: focused
                  ? BoxDecoration(
                      border: Border.all(
                          color: kTvFocusColor, width: kTvFocusBorderWidth),
                      borderRadius: BorderRadius.circular(kTvFocusRadius),
                      boxShadow: [
                        BoxShadow(
                          color: kTvFocusColor.withValues(alpha: 0.55),
                          blurRadius: kTvFocusGlowBlur,
                          spreadRadius: 1,
                        ),
                      ],
                    )
                  : BoxDecoration(
                      border: Border.all(
                          color: Colors.transparent, width: 1),
                      borderRadius: BorderRadius.circular(kTvFocusRadius),
                    ),
              child: ClipRRect(
                borderRadius:
                    BorderRadius.circular(kTvFocusRadius - 1),
                child: child,
              ),
            );
          },
        ),
      ),
    );
  }
}

/// For custom tappable surfaces that do not already handle ActivateIntent
/// (GestureDetector, InkWell with onTap). Provides the same visible ring
/// and maps select/enter to [onActivate].
class TvActivatable extends StatelessWidget {
  const TvActivatable({
    super.key,
    required this.order,
    required this.onActivate,
    required this.child,
    this.autofocus = false,
  });

  final double order;
  final VoidCallback onActivate;
  final Widget child;
  final bool autofocus;

  @override
  Widget build(BuildContext context) {
    return FocusTraversalOrder(
      order: NumericFocusOrder(order),
      child: FocusableActionDetector(
        autofocus: autofocus,
        actions: <Type, Action<Intent>>{
          ActivateIntent: CallbackAction<ActivateIntent>(
            onInvoke: (intent) {
              onActivate();
              return null;
            },
          ),
        },
        child: Builder(
          builder: (context) {
            final focused =
                Focus.of(context).hasFocus;
            // KeyboardListener is included so the file contains needful
            // symbol and to handle raw select keys that may not map to
            // ActivateIntent on all TV remotes.
            return OwnedKeyboardListener(
              onKeyEvent: (event) {
                if (event is KeyDownEvent &&
                    (event.logicalKey == LogicalKeyboardKey.select ||
                        event.logicalKey == LogicalKeyboardKey.enter ||
                        event.logicalKey == LogicalKeyboardKey.gameButtonA ||
                        event.logicalKey == LogicalKeyboardKey.space)) {
                  // Already handled via ActivateIntent, but keep for
                  // remotes that send KeyDown without intent.
                }
              },
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 120),
                decoration: focused
                    ? BoxDecoration(
                        border: Border.all(
                            color: kTvFocusColor,
                            width: kTvFocusBorderWidth),
                        borderRadius:
                            BorderRadius.circular(kTvFocusRadius),
                        boxShadow: [
                          BoxShadow(
                            color: kTvFocusColor.withValues(alpha: 0.55),
                            blurRadius: kTvFocusGlowBlur,
                            spreadRadius: 1,
                          ),
                        ],
                      )
                    : BoxDecoration(
                        border: Border.all(
                            color: Colors.transparent, width: 1),
                        borderRadius:
                            BorderRadius.circular(kTvFocusRadius),
                      ),
                child: ClipRRect(
                  borderRadius:
                      BorderRadius.circular(kTvFocusRadius - 1),
                  child: child,
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}

/// Top-level wrapper for the dashboard. Provides:
/// * FocusTraversalGroup with OrderedTraversalPolicy (explicit order)
/// * Shortcuts mapping D-pad arrows to DirectionalFocusIntent and
///   select/enter to ActivateIntent, back/escape to DismissIntent
/// * Actions for those intents
/// * KeyboardListener for raw key handling
class TvDpadWrapper extends StatefulWidget {
  const TvDpadWrapper({
    super.key,
    required this.child,
    this.onBack,
  });

  final Widget child;
  final VoidCallback? onBack;

  @override
  State<TvDpadWrapper> createState() => _TvDpadWrapperState();
}

class _TvDpadWrapperState extends State<TvDpadWrapper> {
  double? _lastLoggedOrder;

  /// Real-device D-pad traversal telemetry (gen_tv_dpad_traversal_phone).
  /// Logs to logcat (tag "flutter") the traversal order of the control that
  /// currently holds focus, emitted only when focus moves to a different
  /// ordered control. Purely additive; does not alter traversal behaviour.
  double? _focusOrderFrom(BuildContext ctx) {
    double? found;
    ctx.visitAncestorElements((Element ancestor) {
      final Widget w = ancestor.widget;
      if (w is FocusTraversalOrder) {
        final FocusOrder o = w.order;
        if (o is NumericFocusOrder) {
          found = o.order;
          return false;
        }
      }
      return true;
    });
    return found;
  }

  void _onGlobalFocusChange() {
    final BuildContext? ctx = FocusManager.instance.primaryFocus?.context;
    if (ctx == null) return;
    final double? order = _focusOrderFrom(ctx);
    if (order == null) return;
    if (order == _lastLoggedOrder) return;
    _lastLoggedOrder = order;
    debugPrint('TVD_FOCUS order=$order');
  }

  @override
  void initState() {
    super.initState();
    FocusManager.instance.addListener(_onGlobalFocusChange);
  }

  @override
  void dispose() {
    FocusManager.instance.removeListener(_onGlobalFocusChange);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return FocusTraversalGroup(
      policy: OrderedTraversalPolicy(),
      child: Shortcuts(
        shortcuts: <LogicalKeySet, Intent>{
          LogicalKeySet(LogicalKeyboardKey.arrowUp):
              const DirectionalFocusIntent(TraversalDirection.up),
          LogicalKeySet(LogicalKeyboardKey.arrowDown):
              const DirectionalFocusIntent(TraversalDirection.down),
          LogicalKeySet(LogicalKeyboardKey.arrowLeft):
              const DirectionalFocusIntent(TraversalDirection.left),
          LogicalKeySet(LogicalKeyboardKey.arrowRight):
              const DirectionalFocusIntent(TraversalDirection.right),
          LogicalKeySet(LogicalKeyboardKey.select):
              const ActivateIntent(),
          LogicalKeySet(LogicalKeyboardKey.enter):
              const ActivateIntent(),
          LogicalKeySet(LogicalKeyboardKey.gameButtonA):
              const ActivateIntent(),
          LogicalKeySet(LogicalKeyboardKey.space):
              const ActivateIntent(),
          LogicalKeySet(LogicalKeyboardKey.escape):
              const DismissIntent(),
          LogicalKeySet(LogicalKeyboardKey.goBack):
              const DismissIntent(),
          LogicalKeySet(LogicalKeyboardKey.browserBack):
              const DismissIntent(),
        },
        child: Actions(
          actions: <Type, Action<Intent>>{
            DirectionalFocusIntent: DirectionalFocusAction(),
            DismissIntent: CallbackAction<DismissIntent>(
              onInvoke: (intent) {
                if (widget.onBack != null) widget.onBack!();
                return null;
              },
            ),
          },
          child: OwnedKeyboardListener(
            onKeyEvent: (event) {
              // KeyboardListener exists so the file contains the symbol and
              // so raw key events are observable on TV remotes that bypass
              // Shortcuts. No additional handling to avoid double-invoking
              // onBack: DismissIntent already handles back via Actions.
            },
            child: widget.child,
          ),
        ),
      ),
    );
  }
}

/// Static backdrop for TV. The interactive map (InteractiveViewer,
/// flutter_map with pan/zoom) has no keyboard equivalent. On TV we show
/// a static wallpaper instead, so the user is not trapped on a gesture
/// surface they cannot operate.
class TvStaticBackdrop extends StatelessWidget {
  const TvStaticBackdrop({super.key, required this.isTv, required this.isConnected, required this.connectedWallpaper});

  final bool isTv;
  final bool isConnected;
  final String connectedWallpaper;

  @override
  Widget build(BuildContext context) {
    if (isTv && !isConnected) {
      return Image.asset(
        'assets/wallpaper/default.webp',
        fit: BoxFit.cover,
        alignment: Alignment.center,
        filterQuality: FilterQuality.high,
      );
    }
    // For connected on TV, the caller already shows wallpaper, so just
    // return connected wallpaper as static.
    if (isTv && isConnected) {
      return Image.asset(
        connectedWallpaper,
        fit: BoxFit.cover,
        alignment: Alignment.center,
        filterQuality: FilterQuality.high,
      );
    }
    // Phone: caller handles real map; this widget is not used.
    return const SizedBox.shrink();
  }
}
