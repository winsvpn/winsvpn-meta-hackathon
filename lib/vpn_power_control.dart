import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'l10n/app_localizations.dart';
import 'owned_keyboard_listener.dart';

class VpnPowerControl extends StatelessWidget {
  const VpnPowerControl({
    super.key,
    required this.isConnected,
    required this.isConnectInFlight,
    required this.connectedColor,
    required this.disconnectedColor,
    required this.onPressed,
    this.radius = 42.0,
  });

  final bool isConnected;
  final bool isConnectInFlight;
  final Color connectedColor;
  final Color disconnectedColor;
  final VoidCallback onPressed;
  final double radius;

  /// Localised when the app's delegates are in scope; the English text is
  /// the fallback for a bare widget (tests, previews) without them.
  String semanticLabelFor(BuildContext context) {
    final strings = Localizations.of<AppLocalizations>(context, AppLocalizations);
    if (isConnectInFlight) {
      return strings?.cancelVpnConnectionAction ?? 'Cancel VPN connection';
    }
    return isConnected
        ? strings?.disconnectVpnAction ?? 'Disconnect VPN'
        : strings?.connectVpnAction ?? 'Connect VPN';
  }

  @override
  Widget build(BuildContext context) {
    final color =
        isConnected && !isConnectInFlight ? connectedColor : disconnectedColor;
    // TV D-pad: visible focus ring, handles select and directional focus.
    // This control is a GestureDetector (no Material focus), so we make it
    // focusable here and map select/enter to onPressed. The outer
    // FocusTraversalGroup in main.dart orders it (order 2), but this inner
    // decoration ensures the ring is visible even when the control is used
    // elsewhere (e.g. in VpnConnectTransitionView).
    return Focus(
      canRequestFocus: true,
      skipTraversal: false,
      onKeyEvent: (node, event) {
        if (event is KeyDownEvent &&
            (event.logicalKey == LogicalKeyboardKey.select ||
                event.logicalKey == LogicalKeyboardKey.enter ||
                event.logicalKey == LogicalKeyboardKey.gameButtonA ||
                event.logicalKey == LogicalKeyboardKey.space)) {
          onPressed();
          return KeyEventResult.handled;
        }
        if (event is KeyDownEvent &&
            (event.logicalKey == LogicalKeyboardKey.arrowUp ||
                event.logicalKey == LogicalKeyboardKey.arrowDown ||
                event.logicalKey == LogicalKeyboardKey.arrowLeft ||
                event.logicalKey == LogicalKeyboardKey.arrowRight)) {
          // Let Shortcuts/DirectonalFocusIntent handle movement. Returning
          // ignored allows the Shortcuts widget to map arrow keys to
          // DirectionalFocusIntent and move focus.
          return KeyEventResult.ignored;
        }
        return KeyEventResult.ignored;
      },
      child: Builder(
        builder: (context) {
          final focused = Focus.of(context).hasFocus;
          return Shortcuts(
            shortcuts: <LogicalKeySet, Intent>{
              LogicalKeySet(LogicalKeyboardKey.select): const ActivateIntent(),
              LogicalKeySet(LogicalKeyboardKey.enter): const ActivateIntent(),
              LogicalKeySet(LogicalKeyboardKey.gameButtonA): const ActivateIntent(),
              LogicalKeySet(LogicalKeyboardKey.arrowUp):
                  const DirectionalFocusIntent(TraversalDirection.up),
              LogicalKeySet(LogicalKeyboardKey.arrowDown):
                  const DirectionalFocusIntent(TraversalDirection.down),
              LogicalKeySet(LogicalKeyboardKey.arrowLeft):
                  const DirectionalFocusIntent(TraversalDirection.left),
              LogicalKeySet(LogicalKeyboardKey.arrowRight):
                  const DirectionalFocusIntent(TraversalDirection.right),
              LogicalKeySet(LogicalKeyboardKey.escape): const DismissIntent(),
              LogicalKeySet(LogicalKeyboardKey.goBack): const DismissIntent(),
            },
            child: Actions(
              actions: <Type, Action<Intent>>{
                ActivateIntent: CallbackAction<ActivateIntent>(
                  onInvoke: (intent) {
                    onPressed();
                    return null;
                  },
                ),
                DirectionalFocusIntent: DirectionalFocusAction(),
                DismissIntent: CallbackAction<DismissIntent>(
                  onInvoke: (intent) => null,
                ),
              },
              child: OwnedKeyboardListener(
                onKeyEvent: (event) {},
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 120),
                  decoration: focused
                      ? BoxDecoration(
                          shape: BoxShape.circle,
                          border: Border.all(
                              color: const Color(0xFFFFD21F), width: 3.5),
                          boxShadow: [
                            BoxShadow(
                              color: const Color(0xFFFFD21F).withValues(alpha: 0.55),
                              blurRadius: 16,
                              spreadRadius: 1,
                            ),
                          ],
                        )
                      : const BoxDecoration(shape: BoxShape.circle),
                  child: Semantics(
                    button: true,
                    label: semanticLabelFor(context),
                    excludeSemantics: true,
                    onTap: onPressed,
                    child: GestureDetector(
                      behavior: HitTestBehavior.opaque,
                      excludeFromSemantics: true,
                      onTap: onPressed,
                      child: Container(
                        width: radius * 2,
                        height: radius * 2,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: color.withValues(alpha: 0.12),
                          border: Border.all(
                            color: color.withValues(alpha: 0.38),
                            width: 2.2,
                          ),
                          boxShadow: [
                            BoxShadow(
                              color: color.withValues(alpha: 0.15),
                              blurRadius: 10,
                              spreadRadius: 1,
                            ),
                          ],
                        ),
                        child: Center(
                          child: Icon(
                            isConnectInFlight ? Icons.close : Icons.power_settings_new,
                            size: radius * 0.85,
                            color: color,
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}

class VpnConnectTransitionView extends StatelessWidget {
  const VpnConnectTransitionView({
    super.key,
    required this.status,
    required this.connectedColor,
    required this.disconnectedColor,
    required this.onCancel,
  });

  final String status;
  final Color connectedColor;
  final Color disconnectedColor;
  final VoidCallback onCancel;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      container: true,
      explicitChildNodes: true,
      label: Localizations.of<AppLocalizations>(context, AppLocalizations)
              ?.vpnConnectionInProgress ??
          'VPN connection in progress',
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 18),
            Text(
              status,
              textAlign: TextAlign.center,
              style: const TextStyle(color: Colors.black54, fontSize: 12),
            ),
            const SizedBox(height: 18),
            VpnPowerControl(
              isConnected: false,
              isConnectInFlight: true,
              connectedColor: connectedColor,
              disconnectedColor: disconnectedColor,
              onPressed: onCancel,
            ),
            // The label cancels too: it reads as a button, and a label that
            // ignores the tap reads as a cancel that failed. It is excluded
            // from semantics and adds no focus node, so it is meant to add no
            // second cancel control for a screen reader or a TV D-pad. What is
            // tested is narrower: one "Cancel VPN connection" semantics label
            // remains. Assistive-technology and D-pad behaviour were not
            // exercised.
            GestureDetector(
              behavior: HitTestBehavior.opaque,
              excludeFromSemantics: true,
              onTap: onCancel,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 10, 16, 10),
                child: Text(
                  Localizations.of<AppLocalizations>(context, AppLocalizations)
                          ?.cancelConnectionAction ??
                      'Cancel connection',
                  style: const TextStyle(color: Colors.black54, fontSize: 12),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
