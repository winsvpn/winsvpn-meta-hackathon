import 'package:flutter/material.dart';

import 'apple_tunnel_diagnostics.dart';

/// Round A3: the Winn v3 engine's CURRENT lifecycle as the native host
/// publishes it after promotion, read from `getTunnelReadiness`.
///
/// This is deliberately separate from the historical start verdict
/// (`winn3_verdict`, `winn3_start_state`) and from the cover authorization
/// token: nothing here is read by `winn3_cover_fallback.dart`, and nothing
/// here can authorise AmneziaWG, Xray or any other protocol. It decides only
/// what the app may CLAIM and which controls stay available.
///
/// Android publishes it under `winn3_*` keys from `VpnTunnelService`'s
/// lifecycle board. Apple publishes the host verdict under
/// `provider_winn3_recovery_*`, forwarded by the app bridge from
/// `WinsWinnSeamObservabilitySample.publishedStatusKeys`.
enum Winn3HostLifecycleState {
  /// No supervised lifecycle is published: a non-v3 engine, an engine older
  /// than the field, or no session. The platform's own readiness rules apply.
  none,

  /// The engine has proven delivery on its current round.
  connected,

  /// The engine is rebuilding its session in place; the tunnel and its
  /// capture are kept and nothing is claimed.
  recovering,

  /// The engine stopped trying, or this host stopped waiting, or the promoted
  /// session ended without reporting why. The user must act.
  blocked,
}

@immutable
class Winn3HostLifecycleView {
  const Winn3HostLifecycleView({
    required this.state,
    this.captureHeld = false,
    this.observer = '',
    this.cause = '',
    this.limitation = '',
  });

  static const Winn3HostLifecycleView none =
      Winn3HostLifecycleView(state: Winn3HostLifecycleState.none);

  final Winn3HostLifecycleState state;

  /// The tunnel's capture is still installed (traffic is held, not leaked).
  final bool captureHeld;

  /// Who observed a blocked end: `engine`, `recovery_ceiling`,
  /// `session_ended`, `invalid_status` or `invalid_transition`. Empty
  /// otherwise.
  final String observer;

  /// The engine's own `lifecycle_cause`, when the engine reported blocked.
  final String cause;

  /// A platform limitation on the hold, when there is one.
  final String limitation;

  /// A session exists and holds capture, but is not proven connected: the UI
  /// must not paint connected, and must keep Disconnect and Reconnect usable.
  bool get holdsSession =>
      captureHeld &&
      (state == Winn3HostLifecycleState.recovering ||
          state == Winn3HostLifecycleState.blocked);

  bool get actionRequired => state == Winn3HostLifecycleState.blocked;

  /// Capture a promoted session was owed was released, and the native host
  /// said why (the disguise refused the hold's notification, no interface
  /// could be held, the service was destroyed, or VPN permission was
  /// withdrawn while the hold was being built).
  bool get releasedWithLimitation =>
      state == Winn3HostLifecycleState.blocked &&
      !captureHeld &&
      limitation.isNotEmpty;

  /// Something for the dashboard to say, or null when nothing applies.
  String? statusLine(String Function(String) t) {
    if (releasedWithLimitation) {
      final String why;
      switch (limitation) {
        case 'disguise_refused_notification':
          why = t('The disguise could not show the notification Android '
              'needs to keep traffic held.');
          break;
        case 'vpn_permission_revoked':
          why = t('VPN permission was withdrawn.');
          break;
        case 'service_destroyed':
          why = t('The VPN service was closed.');
          break;
        default:
          why = t('Android could not keep traffic held.');
      }
      return '${t('The tunnel stopped and traffic is no longer held.')} $why '
          '${t('Traffic may now leave outside the VPN. Connect again.')}';
    }
    if (!holdsSession) return null;
    if (state == Winn3HostLifecycleState.recovering) {
      return t('Reconnecting... Traffic is held until the tunnel is back.');
    }
    final String head;
    switch (observer) {
      case 'recovery_ceiling':
        head = t('Reconnecting is taking too long.');
        break;
      case 'session_ended':
        head = t('The tunnel stopped.');
        break;
      case 'invalid_status':
        head = t('The tunnel reported a state this app does not recognise.');
        break;
      case 'invalid_transition':
        head = t('The tunnel reported a change this app does not accept.');
        break;
      default:
        head = t('Could not reconnect.');
    }
    final tail = limitation == 'foreground_refresh_failed'
        ? t(' Traffic is held, but Android may end the hold.')
        : t(' Traffic is held.');
    return '$head$tail ${t('Reconnect or disconnect.')}';
  }

  @override
  bool operator ==(Object other) =>
      other is Winn3HostLifecycleView &&
      other.state == state &&
      other.captureHeld == captureHeld &&
      other.observer == observer &&
      other.cause == cause &&
      other.limitation == limitation;

  @override
  int get hashCode => Object.hash(state, captureHeld, observer, cause, limitation);

  @override
  String toString() => 'Winn3HostLifecycleView($state, held=$captureHeld, '
      'observer=$observer, cause=$cause, limitation=$limitation)';
}

/// The closed vocabulary. A value outside it is `blocked`, which is what the
/// engine's driver requires of a host that meets an unknown value.
Winn3HostLifecycleState _stateFromWire(Object? value) {
  switch (value) {
    case 'connected':
      return Winn3HostLifecycleState.connected;
    case 'recovering':
      return Winn3HostLifecycleState.recovering;
    case 'blocked':
      return Winn3HostLifecycleState.blocked;
    default:
      return Winn3HostLifecycleState.blocked;
  }
}

String _string(Map<dynamic, dynamic> readiness, String key) {
  final value = readiness[key];
  return value is String ? value : '';
}

/// Reads the host lifecycle out of one `getTunnelReadiness` map.
Winn3HostLifecycleView winn3HostLifecycleFromReadiness(
  Map<dynamic, dynamic>? readiness, {
  required bool apple,
}) {
  if (readiness == null) return Winn3HostLifecycleView.none;
  return apple ? _fromApple(readiness) : _fromAndroid(readiness);
}

Winn3HostLifecycleView _fromAndroid(Map<dynamic, dynamic> readiness) {
  if (!readiness.containsKey('winn3_lifecycle')) {
    return Winn3HostLifecycleView.none;
  }
  // Capture is held only while the interface the service kept is open.
  final held = readiness['winn3_capture_held'] == true &&
      readiness['interface_open'] == true;
  return Winn3HostLifecycleView(
    state: _stateFromWire(readiness['winn3_lifecycle']),
    captureHeld: held,
    observer: _string(readiness, 'winn3_lifecycle_observer'),
    cause: _string(readiness, 'winn3_lifecycle_cause'),
    limitation: _string(readiness, 'winn3_hold_limitation'),
  );
}

Winn3HostLifecycleView _fromApple(Map<dynamic, dynamic> readiness) {
  final raw = readiness['provider_winn3_recovery_state'];
  if (raw == null || raw == 'unreported' || raw == 'not_live') {
    return Winn3HostLifecycleView.none;
  }
  // A stale or foreign provider document describes no current session, and
  // capture exists only while the system tunnel is connected.
  final current = appleReadinessBool(readiness, 'active') &&
      appleTunnelProviderStatusCurrent(readiness);
  if (!current) return Winn3HostLifecycleView.none;
  return Winn3HostLifecycleView(
    state: _stateFromWire(raw),
    captureHeld:
        appleReadinessBool(readiness, 'provider_winn3_recovery_capture_held'),
    observer: _string(readiness, 'provider_winn3_recovery_observer'),
    cause: _string(readiness, 'provider_winn3_recovery_cause'),
  );
}

/// What `_readNativeTunnelActive()` reports, kept apart by purpose.
///
/// A held Winn v3 session is a SESSION (the controls stay Disconnect and
/// Reconnect) with capture in CUSTODY (traffic is held), and it is NOT a
/// connected tunnel: it has no connected proof. Callers that decide what is
/// claimed (the green headline, the "secured" label, the Apple smoke
/// diagnostics) must read [connectedProof]; callers that decide whether a
/// session exists read [sessionExists].
@immutable
class Winn3NativeTunnelReading {
  const Winn3NativeTunnelReading({
    required this.sessionExists,
    required this.heldSession,
  });

  /// A tunnel session exists: connected-proven, or held.
  final bool sessionExists;

  /// The session exists and holds capture without connected proof.
  final bool heldSession;

  /// Current connected proof: a session that is not merely held.
  bool get connectedProof => sessionExists && !heldSession;
}

/// Shown beside Reconnect. Reconnect stops the tunnel and starts a new one;
/// between the two the capture is released. The interval is not measured, so
/// nothing here claims it is short.
const String winn3ReconnectReleaseDisclosure =
    'Reconnect stops this tunnel before it starts a new one. Until the new '
    'one is up, traffic is no longer held and may leave outside the VPN.';

const String winn3ManualRecoveryDisclosure =
    'Traffic is held. Disconnect before connecting again or choosing another '
    'server. Disconnecting releases the hold, so traffic may leave outside '
    'the VPN.';

/// Whether a server the user picks must first release a held session.
///
/// The ordinary switch keeps the old route up while it prepares the new
/// server, and preparation needs the control plane. A held session's capture
/// is a blackhole that also takes the app's own requests, so preparation
/// through it can only time out (measured on an S26, 2026-09-23: "Switching
/// VPN server..." never completed). Picking a server is the owner acting, so
/// the pick releases the hold, after the disclosure below, and connects the
/// same way the banner's Reconnect does. Nothing bypasses the capture.
bool winn3ServerSwitchMustReleaseHold(Winn3HostLifecycleView lifecycle) =>
    lifecycle.holdsSession;

/// Shown before a server pick releases a held session.
const String winn3ServerSwitchReleaseDisclosure =
    'Traffic is held because the tunnel stopped. Switching server stops this '
    'tunnel before it starts the new one. Until the new one is up, traffic is '
    'no longer held and may leave outside the VPN.';

/// The dashboard line and the two controls for a held Winn v3 session.
class Winn3HostLifecycleBanner extends StatelessWidget {
  const Winn3HostLifecycleBanner({
    super.key,
    required this.lifecycle,
    required this.translate,
    required this.enabled,
    required this.onDisconnect,
    required this.onReconnect,
    this.reconnectAvailable = true,
    this.color = Colors.orangeAccent,
  });

  final Winn3HostLifecycleView lifecycle;
  final String Function(String) translate;
  final bool enabled;
  final VoidCallback onDisconnect;
  final VoidCallback onReconnect;
  final bool reconnectAvailable;
  final Color color;

  @override
  Widget build(BuildContext context) {
    final line = lifecycle.statusLine(translate);
    if (line == null) return const SizedBox.shrink();
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          lifecycle.holdsSession && !reconnectAvailable
              ? translate(winn3ManualRecoveryDisclosure)
              : line,
          key: const Key('winn3_host_lifecycle_status'),
          textAlign: TextAlign.center,
          style: TextStyle(color: color, fontSize: 12),
        ),
        if (lifecycle.holdsSession)
          Text(
            translate(
              reconnectAvailable
                  ? winn3ReconnectReleaseDisclosure
                  : winn3ManualRecoveryDisclosure,
            ),
            key: const Key('winn3_host_lifecycle_reconnect_disclosure'),
            textAlign: TextAlign.center,
            style: TextStyle(color: color, fontSize: 11),
          ),
        if (lifecycle.holdsSession)
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextButton(
                key: const Key('winn3_host_lifecycle_disconnect'),
                onPressed: enabled ? onDisconnect : null,
                child: Text(translate('Disconnect')),
              ),
              if (reconnectAvailable)
                TextButton(
                  key: const Key('winn3_host_lifecycle_reconnect'),
                  onPressed: enabled ? onReconnect : null,
                  child: Text(translate('Reconnect')),
                ),
            ],
          ),
      ],
    );
  }
}
