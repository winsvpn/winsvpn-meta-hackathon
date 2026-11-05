/// Pure, side-effect-free verdict logic for the duress app-group + keychain purge.
///
/// These live outside `main.dart`'s private `State` class for the same reason
/// `duress_dispatch.dart` does: Dart privacy is per-library, so nothing inside
/// that class is reachable from a test file, and "did the duress wipe actually
/// clear the Apple durable state" is exactly the property that most needs direct
/// unit tests. Nothing in this file performs I/O, touches the network, reads the
/// clock, or logs. It only interprets the two native purge reports the
/// method-channel wipe receives.
///
/// The stores under scrutiny are the only two Apple roots that outlive app
/// deletion: the device Keychain (a WireGuard client private key, a peer
/// preshared key, an Xray UUID and the stable per-install id) and the shared
/// App Group container (the plaintext `Tunnel/latest_tunnel.conf` the Packet
/// Tunnel extension writes, plus `latest_tunnel.json` and `latest_status.json`).
/// A duress wipe that leaves either one holding a residual has not done its job.
///
/// Everything here fails CLOSED. A missing, malformed, or incomplete report is
/// treated as a residual, never as a pass — because a Keychain query or
/// directory read that matches nothing proves only that the query matched
/// nothing, not that the state is gone. That is the exact defect class this
/// whole path was audited for.
library;

/// True when a native Keychain purge report still leaves state behind.
///
/// [report] is the map returned by the `purgeKeychainIdentity` method-channel
/// call (dropped to null when the call timed out or threw). `complete` is
/// strict on the native side: it requires each store to have been OBSERVED to
/// hold something and then observed empty, so a report that is not explicitly
/// complete can never be mistaken for a clean one. The residual check then
/// requires the observed `remaining` count to be present and zero; a count that
/// is missing, non-integer, or nonzero is still a residual.
bool keychainPurgeLeftResidual(Map<String, dynamic>? report) {
  if (report == null) return true;
  if (report['keychain_purge_complete'] != true) return true;
  final remaining = report['keychain_purge_remaining_items'];
  return remaining is! int || remaining != 0;
}

/// True when a native App Group purge report still leaves state behind.
///
/// Mirror of [keychainPurgeLeftResidual] for the `purgeAppGroupContainer`
/// report, with the same fail-closed contract: the container must be observed
/// complete AND re-read to show zero [app_group_purge_remaining_count] entries
/// before it counts as cleared.
bool appGroupPurgeLeftResidual(Map<String, dynamic>? report) {
  if (report == null) return true;
  if (report['app_group_purge_complete'] != true) return true;
  final remaining = report['app_group_purge_remaining_count'];
  return remaining is! int || remaining != 0;
}

/// True only when EITHER Apple durable root still holds a residual after the
/// duress wipe. This is the single ask the wipe answers: invoking duress must
/// clear the app-group and keychain state with nothing left behind. The two
/// stores fail independently — the container dies with the app, the Keychain
/// does not — so either one being unclean means the wipe is not complete.
bool appleDuressPurgeLeftAnyResidual({
  required Map<String, dynamic>? keychain,
  required Map<String, dynamic>? appGroup,
}) =>
    keychainPurgeLeftResidual(keychain) || appGroupPurgeLeftResidual(appGroup);
