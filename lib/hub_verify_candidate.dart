import 'double_vpn_assignment_retry.dart';
import 'vpn_config_validation.dart';
import 'winn3_cover_fallback.dart';
import 'winn3_device_key.dart';
import 'winn_protocol_dispatch.dart';

/// What one /verify or /free/verify request asked for, captured from the very
/// payload that was encoded into its body, so every attempt of that request is
/// validated against the same immutable values.
class HubVerifyRequirements {
  const HubVerifyRequirements({
    required this.exactTarget,
    required this.doubleVpnRequired,
  });

  /// [enforceDoubleVpn] is false only for activation, which has always
  /// accepted a single-hop reply to a two-hop request (the connect path then
  /// says so and connects single-hop).
  factory HubVerifyRequirements.fromRequestPayload(
    Map<String, dynamic> payload, {
    bool enforceDoubleVpn = true,
  }) {
    final location = payload['location'];
    return HubVerifyRequirements(
      exactTarget: location is String ? location.trim() : '',
      doubleVpnRequired: enforceDoubleVpn && payload['double_vpn'] == true,
    );
  }

  /// The requested node slug, or empty or `auto` for automatic selection.
  final String exactTarget;
  final bool doubleVpnRequired;
}

/// Every check an authenticated /verify or /free/verify reply must pass
/// BEFORE the hub window may declare it the winner. It reads only its
/// arguments: nothing is persisted and no account or tunnel state changes, so
/// an invalid reply simply loses and a later valid one can still win.
///
/// Reply-body authenticity relies on pinned TLS. Paid reconnect authorization
/// checks the account-scoped device record, matching public key and device
/// token; enrollment has a separate activation-secret path. Free verification
/// derives its account/device identity through the free-admission path and
/// does not require that paid bearer authorization. The client rejects a
/// mismatching nonempty device-key echo; accepting an absent echo is an
/// explicit compatibility exception. Only the gateway descriptor is signed.
///
/// When the request carried this device's own winn/3 public key
/// ([localWinn3StaticPublic] non-empty), the same binding applies to the
/// `winn3_static_public` echo (`winn3_key_mismatch`), and a served
/// `winn3_static_private` beside an echo of this device's own key is refused
/// (`winn3_served_private_key`). A served private with no echo (a hub not yet
/// upgraded) is accepted for that session only (winn3_device_key.dart).
///
/// For a standalone `winn3` carrier the descriptor must verify AND name the
/// route-selected node, using the start path's own rule
/// ([winn3DescriptorBindsSelectedNode]); the start keeps both checks as
/// defense in depth. The relay binding ([winn3RelayBindingForServedConfig])
/// then refuses a Double label without a relay and a malformed or
/// inconsistent relay with its refusal code.
///
/// Returns null when the reply is acceptable, otherwise a short reason.
///
/// [servedConfig] is the raw `vpn_config` object as served; [normalizedConfig]
/// is the caller's normalized config with this device's local keys attached,
/// which is what the connect path will actually use.
Future<String?> hubVerifyCandidateRejection({
  required Map<String, dynamic> responseData,
  required Map<String, dynamic> servedConfig,
  required Map<String, dynamic> normalizedConfig,
  required String localClientPublicKey,
  String localWinn3StaticPublic = '',
  required HubVerifyRequirements requirements,
  Winn3DescriptorKeyRing? descriptorRing,
  DateTime? now,
}) async {
  // 1. Device binding (AWG and winn/3), the same check every accepting path
  //    runs before it commits or persists anything.
  final bindingRejection = hubVerifyKeyBindingRejection(
    servedConfig: servedConfig,
    localClientPublicKey: localClientPublicKey,
    localWinn3StaticPublic: localWinn3StaticPublic,
  );
  if (bindingRejection != null) return bindingRejection;
  // 2. The requested route shape.
  if (!acceptsRequestedDoubleVpnConfig(
    doubleVpnRequested: requirements.doubleVpnRequired,
    config: normalizedConfig,
  )) {
    return 'double_vpn_not_served';
  }
  // 3. Structural usability, and the requested exact target.
  if (!VpnConfigValidator.isUsable(normalizedConfig)) {
    return 'config_unusable';
  }
  final exact = requirements.exactTarget;
  if (exact.isNotEmpty &&
      exact != 'auto' &&
      !returnedNodeMatchesExactCoverTarget(
        exactTargetSlug: exact,
        vpnConfig: normalizedConfig,
        selectedNode:
            responseData['selected_node'] ?? responseData['selectednode'],
      )) {
    return 'response_target_mismatch';
  }
  // 4. The signed gateway descriptor, bound to the selected node, where the
  //    start path requires one.
  if (isStandaloneWinn3ServedConfig(normalizedConfig)) {
    final check = await verifyWinn3Descriptor(
      config: normalizedConfig,
      ring: descriptorRing,
      now: now,
    );
    final descriptor = check.descriptor;
    if (!check.verified || descriptor == null) {
      return 'winn3_descriptor_unverified:${check.reason}';
    }
    if (!winn3DescriptorBindsSelectedNode(
      served: normalizedConfig,
      descriptor: descriptor,
    )) {
      return 'winn3_descriptor_node_mismatch';
    }
    // 5. The relay binding of a ciphertext relay Double VPN. Runs after the
    //    ruled node binding (the descriptor is the exit's own) and mirrors the
    //    start path, so a reply the start would refuse never wins the window.
    final relayBinding = winn3RelayBindingForServedConfig(
      served: normalizedConfig,
      descriptor: descriptor,
    );
    if (!relayBinding.accepted) return relayBinding.refusal.code;
  }
  return null;
}

/// The raw key-binding checks on a served `vpn_config`, before the local keys
/// are attached (attachment would overwrite exactly what is being checked).
/// This is step 1 of [hubVerifyCandidateRejection], exposed so the paths that
/// do not run the full window check (paid activation, the Double VPN
/// assignment refreshes, and `_onAuthSuccess` itself) run the SAME binding
/// before they commit a staged identity or persist anything (Sol, N-1).
///
///  * AWG: a nonempty `client_public_key` echo must be this device's key
///    (`client_key_mismatch`);
///  * winn/3: [winn3ServedKeyRejection] (`winn3_key_mismatch`,
///    `winn3_served_private_key`).
String? hubVerifyKeyBindingRejection({
  required Map<String, dynamic> servedConfig,
  required String localClientPublicKey,
  String localWinn3StaticPublic = '',
}) {
  final servedKey = (servedConfig['client_public_key'] ??
          servedConfig['clientpublickey'] ??
          '')
      .toString()
      .trim();
  if (servedKey.isNotEmpty && servedKey != localClientPublicKey.trim()) {
    return 'client_key_mismatch';
  }
  return winn3ServedKeyRejection(
    servedConfig: servedConfig,
    localWinn3StaticPublic: localWinn3StaticPublic,
  );
}
