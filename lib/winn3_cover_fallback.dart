import 'dart:convert';
import 'dart:math';

import 'winn_protocol_dispatch.dart';

/// Node-level cover fallback for a standalone (or otherwise uncoverable) v3
/// session whose node has stopped answering.
///
/// # Why this exists, and what it is not
///
/// A `carrier=winn3` config cannot enter the shipping TCP/Xray escalation
/// loop: `_configForTransport(stealthMode: true)` sets `stealth_active`, and
/// `resolveWinnProtocolStartForServedConfig` refuses that pairing with
/// `stealthTransportConflict`. The stealth chain that would make v3 ride
/// cover is gated on `direct-awg` because standalone has no AmneziaWG peer
/// endpoint to repoint.
///
/// The datapath already has escalation, failover, dpbridge and reconnect —
/// all default-off, and the mobile C ABI has no migrate verb. Wiring those
/// would be v3-on-v3 carrier switching (and on Android/iOS it is refused
/// anyway: `OpenConfigWithFailover` requires `allow_own_socket`). This file
/// does the smaller thing the shipping client can already do: pick a
/// different listed node that speaks cover-bearing winn/1.
///
/// # What this deliberately does not do
///
/// It never names AmneziaWG as a fallback for the SAME v3 config. Same-node
/// downgrade stays refused in `_startTunnelCandidate`. It never recommends
/// cleartext. If the listing has no cover-bearing winn/1 successor, it
/// returns null and the connect path fails closed.

/// Hard cap on how many slugs one connect may try, including the original.
///
/// One original plus two cover successors. A fleet of only-v3 nodes must
/// still fail closed rather than walk the whole list.
const int kWinn3CoverFallbackMaxAttempts = 3;

/// Positive signed 63-bit start token. Zero is not a token.
const int kWinn3StartTokenMax = 0x7fffffffffffffff;

/// Native AWG-then-Xray cover grant lifetime. Monotonic, not wall clock.
const int kWinn3AwgXrayGrantTtlMs = kWinn1FallbackDispatchGrantTtlMs;

/// Mints a positive signed 63-bit per-start token from [Random.secure].
int mintWinn3StartToken([Random? random]) {
  final rng = random ?? Random.secure();
  var token = 0;
  while (token <= 0) {
    final high = rng.nextInt(1 << 31);
    final low = rng.nextInt(1 << 32);
    token = (high << 32) | low;
  }
  return token;
}

/// Exact control-plane generation fields for one v3 selection attempt.
///
/// The ordinary-failure field is emitted only after the typed native verdict
/// for this same generation is [Winn3NativeVerdict.ordinaryConnectivity]. A
/// malformed or absent generation returns no fields, which keeps v1 selection
/// unauthorized at the hub.
Map<String, String> winn3SelectionGenerationPayload({
  required String selectionGeneration,
  required bool ordinaryConnectivityAuthorized,
}) {
  synchronizeWinn1FallbackDispatchGeneration(
    selectionGeneration: selectionGeneration,
    ordinaryConnectivityAuthorized: ordinaryConnectivityAuthorized,
  );
  if (!kWinn3SelectionGenerationPattern.hasMatch(selectionGeneration)) {
    return const <String, String>{};
  }
  return <String, String>{
    'selection_generation': selectionGeneration,
    if (ordinaryConnectivityAuthorized)
      'ordinary_v3_failure_generation': selectionGeneration,
  };
}

/// Why a served direct candidate is, or is not, allowed to lead the connect.
///
/// Winn v3 is decided before legacy AWG transport policy. A user's TCP-fallback
/// preference never skips Winn v3 or the Winn v1 AWG lead. A diagnostic
/// force-Xray request applies only to the legacy compatibility pair after a
/// typed ordinary v3 failure.
enum Winn3LeadPolicy {
  legacyTransportPolicy,
  attemptPrimary,
  diagnosticForceXrayOverride,
}

bool diagnosticForceXrayEnabled({
  required bool requested,
  required bool releaseMode,
}) {
  return requested && !releaseMode;
}

Winn3LeadPolicy winn3LeadPolicy({
  required Map<String, dynamic> config,
  required bool userTcpOnly,
  required bool forceXrayForDiagnostics,
}) {
  final version = strictWinnProtocolVersion(config);
  if (version == kWinnProtocolV3) {
    return Winn3LeadPolicy.attemptPrimary;
  }
  if (version != kWinnProtocolV1) {
    throw StateError('Refusing a missing, unknown, or ambiguous Winn protocol '
        'state before any tunnel candidate or transport preflight.');
  }
  if (!winn1FallbackDispatchMayLead(config)) {
    throw StateError('Refusing Winn Protocol v1 before an exact, current '
        'ordinary Winn Protocol v3 failure authorizes the reviewed fallback.');
  }
  // Preferences and diagnostic overrides cannot reorder the owner-required
  // compatibility pair. A v1 route that reaches this point is AWG first.
  return Winn3LeadPolicy.legacyTransportPolicy;
}

bool winn3LeadPolicyIsExplicitOverride(Winn3LeadPolicy policy) {
  return policy == Winn3LeadPolicy.diagnosticForceXrayOverride;
}

/// A generation-bound native decision about the current standalone v3 start.
///
/// Only [ordinaryConnectivity] authorizes moving to Winn v1. Pending, stale,
/// malformed, unknown and terminal security outcomes all fail closed.
enum Winn3NativeVerdict {
  pending,
  connected,
  ordinaryConnectivity,
  terminalSecurity,
  unknownTerminal,
}

/// Whether the served direct candidate owns the first attempt.
///
/// The legacy control-plane flag applies only to v1 AWG. A v3 primary attempt
/// therefore stays enabled even when that legacy flag is false.
bool shouldAttemptServedLeadCandidate({
  required Winn3LeadPolicy policy,
  required bool directAwgEnabled,
}) {
  return policy == Winn3LeadPolicy.attemptPrimary ||
      policy == Winn3LeadPolicy.legacyTransportPolicy;
}

/// Exact, closed protocol state from a served config or listing row.
///
/// Both accepted aliases must be strings and must agree when both are present.
/// Missing, blank, unknown, non-string, or conflicting state returns null.
String? strictWinnProtocolVersion(Map<String, dynamic> value) {
  final observed = <String>[];
  for (final key in const <String>['protocol_version', 'protocolversion']) {
    if (!value.containsKey(key)) continue;
    final raw = value[key];
    if (raw is! String) return null;
    final version = raw.trim();
    if (version.isEmpty) return null;
    observed.add(version);
  }
  if (observed.isEmpty || observed.toSet().length != 1) return null;
  final version = observed.first;
  return version == kWinnProtocolV1 || version == kWinnProtocolV3
      ? version
      : null;
}

/// Whether selection may proceed from the served v3 node to a legacy node.
///
/// A normal fallback requires an actual v3 attempt followed by a connectivity
/// failure. An explicit override deliberately skips that attempt. A security
/// refusal is terminal in both cases.
bool maySelectLegacyRouteAfterWinn3Lead({
  required Winn3LeadPolicy policy,
  required bool primaryAttempted,
  required Winn3NativeVerdict primaryVerdict,
  required bool securityRefused,
  required bool servedConfigNeedsLegacyNode,
}) {
  return !securityRefused &&
      servedConfigNeedsLegacyNode &&
      policy == Winn3LeadPolicy.attemptPrimary &&
      primaryAttempted &&
      primaryVerdict == Winn3NativeVerdict.ordinaryConnectivity;
}

/// The `carrier` this served config selects. An absent value means
/// `direct-awg`, matching `_resolvedCarrier` in winn_protocol_dispatch.dart.
String servedWinnCarrier(Map<String, dynamic> config) {
  final params = config['protocol_params'];
  final map = params is Map
      ? Map<String, dynamic>.from(params)
      : const <String, dynamic>{};
  final fromParams = (map['carrier'] ?? '').toString().trim().toLowerCase();
  if (fromParams.isNotEmpty) return fromParams;
  final fromTop = (config['carrier'] ?? '').toString().trim().toLowerCase();
  return fromTop.isEmpty ? kWinnCarrierDirectAwg : fromTop;
}

/// True when this served config is standalone v3: `winn/3` with carrier
/// `winn3`. Relay v3 (`direct-awg`) is a different session and is not this.
bool isStandaloneWinn3ServedConfig(Map<String, dynamic> config) {
  return strictWinnProtocolVersion(config) == kWinnProtocolV3 &&
      servedWinnCarrier(config) == kWinnCarrierWinn3;
}

/// True when this v3 config cannot use the shipping cover-bearing TCP loop
/// and a different (winn/1) node is the remaining cover path.
///
/// winn/1 keeps the existing UDP-then-TCP loop. A v3 stealth-chain config
/// already has cover on this node. Everything else that is `winn/3` —
/// standalone, or relay without the chain — is refused if the connect path
/// sets `stealth_active`, so rotating nodes is the cover that remains.
bool servedConfigNeedsCoverNodeFallback(Map<String, dynamic> config) {
  if (strictWinnProtocolVersion(config) != kWinnProtocolV3) {
    return false;
  }
  if (winnConfigUsesStealthChain(config)) return false;
  return true;
}

/// Whether a failed v3 attempt may rotate to a different cover-bearing node.
///
/// A schema, descriptor, signature, platform, or other pre-start security
/// refusal is not evidence that the transport is censored or unavailable. It
/// ends this connect attempt. Only a v3 candidate that passed its security
/// gates and then failed liveness/carriage may use node-level cover fallback.
bool servedConfigMayAttemptCoverNodeFallback({
  required Map<String, dynamic> config,
  required Winn3NativeVerdict primaryVerdict,
}) {
  final securityRefused =
      primaryVerdict != Winn3NativeVerdict.ordinaryConnectivity;
  return !securityRefused && servedConfigNeedsCoverNodeFallback(config);
}

/// Whether an exception before the native host accepts a served v3 start must
/// terminate the connect instead of authorizing a winn/1 cover-node fallback.
///
/// Native hosts re-validate the descriptor, node binding, key material and
/// protocol posture. Several bridges expose those refusals through a generic
/// start error, so absence of a platform-specific error code is not proof of a
/// connectivity failure. Native start acceptance alone never authorizes cover
/// fallback: a later failure still needs the exact, identity-bound
/// ordinary_connectivity verdict and fallback authorization token. User-owned
/// VPN permission refusal is handled separately and must prompt rather than be
/// labelled as a protocol security refusal.
bool winn3PreAcceptanceFailureMustRefuseFallback({
  required Map<String, dynamic> config,
  required bool nativeStartAccepted,
  required bool permissionApprovalRequired,
}) {
  return strictWinnProtocolVersion(config) == kWinnProtocolV3 &&
      !nativeStartAccepted &&
      !permissionApprovalRequired;
}

/// Security refusal fields surfaced by native readiness bridges after a start
/// call has already returned. Values are booleans or bounded status labels;
/// no key, descriptor, endpoint or provider error prose is needed here.
bool nativeWinn3ReadinessReportsSecurityRefusal(
  Map<dynamic, dynamic>? readiness, {
  int? startToken,
}) {
  if (readiness == null) return false;
  if (startToken != null &&
      !nativeWinn3ReadinessMatchesStartToken(readiness, startToken)) {
    return false;
  }
  final android = readiness['winn3_security_refusal'];
  if (android == true || android?.toString().toLowerCase() == 'true') {
    return true;
  }
  final providerStage =
      (readiness['provider_stage'] ?? '').toString().trim().toLowerCase();
  if (providerStage == 'start_rejected') return true;
  final providerCode =
      (readiness['provider_error_code'] ?? '').toString().trim();
  return providerCode == '1101' || providerCode == '1105';
}

/// What a failed v3 start's readiness says about the SHAPE of the failure,
/// for the message the user reads. It never authorizes anything: fallback
/// eligibility stays with [nativeWinn3ReadinessVerdict], which treats both
/// shapes below as terminal.
///
/// Android publishes `unknown_terminal` with `winn3_security_refusal=true` for
/// a handshake that exhausted its attempts with nothing arriving (the engine's
/// ErrCarrierExhausted), so the security bit alone cannot tell a silent
/// server from a refused configuration. The typed verdict string can:
/// `terminal_security` is a refusal. `unknown_terminal` is only "not
/// established, cause unconfirmed": Android also publishes it for runtime
/// death and untrustworthy status (WinnV3StagedStart.kt), so it is never read
/// as silence. Anything else, or a readiness document for another start, is
/// [Winn3FailureShape.unclassified].
enum Winn3FailureShape { unclassified, unconfirmedTerminal, securityRefusal }

Winn3FailureShape nativeWinn3FailureShape(
  Map<dynamic, dynamic>? readiness, {
  required int? startToken,
}) {
  if (readiness == null || startToken == null) {
    return Winn3FailureShape.unclassified;
  }
  if (!nativeWinn3ReadinessMatchesStartToken(readiness, startToken)) {
    return Winn3FailureShape.unclassified;
  }
  final verdicts = <Object?>[
    for (final key in const <String>[
      'winn3_verdict',
      'winn3_start_verdict',
      'provider_verdict',
    ])
      if (readiness.containsKey(key)) readiness[key],
  ];
  if (verdicts.isEmpty || verdicts.any((value) => value is! String)) {
    return Winn3FailureShape.unclassified;
  }
  final exact = verdicts.cast<String>().toSet();
  if (exact.contains('terminal_security')) {
    return Winn3FailureShape.securityRefusal;
  }
  if (exact.length == 1 && exact.single == 'unknown_terminal') {
    return Winn3FailureShape.unconfirmedTerminal;
  }
  return Winn3FailureShape.unclassified;
}

/// Monotonic merge for one candidate: a security refusal seen once is never
/// relabelled as silence by a later read.
Winn3FailureShape mergeWinn3FailureShape(
  Winn3FailureShape previous,
  Winn3FailureShape observed,
) {
  if (previous == Winn3FailureShape.securityRefusal ||
      observed == Winn3FailureShape.securityRefusal) {
    return Winn3FailureShape.securityRefusal;
  }
  if (observed == Winn3FailureShape.unconfirmedTerminal) {
    return Winn3FailureShape.unconfirmedTerminal;
  }
  return previous;
}

int? _strictReadinessInteger(Object? value) {
  return value is int ? value : null;
}

String? _strictReadinessString(Object? value) {
  return value is String ? value : null;
}

/// Generic native active/engine-ready fields may be evaluated only after the
/// exact current v3 start has produced its typed connected verdict.
bool nativeWinn3VerdictAllowsReadyState(Winn3NativeVerdict verdict) {
  return verdict == Winn3NativeVerdict.connected;
}

/// Monotonic verdict latch for one generation-bound native start.
Winn3NativeVerdict mergeWinn3NativeVerdict(
  Winn3NativeVerdict previous,
  Winn3NativeVerdict observed,
) {
  final merged = _mergeWinn3NativeVerdict(previous, observed);
  if (merged == Winn3NativeVerdict.connected ||
      merged == Winn3NativeVerdict.terminalSecurity ||
      merged == Winn3NativeVerdict.unknownTerminal) {
    clearWinn1FallbackDispatchAuthorization();
  }
  return merged;
}

Winn3NativeVerdict _mergeWinn3NativeVerdict(
  Winn3NativeVerdict previous,
  Winn3NativeVerdict observed,
) {
  if (observed == Winn3NativeVerdict.terminalSecurity) {
    return Winn3NativeVerdict.terminalSecurity;
  }
  switch (previous) {
    case Winn3NativeVerdict.pending:
      return observed;
    case Winn3NativeVerdict.connected:
      return observed == Winn3NativeVerdict.pending ||
              observed == Winn3NativeVerdict.connected
          ? Winn3NativeVerdict.connected
          : Winn3NativeVerdict.unknownTerminal;
    case Winn3NativeVerdict.ordinaryConnectivity:
      if (observed == Winn3NativeVerdict.pending ||
          observed == Winn3NativeVerdict.ordinaryConnectivity) {
        return Winn3NativeVerdict.ordinaryConnectivity;
      }
      return Winn3NativeVerdict.unknownTerminal;
    case Winn3NativeVerdict.terminalSecurity:
      return Winn3NativeVerdict.terminalSecurity;
    case Winn3NativeVerdict.unknownTerminal:
      return Winn3NativeVerdict.unknownTerminal;
  }
}

/// Parses only a typed, current-start native verdict.
///
/// If either identity is supplied by the caller, the readiness response must
/// contain the same identity. Legacy labels such as `connectivity_failed` and
/// generic provider failures are intentionally not ordinary-connectivity proof.
Winn3NativeVerdict nativeWinn3ReadinessVerdict(
  Map<dynamic, dynamic>? readiness, {
  int? startToken,
  int? startGeneration,
  String? selectionGeneration,
  String? failedNode,
}) {
  final verdict = _parseNativeWinn3ReadinessVerdict(
    readiness,
    startToken: startToken,
    startGeneration: startGeneration,
    selectionGeneration: selectionGeneration,
    failedNode: failedNode,
  );
  if (verdict == Winn3NativeVerdict.ordinaryConnectivity) {
    final armed = startToken != null &&
        startGeneration != null &&
        selectionGeneration != null &&
        failedNode != null &&
        armWinn1FallbackDispatchAuthorization(
          startToken: startToken,
          startGeneration: startGeneration,
          selectionGeneration: selectionGeneration,
          failedV3Node: failedNode,
        );
    if (!armed) {
      clearWinn1FallbackDispatchAuthorization(
        selectionGeneration: selectionGeneration,
      );
      return Winn3NativeVerdict.unknownTerminal;
    }
  } else if (verdict == Winn3NativeVerdict.connected ||
      verdict == Winn3NativeVerdict.terminalSecurity ||
      verdict == Winn3NativeVerdict.unknownTerminal) {
    clearWinn1FallbackDispatchAuthorization(
      selectionGeneration: selectionGeneration,
    );
  }
  return verdict;
}

Winn3NativeVerdict _parseNativeWinn3ReadinessVerdict(
  Map<dynamic, dynamic>? readiness, {
  int? startToken,
  int? startGeneration,
  String? selectionGeneration,
  String? failedNode,
}) {
  if (readiness == null) return Winn3NativeVerdict.unknownTerminal;
  final observedStartToken =
      _strictReadinessInteger(readiness['winn3_start_token']);
  if (startToken != null && observedStartToken != startToken) {
    return Winn3NativeVerdict.unknownTerminal;
  }
  if (observedStartToken != null && observedStartToken <= 0) {
    return Winn3NativeVerdict.unknownTerminal;
  }
  if (startGeneration != null) {
    final generations = <Object?>[
      if (readiness.containsKey('winn3_start_generation'))
        readiness['winn3_start_generation'],
      if (readiness.containsKey('transition_generation'))
        readiness['transition_generation'],
    ];
    if (generations.isEmpty ||
        generations.any((value) {
          final exact = _strictReadinessInteger(value);
          return exact == null || exact <= 0 || exact != startGeneration;
        })) {
      return Winn3NativeVerdict.unknownTerminal;
    }
  }
  if (selectionGeneration != null) {
    final observedSelection = _strictReadinessString(
      readiness['winn3_selection_generation'],
    );
    if (!kWinn3SelectionGenerationPattern.hasMatch(selectionGeneration) ||
        observedSelection != selectionGeneration) {
      return Winn3NativeVerdict.unknownTerminal;
    }
  }
  if (failedNode != null) {
    final observedFailed =
        _strictReadinessString(readiness['winn3_failed_node']);
    if (failedNode.trim().isEmpty ||
        failedNode.trim().toLowerCase() == 'auto' ||
        observedFailed != failedNode) {
      return Winn3NativeVerdict.unknownTerminal;
    }
  }

  // A native bridge must never be able to authorize downgrade and report a
  // security refusal in the same generation. Security wins even when typed
  // verdict aliases otherwise agree.
  if (nativeWinn3ReadinessReportsSecurityRefusal(
    readiness,
    startToken: startToken,
  )) {
    return Winn3NativeVerdict.terminalSecurity;
  }

  final rawVerdicts = <Object?>[
    if (readiness.containsKey('winn3_verdict')) readiness['winn3_verdict'],
    if (readiness.containsKey('winn3_start_verdict'))
      readiness['winn3_start_verdict'],
    if (readiness.containsKey('provider_verdict'))
      readiness['provider_verdict'],
  ];
  if (rawVerdicts.isEmpty) {
    return nativeWinn3ReadinessReportsSecurityRefusal(
      readiness,
      startToken: startToken,
    )
        ? Winn3NativeVerdict.terminalSecurity
        : Winn3NativeVerdict.unknownTerminal;
  }
  if (rawVerdicts.any((value) => value is! String)) {
    return Winn3NativeVerdict.unknownTerminal;
  }
  final exactVerdicts = rawVerdicts.cast<String>().toSet();
  if (exactVerdicts.length != 1) {
    return Winn3NativeVerdict.unknownTerminal;
  }
  switch (exactVerdicts.single) {
    case 'pending':
      return Winn3NativeVerdict.pending;
    case 'connected':
      return Winn3NativeVerdict.connected;
    case 'ordinary_connectivity':
      final authorizationToken = _strictReadinessInteger(
        readiness['winn3_awg_xray_authorization_token'],
      );
      if (observedStartToken == null ||
          observedStartToken <= 0 ||
          authorizationToken != observedStartToken) {
        return Winn3NativeVerdict.unknownTerminal;
      }
      return Winn3NativeVerdict.ordinaryConnectivity;
    case 'terminal_security':
      return Winn3NativeVerdict.terminalSecurity;
    case 'unknown_terminal':
      return Winn3NativeVerdict.unknownTerminal;
    default:
      return Winn3NativeVerdict.unknownTerminal;
  }
}

/// True only when [readiness] belongs to this exact Android v3 start.
///
/// The service can finish a superseded start after Dart has already begun a
/// replacement. A bare sticky refusal bit is therefore not authority to block
/// or permit the replacement: the MethodChannel response must bind it to the
/// caller's start token first.
bool nativeWinn3ReadinessMatchesStartToken(
  Map<dynamic, dynamic>? readiness,
  int startToken,
) {
  if (readiness == null) return false;
  return _strictReadinessInteger(readiness['winn3_start_token']) == startToken;
}

/// Whether a native v3 start has reached its ordinary connectivity verdict.
///
/// This is deliberately narrower than "not ready". A pending, unreadable, or
/// differently-tokened status cannot prove that descriptor/key/admission/
/// handshake validation did not subsequently refuse, so it must not authorize
/// a v1 fallback. Only the exact typed `ordinary_connectivity` verdict for this
/// start is eligible for the documented cover-node path.
bool nativeWinn3ReadinessReportsConnectivityFailure(
  Map<dynamic, dynamic>? readiness, {
  required int startToken,
  int? startGeneration,
  String? selectionGeneration,
  String? failedNode,
}) {
  return nativeWinn3ReadinessVerdict(
        readiness,
        startToken: startToken,
        startGeneration: startGeneration,
        selectionGeneration: selectionGeneration,
        failedNode: failedNode,
      ) ==
      Winn3NativeVerdict.ordinaryConnectivity;
}

/// True when a failed Android v3 readiness wait must remain terminal.
///
/// The sole non-terminal native result is an identity-bound typed
/// `ordinary_connectivity` verdict. Legacy `connectivity_failed`, pending,
/// malformed and unreadable states remain terminal for fallback purposes.
bool nativeWinn3ReadinessMustRefuseFallback(
  Map<dynamic, dynamic>? readiness, {
  required int startToken,
  int? startGeneration,
  String? selectionGeneration,
  String? failedNode,
}) {
  if (nativeWinn3ReadinessReportsConnectivityFailure(
    readiness,
    startToken: startToken,
    startGeneration: startGeneration,
    selectionGeneration: selectionGeneration,
    failedNode: failedNode,
  )) {
    return false;
  }
  return true;
}

/// Exact hub location for one connect. Cover uses an immutable concrete slug
/// and never substitutes `auto`.
String winn3RequestLocationSlug({
  required bool automatic,
  required String displayedNodeSlug,
  String? exactCoverTargetSlug,
}) {
  final cover = (exactCoverTargetSlug ?? '').trim();
  if (cover.isNotEmpty) {
    if (cover.toLowerCase() == 'auto') {
      throw StateError('Cover exact target must be a concrete node slug.');
    }
    return cover;
  }
  if (automatic) return 'auto';
  final normalized = displayedNodeSlug.trim();
  if (normalized.isEmpty || normalized.toLowerCase() == 'auto') {
    throw StateError('Explicit node selection has no concrete node slug.');
  }
  return normalized;
}

String? servedConfigNodeSlug(Map<String, dynamic> config) {
  final slug = (config['node_slug'] ?? '').toString().trim();
  return slug.isEmpty ? null : slug;
}

String? selectedNodeSlug(Object? selectedNode) {
  if (selectedNode is String) {
    final slug = selectedNode.trim();
    return slug.isEmpty ? null : slug;
  }
  if (selectedNode is Map) {
    final slug = (selectedNode['slug'] ?? '').toString().trim();
    return slug.isEmpty ? null : slug;
  }
  return null;
}

bool returnedNodeMatchesExactCoverTarget({
  required String exactTargetSlug,
  required Map<String, dynamic> vpnConfig,
  Object? selectedNode,
}) {
  final expected = exactTargetSlug.trim();
  if (expected.isEmpty || expected.toLowerCase() == 'auto') return false;
  final configSlug = servedConfigNodeSlug(vpnConfig);
  if (configSlug != expected) return false;
  final hubSlug = selectedNodeSlug(selectedNode);
  if (hubSlug != null && hubSlug != expected) return false;
  return true;
}

/// One AWG then optionally one Xray. Direct user-selected v1 does not use this.
enum Winn3CoverLeg { awg, xray }

enum Winn3GrantConsumeResult { ok, empty, expired, mismatch, wrongLeg }

class Winn3AwgXrayGrant {
  const Winn3AwgXrayGrant({
    required this.startToken,
    required this.startGeneration,
    required this.selectionGeneration,
    required this.failedV3Node,
    required this.exactV1Target,
    required this.issuedMonotonicMs,
    this.nextLeg = Winn3CoverLeg.awg,
    this.targetBound = false,
  });

  final int startToken;
  final int startGeneration;
  final String selectionGeneration;
  final String failedV3Node;
  final String exactV1Target;
  final int issuedMonotonicMs;
  final Winn3CoverLeg nextLeg;
  final bool targetBound;

  Winn3AwgXrayGrant copyWith({
    String? exactV1Target,
    Winn3CoverLeg? nextLeg,
    bool? targetBound,
  }) {
    return Winn3AwgXrayGrant(
      startToken: startToken,
      startGeneration: startGeneration,
      selectionGeneration: selectionGeneration,
      failedV3Node: failedV3Node,
      exactV1Target: exactV1Target ?? this.exactV1Target,
      issuedMonotonicMs: issuedMonotonicMs,
      nextLeg: nextLeg ?? this.nextLeg,
      targetBound: targetBound ?? this.targetBound,
    );
  }
}

bool winn3AwgXrayGrantExpired(Winn3AwgXrayGrant grant, int nowMonotonicMs) {
  if (grant.startToken <= 0 || grant.issuedMonotonicMs <= 0) return true;
  if (nowMonotonicMs < grant.issuedMonotonicMs) return true;
  return (nowMonotonicMs - grant.issuedMonotonicMs) > kWinn3AwgXrayGrantTtlMs;
}

Winn3AwgXrayGrant? armWinn3AwgXrayGrant({
  required int startToken,
  required int startGeneration,
  required String selectionGeneration,
  required String failedV3Node,
  required int issuedMonotonicMs,
}) {
  final failed = failedV3Node.trim();
  if (startToken <= 0 ||
      startGeneration <= 0 ||
      issuedMonotonicMs <= 0 ||
      !kWinn3SelectionGenerationPattern.hasMatch(selectionGeneration) ||
      failed.isEmpty ||
      failed.toLowerCase() == 'auto') {
    return null;
  }
  return Winn3AwgXrayGrant(
    startToken: startToken,
    startGeneration: startGeneration,
    selectionGeneration: selectionGeneration,
    failedV3Node: failed,
    exactV1Target: '',
    issuedMonotonicMs: issuedMonotonicMs,
  );
}

class Winn3GrantConsumeOutcome {
  const Winn3GrantConsumeOutcome(this.result, [this.grant]);
  final Winn3GrantConsumeResult result;
  final Winn3AwgXrayGrant? grant;
}

Winn3GrantConsumeOutcome consumeWinn3AwgXrayGrant({
  required Winn3AwgXrayGrant? grant,
  required int startToken,
  required int startGeneration,
  required String selectionGeneration,
  required String failedV3Node,
  required String exactV1Target,
  required Winn3CoverLeg requestedLeg,
  required int nowMonotonicMs,
}) {
  if (grant == null) {
    return const Winn3GrantConsumeOutcome(Winn3GrantConsumeResult.empty);
  }
  if (winn3AwgXrayGrantExpired(grant, nowMonotonicMs)) {
    return const Winn3GrantConsumeOutcome(Winn3GrantConsumeResult.expired);
  }
  final target = exactV1Target.trim();
  if (startToken != grant.startToken ||
      startGeneration != grant.startGeneration ||
      selectionGeneration != grant.selectionGeneration ||
      failedV3Node.trim() != grant.failedV3Node ||
      target.isEmpty ||
      target.toLowerCase() == 'auto') {
    return const Winn3GrantConsumeOutcome(Winn3GrantConsumeResult.mismatch);
  }
  if (grant.targetBound && target != grant.exactV1Target) {
    return const Winn3GrantConsumeOutcome(Winn3GrantConsumeResult.mismatch);
  }
  if (requestedLeg != grant.nextLeg) {
    return const Winn3GrantConsumeOutcome(Winn3GrantConsumeResult.wrongLeg);
  }
  if (requestedLeg == Winn3CoverLeg.awg) {
    return Winn3GrantConsumeOutcome(
      Winn3GrantConsumeResult.ok,
      grant.copyWith(
        exactV1Target: target,
        nextLeg: Winn3CoverLeg.xray,
        targetBound: true,
      ),
    );
  }
  return const Winn3GrantConsumeOutcome(Winn3GrantConsumeResult.ok);
}

/// True when a GET /nodes listing entry is labelled standalone v3.
///
/// Current hubs send `protocol_version` and the resolved `carrier`. Unknown is
/// still NOT treated as standalone for cached entries and older hubs: skipping
/// every unlabelled node would leave the user with nothing. The connect path
/// re-classifies from the served vpn_config before starting a tunnel.
bool listingNodeIsStandaloneWinn3(Map<String, dynamic> node) {
  final version = strictWinnProtocolVersion(node);
  final carrier = (node['carrier'] ?? '').toString().trim().toLowerCase();
  return version == kWinnProtocolV3 && carrier == kWinnCarrierWinn3;
}

/// True only for an explicitly v1 node or an unversioned legacy node.
///
/// In particular, a `winn/3` relay is still v3. Its carrier label must never
/// make it eligible for the compatibility fallback picker.
bool listingNodeIsWinn1OrLegacy(Map<String, dynamic> node) {
  final version = strictWinnProtocolVersion(node);
  final carrier = (node['carrier'] ?? '').toString().trim().toLowerCase();
  return version == kWinnProtocolV1 && carrier != kWinnCarrierWinn3;
}

/// True when a persisted vpn_config is the shipping Winn v1 path.
///
/// Absent, blank, conflicting, or unknown protocol state is not v1 evidence.
/// Structural VPN-config usability is not this protocol-authorization check.
bool persistedConfigIsWinnV1(Map<String, dynamic> config) {
  return strictWinnProtocolVersion(config) == kWinnProtocolV1;
}

/// Listing row for [slug], or null when the slug is empty, `auto`, or absent.
Map<String, dynamic>? listingNodeForSlug(
  List<Map<String, dynamic>> locations,
  String slug,
) {
  final wanted = slug.trim();
  if (wanted.isEmpty || wanted.toLowerCase() == 'auto') return null;
  for (final node in locations) {
    if (_nodeSlug(node) == wanted) return node;
  }
  return null;
}

/// Current hub listing evidence that this node is still a v1/legacy primary.
///
/// A missing row is not evidence. A row labelled `winn/3` or `carrier=winn3`
/// means the persisted v1 document is a downgrade, not an offline copy.
bool listingAuthorizesPersistedWinn1Lead(Map<String, dynamic>? listingNode) {
  if (listingNode == null) return false;
  return listingNodeIsWinn1OrLegacy(listingNode);
}

/// When the hub served this config, as UTC epoch milliseconds. Written by the
/// app on every accepted hub response, never trusted from the hub itself.
const String kVpnConfigFetchedAtKey = 'config_fetched_at_ms';

/// Longest a cached winn/3 config may lead an explicit-node connect without
/// asking the hub first.
///
/// The cache holds operator state (the node's path MTU and carrier classes,
/// its signed descriptor) that the hub can change at any time; a client that
/// never re-asks plans at the old values forever. The terminal-failure retry
/// in `_connectWithSmartProtocol` self-heals the first attempt after such a
/// change, so this bound is the backstop for changes that do not fail loudly.
/// Six hours keeps repeat taps within a working session on the cached path
/// with no hub round trip, costs at most four refresh round trips a day of
/// continuous use, and sits well under the 30-day descriptor ceiling. The
/// one-hour descriptor minimum is enforced separately through `not_after`.
const Duration kWinn3CachedConfigMaxAge = Duration(hours: 6);

/// A fetch stamp this far ahead of the local clock is still accepted.
const Duration kVpnConfigFetchedAtFutureSkew = Duration(minutes: 5);

/// A cached descriptor this close to `not_after` refreshes first rather than
/// failing verification mid-connect.
const Duration kWinn3CachedDescriptorExpiryMargin = Duration(minutes: 2);

/// [config] stamped as served by the hub at [now].
Map<String, dynamic> stampVpnConfigFetchedAt(
  Map<String, dynamic> config,
  DateTime now,
) {
  return Map<String, dynamic>.from(config)
    ..[kVpnConfigFetchedAtKey] = now.toUtc().millisecondsSinceEpoch;
}

/// [config] with no fetch stamp, so the next explicit-node connect asks the
/// hub first. The document itself stays usable as the offline fallback.
Map<String, dynamic> markVpnConfigStale(Map<String, dynamic> config) {
  return Map<String, dynamic>.from(config)..remove(kVpnConfigFetchedAtKey);
}

/// Whether a cached config is recent enough to skip the hub.
///
/// No stamp (every cache written before this rule, or one marked stale), a
/// stamp outside [kVpnConfigFetchedAtFutureSkew], an age of [maxAge] or more,
/// or a served descriptor within [kWinn3CachedDescriptorExpiryMargin] of its
/// `not_after` is not fresh.
bool cachedVpnConfigIsFresh(
  Map<String, dynamic> config, {
  required DateTime now,
  Duration maxAge = kWinn3CachedConfigMaxAge,
}) {
  final stamp = config[kVpnConfigFetchedAtKey];
  if (stamp is! int || stamp <= 0) return false;
  final nowMs = now.toUtc().millisecondsSinceEpoch;
  final ageMs = nowMs - stamp;
  if (ageMs < -kVpnConfigFetchedAtFutureSkew.inMilliseconds) return false;
  if (ageMs >= maxAge.inMilliseconds) return false;
  final notAfter = _cachedDescriptorNotAfterSeconds(config);
  if (notAfter != null &&
      nowMs ~/ 1000 >=
          notAfter - kWinn3CachedDescriptorExpiryMargin.inSeconds) {
    return false;
  }
  return true;
}

/// `not_after` from the cached descriptor payload, or null when absent or
/// unreadable. UNVERIFIED on purpose: it can only make the client ask the hub
/// sooner, never start anything. [verifyWinn3Descriptor] still gates the start.
int? _cachedDescriptorNotAfterSeconds(Map<String, dynamic> config) {
  final envelope = config['winn3_descriptor'] ?? config['winn3descriptor'];
  if (envelope is! Map) return null;
  final payload = envelope['payload'];
  if (payload is! String ||
      payload.isEmpty ||
      payload.length > kWinn3MaxDescriptorPayloadB64Chars) {
    return null;
  }
  try {
    final bytes = base64.decode(payload.trim());
    if (bytes.length > kWinn3MaxDescriptorBytes) return null;
    final decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map) return null;
    final notAfter = decoded['not_after'];
    return notAfter is int ? notAfter : null;
  } catch (_) {
    return null;
  }
}

/// Whether [cachedConfig] is the kind of cache that may lead an initiation
/// without the hub, ignoring its age.
///
/// Only an explicit v3 cache qualifies. Persisted v1 never does: the same
/// node may now be v3, and using it as primary would bypass the
/// generation-bound ordinary-v3-failure authorization. Unknown or ambiguous
/// protocol state is not v3 evidence.
bool cachedConfigIsExplicitWinn3FastPathCandidate({
  required Map<String, dynamic>? cachedConfig,
  required bool automaticMode,
  required bool coverExactTarget,
}) {
  if (cachedConfig == null) return false;
  if (automaticMode || coverExactTarget) return false;
  // A config that carries a Core relay route (w3r/1) never leads without the
  // hub: the relay is a path through a residential address that can change
  // between sessions, and only a fresh answer says where it is now.
  if (winn3ConfigCarriesRelay(cachedConfig)) return false;
  return strictWinnProtocolVersion(cachedConfig) == kWinnProtocolV3;
}

/// Whether this initiation may skip the control-plane refresh using [cachedConfig].
///
/// An explicit v3 cache ([cachedConfigIsExplicitWinn3FastPathCandidate]) that
/// is also fresh ([cachedVpnConfigIsFresh]). A stale one goes to the hub
/// first and stays the fallback if the hub cannot be reached
/// ([mayLeadWithCachedConfigAfterRefreshFailure]).
bool maySkipControlPlaneRefreshWithCachedConfig({
  required Map<String, dynamic>? cachedConfig,
  required bool automaticMode,
  required bool coverExactTarget,
  DateTime? now,
}) {
  if (!cachedConfigIsExplicitWinn3FastPathCandidate(
    cachedConfig: cachedConfig,
    automaticMode: automaticMode,
    coverExactTarget: coverExactTarget,
  )) {
    return false;
  }
  return cachedVpnConfigIsFresh(cachedConfig!, now: now ?? DateTime.now());
}

/// The served fields that make up a winn/3 session plan. A hub change to any
/// of them (a path MTU, the carrier classes, a rotated descriptor, a moved
/// endpoint) is what a cached config cannot know about.
const List<String> kWinn3ServedPlanKeys = <String>[
  'protocol_version',
  'protocol_params',
  'server_endpoint',
  'server_public_key',
  kWinnOuterTransportKey,
  'winn3_descriptor',
  'winn3_inner_v4',
  'winn3_static_private',
  'winn3_path_mtu',
  'winn3_carrier_classes',
  'winn3_psk',
  // The Core relay route of a ciphertext relay Double VPN (w3r/1): a moved or
  // withdrawn relay is a changed plan, so a cached config that lacks it is
  // refreshed instead of retried.
  kWinn3RelayKey,
];

/// Whether the hub now serves a different winn/3 plan than [previous].
///
/// Compared on [kWinn3ServedPlanKeys] only, with map keys order-independent,
/// so client keys, the fetch stamp and transport projection never count.
bool winn3ServedPlanChanged({
  required Map<String, dynamic> previous,
  required Map<String, dynamic> current,
}) {
  for (final key in kWinn3ServedPlanKeys) {
    if (_canonicalPlanValue(previous[key]) !=
        _canonicalPlanValue(current[key])) {
      return true;
    }
  }
  return false;
}

String _canonicalPlanValue(Object? value) {
  Object? canonical(Object? node) {
    if (node is Map) {
      final keys = node.keys.map((key) => key.toString()).toList()..sort();
      return <String, Object?>{
        for (final key in keys) key: canonical(node[key]),
      };
    }
    if (node is List) return node.map(canonical).toList();
    if (node == null || node is num || node is bool || node is String) {
      return node;
    }
    return node.toString();
  }

  return jsonEncode(canonical(value));
}

/// Whether a terminal v3 failure may spend its one fresh-config retry.
///
/// Only a config that led from the cache without a hub round trip can be
/// stale in a way the hub would correct, and only one retry per tap is ever
/// taken. The retry itself runs only if the fresh plan differs
/// ([winn3ServedPlanChanged]), so a silent or refusing node with an
/// unchanged plan still fails once, not twice.
bool winn3TerminalFailureMayRetryWithFreshConfig({
  required bool configFromFastPath,
  required bool retryAlreadyUsed,
}) {
  return configFromFastPath && !retryAlreadyUsed;
}

/// Whether a cached document may lead AWG or authorize Xray without a freshly
/// served vpn_config.
///
/// V3 remains primary. V1 requires the active exact-target, generation-bound
/// ordinary-v3-failure grant, plus fresh matching listing evidence when the
/// config itself was not freshly served. Unknown protocol state is refused.
bool cachedConfigMayAuthorizeAwgOrXray({
  required Map<String, dynamic> config,
  required bool hasFreshHubConfig,
  required Map<String, dynamic>? listingNode,
}) {
  final version = strictWinnProtocolVersion(config);
  if (version == kWinnProtocolV3) return true;
  if (version != kWinnProtocolV1 ||
      !winn1FallbackDispatchMayAuthorizeConfig(config)) {
    return false;
  }
  if (hasFreshHubConfig) return true;
  final target = winn3SelectedNodeIdentity(config);
  if (target.isEmpty || listingNode == null) return false;
  return listingAuthorizesPersistedWinn1Lead(listingNode) &&
      _nodeSlug(listingNode) == target;
}

/// Whether a cached config may be used after this initiation's refresh failed.
///
/// Cover-exact always needs a fresh target config. Cached v1 may be reused
/// only after an ordinary-v3 grant and with current exact-node v1 listing
/// evidence. Cached v3 keeps automatic offline fallback, and keeps explicit
/// offline fallback when [explicitFastPathCandidate] says it would have led
/// without the hub had it been fresh: a censor that blocks the hub must not
/// strand a client whose cached config still works. Unknown state is refused.
bool mayLeadWithCachedConfigAfterRefreshFailure({
  required Map<String, dynamic> cachedConfig,
  required Map<String, dynamic>? listingNode,
  required bool automaticMode,
  required bool coverExactTarget,
  bool explicitFastPathCandidate = false,
}) {
  if (coverExactTarget) return false;
  final version = strictWinnProtocolVersion(cachedConfig);
  if (version == kWinnProtocolV1) {
    return cachedConfigMayAuthorizeAwgOrXray(
      config: cachedConfig,
      hasFreshHubConfig: false,
      listingNode: listingNode,
    );
  }
  return version == kWinnProtocolV3 &&
      (automaticMode || explicitFastPathCandidate);
}

/// True when the listing says this node has a cover-bearing TCP/stealth
/// registration. A UDP-only node is not cover against a drop-UDP censor.
bool listingNodeIsCoverBearing(Map<String, dynamic> node) {
  final stealth = (node['stealth_endpoint'] ?? node['stealthendpoint'] ?? '')
      .toString()
      .trim();
  if (stealth.isNotEmpty) return true;
  final transports = node['transports'];
  if (transports is Map) {
    final tcp =
        (transports['stealth_tcp_ws'] ?? '').toString().trim().toLowerCase();
    if (tcp == 'ok') return true;
  }
  return false;
}

/// Mirrors `_normalizeNodeItem`'s reachable default: absent means reachable,
/// because cached and bootstrap entries predate the field.
bool listingNodeIsReachable(Map<String, dynamic> node) {
  final raw = node['reachable'];
  if (raw == null) return true;
  if (raw is bool) return raw;
  final text = raw.toString().trim().toLowerCase();
  if (text.isEmpty) return true;
  return text == 'true' || text == '1' || text == 'yes';
}

String _nodeSlug(Map<String, dynamic> node) =>
    (node['slug'] ?? '').toString().trim();

/// Index of the next cover-bearing winn/1 node after [failedSlug] dies.
///
/// Returns null when there is no such successor — fail closed, no cleartext,
/// no same-node AWG downgrade. Walks [locations] in listing order. Skips:
///
///  * the failed slug and every slug in [alreadyTriedSlugs]
///  * every node labelled winn/3, regardless of carrier
///  * unknown or future protocol versions
///  * nodes the hub marked unreachable
///  * nodes with no stealth/TCP cover registration
int? indexOfCoverBearingWinn1Fallback({
  required List<Map<String, dynamic>> locations,
  required String failedSlug,
  required Set<String> alreadyTriedSlugs,
}) {
  final failed = failedSlug.trim();
  for (var index = 0; index < locations.length; index++) {
    final node = locations[index];
    final slug = _nodeSlug(node);
    if (slug.isEmpty || slug == 'auto') continue;
    if (slug == failed) continue;
    if (alreadyTriedSlugs.contains(slug)) continue;
    if (!listingNodeIsReachable(node)) continue;
    if (!listingNodeIsWinn1OrLegacy(node)) continue;
    if (!listingNodeIsCoverBearing(node)) continue;
    return index;
  }
  return null;
}

/// Whether another cover attempt is still inside the cap, given slugs
/// already tried this connect (including the original).
bool winn3CoverFallbackBudgetRemains(Set<String> alreadyTriedSlugs) {
  return alreadyTriedSlugs.length < kWinn3CoverFallbackMaxAttempts;
}

/// The node a v3 start names as its would-be failed node. A cover leg names
/// the v3 node that failed; a primary v3 start names its own selected node.
String winn3StartFailedNodeArgument({
  required bool coverFallbackInProgress,
  required String coverFailedNode,
  required String selectedSlug,
}) =>
    coverFallbackInProgress && coverFailedNode.trim().isNotEmpty
        ? coverFailedNode
        : selectedSlug;

// ---------------------------------------------------------------------------
// Ciphertext relay Double VPN (w3r/1): capability, suppression window, failure
// action. Pure functions; the dashboard owns the one in-memory window value.
// ---------------------------------------------------------------------------

/// The exact hub flag a client advertises when it can carry a Double VPN route
/// as a standalone winn/3 session to the exit through a Core relay: it
/// verifies the exit's own descriptor and dials the served `winn3_relay`.
///
/// Default-off and ABSENT from the advertisement unless true, so a build that
/// does not carry it sends exactly the capability map it sends today and the
/// hub serves it the AmneziaWG Double route it serves today.
const String kWinnClientCapabilityRelay = 'supports_winn3_relay';

/// Owner-controlled release enablement for the relay Double route, parsed like
/// [kWinn3EnabledPlatformsBuildValue]: for example
/// `--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=android`. Unknown,
/// duplicated, padded, or cased values invalidate the entire define. Empty by
/// default, which means no platform advertises [kWinnClientCapabilityRelay].
const String kWinn3RelayEnabledPlatformsBuildValue = String.fromEnvironment(
  'WINS_WINN3_RELAY_ENABLED_PLATFORMS',
  defaultValue: '',
);

/// The platforms [kWinn3RelayEnabledPlatformsBuildValue] (or [buildValue])
/// enables for the relay Double route. Any malformed element empties the set.
Set<String> winn3RelayBuildEnabledPlatforms([String? buildValue]) {
  final raw = buildValue ?? kWinn3RelayEnabledPlatformsBuildValue;
  if (raw.isEmpty) return <String>{};
  final enabled = <String>{};
  for (final part in raw.split(',')) {
    if (part.isEmpty ||
        part != part.trim() ||
        part != part.toLowerCase() ||
        !kWinn3StandaloneReleasePlatforms.contains(part) ||
        !enabled.add(part)) {
      return <String>{};
    }
  }
  return enabled;
}

/// How long a relay failure keeps this app from asking for a relay again. In
/// memory only: a restart, or the window ending, tries the relay again.
const Duration kWinn3RelaySuppressionWindow = Duration(minutes: 5);

/// Whether the suppression window opened by a relay failure is still open.
bool winn3RelaySuppressed({required DateTime? until, required DateTime now}) {
  return until != null && now.isBefore(until);
}

/// The end of a suppression window opened at [now].
DateTime winn3RelaySuppressionUntil(DateTime now) =>
    now.add(kWinn3RelaySuppressionWindow);

/// Whether this build may advertise [kWinnClientCapabilityRelay] on
/// [operatingSystem]: the platform is named by the relay define, the same
/// build already advertises `supports_winn3` and `supports_winn3_descriptor`
/// (the datapath and the verifier ring the exit descriptor needs), and no
/// relay failure window is open.
bool winnClientAdvertisesRelay({
  required String operatingSystem,
  required bool supportsWinn3,
  required bool supportsWinn3Descriptor,
  bool suppressed = false,
  String? buildValue,
}) {
  return !suppressed &&
      supportsWinn3 &&
      supportsWinn3Descriptor &&
      winn3RelayBuildEnabledPlatforms(buildValue)
          .contains(operatingSystem.trim().toLowerCase());
}

/// The relay capability as it joins the capability map: exactly
/// `{supports_winn3_relay: true}` when [winnClientAdvertisesRelay] holds and
/// the EMPTY map otherwise, so the advertisement of every build that lacks the
/// capability is unchanged byte for byte (the hub reads an absent key as
/// false).
Map<String, bool> winnClientRelayCapabilityFlags({
  required String operatingSystem,
  required bool supportsWinn3,
  required bool supportsWinn3Descriptor,
  bool suppressed = false,
  String? buildValue,
}) {
  return winnClientAdvertisesRelay(
    operatingSystem: operatingSystem,
    supportsWinn3: supportsWinn3,
    supportsWinn3Descriptor: supportsWinn3Descriptor,
    suppressed: suppressed,
    buildValue: buildValue,
  )
      ? <String, bool>{kWinnClientCapabilityRelay: true}
      : <String, bool>{};
}

/// Whether a failed relay-served start is a PATH failure (the relay or the
/// exit did not answer) rather than a typed refusal.
///
/// Only a failure the native host classified as ordinary connectivity, or as
/// the silence of an unconfirmed terminal start, qualifies. A security
/// refusal (a typed `terminal_security` verdict or a Dart-side refusal), a
/// pending verdict and an unclassified unknown one all stay terminal: they are
/// not evidence that the relay path is down.
///
/// The silence case has TWO verdict spellings and the SHAPE is what tells them
/// from a refusal. Android publishes `unknown_terminal` WITH the
/// security-refusal bit for a handshake that exhausted its attempts with
/// nothing arriving (the engine's ErrCarrierExhausted), and
/// [nativeWinn3ReadinessVerdict] reads that bit first, so the verdict of a
/// silent relay is [Winn3NativeVerdict.terminalSecurity] and only the shape
/// [Winn3FailureShape.unconfirmedTerminal] (a lone typed `unknown_terminal`,
/// never a `terminal_security`) separates it from a refused configuration. A
/// Dart-side [Winn3NativeVerdict.unknownTerminal] with that shape is the same
/// silence. A shape of [Winn3FailureShape.securityRefusal] always wins.
bool winn3RelayStartFailureIsPathFailure({
  required Winn3NativeVerdict verdict,
  required Winn3FailureShape shape,
}) {
  if (shape == Winn3FailureShape.securityRefusal) return false;
  switch (verdict) {
    case Winn3NativeVerdict.ordinaryConnectivity:
      return true;
    case Winn3NativeVerdict.unknownTerminal:
    case Winn3NativeVerdict.terminalSecurity:
      return shape == Winn3FailureShape.unconfirmedTerminal;
    case Winn3NativeVerdict.pending:
    case Winn3NativeVerdict.connected:
      return false;
  }
}

/// What the connect path does after a start failed.
enum Winn3RelayFailureAction {
  /// Not a relay path failure: the existing failure handling runs unchanged.
  none,

  /// Open the suppression window and leave the rest to the existing handling
  /// (an upgrade attempt restores its single hop session; the upgrade loop
  /// then asks again without the relay).
  suppressOnly,

  /// Open the suppression window, stop the native tunnel and run ONE full
  /// connect again. The capability is not sent during the window, so the hub
  /// serves today's AmneziaWG Double.
  suppressAndRetry,
}

/// The action for a failed start of [config] (the config that led the attempt).
Winn3RelayFailureAction winn3RelayFailureAction({
  required Map<String, dynamic> config,
  required bool isUpgradeAttempt,
  required bool retryAlreadyUsed,
  required Winn3NativeVerdict verdict,
  required Winn3FailureShape shape,
}) {
  if (readWinn3ServedRelay(config).kind != Winn3RelayReadKind.valid) {
    return Winn3RelayFailureAction.none;
  }
  if (!winn3RelayStartFailureIsPathFailure(verdict: verdict, shape: shape)) {
    return Winn3RelayFailureAction.none;
  }
  if (isUpgradeAttempt || retryAlreadyUsed) {
    return Winn3RelayFailureAction.suppressOnly;
  }
  return Winn3RelayFailureAction.suppressAndRetry;
}
