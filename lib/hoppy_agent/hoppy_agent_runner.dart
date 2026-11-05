// Hoppy agent runner: receives a user request, chooses a structured action,
// evaluates it through the deterministic policy engine, and returns a result.
// Authority: docs/design/HOPPY_AGENT_V1_20260811.md
// Principle: model proposes, engine disposes. This runner is the harness that
// wires a deterministic proposer (keyword map) to the engine for E2E testing.
// No model weights are loaded; proposer is rule-based and deterministic.

import 'hoppy_action_schema.dart';
import 'hoppy_corpus_gate.dart';
import 'hoppy_policy_engine.dart';

/// Result of an agent handling a single request end to end.
class HoppyAgentResult {
  const HoppyAgentResult({
    required this.requestId,
    required this.userText,
    required this.chosenAction,
    required this.decision,
    required this.assistantText,
    required this.transcriptJson,
  });

  /// Request id supplied by caller (or auto-generated).
  final String requestId;

  /// Original user text that was received.
  final String userText;

  /// Action the proposer chose (or the raw unknown string if denied).
  final String chosenAction;

  /// Policy engine decision.
  final HoppyPolicyDecision decision;

  /// Text the agent would return to the user (without em dash).
  final String assistantText;

  /// Machine-readable transcript of the whole handling, serialized as map.
  final Map<String, Object?> transcriptJson;

  Map<String, Object?> toJson() => transcriptJson;
}

/// Minimal deterministic proposer. Maps user utterances to a schema action
/// via keyword rules. This stands in for the LLM proposing a structured
/// call; the security guarantee is that even if the proposer is tricked,
/// the policy engine still refuses/escalates.
String _proposeAction(String userText) {
  final lower = userText.toLowerCase();
  // Tier2 triggers first so injection attempting to promote tier2 stays tier2
  if (lower.contains('refund') || lower.contains('chargeback')) {
    if (lower.contains('refund')) return 'request_refund';
    return 'request_chargeback';
  }
  if (lower.contains('prepaid')) {
    if (lower.contains('issue')) return 'issue_prepaid_code';
    if (lower.contains('revoke')) return 'revoke_prepaid_code';
    return 'lookup_prepaid_code';
  }
  if (lower.contains('delete account') || lower.contains('delete my account')) {
    return 'delete_account';
  }
  if (lower.contains('change email') || lower.contains('update email')) {
    return 'change_email_on_file';
  }
  if (lower.contains('other account') || lower.contains("friend") && lower.contains('reset')) {
    return 'access_other_account';
  }
  if (lower.contains('disable') && lower.contains('security')) {
    return 'disable_security_feature';
  }
  if (lower.contains('server') || lower.contains('region')) {
    if (lower.contains('manage server') || lower.contains('add server')) {
      return 'manage_servers';
    }
    return 'change_preferred_server';
  }
  // Tier1
  if (lower.contains('device limit') || lower.contains('reset limit') || lower.contains('clear device')) {
    return 'reset_device_limit';
  }
  if (lower.contains('revoke') && (lower.contains('device') || lower.contains('session'))) {
    return 'revoke_device_session';
  }
  if (lower.contains('resend') && (lower.contains('credential') || lower.contains('password') || lower.contains('login'))) {
    return 'resend_credentials';
  }
  if (lower.contains('receipt') && (lower.contains('reissue') || lower.contains('resend') || lower.contains('send'))) {
    return 'reissue_receipt';
  }
  if (lower.contains('preference') || lower.contains('toggle') && lower.contains('notification')) {
    return 'toggle_non_security_preference';
  }
  // Tier0
  if (lower.contains('plan') || lower.contains('expiry') || lower.contains('renewal') || lower.contains('subscription status')) {
    return 'get_plan_status';
  }
  if (lower.contains('device list') || lower.contains('how many device')) {
    return 'get_device_list';
  }
  if (lower.contains('server list') || lower.contains('which server') || lower.contains('recommended server')) {
    return 'get_server_list';
  }
  if (lower.contains('troubleshoot') || lower.contains('cannot connect') || lower.contains('vpn not connecting')) {
    return 'get_troubleshooting_guidance';
  }
  if (lower.contains('lookup receipt') || lower.contains('find receipt')) {
    return 'lookup_receipt';
  }
  // Unknown
  return 'unknown_action_for_test';
}

/// Deterministic agent that handles a request end to end.
class HoppyAgent {
  HoppyAgent({
    HoppyPolicyEngine? engine,
    DateTime Function()? clock,
  })  : _engine = engine ?? HoppyPolicyEngine(clock: clock),
        _clock = clock ?? DateTime.now;

  final HoppyPolicyEngine _engine;
  final DateTime Function() _clock;

  HoppyPolicyEngine get engine => _engine;

  /// Handle a user request end to end, returning a transcript.
  HoppyAgentResult handle({
    required HoppySession session,
    required String userText,
    String? requestId,
    Map<String, Object?> parameters = const {},
    DateTime? proposedAt,
  }) {
    final rid = requestId ?? 'req_${_clock().millisecondsSinceEpoch}';
    final now = _clock();
    final chosen = _proposeAction(userText);

    // Build structured request as the model would propose it.
    final request = HoppyActionRequest(
      action: chosen,
      accountId: session.accountId,
      requestId: rid,
      proposedAt: proposedAt ?? now,
      parameters: parameters,
      chatContent: userText,
    );

    // Policy engine disposes.
    final decision = _engine.evaluate(session: session, request: request);

    // Build assistant text that would be returned to user.
    final String assistantText;
    if (decision.isAllow) {
      if (decision.tier == HoppyActionTier.tier1) {
        assistantText = 'Done: $chosen completed for your account. Audit id ${decision.auditRecord?.requestId}.';
      } else {
        assistantText = 'Here is the information you requested for $chosen.';
      }
    } else if (decision.isEscalate) {
      assistantText = 'This request requires human review. Ticket ${decision.ticketReference} has been created.';
    } else {
      assistantText = 'Sorry, I cannot do that: ${decision.reason}.';
    }

    // Enforce em dash gate on output (probe must pass).
    assert(
      hoppyProbeOutput(assistantText),
      'assistantText violated em dash gate: $assistantText',
    );

    // Build machine transcript.
    final transcript = <String, Object?>{
      'received_at': now.toIso8601String(),
      'session': {
        'accountId': session.accountId,
        'sessionId': session.sessionId,
        'expiresAt': session.expiresAt.toIso8601String(),
      },
      'userText': userText,
      'requestId': rid,
      'chosenAction': chosen,
      'decision': decision.decision.name,
      'reason': decision.reason,
      'tier': decision.tier?.name,
      'ticketReference': decision.ticketReference,
      'auditRecord': decision.auditRecord?.toJson(),
      'assistantText': assistantText,
      'gateProbePassed': hoppyProbeOutput(assistantText),
      'schemaVersion': kHoppySchemaVersion,
    };

    return HoppyAgentResult(
      requestId: rid,
      userText: userText,
      chosenAction: chosen,
      decision: decision,
      assistantText: assistantText,
      transcriptJson: transcript,
    );
  }

  /// Variant that accepts an externally proposed action (simulates model output)
  /// rather than inferring from text. Useful for injection tests where the
  /// model is tricked into proposing a tier2 action under tier1 guise.
  HoppyAgentResult handleWithProposedAction({
    required HoppySession session,
    required String userText,
    required String proposedAction,
    String? requestId,
    Map<String, Object?> parameters = const {},
    DateTime? proposedAt,
  }) {
    final rid = requestId ?? 'req_${_clock().millisecondsSinceEpoch}';
    final now = _clock();
    final request = HoppyActionRequest(
      action: proposedAction,
      accountId: session.accountId,
      requestId: rid,
      proposedAt: proposedAt ?? now,
      parameters: parameters,
      chatContent: userText,
    );
    final decision = _engine.evaluate(session: session, request: request);
    final String assistantText;
    if (decision.isAllow) {
      if (decision.tier == HoppyActionTier.tier1) {
        assistantText = 'Done: $proposedAction completed for your account. Audit id ${decision.auditRecord?.requestId}.';
      } else {
        assistantText = 'Here is the information you requested for $proposedAction.';
      }
    } else if (decision.isEscalate) {
      assistantText = 'This request requires human review. Ticket ${decision.ticketReference} has been created.';
    } else {
      assistantText = 'Sorry, I cannot do that: ${decision.reason}.';
    }
    assert(hoppyProbeOutput(assistantText));
    final transcript = <String, Object?>{
      'received_at': now.toIso8601String(),
      'session': {
        'accountId': session.accountId,
        'sessionId': session.sessionId,
        'expiresAt': session.expiresAt.toIso8601String(),
      },
      'userText': userText,
      'requestId': rid,
      'chosenAction': proposedAction,
      'decision': decision.decision.name,
      'reason': decision.reason,
      'tier': decision.tier?.name,
      'ticketReference': decision.ticketReference,
      'auditRecord': decision.auditRecord?.toJson(),
      'assistantText': assistantText,
      'gateProbePassed': hoppyProbeOutput(assistantText),
      'schemaVersion': kHoppySchemaVersion,
    };
    return HoppyAgentResult(
      requestId: rid,
      userText: userText,
      chosenAction: proposedAction,
      decision: decision,
      assistantText: assistantText,
      transcriptJson: transcript,
    );
  }
}
