// Hoppy policy engine
// Authority: docs/design/HOPPY_AGENT_V1_20260811.md
// Principle: the model proposes, a deterministic policy engine disposes.
// The model never executes anything. This engine authorises every request
// against the authenticated session, the action tier, and rate budgets.

import 'hoppy_action_schema.dart';

/// Authenticated session. Identity comes from here, never from conversation.
///
/// No string in chat can establish who the user is or promote a tier.
class HoppySession {
  const HoppySession({
    required this.accountId,
    required this.sessionId,
    required this.expiresAt,
    required this.issuedAt,
  });

  /// Account that this session is authenticated as. All Tier 0 and Tier 1
  /// actions are scoped to this account. Any request targeting a different
  /// account is Tier 2 by definition.
  final String accountId;

  /// Opaque session identifier.
  final String sessionId;

  /// Point in time after which the session is no longer valid. The engine
  /// checks this at execution time, so a session that expired between
  /// proposal and execution is denied.
  final DateTime expiresAt;

  /// When the session was issued, for audit completeness.
  final DateTime issuedAt;

  bool isExpiredAt(DateTime now) => now.isAfter(expiresAt);
}

/// Structured action request emitted by the model. The model never executes
/// anything; it only proposes this structure.
class HoppyActionRequest {
  const HoppyActionRequest({
    required this.action,
    required this.accountId,
    required this.requestId,
    required this.proposedAt,
    this.parameters = const <String, Object?>{},
    this.chatContent,
  });

  /// Action name. Must be present in [kHoppyActionSchema] with exact match.
  /// Case or homoglyph variants are unknown and refused.
  final String action;

  /// Account the request claims to act on. The engine compares this against
  /// [HoppySession.accountId] and refuses or escalates on mismatch.
  final String accountId;

  /// Unique request identifier for replay protection and audit correlation.
  final String requestId;

  /// When the request was proposed.
  final DateTime proposedAt;

  /// Action parameters. For Tier 1 actions that involve email, any attempt to
  /// supply an email address is rejected; those actions always use the email
  /// already on file. The engine never trusts an address from chat.
  final Map<String, Object?> parameters;

  /// Raw chat content or system prompt fragment that may contain injected
  /// instructions. The engine ignores this field entirely. It exists so tests
  /// can prove that injection does not affect the decision.
  final String? chatContent;
}

/// Result of policy evaluation.
enum HoppyDecision {
  allow,
  escalate,
  deny,
}

/// Reason codes for deny and escalate. These are stable strings that tests
/// assert on.
class HoppyDecisionReason {
  static const String unknownAction = 'unknown_action';
  static const String crossAccount = 'cross_account_denied';
  static const String sessionExpired = 'session_expired';
  static const String replayedRequestId = 'replayed_request_id';
  static const String rateLimited = 'rate_limited';
  static const String tier2Escalation = 'tier2_requires_human';
  static const String allowTier0 = 'allow_tier0_read_only';
  static const String allowTier1 = 'allow_tier1_audited';
  static const String emailOverrideRejected = 'email_override_rejected';
  static const String missingRequestId = 'missing_request_id';
  static const String missingAccountId = 'missing_account_id';
}

/// What the engine returns for every request.
class HoppyPolicyDecision {
  const HoppyPolicyDecision({
    required this.decision,
    required this.reason,
    required this.tier,
    this.auditRecord,
    this.ticketReference,
  });

  final HoppyDecision decision;
  final String reason;
  final HoppyActionTier? tier;
  final HoppyAuditRecord? auditRecord;
  final String? ticketReference;

  bool get isAllow => decision == HoppyDecision.allow;
  bool get isEscalate => decision == HoppyDecision.escalate;
  bool get isDeny => decision == HoppyDecision.deny;
}

/// Audit record written for every Tier 1 execution. The actor is always
/// hoppy-agent, naming the account, action, timestamp and request id.
class HoppyAuditRecord {
  const HoppyAuditRecord({
    required this.actor,
    required this.accountId,
    required this.action,
    required this.timestamp,
    required this.requestId,
    required this.sessionId,
    required this.schemaVersion,
  });

  final String actor;
  final String accountId;
  final String action;
  final DateTime timestamp;
  final String requestId;
  final String sessionId;
  final String schemaVersion;

  Map<String, Object?> toJson() => <String, Object?>{
        'actor': actor,
        'accountId': accountId,
        'action': action,
        'timestamp': timestamp.toIso8601String(),
        'requestId': requestId,
        'sessionId': sessionId,
        'schemaVersion': schemaVersion,
      };
}

/// Per account per action rate budget. Sliding window.
class HoppyRateBudget {
  HoppyRateBudget({
    this.maxRequests = 5,
    this.window = const Duration(minutes: 1),
  });

  final int maxRequests;
  final Duration window;

  final Map<String, List<DateTime>> _history = <String, List<DateTime>>{};

  String _key(String accountId, String action) => '$accountId::$action';

  bool isAllowed(String accountId, String action, DateTime now) {
    final key = _key(accountId, action);
    final timestamps = _history[key] ?? <DateTime>[];
    final cutoff = now.subtract(window);
    final recent = timestamps.where((t) => t.isAfter(cutoff)).toList();
    _history[key] = recent;
    return recent.length < maxRequests;
  }

  void record(String accountId, String action, DateTime now) {
    final key = _key(accountId, action);
    final list = _history.putIfAbsent(key, () => <DateTime>[]);
    list.add(now);
  }

  void clear() => _history.clear();
}

/// Deterministic policy engine. All decisions are derived from session,
/// schema, and rate state. No model output, no chat content, and no prompt
/// can override the decision.
class HoppyPolicyEngine {
  HoppyPolicyEngine({
    DateTime Function()? clock,
    HoppyRateBudget? rateBudget,
    String Function(String requestId)? ticketGenerator,
  })  : _clock = clock ?? DateTime.now,
        _rateBudget = rateBudget ?? HoppyRateBudget(),
        _ticketGenerator = ticketGenerator ??
            ((String requestId) =>
                'HOPPY-T2-${requestId.substring(0, requestId.length > 8 ? 8 : requestId.length).toUpperCase()}-${DateTime.now().millisecondsSinceEpoch}');

  final DateTime Function() _clock;
  final HoppyRateBudget _rateBudget;
  final String Function(String) _ticketGenerator;

  // Replay protection: per account set of seen request ids.
  final Map<String, Set<String>> _seenRequestIds = <String, Set<String>>{};

  // Audit log: in memory, ordered. Production control plane persists this.
  final List<HoppyAuditRecord> _auditLog = <HoppyAuditRecord>[];

  List<HoppyAuditRecord> get auditLog => List<HoppyAuditRecord>.unmodifiable(_auditLog);

  void clearState() {
    _seenRequestIds.clear();
    _auditLog.clear();
    _rateBudget.clear();
  }

  HoppyPolicyDecision evaluate({
    required HoppySession session,
    required HoppyActionRequest request,
  }) {
    final now = _clock();

    // Basic validation: missing identifiers are denied before any other check.
    if (request.requestId.trim().isEmpty) {
      return const HoppyPolicyDecision(
        decision: HoppyDecision.deny,
        reason: HoppyDecisionReason.missingRequestId,
        tier: null,
      );
    }
    if (request.accountId.trim().isEmpty) {
      return const HoppyPolicyDecision(
        decision: HoppyDecision.deny,
        reason: HoppyDecisionReason.missingAccountId,
        tier: null,
      );
    }

    // Identity is from session, and session expiry is checked at execution
    // time. A session that expired between proposal and execution is denied.
    if (session.isExpiredAt(now)) {
      return HoppyPolicyDecision(
        decision: HoppyDecision.deny,
        reason: HoppyDecisionReason.sessionExpired,
        tier: tierForHoppyAction(request.action),
      );
    }

    // Replay protection: same request id for same account must not execute
    // twice. This is keyed by account so an attacker cannot poison another
    // account's id space.
    final accountSeen = _seenRequestIds.putIfAbsent(
        session.accountId, () => <String>{});
    if (accountSeen.contains(request.requestId)) {
      return HoppyPolicyDecision(
        decision: HoppyDecision.deny,
        reason: HoppyDecisionReason.replayedRequestId,
        tier: tierForHoppyAction(request.action),
      );
    }

    // Cross account check. Any request that names an account other than the
    // authenticated session's account is Tier 2 by definition and is never
    // allowed autonomously. We return escalate with a ticket so it can be
    // handled by a human, and we also record the replay id so it cannot be
    // retried as a deny bypass.
    if (request.accountId != session.accountId) {
      accountSeen.add(request.requestId);
      final ticket = _ticketGenerator(request.requestId);
      return HoppyPolicyDecision(
        decision: HoppyDecision.escalate,
        reason: HoppyDecisionReason.crossAccount,
        tier: HoppyActionTier.tier2,
        ticketReference: ticket,
      );
    }

    // Refuse by default: action absent from schema is denied, not passed
    // through. Lookup is exact, case sensitive, no normalization.
    final definition = kHoppyActionSchema[request.action];
    if (definition == null) {
      accountSeen.add(request.requestId);
      return const HoppyPolicyDecision(
        decision: HoppyDecision.deny,
        reason: HoppyDecisionReason.unknownAction,
        tier: null,
      );
    }

    // For actions that must only use the email on file, reject any attempt
    // to supply an email via parameters or chat. This enforces the design
    // rule that resend_credentials and reissue_receipt never send to an
    // address supplied in chat.
    if (definition.name == 'resend_credentials' ||
        definition.name == 'reissue_receipt') {
      if (_containsEmailOverride(request.parameters)) {
        accountSeen.add(request.requestId);
        return HoppyPolicyDecision(
          decision: HoppyDecision.deny,
          reason: HoppyDecisionReason.emailOverrideRejected,
          tier: definition.tier,
        );
      }
      // Also check chatContent for an email pattern that looks like an
      // override attempt. The engine ignores chat for identity and tier, but
      // for these two actions it actively refuses if chat tries to smuggle
      // an email. This is defence in depth; the primary guarantee is that
      // the control plane never reads an email from chat at all.
      if (request.chatContent != null &&
          _containsEmailInText(request.chatContent!)) {
        // We do not deny on chat email alone, because chat may legitimately
        // mention an email. The guarantee is that the execution will use
        // the account's stored email. So we do not deny here; the audit
        // record will show the action was sent to the account email.
        // This branch is intentionally not a deny.
      }
    }

    // Rate budgets per account per action. Check before tier decision so a
    // compromised session cannot loop any action, including Tier 0.
    if (!_rateBudget.isAllowed(session.accountId, request.action, now)) {
      accountSeen.add(request.requestId);
      return HoppyPolicyDecision(
        decision: HoppyDecision.deny,
        reason: HoppyDecisionReason.rateLimited,
        tier: definition.tier,
      );
    }

    // Tier dispatch. The tier comes from the schema, never from chat.
    // No string in chat can promote a tier.
    switch (definition.tier) {
      case HoppyActionTier.tier0:
        accountSeen.add(request.requestId);
        _rateBudget.record(session.accountId, request.action, now);
        return const HoppyPolicyDecision(
          decision: HoppyDecision.allow,
          reason: HoppyDecisionReason.allowTier0,
          tier: HoppyActionTier.tier0,
        );
      case HoppyActionTier.tier1:
        accountSeen.add(request.requestId);
        _rateBudget.record(session.accountId, request.action, now);
        final audit = HoppyAuditRecord(
          actor: 'hoppy-agent',
          accountId: session.accountId,
          action: definition.name,
          timestamp: now,
          requestId: request.requestId,
          sessionId: session.sessionId,
          schemaVersion: kHoppySchemaVersion,
        );
        _auditLog.add(audit);
        return HoppyPolicyDecision(
          decision: HoppyDecision.allow,
          reason: HoppyDecisionReason.allowTier1,
          tier: HoppyActionTier.tier1,
          auditRecord: audit,
        );
      case HoppyActionTier.tier2:
        accountSeen.add(request.requestId);
        _rateBudget.record(session.accountId, request.action, now);
        final ticket = _ticketGenerator(request.requestId);
        return HoppyPolicyDecision(
          decision: HoppyDecision.escalate,
          reason: HoppyDecisionReason.tier2Escalation,
          tier: HoppyActionTier.tier2,
          ticketReference: ticket,
        );
    }
  }

  bool _containsEmailOverride(Map<String, Object?> params) {
    for (final key in params.keys) {
      final lower = key.toLowerCase();
      if (lower.contains('email') ||
          lower.contains('target') && lower.contains('mail') ||
          lower == 'to' ||
          lower == 'recipient') {
        final value = params[key];
        if (value is String && value.trim().isNotEmpty) {
          return true;
        }
      }
    }
    return false;
  }

  bool _containsEmailInText(String text) {
    // Simple pattern to detect an email like string in chat. This is not
    // used to extract the email, only to note that chat contained one.
    // The engine never uses this email.
    final emailPattern = RegExp(r'[^\s@]+@[^\s@]+\.[^\s@]+');
    return emailPattern.hasMatch(text);
  }
}
