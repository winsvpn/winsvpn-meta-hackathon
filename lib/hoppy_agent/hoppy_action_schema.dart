// Hoppy Agent v1 action schema
// Authority: docs/design/HOPPY_AGENT_V1_20260811.md
// Principle: the model proposes, a deterministic policy engine disposes.
// Every action carries an explicit tier. Adding an action requires editing
// this file, never just a prompt.

/// Schema version. Bump whenever the action set or tier mapping changes.
const String kHoppySchemaVersion = 'hoppy-agent-actions/v1';

/// Action tier, exactly as defined in the design doc.
///
/// Tier 0 is read only with no side effects.
/// Tier 1 is mutating, autonomous, audited and reversible, scoped to the
/// authenticated account.
/// Tier 2 never runs autonomously and always escalates.
enum HoppyActionTier {
  tier0,
  tier1,
  tier2,
}

/// Definition of a single Hoppy action.
class HoppyActionDefinition {
  const HoppyActionDefinition({
    required this.name,
    required this.tier,
    required this.description,
    required this.reversible,
    required this.scopedToAuthenticatedAccount,
  });

  /// Canonical action name. Lookup is exact, case sensitive, no unicode
  /// normalization. A name that differs by case or homoglyph is unknown.
  final String name;

  /// Tier assignment from the design doc. This is the security boundary.
  final HoppyActionTier tier;

  /// Human readable description taken from the design doc bullet.
  final String description;

  /// Whether the action is reversible by a human. True for Tier 1, false for
  /// Tier 2, not applicable for Tier 0.
  final bool reversible;

  /// Whether the action is scoped to the authenticated account.
  final bool scopedToAuthenticatedAccount;
}

// Tier 0: read only, no side effects (5 actions)
const HoppyActionDefinition kActionGetPlanStatus =
    HoppyActionDefinition(
  name: 'get_plan_status',
  tier: HoppyActionTier.tier0,
  description: 'plan status, expiry, renewal date',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionGetDeviceList =
    HoppyActionDefinition(
  name: 'get_device_list',
  tier: HoppyActionTier.tier0,
  description: 'device count and device list for the authenticated account',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionGetServerList =
    HoppyActionDefinition(
  name: 'get_server_list',
  tier: HoppyActionTier.tier0,
  description: 'server list and a recommended server',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionGetTroubleshootingGuidance =
    HoppyActionDefinition(
  name: 'get_troubleshooting_guidance',
  tier: HoppyActionTier.tier0,
  description: 'connection troubleshooting guidance',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionLookupReceipt =
    HoppyActionDefinition(
  name: 'lookup_receipt',
  tier: HoppyActionTier.tier0,
  description: 'receipt lookup for the authenticated account',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

// Tier 1: mutating, autonomous, audited and reversible, scoped to
// authenticated account (6 actions)
const HoppyActionDefinition kActionResetDeviceLimit =
    HoppyActionDefinition(
  name: 'reset_device_limit',
  tier: HoppyActionTier.tier1,
  description: 'reset the device limit, clear the device list',
  reversible: true,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionRevokeDeviceSession =
    HoppyActionDefinition(
  name: 'revoke_device_session',
  tier: HoppyActionTier.tier1,
  description: 'revoke one named device session',
  reversible: true,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionResendCredentials =
    HoppyActionDefinition(
  name: 'resend_credentials',
  tier: HoppyActionTier.tier1,
  description:
      'resend account credentials to the email already on file, never to an address supplied in chat',
  reversible: true,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionReissueReceipt =
    HoppyActionDefinition(
  name: 'reissue_receipt',
  tier: HoppyActionTier.tier1,
  description: 'reissue a receipt to the email already on file',
  reversible: true,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionChangePreferredServer =
    HoppyActionDefinition(
  name: 'change_preferred_server',
  tier: HoppyActionTier.tier1,
  description: 'change the preferred server or region',
  reversible: true,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionToggleNonSecurityPreference =
    HoppyActionDefinition(
  name: 'toggle_non_security_preference',
  tier: HoppyActionTier.tier1,
  description: 'toggle non-security preferences',
  reversible: true,
  scopedToAuthenticatedAccount: true,
);

// Tier 2: never autonomous, always escalate to a human (17 actions)
// Each bullet from the design doc is represented explicitly.
// Adding any new admin surface requires editing this list.

const HoppyActionDefinition kActionAccessOtherAccount =
    HoppyActionDefinition(
  name: 'access_other_account',
  tier: HoppyActionTier.tier2,
  description: 'anything concerning an account other than the authenticated one',
  reversible: false,
  scopedToAuthenticatedAccount: false,
);

const HoppyActionDefinition kActionChangeEmailOnFile =
    HoppyActionDefinition(
  name: 'change_email_on_file',
  tier: HoppyActionTier.tier2,
  description: 'changing the email on file',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionChangePhoneNumber =
    HoppyActionDefinition(
  name: 'change_phone_number',
  tier: HoppyActionTier.tier2,
  description: 'changing the phone number',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionChangeRecoveryContact =
    HoppyActionDefinition(
  name: 'change_recovery_contact',
  tier: HoppyActionTier.tier2,
  description: 'changing the recovery contact',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionRequestRefund =
    HoppyActionDefinition(
  name: 'request_refund',
  tier: HoppyActionTier.tier2,
  description: 'refunds, involving money',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionRequestChargeback =
    HoppyActionDefinition(
  name: 'request_chargeback',
  tier: HoppyActionTier.tier2,
  description: 'chargebacks, involving money',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionChangePaymentMethod =
    HoppyActionDefinition(
  name: 'change_payment_method',
  tier: HoppyActionTier.tier2,
  description: 'payment method changes, involving money',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionChangeSubscriptionTier =
    HoppyActionDefinition(
  name: 'change_subscription_tier',
  tier: HoppyActionTier.tier2,
  description: 'subscription tier changes involving money',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionDeleteAccount =
    HoppyActionDefinition(
  name: 'delete_account',
  tier: HoppyActionTier.tier2,
  description: 'account deletion',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionIssuePrepaidCode =
    HoppyActionDefinition(
  name: 'issue_prepaid_code',
  tier: HoppyActionTier.tier2,
  description: 'issuing prepaid redemption codes',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionRevokePrepaidCode =
    HoppyActionDefinition(
  name: 'revoke_prepaid_code',
  tier: HoppyActionTier.tier2,
  description: 'revoking prepaid redemption codes',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionLookupPrepaidCode =
    HoppyActionDefinition(
  name: 'lookup_prepaid_code',
  tier: HoppyActionTier.tier2,
  description: 'looking up prepaid redemption codes',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

const HoppyActionDefinition kActionManageServers =
    HoppyActionDefinition(
  name: 'manage_servers',
  tier: HoppyActionTier.tier2,
  description: 'anything touching servers',
  reversible: false,
  scopedToAuthenticatedAccount: false,
);

const HoppyActionDefinition kActionManageKeys =
    HoppyActionDefinition(
  name: 'manage_keys',
  tier: HoppyActionTier.tier2,
  description: 'anything touching keys',
  reversible: false,
  scopedToAuthenticatedAccount: false,
);

const HoppyActionDefinition kActionManageCredentials =
    HoppyActionDefinition(
  name: 'manage_credentials',
  tier: HoppyActionTier.tier2,
  description: 'anything touching credentials',
  reversible: false,
  scopedToAuthenticatedAccount: false,
);

const HoppyActionDefinition kActionManageInfrastructure =
    HoppyActionDefinition(
  name: 'manage_infrastructure',
  tier: HoppyActionTier.tier2,
  description: 'anything touching infrastructure',
  reversible: false,
  scopedToAuthenticatedAccount: false,
);

const HoppyActionDefinition kActionDisableSecurityFeature =
    HoppyActionDefinition(
  name: 'disable_security_feature',
  tier: HoppyActionTier.tier2,
  description: 'disabling a security feature',
  reversible: false,
  scopedToAuthenticatedAccount: true,
);

/// Versioned canonical schema. This is the single source of truth for
/// which actions exist and which tier they belong to. The policy engine
/// refuses any action not present here.
///
/// To add a new action, edit this map and bump [kHoppySchemaVersion].
/// No prompt can add an action at runtime.
const Map<String, HoppyActionDefinition> kHoppyActionSchema =
    <String, HoppyActionDefinition>{
  // Tier 0
  'get_plan_status': kActionGetPlanStatus,
  'get_device_list': kActionGetDeviceList,
  'get_server_list': kActionGetServerList,
  'get_troubleshooting_guidance': kActionGetTroubleshootingGuidance,
  'lookup_receipt': kActionLookupReceipt,
  // Tier 1
  'reset_device_limit': kActionResetDeviceLimit,
  'revoke_device_session': kActionRevokeDeviceSession,
  'resend_credentials': kActionResendCredentials,
  'reissue_receipt': kActionReissueReceipt,
  'change_preferred_server': kActionChangePreferredServer,
  'toggle_non_security_preference': kActionToggleNonSecurityPreference,
  // Tier 2
  'access_other_account': kActionAccessOtherAccount,
  'change_email_on_file': kActionChangeEmailOnFile,
  'change_phone_number': kActionChangePhoneNumber,
  'change_recovery_contact': kActionChangeRecoveryContact,
  'request_refund': kActionRequestRefund,
  'request_chargeback': kActionRequestChargeback,
  'change_payment_method': kActionChangePaymentMethod,
  'change_subscription_tier': kActionChangeSubscriptionTier,
  'delete_account': kActionDeleteAccount,
  'issue_prepaid_code': kActionIssuePrepaidCode,
  'revoke_prepaid_code': kActionRevokePrepaidCode,
  'lookup_prepaid_code': kActionLookupPrepaidCode,
  'manage_servers': kActionManageServers,
  'manage_keys': kActionManageKeys,
  'manage_credentials': kActionManageCredentials,
  'manage_infrastructure': kActionManageInfrastructure,
  'disable_security_feature': kActionDisableSecurityFeature,
};

/// Returns true if the action name is present in the schema, using exact
/// string equality only. No case folding, no unicode normalization, no
/// homoglyph resolution. A near miss is unknown.
bool isKnownHoppyAction(String name) {
  return kHoppyActionSchema.containsKey(name);
}

/// Returns the tier for a known action, or null if unknown.
HoppyActionTier? tierForHoppyAction(String name) {
  return kHoppyActionSchema[name]?.tier;
}

/// All tier 0 action names.
List<String> get hoppyTier0Actions => kHoppyActionSchema.entries
    .where((e) => e.value.tier == HoppyActionTier.tier0)
    .map((e) => e.key)
    .toList(growable: false);

/// All tier 1 action names.
List<String> get hoppyTier1Actions => kHoppyActionSchema.entries
    .where((e) => e.value.tier == HoppyActionTier.tier1)
    .map((e) => e.key)
    .toList(growable: false);

/// All tier 2 action names.
List<String> get hoppyTier2Actions => kHoppyActionSchema.entries
    .where((e) => e.value.tier == HoppyActionTier.tier2)
    .map((e) => e.key)
    .toList(growable: false);
