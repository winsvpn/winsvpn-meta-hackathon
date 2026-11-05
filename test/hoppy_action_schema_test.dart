import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/hoppy_agent/hoppy_action_schema.dart';

void main() {
  test('schema version is pinned and non-empty', () {
    expect(kHoppySchemaVersion, isNotEmpty);
    expect(kHoppySchemaVersion, 'hoppy-agent-actions/v1');
  });

  test('schema contains exactly the expected counts per tier', () {
    expect(hoppyTier0Actions.length, 5,
        reason: 'Tier 0 must have exactly 5 read only actions');
    expect(hoppyTier1Actions.length, 6,
        reason: 'Tier 1 must have exactly 6 autonomous actions');
    expect(hoppyTier2Actions.length, 17,
        reason: 'Tier 2 must have exactly 17 escalating actions');
    expect(kHoppyActionSchema.length, 28,
        reason: 'Total schema size must be 28, no more no less');
  });

  test('all expected Tier 0 actions are present with correct tier', () {
    const expected = <String>[
      'get_plan_status',
      'get_device_list',
      'get_server_list',
      'get_troubleshooting_guidance',
      'lookup_receipt',
    ];
    for (final name in expected) {
      expect(isKnownHoppyAction(name), isTrue, reason: '$name must be known');
      expect(tierForHoppyAction(name), HoppyActionTier.tier0,
          reason: '$name must be tier0');
    }
  });

  test('all expected Tier 1 actions are present with correct tier', () {
    const expected = <String>[
      'reset_device_limit',
      'revoke_device_session',
      'resend_credentials',
      'reissue_receipt',
      'change_preferred_server',
      'toggle_non_security_preference',
    ];
    for (final name in expected) {
      expect(isKnownHoppyAction(name), isTrue, reason: '$name must be known');
      expect(tierForHoppyAction(name), HoppyActionTier.tier1,
          reason: '$name must be tier1');
    }
  });

  test('all expected Tier 2 actions are present with correct tier', () {
    const expected = <String>[
      'access_other_account',
      'change_email_on_file',
      'change_phone_number',
      'change_recovery_contact',
      'request_refund',
      'request_chargeback',
      'change_payment_method',
      'change_subscription_tier',
      'delete_account',
      'issue_prepaid_code',
      'revoke_prepaid_code',
      'lookup_prepaid_code',
      'manage_servers',
      'manage_keys',
      'manage_credentials',
      'manage_infrastructure',
      'disable_security_feature',
    ];
    for (final name in expected) {
      expect(isKnownHoppyAction(name), isTrue, reason: '$name must be known');
      expect(tierForHoppyAction(name), HoppyActionTier.tier2,
          reason: '$name must be tier2');
    }
  });

  test('Tier 1 actions are reversible and scoped to authenticated account', () {
    for (final name in hoppyTier1Actions) {
      final def = kHoppyActionSchema[name]!;
      expect(def.reversible, isTrue,
          reason: '$name Tier1 must be reversible');
      expect(def.scopedToAuthenticatedAccount, isTrue,
          reason: '$name Tier1 must be scoped to authenticated account');
    }
  });

  test('Tier 2 actions are never reversible', () {
    for (final name in hoppyTier2Actions) {
      final def = kHoppyActionSchema[name]!;
      expect(def.reversible, isFalse,
          reason: '$name Tier2 must not be reversible');
    }
  });

  test('lookup is exact, case sensitive, no normalization', () {
    expect(isKnownHoppyAction('Reset_Device_Limit'), isFalse);
    expect(isKnownHoppyAction('RESET_DEVICE_LIMIT'), isFalse);
    expect(isKnownHoppyAction('reset_device_limit '), isFalse);
    expect(isKnownHoppyAction(' reset_device_limit'), isFalse);
    // Unicode homoglyph: Cyrillic a (U+0430) looks like latin a
    expect(isKnownHoppyAction('reset_device_limit\u0430'), isFalse);
    expect(isKnownHoppyAction('get_plan_status'), isTrue);
  });

  test('unknown action returns null tier', () {
    expect(tierForHoppyAction('unknown_action_xyz'), isNull);
    expect(tierForHoppyAction(''), isNull);
    expect(tierForHoppyAction('delete_account '), isNull);
  });

  test('every definition has a description and a name matching its key', () {
    for (final entry in kHoppyActionSchema.entries) {
      expect(entry.value.name, entry.key,
          reason: 'definition name must match map key for ${entry.key}');
      expect(entry.value.description, isNotEmpty,
          reason: '${entry.key} must have description');
    }
  });

  test('schema file contains no em dash or en dash', () {
    // The design doc enforces this at corpus gate. We enforce it at schema
    // definition too so no action name or description smuggles one.
    for (final def in kHoppyActionSchema.values) {
      expect(def.name.contains('\u2014'), isFalse,
          reason: '${def.name} must not contain em dash');
      expect(def.name.contains('\u2013'), isFalse,
          reason: '${def.name} must not contain en dash');
      expect(def.description.contains('\u2014'), isFalse,
          reason: '${def.name} description must not contain em dash');
      expect(def.description.contains('\u2013'), isFalse,
          reason: '${def.name} description must not contain en dash');
      expect(def.description.contains('--'), isFalse,
          reason: '${def.name} description must not contain double hyphen as dash');
    }
    expect(kHoppySchemaVersion.contains('\u2014'), isFalse);
    expect(kHoppySchemaVersion.contains('\u2013'), isFalse);
  });
}
