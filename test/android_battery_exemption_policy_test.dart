import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/android_battery_exemption_policy.dart';

void main() {
  test('battery exemption evaluation is Android-only and post-success', () {
    bool evaluate({
      String platform = 'android',
      bool consent = true,
      bool committed = true,
      bool requested = false,
    }) {
      return shouldEvaluateAndroidBatteryExemption(
        operatingSystem: platform,
        privacyConsentGranted: consent,
        tunnelCommitted: committed,
        requestedThisSession: requested,
      );
    }

    expect(evaluate(), isTrue);
    expect(evaluate(platform: 'ios'), isFalse);
    expect(evaluate(platform: 'windows'), isFalse);
    expect(evaluate(consent: false), isFalse);
    expect(evaluate(committed: false), isFalse);
    expect(evaluate(requested: true), isFalse);
  });

  test('battery exemption prompt has an exact seven-day cooldown', () {
    final promptedAt = DateTime.utc(2026, 7, 1, 12);
    expect(
      isAndroidBatteryExemptionPromptOnCooldown(
        now: promptedAt.add(const Duration(days: 6, hours: 23)),
        promptedAt: promptedAt,
      ),
      isTrue,
    );
    expect(
      isAndroidBatteryExemptionPromptOnCooldown(
        now: promptedAt.add(const Duration(days: 7)),
        promptedAt: promptedAt,
      ),
      isFalse,
    );
    expect(
      isAndroidBatteryExemptionPromptOnCooldown(
        now: promptedAt.subtract(const Duration(minutes: 1)),
        promptedAt: promptedAt,
      ),
      isTrue,
      reason: 'clock rollback must not cause repeated system prompts',
    );
  });

  test('initialization never invokes the battery exemption request', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf(
      'void _startPostPrivacyConsentInitialization()',
    );
    final end = source.indexOf(
      'Future<Directory> _appleLiveTunnelSmokeDirectory()',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final initialization = source.substring(start, end);

    expect(
      initialization,
      isNot(contains('_requestAndroidBatteryExemptionAfterTunnelCommit')),
    );
    expect(initialization, isNot(contains('requestBatteryExemption')));
  });

  test('request is bound to the successful Android tunnel commit boundary', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _startTunnelCandidate(');
    final end = source.indexOf(
      'Future<bool> _loadPowerProtectionPromptSeen(',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final candidate = source.substring(start, end);
    const request =
        'unawaited(_requestAndroidBatteryExemptionAfterTunnelCommit())';
    final requestIndex = candidate.indexOf(request);

    expect(
      requestIndex,
      greaterThan(candidate.indexOf('if (Platform.isAndroid)')),
    );
    expect(
      requestIndex,
      greaterThan(candidate.indexOf('await _clearTunnelFailureDiagnostic()')),
    );
    expect(
      requestIndex,
      greaterThan(candidate.indexOf('_isConnected = true;')),
    );
    expect(
      requestIndex,
      greaterThan(candidate.indexOf('await _saveVpnRuntimeSettings(')),
      reason: 'system UI must not race the successful settings commit',
    );
    expect(requestIndex, lessThan(candidate.lastIndexOf('return true;')));
    expect(RegExp(RegExp.escape(request)).allMatches(source).length, 1);
  });

  test('Single and Double AWG/Xray successes share one once-only boundary', () {
    final source = File('lib/main.dart').readAsStringSync();
    final smartStart = source.indexOf(
      'Future<void> _connectWithSmartProtocol(',
    );
    final smartEnd = source.indexOf(
      'Future<void> _toggleVpnConnection() async',
      smartStart,
    );
    expect(smartStart, greaterThanOrEqualTo(0));
    expect(smartEnd, greaterThan(smartStart));
    final smart = source.substring(smartStart, smartEnd);

    expect(
      RegExp(r'await _startTunnelCandidate\(').allMatches(smart).length,
      2,
      reason: 'direct AWG and bounded Xray fallback must use the same commit',
    );
    expect(
      smart,
      contains('shouldAttemptServedLeadCandidate('),
      reason: 'the shared commit site must consume the behavior-tested lead '
          'policy instead of duplicating legacy transport gates',
    );
    expect(
      smart,
      contains('final boundedCandidates = boundedXrayTransportOptions('),
    );
    expect(smart, contains("_boolValue(directConfig['double_vpn_active'])"));
    expect(smart, contains("_boolValue(stealthBase['double_vpn_active'])"));
    expect(
      smart,
      isNot(contains('_requestAndroidBatteryExemptionAfterTunnelCommit')),
      reason: 'transport and mode branches must not create extra prompt sites',
    );
    final legacyDisclosureGate = smart.indexOf(
      '!_hasCurrentAndroidVpnServiceDisclosureConsent',
    );
    final legalAcceptance = smart.indexOf(
      'await _ensureLegalAcceptanceForActivation(',
    );
    final firstCandidate = smart.indexOf('await _startTunnelCandidate(');
    expect(legacyDisclosureGate, greaterThanOrEqualTo(0));
    expect(legalAcceptance, greaterThan(legacyDisclosureGate));
    expect(
      legalAcceptance,
      lessThan(firstCandidate),
      reason: 'a legacy cached config must not bypass current disclosure',
    );

    const lanes = <String>[
      'Single VPN / direct AWG',
      'Single VPN / Xray fallback',
      'Double VPN / direct AWG',
      'Double VPN / Xray fallback',
    ];
    for (final lane in lanes) {
      var requestedThisSession = false;
      var evaluations = 0;
      for (final committed in <bool>[false, true, true]) {
        if (shouldEvaluateAndroidBatteryExemption(
          operatingSystem: 'android',
          privacyConsentGranted: true,
          tunnelCommitted: committed,
          requestedThisSession: requestedThisSession,
        )) {
          evaluations += 1;
          requestedThisSession = true;
        }
      }
      expect(evaluations, 1, reason: lane);
    }
  });

  test(
    'legacy Android users must accept the current VpnService disclosure',
    () {
      final source = File('lib/main.dart').readAsStringSync();
      final ensureStart = source.indexOf(
        'Future<Map<String, dynamic>?> _ensureLegalAcceptanceForActivation(',
      );
      final ensureEnd = source.indexOf(
        'Future<bool> _fetchAvailableNodes(',
        ensureStart,
      );
      expect(ensureStart, greaterThanOrEqualTo(0));
      expect(ensureEnd, greaterThan(ensureStart));
      final ensure = source.substring(ensureStart, ensureEnd);
      // Whitespace-normalized so marker checks survive reformatting
      // (e.g. dart format wrapping a long line) without losing coverage.
      final normalizedEnsure = ensure.replaceAll(RegExp(r'\s+'), ' ');

      for (final marker in <String>[
        'hasCurrentAndroidVpnServiceDisclosure',
        '_hasCurrentAndroidVpnServiceDisclosureConsent',
        '!hasCurrentAndroidVpnServiceDisclosure',
        '_androidVpnServiceDisclosureConsentVersion =',
        '_androidVpnServiceDisclosureAcceptedAtUtc =',
        'DateTime.now().toUtc().toIso8601String()',
        'androidVpnServiceDisclosureConsentVersion: _androidVpnServiceDisclosureVersion',
        'androidVpnServiceDisclosureAcceptedAtUtc: _androidVpnServiceDisclosureAcceptedAtUtc',
      ]) {
        expect(
            normalizedEnsure, contains(marker.replaceAll(RegExp(r'\s+'), ' ')));
      }
      expect(
        ensure.indexOf('hasCurrentAndroidVpnServiceDisclosure) {'),
        lessThan(ensure.indexOf('return _legalAcceptancePayload({')),
      );
      final legalDialog = ensure.indexOf('_tryShowLegalAcceptanceDialog(doc)');
      final vpnDialog =
          ensure.indexOf('_ensureAndroidVpnServiceDisclosureConsent()');
      expect(legalDialog, greaterThanOrEqualTo(0));
      expect(vpnDialog, greaterThanOrEqualTo(0));
      expect(
        legalDialog,
        lessThan(vpnDialog),
        reason:
            'the standalone VPN disclosure must follow any stale legal dialog',
      );
      expect(
        RegExp(
          'android_vpn_service_disclosure_consent_version',
        ).allMatches(source).length,
        greaterThanOrEqualTo(2),
        reason: 'the disclosure version must be both persisted and restored',
      );
      expect(
        RegExp(
          'android_vpn_service_disclosure_accepted_at',
        ).allMatches(source).length,
        greaterThanOrEqualTo(3),
        reason:
            'the separate disclosure timestamp must be sent, persisted, and restored',
      );
    },
  );

  test('Dart and native layers both enforce the post-success gate', () {
    final dart = File('lib/main.dart').readAsStringSync();
    final methodStart = dart.indexOf(
      'Future<void> _requestAndroidBatteryExemptionAfterTunnelCommit() async',
    );
    final methodEnd = dart.indexOf(
      'void _finishTunnelConnectFailure(',
      methodStart,
    );
    expect(methodStart, greaterThanOrEqualTo(0));
    expect(methodEnd, greaterThan(methodStart));
    final method = dart.substring(methodStart, methodEnd);
    for (final marker in <String>[
      'operatingSystem: Platform.operatingSystem',
      'privacyConsentGranted: _privacyConsentGranted',
      'tunnelCommitted: _isConnected',
      'requestedThisSession: _powerProtectionRequestedThisSession',
      '_powerProtectionRequestedThisSession = true',
      "invokeMapMethod<String, dynamic>('getPowerOptimizationStatus')",
      'await _markPowerProtectionPromptSeen()',
      "invokeMethod('requestBatteryExemption')",
    ]) {
      expect(method, contains(marker));
    }
    expect(
      method.indexOf('await _markPowerProtectionPromptSeen()'),
      lessThan(method.indexOf("invokeMethod('requestBatteryExemption')")),
      reason: 'denial or an unavailable system screen must consume cooldown',
    );

    final native = File(
      'android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt',
    ).readAsStringSync();
    final nativeStart = native.indexOf('"requestBatteryExemption" ->');
    final nativeEnd = native.indexOf('"triggerCamouflageSwap" ->', nativeStart);
    expect(nativeStart, greaterThanOrEqualTo(0));
    expect(nativeEnd, greaterThan(nativeStart));
    final requestBlock = native.substring(nativeStart, nativeEnd);
    expect(requestBlock, contains('!VpnTunnelService.isTunnelHealthy()'));
    expect(
      requestBlock.indexOf('!VpnTunnelService.isTunnelHealthy()'),
      lessThan(
        requestBlock.indexOf('ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS'),
      ),
    );
  });

  test('manifest and reviewer declarations match the direct exemption', () {
    final manifest = File(
      'android/app/src/main/AndroidManifest.xml',
    ).readAsStringSync();
    expect(
      RegExp(
        'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
      ).allMatches(manifest).length,
      1,
    );

    final declaration = File(
      'docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md',
    ).readAsStringSync();
    expect(
      declaration,
      isNot(contains('No request for `REQUEST_IGNORE')),
    );
    expect(declaration, contains('seven-day'));
    expect(
      declaration,
      contains('## Battery Optimization Exemption Declaration'),
    );
    expect(
      declaration,
      contains('only after the tunnel passes native readiness'),
    );
    expect(
      declaration.replaceAll(RegExp(r'\s+'), ' '),
      contains('does not repeat'),
    );
  });

  test('Always-on VPN takes precedence over the battery exemption prompt', () {
    expect(
      shouldRequestBatteryExemptionGivenAlwaysOn(alwaysOnArmed: true),
      isFalse,
      reason:
          'always-on already holds the tunnel, so the exemption prompt is redundant',
    );
    expect(
      shouldRequestBatteryExemptionGivenAlwaysOn(alwaysOnArmed: false),
      isTrue,
      reason:
          'without always-on the exemption is what keeps the background tunnel alive',
    );
  });

  test('exemption round-trips through the dumpsys deviceidle whitelist', () {
    const beforeGrant = 'system,com.android.shell,2000\n'
        'system-excidle,com.android.vending,10234\n'
        'user,com.surfshark.vpnclient.android,10492\n';
    expect(
      isAndroidPackageBatteryExempt(
        packageName: 'org.winsvpn.app.debug',
        deviceIdleWhitelistOutput: beforeGrant,
      ),
      isFalse,
      reason: 'no exemption record exists before the user grants it',
    );

    final afterGrant = '${beforeGrant}user,org.winsvpn.app.debug,10499\n';
    expect(
      isAndroidPackageBatteryExempt(
        packageName: 'org.winsvpn.app.debug',
        deviceIdleWhitelistOutput: afterGrant,
      ),
      isTrue,
      reason: 'a granted app is recorded as a user whitelist entry',
    );
  });

  test('exemption check does not confuse system or longer names', () {
    expect(
      isAndroidPackageBatteryExempt(
        packageName: 'org.winsvpn.app',
        deviceIdleWhitelistOutput:
            'system,org.winsvpn.app,10100\nuser,org.winsvpn.app.debug,10101\n',
      ),
      isFalse,
      reason: 'a system entry and a longer package name are not an exemption',
    );
    expect(
      isAndroidPackageBatteryExempt(
        packageName: 'org.winsvpn.app.debug',
        deviceIdleWhitelistOutput:
            'system,org.winsvpn.app.debug,10100\nuser,org.winsvpn.app,10101\n',
      ),
      isFalse,
      reason: 'only a user entry naming the exact package counts',
    );
  });

  test('malformed dumpsys lines fail closed with no match', () {
    expect(
      isAndroidPackageBatteryExempt(
        packageName: 'org.winsvpn.app.debug',
        deviceIdleWhitelistOutput:
            'not-a-valid-line\nuser\n,org.winsvpn.app.debug\n',
      ),
      isFalse,
    );
  });
}
