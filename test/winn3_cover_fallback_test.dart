import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Behaviour of the v3 → cover-bearing winn/1 node picker.
///
/// The property: a standalone v3 node that has stopped answering may rotate
/// onto a different listed winn/1 node that has cover. It must never rotate
/// onto itself, onto another labelled standalone v3 node, onto an unreachable
/// node, onto a UDP-only node, or onto cleartext (null means fail closed).
Map<String, dynamic> _node({
  required String slug,
  String stealth = 'cdn.example:443',
  Object? reachable = true,
  String? protocolVersion = kWinnProtocolV1,
  String? carrier,
  Map<String, String>? transports,
}) {
  return <String, dynamic>{
    'slug': slug,
    'stealth_endpoint': stealth,
    if (reachable != null) 'reachable': reachable,
    if (protocolVersion != null) 'protocol_version': protocolVersion,
    if (carrier != null) 'carrier': carrier,
    if (transports != null) 'transports': transports,
  };
}

Map<String, dynamic> _standaloneV3Config({bool stealthActive = false}) {
  return <String, dynamic>{
    'protocol_version': kWinnProtocolV3,
    'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
    'stealth_active': stealthActive,
    'server_endpoint': '203.0.113.7:51820',
  };
}

Map<String, dynamic> _winn1Config({
  bool stealthActive = false,
  String nodeSlug = 'france-winn1',
}) {
  return <String, dynamic>{
    'protocol_version': kWinnProtocolV1,
    'protocol_params': <String, dynamic>{},
    'node_slug': nodeSlug,
    'stealth_active': stealthActive,
    'server_endpoint': '203.0.113.8:9110',
  };
}

const String _selectionGeneration = '0123456789abcdef0123456789abcdef';
const int _startToken = 41;
const int _startGeneration = 7;
const String _failedV3Node = 'spain-v3';

void _authorizeReviewedV1Fallback({
  String selectionGeneration = _selectionGeneration,
  int startToken = _startToken,
  int startGeneration = _startGeneration,
  String failedV3Node = _failedV3Node,
}) {
  winn3SelectionGenerationPayload(
    selectionGeneration: selectionGeneration,
    ordinaryConnectivityAuthorized: false,
  );
  final verdict = nativeWinn3ReadinessVerdict(
    <String, dynamic>{
      'winn3_start_token': startToken,
      'winn3_start_generation': startGeneration,
      'winn3_selection_generation': selectionGeneration,
      'winn3_failed_node': failedV3Node,
      'winn3_awg_xray_authorization_token': startToken,
      'winn3_verdict': 'ordinary_connectivity',
    },
    startToken: startToken,
    startGeneration: startGeneration,
    selectionGeneration: selectionGeneration,
    failedNode: failedV3Node,
  );
  expect(verdict, Winn3NativeVerdict.ordinaryConnectivity);
  winn3SelectionGenerationPayload(
    selectionGeneration: selectionGeneration,
    ordinaryConnectivityAuthorized: true,
  );
}

Map<String, dynamic> _stealthChainV3Config() {
  return <String, dynamic>{
    'protocol_version': kWinnProtocolV3,
    'protocol_params': <String, dynamic>{'carrier': kWinnCarrierDirectAwg},
    kWinnOuterTransportKey: kWinnOuterTransportStealthChain,
    'stealth_active': true,
    'xray': <String, dynamic>{
      'enabled': true,
      'uuid': '00000000-0000-4000-8000-000000000000',
      'host': 'stealth.example',
      'port': 443,
      'server_name': 'stealth.example',
      'path': '/wins-stealth-tunnel',
      'security': 'tls',
      'local_port': 42110,
      'remote_awg_host': '127.0.0.1',
      'remote_awg_port': 9110,
    },
  };
}

void main() {
  test('a primary v3 start names its selected node', () {
    expect(
      winn3StartFailedNodeArgument(
        coverFallbackInProgress: false,
        coverFailedNode: '',
        selectedSlug: 'primary-v3',
      ),
      'primary-v3',
    );
  });
  test('a cover leg retains the failed v3 node', () {
    expect(
      winn3StartFailedNodeArgument(
        coverFallbackInProgress: true,
        coverFailedNode: 'primary-v3',
        selectedSlug: 'cover-v1',
      ),
      'primary-v3',
    );
  });
  setUp(resetWinn1FallbackDispatchAuthorization);
  tearDown(resetWinn1FallbackDispatchAuthorization);

  group('control-plane fallback generation', () {
    const generation = '0123456789abcdef0123456789abcdef';

    test('initial v3 selection carries no ordinary-failure authorization', () {
      expect(
        winn3SelectionGenerationPayload(
          selectionGeneration: generation,
          ordinaryConnectivityAuthorized: false,
        ),
        const <String, String>{'selection_generation': generation},
      );
    });

    test('typed ordinary failure carries the exact matching generation', () {
      expect(
        winn3SelectionGenerationPayload(
          selectionGeneration: generation,
          ordinaryConnectivityAuthorized: true,
        ),
        const <String, String>{
          'selection_generation': generation,
          'ordinary_v3_failure_generation': generation,
        },
      );
    });

    test('malformed or absent generation fails closed', () {
      for (final value in <String>['', 'short', 'bad value', '../escape']) {
        expect(
          winn3SelectionGenerationPayload(
            selectionGeneration: value,
            ordinaryConnectivityAuthorized: true,
          ),
          isEmpty,
          reason: value,
        );
      }
    });
  });

  group('v3 lead ordering policy', () {
    test('release mode disables the diagnostic force-Xray request', () {
      expect(
        diagnosticForceXrayEnabled(requested: true, releaseMode: true),
        isFalse,
      );
      expect(
        diagnosticForceXrayEnabled(requested: true, releaseMode: false),
        isTrue,
      );
    });

    test('served v3 leads even when legacy direct AWG is disabled', () {
      final policy = winn3LeadPolicy(
        config: _standaloneV3Config(),
        userTcpOnly: false,
        forceXrayForDiagnostics: false,
      );
      expect(policy, Winn3LeadPolicy.attemptPrimary);
      expect(
        shouldAttemptServedLeadCandidate(
          policy: policy,
          directAwgEnabled: false,
        ),
        isTrue,
        reason: 'direct_awg_enabled controls v1 AWG, not the v3 primary',
      );
    });

    test('direct v1 without an ordinary-v3-failure grant is refused', () {
      expect(
        () => winn3LeadPolicy(
          config: _winn1Config(),
          userTcpOnly: false,
          forceXrayForDiagnostics: false,
        ),
        throwsStateError,
      );
    });

    test('authorized v1 always attempts AWG even when legacy AWG is disabled',
        () {
      _authorizeReviewedV1Fallback();
      final policy = winn3LeadPolicy(
        config: _winn1Config(),
        userTcpOnly: false,
        forceXrayForDiagnostics: false,
      );
      expect(policy, Winn3LeadPolicy.legacyTransportPolicy);
      expect(
        shouldAttemptServedLeadCandidate(
          policy: policy,
          directAwgEnabled: false,
        ),
        isTrue,
      );
    });

    test('TCP-only never skips the served v3 primary', () {
      final policy = winn3LeadPolicy(
        config: _standaloneV3Config(),
        userTcpOnly: true,
        forceXrayForDiagnostics: false,
      );
      expect(policy, Winn3LeadPolicy.attemptPrimary);
      expect(
        shouldAttemptServedLeadCandidate(
          policy: policy,
          directAwgEnabled: true,
        ),
        isTrue,
      );
      expect(
        maySelectLegacyRouteAfterWinn3Lead(
          policy: policy,
          primaryAttempted: false,
          primaryVerdict: Winn3NativeVerdict.pending,
          securityRefused: false,
          servedConfigNeedsLegacyNode: true,
        ),
        isFalse,
        reason: 'the preference applies to v1 only after a proven v3 failure',
      );
    });

    test('force-Xray never skips the served v3 primary', () {
      final policy = winn3LeadPolicy(
        config: _standaloneV3Config(),
        userTcpOnly: false,
        forceXrayForDiagnostics: true,
      );
      expect(policy, Winn3LeadPolicy.attemptPrimary);
      expect(
        shouldAttemptServedLeadCandidate(
          policy: policy,
          directAwgEnabled: true,
        ),
        isTrue,
      );
    });

    test('force-Xray cannot preempt AWG on an authorized v1 fallback', () {
      _authorizeReviewedV1Fallback();
      final policy = winn3LeadPolicy(
        config: _winn1Config(),
        userTcpOnly: false,
        forceXrayForDiagnostics: true,
      );
      expect(policy, Winn3LeadPolicy.legacyTransportPolicy);
      expect(
        shouldAttemptServedLeadCandidate(
          policy: policy,
          directAwgEnabled: false,
        ),
        isTrue,
      );
    });

    test('ordinary v3 fallback requires attempt before failure', () {
      const policy = Winn3LeadPolicy.attemptPrimary;
      expect(
        maySelectLegacyRouteAfterWinn3Lead(
          policy: policy,
          primaryAttempted: false,
          primaryVerdict: Winn3NativeVerdict.ordinaryConnectivity,
          securityRefused: false,
          servedConfigNeedsLegacyNode: true,
        ),
        isFalse,
      );
      expect(
        maySelectLegacyRouteAfterWinn3Lead(
          policy: policy,
          primaryAttempted: true,
          primaryVerdict: Winn3NativeVerdict.ordinaryConnectivity,
          securityRefused: false,
          servedConfigNeedsLegacyNode: true,
        ),
        isTrue,
      );
      expect(
        maySelectLegacyRouteAfterWinn3Lead(
          policy: policy,
          primaryAttempted: true,
          primaryVerdict: Winn3NativeVerdict.terminalSecurity,
          securityRefused: true,
          servedConfigNeedsLegacyNode: true,
        ),
        isFalse,
        reason: 'explicit security refusal remains terminal after an attempt',
      );
    });
  });

  group('Dart v1 start authorization', () {
    test('direct-v1 config-builder bypass is refused before native start', () {
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: _winn1Config(),
        ),
        throwsStateError,
      );
    });

    test('authorized order is exactly one AWG then exactly one Xray', () {
      _authorizeReviewedV1Fallback();
      final awg = _winn1Config();
      final xray = _winn1Config(stealthActive: true);

      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: awg,
        ),
        isEmpty,
      );
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: awg,
        ),
        throwsStateError,
        reason: 'AWG cannot be replayed after its one authorized attempt',
      );
      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: xray,
        ),
        isEmpty,
      );
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: xray,
        ),
        throwsStateError,
        reason: 'Xray cannot be retried from a burned grant',
      );
    });

    test('Xray-before-AWG is refused without consuming the AWG grant', () {
      _authorizeReviewedV1Fallback();
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: _winn1Config(stealthActive: true),
        ),
        throwsStateError,
      );
      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: _winn1Config(),
        ),
        isEmpty,
      );
    });

    test('sticky ordinary readiness cannot rewind an AWG-consumed grant', () {
      _authorizeReviewedV1Fallback();
      final awg = _winn1Config();
      final xray = _winn1Config(stealthActive: true);
      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: awg,
        ),
        isEmpty,
      );

      expect(
        nativeWinn3ReadinessVerdict(
          <String, dynamic>{
            'winn3_start_token': _startToken,
            'winn3_start_generation': _startGeneration,
            'winn3_selection_generation': _selectionGeneration,
            'winn3_failed_node': _failedV3Node,
            'winn3_awg_xray_authorization_token': _startToken,
            'winn3_verdict': 'ordinary_connectivity',
          },
          startToken: _startToken,
          startGeneration: _startGeneration,
          selectionGeneration: _selectionGeneration,
          failedNode: _failedV3Node,
        ),
        Winn3NativeVerdict.ordinaryConnectivity,
      );
      winn3SelectionGenerationPayload(
        selectionGeneration: _selectionGeneration,
        ordinaryConnectivityAuthorized: true,
      );
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: awg,
        ),
        throwsStateError,
        reason: 're-reading the same native verdict is not a retry grant',
      );
      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: xray,
        ),
        isEmpty,
      );
    });

    test('stale selection generation cannot authorize v1', () {
      _authorizeReviewedV1Fallback();
      winn3SelectionGenerationPayload(
        selectionGeneration: 'fedcba9876543210fedcba9876543210',
        ordinaryConnectivityAuthorized: true,
      );
      expect(
        () => winn3LeadPolicy(
          config: _winn1Config(),
          userTcpOnly: false,
          forceXrayForDiagnostics: false,
        ),
        throwsStateError,
      );
    });

    test('terminal security after ordinary failure burns v1 authorization', () {
      _authorizeReviewedV1Fallback();
      expect(
        nativeWinn3ReadinessVerdict(
          <String, dynamic>{
            'winn3_start_token': _startToken,
            'winn3_start_generation': _startGeneration,
            'winn3_selection_generation': _selectionGeneration,
            'winn3_failed_node': _failedV3Node,
            'winn3_security_refusal': true,
            'winn3_verdict': 'terminal_security',
          },
          startToken: _startToken,
          startGeneration: _startGeneration,
          selectionGeneration: _selectionGeneration,
          failedNode: _failedV3Node,
        ),
        Winn3NativeVerdict.terminalSecurity,
      );
      expect(
        () => winn3LeadPolicy(
          config: _winn1Config(),
          userTcpOnly: false,
          forceXrayForDiagnostics: false,
        ),
        throwsStateError,
      );
    });

    test('partial or ambiguous protocol and target state fails closed', () {
      winn3SelectionGenerationPayload(
        selectionGeneration: _selectionGeneration,
        ordinaryConnectivityAuthorized: true,
      );
      for (final partial in <Map<String, dynamic>>[
        <String, dynamic>{},
        <String, dynamic>{'protocol_version': ''},
        <String, dynamic>{'protocol_version': 'winn/99'},
        <String, dynamic>{
          'protocol_version': kWinnProtocolV1,
          'protocolversion': kWinnProtocolV3,
        },
      ]) {
        expect(
          () => winn3LeadPolicy(
            config: partial,
            userTcpOnly: false,
            forceXrayForDiagnostics: false,
          ),
          throwsStateError,
          reason: partial.toString(),
        );
      }

      _authorizeReviewedV1Fallback();
      for (final partialProtocol in <Map<String, dynamic>>[
        _winn1Config()..remove('protocol_version'),
        _winn1Config()..['protocolversion'] = kWinnProtocolV3,
      ]) {
        expect(
          () => winnSectionForTunnelConfig(
            operatingSystem: 'android',
            config: partialProtocol,
          ),
          throwsStateError,
          reason: partialProtocol.toString(),
        );
      }
      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: _winn1Config(),
        ),
        isEmpty,
        reason: 'partial-state probes cannot consume the valid AWG grant',
      );

      resetWinn1FallbackDispatchAuthorization();
      _authorizeReviewedV1Fallback();
      for (final partialTarget in <Map<String, dynamic>>[
        _winn1Config()..remove('node_slug'),
        _winn1Config()..['location_slug'] = 'germany-winn1',
        _winn1Config(nodeSlug: _failedV3Node),
      ]) {
        expect(
          () => winn3LeadPolicy(
            config: partialTarget,
            userTcpOnly: false,
            forceXrayForDiagnostics: false,
          ),
          throwsStateError,
          reason: partialTarget.toString(),
        );
      }
    });
  });

  group('servedConfigNeedsCoverNodeFallback', () {
    test('standalone v3 needs a different node, including with stealth_active',
        () {
      expect(servedConfigNeedsCoverNodeFallback(_standaloneV3Config()), isTrue);
      expect(
        servedConfigNeedsCoverNodeFallback(
          _standaloneV3Config(stealthActive: true),
        ),
        isTrue,
        reason: 'stealth_active on standalone is the conflict, not cover',
      );
      expect(isStandaloneWinn3ServedConfig(_standaloneV3Config()), isTrue);
    });

    test('winn/1 keeps the existing TCP loop even when stealth_active', () {
      expect(servedConfigNeedsCoverNodeFallback(_winn1Config()), isFalse);
      expect(
        servedConfigNeedsCoverNodeFallback(_winn1Config(stealthActive: true)),
        isFalse,
      );
      expect(isStandaloneWinn3ServedConfig(_winn1Config()), isFalse);
    });

    test('v3 stealth-chain already has cover on this node', () {
      expect(
        servedConfigNeedsCoverNodeFallback(_stealthChainV3Config()),
        isFalse,
      );
      expect(isStandaloneWinn3ServedConfig(_stealthChainV3Config()), isFalse);
    });

    test('absent protocol_version is unknown and cannot become a fallback', () {
      expect(
        servedConfigNeedsCoverNodeFallback(<String, dynamic>{}),
        isFalse,
      );
    });

    test('relay v3 without stealth chain cannot use the TCP loop either', () {
      expect(
        servedConfigNeedsCoverNodeFallback(<String, dynamic>{
          'protocol_version': kWinnProtocolV3,
          'protocol_params': <String, dynamic>{
            'carrier': kWinnCarrierDirectAwg,
          },
        }),
        isTrue,
        reason: 'stealth_active on relay v3 without a chain is the same '
            'stealthTransportConflict; rotating nodes is the remaining cover',
      );
      expect(
        isStandaloneWinn3ServedConfig(<String, dynamic>{
          'protocol_version': kWinnProtocolV3,
          'protocol_params': <String, dynamic>{
            'carrier': kWinnCarrierDirectAwg,
          },
        }),
        isFalse,
      );
    });

    test('http3 v3 is UDP-shaped and needs a cover node', () {
      expect(
        servedConfigNeedsCoverNodeFallback(<String, dynamic>{
          'protocol_version': kWinnProtocolV3,
          'protocol_params': <String, dynamic>{'carrier': kWinnCarrierHttp3},
        }),
        isTrue,
      );
    });

    test('a v3 security refusal never authorizes cover-node fallback', () {
      expect(
        servedConfigMayAttemptCoverNodeFallback(
          config: _standaloneV3Config(),
          primaryVerdict: Winn3NativeVerdict.terminalSecurity,
        ),
        isFalse,
      );
      expect(
        servedConfigMayAttemptCoverNodeFallback(
          config: _standaloneV3Config(),
          primaryVerdict: Winn3NativeVerdict.ordinaryConnectivity,
        ),
        isTrue,
        reason: 'transport/liveness failure remains eligible for cover',
      );
    });

    test('a pre-acceptance native v3 error fails closed', () {
      expect(
        winn3PreAcceptanceFailureMustRefuseFallback(
          config: _standaloneV3Config(),
          nativeStartAccepted: false,
          permissionApprovalRequired: false,
        ),
        isTrue,
      );
      expect(
        winn3PreAcceptanceFailureMustRefuseFallback(
          config: _standaloneV3Config(),
          nativeStartAccepted: true,
          permissionApprovalRequired: false,
        ),
        isFalse,
        reason:
            'post-acceptance failures are classified by the typed readiness verdict',
      );
      expect(
        winn3PreAcceptanceFailureMustRefuseFallback(
          config: _standaloneV3Config(),
          nativeStartAccepted: false,
          permissionApprovalRequired: true,
        ),
        isFalse,
        reason: 'OS VPN consent needs a prompt, not a security-refusal label',
      );
      expect(
        winn3PreAcceptanceFailureMustRefuseFallback(
          config: _winn1Config(),
          nativeStartAccepted: false,
          permissionApprovalRequired: false,
        ),
        isFalse,
        reason: 'the v1 AWG/Xray fallback chain keeps its existing behavior',
      );
    });

    test('native readiness carries only explicit security refusals', () {
      expect(
        nativeWinn3ReadinessReportsSecurityRefusal(
          <String, dynamic>{'winn3_security_refusal': true},
        ),
        isTrue,
      );
      expect(
        nativeWinn3ReadinessReportsSecurityRefusal(
          <String, dynamic>{'provider_stage': 'start_rejected'},
        ),
        isTrue,
      );
      expect(
        nativeWinn3ReadinessReportsSecurityRefusal(
          <String, dynamic>{'provider_error_code': '1105'},
        ),
        isTrue,
      );
      expect(
        nativeWinn3ReadinessReportsSecurityRefusal(
          <String, dynamic>{
            'engine_ready': false,
            'provider_stage': 'starting',
          },
        ),
        isFalse,
        reason:
            'not being an explicit refusal does not itself authorize cover fallback',
      );
    });

    test('fallback requires a typed matching native v3 verdict', () {
      const token = 41;
      winn3SelectionGenerationPayload(
        selectionGeneration: _selectionGeneration,
        ordinaryConnectivityAuthorized: false,
      );
      expect(
        nativeWinn3ReadinessReportsSecurityRefusal(
          <String, dynamic>{
            'winn3_start_token': token - 1,
            'winn3_security_refusal': true,
          },
          startToken: token,
        ),
        isFalse,
        reason: 'a stale previous-connect refusal cannot classify this start',
      );
      expect(
        nativeWinn3ReadinessMustRefuseFallback(
          <String, dynamic>{
            'winn3_start_token': token,
            'winn3_verdict': 'pending',
          },
          startToken: token,
        ),
        isTrue,
        reason: 'a Dart timeout while native validation is pending is terminal',
      );
      expect(
        nativeWinn3ReadinessMustRefuseFallback(
          <String, dynamic>{
            'winn3_start_token': token - 1,
            'winn3_verdict': 'ordinary_connectivity',
          },
          startToken: token,
        ),
        isTrue,
        reason: 'a stale connectivity result cannot authorize the new attempt',
      );
      expect(
        nativeWinn3ReadinessMustRefuseFallback(
          <String, dynamic>{
            'winn3_start_token': token,
            'winn3_start_state': 'connectivity_failed',
          },
          startToken: token,
        ),
        isTrue,
        reason: 'the legacy untyped label cannot authorize v1 fallback',
      );
      expect(
        nativeWinn3ReadinessMustRefuseFallback(
          <String, dynamic>{
            'winn3_start_token': token,
            'winn3_start_generation': _startGeneration,
            'winn3_selection_generation': _selectionGeneration,
            'winn3_failed_node': _failedV3Node,
            'winn3_awg_xray_authorization_token': token,
            'winn3_verdict': 'ordinary_connectivity',
          },
          startToken: token,
          startGeneration: _startGeneration,
          selectionGeneration: _selectionGeneration,
          failedNode: _failedV3Node,
        ),
        isFalse,
        reason: 'only the exact typed native verdict may use v1 cover',
      );
      expect(
        nativeWinn3ReadinessVerdict(
          <String, dynamic>{
            'winn3_start_token': token,
            'winn3_awg_xray_authorization_token': token,
            'winn3_verdict': 'ordinary_connectivity',
            'winn3_security_refusal': true,
          },
          startToken: token,
        ),
        Winn3NativeVerdict.terminalSecurity,
        reason:
            'a contradictory security refusal must override downgrade authorization',
      );
      for (final invalidAuthorization in <Object?>[null, token - 1, '$token']) {
        expect(
          nativeWinn3ReadinessMustRefuseFallback(
            <String, dynamic>{
              'winn3_start_token': token,
              if (invalidAuthorization != null)
                'winn3_awg_xray_authorization_token': invalidAuthorization,
              'winn3_verdict': 'ordinary_connectivity',
            },
            startToken: token,
          ),
          isTrue,
          reason:
              'ordinary cover requires the exact native authorization token',
        );
      }
      expect(
        nativeWinn3ReadinessMustRefuseFallback(null, startToken: token),
        isTrue,
        reason: 'an unreadable readiness channel must not authorize fallback',
      );
      expect(
        nativeWinn3ReadinessVerdict(
          <String, dynamic>{
            'winn3_start_token': token,
            'winn3_start_generation': 7,
            'transition_generation': 8,
            'winn3_verdict': 'ordinary_connectivity',
          },
          startToken: token,
          startGeneration: 7,
        ),
        Winn3NativeVerdict.unknownTerminal,
        reason: 'conflicting generation aliases fail closed',
      );
      expect(
        nativeWinn3ReadinessVerdict(
          <String, dynamic>{
            'winn3_start_token': token,
            'winn3_start_generation': 7,
            'winn3_verdict': 'ordinary_connectivity',
            'provider_verdict': 'terminal_security',
          },
          startToken: token,
          startGeneration: 7,
        ),
        Winn3NativeVerdict.unknownTerminal,
        reason: 'conflicting verdict aliases fail closed',
      );
      for (final malformed in <Map<String, dynamic>>[
        <String, dynamic>{
          'winn3_start_token': token.toString(),
          'winn3_verdict': 'ordinary_connectivity',
        },
        <String, dynamic>{
          'winn3_start_token': token,
          'winn3_verdict': ' ordinary_connectivity ',
        },
        <String, dynamic>{
          'winn3_start_token': token,
          'winn3_verdict': 'ORDINARY_CONNECTIVITY',
        },
      ]) {
        expect(
          nativeWinn3ReadinessVerdict(malformed, startToken: token),
          Winn3NativeVerdict.unknownTerminal,
          reason: 'identity and verdict fields use an exact typed schema',
        );
      }
      expect(
        nativeWinn3VerdictAllowsReadyState(Winn3NativeVerdict.pending),
        isFalse,
        reason: 'pending may not fall through to generic readiness booleans',
      );
      expect(
        nativeWinn3VerdictAllowsReadyState(Winn3NativeVerdict.connected),
        isTrue,
      );
      expect(
        mergeWinn3NativeVerdict(
          Winn3NativeVerdict.terminalSecurity,
          Winn3NativeVerdict.ordinaryConnectivity,
        ),
        Winn3NativeVerdict.terminalSecurity,
      );
      expect(
        mergeWinn3NativeVerdict(
          Winn3NativeVerdict.unknownTerminal,
          Winn3NativeVerdict.ordinaryConnectivity,
        ),
        Winn3NativeVerdict.unknownTerminal,
      );
      expect(
        mergeWinn3NativeVerdict(
          Winn3NativeVerdict.ordinaryConnectivity,
          Winn3NativeVerdict.terminalSecurity,
        ),
        Winn3NativeVerdict.terminalSecurity,
        reason: 'a terminal security signal overrides earlier connectivity',
      );
      expect(
        mergeWinn3NativeVerdict(
          Winn3NativeVerdict.connected,
          Winn3NativeVerdict.ordinaryConnectivity,
        ),
        Winn3NativeVerdict.unknownTerminal,
        reason: 'connected plus a later ordinary result is contradictory',
      );
      expect(
        mergeWinn3NativeVerdict(
          Winn3NativeVerdict.pending,
          Winn3NativeVerdict.ordinaryConnectivity,
        ),
        Winn3NativeVerdict.ordinaryConnectivity,
      );
      expect(
        nativeWinn3ReadinessMatchesStartToken(
          <String, dynamic>{'winn3_start_token': token.toString()},
          token,
        ),
        isFalse,
      );
    });

    test('hostile typed fields never authorize ordinary cover', () {
      const token = 41;
      const generation = 7;
      const selection = '0123456789abcdef';
      const failed = 'spain-v3';
      Map<String, dynamic> ordinary({
        Object? startToken = token,
        Object? startGeneration = generation,
        Object? selectionGeneration = selection,
        Object? failedNode = failed,
        Object? authorization = token,
        Object? verdict = 'ordinary_connectivity',
      }) {
        return <String, dynamic>{
          if (startToken != null) 'winn3_start_token': startToken,
          if (startGeneration != null)
            'winn3_start_generation': startGeneration,
          if (selectionGeneration != null)
            'winn3_selection_generation': selectionGeneration,
          if (failedNode != null) 'winn3_failed_node': failedNode,
          if (authorization != null)
            'winn3_awg_xray_authorization_token': authorization,
          if (verdict != null) 'winn3_verdict': verdict,
        };
      }

      winn3SelectionGenerationPayload(
        selectionGeneration: selection,
        ordinaryConnectivityAuthorized: false,
      );

      expect(
        nativeWinn3ReadinessVerdict(
          ordinary(),
          startToken: token,
          startGeneration: generation,
          selectionGeneration: selection,
          failedNode: failed,
        ),
        Winn3NativeVerdict.ordinaryConnectivity,
      );

      for (final hostile in <Object?>[true, false, '41', 41.5, 0, -1]) {
        expect(
          nativeWinn3ReadinessVerdict(
            ordinary(startToken: hostile),
            startToken: token,
            startGeneration: generation,
            selectionGeneration: selection,
            failedNode: failed,
          ),
          Winn3NativeVerdict.unknownTerminal,
          reason: 'start token $hostile',
        );
        expect(
          nativeWinn3ReadinessVerdict(
            ordinary(startGeneration: hostile),
            startToken: token,
            startGeneration: generation,
            selectionGeneration: selection,
            failedNode: failed,
          ),
          Winn3NativeVerdict.unknownTerminal,
          reason: 'start generation $hostile',
        );
        expect(
          nativeWinn3ReadinessVerdict(
            ordinary(authorization: hostile),
            startToken: token,
            startGeneration: generation,
            selectionGeneration: selection,
            failedNode: failed,
          ),
          Winn3NativeVerdict.unknownTerminal,
          reason: 'authorization $hostile',
        );
      }
      for (final hostile in <Object?>[true, 12, 12.5, 'short', '']) {
        expect(
          nativeWinn3ReadinessVerdict(
            ordinary(selectionGeneration: hostile),
            startToken: token,
            startGeneration: generation,
            selectionGeneration: selection,
            failedNode: failed,
          ),
          Winn3NativeVerdict.unknownTerminal,
          reason: 'selection $hostile',
        );
      }
      for (final hostile in <Object?>[true, 1, 1.5, 'auto', 'AUTO', '']) {
        expect(
          nativeWinn3ReadinessVerdict(
            ordinary(failedNode: hostile),
            startToken: token,
            startGeneration: generation,
            selectionGeneration: selection,
            failedNode: failed,
          ),
          Winn3NativeVerdict.unknownTerminal,
          reason: 'failed node $hostile',
        );
      }
      expect(
        nativeWinn3ReadinessVerdict(
          ordinary(startToken: null, authorization: token),
          startToken: token,
          startGeneration: generation,
          selectionGeneration: selection,
          failedNode: failed,
        ),
        Winn3NativeVerdict.unknownTerminal,
        reason: 'missing start token',
      );
      expect(
        nativeWinn3ReadinessVerdict(
          ordinary(authorization: null),
          startToken: token,
          startGeneration: generation,
          selectionGeneration: selection,
          failedNode: failed,
        ),
        Winn3NativeVerdict.unknownTerminal,
        reason: 'missing authorization token',
      );
      expect(
        nativeWinn3ReadinessVerdict(
          ordinary(startToken: token - 1, authorization: token - 1),
          startToken: token,
          startGeneration: generation,
          selectionGeneration: selection,
          failedNode: failed,
        ),
        Winn3NativeVerdict.unknownTerminal,
        reason: 'stale start token',
      );
      expect(
        nativeWinn3ReadinessVerdict(
          ordinary(failedNode: 'other-node'),
          startToken: token,
          startGeneration: generation,
          selectionGeneration: selection,
          failedNode: failed,
        ),
        Winn3NativeVerdict.unknownTerminal,
        reason: 'conflicting failed node',
      );
      expect(
        nativeWinn3ReadinessVerdict(
          ordinary()..['winn3_security_refusal'] = true,
          startToken: token,
          startGeneration: generation,
          selectionGeneration: selection,
          failedNode: failed,
        ),
        Winn3NativeVerdict.terminalSecurity,
      );
      expect(
        nativeWinn3ReadinessVerdict(
          ordinary(authorization: null, verdict: 'unknown_terminal'),
          startToken: token,
          startGeneration: generation,
          selectionGeneration: selection,
          failedNode: failed,
        ),
        Winn3NativeVerdict.unknownTerminal,
      );
      expect(
        nativeWinn3ReadinessVerdict(
          ordinary(authorization: token, verdict: 'unknown_terminal'),
          startToken: token,
          startGeneration: generation,
          selectionGeneration: selection,
          failedNode: failed,
        ),
        Winn3NativeVerdict.unknownTerminal,
        reason: 'timeout/unknown must ignore a leftover authorization token',
      );
    });
  });

  group('start token mint', () {
    test('Random.secure mint is a positive signed 63-bit integer', () {
      expect(
        File('lib/winn3_cover_fallback.dart').readAsStringSync(),
        contains('random ?? Random.secure()'),
      );
      for (var i = 0; i < 32; i++) {
        final token = mintWinn3StartToken();
        expect(token, greaterThan(0));
        expect(token, lessThanOrEqualTo(kWinn3StartTokenMax));
      }
    });
  });

  group('exact cover target', () {
    test('cover uses the immutable slug even in automatic mode', () {
      expect(
        winn3RequestLocationSlug(
          automatic: true,
          displayedNodeSlug: 'hub-selected-node',
          exactCoverTargetSlug: 'france-winn1',
        ),
        'france-winn1',
      );
    });

    test('cover auto slug is refused', () {
      expect(
        () => winn3RequestLocationSlug(
          automatic: true,
          displayedNodeSlug: 'hub-selected-node',
          exactCoverTargetSlug: 'auto',
        ),
        throwsStateError,
      );
    });

    test('a different returned node is rejected', () {
      expect(
        returnedNodeMatchesExactCoverTarget(
          exactTargetSlug: 'france-winn1',
          vpnConfig: <String, dynamic>{'node_slug': 'france-winn1'},
          selectedNode: 'germany-winn1',
        ),
        isFalse,
      );
      expect(
        returnedNodeMatchesExactCoverTarget(
          exactTargetSlug: 'france-winn1',
          vpnConfig: <String, dynamic>{'node_slug': 'germany-winn1'},
          selectedNode: 'france-winn1',
        ),
        isFalse,
      );
      expect(
        returnedNodeMatchesExactCoverTarget(
          exactTargetSlug: 'france-winn1',
          vpnConfig: <String, dynamic>{'node_slug': 'france-winn1'},
          selectedNode: <String, dynamic>{'slug': 'france-winn1'},
        ),
        isTrue,
      );
    });
  });

  group('AWG then Xray grant', () {
    test('TTL, one-use, and AWG-then-Xray order', () {
      expect(
        armWinn3AwgXrayGrant(
          startToken: 0,
          startGeneration: 3,
          selectionGeneration: '0123456789abcdef',
          failedV3Node: 'spain-v3',
          issuedMonotonicMs: 1000,
        ),
        isNull,
      );
      final armed = armWinn3AwgXrayGrant(
        startToken: 9,
        startGeneration: 3,
        selectionGeneration: '0123456789abcdef',
        failedV3Node: 'spain-v3',
        issuedMonotonicMs: 1000,
      );
      expect(armed, isNotNull);
      expect(
        consumeWinn3AwgXrayGrant(
          grant: armed,
          startToken: 9,
          startGeneration: 3,
          selectionGeneration: '0123456789abcdef',
          failedV3Node: 'spain-v3',
          exactV1Target: 'france-winn1',
          requestedLeg: Winn3CoverLeg.xray,
          nowMonotonicMs: 1001,
        ).result,
        Winn3GrantConsumeResult.wrongLeg,
      );
      final afterAwg = consumeWinn3AwgXrayGrant(
        grant: armed,
        startToken: 9,
        startGeneration: 3,
        selectionGeneration: '0123456789abcdef',
        failedV3Node: 'spain-v3',
        exactV1Target: 'france-winn1',
        requestedLeg: Winn3CoverLeg.awg,
        nowMonotonicMs: 1001,
      );
      expect(afterAwg.result, Winn3GrantConsumeResult.ok);
      expect(
        consumeWinn3AwgXrayGrant(
          grant: afterAwg.grant,
          startToken: 9,
          startGeneration: 3,
          selectionGeneration: '0123456789abcdef',
          failedV3Node: 'spain-v3',
          exactV1Target: 'germany-winn1',
          requestedLeg: Winn3CoverLeg.xray,
          nowMonotonicMs: 1002,
        ).result,
        Winn3GrantConsumeResult.mismatch,
      );
      expect(
        consumeWinn3AwgXrayGrant(
          grant: afterAwg.grant,
          startToken: 9,
          startGeneration: 3,
          selectionGeneration: '0123456789abcdef',
          failedV3Node: 'spain-v3',
          exactV1Target: 'france-winn1',
          requestedLeg: Winn3CoverLeg.xray,
          nowMonotonicMs: 1000 + kWinn3AwgXrayGrantTtlMs + 1,
        ).result,
        Winn3GrantConsumeResult.expired,
      );
      final afterXray = consumeWinn3AwgXrayGrant(
        grant: afterAwg.grant,
        startToken: 9,
        startGeneration: 3,
        selectionGeneration: '0123456789abcdef',
        failedV3Node: 'spain-v3',
        exactV1Target: 'france-winn1',
        requestedLeg: Winn3CoverLeg.xray,
        nowMonotonicMs: 1011,
      );
      expect(afterXray.result, Winn3GrantConsumeResult.ok);
      expect(afterXray.grant, isNull);
    });
  });

  group('indexOfCoverBearingWinn1Fallback', () {
    test('picks the next cover-bearing node after a failed v3 slug', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(slug: 'france-winn1'),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        1,
      );
    });

    test('NEGATIVE: never returns the failed slug', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'only-one'),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'only-one',
          alreadyTriedSlugs: <String>{'only-one'},
        ),
        isNull,
      );
    });

    test('NEGATIVE: never returns a labelled standalone v3 node', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(
          slug: 'japan-v3',
          protocolVersion: kWinnProtocolV3,
          carrier: kWinnCarrierWinn3,
        ),
      ];
      final japan = locations[1];
      expect(listingNodeIsCoverBearing(japan), isTrue);
      expect(listingNodeIsStandaloneWinn3(japan), isTrue);
      expect(listingNodeIsReachable(japan), isTrue);
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        isNull,
        reason: 'rotating v3-to-v3 is not cover against a drop-UDP censor. '
            'If listingNodeIsStandaloneWinn3 were constant false this would '
            'return 1, because japan-v3 is cover-bearing and reachable.',
      );
    });

    test('NEGATIVE: never returns an unreachable node', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(slug: 'france-winn1', reachable: false),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        isNull,
      );
    });

    test('NEGATIVE: never returns a UDP-only node (no stealth cover)', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(slug: 'udp-only', stealth: ''),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        isNull,
        reason: 'a UDP-only successor dies under the same drop-UDP rule',
      );
    });

    test(
        'a node with stealth_tcp_ws=ok and empty stealth_endpoint still counts',
        () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(
          slug: 'cdn-fronted',
          stealth: '',
          transports: <String, String>{'stealth_tcp_ws': 'ok'},
        ),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        1,
      );
    });

    test('skips already-tried slugs and takes the next cover node', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(slug: 'france-tried'),
        _node(slug: 'germany-ok'),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3', 'france-tried'},
        ),
        2,
      );
    });

    test('unlabelled listing nodes fail closed instead of becoming v1', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', protocolVersion: null),
        _node(slug: 'france-unknown', protocolVersion: null),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        isNull,
      );
    });

    test('empty listing fails closed', () {
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: const <Map<String, dynamic>>[],
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        isNull,
      );
    });

    test('skips auto slug and picks the next named cover node', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'auto'),
        _node(slug: 'france-winn1'),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        1,
      );
    });

    test('NEGATIVE: labelled relay v3 is never a v1 fallback candidate', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(
          slug: 'relay-v3',
          protocolVersion: kWinnProtocolV3,
          carrier: kWinnCarrierDirectAwg,
        ),
      ];
      expect(listingNodeIsStandaloneWinn3(locations[1]), isFalse);
      expect(listingNodeIsWinn1OrLegacy(locations[1]), isFalse);
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        isNull,
        reason: 'carrier labels cannot reclassify protocol_version winn/3 as '
            'a Winn v1 compatibility route',
      );
    });

    test('NEGATIVE: an unversioned winn3 carrier is not legacy', () {
      final locations = <Map<String, dynamic>>[
        _node(
          slug: 'failed-v3',
          protocolVersion: null,
          carrier: kWinnCarrierWinn3,
        ),
        _node(
          slug: 'contradictory',
          protocolVersion: null,
          carrier: kWinnCarrierWinn3,
        ),
      ];
      expect(listingNodeIsWinn1OrLegacy(locations[1]), isFalse);
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'failed-v3',
          alreadyTriedSlugs: <String>{'failed-v3'},
        ),
        isNull,
      );
    });

    test('NEGATIVE: unknown protocol versions are not treated as legacy', () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(slug: 'future', protocolVersion: 'winn/99'),
      ];
      expect(listingNodeIsWinn1OrLegacy(locations[1]), isFalse);
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        isNull,
      );
    });

    test('absent reachable defaults to reachable, matching the listing ingest',
        () {
      final locations = <Map<String, dynamic>>[
        _node(slug: 'spain-v3', carrier: kWinnCarrierWinn3),
        _node(slug: 'cached-old', reachable: null),
      ];
      expect(
        indexOfCoverBearingWinn1Fallback(
          locations: locations,
          failedSlug: 'spain-v3',
          alreadyTriedSlugs: <String>{'spain-v3'},
        ),
        1,
      );
    });
  });

  group('budget', () {
    test('three tried slugs exhausts the cap', () {
      expect(
        winn3CoverFallbackBudgetRemains(<String>{'a', 'b', 'c'}),
        isFalse,
      );
      expect(
        winn3CoverFallbackBudgetRemains(<String>{'a'}),
        isTrue,
      );
    });

    test('the cap is 3 including the original, not unbounded', () {
      expect(kWinn3CoverFallbackMaxAttempts, 3);
    });
  });

  group('servedWinnCarrier', () {
    test('absent carrier is direct-awg, not winn3', () {
      expect(
        servedWinnCarrier(
            <String, dynamic>{'protocol_params': <String, dynamic>{}}),
        kWinnCarrierDirectAwg,
      );
    });

    test('protocol_params.carrier wins over a top-level carrier', () {
      expect(
        servedWinnCarrier(<String, dynamic>{
          'carrier': kWinnCarrierDirectAwg,
          'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
        }),
        kWinnCarrierWinn3,
      );
    });
  });
}
