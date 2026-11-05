import 'package:flutter_test/flutter_test.dart';
import 'dart:io';
import 'package:wins_vpn/vpn_config_validation.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

Map<String, dynamic> _persistedV1({String slug = 'spain'}) {
  return <String, dynamic>{
    'protocol_version': kWinnProtocolV1,
    'node_slug': slug,
    'client_private_key': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
    'server_public_key': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
    'preshared_key': '',
    'client_ip': '10.8.1.2',
    'dns': '10.8.1.1',
    'server_endpoint': '203.0.113.20:9110',
    'mtu': 1280,
    'obfuscation': <String, dynamic>{
      'Jc': 2,
      'Jmin': 10,
      'Jmax': 30,
      'S1': 16,
      'S2': 80,
      'S3': 16,
      'S4': 0,
      'H1': 11,
      'H2': 22,
      'H3': 33,
      'H4': 44,
    },
  };
}

Map<String, dynamic> _freshV3({String slug = 'spain'}) {
  return <String, dynamic>{
    'protocol_version': kWinnProtocolV3,
    'node_slug': slug,
    'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
  };
}

Map<String, dynamic> _listing({
  required String slug,
  String? protocolVersion,
  String? carrier,
}) {
  return <String, dynamic>{
    'slug': slug,
    if (protocolVersion != null) 'protocol_version': protocolVersion,
    if (carrier != null) 'carrier': carrier,
  };
}

void main() {
  setUp(resetWinn1FallbackDispatchAuthorization);
  tearDown(resetWinn1FallbackDispatchAuthorization);

  test('validator default persisted v1 matches protocol dispatch', () {
    expect(
      VpnConfigValidator.defaultPersistedProtocolVersion,
      kWinnProtocolV1,
    );
  });

  group('v1 cache then hub v3 migration', () {
    final cachedV1 = _persistedV1();
    final listingV3 = _listing(
      slug: 'spain',
      protocolVersion: kWinnProtocolV3,
      carrier: kWinnCarrierWinn3,
    );

    test('structurally valid persisted v1 is still v1, not hub evidence', () {
      expect(VpnConfigValidator.isUsable(cachedV1), isTrue);
      expect(persistedConfigIsWinnV1(cachedV1), isTrue);
      expect(listingNodeIsWinn1OrLegacy(listingV3), isFalse);
    });

    test('explicit fast-connect cannot skip refresh after v1-to-v3 migration',
        () {
      expect(
        maySkipControlPlaneRefreshWithCachedConfig(
          cachedConfig: cachedV1,
          automaticMode: false,
          coverExactTarget: false,
        ),
        isFalse,
        reason:
            'a matching explicit slug must still refresh protocol selection',
      );
    });

    test('cached v1 cannot lead AWG/Xray after the hub registered v3', () {
      expect(
        listingAuthorizesPersistedWinn1Lead(listingV3),
        isFalse,
      );
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: cachedV1,
          listingNode: listingV3,
          automaticMode: false,
          coverExactTarget: false,
        ),
        isFalse,
      );
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: cachedV1,
          listingNode: listingV3,
          automaticMode: true,
          coverExactTarget: false,
        ),
        isFalse,
        reason: 'automatic offline must not reuse v1 once listing says v3',
      );
      expect(
        cachedConfigMayAuthorizeAwgOrXray(
          config: cachedV1,
          hasFreshHubConfig: false,
          listingNode: listingV3,
        ),
        isFalse,
      );
    });

    test('fresh hub v3 leads and still requires matching-generation fallback',
        () {
      final fresh = _freshV3();
      expect(
        cachedConfigMayAuthorizeAwgOrXray(
          config: fresh,
          hasFreshHubConfig: true,
          listingNode: listingV3,
        ),
        isTrue,
      );
      final policy = winn3LeadPolicy(
        config: fresh,
        userTcpOnly: false,
        forceXrayForDiagnostics: false,
      );
      expect(policy, Winn3LeadPolicy.attemptPrimary);
      expect(
        maySelectLegacyRouteAfterWinn3Lead(
          policy: policy,
          primaryAttempted: false,
          primaryVerdict: Winn3NativeVerdict.pending,
          securityRefused: false,
          servedConfigNeedsLegacyNode: true,
        ),
        isFalse,
        reason: 'v1 cover stays unauthorized until a matching ordinary failure',
      );
      expect(
        winn3SelectionGenerationPayload(
          selectionGeneration: '0123456789abcdef0123456789abcdef',
          ordinaryConnectivityAuthorized: false,
        ).containsKey('ordinary_v3_failure_generation'),
        isFalse,
      );
    });

    test('listing lookup binds the persisted slug, not auto', () {
      final france = _listing(
        slug: 'france',
        protocolVersion: kWinnProtocolV1,
      );
      final locations = <Map<String, dynamic>>[france, listingV3];
      expect(listingNodeForSlug(locations, 'spain'), listingV3);
      expect(listingNodeForSlug(locations, 'france'), france);
      expect(listingNodeForSlug(locations, 'auto'), isNull);
      expect(listingNodeForSlug(locations, ''), isNull);
      expect(VpnConfigValidator.persistedNodeSlug(cachedV1), 'spain');
    });

    test('connect path rejects cached or bootstrap listing evidence', () {
      final source = File('lib/main.dart').readAsStringSync();
      expect(
        source,
        contains(
          'protocolListingNode = _lastConfigRefreshHadLiveNodeListing',
        ),
      );
      expect(
        source,
        contains('? _protocolListingNodeForConfig(cachedDirectConfig)'),
      );
    });
  });

  group('genuine offline and automatic mode', () {
    test('automatic mode still refreshes before any cached reuse', () {
      expect(
        maySkipControlPlaneRefreshWithCachedConfig(
          cachedConfig: _persistedV1(),
          automaticMode: true,
          coverExactTarget: false,
        ),
        isFalse,
      );
      expect(
        maySkipControlPlaneRefreshWithCachedConfig(
          cachedConfig: _freshV3(),
          automaticMode: true,
          coverExactTarget: false,
        ),
        isFalse,
      );
    });

    test('v1 listing alone cannot authorize cached v1', () {
      final cached = _persistedV1(slug: 'france');
      final stillV1 = _listing(
        slug: 'france',
        protocolVersion: kWinnProtocolV1,
      );
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: cached,
          listingNode: stillV1,
          automaticMode: true,
          coverExactTarget: false,
        ),
        isFalse,
      );
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: cached,
          listingNode: stillV1,
          automaticMode: false,
          coverExactTarget: false,
        ),
        isFalse,
      );
      expect(
        cachedConfigMayAuthorizeAwgOrXray(
          config: cached,
          hasFreshHubConfig: false,
          listingNode: stillV1,
        ),
        isFalse,
        reason: 'listing evidence is not an ordinary-v3-failure grant',
      );
    });

    test('generation-bound ordinary failure authorizes exact cached v1', () {
      const generation = '0123456789abcdef0123456789abcdef';
      final cached = _persistedV1(slug: 'france');
      final stillV1 = _listing(
        slug: 'france',
        protocolVersion: kWinnProtocolV1,
      );
      synchronizeWinn1FallbackDispatchGeneration(
        selectionGeneration: generation,
        ordinaryConnectivityAuthorized: false,
      );
      expect(
        armWinn1FallbackDispatchAuthorization(
          startToken: 41,
          startGeneration: 9,
          selectionGeneration: generation,
          failedV3Node: 'spain',
        ),
        isTrue,
      );
      synchronizeWinn1FallbackDispatchGeneration(
        selectionGeneration: generation,
        ordinaryConnectivityAuthorized: true,
      );
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: cached,
          listingNode: stillV1,
          automaticMode: false,
          coverExactTarget: false,
        ),
        isTrue,
      );
      expect(
        cachedConfigMayAuthorizeAwgOrXray(
          config: cached,
          hasFreshHubConfig: false,
          listingNode: stillV1,
        ),
        isTrue,
      );
    });

    test('missing listing is not hub evidence for cached v1', () {
      final cached = _persistedV1();
      expect(listingAuthorizesPersistedWinn1Lead(null), isFalse);
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: cached,
          listingNode: null,
          automaticMode: true,
          coverExactTarget: false,
        ),
        isFalse,
      );
      expect(
        cachedConfigMayAuthorizeAwgOrXray(
          config: cached,
          hasFreshHubConfig: false,
          listingNode: null,
        ),
        isFalse,
      );
    });

    test('automatic offline may reuse cached v3 without a v1 listing grant',
        () {
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: _freshV3(),
          listingNode: null,
          automaticMode: true,
          coverExactTarget: false,
        ),
        isTrue,
      );
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: _freshV3(),
          listingNode: null,
          automaticMode: false,
          coverExactTarget: false,
        ),
        isFalse,
      );
    });

    test('cover-exact never reuses persisted v1 after a failed refresh', () {
      expect(
        maySkipControlPlaneRefreshWithCachedConfig(
          cachedConfig: _persistedV1(),
          automaticMode: false,
          coverExactTarget: true,
        ),
        isFalse,
      );
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: _persistedV1(),
          listingNode: _listing(
            slug: 'spain',
            protocolVersion: kWinnProtocolV1,
          ),
          automaticMode: false,
          coverExactTarget: true,
        ),
        isFalse,
      );
    });

    test('explicit non-v1 cache may still skip refresh', () {
      // Only while fresh: an unstamped v3 cache now asks the hub first
      // (winn3_stale_cached_config_test.dart).
      expect(
        maySkipControlPlaneRefreshWithCachedConfig(
          cachedConfig: stampVpnConfigFetchedAt(_freshV3(), DateTime.now()),
          automaticMode: false,
          coverExactTarget: false,
        ),
        isTrue,
      );
    });

    test('omitted protocol_version is ambiguous, not persisted v1', () {
      final omitted = _persistedV1()..remove('protocol_version');
      expect(persistedConfigIsWinnV1(omitted), isFalse);
      expect(
        maySkipControlPlaneRefreshWithCachedConfig(
          cachedConfig: omitted,
          automaticMode: false,
          coverExactTarget: false,
        ),
        isFalse,
      );
    });
  });

  group('primary hub v1 authorization (iOS / non-Winn3)', () {
    const generation = '0123456789abcdef0123456789abcdef';
    final freshV1 = _persistedV1(slug: 'spain-madrid');
    final listingV1 = _listing(
      slug: 'spain-madrid',
      protocolVersion: kWinnProtocolV1,
      carrier: 'amneziawg',
    );

    test('armWinn1PrimaryHubDispatchAuthorization authorizes AWG/Xray and winnSection', () {
      synchronizeWinn1FallbackDispatchGeneration(
        selectionGeneration: generation,
        ordinaryConnectivityAuthorized: false,
      );
      expect(
        armWinn1PrimaryHubDispatchAuthorization(
          config: freshV1,
          selectionGeneration: generation,
        ),
        isTrue,
      );
      expect(
        cachedConfigMayAuthorizeAwgOrXray(
          config: freshV1,
          hasFreshHubConfig: true,
          listingNode: listingV1,
        ),
        isTrue,
      );
      expect(
        winn3LeadPolicy(
          config: freshV1,
          userTcpOnly: false,
          forceXrayForDiagnostics: false,
        ),
        Winn3LeadPolicy.legacyTransportPolicy,
      );
      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'ios',
          config: freshV1,
        ),
        '',
      );
    });

    test('primary grant cannot be armed with wrong selection generation', () {
      synchronizeWinn1FallbackDispatchGeneration(
        selectionGeneration: generation,
        ordinaryConnectivityAuthorized: false,
      );
      expect(
        armWinn1PrimaryHubDispatchAuthorization(
          config: freshV1,
          selectionGeneration: 'differentgeneration0123456789abc',
        ),
        isFalse,
      );
    });
  });
}
