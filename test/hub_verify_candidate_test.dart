import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/hub_request_window.dart';
import 'package:wins_vpn/hub_verify_candidate.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Validation BEFORE a winner is declared: each invalid reply below loses, and
/// a valid reply that arrives after it still wins.
void main() {
  late SimpleKeyPair gatewaySigner;
  late SimpleKeyPair forger;
  late Winn3DescriptorKeyRing ring;

  // A valid WireGuard key shape: 43 base64 characters ending in a legal
  // final character, then '='.
  String wgKey(int fill) => base64.encode(List<int>.filled(32, fill));
  final localPublic = wgKey(0x21);
  final otherDevicePublic = wgKey(0x22);
  final insideLifetime =
      DateTime.fromMillisecondsSinceEpoch(1786000100 * 1000, isUtc: true);

  setUp(() async {
    gatewaySigner = await Ed25519().newKeyPair();
    forger = await Ed25519().newKeyPair();
    final pub = await gatewaySigner.extractPublicKey();
    ring = Winn3DescriptorKeyRing.fromEncoded(
        <String, String>{'g1': base64.encode(pub.bytes)});
  });

  Future<Map<String, dynamic>> envelope(SimpleKeyPair signer,
      {String node = 'lab-alpha'}) async {
    final raw = utf8.encode(json.encode(<String, dynamic>{
      'v': kWinn3DescriptorFormatVersion,
      'alg': 'ed25519',
      'kid': 'g1',
      'node': node,
      'endpoint': '203.0.113.7:51820',
      'inner_router_v4': '10.10.0.1',
      'inner_resolver_v4': '10.10.0.1',
      'static_pub': base64.encode(List<int>.filled(32, 0x53)),
      'gateway_id': base64.encode(utf8.encode('winsgw01')),
      'admission_secret': base64.encode(utf8.encode('ab' * 32)),
      'admission_gen': 1,
      'tag_size': 32,
      'padding': 'bucket',
      'bucket_window_s': 10,
      'max_skew_s': 60,
      'seq': 1,
      'iat': 1786000000,
      'not_after': 1786086400,
    }));
    final signature = await Ed25519().sign(
      <int>[...utf8.encode(kWinn3DescriptorDomain), 0x00, ...raw],
      keyPair: signer,
    );
    return <String, dynamic>{
      'payload': base64.encode(raw),
      'sig': base64.encode(signature.bytes),
    };
  }

  /// What the connect path's normalization produces, with this device's local
  /// keys attached.
  Map<String, dynamic> normalized({
    String node = 'lab-alpha',
    bool standalone = false,
    Map<String, dynamic>? descriptor,
    bool usable = true,
    String? locationSlugAlias,
  }) =>
      <String, dynamic>{
        'client_private_key': usable ? wgKey(0x11) : 'not-a-key',
        'client_public_key': localPublic,
        'server_public_key': wgKey(0x31),
        'client_ip': '10.8.1.3',
        'dns': '10.8.1.1',
        'server_endpoint': '203.0.113.7:51820',
        'mtu': 1280,
        'node_slug': node,
        if (locationSlugAlias != null) 'location_slug': locationSlugAlias,
        if (standalone) ...<String, dynamic>{
          'protocol_version': kWinnProtocolV3,
          'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
          'winn3_inner_v4': '10.10.4.9',
          'winn3_static_private': base64.encode(List<int>.filled(32, 0x11)),
        },
        if (descriptor != null) 'winn3_descriptor': descriptor,
      };

  Future<String?> reject({
    Map<String, dynamic>? config,
    String servedKey = '',
    String target = 'lab-alpha',
    Object? selectedNode = 'lab-alpha',
  }) async {
    final normalizedConfig = config ?? normalized();
    return hubVerifyCandidateRejection(
      responseData: <String, dynamic>{
        'status': 'authenticated',
        'selected_node': selectedNode,
      },
      servedConfig: <String, dynamic>{
        ...normalizedConfig,
        'client_public_key': servedKey,
      },
      normalizedConfig: normalizedConfig,
      localClientPublicKey: localPublic,
      requirements: HubVerifyRequirements(
        exactTarget: target,
        doubleVpnRequired: false,
      ),
      descriptorRing: ring,
      now: insideLifetime,
    );
  }

  group('each check', () {
    test('a usable, bound, on-target reply is accepted', () async {
      expect(await reject(servedKey: localPublic), isNull);
    });
    test('an unusable config is rejected', () async {
      expect(await reject(config: normalized(usable: false)),
          'config_unusable');
    });
    test('a reply for a different target is rejected', () async {
      expect(await reject(config: normalized(node: 'lab-beta')),
          'response_target_mismatch');
      expect(await reject(selectedNode: 'lab-beta'),
          'response_target_mismatch');
    });
    test('a reply built for another device key is rejected', () async {
      expect(await reject(servedKey: otherDevicePublic), 'client_key_mismatch');
    });
    test('an absent key echo is accepted (older hub lineages)', () async {
      expect(await reject(servedKey: ''), isNull);
    });
    test('a standalone v3 reply needs a descriptor signed by the gateway key',
        () async {
      expect(
        await reject(
            config: normalized(
                standalone: true, descriptor: await envelope(gatewaySigner))),
        isNull,
      );
      expect(
        await reject(
            config: normalized(
                standalone: true, descriptor: await envelope(forger))),
        'winn3_descriptor_unverified:descriptor-signature-invalid',
      );
      expect(
        await reject(config: normalized(standalone: true)),
        startsWith('winn3_descriptor_unverified:'),
      );
    });
    test('a correctly signed descriptor for the WRONG node is rejected',
        () async {
      expect(
        await reject(
            config: normalized(
                standalone: true,
                descriptor: await envelope(gatewaySigner, node: 'lab-beta'))),
        'winn3_descriptor_node_mismatch',
      );
    });
    test('conflicting served node aliases never bind a descriptor', () async {
      expect(
        await reject(
            config: normalized(
                standalone: true,
                locationSlugAlias: 'lab-beta',
                descriptor: await envelope(gatewaySigner)),
            target: 'auto'),
        'winn3_descriptor_node_mismatch',
      );
    });
    test('requirements come from the payload that was sent', () {
      final activation = HubVerifyRequirements.fromRequestPayload(
        <String, dynamic>{'location': ' lab-alpha ', 'double_vpn': true},
        enforceDoubleVpn: false,
      );
      expect(activation.exactTarget, 'lab-alpha');
      expect(activation.doubleVpnRequired, isFalse);
      final paid = HubVerifyRequirements.fromRequestPayload(
          <String, dynamic>{'location': 'auto', 'double_vpn': true});
      expect(paid.exactTarget, 'auto');
      expect(paid.doubleVpnRequired, isTrue);
      expect(
          HubVerifyRequirements.fromRequestPayload(<String, dynamic>{})
              .exactTarget,
          '');
    });
    test('auto selection has no exact target to enforce', () async {
      expect(await reject(config: normalized(node: 'lab-beta'), target: 'auto'),
          isNull);
    });
  });

  test('invalid config, a different requested node, wrong device, forged '
      'signature, a signed descriptor for the wrong node and conflicting '
      'aliases all arrive first and lose; the valid reply wins', () async {
    final forged = await envelope(forger);
    final genuine = await envelope(gatewaySigner);
    // Real time, short stagger: this test is about ordering, not timing. Front
    // i answers 30 ms + 30 ms * i after it starts, with candidate i.
    final wrongNode = await envelope(gatewaySigner, node: 'lab-beta');
    final replies = <Map<String, dynamic>>[
      normalized(usable: false),
      // An activation reply for a different node than the one this request
      // explicitly asked for.
      normalized(node: 'lab-beta'),
      <String, dynamic>{...normalized(), '_served_key': otherDevicePublic},
      normalized(standalone: true, descriptor: forged),
      normalized(standalone: true, descriptor: wrongNode, node: 'lab-alpha'),
      normalized(
          standalone: true, descriptor: genuine, locationSlugAlias: 'lab-beta'),
      normalized(standalone: true, descriptor: genuine),
    ];
    // Captured the way activation captures them: from its request payload.
    final requirements = HubVerifyRequirements.fromRequestPayload(
      <String, dynamic>{'location': 'lab-alpha'},
      enforceDoubleVpn: false,
    );
    final reasons = <int, String?>{};
    final order = <int>[];
    final outcome = await runHubRequestWindow<int>(
      urls: List<String>.generate(replies.length, (i) => 'https://f$i/verify'),
      permits: HubTransportPermits(replies.length),
      policy: HubRequestWindowPolicy(
        stagger: const Duration(milliseconds: 20),
        minSpacing: const Duration(milliseconds: 5),
        maxInFlight: replies.length,
      ),
      attempt: (url, abort) async {
        final i = int.parse(url.substring(9, 10));
        await Future<void>.delayed(Duration(milliseconds: 30 + 30 * i));
        final config = replies[i];
        final rejection = await hubVerifyCandidateRejection(
          responseData: const <String, dynamic>{'status': 'authenticated'},
          servedConfig: <String, dynamic>{
            ...config,
            'client_public_key': config['_served_key'] ?? localPublic,
          },
          normalizedConfig: config,
          localClientPublicKey: localPublic,
          requirements: requirements,
          descriptorRing: ring,
          now: insideLifetime,
        );
        order.add(i);
        reasons[i] = rejection;
        return rejection == null
            ? HubAttemptResult<int>.accepted(i)
            : const HubAttemptResult<int>.rejected();
      },
    );
    expect(outcome.value, 6);
    expect(order.take(6), <int>[0, 1, 2, 3, 4, 5]);
    expect(reasons[0], 'config_unusable');
    expect(reasons[1], 'response_target_mismatch');
    expect(reasons[2], 'client_key_mismatch');
    expect(reasons[3], 'winn3_descriptor_unverified:descriptor-signature-invalid');
    expect(reasons[4], 'winn3_descriptor_node_mismatch');
    expect(reasons[5], 'winn3_descriptor_node_mismatch');
    expect(reasons[6], isNull);
  });
}
