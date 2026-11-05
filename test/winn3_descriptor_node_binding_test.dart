import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Hostile binding of a verified Winn v3 descriptor to the route-selected node.
///
/// Signature validity is not enough: a valid descriptor for gateway A
/// substituted into gateway B's config would seal initiations only A can
/// open. These rows pin that the start path refuses before any credential
/// (`inner_v4`, `static_private`, `admission_key`) is emitted.
void main() {
  late SimpleKeyPair signingKey;
  late String publicKeyB64;

  setUp(() async {
    signingKey = await Ed25519().newKeyPair();
    final pub = await signingKey.extractPublicKey();
    publicKeyB64 = base64.encode(pub.bytes);
  });

  Winn3DescriptorKeyRing ring() => Winn3DescriptorKeyRing.fromEncoded(
        <String, String>{'g1': publicKeyB64},
      );

  DateTime insideLifetime() =>
      DateTime.fromMillisecondsSinceEpoch(1786000100 * 1000, isUtc: true);

  Map<String, dynamic> descriptorPayload({
    String node = 'lab-alpha',
    Map<String, dynamic> overrides = const <String, dynamic>{},
  }) =>
      <String, dynamic>{
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
        ...overrides,
      };

  Future<Map<String, dynamic>> envelopeFor(Map<String, dynamic> payload) async {
    final raw = utf8.encode(json.encode(payload));
    final message = <int>[
      ...utf8.encode(kWinn3DescriptorDomain),
      0x00,
      ...raw,
    ];
    final signature = await Ed25519().sign(message, keyPair: signingKey);
    return <String, dynamic>{
      'payload': base64.encode(raw),
      'sig': base64.encode(signature.bytes),
    };
  }

  Future<Map<String, dynamic>> standaloneConfig({
    Map<String, dynamic>? payload,
    Map<String, dynamic> overrides = const <String, dynamic>{},
  }) async {
    final config = <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
      'node_slug': 'lab-alpha',
      'server_endpoint': '203.0.113.7:51820',
      'client_ip': '10.8.1.3',
      'mtu': 1280,
      'winn3_descriptor': await envelopeFor(payload ?? descriptorPayload()),
      'winn3_inner_v4': '10.10.4.9',
      'winn3_static_private': base64.encode(List<int>.filled(32, 0x11)),
    };
    config.addAll(overrides);
    return config;
  }

  Future<Winn3DescriptorCheck> verify(Map<String, dynamic> config) {
    return verifyWinn3Descriptor(
      config: config,
      ring: ring(),
      now: insideLifetime(),
    );
  }

  Future<WinnStartDecision> startOf(Map<String, dynamic> config) async {
    final check = await verify(config);
    expect(check.verified, isTrue, reason: check.reason);
    return resolveWinnProtocolStartForServedConfig(
      config: config,
      winn3Descriptor: check,
    );
  }

  Map<String, String> iniPairs(String section) {
    final pairs = <String, String>{};
    for (final line in section.split('\n')) {
      final idx = line.indexOf('=');
      if (idx < 0) continue;
      pairs[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
    }
    return pairs;
  }

  void expectMismatch(WinnStartDecision decision, {required String reason}) {
    expect(decision.supported, isFalse, reason: reason);
    expect(
      decision.reason,
      WinnRefusalReason.winn3DescriptorNodeMismatch,
      reason: reason,
    );
    expect(decision.iniSection, isEmpty, reason: reason);
    expect(
      decision.iniSection.contains('admission_key'),
      isFalse,
      reason: '$reason: credentials must not be emitted after a mismatch',
    );
  }

  test('ASCII mixed-case selected node matches the signed descriptor node',
      () async {
    expect(winn3NormalizedNodeIdentity('Lab-Alpha'), 'lab-alpha');
    expect(winn3NormalizedNodeIdentity(' lab-alpha '), 'lab-alpha');
    expect(winn3AsciiLowercase('LAB-ALPHA'), 'lab-alpha');

    final config = await standaloneConfig(
      overrides: <String, dynamic>{'node_slug': 'LAB-ALPHA'},
    );
    final decision = await startOf(config);
    expect(decision.supported, isTrue,
        reason: '${decision.reason.code}: ${decision.message}');
    final pairs = iniPairs(decision.iniSection);
    expect(pairs['node'], 'lab-alpha');
    expect(pairs['selected_node'], 'lab-alpha');
    expect(pairs['admission_key'], isNotEmpty);
  });

  test('each selected-node alias alone binds when it names the signed node',
      () async {
    for (final key in kWinn3SelectedNodeIdentityKeys) {
      final config = await standaloneConfig();
      config.remove('node_slug');
      config[key] = 'lab-alpha';
      final decision = await startOf(config);
      expect(decision.supported, isTrue,
          reason: '$key: ${decision.reason.code}: ${decision.message}');
      expect(iniPairs(decision.iniSection)['selected_node'], 'lab-alpha',
          reason: key);
    }
  });

  test('auth-response selected_node map binds through its slug', () async {
    final config = await standaloneConfig();
    config.remove('node_slug');
    config['selected_node'] = <String, dynamic>{
      'slug': 'Lab-Alpha',
      'name': 'Lab Alpha',
      'flag': 'xx',
    };
    final decision = await startOf(config);
    expect(decision.supported, isTrue,
        reason: '${decision.reason.code}: ${decision.message}');
    expect(iniPairs(decision.iniSection)['selected_node'], 'lab-alpha');
  });

  test('agreeing aliases still start', () async {
    final config = await standaloneConfig(
      overrides: <String, dynamic>{
        'node_slug': 'lab-alpha',
        'nodeslug': 'LAB-ALPHA',
        'location_slug': 'lab-alpha',
        'selected_node': 'lab-alpha',
      },
    );
    final decision = await startOf(config);
    expect(decision.supported, isTrue,
        reason: '${decision.reason.code}: ${decision.message}');
  });

  test('a matching decoy alias cannot hide a different selected node', () async {
    final config = await standaloneConfig(
      overrides: <String, dynamic>{
        'node_slug': 'lab-alpha',
        'location_slug': 'lab-beta',
      },
    );
    expectMismatch(
      await startOf(config),
      reason: 'node_slug matches the descriptor while location_slug does not',
    );
  });

  test('selected_node disagreeing with node_slug is a mismatch, not first-wins',
      () async {
    final config = await standaloneConfig(
      overrides: <String, dynamic>{
        'node_slug': 'lab-alpha',
        'selected_node': 'lab-beta',
      },
    );
    expectMismatch(
      await startOf(config),
      reason: 'native selected_node must not be ignored when node_slug matches',
    );
  });

  test('nested selected_node slug conflict is a mismatch', () async {
    final config = await standaloneConfig();
    config.remove('node_slug');
    config['selected_node'] = <String, dynamic>{
      'slug': 'lab-alpha',
      'node_slug': 'lab-beta',
    };
    expectMismatch(
      await startOf(config),
      reason: 'conflicting slug keys inside selected_node',
    );
  });

  test('missing selected-node identity refuses before credentials', () async {
    final config = await standaloneConfig()..remove('node_slug');
    expect(winn3SelectedNodeIdentity(config), isEmpty);
    expectMismatch(await startOf(config), reason: 'no selected-node identity');
  });

  test('whitespace-only node_slug is missing, not a match', () async {
    final config = await standaloneConfig(
      overrides: <String, dynamic>{'node_slug': '   '},
    );
    expectMismatch(await startOf(config), reason: 'whitespace node_slug');
  });

  test('a selected_node map without a slug is missing, not toString-coerced',
      () async {
    final config = await standaloneConfig();
    config.remove('node_slug');
    config['selected_node'] = <String, dynamic>{
      'name': 'Lab Alpha',
      'flag': 'xx',
    };
    expectMismatch(
      await startOf(config),
      reason: 'selected_node object with no slug',
    );
  });

  test('non-string selected node identities are refused, not coerced', () async {
    for (final hostile in <Object?>[
      1,
      true,
      <String>['lab-alpha'],
    ]) {
      final config = await standaloneConfig();
      config.remove('node_slug');
      config['selected_node'] = hostile;
      expectMismatch(
        await startOf(config),
        reason: 'selected_node=$hostile',
      );
    }
  });

  test('cross-node: signed lab-alpha cannot start as lab-beta', () async {
    final config = await standaloneConfig(
      overrides: <String, dynamic>{'node_slug': 'lab-beta'},
    );
    final check = await verify(config);
    expect(check.verified, isTrue, reason: check.reason);
    expect(check.descriptor!.node, 'lab-alpha');
    expect(
      winn3DescriptorMatchesSelectedNode(
        descriptor: check.descriptor!,
        config: config,
      ),
      isFalse,
    );
    expectMismatch(
      resolveWinnProtocolStartForServedConfig(
        config: config,
        winn3Descriptor: check,
      ),
      reason: 'cross-node substitution',
    );
  });

  test('replayed descriptor: a previously accepted envelope cannot retarget',
      () async {
    final accepted = await standaloneConfig();
    final acceptedDecision = await startOf(accepted);
    expect(acceptedDecision.supported, isTrue,
        reason: '${acceptedDecision.reason.code}: ${acceptedDecision.message}');
    expect(iniPairs(acceptedDecision.iniSection)['admission_key'], isNotEmpty);

    final replayed = Map<String, dynamic>.from(accepted)
      ..['node_slug'] = 'lab-beta';
    final replayedCheck = await verify(replayed);
    expect(replayedCheck.verified, isTrue,
        reason: 'the envelope is still a valid signed descriptor; retargeting '
            'is a start-time binding refusal, not a signature failure. '
            'got ${replayedCheck.reason}');
    expect(
      identical(
        accepted['winn3_descriptor'],
        replayed['winn3_descriptor'],
      ),
      isTrue,
      reason: 'the same envelope object is replayed onto another selected node',
    );
    expectMismatch(
      resolveWinnProtocolStartForServedConfig(
        config: replayed,
        winn3Descriptor: replayedCheck,
      ),
      reason: 'replayed envelope onto lab-beta',
    );
  });

  test('replayed descriptor transplanted onto a different served config',
      () async {
    final alpha = await standaloneConfig();
    final envelope = alpha['winn3_descriptor'];
    final beta = await standaloneConfig(
      overrides: <String, dynamic>{
        'node_slug': 'lab-gamma',
        'winn3_descriptor': envelope,
      },
    );
    expectMismatch(
      await startOf(beta),
      reason: 'transplanted lab-alpha envelope onto lab-gamma',
    );
  });

  test('Unicode homoglyphs, folds, and compatibility forms cannot bind',
      () async {
    const ascii = 'lab-alpha';
    final hostileSelected = <String>[
      'l\u0430b-alpha', // Cyrillic a
      'lab-\u03b1lpha', // Greek alpha
      'lab-alpha\u200b', // zero-width space
      'lab-\u0061\u0301lpha', // combining acute
      'lab\u2010alpha', // hyphen vs non-breaking hyphen
      '\uff4c\uff41\uff42-\uff41\uff4c\uff50\uff48\uff41', // fullwidth
      'lab-alpha\u00a0', // NBSP: Dart trim() would eat it, native Trim would not
    ];

    for (final selected in hostileSelected) {
      expect(
        winn3NormalizedNodeIdentity(selected),
        isNull,
        reason: 'selected=$selected must not fold onto $ascii',
      );
      final config = await standaloneConfig(
        overrides: <String, dynamic>{'node_slug': selected},
      );
      expectMismatch(
        await startOf(config),
        reason: 'unicode selected=$selected',
      );
    }
  });

  test('Kelvin-sign case fold cannot match a signed k1 node', () async {
    // Dart toLowerCase() maps U+212A onto 'k'. ASCII-only must not.
    expect('\u212A'.toLowerCase(), 'k');
    expect(winn3NormalizedNodeIdentity('\u212A1'), isNull);
    expect(winn3NormalizedNodeIdentity('k1'), 'k1');

    final config = await standaloneConfig(
      payload: descriptorPayload(node: 'k1'),
      overrides: <String, dynamic>{'node_slug': '\u212A1'},
    );
    final check = await verify(config);
    expect(check.verified, isTrue, reason: check.reason);
    expect(check.descriptor!.node, 'k1');
    expectMismatch(
      resolveWinnProtocolStartForServedConfig(
        config: config,
        winn3Descriptor: check,
      ),
      reason: 'Kelvin U+212A must not bind to signed k1',
    );
  });

  test('a signed descriptor whose node is a Kelvin fold is not a node identity',
      () async {
    final config = await standaloneConfig(
      payload: descriptorPayload(node: '\u212A1'),
      overrides: <String, dynamic>{'node_slug': 'k1'},
    );
    final check = await verify(config);
    expect(check.verified, isFalse);
    expect(check.reason, 'descriptor-missing-node');
    expect(check.descriptor, isNull);
  });

  test('binding refusal does not authorize reading device or gateway keys',
      () async {
    final config = await standaloneConfig(
      overrides: <String, dynamic>{'node_slug': 'lab-beta'},
    );
    final decision = await startOf(config);
    expectMismatch(decision, reason: 'no credential emission');
    expect(decision.iniSection.contains('static_private'), isFalse);
    expect(decision.iniSection.contains('gateway_static'), isFalse);
    expect(decision.iniSection.contains('admission_key'), isFalse);
    expect(decision.iniSection.contains('inner_v4'), isFalse);
  });
}
