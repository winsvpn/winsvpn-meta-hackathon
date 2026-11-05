import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Pins the v3 descriptor field set across the per-node key rollout
/// (Round GK OI-GK-3, 2026-09-26).
///
/// This client refuses a signed descriptor that carries any field outside its
/// closed schema (descriptor-unknown-fields). Per-node ECH configs, cover
/// pins and Winn leaf pins must therefore NOT be added to the descriptor until
/// a client release that accepts them is fleet-wide; they travel in a separate
/// signed document instead. If this test goes red, a field was added to the
/// descriptor in one of its three copies (this client, the hub, the offline
/// signer), and every shipped client would drop standalone v3 for any node
/// whose descriptor used it.
void main() {
  const pinnedRequired = <String>{
    'admission_gen',
    'admission_secret',
    'alg',
    'bucket_window_s',
    'endpoint',
    'gateway_id',
    'iat',
    'inner_resolver_v4',
    'inner_router_v4',
    'kid',
    'max_skew_s',
    'node',
    'not_after',
    'padding',
    'seq',
    'static_pub',
    'tag_size',
    'v',
  };
  const pinnedOptional = <String>{'auth_ed25519', 'auth_mldsa65'};

  test('the client descriptor field set is exactly the pinned set', () {
    expect(kWinn3DescriptorRequiredFields, equals(pinnedRequired));
    expect(kWinn3DescriptorOptionalFields, equals(pinnedOptional));
    for (final field in <String>{
      ...kWinn3DescriptorRequiredFields,
      ...kWinn3DescriptorOptionalFields,
    }) {
      expect(field, isNot(matches(RegExp('ech|cover|leaf|spki'))),
          reason: '$field looks like per-node key material');
    }
  });

  // The hub and the offline signer each keep their own copy. A field added to
  // one of them and not here is the silent-drop failure this file guards.
  Set<String> pythonTuple(String path, String name) {
    final source = File(path).readAsStringSync();
    final match = RegExp('^$name = \\(([^)]*)\\)', multiLine: true)
        .firstMatch(source);
    expect(match, isNotNull, reason: '$name not found in $path');
    return RegExp('"([a-z0-9_]+)"')
        .allMatches(match!.group(1)!)
        .map((m) => m.group(1)!)
        .toSet();
  }

  test('the hub and the offline signer carry the same pinned field set', () {
    const hub = 'server/wins_control_plane_setup_ONETOUCH.sh';
    const signer = 'tools/winn3_sign_descriptor.py';
    expect(pythonTuple(hub, 'WINN3_DESCRIPTOR_REQUIRED_FIELDS'),
        equals(pinnedRequired));
    expect(pythonTuple(hub, 'WINN3_DESCRIPTOR_OPTIONAL_FIELDS'),
        equals(pinnedOptional));
    expect(pythonTuple(signer, 'REQUIRED_FIELDS'), equals(pinnedRequired));
    expect(pythonTuple(signer, 'OPTIONAL_FIELDS'), equals(pinnedOptional));
  });

  test('a correctly signed descriptor carrying an ECH config is refused',
      () async {
    final signingKey = await Ed25519().newKeyPair();
    final publicKey = await signingKey.extractPublicKey();
    final ring = Winn3DescriptorKeyRing.fromEncoded(
      <String, String>{'g1': base64.encode(publicKey.bytes)},
    );
    Future<Winn3DescriptorCheck> check(Map<String, dynamic> extra) async {
      final body = <String, dynamic>{
        'v': kWinn3DescriptorFormatVersion,
        'alg': 'ed25519',
        'kid': 'g1',
        'node': 'lab-alpha',
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
        ...extra,
      };
      final raw = utf8.encode(json.encode(body));
      final signature = await Ed25519().sign(
        <int>[...utf8.encode(kWinn3DescriptorDomain), 0x00, ...raw],
        keyPair: signingKey,
      );
      return verifyWinn3Descriptor(
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(raw),
            'sig': base64.encode(signature.bytes),
          },
        },
        ring: ring,
        now: DateTime.fromMillisecondsSinceEpoch(1786000100 * 1000,
            isUtc: true),
      );
    }

    // Anti-vacuity: the same envelope without the extra field verifies, so
    // the refusal below is the closed schema and not a broken fixture.
    final baseline = await check(const <String, dynamic>{});
    expect(baseline.reason, 'winn3-descriptor-verified');
    for (final extra in <Map<String, dynamic>>[
      <String, dynamic>{'ech_config_list': 'AAAA'},
      <String, dynamic>{'leaf_spki_sha256': 'aa' * 32},
    ]) {
      final refused = await check(extra);
      expect(refused.reason, 'descriptor-unknown-fields',
          reason: 'extra ${extra.keys.first}');
    }
  });
}
