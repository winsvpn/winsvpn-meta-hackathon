import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Adversarial table for [verifyWinn3Descriptor].
///
/// The signed descriptor is the network-reachable JSON parser on the
/// standalone v3 path: the hub serves `vpn_config["winn3_descriptor"]` and
/// this function is what a hostile or malformed envelope hits. A throw here
/// is a denial of service. A silent accept of invalid material is a session
/// that starts and is ignored by the gateway, which on a censored network is
/// indistinguishable from a block.
///
/// Each row names the expected [Winn3DescriptorCheck.reason]. Rows that
/// already refused correctly are here so they stay that way. Rows that used
/// to silently accept (payload larger than the hub ceiling, a static_pub
/// that is not 32 bytes, a gateway_id with edge whitespace) now refuse by
/// name; deleting the matching guard must turn the row red.
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

  Map<String, dynamic> payload({
    Map<String, dynamic> overrides = const <String, dynamic>{},
  }) =>
      <String, dynamic>{
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
        ...overrides,
      };

  Future<Map<String, dynamic>> signedEnvelope(Map<String, dynamic> body) async {
    final raw = utf8.encode(json.encode(body));
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

  Future<Winn3DescriptorCheck> checkOf(
    Map<String, dynamic> config, {
    Winn3DescriptorKeyRing? keys,
  }) {
    return verifyWinn3Descriptor(
      config: config,
      ring: keys ?? ring(),
      now: insideLifetime(),
    );
  }

  test('adversarial envelope and payload table', () async {
    final goodEnvelope = await signedEnvelope(payload());

    final rows = <_Row>[
      _Row(
        'empty config is no-descriptor-served',
        config: <String, dynamic>{},
        reason: 'no-descriptor-served',
      ),
      _Row(
        'empty envelope object is no-descriptor-served',
        config: <String, dynamic>{'winn3_descriptor': <String, dynamic>{}},
        reason: 'no-descriptor-served',
      ),
      _Row(
        'descriptor served as a JSON string is not silently parsed',
        config: <String, dynamic>{'winn3_descriptor': json.encode(goodEnvelope)},
        reason: 'no-descriptor-served',
      ),
      _Row(
        'descriptor served as a list is not silently parsed',
        config: <String, dynamic>{
          'winn3_descriptor': <dynamic>[goodEnvelope],
        },
        reason: 'no-descriptor-served',
      ),
      _Row(
        'missing sig is envelope-incomplete',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope['payload'],
          },
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'missing payload is envelope-incomplete',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{'sig': goodEnvelope['sig']},
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'payload that is not base64 is named',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': '@@@not-base64@@@',
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-envelope-not-base64',
      ),
      _Row(
        'payload that is not UTF-8 is named, not thrown',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(const <int>[0xff, 0xfe, 0xfd]),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-not-utf8-json',
      ),
      _Row(
        'payload that is a JSON array is not-an-object',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('[]')),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-not-an-object',
      ),
      _Row(
        'payload that is a JSON string is not-an-object',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('"hello"')),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-not-an-object',
      ),
      _Row(
        'payload that is a JSON number is not-an-object',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('7')),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-not-an-object',
      ),
      _Row(
        'payload that is JSON true is not-an-object',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('true')),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-not-an-object',
      ),
      _Row(
        'payload that is JSON null is not-an-object',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('null')),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-not-an-object',
      ),
      _Row(
        'trailing JSON after the payload object is refused, not under-read',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(
                utf8.encode('${json.encode(payload())}{"x":1}')),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-not-utf8-json',
      ),
      _Row(
        'payload one byte over the hub ceiling is refused before json.parse',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(List<int>.filled(
                kWinn3MaxDescriptorBytes + 1, 0x41)),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-payload-too-large',
      ),
      _Row(
        'payload at the hub ceiling is not too-large (it fails as JSON)',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload':
                base64.encode(List<int>.filled(kWinn3MaxDescriptorBytes, 0x41)),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-not-utf8-json',
      ),
      _Row(
        'signature of the wrong length is invalid, not parsed as JSON first',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope['payload'],
            'sig': base64.encode(List<int>.filled(32, 0x00)),
          },
        },
        reason: 'descriptor-signature-invalid',
      ),
      _Row(
        'empty ring cannot verify',
        config: <String, dynamic>{'winn3_descriptor': goodEnvelope},
        keys: Winn3DescriptorKeyRing.fromEncoded(const <String, String>{}),
        reason: 'descriptor-no-verification-keys-compiled',
      ),
      _Row(
        'unknown kid g4 is refused before a signature is accepted',
        signed: payload(overrides: <String, dynamic>{'kid': 'g4'}),
        reason: 'descriptor-unknown-key-slot',
      ),
      _Row(
        'kid from the announcement family is not a descriptor slot',
        signed: payload(overrides: <String, dynamic>{'kid': 'a1'}),
        reason: 'descriptor-unknown-key-slot',
      ),
      _Row(
        'format version 1 is refused, not partially read',
        signed: payload(overrides: <String, dynamic>{'v': 1}),
        reason: 'descriptor-unsupported-format-version',
      ),
      _Row(
        'format version 2 is refused after the client pins 3',
        signed: payload(overrides: <String, dynamic>{'v': 2}),
        reason: 'descriptor-unsupported-format-version',
      ),
      _Row(
        'format version 4 is refused; the pin is exact, not >=',
        signed: payload(overrides: <String, dynamic>{'v': 4}),
        reason: 'descriptor-unsupported-format-version',
      ),
      _Row(
        'JSON number 3.0 is not an int format version',
        signed: payload(overrides: <String, dynamic>{'v': 3.0}),
        reason: 'descriptor-unsupported-format-version',
      ),
      _Row(
        'string format version is refused',
        signed: payload(overrides: <String, dynamic>{'v': '3'}),
        reason: 'descriptor-unsupported-format-version',
      ),
      _Row(
        'not_after equal to iat is lifetime-malformed',
        signed: payload(overrides: <String, dynamic>{
          'iat': 1786000000,
          'not_after': 1786000000,
        }),
        reason: 'descriptor-lifetime-malformed',
      ),
      _Row(
        'not_after before iat is lifetime-malformed',
        signed: payload(overrides: <String, dynamic>{
          'iat': 1786000000,
          'not_after': 1785999999,
        }),
        reason: 'descriptor-lifetime-malformed',
      ),
      _Row(
        'string not_after is lifetime-malformed, not parsed',
        signed: payload(overrides: <String, dynamic>{
          'not_after': '1786086400',
        }),
        reason: 'descriptor-lifetime-malformed',
      ),
      _Row(
        'hostname endpoint is refused (would DNS-leak on the censored path)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': 'gateway.example:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'port zero is not an endpoint',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '203.0.113.7:0',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'loopback inner router is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '127.0.0.1',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'leading-zero inner router is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '10.10.0.01',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'present but malformed inner_resolver_v4 is named, not ignored',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '8.8.8.8:53',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'loopback inner_resolver_v4 is named',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '127.0.0.1',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'empty static_pub is missing-fields',
        signed: payload(overrides: <String, dynamic>{'static_pub': ''}),
        reason: 'descriptor-missing-fields',
      ),
      _Row(
        'static_pub of 31 bytes is refused, not passed to the engine',
        signed: payload(overrides: <String, dynamic>{
          'static_pub': base64.encode(List<int>.filled(31, 0x53)),
        }),
        reason: 'descriptor-static-pub-wrong-length',
      ),
      _Row(
        'static_pub of 33 bytes is refused',
        signed: payload(overrides: <String, dynamic>{
          'static_pub': base64.encode(List<int>.filled(33, 0x53)),
        }),
        reason: 'descriptor-static-pub-wrong-length',
      ),
      _Row(
        'static_pub that is not base64 is refused',
        signed: payload(overrides: <String, dynamic>{
          'static_pub': 'not-base64!!',
        }),
        reason: 'descriptor-static-pub-wrong-length',
      ),
      _Row(
        'gateway_id that is not UTF-8 text is refused',
        signed: payload(overrides: <String, dynamic>{
          'gateway_id': base64.encode(const <int>[0xff, 0xfe]),
        }),
        reason: 'descriptor-gateway-id-not-text',
      ),
      _Row(
        'gateway_id with a trailing space is refused (hub trap 3)',
        signed: payload(overrides: <String, dynamic>{
          'gateway_id': base64.encode(utf8.encode('winsgw01 ')),
        }),
        reason: 'descriptor-gateway-id-has-edge-whitespace',
      ),
      _Row(
        'gateway_id with a leading space is refused',
        signed: payload(overrides: <String, dynamic>{
          'gateway_id': base64.encode(utf8.encode(' winsgw01')),
        }),
        reason: 'descriptor-gateway-id-has-edge-whitespace',
      ),
      _Row(
        'a well-formed signed descriptor is accepted',
        signed: payload(),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'inner_resolver_v4 equal to inner_router_v4 is accepted',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '10.10.0.1',
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'unknown extra field is refused by the closed v3 schema',
        signed: payload(overrides: <String, dynamic>{
          'dns': '8.8.8.8',
          'mlkem_public_key': 'AAAA',
        }),
        reason: 'descriptor-unknown-fields',
      ),
      _Row(
        'winn3descriptor alias is accepted the same as winn3_descriptor',
        aliasKey: 'winn3descriptor',
        signed: payload(),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'payload as a Map is envelope-incomplete, not toString-coerced',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope,
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'sig as a number is envelope-incomplete, not toString-coerced',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope['payload'],
            'sig': 1,
          },
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'whitespace-only payload is envelope-incomplete',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': '   ',
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'empty JSON object payload is unknown-key-slot, not a throw',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('{}')),
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-unknown-key-slot',
      ),
      _Row(
        'JSON comments are not-utf8-json, not silently stripped',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('{"kid":"g1"/*x*/}')),
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-not-utf8-json',
      ),
      _Row(
        'trailing comma is not-utf8-json, not silently accepted',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('{"kid":"g1",}')),
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-not-utf8-json',
      ),
      _Row(
        'missing v is unsupported-format-version, not a default',
        signed: payload(overrides: <String, dynamic>{'v': null}),
        reason: 'descriptor-unsupported-format-version',
      ),
      _Row(
        'not_after as a JSON double is lifetime-malformed, not truncated',
        signed: payload(overrides: <String, dynamic>{
          'not_after': 1786086400.5,
        }),
        reason: 'descriptor-lifetime-malformed',
      ),
      _Row(
        'expired descriptor is named, not partially read',
        signed: payload(overrides: <String, dynamic>{
          'iat': 1785996450,
          'not_after': 1786000050,
        }),
        reason: 'descriptor-expired',
      ),
      _Row(
        'port 65536 is not an endpoint',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '203.0.113.7:65536',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'leading-zero IPv4 endpoint is refused (hub ipaddress rejects it)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '203.0.113.007:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'unspecified IPv4 endpoint is refused',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '0.0.0.0:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'multicast IPv4 endpoint is refused',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '224.0.0.1:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'unbracketed IPv6 endpoint is refused',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '2001:db8::1:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'inner_resolver_v4 with leading zeros is named',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '10.10.0.053',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'admission_secret that is not base64 is named at verify, not later',
        signed: payload(overrides: <String, dynamic>{
          'admission_secret': 'not-base64!!',
        }),
        reason: 'descriptor-admission-secret-not-base64',
      ),
      _Row(
        'admission_secret with a trailing space is refused (hub trap)',
        signed: payload(overrides: <String, dynamic>{
          'admission_secret': base64.encode(utf8.encode('${'ab' * 32} ')),
        }),
        reason: 'descriptor-admission-secret-has-edge-whitespace',
      ),
      _Row(
        'admission_secret with a leading tab is refused',
        signed: payload(overrides: <String, dynamic>{
          'admission_secret': base64.encode(utf8.encode('\t${'ab' * 32}')),
        }),
        reason: 'descriptor-admission-secret-has-edge-whitespace',
      ),
      _Row(
        'loopback IPv4 endpoint is accepted (hub documents stealth-chain)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '127.0.0.1:51820',
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'bracketed IPv6 endpoint is accepted',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[2001:db8::1]:51820',
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'port 65535 is accepted',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '203.0.113.7:65535',
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'gateway_id of 255 UTF-8 bytes is accepted (hub max)',
        signed: payload(overrides: <String, dynamic>{
          'gateway_id': base64.encode(utf8.encode('w' * 255)),
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'kid G1 is folded to g1 and verifies (slot select is case-insensitive)',
        signed: payload(overrides: <String, dynamic>{'kid': 'G1'}),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'inner_resolver_v4 that is only whitespace is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '   ',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'alg none is refused to match the hub algorithm contract',
        signed: payload(overrides: <String, dynamic>{'alg': 'none'}),
        reason: 'descriptor-unsupported-algorithm',
      ),
      _Row(
        'empty node is refused to match the hub node contract',
        signed: payload(overrides: <String, dynamic>{'node': ''}),
        reason: 'descriptor-missing-node',
      ),
      _Row(
        'tag_size above the hub ceiling is refused',
        signed: payload(overrides: <String, dynamic>{'tag_size': 999}),
        reason: 'descriptor-tag-size-out-of-range',
      ),
      _Row(
        'supported but nondefault tag_size is refused until hosts carry it',
        signed: payload(overrides: <String, dynamic>{'tag_size': 16}),
        reason: 'descriptor-wire-profile-not-implemented',
      ),
      _Row(
        'supported but nondefault padding is refused until hosts carry it',
        signed: payload(overrides: <String, dynamic>{'padding': 'mimic'}),
        reason: 'descriptor-wire-profile-not-implemented',
      ),
      _Row(
        'valid nondefault bucket window is refused until hosts carry it',
        signed: payload(overrides: <String, dynamic>{'bucket_window_s': 20}),
        reason: 'descriptor-wire-profile-not-implemented',
      ),
      _Row(
        'valid nondefault max skew is refused until hosts carry it',
        signed: payload(overrides: <String, dynamic>{'max_skew_s': 120}),
        reason: 'descriptor-wire-profile-not-implemented',
      ),
      _Row(
        'TTL longer than the hub 30-day max is refused',
        signed: payload(overrides: <String, dynamic>{
          'iat': 1786000000,
          'not_after': 1786000000 + 31 * 24 * 3600,
        }),
        reason: 'descriptor-ttl-too-long',
      ),
      _Row(
        'TTL shorter than the hub one-hour minimum is refused',
        signed: payload(overrides: <String, dynamic>{
          'iat': 1786000000,
          'not_after': 1786000000 + 3599,
        }),
        reason: 'descriptor-ttl-too-short',
      ),
      _Row(
        'a descriptor whose lifetime has not started is refused',
        signed: payload(overrides: <String, dynamic>{
          'iat': 1786000200,
          'not_after': 1786000200 + 3600,
        }),
        reason: 'descriptor-not-yet-valid',
      ),
      _Row(
        'leading + on the port is refused (hub isdigit; Go ParseAddrPort)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '203.0.113.7:+51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'invalid IPv6 1:::2 is refused, not accepted by the old group scanner',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[1:::2]:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'IPv4-mapped unspecified is refused, not a bypass of 0.0.0.0',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[::ffff:0.0.0.0]:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'IPv4-mapped multicast is refused, not a bypass of 224.0.0.1',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[::ffff:224.0.0.1]:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'IPv6 zone id is refused (local interface, not a gateway)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[fe80::1%lo0]:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'IPv4-mapped unicast is accepted (valid address, not a bypass)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[::ffff:203.0.113.7]:51820',
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'unspecified inner router is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '0.0.0.0',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'broadcast inner router is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '255.255.255.255',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'IPv6 inner router is refused (inner fields are dotted-quad only)',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': 'fd00::1',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'inner router with a port is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '10.10.0.1:51820',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'empty gateway_id is missing-fields',
        signed: payload(overrides: <String, dynamic>{'gateway_id': ''}),
        reason: 'descriptor-missing-fields',
      ),
      _Row(
        'empty admission_secret is missing-fields',
        signed: payload(overrides: <String, dynamic>{'admission_secret': ''}),
        reason: 'descriptor-missing-fields',
      ),
      _Row(
        'kid as a JSON number is unknown-key-slot, not toString-coerced',
        signed: payload(overrides: <String, dynamic>{'kid': 1}),
        reason: 'descriptor-unknown-key-slot',
      ),
      _Row(
        'kid g2 with only g1 in the ring is signature-invalid, not try-all-keys',
        signed: payload(overrides: <String, dynamic>{'kid': 'g2'}),
        reason: 'descriptor-signature-invalid',
      ),
      _Row(
        '64-byte zero signature on a real payload is signature-invalid',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope['payload'],
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-signature-invalid',
      ),
      _Row(
        'missing iat is refused by the closed schema',
        signed: () {
          final body = payload();
          body.remove('iat');
          return body;
        }(),
        reason: 'descriptor-missing-fields',
      ),
      _Row(
        'bool format version is unsupported, not truncated to 1',
        signed: payload(overrides: <String, dynamic>{'v': true}),
        reason: 'descriptor-unsupported-format-version',
      ),
      _Row(
        'not_after equal to injected now is expired (>= bound)',
        signed: payload(overrides: <String, dynamic>{
          'iat': 1785996500,
          'not_after': 1786000100,
        }),
        reason: 'descriptor-expired',
      ),
      _Row(
        'not_after one second after injected now is accepted',
        signed: payload(overrides: <String, dynamic>{
          'iat': 1785996501,
          'not_after': 1786000101,
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'envelope payload string over the b64-char ceiling is too-large before decode',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': 'A' * (kWinn3MaxDescriptorPayloadB64Chars + 1),
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-payload-too-large',
      ),
      _Row(
        'envelope sig string over the b64-char ceiling is signature-invalid before decode',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope['payload'],
            'sig': 'A' * (kWinn3MaxDescriptorSignatureB64Chars + 1),
          },
        },
        reason: 'descriptor-signature-invalid',
      ),
      _Row(
        'non-string envelope keys do not throw (DoS)',
        config: <String, dynamic>{
          'winn3_descriptor': <dynamic, dynamic>{
            1: 'x',
            'payload': goodEnvelope['payload'],
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'no-descriptor-served',
      ),
      _Row(
        'JSON integer beyond 64 bits is coerced to a double by dart:convert, then the zero signature refuses; no throw',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode(
                '{"kid":"g1","v":999999999999999999999999999999}')),
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-signature-invalid',
      ),
      _Row(
        'UTF-8 BOM before the payload object is tolerated by dart:convert, then the zero signature refuses; no throw',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(
                <int>[0xef, 0xbb, 0xbf, ...utf8.encode('{"kid":"g1"}')]),
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-signature-invalid',
      ),
      _Row(
        'base64url alphabet is envelope-not-base64, not silently decoded',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': '-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_',
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-envelope-not-base64',
      ),
      _Row(
        'unspecified inner_resolver_v4 is named (same rule as inner_router)',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '0.0.0.0',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'multicast inner_resolver_v4 is named',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '224.0.0.1',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'broadcast inner_resolver_v4 is named',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '255.255.255.255',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'IPv6 inner_resolver_v4 is named (inner fields are dotted-quad only)',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': 'fd00::53',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'Class-E 240.0.0.1 inner_resolver_v4 is named (client >=224, hub shape would accept)',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '240.0.0.1',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'resolver differing from the gateway bind is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '8.8.8.8',
        }),
        reason: 'descriptor-resolver-does-not-match-gateway-bind',
      ),
      _Row(
        'AWG-pool resolver differing from the gateway bind is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '10.8.0.1',
        }),
        reason: 'descriptor-resolver-does-not-match-gateway-bind',
      ),
      _Row(
        'inner_resolver_v4 as a JSON array is named, not toString-coerced into a dotted quad',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': <dynamic>['10.10.0.53'],
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'inner_resolver_v4 as a JSON object is named, not toString-coerced',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': <String, dynamic>{'addr': '10.10.0.53'},
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'inner_resolver_v4 as a JSON number is named, not toString-coerced',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': 168430133,
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'inner_router_v4 as a JSON array is named, not toString-coerced',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': <dynamic>['10.10.0.1'],
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'endpoint as a JSON object is named, not toString-coerced into host:port',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': <String, dynamic>{'host': '203.0.113.7', 'port': 51820},
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'static_pub as a JSON array of 32 bytes is wrong-length, not joined',
        signed: payload(overrides: <String, dynamic>{
          'static_pub': List<int>.filled(32, 0x53),
        }),
        reason: 'descriptor-static-pub-wrong-length',
      ),
      _Row(
        'newline in endpoint is refused at verify (would forge an INI line)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '203.0.113.7:51820\ncarrier = direct-awg',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'CR at end of gateway_id operator text is edge-whitespace (hub trap 3)',
        signed: payload(overrides: <String, dynamic>{
          'gateway_id': base64.encode(utf8.encode('winsgw01\r')),
        }),
        reason: 'descriptor-gateway-id-has-edge-whitespace',
      ),
      _Row(
        'LF at start of gateway_id operator text is edge-whitespace',
        signed: payload(overrides: <String, dynamic>{
          'gateway_id': base64.encode(utf8.encode('\nwinsgw01')),
        }),
        reason: 'descriptor-gateway-id-has-edge-whitespace',
      ),
      _Row(
        'empty winn3_descriptor object shadows a valid winn3descriptor alias',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{},
          'winn3descriptor': goodEnvelope,
        },
        reason: 'no-descriptor-served',
      ),
      _Row(
        'null winn3_descriptor falls through to the winn3descriptor alias',
        config: <String, dynamic>{
          'winn3_descriptor': null,
          'winn3descriptor': goodEnvelope,
        },
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'envelope extra fields besides payload/sig are ignored',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope['payload'],
            'sig': goodEnvelope['sig'],
            'kid': 'g4',
            'alg': 'none',
          },
        },
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'Class-E 240.0.0.1 endpoint is accepted (not multicast; hub ipaddress agrees)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '240.0.0.1:51820',
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'plus-prefixed inner-router octet is refused (hub ipaddress; Dart tryParse would accept)',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '10.10.0.+1',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'plus-prefixed first inner-router octet is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '+10.10.0.1',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'plus-prefixed inner-resolver octet is refused',
        signed: payload(overrides: <String, dynamic>{
          'inner_resolver_v4': '10.10.0.+53',
        }),
        reason: 'descriptor-inner-resolver-not-ipv4',
      ),
      _Row(
        'empty inner_router_v4 is named, not defaulted',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'missing inner_router_v4 is named, not defaulted',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': null,
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'empty endpoint is named, not defaulted',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'empty kid is unknown-key-slot, not a default g1',
        signed: payload(overrides: <String, dynamic>{'kid': ''}),
        reason: 'descriptor-unknown-key-slot',
      ),
      _Row(
        'kid with surrounding spaces trims to g1 and verifies',
        signed: payload(overrides: <String, dynamic>{'kid': ' g1 '}),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'public 8.8.8.8 inner_router_v4 is accepted at verify (shape-only; hub in-pool would refuse)',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '8.8.8.8',
          'inner_resolver_v4': '8.8.8.8',
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'Class-E 240.0.0.1 inner_router_v4 is named (client >=224)',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': '240.0.0.1',
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'IPv6 unspecified endpoint is refused',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[::]:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'IPv6 multicast endpoint is refused',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[ff02::1]:51820',
        }),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'link-local IPv6 without a zone verifies (shape-only; not a public gateway)',
        signed: payload(overrides: <String, dynamic>{
          'endpoint': '[fe80::1]:51820',
        }),
        verified: true,
        reason: 'winn3-descriptor-verified',
      ),
      _Row(
        'endpoint as a JSON number is named, not toString-coerced into a port',
        signed: payload(overrides: <String, dynamic>{'endpoint': 51820}),
        reason: 'descriptor-endpoint-not-ip-literal',
      ),
      _Row(
        'inner_router_v4 as a JSON object is named, not toString-coerced',
        signed: payload(overrides: <String, dynamic>{
          'inner_router_v4': <String, dynamic>{'addr': '10.10.0.1'},
        }),
        reason: 'descriptor-inner-router-not-ipv4',
      ),
      _Row(
        'gateway_id as a JSON array is not-text, not joined',
        signed: payload(overrides: <String, dynamic>{
          'gateway_id': <dynamic>['winsgw01'],
        }),
        reason: 'descriptor-gateway-id-not-text',
      ),
      _Row(
        'admission_secret as a JSON number is not-base64, not toString-coerced',
        signed: payload(overrides: <String, dynamic>{
          'admission_secret': 1,
        }),
        reason: 'descriptor-admission-secret-not-base64',
      ),
      _Row(
        'not_after as a JSON bool is lifetime-malformed, not truncated to 1',
        signed: payload(overrides: <String, dynamic>{'not_after': true}),
        reason: 'descriptor-lifetime-malformed',
      ),
      _Row(
        'iat as a JSON string is lifetime-malformed, not parsed',
        signed: payload(overrides: <String, dynamic>{'iat': '1786000000'}),
        reason: 'descriptor-lifetime-malformed',
      ),
      _Row(
        'negative not_after is lifetime-malformed, not wrapped',
        signed: payload(overrides: <String, dynamic>{'not_after': -1}),
        reason: 'descriptor-lifetime-malformed',
      ),
      _Row(
        'payload as a JSON number is envelope-incomplete, not toString-coerced',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': 1,
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'sig as a Map is envelope-incomplete, not toString-coerced',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope['payload'],
            'sig': goodEnvelope,
          },
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'empty payload string is envelope-incomplete',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': '',
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'empty sig string is envelope-incomplete',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': goodEnvelope['payload'],
            'sig': '',
          },
        },
        reason: 'descriptor-envelope-incomplete',
      ),
      _Row(
        'JSON NaN is not-utf8-json, not a throw',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('{"kid":"g1","v":NaN}')),
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-not-utf8-json',
      ),
      _Row(
        'JSON Infinity is not-utf8-json, not a throw',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload':
                base64.encode(utf8.encode('{"kid":"g1","v":Infinity}')),
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-not-utf8-json',
      ),
      _Row(
        'unclosed JSON string is not-utf8-json, not a hang',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': base64.encode(utf8.encode('{"kid":"g1')),
            'sig': base64.encode(List<int>.filled(64, 0x00)),
          },
        },
        reason: 'descriptor-not-utf8-json',
      ),
      _Row(
        'MIME base64 with an interior newline is envelope-not-base64, not decoded',
        config: <String, dynamic>{
          'winn3_descriptor': <String, dynamic>{
            'payload': '${goodEnvelope['payload']}\nAA==',
            'sig': goodEnvelope['sig'],
          },
        },
        reason: 'descriptor-envelope-not-base64',
      ),
      _Row(
        'node as a JSON array is refused instead of string-coerced',
        signed: payload(overrides: <String, dynamic>{
          'node': <dynamic>['lab-alpha'],
        }),
        reason: 'descriptor-missing-node',
      ),
    ];

    expect(kWinn3MaxDescriptorBytes, 4096,
        reason: 'must equal WINN3_MAX_DESCRIPTOR_BYTES on the hub');
    expect(kWinn3DescriptorFormatVersion, 3,
        reason: 'must equal WINN3_DESCRIPTOR_FORMAT_VERSION on the hub');
    expect(kWinn3MaxDescriptorJSONDepth, 8,
        reason: 'must stay at the Go host-profile ceiling; raising it '
            're-opens the nesting-bomb DoS');
    expect(kWinn3MaxDescriptorPayloadB64Chars, 8192,
        reason: 'pre-decode envelope bound; raising it re-opens unbounded '
            'base64 allocation');
    expect(kWinn3MaxDescriptorSignatureB64Chars, 256,
        reason: 'pre-decode sig bound; a 64-byte sig is 88 characters');

    for (final row in rows) {
      Map<String, dynamic> config = row.config ?? <String, dynamic>{};
      if (row.signed != null) {
        final envelope = await signedEnvelope(row.signed!);
        config = <String, dynamic>{
          row.aliasKey: envelope,
        };
      }
      final result = await checkOf(config, keys: row.keys);
      expect(
        result.verified,
        row.verified,
        reason: '${row.name}: verified=${result.verified} reason=${result.reason}',
      );
      expect(
        result.reason,
        row.reason,
        reason: row.name,
      );
      if (row.verified) {
        expect(result.descriptor, isNotNull, reason: row.name);
      } else {
        expect(result.descriptor, isNull, reason: row.name);
      }
    }
  });

  test('the hub-bound inner_resolver_v4 is carried into the [winn] section',
      () async {
    final config = <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
      'node_slug': 'lab-alpha',
      'server_endpoint': '203.0.113.7:51820',
      'winn3_descriptor': await signedEnvelope(payload(overrides: <String, dynamic>{
        'inner_resolver_v4': '10.10.0.1',
      })),
      'winn3_inner_v4': '10.10.4.9',
      'winn3_static_private': base64.encode(List<int>.filled(32, 0x11)),
    };
    final verified = await checkOf(config);
    expect(verified.verified, isTrue, reason: verified.reason);
    expect(verified.descriptor!.innerResolverV4, '10.10.0.1');

    final decision = resolveWinnProtocolStartForServedConfig(
      config: config,
      winn3Descriptor: verified,
    );
    expect(decision.supported, isTrue,
        reason: '${decision.reason.code}: ${decision.message}');
    final pairs = <String, String>{};
    for (final line in decision.iniSection.split('\n')) {
      final idx = line.indexOf('=');
      if (idx < 0) continue;
      pairs[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
    }
    expect(pairs['inner_resolver_v4'], '10.10.0.1');
    expect(pairs.containsKey('mlkem_public_key'), isFalse);
  });

  test('absent inner_resolver_v4 is refused by the closed v3 schema',
      () async {
    final config = <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
      'server_endpoint': '203.0.113.7:51820',
      'winn3_descriptor': await signedEnvelope(
        payload()..remove('inner_resolver_v4'),
      ),
      'winn3_inner_v4': '10.10.4.9',
      'winn3_static_private': base64.encode(List<int>.filled(32, 0x11)),
    };
    final verified = await checkOf(config);
    expect(verified.verified, isFalse);
    expect(verified.reason, 'descriptor-missing-fields');
  });

  test('deeply nested JSON is json-too-deep, not a throw and not parsed',
      () async {
    var nested = '"x"';
    for (var i = 0; i < 40; i++) {
      nested = '{"a":$nested}';
    }
    final bytes = utf8.encode(nested);
    expect(bytes.length <= kWinn3MaxDescriptorBytes, isTrue,
        reason: 'the nest must sit under the ceiling so this row tests '
            'the depth guard, not the size guard');
    expect(winn3DescriptorJSONNestingDepth(bytes), 40);
    final result = await checkOf(<String, dynamic>{
      'winn3_descriptor': <String, dynamic>{
        'payload': base64.encode(bytes),
        'sig': base64.encode(List<int>.filled(64, 0x00)),
      },
    });
    expect(result.verified, isFalse);
    expect(result.reason, 'descriptor-json-too-deep',
        reason: 'deleting the depth guard turns this red (old behaviour was '
            'unknown-key-slot after json.decode); got ${result.reason}');
  });

  test('a compact array nest under the byte ceiling is json-too-deep, not a throw',
      () async {
    // `[` is one byte per level, so 4096 levels sit exactly on the ceiling.
    // dart:convert recurses; without the depth guard this is a stack overflow.
    final bytes = List<int>.filled(kWinn3MaxDescriptorBytes, 0x5b); // '['
    expect(bytes.length, kWinn3MaxDescriptorBytes);
    expect(winn3DescriptorJSONNestingDepth(bytes), kWinn3MaxDescriptorBytes);
    final result = await checkOf(<String, dynamic>{
      'winn3_descriptor': <String, dynamic>{
        'payload': base64.encode(bytes),
        'sig': base64.encode(List<int>.filled(64, 0x00)),
      },
    });
    expect(result.verified, isFalse);
    expect(result.reason, 'descriptor-json-too-deep',
        reason: 'got ${result.reason}');
  });

  test('JSON nesting depth scanner: braces in strings are not nesting', () {
    expect(winn3DescriptorJSONNestingDepth(utf8.encode('{}')), 1);
    expect(winn3DescriptorJSONNestingDepth(utf8.encode('[]')), 1);
    expect(winn3DescriptorJSONNestingDepth(utf8.encode('"x"')), 0);
    expect(
      winn3DescriptorJSONNestingDepth(utf8.encode('{"a":"{{[["}')),
      1,
      reason: 'braces and brackets inside a string must not count',
    );
    expect(
      winn3DescriptorJSONNestingDepth(utf8.encode('{"a":"\\"{"}')),
      1,
      reason: 'an escaped quote must not end the string early',
    );
    var nested = '"x"';
    for (var i = 0; i < kWinn3MaxDescriptorJSONDepth; i++) {
      nested = '{"a":$nested}';
    }
    expect(
      winn3DescriptorJSONNestingDepth(utf8.encode(nested)),
      kWinn3MaxDescriptorJSONDepth,
    );
    nested = '{"a":$nested}';
    expect(
      winn3DescriptorJSONNestingDepth(utf8.encode(nested)),
      kWinn3MaxDescriptorJSONDepth + 1,
    );
    expect(
      winn3DescriptorJSONNestingDepth(utf8.encode('[{[{[{[{')),
      8,
      reason: 'mixed array/object openers count as the same nesting',
    );
    expect(
      winn3DescriptorJSONNestingDepth(utf8.encode('[{[{[{[{[')),
      9,
    );
  });

  test('nesting at the depth ceiling still parses (depth 8 is allowed)',
      () async {
    // A signed flat object is depth 1. This row pins that the ceiling is
    // inclusive: depth == 8 is not too-deep. The payload has no usable kid
    // at the root, so the named refusal after a successful decode is
    // unknown-key-slot.
    var nested = '{"kid":"g4"}';
    for (var i = 0; i < kWinn3MaxDescriptorJSONDepth - 1; i++) {
      nested = '{"a":$nested}';
    }
    expect(winn3DescriptorJSONNestingDepth(utf8.encode(nested)),
        kWinn3MaxDescriptorJSONDepth);
    final result = await checkOf(<String, dynamic>{
      'winn3_descriptor': <String, dynamic>{
        'payload': base64.encode(utf8.encode(nested)),
        'sig': base64.encode(List<int>.filled(64, 0x00)),
      },
    });
    expect(result.verified, isFalse);
    expect(result.reason, 'descriptor-unknown-key-slot',
        reason: 'depth == 8 must still reach json.decode; got ${result.reason}');
  });

  test('verifyWinn3Descriptor never throws on hostile envelope shapes',
      () async {
    final shapes = <Object?>[
      null,
      7,
      true,
      <dynamic>[],
      <String, dynamic>{'payload': 1, 'sig': 2},
      <dynamic, dynamic>{1: 2, 3: 4},
      <String, dynamic>{
        'payload': 'A' * 100,
        'sig': 'B' * 100,
      },
    ];
    for (final shape in shapes) {
      Winn3DescriptorCheck? result;
      Object? thrown;
      try {
        result = await checkOf(<String, dynamic>{'winn3_descriptor': shape});
      } catch (e) {
        thrown = e;
      }
      expect(thrown, isNull, reason: 'threw on $shape: $thrown');
      expect(result, isNotNull, reason: '$shape');
      expect(result!.verified, isFalse, reason: '$shape');
      expect(result.descriptor, isNull, reason: '$shape');
    }
  });

  test('duplicate JSON kid keys: last wins for slot select, bytes are signed',
      () async {
    // encoding/json and dart:convert both last-win. The signature is over
    // the raw bytes, so this is authentic; the row pins that we do not
    // try the first kid and then the last.
    final body = payload();
    body['kid'] = 'g1';
    final encoded = json.encode(body);
    // Insert a first kid that would select a missing slot if we read it.
    final withDup = encoded.replaceFirst('"kid":"g1"', '"kid":"g4","kid":"g1"');
    expect(withDup.contains('"kid":"g4"'), isTrue);
    expect(withDup.contains('"kid":"g1"'), isTrue);
    final raw = utf8.encode(withDup);
    final message = <int>[
      ...utf8.encode(kWinn3DescriptorDomain),
      0x00,
      ...raw,
    ];
    final signature = await Ed25519().sign(message, keyPair: signingKey);
    final result = await checkOf(<String, dynamic>{
      'winn3_descriptor': <String, dynamic>{
        'payload': base64.encode(raw),
        'sig': base64.encode(signature.bytes),
      },
    });
    expect(result.verified, isTrue, reason: result.reason);
    expect(result.descriptor!.kid, 'g1');
  });

  test('bracketed IPv6 verifies but standalone start refuses INI brackets',
      () async {
    // Linux ParseLinuxWinn3Section treats a line that STARTS with '[' and
    // ENDS with ']' as a section header. `endpoint = [2001:db8::1]:51820`
    // starts with 'e', so the value is safe once newlines are banned.
    // `_isSafeIniValue` still rejects '[' / ']' in values, so a verified
    // IPv6 descriptor cannot emit a [winn] section. Pin both halves so a
    // later INI fix cannot silently drop the verify-side IPv6 accept, and
    // so the start-side refusal stays named rather than becoming a session
    // that starts and is ignored.
    final config = <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
      'node_slug': 'lab-alpha',
      'server_endpoint': '[2001:db8::1]:51820',
      'winn3_descriptor': await signedEnvelope(payload(overrides: <String, dynamic>{
        'endpoint': '[2001:db8::1]:51820',
      })),
      'winn3_inner_v4': '10.10.4.9',
      'winn3_static_private': base64.encode(List<int>.filled(32, 0x11)),
    };
    final verified = await checkOf(config);
    expect(verified.verified, isTrue, reason: verified.reason);
    expect(verified.descriptor!.endpoint, '[2001:db8::1]:51820');
    final decision = resolveWinnProtocolStartForServedConfig(
      config: config,
      winn3Descriptor: verified,
    );
    expect(decision.supported, isFalse,
        reason: 'INI writer currently rejects brackets in values; '
            'got supported=${decision.supported} reason=${decision.reason.code}');
    expect(decision.reason, WinnRefusalReason.winn3FieldMalformed);
  });

  test('gateway_id of 256 UTF-8 bytes is too long', () async {
    final tooLong = 'w' * 256;
    final result = await checkOf(<String, dynamic>{
      'winn3_descriptor': await signedEnvelope(payload(overrides: <String, dynamic>{
        'gateway_id': base64.encode(utf8.encode(tooLong)),
      })),
    });
    expect(result.verified, isFalse);
    expect(result.reason, 'descriptor-gateway-id-too-long');
  });

  test('duplicate JSON v keys: last wins, so a trailing v=2 is refused',
      () async {
    final body = payload();
    final encoded = json.encode(body);
    expect(encoded.contains('"v":3'), isTrue,
        reason: 'the fixture must pin format version 3 as a JSON int');
    final withDup = encoded.replaceFirst('"v":3', '"v":3,"v":2');
    expect(withDup.contains('"v":2'), isTrue);
    final raw = utf8.encode(withDup);
    final message = <int>[
      ...utf8.encode(kWinn3DescriptorDomain),
      0x00,
      ...raw,
    ];
    final signature = await Ed25519().sign(message, keyPair: signingKey);
    final result = await checkOf(<String, dynamic>{
      'winn3_descriptor': <String, dynamic>{
        'payload': base64.encode(raw),
        'sig': base64.encode(signature.bytes),
      },
    });
    expect(result.verified, isFalse, reason: result.reason);
    expect(result.reason, 'descriptor-unsupported-format-version');
  });

  test('raw JSON v:3.0 in the signed bytes is unsupported (dart:convert keeps the dot as double)',
      () async {
    final body = payload();
    final encoded = json.encode(body).replaceFirst('"v":3', '"v":3.0');
    expect(encoded.contains('"v":3.0'), isTrue);
    final raw = utf8.encode(encoded);
    final message = <int>[
      ...utf8.encode(kWinn3DescriptorDomain),
      0x00,
      ...raw,
    ];
    final signature = await Ed25519().sign(message, keyPair: signingKey);
    final result = await checkOf(<String, dynamic>{
      'winn3_descriptor': <String, dynamic>{
        'payload': base64.encode(raw),
        'sig': base64.encode(signature.bytes),
      },
    });
    expect(result.verified, isFalse, reason: result.reason);
    expect(result.reason, 'descriptor-unsupported-format-version',
        reason: 'a hub that wrote 3.0 would currently fail closed on this client');
  });

  test('a resolver differing from the gateway bind never reaches [winn]',
      () async {
    final config = <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
      'node_slug': 'lab-alpha',
      'server_endpoint': '203.0.113.7:51820',
      'winn3_descriptor': await signedEnvelope(payload(overrides: <String, dynamic>{
        'inner_resolver_v4': '8.8.8.8',
      })),
      'winn3_inner_v4': '10.10.4.9',
      'winn3_static_private': base64.encode(List<int>.filled(32, 0x11)),
    };
    final verified = await checkOf(config);
    expect(verified.verified, isFalse);
    expect(
      verified.reason,
      'descriptor-resolver-does-not-match-gateway-bind',
    );
  });

  test('isWinnInnerIpv4 refuses a plus-prefixed octet that Dart tryParse would accept',
      () {
    expect(isWinnInnerIpv4('10.10.0.1'), isTrue);
    expect(isWinnInnerIpv4('10.10.0.+1'), isFalse,
        reason: 'int.tryParse("+1") is 1; the hub ipaddress rejects it');
    expect(isWinnInnerIpv4('+10.10.0.1'), isFalse);
    expect(isWinnInnerIpv4('10.10.+0.1'), isFalse);
    expect(isWinnInnerIpv4('10.10.0.1'), isTrue,
        reason: 'the plus-octet guard must not refuse a well-formed inner address');
  });
}

class _Row {
  const _Row(
    this.name, {
    this.config,
    this.signed,
    this.keys,
    this.aliasKey = 'winn3_descriptor',
    this.verified = false,
    required this.reason,
  });

  final String name;
  final Map<String, dynamic>? config;
  final Map<String, dynamic>? signed;
  final Winn3DescriptorKeyRing? keys;
  final String aliasKey;
  final bool verified;
  final String reason;
}
