import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// End-to-end attestation of the shipping winn/3 descriptor ring.
///
/// Release producers inject four `--dart-define` values (G1/G2/G3 public keys
/// plus the WIRE-FORM identity). This file compiles the same four names via
/// `const String.fromEnvironment`, with `defaultValue` equal to what those
/// producers inject, so a plain `flutter test` of this file attests the ring
/// without a define flag. If a caller *does* pass `--dart-define`, those
/// values win ([String.fromEnvironment](https://api.dart.dev/dart-core/String/String.fromEnvironment.html),
/// [compilation environment declarations](https://dart.dev/libraries/core/environment-declarations))
/// and this file still demands they be the wire-form ring.
///
/// Canonical identity (SPEC.md:31, `Winn3DescriptorKeyRing.identitySha256`):
/// one `slot=<lowercase hex of 32 raw bytes>\n` line per populated slot, in
/// fixed `g1, g2, g3` order, UTF-8, including the trailing newline. SHA-256
/// of those bytes, lowercase hex ([package:crypto `sha256`](https://pub.dev/documentation/crypto/latest/crypto/sha256-constant.html),
/// [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234),
/// [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)).
///
/// WIRE-FORM is the only legal `WINS_WINN3_DESCRIPTOR_RING_SHA256`.
/// MANIFEST-FORM (ceremony `ring_sha256`) must be rejected as that identity.
const String _compiledPubKeyG1 = String.fromEnvironment(
  'WINS_WINN3_DESCRIPTOR_PUBKEY_G1',
  defaultValue: 'L2mAYdYIXPCFuNoH5ntgBBubFSnnlzIAnXwKttpehaQ=',
);
const String _compiledPubKeyG2 = String.fromEnvironment(
  'WINS_WINN3_DESCRIPTOR_PUBKEY_G2',
  defaultValue: 'eVCAHWXqUM1+m5nlVy2JR+Q4/mkYGTxlk119aiQh89M=',
);
const String _compiledPubKeyG3 = String.fromEnvironment(
  'WINS_WINN3_DESCRIPTOR_PUBKEY_G3',
  defaultValue: '53JhsQBxKH5DG145LcaBunOX4lbt+J7Js0oPyJnj9Q0=',
);
const String _compiledRingSha256 = String.fromEnvironment(
  'WINS_WINN3_DESCRIPTOR_RING_SHA256',
  defaultValue: '52e91c72ca52d23059724e0a6c25c2f45bae574a85a84c884c5b7fd367cbf032',
);

const String _kWireFormIdentity =
    '52e91c72ca52d23059724e0a6c25c2f45bae574a85a84c884c5b7fd367cbf032';
const String _kManifestFormDigest =
    '29c66c18f5aef6eb064e065a5d7c3c98aa1548f758ac6d19b19a9d4a7863e7fb';

const Map<String, String> _compiledEncodedRing = <String, String>{
  'g1': _compiledPubKeyG1,
  'g2': _compiledPubKeyG2,
  'g3': _compiledPubKeyG3,
};

final _hex64 = RegExp(r'^[0-9a-f]{64}$');

String _hex32(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

/// Canonical attestation input: `g1=<hex>\ng2=<hex>\ng3=<hex>\n`.
String canonicalAttestationString(Map<String, String> encoded) {
  final canonical = StringBuffer();
  for (final slot in kWinn3DescriptorSlotIds) {
    final value = (encoded[slot] ?? '').trim();
    expect(value, isNotEmpty, reason: 'compiled $slot must be present');
    final raw = base64.decode(value);
    expect(raw, hasLength(kWinn3DescriptorPublicKeyBytes),
        reason: 'compiled $slot must be a 32-byte Ed25519 public key');
    canonical
      ..write(slot)
      ..write('=')
      ..write(_hex32(raw))
      ..write('\n');
  }
  return canonical.toString();
}

void main() {
  test('compiled ring defaults attest the WIRE-FORM identity', () {
    expect(_compiledPubKeyG1, 'L2mAYdYIXPCFuNoH5ntgBBubFSnnlzIAnXwKttpehaQ=');
    expect(_compiledPubKeyG2, 'eVCAHWXqUM1+m5nlVy2JR+Q4/mkYGTxlk119aiQh89M=');
    expect(_compiledPubKeyG3, '53JhsQBxKH5DG145LcaBunOX4lbt+J7Js0oPyJnj9Q0=');
    expect(_compiledRingSha256, _kWireFormIdentity);
    expect(_compiledRingSha256, isNot(_kManifestFormDigest));
    expect(_hex64.hasMatch(_compiledRingSha256), isTrue);

    final canonical = canonicalAttestationString(_compiledEncodedRing);
    expect(utf8.encode(canonical), hasLength(204));

    final independentIdentity =
        sha256.convert(utf8.encode(canonical)).toString();
    expect(independentIdentity, _kWireFormIdentity);
    expect(independentIdentity, _compiledRingSha256);

    final ring = Winn3DescriptorKeyRing.fromEncoded(_compiledEncodedRing);
    expect(ring.enforcing, isTrue);
    expect(ring.compiledSlotIds, kWinn3DescriptorSlotIds);
    expect(ring.identitySha256, independentIdentity);
    expect(ring.identitySha256, _kWireFormIdentity);
    expect(ring.attestsExpectedIdentity(_compiledRingSha256), isTrue);
    expect(ring.attestsExpectedIdentity(_kWireFormIdentity), isTrue);
  });

  test('MANIFEST-form digest is rejected as a wire-form identity', () {
    expect(_hex64.hasMatch(_kManifestFormDigest), isTrue,
        reason: 'rejection must be a wrong identity, not a malformed hex');
    expect(_kManifestFormDigest, isNot(_kWireFormIdentity));
    expect(_compiledRingSha256, isNot(_kManifestFormDigest));

    final ring = Winn3DescriptorKeyRing.fromEncoded(_compiledEncodedRing);
    expect(ring.enforcing, isTrue);
    expect(ring.identitySha256, _kWireFormIdentity);
    expect(ring.attestsExpectedIdentity(_kManifestFormDigest), isFalse);
    expect(ring.attestsExpectedIdentity(_kWireFormIdentity), isTrue);
  });

  test('every release producer injects exactly the ring this test attests', () {
    // The producers carry `NAME=value` as base64 blobs inside their define
    // lists. Asserting the blob of each attested pair appears exactly once
    // per producer binds the defaults above to the shipped ring: rotating a
    // slot in the build without updating this file turns this red.
    const producers = <String>[
      'windows/flutter/Winn3DescriptorRing.cmake',
      'linux/flutter/Winn3DescriptorRing.cmake',
      'ios/Flutter/Winn3DescriptorRing.xcconfig',
      'macos/Flutter/Winn3DescriptorRing.xcconfig',
      'android/app/build.gradle.kts',
    ];
    final pairs = <String, String>{
      'WINS_WINN3_DESCRIPTOR_PUBKEY_G1': _compiledPubKeyG1,
      'WINS_WINN3_DESCRIPTOR_PUBKEY_G2': _compiledPubKeyG2,
      'WINS_WINN3_DESCRIPTOR_PUBKEY_G3': _compiledPubKeyG3,
      'WINS_WINN3_DESCRIPTOR_RING_SHA256': _kWireFormIdentity,
    };
    for (final path in producers) {
      final source = File(path).readAsStringSync();
      for (final entry in pairs.entries) {
        final blob = base64Encode(utf8.encode('${entry.key}=${entry.value}'));
        expect(source.split(blob).length - 1, 1,
            reason: '$path must inject ${entry.key} exactly once as the '
                'attested value');
      }
      expect(
          source.contains(base64Encode(
              utf8.encode('WINS_WINN3_DESCRIPTOR_RING_SHA256=$_kManifestFormDigest'))),
          isFalse,
          reason: '$path must never inject the manifest-form digest');
    }
  });
}
