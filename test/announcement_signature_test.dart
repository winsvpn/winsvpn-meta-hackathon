import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/announcement_signature.dart';

// testSeed1/2/3 are fixture data for these tests only - deterministic,
// obviously-synthetic 32-byte seeds, never real credentials. Same convention
// as winn_protocol_experimental/internal/knock/keys_test.go. The matching
// public keys are derived at test time, so no key material of any kind is
// checked into the repository.
final List<int> testSeed1 = List<int>.filled(32, 0x01);
final List<int> testSeed2 = List<int>.filled(32, 0x02);
final List<int> testSeed3 = List<int>.filled(32, 0x03);

/// Builds the same payload bytes the offline signing tool
/// (tools/winn3_sign_announcement.py) does: compact, key-sorted JSON. The hub
/// holds no signer since the 2026-09-29 key-custody ruling; it only verifies.
List<int> _payloadBytes({
  required String keyId,
  required int seq,
  required int iat,
  required String text,
}) {
  // Keys emitted in sorted order to match Python's sort_keys=True.
  return utf8.encode(jsonEncode({
    'iat': iat,
    'kid': keyId,
    'seq': seq,
    'text': text,
  }));
}

/// Signs [payload] the way the offline tool does: over DOMAIN || 0x00 || payload.
Future<String> _sign(List<int> payload, List<int> seed) async {
  final keyPair = await Ed25519().newKeyPairFromSeed(seed);
  final signature = await Ed25519()
      .sign(announcementSigningBytes(payload), keyPair: keyPair);
  return base64.encode(signature.bytes);
}

Future<List<int>> _publicKey(List<int> seed) async {
  final keyPair = await Ed25519().newKeyPairFromSeed(seed);
  return (await keyPair.extractPublicKey()).bytes;
}

Map<String, dynamic> _response(String payloadB64, String sigB64,
    {String plaintext = 'plaintext that must be ignored'}) {
  return <String, dynamic>{
    'announcement': plaintext,
    'announcement_signed': {'payload': payloadB64, 'sig': sigB64},
  };
}

/// Extracts the body of a method starting at the first occurrence of
/// [signature] (same intent as the helper in announcement_delivery_test.dart:
/// walk the parameter list, then match braces).
String _functionBody(String source, String signature) {
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: 'could not find $signature');

  var cursor = start;
  var parenDepth = 0;
  var sawParen = false;
  while (cursor < source.length) {
    final ch = source[cursor];
    if (ch == '(') {
      parenDepth++;
      sawParen = true;
    } else if (ch == ')') {
      parenDepth--;
      if (sawParen && parenDepth == 0) break;
    }
    cursor++;
  }
  expect(sawParen && parenDepth == 0, isTrue,
      reason: 'unterminated parameter list for $signature');

  final bodyOpen = source.indexOf('{', cursor);
  expect(bodyOpen, greaterThan(cursor), reason: 'no body for $signature');

  var depth = 0;
  for (var i = bodyOpen; i < source.length; i++) {
    if (source[i] == '{') depth++;
    if (source[i] == '}') {
      depth--;
      if (depth == 0) return source.substring(start, i + 1);
    }
  }
  fail('unterminated function for signature: $signature');
}

void main() {
  group('signature verification', () {
    test('a correctly signed announcement is accepted and its text used',
        () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 4, iat: 1786000000, text: 'Yangon node degraded.');
      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed1)),
        minimumSequence: 0,
      );

      expect(result.accepted, isTrue);
      expect(result.envelope!.text, equals('Yangon node degraded.'));
      expect(result.envelope!.sequence, equals(4));
      expect(result.envelope!.keyId, equals('a1'));
      expect(result.envelope!.issuedAt.toUtc().year, equals(2026));
    });

    test(
        'the verified payload text is used, never the sibling plaintext field, '
        'so tampering with the plaintext changes nothing', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 1, iat: 1786000000, text: 'the authentic text');
      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed1),
            plaintext: 'ATTACKER TEXT: delete the app immediately'),
        minimumSequence: 0,
      );

      expect(result.accepted, isTrue);
      expect(result.envelope!.text, equals('the authentic text'));
    });

    test('Burmese text survives the byte-exact round trip', () async {
      const burmese = 'ဆာဗာပြproblemနာရှိပါသည်။';
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 2, iat: 1786000000, text: burmese);
      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed1)),
        minimumSequence: 0,
      );

      expect(result.accepted, isTrue);
      expect(result.envelope!.text, equals(burmese));
    });
  });

  group('a bad signature is refused', () {
    test('a signature from the wrong key is rejected', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 1, iat: 1786000000, text: 'forged');
      // Signed with seed2 but claiming to be key a1.
      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed2)),
        minimumSequence: 0,
      );

      expect(result.accepted, isFalse);
      expect(result.rejection, equals(AnnouncementRejection.badSignature));
    });

    test('flipping one byte of the payload invalidates the signature',
        () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 1, iat: 1786000000, text: 'all systems normal');
      final sig = await _sign(payload, testSeed1);
      final tampered = List<int>.from(payload);
      tampered[tampered.length - 3] ^= 0x01;

      final result = await verifier.verify(
        _response(base64.encode(tampered), sig),
        minimumSequence: 0,
      );

      expect(result.rejection, equals(AnnouncementRejection.badSignature));
    });

    test(
        'a signature made WITHOUT the domain separator is rejected, so a '
        'signature over another project object cannot be reinterpreted here',
        () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 1, iat: 1786000000, text: 'cross-context replay');
      // Sign the bare payload, omitting DOMAIN || 0x00.
      final keyPair = await Ed25519().newKeyPairFromSeed(testSeed1);
      final bare = await Ed25519().sign(payload, keyPair: keyPair);

      final result = await verifier.verify(
        _response(base64.encode(payload), base64.encode(bare.bytes)),
        minimumSequence: 0,
      );

      expect(result.rejection, equals(AnnouncementRejection.badSignature));
    });

    test('a malformed envelope is rejected without crashing', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});

      for (final envelope in <Map<String, dynamic>>[
        {'announcement_signed': 'not an object'},
        {'announcement_signed': <String, dynamic>{}},
        {
          'announcement_signed': {'payload': 'not base64!!', 'sig': 'AAAA'}
        },
        {
          'announcement_signed': {'payload': '', 'sig': ''}
        },
      ]) {
        final result = await verifier.verify(envelope, minimumSequence: 0);
        expect(result.accepted, isFalse,
            reason: 'must never accept ${envelope['announcement_signed']}');
      }
    });

    test('a signature of the wrong length is rejected', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 1, iat: 1786000000, text: 'short sig');
      final result = await verifier.verify(
        _response(base64.encode(payload), base64.encode(List<int>.filled(8, 0))),
        minimumSequence: 0,
      );

      expect(result.rejection, equals(AnnouncementRejection.malformedEnvelope));
    });
  });

  group('replay is refused', () {
    test(
        'a correctly signed announcement with a LOWER sequence is rejected, '
        'so a captured "all systems normal" cannot be re-served during an '
        'outage', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final stale = _payloadBytes(
          keyId: 'a1', seq: 3, iat: 1786000000, text: 'all systems normal');

      final result = await verifier.verify(
        _response(base64.encode(stale), await _sign(stale, testSeed1)),
        minimumSequence: 9,
      );

      expect(result.accepted, isFalse);
      expect(result.rejection, equals(AnnouncementRejection.replayedSequence));
    });

    test(
        'the SAME sequence is still accepted, because one announcement '
        'legitimately arrives on all four polled routes', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 9, iat: 1786000000, text: 'current announcement');

      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed1)),
        minimumSequence: 9,
      );

      expect(result.accepted, isTrue);
      expect(result.envelope!.sequence, equals(9));
    });

    test('a higher sequence is accepted and moves the floor up', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 12, iat: 1786000000, text: 'newer announcement');

      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed1)),
        minimumSequence: 9,
      );

      expect(result.accepted, isTrue);
      expect(result.envelope!.sequence, equals(12));
    });

    test('the sequence check runs only AFTER the signature is verified',
        () async {
      // An unsigned payload claiming a huge sequence must not be able to push
      // the device's replay floor up and lock out real announcements.
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a1', seq: 999999, iat: 1786000000, text: 'floor poisoning');

      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed2)),
        minimumSequence: 1,
      );

      expect(result.rejection, equals(AnnouncementRejection.badSignature));
      expect(result.envelope, isNull,
          reason: 'no sequence may be reported from an unverified payload');
    });
  });

  group('key rotation across the compiled-in key set', () {
    test('any key in the set may sign, so the hub can rotate without a '
        'client release', () async {
      final verifier = AnnouncementVerifier({
        'a1': await _publicKey(testSeed1),
        'a2': await _publicKey(testSeed2),
        'a3': await _publicKey(testSeed3),
      });

      for (final rotation in <List<Object>>[
        ['a1', testSeed1],
        ['a2', testSeed2],
        ['a3', testSeed3],
      ]) {
        final keyId = rotation[0] as String;
        final seed = rotation[1] as List<int>;
        final payload = _payloadBytes(
            keyId: keyId, seq: 5, iat: 1786000000, text: 'signed by $keyId');
        final result = await verifier.verify(
          _response(base64.encode(payload), await _sign(payload, seed)),
          minimumSequence: 0,
        );

        expect(result.accepted, isTrue, reason: '$keyId must be accepted');
        expect(result.envelope!.keyId, equals(keyId));
      }
    });

    test(
        'a client that predates the key in use rejects everything - this is '
        'the stranding case the successor slots exist to prevent', () async {
      // Only a1 compiled in; the hub has rotated to a2.
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload = _payloadBytes(
          keyId: 'a2', seq: 5, iat: 1786000000, text: 'signed by the new key');

      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed2)),
        minimumSequence: 0,
      );

      expect(result.rejection, equals(AnnouncementRejection.unknownKeyId));
    });

    test(
        'the key id inside the signed payload is authoritative - relabelling '
        'the outer envelope does not pick a different key', () async {
      final verifier = AnnouncementVerifier({
        'a1': await _publicKey(testSeed1),
        'a2': await _publicKey(testSeed2),
      });
      // Payload says a1 and is signed by a1; the outer envelope lies and says
      // a2. The inner value is what is used, so this still verifies as a1.
      final payload = _payloadBytes(
          keyId: 'a1', seq: 1, iat: 1786000000, text: 'inner kid wins');
      final result = await verifier.verify({
        'announcement_signed': {
          'payload': base64.encode(payload),
          'sig': await _sign(payload, testSeed1),
          'kid': 'a2',
        }
      }, minimumSequence: 0);

      expect(result.accepted, isTrue);
      expect(result.envelope!.keyId, equals('a1'));
    });
  });

  group('absent signature and the bundled default', () {
    test(
        'a response with NO announcement_signed field is refused - fail '
        'closed against a stripped signature', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final result = await verifier.verify(
        {'announcement': 'unsigned text an attacker could have written'},
        minimumSequence: 0,
      );

      expect(result.accepted, isFalse);
      expect(result.rejection, equals(AnnouncementRejection.missingSignature));
    });

    test('an empty key set is not enforcing, which is what makes the rollout '
        'order safe by construction', () async {
      const verifier = AnnouncementVerifier(<String, List<int>>{});
      expect(verifier.enforcing, isFalse);

      final withKeys =
          AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      expect(withKeys.enforcing, isTrue);
    });

    test('a verified but empty announcement is not displayable', () async {
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final payload =
          _payloadBytes(keyId: 'a1', seq: 1, iat: 1786000000, text: '   ');
      final result = await verifier.verify(
        _response(base64.encode(payload), await _sign(payload, testSeed1)),
        minimumSequence: 0,
      );

      expect(result.rejection, equals(AnnouncementRejection.emptyText));
    });
  });

  group('compiled defaults are enforcing (C-2)', () {
    final keySource =
        File('lib/announcement_signature.dart').readAsStringSync();

    test('the reviewed ceremony public keys are the compile-time defaults',
        () {
      // These are the REAL announcement keypair public halves (hub signing
      // key a1 + offline successors a2/a3). If a lane empties the defaults
      // the verifier silently stops enforcing again -- the exact C-2 defect.
      expect(keySource, contains(kReviewedAnnouncementPubkeyA1));
      expect(keySource, contains(kReviewedAnnouncementPubkeyA2));
      expect(keySource, contains(kReviewedAnnouncementPubkeyA3));
      for (final key in <String>[
        kReviewedAnnouncementPubkeyA1,
        kReviewedAnnouncementPubkeyA2,
        kReviewedAnnouncementPubkeyA3,
      ]) {
        expect(base64.decode(key), hasLength(32),
            reason: 'a compiled public key must be raw 32 bytes');
      }
    });

    test('enforcement fails when the pinned key is absent and succeeds with '
        'it', () async {
      // Absent keys: not enforcing, exactly the pre-signing behaviour.
      const withoutKeys = AnnouncementVerifier(<String, List<int>>{});
      expect(withoutKeys.enforcing, isFalse);

      // Pinned keys: the compiled defaults ARE the ceremony keys, and the
      // verifier enforces. A1 must be present as the active hub key.
      final compiled = AnnouncementVerifier.fromCompiledDefines();
      expect(compiled.enforcing, isTrue);
      expect(compiled.trustedKeys['a1'],
          base64.decode(kReviewedAnnouncementPubkeyA1));
      expect(compiled.trustedKeys['a2'],
          base64.decode(kReviewedAnnouncementPubkeyA2));
      expect(compiled.trustedKeys['a3'],
          base64.decode(kReviewedAnnouncementPubkeyA3));

      // Enforcement is real, not cosmetic: an enforcing verifier still
      // refuses an announcement signed by any key that is NOT the pinned
      // key, which is the whole point of the gate.
      final payload = _payloadBytes(
          keyId: 'a1', seq: 1, iat: 1786000000, text: 'must not verify');
      final forged = await _sign(payload, testSeed2);
      final result = await compiled.verify(
        _response(base64.encode(payload), forged),
        minimumSequence: 0,
      );
      expect(result.accepted, isFalse);
      expect(result.rejection, equals(AnnouncementRejection.badSignature));
    });

    test('non-enforcing is reachable only in debug builds with every slot '
        'explicitly emptied (F-08)', () {
      // The override mechanism must remain: WINS_ANNOUNCE_PUBKEY_A* overrides
      // the defaults, so a dev/test build can still compile non-enforcing.
      expect(keySource, contains('WINS_ANNOUNCE_PUBKEY_A1'));
      expect(keySource, contains('WINS_ANNOUNCE_PUBKEY_A2'));
      expect(keySource, contains('WINS_ANNOUNCE_PUBKEY_A3'));
      expect(keySource, contains('defaultValue: kReviewedAnnouncementPubkeyA1'));
      expect(keySource, contains('defaultValue: kReviewedAnnouncementPubkeyA2'));
      expect(keySource, contains('defaultValue: kReviewedAnnouncementPubkeyA3'));

      final valid = <String, String>{
        'a1': kReviewedAnnouncementPubkeyA1,
        'a2': kReviewedAnnouncementPubkeyA2,
        'a3': kReviewedAnnouncementPubkeyA3,
      };
      final emptied = <String, String>{'a1': '', 'a2': '', 'a3': ''};

      // Debug + explicitly emptied: non-enforcing, pre-signing behaviour.
      expect(
        compiledAnnouncementTrustedKeys(isReleaseBuild: false, defines: emptied),
        isEmpty,
      );

      // Debug + valid: enforcing.
      expect(
        compiledAnnouncementTrustedKeys(isReleaseBuild: false, defines: valid),
        hasLength(3),
      );

      // Release + valid: enforcing.
      expect(
        compiledAnnouncementTrustedKeys(isReleaseBuild: true, defines: valid),
        hasLength(3),
      );

      // Release + empty keyring: construction must throw.
      expect(
        () => compiledAnnouncementTrustedKeys(
            isReleaseBuild: true, defines: emptied),
        throwsStateError,
      );

      // Release + malformed keyring: construction must throw.
      expect(
        () => compiledAnnouncementTrustedKeys(
          isReleaseBuild: true,
          defines: <String, String>{
            'a1': kReviewedAnnouncementPubkeyA1,
            'a2': 'not base64 at all!!',
            'a3': '',
          },
        ),
        throwsStateError,
      );

      // Debug + malformed define that empties the ring: that is NOT
      // "explicitly emptied", so it throws instead of silently not enforcing.
      expect(
        () => compiledAnnouncementTrustedKeys(
          isReleaseBuild: false,
          defines: <String, String>{'a1': 'bm90IGEgcmVhbCBrZXk=', 'a2': '', 'a3': ''},
        ),
        throwsStateError,
      );

      // Debug + one usable slot beside empty slots: still enforcing; the
      // empty slots degrade to "that key does not exist", never to a
      // silently empty ring.
      final degraded = compiledAnnouncementTrustedKeys(
        isReleaseBuild: false,
        defines: <String, String>{'a1': kReviewedAnnouncementPubkeyA1, 'a2': '', 'a3': ''},
      );
      expect(degraded.keys, equals(<String>['a1']));
    });
  });

  group('client wiring', () {
    final source = File('lib/main.dart').readAsStringSync();

    test('the bundled default is still compiled in and still displayable '
        'with no signature at all', () {
      expect(source, contains('static const String _defaultAnnouncement'));
      // Every rejection path lands on the bundled default rather than on
      // attacker-supplied text.
      expect(source, contains('return _defaultAnnouncement;'));
    });

    test('all three ingestion points go through the one resolver', () {
      // If any of these read data['announcement'] directly again, a route
      // could deliver unverified text while the others enforced.
      for (final marker in const [
        'Future<void> _applyAccountSyncData',
        'Future<void> _parseNodesResponse',
        'Future<void> _onAuthSuccess',
      ]) {
        expect(source, contains(marker),
            reason: '$marker must be async to await verification');
      }
      final resolverCalls = '_resolveAnnouncement('.allMatches(source).length;
      expect(resolverCalls, greaterThanOrEqualTo(4),
          reason: 'one definition plus a call from each ingestion point');
    });

    test('the replay floor is persisted, so a relaunch does not reset it', () {
      expect(source, contains('announcement_seq_floor'));
      expect(source, contains('_announcementSeqFloor'));
    });

    test(
        'a persisted announcement is re-verified on restore and an unsigned '
        'or tampered record never renders (WVP-005)', () async {
      // The signed envelope is what gets persisted and later re-verified; a
      // bare plaintext copy can be rewritten by anything with file access,
      // so it must never be the restore source.
      expect(source, contains('server_announcement_signed'));
      final restore =
          _functionBody(source, 'Future<String> _restoreAnnouncementForDisplay(');
      expect(restore, contains("['server_announcement_signed']"));
      expect(restore, contains('_resolveAnnouncement('),
          reason: 'the persisted record must flow through the SAME '
              'Ed25519 verification path hub responses take');
      expect(restore, contains('_defaultAnnouncement'),
          reason: 'an unsigned/tampered record must fall back to the '
              'compiled default, never to the persisted bytes');
      expect(restore, contains('_announcementRestoreDiscardLogged'),
          reason: 'the discard must be logged (once per launch)');
      // The persisted PLAINTEXT key is never read back as display text: the
      // only remaining occurrences are the write path, not a restore read.
      expect(source, isNot(contains("settingsData['server_announcement']")),
          reason: 'raw persisted plaintext must never be restored into the '
              'display sink');

      // Behavioural half: the verification the restore calls rejects a
      // tampered or unsigned record (badSignature/missingSignature), so
      // _resolveAnnouncement lands on _defaultAnnouncement rather than the
      // offending text. Same cert-level proofs as the groups above, framed
      // as the WVP-005 restore outcome.
      final verifier = AnnouncementVerifier({'a1': await _publicKey(testSeed1)});
      final genuinePayload = _payloadBytes(
          keyId: 'a1', seq: 3, iat: 1786000000, text: 'genuine');
      final signed = _response(
          base64.encode(_payloadBytes(
              keyId: 'a1', seq: 3, iat: 1786000000,
              text: 'ATTACKER: delete the app')),
          await _sign(genuinePayload, testSeed1));
      final envelope =
          Map<String, dynamic>.from(signed['announcement_signed'] as Map);
      // Tampering with the signed payload after persistence: one flipped
      // byte turns the restored record into a badSignature rejection.
      final tampered = List<int>.from(base64.decode(envelope['payload'] as String));
      tampered[tampered.length ~/ 2] ^= 0x01;
      final tamperedRecord = <String, dynamic>{
        'announcement_signed': <String, dynamic>{
          'payload': base64.encode(tampered),
          'sig': envelope['sig'],
        },
      };
      expect(
        (await verifier.verify(tamperedRecord, minimumSequence: 2)).rejection,
        equals(AnnouncementRejection.badSignature),
      );
      // And a record with no signature at all is the discard case the
      // restore helper turns into the compiled default.
      expect(
        (await verifier.verify(
                <String, dynamic>{'announcement': 'bare persisted text'},
                minimumSequence: 2))
            .rejection,
        equals(AnnouncementRejection.missingSignature),
      );
    });

    test('a release build can never take the non-enforcing plaintext path '
        '(F-08 release guard)', () {
      // fromCompiledDefines throws in release for an empty or malformed
      // keyring, and the resolver carries a second gate: a release build
      // that somehow reached the non-enforcing branch throws instead of
      // displaying unverified text.
      expect(source, contains('if (!_announcementVerifier.enforcing)'));
      expect(source, contains('if (kReleaseMode) {'));
      expect(source, contains('refusing to display unverified announcement text'));
    });

    test('no private key material is compiled into the client', () {
      // Only PUBLIC keys belong in the client, via build defines whose
      // defaults are the reviewed ceremony keys (lib/announcement_signature
      // .dart, the same base64-define override mechanism the descriptor
      // ring uses).
      final keys = File('lib/announcement_signature.dart').readAsStringSync();
      expect(keys, contains('WINS_ANNOUNCE_PUBKEY_A1'));
      expect(keys, contains('WINS_ANNOUNCE_PUBKEY_A2'));
      expect(keys, contains('WINS_ANNOUNCE_PUBKEY_A3'));
      expect(keys, isNot(contains('PRIVATE KEY')));
      expect(keys, isNot(contains('BEGIN OPENSSH')));
      // main.dart must build its verifier from the compiled defines rather
      // than carrying a second, drift-prone key list.
      expect(source, contains('AnnouncementVerifier.fromCompiledDefines()'));
    });

    test('the resolver rechecks the account epoch after verification and '
        'before it raises the floor, persists the envelope or returns text',
        () {
      // A verification started under one account epoch must not raise the
      // replay floor, schedule a settings write or return text under the
      // next one. The State is private and builds its verifier from the
      // compiled defines, so a test cannot suspend verification; this pins
      // the order instead: epoch captured before the only await, recheck
      // right after it, every effect after the recheck.
      final body =
          _functionBody(source, 'Future<String?> _resolveAnnouncement(');
      const capture = 'final accountEpoch = _accountSessionEpoch.current;';
      const verify = 'await _announcementVerifier.verify(';
      const recheck = 'if (!_accountEpochIsCurrent(accountEpoch)) return null;';
      expect(body, contains(capture));
      expect(body, contains(verify));
      expect(body, contains(recheck));
      expect('await '.allMatches(body), hasLength(1),
          reason: 'a second await would reopen the window after the recheck');
      expect(body.indexOf(capture), lessThan(body.indexOf(verify)));
      final verifyEnd = body.indexOf(');', body.indexOf(verify));
      final guard = body.indexOf(recheck);
      expect(guard, greaterThan(verifyEnd));
      for (final effect in const [
        'final envelope = result.envelope;',
        '_announcementSeqFloor = envelope.sequence;',
        "'announcement_seq_floor'",
        "'server_announcement_signed'",
        'return envelope.text;',
      ]) {
        expect(body.indexOf(effect), greaterThan(guard),
            reason: '$effect must come after the epoch recheck');
      }
    });
  });

  group('hub contract', () {
    final hub =
        File('server/wins_control_plane_setup_ONETOUCH.sh').readAsStringSync();

    test('the hub and client agree on the signature domain', () {
      final dartDomain = RegExp(
              r"kAnnouncementSignatureDomain\s*=\s*'([^']+)'")
          .firstMatch(
              File('lib/announcement_signature.dart').readAsStringSync());
      final hubDomain =
          RegExp(r'ANNOUNCE_SIGNATURE_DOMAIN = b"([^"]+)"').firstMatch(hub);

      expect(dartDomain, isNotNull);
      expect(hubDomain, isNotNull);
      expect(dartDomain!.group(1), equals(hubDomain!.group(1)));
    });

    test('all four polled routes emit the announcement through one helper',
        () {
      // Five call sites: /nodes, /account/status, /verify and both branches of
      // /free/status. A route left on the old inline get_setting would serve
      // bare text and make enforcing clients flip between valid and invalid.
      final helperCalls = '**announcement_fields(conn),'.allMatches(hub).length;
      expect(helperCalls, equals(5),
          reason: 'every announcement-bearing response must use the helper');
      final inline = RegExp(
              r'"announcement": get_setting\(conn, "global_announcement"')
          .allMatches(hub)
          .length;
      expect(inline, equals(1),
          reason: 'the only remaining inline read is inside the helper itself');
    });

    test('the plaintext announcement field is still emitted unconditionally, '
        'so already-shipped clients are unaffected', () {
      expect(hub, contains('"announcement": get_setting(conn, "global_announcement", WELCOME_MESSAGE_DEFAULT)'));
    });

    // Fable 5.1 ruling 2026-09-29 (IA-CP-06): announcements are signed
    // OFFLINE (tools/winn3_sign_announcement.py). The hub verifies an
    // uploaded envelope against the a1..a3 PUBLIC keys and stores it verbatim.
    String hubMainPy() {
      const open = 'cat > "\${APP_DIR}/main.py" <<\'PYEOF\'\n';
      final start = hub.indexOf(open);
      expect(start, greaterThan(0), reason: 'main.py heredoc not found');
      final end = hub.indexOf('\nPYEOF\n', start);
      expect(end, greaterThan(start));
      return hub.substring(start + open.length, end);
    }

    test('/admin/announce verifies an offline envelope and refuses to '
        'half-write on failure', () {
      expect(hub, contains('store_verified_announcement('));
      expect(hub, contains('nothing was changed.'));
      // Signature and sequence are checked before any set_setting call.
      final body =
          hub.substring(hub.indexOf('def store_verified_announcement'));
      final verifyAt = body.indexOf('verify_announcement_signature(');
      final floorAt = body.indexOf('announcement_sequence_floor(conn)');
      final writeAt = body.indexOf('set_setting(conn, "global_announcement"');
      expect(verifyAt, greaterThan(0));
      expect(floorAt, greaterThan(verifyAt));
      expect(writeAt, greaterThan(floorAt),
          reason: 'verification must happen before anything is written');
    });

    test('the hub holds no announcement signing key', () {
      final main = hubMainPy();
      for (final gone in <String>[
        'sign_announcement_payload',
        'announce_signing_key_path',
        'ANNOUNCE_SIGNING_KEY_ID',
        'CREDENTIALS_DIRECTORY',
        'announce-sign.key',
      ]) {
        expect(main, isNot(contains(gone)), reason: gone);
      }
      expect(main, isNot(contains('"-sign"')),
          reason: 'the hub must not sign anything with openssl');
      expect(main, contains('ANNOUNCE_PUBKEY_{slot.upper()}'));
      expect(hub, isNot(contains('LoadCredential=announce-sign.key')));
      expect(hub, isNot(contains('install -d -m 700 /etc/winn/announce')));
      // The installer must not mint a keypair either.
      expect(hub, isNot(contains('genpkey -algorithm ed25519')));
      expect(hub, isNot(contains('BEGIN PRIVATE KEY')));
    });

    test('the hub default verification ring is the ring this client compiles',
        () {
      final keys = File('lib/announcement_signature.dart').readAsStringSync();
      for (final slot in <String>['A1', 'A2', 'A3']) {
        final reviewed = RegExp(
                "kReviewedAnnouncementPubkey$slot =\\s*'([A-Za-z0-9+/=]+)'")
            .firstMatch(keys);
        expect(reviewed, isNotNull, reason: slot);
        expect(hub, contains("$slot) printf '%s' '${reviewed!.group(1)}' ;;"),
            reason: 'installer default for ANNOUNCE_PUBKEY_$slot drifted');
      }
    });

    test('the sequence number is stored and must strictly increase', () {
      expect(hub, contains('global_announcement_seq'));
      expect(hub, contains('if seq <= announcement_sequence_floor(conn):'));
    });
  });
}
