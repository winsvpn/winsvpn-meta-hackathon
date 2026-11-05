/// Client-side discovery-record path: try-all-keys verification, family and
/// domain separation, the independent replay floor, paste-in, and the merge
/// into the gateway sweep.
///
/// **All key material below is fixture data for these tests only** —
/// deterministic, obviously-synthetic Ed25519 seeds (`0x01…`, `0x02…`,
/// `0x03…`, `0x0a…`), following the convention in
/// `winn_protocol_experimental/internal/knock/keys_test.go`. No production key
/// is generated, referenced or implied anywhere in this file, and none of
/// these seeds may ever be used for anything real.
library;

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/announcement_signature.dart';
import 'package:wins_vpn/bootstrap_resilience.dart';
import 'package:wins_vpn/discovery_intake.dart';
import 'package:wins_vpn/discovery_keys.dart';
import 'package:wins_vpn/discovery_paste_in.dart';
import 'package:wins_vpn/recovery_beacon_gate.dart';

// ---------------------------------------------------------------------------
// Synthetic fixture keys. NOT REAL KEYS.
// ---------------------------------------------------------------------------

List<int> _seed(int byte) => List<int>.filled(32, byte);

final List<int> kSeedD1 = _seed(0x01);
final List<int> kSeedD2 = _seed(0x02);
final List<int> kSeedD3 = _seed(0x03);
final List<int> kSeedAnnouncement = _seed(0x0a);

/// Public halves of the fixture seeds, as emitted by
/// `openssl pkey -pubout -outform DER | tail -c 32 | base64` — the exact
/// pipeline the key ceremony uses. Hard-coded so the Dart signing helper below
/// is pinned against an independent implementation rather than against itself.
const String kPubD1 = 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=';
const String kPubD2 = 'gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=';
const String kPubD3 = '7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=';
const String kPubAnnouncement = 'Q6cucUQBdi32a2jCbfvfJoKq7J8kdOykYT5CSg+6/Tw=';

// ---------------------------------------------------------------------------
// Cross-implementation vectors, produced by `openssl pkeyutl -sign -rawin`
// following `make-discovery-record.sh` from the key-management design exactly.
// These prove the openssl -> Dart pipeline end to end, including the byte
// boundary that the signing lane hit experimentally.
// ---------------------------------------------------------------------------

const int kVectorExpiry = 1786000000;
const String kVectorHosts = 'gw-alpha.example,gw-bravo.example';
const String kVectorPortion = 'v1|10|1786000000|$kVectorHosts';

/// Signed over `v1|10|<exp>|<hosts>` — **no trailing pipe**. Canonical.
const String kRecordOpensslD2 =
    'v1|10|1786000000|gw-alpha.example,gw-bravo.example|'
    'eBUR80Bq0OfmRv314/8RZx8Z1H1nuRRNp1KOF209tt+VkNp6U8lfidmeX5Vq8M2LNhUicBaOQ23W7pHF/qi2AQ==';
const String kRecordOpensslD1 =
    'v1|10|1786000000|gw-alpha.example,gw-bravo.example|'
    'TNAW49Tpp9+O6OO9Zu3DW8PveWpmqXfBdc8zkyR5XbI3px96cMMNwh1rSGS5ZMJvlu3h1VrMmXggmZqjkK7DAQ==';
const String kRecordOpensslD3 =
    'v1|10|1786000000|gw-alpha.example,gw-bravo.example|'
    'X3EzBChyP2vOwffpgqDgi/wWrJNEuxE8PNUPrFzbSIb+PvbvvY7yrI6pYQ4M0IpxZihsFvQaQVtiyIiqwv/gBA==';

/// The mistake the design warns about: signed over the portion *including* its
/// trailing `|`. Byte-identical record text; only the signed bytes differ.
const String kRecordTrailingPipeMistake =
    'v1|10|1786000000|gw-alpha.example,gw-bravo.example|'
    's7iQJsJa7P20eLq/HmCR8lkj0ocA2Yur8RwACJmBdaUfoinqq4qnroLxudQ7+/Nn80xmW52gt5oO1pUm+wfpCg==';

/// Correct bytes, correct domain — but signed by an **announcement-family**
/// key. Key-set separation must refuse it.
const String kRecordSignedByAnnouncementKey =
    'v1|10|1786000000|gw-alpha.example,gw-bravo.example|'
    'ToI51/Eto7GbiSvWKHZgQXDFh9hKGcHIxCQ83lRFuFV8JBQ+f5NDlMlzITsZuxsp6JiE+iysSutL0yrnT3DOBA==';

/// Correct bytes, **discovery key** — but signed under the *announcement*
/// domain separator. Domain separation alone must refuse it.
const String kRecordSignedUnderAnnouncementDomain =
    'v1|10|1786000000|gw-alpha.example,gw-bravo.example|'
    'R5xkkpE7FV2mHXBgYSOAaLDj7XttsdmkMA4WltftrXb8mWpVH2DOtRYP6szNrRvEyzDaxfQGzYmq5USgJgaLBw==';

final DateTime kVectorNow =
    DateTime.fromMillisecondsSinceEpoch(kVectorExpiry * 1000, isUtc: true)
        .subtract(const Duration(days: 1));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Future<SimpleKeyPair> _keyPair(List<int> seed) =>
    Ed25519().newKeyPairFromSeed(seed);

Future<String> _publicKeyB64(List<int> seed) async {
  final pk = await (await _keyPair(seed)).extractPublicKey();
  return base64.encode(pk.bytes);
}

/// Sign an arbitrary record with a fixture seed, mirroring
/// `make-discovery-record.sh`.
Future<String> _makeRecord({
  required List<int> seed,
  required int sequence,
  int expiry = kVectorExpiry,
  String hosts = kVectorHosts,
  String domain = kDiscoverySignatureDomain,
  bool signTrailingPipe = false,
}) async {
  final portion = 'v1|$sequence|$expiry|$hosts';
  final signedText = signTrailingPipe ? '$portion|' : portion;
  final message = <int>[...utf8.encode(domain), 0, ...utf8.encode(signedText)];
  final signature =
      await Ed25519().sign(message, keyPair: await _keyPair(seed));
  return '$portion|${base64.encode(signature.bytes)}';
}

DiscoveryRecordVerifier _verifierWith(Map<String, String> encoded) =>
    DiscoveryRecordVerifier(DiscoveryKeyRing.fromEncoded(encoded));

const Map<String, String> _allThreeDiscoveryKeys = <String, String>{
  'd1': kPubD1,
  'd2': kPubD2,
  'd3': kPubD3,
};

void main() {
  group('fixture keys agree with openssl', () {
    test('Dart seed derivation reproduces the openssl public halves', () async {
      // Pins the in-test signing helper against an independent implementation.
      // If this fails, every vector below is meaningless.
      expect(await _publicKeyB64(kSeedD1), kPubD1);
      expect(await _publicKeyB64(kSeedD2), kPubD2);
      expect(await _publicKeyB64(kSeedD3), kPubD3);
      expect(await _publicKeyB64(kSeedAnnouncement), kPubAnnouncement);
    });
  });

  group('the trailing pipe is EXCLUDED from the signed portion', () {
    test('splitDiscoveryRecord signs everything before the LAST pipe', () {
      final split = splitDiscoveryRecord(kRecordOpensslD2)!;
      expect(split.signedPortion, kVectorPortion);
      expect(split.signedPortion.endsWith('|'), isFalse,
          reason: 'the signed portion must not carry a trailing separator');
      expect(split.signature.length, 64);
    });

    test('an openssl record signed WITHOUT the trailing pipe verifies',
        () async {
      final report = await _verifierWith(_allThreeDiscoveryKeys).verify(
        kRecordOpensslD2,
        now: kVectorNow,
        lastAcceptedSequence: 0,
      );
      expect(report.accepted, isTrue,
          reason: 'canonical make-discovery-record.sh output must verify');
    });

    test('a record signed WITH the trailing pipe is rejected', () async {
      // This is the whole test. If someone "fixes" the signing script or the
      // splitter to include the final separator, the vector above starts
      // failing and this one starts passing -- and both directions are
      // asserted so the mistake cannot be made in either place silently.
      final report = await _verifierWith(_allThreeDiscoveryKeys).verify(
        kRecordTrailingPipeMistake,
        now: kVectorNow,
        lastAcceptedSequence: 0,
      );
      expect(report.accepted, isFalse);
      expect(report.rejection, DiscoveryRejection.badSignature);
      expect(report.diagnostics.signatureFailure,
          DiscoverySignatureFailure.noKeyAccepted);
    });

    test('the two records are textually identical except for the signature',
        () {
      final good = splitDiscoveryRecord(kRecordOpensslD2)!;
      final bad = splitDiscoveryRecord(kRecordTrailingPipeMistake)!;
      expect(good.signedPortion, bad.signedPortion,
          reason: 'only the signed BYTES differ, which is what makes this '
              'mistake invisible without a test');
      expect(good.signature, isNot(bad.signature));
    });

    test('a Dart-signed record with the trailing pipe is also rejected',
        () async {
      final wrong = await _makeRecord(
        seed: kSeedD1,
        sequence: 11,
        signTrailingPipe: true,
      );
      final right = await _makeRecord(seed: kSeedD1, sequence: 11);
      final verifier = _verifierWith(_allThreeDiscoveryKeys);
      expect(
        (await verifier.verify(wrong,
                now: kVectorNow, lastAcceptedSequence: 0))
            .accepted,
        isFalse,
      );
      expect(
        (await verifier.verify(right,
                now: kVectorNow, lastAcceptedSequence: 0))
            .accepted,
        isTrue,
      );
    });
  });

  group('try-all-keys rotation', () {
    test('a record verifies under any of the three compiled slots', () async {
      final verifier = _verifierWith(_allThreeDiscoveryKeys);
      for (final entry in <String, String>{
        'd1': kRecordOpensslD1,
        'd2': kRecordOpensslD2,
        'd3': kRecordOpensslD3,
      }.entries) {
        final report = await verifier.verify(entry.value,
            now: kVectorNow, lastAcceptedSequence: 0);
        expect(report.accepted, isTrue,
            reason: 'slot ${entry.key} must not strand the installed base');
        expect(report.diagnostics.acceptedSlotId, entry.key);
      }
    });

    test('rotation to d3 works on a build that never saw a d3 record before',
        () async {
      // The stranding scenario: the owner starts publishing under a successor.
      // Nothing on the client changes.
      final report = await _verifierWith(_allThreeDiscoveryKeys)
          .verify(kRecordOpensslD3, now: kVectorNow, lastAcceptedSequence: 0);
      expect(report.diagnostics.acceptedSlotId, 'd3');
    });

    test('a record signed by a key this build lacks is refused', () async {
      // Only d1 compiled; record signed by d3. This is what stranding looks
      // like, and it must be a clean refusal, not an acceptance.
      final report = await _verifierWith(const <String, String>{'d1': kPubD1})
          .verify(kRecordOpensslD3, now: kVectorNow, lastAcceptedSequence: 0);
      expect(report.accepted, isFalse);
      expect(report.diagnostics.signatureFailure,
          DiscoverySignatureFailure.noKeyAccepted);
      expect(report.diagnostics.trials.map((t) => t.slotId), <String>['d1']);
    });

    test('trials stop at the accepting key and are reported in slot order',
        () async {
      final report = await _verifierWith(_allThreeDiscoveryKeys)
          .verify(kRecordOpensslD2, now: kVectorNow, lastAcceptedSequence: 0);
      expect(report.diagnostics.trials.map((t) => t.slotId),
          <String>['d1', 'd2']);
      expect(report.diagnostics.trials.last.verified, isTrue);
    });
  });

  group('key ring hygiene', () {
    test('an empty ring is inert and says so', () async {
      final verifier = _verifierWith(const <String, String>{});
      expect(verifier.enforcing, isFalse);
      final report = await verifier.verify(kRecordOpensslD2,
          now: kVectorNow, lastAcceptedSequence: 0);
      expect(report.accepted, isFalse);
      expect(report.diagnostics.signatureFailure,
          DiscoverySignatureFailure.noKeysCompiled);
      expect(report.diagnostics.describe(), contains('no keys compiled'));
    });

    test('a malformed define is dropped, never trusted, and is reported', () {
      final ring = DiscoveryKeyRing.fromEncoded(const <String, String>{
        'd1': kPubD1,
        'd2': 'not base64 at all !!!',
        'd3': 'c2hvcnQ=', // valid base64, wrong length
      });
      expect(ring.compiledSlotIds, <String>['d1']);
      expect(ring.droppedSlotIds, <String>['d2', 'd3']);
      expect(ring.enforcing, isTrue);
    });

    test('an empty slot is absent rather than dropped', () {
      final ring = DiscoveryKeyRing.fromEncoded(const <String, String>{
        'd1': kPubD1,
        'd2': '',
        'd3': '   ',
      });
      expect(ring.compiledSlotIds, <String>['d1']);
      expect(ring.droppedSlotIds, isEmpty);
    });

    test('a wrong-length signature is refused before the crypto library',
        () async {
      final report = await _verifierWith(_allThreeDiscoveryKeys).verify(
        'v1|10|$kVectorExpiry|$kVectorHosts|${base64.encode(List<int>.filled(63, 7))}',
        now: kVectorNow,
        lastAcceptedSequence: 0,
      );
      expect(report.accepted, isFalse);
      expect(report.diagnostics.signatureFailure,
          DiscoverySignatureFailure.malformedSignatureLength);
      expect(report.diagnostics.trials, isEmpty,
          reason: 'no key should have been tried at all');
    });

    test('diagnostics never leak the record, hosts, or key material',
        () async {
      final report = await _verifierWith(_allThreeDiscoveryKeys).verify(
        kRecordTrailingPipeMistake,
        now: kVectorNow,
        lastAcceptedSequence: 0,
      );
      final text = report.diagnostics.describe();
      expect(text, isNot(contains('gw-alpha')));
      expect(text, isNot(contains('gw-bravo')));
      expect(text, isNot(contains(kPubD1)));
      expect(text, isNot(contains('1786000000')));
      // ...but it is still actionable.
      expect(text, contains('d1'));
      expect(text, contains('noKeyAccepted'));
    });
  });

  group('the two key families are never interchangeable', () {
    test('DIRECTION 1: a discovery record signed by an announcement key fails',
        () async {
      final report = await _verifierWith(_allThreeDiscoveryKeys).verify(
        kRecordSignedByAnnouncementKey,
        now: kVectorNow,
        lastAcceptedSequence: 0,
      );
      expect(report.accepted, isFalse);
      expect(report.rejection, DiscoveryRejection.badSignature);
    });

    test(
        'DIRECTION 2: an announcement signed by a discovery key fails, even '
        'when the key sets are collapsed', () async {
      // Simulates the future mistake of putting a discovery key into the
      // announcement trust set. Domain separation alone must still refuse it,
      // which is the belt-and-suspenders property the design claims.
      final payload = utf8.encode(jsonEncode(<String, Object>{
        'kid': 'a1',
        'seq': 5,
        'iat': kVectorExpiry - 86400,
        'text': 'synthetic fixture announcement',
      }));
      final signature = await Ed25519().sign(
        // Signed under the DISCOVERY domain -- the cross-domain attempt.
        <int>[...utf8.encode(kDiscoverySignatureDomain), 0, ...payload],
        keyPair: await _keyPair(kSeedD1),
      );
      final verifier = AnnouncementVerifier(<String, List<int>>{
        'a1': base64.decode(kPubD1), // deliberately the discovery key
      });
      final result = await verifier.verify(<String, dynamic>{
        'announcement_signed': <String, dynamic>{
          'payload': base64.encode(payload),
          'sig': base64.encode(signature.bytes),
        },
      }, minimumSequence: 0);
      expect(result.accepted, isFalse);
      expect(result.rejection, AnnouncementRejection.badSignature);
    });

    test(
        'DIRECTION 1 (domain): a discovery key signing under the announcement '
        'domain fails against the discovery verifier', () async {
      final report = await _verifierWith(_allThreeDiscoveryKeys).verify(
        kRecordSignedUnderAnnouncementDomain,
        now: kVectorNow,
        lastAcceptedSequence: 0,
      );
      expect(report.accepted, isFalse);
      expect(report.rejection, DiscoveryRejection.badSignature);
    });

    test('the two domain separators are distinct and neither is a prefix',
        () {
      expect(kDiscoverySignatureDomain, 'winsvpn-bootstrap-discovery/v1');
      expect(kAnnouncementSignatureDomain, 'winsvpn-announcement/v1');
      expect(kDiscoverySignatureDomain == kAnnouncementSignatureDomain, isFalse);
      // The 0x00 terminator makes prefix confusion impossible regardless, but
      // an accidental edit that made one a prefix of the other would be a
      // near-miss worth catching here.
      expect(kDiscoverySignatureDomain.startsWith(kAnnouncementSignatureDomain),
          isFalse);
      expect(kAnnouncementSignatureDomain.startsWith(kDiscoverySignatureDomain),
          isFalse);
    });

    test('the same bytes under the two domains produce different signing input',
        () {
      const portion = 'v1|10|1|h.example';
      expect(discoverySigningBytes(portion),
          isNot(announcementSigningBytes(utf8.encode(portion))));
    });
  });

  group('discovery_seq_floor is independent of announcement_seq_floor', () {
    test('the setting keys are different', () {
      expect(kDiscoverySeqFloorSettingKey, 'discovery_seq_floor');
      expect(kDiscoverySeqFloorSettingKey == 'announcement_seq_floor', isFalse);
    });

    test('a high announcement floor does not shadow a low discovery record',
        () async {
      // The attack recorded in the key-management design: an attacker holding
      // a valid ANNOUNCEMENT key drives that floor arbitrarily high. With a
      // shared counter this record would be "a replay" forever, permanently
      // denying the channel needed to route around them.
      final settings = <String, dynamic>{
        'announcement_seq_floor': 999999,
        kDiscoverySeqFloorSettingKey: 9,
      };
      final state = DiscoveryIntakeState.restore(settings);
      expect(state.seqFloor, 9);

      final intake = DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys));
      final outcome = await intake.acceptPastedRecord(
        kRecordOpensslD2, // seq 10
        now: kVectorNow,
        current: state,
      );
      expect(outcome.accepted, isTrue);
      expect(outcome.state.seqFloor, 10);
    });

    test('advancing the discovery floor writes only discovery keys', () async {
      final intake = DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys));
      final outcome = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      final written = outcome.state.toSettings();
      expect(written.keys, isNot(contains('announcement_seq_floor')));
      expect(written[kDiscoverySeqFloorSettingKey], 10);
      expect(written[kDiscoveryAcceptedSeqSettingKey], 10);
    });

    test('a corrupt persisted floor degrades to zero, not to a trusted value',
        () {
      expect(
        DiscoveryIntakeState.restore(
            <String, dynamic>{kDiscoverySeqFloorSettingKey: 'lots'}).seqFloor,
        0,
      );
      expect(
        DiscoveryIntakeState.restore(
            <String, dynamic>{kDiscoverySeqFloorSettingKey: -5}).seqFloor,
        0,
      );
    });

    test('a tampered persisted endpoint list cannot inject an unsafe host', () {
      final state = DiscoveryIntakeState.restore(<String, dynamic>{
        kDiscoveryEndpointsSettingKey: <dynamic>[
          'https://good.example',
          'http://insecure.example',
          'https://has.path.example/evil',
          42,
          'https://good.example', // duplicate
        ],
      });
      expect(state.endpoints, <String>['https://good.example']);
    });
  });

  group('paste-in', () {
    late DiscoveryIntake intake;

    setUp(() {
      intake = DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys));
    });

    test('a good paste is accepted and yields the endpoints', () async {
      final outcome = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      expect(outcome.status, DiscoveryIntakeStatus.accepted);
      expect(outcome.state.endpoints,
          <String>['https://gw-alpha.example', 'https://gw-bravo.example']);
      expect(discoveryIntakeMessage(outcome), contains('2 new server'));
    });

    test('surrounding whitespace and newlines survive a messaging app',
        () async {
      final outcome = await intake.acceptPastedRecord(
        '\n   $kRecordOpensslD2  \n\n',
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      expect(outcome.accepted, isTrue);
    });

    test('pasting the SAME record twice is a no-op and changes nothing',
        () async {
      final first = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      expect(first.accepted, isTrue);

      final second = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: first.state,
      );
      // The device recognises its own retained record, which is a more useful
      // thing to tell the user than "already used".
      expect(second.status, DiscoveryIntakeStatus.alreadyHeld);
      // Identical, not merely equal: a caller that persists unconditionally
      // writes back exactly what was already stored.
      expect(identical(second.state, first.state), isTrue);
      expect(second.state.seqFloor, 10);
      expect(second.state.endpoints, first.state.endpoints);
    });

    test('a DIFFERENT record at or below the floor is a replay', () async {
      // The replay control proper: distinct bytes, so the retention fast path
      // does not apply and the sequence floor has to do the work.
      final first = await intake.acceptPastedRecord(
        kRecordOpensslD2, // seq 10
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      for (final seq in <int>[4, 10]) {
        final stale = await _makeRecord(
            seed: kSeedD3, sequence: seq, hosts: 'gw-stale.example');
        final outcome = await intake.acceptPastedRecord(stale,
            now: kVectorNow, current: first.state);
        expect(outcome.status, DiscoveryIntakeStatus.replayed,
            reason: 'seq $seq must not pass a floor of 10');
        expect(identical(outcome.state, first.state), isTrue);
      }
    });

    test('a rejected record never moves the floor', () async {
      const before = DiscoveryIntakeState(seqFloor: 3);
      for (final bad in <String>[
        kRecordTrailingPipeMistake,
        kRecordSignedByAnnouncementKey,
        kRecordSignedUnderAnnouncementDomain,
        'complete nonsense',
        '',
      ]) {
        final outcome = await intake.acceptPastedRecord(
          bad,
          now: kVectorNow,
          current: before,
        );
        expect(outcome.accepted, isFalse, reason: bad);
        expect(outcome.state.seqFloor, 3, reason: bad);
        expect(outcome.state.endpoints, isEmpty, reason: bad);
      }
    });

    test('an empty paste is distinguished from a malformed one', () async {
      final empty = await intake.acceptPastedRecord('   ',
          now: kVectorNow, current: const DiscoveryIntakeState());
      expect(empty.status, DiscoveryIntakeStatus.empty);
      final malformed = await intake.acceptPastedRecord('v1|nope',
          now: kVectorNow, current: const DiscoveryIntakeState());
      expect(malformed.status, DiscoveryIntakeStatus.malformed);
      expect(discoveryIntakeMessage(empty),
          isNot(discoveryIntakeMessage(malformed)));
    });

    test('an expired record is reported as expired, not as malformed',
        () async {
      final old = await _makeRecord(
        seed: kSeedD1,
        sequence: 20,
        expiry: kVectorExpiry - const Duration(days: 30).inSeconds,
      );
      final outcome = await intake.acceptPastedRecord(old,
          now: kVectorNow, current: const DiscoveryIntakeState());
      expect(outcome.status, DiscoveryIntakeStatus.expired);
    });

    test('a build with no keys reports notProvisioned, not badSignature',
        () async {
      final inert = DiscoveryIntake(_verifierWith(const <String, String>{}));
      expect(inert.enforcing, isFalse);
      final outcome = await inert.acceptPastedRecord(kRecordOpensslD2,
          now: kVectorNow, current: const DiscoveryIntakeState());
      expect(outcome.status, DiscoveryIntakeStatus.notProvisioned);
      expect(discoveryIntakeMessage(outcome), contains('cannot accept'));
    });

    test('every status has distinct, non-empty user text naming no adversary',
        () {
      final seen = <String>{};
      for (final status in DiscoveryIntakeStatus.values) {
        final outcome = DiscoveryIntakeOutcome(
          status: status,
          state: const DiscoveryIntakeState(),
          diagnostics: const DiscoveryVerificationDiagnostics(
            enforcing: true,
            compiledSlotIds: <String>['d1'],
            droppedSlotIds: <String>[],
            trials: <DiscoveryKeyTrial>[],
          ),
        );
        final message = discoveryIntakeMessage(outcome);
        expect(message.trim(), isNotEmpty);
        expect(seen.add(message), isTrue, reason: '$status duplicates text');
        for (final word in <String>[
          'censor',
          'block',
          'Myanmar',
          'government',
          'VPN',
        ]) {
          expect(message.toLowerCase(), isNot(contains(word.toLowerCase())),
              reason: '$status leaks "$word" onto a screen that may be read '
                  'by someone else holding the phone');
        }
      }
    });

    test('a later record supersedes and its endpoints lead', () async {
      final first = await intake.acceptPastedRecord(kRecordOpensslD2,
          now: kVectorNow, current: const DiscoveryIntakeState());
      final next = await _makeRecord(
        seed: kSeedD3,
        sequence: 11,
        hosts: 'gw-charlie.example',
      );
      final second = await intake.acceptPastedRecord(next,
          now: kVectorNow, current: first.state);
      expect(second.accepted, isTrue);
      expect(second.state.seqFloor, 11);
      expect(second.state.endpoints.first, 'https://gw-charlie.example');
      // The previous ones are kept behind it, not discarded.
      expect(second.state.endpoints, contains('https://gw-alpha.example'));
    });

    test('the merged set never exceeds the endpoint cap', () {
      final merged = mergeDiscoveredEndpoints(
        existing: List<String>.generate(6, (i) => 'https://old$i.example'),
        incoming: List<String>.generate(6, (i) => 'https://new$i.example'),
      );
      expect(merged.length, kMaxDiscoveryEndpoints);
      expect(merged.first, 'https://new0.example');
    });
  });

  group('sweep merge', () {
    const compiled = <String>[
      'https://gw-one.example',
      'https://gw-two.example',
    ];

    test('endpoints already compiled are not re-admitted', () {
      final forSweep = discoveredEndpointsForSweep(
        compiledEndpoints: compiled,
        discovered: const <String>[
          'https://gw-two.example',
          'https://gw-alpha.example',
        ],
      );
      expect(forSweep, <String>['https://gw-alpha.example']);
    });

    test('the compiled Tier-0 list is never replaced or reordered', () {
      final gate = RecoveryBeaconGate(compiledGateways: compiled);
      gate.adoptDiscoveredEndpoints(const <String>['https://gw-alpha.example']);
      expect(gate.compiledGateways, compiled);
      final now = DateTime.utc(2026, 8, 6, 12);
      expect(gate.plannedGatewayOrder(now), compiled,
          reason: 'a discovered endpoint must not appear while the compiled '
              'set still works');
    });

    test('a discovered endpoint is admitted only after the compiled set is '
        'exhausted, and only one per launch', () {
      final gate = RecoveryBeaconGate(compiledGateways: compiled);
      gate.adoptDiscoveredEndpoints(const <String>[
        'https://gw-alpha.example',
        'https://gw-bravo.example',
      ]);
      var now = DateTime.utc(2026, 8, 6, 12);
      expect(gate.plannedGatewayOrder(now), compiled);

      // Drive every compiled endpoint to blocked.
      for (var i = 0; i < 3; i++) {
        gate.recordGatewaySweepFailure(
          now: now,
          observation: BootstrapObservation.tlsResetAfterClientHello,
          control: ControlProbeOutcome.reachable,
        );
        now = now.add(const Duration(minutes: 1));
      }

      final order = gate.plannedGatewayOrder(now);
      expect(order, contains('https://gw-alpha.example'));
      expect(order, isNot(contains('https://gw-bravo.example')),
          reason: 'one new endpoint per launch -- a false positive must cost '
              'exactly one host, not the whole reserve');
      expect(gate.discoveryRequired(now), isFalse,
          reason: 'a discovered endpoint is available, so no NEW record is '
              'needed yet');
    });

    test('with nothing discovered, an exhausted sweep still asks for a record',
        () {
      final gate = RecoveryBeaconGate(compiledGateways: compiled);
      var now = DateTime.utc(2026, 8, 6, 12);
      for (var i = 0; i < 3; i++) {
        gate.recordGatewaySweepFailure(
          now: now,
          observation: BootstrapObservation.tlsResetAfterClientHello,
          control: ControlProbeOutcome.reachable,
        );
        now = now.add(const Duration(minutes: 1));
      }
      expect(gate.discoveryRequired(now), isTrue);
    });

    test('adopting an endpoint already in the compiled set is a no-op', () {
      final gate = RecoveryBeaconGate(compiledGateways: compiled);
      gate.adoptDiscoveredEndpoints(const <String>['https://gw-two.example']);
      expect(gate.discoveredGateways, isEmpty);
    });

    test('discovered endpoints survive a network-scope change', () {
      // EndpointHealth is scoped because reachability is a property of the
      // path; a signed record is not. Changing Wi-Fi must not discard the
      // owner's statement about where the control plane lives.
      final gate = RecoveryBeaconGate(compiledGateways: compiled);
      gate.adoptDiscoveredEndpoints(const <String>['https://gw-alpha.example']);
      gate.recordGatewaySuccess(
        gateway: compiled.first,
        now: DateTime.utc(2026, 8, 6, 12),
        networkScope: 'wifi-a',
      );
      gate.recordGatewaySuccess(
        gateway: compiled.first,
        now: DateTime.utc(2026, 8, 6, 13),
        networkScope: 'cell-b',
      );
      expect(gate.discoveredGateways, <String>['https://gw-alpha.example']);
    });

    test('a full round trip: paste, persist, restore, sweep', () async {
      final intake = DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys));
      final outcome = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      expect(outcome.accepted, isTrue);

      // Persist -> restore, as the settings file would.
      final persisted = jsonDecode(jsonEncode(outcome.state.toSettings()))
          as Map<String, dynamic>;
      final restored = DiscoveryIntakeState.restore(persisted);
      expect(restored.seqFloor, 10);
      expect(restored.endpoints, outcome.state.endpoints);

      final gate = RecoveryBeaconGate(compiledGateways: compiled);
      gate.adoptDiscoveredEndpoints(discoveredEndpointsForSweep(
        compiledEndpoints: gate.compiledGateways,
        discovered: restored.endpoints,
      ));
      expect(gate.discoveredGateways, <String>[
        'https://gw-alpha.example',
        'https://gw-bravo.example',
      ]);

      // And the retained record plus the floor both survive the round trip.
      final again = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: restored,
      );
      expect(again.status, DiscoveryIntakeStatus.alreadyHeld);
      final stale = await _makeRecord(seed: kSeedD3, sequence: 2);
      final replay = await intake.acceptPastedRecord(
        stale,
        now: kVectorNow,
        current: restored,
      );
      expect(replay.status, DiscoveryIntakeStatus.replayed);
    });
  });

  group('in-tunnel pre-positioning', () {
    late DiscoveryIntake intake;

    setUp(() {
      intake = DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys));
    });

    test('a served record is verified and applied exactly like a pasted one',
        () async {
      final served = await intake.ingestPrePositionedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      final pasted = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      expect(served.accepted, isTrue);
      expect(served.source, DiscoveryIntakeSource.prePositioned);
      expect(pasted.source, DiscoveryIntakeSource.pasteIn);
      // Byte-identical outcomes: transport bought the record nothing.
      expect(served.state.seqFloor, pasted.state.seqFloor);
      expect(served.state.endpoints, pasted.state.endpoints);
      expect(served.state.rawRecords, pasted.state.rawRecords);
    });

    test('NO SHORTCUT: a forged served record is refused like a forged paste',
        () async {
      // The hub is modelled as seizable. A seized hub that could inject
      // endpoints merely by serving them would defeat the point of signing.
      for (final bad in <String>[
        kRecordSignedByAnnouncementKey,
        kRecordSignedUnderAnnouncementDomain,
        kRecordTrailingPipeMistake,
      ]) {
        final outcome = await intake.ingestPrePositionedRecord(
          bad,
          now: kVectorNow,
          current: const DiscoveryIntakeState(),
        );
        expect(outcome.accepted, isFalse, reason: bad);
        expect(outcome.status, DiscoveryIntakeStatus.badSignature,
            reason: bad);
        expect(outcome.state.endpoints, isEmpty, reason: bad);
        expect(outcome.state.rawRecords, isEmpty, reason: bad);
      }
    });

    test('it respects the sequence floor exactly as paste-in does', () async {
      final first = await intake.ingestPrePositionedRecord(
        kRecordOpensslD2, // seq 10
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      final older = await _makeRecord(seed: kSeedD1, sequence: 4);
      final outcome = await intake.ingestPrePositionedRecord(
        older,
        now: kVectorNow,
        current: first.state,
      );
      expect(outcome.status, DiscoveryIntakeStatus.replayed);
      expect(outcome.state.seqFloor, 10);
    });

    test('IDEMPOTENT: serving the same record on every poll is a silent no-op',
        () async {
      var state = const DiscoveryIntakeState();
      final outcomes = <DiscoveryIntakeOutcome>[];
      for (var poll = 0; poll < 5; poll++) {
        final outcome = await intake.ingestPrePositionedRecord(
          kRecordOpensslD2,
          now: kVectorNow,
          current: state,
        );
        outcomes.add(outcome);
        state = outcome.state;
      }
      expect(outcomes.first.status, DiscoveryIntakeStatus.accepted);
      for (final later in outcomes.skip(1)) {
        expect(later.status, DiscoveryIntakeStatus.alreadyHeld);
        // Same object, so a caller that persists unconditionally rewrites
        // exactly what was there -- and nothing is logged.
        expect(identical(later.state, state), isTrue);
      }
      expect(state.seqFloor, 10);
      expect(state.rawRecords, <String>[kRecordOpensslD2]);
    });

    test('ADDITIVE: pre-positioning and paste-in compose in either order',
        () async {
      final servedFirst = await intake.ingestPrePositionedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      final laterRecord =
          await _makeRecord(seed: kSeedD3, sequence: 11, hosts: 'gw-c.example');
      final thenPasted = await intake.acceptPastedRecord(
        laterRecord,
        now: kVectorNow,
        current: servedFirst.state,
      );
      expect(thenPasted.accepted, isTrue);
      expect(thenPasted.state.seqFloor, 11);
      expect(thenPasted.state.rawRecords,
          <String>[laterRecord, kRecordOpensslD2]);
      expect(await intake.endpointsForUse(thenPasted.state, now: kVectorNow),
          containsAll(<String>[
            'https://gw-c.example',
            'https://gw-alpha.example',
          ]));
    });

    test('retention is capped and drops the oldest record', () async {
      var state = const DiscoveryIntakeState();
      final records = <String>[];
      for (var seq = 10; seq <= 13; seq++) {
        final record = await _makeRecord(
            seed: kSeedD1, sequence: seq, hosts: 'gw-$seq.example');
        records.add(record);
        state = (await intake.ingestPrePositionedRecord(record,
                now: kVectorNow, current: state))
            .state;
      }
      expect(state.rawRecords.length, kMaxRetainedDiscoveryRecords);
      expect(state.rawRecords.first, records.last);
      expect(state.rawRecords, isNot(contains(records.first)));
    });
  });

  group('storage is not a trust boundary (verify at use)', () {
    late DiscoveryIntake intake;

    setUp(() {
      intake = DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys));
    });

    test('a tampered stored record contributes no endpoints', () async {
      final accepted = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      expect(await intake.endpointsForUse(accepted.state, now: kVectorNow),
          isNotEmpty);

      // Someone edits vpn_settings.txt to point at their own host, keeping the
      // signature that used to be valid.
      final tampered = DiscoveryIntakeState(
        seqFloor: accepted.state.seqFloor,
        endpoints: const <String>['https://attacker.example'],
        acceptedSequence: accepted.state.acceptedSequence,
        rawRecords: <String>[
          accepted.state.rawRecords.single
              .replaceAll('gw-alpha.example', 'attacker.example'),
        ],
      );
      expect(await intake.endpointsForUse(tampered, now: kVectorNow), isEmpty,
          reason: 'a tampered store must inject nothing at all');
    });

    test('the persisted endpoint list alone can never steer the sweep',
        () async {
      // No raw record at all, but a fully-populated endpoint cache.
      const forged = DiscoveryIntakeState(
        seqFloor: 10,
        endpoints: <String>['https://attacker.example'],
        acceptedSequence: 10,
      );
      expect(await intake.endpointsForUse(forged, now: kVectorNow), isEmpty);
    });

    test('an expired stored record stops steering', () async {
      final accepted = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      // Same state, read eight days later: the record has aged out, which is
      // what bounds a key compromise and makes rotation tempo load-bearing.
      final later = kVectorNow.add(const Duration(days: 8));
      expect(await intake.endpointsForUse(accepted.state, now: later), isEmpty);
      expect(await intake.endpointsForUse(accepted.state, now: kVectorNow),
          isNotEmpty);
    });

    test('a record signed by a key this build lacks stops steering', () async {
      final accepted = await intake.acceptPastedRecord(
        kRecordOpensslD3,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      final narrowed =
          DiscoveryIntake(_verifierWith(const <String, String>{'d1': kPubD1}));
      expect(await narrowed.endpointsForUse(accepted.state, now: kVectorNow),
          isEmpty);
    });

    test('the round trip through settings preserves the raw records', () async {
      final accepted = await intake.acceptPastedRecord(
        kRecordOpensslD2,
        now: kVectorNow,
        current: const DiscoveryIntakeState(),
      );
      final persisted = jsonDecode(jsonEncode(accepted.state.toSettings()))
          as Map<String, dynamic>;
      final restored = DiscoveryIntakeState.restore(persisted);
      expect(restored.rawRecords, <String>[kRecordOpensslD2]);
      expect(await intake.endpointsForUse(restored, now: kVectorNow), <String>[
        'https://gw-alpha.example',
        'https://gw-bravo.example',
      ]);
    });
  });

  group('the paste-in box, as the user meets it', () {
    Future<List<DiscoveryIntakeOutcome>> pump(
      WidgetTester tester, {
      required DiscoveryIntake intake,
      DiscoveryIntakeState state = const DiscoveryIntakeState(),
    }) async {
      final accepted = <DiscoveryIntakeOutcome>[];
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: DiscoveryPasteInSheet(
            intake: intake,
            currentState: state,
            now: () => kVectorNow,
            onAccepted: (outcome) async => accepted.add(outcome),
          ),
        ),
      ));
      return accepted;
    }

    testWidgets('pasting a good code accepts it and tells the user',
        (tester) async {
      final accepted = await pump(tester,
          intake: DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys)));

      await tester.enterText(find.byType(TextField), kRecordOpensslD2);
      await tester.tap(find.text('Apply'));
      await tester.pumpAndSettle();

      expect(accepted, hasLength(1));
      expect(accepted.single.state.seqFloor, 10);
      expect(find.textContaining('2 new server addresses'), findsOneWidget);
      // The field is cleared so the same code is not accidentally re-applied.
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        isEmpty,
      );
    });

    testWidgets('a bad code is refused, explained, and changes nothing',
        (tester) async {
      final accepted = await pump(tester,
          intake: DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys)));

      await tester.enterText(find.byType(TextField), kRecordTrailingPipeMistake);
      await tester.tap(find.text('Apply'));
      await tester.pumpAndSettle();

      expect(accepted, isEmpty);
      expect(find.textContaining('could not be verified'), findsOneWidget);
    });

    testWidgets('the failure is diagnosable on demand, not shouted',
        (tester) async {
      await pump(tester,
          intake: DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys)));

      await tester.enterText(find.byType(TextField), kRecordTrailingPipeMistake);
      await tester.tap(find.text('Apply'));
      await tester.pumpAndSettle();

      // Hidden until asked for...
      expect(find.textContaining('noKeyAccepted'), findsNothing);
      await tester.tap(find.text('Details'));
      await tester.pumpAndSettle();
      // ...then specific enough to debug over a messaging app.
      expect(find.textContaining('noKeyAccepted'), findsOneWidget);
    });

    testWidgets('a build with no keys disables the box and says why',
        (tester) async {
      await pump(tester,
          intake: DiscoveryIntake(_verifierWith(const <String, String>{})));

      expect(find.textContaining('not available in this build'), findsOneWidget);
      expect(tester.widget<TextField>(find.byType(TextField)).enabled, isFalse);
      final apply = tester.widget<FilledButton>(find.byType(FilledButton));
      expect(apply.onPressed, isNull);
    });

    testWidgets('pasting the same code twice is refused the second time',
        (tester) async {
      final accepted = await pump(tester,
          intake: DiscoveryIntake(_verifierWith(_allThreeDiscoveryKeys)));

      for (var i = 0; i < 2; i++) {
        await tester.enterText(find.byType(TextField), kRecordOpensslD2);
        await tester.tap(find.text('Apply'));
        await tester.pumpAndSettle();
      }

      expect(accepted, hasLength(1), reason: 'accepted exactly once');
      expect(find.textContaining('already has that code'), findsOneWidget);
    });
  });
}
