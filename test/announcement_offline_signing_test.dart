import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/announcement_signature.dart';

/// IA-CP-06, app side (Fable 5.1 ruling 2026-09-29): announcements are now
/// signed OFFLINE by `tools/winn3_sign_announcement.py` (lane FX-KEYS-HUB,
/// sha256 2ece8da039060b0d389c89661264fc27afa880a59d09c2d0f0113ea0c2dc1705)
/// and the hub serves the uploaded envelope verbatim. The client verifier is
/// unchanged; this pins that it accepts exactly what that tool emits, under
/// each of the a1..a3 slots, and still enforces the sequence floor.
///
/// Every envelope below is REAL tool output: three throwaway Ed25519 keys
/// (`openssl genpkey -algorithm ED25519`), then
/// `winn3_sign_announcement.py sign --key aN.pem --kid aN --seq S --iat T
/// --text ...`, which signs with `openssl pkeyutl -sign -rawin` and
/// self-verifies before printing. The throwaway private keys were deleted.
const _a1 = 'eCLOYxrA/SjgfcwqcXWmxqSq/kmzTN36yJ1Ew8AZb3Q=';
const _a2 = '5h32Il3i5AKmpqQ5xeMYjF8jrvhjdi++dWywbU4EHFk=';
const _a3 = 'gwJrrhkzstsnkV3gTf/DpvC8P5n6QdezXulF0Vd1CpA=';

/// a1, seq 5, non-ASCII text: the tool serialises with ensure_ascii=False,
/// so these payload bytes carry raw UTF-8 and must verify byte for byte.
const _signedA1Seq5 = <String, String>{
  'payload':
      'eyJpYXQiOjE3OTAwMDAwMDAsImtpZCI6ImExIiwic2VxIjo1LCJ0ZXh0Ijoi4YCd4YCE4YC64YC4VlBOOiBzZXJ2aWNlIG5vdGUsIGNhZsOpIn0=',
  'sig':
      'SHmdeL1+jUmxnjVPxeF0ecxfhCDDP09Ra/1d3Rlsbw81kKUW2z8sjcUcTZ5F1Q7jUD3I+ZKmbSPbNfUPqvcPAw==',
};
const _signedA2Seq6 = <String, String>{
  'payload':
      'eyJpYXQiOjE3OTAwMDAxMDAsImtpZCI6ImEyIiwic2VxIjo2LCJ0ZXh0IjoiUm90YXRlZCB0byBhMi4ifQ==',
  'sig':
      'IBcBto0yguuFoVnaHoQyN0uERqXaZIAv+WWhExr3HGJWRWDr3+4eDeyj2LmwPKYVgVErT5jDhgwCMcqek06QBQ==',
};
const _signedA3Seq7 = <String, String>{
  'payload':
      'eyJpYXQiOjE3OTAwMDAyMDAsImtpZCI6ImEzIiwic2VxIjo3LCJ0ZXh0IjoiUm90YXRlZCB0byBhMy4ifQ==',
  'sig':
      'GtMmvqLKG0C88L8KA3OOecurE+sjcYKJRoR8te0BviIZM67nO52VeXlLtAGKhOc4xFPIdBCZ74Ioa4YiyNMJAg==',
};

/// Signed with the a1 PRIVATE key but labelled `kid: a2`: the key the hub
/// would check it under is a2's, so it must not verify.
const _a1KeyLabelledA2Seq8 = <String, String>{
  'payload':
      'eyJpYXQiOjE3OTAwMDAzMDAsImtpZCI6ImEyIiwic2VxIjo4LCJ0ZXh0IjoiYTEga2V5IGxhYmVsbGVkIGEyIn0=',
  'sig':
      'ujx51DzvVvYzEE0PxoKi8PIAcCmr2qWD8uOIEaZoB8eqAPi9BQBFV3OjrqwABVRqEDbSVl2wdeYQ28IixAxQDw==',
};

void main() {
  final verifier = AnnouncementVerifier(compiledAnnouncementTrustedKeys(
    isReleaseBuild: true,
    defines: const <String, String>{'a1': _a1, 'a2': _a2, 'a3': _a3},
  ));

  Future<AnnouncementVerification> verify(Map<String, String> envelope,
          {int floor = 0}) =>
      verifier.verify(
        <String, dynamic>{'announcement_signed': envelope},
        minimumSequence: floor,
      );

  test('the tool output verifies under a1, a2 and a3', () async {
    final a1 = await verify(_signedA1Seq5);
    expect(a1.rejection, isNull);
    expect(a1.envelope!.keyId, 'a1');
    expect(a1.envelope!.sequence, 5);
    expect(a1.envelope!.text, 'ဝင်းVPN: service note, café');
    expect(a1.envelope!.issuedAt.toUtc().millisecondsSinceEpoch,
        1790000000 * 1000);

    final a2 = await verify(_signedA2Seq6);
    expect(a2.envelope?.keyId, 'a2', reason: '${a2.rejection}');
    final a3 = await verify(_signedA3Seq7);
    expect(a3.envelope?.keyId, 'a3', reason: '${a3.rejection}');
  });

  test('the sequence floor still holds for offline-signed envelopes', () async {
    // Equal to the floor passes: the same envelope arrives on all four routes.
    expect((await verify(_signedA2Seq6, floor: 6)).accepted, isTrue);
    expect((await verify(_signedA3Seq7, floor: 6)).accepted, isTrue);
    expect((await verify(_signedA1Seq5, floor: 6)).rejection,
        AnnouncementRejection.replayedSequence);
  });

  test('a signature under the wrong slot is refused', () async {
    expect((await verify(_a1KeyLabelledA2Seq8)).rejection,
        AnnouncementRejection.badSignature);
  });

  test('a ring that predates a slot refuses that slot by name', () async {
    final oldRing = AnnouncementVerifier(compiledAnnouncementTrustedKeys(
      isReleaseBuild: true,
      defines: const <String, String>{'a1': _a1},
    ));
    final result = await oldRing.verify(
      <String, dynamic>{'announcement_signed': _signedA3Seq7},
      minimumSequence: 0,
    );
    expect(result.rejection, AnnouncementRejection.unknownKeyId);
  });

  test('one altered payload byte breaks the signature', () async {
    final bytes = base64.decode(_signedA2Seq6['payload']!);
    final tampered = List<int>.from(bytes);
    final index = utf8.decode(bytes).indexOf('a2.');
    tampered[index] = 'b'.codeUnitAt(0);
    expect(
        (await verify(<String, String>{
          'payload': base64.encode(tampered),
          'sig': _signedA2Seq6['sig']!,
        }))
            .rejection,
        AnnouncementRejection.badSignature);
  });
}
