import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/local_security.dart';

void main() {
  group('duressPinPolicyRejectionReason', () {
    const realSix = '730914';

    test('accepts a strong six-digit code distinct from the main code', () {
      expect(duressPinPolicyRejectionReason(realSix, '042073'), isNull);
    });

    test('rejects a duress code equal to the main code', () {
      final reason = duressPinPolicyRejectionReason(realSix, realSix);
      expect(reason, isNotNull);
      expect(reason, contains('different'));
    });

    test('rejects a trivially guessable duress code', () {
      expect(duressPinPolicyRejectionReason(realSix, '123456'), isNotNull);
      expect(duressPinPolicyRejectionReason(realSix, '000000'), isNotNull);
    });

    test('rejects a duress code of the wrong length', () {
      expect(duressPinPolicyRejectionReason(realSix, '0420'), isNotNull);
      expect(duressPinPolicyRejectionReason(realSix, '04207'), isNotNull);
    });

    test('requires the main code to be six digits first (legacy must upgrade)',
        () {
      // A 4-digit legacy main code cannot have a duress code created beside it
      // until it is upgraded to six -- the two must share a length.
      final reason = duressPinPolicyRejectionReason('0420', '042073');
      expect(reason, isNotNull);
      expect(reason, contains('6-digit'));
    });

    test('no rejection message names a VPN, tunnel, or panic feature', () {
      final messages = <String?>[
        duressPinPolicyRejectionReason(realSix, realSix),
        duressPinPolicyRejectionReason(realSix, '123456'),
        duressPinPolicyRejectionReason(realSix, '0420'),
        duressPinPolicyRejectionReason('0420', '042073'),
      ];
      for (final message in messages) {
        expect(message, isNotNull);
        final lower = message!.toLowerCase();
        expect(lower, isNot(contains('vpn')));
        expect(lower, isNot(contains('tunnel')));
        expect(lower, isNot(contains('panic')));
        expect(lower, isNot(contains('duress')));
        expect(lower, isNot(contains('emergency')));
      }
    });
  });
}
