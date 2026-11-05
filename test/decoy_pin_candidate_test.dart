import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/camouflage_policy.dart';

void main() {
  test('a bare six-digit display is a candidate', () {
    expect(decoyPinCandidateFromDisplay('123456', 6), '123456');
  });
  test('digits spread across an expression are not a candidate', () {
    expect(decoyPinCandidateFromDisplay('12+3456', 6), '');
    expect(decoyPinCandidateFromDisplay('1×23456', 6), '');
  });
  test('the current operand alone decides', () {
    expect(decoyPinCandidateFromDisplay('7×123456', 6), '123456');
    expect(decoyPinCandidateFromDisplay('7×1234567', 6), '');
  });
}
