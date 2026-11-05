// CORE-7 (Claude-core-T9-1): an unreadable credential store must not end the
// consent gate with an unhandled error, and must not reach the branded
// consent dialog on a platform that carries the calculator disguise.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('a failed PIN read in the consent gate arms the decoy, never the dialog',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('  Future<void> _initializePrivacyConsentGate() async {');
    final end = source.indexOf('  Future<void> _armCamouflageBeforeConsent() async {');
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final gate = source.substring(start, end);
    const guarded = '    String? storedPin;\n'
        '    try {\n'
        "      storedPin = await _readSensitiveText('user_pin.txt');\n"
        '    } catch (_) {\n'
        '      if (_supportsInAppCamouflage) return _armCamouflageBeforeConsent();\n'
        '    }\n';
    expect(gate, contains(guarded));
    expect(gate, isNot(contains("final storedPin = await _readSensitiveText('user_pin.txt');")));
    expect(gate.indexOf(guarded),
        lessThan(gate.indexOf('_showPrivacyPolicyDialog(requireConsent: true)')));
  });
}
