import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/camouflage_policy.dart';

void main() {
  final mainSource = File('lib/main.dart').readAsStringSync();
  final manifest =
      File('android/app/src/main/AndroidManifest.xml').readAsStringSync();

  test('mobile first frame is neutral until activation state is restored', () {
    expect(
        calculatorCoversFirstFrame('android', DeviceFormFactor.phone), isTrue);
    expect(calculatorCoversFirstFrame('ios', DeviceFormFactor.phone), isTrue);
    // L91: the flag is backed by decoy_cover.dart's decoyCoverActive (the
    // root navigator's route guard reads it), so the first-frame value is set
    // first thing in initState, before any build.
    expect(
      mainSource,
      contains('  void initState() {\n    super.initState();\n'
          '    _showDecoyCalculator = calculatorCoversFirstFrame('),
    );
    expect(mainSource,
        contains('  bool get _showDecoyCalculator => decoyCoverActive;'));
    expect(
      mainSource,
      contains('if (_supportsInAppCamouflage &&\n        (activatedLocally || await _camouflageLatched() != false))'),
    );
  });

  test('confirmed asynchronous tunnel loss re-arms calculator camouflage', () {
    final reconcileStart =
        mainSource.indexOf('Future<void> _reconcileNativeTunnelState(');
    final helperStart = mainSource.indexOf(
      'void _armCalculatorAfterConfirmedDisconnect()',
      reconcileStart,
    );
    expect(reconcileStart, greaterThanOrEqualTo(0));
    expect(helperStart, greaterThan(reconcileStart));
    final reconcile = mainSource.substring(reconcileStart, helperStart);
    expect(reconcile, contains('_armCalculatorAfterConfirmedDisconnect();'));
  });

  test('new activation no longer enrolls recovery or duress', () {
    final activationEnd = mainSource.indexOf(
      'Future<bool> _refreshFreeVpnConfig(',
    );
    final activationStart = mainSource.lastIndexOf(
      'Future<',
      activationEnd - 1,
    );
    expect(activationStart, greaterThanOrEqualTo(0));
    final activation = mainSource.substring(activationStart, activationEnd);
    expect(activation, isNot(contains('_issueAndShowRecoveryCode()')));
    expect(activation, isNot(contains('_promptDuressEnrollment(')));
    expect(activation, contains('await _latchCamouflage();'));
    expect(activation, contains('_showDecoyCalculator = true'));
    expect(kRecoveryUnlockEnabled, isFalse);
    expect(supportsDuress('android', DeviceFormFactor.phone), isFalse);
    expect(supportsDuress('ios', DeviceFormFactor.phone), isFalse);
  });

  test('Android release manifest requests no SMS permission', () {
    expect(manifest, isNot(contains('android.permission.SEND_SMS')));
    final native = File(
      'android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt',
    ).readAsStringSync();
    expect(native, contains('private fun isSendSmsDeclared(): Boolean'));
    expect(native, contains('PackageManager.GET_PERMISSIONS'));
    expect(native, contains('private fun canOfferDuressSms(): Boolean'));
    expect(native, contains('!canOfferDuressSms() -> result.success(false)'));
    expect(native, contains('"can_offer_sms" to canOfferDuressSms()'));
    expect(mainSource, contains("cap['can_offer_sms'] == true"));
  });
}
