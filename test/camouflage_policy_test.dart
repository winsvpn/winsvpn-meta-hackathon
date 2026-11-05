import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/camouflage_policy.dart';

void main() {
  test('in-app calculator camouflage includes iPhone and iPad through iOS', () {
    expect(supportsInAppCalculatorCamouflage('android', DeviceFormFactor.phone), isTrue);
    expect(supportsInAppCalculatorCamouflage('ios', DeviceFormFactor.phone), isTrue);
    expect(supportsInAppCalculatorCamouflage('macos', DeviceFormFactor.phone), isFalse);
    expect(supportsInAppCalculatorCamouflage('windows', DeviceFormFactor.phone), isFalse);
    expect(supportsInAppCalculatorCamouflage('linux', DeviceFormFactor.phone), isFalse);
  });

  test('TV form factor is never camouflaged, phone still is', () {
    // This test would FAIL before the TV gate: android on TV returned true
    // because Platform.operatingSystem is still 'android' on Android TV,
    // so the decoy armed and the user was permanently locked out (no focus
    // handling on the calculator keys). After the fix TV must be false for
    // all three predicates while phone stays true.
    expect(supportsInAppCalculatorCamouflage('android', DeviceFormFactor.tv), isFalse);
    expect(supportsInAppCalculatorCamouflage('ios', DeviceFormFactor.tv), isFalse);
    expect(supportsLauncherIconCamouflage('android', DeviceFormFactor.tv), isFalse);
    expect(supportsLauncherIconCamouflage('ios', DeviceFormFactor.tv), isFalse);
    expect(supportsDuress('android', DeviceFormFactor.tv), isFalse);
    expect(supportsDuress('ios', DeviceFormFactor.tv), isFalse);

    // Phone camouflage remains enabled, while duress is retired everywhere.
    expect(supportsInAppCalculatorCamouflage('android', DeviceFormFactor.phone), isTrue);
    expect(supportsInAppCalculatorCamouflage('ios', DeviceFormFactor.phone), isTrue);
    expect(supportsLauncherIconCamouflage('android', DeviceFormFactor.phone), isTrue);
    expect(supportsLauncherIconCamouflage('ios', DeviceFormFactor.phone), isTrue);
    expect(supportsDuress('android', DeviceFormFactor.phone), isFalse);
    expect(supportsDuress('ios', DeviceFormFactor.phone), isFalse);
  });

  test('duress is retired on every platform and form factor', () {
    for (final platform in const <String>[
      'android',
      'ios',
      'macos',
      'windows',
      'linux',
    ]) {
      expect(
        supportsDuress(platform, DeviceFormFactor.phone),
        isFalse,
        reason: platform,
      );
    }
    for (final platform in const <String>[
      'android',
      'ios',
    ]) {
      expect(supportsDuress(platform, DeviceFormFactor.tv), isFalse);
    }
  });

  test('phone builds cover the first frame while activation state loads', () {
    expect(calculatorCoversFirstFrame('android', DeviceFormFactor.phone), isTrue);
    expect(calculatorCoversFirstFrame('ios', DeviceFormFactor.phone), isTrue);
    expect(calculatorCoversFirstFrame('android', DeviceFormFactor.tv), isFalse);
    expect(calculatorCoversFirstFrame('macos', DeviceFormFactor.phone), isFalse);
  });

  test('offline recovery unlock is retired', () {
    expect(kRecoveryUnlockEnabled, isFalse);
  });

  test('launcher icon camouflage includes Android, iPhone, and iPad', () {
    expect(supportsLauncherIconCamouflage('android', DeviceFormFactor.phone), isTrue);
    expect(supportsLauncherIconCamouflage('ios', DeviceFormFactor.phone), isTrue);
    expect(supportsLauncherIconCamouflage('macos', DeviceFormFactor.phone), isFalse);
    // TV never launcher-camouflaged either.
    expect(supportsLauncherIconCamouflage('android', DeviceFormFactor.tv), isFalse);
    expect(supportsLauncherIconCamouflage('ios', DeviceFormFactor.tv), isFalse);
  });

  test('calculator PIN entry preserves leading zeroes and resets by attempt',
      () {
    final entry = CalculatorPinEntry();

    for (var index = 0; index < kCamouflagePinLength - 1; index++) {
      expect(entry.addDigit('0'), isEmpty);
    }
    expect(entry.addDigit('0'), '0' * kCamouflagePinLength);

    expect(entry.addDigit('1'), isEmpty);
    expect(entry.addDigit('2'), isEmpty);
    entry.reset();
    expect(entry.addDigit('3'), isEmpty);
    expect(entry.addDigit('4'), isEmpty);
    expect(entry.addDigit('5'), isEmpty);
    expect(entry.addDigit('6'), isEmpty);
    expect(entry.addDigit('7'), isEmpty);
    expect(entry.addDigit('8'), '345678');
  });

  test('an install enrolled at the legacy length still fires at four digits',
      () {
    final entry = CalculatorPinEntry(pinLength: kLegacyCamouflagePinLength);

    expect(entry.pinLength, kLegacyCamouflagePinLength);
    expect(entry.addDigit('0'), isEmpty);
    expect(entry.addDigit('4'), isEmpty);
    expect(entry.addDigit('2'), isEmpty);
    expect(entry.addDigit('0'), '0420');
  });

  test('only the two supported lengths are accepted, and switching clears the '
      'partly-typed window', () {
    final entry = CalculatorPinEntry(pinLength: 5);
    expect(entry.pinLength, kCamouflagePinLength);

    entry.addDigit('1');
    entry.addDigit('2');
    entry.pinLength = kLegacyCamouflagePinLength;
    expect(entry.addDigit('7'), isEmpty);
    expect(entry.addDigit('3'), isEmpty);
    expect(entry.addDigit('0'), isEmpty);
    expect(entry.addDigit('9'), '7309');
  });

  group('longer-credential terminator', () {
    test('with no credential enrolled, "=" never produces a candidate', () {
      final entry = CalculatorPinEntry();

      for (final digit in '4815162342'.split('')) {
        entry.addDigit(digit);
      }
      // This is the property that keeps ordinary arithmetic on the decoy
      // from spending anti-brute-force throttle failures.
      expect(entry.submit(), isEmpty);
    });

    test('"=" hands over the whole entry at exactly the enrolled length', () {
      final entry = CalculatorPinEntry(recoveryLength: 10);

      for (final digit in '4815162342'.split('')) {
        entry.addDigit(digit);
      }
      expect(entry.submit(), '4815162342');
    });

    test('a wrong-length entry produces nothing, so "=" during arithmetic '
        'stays free', () {
      final entry = CalculatorPinEntry(recoveryLength: 10);

      for (final digit in '481516'.split('')) {
        entry.addDigit(digit);
      }
      expect(entry.submit(), isEmpty);
    });

    test('"=" clears both buffers even when it produces no candidate', () {
      final entry = CalculatorPinEntry(recoveryLength: 10);

      entry.addDigit('4');
      entry.addDigit('8');
      expect(entry.submit(), isEmpty);
      expect(entry.addDigit('7'), isEmpty);
      expect(entry.addDigit('3'), isEmpty);
      expect(entry.addDigit('0'), isEmpty);
      expect(entry.addDigit('9'), isEmpty);
      expect(entry.addDigit('1'), isEmpty);
      expect(entry.addDigit('4'), '730914');
    });

    test('the long entry keeps accumulating after the PIN candidate fires',
        () {
      final entry = CalculatorPinEntry(recoveryLength: 12);

      // Six digits in, a PIN candidate is offered; the long buffer keeps
      // collecting so the full credential still reaches submit().
      expect(entry.addDigit('7'), isEmpty);
      expect(entry.addDigit('3'), isEmpty);
      expect(entry.addDigit('0'), isEmpty);
      expect(entry.addDigit('9'), isEmpty);
      expect(entry.addDigit('1'), isEmpty);
      expect(entry.addDigit('4'), '730914');
      for (final digit in '250836'.split('')) {
        entry.addDigit(digit);
      }
      expect(entry.submit(), '730914250836');
    });

    // This is a throttle-budget property, not a cosmetic one. Every PIN
    // candidate produced costs one anti-brute-force failure, so a 16-digit
    // recovery code that fired a candidate at digit 6 and again at digit 12
    // would burn three failures per attempt out of a budget of five.
    test('exactly one PIN candidate is offered per entry session', () {
      final entry =
          CalculatorPinEntry(recoveryLength: kRecoveryCodeLength);

      var candidates = 0;
      for (final digit in '7309142508361479'.split('')) {
        if (entry.addDigit(digit).isNotEmpty) candidates += 1;
      }
      expect(candidates, 1);
      expect(entry.submit(), '7309142508361479');
    });

    test('clearing starts a new session, so a PIN can be retried', () {
      final entry = CalculatorPinEntry();

      for (final digit in '111117'.split('')) {
        entry.addDigit(digit);
      }
      // No further candidate without a clear...
      for (final digit in '730914'.split('')) {
        expect(entry.addDigit(digit), isEmpty);
      }
      // ...and one again immediately after.
      entry.reset();
      expect(entry.addDigit('7'), isEmpty);
      expect(entry.addDigit('3'), isEmpty);
      expect(entry.addDigit('0'), isEmpty);
      expect(entry.addDigit('9'), isEmpty);
      expect(entry.addDigit('1'), isEmpty);
      expect(entry.addDigit('4'), '730914');
    });

    test('backspace corrects a typo and allows PIN candidate production', () {
      final entry = CalculatorPinEntry();

      expect(entry.addDigit('1'), isEmpty);
      expect(entry.addDigit('4'), isEmpty);
      expect(entry.addDigit('3'), isEmpty); // typo: 143
      entry.backspace(); // delete 3 -> 14
      expect(entry.addDigit('2'), isEmpty); // 142
      expect(entry.addDigit('5'), isEmpty); // 1425
      expect(entry.addDigit('3'), isEmpty); // 14253
      expect(entry.addDigit('6'), '142536'); // completes 142536!
    });

    test('submit with fallback matching pin length yields candidate', () {
      final entry = CalculatorPinEntry();
      expect(entry.submit(fallbackValue: '142536'), '142536');
      expect(entry.submit(fallbackValue: '123'), isEmpty);
    });

    test('buffered entry is bounded so a long arithmetic session cannot grow '
        'without limit', () {
      final entry = CalculatorPinEntry(recoveryLength: 200);

      for (var index = 0; index < 200; index++) {
        entry.addDigit('7');
      }
      expect(entry.submit(), isEmpty);
    });
  });

  group('camouflage surface policy helpers', () {
    // These tests cover pure predicates and text transformation.
    // They do not prove native surface anonymity or production enforcement.
    // The OS badge is not ours to remove: Android/iOS draw a status-bar VPN
    // icon the moment any tunnel runs, whether or not the in-app disguise is
    // up. These tests pin the OTHER half of the property -- that the app's
    // own surface never does the identifying.
    test('the OS draws a VPN badge only where a status-bar exists and the '
        'in-app disguise is supported', () {
      expect(osDrawsVpnBadge('android', DeviceFormFactor.phone), isTrue);
      expect(osDrawsVpnBadge('ios', DeviceFormFactor.phone), isTrue);
      // The disguise cannot arm on TV, and desktop OSes draw no badge.
      expect(osDrawsVpnBadge('android', DeviceFormFactor.tv), isFalse);
      expect(osDrawsVpnBadge('ios', DeviceFormFactor.tv), isFalse);
      expect(osDrawsVpnBadge('macos', DeviceFormFactor.phone), isFalse);
      expect(osDrawsVpnBadge('windows', DeviceFormFactor.phone), isFalse);
      expect(osDrawsVpnBadge('linux', DeviceFormFactor.phone), isFalse);
    });

    test('a surface that names the app as a VPN is flagged', () {
      expect(camouflageSurfaceCarriesVpnIdentity('winsvpn_tun.log'), isTrue);
      expect(camouflageSurfaceCarriesVpnIdentity('capture.decoy.state'), isTrue);
      expect(camouflageSurfaceCarriesVpnIdentity('WIRE.VPN.status'), isTrue);
      // An innocent calculator surface keeps its word and is NOT flagged --
      // this is the negative half, so the matcher cannot be vacuous.
      expect(camouflageSurfaceCarriesVpnIdentity('calc_prefs.json'), isFalse);
      expect(camouflageSurfaceCarriesVpnIdentity('0.0.0.0:443'), isFalse);
    });

    // The helper removes forbidden tokens from a synthetic string.
    test('the text helper removes synthetic VPN-app identity tokens', () {
      // What an examiner could read off the app's own tunnel surface if it
      // were allowed to name itself. Every token is in
      // kCamouflageSurfaceForbiddenTokens.
      const hostilePacket =
          'src=10.0.0.5 dst=203.0.113.9 sport=49321 dport=443 flags=ACK '
          'payload=1400 app=WinsVPN transport=stealth tun=tun0 '
          'account=winn-user proxy=relay';

      final enforced =
          camouflageSurfaceWithoutVpnIdentity(hostilePacket);

      // The enforcement must have removed a real identity (not a no-op).
      expect(enforced, isNot(equals(hostilePacket)));
      // And after enforcement no forbidden token survives anywhere.
      expect(camouflageSurfaceCarriesVpnIdentity(enforced), isFalse,
          reason: 'after enforcement the hostile packet still leaked: '
              '"$enforced"');
    });

    // This checks the synthetic input before transformation.
    test('an UNenforced hostile packet still leaks the VPN-app identity', () {
      const hostilePacket =
          'src=10.0.0.5 dst=203.0.113.9 sport=49321 dport=443 app=WinsVPN '
          'transport=stealth tun=tun0';

      // Before enforcement the surface DOES name the app -- this is what the
      // cleaner exists to remove, so a cleaner that strips nothing (or that
      // returns the empty string for everything) cannot pass silently.
      expect(camouflageSurfaceCarriesVpnIdentity(hostilePacket), isTrue);
    });

    test('the enforcement applies exactly where the badge and the disguise '
        'both hold', () {
      // Phone on Android/iOS: badge drawn AND decoy supports -> enforce.
      expect(
          camouflageSurfaceMustStayAnonymous(
              'android', DeviceFormFactor.phone),
          isTrue);
      expect(
          camouflageSurfaceMustStayAnonymous('ios', DeviceFormFactor.phone),
          isTrue);
      // Desktop shows no badge -> nothing heightened to defend.
      expect(
          camouflageSurfaceMustStayAnonymous('macos', DeviceFormFactor.phone),
          isFalse);
      // TV: badge clause already refuses, no decoy anyway.
      expect(
          camouflageSurfaceMustStayAnonymous('android', DeviceFormFactor.tv),
          isFalse);
    });

    // Cross-check: the durable latch that keeps the disguise alive across a
    // duress wipe must itself carry no VPN-app identity, else the survivor
    // becomes the tell it exists to avoid.
    test('the camouflage latch never names the app as a VPN', () {
      expect(camouflageSurfaceCarriesVpnIdentity(kCamouflageLatchFileName),
          isFalse);
      final latchText = kCamouflageLatchContents.values.join(' ');
      expect(camouflageSurfaceCarriesVpnIdentity(latchText), isFalse);
    });

    test('constantTimePinEquals verifies PIN strings with constant-time evaluation', () {
      expect(constantTimePinEquals('142536', '142536'), isTrue);
      expect(constantTimePinEquals('142536', '142537'), isFalse);
      expect(constantTimePinEquals('142536', '14253'), isFalse);
      expect(constantTimePinEquals('142536', '1425367'), isFalse);
      expect(constantTimePinEquals('', ''), isTrue);
      expect(constantTimePinEquals('', '1'), isFalse);
    });
  });
}
