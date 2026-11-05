import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

void main() {
  const expectedPlatform = String.fromEnvironment(
    'WINS_TEST_EXPECTED_WINN3_PLATFORM',
    defaultValue: '',
  );

  const shippingDefine = String.fromEnvironment(
    'WINS_WINN3_ENABLED_PLATFORMS',
    defaultValue: '',
  );

  final failClosed = shippingDefine.isEmpty;

  Map<String, dynamic> config({String? carrier}) => <String, dynamic>{
        'protocol_version': kWinnProtocolV3,
        'protocol_params': <String, dynamic>{
          if (carrier != null) 'carrier': carrier,
        },
        'server_endpoint': '203.0.113.7:51820',
        'client_ip': '10.8.1.3',
        'mtu': 1280,
        'dns': '10.8.1.1',
        'stealth_active': false,
      };

  test('shipping define enables exactly the intended standalone platform', () {
    if (failClosed) {
      expect(winn3BuildEnabledPlatforms(), isEmpty);
      for (final platform in <String>[
        'android',
        'ios',
        'macos',
        'windows',
        'linux',
      ]) {
        expect(platformSupportsWinnProtocol(platform), isFalse,
            reason: 'platform=$platform');
      }
      return;
    }
    expect(expectedPlatform, isNotEmpty);
    expect(winn3BuildEnabledPlatforms(), <String>{expectedPlatform});
    expect(platformSupportsWinnProtocol(expectedPlatform), isTrue);
  });

  test('shipping build refuses every retired relay carrier', () {
    for (final carrier in <String?>[
      null,
      kWinnCarrierDirectAwg,
      kWinnCarrierHttp3,
      kWinnCarrierHttp2,
    ]) {
      // On the merits, independent of the build define: the served-config
      // resolver must refuse the retired relay carriers by name so a plain
      // `flutter test` still exercises the refusal this file is about.
      final merits = resolveWinnProtocolStartForServedConfig(
        config: config(carrier: carrier),
      );
      expect(merits.supported, isFalse, reason: 'merits carrier=$carrier');
      expect(merits.iniSection, isEmpty, reason: 'merits carrier=$carrier');
      final decision = resolveWinnProtocolStart(
        operatingSystem: expectedPlatform,
        config: config(carrier: carrier),
      );
      expect(decision.supported, isFalse, reason: 'carrier=$carrier');
      expect(
        decision.reason,
        failClosed
            ? WinnRefusalReason.unsupportedPlatform
            : WinnRefusalReason.carrierUnsupported,
        reason: 'carrier=$carrier',
      );
      expect(decision.iniSection, isEmpty);
    }
  });

  test('standalone carrier cannot bypass descriptor verification', () {
    final merits = resolveWinnProtocolStartForServedConfig(
      config: config(carrier: kWinnCarrierWinn3),
    );
    expect(merits.supported, isFalse);
    expect(merits.reason, WinnRefusalReason.winn3DescriptorUnverified,
        reason: 'exercised without any build define');
    expect(merits.iniSection, isEmpty);
    final decision = resolveWinnProtocolStart(
      operatingSystem: expectedPlatform,
      config: config(carrier: kWinnCarrierWinn3),
    );
    expect(decision.supported, isFalse);
    expect(
      decision.reason,
      failClosed
          ? WinnRefusalReason.unsupportedPlatform
          : WinnRefusalReason.winn3DescriptorUnverified,
    );
    expect(decision.iniSection, isEmpty);
  });
}
