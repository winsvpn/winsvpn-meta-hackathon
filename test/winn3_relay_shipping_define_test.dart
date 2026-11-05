import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Relay twin of `winn3_shipping_define_test.dart`.
///
/// A plain `flutter test` runs the fail-closed branch: with no relay define no
/// platform advertises the relay capability. A release producer's define is
/// exercised per platform with, for example:
///
///   flutter test test/winn3_relay_shipping_define_test.dart \
///     --dart-define=WINS_WINN3_ENABLED_PLATFORMS=linux \
///     --dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux \
///     --dart-define=WINS_TEST_EXPECTED_WINN3_PLATFORM=linux
void main() {
  const expectedPlatform = String.fromEnvironment(
    'WINS_TEST_EXPECTED_WINN3_PLATFORM',
    defaultValue: '',
  );
  const relayDefine = String.fromEnvironment(
    'WINS_WINN3_RELAY_ENABLED_PLATFORMS',
    defaultValue: '',
  );
  final failClosed = relayDefine.isEmpty;
  final platforms = kWinn3StandaloneReleasePlatforms.toList()..sort();

  bool advertises(
    String platform, {
    bool supportsWinn3 = true,
    bool supportsWinn3Descriptor = true,
    bool suppressed = false,
  }) =>
      winnClientAdvertisesRelay(
        operatingSystem: platform,
        supportsWinn3: supportsWinn3,
        supportsWinn3Descriptor: supportsWinn3Descriptor,
        suppressed: suppressed,
      );

  test('relay define enables exactly the intended platform', () {
    if (failClosed) {
      expect(winn3RelayBuildEnabledPlatforms(), isEmpty);
      for (final platform in platforms) {
        expect(advertises(platform), isFalse, reason: 'platform=$platform');
      }
      return;
    }
    expect(expectedPlatform, isNotEmpty);
    expect(winn3RelayBuildEnabledPlatforms(), <String>{expectedPlatform});
    expect(advertises(expectedPlatform), isTrue);
    for (final platform in platforms) {
      if (platform == expectedPlatform) continue;
      expect(advertises(platform), isFalse, reason: 'platform=$platform');
    }
  });

  test('relay capability needs the standalone host, the ring and no failure',
      () {
    if (failClosed) return;
    expect(advertises(expectedPlatform, supportsWinn3: false), isFalse);
    expect(advertises(expectedPlatform, supportsWinn3Descriptor: false),
        isFalse);
    expect(advertises(expectedPlatform, suppressed: true), isFalse);
    expect(
      winnClientRelayCapabilityFlags(
        operatingSystem: expectedPlatform,
        supportsWinn3: true,
        supportsWinn3Descriptor: true,
      ),
      <String, bool>{kWinnClientCapabilityRelay: true},
    );
    expect(
      winnClientRelayCapabilityFlags(
        operatingSystem: expectedPlatform,
        supportsWinn3: false,
        supportsWinn3Descriptor: true,
      ),
      isEmpty,
    );
  });
}
