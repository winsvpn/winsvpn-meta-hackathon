import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Dual-auth hub capability advertisement. The hub serves both attestation
/// public keys only to a client that sent supports_winn3_dualauth as an
/// explicit true. This file pins what this build may honestly send.
void main() {
  test('the advertised flag is exactly supports_winn3_dualauth', () {
    expect(kWinnClientCapabilityDualAuth, 'supports_winn3_dualauth');
  });

  test('unsupported iOS, macOS, Linux, and Windows clients advertise false',
      () {
    for (final os in const <String>['ios', 'macos', 'linux', 'windows']) {
      final flags = winnClientCapabilities(
        operatingSystem: os,
        spaKeyProvisioned: true,
        descriptorRingCarried: true,
        dualAuthHostSupported: true,
      );
      expect(
        flags[kWinnClientCapabilityDualAuth],
        isFalse,
        reason: '$os: kWinnHostCapabilities is .absent, so even an injected '
            'dual-auth define must not advertise true. A second, inline OS '
            'list would drift from the table.',
      );
      expect(
        winnClientCapabilities(
          operatingSystem: os,
          spaKeyProvisioned: true,
        )[kWinnClientCapabilityDualAuth],
        isFalse,
        reason: '$os: the shipping define is default-off.',
      );
    }
  });

  test('an Android release that actually consumes both keys may advertise true',
      () {
    final androidRelease = winnClientCapabilityFlags(
      hostCanCarryWinn3: true,
      spaKeyProvisioned: true,
      descriptorRingCarried: true,
      dualAuthHostSupported: true,
    );
    expect(androidRelease[kWinnClientCapabilityDualAuth], isTrue);
    expect(androidRelease['supports_winn3'], isTrue);
    expect(androidRelease['supports_winn3_descriptor'], isTrue);

    expect(
      winnClientCapabilityFlags(
        hostCanCarryWinn3: true,
        spaKeyProvisioned: true,
        descriptorRingCarried: true,
        dualAuthHostSupported: false,
      )[kWinnClientCapabilityDualAuth],
      isFalse,
      reason: 'a build that does not emit both keys must advertise false.',
    );
    expect(
      winnClientCapabilityFlags(
        hostCanCarryWinn3: true,
        spaKeyProvisioned: true,
        descriptorRingCarried: false,
        dualAuthHostSupported: true,
      )[kWinnClientCapabilityDualAuth],
      isFalse,
      reason: 'dual-auth keys ride the signed descriptor.',
    );
    expect(
      winnClientCapabilityFlags(
        hostCanCarryWinn3: false,
        spaKeyProvisioned: true,
        descriptorRingCarried: true,
        dualAuthHostSupported: true,
      )[kWinnClientCapabilityDualAuth],
      isFalse,
      reason: 'no datapath, no dual-auth advertisement.',
    );
  });

  test('the compiled define is default-off, so unit tests advertise false', () {
    expect(kWinn3DualAuthHostSupported, isFalse);
    for (final os in const <String>[
      'android',
      'ios',
      'macos',
      'linux',
      'windows',
    ]) {
      expect(
        winnClientCapabilities(
          operatingSystem: os,
          spaKeyProvisioned: true,
          descriptorRingCarried: true,
        )[kWinnClientCapabilityDualAuth],
        isFalse,
        reason: os,
      );
    }
  });
}
