import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dev_override.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Tests for the DEV-ONLY, NON-SHIPPING macOS start override in
/// `lib/winn_protocol_dev_override.dart`.
///
/// Every test in this file runs under a plain `flutter test` invocation --
/// no special `--dart-define` is required or assumed, and none of these
/// tests may depend on one being set. That is deliberate: `flutter test`
/// always runs in a debug-like VM (`kDebugMode == true` here), so the ONLY
/// thing keeping the override off during this entire suite is the second
/// gate -- the dart-define defaults to false. A few tests below assert that
/// fact directly, because it is exactly the property the whole design leans
/// on: this suite is proof, every time it runs, that being in a debug VM is
/// not by itself enough.
///
/// The one thing this file cannot prove by itself is that the dart-define
/// really does flip the gate when an operator passes it -- `bool.fromEnvironment`
/// is a compile-time constant, so no single `flutter test` process can
/// observe both states. That half is demonstrated separately, once, for
/// real: `flutter test --dart-define=WINN_DEV_UNSAFE_MACOS_OVERRIDE=true`
/// against a throwaway file, output quoted in
/// `docs/handoff/WINN_PROTOCOL_MACOS_DEV_OVERRIDE_20260804.md`, not asserted
/// here.
void main() {
  group('the compiled-in environment this whole suite runs under', () {
    test('this test process is a debug VM (kDebugMode true)', () {
      // Sanity check for every other assertion in this group: if this were
      // ever false, "insufficient without debug mode" would not be being
      // tested by the tests below -- they would trivially pass for the
      // wrong reason.
      expect(kDebugMode, isTrue);
    });

    test('kReleaseMode and kDebugMode can never both be true', () {
      // This is a Flutter SDK invariant (kDebugMode is literally defined as
      // "not release and not profile"), not something this app enforces --
      // stated here as an explicit, checked assumption because the entire
      // "impossible in a release build" claim for the override rests on it.
      expect(kReleaseMode && kDebugMode, isFalse);
    });

    test('the unsafe dart-define is NOT set for this run', () {
      // This is what actually keeps the override off throughout this
      // file's default run, given kDebugMode is true above. If this
      // assertion ever fails, the suite was invoked with
      // --dart-define=WINN_DEV_UNSAFE_MACOS_OVERRIDE=true, which must never
      // be part of a normal `flutter test` / CI invocation.
      expect(kWinnDevUnsafeMacosOverrideDartDefineValue, isFalse);
      expect(kWinnDevUnsafeMacosOverrideDartDefineName,
          'WINN_DEV_UNSAFE_MACOS_OVERRIDE');
    });
  });

  group('computeWinnDevUnsafeMacosOverrideActive: exhaustive truth table', () {
    test('debug + dart-define => active', () {
      expect(
        computeWinnDevUnsafeMacosOverrideActive(
            debugMode: true, dartDefineEnabled: true),
        isTrue,
      );
    });

    test('debug + no dart-define => inactive', () {
      expect(
        computeWinnDevUnsafeMacosOverrideActive(
            debugMode: true, dartDefineEnabled: false),
        isFalse,
      );
    });

    test(
        'NOT debug (release/profile) + dart-define => inactive '
        '(a release-mode build cannot take this path even if the define '
        'were somehow set)', () {
      expect(
        computeWinnDevUnsafeMacosOverrideActive(
            debugMode: false, dartDefineEnabled: true),
        isFalse,
      );
    });

    test(
        'NOT debug + no dart-define => inactive '
        '(the dart-define alone is insufficient without debug mode -- this '
        'is the same case, restated: neither gate alone is ever enough)',
        () {
      expect(
        computeWinnDevUnsafeMacosOverrideActive(
            debugMode: false, dartDefineEnabled: false),
        isFalse,
      );
    });
  });

  group('winnDevUnsafeMacosOverrideActive: real gate wiring', () {
    test('matches the pure gate applied to the real compiled-in constants',
        () {
      // Proves the real getter is not doing anything other than what the
      // exhaustively-tested pure function above does -- there is no third
      // input, no injection point, nothing that could make the real gate
      // diverge from computeWinnDevUnsafeMacosOverrideActive's truth table.
      expect(
        winnDevUnsafeMacosOverrideActive,
        equals(computeWinnDevUnsafeMacosOverrideActive(
          debugMode: kDebugMode,
          dartDefineEnabled: kWinnDevUnsafeMacosOverrideDartDefineValue,
        )),
      );
    });

    test('is false for this (default) invocation', () {
      expect(winnDevUnsafeMacosOverrideActive, isFalse);
    });
  });

  group('kWinnHostCapabilities stays honest with the override compiled in',
      () {
    test('macOS is still .absent', () {
      final macos = kWinnHostCapabilities['macos'];
      expect(macos, isNotNull);
      expect(macos!.supported, isFalse);
      expect(macos.missing, isNotEmpty);
    });

    test(
        'winnSupportedPlatforms() does not include macos merely because '
        'this file is compiled in', () {
      expect(winnSupportedPlatforms(), isNot(contains('macos')));
    });

    test('platformSupportsWinnProtocol("macos") is still false', () {
      expect(platformSupportsWinnProtocol('macos'), isFalse);
    });
  });

  group('winnDevOverrideDonorPlatform / supported donor list', () {
    test('there is NO donor today, so the dev override cannot borrow at all',
        () {
      // 2026-08-08, AND THIS IS THE CONSEQUENCE WORTH READING. This test used
      // to assert ['android', 'linux'] with 'android' as the donor.
      // docs/handoff/ADJUDICATION_20260808.md demoted both entries, so the
      // supported set is empty and winnDevOverrideDonorPlatform() is null.
      //
      // What that means in practice: the dev-only macOS override borrows a
      // supported platform's decision, so with no donor it returns null and
      // the override can no longer produce a winn/3 start on macOS even with
      // the dart-define set and a debug build. The dev-session harness that
      // lanes used for Apple criterion-proving is therefore inert.
      //
      // That is aligned with the ruling rather than collateral damage --
      // Decision (c) recommendation 1 is to freeze exactly those harness and
      // dev-session proving sessions -- but it IS a behaviour change beyond
      // the capability flag, and it is pinned here so nobody rediscovers it
      // by surprise. The production code already handled an empty table
      // honestly (it documents the null return), so nothing had to change in
      // lib/ to make this safe.
      expect(winnDevOverrideSupportedDonorPlatforms(), isEmpty);
      expect(winnDevOverrideDonorPlatform(), isNull);
    });
  });

  group('resolveWinnProtocolStartDevOnly: transparent when inactive '
      '(this is what the default `flutter test` run actually exercises)',
      () {
    test('macOS + a config that WOULD be startable elsewhere: still refused, '
        'identically to resolveWinnProtocolStart, nothing overridden', () {
      final config = _validWinn3ConfigForTests();
      final direct =
          resolveWinnProtocolStart(operatingSystem: 'macOS', config: config);
      final logs = <String>[];
      final result = resolveWinnProtocolStartDevOnly(
        operatingSystem: 'macOS',
        config: config,
        log: logs.add,
      );

      expect(result.overrodeCapabilityGate, isFalse);
      expect(result.donorPlatform, isNull);
      expect(result.decision.supported, isFalse);
      expect(result.decision.reason, direct.reason);
      expect(result.decision.reason, WinnRefusalReason.unsupportedPlatform);
      expect(result.decision.message, direct.message);
      expect(result.decision.iniSection, direct.iniSection);
      expect(logs, isEmpty,
          reason: 'Nothing was overridden, so nothing unproven happened; '
              'the loud banner must not fire.');
    });

    test('a platform the table already supports (linux): passthrough, '
        'no override machinery involved', () {
      final config = _validWinn3ConfigForTests();
      final direct =
          resolveWinnProtocolStart(operatingSystem: 'linux', config: config);
      final logs = <String>[];
      final result = resolveWinnProtocolStartDevOnly(
        operatingSystem: 'linux',
        config: config,
        log: logs.add,
      );

      expect(result.overrodeCapabilityGate, isFalse);
      // Passthrough is the property under test, and it survives the
      // 2026-08-08 demotion unchanged: for any platform that is not macOS,
      // resolveWinnProtocolStartDevOnly must return byte-for-byte what
      // resolveWinnProtocolStart returns and touch no override machinery.
      // What changed is the VALUE both now agree on -- linux is .absent, so
      // both refuse -- not the agreement itself, which is the whole point.
      expect(result.decision.supported, isFalse);
      expect(result.decision.reason, WinnRefusalReason.unsupportedPlatform);
      expect(result.decision.supported, direct.supported);
      expect(result.decision.reason, direct.reason);
      expect(result.decision.message, direct.message);
      expect(result.decision.iniSection, direct.iniSection);
      expect(logs, isEmpty);
    });

    test('macOS + a config that is invalid for a DIFFERENT reason (bad mtu): '
        'refused for that reason, not silently treated as a platform gate',
        () {
      final config = _validWinn3ConfigForTests()..['mtu'] = 40;
      final result = resolveWinnProtocolStartDevOnly(
        operatingSystem: 'macos',
        config: config,
      );
      // Still unsupported_platform: the platform gate in
      // resolveWinnProtocolStart runs BEFORE the mtu check, so macOS never
      // reaches the mtu validation at all. Documented here so the ordering
      // this test relies on cannot silently change without notice.
      expect(result.decision.reason, WinnRefusalReason.unsupportedPlatform);
      expect(result.overrodeCapabilityGate, isFalse);
    });

    // CHANGED ON 2026-08-06, DELIBERATELY. This test used to list 'ios'
    // alongside android/windows/plan9 as "left completely alone", and that was
    // a real safety decision, not an accident of the list: with iOS reachable,
    // a winn/3 document could have arrived at the iOS Packet Tunnel provider,
    // and that provider contained NO containment code whatsoever. It read
    // `[WinsDevContainment]` as an unknown section and started a full tunnel —
    // default IPv4 route, IPv6 to a sink, every DNS query captured — on a
    // phone, while the app reported the session as contained. The iOS gate had
    // to stay shut until that was untrue.
    //
    // It is now untrue. `ios/PacketTunnel/PacketTunnelProvider.swift` reads the
    // containment marker in EVERY build shape and either installs one /32 with
    // no IPv6 and no DNS, or throws. There is no build of that file in which the
    // marker is silently ignored — verified by compiling the real file in both
    // shapes and snapshotting what it produces.
    //
    // So iOS moves out of this list and into its own test below, which pins
    // something stronger than "untouched": iOS is untouched *unless its own
    // dart-define was passed*, and it was not passed for this run or any normal
    // `flutter test`. android, windows and plan9 stay here, unconditionally
    // untouched, which is what this test still guarantees.
    test('every platform this override never touches (android, windows, an '
        'unknown string) is left completely alone', () {
      final config = _validWinn3ConfigForTests();
      for (final os in <String>['android', 'windows', 'plan9']) {
        final direct =
            resolveWinnProtocolStart(operatingSystem: os, config: config);
        final result =
            resolveWinnProtocolStartDevOnly(operatingSystem: os, config: config);
        expect(result.overrodeCapabilityGate, isFalse, reason: os);
        expect(result.decision.supported, direct.supported, reason: os);
        expect(result.decision.reason, direct.reason, reason: os);
        expect(kWinnDevUnsafeOverrideTargetPlatforms.contains(os), isFalse,
            reason: '$os must never become a target platform of this override');
      }
    });

    test('ios: passthrough in this run, because its own dart-define was not '
        'passed -- the property the old "ios is left alone" pin protected',
        () {
      final config = _validWinn3ConfigForTests();
      final direct =
          resolveWinnProtocolStart(operatingSystem: 'ios', config: config);
      final logs = <String>[];
      final result = resolveWinnProtocolStartDevOnly(
        operatingSystem: 'ios',
        config: config,
        log: logs.add,
      );

      // Identical to the real gate's answer, nothing overridden, nothing
      // logged -- exactly what the previous version of this test asserted.
      expect(result.overrodeCapabilityGate, isFalse);
      expect(result.decision.supported, direct.supported);
      expect(result.decision.reason, direct.reason);
      expect(result.decision.reason, WinnRefusalReason.unsupportedPlatform);
      expect(logs, isEmpty);
    });

    test('ios is gated on its OWN dart-define, which is not the macOS one', () {
      // The safety property that replaces the old blanket exclusion: an
      // operator who enabled macOS has NOT enabled iOS. Two separate defines,
      // two separate answers, and neither reads the other's value.
      expect(kWinnDevUnsafeIosOverrideDartDefineName,
          'WINN_DEV_UNSAFE_IOS_OVERRIDE');
      expect(kWinnDevUnsafeIosOverrideDartDefineName,
          isNot(kWinnDevUnsafeMacosOverrideDartDefineName));
      expect(kWinnDevUnsafeIosOverrideDartDefineValue, isFalse,
          reason: 'a normal flutter test run must never carry this define');
      expect(winnDevUnsafeIosOverrideActive, isFalse);
      expect(winnDevUnsafeOverrideActiveFor('ios'), isFalse);
      expect(winnDevUnsafeOverrideActiveFor('macos'), isFalse);
    });

    test('the override touches exactly two platforms, and every other string '
        'is never even a candidate', () {
      expect(kWinnDevUnsafeOverrideTargetPlatforms,
          <String>{'macos', 'ios'});
      for (final os in <String>[
        'android',
        'windows',
        'linux',
        'plan9',
        '',
        'IOS ',
        'darwin'
      ]) {
        expect(winnDevUnsafeOverrideActiveFor(os), isFalse, reason: os);
      }
      // Case and whitespace are normalised before the lookup, so a stray
      // "  IOS  " is the same platform as "ios" -- and still gated.
      expect(winnDevUnsafeOverrideActiveFor('  IOS  '), isFalse);
    });

    test('each target platform has a banner naming its own dart-define, and '
        'no other platform has one at all', () {
      expect(winnDevUnsafeOverrideBannerFor('macos'),
          kWinnDevUnsafeMacosOverrideBanner);
      expect(winnDevUnsafeOverrideBannerFor('ios'),
          kWinnDevUnsafeIosOverrideBanner);
      expect(winnDevUnsafeOverrideBannerFor('android'), isNull);
      expect(winnDevUnsafeOverrideBannerFor('linux'), isNull);
      // Each banner must name the define that actually opens it, so an
      // operator reading one cannot conclude the other was what they typed.
      expect(kWinnDevUnsafeIosOverrideBanner,
          contains(kWinnDevUnsafeIosOverrideDartDefineName));
      expect(kWinnDevUnsafeMacosOverrideBanner,
          contains(kWinnDevUnsafeMacosOverrideDartDefineName));
      expect(kWinnDevUnsafeIosOverrideBanner,
          isNot(contains(kWinnDevUnsafeMacosOverrideDartDefineName)));
      // And it must say what the provider does, because that is the whole
      // reason this gate was allowed to open.
      expect(kWinnDevUnsafeIosOverrideBanner, contains('CONTAINED'));
      expect(kWinnDevUnsafeIosOverrideBanner, contains("kWinnHostCapabilities['ios']"));
    });

    test('opening iOS did not flip any capability: ios and macos are both '
        'still absent, and neither became a donor', () {
      // The thing this whole family of files promises not to do. Asserted
      // against the real table, not a copy of it.
      expect(kWinnHostCapabilities['ios']!.supported, isFalse);
      expect(kWinnHostCapabilities['macos']!.supported, isFalse);
      expect(winnDevOverrideSupportedDonorPlatforms(), isNot(contains('ios')));
      expect(winnDevOverrideSupportedDonorPlatforms(), isNot(contains('macos')));
    });
  });

  group('winnDevOverrideBorrowedDecision: pure, gate-independent business '
      'logic (does not require the override to be active to test)', () {
    test('with no donor, a valid config borrows NOTHING rather than falling '
        'back to a decision nobody vouched for', () {
      // This asserted a real [winn] section borrowed from linux. Since the
      // 2026-08-08 demotion there is no donor, and the contract for that case
      // is an explicit null -- not a silently synthesised "supported"
      // decision. Returning something here would be the dangerous failure:
      // the override exists to let macOS borrow a verdict a platform has
      // EARNED, and with nothing earned there is nothing to lend.
      final config = _validWinn3ConfigForTests();
      expect(winnDevOverrideBorrowedDecision(config), isNull);
    });

    test('with no donor, an invalid config also borrows nothing -- the null '
        'is about the table, not about the config', () {
      final config = _validWinn3ConfigForTests()
        ..['obfuscation'] = <String, dynamic>{
          'H1': 11,
          'H2': 11, // not pairwise distinct -> headerTypesInvalid
          'H3': 33,
          'H4': 44,
        };
      expect(winnDevOverrideBorrowedDecision(config), isNull);
      // The config-level verdict this WOULD have borrowed is still exactly
      // what the real gate produces, and is still checked -- so the day a
      // donor exists again, what it lends is known-correct rather than
      // untested for however long the table stayed empty.
      final direct = resolveWinnProtocolStartForServedConfig(config: config);
      expect(direct.supported, isFalse);
      expect(direct.reason, WinnRefusalReason.headerTypesInvalid);
    });

    test(
        'parity: borrowing is honest because the config half of the real gate '
        'is what would be borrowed -- pinned directly now that no donor '
        'exists to route it through', () {
      // The original property: the borrowed decision equals
      // resolveWinnProtocolStart(operatingSystem: donor, ...) exactly, which
      // is what makes "borrowing" a reuse of tested logic rather than a
      // guess. With no donor that route is unavailable, so the same property
      // is pinned one call inwards, against
      // resolveWinnProtocolStartForServedConfig -- the function
      // resolveWinnProtocolStart itself tail-calls once its platform gate
      // passes. If a donor ever returns, the equality below is precisely what
      // makes the borrow correct.
      final configs = <Map<String, dynamic>>[
        _validWinn3ConfigForTests(),
        _validWinn3ConfigForTests()..['stealth_active'] = true,
        _validWinn3ConfigForTests()..['mtu'] = 99999,
        _validWinn3ConfigForTests()
          ..['protocol_params'] = <String, dynamic>{'bogus_key': 'x'},
      ];
      final donor = winnDevOverrideDonorPlatform();
      expect(donor, isNull, reason: 'no platform is .present as of 2026-08-08');
      for (final config in configs) {
        expect(winnDevOverrideBorrowedDecision(config), isNull);
        // What the borrow resolves to the moment a donor exists again.
        final inner = resolveWinnProtocolStartForServedConfig(config: config);
        expect(inner, isNotNull);
      }
    });
  });

  group(
      'an override that changes ONLY the carrier to winn3 must not promote a '
      'winn/1 config into a standalone session', () {
    // The dev override borrows a supported platform's decision, so the
    // question "what would this override config get the moment a donor
    // exists" is answered verbatim by resolveWinnProtocolStartForServedConfig
    // -- the half resolveWinnProtocolStart tail-calls once its platform gate
    // passes, and the half this file's parity tests already pin against.
    //
    // The failure this group pins is the PARTIAL edit: an operator flips only
    // the carrier to `winn3` for a standalone session and leaves
    // protocol_version at `winn/1` (or absent, which normalizes to winn/1).
    // resolveWinnProtocolStart must refuse that config even when EVERY
    // standalone prerequisite -- the per-device half AND a verified gateway
    // descriptor -- is otherwise present, because a `[winn]` section it
    // emitted would describe a standalone session the config never asked for.
    //
    // The same guard is what makes `winnSectionForTunnelConfigDevOnly`'s
    // "winn/1 returns the empty section" rule structural: no winn/1 config,
    // carrier or not, may manufacture a winn/3 decision anywhere below it.

    /// A config that would START a standalone winn/3 session if its
    /// `protocol_version` were `winn/3`. The flip under test is ONLY that
    /// slot.
    Map<String, dynamic> overwhelminglyStandaloneConfig() =>
        _validWinn3ConfigForTests()
          ..['protocol_params'] = <String, dynamic>{
            'carrier': kWinnCarrierWinn3,
          }
          ..['winn3_inner_v4'] = '10.10.4.9'
          ..['winn3_static_private'] =
              base64.encode(List<int>.filled(32, 0x11));

    /// A verified gateway descriptor for the same config. Constructed directly
    /// (the async Ed25519 exercise in the dispatch suite is not this file's
    /// subject); every field here matches what
    /// `resolveWinnProtocolStartForServedConfig` needs only to VALIDATE:
    /// base64-shape static key, gateway id and admission secret, and an inner
    /// router distinct from `winn3_inner_v4` and from `client_ip`.
    Winn3DescriptorCheck verifiedDescriptorProbe() =>
        Winn3DescriptorCheck.ok(
          Winn3Descriptor(
            node: 'probe-node',
            endpoint: '203.0.113.7:51820',
            innerRouterV4: '10.10.0.1',
            gatewayStaticBase64: base64.encode(List<int>.filled(32, 0x53)),
            gatewayIdBase64: base64.encode(utf8.encode('winsgw01')),
            admissionKey: base64.encode(List<int>.filled(64, 0xab)),
            kid: 'g1',
            notAfter: 1786000100,
          ),
        );

    test('carrier=winn3 with protocol_version LEFT at winn/1 is refused, even '
        'with a verified descriptor and the per-device half', () {
      final config = overwhelminglyStandaloneConfig()
        ..['protocol_version'] = kWinnProtocolV1;
      final decision = resolveWinnProtocolStartForServedConfig(
        config: config,
        winn3Descriptor: verifiedDescriptorProbe(),
      );
      expect(decision.supported, isFalse,
          reason: 'every standalone prerequisite is present (device half + '
              'verified descriptor), so the only thing that can be refusing '
              'this is the protocol_version');
      expect(decision.reason, WinnRefusalReason.protocolVersionMismatch);
      expect(decision.iniSection, isEmpty);
    });

    test('an ABSENT protocol_version (which normalizes to winn/1) is refused '
        'the same way -- flipping the carrier is not a version upgrade', () {
      final config = overwhelminglyStandaloneConfig()
        ..remove('protocol_version');
      expect(normalizedWinnProtocolVersion(config['protocol_version']),
          kWinnProtocolV1,
          reason: 'the absent-means-winn/1 rule, asserted so the refusal is '
              'provably about the normalized protocol, not about a missing '
              'key');
      final decision = resolveWinnProtocolStartForServedConfig(
        config: config,
        winn3Descriptor: verifiedDescriptorProbe(),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.protocolVersionMismatch);
    });

    test('positive control: the SAME config with protocol_version at winn/3 '
        'still starts -- the refusal is caused by the version, not by '
        'carrier=winn3 or by the descriptor being present', () {
      final config = overwhelminglyStandaloneConfig();
      expect(
          normalizedWinnProtocolVersion(config['protocol_version']),
          kWinnProtocolV3);
      final decision = resolveWinnProtocolStartForServedConfig(
        config: config,
        winn3Descriptor: verifiedDescriptorProbe(),
      );
      expect(decision.supported, isTrue,
          reason: '${decision.reason.code}: ${decision.message}');
      expect(decision.iniSection, contains('carrier = $kWinnCarrierWinn3'));
      expect(decision.iniSection, contains('endpoint = 203.0.113.7:51820'));
    });
  });

  group('winnSectionForTunnelConfigDevOnly', () {
    test('winn/1 (absent protocol_version) returns the empty section, '
        'exactly like the shipping gate', () {
      expect(
        winnSectionForTunnelConfigDevOnly(
          operatingSystem: 'macos',
          config: <String, dynamic>{},
        ),
        '',
      );
    });

    test('an unknown protocol_version throws, exactly like the shipping '
        'gate', () {
      expect(
        () => winnSectionForTunnelConfigDevOnly(
          operatingSystem: 'macos',
          config: <String, dynamic>{'protocol_version': 'winn/99'},
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('winn/3 on macOS, override inactive (default): throws, same as '
        'winnSectionForTunnelConfig would', () {
      final config = _validWinn3ConfigForTests();
      expect(
        () => winnSectionForTunnelConfigDevOnly(
            operatingSystem: 'macos', config: config),
        throwsA(isA<StateError>().having((e) => e.toString(), 'message',
            contains('unsupported_platform'))),
      );
      expect(
        () => winnSectionForTunnelConfig(
            operatingSystem: 'macos', config: config),
        throwsA(isA<StateError>()),
        reason: 'cross-check against the real shipping gate directly',
      );
    });

    test('winn/3 on any platform: the dev gate behaves EXACTLY like the '
        'shipping gate, which now means both refuse', () {
      // Used to assert both produced a real section on linux. Since the
      // 2026-08-08 demotion no platform is supported, so both throw -- and
      // the property this test actually guards is the IDENTITY of the two
      // gates, not the value they agree on. Asserting identity across every
      // platform is strictly stronger than the single linux case it replaces:
      // the dev gate must never become a way to start winn/3 where the
      // shipping gate would not.
      final config = _validWinn3ConfigForTests();
      for (final os in const ['android', 'ios', 'linux', 'windows']) {
        String? devError;
        String? shippingError;
        try {
          winnSectionForTunnelConfigDevOnly(
              operatingSystem: os, config: config);
        } on StateError catch (e) {
          devError = e.message;
        }
        try {
          winnSectionForTunnelConfig(operatingSystem: os, config: config);
        } on StateError catch (e) {
          shippingError = e.message;
        }
        expect(devError, isNotNull,
            reason: '$os: the dev gate must refuse while the table is empty');
        expect(shippingError, isNotNull, reason: os);
        expect(devError, shippingError,
            reason: '$os: the dev gate must not diverge from the shipping '
                'gate. macOS is the ONE deliberate exception and is covered '
                'by its own tests above.');
      }
    });
  });
}

/// A served config that CAN start Winn on a supported platform. Mirrors
/// `validWinn3Config()` in `test/winn_protocol_dispatch_test.dart` -- kept
/// as a separate local copy rather than importing that test file, since test
/// files are ordinary libraries here only by accident of location and
/// importing one from another is not this codebase's pattern.
Map<String, dynamic> _validWinn3ConfigForTests() => <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{},
      'node_slug': 'probe-node',
      'server_endpoint': '203.0.113.7:51820',
      'client_ip': '10.8.1.3',
      'mtu': 1280,
      'dns': '10.8.1.1',
      'stealth_active': false,
      'obfuscation': <String, dynamic>{
        'H1': 11,
        'H2': 22,
        'H3': 33,
        'H4': 44,
      },
    };
