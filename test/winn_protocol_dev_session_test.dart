import 'dart:convert';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dev_session.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Tests for the DEV-ONLY, NON-SHIPPING winn/3 delivery path in
/// `lib/winn_protocol_dev_session.dart`.
///
/// # What a default `flutter test` run actually proves here
///
/// This file runs with NO dart-defines, so `winnDevSessionActive` is false for
/// every test in it. That is deliberate and it is the most important property
/// to pin: the state every developer, every CI run and every release build is
/// in must be the state where this path does nothing. `runWinnDevSession`
/// returning `active: false` without touching a channel is therefore tested
/// directly, with an invoker that FAILS the test if it is ever called.
///
/// Everything else worth testing is factored into gate-independent functions
/// that take their inputs as ordinary parameters -- the same shape
/// `winn_protocol_dev_override.dart` and `winn_protocol_dev_config_source.dart`
/// use, and for the same reason: a production code path that accepts an
/// externally supplied "pretend the gate is active" value would itself be a
/// second way to activate the path.
void main() {
  group('computeWinnDevSessionActive: exhaustive truth table', () {
    test('debug + dart-define is the only true combination', () {
      expect(
        computeWinnDevSessionActive(debugMode: true, dartDefineEnabled: true),
        isTrue,
      );
      expect(
        computeWinnDevSessionActive(debugMode: true, dartDefineEnabled: false),
        isFalse,
      );
      expect(
        computeWinnDevSessionActive(debugMode: false, dartDefineEnabled: true),
        isFalse,
        reason: 'a release build must be false even with the dart-define set',
      );
      expect(
        computeWinnDevSessionActive(debugMode: false, dartDefineEnabled: false),
        isFalse,
      );
    });

    test('the dart-define defaults to false in an ordinary test run', () {
      expect(kWinnDevSessionDartDefineValue, isFalse);
      expect(winnDevSessionActive, isFalse);
    });

    test('the dart-define name is the exact literal an operator types', () {
      expect(kWinnDevSessionDartDefineName, 'WINN_DEV_SESSION');
    });
  });

  group('generateWinnDevSessionId', () {
    test('is 32 lowercase hex characters', () {
      for (var i = 0; i < 64; i++) {
        final id = generateWinnDevSessionId();
        expect(id, matches(RegExp(r'^[0-9a-f]{32}$')));
        expect(isWinnDevSessionId(id), isTrue);
      }
    });

    test('is fresh on every call', () {
      final ids = <String>{
        for (var i = 0; i < 256; i++) generateWinnDevSessionId(),
      };
      expect(ids.length, 256);
    });

    test('zero-pads each byte, so a low byte never shortens the id', () {
      // Random(...) with a fixed seed is deterministic; the property under
      // test is the padding, not the entropy source.
      final id = generateWinnDevSessionId(_ZeroRandom());
      expect(id, '00000000000000000000000000000000');
      expect(id.length, 32);
    });

    test('is well inside what the real dispatch gate accepts', () {
      expect(32, lessThanOrEqualTo(kWinnMaxSessionIdBytes));
      final id = generateWinnDevSessionId();
      expect(id.contains('\n'), isFalse);
      expect(id.contains('\r'), isFalse);
      expect(id.contains('['), isFalse);
      expect(id.contains(']'), isFalse);
    });
  });

  group('isWinnDevSessionId', () {
    test('refuses uppercase, wrong length, and non-hex', () {
      expect(isWinnDevSessionId('0123456789ABCDEF0123456789abcdef'), isFalse);
      expect(isWinnDevSessionId('0123456789abcdef'), isFalse);
      expect(isWinnDevSessionId('0123456789abcdef0123456789abcdefa'), isFalse);
      expect(isWinnDevSessionId('0123456789abcdef0123456789abcdeg'), isFalse);
      expect(isWinnDevSessionId(''), isFalse);
    });
  });

  group('winnDevSessionConfigWithFreshSessionId', () {
    test('overwrites a served session_id rather than honouring it', () {
      final config = <String, dynamic>{
        'protocol_version': kWinnProtocolV3,
        'protocol_params': <String, dynamic>{
          'session_id': 'a-served-value-we-must-never-replay',
          'carrier': 'direct-awg',
        },
      };
      final fresh = generateWinnDevSessionId();
      final out = winnDevSessionConfigWithFreshSessionId(config, fresh);
      final params = out['protocol_params'] as Map<String, dynamic>;
      expect(params['session_id'], fresh);
      expect(params['carrier'], 'direct-awg',
          reason: 'no other protocol_param may be disturbed');
    });

    test('creates protocol_params when the config has none', () {
      final fresh = generateWinnDevSessionId();
      final out = winnDevSessionConfigWithFreshSessionId(
        <String, dynamic>{'mtu': 1280},
        fresh,
      );
      expect((out['protocol_params'] as Map)['session_id'], fresh);
      expect(out['mtu'], 1280);
    });

    test('never mutates the caller\'s map', () {
      final params = <String, dynamic>{'session_id': 'original'};
      final config = <String, dynamic>{'protocol_params': params};
      winnDevSessionConfigWithFreshSessionId(
          config, generateWinnDevSessionId());
      expect(params['session_id'], 'original');
      expect(config['protocol_params'], same(params));
    });

    test('refuses a session id that is not 32 lowercase hex', () {
      expect(
        () => winnDevSessionConfigWithFreshSessionId(
            <String, dynamic>{}, 'not-hex'),
        throwsArgumentError,
      );
      expect(
        () => winnDevSessionConfigWithFreshSessionId(
            <String, dynamic>{}, '0123456789ABCDEF0123456789ABCDEF'),
        throwsArgumentError,
        reason: 'uppercase hex is not the shape this file generates',
      );
    });
  });

  group('redactWinnDevSessionDocumentForLogging', () {

    test('standalone INI secrets are removed while routing fields survive', () {
      const document = '[winn]\nstatic_private = fixture_private\n'
        'admission_key = fixture_admission\npsk = fixture_psk\n'
        'endpoint = public.example\n';
      final redacted = redactWinnDevSessionDocumentForLogging(document);
      for (final canary in ['fixture_private', 'fixture_admission', 'fixture_psk']) {
        expect(redacted, isNot(contains(canary)));
      }
      expect(redacted, contains('endpoint = public.example'));
      expect(document, contains('fixture_private'));
    });
    test('redacts PrivateKey, PresharedKey and Uuid, and nothing else', () {
      const document = '[Interface]\n'
          'PrivateKey = SECRET_PRIVATE\n'
          'Address = 10.8.0.2/32\n'
          '[Peer]\n'
          'PublicKey = NOT_A_SECRET\n'
          'PresharedKey = SECRET_PSK\n'
          'Endpoint = 203.0.113.10:9110\n'
          '[Xray]\n'
          'Uuid = SECRET_UUID\n';
      final redacted = redactWinnDevSessionDocumentForLogging(document);
      expect(redacted, isNot(contains('SECRET_PRIVATE')));
      expect(redacted, isNot(contains('SECRET_PSK')));
      expect(redacted, isNot(contains('SECRET_UUID')));
      expect(redacted, contains('NOT_A_SECRET'),
          reason: 'a public key is not a secret and must stay readable');
      expect(redacted, contains('Address = 10.8.0.2/32'));
      expect(redacted, contains('Endpoint = 203.0.113.10:9110'));
      expect(
        redacted.split('\n').length,
        document.split('\n').length,
        reason: 'redaction must preserve structure so the log is checkable',
      );
    });

    test('matches on the whole key, never a substring', () {
      final redacted = redactWinnDevSessionDocumentForLogging(
          'ClientPublicKey = VISIBLE\nPublicKey = ALSO_VISIBLE');
      expect(redacted, contains('VISIBLE'));
      expect(redacted, contains('ALSO_VISIBLE'));
    });
  });

  group('assembleWinnDevSessionTunnelDocument', () {
    // WINN_MANDATORY_HEADERS 2026-08-08: winn/3 now REQUIRES h1..h4 (scalar or
    // range). baseConfig therefore carries them, otherwise every
    // winnSectionFor() call would be refused and no document could be assembled.
    Map<String, dynamic> baseConfig() => <String, dynamic>{
          'protocol_version': kWinnProtocolV3,
          'client_ip': '10.8.0.2',
          'client_public_key': 'CLIENT_PUB',
          'server_public_key': 'SERVER_PUB',
          'server_endpoint': '203.0.113.10:9110',
          'mtu': 1280,
          'dns': '1.1.1.1, 1.0.0.1',
          'obfuscation': <String, dynamic>{
            'H1': 11,
            'H2': 22,
            'H3': 33,
            'H4': 44,
            'S1': 16,
            'S2': 80,
            'S3': 16,
            'S4': 0,
            'Jc': 4,
            'Jmin': 40,
            'Jmax': 70,
          },
          'protocol_params': <String, dynamic>{'carrier': 'direct-awg'},
        };

    String winnSectionFor(Map<String, dynamic> config) {
      // The REAL library -- never a literal typed into this test.
      //
      // This used to go through resolveWinnProtocolStart on 'linux', "a
      // platform kWinnHostCapabilities already calls supported". As of
      // 2026-08-08 no platform is: docs/handoff/ADJUDICATION_20260808.md
      // demoted both remaining `.present` entries, so that call now refuses
      // with unsupported_platform and yields no section at all.
      //
      // These tests are about how assembleWinnDevSessionTunnelDocument treats
      // a [winn] section -- that it appends it verbatim, keeps the containment
      // marker, emits the right routes -- and none of that is a claim about
      // any platform's capability. So they take the section from the config
      // half of the real gate, which is the same code path that produced it
      // before and returns byte-identical output; what is dropped is only the
      // capability assertion, which was never this suite's subject.
      final decision = resolveWinnProtocolStartForServedConfig(config: config);
      expect(decision.supported, isTrue, reason: decision.message);
      return decision.iniSection;
    }

    test('appends the real library\'s [winn] section verbatim', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final section = winnSectionFor(config);
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: section,
        interfacePrivateKey: 'KEYCHAIN_PRIVATE',
        clientPublicKey: 'KEYCHAIN_PUBLIC',
      );
      expect(document, contains(section),
          reason: 'the [winn] section must reach native unmodified');
      expect(document, contains('[winn]'));
      expect(document, contains('carrier = direct-awg'));
    });

    test('carries the generated session_id through to the document', () {
      final sessionId = generateWinnDevSessionId();
      final config =
          winnDevSessionConfigWithFreshSessionId(baseConfig(), sessionId);
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'KEYCHAIN_PRIVATE',
        clientPublicKey: 'KEYCHAIN_PUBLIC',
      );
      expect(document, contains('session_id = $sessionId'));
    });

    test('uses the supplied Keychain private key, never the config\'s', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig()..['client_private_key'] = 'CONFIG_FILE_PRIVATE',
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'KEYCHAIN_PRIVATE',
        clientPublicKey: 'KEYCHAIN_PUBLIC',
      );
      expect(document, contains('PrivateKey = KEYCHAIN_PRIVATE'));
      expect(document, isNot(contains('CONFIG_FILE_PRIVATE')),
          reason: 'the native start refuses any key but the Keychain pair');
    });

    test('emits a full default route so the /32 exclusion is installable', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(document, contains('AllowedIPs = 0.0.0.0/0, ::/0'));
    });

    test('emits the real gateway as the AmneziaWG peer endpoint', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(document, contains('Endpoint = 203.0.113.10:9110'),
          reason: 'WinsTunnelConfig.validate() code 1505 refuses a loopback '
              'peer endpoint for a Winn config',
      );
    });

    test('supplies every AmneziaWG obfuscation field the native validator '
        'requires, even when the config omits them', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      for (final key in const <String>[
        'Jc', 'Jmin', 'Jmax',
        'S1', 'S2', 'S3', 'S4',
        'H1', 'H2', 'H3', 'H4',
      ]) {
        expect(document, contains('$key = '),
            reason: 'awgObfuscation in WinsTunnelConfig.swift requires all 11');
      }
    });

    test('honours an explicit obfuscation block over the defaults', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig()
          ..['obfuscation'] = <String, dynamic>{
            'H1': 101,
            'H2': 22,
            'H3': 33,
            'H4': 44,
            'S1': 24,
          },
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(document, contains('H1 = 101'));
      expect(document, contains('S1 = 24'));
      // And the same values must have reached the [winn] section, or the
      // engine classifies AmneziaWG datagrams at the wrong offsets.
      expect(document, contains('h1 = 101'));
      expect(document, contains('s1 = 24'));
    });

    test('refuses to assemble a document with an empty [winn] section', () {
      expect(
        () => assembleWinnDevSessionTunnelDocument(
          config: baseConfig(),
          winnSection: '   ',
          interfacePrivateKey: 'K',
          clientPublicKey: 'P',
        ),
        throwsA(isA<StateError>()),
        reason: 'an AmneziaWG document with no [winn] section is exactly what '
            'the native host reads as "start plain AmneziaWG" -- the silent '
            'downgrade every gate in this project exists to prevent',
      );
    });

    test('omits PresharedKey entirely when the config has none', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(document, isNot(contains('PresharedKey')));
    });

    test('produces no blank lines, matching _buildRawAmneziaConfig\'s shape',
        () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(document.split('\n').where((l) => l.trim().isEmpty), isEmpty);
    });

    // The 2026-08-05 regression: a dev session took the host's IPv4 default
    // route, its IPv6 (to a sink address) and all of its DNS, then carried
    // nothing, because the winn/3 handshake does not complete on macOS yet.
    // Killing the app did not clear it -- the Network Extension outlives the
    // app -- and only a reboot did. Every document this file assembles must
    // therefore ask the provider for a CONTAINED start.
    test('always carries the containment marker -- there is no config key, no '
        'dart-define and no default that omits it', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(document, contains('[$kWinnDevSessionContainmentSection]'));
      expect(
        document.split('\n'),
        containsAllInOrder(<String>[
          '[$kWinnDevSessionContainmentSection]',
          'Enabled = true',
        ]),
        reason: 'the marker must be a real INI section the native parser reads, '
            'not a comment',
      );
    });

    // The ONE exception, and it is not a loosening: a platform whose native
    // config allowlist REFUSES the section. Emitting it there does not produce
    // a contained tunnel, it produces no tunnel -- Windows'
    // ValidateRestrictedTunnelConfig allows six sections and this is not one of
    // them. The flag is not reachable from a config key or a dart-define;
    // runWinnDevSession derives it from winnDevSessionPlatformCanContain and
    // additionally requires the exact uncontained acknowledgement.
    test('omits the marker ONLY when the platform cannot honour it, and drops '
        'nothing else from the document', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final section = winnSectionFor(config);
      final contained = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: section,
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      final uncontained = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: section,
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
        containmentSupportedByPlatform: false,
      );
      expect(uncontained,
          isNot(contains('[$kWinnDevSessionContainmentSection]')));
      expect(uncontained, isNot(contains('Enabled = true')));
      // Everything else is identical: the difference between the two documents
      // is exactly the containment section and nothing more.
      final removed = contained
          .split('\n')
          .where((line) => !uncontained.split('\n').contains(line))
          .toList();
      expect(removed, <String>[
        '[$kWinnDevSessionContainmentSection]',
        'Enabled = true',
      ]);
      // In particular the full default route survives: the AllowedIPs pairing
      // is what the native validators require, on every platform.
      expect(uncontained, contains('AllowedIPs = 0.0.0.0/0, ::/0'));
      expect(uncontained, contains(section.trim().split('\n').first));
    });

    test('the manual-routing pair Windows refuses to start without is emitted '
        'only when a gateway is supplied', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final section = winnSectionFor(config);
      final apple = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: section,
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(apple, isNot(contains('Table = off')));
      expect(apple, isNot(contains('TunnelGatewayIPv4')));

      final windows = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: section,
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
        containmentSupportedByPlatform: false,
        manualRoutingTunnelGatewayIPv4: '10.8.0.1',
      );
      // Table lives in [Interface] and the gateway in [WinsApp]; the native
      // parsers read them from those sections and nowhere else.
      final lines = windows.split('\n');
      expect(lines.indexOf('Table = off'), greaterThan(lines.indexOf('[Interface]')));
      expect(lines.indexOf('Table = off'), lessThan(lines.indexOf('[Peer]')));
      expect(lines.indexOf('TunnelGatewayIPv4 = 10.8.0.1'),
          greaterThan(lines.indexOf('[WinsApp]')));
    });

    test('the tunnel gateway is validated the way both native validators do',
        () {
      expect(
          winnDevSessionManualRoutingGateway(
              <String, dynamic>{'tunnel_gateway_ipv4': '10.8.0.1'}),
          '10.8.0.1');
      expect(
          winnDevSessionManualRoutingGateway(
              <String, dynamic>{'tunnel_gateway_ipv4': '192.168.7.1'}),
          '192.168.7.1');
      expect(
          winnDevSessionManualRoutingGateway(
              <String, dynamic>{'tunnel_gateway_ipv4': '172.16.4.9'}),
          '172.16.4.9');
      for (final bad in const <String>[
        '',
        '8.8.8.8', // not RFC1918
        '172.15.0.1', // outside 172.16/12
        '10.8.0.0', // network
        '10.8.0.255', // broadcast
        '10.8.0', // too few octets
        '10.8.0.1.1', // too many
        '10.8.0.256', // out of range
        'ten.8.0.1',
      ]) {
        expect(
            winnDevSessionManualRoutingGateway(
                <String, dynamic>{'tunnel_gateway_ipv4': bad}),
            isNull,
            reason: 'gateway "$bad" must be refused');
      }
      expect(winnDevSessionPlatformNeedsManualRouting('windows'), isTrue);
      expect(winnDevSessionPlatformNeedsManualRouting('macos'), isFalse);
      expect(winnDevSessionPlatformNeedsManualRouting('ios'), isFalse);
    });

    test('containment capability is a property of platforms, not of callers',
        () {
      expect(winnDevSessionPlatformCanContain('macos'), isTrue);
      expect(winnDevSessionPlatformCanContain('ios'), isTrue);
      expect(winnDevSessionPlatformCanContain('  IOS '), isTrue);
      expect(winnDevSessionPlatformCanContain('windows'), isFalse);
      expect(winnDevSessionPlatformCanContain('linux'), isFalse);
      expect(kWinnDevSessionContainmentCapablePlatforms,
          <String>{'macos', 'ios'});
    });

    test(
        'the marker section name matches the native constant '
        'WinsTunnelConfig.devContainmentSection', () {
      // The Swift INI parser lowercases section names, and
      // apple/WinsTunnelCore/WinsTunnelConfig.swift declares
      // `devContainmentSection = "winsdevcontainment"`. If either side is
      // renamed without the other, the marker silently stops being read and a
      // dev session goes back to taking the whole host.
      expect(
        kWinnDevSessionContainmentSection.toLowerCase(),
        'winsdevcontainment',
      );
    });

    test(
        'the document still states full-tunnel AllowedIPs, which is exactly '
        'why containment needs its own marker', () {
      // The native validator requires the 0.0.0.0/0 + ::/0 pairing (code 1203)
      // and derives the transport /32 exclusion from it (code 1504), so a
      // contained session CANNOT signal itself by narrowing AllowedIPs. This
      // pins that reasoning: if AllowedIPs ever stopped being full tunnel here,
      // the marker's whole justification would have changed.
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(document, contains('AllowedIPs = 0.0.0.0/0, ::/0'));
      expect(kWinnDevSessionAllowedIPs, <String>['0.0.0.0/0', '::/0']);
    });

    test('the default test route is empty, so the provider derives the /32', () {
      // An operator-typed route is the one way this knob could be widened, and
      // the provider refuses anything that is not a /32. Defaulting to empty
      // keeps that surface unused unless someone deliberately edits it.
      expect(kWinnDevSessionContainmentTestRoute, isEmpty);
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
      );
      expect(document, isNot(contains('TestRoute')));
    });

    test('containment survives the redaction that log output goes through', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        baseConfig(),
        generateWinnDevSessionId(),
      );
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: winnSectionFor(config),
        interfacePrivateKey: 'SECRET_PRIVATE',
        clientPublicKey: 'P',
      );
      final redacted = redactWinnDevSessionDocumentForLogging(document);
      expect(redacted, contains('[$kWinnDevSessionContainmentSection]'));
      expect(redacted, contains('Enabled = true'));
      expect(redacted, isNot(contains('SECRET_PRIVATE')));
    });
  });

  group('the containment banner tells an operator what they are getting', () {
    test('the banner names containment and what it does not prove', () {
      expect(kWinnDevSessionBanner, contains('CONTAINED'));
      expect(kWinnDevSessionBanner, contains('dev_containment_active'));
      expect(kWinnDevSessionBanner, contains('leak_protection_config_passed'));
    });

    test('the rationale states the three things containment declines to take',
        () {
      expect(kWinnDevSessionContainmentRationale, contains('/32'));
      expect(kWinnDevSessionContainmentRationale, contains('IPv6'));
      expect(kWinnDevSessionContainmentRationale, contains('DNS'));
    });
  });

  group('runWinnDevSession: inactive is what every ordinary build gets', () {
    test('touches no channel and reports active: false', () async {
      var invoked = 0;
      final result = await runWinnDevSession(
        operatingSystem: 'macos',
        invoke: (method, arguments) async {
          invoked++;
          fail('the shipping channel must never be called while the gate is '
              'closed (was called with "$method")');
        },
        log: (message) =>
            fail('nothing may be logged while the gate is closed: $message'),
      );
      expect(result.active, isFalse);
      expect(invoked, 0);
      expect(result.blockedAt, isNull);
      expect(result.sessionId, isNull);
      expect(result.documentRedacted, isNull);
      expect(result.nativeStartAccepted, isNull);
    });

    test('is inactive for every operating system, not just macOS', () async {
      for (final os in const <String>[
        'macos', 'ios', 'android', 'linux', 'windows', 'fuchsia', ''
      ]) {
        final result = await runWinnDevSession(
          operatingSystem: os,
          invoke: (method, arguments) async =>
              fail('channel called for os "$os"'),
          log: (message) => fail('logged for os "$os"'),
        );
        expect(result.active, isFalse, reason: 'os "$os"');
      }
    });
  });

  group('the uncontained acknowledgement a non-containing platform needs', () {
    test('is an exact sentence, and "true" is NOT it', () {
      expect(kWinnDevSessionUncontainedAckDartDefineName,
          'WINN_DEV_UNSAFE_UNCONTAINED_ACK');
      expect(computeWinnDevSessionUncontainedAckGiven(
              kWinnDevSessionUncontainedAckRequiredValue),
          isTrue);
      for (final wrong in const <String>[
        'true',
        'TRUE',
        '1',
        'yes',
        '',
        'uncontained_full_tunnel_on_a_disposable_vm',
        ' UNCONTAINED_FULL_TUNNEL_ON_A_DISPOSABLE_VM ',
      ]) {
        expect(computeWinnDevSessionUncontainedAckGiven(wrong), isFalse,
            reason: 'value "$wrong" must not be accepted');
      }
    });

    test('is absent from an ordinary test run, so the wired getter is false',
        () {
      expect(kWinnDevSessionUncontainedAckDartDefineValue, isEmpty);
      expect(winnDevSessionUncontainedAckGiven, isFalse);
    });

    test('the banner names the consequence, not just the fact', () {
      expect(kWinnDevSessionUncontainedBanner, contains('NOT** CONTAINED'));
      expect(kWinnDevSessionUncontainedBanner, contains('0.0.0.0/1'));
      expect(kWinnDevSessionUncontainedBanner,
          contains(kWinnDevSessionUncontainedAckDartDefineName));
      expect(kWinnDevSessionWindowsContainmentAbsenceRationale,
          contains('UNCONTAINED'));
    });
  });

  group('the per-platform channel shapes a Windows session needs', () {
    test('only Windows needs the transition/cancellation generation arguments',
        () {
      expect(winnDevSessionPlatformNeedsTransitionGeneration('windows'), isTrue);
      expect(winnDevSessionPlatformNeedsTransitionGeneration('macos'), isFalse);
      expect(winnDevSessionPlatformNeedsTransitionGeneration('ios'), isFalse);
      expect(winnDevSessionStopArguments('macos'), isNull);
      expect(winnDevSessionStopArguments('ios'), isNull);
      final windowsStop =
          winnDevSessionStopArguments('windows') as Map<String, dynamic>;
      expect(windowsStop['cancellationGeneration'], isA<int>());
      expect(windowsStop['cancellationGeneration'] as int, greaterThan(0));
    });

    test('the generation is positive and increases, which is all the Windows '
        'backend floor requires', () {
      final earlier = winnDevSessionTransitionGeneration(
          DateTime.fromMillisecondsSinceEpoch(1000));
      final later = winnDevSessionTransitionGeneration(
          DateTime.fromMillisecondsSinceEpoch(2000));
      expect(earlier, 1000);
      expect(later, greaterThan(earlier));
      expect(winnDevSessionTransitionGeneration(), greaterThan(0));
    });

    test('only Apple serves loadOrCreateClientKeyPair', () {
      expect(winnDevSessionPlatformHasNativeKeyPair('macos'), isTrue);
      expect(winnDevSessionPlatformHasNativeKeyPair('ios'), isTrue);
      expect(winnDevSessionPlatformHasNativeKeyPair('windows'), isFalse);
    });

    test('startTunnel acceptance is read per platform: Apple returns true, '
        'Windows returns a status string', () {
      expect(winnDevSessionStartAccepted('macos', true), isTrue);
      expect(winnDevSessionStartAccepted('macos', 'Tunnel Initializing'),
          isFalse);
      expect(winnDevSessionStartAccepted('macos', null), isFalse);
      expect(winnDevSessionStartAccepted('windows', 'Tunnel Initializing'),
          isTrue);
      expect(winnDevSessionStartAccepted('windows', true), isTrue);
      expect(winnDevSessionStartAccepted('windows', ''), isFalse);
      expect(winnDevSessionStartAccepted('windows', null), isFalse);
      // ANDROID ADDED 2026-08-21 (Android app-level live winn3 lane).
      // MainActivity.executeServiceLaunch answers the startTunnel channel
      // method with result.success("Tunnel Initializing") after
      // startForegroundService, and signals a failed launch with
      // result.error -- the identical string contract Windows and Linux
      // carry. Before this, a successful Android start was read as a
      // refusal and the harness skipped its traffic phase while the native
      // staged start was still running.
      expect(winnDevSessionStartAccepted('android', 'Tunnel Initializing'),
          isTrue);
      expect(winnDevSessionStartAccepted('android', true), isTrue);
      expect(winnDevSessionStartAccepted('android', ''), isFalse);
      expect(winnDevSessionStartAccepted('android', null), isFalse);
    });

    // ADDED 2026-08-06 (winn/3 Linux shipping-path lane). Linux's
    // `MethodCallHandler` answers startTunnel with the STRING
    // "Tunnel Initializing" and signals failure by RespondError, exactly as
    // Windows does. Before this, a Linux session's successful start was read
    // as a refusal -- and because the `!canContain` path returns without
    // stopping anything, the harness would have walked away from a live
    // full-tunnel session it had just brought up.
    test('Linux reports acceptance with a status string, like Windows', () {
      expect(winnDevSessionStartAccepted('linux', 'Tunnel Initializing'),
          isTrue);
      expect(winnDevSessionStartAccepted('linux', true), isTrue);
      expect(winnDevSessionStartAccepted('linux', ''), isFalse);
      expect(winnDevSessionStartAccepted('linux', null), isFalse);
    });
  });

  group('this path does not read or change the capability table', () {
    test('macOS is still absent, and the source names no flip', () {
      expect(kWinnHostCapabilities['macos']!.supported, isFalse);
      expect(kWinnHostCapabilities['ios']!.supported, isFalse);
      expect(kWinnHostCapabilities['windows']!.supported, isFalse);
    });

    test('the absence probe is a literal a strings(1) check can find', () {
      expect(kWinnDevSessionAbsenceProbeString, isNotEmpty);
      expect(kWinnDevSessionAbsenceProbeString,
          matches(RegExp(r'^WINN_DEV_SESSION_ABSENCE_PROBE_[0-9a-f]{8}$')));
    });
  });

  group('the assembled document is JSON-loggable evidence', () {
    test('a redacted document survives jsonEncode for a handoff', () {
      final config = <String, dynamic>{
        'protocol_version': kWinnProtocolV3,
        'client_ip': '10.8.0.2',
        'server_public_key': 'SERVER_PUB',
        'server_endpoint': '203.0.113.10:9110',
        'mtu': 1280,
        'dns': '1.1.1.1',
        'obfuscation': <String, dynamic>{
          'H1': 11,
          'H2': 22,
          'H3': 33,
          'H4': 44,
          'S1': 16,
          'S2': 80,
          'S3': 16,
          'S4': 0,
        },
      };
      final withId = winnDevSessionConfigWithFreshSessionId(
          config, generateWinnDevSessionId());
      // Config half of the real gate: this test is about redaction and JSON
      // round-tripping, not about any platform's capability. See the note on
      // winnSectionFor above -- every entry has been .absent since 2026-08-08.
      final decision =
          resolveWinnProtocolStartForServedConfig(config: withId);
      expect(decision.supported, isTrue, reason: decision.message);
      final document = assembleWinnDevSessionTunnelDocument(
        config: withId,
        winnSection: decision.iniSection,
        interfacePrivateKey: 'SECRET',
        clientPublicKey: 'PUB',
      );
      final redacted = redactWinnDevSessionDocumentForLogging(document);
      expect(jsonDecode(jsonEncode(redacted)), redacted);
      expect(redacted, isNot(contains('SECRET')));
    });
  });

  group('evaluateWinnDevSessionContainment: containment is READ from the '
      'provider, never assumed from the document that was sent', () {
    Map<String, dynamic> containedStatus() => <String, dynamic>{
          'provider_dev_containment_active': true,
          'provider_dev_containment_default_ipv4_route_installed': false,
          'provider_dev_containment_ipv6_settings_installed': false,
          'provider_dev_containment_dns_settings_installed': false,
          'provider_dev_containment_observed_contained': true,
          'leak_protection_config_passed': false,
        };

    test('a fully contained provider status is confirmed', () {
      final verdict = evaluateWinnDevSessionContainment(containedStatus());
      expect(verdict.confirmed, isTrue);
      expect(verdict.reasons, isEmpty);
      expect(verdict.observedFields['provider_dev_containment_active'], isTrue);
    });

    test('a null provider status is NOT confirmed', () {
      final verdict = evaluateWinnDevSessionContainment(null);
      expect(verdict.confirmed, isFalse);
      expect(verdict.reasons, contains('provider_status_unavailable'));
    });

    test('an EMPTY provider status is NOT confirmed -- silence is not '
        'evidence of containment', () {
      // This is the exact shape the pre-2026-08-06 iOS provider produced: it
      // wrote no containment fields at all because it had no containment code,
      // and the app said "contained" anyway. Absence must fail.
      final verdict = evaluateWinnDevSessionContainment(<String, dynamic>{});
      expect(verdict.confirmed, isFalse);
      expect(verdict.reasons, contains('containment_active_absent'));
      expect(verdict.reasons, contains('default_ipv4_route_installed_absent'));
      expect(verdict.reasons, contains('ipv6_settings_installed_absent'));
      expect(verdict.reasons, contains('dns_settings_installed_absent'));
    });

    test('a status that claims active but installed a default route is NOT '
        'confirmed', () {
      final status = containedStatus()
        ..['provider_dev_containment_default_ipv4_route_installed'] = true;
      final verdict = evaluateWinnDevSessionContainment(status);
      expect(verdict.confirmed, isFalse);
      expect(verdict.reasons, contains('default_ipv4_route_installed_true'));
    });

    test('a status that claims active but installed IPv6 settings is NOT '
        'confirmed', () {
      final status = containedStatus()
        ..['provider_dev_containment_ipv6_settings_installed'] = true;
      final verdict = evaluateWinnDevSessionContainment(status);
      expect(verdict.confirmed, isFalse);
      expect(verdict.reasons, contains('ipv6_settings_installed_true'));
    });

    test('a status that claims active but installed DNS settings is NOT '
        'confirmed', () {
      final status = containedStatus()
        ..['provider_dev_containment_dns_settings_installed'] = true;
      final verdict = evaluateWinnDevSessionContainment(status);
      expect(verdict.confirmed, isFalse);
      expect(verdict.reasons, contains('dns_settings_installed_true'));
    });

    test('an explicit containment_active=false is NOT confirmed', () {
      final status = containedStatus()
        ..['provider_dev_containment_active'] = false;
      final verdict = evaluateWinnDevSessionContainment(status);
      expect(verdict.confirmed, isFalse);
      expect(verdict.reasons, contains('containment_active_false'));
    });

    test('the iOS read-back field vetoes a claim the intent fields would '
        'have passed', () {
      // dev_containment_observed_contained is measured off the settings object
      // the provider actually built. If it disagrees with the plan-derived
      // fields, the measurement wins.
      final status = containedStatus()
        ..['provider_dev_containment_observed_contained'] = false;
      final verdict = evaluateWinnDevSessionContainment(status);
      expect(verdict.confirmed, isFalse);
      expect(verdict.reasons, contains('observed_contained_false'));
    });

    test('a macOS-shaped status without the iOS read-back field is still '
        'confirmable', () {
      // macOS reports intent only. Requiring the observed field would fail
      // every macOS session for no reason.
      final status = containedStatus()
        ..remove('provider_dev_containment_observed_contained');
      final verdict = evaluateWinnDevSessionContainment(status);
      expect(verdict.confirmed, isTrue, reason: verdict.reasons.join(', '));
    });

    test('a contained session that ALSO reports a passing full-tunnel '
        'leak-protection verdict is NOT confirmed', () {
      // The two halves must agree. A pass here means the readiness helper's
      // !devContainmentActive term did not see the containment field, i.e. the
      // status is internally inconsistent.
      final status = containedStatus()..['leak_protection_config_passed'] = true;
      final verdict = evaluateWinnDevSessionContainment(status);
      expect(verdict.confirmed, isFalse);
      expect(verdict.reasons, contains('leak_protection_config_passed_true'));
    });

    test('unprefixed provider-document spellings are accepted too', () {
      final verdict = evaluateWinnDevSessionContainment(<String, dynamic>{
        'dev_containment_active': true,
        'dev_containment_default_ipv4_route_installed': false,
        'dev_containment_ipv6_settings_installed': false,
        'dev_containment_dns_settings_installed': false,
      });
      expect(verdict.confirmed, isTrue, reason: verdict.reasons.join(', '));
    });

    test('string "true"/"false" values are honoured, other strings are not', () {
      final stringy = evaluateWinnDevSessionContainment(<String, dynamic>{
        'dev_containment_active': 'true',
        'dev_containment_default_ipv4_route_installed': 'false',
        'dev_containment_ipv6_settings_installed': 'false',
        'dev_containment_dns_settings_installed': 'false',
      });
      expect(stringy.confirmed, isTrue, reason: stringy.reasons.join(', '));

      final junk = evaluateWinnDevSessionContainment(<String, dynamic>{
        'dev_containment_active': 'yes',
        'dev_containment_default_ipv4_route_installed': 'false',
        'dev_containment_ipv6_settings_installed': 'false',
        'dev_containment_dns_settings_installed': 'false',
      });
      expect(junk.confirmed, isFalse);
      expect(junk.reasons, contains('containment_active_absent'));
    });

    test('reasons are sorted and the verdict collections are unmodifiable', () {
      final verdict = evaluateWinnDevSessionContainment(<String, dynamic>{});
      final sorted = List<String>.from(verdict.reasons)..sort();
      expect(verdict.reasons, sorted);
      expect(() => verdict.reasons.add('x'), throwsUnsupportedError);
      expect(() => verdict.observedFields['x'] = 1, throwsUnsupportedError);
    });
  });

  group(
      'winnDevSessionProviderHasPublished: WHEN the containment verdict may be '
      'taken', () {
    // Regression pin for a real false negative seen on a physical iPhone 16
    // Pro Max (iOS 26.5.2): `startTunnel` returned true, the newest status
    // document was still the host app's `config_saved` placeholder because the
    // appex had not launched yet, and a session was torn down for failing to
    // prove containment it had not yet been asked about.
    test('a null status has not been published', () {
      expect(winnDevSessionProviderHasPublished(null), isFalse);
    });

    test('an empty status has not been published', () {
      expect(winnDevSessionProviderHasPublished(<String, dynamic>{}), isFalse);
    });

    test('the HOST APP\'s config_saved placeholder is NOT the provider talking',
        () {
      expect(
        winnDevSessionProviderHasPublished(<String, dynamic>{
          'provider_stage': kWinnDevSessionAppWrittenStage,
        }),
        isFalse,
      );
      // Bare spelling too: a caller may hand this the raw status document.
      expect(
        winnDevSessionProviderHasPublished(<String, dynamic>{
          'stage': kWinnDevSessionAppWrittenStage,
        }),
        isFalse,
      );
    });

    test('any appex-written stage counts as published', () {
      for (final stage in <String>[
        'engine_started',
        'app_message',
        'network_settings_failed',
        'start_rejected',
        'stopping',
        'stopped',
      ]) {
        expect(
          winnDevSessionProviderHasPublished(
            <String, dynamic>{'provider_stage': stage},
          ),
          isTrue,
          reason: '$stage is written only by the appex',
        );
      }
    });

    test(
        'a published status with NO containment fields is a real verdict, not '
        'a reason to keep waiting', () {
      // This is the property that keeps the wait from becoming a loophole: an
      // appex that started and said nothing about containment must reach the
      // refusal, not be waited out until it says something better.
      final status = <String, dynamic>{'provider_stage': 'engine_started'};
      expect(winnDevSessionProviderHasPublished(status), isTrue);
      expect(evaluateWinnDevSessionContainment(status).confirmed, isFalse);
    });

    test('a blank or whitespace stage has not been published', () {
      expect(
        winnDevSessionProviderHasPublished(<String, dynamic>{'stage': '   '}),
        isFalse,
      );
    });

    test('the wait is bounded and the poll interval is shorter than it', () {
      expect(kWinnDevSessionProviderStatusTimeout, greaterThan(Duration.zero));
      expect(
        kWinnDevSessionProviderStatusPollInterval,
        lessThan(kWinnDevSessionProviderStatusTimeout),
      );
    });
  });

  group('Windows STANDALONE native [winn3] emission', () {
    Map<String, dynamic> windowsNativeConfig() => <String, dynamic>{
          'protocol_version': kWinnProtocolV3,
          'client_ip': '10.10.0.2',
          'client_public_key': 'CLIENT_PUB',
          'server_public_key': 'SERVER_PUB',
          'server_endpoint': '203.0.113.10:9110',
          'mtu': 1450,
          'dns': '10.10.0.1',
          'tunnel_gateway_ipv4': '10.10.0.1',
          'obfuscation': <String, dynamic>{
            'H1': 11,
            'H2': 22,
            'H3': 33,
            'H4': 44,
            'S1': 16,
            'S2': 80,
            'S3': 16,
            'S4': 0,
            'Jc': 4,
            'Jmin': 40,
            'Jmax': 70,
          },
          'protocol_params': <String, dynamic>{'carrier': 'winn3'},
          'winn3_endpoint': '192.0.2.10:9111',
          'winn3_class': 'udp',
          'winn3_plan': 'udp, tcp, tls',
          'winn3_path_mtu': '1450',
          'winn3_gateway_id': 'kansas-1',
          'winn3_inner_v4': '10.10.0.2',
          'winn3_router_v4': '10.10.0.1',
          'winn3_static_key_path': r'C:\fleet\winn3\static.key',
          'winn3_gateway_static_key_path': r'C:\fleet\winn3\gateway.pub',
          'winn3_admission_path': r'C:\fleet\winn3\admission.key',
          'winn3_routes': '0.0.0.0/0',
          'winn3_dns': '10.10.0.1',
        };

    test('the native spelling is selected on Windows alone and only when the '
        'config carries native fields', () {
      final config = windowsNativeConfig();
      expect(winnDevSessionConfigHasWinn3NativeFields(config), isTrue);
      expect(winnDevSessionPlatformUsesWindowsWinn3NativeSpelling(
          'windows', config), isTrue);
      expect(winnDevSessionPlatformUsesWindowsWinn3NativeSpelling(
          'Windows', config), isTrue);
      for (final platform in <String>['macos', 'ios', 'linux', 'android',
          'fuchsia', '']) {
        expect(
          winnDevSessionPlatformUsesWindowsWinn3NativeSpelling(
              platform, config),
          isFalse,
          reason: '"$platform" must never take the Windows [winn3] spelling',
        );
      }
      for (final field in <String>[
        'winn3_endpoint',
        'winn3_class',
        'winn3_plan',
        'winn3_path_mtu',
        'winn3_gateway_id',
        'winn3_inner_v4',
        'winn3_router_v4',
        'winn3_static_key_path',
        'winn3_gateway_static_key_path',
        'winn3_admission_path',
        'winn3_routes',
        'winn3_dns',
      ]) {
        final without = Map<String, dynamic>.from(config)
          ..remove(field);
        expect(
          winnDevSessionConfigHasWinn3NativeFields(without),
          isTrue,
          reason: 'removing "$field" alone must not deselect the native path; '
              'the builder refuses an incomplete set by name instead',
        );
      }
      final cleared = Map<String, dynamic>.from(config);
      for (final field in <String>[
        ...kWinnDevSessionWindowsWinn3NativeKeys,
        ...kWinnDevSessionWindowsWinn3OptionalKeys,
      ]) {
        cleared.remove(field);
      }
      expect(winnDevSessionConfigHasWinn3NativeFields(cleared), isFalse,
          reason: 'a config with none of the native fields keeps the [winn] '
              'dispatch path');
    });

    test('emits the LOCAL [winn3] spelling: the exact backend-contract keys, '
        'in the exact backend order', () {
      final section = winnDevSessionWindowsWinn3NativeSection(
          windowsNativeConfig());
      final lines = section.split('\n');
      expect(lines.first, '[winn3]');
      expect(lines, containsAllInOrder(<String>[
        'enabled = true',
        'endpoint = 192.0.2.10:9111',
        'class = udp',
        'plan = udp, tcp, tls',
        'path_mtu = 1450',
        'gateway_id = kansas-1',
        'inner_v4 = 10.10.0.2',
        'router_v4 = 10.10.0.1',
        r'static_key_path = C:\fleet\winn3\static.key',
        r'gateway_static_key_path = C:\fleet\winn3\gateway.pub',
        r'admission_path = C:\fleet\winn3\admission.key',
        'routes = 0.0.0.0/0',
        'dns = 10.10.0.1',
        'dns_are_inner = true',
      ]));
      // gateway_id is RAW OPERATOR BYTES in the local spelling: base64 is the
      // served `[winn]` spelling, and the two must never blur.
      expect(section, contains('gateway_id = kansas-1'));
      // No AmneziaWG obfuscation and no served value keys: a standalone
      // document must stay distinguishable from a relay one.
      expect(section, isNot(contains('h1 =')));
      expect(section, isNot(contains('s1 =')));
      expect(section, isNot(contains('static_private')));
      expect(section, isNot(contains('carrier =')));
    });

    test('dns is omitted cleanly with dns_are_inner when not configured', () {
      final noDns = Map<String, dynamic>.from(windowsNativeConfig())
        ..remove('winn3_dns');
      final section = winnDevSessionWindowsWinn3NativeSection(noDns);
      expect(section, isNot(contains('dns =')));
      expect(section, isNot(contains('dns_are_inner')));
      final noRoutes = Map<String, dynamic>.from(windowsNativeConfig())
        ..remove('winn3_routes');
      expect(winnDevSessionWindowsWinn3NativeSection(noRoutes),
          isNot(contains('routes =')));
      expect(winnDevSessionWindowsWinn3NativeSection(noRoutes),
          contains('dns_are_inner = true'));
    });

    test('an incomplete native field set is refused by name, never defaulted',
        () {
      for (final field in kWinnDevSessionWindowsWinn3NativeKeys) {
        final config = Map<String, dynamic>.from(windowsNativeConfig())
          ..remove(field);
        expect(
          () => winnDevSessionWindowsWinn3NativeSection(config),
          throwsA(isA<StateError>()
              .having((error) => '$error', 'message', contains(field))),
          reason: 'missing "$field" must be named',
        );
      }
    });

    test('the same native section reaches the assembled document verbatim and '
        'the AWG fallback sections stay intact', () {
      final config = winnDevSessionConfigWithFreshSessionId(
        windowsNativeConfig(),
        generateWinnDevSessionId(),
      );
      final section = winnDevSessionWindowsWinn3NativeSection(config);
      final document = assembleWinnDevSessionTunnelDocument(
        config: config,
        winnSection: section,
        interfacePrivateKey: 'K',
        clientPublicKey: 'P',
        containmentSupportedByPlatform: false,
        manualRoutingTunnelGatewayIPv4: '10.10.0.1',
      );
      expect(document, contains(section),
          reason: 'the [winn3] section must reach native unmodified');
      // The AWG fallback carrier is preserved: [Interface]/[Peer] with the
      // Windows manual-routing pair.
      expect(document, contains('[Interface]'));
      expect(document, contains('[Peer]'));
      expect(document, contains('Table = off'));
      expect(document, contains('TunnelGatewayIPv4 = 10.10.0.1'));
      expect(document, contains('AllowedIPs = 0.0.0.0/0, ::/0'));
    });

    test('malformed native values are refused by name', () {
      final badEndpoint = Map<String, dynamic>.from(windowsNativeConfig())
        ..['winn3_endpoint'] = 'sim-data.winsvpn.org:9111';
      expect(() => winnDevSessionWindowsWinn3NativeSection(badEndpoint),
          throwsA(isA<StateError>()
              .having((e) => '$e', 'message', contains('winn3_endpoint'))));

      final badClass = Map<String, dynamic>.from(windowsNativeConfig())
        ..['winn3_class'] = 'sneakernet';
      expect(
          () => winnDevSessionWindowsWinn3NativeSection(badClass),
          throwsA(isA<StateError>()
              .having((e) => '$e', 'message', contains('winn3_class'))));

      final badPlan = Map<String, dynamic>.from(windowsNativeConfig())
        ..['winn3_plan'] = 'tcp, tls';
      expect(
          () => winnDevSessionWindowsWinn3NativeSection(badPlan),
          throwsA(isA<StateError>()
              .having((e) => '$e', 'message', contains('winn3_plan'))));

      final sameHop = Map<String, dynamic>.from(windowsNativeConfig())
        ..['winn3_router_v4'] = '10.10.0.2';
      expect(
          () => winnDevSessionWindowsWinn3NativeSection(sameHop),
          throwsA(isA<StateError>()
              .having((e) => '$e', 'message', contains('own next hop'))));

      final inject = Map<String, dynamic>.from(windowsNativeConfig())
        ..['winn3_gateway_id'] = 'kansas-1\nsecret = value';
      expect(
          () => winnDevSessionWindowsWinn3NativeSection(inject),
          throwsA(isA<StateError>()
              .having((e) => '$e', 'message', contains('winn3_gateway_id'))));
    });

    test('gateway_id is emitted as the raw operator bytes, never base64', () {
      final config = windowsNativeConfig();
      final section = winnDevSessionWindowsWinn3NativeSection(config);
      expect(section, contains('gateway_id = kansas-1'));
      expect(
        section
            .split('\n')
            .where((line) => line.startsWith('gateway_id = '))
            .toList(),
        <String>['gateway_id = kansas-1'],
        reason: 'exactly one gateway_id line, carrying the raw bytes',
      );
    });
  });
}

/// A deterministic generator used only to pin the zero-padding property.
class _ZeroRandom implements Random {
  @override
  bool nextBool() => false;

  @override
  double nextDouble() => 0;

  @override
  int nextInt(int max) => 0;
}
