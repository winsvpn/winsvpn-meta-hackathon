import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dev_config_source.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Tests for the DEV-ONLY, NON-SHIPPING config source in
/// `lib/winn_protocol_dev_config_source.dart`.
///
/// Every test in this file runs under a plain `flutter test` invocation --
/// no special `--dart-define` is required or assumed, and none of these
/// tests may depend on one being set. As with
/// `test/winn_protocol_dev_override_test.dart`, the ONLY thing keeping this
/// module's gate off throughout this entire suite is that
/// `WINN_DEV_CONFIG_PATH` defaults to `''` -- `kDebugMode` is already true in
/// every `flutter test` VM. A few tests below assert that fact directly.
///
/// What this file CANNOT prove by itself: that the dart-define really does
/// flip the gate, and that a loaded, validated file-sourced config really
/// does drive a real `labgateway` handshake. Both are demonstrated once, for
/// real, with quoted command output, in this session's dated handoff file --
/// not asserted here. What this suite proves instead is everything that
/// does not require the real gate to be active: file loading, required-field
/// checking, secret redaction, and (via [evaluateWinnDevConfigSourceConfig],
/// which is deliberately gate-independent -- see its doc comment) the full
/// business-logic path a loaded config takes, including the real,
/// unmodified [resolveWinnProtocolStart] underneath it.
void main() {
  group('the compiled-in environment this whole suite runs under', () {
    test('this test process is a debug VM (kDebugMode true)', () {
      expect(kDebugMode, isTrue);
    });

    test('kReleaseMode and kDebugMode can never both be true', () {
      expect(kReleaseMode && kDebugMode, isFalse);
    });

    test('the config-path dart-define is NOT set for this run', () {
      // What actually keeps this module off throughout this file's default
      // run, given kDebugMode is true above. If this assertion ever fails,
      // the suite was invoked with --dart-define=WINN_DEV_CONFIG_PATH=...,
      // which must never be part of a normal `flutter test` / CI invocation.
      expect(kWinnDevConfigPathDartDefineValue, isEmpty);
      expect(kWinnDevConfigPathDartDefineName, 'WINN_DEV_CONFIG_PATH');
    });
  });

  group('computeWinnDevConfigSourceActive: exhaustive truth table', () {
    test('debug + non-blank path => active', () {
      expect(
        computeWinnDevConfigSourceActive(
            debugMode: true, configPath: '/tmp/winn-dev-config.json'),
        isTrue,
      );
    });

    test('debug + blank path => inactive', () {
      expect(
        computeWinnDevConfigSourceActive(debugMode: true, configPath: ''),
        isFalse,
      );
    });

    test('debug + whitespace-only path => inactive (trimmed before checking)',
        () {
      expect(
        computeWinnDevConfigSourceActive(debugMode: true, configPath: '   '),
        isFalse,
      );
    });

    test(
        'NOT debug (release/profile) + non-blank path => inactive '
        '(a release-mode build cannot take this path even if the define '
        'were somehow set)', () {
      expect(
        computeWinnDevConfigSourceActive(
            debugMode: false, configPath: '/tmp/winn-dev-config.json'),
        isFalse,
      );
    });

    test('NOT debug + blank path => inactive', () {
      expect(
        computeWinnDevConfigSourceActive(debugMode: false, configPath: ''),
        isFalse,
      );
    });
  });

  group('winnDevConfigSourceActive: real gate wiring', () {
    test('matches the pure gate applied to the real compiled-in constants',
        () {
      expect(
        winnDevConfigSourceActive,
        equals(computeWinnDevConfigSourceActive(
          debugMode: kDebugMode,
          configPath: kWinnDevConfigPathDartDefineValue,
        )),
      );
    });

    test('is false for this (default) invocation', () {
      expect(winnDevConfigSourceActive, isFalse);
    });
  });

  group('kWinnHostCapabilities stays honest with this file compiled in', () {
    test('macOS is still .absent', () {
      final macos = kWinnHostCapabilities['macos'];
      expect(macos, isNotNull);
      expect(macos!.supported, isFalse);
    });

    test('windows is still .absent', () {
      final windows = kWinnHostCapabilities['windows'];
      expect(windows, isNotNull);
      expect(windows!.supported, isFalse);
    });

    test('winnSupportedPlatforms() is unaffected by this file existing', () {
      expect(winnSupportedPlatforms(), isNot(contains('macos')));
      expect(winnSupportedPlatforms(), isNot(contains('windows')));
    });
  });

  group('loadWinnDevConfigFromFile', () {
    late Directory tempDir;

    setUp(() {
      tempDir = Directory.systemTemp.createTempSync('winn_dev_config_test_');
    });

    tearDown(() {
      if (tempDir.existsSync()) {
        tempDir.deleteSync(recursive: true);
      }
    });

    test('blank path is refused without touching the filesystem', () {
      final result = loadWinnDevConfigFromFile('   ');
      expect(result.loaded, isFalse);
      expect(result.error, contains('blank'));
    });

    test('a nonexistent file is refused, naming the path, not crashing', () {
      final path = '${tempDir.path}/does-not-exist.json';
      final result = loadWinnDevConfigFromFile(path);
      expect(result.loaded, isFalse);
      expect(result.error, isNotNull);
      expect(result.error, contains(path));
    });

    test('malformed JSON is refused; the error names the failure, not the '
        'file contents', () {
      final file = File('${tempDir.path}/bad.json')
        ..writeAsStringSync('{not valid json,,,');
      final result = loadWinnDevConfigFromFile(file.path);
      expect(result.loaded, isFalse);
      expect(result.error, contains('could not parse'));
      expect(result.error, isNot(contains('not valid json')));
    });

    test('a JSON array at the top level is refused (must be an object)', () {
      final file = File('${tempDir.path}/array.json')
        ..writeAsStringSync('[1, 2, 3]');
      final result = loadWinnDevConfigFromFile(file.path);
      expect(result.loaded, isFalse);
      expect(result.error, contains('JSON object'));
    });

    test('a bare JSON string at the top level is refused', () {
      final file = File('${tempDir.path}/string.json')
        ..writeAsStringSync('"just a string"');
      final result = loadWinnDevConfigFromFile(file.path);
      expect(result.loaded, isFalse);
      expect(result.error, contains('JSON object'));
    });

    test('a well-formed JSON object loads successfully', () {
      final file = File('${tempDir.path}/good.json')
        ..writeAsStringSync(jsonEncode(<String, dynamic>{
          'server_endpoint': '127.0.0.1:51820',
          'mtu': 1280,
        }));
      final result = loadWinnDevConfigFromFile(file.path);
      expect(result.loaded, isTrue);
      expect(result.config!['server_endpoint'], '127.0.0.1:51820');
      expect(result.config!['mtu'], 1280);
    });

    test('leading/trailing whitespace in the path is trimmed', () {
      final file = File('${tempDir.path}/good2.json')
        ..writeAsStringSync('{"x": 1}');
      final result = loadWinnDevConfigFromFile('  ${file.path}  ');
      expect(result.loaded, isTrue);
    });
  });

  group('missingWinnDevConfigFields', () {
    test('a config with every required field present is complete', () {
      expect(missingWinnDevConfigFields(_validWinn3ConfigForTests()), isEmpty);
    });

    test('a completely empty config is missing every required field', () {
      final missing = missingWinnDevConfigFields(<String, dynamic>{});
      expect(missing, unorderedEquals(kWinnDevConfigRequiredFields));
    });

    test('a blank (whitespace-only) value counts as missing', () {
      final config = _validWinn3ConfigForTests()..['client_ip'] = '   ';
      expect(missingWinnDevConfigFields(config), contains('client_ip'));
    });

    test('missing fields are reported sorted', () {
      final config = <String, dynamic>{
        'server_public_key': 'x',
      }; // missing client_ip, client_private_key, client_public_key
      final missing = missingWinnDevConfigFields(config);
      expect(missing, <String>[
        'client_ip',
        'client_private_key',
        'client_public_key',
      ]);
    });

    test('server_endpoint and mtu are NOT in the required set -- the real '
        'gate already validates both, and this set must never be stricter',
        () {
      expect(kWinnDevConfigRequiredFields, isNot(contains('server_endpoint')));
      expect(kWinnDevConfigRequiredFields, isNot(contains('mtu')));
    });
  });

  group('redactWinnDevConfigForLogging', () {

    test('standalone secret aliases are redacted at every nesting level', () {
      const aliases = ['winn3_psk', 'winn3psk', 'static_private',
        'winn3_static_private', 'winn3staticprivate', 'winn3_private_key',
        'admission_key', 'admissionkey', 'admission_secret', 'admissionsecret',
        'winn3_descriptor', 'winn3descriptor'];
      final document = <String, dynamic>{
        for (final alias in aliases) alias: 'fixture_$alias',
        'nested': [{for (final alias in aliases) alias.toUpperCase(): 'fixture_$alias'}],
        'endpoint': 'public.example',
      };
      final encoded = jsonEncode(redactWinnDevConfigForLogging(document));
      for (final alias in aliases) {
        expect(encoded, isNot(contains('fixture_$alias')));
      }
      expect(encoded, contains('public.example'));
    });
    test('client_private_key is redacted', () {
      final redacted = redactWinnDevConfigForLogging(
          <String, dynamic>{'client_private_key': 'super-secret-key-value'});
      expect(redacted['client_private_key'], '<redacted>');
    });

    test('preshared_key is redacted', () {
      final redacted = redactWinnDevConfigForLogging(
          <String, dynamic>{'preshared_key': 'super-secret-psk-value'});
      expect(redacted['preshared_key'], '<redacted>');
    });

    test('matching is case-insensitive but preserves the original key '
        'casing in the output', () {
      final redacted = redactWinnDevConfigForLogging(
          <String, dynamic>{'Client_Private_Key': 'secret-value'});
      expect(redacted.containsKey('Client_Private_Key'), isTrue);
      expect(redacted['Client_Private_Key'], '<redacted>');
    });

    test('public keys are never redacted', () {
      final redacted = redactWinnDevConfigForLogging(<String, dynamic>{
        'client_public_key': 'pub-client-value',
        'server_public_key': 'pub-server-value',
      });
      expect(redacted['client_public_key'], 'pub-client-value');
      expect(redacted['server_public_key'], 'pub-server-value');
    });

    test('exact match only -- a field that merely contains "key" as a '
        'substring is not redacted', () {
      final redacted = redactWinnDevConfigForLogging(
          <String, dynamic>{'keyboard_layout': 'qwerty'});
      expect(redacted['keyboard_layout'], 'qwerty');
    });

    test('an empty secret value is left empty, not marked redacted -- '
        'there is nothing to hide', () {
      final redacted =
          redactWinnDevConfigForLogging(<String, dynamic>{'preshared_key': ''});
      expect(redacted['preshared_key'], '');
    });

    test('redaction descends into nested maps', () {
      final redacted = redactWinnDevConfigForLogging(<String, dynamic>{
        'protocol_params': <String, dynamic>{'token': 'nested-secret'},
      });
      final params = redacted['protocol_params'] as Map<String, dynamic>;
      expect(params['token'], '<redacted>');
    });

    test('redaction descends into lists of maps', () {
      final redacted = redactWinnDevConfigForLogging(<String, dynamic>{
        'peers': <Map<String, dynamic>>[
          <String, dynamic>{'preshared_key': 'a'},
          <String, dynamic>{'preshared_key': 'b'},
        ],
      });
      final peers = redacted['peers'] as List<dynamic>;
      expect((peers[0] as Map)['preshared_key'], '<redacted>');
      expect((peers[1] as Map)['preshared_key'], '<redacted>');
    });

    test('a planted secret string never survives into the JSON-encoded '
        'redacted output', () {
      const planted = 'PLANTED_SECRET_VALUE_DO_NOT_LEAK_9f3ac2';
      final config = _validWinn3ConfigForTests()
        ..['client_private_key'] = planted
        ..['preshared_key'] = planted;
      final encoded = jsonEncode(redactWinnDevConfigForLogging(config));
      expect(encoded, isNot(contains(planted)));
    });

    test('kWinnDevConfigSecretFieldNames does not accidentally cover a '
        'public/non-secret field', () {
      expect(kWinnDevConfigSecretFieldNames,
          isNot(contains('client_public_key')));
      expect(kWinnDevConfigSecretFieldNames,
          isNot(contains('server_public_key')));
      expect(kWinnDevConfigSecretFieldNames, isNot(contains('client_ip')));
      expect(
          kWinnDevConfigSecretFieldNames, isNot(contains('server_endpoint')));
    });
  });

  group('evaluateWinnDevConfigSourceConfig: gate-independent business logic '
      '(does not require the real gate to be active to test)', () {
    test('a config missing a required field is refused before any winn/3 '
        'validation runs', () {
      final config = _validWinn3ConfigForTests()..remove('client_private_key');
      final result = evaluateWinnDevConfigSourceConfig(
        config: config,
        operatingSystem: 'linux',
      );
      expect(result.active, isTrue);
      expect(result.loadError, contains('client_private_key'));
      expect(result.overrideResult, isNull);
    });

    test('protocol_version "winn/1" is reported out of scope, not as a '
        'failure', () {
      final config = _validWinn3ConfigForTests()
        ..['protocol_version'] = kWinnProtocolV1;
      final result = evaluateWinnDevConfigSourceConfig(
        config: config,
        operatingSystem: 'linux',
      );
      expect(result.active, isTrue);
      expect(result.loadError, contains(kWinnProtocolV1));
      expect(result.normalizedConfig, isNotNull);
      expect(result.overrideResult, isNull);
    });

    test('an absent protocol_version normalizes to winn/1, same as the '
        'shipping schema', () {
      final config = _validWinn3ConfigForTests()..remove('protocol_version');
      final result = evaluateWinnDevConfigSourceConfig(
        config: config,
        operatingSystem: 'linux',
      );
      expect(result.loadError, contains(kWinnProtocolV1));
    });

    test('an unknown protocol_version is refused by name', () {
      final config = _validWinn3ConfigForTests()
        ..['protocol_version'] = 'winn/99';
      final result = evaluateWinnDevConfigSourceConfig(
        config: config,
        operatingSystem: 'linux',
      );
      expect(result.loadError, contains('winn/99'));
      expect(result.overrideResult, isNull);
    });

    test('winn/3 on macOS, without the separate capability override: '
        'refused with unsupported_platform, exactly like a server-delivered '
        'config -- this file does not touch that gate', () {
      final config = _validWinn3ConfigForTests();
      final direct =
          resolveWinnProtocolStart(operatingSystem: 'macos', config: config);
      final result = evaluateWinnDevConfigSourceConfig(
        config: config,
        operatingSystem: 'macos',
      );
      expect(result.overrideResult, isNotNull);
      expect(result.overrideResult!.overrodeCapabilityGate, isFalse);
      expect(result.overrideResult!.decision.supported, isFalse);
      expect(result.overrideResult!.decision.reason,
          WinnRefusalReason.unsupportedPlatform);
      expect(result.overrideResult!.decision.reason, direct.reason);
    });

    test('winn/3 on linux: refused now that no platform is supported, and '
        'the section logic itself is still exercised', () {
      // 2026-08-08: this asserted "linux (already supported): a real, usable
      // [winn] section comes back". docs/handoff/ADJUDICATION_20260808.md
      // demoted every entry in kWinnHostCapabilities, so this path now
      // refuses at the capability gate on linux exactly as it always did on
      // ios/windows.
      final config = _validWinn3ConfigForTests();
      final result = evaluateWinnDevConfigSourceConfig(
        config: config,
        operatingSystem: 'linux',
      );
      final direct =
          resolveWinnProtocolStart(operatingSystem: 'linux', config: config);
      expect(result.overrideResult!.decision.supported, isFalse);
      expect(result.overrideResult!.decision.reason,
          WinnRefusalReason.unsupportedPlatform);
      // The file must still mirror the real gate exactly rather than growing
      // a second opinion -- that is the property this group is named for, and
      // it is unchanged.
      expect(result.overrideResult!.decision.reason, direct.reason);
      expect(result.overrideResult!.decision.message, direct.message);
      expect(result.overrideResult!.decision.iniSection, direct.iniSection);

      // And the section this WOULD produce is still real and still checked,
      // so the demotion does not quietly retire coverage of the builder.
      final built = resolveWinnProtocolStartForServedConfig(config: config);
      expect(built.supported, isTrue, reason: built.message);
      expect(built.iniSection, contains('[winn]'));
      expect(built.iniSection, contains('enabled = true'));
      expect(built.iniSection, contains('endpoint = 127.0.0.1:51820'));
      expect(built.iniSection, contains('carrier = direct-awg'));
    });

    test('a winn/3 config invalid for a reason unrelated to the platform '
        '(bad mtu) surfaces that real reason, not swallowed by the '
        'required-field pre-check', () {
      // The subject is the pre-check in this file: it must not mask a real
      // config-level refusal behind a generic "missing field" verdict.
      //
      // Since 2026-08-08 the capability gate refuses first on every platform,
      // so the mtu reason is no longer reachable through
      // evaluateWinnDevConfigSourceConfig. Both halves are asserted: the
      // evaluation reports the platform gate honestly, and the mtu refusal is
      // proven still to fire on its own merits one call inwards -- which is
      // where the pre-check would have to mask it.
      final config = _validWinn3ConfigForTests()..['mtu'] = 40;
      final result = evaluateWinnDevConfigSourceConfig(
        config: config,
        operatingSystem: 'linux',
      );
      expect(result.overrideResult!.decision.supported, isFalse);
      expect(result.overrideResult!.decision.reason,
          WinnRefusalReason.unsupportedPlatform);

      final inner = resolveWinnProtocolStartForServedConfig(config: config);
      expect(inner.supported, isFalse);
      expect(
        inner.reason,
        WinnRefusalReason.mtuOutOfRange,
        reason: 'a bad mtu must still be reported as a bad mtu, not as a '
            'missing required field. When a platform is re-promoted this '
            'reason becomes reachable through the evaluation again.',
      );
    });

    test('parity: the [winn] section this file produces for a supported '
        'platform is byte-identical to calling resolveWinnProtocolStart '
        'directly, for several configs', () {
      final configs = <Map<String, dynamic>>[
        _validWinn3ConfigForTests(),
        _validWinn3ConfigForTests()..['mtu'] = 1420,
        _validWinn3ConfigForTests()
          ..['obfuscation'] = <String, dynamic>{
            'H1': 5,
            'H2': 6,
            'H3': 7,
            'H4': 8,
          },
      ];
      for (final config in configs) {
        final result = evaluateWinnDevConfigSourceConfig(
          config: config,
          operatingSystem: 'linux',
        );
        final direct = resolveWinnProtocolStart(
            operatingSystem: 'linux', config: config);
        expect(result.overrideResult!.decision.supported, direct.supported);
        expect(result.overrideResult!.decision.iniSection, direct.iniSection);
      }
    });

    test('logs are silent about secrets even along the full evaluate path',
        () {
      const planted = 'PLANTED_SECRET_EVAL_PATH_7c1e90';
      final config = _validWinn3ConfigForTests()
        ..['client_private_key'] = planted;
      final logs = <String>[];
      evaluateWinnDevConfigSourceConfig(
        config: config,
        operatingSystem: 'linux',
        log: logs.add,
      );
      expect(logs, isNotEmpty);
      for (final line in logs) {
        expect(line, isNot(contains(planted)));
      }
    });
  });

  group('resolveWinnDevConfigSourceStart: inactive (this is what the '
      'default `flutter test` run actually exercises)', () {
    test('returns active: false and touches nothing else', () {
      final logs = <String>[];
      final result = resolveWinnDevConfigSourceStart(
        operatingSystem: 'macos',
        log: logs.add,
      );
      expect(result.active, isFalse);
      expect(result.loadError, isNull);
      expect(result.normalizedConfig, isNull);
      expect(result.overrideResult, isNull);
      expect(logs, isEmpty,
          reason: 'Nothing was activated, so nothing should be logged -- '
              'in particular, no file should have been touched.');
    });
  });

  group('winnDevConfigSourceIniSection: throwing wrapper', () {
    test('throws when the module is inactive, naming why', () {
      expect(
        () => winnDevConfigSourceIniSection(operatingSystem: 'macos'),
        throwsA(isA<StateError>().having(
            (e) => e.toString(), 'message', contains('not active'))),
      );
    });
  });

  group('resolveWinnDevConfigPath: the "container:" scheme, which is the only '
      'way WINN_DEV_CONFIG_PATH is usable on iOS at all', () {
    test('a plain absolute path is passed through untouched, on every '
        'platform', () {
      final resolution = resolveWinnDevConfigPath('/tmp/dev_winn3.json');
      expect(resolution.usedContainerScheme, isFalse);
      expect(resolution.resolved, isTrue);
      expect(resolution.path, '/tmp/dev_winn3.json');
      expect(resolution.error, isNull);
    });

    test('a plain relative path is ALSO passed through untouched -- this '
        'change cannot alter what any existing invocation does', () {
      final resolution = resolveWinnDevConfigPath('dev_winn3.json');
      expect(resolution.usedContainerScheme, isFalse);
      expect(resolution.path, 'dev_winn3.json');
    });

    test('a container: path resolves under the container root\'s Documents/',
        () {
      final resolution = resolveWinnDevConfigPath(
        'container:dev_winn3_ios.json',
        containerRoot: '/var/mobile/Containers/Data/Application/ABC',
      );
      expect(resolution.usedContainerScheme, isTrue);
      expect(resolution.resolved, isTrue);
      expect(
        resolution.path,
        '/var/mobile/Containers/Data/Application/ABC/Documents/dev_winn3_ios.json',
      );
      expect(resolution.containerRoot,
          '/var/mobile/Containers/Data/Application/ABC');
    });

    test('a trailing slash on the container root does not double up', () {
      final resolution = resolveWinnDevConfigPath(
        'container:a.json',
        containerRoot: '/root/',
      );
      expect(resolution.path, '/root/Documents/a.json');
    });

    test('a nested container: path is allowed', () {
      final resolution = resolveWinnDevConfigPath(
        'container:winn/dev.json',
        containerRoot: '/root',
      );
      expect(resolution.path, '/root/Documents/winn/dev.json');
    });

    test('container: with nothing after it is refused', () {
      final resolution =
          resolveWinnDevConfigPath('container:', containerRoot: '/root');
      expect(resolution.resolved, isFalse);
      expect(resolution.error, contains('named no file'));
    });

    test('container: with an absolute remainder is refused rather than '
        'silently reinterpreted', () {
      final resolution = resolveWinnDevConfigPath(
        'container:/etc/passwd',
        containerRoot: '/root',
      );
      expect(resolution.resolved, isFalse);
      expect(resolution.error, contains('absolute'));
    });

    test('container: cannot escape the container with ..', () {
      for (final attempt in <String>[
        'container:../../../etc/passwd',
        'container:winn/../../secret.json',
        'container:..',
      ]) {
        final resolution =
            resolveWinnDevConfigPath(attempt, containerRoot: '/root');
        expect(resolution.resolved, isFalse, reason: attempt);
        expect(resolution.error, contains('".." segment'), reason: attempt);
      }
    });

    test('container: with no determinable container root is refused, not '
        'guessed', () {
      final resolution =
          resolveWinnDevConfigPath('container:a.json', containerRoot: '');
      expect(resolution.resolved, isFalse);
      expect(resolution.error, contains('could not be determined'));
    });

    test('the scheme and subdirectory constants are the ones the push tool '
        'and the docs name', () {
      expect(kWinnDevConfigContainerScheme, 'container:');
      expect(kWinnDevConfigContainerSubdirectory, 'Documents');
    });
  });

  group('winnDevConfigContainerRoot', () {
    test('prefers HOME, which on iOS IS the app data container root', () {
      expect(
        winnDevConfigContainerRoot(
          environment: <String, String>{'HOME': '/var/mobile/Containers/Data/Application/X'},
        ),
        '/var/mobile/Containers/Data/Application/X',
      );
    });

    test('falls back to the parent of the system temp directory', () {
      expect(
        winnDevConfigContainerRoot(
          environment: <String, String>{},
          systemTempPath: '/var/mobile/Containers/Data/Application/Y/tmp',
        ),
        '/var/mobile/Containers/Data/Application/Y',
      );
    });

    test('returns null when neither is available', () {
      expect(
        winnDevConfigContainerRoot(
          environment: <String, String>{},
          systemTempPath: '',
        ),
        isNull,
      );
    });
  });

  group('winnDevConfigSiblingJsonFileNames', () {
    test('lists only .json NAMES next to a resolved path, never contents', () {
      final dir = Directory.systemTemp.createTempSync('winn_dev_container');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}/b.json').writeAsStringSync('{"secret":"x"}');
      File('${dir.path}/a.json').writeAsStringSync('{}');
      File('${dir.path}/notes.txt').writeAsStringSync('ignored');

      final names = winnDevConfigSiblingJsonFileNames('${dir.path}/missing.json');
      expect(names, <String>['a.json', 'b.json']);
      expect(names.join(), isNot(contains('secret')));
    });

    test('a directory that does not exist yields an empty list, not a throw',
        () {
      expect(
        winnDevConfigSiblingJsonFileNames('/definitely/not/here/x.json'),
        isEmpty,
      );
    });
  });
}

/// A config that satisfies every required field this file checks AND is a
/// startable winn/3 config on a platform [kWinnHostCapabilities] already
/// supports. Kept as a local copy for the same reason
/// `test/winn_protocol_dev_override_test.dart` keeps its own rather than
/// importing another test file.
Map<String, dynamic> _validWinn3ConfigForTests() => <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{},
      'server_endpoint': '127.0.0.1:51820',
      'client_ip': '10.99.0.2',
      'client_private_key': '<REDACTED_WG_KEY>',
      'client_public_key': '<REDACTED_WG_KEY>',
      'server_public_key': '<REDACTED_WG_KEY>',
      'mtu': 1280,
      'dns': '10.99.0.1',
      'stealth_active': false,
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
