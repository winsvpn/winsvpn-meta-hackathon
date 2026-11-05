// Crash-report privacy tests.
//
// Every rule in kCrashRedactionRules is asserted twice: once that it fires on
// its own needle (the POSITIVE control), and once that the whole rule set has
// exactly the expected membership so a deleted or renamed rule fails loudly
// (the structural guard the catalogue says is usually the missing negative).
// Two controls prevent the readactor being "safe by over-redaction": timestamps
// and package-relative stack lines must survive untouched, and a consent gate
// that mis-reports ANY of its fail-closed states is caught.

import 'dart:convert';
import 'dart:io';
import 'dart:ui' show PlatformDispatcher;

import 'package:flutter/foundation.dart' show FlutterError, FlutterErrorDetails, ErrorDescription;
import 'package:flutter_test/flutter_test.dart';

import 'package:wins_vpn/crash_report_privacy.dart';

const kHex64 =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

final kNeedles = <String, ({String needle, String tag, String gone})>{
  'url': (
    needle: 'wss://edge.example.net:443/ws?token=abc',
    tag: '<url>',
    gone: 'edge.example.net',
  ),
  'credential': (
    needle: 'alice:supersecret@carrier.example.com',
    tag: '<credential>',
    gone: 'carrier.example.com',
  ),
  'winpath': (
    needle: r'C:\Users\operator\AppData\Roaming\WinsVPN\config.json',
    tag: '<path>',
    gone: r'C:\Users\operator',
  ),
  'posix_path': (
    needle: '/Users/operator/Library/Application Support/WinsVPN/config.json',
    tag: '<path>',
    gone: '/Users/operator',
  ),
  'ipv6': (
    needle: '2001:db8:85a3::8a2e:370:7334',
    tag: '<ip>',
    gone: '2001:db8',
  ),
  'ipv4': (
    needle: '203.0.113.7:51820',
    tag: '<ip>',
    gone: '203.0.113.7',
  ),
  'host_port': (
    needle: 'fallback.example.com:8443',
    tag: '<host>',
    gone: 'fallback.example.com',
  ),
  'email': (
    needle: 'win.operator@example.org',
    tag: '<email>',
    gone: 'win.operator',
  ),
  'account_dashed': (
    needle: '9999-9999-9999',
    tag: '<account>',
    gone: '9999-9999',
  ),
  'account_plain': (
    needle: '999999999999',
    tag: '<account>',
    gone: '999999999999',
  ),
  'uuid': (
    needle: '01234567-89ab-cdef-0123-456789abcdef',
    tag: '<id>',
    gone: '01234567',
  ),
  'mac_address': (
    needle: '00:11:22:33:44:55',
    tag: '<id>',
    gone: '00:11:22:33:44:55',
  ),
  'hex64_key': (needle: kHex64, tag: '<key>', gone: kHex64),
  'jwt': (
    needle:
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
        'abcdefghijklmnopqrstuvwxyzabcdefghijklm',
    tag: '<token>',
    gone: 'eyJhbGci',
  ),
  'base64_key': (
    needle: '${'Q' * 43}=',
    tag: '<key>',
    gone: 'QQQ',
  ),
  'long_token': (
    needle: 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_AbCdEfGhIjKlMnOpQrStUv',
    tag: '<key>',
    gone: 'AbCdEfGhIjKlMnOpQrStUvWxYz',
  ),
  'install_id': (
    needle: 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456',
    tag: '<id>',
    gone: 'AbCdEfGhIjKl',
  ),
  'device_id_install': (
    needle: 'INSTALL-ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    tag: '<id>',
    gone: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  ),
  'bare_hostname': (
    needle: 'lookup cdn.example-edge.net failed',
    tag: '<host>',
    gone: 'cdn.example-edge.net',
  ),
};

void main() {
  group('redactor: hostname rule order', () {
    test('the hostname rule runs after the email, jwt and key rules', () {
      final names = kCrashRedactionRules.map((r) => r.name).toList();
      expect(names.last, 'bare_hostname');
      for (final earlier in <String>['email', 'jwt', 'long_token']) {
        expect(names.indexOf(earlier), lessThan(names.indexOf('bare_hostname')));
      }
    });

    test('an email address is one email, not a host fragment', () {
      final out = redactCrashReport('contact win.operator@example.org failed');
      expect(out.redacted, 'contact <email> failed');
      expect(out.redacted, isNot(contains('<host>@')));
    });

    test('a dotted token never leaves a fragment behind', () {
      const token =
          'abcdefghijklmnopqrst.uvwxyzabcdefghijklmn.0123456789abcdefghijkl';
      final out = redactCrashReport('token $token end');
      expect(out.redacted, isNot(contains('0123456789abcdefghijkl')));
    });
  });

  group('redactor: rule set structural guard', () {
    test('every rule that exists fires on its own needle', () {
      final byName = {for (final r in kCrashRedactionRules) r.name: r};
      expect(byName.keys.toSet(), kNeedles.keys.toSet());
      for (final entry in kNeedles.entries) {
        final rule = byName[entry.key];
        expect(rule, isNotNull, reason: 'rule ${entry.key} must exist');
        expect(
          rule!.pattern.hasMatch(entry.value.needle),
          isTrue,
          reason: 'rule ${entry.key} must fire on its own needle',
        );
      }
    });

    test('the published rule set is exactly the reviewed set', () {
      expect(
        kCrashRedactionRules.map((r) => r.name).toList(),
        kNeedles.keys.toList(),
      );
    });
  });

  group('redactor: rules fire end to end', () {
    test('each sensitive shape disappears and leaves its tag', () {
      for (final entry in kNeedles.entries) {
        final input = 'sentinel ${entry.value.needle} sentinel';
        final result = redactCrashReport(input);
        expect(
          result.replacedByTag.containsKey(entry.value.tag),
          isTrue,
          reason: 'rule ${entry.key} should report tag ${entry.value.tag}',
        );
        expect(
          result.redacted,
          isNot(contains(entry.value.gone)),
          reason: 'rule ${entry.key} must remove ${entry.value.gone}',
        );
      }
    });

    test('a credential inside a URL is consumed whole, not left behind', () {
      final result = redactCrashReport(
        'vless://01234567-89ab-cdef-0123-456789abcdef@edge.example.net:80',
      );
      expect(result.replacedByTag['<url>'], 1);
      expect(result.redacted, contains('<url>'));
      expect(result.redacted, isNot(contains('vless://')));
      expect(result.redacted, isNot(contains('edge.example.net')));
      expect(result.redacted, isNot(contains('01234567-89ab')));
    });

    test('IPv6 with port and zone identifier is redacted', () {
      final result = redactCrashReport('[2001:db8::1%en0]:443');
      expect(result.replacedByTag['<ip>'], greaterThanOrEqualTo(1));
      expect(result.redacted, isNot(contains('2001:db8')));
    });

    test('IPv6 before a sentence period is redacted', () {
      final result = redactCrashReport(
          'SocketException: no route to 2001:db8::2. Retrying via 2a02:6b8:a::a.');
      expect(result.replacedByTag['<ip>'], greaterThanOrEqualTo(2));
      expect(result.redacted, isNot(contains('2001:db8')));
      expect(result.redacted, isNot(contains('2a02:6b8')));
      expect(result.redacted, contains('<ip>.'));
    });
  });

  group('redactor: does not over-redact', () {
    test('timestamps are not classified as IPs', () {
      const input = 'attempt started at 12:34:56 and ended at 23:59:59';
      final result = redactCrashReport(input);
      expect(result.redacted, contains('12:34:56'));
      expect(result.redacted, contains('23:59:59'));
      expect(result.replacedByTag.containsKey('<ip>'), isFalse);
    });

    test('package-relative stack lines and line numbers survive', () {
      const input = 'Bad state: tunnel closed\n'
          '#0      _VpnDashboardBodyState._connect '
          '(package:wins_vpn/lib/main.dart:421:9)\n'
          '#1      _VpnDashboardBodyState.initState '
          '(package:wins_vpn/lib/main.dart:5200:15)';
      final result = redactCrashReport(input);
      expect(result.redacted, isNot(contains('<path>')));
      expect(result.redacted, contains('package:wins_vpn/lib/main.dart'));
      expect(result.redacted, contains('421:9'));
      expect(result.redacted, contains('5200:15'));
    });

    test('a long pure-letter class name is not an install identifier', () {
      final className =
          'TomcatServerCouldNotStartBecauseOfADefect';
      final result = redactCrashReport(
        'RemoteException: $className (java.internals)',
      );
      expect(result.redacted, contains(className));
      expect(result.replacedByTag.containsKey('<id>'), isFalse);
    });

    test('an all-letters INSTALL device id is redacted (no digit needed)', () {
      const deviceId = 'INSTALL-ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      final result = redactCrashReport('device $deviceId rejected');
      expect(result.redacted, isNot(contains('ABCDEFGHIJKLMNOP')));
      expect(result.replacedByTag['<id>'], greaterThanOrEqualTo(1));
    });

    test('a class name beginning with Install is not a device id', () {
      const className = 'InstallationValidatorRejectedThePayload';
      final result = redactCrashReport('RemoteException: $className');
      expect(result.redacted, contains(className));
      expect(result.replacedByTag.containsKey('<id>'), isFalse);
    });


    test('placeholder tags are not re-scanned into false shapes', () {
      final result = redactCrashReport(
        'host 203.0.113.7 then -100.0.0 > -200.0.0 in a negative numbers list',
      );
      expect(result.redacted, contains('<ip>'));
    });
  });

  group('redactor: realistic sample log lines', () {
    test('nothing sensitive survives a mixed multi-line crash log', () {
      final rawLog = '[2026-08-11 02:00:00.000] INFO  TunController: '
          'connecting to 203.0.113.7:51820 as '
          'alice:supersecret@carrier.example.com\n'
          '[2026-08-11 02:00:01.000] DEBUG ConfigLoader: loaded '
          '/Users/operator/Library/config.json\n'
          '[2026-08-11 02:00:02.000] ERROR Handshake: key $kHex64 failed\n'
          'E/flutter ( 1234): StateError: Bad state: no element\n'
          '#0      _connect (package:wins_vpn/lib/main.dart:421)\n'
          'agent win.operator@example.org '
          'install AbCdEfGhIjKlMnOpQrStUvWxYz0123456 '
          'DEVICE INSTALL-ABCDEFGHIJKLMNOPQRSTUVWXYZ234567\n'
          'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
          'abcdefghijklmnopqrstuvwxyzabcdefghijklm '
          'account 9999-9999-9999 mac 00:11:22:33:44:55';

      final result = redactCrashReport(rawLog);
      const mustVanish = <String>[
        '203.0.113.7',
        '51820',
        'alice:supersecret@carrier.example.com',
        'supersecret@carrier.example.com',
        '/Users/operator',
        kHex64,
        'win.operator@example.org',
        'AbCdEfGhIjKlMnOpQrStUvWxYz0123456',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
        'eyJhbGciOiJIUzI1NiJ9',
        '9999-9999-9999',
        '00:11:22:33:44:55',
      ];
      for (final token in mustVanish) {
        expect(
          result.redacted,
          isNot(contains(token)),
          reason: 'sensitive token must be scrubbed from the log: $token',
        );
      }
      // The log's non-sensitive structure must survive into the record so the
      // triage value is not lost to over-redaction.
      expect(result.redacted, contains('TunController'));
      expect(result.redacted, contains('package:wins_vpn/lib/main.dart'));
      expect(result.redacted, contains('02:00:00.000'));
      expect(result.redacted, contains('Handshake'));
    });
  });

  group('redactCrashReport: boundaries', () {
    test('a payload is truncated to the limit and flagged', () {
      final result = redactCrashReport(
        'x' * (kCrashReportTextLimit + 200),
      );
      expect(result.truncated, isTrue);
      expect(result.redacted.length, kCrashReportTextLimit);
    });

    test('an all-whitespace payload becomes a safe sentinel', () {
      expect(redactCrashReport('   \n  ').redacted, 'unspecified_crash');
    });
  });

  group('consent gate: fails closed', () {
    late Directory tempDir;
    late File consentFile;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('wins_crash_priv_test');
      consentFile = File('${tempDir.path}/$kCrashReportConsentFileName');
    });

    tearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test('no consent file means no consent', () async {
      final gate = CrashReportConsentGate(consentFile);
      expect(await gate.isExplicitlyGranted(), isFalse);
    });

    test('an explicit grant flips the gate, revoke flips it back', () async {
      final gate = CrashReportConsentGate(consentFile);
      expect(await gate.isExplicitlyGranted(), isFalse);
      await gate.grantExplicitly();
      expect(await gate.isExplicitlyGranted(), isTrue);
      await gate.revoke();
      expect(await gate.isExplicitlyGranted(), isFalse);
      expect(await consentFile.exists(), isFalse,
          reason: 'revocation must delete the marker, not blank it');
    });

    test('oversized marker file is treated as no consent', () async {
      await consentFile.parent.create(recursive: true);
      await consentFile.writeAsString('${CrashReportConsentGate.grantedMarker}\n'
          '${' ' * (CrashReportConsentGate.kMaxConsentFileBytes)}');
      final gate = CrashReportConsentGate(consentFile);
      expect(await gate.isExplicitlyGranted(), isFalse);
    });

    test('a marker that is not exactly the granted value is no consent',
        () async {
      await consentFile.parent.create(recursive: true);
      await consentFile.writeAsString('grantedX\n');
      expect(
        await CrashReportConsentGate(consentFile).isExplicitlyGranted(),
        isFalse,
      );
    });

    test('an unreadable consent path is no consent', () async {
      await consentFile.parent.create(recursive: true);
      await tempDir.delete(recursive: true);
      final gate = CrashReportConsentGate(consentFile);
      expect(await gate.isExplicitlyGranted(), isFalse);
    });
  });

  group('upload guard: no automatic upload without consent', () {
    late Directory tempDir;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('wins_crash_priv_test');
    });

    tearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test('refuses and never calls the transport without consent', () async {
      final gate = CrashReportConsentGate(consentFileAt(tempDir));
      var calls = 0;
      Future<void> transport(String record) async {
        calls += 1;
      }

      await expectLater(
        uploadCrashReportIfConsented(
          consent: gate,
          redactedReport: 'redacted',
          transport: transport,
        ),
        throwsA(isA<CrashReportUploadRefused>()),
      );
      expect(calls, 0,
          reason: 'the transport must not run when consent is absent');
    });

    test('calls the transport exactly once after explicit consent', () async {
      final gate = CrashReportConsentGate(consentFileAt(tempDir));
      await gate.grantExplicitly();
      final records = <String>[];
      Future<void> transport(String record) async => records.add(record);

      await uploadCrashReportIfConsented(
        consent: gate,
        redactedReport: 'redacted-a',
        transport: transport,
      );
      await uploadCrashReportIfConsented(
        consent: gate,
        redactedReport: 'redacted-b',
        transport: transport,
      );

      expect(records, ['redacted-a', 'redacted-b']);
    });

    test('refuses again after consent is revoked', () async {
      final gate = CrashReportConsentGate(consentFileAt(tempDir));
      await gate.grantExplicitly();
      await gate.revoke();
      var calls = 0;
      await expectLater(
        uploadCrashReportIfConsented(
          consent: gate,
          redactedReport: 'redacted',
          transport: (String record) async {
            calls += 1;
          },
        ),
        throwsA(isA<CrashReportUploadRefused>()),
      );
      expect(calls, 0);
    });
  });

  group('capture pipeline: redaction at the boundary', () {
    late Directory tempDir;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('wins_crash_priv_test');
    });

    tearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    const raw =
        'StateError: endpoint 203.0.113.7 key $kHex64 account 9999-9999-9999 '
        'install AbCdEfGhIjKlMnOpQrStUvWxYz0123456';
    final stack = StackTrace.fromString(
      '#0      _connect (package:wins_vpn/lib/main.dart:421)',
    );

    test('only the scrubbed record is written to disk', () async {
      final gate = CrashReportConsentGate(consentFileAt(tempDir));
      final capture = CrashReportCapture(
        reportDirectory: tempDir,
        consentGate: gate,
        platformName: 'android',
        appVersion: '1.0.0+1',
      );
      await capture.capture(StateError(raw), stack);

      final reportsDir = Directory('${tempDir.path}/crash_reports');
      final files = reportsDir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.endsWith('.txt'))
          .toList();
      expect(files, hasLength(1));
      final body = await files.single.readAsString();
      expect(
        body,
        isNot(contains('203.0.113.7')),
        reason: 'endpoint must never reach disk',
      );
      expect(body, isNot(contains(kHex64)));
      expect(body, isNot(contains('9999-9999-9999')));
      expect(body, isNot(contains('AbCdEfGhIjKlMnOp')));
      expect(body, contains('<ip>'));
      expect(body, contains('<key>'));
      expect(body, contains('<account>'));
      expect(body, contains('<id>'));
      expect(body, contains('"schema": "1"'));
      expect(body, contains('"platform": "android"'));
      expect(body, contains('"app_version": "1.0.0+1"'));
      final decoded = jsonDecode(body) as Map<String, dynamic>;
      expect(decoded['redacted_crash_text'], isA<String>());
      // The identity-bearing raw material must not be recoverable from the
      // record's JSON text.
      expect(body.contains('AbCdEfGhIjKl'), isFalse);
    });

    test('transport is not called when consent is absent', () async {
      var calls = 0;
      final capture = CrashReportCapture(
        reportDirectory: tempDir,
        consentGate: CrashReportConsentGate(consentFileAt(tempDir)),
        transport: (String record) async {
          calls += 1;
        },
      );
      await capture.capture(StateError(raw), stack);
      expect(calls, 0);
    });

    test('transport receives only the scrubbed record once consent given',
        () async {
      final gate = CrashReportConsentGate(consentFileAt(tempDir));
      await gate.grantExplicitly();
      final received = <String>[];
      final capture = CrashReportCapture(
        reportDirectory: tempDir,
        consentGate: gate,
        transport: (String record) async {
          received.add(record);
        },
      );
      await capture.capture(StateError(raw), stack);
      expect(received, hasLength(1));
      expect(received.single, isNot(contains('203.0.113.7')));
      expect(received.single, isNot(contains(kHex64)));
      expect(received.single, contains('<account>'));
    });

    test('capture never throws even when no directory can be created',
        () async {
      final blocker = File('${tempDir.path}/blocker');
      await blocker.writeAsString('x');
      final capture = CrashReportCapture(
        reportDirectory: Directory('${tempDir.path}/blocker'),
        consentGate: CrashReportConsentGate(consentFileAt(tempDir)),
      );
      final result = await capture.capture(StateError(raw), stack);
      expect(result.redacted, isNot(contains('203.0.113.7')));
    });
  });

  group('global crash sink wiring', () {

    test('prior handlers receive only redacted errors and stacks', () {
      const address = '203.0.113.7';
      const account = '9999-9999-9999';
      const key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const path = '/Users/example/private/account.txt';
      const canary = '$address account $account private_key=$key $path';
      Object? receivedError;
      StackTrace? receivedStack;
      FlutterErrorDetails? receivedDetails;
      PlatformDispatcher.instance.onError = (error, stack) {
        receivedError = error;
        receivedStack = stack;
        return false;
      };
      FlutterError.onError = (details) => receivedDetails = details;
      installPrivacySafeCrashSink();
      expect(PlatformDispatcher.instance.onError!(
        StateError(canary), StackTrace.fromString(canary)), isTrue);
      FlutterError.onError!(FlutterErrorDetails(
        exception: StateError(canary),
        stack: StackTrace.fromString(canary),
        context: ErrorDescription(canary),
        library: canary,
        informationCollector: () => [ErrorDescription(canary)],
      ));
      for (final value in [receivedError.toString(), receivedStack.toString(),
        receivedDetails!.exception.toString(), receivedDetails!.stack.toString()]) {
        for (final secret in [address, account, key, path]) {
          expect(value, isNot(contains(secret)));
        }
      }
      expect(receivedDetails!.context, isNull);
      expect(receivedDetails!.library, isNot(contains(canary)));
      expect(receivedDetails!.informationCollector, isNull);
    });

    test('sink handles an error when no prior platform handler exists', () {
      PlatformDispatcher.instance.onError = null;
      installPrivacySafeCrashSink();
      expect(PlatformDispatcher.instance.onError!(
        StateError('203.0.113.7'), StackTrace.empty), isTrue);
    });
    late Directory tempDir;
    final previousOnError = PlatformDispatcher.instance.onError;
    final previousFlutterOnError = FlutterError.onError;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('wins_crash_priv_test');
    });

    tearDown(() async {
      globalCrashReportDirectory = null;
      PlatformDispatcher.instance.onError = previousOnError;
      FlutterError.onError = previousFlutterOnError;
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test('sink redacts and drops when no directory provider is set', () {
      final priorCalled = <String>[];
      PlatformDispatcher.instance.onError =
          (Object error, StackTrace stack) {
        priorCalled.add('prior:${error.runtimeType}');
        return true;
      };
      installPrivacySafeCrashSink();

      final handler = PlatformDispatcher.instance.onError;
      final handled = handler!(
        StateError('naked 203.0.113.7'),
        StackTrace.empty,
      );
      expect(handled, isTrue);
      expect(priorCalled, hasLength(1));
    });

    test(
        'sink writes a scrubbed record and does not upload without consent',
        () async {
      globalCrashReportDirectory = tempDir;
      var uploadCalls = 0;
      installPrivacySafeCrashSink(transport: (String record) {
        uploadCalls += 1;
        return Future.value();
      });

      final handler = PlatformDispatcher.instance.onError!;
      handler(
        StateError('naked 203.0.113.7 account 9999-9999-9999'),
        StackTrace.fromString('#0 _x (package:wins_vpn/lib/x.dart:1)'),
      );

      await _pollUntil(() async {
        final reportsDir = Directory('${tempDir.path}/crash_reports');
        return await reportsDir.exists() &&
            reportsDir
                .listSync()
                .any((f) => f is File && f.path.endsWith('.txt'));
      });
      final reportsDir = Directory('${tempDir.path}/crash_reports');
      final bodies = reportsDir
          .listSync()
          .whereType<File>()
          .map((f) => f.readAsString())
          .toList();
      expect(bodies, isNotEmpty);
      for (final body in bodies) {
        expect(await body, isNot(contains('203.0.113.7')));
        expect(await body, isNot(contains('9999-9999-9999')));
        expect(await body, contains('<ip>'));
      }
      expect(uploadCalls, 0,
          reason: 'no consent file exists, so no upload may happen');
    });
  });

  test('unbracketed IPv6 with port is redacted', () {
    const rawLog = 'Handshake failed connecting to 2001:0db8:0000:0000:0000:0000:0000:0001:51820 timeout';
    final result = redactCrashReport(rawLog);
    expect(result.redacted, isNot(contains('2001:0db8')));
    expect(result.replacedByTag['<ip>'], greaterThanOrEqualTo(1));
  });
}

Future<void> _pollUntil(Future<bool> Function() predicate) async {
  for (var i = 0; i < 100; i++) {
    if (await predicate()) return;
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  fail('condition was not satisfied within the poll window');
}

File consentFileAt(Directory dir) =>
    File('${dir.path}/$kCrashReportConsentFileName');