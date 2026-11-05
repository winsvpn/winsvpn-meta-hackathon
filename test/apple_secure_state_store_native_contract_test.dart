import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Regression coverage for the 2026-08-04 macOS privacy-consent bug: every
// secureStateRead/Write/Delete call on iOS and macOS was silently rejected
// by WinsSecureStateStore's allowedNames set (apple/WinsTunnelCore/
// WinsSecureStateStore.swift), which held "cleaned up" bare names
// ("user_pin", "vpn_settings", "pending_logout") that never matched what
// Dart actually sends -- the file-extension-carrying names in
// _sensitiveStateFileNames (lib/main.dart). The mismatch meant the write
// never reached Keychain at all (rejected before any Security-framework
// call), so the Privacy Policy acceptance flag never persisted and every
// launch re-prompted. See docs/handoff/ for the full incident writeup.
//
// This is a cross-language contract with nothing at compile time to keep
// the two allowlists in agreement, so -- following the same pattern already
// used for the Linux native store in linux_secure_store_native_contract_
// test.dart and for dozens of other lib/main.dart contracts in
// secure_sensitive_state_contract_test.dart -- these tests read both source
// files as text and pin them against each other directly.
void main() {
  final dartSource = File('lib/main.dart').readAsStringSync();
  final swiftSource =
      File('apple/WinsTunnelCore/WinsSecureStateStore.swift').readAsStringSync();

  const canonicalNames = <String>{
    'client_keypair.json',
    'calc_session.json',
    'calc_state.json',
    'install_id.txt',
    'node_cache.json',
    'pending_logout.json',
    'user_pin.txt',
    'vpn_config.txt',
    'vpn_settings.txt',
    'wins_vpn_restart_config.conf',
    // This device's own winn/3 static identity (IA-CP-05, 2026-09-29).
    'winn3_keypair.json',
    'direct_udp_transport_memory.json',
  };

  test('iOS and macOS secure state is non-migratable device-only Keychain data', () {
    expect(swiftSource, contains('#if os(iOS) || os(macOS)'));
    expect(
      swiftSource,
      contains('kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly'),
    );
  });

  test(
      'WinsSecureStateStore.allowedNames is byte-for-byte the same set as '
      "Dart's _sensitiveStateFileNames, not the old extension-less names",
      () {
    final dartNamesStart =
        dartSource.indexOf('static const Set<String> _sensitiveStateFileNames = <String>{');
    final dartNamesEnd = dartSource.indexOf('};', dartNamesStart);
    expect(dartNamesStart, greaterThanOrEqualTo(0));
    expect(dartNamesEnd, greaterThan(dartNamesStart));
    final dartNamesBody = dartSource.substring(dartNamesStart, dartNamesEnd);

    final swiftNamesStart =
        swiftSource.indexOf('private static let allowedNames: Set<String> = [');
    final swiftNamesEnd = swiftSource.indexOf(']', swiftNamesStart);
    expect(swiftNamesStart, greaterThanOrEqualTo(0));
    expect(swiftNamesEnd, greaterThan(swiftNamesStart));
    final swiftNamesBody = swiftSource.substring(swiftNamesStart, swiftNamesEnd);

    final dartNames = RegExp(r"'([^']+)'")
        .allMatches(dartNamesBody)
        .map((m) => m.group(1)!)
        .toSet();
    final swiftNames = RegExp('"([^"]+)"')
        .allMatches(swiftNamesBody)
        .map((m) => m.group(1)!)
        .toSet();

    expect(dartNames, equals(canonicalNames),
        reason: '_sensitiveStateFileNames drifted from the canonical set');
    expect(swiftNames, equals(canonicalNames),
        reason: 'WinsSecureStateStore.allowedNames drifted from the '
            'canonical set (this is exactly the pre-fix bug shape)');

    // The pre-fix bug, pinned directly: these bare, extension-less names
    // must never reappear in the allowlist body specifically (each checked
    // as a complete quoted token, so this does not false-positive against
    // e.g. "vpn_settings.txt", which contains "vpn_settings" as a
    // substring but is a different token).
    for (final staleName in <String>['user_pin', 'vpn_settings', 'pending_logout']) {
      expect(swiftNamesBody, isNot(contains('"$staleName"')), reason: staleName);
    }
  });

  test(
      'isNameAllowed is an unmodified Set.contains with no prefix/suffix/'
      'regex normalization applied to the name first', () {
    final start = swiftSource.indexOf('static func isNameAllowed(_ name: String) -> Bool {');
    final end = swiftSource.indexOf('static func read(name: String)', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    expect(
      swiftSource.substring(start, end),
      contains('allowedNames.contains(name)'),
    );

    // read/write/delete must each fail closed on an unrecognized name
    // before doing anything else -- in particular, before any
    // transformation of `name` that could let two different wire names
    // collide on the same Keychain item.
    for (final signature in <String>[
      'static func read(name: String) throws -> String? {',
      'static func write(name: String, value: String) throws {',
      'static func delete(name: String) throws {',
    ]) {
      final fnStart = swiftSource.indexOf(signature);
      expect(fnStart, greaterThanOrEqualTo(0), reason: signature);
      final guardStart = swiftSource.indexOf('guard isNameAllowed(name) else {', fnStart);
      final throwStart = swiftSource.indexOf('throw nameNotAllowedError()', guardStart);
      expect(guardStart, greaterThanOrEqualTo(0), reason: signature);
      expect(throwStart, greaterThan(guardStart), reason: signature);
      // The allowlist guard must be the very first statement in the
      // function body (immediately after the opening brace of the
      // signature), not preceded by any name transformation.
      expect(
        swiftSource.substring(fnStart + signature.length, guardStart).trim(),
        isEmpty,
        reason: '$signature must check isNameAllowed(name) before doing '
            'anything else with name',
      );
    }

    for (final loosening in <String>[
      '.lowercased()',
      '.trimmingCharacters',
      'hasPrefix(',
      'hasSuffix(',
      'replacingOccurrences',
      'NSRegularExpression',
    ]) {
      expect(swiftSource, isNot(contains(loosening)), reason: loosening);
    }
  });

  test(
      'secureStateRead/Write/Delete NSLog the real (redaction-safe) failure '
      'before returning the FlutterError, so a native failure is never '
      'silent outside of a Dart debug console', () {
    for (final entry in <List<String>>[
      [
        'private func secureStateRead(_ arguments: Any?, result: @escaping FlutterResult) {',
        'private func secureStateWrite(',
        'APPLE_SECURE_STATE_READ_FAILED',
      ],
      [
        'private func secureStateWrite(_ arguments: Any?, result: @escaping FlutterResult) {',
        'private func secureStateDelete(',
        'APPLE_SECURE_STATE_WRITE_FAILED',
      ],
      [
        'private func secureStateDelete(_ arguments: Any?, result: @escaping FlutterResult) {',
        'private func measureDownloadMbps(',
        'APPLE_SECURE_STATE_DELETE_FAILED',
      ],
    ]) {
      final source =
          File('macos/Runner/MainFlutterWindow.swift').readAsStringSync();
      final start = source.indexOf(entry[0]);
      final end = source.indexOf(entry[1], start);
      expect(start, greaterThanOrEqualTo(0), reason: entry[0]);
      expect(end, greaterThan(start), reason: entry[0]);
      final body = source.substring(start, end);

      var cursor = 0;
      void expectInOrder(String needle) {
        final index = body.indexOf(needle, cursor);
        expect(index, greaterThanOrEqualTo(cursor),
            reason: 'expected "$needle" after offset $cursor in ${entry[0]}');
        cursor = index + needle.length;
      }

      expectInOrder('} catch {');
      expectInOrder('NSLog(');
      expectInOrder('WinsTunnelDiagnostics.redactedAppleErrorMessage(error)');
      expectInOrder('result(flutterError("${entry[2]}", error))');
    }
  });

  test(
      'accepting the Privacy Policy never claims consent granted when the '
      'durable write fails, and shows the real reason instead of silently '
      'looping the dialog', () {
    final start = dartSource
        .indexOf('Future<bool> _showPrivacyPolicyDialog({required bool requireConsent}) async {');
    final end = dartSource.indexOf(
        'Future<void> _showSecureStateFailureDialog(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = dartSource.substring(start, end);

    var cursor = 0;
    void expectInOrder(String needle) {
      final index = body.indexOf(needle, cursor);
      expect(index, greaterThanOrEqualTo(cursor),
          reason: 'expected "$needle" after offset $cursor in '
              '_showPrivacyPolicyDialog');
      cursor = index + needle.length;
    }

    expectInOrder('if (requireConsent && result == true) {');
    expectInOrder('try {');
    expectInOrder('await _persistPrivacyConsent();');
    expectInOrder('} catch (e) {');
    expectInOrder('await _showSecureStateFailureDialog(');
    expectInOrder('return _privacyConsentGranted;');
    // _privacyConsentGranted = true must only be reachable after the
    // catch block above, i.e. only on a successful persist.
    expectInOrder('_privacyConsentGranted = true;');
    expectInOrder('_startPostPrivacyConsentInitialization();');

    final dialogStart =
        dartSource.indexOf('Future<void> _showSecureStateFailureDialog({');
    final dialogEnd =
        dartSource.indexOf('Future<bool> _ensurePrivacyConsentForNetworkUse()', dialogStart);
    expect(dialogStart, greaterThanOrEqualTo(0));
    expect(dialogEnd, greaterThan(dialogStart));
    final dialogBody = dartSource.substring(dialogStart, dialogEnd);
    // Reuses the same redaction-safe formatter already used for tunnel
    // errors (apple_tunnel_diagnostics.dart) instead of a fresh,
    // independently-reviewed path that could leak something unsafe.
    expect(dialogBody, contains('nativeTunnelErrorSummary(error)'));
  });
}
