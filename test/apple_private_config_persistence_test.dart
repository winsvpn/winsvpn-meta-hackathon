import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('macOS VPN credentials use native owner-only persistence', () {
    final dart = File('lib/main.dart').readAsStringSync();
    final macos =
        File('macos/Runner/MainFlutterWindow.swift').readAsStringSync();

    expect(dart, contains("if (Platform.isIOS || Platform.isMacOS)"));
    expect(dart, contains("'persistVpnConfig'"));
    expect(
      dart,
      contains("(Platform.isIOS || Platform.isMacOS) &&"),
    );
    final restoreStart = dart.indexOf('_restoreAppleSmokeLocalState');
    final restoreEnd = dart.indexOf('_runAppleLiveTunnelSmoke()', restoreStart);
    final restoreBody = dart.substring(restoreStart, restoreEnd);
    expect(
      restoreBody.indexOf('_persistEncodedVpnConfigOnApple'),
      lessThan(restoreBody.indexOf('writeAsBytes')),
    );
    final persistStart = dart.indexOf('_persistVpnConfigBestEffort');
    final persistEnd =
        dart.indexOf('_persistEncodedVpnConfigOnApple', persistStart);
    expect(persistStart, greaterThanOrEqualTo(0));
    expect(persistEnd, greaterThan(persistStart));
    expect(
      dart.substring(persistStart, persistEnd),
      isNot(contains("File('\${directory.path}/vpn_config.txt')")),
    );
    expect(macos, contains('O_CREAT | O_EXCL | O_NOFOLLOW'));
    expect(macos, contains('renameat(directoryDescriptor'));
    expect(macos, contains('(finalInfo.st_mode & 0o777) == 0o600'));
    expect(macos, contains('case "persistVpnConfig"'));
  });

  test('iOS VPN credentials use protected native persistence end to end', () {
    final dart = File('lib/main.dart').readAsStringSync();
    final ios = File('ios/Runner/AppDelegate.swift').readAsStringSync();

    final persistStart = dart.indexOf('_persistVpnConfigBestEffort');
    final persistEnd = dart.indexOf('_readVpnRuntimeSettings', persistStart);
    final persistBody = dart.substring(persistStart, persistEnd);
    expect(persistBody, contains('Platform.isIOS || Platform.isMacOS'));
    expect(persistBody, contains('_persistEncodedVpnConfigOnApple(encoded)'));
    expect(
      persistBody,
      isNot(contains("File('\${directory.path}/vpn_config.txt')")),
    );

    final loadStart = dart.indexOf('_loadCachedVpnConfigFromDisk');
    final loadEnd = dart.indexOf('_currentAccountNumberForRefresh', loadStart);
    final loadBody = dart.substring(loadStart, loadEnd);
    expect(loadBody, contains('if (_isApplePlatform)'));
    expect(loadBody, contains('_readEncodedVpnConfigOnApple()'));

    final captureStart = dart.indexOf('_captureAppleSmokeLocalState');
    final captureEnd = dart.indexOf('_runAppleLiveTunnelSmoke()', captureStart);
    final smokeBody = dart.substring(captureStart, captureEnd);
    expect(smokeBody, contains('_readEncodedVpnConfigOnApple()'));
    expect(smokeBody, contains('_persistEncodedVpnConfigOnApple'));
    expect(smokeBody, contains('_deleteVpnConfigOnApple()'));

    expect(ios, contains('enum WinsIOSPrivateConfigStore'));
    expect(ios, contains('FileProtectionType.complete'));
    expect(ios, contains('#if targetEnvironment(simulator)'));
    expect(ios, contains('if requiresRuntimeDataProtectionValidation'));
    expect(ios, contains('iOS complete file protection is not active.'));
    expect(ios, contains('resourceValues.isExcludedFromBackup = true'));
    expect(ios, contains('O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW'));
    expect(ios, contains('AT_SYMLINK_NOFOLLOW'));
    expect(ios, contains('renameat(directoryDescriptor'));
    expect(ios, contains('(info.st_mode & 0o777) == 0o600'));
    expect(ios, contains('case "persistVpnConfig"'));
    expect(ios, contains('case "readVpnConfig"'));
    expect(ios, contains('case "deleteVpnConfig"'));
  });

  test('runtime settings use the cross-platform sensitive state path', () {
    final dart = File('lib/main.dart').readAsStringSync();
    expect(dart, contains("_readSensitiveJsonMap('vpn_settings.txt')"));
    expect(
      dart,
      contains("_writeSensitiveText('vpn_settings.txt', jsonEncode(data))"),
    );
  });

  // WIRING ONLY, AND DELIBERATELY SO.
  //
  // What this test can show is that the three sides are connected: the duress
  // sweep asks for the purge, and both Apple hosts answer. What it CANNOT show
  // is that the purge deletes anything -- an in-process Dart assertion has no
  // App Group container to look at. That property is proven where it can
  // actually be observed, against a real directory, by
  // `expectAppGroupDuressPurge()` in `tools/verify_apple_tunnel_config.swift`:
  // it builds a container holding the handoff documents, the Winn credential
  // set and a symbolic link pointing outward, purges it, and then RE-READS the
  // directory to assert only the container-manager metadata survived. It also
  // asserts the purge reports failure when removals are blocked and when the
  // container is missing, because a guard that cannot fail is not a guard.
  //
  // The gap this closes: until 2026-08-07 nothing on any deletion path --
  // duress, account deletion or Deactivate Device -- removed a single byte
  // from the App Group container. Dart cannot reach it (no Flutter plugins are
  // registered on either Apple platform, so the duress sweep can only
  // enumerate the app's own `Application Support/wins_vpn`), no method channel
  // exposed it, and neither Packet Tunnel provider ever deletes. A seized
  // device kept `Tunnel/latest_tunnel.conf` through a wipe the user believed
  // had cleared it.
  test('the duress sweep reaches the Apple App Group container', () {
    final dart = File('lib/main.dart').readAsStringSync();
    final ios = File('ios/Runner/AppDelegate.swift').readAsStringSync();
    final macos =
        File('macos/Runner/MainFlutterWindow.swift').readAsStringSync();

    // The call must live INSIDE the duress sweep, not merely somewhere in the
    // file. `_sweepAppStorageForDuress` is what the duress wipe calls; a purge
    // wired anywhere else would not run on the path that needs it.
    final sweepStart = dart.indexOf('_sweepAppStorageForDuress({');
    expect(sweepStart, greaterThanOrEqualTo(0));
    final sweepEnd = dart.indexOf(
      'THERE IS DELIBERATELY NO NATIVE APP-DATA WIPE ON THIS PATH ANY MORE',
      sweepStart,
    );
    expect(sweepEnd, greaterThan(sweepStart));
    final sweepBody = dart.substring(sweepStart, sweepEnd);
    expect(sweepBody, contains("'purgeAppGroupContainer'"));
    expect(sweepBody, contains('Platform.isIOS || Platform.isMacOS'));

    // The app's own storage and the App Group container must fail
    // independently: the purge sits outside the try that wraps the
    // app-container sweep, so a directory that cannot be resolved cannot take
    // the container purge down with it.
    expect(
      sweepBody.indexOf('Duress storage sweep did not fully complete'),
      lessThan(sweepBody.indexOf("'purgeAppGroupContainer'")),
    );

    for (final host in <String>[ios, macos]) {
      expect(host, contains('case "purgeAppGroupContainer"'));
      expect(host, contains('WinsAppGroupDuressPurge.purge('));
      // Absence must be reported rather than swallowed: an unresolvable
      // container is not a cleared one.
      expect(
          host, contains('WinsAppGroupDuressPurge.containerUnavailableReport'));
    }

    final core =
        File('apple/WinsTunnelCore/WinsTunnelConfig.swift').readAsStringSync();
    // The rule is inverted, exactly as `duressWipeKeepsEntry` inverts it on
    // the Dart side: everything goes except a closed keep-set. A named-file
    // list is what let `node_cache.json` survive an Android duress wipe.
    expect(core, contains('enum WinsAppGroupDuressPurge'));
    expect(
        core, contains('static func isPreservedEntry(_ name: String) -> Bool'));
    expect(core, contains('name.hasPrefix(".com.apple.")'));
    // The outcome is observed, not inferred from the removals.
    expect(core, contains('let remainingObserved: Bool'));
    expect(core, contains('&& remainingObserved'));
  });
}
