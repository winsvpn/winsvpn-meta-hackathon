// CORE-7-T17C-claude: the native edges of the local account reset. Android
// refuses every tunnel start from the start seal on, before any configuration
// is read; Apple purges the shared App Group container, and Windows and Linux
// erase their runtime configuration copies and observe none left, before the
// cleanup journal goes. Kotlin, Swift and C++ are not compiled by the Flutter
// suite; their source is pinned here.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _block(String source, String start, String end) {
  final first = source.indexOf(start);
  expect(first, greaterThanOrEqualTo(0), reason: start);
  final last = source.indexOf(end, first + start.length);
  expect(last, greaterThan(first), reason: end);
  return source.substring(first, last);
}

void main() {
  test('Android start gates precede configuration consumption', () {
    const nativeRoot = 'android/app/src/main/kotlin/org/winsvpn/app';
    final store = File('$nativeRoot/SecureFileStore.kt').readAsStringSync();
    final activity = File('$nativeRoot/MainActivity.kt').readAsStringSync();
    final service =
        File('$nativeRoot/VpnTunnelService.kt').readAsStringSync();

    expect(
      store,
      contains('accountStartsSealed || accountDataResetStarted'),
    );
    expect(
      store,
      contains('@Volatile\n    private var accountStartsSealed'),
    );
    expect(store, isNot(contains('accountStartsSealed = false')),
        reason: 'the start seal never lifts in this process');

    final start = _block(
      activity,
      '                "startTunnel" -> {',
      '                "stopTunnel" -> {',
    );
    final startGate =
        start.indexOf('if (secureFileStore.accountResetPending()) {');
    expect(startGate, greaterThanOrEqualTo(0));
    expect(startGate, lessThan(start.indexOf('val configString')));
    expect(start, contains('return@setMethodCallHandler'));

    final launch = _block(
      activity,
      '    private fun executeServiceLaunch() {',
      '        val config = pendingConfig',
    );
    expect(launch, contains('if (secureFileStore.accountResetPending()) {'));
    expect(launch, contains('cancelPendingVpnAuthorization()'));
    expect(launch, contains('return\n'));

    final command = _block(
      service,
      '    override fun onStartCommand(',
      '        val suppliedConfig =',
    );
    final commandGate = command.indexOf(
        'if (secureFileStore.accountResetPending() &&');
    expect(commandGate, greaterThanOrEqualTo(0));
    expect(command, contains('action != "ACTION_DISCONNECT"'));
    expect(command, contains('action != ACTION_EXIT_BLOCK'));
    expect(command, contains('return START_NOT_STICKY'));
    expect(
      commandGate,
      lessThan(command.indexOf('if (action == "ACTION_DISCONNECT") {')),
    );

    final dart = File('lib/main.dart').readAsStringSync();
    final request = _block(
      dart,
      '  Future<void> _requestLocalAccountReset() async {',
      '  Future<bool> _eraseLocalAccountDataKeepingDevice(',
    );
    final seal = request.indexOf("'sealAccountStartsForRecovery'");
    expect(seal, greaterThanOrEqualTo(0));
    expect(
      seal,
      lessThan(request.indexOf('await _stopAndProveTunnelInactive()')),
    );
    expect(
      dart,
      contains('''
        if (sealed != true || !_accountEpochIsCurrent(epoch)) {
          throw StateError('Local account tunnel starts were not sealed');
        }'''),
    );
  });

  test('Apple shared storage and desktop runtime precede journal deletion',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final erase = _block(
      source,
      '  Future<bool> _eraseLocalAccountDataKeepingDevice(',
      '  Future<void> _deactivateCurrentDevice() async {',
    );
    final appGroup = erase.indexOf("'purgeAppGroupContainer'");
    final appGroupVerdict =
        erase.indexOf('appGroupPurgeLeftResidual(appGroupReport)');
    final runtime = erase.indexOf("'eraseLocalAccountRuntime'");
    final runtimeVerdict =
        erase.indexOf('if (runtimeErased != true) return false;');
    final journal =
        erase.indexOf("_deleteSensitiveArtifactVerified('calc_session.json')");
    final marker = erase.indexOf('await marker.delete();');

    expect(appGroup, greaterThanOrEqualTo(0));
    expect(appGroupVerdict, greaterThan(appGroup));
    expect(runtime, greaterThan(appGroupVerdict));
    expect(runtimeVerdict, greaterThan(runtime));
    expect(journal, greaterThan(runtimeVerdict));
    expect(marker, greaterThan(journal));

    for (final host in const <String>[
      'ios/Runner/AppDelegate.swift',
      'macos/Runner/MainFlutterWindow.swift',
    ]) {
      expect(
        File(host).readAsStringSync(),
        contains('    case "purgeAppGroupContainer":\n'
            '      purgeAppGroupContainer(result: result)\n'),
        reason: host,
      );
    }
  });

  test('desktop runtime copies are erased and observed absent', () {
    final windows = File(
      'windows/runner/windows_tunnel_backend.cpp',
    ).readAsStringSync();
    final linux = File(
      'linux/runner/linux_tunnel_backend.cc',
    ).readAsStringSync();

    final windowsScan = _block(
      windows,
      'AccountRuntimeScan ScanAccountRuntimeEntries(',
      'bool AccountResetRuntimePathAbsent(',
    );
    expect(windowsScan, contains('L"wins_xray_client*"'));
    expect(windowsScan, contains('error == ERROR_FILE_NOT_FOUND'));
    expect(windowsScan, contains('error == ERROR_PATH_NOT_FOUND'));
    expect(windowsScan, contains('error != ERROR_NO_MORE_FILES'));
    expect(windowsScan, contains('AccountRuntimeScan::kError'));

    final windowsAbsent = _block(
      windows,
      'bool AccountResetRuntimePathAbsent(',
      'bool EraseLocalAccountRuntime() {',
    );
    expect(windowsAbsent, contains('GetLastError()'));
    expect(windowsAbsent, contains('error == ERROR_FILE_NOT_FOUND'));
    expect(windowsAbsent, contains('error == ERROR_PATH_NOT_FOUND'));

    final windowsErase = _block(
      windows,
      'bool EraseLocalAccountRuntime() {',
      '\n}\n',
    );
    final xrayRunning = windowsErase.indexOf('IsXrayProcessRunning()');
    final deletion = windowsErase.indexOf('DeleteFileW(');
    final rescan = windowsErase.lastIndexOf('ScanAccountRuntimeEntries(');
    final legacy = windowsErase.indexOf(
        'JoinPath(ProgramDataDirectory(), L"winsvpn.conf")');
    expect(xrayRunning, greaterThanOrEqualTo(0));
    expect(deletion, greaterThan(xrayRunning));
    expect(rescan, greaterThan(deletion));
    expect(legacy, greaterThan(rescan));
    expect(windowsErase, contains('AccountRuntimeScan::kNone'));

    final linuxNames = _block(
      linux,
      'bool IsLocalAccountRuntimeName(',
      'int ScanLocalAccountRuntime(',
    );
    for (final name in const <String>[
      '"winsvpn.conf"',
      '"wins_xray_client.json"',
      '".winsvpn.conf.tmp."',
      '".wins_xray_client.json.tmp."',
    ]) {
      expect(linuxNames, contains(name));
    }
    final linuxScan = _block(
      linux,
      'int ScanLocalAccountRuntime(',
      'bool EraseLocalAccountRuntime() {',
    );
    expect(linuxScan, contains('const bool listed = errno == 0;'));
    expect(linuxScan, contains('return -1;'));
    final linuxErase = _block(
      linux,
      'bool EraseLocalAccountRuntime() {',
      'void StopTunnelPowerProtection()',
    );
    final unlink = linuxErase.indexOf('unlinkat(directory_fd, name.c_str(), 0)');
    final sync = linuxErase.indexOf('fsync(directory_fd)');
    final linuxRescan = linuxErase.lastIndexOf('ScanLocalAccountRuntime(');
    expect(unlink, greaterThanOrEqualTo(0));
    expect(linuxErase, contains('errno != ENOENT'));
    expect(sync, greaterThan(unlink));
    expect(linuxRescan, greaterThan(sync));
    expect(linuxErase, contains('&remaining) != 0'));

    expect(
      windows,
      contains('call.method_name() == "eraseLocalAccountRuntime"'),
    );
    expect(linux, contains('method == "eraseLocalAccountRuntime"'));
  });
}
