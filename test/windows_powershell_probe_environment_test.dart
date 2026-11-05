// The Windows PowerShell probes of the browser bridge (ACL, Authenticode and
// process-path checks) run with a fixed environment, never the caller's. The
// native host inherits the browser's environment, so an inherited PSModulePath
// could load a module that shadows Get-Acl, and an inherited SystemRoot could
// pick the PowerShell binary itself.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/windows_system_executable.dart';

void main() {
  test('the probe environment is fixed and derives from System32', () {
    final env = windowsPowerShellProbeEnvironment(
      systemDirectory: r'C:\Windows\System32',
      values: <String, String>{'WINS_IPC_PID': '4242'},
    );
    expect(env, <String, String>{
      'SystemRoot': r'C:\Windows',
      'windir': r'C:\Windows',
      'SystemDrive': 'C:',
      'ComSpec': r'C:\Windows\System32\cmd.exe',
      'PATH': r'C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;'
          r'C:\Windows\System32\WindowsPowerShell\v1.0\',
      'PATHEXT': '.COM;.EXE;.BAT;.CMD',
      'PSModulePath': r'C:\Windows\System32\WindowsPowerShell\v1.0\Modules',
      'WINS_IPC_PID': '4242',
    });
  });

  test('a trailing separator on System32 does not change the environment', () {
    expect(
      windowsPowerShellProbeEnvironment(systemDirectory: r'D:\WINNT\System32\\'),
      windowsPowerShellProbeEnvironment(systemDirectory: r'D:\WINNT\System32'),
    );
    expect(
      windowsPowerShellProbeEnvironment(
        systemDirectory: r'D:\WINNT\System32',
      )['PSModulePath'],
      r'D:\WINNT\System32\WindowsPowerShell\v1.0\Modules',
    );
  });

  test('probe inputs cannot replace a fixed entry or add other variables', () {
    for (final key in <String>[
      'PSModulePath',
      'psmodulepath',
      'SystemRoot',
      'PATH',
      'USERPROFILE',
      'WINS_IPC',
    ]) {
      expect(
        () => windowsPowerShellProbeEnvironment(
          systemDirectory: r'C:\Windows\System32',
          values: <String, String>{key: r'Z:\evil'},
        ),
        throwsArgumentError,
        reason: key,
      );
    }
  });

  test('an unusable System32 is refused', () {
    for (final dir in <String>[
      '',
      'System32',
      r'\\server\share\System32',
      'C:',
      'C:\\Windows\\System32\nX',
    ]) {
      expect(
        () => windowsPowerShellProbeEnvironment(systemDirectory: dir),
        throwsStateError,
        reason: dir,
      );
    }
  });

  test('off Windows there is no known-folder System32', () {
    if (Platform.isWindows) return;
    expect(windowsKnownSystemDirectory(), isNull);
  });

  test('every PowerShell probe runs without the parent environment', () {
    final source =
        File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
    expect(source.contains('...Platform.environment'), isFalse);
    final probes = RegExp(
      r"windowsSystemExecutable\(r'WindowsPowerShell\\v1\.0\\powershell\.exe'\)",
    ).allMatches(source).toList();
    expect(probes, hasLength(3));
    for (final probe in probes) {
      final call = source.substring(probe.start, probe.start + 900);
      final end = call.indexOf(');\n');
      final body = end < 0 ? call : call.substring(0, end);
      expect(body, contains('environment: windowsPowerShellProbeEnvironment('));
      expect(body, contains('includeParentEnvironment: false'));
    }
  });
}
