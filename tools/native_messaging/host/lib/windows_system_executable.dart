import 'dart:ffi';
import 'dart:io';

typedef _GetSystemDirectoryWC = Uint32 Function(Pointer<Uint16>, Uint32);
typedef _GetSystemDirectoryWDart = int Function(Pointer<Uint16>, int);
typedef _LocalAllocC = Pointer<Uint16> Function(Uint32, IntPtr);
typedef _LocalAllocDart = Pointer<Uint16> Function(int, int);
typedef _LocalFreeC = Pointer<Void> Function(Pointer<Uint16>);
typedef _LocalFreeDart = Pointer<Void> Function(Pointer<Uint16>);

final RegExp _kWindowsDrivePath = RegExp(r'^[A-Za-z]:\\');
final RegExp _kWindowsLineBreak = RegExp(r'[\r\n]');

/// System32 as the Windows API reports it (GetSystemDirectoryW), never from
/// the inherited environment: a same-user launcher can set `SystemRoot` for
/// the process it starts (the browser that spawns the native host), and the
/// host would then run that launcher's `System32\powershell.exe`. kernel32 is
/// a KnownDLL, so the loader takes it from the real system directory.
/// Returns null off Windows or when the API answers nothing usable.
String? windowsKnownSystemDirectory() {
  if (!Platform.isWindows) return null;
  try {
    final kernel32 = DynamicLibrary.open('kernel32.dll');
    final getSystemDirectory =
        kernel32.lookupFunction<_GetSystemDirectoryWC, _GetSystemDirectoryWDart>(
      'GetSystemDirectoryW',
    );
    final localAlloc =
        kernel32.lookupFunction<_LocalAllocC, _LocalAllocDart>('LocalAlloc');
    final localFree =
        kernel32.lookupFunction<_LocalFreeC, _LocalFreeDart>('LocalFree');
    const capacity = 1024; // UTF-16 code units, well beyond MAX_PATH
    const lptr = 0x0040; // LMEM_ZEROINIT | LMEM_FIXED
    final buffer = localAlloc(lptr, capacity * 2);
    if (buffer.address == 0) return null;
    try {
      final length = getSystemDirectory(buffer, capacity);
      if (length <= 0 || length >= capacity) return null;
      final path = String.fromCharCodes(buffer.asTypedList(length));
      if (!_kWindowsDrivePath.hasMatch(path) ||
          path.contains(_kWindowsLineBreak)) {
        return null;
      }
      return path.replaceFirst(RegExp(r'\\+$'), '');
    } finally {
      localFree(buffer);
    }
  } catch (_) {
    return null;
  }
}

/// The System32 directory the reviewed system executables are run from. On
/// Windows it is the API's answer and nothing else (fail closed); elsewhere
/// (unit tests on a Mac or Linux host) it is derived from `SystemRoot`.
String windowsSystemDirectory() {
  if (Platform.isWindows) {
    final known = windowsKnownSystemDirectory();
    if (known == null) {
      throw StateError('The Windows system directory is unavailable');
    }
    return known;
  }
  final root =
      (Platform.environment['SystemRoot'] ?? r'C:\Windows').trim();
  if (!_kWindowsDrivePath.hasMatch(root) || root.contains(_kWindowsLineBreak)) {
    throw StateError('The Windows system directory is unavailable');
  }
  final normalizedRoot = root.replaceFirst(RegExp(r'\\+$'), '');
  return '$normalizedRoot\\System32';
}

String windowsSystemExecutable(String relative) {
  const allowed = <String>{
    'rundll32.exe',
    'tasklist.exe',
    'NETSTAT.EXE',
    r'wbem\WMIC.exe',
    r'WindowsPowerShell\v1.0\powershell.exe',
  };
  if (!allowed.contains(relative)) {
    throw ArgumentError.value(relative, 'relative');
  }
  return '${windowsSystemDirectory()}\\$relative';
}

/// The fixed environment for a Windows PowerShell probe. A probe never
/// inherits the caller's environment: the native host runs with whatever
/// environment the browser was started with, and a same-user launcher could
/// point `PSModulePath` at a module that shadows `Get-Acl`, `Get-Process` or
/// `Get-AuthenticodeSignature`. Module lookup is limited to the system
/// PowerShell modules, and every system path derives from [systemDirectory]
/// (the known-folder System32), not from an inherited variable. [values]
/// carries the probe's own inputs (WINS_IPC_*), which may not replace a fixed
/// entry.
Map<String, String> windowsPowerShellProbeEnvironment({
  required String systemDirectory,
  Map<String, String> values = const <String, String>{},
}) {
  final system = systemDirectory.replaceFirst(RegExp(r'\\+$'), '');
  final cut = system.lastIndexOf('\\');
  if (!_kWindowsDrivePath.hasMatch(system) ||
      system.contains(_kWindowsLineBreak) ||
      cut < 2) {
    throw StateError('The Windows system directory is unavailable');
  }
  final root = system.substring(0, cut);
  final powershellHome = '$system\\WindowsPowerShell\\v1.0';
  final fixed = <String, String>{
    'SystemRoot': root,
    'windir': root,
    'SystemDrive': system.substring(0, 2),
    'ComSpec': '$system\\cmd.exe',
    'PATH': '$system;$root;$system\\Wbem;$powershellHome\\',
    'PATHEXT': '.COM;.EXE;.BAT;.CMD',
    'PSModulePath': '$powershellHome\\Modules',
  };
  for (final key in values.keys) {
    if (!key.startsWith('WINS_IPC_') ||
        fixed.keys.any((String name) => name.toLowerCase() == key.toLowerCase())) {
      throw ArgumentError.value(key, 'values', 'not a probe input');
    }
  }
  return <String, String>{...fixed, ...values};
}
