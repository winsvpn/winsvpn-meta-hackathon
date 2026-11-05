import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// DESKTOP-40 (Fix H): diagnostics are opt-in and a release build prints
/// nothing to stdout.
///
/// The preference and the failure writer live as private members of the 17k
/// line `VpnHomeScreenState`, which a widget test can only reach by driving the
/// whole network-bound shell. So this suite lifts the PRODUCTION method text out
/// of `lib/main.dart` (balanced-brace extraction), compiles it into a small
/// probe class whose collaborators are stubbed with a file-backed settings
/// store, and runs that probe under the real Dart VM:
///
///  * absent / true / false preference across save and reload,
///  * a disabled preference writes no `last_tunnel_failure.json` and a
///    disable removes one that already exists,
///  * `_debugLog` prints nothing to stdout when `dart.vm.product` is true
///    (which is what `kReleaseMode` is) and, when it is not, writes only through
///    the assert-only `debugPrint`, never with `print`.
///
/// The source path is injectable via `--dart-define=MAIN_DART_PATH=...` so a
/// mutant copy of main.dart can be pointed at the SAME assertions and must turn
/// them red.
const String _sourcePath = String.fromEnvironment(
  'MAIN_DART_PATH',
  defaultValue: 'lib/main.dart',
);

/// Returns the text from [anchor] to the closing brace of its body.
String _extractMember(String source, String anchor) {
  final start = source.indexOf(anchor);
  expect(start, greaterThanOrEqualTo(0), reason: 'missing member: $anchor');
  expect(
    source.indexOf(anchor, start + anchor.length),
    -1,
    reason: 'member is declared more than once: $anchor',
  );
  final open = source.indexOf('{', start);
  expect(open, greaterThan(start));
  var depth = 0;
  for (var i = open; i < source.length; i++) {
    final c = source[i];
    if (c == '/' && i + 1 < source.length && source[i + 1] == '/') {
      final eol = source.indexOf('\n', i);
      i = eol < 0 ? source.length : eol;
      continue;
    }
    if (c == '{') depth++;
    if (c == '}') {
      depth--;
      if (depth == 0) return source.substring(start, i + 1);
    }
  }
  fail('unbalanced braces after $anchor');
}

String _withoutComments(String code) => code
    .split('\n')
    .where((line) => !line.trimLeft().startsWith('//'))
    .join('\n');

String _dartExecutable() {
  final candidates = <String>[
    if (Platform.environment['FLUTTER_ROOT'] != null)
      '${Platform.environment['FLUTTER_ROOT']}/bin/cache/dart-sdk/bin/dart',
    ...(Platform.environment['PATH'] ?? '')
        .split(Platform.isWindows ? ';' : ':')
        .where((d) => d.isNotEmpty)
        .map((d) => '$d/dart'),
  ];
  for (final candidate in candidates) {
    if (File(candidate).existsSync()) return candidate;
  }
  fail('no dart executable found via FLUTTER_ROOT or PATH: $candidates');
}

void main() {
  late String source;
  late String harness;
  late Directory work;
  late File harnessFile;

  setUpAll(() {
    source = File(_sourcePath).readAsStringSync();
    final root = Directory.current.absolute.path;

    final fieldMatch =
        RegExp(r'^\s*bool _diagnosticsEnabled = (true|false);', multiLine: true)
            .allMatches(source)
            .toList();
    expect(fieldMatch.length, 1);
    final restoreMatch = RegExp(
      r"^\s*_diagnosticsEnabled = settingsData\['diagnostics_enabled'\][^;]*;",
      multiLine: true,
    ).allMatches(source).toList();
    expect(restoreMatch.length, 1,
        reason: 'the settings restore line must exist exactly once');

    final debugLog = _extractMember(source, 'void _debugLog(String message) {');
    final persist =
        _extractMember(source, 'Future<void> _persistTunnelFailureDiagnostic(');
    final clear = _extractMember(
        source, 'Future<void> _clearTunnelFailureDiagnostic() async {');
    final setter = _extractMember(
        source, 'Future<bool> _setDiagnosticsEnabled(bool enabled) async {');
    final reader = _extractMember(
        source, 'Future<bool> _readDiagnosticsCollectionEnabled() async {');

    harness = '''
import 'dart:convert';
import 'dart:io';
import 'file://$root/lib/diagnostic_redaction.dart';

const bool kReleaseMode = bool.fromEnvironment('dart.vm.product');
void debugPrint(String? message) => stdout.writeln('DEBUGPRINT:\$message');

class Probe {
  Probe(this.dir);
  final Directory dir;
  ${fieldMatch.single.group(0)!.trim()}
  bool get mounted => true;
  void setState(void Function() fn) => fn();
  File get _store => File('\${dir.path}/vpn_settings.txt');
  Future<Map<String, dynamic>> _readVpnRuntimeSettings() async {
    if (!_store.existsSync()) return <String, dynamic>{};
    return Map<String, dynamic>.from(
        jsonDecode(await _store.readAsString()) as Map);
  }
  Future<void> _mutateVpnRuntimeSettings(
      void Function(Map<String, dynamic> data) mutation) async {
    final data = await _readVpnRuntimeSettings();
    mutation(data);
    await _store.writeAsString(jsonEncode(data));
  }
  Future<Directory> _appDocumentsDirectory() async => dir;
  String _normalizeProtocolLabel(String value) => value;
  String _redactedTunnelFailureText(Object error) =>
      redactLogSecrets(error.toString());
  void restore(Map<String, dynamic> settingsData) {
    ${restoreMatch.single.group(0)!.trim()}
  }
  bool get value => _diagnosticsEnabled;
  File get failureFile => File('\${dir.path}/last_tunnel_failure.json');
  Future<void> persist() => _persistTunnelFailureDiagnostic('winn', 'boom');
  Future<bool> save(bool enabled) => _setDiagnosticsEnabled(enabled);
  Future<bool> read() => _readDiagnosticsCollectionEnabled();
  void log(String message) => _debugLog(message);
  $debugLog
  $persist
  $clear
  $setter
  $reader
}

Future<Map<String, dynamic>> reloaded(Directory dir) async {
  // A brand new State object: only the settings file survives.
  final p = Probe(dir);
  final settings = File('\${dir.path}/vpn_settings.txt').existsSync()
      ? Map<String, dynamic>.from(
          jsonDecode(File('\${dir.path}/vpn_settings.txt').readAsStringSync())
              as Map)
      : <String, dynamic>{};
  p.restore(settings);
  return <String, dynamic>{
    'restore': p.value,
    'reader': await p.read(),
    'stored': settings.containsKey('diagnostics_enabled')
        ? settings['diagnostics_enabled']
        : 'ABSENT',
  };
}

Future<void> main(List<String> args) async {
  final mode = args[0];
  final root = Directory(args[1]);
  if (mode == 'log') {
    // Diagnostics are opt-in, so the line is only produced once the user has
    // turned them on.
    final p = Probe(root)
      ..restore(<String, dynamic>{'diagnostics_enabled': true});
    p.log("Failed host lookup: 'cdn.example-edge.net'");
    return;
  }
  Directory fresh(String name) {
    final d = Directory('\${root.path}/\$name')..createSync(recursive: true);
    return d;
  }
  final out = <String, dynamic>{};

  final absent = fresh('absent');
  out['field_default'] = Probe(absent).value;
  out['absent'] = await reloaded(absent);
  final absentProbe = Probe(absent);
  await absentProbe.persist();
  out['absent_file'] = absentProbe.failureFile.existsSync();

  final saved = fresh('saved');
  final p = Probe(saved);
  out['save_true_returns'] = await p.save(true);
  out['after_save_true_live'] = p.value;
  out['true'] = await reloaded(saved);
  final enabledProbe = Probe(saved)..restore(<String, dynamic>{'diagnostics_enabled': true});
  await enabledProbe.persist();
  out['enabled_file'] = enabledProbe.failureFile.existsSync();
  out['enabled_file_text'] = enabledProbe.failureFile.existsSync()
      ? enabledProbe.failureFile.readAsStringSync()
      : '';
  out['save_false_returns'] = await enabledProbe.save(false);
  out['after_save_false_live'] = enabledProbe.value;
  out['false'] = await reloaded(saved);
  out['file_after_disable'] = enabledProbe.failureFile.existsSync();
  await Probe(saved).persist();
  out['file_after_disabled_persist'] = enabledProbe.failureFile.existsSync();

  final legacy = fresh('legacy');
  File('\${legacy.path}/vpn_settings.txt')
      .writeAsStringSync(jsonEncode({'diagnostics_enabled': false}));
  out['legacy_false'] = await reloaded(legacy);
  for (final raw in <Object>['true', 1, 'yes']) {
    final d = fresh('odd_\${raw.toString()}');
    File('\${d.path}/vpn_settings.txt')
        .writeAsStringSync(jsonEncode({'diagnostics_enabled': raw}));
    out['odd_\${raw.toString()}'] = await reloaded(d);
  }

  final stale = fresh('stale');
  final staleProbe = Probe(stale)..restore(<String, dynamic>{'diagnostics_enabled': true});
  await staleProbe.persist();
  final staleBefore = staleProbe.failureFile.existsSync();
  await staleProbe.save(false);
  out['stale_before'] = staleBefore;
  out['stale_after'] = staleProbe.failureFile.existsSync();

  stdout.writeln('RESULT:' + jsonEncode(out));
}
''';
    work = Directory.systemTemp.createTempSync('diag_consent_');
    harnessFile = File('${work.path}/probe.dart')..writeAsStringSync(harness);
  });

  tearDownAll(() {
    try {
      work.deleteSync(recursive: true);
    } catch (_) {}
  });

  ProcessResult run(String mode,
      {required bool product, bool asserts = false, String? dir}) {
    final sub = Directory('${work.path}/${dir ?? mode}_${product}_$asserts')
      ..createSync(recursive: true);
    return Process.runSync(
      _dartExecutable(),
      <String>[
        if (asserts) '--enable-asserts',
        '-Ddart.vm.product=$product',
        harnessFile.path,
        mode,
        sub.path,
      ],
    );
  }

  Map<String, dynamic> state() {
    final result = run('state', product: false);
    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
    final line = (result.stdout as String)
        .split('\n')
        .firstWhere((l) => l.startsWith('RESULT:'));
    return jsonDecode(line.substring('RESULT:'.length)) as Map<String, dynamic>;
  }

  group('diagnostics preference across save and reload', () {
    late Map<String, dynamic> r;
    setUpAll(() => r = state());

    test('an absent preference is OFF in the field, the reader and the restore',
        () {
      expect(r['field_default'], isFalse);
      expect(r['absent']['stored'], 'ABSENT');
      expect(r['absent']['restore'], isFalse);
      expect(r['absent']['reader'], isFalse);
    });

    test('saving true persists and survives a reload', () {
      expect(r['save_true_returns'], isTrue);
      expect(r['after_save_true_live'], isTrue);
      expect(r['true']['stored'], isTrue);
      expect(r['true']['restore'], isTrue);
      expect(r['true']['reader'], isTrue);
    });

    test('saving false stores an explicit false and the reload reads OFF', () {
      expect(r['save_false_returns'], isTrue);
      expect(r['after_save_false_live'], isFalse);
      expect(r['false']['stored'], isFalse);
      expect(r['false']['restore'], isFalse);
      expect(r['false']['reader'], isFalse);
    });

    test('an explicit legacy false and non-boolean values read OFF', () {
      expect(r['legacy_false']['restore'], isFalse);
      expect(r['legacy_false']['reader'], isFalse);
      for (final key in <String>['odd_true', 'odd_1', 'odd_yes']) {
        expect(r[key]['restore'], isFalse, reason: key);
        expect(r[key]['reader'], isFalse, reason: key);
      }
    });
  });

  group('failure file follows the preference', () {
    late Map<String, dynamic> r;
    setUpAll(() => r = state());

    test('absent or disabled diagnostics write no failure file', () {
      expect(r['absent_file'], isFalse);
      expect(r['file_after_disabled_persist'], isFalse);
    });

    test('enabled diagnostics write the redacted failure file', () {
      expect(r['enabled_file'], isTrue);
      final body =
          jsonDecode(r['enabled_file_text'] as String) as Map<String, dynamic>;
      expect(body['protocol'], 'winn');
      expect(body['secret_material_redacted'], isTrue);
    });

    test('disabling removes an already collected failure file', () {
      expect(r['stale_before'], isTrue);
      expect(r['stale_after'], isFalse);
      expect(r['file_after_disable'], isFalse);
    });
  });

  group('debug log stdout', () {
    test('a release build (dart.vm.product) prints nothing to stdout', () {
      final result = run('log', product: true);
      expect(result.exitCode, 0, reason: '${result.stderr}');
      expect((result.stdout as String).trim(), isEmpty);
    });

    test('a non-release build routes the redacted line through debugPrint',
        () {
      // Diagnostics on, asserts on (a debug or profile build): the line comes
      // out only through the assert-only debugPrint stub, redacted.
      final result = run('log', product: false, asserts: true);
      expect(result.exitCode, 0, reason: '${result.stderr}');
      final lines = (result.stdout as String)
          .split('\n')
          .where((l) => l.trim().isNotEmpty)
          .toList();
      expect(lines, hasLength(1));
      expect(lines.single, startsWith('DEBUGPRINT:'),
          reason: 'nothing may reach stdout except through debugPrint');
      expect(lines.single, contains('<host>'));
      expect(lines.single, isNot(contains('example-edge')));
    });

    test('a non-release build with asserts off writes nothing', () {
      // The debugPrint call sits inside an assert, so it is compiled out.
      final result = run('log', product: false, asserts: false);
      expect(result.exitCode, 0, reason: '${result.stderr}');
      expect((result.stdout as String).trim(), isEmpty);
    });

    test('the log sink never writes with print', () {
      final body = _withoutComments(
          _extractMember(source, 'void _debugLog(String message) {'));
      expect(RegExp(r'(^|[^A-Za-z0-9_.])print\(').hasMatch(body), isFalse,
          reason: 'only debugPrint inside the assert may write');
      final assertAt = body.indexOf('assert(');
      final printAt = body.indexOf('debugPrint(');
      expect(assertAt, greaterThanOrEqualTo(0));
      expect(printAt, greaterThan(assertAt));
      expect(body.indexOf('if (kReleaseMode'), lessThan(assertAt));
    });
  });

  group('source pins', () {
    test('the failure writer is gated before it touches the disk', () {
      final persist = _withoutComments(_extractMember(
          source, 'Future<void> _persistTunnelFailureDiagnostic('));
      final gate = persist.indexOf('if (!_diagnosticsEnabled) return;');
      expect(gate, greaterThanOrEqualTo(0));
      expect(gate, lessThan(persist.indexOf('_appDocumentsDirectory()')));
      expect(gate, lessThan(persist.indexOf('writeAsString')));
      expect(
        RegExp(r'last_tunnel_failure\.json').allMatches(source).length,
        2,
        reason: 'only the writer and the remover may name the failure file',
      );
    });

    test('every diagnostics reader treats only a stored true as enabled', () {
      expect(source, isNot(contains("['diagnostics_enabled'] != false")));
      expect(
        RegExp(r"\['diagnostics_enabled'\] == true").allMatches(source).length,
        2,
      );
    });
  });
}
