// CORE-7 (Claude-core-T10-1): a camouflage latch check that fails must never
// read as "not latched", because that answer takes the disguise off a wiped
// phone. The check and the latch path run verbatim in a child program with a
// controllable platform answer.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production method: $start');
  }
  return source.substring(first, last);
}

const _harness = r'''
import 'dart:async';
import 'dart:io';

const String kCamouflageLatchFileName = 'calculator_display_prefs.json';

class _Channel {
  Object? reply;
  bool throws = false;
  bool hangs = false;
  Future<T?> invokeMethod<T>(String method, [Object? arguments]) {
    if (method != 'getAppDocumentsDirectory') throw StateError(method);
    if (hangs) return Completer<T?>().future;
    if (throws) return Future<T?>.error(StateError('channel unavailable'));
    return Future<T?>.value(reply as T?);
  }
}

class Harness {
  Harness(this.fallback);
  final Directory fallback;
  final _methodChannel = _Channel();
  bool _supportsInAppCamouflage = true;
  bool fallbackUsed = false;
  void _debugLog(String message) {}
  Future<Directory> _appDocumentsDirectory() async {
    fallbackUsed = true;
    return fallback;
  }
''';

const _harnessEnd = r'''
}

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

Future<void> main(List<String> arguments) async {
  final root = Directory(arguments.single);
  final native = Directory('${root.path}/native')..createSync();
  final fallback = Directory('${root.path}/fallback')..createSync();
  final h = Harness(fallback);

  h._methodChannel.throws = true;
  check(await h._camouflageLatched() == null,
      'a failed platform answer read as a definite latch state');
  check(!h.fallbackUsed, 'the latch was looked for at a guessed path');

  h._methodChannel.throws = false;
  h._methodChannel.reply = '   ';
  check(await h._camouflageLatched() == null,
      'an empty platform answer read as a definite latch state');

  // A platform that never answers is a failed check, after the 4 s bound.
  h._methodChannel.hangs = true;
  final waited = Stopwatch()..start();
  check(await h._camouflageLatched() == null,
      'an unanswered platform call read as a definite latch state');
  check(waited.elapsed < const Duration(seconds: 6),
      'the latch check waited ${waited.elapsed} on an unanswered call');
  h._methodChannel.hangs = false;

  // A directory the filesystem cannot create is a failed check too.
  final notADirectory = File('${root.path}/plain')..writeAsStringSync('x');
  h._methodChannel.reply = '${notADirectory.path}/documents';
  check(await h._camouflageLatched() == null,
      'a filesystem failure read as a definite latch state');

  h._methodChannel.reply = native.path;
  check(await h._camouflageLatched() == false, 'an absent latch read as set');
  File('${native.path}/$kCamouflageLatchFileName').writeAsStringSync('{}');
  check(await h._camouflageLatched() == true, 'a present latch read as absent');
  check(!h.fallbackUsed, 'the latch was looked for at a guessed path');

  h._supportsInAppCamouflage = false;
  check(await h._camouflageLatched() == false,
      'a platform without the disguise reported a latch');
  print('PASS camouflage latch');
}
''';

void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('a failed latch check is unknown, never "not latched"', () async {
    final methods = _between(
      source,
      '  Future<File> _camouflageLatchFile() async {',
      '  /// Idempotent. Called every time the decoy is armed',
    );
    final temporary = await Directory.systemTemp.createTemp('wins-latch-');
    try {
      final program = File('${temporary.path}/latch.dart');
      await program.writeAsString('$_harness$methods$_harnessEnd');
      final work = Directory('${temporary.path}/work')..createSync();
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[program.path, work.path],
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS camouflage latch'));
    } finally {
      await temporary.delete(recursive: true);
    }
  });

  test('both latch callers arm the decoy on an unknown latch', () {
    final gate = _between(source,
        '  Future<void> _initializePrivacyConsentGate() async {',
        '  Future<void> _armCamouflageBeforeConsent() async {');
    expect(gate,
        contains('(activatedLocally || await _camouflageLatched() != false)'));
    final latchFile = _between(source,
        '  Future<File> _camouflageLatchFile() async {',
        '  /// `true` latched, `false` not latched');
    expect(latchFile, contains('.timeout(const Duration(seconds: 4))'));
    final restore = _between(source,
        '  Future<void> _determineSecurityOnboardingLayer() async {',
        '  Future<void> _onCalculatorButtonPressed(');
    expect(restore,
        contains('final bool? camouflageLatchState = await _camouflageLatched();'));
    expect(restore,
        contains('final bool camouflageLatched = camouflageLatchState != false;'));
  });

  test('an unknown latch alone never writes the latch', () {
    final restore = _between(source,
        '  Future<void> _determineSecurityOnboardingLayer() async {',
        '  Future<void> _onCalculatorButtonPressed(');
    expect(
        restore,
        contains('      if (_showDecoyCalculator &&\n'
            '          (camouflageLatchState != null ||\n'
            '              appIsActivated ||\n'
            '              _isFreeAccessSession)) {\n'
            '        unawaited(_latchCamouflage());\n'
            '      }'));
    expect(restore,
        isNot(contains('if (_showDecoyCalculator) unawaited(_latchCamouflage());')));
  });
}
