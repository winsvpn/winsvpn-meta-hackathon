import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// C-8: the Android release injection must flip the winn/3 dual-signature
/// gate. `kWinn3DualAuthHostSupported` in lib/winn_protocol_dispatch.dart
/// reads `WINS_WINN3_DUAL_AUTH` (default false); only when the Gradle
/// dart-defines injection carries `WINS_WINN3_DUAL_AUTH=true` do the
/// `auth_ed25519` / `auth_mldsa65` attestation keys get emitted into the
/// `[winn]` section. Android's parser accepts those keys and the native host
/// can verify them, so the release gate must be flipped. This test decodes
/// the injection list exactly the way Flutter's `encodeDartDefines` encoded
/// it (base64 of "NAME=VALUE") and pins the define's presence, so a silent
/// drop of the entry fails here instead of shipping a dual-auth-capable
/// Android build with the capability off.
void main() {
  test('winn3ReleaseDartDefines carries base64("WINS_WINN3_DUAL_AUTH=true")',
      () {
    final gradle =
        File('android/app/build.gradle.kts').readAsStringSync();

    final listStart = gradle.indexOf('val winn3ReleaseDartDefines =');
    final listEnd = gradle.indexOf(').joinToString(",")', listStart);
    expect(listStart, greaterThanOrEqualTo(0));
    expect(listEnd, greaterThan(listStart));
    final listBody = gradle.substring(listStart, listEnd);

    final decoded = RegExp(r'"([A-Za-z0-9+/=]+)"')
        .allMatches(listBody)
        .map((match) => utf8.decode(base64Decode(match.group(1)!)))
        .toList();
    expect(decoded, isNotEmpty);
    expect(
      decoded,
      contains('WINS_WINN3_DUAL_AUTH=true'),
      reason: 'the Android release AND debug injection (the same list) must '
          'flip the dual-signature gate',
    );
    // The define must not be duplicated: Flutter keeps the LAST occurrence,
    // and a stray second entry could silently shadow a corrected first one.
    expect(
      decoded.where((entry) => entry.startsWith('WINS_WINN3_DUAL_AUTH=')),
      hasLength(1),
    );
  });

  test('the injection list is applied to both release and debug FlutterTasks',
      () {
    // Text-level pin of the seam only. The behavioural check is
    // tools/test_android_flutter_task_dart_defines.py, which asks Gradle.
    final gradle =
        File('android/app/build.gradle.kts').readAsStringSync();
    const seam = 'gradle.taskGraph.whenReady {\n'
        '    val flutterTasks = tasks.withType<FlutterTask>().filter { hasTask(it) }';
    final start = gradle.indexOf(seam);
    expect(start, greaterThanOrEqualTo(0),
        reason: 'the merge must run once the task graph is ready, after the '
            'Flutter plugin has assigned FlutterTask.dartDefines');
    final block = gradle.substring(start, gradle.indexOf('\n}\n', start));
    expect(block, contains('mergeWinn3DartDefines(it)'));
    final merge = gradle.substring(
      gradle.indexOf('fun mergeWinn3DartDefines(task: FlutterTask) {'),
      gradle.indexOf('val winn3ConfigurationCache ='),
    );
    expect(merge, contains('winn3FlutterTaskMode(task) != "profile"'));
    expect(merge, contains('winn3ReleaseDartDefines'));
    expect(merge, contains('task.dartDefines ='));
    final guard = gradle.substring(
      gradle.indexOf('fun verifyWinn3DartDefines(task: FlutterTask) {'),
      gradle.indexOf('tasks.withType<Test>().configureEach {'),
    );
    expect(guard, contains('winn3FlutterTaskMode(task) != "profile"'),
        reason: 'merge and execution guard share one mode policy');
  });

  test('no FlutterTask configureEach action assigns dartDefines', () {
    // MEASURED 2026-09-23 (Flutter 3.44.6, Gradle 9.7.1): a configureEach
    // action registered by the build script runs BEFORE the plugin's
    // tasks.register { dartDefines = ... } action, so any assignment made
    // there is overwritten and never reaches flutter assemble.
    //
    // Text-level only: this sees assignments written inline in a
    // configureEach block, qualified or not (`dartDefines =`,
    // `task.dartDefines =`, `this.dartDefines =`, `+=`, `setDartDefines(`).
    // It cannot see one hidden behind a helper function call.
    final assignsDartDefines =
        RegExp(r'\bdartDefines\s*\+?=(?!=)|\bsetDartDefines\s*\(');
    for (final sample in <String>[
      'dartDefines = x',
      'task.dartDefines = x',
      'this.dartDefines = x',
      'dartDefines += x',
      'setDartDefines(x)',
    ]) {
      expect(assignsDartDefines.hasMatch(sample), isTrue, reason: sample);
    }
    expect(assignsDartDefines.hasMatch('dartDefines == x'), isFalse);
    final gradle =
        File('android/app/build.gradle.kts').readAsStringSync();
    const opener = 'tasks.withType<FlutterTask>().configureEach {';
    var from = 0;
    while (true) {
      final start = gradle.indexOf(opener, from);
      if (start < 0) break;
      var depth = 0;
      var end = start;
      for (var i = start; i < gradle.length; i++) {
        final char = gradle[i];
        if (char == '{') depth++;
        if (char == '}') {
          depth--;
          if (depth == 0) {
            end = i;
            break;
          }
        }
      }
      expect(end, greaterThan(start), reason: 'unbalanced configureEach block');
      final block = gradle.substring(start, end);
      expect(assignsDartDefines.hasMatch(block), isFalse,
          reason: 'configureEach runs before the plugin assigns dartDefines');
      from = end;
    }
  });

  test('the dual-auth gate itself is default-off in lib/', () {
    final source = File('lib/winn_protocol_dispatch.dart').readAsStringSync();
    expect(
      source,
      contains(
          "'WINS_WINN3_DUAL_AUTH', defaultValue: false"),
      reason: 'lib/ must stay default-off; only the platform release build '
          'flips it, never the capability logic',
    );
  });
}
