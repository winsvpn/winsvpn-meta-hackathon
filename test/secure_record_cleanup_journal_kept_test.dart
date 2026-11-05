// CORE-7 (Sol-core-T12-1): the account cleanup journal is the one secure
// record whose presence is itself state. While it exists, startup and
// activation stay closed, and lib/main.dart reads a failed read of it as
// present. So a journal that fails to authenticate, in the current or the
// legacy `.wvs` layout, is kept and its read fails: it is never removed and
// read as absent, and nothing beside it is wiped or retired first. Kotlin is
// not compiled by the Flutter suite; this pins the source on both sides.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _block(String source, String start, String end) {
  final a = source.indexOf(start);
  expect(a, greaterThanOrEqualTo(0), reason: 'missing $start');
  final b = source.indexOf(end, a + start.length);
  expect(b, greaterThan(a), reason: 'missing $end after $start');
  return source.substring(a, b);
}

void main() {
  test('an unusable cleanup journal is kept in both layouts', () {
    final source = File(
            'android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt')
        .readAsStringSync();
    final helper = _block(source,
        '        internal fun isKeptWhenUnusable(name: String): Boolean =',
        '\n\n');
    expect(helper, contains('name == "calc_session.json"'));
    expect('internal fun isKeptWhenUnusable'.allMatches(source).length, 1);

    final read = _block(source,
        '    fun read(name: String, legacyFile: File? = null): String? {',
        '    fun delete(name: String');
    const guard = 'if (!isPermanentRecordFailure(e)) throw e\n';
    const kept = 'if (isKeptWhenUnusable(name)) throw e\n';
    expect(guard.allMatches(read).length, 2);
    expect(kept.allMatches(read).length, 2,
        reason: 'current and legacy layouts both keep the journal');
    for (final record in const <String>['encryptedFile', 'legacy']) {
      final delete = read.indexOf('                $record.delete()\n');
      expect(delete, greaterThan(0), reason: record);
      final g = read.lastIndexOf(guard, delete);
      final k = read.lastIndexOf(kept, delete);
      expect(k, greaterThan(g),
          reason: '$record: kept only once the failure is permanent');
      expect(g, greaterThan(0), reason: record);
      final catchStart = read.lastIndexOf('} catch (e: Exception) {', g);
      expect(catchStart, greaterThan(0), reason: record);
      final body = read.substring(catchStart, delete);
      for (final mutation in const <String>[
        'wipeLegacyFile(',
        'retireSupersededLegacyRecord(',
        '.delete()',
      ]) {
        final at = body.indexOf(mutation);
        if (at < 0) continue;
        expect(catchStart + at, greaterThan(k),
            reason: '$record: $mutation must run only after the kept check');
      }
    }
  });

  test('a failed journal read keeps startup and activation closed', () {
    final source = File('lib/main.dart').readAsStringSync();
    final exists = _block(source,
        '  Future<bool> _accountCleanupJournalExists() async {', '\n  }\n');
    expect(exists, contains("_readSensitiveText('calc_session.json') != null"));
    final failure = exists.indexOf('} catch (_) {');
    expect(failure, greaterThan(0));
    expect(exists.substring(failure), contains('return true;'),
        reason: 'a read that throws must read as an open journal');
    expect(source,
        contains('journalExists: _accountCleanupJournalExists,'),
        reason: 'the startup and activation barrier uses this predicate');
  });
}
