// Claude-core-T12-1: a `.wvs` record left beside a current record by a failed
// layout migration must never take that record's place. A delete removes it
// FIRST and keeps the current record while it is still there (once the
// current record is gone, the migration on the next call would rename the
// older record into its name). A write retires it once the new record is
// committed. Kotlin is not compiled by the Flutter suite; this pins the source.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _method(String source, String signature) {
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: signature);
  return source.substring(start, source.indexOf('\n    }\n', start));
}

void main() {
  final source = File(
          'android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt')
      .readAsStringSync();

  test('delete removes the older .wvs record before the current one', () {
    final delete = _method(source,
        '    fun delete(name: String, legacyFile: File? = null): Boolean {');
    final legacy =
        delete.indexOf('legacySecureFile(name)?.let { deleted = it.delete()');
    final current = delete.indexOf(
        'if (deleted && encryptedFile.exists()) deleted = encryptedFile.delete()');
    expect(legacy, greaterThan(0));
    expect(current, greaterThan(legacy),
        reason: 'the current record goes after the .wvs record, and only '
            'once it is gone');
    expect('encryptedFile.delete()'.allMatches(delete).length, 1,
        reason: 'no second, unguarded delete of the current record');
  });

  test('a committed write retires the older .wvs record', () {
    final write =
        _method(source, '    fun write(name: String, plaintext: String) {');
    final commit = write
        .indexOf('Os.rename(temporary.absolutePath, destination.absolutePath)');
    final retire = write.indexOf('superseded.delete()');
    expect(commit, greaterThan(0));
    expect(retire, greaterThan(commit),
        reason: 'retired only after the new record is committed');
    expect(write,
        contains('superseded.absolutePath != destination.absolutePath'));
  });
}
