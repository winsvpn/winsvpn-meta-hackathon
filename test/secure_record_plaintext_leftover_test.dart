// CORE-7 (Claude-core-T10-2): a plaintext copy left beside a secure record
// that fails to authenticate must never be imported in the record's place.
// It is wiped before the unusable record is removed, so a failed wipe keeps
// the record and fails the read, and no later read finds the plaintext alone.
// Kotlin is not compiled by the Flutter suite; this pins the source.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('an unusable record takes its plaintext leftover with it', () {
    final source = File(
            'android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt')
        .readAsStringSync();
    final start = source.indexOf(
        '    fun read(name: String, legacyFile: File? = null): String? {');
    final end = source.indexOf('    fun delete(name: String', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final read = source.substring(start, end);

    for (final record in const <String>['encryptedFile', 'legacy']) {
      final delete = read.indexOf('                $record.delete()\n');
      expect(delete, greaterThan(0), reason: record);
      final guard =
          read.lastIndexOf('if (!isPermanentRecordFailure(e)) throw e', delete);
      final wipe =
          read.lastIndexOf('legacyFile?.let { wipeLegacyFile(it) }', delete);
      expect(guard, greaterThan(0), reason: record);
      expect(wipe, greaterThan(guard),
          reason: '$record: the plaintext leftover must be wiped after the '
              'failure is classified permanent and before the record goes');
    }
    final import = read.indexOf('val legacyText = legacyFile.readText(');
    expect(import, greaterThan(read.lastIndexOf('legacy.delete()')),
        reason: 'the import runs only after both permanent-failure branches');
  });
}
