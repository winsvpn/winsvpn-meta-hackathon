// CORE-7 (Sol-core-T11-1): a `.wvs` record left beside a current record by a
// failed layout migration is older than that record. When the current record
// fails to authenticate, the `.wvs` record is removed BEFORE it, so neither
// this read nor the migration on the next call can return the older value,
// and a `.wvs` record that cannot be removed keeps the current one and fails
// the read. Kotlin is not compiled by the Flutter suite; this pins the source.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('a failed record removes its older .wvs record before itself', () {
    final source = File(
            'android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt')
        .readAsStringSync();
    final start = source.indexOf(
        '    fun read(name: String, legacyFile: File? = null): String? {');
    final end = source.indexOf('    fun delete(name: String', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final read = source.substring(start, end);

    final delete = read.indexOf('                encryptedFile.delete()\n');
    expect(delete, greaterThan(0));
    final guard =
        read.lastIndexOf('if (!isPermanentRecordFailure(e)) throw e', delete);
    final retire =
        read.lastIndexOf('retireSupersededLegacyRecord(name)', delete);
    expect(guard, greaterThan(0));
    expect(retire, greaterThan(guard),
        reason: 'the .wvs record must go after the failure is classified '
            'permanent and before the current record');
    expect(read.indexOf('legacySecureFile(name)'), greaterThan(delete),
        reason: 'the .wvs lookup runs only after the current record is gone');

    final helperStart = source
        .indexOf('    private fun retireSupersededLegacyRecord(name: String) {');
    expect(helperStart, greaterThan(0));
    final helper =
        source.substring(helperStart, source.indexOf('\n    }\n', helperStart));
    expect(helper, contains('File(secureDirectory, legacyOnDiskName(name))'));
    expect(helper, contains('check(!legacy.exists() || legacy.delete())'),
        reason: 'a .wvs record that cannot be removed must fail the read');
  });
}
