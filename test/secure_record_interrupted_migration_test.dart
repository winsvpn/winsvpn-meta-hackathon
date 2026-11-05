// A plaintext migration that stopped after its encrypted write (process death
// between write() and wipeLegacyFile()) left the plaintext copy beside a
// record that authenticates. Every later read returned the record and never
// touched the copy, so the key, config or PIN stayed on disk in plaintext.
// A read that authenticates either layout now finishes that cleanup first,
// best effort, so a failed wipe never fails a good read.
// Kotlin is not compiled by the Flutter suite; this pins the source.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('an authenticated read retires an interrupted migration leftover', () {
    final source = File(
            'android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt')
        .readAsStringSync();
    final start = source.indexOf(
        '    fun read(name: String, legacyFile: File? = null): String? {');
    final end = source.indexOf('    fun delete(name: String', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final read = source.substring(start, end);

    for (final layout in const <String>[
      'encryptedFile.readBytes()',
      'legacy.readBytes()',
    ]) {
      final decrypt = read.indexOf('val plaintext = decrypt(name, $layout)');
      expect(decrypt, greaterThan(0), reason: layout);
      final cleanup =
          read.indexOf('finishInterruptedMigration(legacyFile)', decrypt);
      final returned = read.indexOf('return plaintext', decrypt);
      expect(cleanup, greaterThan(decrypt), reason: layout);
      expect(returned, greaterThan(cleanup),
          reason: '$layout: cleanup runs before the authenticated value '
              'is returned');
      expect(read.indexOf('} catch (e: Exception) {', decrypt),
          greaterThan(returned),
          reason: '$layout: cleanup sits in the success path, not the catch');
    }

    final helperStart =
        source.indexOf('    private fun finishInterruptedMigration(');
    expect(helperStart, greaterThan(0));
    final helper =
        source.substring(helperStart, source.indexOf('\n    }\n', helperStart));
    expect(helper, contains('runCatching { wipeLegacyFile(legacyFile) }'),
        reason: 'a failed wipe must not fail a read that authenticated');
  });
}
