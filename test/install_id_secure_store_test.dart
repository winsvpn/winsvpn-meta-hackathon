import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('install id lives in the secure store on every platform (ruling 8b)',
      () async {
    final source = await File('lib/main.dart').readAsString();
    final start = source.indexOf('Future<String> _loadOrCreateInstallId()');
    expect(start, greaterThan(0));
    final body = source.substring(start, source.indexOf('\n  }\n', start));
    expect(body, contains("_readSensitiveText('install_id.txt')"));
    expect(body, contains("_writeSensitiveText('install_id.txt', installId)"));
    expect(body, isNot(contains('.writeAsString(')),
        reason: 'the install id is never written as a plaintext file');
    expect(body, isNot(contains('Platform.isLinux')),
        reason: 'no platform keeps a plaintext install id');
    final readBack = body.indexOf('Install id failed durable read-back');
    final removal = body.indexOf('await legacyFile.delete();');
    expect(readBack, greaterThan(0));
    expect(removal, greaterThan(readBack));
    expect(body.substring(removal), contains('catch (e)'));
  });

  test('the Linux store accepts install_id.txt', () {
    final store = File('linux/runner/linux_secure_store.cc').readAsStringSync();
    final start = store.indexOf('bool IsAllowedLinuxSecureTextName(');
    final allow = store.substring(start, store.indexOf('\n}\n', start));
    expect(allow, contains('"install_id.txt"'));
  });
}
