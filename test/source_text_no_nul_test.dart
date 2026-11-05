// A raw 0x00 byte inside the first 8000 bytes of a file makes git classify it
// as binary: `git diff` prints "Binary files differ" and grep without -a shows
// no lines, so a change to that file is invisible to ordinary review. A NUL in
// a Dart string literal is written as the escape '\u0000', which yields the
// same code point.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('no Dart source under lib/ or test/ carries a raw NUL byte', () {
    final offenders = <String>[];
    for (final root in const <String>['lib', 'test']) {
      for (final entity in Directory(root).listSync(recursive: true)) {
        if (entity is! File || !entity.path.endsWith('.dart')) continue;
        if (entity.readAsBytesSync().contains(0)) offenders.add(entity.path);
      }
    }
    expect(offenders, isEmpty);
  });
}
