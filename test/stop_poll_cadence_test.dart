import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('only Android polls a stop at 100 ms; Linux and Apple keep 500 ms', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(
      source,
      contains(
        'attempts: Platform.isAndroid ? 80 : 16,\n'
        '          delay: Duration(milliseconds: Platform.isAndroid ? 100 : 500));',
      ),
    );
  });
}
