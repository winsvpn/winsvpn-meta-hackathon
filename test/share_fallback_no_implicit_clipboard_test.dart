import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('the share fallback never writes the clipboard without a tap', () async {
    final source = await File('lib/main.dart').readAsString();
    final start = source.indexOf('Future<void> _shareReferralLink()');
    final end = source.indexOf('Future<void> _showShareFallback(');
    expect(start, greaterThan(0));
    expect(end, greaterThan(start));
    expect(source.substring(start, end), isNot(contains('Clipboard.setData')));
  });
}
