import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Linux split launch remains a distinct accessible button', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('final excluded = _excludedVpnPackages');
    final end = source.indexOf('Widget _buildSpeedTestPanel()', start);

    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final splitAppList = source.substring(start, end);

    expect(splitAppList, contains('child: Stack('));
    expect(splitAppList, contains('if (Platform.isLinux)'));
    expect(splitAppList, contains('child: Semantics('));
    expect(splitAppList, contains("? 'Launch outside VPN'"));
    expect(splitAppList, contains('button: true'));
    expect(splitAppList, contains('enabled: excluded &&'));
    expect(splitAppList, contains('container: true'));
    expect(splitAppList, contains('excludeSemantics: true'));

    final semantics = splitAppList.indexOf('child: Semantics(');
    final iconButton = splitAppList.indexOf('child: IconButton(', semantics);
    expect(semantics, greaterThanOrEqualTo(0));
    expect(iconButton, greaterThan(semantics));
    expect(
      splitAppList.substring(0, semantics),
      isNot(contains('secondary: Platform.isLinux')),
      reason: 'CheckboxListTile merges secondary control semantics.',
    );
  });
}
