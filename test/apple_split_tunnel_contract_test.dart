import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('consumer Apple builds expose destination split without claiming MDM per-app VPN',
      () {
    final source = File('lib/main.dart').readAsStringSync();

    final supportStart = source.indexOf('bool get _supportsPerAppSplitTunneling');
    final descriptionStart = source.indexOf(
      'String get _unsupportedPerAppSplitTunnelMessage',
      supportStart,
    );
    final descriptionEnd = source.indexOf('\n  }', descriptionStart);

    expect(supportStart, greaterThanOrEqualTo(0));
    expect(descriptionStart, greaterThan(supportStart));
    expect(descriptionEnd, greaterThan(descriptionStart));

    final supportEnd = source.indexOf(';', supportStart);
    expect(supportEnd, greaterThan(supportStart));
    final support = source.substring(supportStart, supportEnd);
    expect(support, contains('Platform.isAndroid || Platform.isLinux'));
    // The affected Mullvad Windows kernel driver is no longer shipped. Keep
    // destination routing support native-side, but do not advertise per-app
    // process splitting until a reviewed replacement exists.
    expect(support, isNot(contains('Platform.isWindows')));
    expect(support, isNot(contains('Platform.isIOS')));
    expect(support, isNot(contains('Platform.isMacOS')));

    final description = source.substring(descriptionStart, descriptionEnd);
    expect(description, contains('Destination-based split tunneling is available.'));
    expect(description, contains('Apple permits per-app VPN only for MDM-managed apps'));
    expect(description, contains('not presented as a consumer feature'));
  });
}
