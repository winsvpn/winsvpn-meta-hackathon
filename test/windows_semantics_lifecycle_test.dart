import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('release main never forces a process-lifetime semantics client', () {
    final source = File('lib/main.dart').readAsStringSync();

    expect(source, contains('WidgetsFlutterBinding.ensureInitialized();'));
    expect(source, contains('runApp(const MyApp());'));
    expect(source, isNot(contains('ensureSemantics')));
    expect(source, isNot(contains('ensureWindowsProcessLifetimeSemantics')));
    expect(source, isNot(contains('wins_vpn/window_lifecycle')));
    expect(
      File('lib/windows_process_lifetime_semantics.dart').existsSync(),
      isFalse,
    );
  });

  test('Windows runner retains the standard first-frame Show path', () {
    final source = File('windows/runner/flutter_window.cpp').readAsStringSync();
    final header = File('windows/runner/flutter_window.h').readAsStringSync();

    final callback = source.indexOf('SetNextFrameCallback([this]()');
    final show = source.indexOf('this->Show();', callback);
    final redraw = source.indexOf('flutter_controller_->ForceRedraw();', show);

    expect(callback, greaterThanOrEqualTo(0));
    expect(show, greaterThan(callback));
    expect(redraw, greaterThan(show));
    expect(source, isNot(contains('wins_vpn/window_lifecycle')));
    expect(source, isNot(contains('waitUntilVisible')));
    expect(source, isNot(contains('CompleteWindowVisibleWaiter')));
    expect(header, isNot(contains('window_lifecycle_channel_')));
    expect(header, isNot(contains('pending_window_visible_result_')));
  });

  test('real VPN power semantics remain in the release UI', () {
    final source = File('lib/main.dart').readAsStringSync();
    final powerControl = File('lib/vpn_power_control.dart').readAsStringSync();

    expect(source, contains('Semantics('));
    expect(powerControl, contains("'Connect VPN'"));
    expect(powerControl, contains("'Disconnect VPN'"));
    expect(powerControl, contains('Semantics('));
    expect(powerControl, contains('button: true'));
  });
}
