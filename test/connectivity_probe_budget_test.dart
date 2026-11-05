import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/connectivity_probe_budget.dart';

void main() {
  test('Windows uses a compact failover budget', () {
    expect(
      tunnelConnectivityAttempts(
        platform: 'windows',
        isApplePlatform: false,
        stealthActive: false,
      ),
      2,
    );
    expect(
      tunnelConnectivityAttempts(
        platform: 'windows',
        isApplePlatform: false,
        stealthActive: true,
      ),
      3,
    );
  });

  test('Android Linux and Apple attempt counts remain unchanged', () {
    expect(
      tunnelConnectivityAttempts(
        platform: 'android',
        isApplePlatform: false,
        stealthActive: false,
      ),
      3,
    );
    expect(
      tunnelConnectivityAttempts(
        platform: 'android',
        isApplePlatform: false,
        stealthActive: true,
      ),
      3,
    );
    expect(
      tunnelConnectivityAttempts(
        platform: 'linux',
        isApplePlatform: false,
        stealthActive: false,
      ),
      4,
    );
    expect(
      tunnelConnectivityAttempts(
        platform: 'linux',
        isApplePlatform: false,
        stealthActive: true,
      ),
      6,
    );
    expect(
      tunnelConnectivityAttempts(
        platform: 'macos',
        isApplePlatform: true,
        stealthActive: false,
      ),
      8,
    );
    expect(
      tunnelConnectivityAttempts(
        platform: 'ios',
        isApplePlatform: true,
        stealthActive: true,
      ),
      8,
    );
  });

  test('Windows native probe finishes before the Dart timeout', () {
    final dartSource = File('lib/main.dart').readAsStringSync();
    final nativeSource =
        File('windows/runner/windows_tunnel_backend.cpp').readAsStringSync();

    expect(
      dartSource,
      contains('Duration(seconds: Platform.isWindows ? 9 : 10)'),
    );
    expect(nativeSource, contains('constexpr wchar_t kTunnelName[] = L"winsvpn"'));
    expect(nativeSource, contains('ConvertInterfaceAliasToLuid(kTunnelName'));
    expect(nativeSource, contains('bind(socket_handle'));
    expect(nativeSource, contains('IP_UNICAST_IF'));
    expect(nativeSource, contains('GET /cdn-cgi/trace HTTP/1.1'));
    expect(nativeSource, contains('kProbeBudgetMilliseconds = 7000'));
    expect(nativeSource, isNot(contains('curl.exe -fsS --max-time 3')));
  });
}
