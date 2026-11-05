import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Windows physical live cycle reads the DPAPI secure-state format', () {
    final source =
        File('tools/windows_interactive_live_cycle.ps1').readAsStringSync();
    final helper =
        File('tools/windows_secure_state_helpers.ps1').readAsStringSync();

    expect(source, contains("'windows_secure_state_helpers.ps1'"));
    expect(source, contains('. \$secureStateHelper'));
    expect(helper, contains("(\$Name + '.wvdp')"));
    expect(helper, contains("'WinsVPN:WindowsSecureText:v1:' + \$Name"));
    expect(helper, contains('0x57, 0x56, 0x44, 0x50, 1, 0, 0, 0'));
    expect(helper, contains('DataProtectionScope]::CurrentUser'));
    expect(helper, contains('Add-Type -AssemblyName System.Security'));
    expect(helper, contains(r'[Array]::Clear($plaintext'));
    expect(helper, contains(r'[Array]::Clear($ciphertext'));
    expect(source, contains("Read-WinsVpnSecureJson -Name 'vpn_settings.txt'"));
    expect(source, contains("Read-WinsVpnSecureJson -Name 'vpn_config.txt'"));
    expect(
      source,
      contains(
        'Expected protected VPN egress must differ from disconnected egress.',
      ),
    );

    expect(helper, contains("'vpn_settings.txt'"));
    expect(helper, contains("'vpn_config.txt'"));
    expect(helper, contains("(\$Name + '.wvdp')"));
  });
}
