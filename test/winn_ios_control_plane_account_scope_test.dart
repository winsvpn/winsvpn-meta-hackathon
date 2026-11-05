import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_ios_raw_config.dart';

// Served standalone winn/3 document as _buildRawAmneziaConfig emits it: the
// Interface carries a REAL private key, which deliverWinnIosServedTunnelConfig
// must replace with the Keychain placeholder before the channel.
const String _served = '''
[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.8.0.2/32
MTU = 1280
DNS = 10.64.0.1

[Peer]
PublicKey = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0, ::/0

[winn]
enabled = true
carrier = winn3
endpoint = 192.0.2.20:51844
inner_v4 = 10.64.0.2
inner_router_v4 = 10.64.0.254
static_private = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
gateway_static = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
gateway_id = bGFiLWdhdGV3YXk=
admission_key = MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm
path_mtu = 1280
carrier_classes = udp,tls
''';

void main() {
  test('served winn/3 delivery names the Keychain scope the native host must resolve',
      () async {
    final calls = <String, Object?>{};
    final result = await deliverWinnIosServedTunnelConfig(
      rawTunnelConfig: _served,
      accountScope: 'scope-token-123',
      invoke: (method, arguments) async {
        calls[method] = arguments;
        return true;
      },
    );
    expect(result.accepted, isTrue);
    final args = calls[kWinnIosControlPlaneNativeMethod] as Map;
    // Without the scope, AppDelegate.installWinn3ControlPlaneConfig falls back
    // to accountScope "" (the legacy unscoped Keychain item).
    expect(args['accountScope'], 'scope-token-123');
    final config = args['config'] as String;
    expect(config, contains('PrivateKey = $kWinnIosRawConfigKeychainPlaceholder'));
    expect(config, isNot(contains('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=')));
  });
}
