import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_ios_raw_config.dart';

// Pins what preflightWinnIosRawConfig does and does not refuse, so the dev
// lab document the iOS provider installs is judged by assertions, not by a
// print an operator has to read. Where the Dart preflight accepts a shape,
// the assertion says so explicitly: the native parser is the backstop for
// unknown [winn] keys, and this file must turn red the day the Dart side
// starts refusing them (so the two layers are re-reconciled deliberately).
const String _valid = '''
[Interface]
PrivateKey = __WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__
Address = 10.8.0.2/32
MTU = 1280
DNS = 10.64.0.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 16
S2 = 80
S3 = 16
S4 = 0
H1 = 11
H2 = 22
H3 = 33
H4 = 44

[Peer]
PublicKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[WinsDebug]
ClientPublicKey = BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=

[WinsApp]
ExcludedPackages =
ExcludedPathsB64 = W10=

[WinsDevContainment]
Enabled = true

[winn]
enabled = true
carrier = winn3
endpoint = 192.0.2.20:51844
inner_v4 = 10.64.0.2
inner_router_v4 = 10.64.0.254
static_private = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
gateway_static = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
gateway_id = bGFiLWdhdGV3YXk=
admission_key = MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm
path_mtu = 1280
carrier_classes = udp
session_id = iosraw-test
''';

void main() {
  test('the fixture itself is accepted (anti-vacuity control)', () {
    final r = preflightWinnIosRawConfig(_valid);
    expect(r.accepted, isTrue, reason: r.errors.join(','));
    expect(r.errors, isEmpty);
  });

  test('an unknown [winn] key passes the Dart preflight (native is the backstop)',
      () {
    final r = preflightWinnIosRawConfig('$_valid\nbogus_key = xyz\n');
    expect(r.accepted, isTrue,
        reason: 'preflightWinnIosRawConfig has no closed [winn] key set; '
            'if this goes red the Dart side started refusing unknown keys '
            'and the Swift allowlist must be re-reconciled with it');
    expect(r.errors, isEmpty);
  });

  test('an unknown [Interface] key passes the Dart preflight', () {
    final r = preflightWinnIosRawConfig(
        _valid.replaceFirst('Jc = 4', 'Jc = 4\nBogusKey = 999'));
    expect(r.accepted, isTrue, reason: r.errors.join(','));
  });

  test('missing H1..H4 passes the Dart preflight (AWG header rules live natively)',
      () {
    final r = preflightWinnIosRawConfig(_valid
        .replaceFirst('H1 = 11\n', '')
        .replaceFirst('H2 = 22\n', '')
        .replaceFirst('H3 = 33\n', '')
        .replaceFirst('H4 = 44\n', ''));
    expect(r.accepted, isTrue, reason: r.errors.join(','));
  });

  test('missing S1..S4 passes the Dart preflight', () {
    final r = preflightWinnIosRawConfig(_valid
        .replaceFirst('S1 = 16\n', '')
        .replaceFirst('S2 = 80\n', '')
        .replaceFirst('S3 = 16\n', '')
        .replaceFirst('S4 = 0\n', ''));
    expect(r.accepted, isTrue, reason: r.errors.join(','));
  });

  test('carrier is matched case-insensitively', () {
    final r = preflightWinnIosRawConfig(
        _valid.replaceFirst('carrier = winn3', 'carrier = WINN3'));
    expect(r.accepted, isTrue, reason: r.errors.join(','));
    expect(r.errors, isNot(contains('carrier_not_winn3')));
  });

  test('a trailing H1 line joins the LAST section ([winn]) as a new key', () {
    // The fixture ends inside [winn]; the appended line is not an [Interface]
    // duplicate and the Dart preflight accepts it. Pinned so nobody reads the
    // old PROBE name as proof that duplicate AWG headers are refused.
    final r = preflightWinnIosRawConfig('$_valid\nH1 = 55\n');
    expect(r.accepted, isTrue, reason: r.errors.join(','));
    expect(r.errors, isNot(contains('duplicate_key_interface_h1')));
  });

  test('a real duplicate inside [winn] is refused by name (negative control)',
      () {
    final r = preflightWinnIosRawConfig('$_valid\ncarrier = winn3\n');
    expect(r.accepted, isFalse);
    expect(r.errors, contains('duplicate_key_winn_carrier'));
  });
}
