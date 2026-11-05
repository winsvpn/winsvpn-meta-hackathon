import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_ios_raw_config.dart';

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
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[WinsDebug]
ClientPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

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
static_private = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
gateway_static = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
gateway_id = bGFiLWdhdGV3YXk=
admission_key = MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm
path_mtu = 1280
carrier_classes = udp
session_id = iosraw-test
''';

void main() {
  test('lab gate is fail-closed and defaults off', () {
    expect(
      computeWinnIosRawConfigLabActive(
        debugMode: true,
        dartDefineEnabled: true,
      ),
      isTrue,
    );
    expect(
      computeWinnIosRawConfigLabActive(
        debugMode: false,
        dartDefineEnabled: true,
      ),
      isFalse,
    );
    expect(
      computeWinnIosRawConfigLabActive(
        debugMode: true,
        dartDefineEnabled: false,
      ),
      isFalse,
    );
    expect(kWinnIosRawConfigLabDartDefineValue, isFalse);
    expect(winnIosRawConfigLabActive, isFalse);
  });

  test('complete contained standalone template passes', () {
    final result = preflightWinnIosRawConfig(_valid);
    expect(result.accepted, isTrue, reason: result.errors.join(','));
  });

  test('embedded interface private key is refused', () {
    final result = preflightWinnIosRawConfig(
      _valid.replaceFirst(kWinnIosRawConfigKeychainPlaceholder, 'SECRET'),
    );
    expect(result.accepted, isFalse);
    expect(
      result.errors,
      contains('interface_privatekey_must_be_keychain_placeholder'),
    );
  });

  test('relay carrier is refused rather than downgraded', () {
    final result = preflightWinnIosRawConfig(
      _valid.replaceFirst('carrier = winn3', 'carrier = direct-awg'),
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('carrier_not_winn3'));
  });

  test('missing containment is refused', () {
    final result = preflightWinnIosRawConfig(
      _valid.replaceFirst('[WinsDevContainment]\nEnabled = true\n', ''),
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('missing_section_winsdevcontainment'));
    expect(result.errors, contains('containment_not_enabled'));
  });

  test('duplicate section and key are refused as ambiguous', () {
    final result = preflightWinnIosRawConfig(
      '$_valid\n[winn]\ncarrier = winn3\ncarrier = winn3\n',
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('duplicate_section_winn'));
    expect(result.errors, contains('duplicate_key_winn_carrier'));
  });

  test('path_mtu and carrier_classes are mandatory', () {
    final result = preflightWinnIosRawConfig(
      _valid
          .replaceFirst('path_mtu = 1280\n', '')
          .replaceFirst('carrier_classes = udp\n', ''),
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('winn_path_mtu_missing'));
    expect(result.errors, contains('winn_path_mtu_invalid'));
    expect(result.errors, contains('winn_carrier_classes_missing'));
  });

  test('NUL and oversize inputs are refused', () {
    expect(
      preflightWinnIosRawConfig('$_valid\u0000').errors,
      contains('config_contains_nul'),
    );
    expect(
      preflightWinnIosRawConfig('x' * (kWinnIosRawConfigMaxBytes + 1)).errors,
      contains('config_too_large'),
    );
  });

  test('placeholder outside Interface is refused', () {
    final result = preflightWinnIosRawConfig(
      '$_valid\n# __WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__\n',
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('keychain_placeholder_count_not_one'));
  });

  test('inactive run never reads a file or invokes native', () async {
    var invoked = false;
    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      invoke: (method, arguments) async {
        invoked = true;
        fail('native must not be invoked with the default-off gate');
      },
    );
    expect(result.active, isFalse);
    expect(invoked, isFalse);
  });

  test('active run refuses every non-iOS platform before reading', () async {
    var read = false;
    var invoked = false;
    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'macos',
      activeOverride: true,
      configuredPathOverride: 'container:test.ini',
      readBytesOverride: (path) async {
        read = true;
        return utf8.encode(_valid);
      },
      invoke: (method, arguments) async {
        invoked = true;
        return true;
      },
    );
    expect(result.blockedAt, 'platform');
    expect(read, isFalse);
    expect(invoked, isFalse);
  });

  test('active run requires a container-relative path', () async {
    var read = false;
    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      activeOverride: true,
      configuredPathOverride: '/tmp/test.ini',
      readBytesOverride: (path) async {
        read = true;
        return utf8.encode(_valid);
      },
    );
    expect(result.blockedAt, 'config_path');
    expect(read, isFalse);
  });

  test('active run rejects unreadable, malformed UTF-8 and bad config',
      () async {
    for (final bytes in <List<int>>[
      const <int>[0xff],
      utf8.encode('[winn]\ncarrier = direct-awg\n'),
    ]) {
      var invoked = false;
      final result = await runWinnIosRawConfigLab(
        operatingSystem: 'ios',
        activeOverride: true,
        configuredPathOverride: 'container:test.ini',
        readBytesOverride: (path) async => bytes,
        invoke: (method, arguments) async {
          invoked = true;
          return true;
        },
      );
      expect(result.accepted, isFalse);
      expect(invoked, isFalse);
    }
  });

  test('active run sends exact template and explicit account scope once',
      () async {
    var calls = 0;
    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      accountScope: 'scope-token',
      activeOverride: true,
      configuredPathOverride: 'container:test.ini',
      readBytesOverride: (path) async => utf8.encode(_valid),
      invoke: (method, arguments) async {
        calls++;
        expect(method, 'startIosRawConfigLabTunnel');
        expect(arguments, isA<Map<String, dynamic>>());
        final map = arguments! as Map<String, dynamic>;
        expect(map['configTemplate'], _valid);
        expect(map['accountScope'], 'scope-token');
        return true;
      },
    );
    expect(calls, 1);
    expect(result.accepted, isTrue);
    expect(result.blockedAt, isNull);
  });

  test('native false and native exception are distinct refusals', () async {
    final notAccepted = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:test.ini',
      readBytesOverride: (path) async => utf8.encode(_valid),
      invoke: (method, arguments) async => false,
    );
    expect(notAccepted.blockedAt, 'native_start');
    expect(notAccepted.reason, 'not_accepted');

    final threw = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:test.ini',
      readBytesOverride: (path) async => utf8.encode(_valid),
      invoke: (method, arguments) async => throw StateError('refused'),
    );
    expect(threw.blockedAt, 'native_start');
    expect(threw.reason, 'native_refused');
  });

  test('malformed endpoint is refused at preflight, never shipped to native',
      () {
    final result = preflightWinnIosRawConfig(
      _valid.replaceFirst(
        'endpoint = 192.0.2.20:51844',
        'endpoint = 192.0.2.20',
      ),
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('winn_endpoint_malformed'));
  });

  test('malformed inner and inner_router v4 addresses are refused', () {
    final badInner = preflightWinnIosRawConfig(
      _valid.replaceFirst('inner_v4 = 10.64.0.2', 'inner_v4 = 999.1.1.1'),
    );
    expect(badInner.accepted, isFalse);
    expect(badInner.errors, contains('winn_inner_v4_malformed'));

    final badRouter = preflightWinnIosRawConfig(
      _valid.replaceFirst(
        'inner_router_v4 = 10.64.0.254',
        'inner_router_v4 = 10.64.0',
      ),
    );
    expect(badRouter.accepted, isFalse);
    expect(badRouter.errors, contains('winn_inner_router_v4_malformed'));
  });

  test('non-base64 descriptor credentials and identifiers are refused', () {
    final badGatewayId = preflightWinnIosRawConfig(
      _valid.replaceFirst('gateway_id = bGFiLWdhdGV3YXk=', 'gateway_id = <id!>'),
    );
    expect(badGatewayId.accepted, isFalse);
    expect(badGatewayId.errors, contains('winn_gateway_id_malformed'));

    final badAdmission = preflightWinnIosRawConfig(
      _valid.replaceFirst('admission_key = MDEyMzQ1', 'admission_key = not-key'),
    );
    expect(badAdmission.accepted, isFalse);
    expect(badAdmission.errors, contains('winn_admission_key_malformed'));

    final badStatic = preflightWinnIosRawConfig(
      _valid.replaceFirst(
        'static_private = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'static_private = @@@@@',
      ),
    );
    expect(badStatic.accepted, isFalse);
    expect(badStatic.errors, contains('winn_static_private_malformed'));

    final badGatewayStatic = preflightWinnIosRawConfig(
      _valid.replaceFirst(
        'gateway_static = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'gateway_static = not base64!',
      ),
    );
    expect(badGatewayStatic.accepted, isFalse);
    expect(badGatewayStatic.errors, contains('winn_gateway_static_malformed'));
  });

  test('a winn section with no carrier line is refused as a wrong carrier', () {
    final result = preflightWinnIosRawConfig(
      _valid.replaceFirst('carrier = winn3\n', ''),
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('carrier_not_winn3'));
  });

  test('malformed descriptor returns a refusal reason, not a native call',
      () async {
    final malformed = _valid.replaceFirst(
      'inner_v4 = 10.64.0.2',
      'inner_v4 = not-an-address',
    );
    var invoked = false;
    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:test.ini',
      readBytesOverride: (path) async => utf8.encode(malformed),
      invoke: (method, arguments) async {
        invoked = true;
        return true;
      },
    );
    expect(result.accepted, isFalse);
    expect(result.blockedAt, 'preflight');
    expect(result.reason, contains('winn_inner_v4_malformed'));
    expect(invoked, isFalse);
  });

  test('a wrong carrier returns a refusal reason, not a native call', () async {
    final relay = _valid.replaceFirst('carrier = winn3', 'carrier = relay-awg');
    var invoked = false;
    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:test.ini',
      readBytesOverride: (path) async => utf8.encode(relay),
      invoke: (method, arguments) async {
        invoked = true;
        return true;
      },
    );
    expect(result.accepted, isFalse);
    expect(result.blockedAt, 'preflight');
    expect(result.reason, contains('carrier_not_winn3'));
    expect(invoked, isFalse);
  });

  test('device becomes its own next hop (inner_v4 == inner_router_v4) is refused',
      () {
    final result = preflightWinnIosRawConfig(
      _valid.replaceFirst('inner_router_v4 = 10.64.0.254', 'inner_router_v4 = 10.64.0.2'),
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('winn_inner_v4_equals_router'));
  });

  test('same-address descriptor returns a refusal reason, never a native call',
      () async {
    final sameHop = _valid.replaceFirst(
      'inner_router_v4 = 10.64.0.254',
      'inner_router_v4 = 10.64.0.2',
    );
    var invoked = false;
    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:test.ini',
      readBytesOverride: (path) async => utf8.encode(sameHop),
      invoke: (method, arguments) async {
        invoked = true;
        return true;
      },
    );
    expect(result.accepted, isFalse);
    expect(result.blockedAt, 'preflight');
    expect(result.reason, contains('winn_inner_v4_equals_router'));
    expect(invoked, isFalse);
  });

  test('a carrier plan naming an unknown class is refused', () {
    final result = preflightWinnIosRawConfig(
      _valid.replaceFirst('carrier_classes = udp', 'carrier_classes = bogus'),
    );
    expect(result.accepted, isFalse);
    expect(result.errors, contains('winn_carrier_classes_malformed'));
  });

  test('a known carrier plan is accepted verbatim', () {
    final plan = _valid.replaceFirst(
      'carrier_classes = udp',
      'carrier_classes = udp, tcp ,tls',
    );
    final result = preflightWinnIosRawConfig(plan);
    expect(result.accepted, isTrue, reason: result.errors.join(','));
  });

  test('every wrong carrier variant is refused and never reaches native',
      () async {
    for (final carrier in <String>[
      'direct-awg',
      'relay-awg',
      'amneziawg',
      'bogus',
      'winn2',
    ]) {
      final doc = _valid.replaceFirst('carrier = winn3', 'carrier = $carrier');
      final pre = preflightWinnIosRawConfig(doc);
      expect(pre.accepted, isFalse, reason: 'carrier $carrier must refuse');
      expect(pre.errors, contains('carrier_not_winn3'));

      var invoked = false;
      final result = await runWinnIosRawConfigLab(
        operatingSystem: 'ios',
        activeOverride: true,
        configuredPathOverride: 'container:test.ini',
        readBytesOverride: (path) async => utf8.encode(doc),
        invoke: (method, arguments) async {
          invoked = true;
          return true;
        },
      );
      expect(result.accepted, isFalse, reason: 'carrier $carrier must refuse');
      expect(result.blockedAt, 'preflight');
      expect(result.reason, contains('carrier_not_winn3'));
      expect(invoked, isFalse, reason: 'native must never run for $carrier');
    }
  });

  test('pathological descriptor input is refused, never thrown', () {
    for (final doc in <String>[
      '[winn]',
      '[winn]\ncarrier = winn3\n',
      '[winn\ncarrier = winn3',
      '[]',
      ']',
      '[winn]\ncarrier = winn3\ninner_v4 = ',
      '[winn]\n=value',
      '[winn]\ncarrier = winn3\n=',
    ]) {
      WinnIosRawConfigPreflight result;
      expect(
        () => result = preflightWinnIosRawConfig(doc),
        returnsNormally,
      );
      result = preflightWinnIosRawConfig(doc);
      expect(result.accepted, isFalse, reason: 'input $doc');
    }
  });

  test('every well-formed descriptor segment still passes preflight', () {
    final result = preflightWinnIosRawConfig(_valid);
    expect(result.accepted, isTrue, reason: result.errors.join(','));
  });
}
