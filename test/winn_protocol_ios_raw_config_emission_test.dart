import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';
import 'package:wins_vpn/winn_protocol_ios_raw_config.dart';

/// Pins the iOS `winn/3` control-plane config emission path end to end.
///
/// A session committed with `protocol_version = winn/3` must be normalised to
/// the v3 constant, and the INI document that the iOS raw-config lab seam
/// actually emits to the native host must be a `carrier = winn3` document.
/// The carrier gate in `preflightWinnIosRawConfig` (lib/winn_protocol_ios_raw_config.dart)
/// refuses any other carrier, so a non-winn3 document must never be emitted.
const String _winn3 = '''
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
PublicKey = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[WinsDebug]
ClientPublicKey = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS

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
static_private = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
gateway_static = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
gateway_id = bGFiLWdhdGV3YXk=
admission_key = MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm
path_mtu = 1280
carrier_classes = udp
session_id = iosraw-emission-test
''';

void main() {
  test('a winn/3 protocol_version normalises to the v3 constant', () {
    expect(normalizedWinnProtocolVersion('winn/3'), kWinnProtocolV3);
    expect(kWinnProtocolV3, 'winn/3');
    // Absent protocol_version defaults to v1, exactly as on connect when the
    // map has no 'protocol_version' key at all.
    expect(normalizedWinnProtocolVersion(null), kWinnProtocolV1);
  });

  test('the emitted iOS winn/3 INI is a carrier = winn3 document', () async {
    String? emitted;
    final preflight = preflightWinnIosRawConfig(_winn3);
    expect(preflight.accepted, isTrue, reason: preflight.errors.join(','));

    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
      readBytesOverride: (path) async => utf8.encode(_winn3),
      invoke: (method, arguments) async {
        expect(method, 'startIosRawConfigLabTunnel');
        final map = arguments! as Map<String, dynamic>;
        emitted = (map['configTemplate'] as String?) ?? '';
        return true;
      },
    );

    expect(result.accepted, isTrue, reason: result.reason);
    expect(emitted, isNotNull, reason: 'native invoker was never called');
    expect(emitted, contains('[winn]'));
    expect(emitted, contains('carrier = winn3'));
    // The emitted template is byte-identical to what preflight accepted.
    expect(emitted, _winn3);
  });

  test('a non-winn3 carrier is refused and never emitted', () async {
    final relay = _winn3.replaceFirst('carrier = winn3', 'carrier = direct-awg');
    final preflight = preflightWinnIosRawConfig(relay);
    expect(preflight.accepted, isFalse);
    expect(preflight.errors, contains('carrier_not_winn3'));

    var invoked = false;
    final result = await runWinnIosRawConfigLab(
      operatingSystem: 'ios',
      activeOverride: true,
      configuredPathOverride: 'container:winn3_raw_lab.ini',
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

  // The device-side INI the iOS control-plane emitter splices a winn/3
  // `[winn]` section into. It mirrors the other control-plane fixtures: an
  // [Interface] carrying only the EXISTING Keychain placeholder, a [Peer], and
  // the dev containment marker that keeps an unproven session off the host's
  // default route.
  const String baseTemplate = '''
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
PublicKey = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS
Endpoint = 192.0.2.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[WinsDevContainment]
Enabled = true
''';

  // The winn/3 Create payload: the served fields that become the `[winn]` INI
  // section, carrying the header-typed fields (max_datagram, h1..h4, s1..s4)
  // in the same shape the other platforms' native parser consumes. There is
  // deliberately no `protocol` key.
  const Map<String, String> createWinnFields = <String, String>{
    'enabled': 'true',
    'carrier': 'winn3',
    'endpoint': '192.0.2.20:51844',
    'max_datagram': '1400',
    'inner_v4': '10.64.0.2',
    'inner_router_v4': '10.64.0.254',
    'static_private': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
    'gateway_static': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
    'gateway_id': 'bGFiLWdhdGV3YXk=',
    'admission_key': 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm',
    'path_mtu': '1280',
    'carrier_classes': 'udp',
    'session_id': 'ios-emission-test',
    'h1': '11',
    'h2': '22',
    'h3': '33',
    'h4': '44',
    's1': '16',
    's2': '80',
    's3': '16',
    's4': '0',
  };

  test('the iOS control-plane emitter emits a winn/3 section matching the '
      'Create payload', () {
    final emission = emitWinnIosControlPlaneConfig(
      baseTemplate: baseTemplate,
      winnFields: createWinnFields,
    );
    expect(emission.accepted, isTrue, reason: emission.errors.join(','));

    final config = emission.delivery!.iniDocument;
    final winn = parseWinnIosControlPlaneIni(config).winn;
    // Every required Create-payload field must be present in the emitted INI.
    for (final key in const <String>[
      'enabled',
      'endpoint',
      'carrier',
      'max_datagram',
      'h1', 'h2', 'h3', 'h4',
      's1', 's2', 's3', 's4',
    ]) {
      expect(winn, contains(key), reason: 'emitted [winn] must carry $key');
    }
    // And the negative: the emitted section must NEVER carry a `protocol` key,
    // because the native Apple parser throws on any key outside its own set.
    expect(winn.containsKey('protocol'), isFalse,
        reason: 'emitted [winn] must never carry a protocol key');
  });

  test('a served payload smuggling a protocol key is refused, never emitted', () {
    final smuggled = Map<String, String>.from(createWinnFields)
      ..['protocol'] = 'winn/3';
    final emission = emitWinnIosControlPlaneConfig(
      baseTemplate: baseTemplate,
      winnFields: smuggled,
    );
    expect(emission.accepted, isFalse);
    expect(emission.errors, contains('winn_protocol_key_forbidden'));
    expect(emission.delivery, isNull,
        reason: 'a payload with a protocol key must never reach the device');
  });

  test('a captured emitted winn/3 sample is written for the release record', () {
    final emission = emitWinnIosControlPlaneConfig(
      baseTemplate: baseTemplate,
      winnFields: createWinnFields,
    );
    expect(emission.accepted, isTrue, reason: emission.errors.join(','));

    final sample = emission.delivery!.iniDocument;
    // The device-side sections survive the splice alongside the emitted [winn].
    expect(sample, contains('[Interface]'));
    expect(sample, contains('[WinsDevContainment]'));
    expect(sample, contains('[winn]'));
    expect(sample, contains('h1 = 11'));
    expect(sample, contains('max_datagram = 1400'));

    final out = Directory.systemTemp.createTempSync('gen_ios_cp_raw_emit_');
    addTearDown(() => out.deleteSync(recursive: true));
    final file = File('${out.path}/emitted_winn3_sample.ini');
    file.writeAsStringSync(sample);
    expect(file.existsSync(), isTrue);
  });
}
