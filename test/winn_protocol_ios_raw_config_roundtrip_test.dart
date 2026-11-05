// Round-trip proof for the iOS winn/3 control-plane emitters: write -> parse ->
// match, entirely in Dart, never touching the network or a MethodChannel.
//
// The emission seam renders a served `[winn]` field map into the full INI
// document that the native host installs as a NETunnelProviderProtocol, and the
// parser reads that section back. This suite asserts the two agree byte-for-byte
// on every value the emitter forces and every value it passes through, closing
// the gap left by the presence-only checks in the emission suite: a serializer
// could drop, rename, or corrupt a field and the presence checks would still
// pass, because the shipped native parser throws on any key it does not
// recognise. Equality of parsed values to written values is what distinguishes a
// sound serializer from a lossy one.
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_ios_raw_config.dart';

const String _baseTemplate = '''
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

// The winn/3 Create payload in the exact shape the other platforms' native
// parser consumes: header-typed fields (max_datagram, h1..h4, s1..s4) plus the
// addressing and credential fields. Deliberately no `protocol` key.
const Map<String, String> _createWinnFields = <String, String>{
  'enabled': 'true',
  'carrier': 'winn3',
  'endpoint': '192.0.2.20:51844',
  'max_datagram': '1400',
  'inner_v4': '10.64.0.2',
  'inner_router_v4': '10.64.0.254',
  'static_private': 'UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS',
  'gateway_static': 'UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS',
  'gateway_id': 'bGFiLWdhdGV3YXk=',
  'admission_key': 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm',
  'path_mtu': '1280',
  'carrier_classes': 'udp',
  'session_id': 'ios-roundtrip-test',
  'h1': '11',
  'h2': '22',
  'h3': '33',
  'h4': '44',
  's1': '16',
  's2': '80',
  's3': '16',
  's4': '0',
};

Map<String, String> _expectedWinnFields() => Map<String, String>.from(_createWinnFields);

void main() {
  test('every written [winn] value parses back equal (writes->parses->matches)',
      () {
    final emission = emitWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: _createWinnFields,
    );
    expect(emission.accepted, isTrue, reason: emission.errors.join(','));
    final written = emission.delivery!.iniDocument;

    // Parse back exactly what the serializer wrote. The emitter forces
    // enabled=true and carrier=winn3 even if the caller omitted them, so the
    // expected map carries them explicitly.
    final parsed = parseWinnIosControlPlaneIni(written).winn;
    final expected = _expectedWinnFields()..addAll(<String, String>{
      'enabled': 'true',
      'carrier': 'winn3',
    });

    // Value equality, not key presence: every field must round-trip to the
    // exact value that was written.
    expect(parsed, expected,
        reason: 'parsed [winn] must match the written fields value-for-value');
  });

  test('render -> parse -> render is byte-stable (idempotent)', () {
    final first = emitWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: _createWinnFields,
    );
    expect(first.accepted, isTrue, reason: first.errors.join(','));
    final written = first.delivery!.iniDocument;

    // Re-emitting the already-emitted document (which now has a [winn] section)
    // must reproduce it byte-identically -- the splice must not double the
    // section or reorder anything.
    final parsed = parseWinnIosControlPlaneIni(written).winn;
    final second = renderWinnIosControlPlaneIni(
      baseTemplate: written,
      winnFields: parsed,
    );
    expect(second, written);
  });

  // Control for the round-trip: prove the equality assertion is reading real
  // bytes, not echoing the author's expected map. A hand-corrupted emitted
  // value must land in the parsed map, so a serializer that silently dropped or
  // renamed the field could never satisfy value-equality.
  test('a byte-mutated written value is reflected by the parser (reads bytes)',
      () {
    final written = emitWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: _createWinnFields,
    ).delivery!.iniDocument;

    final mutated = written.replaceFirst('path_mtu = 1280', 'path_mtu = 9000');
    expect(mutated, isNot(written), reason: 'mutation must actually apply');

    final parsed = parseWinnIosControlPlaneIni(mutated).winn;
    expect(parsed['path_mtu'], '9000',
        reason: 'parser must surface the corrupted value so equality bites');
    expect(parsed, isNot(_expectedWinnFields()..addAll(<String, String>{
          'enabled': 'true',
          'carrier': 'winn3',
        })));
  });

  test('a dropped mandatory winn field is refused, never emitted lossy', () {
    // A served payload missing a mandatory field must be refused by the gate
    // (delivery == null), not silently emitted without it -- a lossy write
    // would present to the device as a config that loads fine and then refuses
    // the path, which is indistinguishable from a censor.
    final map = Map<String, String>.from(_createWinnFields)..remove('path_mtu');
    final emission = emitWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: map,
    );
    expect(emission.accepted, isFalse,
        reason: 'a payload missing path_mtu must be refused');
    expect(emission.delivery, isNull,
        reason: 'no lossy document may reach the device');
    expect(emission.errors, contains('winn_path_mtu_missing'));
  });
}
