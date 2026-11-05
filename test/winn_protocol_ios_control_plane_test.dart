import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_ios_raw_config.dart';

/// Pins the shipping iOS control-plane emitter for winn/3 config emission.
///
/// The emitter renders the full `[winn]` INI from a served control-plane
/// payload through the authoritative printer/gate in
/// `winn_protocol_ios_raw_config.dart`, and the round-trip invariant is that
/// parsing the emitted document recovers exactly the payload that produced it
/// (and re-emitting is byte-identical). A non-winn3 carrier must be refused so
/// the delivery path can never install a relay config.
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

[WinsDebug]
ClientPublicKey = UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS

[WinsApp]
ExcludedPackages =
ExcludedPathsB64 = W10=

[WinsDevContainment]
Enabled = true
''';

const Map<String, String> _winn3Fields = <String, String>{
  'enabled': 'true',
  'carrier': 'winn3',
  'endpoint': '192.0.2.20:51844',
  'inner_v4': '10.64.0.2',
  'inner_router_v4': '10.64.0.254',
  'static_private': 'UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS',
  'gateway_static': 'UkVEQUNURURfV0dfS0VZX1BMQUNFSE9MREVS',
  'gateway_id': 'bGFiLWdhdGV3YXk=',
  'admission_key':
      'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm',
  'path_mtu': '1280',
  'carrier_classes': 'udp,tls',
  'session_id': 'cplt-test',
};

void main() {
  test('render -> parse round-trips the winn/3 payload exactly', () {
    final rendered = renderWinnIosControlPlaneIni(
      baseTemplate: _baseTemplate,
      winnFields: _winn3Fields,
    );

    // The authoritative gate accepts the emitted document.
    final preflight = preflightWinnIosRawConfig(rendered);
    expect(preflight.accepted, isTrue, reason: preflight.errors.join(','));

    // Parsing the emitted document recovers every served field, verbatim.
    final parsed = parseWinnIosControlPlaneIni(rendered);
    expect(parsed.winn, equals(_winn3Fields));

    // Re-emitting the parsed document is byte-identical (idempotent printer).
    final reRendered = renderWinnIosControlPlaneIni(
      baseTemplate: rendered,
      winnFields: parsed.winn,
    );
    expect(reRendered, rendered);
  });

  test('the emitted document is a carrier = winn3 document with the plan', () {
    final rendered = renderWinnIosControlPlaneIni(
      baseTemplate: _baseTemplate,
      winnFields: _winn3Fields,
    );
    expect(rendered, contains('[winn]'));
    expect(rendered, contains('carrier = winn3'));
    expect(rendered, contains('path_mtu = 1280'));
    expect(rendered, contains('carrier_classes = udp,tls'));
    expect(rendered, contains('endpoint = 192.0.2.20:51844'));
    // The device-side sections survive the splice.
    expect(rendered, contains('[Interface]'));
    expect(rendered, contains('[WinsDevContainment]'));
  });

  test('the emitter refuses a non-winn3 carrier and delivers nothing',
      () async {
    final relayFields = Map<String, String>.from(_winn3Fields)
      ..['carrier'] = 'direct-awg';
    final emission = emitWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: relayFields,
    );
    expect(emission.accepted, isFalse);
    expect(emission.errors, contains('carrier_not_winn3'));
    expect(emission.delivery, isNull);

    var invoked = false;
    final result = await deliverWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: relayFields,
      invoke: (method, arguments) async {
        invoked = true;
        return true;
      },
    );
    expect(result.accepted, isFalse);
    expect(result.blockedAt, 'emission');
    expect(invoked, isFalse, reason: 'native must not be called for a relay');
  });

  test(
      'an emitted config missing a served field is refused, not silently '
      'served with a default', () {
    final incomplete = Map<String, String>.from(_winn3Fields)
      ..remove('path_mtu');
    final emission = emitWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: incomplete,
    );
    expect(emission.accepted, isFalse);
    expect(emission.errors, contains('winn_path_mtu_missing'));
  });

  test('TCP- or TLS-only carrier plans are refused before native delivery',
      () async {
    for (final plan in const <String>['tcp', 'tls', 'tcp,tls']) {
      final fields = Map<String, String>.from(_winn3Fields)
        ..['carrier_classes'] = plan;
      final emission = emitWinnIosControlPlaneConfig(
        baseTemplate: _baseTemplate,
        winnFields: fields,
      );
      expect(emission.accepted, isFalse, reason: plan);
      expect(emission.errors, contains('winn_carrier_classes_udp_required'),
          reason: plan);
      expect(emission.delivery, isNull, reason: plan);
    }
  });

  test('delivery hands native the full INI plus protocol_version/carrier',
      () async {
    Map<String, Object?>? nativeArguments;
    String? nativeMethod;
    final result = await deliverWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: _winn3Fields,
      invoke: (method, arguments) async {
        nativeMethod = method;
        nativeArguments = arguments as Map<String, Object?>?;
        return true;
      },
    );
    expect(result.accepted, isTrue, reason: result.reason);
    expect(nativeMethod, kWinnIosControlPlaneNativeMethod);
    expect(nativeArguments, isNotNull);
    expect(nativeArguments!['protocolVersion'],
        kWinnIosControlPlaneProtocolVersion);
    expect(nativeArguments!['carrier'], kWinnIosControlPlaneCarrier);
    final config = nativeArguments!['config'] as String;
    expect(config, contains('carrier = winn3'));
    // The delivered document is the same canonical render.
    expect(
      config,
      renderWinnIosControlPlaneIni(
        baseTemplate: _baseTemplate,
        winnFields: _winn3Fields,
      ),
    );
  });

  test('native refusal and native exception are distinct delivery results',
      () async {
    final notInstalled = await deliverWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: _winn3Fields,
      invoke: (method, arguments) async => false,
    );
    expect(notInstalled.accepted, isFalse);
    expect(notInstalled.blockedAt, 'native_install');
    expect(notInstalled.reason, 'not_installed');

    final threw = await deliverWinnIosControlPlaneConfig(
      baseTemplate: _baseTemplate,
      winnFields: _winn3Fields,
      invoke: (method, arguments) async => throw StateError('refused'),
    );
    expect(threw.accepted, isFalse);
    expect(threw.blockedAt, 'native_install');
    expect(threw.reason, 'native_refused');
  });

  test('served shipping document replaces only the Interface private key',
      () async {
    final shippingTemplate = _baseTemplate
        .replaceFirst(
          kWinnIosRawConfigKeychainPlaceholder,
          'DEVICE_PRIVATE_KEY_MUST_NOT_CROSS_CHANNEL',
        )
        .replaceFirst('[WinsDevContainment]\nEnabled = true\n', '');
    final raw = renderWinnIosControlPlaneIni(
      baseTemplate: shippingTemplate,
      winnFields: _winn3Fields,
    );
    Map<String, Object?>? nativeArguments;
    final result = await deliverWinnIosServedTunnelConfig(
      rawTunnelConfig: raw,
      invoke: (method, arguments) async {
        nativeArguments = arguments as Map<String, Object?>?;
        return true;
      },
    );
    expect(result.accepted, isTrue, reason: result.reason);
    final delivered = nativeArguments!['config'] as String;
    expect(delivered, contains(kWinnIosRawConfigKeychainPlaceholder));
    expect(delivered,
        isNot(contains('DEVICE_PRIVATE_KEY_MUST_NOT_CROSS_CHANNEL')));
    expect(delivered, contains('carrier = winn3'));
  });
}
