import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/vpn_config_validation.dart';
import 'package:wins_vpn/xray_transport_options.dart';

import 'vpn_config_validation_test.dart' show validConfig;

void main() {
  test('current raw plaintext primary selects TLS before validation', () {
    final raw = validConfig(stealth: true);
    final xray = raw['xray'] as Map;
    xray['port'] = 80;
    xray['security'] = 'none';
    final advertised = [
      {'port': 80, 'security': 'none'},
      {'port': 443, 'security': 'tls'},
    ];
    xray['transports'] = advertised;

    expect(VpnConfigValidator.isUsable(raw), isFalse);
    final normalized = normalizeTlsOnlyXrayConfig(
      raw,
      advertisedTransports: advertised,
    );
    expect(VpnConfigValidator.isUsable(normalized), isTrue);
    expect((normalized['xray'] as Map)['port'], 443);
    expect((normalized['xray'] as Map)['security'], 'tls');
    expect(xray['security'], 'none');

    expect(
      normalizeTlsOnlyXrayConfig(
        normalized,
        advertisedTransports: (normalized['xray'] as Map)['transports'],
      ),
      normalized,
    );
  });

  test('explicit lists cannot synthesize an unauthorized TLS route', () {
    for (final advertised in <Object>[
      <Object>[],
      'malformed',
      [
        {'port': 80, 'security': 'none'},
      ],
    ]) {
      final raw = validConfig(stealth: true)
        ..['protocol_version'] = 'winn/3'
        ..['protocol_params'] = {'fixture': true};
      final normalized = normalizeTlsOnlyXrayConfig(
        raw,
        advertisedTransports: advertised,
      );

      expect(normalized['stealth_active'], isFalse);
      expect((normalized['xray'] as Map)['enabled'], isFalse);
      expect((normalized['xray'] as Map)['transports'], isEmpty);
      expect(normalized['protocol_version'], raw['protocol_version']);
      expect(normalized['protocol_params'], raw['protocol_params']);
      expect(normalized['server_public_key'], raw['server_public_key']);
    }
  });

  test('omitted legacy list upgrades DNS hosts without plaintext', () {
    final options = buildXrayTransportOptions(
      hosts: ['edge.example.com'],
      advertisedPort: 80,
      advertisedSecurity: 'none',
    );
    expect(options.map((option) => option.key), [
      'edge.example.com:443:tls',
    ]);
    expect(
      buildXrayTransportOptions(
        hosts: ['203.0.113.20'],
        advertisedPort: 80,
        advertisedSecurity: 'none',
      ),
      isEmpty,
    );
  });

  test('explicit TLS legs remain usable with stale primary metadata', () {
    final options = buildXrayTransportOptions(
      hosts: ['edge.example.com'],
      advertisedPort: 0,
      advertisedSecurity: 'none',
      advertisedTransports: [
        {'port': 80, 'security': 'none'},
        {'port': 8443, 'security': 'tls'},
        {'port': 443, 'security': 'tls'},
      ],
    );
    expect(options.map((option) => option.key), [
      'edge.example.com:8443:tls',
      'edge.example.com:443:tls',
    ]);
  });

  test('only key absence lets a legacy primary infer the TLS leg', () {
    Map<String, dynamic> plaintextPrimary() {
      final raw = validConfig(stealth: true);
      final xray = Map<String, dynamic>.from(raw['xray'] as Map)
        ..['port'] = 80
        ..['security'] = 'none';
      raw['xray'] = xray;
      return raw;
    }

    Map<String, dynamic> normalized(
      Map<String, dynamic> raw,
      Map<String, dynamic> hubXray,
    ) =>
        normalizeTlsOnlyXrayConfig(
          raw,
          advertisedTransports: originalAdvertisedXrayTransports(hubXray, raw),
        );

    final omitted = plaintextPrimary();
    final omittedXray = omitted['xray'] as Map<String, dynamic>;
    expect(originalAdvertisedXrayTransports(omittedXray, omitted), isNull);
    final inferred = normalized(omitted, omittedXray);
    expect(inferred['stealth_active'], isTrue);
    expect((inferred['xray'] as Map)['port'], 443);
    expect((inferred['xray'] as Map)['security'], 'tls');

    final explicitNull = plaintextPrimary();
    final explicitNullXray = explicitNull['xray'] as Map<String, dynamic>
      ..['transports'] = null;
    explicitNull['stealth_transports'] = [
      {'port': 443, 'security': 'tls'},
    ];
    expect(
      originalAdvertisedXrayTransports(explicitNullXray, explicitNull),
      isEmpty,
    );
    final refused = normalized(explicitNull, explicitNullXray);
    expect(refused['stealth_active'], isFalse);
    expect((refused['xray'] as Map)['enabled'], isFalse);
    expect((refused['xray'] as Map)['transports'], isEmpty);

    final aliasOnly = plaintextPrimary()
      ..['stealth_transports'] = [
        {'port': 80, 'security': 'none'},
        {'port': 443, 'security': 'tls'},
      ];
    final aliasXray = aliasOnly['xray'] as Map<String, dynamic>;
    final selected = normalized(aliasOnly, aliasXray);
    expect((selected['xray'] as Map)['port'], 443);
    expect((selected['xray'] as Map)['transports'], [
      {'port': 443, 'security': 'tls'},
    ]);

    final emptyCache = plaintextPrimary();
    final emptyCacheXray = emptyCache['xray'] as Map<String, dynamic>
      ..['transports'] = <Object>[];
    expect(normalized(emptyCache, emptyCacheXray)['stealth_active'], isFalse);
  });

  test('only absence of every recognized key permits legacy inference', () {
    final tlsLeg = [
      {'port': 443, 'security': 'tls'},
    ];
    expect(originalAdvertisedXrayTransports({}, {}), isNull);
    expect(originalAdvertisedXrayTransports({'transports': null}, {}), isEmpty);
    expect(
      originalAdvertisedXrayTransports(
        {'transports': null},
        {'stealth_transports': tlsLeg},
      ),
      isEmpty,
    );
    expect(
      originalAdvertisedXrayTransports({}, {'stealthtransports': tlsLeg}),
      same(tlsLeg),
    );

    final explicitNull = validConfig(stealth: true);
    final explicitNullXray =
        Map<String, dynamic>.from(explicitNull['xray'] as Map)
          ..['transports'] = null;
    explicitNull['xray'] = explicitNullXray;
    final refused = normalizeTlsOnlyXrayConfig(
      explicitNull,
      advertisedTransports:
          originalAdvertisedXrayTransports(explicitNullXray, explicitNull),
    );
    expect(refused['stealth_active'], isFalse);
    expect((refused['xray'] as Map)['enabled'], isFalse);

    final omitted = validConfig(stealth: true);
    final kept = normalizeTlsOnlyXrayConfig(
      omitted,
      advertisedTransports:
          originalAdvertisedXrayTransports(omitted['xray'] as Map, omitted),
    );
    expect(kept['stealth_active'], isTrue);
    expect((kept['xray'] as Map)['transports'], [
      {'port': 443, 'security': 'tls'},
    ]);
  });

  test('plaintext preflight refuses before any lookup or dial', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start =
        source.indexOf('Future<bool> _preflightXrayWebSocketTransport(');
    final refusal =
        source.indexOf("if (security != 'tls') return false;", start);
    final lookup =
        source.indexOf('_resolveXrayCarrierIpv4ForPreflight(host)', start);
    final dial = source.indexOf('await Socket.connect(address, port', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(refusal, greaterThan(start));
    expect(lookup, greaterThan(refusal));
    expect(dial, greaterThan(lookup));
  });
}
