import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/vpn_config_validation.dart';
import 'package:wins_vpn/xray_transport_options.dart';

import 'vpn_config_validation_test.dart' show validConfig;

Map<String, dynamic> _legacyConfig() {
  final raw = validConfig(stealth: true);
  final xray = raw['xray'] as Map;
  xray['port'] = 80;
  xray['security'] = 'none';
  return raw;
}

Map<String, dynamic> _normalizeMetadata(Map<String, dynamic> raw) {
  return normalizeTlsOnlyXrayConfig(
    raw,
    advertisedTransports: originalAdvertisedXrayTransports(
      raw['xray'] as Map,
      raw,
    ),
  );
}

void main() {
  test('only genuine metadata omission permits legacy inference', () {
    final raw = _legacyConfig();
    expect(
      originalAdvertisedXrayTransports(raw['xray'] as Map, raw),
      isNull,
    );

    final normalized = _normalizeMetadata(raw);
    final xray = normalized['xray'] as Map;
    expect(xray['port'], 443);
    expect(xray['security'], 'tls');
    expect(normalized['stealth_active'], isTrue);
    expect(VpnConfigValidator.isUsable(normalized), isTrue);
  });

  test('explicit null keeps precedence over every lower alias', () {
    final tls = [
      {'port': 443, 'security': 'tls'},
    ];
    final cases = <List<Map<String, dynamic>>>[
      [
        {'transports': null, 'stealth_transports': tls},
        {'stealth_transports': tls, 'stealthtransports': tls},
      ],
      [
        {'stealth_transports': null},
        {'stealth_transports': tls, 'stealthtransports': tls},
      ],
      [
        {},
        {'stealth_transports': null, 'stealthtransports': tls},
      ],
      [
        {},
        {'stealthtransports': null},
      ],
    ];

    for (final fields in cases) {
      final raw = _legacyConfig();
      raw['xray'] = Map<String, dynamic>.from(raw['xray'] as Map)
        ..addAll(fields[0]);
      raw.addAll(fields[1]);

      expect(
        originalAdvertisedXrayTransports(raw['xray'] as Map, raw),
        isEmpty,
      );
      final normalized = _normalizeMetadata(raw);
      expect(normalized['stealth_active'], isFalse);
      expect((normalized['xray'] as Map)['enabled'], isFalse);
      expect((normalized['xray'] as Map)['transports'], isEmpty);
    }
  });

  test('root mixed metadata preserves TLS order through a cache round trip', () {
    final raw = _legacyConfig();
    raw['stealth_transports'] = [
      {'port': 80, 'security': 'none'},
      {'port': 8443, 'security': 'tls'},
      {'port': 443, 'security': 'tls'},
    ];

    final normalized = _normalizeMetadata(raw);
    final xray = normalized['xray'] as Map;
    expect(xray['port'], 8443);
    expect(xray['security'], 'tls');
    expect(xray['transports'], [
      {'port': 8443, 'security': 'tls'},
      {'port': 443, 'security': 'tls'},
    ]);
    expect(VpnConfigValidator.isUsable(normalized), isTrue);

    final restored =
        Map<String, dynamic>.from(jsonDecode(jsonEncode(normalized)) as Map);
    expect(_normalizeMetadata(restored), normalized);
  });

  test('cached empty metadata stays unauthorized without altering v3 fields', () {
    final raw = _legacyConfig()
      ..['protocol_version'] = 'winn/3'
      ..['protocol_params'] = {'fixture': true}
      ..['direct_awg_enabled'] = true;
    (raw['xray'] as Map)['transports'] = <Object>[];

    final normalized = _normalizeMetadata(raw);
    final restored =
        Map<String, dynamic>.from(jsonDecode(jsonEncode(normalized)) as Map);
    final again = _normalizeMetadata(restored);

    expect(again, normalized);
    expect(again['stealth_active'], isFalse);
    expect((again['xray'] as Map)['enabled'], isFalse);
    expect((again['xray'] as Map)['transports'], isEmpty);
    expect(again['protocol_version'], 'winn/3');
    expect(again['protocol_params'], {'fixture': true});
    expect(again['direct_awg_enabled'], isTrue);
    expect(again['server_public_key'], raw['server_public_key']);
  });
}
