import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/xray_transport_options.dart';

import 'vpn_config_validation_test.dart' show validConfig;

Map<String, dynamic> normalized(
  Map<String, dynamic> xray,
  Map<String, dynamic> raw,
) {
  final source = validConfig(stealth: true);
  final sourceXray = source['xray'] as Map;
  sourceXray['port'] = 80;
  sourceXray['security'] = 'none';
  return normalizeTlsOnlyXrayConfig(
    source,
    advertisedTransports: originalAdvertisedXrayTransports(xray, raw),
  );
}

void main() {
  const tls = <Map<String, Object>>[
    {'port': 8443, 'security': 'tls'},
    {'port': 443, 'security': 'tls'},
  ];

  test('present unusable metadata cannot fall through to a lower alias', () {
    for (final value in <Object?>[
      null,
      <Object>[],
      'malformed',
      <Map<String, Object>>[
        {'port': 80, 'security': 'none'},
      ],
    ]) {
      final selected = originalAdvertisedXrayTransports(
        {'transports': value, 'stealth_transports': tls},
        {'stealth_transports': tls, 'stealthtransports': tls},
      );
      expect(selected, value == null ? isEmpty : equals(value));

      final config = normalized(
        {'transports': value, 'stealth_transports': tls},
        {'stealth_transports': tls},
      );
      expect(config['stealth_active'], isFalse);
      expect((config['xray'] as Map)['enabled'], isFalse);
      expect((config['xray'] as Map)['transports'], isEmpty);
    }
  });

  test('nested alias precedes both top-level aliases', () {
    final config = normalized(
      {'stealth_transports': tls},
      {
        'stealth_transports': [
          {'port': 443, 'security': 'tls'},
        ],
      },
    );
    expect((config['xray'] as Map)['port'], 8443);
  });

  test('TLS order survives a serialized normalized-cache round trip', () {
    final first = normalized({}, {'stealth_transports': tls});
    final cached =
        Map<String, dynamic>.from(jsonDecode(jsonEncode(first)) as Map);
    final second = normalizeTlsOnlyXrayConfig(
      cached,
      advertisedTransports: originalAdvertisedXrayTransports(
        cached['xray'] as Map,
        cached,
      ),
    );
    expect(second, first);
    expect((second['xray'] as Map)['port'], 8443);
  });
}
