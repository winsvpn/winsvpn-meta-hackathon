import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

String _normalizeSourceWhitespace(String source) =>
    source.replaceAll(RegExp(r'\s+'), ' ').trim();

void main() {
  group('protocol version aliases survive normalization', () {
    for (final version in [kWinnProtocolV1, kWinnProtocolV3]) {
      for (final raw in <Map<String, dynamic>>[
        {'protocol_version': version},
        {'protocolversion': version},
        {'protocol_version': version, 'protocolversion': version},
      ]) {
        test('accepts $raw and retains the canonical version', () {
          final copied = copyWinnProtocolVersionAliases(dest: {}, raw: raw);
          expect(strictWinnProtocolVersionForTunnelConfig(copied), version);
          expect(copied['protocol_version'], version);
          for (final key in raw.keys) {
            expect(copied[key], raw[key]);
          }
        });
      }
    }

    for (final raw in <Map<String, dynamic>>[
      {'protocol_version': 'winn/1', 'protocolversion': 'winn/3'},
      {'protocol_version': 'winn/3', 'protocolversion': 'winn/1'},
      {'protocolversion': 'winn/3', 'protocol_version': 'winn/1'},
      {'protocol_version': '', 'protocolversion': 'winn/3'},
      {'protocol_version': 'winn/3', 'protocolversion': null},
      {'protocol_version': 3},
      {'protocolversion': ['winn/3']},
    ]) {
      test('refuses $raw even after repeated normalization', () {
        final first = copyWinnProtocolVersionAliases(dest: {}, raw: raw);
        final second = copyWinnProtocolVersionAliases(dest: {}, raw: first);
        expect(strictWinnProtocolVersionForTunnelConfig(first), isNull);
        expect(strictWinnProtocolVersionForTunnelConfig(second), isNull);
      });
    }

    test('only an absent version defaults to winn/1', () {
      final absent = copyWinnProtocolVersionAliases(dest: {}, raw: {});
      expect(strictWinnProtocolVersionForTunnelConfig(absent), kWinnProtocolV1);
      final blank = copyWinnProtocolVersionAliases(
        dest: {}, raw: {'protocol_version': ''},
      );
      expect(strictWinnProtocolVersionForTunnelConfig(blank), isNull);
    });

    test('app normalization and native start retain the strict gate', () {
      final source = File('lib/main.dart').readAsStringSync();
      final start = source.indexOf('  Map<String, dynamic> _normalizeVpnConfig(');
      final end = source.indexOf('  bool _hasUsableVpnConfig', start);
      final normalization = source.substring(start, end);
      expect(normalization, contains(
        'return normalizeTlsOnlyXrayConfig(\n'
        '      copyWinnProtocolVersionAliases(dest: config, raw: raw),\n',
      ));
      expect(normalization, isNot(contains(
        "_stringValue(raw, ['protocol_version', 'protocolversion'])",
      )));
      final dispatch = source.indexOf('// --- Winn Protocol dispatch seam ---');
      final selection = source.substring(dispatch, source.indexOf(
        'switch (protocolVersion)', dispatch,
      ));
      expect(selection, contains('strictWinnProtocolVersionForTunnelConfig(config)'));
    });
  });

  test('VPN config normalization preserves the dynamic tunnel gateway', () {
    final source = File('lib/main.dart').readAsStringSync();
    final normalizationStart = source.indexOf(
      'Map<String, dynamic> _normalizeVpnConfig(Map<String, dynamic> raw)',
    );
    final normalizationEnd = source.indexOf(
      'bool _hasUsableVpnConfig',
      normalizationStart,
    );

    expect(normalizationStart, greaterThanOrEqualTo(0));
    expect(normalizationEnd, greaterThan(normalizationStart));

    final normalization = _normalizeSourceWhitespace(source.substring(
      normalizationStart,
      normalizationEnd,
    ));
    expect(
      normalization,
      contains(
        "'tunnel_gateway_ipv4': _stringValue(raw, ['tunnel_gateway_ipv4', 'tunnelgatewayipv4']) ?? '',",
      ),
    );
  });
}
