import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _normalizeSourceWhitespace(String source) =>
    source.replaceAll(RegExp(r'\s+'), ' ').trim();

void main() {
  late String source;

  setUpAll(() {
    source = File('lib/main.dart').readAsStringSync();
  });

  test('regional Xray carrier changes preserve the advertised server name', () {
    final configStart = source.indexOf(
      'Map<String, dynamic> _configForTransport(',
    );
    final configEnd = source.indexOf(
      'List<String> _xrayHostCandidates(',
      configStart,
    );
    expect(configStart, greaterThanOrEqualTo(0));
    expect(configEnd, greaterThan(configStart));

    final configBuilder = source.substring(configStart, configEnd);
    expect(configBuilder, contains("xray['host'] = host;"));
    expect(
      configBuilder,
      isNot(contains("xray['server_name'] = host;")),
      reason:
          'A regional carrier hostname must not replace the separately advertised TLS SNI.',
    );

    final preflightStart = source.indexOf(
      'Future<bool> _preflightXrayWebSocketTransport(',
    );
    final preflightEnd = source.indexOf(
      'Future<List<XrayTransportOption>> _reachableTcpFallbackOptions(',
      preflightStart,
    );
    expect(preflightStart, greaterThanOrEqualTo(0));
    expect(preflightEnd, greaterThan(preflightStart));

    final preflight = source.substring(preflightStart, preflightEnd);
    // The plain connect now takes an already-resolved address and a shrinking
    // budget, so a multi-address carrier keeps the failover Socket.connect(<name>)
    // gave for free without extending the caller's connect budget. Still a plain
    // connect that is upgraded afterwards — which is what this guards.
    expect(preflight, contains('await Socket.connect(address, port'));
    expect(preflight, contains('await SecureSocket.secure('));
    expect(preflight, contains('host: serverName,'));
    expect(preflight, contains("'Host: \$serverName\\r\\n'"));
    expect(
      preflight,
      isNot(contains('SecureSocket.connect(host, port')),
      reason:
          'TLS must connect to the carrier host while authenticating with the independent server name.',
    );
  });

  test('explicit direct disable remains fallback-only while legacy is enabled',
      () {
    final normalizeStart = source.indexOf(
      'Map<String, dynamic> _normalizeVpnConfig(',
    );
    final normalizeEnd = source.indexOf(
      'Map<String, dynamic> _configForTransport(',
      normalizeStart,
    );
    expect(normalizeStart, greaterThanOrEqualTo(0));
    expect(normalizeEnd, greaterThan(normalizeStart));

    final normalize = _normalizeSourceWhitespace(
      source.substring(normalizeStart, normalizeEnd),
    );
    expect(
      normalize,
      contains(
        "'direct_awg_enabled': _boolDefaultTrue( raw['direct_awg_enabled'] ?? raw['directawgenabled']),",
      ),
      reason:
          'An absent legacy flag must continue to normalize to direct enabled.',
    );

    final connectStart = source.indexOf(
      'Future<void> _connectWithSmartProtocol(',
    );
    final connectEnd = source.indexOf(
      'Future<void> _toggleVpnConnection() async',
      connectStart,
    );
    expect(connectStart, greaterThanOrEqualTo(0));
    expect(connectEnd, greaterThan(connectStart));

    final connect = source.substring(connectStart, connectEnd);
    expect(
      connect,
      contains("_boolDefaultTrue(directConfig['direct_awg_enabled'])"),
    );
    expect(
      connect,
      contains('shouldAttemptServedLeadCandidate('),
    );
    expect(
      connect,
      isNot(contains(
        '_isApplePlatform && !_forceXrayForDiagnostics && !directAwgEnabled',
      )),
      reason:
          'An explicit control-plane disable must never be bypassed after TCP fallback fails.',
    );
    expect(
      connect,
      isNot(contains('TCP fallback unavailable. Trying direct route...')),
    );
  });
}
