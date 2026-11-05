import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/xray_transport_options.dart';

void main() {
  test('Windows DNS-blind fallback requires a pinned public carrier', () {
    final source = File('lib/main.dart').readAsStringSync();

    final normalizeStart =
        source.indexOf('Map<String, dynamic> _normalizeVpnConfig(');
    final normalizeEnd = source.indexOf(
      'bool _hasUsableVpnConfig(',
      normalizeStart,
    );
    expect(normalizeStart, greaterThanOrEqualTo(0));
    expect(normalizeEnd, greaterThan(normalizeStart));
    final normalize = source.substring(normalizeStart, normalizeEnd);
    expect(normalize, contains('validatedXrayCarrierIpv4Pins('));
    expect(normalize, contains("xrayHost: '',"));
    expect(normalize, contains("raw['windows_transport_bypass_ipv4']"));
    expect(normalize, contains('.take(16).toList(growable: false)'));
    expect(
      normalize,
      contains(
        "'windows_transport_bypass_ipv4': windowsTransportBypassIpv4",
      ),
      reason:
          'Transport normalization must not discard sanitized carrier pins before the DNS-blind fallback builder runs.',
    );

    final detectorStart =
        source.indexOf('bool _hasPinnedWindowsCarrierEndpoint(');
    final builderStart = source.indexOf(
      'List<XrayTransportOption> _windowsBlindTcpFallbackOptions(',
      detectorStart,
    );
    final builderEnd =
        source.indexOf('Future<bool> _waitForTunnelReady(', builderStart);
    expect(detectorStart, greaterThanOrEqualTo(0));
    expect(builderStart, greaterThan(detectorStart));
    expect(builderEnd, greaterThan(builderStart));

    final detector = source.substring(detectorStart, builderStart);
    expect(detector, contains('if (!Platform.isWindows) return false;'));
    expect(detector, isNot(contains("config['server_endpoint']")));
    expect(detector, contains('_pinnedWindowsXrayCarrierAddresses(config)'));

    final pinBuilderStart = source.indexOf(
      'List<String> _pinnedWindowsXrayCarrierAddresses(',
      detectorStart,
    );
    final pinBuilder = source.substring(pinBuilderStart, builderStart);
    expect(pinBuilder, contains("xray['host']"));
    expect(pinBuilder, contains('windows_transport_bypass_ipv4'));
    expect(pinBuilder, isNot(contains("config['server_endpoint']")));

    final builder = source.substring(builderStart, builderEnd);
    expect(
      builder,
      contains('!Platform.isWindows || !_hasPinnedWindowsCarrierEndpoint('),
    );
    expect(builder, contains('buildXrayTransportOptions('));
    expect(builder, contains("advertisedTransports: xray['transports']"));
  });

  test('generic AWG endpoint cannot authorize a DNS-blind Xray start', () {
    expect(
      validatedXrayCarrierIpv4Pins(
        xrayHost: 'carrier.example.test',
        advertisedCarrierPins: const <String>[],
      ),
      isEmpty,
      reason:
          'A public server_endpoint is intentionally absent from this Xray-specific contract.',
    );
  });

  test('literal Xray hosts and explicit public carrier pins are allowed', () {
    expect(
      validatedXrayCarrierIpv4Pins(
        xrayHost: '8.8.8.8',
        advertisedCarrierPins: const <String>['1.1.1.1', '10.0.0.8'],
      ),
      const <String>['8.8.8.8', '1.1.1.1'],
    );
    const explicitlyPinnedServerEndpoint = '1.0.0.1';
    expect(
      validatedXrayCarrierIpv4Pins(
        xrayHost: 'carrier.example.test',
        advertisedCarrierPins: const <String>[explicitlyPinnedServerEndpoint],
      ),
      const <String>[explicitlyPinnedServerEndpoint],
      reason:
          'A server endpoint is eligible only when the control plane also advertises it as an Xray carrier pin.',
    );
  });

  test('blind candidates retain the ordinary fail-closed start proof', () {
    final source = File('lib/main.dart').readAsStringSync();
    final connectStart =
        source.indexOf('Future<void> _connectWithSmartProtocol(');
    final connectEnd = source.indexOf(
        'Future<void> _toggleVpnConnection() async', connectStart);
    final connect = source.substring(connectStart, connectEnd);

    expect(connect, contains('tcp_fallback_candidate_preflight_failed'));
    expect(connect, contains('_windowsBlindTcpFallbackOptions(stealthBase)'));
    expect(
      connect,
      contains('tcp_fallback_preflight_dns_blinded_windows_pinned_start'),
    );
    expect(
      connect.indexOf('_windowsBlindTcpFallbackOptions(stealthBase)'),
      lessThan(connect.indexOf(
        'final boundedCandidates = boundedXrayTransportOptions(',
      )),
    );
    expect(
      connect,
      contains('for (final candidate in boundedCandidates)'),
    );
    expect(connect, contains('await _startTunnelCandidate('));
    expect(
      RegExp(r'if \(!await _stopNativeTunnelForFailover\(\)\)')
          .allMatches(source)
          .length,
      6,
      reason:
          'Only the cover-node rotation stop, the pre-fallback stop, the failed-candidate stop, the stale-plan retry stop, the Double VPN handover stop after a failed single-hop restore (FAST-CONNECT, Android only) and the ciphertext relay path failure retry stop (w3r/1, winn3_relay_test.dart) are valid; an explicitly disabled direct route must not be retried.',
    );
    // The fourth site is the stale-plan retry: it settles the failed v3 lead
    // before the one fresh-config retry of the same node, never a transport
    // the settings excluded (winn3_stale_cached_config_test.dart).
    final staleRetryStart =
        source.indexOf('winn3TerminalFailureMayRetryWithFreshConfig(');
    final staleRetryEnd =
        source.indexOf('await _markCachedVpnConfigStale();', staleRetryStart);
    expect(staleRetryStart, greaterThanOrEqualTo(0));
    expect(staleRetryEnd, greaterThan(staleRetryStart));
    expect(
      RegExp(r'if \(!await _stopNativeTunnelForFailover\(\)\)')
          .allMatches(source.substring(staleRetryStart, staleRetryEnd))
          .length,
      1,
    );
  });

  test('successful Windows fallback retains pins without replacing TLS SNI',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _startTunnelCandidate(');
    final end = source.indexOf(
      'Future<bool> _loadPowerProtectionPromptSeen(',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final candidate = source.substring(start, end);

    expect(candidate, contains('var configForPersistence = config;'));
    expect(
      candidate,
      contains(
        "configForPersistence = Map<String, dynamic>.from(config)\n"
        "          ..['windows_transport_bypass_ipv4'] = <String>[\n"
        "            boundedAddresses.first,",
      ),
    );
    expect(
      candidate.indexOf('...sortedResolvedAddresses'),
      lessThan(candidate.indexOf('...sortedPinnedAddresses')),
      reason:
          'Fresh DNS answers must stay ahead of retained pins after carrier address rotation.',
    );
    expect(
      candidate,
      contains("..['host'] = boundedAddresses.first"),
      reason: 'Only the transient native start config should use the IP pin.',
    );
    expect(
      candidate,
      isNot(contains("..['server_name'] = boundedAddresses.first")),
      reason: 'TLS authentication must keep the advertised server name.',
    );
    expect(
      candidate,
      contains(
        "_persistVpnConfigBestEffort(\n"
        "          configForPersistence, 'connected_tunnel_config')",
      ),
    );
    expect(candidate, contains('_cachedVpnConfig = configForPersistence;'));
  });
}
