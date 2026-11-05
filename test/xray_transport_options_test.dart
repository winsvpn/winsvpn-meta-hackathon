import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/xray_transport_options.dart';

void main() {
  test(
      'transport protocol enum maps to the winn3 carrier udp/stream flag '
      'strings', () {
    expect(
      XrayTransportProtocol.values.map((protocol) => protocol.carrierFlag),
      ['udp', 'tcp', 'tls'],
    );
    expect(xrayCarrierClassFlag(XrayTransportProtocol.udp), 'udp');
    expect(xrayCarrierClassFlag(XrayTransportProtocol.tcp), 'tcp');
    expect(xrayCarrierClassFlag(XrayTransportProtocol.tls), 'tls');
    // No enum value may silently share another's flag; the two-layer agreement
    // only holds if the whole vocabulary is distinct, so a reorder of the enum
    // cannot alias two carriers onto one flag.
    expect(
      XrayTransportProtocol.values
          .map((protocol) => protocol.carrierFlag)
          .toSet(),
      hasLength(XrayTransportProtocol.values.length),
    );
  });

  test('UDP reorder is honored; stream carriers are ordered, not honored', () {
    // Positive: the datagram carrier must be selectable without imposing order.
    expect(XrayTransportProtocol.udp.honorsReorder, isTrue);
    // Negative: the stream carriers ride a byte-ordered transport, so the
    // order-agnostic guarantee must NOT be claimed for them.
    expect(XrayTransportProtocol.tcp.honorsReorder, isFalse);
    expect(XrayTransportProtocol.tls.honorsReorder, isFalse);
    // Classification mirrors the carrier: only UDP is a datagram (non-stream)
    // carrier, and only the stream transports survive a wholesale UDP block.
    expect(XrayTransportProtocol.udp.isStream, isFalse);
    expect(XrayTransportProtocol.tcp.isStream, isTrue);
    expect(XrayTransportProtocol.tls.isStream, isTrue);
    expect(XrayTransportProtocol.udp.survivesUdpBlock, isFalse);
    expect(XrayTransportProtocol.tcp.survivesUdpBlock, isTrue);
    expect(XrayTransportProtocol.tls.survivesUdpBlock, isTrue);
  });

  test('transport mode resolves to a consistent carrier flag order', () {
    expect(xrayCarrierFlagsForTransportMode('udp'), ['udp']);
    expect(xrayCarrierFlagsForTransportMode('tcp'), ['tcp', 'tls']);
    // 'auto' is the shipping behaviour: datagram first, stream fallback second.
    expect(xrayCarrierFlagsForTransportMode('auto'), ['udp', 'tcp', 'tls']);
    // Unknown modes fail closed to the same order, never to nothing.
    expect(xrayCarrierFlagsForTransportMode(''), ['udp', 'tcp', 'tls']);
  });

  test('accepts only a real WebSocket protocol upgrade', () {
    expect(
      isSuccessfulXrayWebSocketUpgradeStatusLine(
        'HTTP/1.1 101 Switching Protocols',
      ),
      isTrue,
    );
    expect(
      isSuccessfulXrayWebSocketUpgradeStatusLine('HTTP/1.0 101'),
      isTrue,
    );
    expect(
      isSuccessfulXrayWebSocketUpgradeStatusLine(
        'HTTP/1.1 301 Moved Permanently',
      ),
      isFalse,
    );
    expect(
      isSuccessfulXrayWebSocketUpgradeStatusLine('HTTP/2 200'),
      isFalse,
    );
  });

  test('a legacy plaintext primary yields only the TLS edge transport', () {
    final options = buildXrayTransportOptions(
      hosts: const ['france.app-cloud-sync.net'],
      advertisedPort: 80,
      advertisedSecurity: 'none',
    );

    expect(options, hasLength(1));
    expect(options.single.host, 'france.app-cloud-sync.net');
    expect(options.single.port, 443);
    expect(options.single.security, 'tls');
  });

  test(
      'M-3: does not invent an unadvertised plaintext fallback for a '
      'legacy TLS-only hub', () {
    final options = buildXrayTransportOptions(
      hosts: const ['EDGE.EXAMPLE.COM', 'edge.example.com'],
      advertisedPort: 443,
      advertisedSecurity: 'tls',
    );

    // Before the fix this synthesized a second, unadvertised port-80/`none`
    // sibling here, exposing the outer WebSocket/VLESS handshake to an
    // on-path observer even though the hub only ever advertised TLS.
    expect(options, hasLength(1));
    expect(options.single.host, 'edge.example.com');
    expect(options.single.port, 443);
    expect(options.single.security, 'tls');
  });

  test('ruling 4: a hub-advertised plaintext route is never selected', () {
    final options = buildXrayTransportOptions(
      hosts: const ['france.app-cloud-sync.net'],
      advertisedPort: 80,
      advertisedSecurity: 'none',
    );

    expect(options.first.host, 'france.app-cloud-sync.net');
    expect(options.first.port, 443);
    expect(options.map((option) => option.security), everyElement('tls'));
  });

  test('uses an explicit server transport order without synthesizing routes',
      () {
    final options = buildXrayTransportOptions(
      hosts: const ['primary.example.com', 'backup.example.com'],
      advertisedPort: 80,
      advertisedSecurity: 'none',
      advertisedTransports: const [
        {'port': 80, 'security': 'none'},
        {'port': 443, 'security': 'tls'},
      ],
    );

    expect(
      options.map((option) => option.key),
      [
        'primary.example.com:443:tls',
        'backup.example.com:443:tls',
      ],
    );
  });

  test('bounded retries preserve every reachable advertised transport', () {
    final options = buildXrayTransportOptions(
      hosts: List<String>.generate(
        10,
        (index) => 'edge-$index.example.com',
      ),
      advertisedPort: 80,
      advertisedSecurity: 'none',
      advertisedTransports: const [
        {'port': 443, 'security': 'tls'},
        {'port': 8443, 'security': 'tls'},
      ],
    );

    final bounded = boundedXrayTransportOptions(
      options,
      maximumCandidates: 8,
    );

    expect(bounded, hasLength(8));
    expect(bounded.first.key, 'edge-0.example.com:443:tls');
    expect(bounded[1].key, 'edge-0.example.com:8443:tls');
    expect(
      bounded.map((option) => option.transportKey).toSet(),
      {'443:tls', '8443:tls'},
      reason:
          'Regional aliases on TCP/443 must not consume the entire retry budget before TCP/8443 is attempted.',
    );
  });

  test('bounded retries de-duplicate exact endpoints and honor zero budget', () {
    const duplicate = XrayTransportOption(
      host: 'edge.example.com',
      port: 80,
      security: 'none',
    );
    expect(
      boundedXrayTransportOptions(
        const [duplicate, duplicate],
        maximumCandidates: 8,
      ).map((option) => option.key),
      ['edge.example.com:80:none'],
    );
    expect(
      boundedXrayTransportOptions(
        const [duplicate],
        maximumCandidates: 0,
      ),
      isEmpty,
    );
  });

  test('sanitizes and preserves dynamic transport order for config caching',
      () {
    final sanitized = sanitizeAdvertisedXrayTransports(const [
      {'port': '8080', 'security': 'NONE'},
      {'port': 8443, 'security': 'tls'},
      {'port': 8080, 'security': 'none'},
      {'port': 0, 'security': 'none'},
      {'port': 9443, 'security': 'reality'},
    ]);

    expect(
      sanitized,
      const [
        {'port': 8080, 'security': 'none'},
        {'port': 8443, 'security': 'tls'},
      ],
    );
    final options = buildXrayTransportOptions(
      hosts: const ['edge.example.com'],
      advertisedPort: 80,
      advertisedSecurity: 'none',
      advertisedTransports: sanitized,
    );
    expect(
      options.map((option) => '${option.port}:${option.security}'),
      ['8443:tls'],
    );
  });

  test('does not synthesize TLS for an IP address without a certificate name',
      () {
    final options = buildXrayTransportOptions(
      hosts: const ['203.0.113.20'],
      advertisedPort: 80,
      advertisedSecurity: 'none',
    );

    expect(options, isEmpty);
  });

  test('rejects invalid advertised transport metadata', () {
    expect(
      buildXrayTransportOptions(
        hosts: const ['edge.example.com'],
        advertisedPort: 0,
        advertisedSecurity: 'none',
      ),
      isEmpty,
    );
    expect(
      buildXrayTransportOptions(
        hosts: const ['edge.example.com'],
        advertisedPort: 443,
        advertisedSecurity: 'reality',
      ),
      isEmpty,
    );
  });

  test(
      'rejects private, loopback, and injected fallback hosts before preflight',
      () {
    final options = buildXrayTransportOptions(
      hosts: const [
        '127.0.0.1',
        '192.168.50.10',
        'edge.example.com\ninternal.example.com',
      ],
      advertisedPort: 80,
      advertisedSecurity: 'none',
    );

    expect(options, isEmpty);
  });

  test('latency probe resolves A-only only when the target is not a literal',
      () {
    expect(requiresAonlyIpv4ProbeResolution('203.0.113.20'), isFalse);
    expect(requiresAonlyIpv4ProbeResolution('198.51.100.7'), isFalse);
    expect(requiresAonlyIpv4ProbeResolution('edge.example.com'), isTrue);
    expect(requiresAonlyIpv4ProbeResolution('192.168.50.1'), isTrue);
    expect(requiresAonlyIpv4ProbeResolution('127.0.0.1'), isTrue);
    expect(requiresAonlyIpv4ProbeResolution(''), isTrue);
  });

  test('probe dials a public literal as-is, never resolving it', () {
    expect(
      firstPublicIpv4ProbeDialTarget(
        host: '203.0.113.20',
        aonlyAddresses: const <String>[],
      ),
      '203.0.113.20',
    );
  });

  test('probe dials the first A-only public IPv4 for a hostname', () {
    expect(
      firstPublicIpv4ProbeDialTarget(
        host: 'edge.example.com',
        aonlyAddresses: const ['10.0.0.1', '198.51.100.7', '203.0.113.9'],
      ),
      '198.51.100.7',
    );
  });

  test('probe refuses rather than dial a hostname with no public IPv4', () {
    expect(
      firstPublicIpv4ProbeDialTarget(
        host: 'edge.example.com',
        aonlyAddresses: const <String>[''],
      ),
      isEmpty,
    );
    expect(
      firstPublicIpv4ProbeDialTarget(
        host: 'edge.example.com',
        aonlyAddresses: const ['10.0.0.1', '192.168.50.1'],
      ),
      isEmpty,
    );
  });
}
