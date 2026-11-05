import 'dart:io';

import 'vpn_config_validation.dart';

/// The Winn3 carrier transports, mirroring the `udp`/`stream` packages of the
/// winn3 carrier (`winn3/carrier`).
///
/// The names and the flag strings are fixed by those packages: `ClassUDP`,
/// `ClassTCP` and `ClassTLS` render as `udp`, `tcp` and `tls` (see
/// `Class.String` in `carrier.go`). Keeping the Dart selection layer on the
/// same vocabulary as the carrier's `udp.go`/`stream.go` means a transport
/// picked here is always spelled exactly the way the carrier can accept it, and
/// the two layers can never drift into a flag the engine does not recognise.
enum XrayTransportProtocol {
  /// One Winn3 message per UDP datagram, with nothing else on the wire. The
  /// datagram carrier is order-agnostic: it carries no sequence number and
  /// hands each datagram through in the order the socket delivers it, never
  /// re-sorting it into a numbering — so reordering on the path is honoured
  /// instead of being turned into a silently-lost message.
  udp('udp'),

  /// The stream record layer over a bare TCP connection (`ClassTCP`). A stream
  /// carrier restores message boundaries and rides a byte-ordered transport.
  tcp('tcp'),

  /// The same stream record layer inside TLS over TCP (`ClassTLS`).
  tls('tls');

  const XrayTransportProtocol(this.carrierFlag);

  /// The flag string the winn3 carrier's udp/stream packages accept for this
  /// transport.
  final String carrierFlag;

  /// Whether this transport is a stream carrier (TCP or TLS) rather than the
  /// datagram carrier. Matches `Class.Stream()` on the carrier.
  bool get isStream => this != XrayTransportProtocol.udp;

  /// Whether this transport still works on a network that drops UDP wholesale.
  /// Matches `Class.SurvivesUDPBlock()` on the carrier: only the stream
  /// transports survive a wholesale UDP block.
  bool get survivesUdpBlock => isStream;

  /// Whether this transport honours reordering of the higher layer.
  ///
  /// Only the datagram carrier does: it delivers each datagram in arrival
  /// order and never re-sorts, so out-of-order delivery is preserved rather
  /// than dropped or re-ordered by the carrier. The stream carriers sit on TCP
  /// and are byte-ordered by the transport, so the concept does not apply.
  bool get honorsReorder => this == XrayTransportProtocol.udp;
}

/// The option-to-flag mapping: the carrier flag string accepted by the winn3
/// carrier's udp/stream packages for a given [protocol].
///
/// The returned string is exactly what `Class.String()` emits for the
/// corresponding `Class`, so a transport selected here can be handed to the
/// engine verbatim.
String xrayCarrierClassFlag(XrayTransportProtocol protocol) =>
    protocol.carrierFlag;

/// Resolves a transport-mode selector to the ordered list of carrier flags the
/// winn3 carrier should try, consistent with its udp/stream packages.
///
/// The app's selector is `'auto'` (datagram first, stream fallback second),
/// `'udp'` (direct datagram only) or `'tcp'` (stream only, the carrier's own
/// `SurvivesUDPBlock` transports). `'udp'` never emits a stream flag and
/// `'tcp'` never emits the datagram flag, matching the leg-suppression
/// semantics of the transport selector.
List<String> xrayCarrierFlagsForTransportMode(String mode) {
  switch (mode) {
    case 'udp':
      return const ['udp'];
    case 'tcp':
      return const ['tcp', 'tls'];
    case 'auto':
    default:
      return const ['udp', 'tcp', 'tls'];
  }
}

class XrayTransportOption {
  const XrayTransportOption({
    required this.host,
    required this.port,
    required this.security,
  });

  final String host;
  final int port;
  final String security;

  String get key => '${host.toLowerCase()}:$port:${security.toLowerCase()}';

  String get transportKey => '$port:${security.toLowerCase()}';
}

/// Bounds runtime attempts without allowing a long regional-alias list for the
/// preferred route to crowd every alternate transport out of the retry budget.
///
/// [options] is expected to already be ordered and preflighted. The first
/// reachable candidate for each distinct port/security route is retained
/// before the remaining slots are filled in the original order.
List<XrayTransportOption> boundedXrayTransportOptions(
  Iterable<XrayTransportOption> options, {
  required int maximumCandidates,
}) {
  if (maximumCandidates <= 0) return const [];

  final ordered = <XrayTransportOption>[];
  final seenOptions = <String>{};
  for (final option in options) {
    if (seenOptions.add(option.key)) ordered.add(option);
  }
  if (ordered.length <= maximumCandidates) {
    return List<XrayTransportOption>.unmodifiable(ordered);
  }

  final selected = <XrayTransportOption>[];
  final selectedOptions = <String>{};
  final representedTransports = <String>{};
  for (final option in ordered) {
    if (!representedTransports.add(option.transportKey)) continue;
    selected.add(option);
    selectedOptions.add(option.key);
    if (selected.length == maximumCandidates) {
      return List<XrayTransportOption>.unmodifiable(selected);
    }
  }
  for (final option in ordered) {
    if (!selectedOptions.add(option.key)) continue;
    selected.add(option);
    if (selected.length == maximumCandidates) break;
  }
  return List<XrayTransportOption>.unmodifiable(selected);
}

/// Whether a probe target must be resolved A-only before it is dialed.
///
/// `Socket.connect(String)` makes dart:io run an implicit
/// `InternetAddress.lookup` with no family hint — an A **and** an AAAA query —
/// through the machine's resolver. For a node-picker latency probe that means
/// the VPN's node hostnames are sent to the local/ISP resolver on the physical
/// interface while the user only looked at the server list, which is the
/// name-leak class this product exists to prevent. A public IPv4 literal needs
/// no lookup and is dialed directly.
bool requiresAonlyIpv4ProbeResolution(String host) {
  return !_isPublicIpv4Literal(host);
}

/// The single literal a latency probe should dial, or '' if none is usable.
///
/// A host that is already a public IPv4 literal is dialed as-is (nothing to
/// resolve, so nothing leaves). Otherwise the first A-only-resolved public IPv4
/// is chosen; empty [aonlyAddresses] (resolution failed, or no public IPv4)
/// yields '' and the caller must refuse the probe rather than fall back to the
/// name, which would reintroduce the implicit dual-stack lookup.
String firstPublicIpv4ProbeDialTarget({
  required String host,
  required Iterable<String> aonlyAddresses,
}) {
  if (_isPublicIpv4Literal(host)) return host;
  for (final address in aonlyAddresses) {
    if (_isPublicIpv4Literal(address)) return address;
  }
  return '';
}

List<String> validatedXrayCarrierIpv4Pins({
  required String xrayHost,
  required Iterable<String> advertisedCarrierPins,
}) {
  final result = <String>[];
  final seen = <String>{};

  void addIfPublicIpv4(String value) {
    final host = value.trim();
    if (_isPublicIpv4Literal(host) && seen.add(host)) result.add(host);
  }

  addIfPublicIpv4(xrayHost);
  for (final pin in advertisedCarrierPins) {
    addIfPublicIpv4(pin);
  }
  return List<String>.unmodifiable(result);
}

bool isSuccessfulXrayWebSocketUpgradeStatusLine(String statusLine) {
  return RegExp(r'^HTTP/1\.[01]\s+101(?:\s|$)', caseSensitive: false)
      .hasMatch(statusLine.trim());
}

List<Map<String, Object>> sanitizeAdvertisedXrayTransports(dynamic value) {
  if (value is! Iterable || value is String) return const [];
  final result = <Map<String, Object>>[];
  final seen = <String>{};
  for (final raw in value) {
    if (raw is! Map) continue;
    final port = int.tryParse((raw['port'] ?? '').toString());
    final security = (raw['security'] ?? '').toString().trim().toLowerCase();
    if (port == null || port < 1 || port > 65535) continue;
    if (security != 'none' && security != 'tls') continue;
    if (seen.add('$port:$security')) {
      result.add(<String, Object>{'port': port, 'security': security});
    }
  }
  return List.unmodifiable(result);
}

dynamic originalAdvertisedXrayTransports(Map xray, Map raw) {
  for (final key in const ['transports', 'stealth_transports']) {
    if (xray.containsKey(key)) {
      return xray[key] ?? const <Object>[];
    }
  }
  for (final key in const ['stealth_transports', 'stealthtransports']) {
    if (raw.containsKey(key)) {
      return raw[key] ?? const <Object>[];
    }
  }
  return null;
}

List<XrayTransportOption> buildXrayTransportOptions({
  required Iterable<String> hosts,
  required dynamic advertisedPort,
  required dynamic advertisedSecurity,
  dynamic advertisedTransports,
}) {
  final validHosts = hosts
      .map((host) => host.trim().toLowerCase())
      .where(VpnConfigValidator.isPublicHost)
      .where(_isDnsName)
      .toSet()
      .toList(growable: false);
  if (validHosts.isEmpty) return const [];

  final transports = <({int port, String security})>[];
  if (advertisedTransports != null) {
    transports.addAll(
      _parseAdvertisedTransports(advertisedTransports)
          .where((transport) => transport.security == 'tls'),
    );
  } else {
    final port = int.tryParse((advertisedPort ?? '').toString());
    final security =
        (advertisedSecurity ?? '').toString().trim().toLowerCase();
    if (port == null || port < 1 || port > 65535) return const [];
    if (security == 'tls') {
      transports.add((port: port, security: 'tls'));
    } else if (port == 80 && security == 'none') {
      transports.add((port: 443, security: 'tls'));
    } else {
      return const [];
    }
  }

  final options = <XrayTransportOption>[];
  final seen = <String>{};
  for (final transport in transports) {
    for (final host in validHosts) {
      final option = XrayTransportOption(
        host: host,
        port: transport.port,
        security: 'tls',
      );
      if (seen.add(option.key)) options.add(option);
    }
  }
  return List<XrayTransportOption>.unmodifiable(options);
}

/// Receives the original transport list before input sanitization.
/// Explicit empty or malformed lists authorize no route.
Map<String, dynamic> normalizeTlsOnlyXrayConfig(
  Map<String, dynamic> source, {
  required dynamic advertisedTransports,
}) {
  final config = Map<String, dynamic>.from(source);
  final rawXray = source['xray'];
  final xray = rawXray is Map
      ? Map<String, dynamic>.from(rawXray)
      : <String, dynamic>{};

  final hosts = <String>[(xray['host'] ?? '').toString()];
  final fallbackHosts = xray['fallback_hosts'];
  if (fallbackHosts is Iterable && fallbackHosts is! String) {
    hosts.addAll(fallbackHosts.map((host) => host.toString()));
  }

  final options = buildXrayTransportOptions(
    hosts: hosts,
    advertisedPort: xray['port'],
    advertisedSecurity: xray['security'],
    advertisedTransports: advertisedTransports,
  );
  final transports = <Map<String, Object>>[];
  final seenTransports = <String>{};
  for (final option in options) {
    if (seenTransports.add(option.transportKey)) {
      transports.add(<String, Object>{
        'port': option.port,
        'security': 'tls',
      });
    }
  }
  xray['transports'] = transports;

  if (options.isEmpty) {
    xray['enabled'] = false;
    xray['port'] = 443;
    xray['security'] = 'tls';
    config['stealth_active'] = false;
    if (config['protocol'] == 'xray-vless-ws+amneziawg') {
      config['protocol'] = 'amneziawg';
    }
  } else {
    final primary = options.first;
    xray['host'] = primary.host;
    xray['port'] = primary.port;
    xray['security'] = 'tls';
    xray['server_name'] = primary.host;
  }
  config['xray'] = xray;
  return config;
}

List<({int port, String security})> _parseAdvertisedTransports(dynamic value) {
  return [
    for (final transport in sanitizeAdvertisedXrayTransports(value))
      (
        port: transport['port']! as int,
        security: transport['security']! as String,
      ),
  ];
}

bool _isDnsName(String host) {
  if (!host.contains('.')) return false;
  return InternetAddress.tryParse(host) == null;
}

bool _isPublicIpv4Literal(String value) {
  final parts = value.trim().split('.');
  if (parts.length != 4) return false;
  final octets = <int>[];
  for (final part in parts) {
    if (part.isEmpty || !RegExp(r'^\d{1,3}$').hasMatch(part)) return false;
    final octet = int.tryParse(part);
    if (octet == null || octet < 0 || octet > 255) return false;
    octets.add(octet);
  }
  final first = octets[0];
  final second = octets[1];
  if (first == 0 || first == 10 || first == 127) return false;
  if (first == 100 && second >= 64 && second <= 127) return false;
  if (first == 169 && second == 254) return false;
  if (first == 172 && second >= 16 && second <= 31) return false;
  if (first == 192 && second == 168) return false;
  if (first >= 224) return false;
  return true;
}
