class _Ipv4Range {
  const _Ipv4Range(this.start, this.end);

  final int start;
  final int end;
}

int? _parseIpv4(String value) {
  final parts = value.trim().split('.');
  if (parts.length != 4) return null;
  var result = 0;
  for (final part in parts) {
    if (part.isEmpty || !RegExp(r'^\d{1,3}$').hasMatch(part)) return null;
    final octet = int.tryParse(part);
    if (octet == null || octet < 0 || octet > 255) return null;
    result = (result << 8) | octet;
  }
  return result;
}

String _formatIpv4(int value) => [
      (value >> 24) & 0xff,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ].join('.');

_Ipv4Range _parseCidr(String raw) {
  final value = raw.trim();
  if (value.isEmpty) throw const FormatException('An empty route is invalid.');
  final parts = value.split('/');
  if (parts.length > 2) {
    throw FormatException('Invalid IPv4 route: $value');
  }
  final address = _parseIpv4(parts.first);
  final prefix = parts.length == 2 ? int.tryParse(parts[1]) : 32;
  if (address == null || prefix == null || prefix < 0 || prefix > 32) {
    throw FormatException('Invalid IPv4 route: $value');
  }
  final size = 1 << (32 - prefix);
  final mask = prefix == 0 ? 0 : (0xffffffff << (32 - prefix)) & 0xffffffff;
  final start = address & mask;
  return _Ipv4Range(start, start + size - 1);
}

List<_Ipv4Range> _mergeRanges(Iterable<String> cidrs) {
  final parsed = cidrs
      .map((value) => value.trim())
      .where((value) => value.isNotEmpty)
      .map(_parseCidr)
      .toList()
    ..sort((a, b) => a.start.compareTo(b.start));
  final merged = <_Ipv4Range>[];
  for (final range in parsed) {
    if (merged.isEmpty || range.start > merged.last.end + 1) {
      merged.add(range);
      continue;
    }
    final previous = merged.removeLast();
    merged.add(_Ipv4Range(
      previous.start,
      range.end > previous.end ? range.end : previous.end,
    ));
  }
  return merged;
}

List<String> _rangeToCidrs(_Ipv4Range range) {
  final result = <String>[];
  var current = range.start;
  while (current <= range.end) {
    var blockSize = current == 0 ? 1 << 32 : current & -current;
    final remaining = range.end - current + 1;
    while (blockSize > remaining) {
      blockSize >>= 1;
    }
    final prefix = 32 - (blockSize.bitLength - 1);
    result.add('${_formatIpv4(current)}/$prefix');
    current += blockSize;
  }
  return result;
}

/// Validates, de-duplicates, and minimally represents IPv4 destinations that
/// should bypass the VPN. A bare IPv4 address is accepted as a /32 route.
List<String> normalizeExcludedIpv4Cidrs(Iterable<String> cidrs) {
  return _mergeRanges(cidrs).expand(_rangeToCidrs).toList(growable: false);
}

/// Produces the minimal IPv4 AllowedIPs set covering everything except the
/// excluded destinations. This is portable across all AmneziaWG clients.
List<String> allowedIpv4CidrsExcluding(Iterable<String> excludedCidrs) {
  final excluded = _mergeRanges(excludedCidrs);
  if (excluded.isEmpty) return const ['0.0.0.0/0'];

  final allowed = <_Ipv4Range>[];
  var cursor = 0;
  for (final range in excluded) {
    if (cursor < range.start) {
      allowed.add(_Ipv4Range(cursor, range.start - 1));
    }
    cursor = range.end + 1;
    if (cursor > 0xffffffff) break;
  }
  if (cursor <= 0xffffffff) {
    allowed.add(_Ipv4Range(cursor, 0xffffffff));
  }
  return allowed.expand(_rangeToCidrs).toList(growable: false);
}

/// Preserves full IPv4/IPv6 tunnel coverage without the Windows WireGuard
/// service's implicit `/0` firewall. That firewall intentionally blocks all
/// physical-interface traffic, including traffic that the signed per-app
/// split driver has rebound to the physical adapter.
///
/// Call this only while Windows per-app exclusions are enabled.
/// Windows sessions never install a `/0` route; leak protection is the service's WFP policy.
List<String> windowsPerAppAllowedIpCidrs(Iterable<String> allowedIpv4Cidrs) {
  final routes = <String>[];
  for (final raw in allowedIpv4Cidrs) {
    final route = raw.trim();
    if (route == '0.0.0.0/0') {
      routes.addAll(const ['0.0.0.0/1', '128.0.0.0/1']);
    } else if (route.isNotEmpty) {
      routes.add(route);
    }
  }
  routes.addAll(const ['::/1', '8000::/1']);
  return List<String>.unmodifiable(routes);
}

/// The Win's VPN product engine is configured through AWG's `setconf` UAPI,
/// which intentionally does not install operating-system routes. Windows must
/// therefore use the owned manual-route path for every connection. App
/// exclusions and the internal Xray carrier add physical bypasses, but they do
/// not decide whether the tunnel itself needs routes.
bool windowsRequiresManualTunnelRoutes() => true;
