import 'dart:io';

/// Redacts connection identifiers from a human-facing log line before it is
/// written anywhere a device could be searched:
///
/// * server hostnames (URLs and bare `host:port`)
/// * endpoint IP addresses (IPv4 and IPv6)
/// * public keys, tokens, account numbers and UUIDs
/// * user identifiers
///
/// This is the anti-leak choke point for log text. It shares its regexes with
/// [redactTunnelFailureText] so the two cannot drift apart, but unlike that
/// function it does not collapse newlines, does not truncate, and does not
/// over-redact paths in general log prose -- callers own those decisions.
String redactLogSecrets(String value) => _applyIdentifierRedactions(value);

/// Redacts the identifier-bearing patterns shared by every redaction surface.
/// Order matters: the URL/credential rules run first so their `scheme://…` and
/// `user:pass@host` forms are collapsed before the bare-host and IP rules run,
/// preventing a later rule from re-printing a captured identifier.
String _applyIdentifierRedactions(String value) => value
    .replaceAll(
      RegExp(
        r'\b[a-z][a-z0-9+.-]{1,31}://[^\s,;]+',
        caseSensitive: false,
      ),
      '<url>',
    )
    .replaceAll(
      RegExp(
        r'(?<![A-Za-z0-9._-])[^\s:@/]+:[^\s@/]+@[A-Za-z0-9.-]+(?::\d{1,5})?',
        caseSensitive: false,
      ),
      '<credential>',
    )
    // The candidate never ends in '.': a sentence period after an address
    // ("connected to 2001:db8::1.") made the whole candidate unparseable,
    // so the address was kept verbatim.
    .replaceAllMapped(
      RegExp(
        r'(?<![A-Za-z0-9])\[?[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*[0-9A-Fa-f:](?:%[A-Za-z0-9_.-]*[A-Za-z0-9_-])?\]?(?::\d{1,5})?(?![A-Za-z0-9])',
      ),
      (match) => _redactIpv6Candidate(match.group(0)!),
    )
    .replaceAll(
      RegExp(r'(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?'),
      '<ip>',
    )
    .replaceAll(
      RegExp(
        r'(?<![A-Za-z0-9_.-])(?:localhost|[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}):\d{0,5}(?![A-Za-z0-9])',
        caseSensitive: false,
      ),
      '<host>',
    )
    .replaceAll(RegExp(r'\b\d{4}-\d{4}-\d{4}\b'), '<account>')
    .replaceAll(RegExp(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,36}\b'), '<id>')
    .replaceAll(
      RegExp(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])'),
      '<key>',
    )
    .replaceAll(
      RegExp(
        r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{20,})?(?![A-Za-z0-9_-])',
      ),
      '<token>',
    )
    .replaceAll(
      RegExp(
        r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43,86}(?![A-Za-z0-9_-])',
      ),
      '<key>',
    )
    .replaceAll(
      RegExp(
        r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42,44}={0,2}(?![A-Za-z0-9+/])',
      ),
      '<key>',
    )
    // The four rules below close the gaps between this redactor and
    // kCrashRedactionRules (crash_report_privacy.dart). They run last so the
    // token, UUID and key rules above see their inputs unmodified.
    .replaceAll(
      RegExp(
        r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}(?![A-Za-z0-9._%+-])',
      ),
      '<email>',
    )
    .replaceAll(RegExp(r'(?<![0-9])\d{12}(?![0-9])'), '<account>')
    .replaceAll(
      RegExp(r'(?<![A-Za-z0-9_-])INSTALL-[A-Za-z0-9_-]{24,42}(?![A-Za-z0-9_-])'),
      '<id>',
    )
    // Bare hostnames with no port: dart:io's "Failed host lookup: 'host'" and
    // the pinned client's refusals, which name `uri.host`. Source-file and
    // library suffixes are left alone so stack-frame names stay readable.
    .replaceAll(
      RegExp(
        r'(?<![A-Za-z0-9_.@/<-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+(?!(?:dart|kt|kts|swift|java|go|js|json|txt|so|dll|cc|cpp|h|mm|log|conf|yaml|plist|xml)(?![A-Za-z0-9-]))[A-Za-z]{2,63}(?![A-Za-z0-9_-])',
        caseSensitive: false,
      ),
      '<host>',
    );

/// Redacts tunnel-failure text for on-disk diagnostics. Identifier-redacts the
/// shared patterns, then additionally collapses newlines, redacts path-like
/// tokens (which name private files), truncates to [maximumLength], and returns
/// a non-empty placeholder rather than an empty string.
String redactTunnelFailureText(Object error, {int maximumLength = 512}) {
  var value = error.toString().replaceAll(RegExp(r'[\r\n]+'), ' ').trim();
  value = _applyIdentifierRedactions(value)
      .replaceAll(
        RegExp(r'[A-Za-z]:\\[^\s,;]+', caseSensitive: false),
        '<path>',
      )
      .replaceAll(
        RegExp(r'(?<![A-Za-z0-9])/(?:[^/\s,;]+/)+[^/\s,;]+'),
        '<path>',
      );
  if (value.length > maximumLength) value = value.substring(0, maximumLength);
  return value.isEmpty ? 'unspecified_tunnel_failure' : value;
}

String _redactIpv6Candidate(String raw) {
  var candidate = raw;
  if (candidate.startsWith('[')) {
    final closingBracket = candidate.indexOf(']');
    if (closingBracket <= 1) return raw;
    candidate = candidate.substring(1, closingBracket);
  } else {
    final lastColon = candidate.lastIndexOf(':');
    if (lastColon > 0 && candidate.indexOf(':') != lastColon) {
      final possiblePort = candidate.substring(lastColon + 1);
      if (int.tryParse(possiblePort) != null) {
        var withoutPort = candidate.substring(0, lastColon);
        final zoneIndex = withoutPort.indexOf('%');
        if (zoneIndex >= 0) {
          withoutPort = withoutPort.substring(0, zoneIndex);
        }
        if (InternetAddress.tryParse(withoutPort)?.type ==
            InternetAddressType.IPv6) {
          return '<ip>';
        }
      }
    }
  }
  final zoneIndex = candidate.indexOf('%');
  if (zoneIndex >= 0) candidate = candidate.substring(0, zoneIndex);
  final address = InternetAddress.tryParse(candidate);
  return address?.type == InternetAddressType.IPv6 ? '<ip>' : raw;
}
