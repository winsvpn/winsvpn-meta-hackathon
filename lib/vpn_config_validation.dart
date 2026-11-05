import 'dart:convert';
import 'dart:io';

/// One `H1`..`H4` specification: either a single value or an inclusive range.
///
/// AmneziaWG's `device/magic-header.go` accepts both spellings on the same
/// field -- `44` and `3221225472-4294967295` -- and a bare value is stored as
/// the degenerate range `start == end`. The distinction matters because
/// `Generate()` is called **once per packet** in `RoutineEncryption`, so a
/// range makes the four header bytes vary per datagram instead of being fixed
/// for the life of the flow. Measured on the pinned engine: with every header
/// a constant, payload offsets 0..3 take exactly one value across a session;
/// with ranges they take 50-86 values per 100 datagrams.
///
/// A scalar is therefore not a legacy special case to be tolerated -- it is
/// the same object with zero width, which is what lets the legacy 11/22/33/44
/// set keep validating through the identical code path.
class AwgHeaderSpec {
  const AwgHeaderSpec(this.start, this.end);

  /// A single value, i.e. a range of width one.
  const AwgHeaderSpec.scalar(int value)
      : start = value,
        end = value;

  final int start;
  final int end;

  bool get isRange => end > start;

  /// Inclusive width. 1 for a scalar.
  int get width => end - start + 1;

  /// Whether the engine could ever emit the same header word for both specs.
  ///
  /// This is `mergeWithDevice`'s rule in `device/uapi.go` verbatim
  /// (`left.start <= right.end && right.start <= left.end`). The engine
  /// **refuses** a device whose four headers overlap, because the receiver
  /// classifies an inbound datagram by testing the word against each range in
  /// turn and two ranges that intersect make that test ambiguous.
  ///
  /// For two scalars this degrades to equality, which is exactly the
  /// pairwise-distinctness rule this validator enforced before ranges existed.
  bool overlaps(AwgHeaderSpec other) =>
      start <= other.end && other.start <= end;

  /// The wire spelling, matching the engine's own `GenSpec()`.
  String get spec => isRange ? '$start-$end' : '$start';

  @override
  String toString() => spec;
}

class VpnConfigValidator {
  const VpnConfigValidator._();

  /// AmneziaWG junk-packet and junk-size knobs. These are packet counts and
  /// byte counts, so a small ceiling is correct for them.
  static const List<String> awgJunkFields = <String>[
    'Jc',
    'Jmin',
    'Jmax',
    'S1',
    'S2',
    'S3',
    'S4',
  ];

  /// AmneziaWG header knobs. H1..H4 replace WireGuard's four message-type
  /// values, which sit in a little-endian uint32 at the head of every packet:
  /// vanilla handshake initiation goes out as 01 00 00 00. A replacement below
  /// 2^24 leaves the top byte zero and so preserves the shape DPI actually
  /// matches on -- a small leading value followed by zero padding. Defeating
  /// that needs the whole uint32, which is why these are bounded separately
  /// from the junk knobs rather than sharing their ceiling.
  static const List<String> awgHeaderFields = <String>['H1', 'H2', 'H3', 'H4'];

  static const int awgJunkMax = 1000000;

  /// 1..4 are WireGuard's own message types; reusing one puts the vanilla value
  /// back on the wire.
  static const int awgHeaderMin = 5;
  static const int awgHeaderMax = 4294967295;

  /// The widest inclusive range the engine can draw from.
  ///
  /// `device/magic-header.go` computes `high := int64(h.end - h.start + 1)`,
  /// and that subtraction happens in **uint32** arithmetic before the widening
  /// cast. A range spanning the whole keyspace therefore wraps to 0 and
  /// `crypto/rand.Int` panics on a non-positive bound -- verified against the
  /// pinned engine, which dies with "crypto/rand: argument to Int is <= 0".
  /// [awgHeaderMin] already keeps every accepted range strictly narrower than
  /// this, so the guard is unreachable today; it is written down so that
  /// lowering the floor to 0 cannot silently arm a remote panic.
  static const int awgHeaderMaxRangeWidth = 4294967295;

  /// The longest `start-end` spelling: two 10-digit values and a separator.
  static const int awgHeaderSpecMaxLength = 21;

  /// The smallest header value whose most significant byte is non-zero. Values
  /// at or above this fill all four header bytes and no longer present the
  /// vanilla WireGuard zero padding.
  static const int awgHeaderFullWidthMin = 16777216;

  /// Parses one `H1`..`H4` value in either spelling, or null if unusable.
  ///
  /// Accepts an `int` or a decimal string (`44`), and a `start-end` string
  /// (`3221225472-4294967295`). Both endpoints must sit in
  /// [awgHeaderMin]..[awgHeaderMax] and `end` must not precede `start` -- the
  /// same three conditions `newMagicHeader` enforces, plus the floor of 5 this
  /// validator has always applied to keep WireGuard's own types 1..4 off the
  /// wire.
  ///
  /// Deliberately permissive about which form arrives, because the hub serves
  /// a JSON number for a scalar and a JSON string for a range, and `main.dart`
  /// interpolates whichever it got straight into `[Interface] H1 = ...`.
  static AwgHeaderSpec? parseAwgHeaderSpec(dynamic raw) {
    final text = _singleLine(raw, maxLength: awgHeaderSpecMaxLength);
    if (text.isEmpty) return null;
    // No interior whitespace. `_boundedNonNegativeInt` trims what it is given,
    // so without this `1000 - 4000` would split into two values that each trim
    // clean and parse -- while the engine's `strconv.ParseUint` refuses the
    // very same string. Being MORE permissive than the engine is the dangerous
    // direction: it accepts a profile the far end cannot start, and these
    // parameters are not negotiated, so nothing downstream can report it.
    if (text.contains(RegExp(r'\s'))) return null;

    final separator = text.indexOf('-');
    if (separator < 0) {
      final value = _boundedNonNegativeInt(
        text,
        max: awgHeaderMax,
        maxDigits: 10,
      );
      if (value == null || value < awgHeaderMin) return null;
      return AwgHeaderSpec.scalar(value);
    }

    // A second separator, an empty side, or a sign is not a range -- it is a
    // malformed value, and guessing at one is how an unusable profile reaches
    // an engine that cannot be told it was wrong.
    final start = _boundedNonNegativeInt(
      text.substring(0, separator),
      max: awgHeaderMax,
      maxDigits: 10,
    );
    final end = _boundedNonNegativeInt(
      text.substring(separator + 1),
      max: awgHeaderMax,
      maxDigits: 10,
    );
    if (start == null || end == null) return null;
    if (start < awgHeaderMin || end < start) return null;
    if (end - start + 1 > awgHeaderMaxRangeWidth) return null;
    return AwgHeaderSpec(start, end);
  }

  /// Shipping protocol_version when a persisted document omits the slot.
  ///
  /// Kept as a literal here so this validator does not import protocol
  /// dispatch. It must remain equal to `kWinnProtocolV1`.
  static const String defaultPersistedProtocolVersion = 'winn/1';

  static bool isUsable(Map<String, dynamic> config) =>
      validationErrors(config).isEmpty;

  /// Protocol version recorded on a persisted vpn_config.
  ///
  /// [isUsable] ignores this field on purpose: structural AWG/Xray checks are
  /// not protocol authorization. A document can stay structurally valid after
  /// the hub migrates the same node to registered Winn v3, so callers must
  /// refresh authoritative protocol selection before a persisted v1 value may
  /// lead or authorize AWG/Xray.
  static String persistedProtocolVersion(Map<String, dynamic> config) {
    final text = (config['protocol_version'] ?? config['protocolversion'] ?? '')
        .toString()
        .trim();
    return text.isEmpty ? defaultPersistedProtocolVersion : text;
  }

  static bool persistedProtocolIsWinn1(Map<String, dynamic> config) {
    return persistedProtocolVersion(config) == defaultPersistedProtocolVersion;
  }

  static String persistedNodeSlug(Map<String, dynamic>? config) {
    if (config == null) return '';
    return (config['node_slug'] ??
            config['nodeslug'] ??
            config['location_slug'] ??
            '')
        .toString()
        .trim();
  }

  static List<String> validationErrors(Map<String, dynamic> config) {
    final errors = <String>[];
    if (!isWireGuardKey(config['client_private_key'])) {
      errors.add('client_private_key');
    }
    if (!isWireGuardKey(config['server_public_key'])) {
      errors.add('server_public_key');
    }
    final presharedKey = (config['preshared_key'] ?? '').toString().trim();
    if (presharedKey.isNotEmpty && !isWireGuardKey(presharedKey)) {
      errors.add('preshared_key');
    }
    if (!isIpv4(config['client_ip'], allowPrivate: true)) {
      errors.add('client_ip');
    }
    if (!isIpv4(config['dns'], allowPrivate: true)) errors.add('dns');
    if (!isEndpoint(config['server_endpoint'])) errors.add('server_endpoint');
    if (!isAllowedIpv4Routes(config['allowedIPv4Routes'])) {
      errors.add('allowedIPv4Routes');
    }

    final mtu = int.tryParse((config['mtu'] ?? '').toString());
    if (mtu == null || mtu < 576 || mtu > 1500) errors.add('mtu');

    final obfuscation = config['obfuscation'];
    if (obfuscation != null) {
      if (obfuscation is! Map) {
        errors.add('obfuscation');
      } else {
        final values = <String, int>{};
        for (final field in awgJunkFields) {
          final value = _boundedNonNegativeInt(
            obfuscation[field],
            max: awgJunkMax,
            maxDigits: 7,
          );
          if (value == null) {
            errors.add('obfuscation.$field');
          } else {
            values[field] = value;
          }
        }
        final headerSpecs = <String, AwgHeaderSpec>{};
        for (final field in awgHeaderFields) {
          final spec = parseAwgHeaderSpec(obfuscation[field]);
          if (spec == null) {
            errors.add('obfuscation.$field');
          } else {
            headerSpecs[field] = spec;
          }
        }
        // Two message types that can produce the same word leave the peer
        // unable to tell a handshake from a transport packet, so a collision is
        // a broken config rather than a weak one. With ranges the test is
        // intersection rather than equality -- the engine's own
        // `mergeWithDevice` refuses an overlapping set outright, so accepting
        // one here would hand the host a config it cannot start.
        if (headerSpecs.length == awgHeaderFields.length) {
          final specs = awgHeaderFields.map((f) => headerSpecs[f]!).toList();
          var collides = false;
          for (var a = 0; a < specs.length && !collides; a++) {
            for (var b = a + 1; b < specs.length; b++) {
              if (specs[a].overlaps(specs[b])) {
                collides = true;
                break;
              }
            }
          }
          if (collides) errors.add('obfuscation.H1/H2/H3/H4');
        }
        if (values['Jmin'] != null &&
            values['Jmax'] != null &&
            values['Jmin']! > values['Jmax']!) {
          errors.add('obfuscation.Jmin/Jmax');
        }
      }
    }

    if (!_boolValue(config['stealth_active'])) return errors;
    final xray = config['xray'];
    if (xray is! Map) return [...errors, 'xray'];
    if (!isUuid(xray['uuid'])) errors.add('xray.uuid');
    if (!isPublicHost(xray['host'])) errors.add('xray.host');
    if (!isPublicHost(xray['server_name'])) errors.add('xray.server_name');
    if (!isPath(xray['path'])) errors.add('xray.path');
    if (!isPort(xray['port'])) errors.add('xray.port');
    if (int.tryParse((xray['local_port'] ?? '').toString()) != 42110) {
      errors.add('xray.local_port');
    }
    if ((xray['remote_awg_host'] ?? '').toString().trim() != '127.0.0.1') {
      errors.add('xray.remote_awg_host');
    }
    if (!isPort(xray['remote_awg_port'])) errors.add('xray.remote_awg_port');
    final security = (xray['security'] ?? '').toString().trim().toLowerCase();
    if (security != 'tls') {
      errors.add('xray.security');
    }
    return errors;
  }

  static bool isWireGuardKey(dynamic raw) {
    final value = (raw ?? '').toString().trim();
    if (!RegExp(r'^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$').hasMatch(value)) {
      return false;
    }
    try {
      return base64Decode(value).length == 32;
    } catch (_) {
      return false;
    }
  }

  static bool isIpv4(dynamic raw, {required bool allowPrivate}) {
    final value = _singleLine(raw, maxLength: 15);
    final address = InternetAddress.tryParse(value);
    if (address == null || address.type != InternetAddressType.IPv4) {
      return false;
    }
    // Canonical dotted-decimal only, the rule isWinnInnerIpv4 enforces on the
    // v3 path. Dart reads 0177 as decimal 177, but this string reaches native
    // parsers verbatim, and the inet_aton family (glibc getaddrinfo, iproute2)
    // reads a leading zero as octal: 0177.0.0.1 is 127.0.0.1 and 0012.0.0.1
    // is 10.0.0.1 there, past the loopback and private refusals below.
    if (value
        .split('.')
        .any((part) => part.length > 1 && part.startsWith('0'))) {
      return false;
    }
    final octets = value.split('.').map(int.tryParse).toList();
    if (octets.length != 4 || octets.any((part) => part == null)) return false;
    final a = octets[0]!;
    final b = octets[1]!;
    if (a == 0 || a == 127 || a >= 224) return false;
    if (!allowPrivate &&
        (a == 10 ||
            (a == 100 && b >= 64 && b <= 127) ||
            (a == 169 && b == 254) ||
            (a == 172 && b >= 16 && b <= 31) ||
            (a == 192 && b == 168))) {
      return false;
    }
    return true;
  }

  /// The longest `A.B.C.D/prefix` spelling: four 3-digit octets, a separator,
  /// and a prefix of `32`.
  static const int ipv4CidrMaxLength = 18;

  /// Parses one allowed IPv4 route into its canonical `A.B.C.D/prefix` string,
  /// or null if it is not a well-formed CIDR block.
  ///
  /// Accepts `10.8.1.0/24` and a bare `10.8.1.2` (a `/32`), rejecting a prefix
  /// outside 0..32 and any octet outside 0..255. The iOS/macOS packet-tunnel
  /// providers widen every accepted entry into a `NEIPv4Settings` included
  /// route; a provider that cannot parse a prefix may widen to the full default
  /// route and silently capture traffic that was never meant to enter the
  /// tunnel, so no malformed entry may reach them.
  static String? parseIpv4Cidr(dynamic raw) {
    final value = _singleLine(raw, maxLength: ipv4CidrMaxLength);
    if (value.isEmpty) return null;
    final separator = value.lastIndexOf('/');
    final addressPart =
        separator < 0 ? value : value.substring(0, separator);
    final prefixPart =
        separator < 0 ? null : value.substring(separator + 1);
    if (separator >= 0 &&
        (prefixPart == null ||
            prefixPart.isEmpty ||
            !RegExp(r'^\d{1,2}$').hasMatch(prefixPart))) {
      return null;
    }
    final octets = addressPart.split('.');
    if (octets.length != 4) return null;
    final ints = <int>[];
    for (final octet in octets) {
      if (octet.isEmpty || !RegExp(r'^\d{1,3}$').hasMatch(octet)) return null;
      final parsed = int.tryParse(octet);
      if (parsed == null || parsed < 0 || parsed > 255) return null;
      ints.add(parsed);
    }
    final prefix = prefixPart == null ? 32 : int.tryParse(prefixPart);
    if (prefix == null || prefix < 0 || prefix > 32) return null;
    return '${ints.join('.')}/$prefix';
  }

  /// Whether a single allowed IPv4 route entry may be handed to a provider.
  ///
  /// A well-formed CIDR block passes, except a `/0`, which is the default route
  /// covering every IPv4 destination. The iOS/macOS providers never install a
  /// literal `0.0.0.0/0` from a config request (they use the `/1` pair or the
  /// shipped full-tunnel posture) and a config that names one is asking to
  /// capture the whole default route -- the exact malformed shape the gate
  /// exists to stop leaking.
  static bool isAllowedIpv4Route(dynamic raw) {
    final cidr = parseIpv4Cidr(raw);
    if (cidr == null) return false;
    final prefix = int.parse(cidr.substring(cidr.indexOf('/') + 1));
    return prefix > 0;
  }

  /// Whether `config['allowedIPv4Routes']`, when present, is a list of usable
  /// non-default IPv4 routes. Absent or empty is allowed (the provider applies
  /// its own default posture); a non-list or any entry that is not an allowed
  /// route is a refusal.
  static bool isAllowedIpv4Routes(dynamic raw) {
    if (raw == null) return true;
    if (raw is! List) return false;
    for (final entry in raw) {
      if (!isAllowedIpv4Route(entry)) return false;
    }
    return true;
  }

  /// The IPv6 counterpart of the public rule in [isIpv4]. Only global unicast
  /// (2000::/3) passes, which refuses the unspecified and loopback addresses
  /// in every spelling (`0:0:0:0:0:0:0:0` keeps that spelling in
  /// [InternetAddress.address], so comparing it with `::` missed it),
  /// unique-local fc00::/7, link-local fe80::/10, multicast and the
  /// IPv4-compatible and NAT64 forms. An IPv4-mapped address (::ffff:0:0/96)
  /// and a 6to4 address (2002::/16) carry an IPv4 address, which must itself
  /// pass the public IPv4 rule: `::ffff:192.168.1.1` is not a public host.
  static bool isPublicIpv6(InternetAddress address) {
    if (address.type != InternetAddressType.IPv6) return false;
    final bytes = address.rawAddress;
    if (bytes.length != 16) return false;
    String embeddedIpv4(int at) =>
        '${bytes[at]}.${bytes[at + 1]}.${bytes[at + 2]}.${bytes[at + 3]}';
    if (bytes.take(10).every((b) => b == 0) &&
        bytes[10] == 0xff &&
        bytes[11] == 0xff) {
      return isIpv4(embeddedIpv4(12), allowPrivate: false);
    }
    if ((bytes[0] & 0xe0) != 0x20) return false;
    if (bytes[0] == 0x20 && bytes[1] == 0x02) {
      return isIpv4(embeddedIpv4(2), allowPrivate: false);
    }
    return true;
  }

  static bool isPublicHost(dynamic raw) {
    final value = _singleLine(raw, maxLength: 253).toLowerCase();
    if (value.isEmpty || value.contains('%')) return false;
    final address = InternetAddress.tryParse(value);
    if (address != null) {
      if (address.type == InternetAddressType.IPv4) {
        return isIpv4(value, allowPrivate: false);
      }
      return isPublicIpv6(address);
    }
    if (!RegExp(r'^[a-z0-9.-]+$').hasMatch(value) || !value.contains('.')) {
      return false;
    }
    final labels = value.split('.');
    // A numeric last label is not a DNS name (RFC 3696 section 2), but
    // getaddrinfo reads such a "hostname" as an IPv4 number in inet_aton form
    // (0x7f.0.0.1 and 127.1 are 127.0.0.1 on glibc and Darwin), which would
    // skip the private and loopback refusals of the literal branch above.
    if (RegExp(r'^(0x[0-9a-f]*|[0-9]+)$').hasMatch(labels.last)) return false;
    return labels.every((label) =>
        label.isNotEmpty &&
        label.length <= 63 &&
        !label.startsWith('-') &&
        !label.endsWith('-'));
  }

  static bool isEndpoint(dynamic raw) {
    final value = _singleLine(raw, maxLength: 320);
    if (value.isEmpty) return false;
    if (value.startsWith('[')) {
      final match = RegExp(r'^\[([^\]]+)\]:(\d{1,5})$').firstMatch(value);
      if (match == null || !isPort(match.group(2))) return false;
      // The zone-ID refusal isPublicHost applies: dart:io accepts
      // `2606:4700:4700::1111%eth0` (and a bare `%`) with a global rawAddress.
      final host = match.group(1)!;
      if (host.contains('%')) return false;
      final address = InternetAddress.tryParse(host);
      return address != null && isPublicIpv6(address);
    }
    final separator = value.lastIndexOf(':');
    if (separator <= 0 || separator == value.length - 1) return false;
    return isPublicHost(value.substring(0, separator)) &&
        isPort(value.substring(separator + 1));
  }

  static bool isPort(dynamic raw) {
    final value = int.tryParse((raw ?? '').toString());
    return value != null && value >= 1 && value <= 65535;
  }

  static int? _boundedNonNegativeInt(
    dynamic raw, {
    required int max,
    required int maxDigits,
  }) {
    final value = _singleLine(raw, maxLength: maxDigits);
    if (!RegExp(r'^\d+$').hasMatch(value)) return null;
    final parsed = int.tryParse(value);
    return parsed != null && parsed <= max ? parsed : null;
  }

  static bool isUuid(dynamic raw) {
    final value = _singleLine(raw, maxLength: 36);
    if (!RegExp(
      r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
    ).hasMatch(value)) {
      return false;
    }
    return value.replaceAll('-', '').contains(RegExp(r'[1-9a-fA-F]'));
  }

  static bool isPath(dynamic raw) {
    final value = _singleLine(raw, maxLength: 256);
    return value.startsWith('/') &&
        !value.contains('..') &&
        !value.contains('?') &&
        !value.contains('#') &&
        !RegExp(r'\s').hasMatch(value);
  }

  static String _singleLine(dynamic raw, {required int maxLength}) {
    final value = (raw ?? '').toString().trim();
    if (value.isEmpty || value.length > maxLength) return '';
    if (value.contains('\r') ||
        value.contains('\n') ||
        value.contains('\u0000')) {
      return '';
    }
    return value;
  }

  static bool _boolValue(dynamic value) {
    if (value is bool) return value;
    final normalized = (value ?? '').toString().trim().toLowerCase();
    return normalized == 'true' || normalized == '1' || normalized == 'yes';
  }
}
