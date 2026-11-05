import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Behavioural tests for the `winn/3` dispatch policy.
///
/// The single most important property in this file is the ANTI-DOWNGRADE one:
/// a `winn/3` config must never end up starting the classical `winn/1`
/// AmneziaWG path. The gateway negotiated a Winn Protocol v3 session; a client
/// that quietly speaks v1 instead has downgraded it without telling anyone.
///
/// That property is enforced structurally as well as by assertion:
/// [WinnStartDecision] has no representation for "fall back to AmneziaWG" at
/// all. A refusal is `supported == false` with an empty section, and the only
/// correct response to it is to fail the connection.
///
/// The companion source-level guard is
/// `test/winn_protocol_refusal_guard_test.dart`, which asserts that the two
/// call sites in `lib/main.dart` actually honour a refusal by returning/
/// throwing rather than by falling through.

/// A served config that CAN start Winn on Linux. Everything else in this
/// file is this map with one thing broken.
Map<String, dynamic> validWinn3Config() => <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{},
      'node_slug': 'lab-alpha',
      'server_endpoint': '203.0.113.7:51820',
      'client_ip': '10.8.1.3',
      'mtu': 1280,
      'dns': '10.8.1.1',
      'stealth_active': false,
      'obfuscation': <String, dynamic>{
        'H1': 11,
        'H2': 22,
        'H3': 33,
        'H4': 44,
      },
    };

/// [validWinn3Config] placed on the stacked stealth chain: the explicit
/// hub-served opt-in plus the v1 stealth leg it stacks in front of.
Map<String, dynamic> stealthChainConfig() => validWinn3Config()
  ..[kWinnOuterTransportKey] = kWinnOuterTransportStealthChain
  ..['stealth_active'] = true
  ..['xray'] = <String, dynamic>{
    'enabled': true,
    'uuid': '00000000-0000-4000-8000-000000000000',
    'host': 'stealth.example',
    'port': 443,
    'server_name': 'stealth.example',
    'path': '/wins-stealth-tunnel',
    'security': 'tls',
    'local_port': 42110,
    'remote_awg_host': '127.0.0.1',
    'remote_awg_port': 9110,
  };

/// Parses an INI `[winn]` section the way
/// `android/.../WinnEngineConfig.kt` parses it: keys lowercased, values
/// trimmed, first `=` splits.
Map<String, String> parseWinnSection(String iniSection) {
  final out = <String, String>{};
  var inSection = false;
  for (final line in iniSection.split('\n')) {
    final trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      inSection =
          trimmed.substring(1, trimmed.length - 1).toLowerCase().trim() ==
              kWinnConfigSection;
      continue;
    }
    if (!inSection || !trimmed.contains('=')) continue;
    final split = trimmed.indexOf('=');
    out[trimmed.substring(0, split).trim().toLowerCase()] =
        trimmed.substring(split + 1).trim();
  }
  return out;
}

/// An independent re-implementation of `WinnEngineConfig.from`'s ACCEPTANCE
/// rules, deliberately written from the Kotlin rather than from the Dart that
/// produces the section. Returns null when the Kotlin would have thrown, so a
/// Dart-side change that starts emitting something the native host rejects
/// fails here instead of at connect time on a device.
String? kotlinWinnConfigRejectionReason(
  Map<String, String> section, {
  required int mtu,
}) {
  // Spelled out rather than imported from lib/, on purpose: a mirror that
  // reuses the implementation it is checking cannot catch that implementation
  // being wrong. These are read off WinnEngineConfig.kt by hand.
  const reserved = <String>{
    'enabled',
    'endpoint',
    'session_id',
    'max_datagram',
    'carrier',
    // WinnCarrierProfile.CARRIER_KEYS, folded into RESERVED_KEYS. Consumed by
    // the host into the carrier profile document, never forwarded into
    // datapath.Config.
    'masque_template',
    'public_target',
    'server_name',
    'suite',
    'controller_id',
    'device_id',
    'device_pq_algorithm',
    'manifest_digest',
    'sequence_epoch',
    'max_inner_datagram',
    'privacy_profile',
  };
  // WinnEngineConfig.SUPPORTED_CARRIERS. http2-stream is absent because its
  // dialer takes a connected TCP socket the Android host does not open.
  const supportedCarriers = <String>{'direct-awg', 'http3-connect-udp'};
  // WinnEngineConfig.REQUIRED_CARRIER_KEYS.
  const requiredCarrierKeys = <String>[
    'masque_template',
    'public_target',
    'server_name',
    'suite',
    'controller_id',
    'device_id',
    'device_pq_algorithm',
    'manifest_digest',
  ];
  const headerKeys = <String>['h1', 'h2', 'h3', 'h4'];
  // Optional and independent of h1..h4, and NOT all-or-none: the shipping
  // profile sets S4 = 0 while S1..S3 are nonzero, so requiring all four would
  // refuse this app's own configuration. Mirrors PADDING_KEYS in
  // WinnEngineConfig.kt.
  const paddingKeys = <String>['s1', 's2', 's3', 's4'];

  final enabled = (section['enabled'] ?? '').toLowerCase();
  if (!<String>['true', '1', 'yes', 'y'].contains(enabled)) {
    return 'Winn section is not enabled';
  }
  if (mtu < 576 || mtu > 9000) return 'Winn MTU is out of range';

  if (!isWinnIpLiteralEndpoint(section['endpoint'] ?? '')) {
    return 'Winn endpoint must be an IP literal with a port';
  }

  final requested = section.containsKey('max_datagram')
      ? int.tryParse(section['max_datagram']!)
      : kWinnMaxDatagramCeiling;
  if (requested == null ||
      requested < kWinnMinDatagram ||
      requested > kWinnMaxDatagramCeiling) {
    return 'Winn max_datagram is out of range';
  }

  if ((section['session_id'] ?? '').length > kWinnMaxSessionIdBytes) {
    return 'Winn session_id exceeds 128 bytes';
  }

  for (final key in section.keys) {
    if (key.isEmpty) continue;
    if (reserved.contains(key) ||
        headerKeys.contains(key) ||
        paddingKeys.contains(key)) {
      continue;
    }
    return "Winn section carries '$key', which the engine rejects";
  }

  final carrier = (section['carrier'] ?? '').trim().toLowerCase();
  final resolvedCarrier = carrier.isEmpty ? 'direct-awg' : carrier;
  if (!supportedCarriers.contains(resolvedCarrier)) {
    return "Winn carrier '$resolvedCarrier' is not one this engine can build";
  }
  if (resolvedCarrier != 'direct-awg') {
    final missing = requiredCarrierKeys
        .where((k) => (section[k] ?? '').trim().isEmpty)
        .toList();
    if (missing.isNotEmpty) {
      return "Winn carrier '$resolvedCarrier' needs ${missing.join(', ')}";
    }
  }

  final present =
      headerKeys.where((k) => (section[k] ?? '').trim().isNotEmpty).toList();
  if (present.isEmpty) return null;
  if (present.length != headerKeys.length) {
    return 'Winn header types must be all of h1..h4 or none';
  }
  final values = <int>[];
  for (final key in paddingKeys) {
    final raw = (section[key] ?? '').trim();
    if (raw.isEmpty) continue;
    final value = int.tryParse(raw);
    if (value == null || value < 0 || value > 0xFFFF) {
      return 'Winn padding size \'$key\' is not a 16-bit unsigned value';
    }
  }

  for (final key in headerKeys) {
    final parsed = int.tryParse(section[key]!.trim());
    if (parsed == null || parsed < 0 || parsed > 0xFFFFFFFF) {
      return "Winn header type '$key' is not a 32-bit unsigned value";
    }
    values.add(parsed);
  }
  if (values.toSet().length != 4) {
    return 'Winn header types h1..h4 must be pairwise distinct';
  }
  return null;
}

/// The user-facing name of a `Platform.operatingSystem` value.
///
/// Deliberately a second, independent copy of the mapping in
/// `lib/winn_protocol_dispatch.dart` rather than an export of it, in the same
/// spirit as [kotlinWinnConfigRejectionReason] above: a test that reuses the
/// implementation it is checking cannot catch that implementation being wrong.
String _platformDisplayNameForTest(String platform) {
  switch (platform) {
    case 'android':
      return 'Android';
    case 'ios':
      return 'iOS';
    case 'macos':
      return 'macOS';
    case 'windows':
      return 'Windows';
    case 'linux':
      return 'Linux';
    default:
      return platform;
  }
}

// ===========================================================================
// RUN-EVIDENCE CONTENT CHECKING
// Added 2026-08-12 by lane v3_promotion_substrate. Nothing below flips, or
// can flip, a `kWinnHostCapabilities` entry: the flip stays owner-reserved
// (OWNER_DELEGATED_DECISIONS_20260807.md section 8 item L). This is the ruler,
// not the measurement.
//
// WHY IT EXISTS. This table has been wrongly promoted TWICE on evidence that a
// test calling only `existsSync` could not tell from the real thing:
//
//  * a JVM double, with no device execution behind it at all;
//  * a same-handset LOOPBACK HARNESS that passed for four days --
//    `package=org.winsvpn.devicecheck`, `"gateway_endpoint":"127.0.0.1:46921"`,
//    tx_bytes 706 / rx_bytes 172 across an 8-second window, zero rekeys
//    (.winn_platform_progress/evidence/
//     devicecheck_20260804T155556Z_motorola_edge_plus_2023.log);
//  * and a third, genuine run whose proof artefacts its own lane's teardown
//    deleted, so it is on no disk anyone can read.
//
// So the threat model for this gate INCLUDES THE AGENT PRESENTING THE
// EVIDENCE. Every check below is written so the cheapest way to satisfy it is
// to have actually run the session.
//
// STATE LIES; ONLY OUTPUT COUNTS. The live example is iOS on 2026-08-11: the
// far end reached `tun.StateCarrying` and reported `"carrying":1` on 67
// samples, while `"rx_packets"` stayed 0 on ALL 1,751 sampled lines and
// `rx_dropped_invalid` reached 50 (winn3_ios_20260811T044620Z_gateway_far_end_
// posture.jsonl). A criteria-checker that read "state == carrying" would have
// promoted it. [winnRunEvidenceDefects] reads DELIVERED COUNTERS and never
// reads state as evidence of carriage.
//
// MACHINE-READABLE OR IT DOES NOT COUNT. Every numeric claim is read out of a
// PARSED JSON object, never out of prose. That is not fussiness: the best
// artefact in the corpus, winn3_linux_20260808_exact_4MiB_fullset.txt, has
// `"digest_match_full_set": true` inside its JSON block AND the words
// "digest_match_full_set false" twice in its narrative, where it is honestly
// describing a DIFFERENT, lossier run. A regex over raw text reads that file
// as a failure. A JSON parse reads it correctly.
// ===========================================================================

/// Criterion 5's floor -- ">=4 MiB each direction" -- in bytes.
///
/// Canonical criteria: `docs/handoff/OWNER_DELEGATED_DECISIONS_20260807.md`,
/// the seven-row table (criterion 8 is iOS-only).
const int kWinnEvidenceByteFloorBytes = 4 * 1024 * 1024;

/// The bundle format tag [winnEvidenceBundleShapeDefects] understands.
const String kWinnEvidenceBundleFormat = 'winn3-evidence-bundle/1';

/// One reason a run-evidence artefact does not meet the promotion bar.
///
/// A defect is a stable [code] plus the VALUE that produced it, so a failure
/// message says what was found rather than that something was wrong.
class WinnEvidenceDefect {
  const WinnEvidenceDefect(this.code, this.detail);

  /// A stable snake_case identifier, safe to assert on.
  final String code;

  /// What was actually found, including the offending value.
  final String detail;

  @override
  String toString() => '$code -- $detail';
}

/// Every balanced `{...}` span in [text] that parses as a JSON object.
///
/// Deliberately tolerant of surrounding prose: the corpus is logcat lines with
/// an embedded status object, pretty-printed blocks inside a narrative, and
/// JSONL. Spans that do not parse are prose that merely contains braces and
/// are dropped, which is the point -- a claim only counts if it is machine
/// readable.
List<Map<String, Object?>> winnEvidenceJsonObjects(String text) {
  final out = <Map<String, Object?>>[];
  var depth = 0;
  var start = -1;
  var inString = false;
  var escaped = false;
  for (var i = 0; i < text.length; i++) {
    final c = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (c == r'\') {
        escaped = true;
      } else if (c == '"') {
        inString = false;
      }
      continue;
    }
    if (c == '"') {
      inString = true;
      continue;
    }
    if (c == '{') {
      if (depth == 0) start = i;
      depth++;
    } else if (c == '}' && depth > 0) {
      depth--;
      if (depth == 0 && start >= 0) {
        try {
          final decoded = jsonDecode(text.substring(start, i + 1));
          if (decoded is Map) out.add(decoded.cast<String, Object?>());
        } on FormatException {
          // Prose that happens to be brace-balanced. Not a claim.
        }
        start = -1;
      }
    }
  }
  return out;
}

/// Flattens [node] into (leaf key, leaf value) pairs. A list inherits the key
/// of the field that holds it, so `"session_states":["established"]` yields
/// `('session_states', 'established')`.
void _winnFlatten(
  Object? node,
  String key,
  List<MapEntry<String, Object?>> into,
) {
  if (node is Map) {
    node.forEach((k, v) => _winnFlatten(v, '$k', into));
  } else if (node is List) {
    for (final v in node) {
      _winnFlatten(v, key, into);
    }
  } else {
    into.add(MapEntry(key, node));
  }
}

/// True when [raw] names a far end that is on the same host as the client:
/// IPv4 loopback, IPv6 loopback, `localhost`, or a wildcard bind.
///
/// A wildcard (`0.0.0.0`, `::`) counts because nothing dials it -- an artefact
/// reporting one as the FAR END is reporting an in-process peer.
bool winnEvidenceEndpointIsLoopback(String raw) {
  final v = raw.trim().toLowerCase();
  if (v.isEmpty) return false;
  if (v.contains('localhost')) return true;
  if (v.contains('[::1]')) return true;
  var host = v;
  final close = host.indexOf(']');
  if (host.startsWith('[') && close > 1) {
    host = host.substring(1, close);
  } else {
    final colon = host.lastIndexOf(':');
    // Only strip a `:port` when what precedes it holds no other colon, so a
    // bare IPv6 literal is never truncated into something unrecognisable.
    if (colon > 0 && !host.substring(0, colon).contains(':')) {
      host = host.substring(0, colon);
    }
  }
  if (host == '::1' || host == '::' || host == '0.0.0.0') return true;
  final v4 = RegExp(r'^(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}$').firstMatch(host);
  return v4 != null && v4.group(1) == '127';
}

/// True when [token] is a dotted identifier naming a debug, test or
/// device-check variant rather than a shipping build.
///
/// Segment-exact rather than substring: `winn_protocol_dispatch_test.dart`
/// must NOT trip this, while `org.winsvpn.app.debug`,
/// `PacketTunnel.debug.dylib` and `group.org.winsvpn.devicecheck` all must.
bool winnEvidenceIdentifierIsNonShipping(String token) {
  for (final segment in token.toLowerCase().split('.')) {
    if (segment == 'debug' || segment == 'test') return true;
    if (segment.contains('devicecheck')) return true;
  }
  return false;
}

/// JSON keys whose value is the FAR END of the session.
///
/// `local_endpoint` and the AmneziaWG `[Peer] Endpoint` line are deliberately
/// NOT here. In relay-era topologies the peer Endpoint is legitimately
/// rewritten to the loopback seam -- `Endpoint = 127.0.0.1:35209` appears in
/// the best artefact in the corpus for exactly that reason -- so treating it
/// as the far end would make the strongest evidence in the repo fail. The
/// winn far end is `gateway_endpoint`; a gateway-side record's `endpoint` is
/// the client as the gateway saw it, and loopback THERE is the same-pid tell.
const Set<String> kWinnEvidenceFarEndKeys = <String>{
  'gateway_endpoint',
  'endpoint',
  'peer_endpoint',
  'observed_peer_endpoint',
  'far_end_endpoint',
};

/// Counters for inner payload SENT. Criterion 5 is measured on these.
const Set<String> kWinnEvidenceTxByteKeys = <String>{
  'tx_bytes',
  'bytes_sent',
  'inner_tx_bytes',
  'udp_payload_bytes_sent',
};

/// Counters for inner payload RECEIVED.
const Set<String> kWinnEvidenceRxByteKeys = <String>{
  'rx_bytes',
  'bytes_received',
  'inner_rx_bytes',
  'udp_payload_bytes_received',
};

/// Counters of inner packets actually DELIVERED, as opposed to offered,
/// admitted, established or carrying. This set is the answer to "state lies".
const Set<String> kWinnEvidenceDeliveredKeys = <String>{
  'rx_packets',
  'rx_datagrams_verified',
  'rx_transport_payload_datagrams',
  'udp_datagrams_echoed',
  'inner_packets_delivered',
};

/// Every counter criterion 5's "ALL rejection counters zero" covers, plus the
/// payload-loss counters a full-set digest already implies.
const Set<String> kWinnEvidenceRejectionKeys = <String>{
  'tx_rejected',
  'rx_dropped',
  'rx_oversize',
  'rx_foreign_sender',
  'rx_corrupt',
  'rx_duplicate',
  'missing_count',
  'rx_dropped_invalid',
  'rx_dropped_closed',
  'tx_dropped_invalid',
  'tx_dropped_closed',
  'session_build_failures',
  'refused_datagrams',
  'stranger_datagrams',
  'send_failed',
  'recv_failed',
  'pipe_recv_errors',
  'pipe_send_errors',
  'dropped_not_echoable',
};

/// Values that mean a state machine SAID it was carrying. Never evidence.
const Set<String> kWinnEvidenceCarryingMarkers = <String>{
  'carrying',
  'established',
  'statecarrying',
};

/// Every way [bundle] fails the promotion bar, or an empty list.
///
/// [bundle] maps an artefact label (normally its committed path) to that
/// artefact's full text. It is a BUNDLE and not a single file because the
/// client is the thing under test: client counters alone cannot establish that
/// anything left the device, so the gateway-side artefact is checked in the
/// same pass and its counters are pooled with the client's.
///
/// The checks, each traceable to a criterion or to a specific past failure:
///
///  * `no_machine_readable_counters` -- nothing in the bundle parsed as JSON,
///    so every number in it is prose. This is what
///    winn3_ios_20260811T044620Z_first_standalone_v3_carriage.txt is on its
///    own: a careful, honest narrative with zero checkable claims.
///  * `loopback_far_end` -- criterion 3. The devicecheck defect.
///  * `byte_floor_not_met` -- criterion 5's >=4 MiB, BOTH directions.
///  * `digest_match_full_set_absent` / `_false` -- criterion 5's digest match,
///    over the FULL ordered set rather than only over what came back.
///  * `non_shipping_build_identifier` -- criterion 1. `.debug`, `.test`,
///    `devicecheck`.
///  * `delivered_counter_zero` / `_absent` -- the iOS trap.
///  * `rejection_counter_nonzero` -- criterion 5's "all rejection counters
///    zero".
///
/// It does NOT check criteria 2, 4, 6, 7 or 8 (exclusion installed, handshake
/// confirmed at both ends, duration and rekeys, lifecycle, iOS memory). Those
/// need bundle-level structure rather than counter scanning; see
/// [winnEvidenceBundlePromotionDefects], which is where a two-sided bundle
/// declares them. An empty result here means "nothing disqualifying was found
/// in the counters", never "promotion is earned".
List<WinnEvidenceDefect> winnRunEvidenceDefects(Map<String, String> bundle) {
  final defects = <WinnEvidenceDefect>[];
  final pairs = <MapEntry<String, Object?>>[];
  var objectCount = 0;

  for (final artefact in bundle.entries) {
    final objects = winnEvidenceJsonObjects(artefact.value);
    objectCount += objects.length;
    for (final object in objects) {
      _winnFlatten(object, '', pairs);
    }
    // Far end, from parsed JSON only.
    for (final object in objects) {
      final flat = <MapEntry<String, Object?>>[];
      _winnFlatten(object, '', flat);
      for (final kv in flat) {
        if (!kWinnEvidenceFarEndKeys.contains(kv.key)) continue;
        final value = kv.value;
        if (value is! String) continue;
        if (winnEvidenceEndpointIsLoopback(value)) {
          defects.add(WinnEvidenceDefect(
            'loopback_far_end',
            '${artefact.key}: "${kv.key}":"$value" is on the same host as '
                'the client. Criterion 3 requires a real remote gateway '
                'across a physical hop, never loopback or in-process.',
          ));
        }
      }
    }
    // Far end, from a textual `gateway_endpoint` that never reached JSON.
    for (final m in RegExp(r'gateway_endpoint\s*[=:]\s*"?([^"\s,}]+)')
        .allMatches(artefact.value)) {
      final value = m.group(1)!;
      if (winnEvidenceEndpointIsLoopback(value)) {
        defects.add(WinnEvidenceDefect(
          'loopback_far_end',
          '${artefact.key}: gateway_endpoint $value is loopback.',
        ));
      }
    }
    // Non-shipping build identifiers.
    final seen = <String>{};
    for (final m in RegExp(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+')
        .allMatches(artefact.value)) {
      final token = m.group(0)!;
      if (!winnEvidenceIdentifierIsNonShipping(token)) continue;
      if (!seen.add(token.toLowerCase())) continue;
      defects.add(WinnEvidenceDefect(
        'non_shipping_build_identifier',
        '${artefact.key}: names "$token". Criterion 1 is the SHIPPING path; '
            'a .debug/.test variant or a devicecheck harness is not it.',
      ));
    }
  }

  if (objectCount == 0) {
    defects.add(const WinnEvidenceDefect(
      'no_machine_readable_counters',
      'no artefact in the bundle contained a parseable JSON object, so every '
          'number it claims is prose. A narrative is not a counter.',
    ));
  }

  int? maxOf(Set<String> keys) {
    int? best;
    for (final kv in pairs) {
      if (!keys.contains(kv.key)) continue;
      final value = kv.value;
      if (value is! int) continue;
      if (best == null || value > best) best = value;
    }
    return best;
  }

  final txBytes = maxOf(kWinnEvidenceTxByteKeys);
  final rxBytes = maxOf(kWinnEvidenceRxByteKeys);
  if (txBytes == null || txBytes < kWinnEvidenceByteFloorBytes) {
    defects.add(WinnEvidenceDefect(
      'byte_floor_not_met',
      'sent: ${txBytes ?? "no counter found"} bytes, floor '
          '$kWinnEvidenceByteFloorBytes (criterion 5, >=4 MiB each '
          'direction).',
    ));
  }
  if (rxBytes == null || rxBytes < kWinnEvidenceByteFloorBytes) {
    defects.add(WinnEvidenceDefect(
      'byte_floor_not_met',
      'received: ${rxBytes ?? "no counter found"} bytes, floor '
          '$kWinnEvidenceByteFloorBytes (criterion 5, >=4 MiB each '
          'direction).',
    ));
  }

  final fullSet = <bool>[
    for (final kv in pairs)
      if (kv.key == 'digest_match_full_set' && kv.value is bool)
        kv.value! as bool,
  ];
  if (fullSet.isEmpty) {
    defects.add(const WinnEvidenceDefect(
      'digest_match_full_set_absent',
      'no artefact asserts digest_match_full_set in machine-readable form. '
          'A digest over only the datagrams that came back cannot show that '
          'what was sent equals what was received; criterion 5 needs the '
          'full ordered set.',
    ));
  } else if (fullSet.contains(false)) {
    defects.add(const WinnEvidenceDefect(
      'digest_match_full_set_false',
      'digest_match_full_set is false: sent != received over the full '
          'ordered set.',
    ));
  }

  final markers = <String>{
    for (final kv in pairs)
      if (kv.value is String &&
          kWinnEvidenceCarryingMarkers
              .contains((kv.value! as String).toLowerCase()))
        '${kv.key}=${kv.value}',
    for (final kv in pairs)
      if (kv.key == 'carrying' && kv.value is int && (kv.value! as int) > 0)
        'carrying=${kv.value}',
  };
  final delivered = maxOf(kWinnEvidenceDeliveredKeys);
  if (delivered == null) {
    defects.add(const WinnEvidenceDefect(
      'delivered_counter_absent',
      'the bundle reports no delivered-packet counter at all '
          '(${'rx_packets, rx_datagrams_verified, '
              'rx_transport_payload_datagrams, udp_datagrams_echoed, '
              'inner_packets_delivered'}), so nothing in it shows that a '
          'single inner packet arrived.',
    ));
  } else if (delivered <= 0) {
    defects.add(WinnEvidenceDefect(
      'delivered_counter_zero',
      'every delivered-packet counter is 0'
          '${markers.isEmpty ? '' : ', while state reported '
              '${markers.join(", ")}'}. State is not carriage: on '
          '2026-08-11 iOS reached StateCarrying with rx_packets 0 on all '
          '1,751 samples.',
    ));
  }

  for (final key in kWinnEvidenceRejectionKeys) {
    final worst = maxOf(<String>{key});
    if (worst != null && worst > 0) {
      defects.add(WinnEvidenceDefect(
        'rejection_counter_nonzero',
        '$key reached $worst. Criterion 5 requires ALL rejection counters '
            'zero.',
      ));
    }
  }

  defects.sort((a, b) => a.code.compareTo(b.code));
  return defects;
}

/// [winnRunEvidenceDefects] over committed files, read from disk.
List<WinnEvidenceDefect> winnRunEvidenceDefectsForPaths(List<String> paths) =>
    winnRunEvidenceDefects(<String, String>{
      for (final path in paths)
        if (File(path).existsSync()) path: File(path).readAsStringSync(),
    });

// ---------------------------------------------------------------------------
// THE TWO-SIDED BUNDLE
// ---------------------------------------------------------------------------

/// A [Sink] that keeps the one [Digest] a chunked SHA-256 emits.
class _WinnDigestSink implements Sink<Digest> {
  Digest? value;

  @override
  void add(Digest data) => value = data;

  @override
  void close() {}
}

/// The normative inner payload of datagram [index], derived from [seed].
///
/// `datagram(i)` is the first [payloadBytes] bytes of
/// `SHA256(seed || u32be(i) || u32be(0)) || SHA256(seed || u32be(i) ||
/// u32be(1)) || ...`.
///
/// The point of a DERIVED payload is that the session's digest stops being a
/// number an agent writes down and becomes a number a verifier computes for
/// itself from `(payload_seed_hex, payload_bytes_each, tx_datagrams)`. A
/// second family re-deriving it never has to trust the first family's
/// arithmetic.
List<int> winnEvidencePayloadDatagram(
  List<int> seed,
  int index,
  int payloadBytes,
) {
  final out = <int>[];
  var block = 0;
  while (out.length < payloadBytes) {
    final input = <int>[
      ...seed,
      (index >> 24) & 0xFF,
      (index >> 16) & 0xFF,
      (index >> 8) & 0xFF,
      index & 0xFF,
      (block >> 24) & 0xFF,
      (block >> 16) & 0xFF,
      (block >> 8) & 0xFF,
      block & 0xFF,
    ];
    out.addAll(sha256.convert(input).bytes);
    block++;
  }
  return out.sublist(0, payloadBytes);
}

/// SHA-256, lowercase hex, over datagrams `0 .. datagramCount-1` in order.
String winnEvidencePayloadDigestHex(
  List<int> seed,
  int payloadBytes,
  int datagramCount,
) {
  final sink = _WinnDigestSink();
  final input = sha256.startChunkedConversion(sink);
  for (var i = 0; i < datagramCount; i++) {
    input.add(winnEvidencePayloadDatagram(seed, i, payloadBytes));
  }
  input.close();
  return sink.value!.toString();
}

List<int>? _winnHexBytes(Object? value, int expectedBytes) {
  if (value is! String) return null;
  if (value.length != expectedBytes * 2) return null;
  final out = <int>[];
  for (var i = 0; i < value.length; i += 2) {
    final b = int.tryParse(value.substring(i, i + 2), radix: 16);
    if (b == null) return null;
    out.add(b);
  }
  return out;
}

Object? _winnAt(Map<String, Object?> root, String path) {
  Object? node = root;
  for (final segment in path.split('.')) {
    if (node is! Map) return null;
    node = node[segment];
  }
  return node;
}

/// Structural defects in a `winn3-evidence-bundle/1` manifest, or an empty
/// list. Shape and INTERNAL CONSISTENCY only -- this says nothing about
/// whether the session was good enough to promote on; that is
/// [winnEvidenceBundlePromotionDefects].
///
/// The four joins below are what make the two sides correlatable MECHANICALLY
/// rather than by a human comparing timestamps:
///
///  * `join_digest` -- the client's digest of what it sent, the client's
///    digest of what came back, and the GATEWAY's independently computed
///    digest of what it received must all be one value, and a verifier
///    re-derives that value from `payload_seed_hex` rather than reading it.
///  * `join_socket` -- the port the client bound for its outer socket must be
///    the port the gateway observed its peer on. Two logs, one socket.
///  * `join_volume` -- `inner_tx_bytes == tx_datagrams * payload_bytes_each`,
///    so the byte total is not a free parameter.
///  * `join_link` -- the gateway capture's pcap link type. `LINKTYPE_NULL`
///    (0) and `LINKTYPE_LOOP` (108) are loopback captures and are rejected at
///    the link layer, which is a far harder thing to fake than the absence of
///    the string "127.0.0.1".
List<WinnEvidenceDefect> winnEvidenceBundleShapeDefects(
  Map<String, Object?> manifest,
) {
  final defects = <WinnEvidenceDefect>[];

  void require(String path, bool Function(Object? v) ok, String expected) {
    final value = _winnAt(manifest, path);
    if (value == null) {
      defects
          .add(WinnEvidenceDefect('missing_field', '$path (want $expected)'));
    } else if (!ok(value)) {
      defects.add(WinnEvidenceDefect(
        'bad_field',
        '$path is ${value.runtimeType} "$value" (want $expected)',
      ));
    }
  }

  bool isText(Object? v) => v is String && v.trim().isNotEmpty;
  bool isCount(Object? v) => v is int && v > 0;
  bool isHex32(Object? v) => _winnHexBytes(v, 32) != null;
  bool isList(Object? v) => v is List && v.isNotEmpty;

  require('bundle_format', (v) => v == kWinnEvidenceBundleFormat,
      '"$kWinnEvidenceBundleFormat"');
  require('platform', isText, 'a Platform.operatingSystem value');
  require('session_id', isText, 'the session id the client emitted');
  require('captured_at_utc', isText, 'an ISO-8601 UTC instant');

  require('client.host_id', isText, 'device model plus serial or uname');
  require('client.build.configuration', isText, '"Release"');
  require('client.build.app_id', isText, 'the shipping bundle/package id');
  require('client.build.version', isText, 'version+build');
  require('client.gateway_endpoint', isText, 'the far end, host:port');
  require('client.outer_local_port', isCount, 'the outer socket source port');
  require('client.artifacts', isList, 'client-side artefact filenames');

  require('gateway.host_id', isText, 'uname plus primary MAC of the far end');
  require('gateway.observed_peer_endpoint', isText, 'client as gateway saw it');
  require('gateway.observed_peer_port', isCount, 'peer source port');
  require('gateway.artifacts', isList, 'gateway-side artefact filenames');
  require('gateway.capture.link_type', (v) => v is int, 'a pcap LINKTYPE_*');

  require('correlation.payload_seed_hex', isHex32, '32 bytes of hex');
  require('correlation.payload_bytes_each', isCount, 'bytes per datagram');
  require('correlation.tx_datagrams', isCount, 'datagrams sent');
  require('correlation.inner_tx_bytes', isCount, 'inner bytes sent');
  require('correlation.inner_rx_bytes', isCount, 'inner bytes received');
  require('correlation.digest_sha256_sent_all', isHex32, '32 bytes of hex');
  require('correlation.digest_sha256_returned', isHex32, '32 bytes of hex');
  require('correlation.gateway_udp_payload_sha256', isHex32, '32 hex bytes');
  require('correlation.digest_match_full_set', (v) => v is bool, 'a bool');
  require('correlation.delivered_packets', (v) => v is int, 'an int');
  require('correlation.rejection_counters', (v) => v is Map, 'a counter map');
  require('artifacts_sha256', (v) => v is Map && v.isNotEmpty,
      'filename -> sha256 for every artefact');

  // join_volume
  final each = _winnAt(manifest, 'correlation.payload_bytes_each');
  final count = _winnAt(manifest, 'correlation.tx_datagrams');
  final txBytes = _winnAt(manifest, 'correlation.inner_tx_bytes');
  if (each is int && count is int && txBytes is int) {
    if (txBytes != each * count) {
      defects.add(WinnEvidenceDefect(
        'join_volume_mismatch',
        'inner_tx_bytes $txBytes != tx_datagrams $count * '
            'payload_bytes_each $each (${each * count})',
      ));
    }
  }

  // join_socket
  final clientPort = _winnAt(manifest, 'client.outer_local_port');
  final gatewayPort = _winnAt(manifest, 'gateway.observed_peer_port');
  if (clientPort is int && gatewayPort is int && clientPort != gatewayPort) {
    defects.add(WinnEvidenceDefect(
      'join_socket_mismatch',
      'client.outer_local_port $clientPort != '
          'gateway.observed_peer_port $gatewayPort -- the two artefacts do '
          'not describe one socket',
    ));
  }

  // join_digest
  final sent = _winnAt(manifest, 'correlation.digest_sha256_sent_all');
  final returned = _winnAt(manifest, 'correlation.digest_sha256_returned');
  final farEnd = _winnAt(manifest, 'correlation.gateway_udp_payload_sha256');
  if (sent is String && returned is String && farEnd is String) {
    final distinct = <String>{
      sent.toLowerCase(),
      returned.toLowerCase(),
      farEnd.toLowerCase(),
    };
    if (distinct.length != 1) {
      defects.add(WinnEvidenceDefect(
        'join_digest_mismatch',
        'sent/returned/gateway digests are not one value: '
            '${distinct.join(" != ")}',
      ));
    }
  }

  // join_link
  final linkType = _winnAt(manifest, 'gateway.capture.link_type');
  if (linkType is int && (linkType == 0 || linkType == 108)) {
    defects.add(WinnEvidenceDefect(
      'join_link_loopback_capture',
      'gateway.capture.link_type $linkType is '
          '${linkType == 0 ? "LINKTYPE_NULL" : "LINKTYPE_LOOP"} -- a '
          'loopback capture. Criterion 3 needs a physical hop.',
    ));
  }

  // Every declared artefact has a committed hash, so the bundle cannot cite a
  // file that was never fixed in place. This is the check the 2026-08-08
  // Android run failed by construction: its artefacts were deleted by its own
  // teardown and nothing recorded what they had been.
  final hashes = _winnAt(manifest, 'artifacts_sha256');
  for (final side in const <String>['client.artifacts', 'gateway.artifacts']) {
    final listed = _winnAt(manifest, side);
    if (listed is! List) continue;
    for (final name in listed) {
      if (hashes is! Map || !hashes.containsKey(name)) {
        defects.add(WinnEvidenceDefect(
          'artifact_unhashed',
          '$side names "$name" but artifacts_sha256 has no hash for it',
        ));
      } else if (_winnHexBytes(hashes[name], 32) == null) {
        defects.add(WinnEvidenceDefect(
          'artifact_unhashed',
          'artifacts_sha256["$name"] is not 32 bytes of hex',
        ));
      }
    }
  }

  defects.sort((a, b) => a.code.compareTo(b.code));
  return defects;
}

/// Everything [winnEvidenceBundleShapeDefects] finds, plus every way the
/// session it describes falls short of the promotion bar.
///
/// A bundle that returns an empty list here has cleared the parts of the bar
/// that are checkable from a manifest. It has NOT been promoted: the flip
/// stays owner-reserved, and criteria 4 and 6 (both-ends handshake, duration
/// and rekeys) are declared here rather than proven here.
List<WinnEvidenceDefect> winnEvidenceBundlePromotionDefects(
  Map<String, Object?> manifest,
) {
  final defects = winnEvidenceBundleShapeDefects(manifest);

  // A synthetic manifest must never be mistaken for a session. The marker is
  // checked FIRST and by value, so copying the fixture into the evidence
  // directory is a loud failure rather than a quiet promotion.
  final synthetic = _winnAt(manifest, 'synthetic');
  final sessionId = _winnAt(manifest, 'session_id');
  if (synthetic == true ||
      (sessionId is String && sessionId.toUpperCase().contains('SYNTHETIC'))) {
    defects.add(const WinnEvidenceDefect(
      'synthetic_bundle_marker',
      'this manifest is a schema fixture, not a session. No run produced it.',
    ));
  }

  for (final path in const <String>[
    'client.gateway_endpoint',
    'gateway.observed_peer_endpoint',
  ]) {
    final value = _winnAt(manifest, path);
    if (value is String && winnEvidenceEndpointIsLoopback(value)) {
      defects.add(WinnEvidenceDefect(
        'loopback_far_end',
        '$path is "$value" (criterion 3)',
      ));
    }
  }

  final clientHost = _winnAt(manifest, 'client.host_id');
  final gatewayHost = _winnAt(manifest, 'gateway.host_id');
  if (clientHost is String && clientHost == gatewayHost) {
    defects.add(WinnEvidenceDefect(
      'same_host_client_and_gateway',
      'client.host_id and gateway.host_id are both "$clientHost" -- one '
          'machine is not a physical hop (criterion 3)',
    ));
  }

  final configuration = _winnAt(manifest, 'client.build.configuration');
  if (configuration is String && configuration.toLowerCase() != 'release') {
    defects.add(WinnEvidenceDefect(
      'build_not_release',
      'client.build.configuration is "$configuration"; criterion 1 is a '
          'signed release build on the shipping path',
    ));
  }
  final appId = _winnAt(manifest, 'client.build.app_id');
  if (appId is String && winnEvidenceIdentifierIsNonShipping(appId)) {
    defects.add(WinnEvidenceDefect(
      'non_shipping_build_identifier',
      'client.build.app_id is "$appId"',
    ));
  }

  for (final entry in const <List<String>>[
    <String>['correlation.inner_tx_bytes', 'sent'],
    <String>['correlation.inner_rx_bytes', 'received'],
  ]) {
    final value = _winnAt(manifest, entry[0]);
    if (value is int && value < kWinnEvidenceByteFloorBytes) {
      defects.add(WinnEvidenceDefect(
        'byte_floor_not_met',
        '${entry[1]}: $value bytes, floor $kWinnEvidenceByteFloorBytes '
            '(criterion 5)',
      ));
    }
  }

  if (_winnAt(manifest, 'correlation.digest_match_full_set') == false) {
    defects.add(const WinnEvidenceDefect(
      'digest_match_full_set_false',
      'sent != received over the full ordered set (criterion 5)',
    ));
  }

  final delivered = _winnAt(manifest, 'correlation.delivered_packets');
  if (delivered is int && delivered <= 0) {
    defects.add(const WinnEvidenceDefect(
      'delivered_counter_zero',
      'correlation.delivered_packets is 0. A session can be admitted, '
          'established and carrying and still deliver nothing.',
    ));
  }

  final rejection = _winnAt(manifest, 'correlation.rejection_counters');
  if (rejection is Map) {
    for (final entry in rejection.entries) {
      final value = entry.value;
      if (value is int && value > 0) {
        defects.add(WinnEvidenceDefect(
          'rejection_counter_nonzero',
          'correlation.rejection_counters["${entry.key}"] is $value '
              '(criterion 5 requires all zero)',
        ));
      }
    }
  }

  // Gateway-side raw material. Client counters alone cannot show that
  // anything left the device, because the client is the thing under test.
  final gatewayArtifacts = _winnAt(manifest, 'gateway.artifacts');
  if (gatewayArtifacts is List) {
    final hasRaw = gatewayArtifacts.any((a) {
      final name = '$a'.toLowerCase();
      return name.endsWith('.pcap') ||
          name.endsWith('.pcapng') ||
          name.endsWith('.jsonl') ||
          name.endsWith('.log');
    });
    if (!hasRaw) {
      defects.add(const WinnEvidenceDefect(
        'no_gateway_side_raw_material',
        'gateway.artifacts lists no .pcap/.pcapng/.jsonl/.log. A bundle '
            'that is only client counters is one side of a two-sided claim.',
      ));
    }
  }

  defects.sort((a, b) => a.code.compareTo(b.code));
  return defects;
}

/// The normative `winn3-evidence-bundle/1` example, and the ONLY manifest in
/// this file. It is a SCHEMA FIXTURE: no session produced it, and
/// [winnEvidenceBundlePromotionDefects] refuses it by name for that reason.
/// Its numbers deliberately mirror the real 3,351 x 1,252-byte block in
/// .winn_platform_progress/evidence/winn3_linux_20260808_exact_4MiB_fullset.txt
/// so the shape is known to be producible.
Map<String, Object?> winnEvidenceBundleFixture() {
  const seedHex =
      '7fe16d012818f30787c33ba627bb4a89852985d9c0abb0fc75dde41d2b36c21f';
  final digest = winnEvidencePayloadDigestHex(
    _winnHexBytes(seedHex, 32)!,
    1252,
    3351,
  );
  return <String, Object?>{
    'bundle_format': kWinnEvidenceBundleFormat,
    'synthetic': true,
    'platform': 'linux',
    'session_id': 'SYNTHETIC-SCHEMA-FIXTURE-NOT-EVIDENCE',
    'captured_at_utc': '2026-08-12T00:00:00Z',
    'client': <String, Object?>{
      'host_id': 'fixture-client uname aarch64 (no such machine)',
      'build': <String, Object?>{
        'configuration': 'Release',
        'app_id': 'org.winsvpn.app',
        'version': '1.0.15+32',
      },
      'gateway_endpoint': '198.51.100.9:51833',
      'outer_local_port': 57994,
      'artifacts': <String>['client_session.txt', 'client_status.json'],
    },
    'gateway': <String, Object?>{
      'host_id': 'fixture-gateway uname x86_64 (no such machine)',
      'observed_peer_endpoint': '203.0.113.4:57994',
      'observed_peer_port': 57994,
      'capture': <String, Object?>{
        'link_type': 1,
        'interface': 'eth0',
        'sha256': digest,
      },
      'artifacts': <String>['gateway_posture.jsonl', 'gateway_capture.pcap'],
    },
    'correlation': <String, Object?>{
      'payload_seed_hex': seedHex,
      'payload_bytes_each': 1252,
      'tx_datagrams': 3351,
      'inner_tx_bytes': 4195452,
      'inner_rx_bytes': 4195452,
      'digest_sha256_sent_all': digest,
      'digest_sha256_returned': digest,
      'gateway_udp_payload_sha256': digest,
      'digest_match_full_set': true,
      'delivered_packets': 3351,
      'rejection_counters': <String, Object?>{
        'tx_rejected': 0,
        'rx_dropped': 0,
        'rx_oversize': 0,
        'rx_foreign_sender': 0,
        'rx_dropped_invalid': 0,
        'missing_count': 0,
      },
    },
    'artifacts_sha256': <String, Object?>{
      'client_session.txt': digest,
      'client_status.json': digest,
      'gateway_posture.jsonl': digest,
      'gateway_capture.pcap': digest,
    },
  };
}

void main() {
  group('anti-downgrade: a winn/3 config never becomes an AmneziaWG start', () {
    test('a refusal carries no configuration a tunnel could be started from',
        () {
      // The property, stated directly. Every way a winn/3 start can fail must
      // produce a decision that is unusable as a start: not supported, and
      // with nothing in it that any caller could hand to the native layer.
      // If a future change ever adds a "fall back to AmneziaWG" outcome, it
      // has to break one of these two assertions to exist.
      final refusals = <String, WinnStartDecision>{
        'ios': resolveWinnProtocolStart(
            operatingSystem: 'ios', config: validWinn3Config()),
        'macos': resolveWinnProtocolStart(
            operatingSystem: 'macos', config: validWinn3Config()),
        'windows': resolveWinnProtocolStart(
            operatingSystem: 'windows', config: validWinn3Config()),
        'hostname endpoint': resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['server_endpoint'] = 'gw.example.net:51820',
        ),
        'no endpoint': resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()..['server_endpoint'] = '',
        ),
        'stealth conflict': resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()..['stealth_active'] = true,
        ),
        'post-quantum material this build cannot honour':
            resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] = <String, dynamic>{
              'mlkem_public_key': 'AAAA',
            },
        ),
      };

      for (final entry in refusals.entries) {
        expect(
          entry.value.supported,
          isFalse,
          reason: '${entry.key}: a winn/3 config that cannot start the Winn '
              'path must NOT report itself startable. Reporting true here is '
              'how a post-quantum negotiation gets silently downgraded to '
              'classical AmneziaWG.',
        );
        expect(
          entry.value.iniSection,
          isEmpty,
          reason: '${entry.key}: a refusal must carry no [winn] section. A '
              'non-empty section on a refusal is a config a caller could '
              'start a tunnel from.',
        );
        expect(
          entry.value.reason,
          isNot(WinnRefusalReason.none),
          reason: '${entry.key}: a refusal must name why.',
        );
        expect(
          entry.value.message,
          isNotEmpty,
          reason: '${entry.key}: the user must be told why the connection '
              'stopped, not left with a silent no-op.',
        );
      }
    });

    test('no refusal message offers AmneziaWG as an alternative', () {
      // A message that told the user "retrying without Winn" would be
      // describing a downgrade. None of them may. Android is no longer
      // here: it is supported now (real device evidence, see
      // kWinnHostCapabilities), so resolveWinnProtocolStart no longer
      // refuses it and there is no refusal message to check.
      for (final os in const ['ios', 'macos', 'windows']) {
        final decision = resolveWinnProtocolStart(
          operatingSystem: os,
          config: validWinn3Config(),
        );
        final lowered = decision.message.toLowerCase();
        expect(lowered, isNot(contains('amneziawg')));
        expect(lowered, isNot(contains('fall back')));
        expect(lowered, isNot(contains('falling back')));
        expect(lowered, isNot(contains('winn/1')));
      }
    });

    test('a supported start always enables Winn, never merely permits it', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config(),
      );
      expect(decision.supported, isTrue);
      final section = parseWinnSection(decision.iniSection);
      expect(
        section['enabled'],
        'true',
        reason: 'The native host branches on [winn] enabled. A section that '
            'omitted it, or set it false, would make VpnTunnelService take '
            'the plain AmneziaWG path for a winn/3 config -- a silent '
            'downgrade produced by the config builder rather than the switch.',
      );
    });
  });

  group('the config-builder gate refuses rather than emits nothing', () {
    // winnSectionForTunnelConfig is the second, independent anti-downgrade
    // gate: it sits inside the only function that turns a served config into
    // the string the native tunnel is started from. Returning '' for an
    // unstartable winn/3 config would be the bug, because an AmneziaWG config
    // with no [winn] section is exactly what VpnTunnelService starts as plain
    // AmneziaWG.

    test('an unstartable winn/3 config throws instead of yielding no section',
        () {
      final cases = <String, Map<String, dynamic>>{
        'unsupported platform': validWinn3Config(),
        'hostname endpoint': validWinn3Config()
          ..['server_endpoint'] = 'gw.example.net:51820',
        'stealth conflict': validWinn3Config()..['stealth_active'] = true,
        'post-quantum material': validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{'mlkem_public_key': 'A'},
      };
      cases.forEach((label, config) {
        expect(
          () => winnSectionForTunnelConfig(
            // 'ios' for the first case, 'linux' for the rest -- either way
            // the config cannot start Winn.
            operatingSystem: label == 'unsupported platform' ? 'ios' : 'linux',
            config: config,
          ),
          throwsA(isA<StateError>()),
          reason: '$label: the gate must refuse to produce a tunnel '
              'configuration at all. Returning an empty [winn] section here '
              'silently downgrades a winn/3 negotiation to AmneziaWG.',
        );
      });
    });

    test('a config that is startable ON ITS MERITS yields the enabled section',
        () {
      // 2026-08-08: this used to drive winnSectionForTunnelConfig with
      // operatingSystem: 'linux'. Both .present entries were demoted by
      // docs/handoff/ADJUDICATION_20260808.md, so there is no platform left
      // that reaches the section builder at all -- winnSectionForTunnelConfig
      // now throws for EVERY platform, which the test below pins as the
      // honest current state.
      //
      // What this test is actually about is unchanged and still worth
      // pinning: a config with nothing wrong with it produces a real,
      // enabled [winn] section rather than an empty string. That is the
      // property winnSectionForTunnelConfig returns verbatim
      // (`return decision.iniSection`) once its gate passes, so exercising
      // the decision directly tests the same bytes without asserting a
      // platform capability that is not earned.
      final decision =
          resolveWinnProtocolStartForServedConfig(config: validWinn3Config());
      expect(decision.supported, isTrue, reason: decision.message);
      expect(decision.iniSection, isNotEmpty);
      expect(parseWinnSection(decision.iniSection)['enabled'], 'true');
    });

    test(
        'with no platform supported, the builder refuses on EVERY platform '
        'rather than emitting a plain AmneziaWG config', () {
      // The anti-downgrade property, restated for the post-demotion table.
      // Every platform now refuses at the capability gate, and the important
      // half is that refusing produces a THROW, never an empty section: an
      // AmneziaWG config with no [winn] section is exactly what
      // VpnTunnelService would start as plain AmneziaWG, silently downgrading
      // a winn/3 negotiation. If a platform is ever honestly re-promoted this
      // test starts failing for that platform, which is the correct prompt to
      // come back and re-earn the assertion rather than to delete it.
      for (final os in const ['android', 'ios', 'macos', 'windows', 'linux']) {
        expect(
          () => winnSectionForTunnelConfig(
            operatingSystem: os,
            config: validWinn3Config(),
          ),
          throwsA(isA<StateError>()),
          reason: '$os: no entry in kWinnHostCapabilities is .present today, '
              'so a winn/3 config must refuse here. If this now passes '
              'because $os was re-promoted, that promotion has to bring its '
              'own committed, content-asserting run evidence with it (see '
              'the flip-back gate on the android entry in '
              'lib/winn_protocol_dispatch.dart).',
        );
      }
    });

    test('direct or ambiguous winn/1 is refused on every platform', () {
      resetWinn1FallbackDispatchAuthorization();
      for (final os in const ['android', 'ios', 'macos', 'windows', 'linux']) {
        expect(
          () => winnSectionForTunnelConfig(
              operatingSystem: os,
              config: <String, dynamic>{
                'protocol_version': kWinnProtocolV1,
                'node_slug': 'france-winn1',
              }),
          throwsStateError,
          reason: '$os: direct v1 cannot bypass the ordinary-v3-failure gate.',
        );
        expect(
          () => winnSectionForTunnelConfig(
            operatingSystem: os,
            config: <String, dynamic>{},
          ),
          throwsStateError,
          reason: '$os: missing protocol state cannot become a v1 start.',
        );
      }
      resetWinn1FallbackDispatchAuthorization();
    });

    test('authorized v1 emits no Winn section in AWG-then-Xray order', () {
      const selection = '0123456789abcdef0123456789abcdef';
      resetWinn1FallbackDispatchAuthorization();
      synchronizeWinn1FallbackDispatchGeneration(
        selectionGeneration: selection,
        ordinaryConnectivityAuthorized: false,
      );
      expect(
        armWinn1FallbackDispatchAuthorization(
          startToken: 41,
          startGeneration: 7,
          selectionGeneration: selection,
          failedV3Node: 'spain-v3',
        ),
        isTrue,
      );
      synchronizeWinn1FallbackDispatchGeneration(
        selectionGeneration: selection,
        ordinaryConnectivityAuthorized: true,
      );
      final awg = <String, dynamic>{
        'protocol_version': kWinnProtocolV1,
        'node_slug': 'france-winn1',
        'stealth_active': false,
      };
      final xray = <String, dynamic>{
        ...awg,
        'stealth_active': true,
      };
      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: awg,
        ),
        isEmpty,
      );
      expect(
        winnSectionForTunnelConfig(
          operatingSystem: 'android',
          config: xray,
        ),
        isEmpty,
      );
      resetWinn1FallbackDispatchAuthorization();
    });

    test('an unknown protocol_version throws rather than yields no section',
        () {
      // Same reasoning as winn/3: a future protocol that quietly produced an
      // AmneziaWG config would be downgraded, not refused.
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'linux',
          config: <String, dynamic>{'protocol_version': 'winn/4'},
        ),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('platform scoping', () {
    test('NO platform has a proven winn/3 path on the shipping build today',
        () {
      // 2026-08-08. This test used to read "Android and Linux have a proven
      // Winn path" and assert both isTrue. docs/handoff/ADJUDICATION_20260808.md
      // demoted both, so it now asserts the opposite -- and it is written to
      // fail LOUDLY on a silent re-promotion rather than to be a placeholder
      // that quietly passes whatever the table says.
      //
      // Why each was demoted (the full citations are on the entries
      // themselves in lib/winn_protocol_dispatch.dart):
      //
      //  - Android: the run this table cited was a SAME-HANDSET LOOPBACK
      //    HARNESS -- package=org.winsvpn.devicecheck, a loopback
      //    gateway_endpoint, 706 bytes over 8 seconds, zero rekeys -- which
      //    fails criteria 1, 3, 5 and 6. The stronger 18.73 MiB physical-hop
      //    run was ruled genuine but its proof artefacts were deleted by its
      //    own lane's teardown, so no reviewer can check it.
      //  - Linux: the cited evidence is a harness and its own document says
      //    so (WINN3_LINUX_CRIT1_20260808.md:15); the release pipeline
      //    additionally cannot target arm64, the only architecture Linux ever
      //    ran winn/3 on (tools/build_linux_release.sh:178-210).
      //  - Both: the datapath they proved RELAYS AmneziaWG, and the owner
      //    ruled on 2026-08-08 that winn/3 is a standalone protocol with
      //    AmneziaWG and Xray removed -- so those claims do not describe v3.
      //
      // The adjudication's finding in one line: zero of five platforms has
      // met criterion 1 on a signed release build.
      for (final os in const [
        'android',
        'ios',
        'linux',
        'macos',
        'windows',
        'fuchsia',
        '',
      ]) {
        expect(
          platformSupportsWinnProtocol(os),
          isFalse,
          reason: '$os is marked supported in kWinnHostCapabilities. No '
              'platform has earned that: the bar is a signed release build '
              'completing the seven applicable criteria in ONE session '
              'against a real winn/3 gateway across a physical hop, with the '
              'runtime evidence COMMITTED under '
              '.winn_platform_progress/evidence/ and the runEvidence test '
              'below extended to assert CONTENT (reject loopback endpoints, '
              'require the byte floor, require digest_match_full_set) rather '
              'than mere existsSync. A harness run, a .profile or Debug '
              'build, a netns, or a dev-session entry point is not that. If '
              'you are re-promoting $os, bring the evidence and update this '
              'test deliberately -- do not delete the assertion.',
        );
      }
    });

    test('platform matching is case and whitespace tolerant', () {
      // Tolerance is a property of the LOOKUP, not of any entry's verdict, so
      // it stays testable with an empty supported set: ' Linux ' and 'LINUX'
      // must still resolve to the real 'linux' record rather than falling
      // through to the unknown-platform default, whose platform field would
      // be the raw key.
      expect(winnHostCapability(' Linux ').platform, 'linux');
      expect(winnHostCapability('LINUX').platform, 'linux');
      expect(
        winnHostCapability(' Linux ').missing,
        kWinnHostCapabilities['linux']!.missing,
        reason: 'a tolerant lookup must return the TABLE\'s record, not a '
            'freshly built unknown-platform placeholder that happens to '
            'also be unsupported.',
      );
    });

    test('each unsupported platform says what the user can actually do', () {
      // With no platform supported, "what the user can actually do" is
      // nothing -- and the copy has to say that plainly rather than name a
      // platform that cannot carry winn/3 either. winnSupportedPlatformsSentence
      // already degrades to 'no platform in this build' for an empty set;
      // this pins that the refusal actually uses it.
      for (final os in const ['android', 'ios', 'linux', 'macos', 'windows']) {
        final decision = resolveWinnProtocolStart(
            operatingSystem: os, config: validWinn3Config());
        expect(decision.supported, isFalse, reason: os);
        expect(decision.reason, WinnRefusalReason.unsupportedPlatform);
        expect(
          decision.message.toLowerCase(),
          contains('no platform in this build'),
          reason: '$os: the refusal must not send the user to another '
              'platform while every entry in the table is .absent.',
        );
      }
    });
  });

  group('a platform may not be turned on without saying how it works', () {
    // These are the guard rails on kWinnHostCapabilities. The predicate they
    // replaced was `operatingSystem == 'android'`, which made turning a
    // platform on a one-character edit. Each test below is one of the two
    // things a host has to have solved before that edit is honest.

    test('every platform the app builds for has a declared Winn host state',
        () {
      // A platform missing from the table is unsupported by default, but the
      // omission would be silent. These five are the ones this app ships.
      for (final os in const ['android', 'ios', 'macos', 'windows', 'linux']) {
        expect(
          kWinnHostCapabilities.containsKey(os),
          isTrue,
          reason: '$os ships in this app and must declare a Winn host state, '
              'supported or not.',
        );
      }
    });

    test(
        'a release build can explicitly enable only its tested standalone hosts',
        () {
      expect(
        winn3BuildEnabledPlatforms('android,ios'),
        <String>{'android', 'ios'},
      );
      // 2026-08-21 (linux app-level live winn3 lane): 'linux' joined
      // kWinn3StandaloneReleasePlatforms next to the android entry, so a
      // single-token linux define is now VALID and must resolve to the linux
      // record, exactly as a single-token android define always did.
      expect(
        winn3BuildEnabledPlatforms('linux'),
        <String>{'linux'},
      );
      expect(
        platformSupportsWinnProtocol(
          'android',
          buildValue: 'android,ios',
        ),
        isTrue,
      );
      expect(
        platformSupportsWinnProtocol(
          'linux',
          buildValue: 'linux',
        ),
        isTrue,
      );
      expect(
        platformSupportsWinnProtocol(
          'windows',
          buildValue: 'android,ios',
        ),
        isFalse,
      );
      expect(
        winnSupportedPlatformsSentence(buildValue: 'android,ios'),
        'Android or iOS',
      );
    });

    test('a malformed standalone-host build define fails closed', () {
      // 2026-08-21 (linux app-level live winn3 lane): 'linux' was removed
      // from this list when it joined kWinn3StandaloneReleasePlatforms; a
      // well-formed single-token linux define now resolves instead of
      // failing closed. 'android,unknown' still covers the unknown-token
      // failure mode, which is the mode the 'linux' entry used to exercise.
      for (final malformed in const <String>[
        'android, ios',
        'Android,ios',
        'android,android',
        'android,unknown',
        'android,',
      ]) {
        expect(winn3BuildEnabledPlatforms(malformed), isEmpty,
            reason: malformed);
      }
    });

    test('supported and missing can never disagree', () {
      for (final entry in kWinnHostCapabilities.entries) {
        expect(
          entry.value.supported,
          entry.value.missing.isEmpty,
          reason: '${entry.key}: supported is derived from missing being '
              'empty, so these cannot come apart.',
        );
        expect(
          entry.value.platform,
          entry.key,
          reason: '${entry.key}: the record must describe the key it is '
              'filed under, or a lookup returns another platform\'s evidence.',
        );
      }
    });

    test(
        'a supported platform names both its datagram seam and its outer '
        'socket exclusion', () {
      final supported =
          kWinnHostCapabilities.values.where((c) => c.supported).toList();
      // 2026-08-08: this used to require the supported set to be NON-empty,
      // on the strength of Linux. Both .present entries were demoted by
      // docs/handoff/ADJUDICATION_20260808.md, so an empty set is now the
      // honest state and requiring otherwise would be the very lie this
      // group guards against.
      //
      // The invariant below is kept and still armed: it is written over
      // whatever the supported set contains, so the day a platform is
      // re-promoted it must name both its datagram seam and its outer socket
      // exclusion or this fails. That is the guard that matters -- an empty
      // set makes the loop vacuous, not the rule weaker.
      expect(
        supported,
        isEmpty,
        reason: 'No platform has earned .present: the adjudication found that '
            'zero of five platforms met criterion 1 on a signed release '
            'build. If you are re-promoting one, this expectation is the '
            'deliberate speed bump -- change it consciously, alongside the '
            'committed run evidence and the content-asserting runEvidence '
            'test, and not just to make a red bar green.',
      );
      for (final capability in supported) {
        // The payload boundary. A host that cannot say where its AmneziaWG
        // outer datagrams come from is a host that is about to pump its tun
        // device into frames the engine will forward in cleartext.
        expect(
          capability.awgDatagramSeam.trim(),
          isNotEmpty,
          reason: '${capability.platform} claims Winn support without naming '
              'the source of its AmneziaWG outer datagrams.',
        );
        // The outer socket. Get this wrong and the tunnel dead-loops.
        expect(
          capability.outerSocketExclusion.trim(),
          isNotEmpty,
          reason: '${capability.platform} claims Winn support without naming '
              'how its outer socket stays out of the tunnel it carries.',
        );
      }
    });

    test('every supported platform names a real file for each claim', () {
      // The generic test above proves the two fields are non-empty. This one
      // proves they point at something a reviewer can open. A prose field that
      // says "handled natively" would pass the emptiness check and tell nobody
      // anything; naming the file is what makes the claim checkable, and it is
      // what makes gutting the host a test failure rather than a silent lie.
      const evidence = <String, List<String>>{
        'android': <String>[
          'android/app/src/main/kotlin/org/winsvpn/app/WinnAwgLoopbackSeam.kt',
          'android/app/src/main/kotlin/org/winsvpn/app/'
              'WinnAndroidEngineHost.kt',
        ],
        'linux': <String>[
          'linux/runner/linux_winn_host.cc',
          'linux/runner/linux_tunnel_backend.cc',
        ],
      };
      for (final entry in kWinnHostCapabilities.entries) {
        if (!entry.value.supported) continue;
        expect(
          evidence.containsKey(entry.key),
          isTrue,
          reason: '${entry.key} was turned on without adding the evidence this '
              'test checks. Name the seam file and the exclusion file.',
        );
        final claims =
            '${entry.value.awgDatagramSeam} ${entry.value.outerSocketExclusion}';
        for (final needle in evidence[entry.key]!) {
          expect(
            claims,
            contains(needle),
            reason: '${entry.key} claims Winn support but its capability entry '
                'no longer names $needle.',
          );
          // Naming a file is not the same as that file existing. A rename or
          // deletion elsewhere in the tree would still leave this string
          // matching -- it is a substring of prose, not a live reference --
          // so without this the check above could pass forever against a
          // path nothing backs any more.
          expect(
            File(needle).existsSync(),
            isTrue,
            reason: '${entry.key} names $needle as the file backing its '
                'claim, but that file does not exist on disk. A citation to '
                'a file that is not there is worse than no citation.',
          );
        }
      }
    });

    test(
        'every supported platform\'s cited RUN EVIDENCE -- proof a session '
        'actually happened, not just that the code exists -- is a file '
        'that is actually on disk', () {
      // The test above pins PROSE: it proves awgDatagramSeam/
      // outerSocketExclusion name a real source file. That is necessary but
      // not sufficient, because "a platform may only be declared supported
      // by naming both" (the class doc on WinnHostCapability) is a claim
      // about EXECUTION, not about source -- see android's own file-level
      // comment: "source that compiles and a harness that passes are not a
      // session." The run itself is cited only in the `//` comment above
      // each entry (e.g. "Full log: .winn_platform_progress/evidence/
      // devicecheck_20260804T155556Z_motorola_edge_plus_2023.log"), which is
      // prose a human reads, not a field this map can already check by
      // string containment. A comment can say "29/29 RESULT lines PASS"
      // whether or not the log proving it is still on disk -- that is
      // exactly the gap this test closes, and exactly why the log files
      // this pins were untracked until .gitignore grew a scoped negation
      // for .winn_platform_progress/evidence/ alongside this test.
      //
      // Each path is also required to still be cited, in the raw source
      // text, by lib/winn_protocol_dispatch.dart -- so this map cannot
      // quietly drift from what the entry actually names. If a platform
      // below has no entry here, that platform's comment does not (yet)
      // cite an in-repo run-evidence artifact this test can check; that is
      // a gap to close separately, not something this test can silently
      // wave through as fine.
      const runEvidence = <String, List<String>>{
        'android': <String>[
          '.winn_platform_progress/evidence/'
              'devicecheck_20260804T155556Z_motorola_edge_plus_2023.log',
        ],
        // Linux was the platform this test's own comment above was describing
        // when it said "that platform's comment does not (yet) cite an in-repo
        // run-evidence artifact this test can check". It was .present on the
        // strength of a real 2026-08-04 session whose evidence lived entirely
        // under ~/.winn-e2e-lab/ -- outside the repository, so uncitable and
        // uncheckable. Re-earned in-repo on 2026-08-06 across two separate
        // physical Linux hosts; see the comment on the 'linux' entry in
        // lib/winn_protocol_dispatch.dart. Committed with a .txt extension on
        // purpose: .gitignore line 3 is `*.log`, and the negation added for
        // this directory re-includes .log files but a .txt needs no negation to
        // survive at all. Criterion 1 is closed by the Flutter app session; the
        // full-set digest is closed by the 20260808 exact block -- both cited
        // so the audit's restricted-set flag moves.
        'linux': <String>[
          '.winn_platform_progress/evidence/'
              'winn3_linux_20260806T194436Z_two_host_lan_gateway_session.txt',
          '.winn_platform_progress/evidence/'
              'winn3_linux_20260806T194436Z_gateway_far_end_timeline.txt',
          '.winn_platform_progress/evidence/'
              'winn3_linux_20260806T203726Z_flutter_app_shipping_path_session.txt',
          '.winn_platform_progress/evidence/'
              'winn3_linux_20260808_exact_4MiB_fullset.txt',
        ],
      };
      // 2026-08-08 -- READ THIS BEFORE TRUSTING A GREEN BAR HERE. Every entry
      // in the table is now `.absent`, so the `continue` below skips all of
      // them and the body of this test does not execute at all. It is
      // VACUOUS today, and that is exactly the failure mode the adjudication
      // called out: `runEvidence` only ever checked `existsSync`, so it could
      // not tell a 706-byte loopback harness log from a 19 MB physical-hop
      // one, and it went green for four days while the table cited the wrong
      // kind of run.
      //
      // So this test is NOT the guard on re-promotion. The guard is the
      // `expect(supported, isEmpty)` above plus the per-entry tests below;
      // this map is kept because the day a platform is honestly re-promoted
      // it is the right place to pin its evidence -- and on that day it must
      // be extended to ASSERT CONTENT, not existence: reject a loopback
      // gateway_endpoint, require the >=4 MiB floor, require the session
      // duration and rekey floors, require digest_match_full_set. See the
      // flip-back gate on the android entry in
      // lib/winn_protocol_dispatch.dart and ADJUDICATION_20260808.md:189.
      final dispatchSource =
          File('lib/winn_protocol_dispatch.dart').readAsStringSync();
      var checkedAny = false;
      for (final entry in kWinnHostCapabilities.entries) {
        if (!entry.value.supported) continue;
        final paths = runEvidence[entry.key];
        if (paths == null) continue;
        checkedAny = true;
        for (final path in paths) {
          expect(
            dispatchSource,
            contains(path),
            reason: '${entry.key}: this test expects $path to still be '
                'cited in lib/winn_protocol_dispatch.dart. Either the '
                'citation moved (update this map to match) or it was '
                'quietly dropped (which would itself be the defect this '
                'test exists to catch).',
          );
          expect(
            File(path).existsSync(),
            isTrue,
            reason: '${entry.key} is marked .present on the strength of a '
                'real run, and its capability entry cites $path as that '
                "run's log. That file does not exist on disk, so the run "
                'this entry claims cannot be checked by anyone reading the '
                'source -- a claim a reviewer cannot check is exactly what '
                'WinnHostCapability\'s own doc comment says these prose '
                'fields exist to prevent. (The likeliest cause is the '
                'working tree being lost or the log never having been '
                'committed -- which an ignored-but-uncommitted evidence '
                'file is exactly one `git clean` away from.)',
          );
        }
        // CONTENT, not existence. Added 2026-08-12 by lane
        // v3_promotion_substrate: this is the extension the tripwire below
        // has been demanding since 2026-08-08. The cited files are read as
        // ONE BUNDLE rather than one at a time, because the criteria are
        // properties of a session and a session spans the client artefact and
        // the gateway artefact together.
        //
        // This wiring is exercised today, with the table all-absent, by the
        // 'run evidence is judged by CONTENT' group below, which runs the
        // same checker against the real committed corpus and against
        // deliberately broken copies of it. It is not a guard that first runs
        // on the day it matters.
        final defects = winnRunEvidenceDefectsForPaths(paths);
        expect(
          defects.map((d) => d.toString()).toList(),
          isEmpty,
          reason: '${entry.key} is .present, but the evidence it cites does '
              'not meet the bar in its own content. Each line above is a '
              'stable defect code and the value that produced it. This is '
              'the check that a 706-byte loopback harness log passed for '
              'four days when the test only called existsSync.',
        );
      }
      expect(
        checkedAny,
        isFalse,
        reason: 'A platform is .present again. The content assertions this '
            'expectation used to demand now exist and run above '
            '(winnRunEvidenceDefects: loopback far end, the >=4 MiB floor '
            'both ways, digest_match_full_set, non-shipping build '
            'identifiers, delivered-packet counters, all rejection counters '
            'zero). What they still do NOT cover is criteria 2, 4, 6, 7 and '
            '8 -- exclusion installed, handshake confirmed at BOTH ends, >=5 '
            'min spanning >=2 rekeys, lifecycle, and the iOS memory sample. '
            'Those are declared in a two-sided bundle manifest '
            '(winnEvidenceBundlePromotionDefects), not inferred from counter '
            'scanning. So: before removing this line, confirm a committed '
            'winn3-evidence-bundle/1 manifest exists for the platform being '
            'promoted and that a DIFFERENT MODEL FAMILY re-derived its '
            'digest from payload_seed_hex. The flip itself is owner-reserved '
            '(OWNER_DELEGATED_DECISIONS_20260807.md section 8 item L); '
            'removing this expectation is part of that flip, not a '
            'precondition an agent may satisfy on its own.',
      );
    });

    test(
        'the Linux entry is .absent and says WHY, naming the harness and the '
        'arm64 release gap', () {
      // 2026-08-08. This test used to assert `linux.supported isTrue` plus the
      // seam/exclusion prose ('127.0.0.1', 'Endpoint', 'fwmark',
      // 'allow_own_socket', 'ip route get'). docs/handoff/ADJUDICATION_20260808.md
      // demoted the entry, so those claims are gone from the table by
      // construction -- `.absent()` forces both prose fields to '' and there
      // is no way to file a capability claim under an absent entry.
      //
      // The assertions are not deleted, they are inverted and re-aimed. What
      // has to stay pinned is no longer "Linux names its seam" but "Linux
      // says, in checkable terms, why it is not claiming one" -- because a
      // vague `missing` is how a demotion quietly rots back into a promotion:
      // nobody can tell what would close it, so the next lane closes it with
      // whatever it happens to have.
      final linux = kWinnHostCapabilities['linux']!;
      expect(
        linux.supported,
        isFalse,
        reason: 'Linux was demoted on 2026-08-08. Re-promoting it needs a '
            'signed release build -- which for arm64, the only architecture '
            'Linux has ever run winn/3 on, this repo cannot currently '
            'produce at all (tools/build_linux_release.sh:178-210).',
      );
      // .absent() makes these structurally empty; assert it anyway, because
      // this is the exact shape of the lie the table exists to prevent.
      expect(linux.awgDatagramSeam, isEmpty);
      expect(linux.outerSocketExclusion, isEmpty);

      final missing = linux.missing.toLowerCase();
      for (final required in const <String>[
        'shipping path',
        'harness',
        'arm64',
      ]) {
        expect(
          missing,
          contains(required),
          reason: 'the Linux entry must keep naming "$required" as part of '
              'what is unmet. Those are the three checkable facts the '
              'adjudication rested on: the criterion-1 evidence is a harness '
              'and its own document says so, the release pipeline cannot '
              'target the tested architecture, and no session has run on the '
              'shipping path.',
        );
      }
      expect(
        linux.missing,
        contains('ADJUDICATION_20260808'),
        reason: 'the demotion must cite the ruling that made it, or the next '
            'lane cannot tell a reasoned demotion from a lane that lost its '
            'nerve.',
      );
    });

    test('the Windows entry names EXECUTION as the gap, not reachability', () {
      // A stale `missing` is the same class of lie as a stale claim, just in
      // the other direction: it tells the next lane to go and fix something
      // that is already fixed, and it hides what is actually left.
      //
      // The Windows host used to be unreachable three times over -- no caller
      // for the privileged start, a section allowlist that rejected `[winn]`
      // before the start path, and a selector on a key Dart never emits. All
      // three are closed. What is left is that no winn/3 session has been
      // carried on a real Windows machine, and that is what this entry has to
      // say so the table stays a record of evidence rather than of history.
      final windows = kWinnHostCapabilities['windows']!;
      expect(windows.supported, isFalse);
      final missing = windows.missing.toLowerCase();
      expect(
        missing,
        contains('no winn/3 session has been carried'),
        reason: 'the Windows gap is execution, and the entry must say so.',
      );
      for (final retired in const <String>[
        'has no caller',
        'rejects a [winn] section',
        'protocol = winn/3',
        'second wintun adapter',
      ]) {
        expect(
          missing,
          isNot(contains(retired)),
          reason: 'the Windows entry still claims "$retired", which is no '
              'longer true. Every one of those was closed; leaving it here '
              'sends the next lane to fix something that is already fixed.',
        );
      }
    });

    test(
        'the Android entry is .absent and names the LOOPBACK HARNESS as the '
        'reason, not merely "pending"', () {
      // Mirrors the Linux test above -- deliberately, because Android is the
      // platform this table has now got wrong TWICE, in the same direction,
      // for the same reason.
      //
      //  - The first time it read WinnHostCapability.present with nothing
      //    behind it but unit tests against a local JVM double: real source,
      //    real tests, zero device execution.
      //  - It was demoted, then re-promoted on a real 29/29 devicecheck run,
      //    and the version of this test written that day said it "pins that
      //    distinction so a future edit cannot quietly go back to claiming
      //    source as if it were execution."
      //  - 2026-08-08: docs/handoff/ADJUDICATION_20260808.md read the cited
      //    log and found the run was a SAME-HANDSET LOOPBACK HARNESS --
      //    package=org.winsvpn.devicecheck (line 4), a loopback
      //    gateway_endpoint (line 57), 706 bytes over 8 seconds, zero rekeys.
      //    So the second promotion was not source-as-execution; it was
      //    HARNESS-as-shipping-path, one rung up and just as wrong.
      //
      // That is why this test now pins the reason and not just the verdict.
      // "Android is absent" alone would let the next lane re-promote it on
      // the next harness that passes. Naming the specific defect -- loopback,
      // harness package, a byte floor and a duration floor that were missed
      // by orders of magnitude -- is what makes the bar re-readable by
      // someone who was not here.
      final android = kWinnHostCapabilities['android']!;
      expect(
        android.supported,
        isFalse,
        reason: 'Android was demoted on 2026-08-08. Source that compiles is '
            'not execution, and a harness that passes is not a session -- '
            'that is the standard the Windows and Apple entries have always '
            'been held to, and it applies here too.',
      );
      expect(android.awgDatagramSeam, isEmpty);
      expect(android.outerSocketExclusion, isEmpty);

      final missing = android.missing.toLowerCase();
      for (final required in const <String>[
        'shipping path',
        'loopback',
        'devicecheck',
      ]) {
        expect(
          missing,
          contains(required),
          reason: 'the Android entry must keep naming "$required". A demotion '
              'that only says "not yet proven" is re-promotable by the next '
              'harness run; one that says WHICH run was cited and WHY it did '
              'not count is not.',
        );
      }
      expect(
        android.missing,
        contains('ADJUDICATION_20260808'),
        reason: 'the demotion must cite the ruling that made it.',
      );
      // The historical claims must not survive as CAPABILITY claims. They are
      // still in the file-level comment above the entry, which is the right
      // place for a record of what a past run showed; the fields a caller
      // reads are what may not assert them.
      final claims =
          '${android.awgDatagramSeam} ${android.outerSocketExclusion}';
      for (final retired in const <String>[
        'WinnAwgLoopbackSeam',
        'VpnService.protect',
        'real hardware',
        'RESULT',
      ]) {
        expect(
          claims,
          isNot(contains(retired)),
          reason: 'the entry is .absent, so it may not still be asserting '
              '"$retired" as a live capability. If Android is genuinely '
              're-promoted, these come back deliberately and with committed, '
              'content-asserting evidence behind them.',
        );
      }
    });

    test('an absent platform may still not name a seam or an exclusion', () {
      // This used to read `for (final os in const <String>['windows', 'ios',
      // 'macos'])` -- exactly the platforms that were unsupported on the day
      // it was written. That hardcoded list was itself an instance of the
      // double standard this whole table exists to prevent: it protects
      // whichever platforms someone remembered to type in, not whichever
      // platforms actually need protecting. It said nothing about 'android',
      // which at the time was WRONGLY marked supported with nothing but a
      // JVM double behind it -- exactly the claim this test exists to catch
      // when made about windows/ios/macos. Deriving the set from the table
      // itself, the same way winnSupportedPlatforms() does, closes that
      // hole: every currently-unsupported platform is covered automatically,
      // and a platform can no longer be silently exempted just because
      // nobody added its name to a literal here.
      for (final entry in kWinnHostCapabilities.entries) {
        if (entry.value.supported) continue;
        final os = entry.key;
        expect(
          entry.value.awgDatagramSeam,
          isEmpty,
          reason: '$os may have seam code, but the field is a claim that the '
              'seam carries traffic, not that it compiles.',
        );
        expect(
          entry.value.outerSocketExclusion,
          isEmpty,
          reason: '$os may have exclusion code, but the field is a claim '
              'that the exclusion was executed and observed to work.',
        );
      }
    });

    test('an unsupported platform names what is missing and claims nothing',
        () {
      final unsupported =
          kWinnHostCapabilities.values.where((c) => !c.supported).toList();
      expect(unsupported, isNotEmpty);
      for (final capability in unsupported) {
        expect(
          capability.missing.trim(),
          isNotEmpty,
          reason: '${capability.platform} is unsupported but does not say what '
              'would have to exist.',
        );
        // Half-filled evidence is how a partially-migrated platform would slip
        // through: seam done, exclusion not, and nobody notices.
        expect(capability.awgDatagramSeam, isEmpty);
        expect(capability.outerSocketExclusion, isEmpty);
      }
    });

    test('an unknown operating system is unsupported and says so', () {
      for (final os in const ['fuchsia', 'freebsd', '', '   ']) {
        final capability = winnHostCapability(os);
        expect(capability.supported, isFalse);
        expect(capability.missing.trim(), isNotEmpty);
      }
    });

    test('capability lookup is case and whitespace tolerant like the predicate',
        () {
      // Every entry is .absent since 2026-08-08, so `supported` no longer
      // distinguishes a real hit from the unknown-platform fallback. The
      // `platform` field does: a tolerant lookup returns the table's own
      // record (platform == the canonical key), while a miss returns a
      // placeholder built from the raw key.
      expect(winnHostCapability(' Linux ').platform, 'linux');
      expect(winnHostCapability('ANDROID').platform, 'android');
      expect(winnHostCapability(' iOS ').platform, 'ios');
      expect(winnHostCapability(' iOS ').supported, isFalse);
      expect(
        winnHostCapability(' Fuchsia ').platform,
        'fuchsia',
        reason: 'an unknown platform still normalizes before it is reported, '
            'and is unsupported by default.',
      );
      expect(winnHostCapability(' Fuchsia ').supported, isFalse);
    });
  });

  group(
      'run evidence is judged by CONTENT, and the judge is proven on the '
      'real corpus', () {
    // Every table entry is `.absent`, so the runEvidence test's own loop is
    // vacuous. These tests are NOT vacuous: they run the same checker
    // against the files actually committed under
    // .winn_platform_progress/evidence/, including the two that fooled this
    // table, so the guard is exercised today rather than first exercised on
    // the day a promotion depends on it.
    const evidenceDir = '.winn_platform_progress/evidence';
    const linuxFullSet = '$evidenceDir/winn3_linux_20260808_exact_4MiB_'
        'fullset.txt';
    const androidHarness = '$evidenceDir/devicecheck_20260804T155556Z_'
        'motorola_edge_plus_2023.log';
    const iosCarriage = '$evidenceDir/winn3_ios_20260811T044620Z_first_'
        'standalone_v3_carriage.txt';
    const iosPosture = '$evidenceDir/winn3_ios_20260811T044620Z_gateway_far_'
        'end_posture.jsonl';
    const macosRelay = '$evidenceDir/winn3_macos_20260806T155246Z_contained_'
        'remote_gateway_session.txt';

    String readEvidence(String path) {
      final file = File(path);
      expect(
        file.existsSync(),
        isTrue,
        reason: '$path is the control this test is built on. If it is gone, '
            'this test is not passing -- it has nothing to judge, which is '
            'the 2026-08-08 "artefacts deleted by the lane\'s own teardown" '
            'failure all over again.',
      );
      return file.readAsStringSync();
    }

    test(
        'POSITIVE CONTROL: the exact-4-MiB Linux full-set artefact passes '
        'every content check', () {
      final defects = winnRunEvidenceDefects(
          <String, String>{linuxFullSet: readEvidence(linuxFullSet)});
      expect(
        defects.map((d) => d.toString()).toList(),
        isEmpty,
        reason: 'this is the strongest artefact in the repository: '
            '3,351 datagrams of 1,252 bytes each way (4,195,452 B), '
            'digest 6905aef... sent == returned == gateway-computed, every '
            'rejection counter zero, gateway on a separate physical machine. '
            'A bar it cannot clear is a bar nothing can clear, and an '
            'unsatisfiable gate gets weakened by the next lane rather than '
            'met.',
      );
    });

    test(
        'the positive control is only readable because claims are parsed as '
        'JSON, not grepped', () {
      final text = readEvidence(linuxFullSet);
      expect(
        text.contains('digest_match_full_set false'),
        isTrue,
        reason: 'this artefact honestly narrates a DIFFERENT, lossier run '
            'that failed the full-set digest. That prose is the trap.',
      );
      expect(
        text.contains('"digest_match_full_set": true'),
        isTrue,
        reason: 'and its own machine-readable block asserts the opposite '
            'about itself.',
      );
      // The checker must read the second and ignore the first.
      expect(
        winnRunEvidenceDefects(<String, String>{linuxFullSet: text}),
        isEmpty,
      );
    });

    test(
        'NEGATIVE CONTROL: the same-handset devicecheck harness log fails on '
        'every count it should, by name', () {
      final defects = winnRunEvidenceDefects(
          <String, String>{androidHarness: readEvidence(androidHarness)});
      final codes = defects.map((d) => d.code).toSet();
      // This exact file stood in for a full-bar session for four days.
      expect(
        codes,
        containsAll(<String>[
          'loopback_far_end',
          'byte_floor_not_met',
          'digest_match_full_set_absent',
          'non_shipping_build_identifier',
        ]),
        reason: 'the four things ADJUDICATION_20260808.md found by reading '
            'this log by hand -- gateway_endpoint 127.0.0.1:46921, 706/172 '
            'bytes, no full-set digest, package=org.winsvpn.devicecheck -- '
            'must each be found mechanically. Found: '
            '${defects.map((d) => d.toString()).join("; ")}',
      );
      expect(
        defects.where((d) => d.code == 'loopback_far_end').single.detail,
        contains('127.0.0.1'),
        reason: 'the defect must quote the value, not merely say "loopback".',
      );
    });

    test(
        'NEGATIVE CONTROL: iOS reached carrying and delivered nothing, and '
        'the checker reads the counter rather than the state', () {
      final posture = readEvidence(iosPosture);
      final defects = winnRunEvidenceDefects(<String, String>{
        iosCarriage: readEvidence(iosCarriage),
        iosPosture: posture,
      });
      final codes = defects.map((d) => d.code).toSet();
      expect(
        codes,
        contains('delivered_counter_zero'),
        reason: 'rx_packets is 0 on all 1,751 sampled lines while carrying '
            'reads 1 on 67 of them. A checker that read state would have '
            'promoted this. Found: '
            '${defects.map((d) => d.toString()).join("; ")}',
      );
      expect(codes, contains('rejection_counter_nonzero'),
          reason: 'rx_dropped_invalid reached 50: every inner packet the '
              'phone sent was rejected at the far end.');
      expect(codes, contains('byte_floor_not_met'));
      expect(codes, contains('non_shipping_build_identifier'),
          reason: 'org.winsvpn.app.debug is not the shipping path.');
      // And the raw material still says what the narrative says, so the
      // failure is the session's, not the artefact's.
      expect(
        RegExp(r'"rx_packets":0').allMatches(posture).length,
        1751,
        reason: 'if this count ever changes, the artefact changed; re-read '
            'it before trusting anything above.',
      );
    });

    test(
        'NEGATIVE CONTROL: the macOS relay session carried 11.9 MiB and is '
        'still refused, because it never asserts a full-set digest', () {
      final defects = winnRunEvidenceDefects(
          <String, String>{macosRelay: readEvidence(macosRelay)});
      final codes = defects.map((d) => d.code).toSet();
      expect(
        codes,
        contains('digest_match_full_set_absent'),
        reason: 'its three-way SHA-256 agreement is narrated in prose. '
            'Criterion 5 needs a machine-readable claim over the full '
            'ordered set, and "the closest thing to good" is not the bar.',
      );
      expect(
        codes,
        isNot(contains('byte_floor_not_met')),
        reason: 'the byte floor is NOT what this run fails -- it carried '
            '11,933,896 / 11,957,560 bytes. Saying otherwise would send the '
            'next lane to fix the wrong thing.',
      );
    });

    test('a prose-only artefact carries no checkable claim at all', () {
      final defects = winnRunEvidenceDefects(
          <String, String>{iosCarriage: readEvidence(iosCarriage)});
      final codes = defects.map((d) => d.code).toSet();
      expect(
        codes,
        contains('no_machine_readable_counters'),
        reason: 'the iOS carriage write-up is careful and honest and '
            'contains zero parseable JSON objects. Every number in it is a '
            'sentence.',
      );
      expect(
        codes,
        contains('delivered_counter_absent'),
        reason: 'and with no counters at all, nothing in it shows a single '
            'inner packet arrived. Absent is not zero and neither is proof.',
      );
    });

    // --- forward mode is a different health contract (D11) ------------------
    //
    // These three lines are NOT a capture and are deliberately not committed
    // next to the real corpus above. They are the byte-exact output of
    // cmd/winn3-gateway's own `json.Marshal(serveStatus{...})` -- generated by
    // the Go marshaller so the SHAPE is the code's and not a Dart author's --
    // carrying the counter values a proof lane measured on 2026-08-12 on a
    // gateway that was forwarding correctly: carrying 2, promoted 0,
    // rx_device_writes 8, rx_packets 0. The first line is that gateway before
    // any reply had come back; the last is after eight had.
    //
    // Why this test exists. Step 5 of the cross-family verifier
    // (WINN3_PROMOTION_EVIDENCE_SUBSTRATE_20260812 section 6) reads the
    // maximum delivered counter over gateway_posture.jsonl ALONE, while
    // winnRunEvidenceDefects pools every artefact in the bundle. Under
    // -forward the gateway's only member of kWinnEvidenceDeliveredKeys used to
    // be rx_packets, which is 0 by construction there -- so the first
    // standalone forward-mode bundle would have FAILED step 5 while passing
    // the Dart checker, whose max was being satisfied by the client's own
    // rx_packets. Two rulers disagreeing means one is wrong. The gateway now
    // publishes inner_packets_delivered, already a member of that set, which
    // makes both rulers agree with no change to either.
    const forwardPostureNoReplyYet =
        '{"event":"posture","listen":"0.0.0.0:51833","sessions":2,"admitted":2,'
        '"sessions_built":2,"datagrams":40,"stranger_datagrams":0,'
        '"refused_datagrams":0,"session_build_failures":0,"carrying":2,'
        '"promoted":0,"carriage_proven":false,"rx_packets":0,"rx_offered":4,'
        '"tx_packets":4,"rx_device_writes":4,"inner_packets_delivered":0,'
        '"rx_dropped_invalid":0,"rx_dropped_closed":0,"tx_dropped_invalid":0,'
        '"tx_dropped_closed":0,"rx_drop_family_off":0,"rx_drop_martian":0,'
        '"rx_drop_not_for_us":0,"rx_drop_reflected":0,"rx_drop_malformed":0,'
        '"reflected":0,"session_states":["carrying","carrying"],'
        '"messages_sent":10,"messages_received":10,"send_failed":0,'
        '"recv_failed":0,"pipe_sent":4,"pipe_delivered":4,'
        '"pipe_recv_errors":0,"pipe_send_errors":0,"inner_mtu":1280,'
        '"message_size":1350,"forward":{"device":{"interface":"winn3fwd0",'
        '"mtu":1280,"reads":0,"delivered":0,"unknown_dest":0,"malformed":0,'
        '"send_refused":0,"device_gone":false},"table":{"size":2,"learned":2,'
        '"forgotten":0,"collisions":0}}}';
    const forwardPostureCarrying =
        '{"event":"posture","listen":"0.0.0.0:51833","sessions":2,"admitted":2,'
        '"sessions_built":2,"datagrams":60,"stranger_datagrams":0,'
        '"refused_datagrams":0,"session_build_failures":0,"carrying":2,'
        '"promoted":0,"carriage_proven":true,"rx_packets":0,"rx_offered":6,'
        '"tx_packets":6,"rx_device_writes":6,"inner_packets_delivered":3,'
        '"rx_dropped_invalid":0,"rx_dropped_closed":0,"tx_dropped_invalid":0,'
        '"tx_dropped_closed":0,"rx_drop_family_off":0,"rx_drop_martian":0,'
        '"rx_drop_not_for_us":0,"rx_drop_reflected":0,"rx_drop_malformed":0,'
        '"reflected":0,"session_states":["carrying","carrying"],'
        '"messages_sent":15,"messages_received":15,"send_failed":0,'
        '"recv_failed":0,"pipe_sent":6,"pipe_delivered":6,'
        '"pipe_recv_errors":0,"pipe_send_errors":0,"inner_mtu":1280,'
        '"message_size":1350,"forward":{"device":{"interface":"winn3fwd0",'
        '"mtu":1280,"reads":3,"delivered":3,"unknown_dest":0,"malformed":0,'
        '"send_refused":0,"device_gone":false},"table":{"size":2,"learned":2,'
        '"forgotten":0,"collisions":0}}}';
    const forwardPostureCarryingMore =
        '{"event":"posture","listen":"0.0.0.0:51833","sessions":2,"admitted":2,'
        '"sessions_built":2,"datagrams":80,"stranger_datagrams":0,'
        '"refused_datagrams":0,"session_build_failures":0,"carrying":2,'
        '"promoted":0,"carriage_proven":true,"rx_packets":0,"rx_offered":8,'
        '"tx_packets":8,"rx_device_writes":8,"inner_packets_delivered":8,'
        '"rx_dropped_invalid":0,"rx_dropped_closed":0,"tx_dropped_invalid":0,'
        '"tx_dropped_closed":0,"rx_drop_family_off":0,"rx_drop_martian":0,'
        '"rx_drop_not_for_us":0,"rx_drop_reflected":0,"rx_drop_malformed":0,'
        '"reflected":0,"session_states":["carrying","carrying"],'
        '"messages_sent":20,"messages_received":20,"send_failed":0,'
        '"recv_failed":0,"pipe_sent":8,"pipe_delivered":8,'
        '"pipe_recv_errors":0,"pipe_send_errors":0,"inner_mtu":1280,'
        '"message_size":1350,"forward":{"device":{"interface":"winn3fwd0",'
        '"mtu":1280,"reads":8,"delivered":8,"unknown_dest":0,"malformed":0,'
        '"send_refused":0,"device_gone":false},"table":{"size":2,"learned":2,'
        '"forgotten":0,"collisions":0}}}';
    const forwardGatewayPosture = '$forwardPostureNoReplyYet\n'
        '$forwardPostureCarrying\n$forwardPostureCarryingMore\n';

    test(
        'a forward-mode gateway_posture.jsonl carries a delivered counter ON '
        'ITS OWN, which is what step 5 reads', () {
      final codes = winnRunEvidenceDefects(<String, String>{
        'gateway_posture.jsonl': forwardGatewayPosture,
      }).map((d) => d.code).toSet();

      // The premise. If these ever stop holding, this artefact is no longer a
      // forward-mode posture and nothing below means what it says.
      expect(forwardGatewayPosture, contains('"promoted":0'));
      expect(forwardGatewayPosture, contains('"rx_packets":0'));
      expect(forwardGatewayPosture, contains('"carrying":2'));

      expect(
        codes,
        isNot(contains('delivered_counter_zero')),
        reason: 'this gateway forwarded real traffic. Its promoted and '
            'rx_packets are 0 BY DESIGN -- the -forward return path bypasses '
            'tun.Tunnel, so DeviceProven never latches -- and before '
            'inner_packets_delivered existed those were the only delivered '
            'keys it published, so the verifier reading this file alone would '
            'have called a working gateway dead. Found: ${codes.join(", ")}',
      );
      expect(
        codes,
        isNot(contains('delivered_counter_absent')),
        reason: 'and the counter must be PRESENT, not merely non-zero: '
            'absent and zero are different diagnoses.',
      );
      expect(
        codes,
        isNot(contains('rejection_counter_nonzero')),
        reason: 'no rejection counter moved in this posture.',
      );
      // What a gateway-only bundle legitimately still fails: the byte floor and
      // the full-set digest are claims the CLIENT and the manifest make. Naming
      // them here keeps the next reader from thinking this test asserts a
      // gateway file alone can promote anything.
      expect(
        codes,
        containsAll(<String>[
          'byte_floor_not_met',
          'digest_match_full_set_absent',
        ]),
        reason: 'a gateway posture alone is not a promotion bundle, and this '
            'test does not claim it is.',
      );
    });

    test(
        'POSITIVE CONTROL: strip inner_packets_delivered and the same '
        'forward-mode posture goes red again', () {
      // Without this control the test above would pass just as happily on a
      // checker that had stopped looking at delivered counters at all.
      final stripped = forwardGatewayPosture.replaceAll(
          RegExp(r'"inner_packets_delivered":\d+,'), '');
      expect(stripped, isNot(contains('inner_packets_delivered')));

      final codes = winnRunEvidenceDefects(<String, String>{
        'gateway_posture.jsonl': stripped,
      }).map((d) => d.code).toSet();
      expect(
        codes,
        contains('delivered_counter_zero'),
        reason: 'this is the pre-fix document, and it is exactly the defect '
            'the proof lane hit: rx_packets 0 while the gateway forwarded. '
            'Found: ${codes.join(", ")}',
      );
    });

    test('the pass comes from the COUNTER, not from the carrying state', () {
      // Same posture, deliveries zeroed, state untouched. If the checker were
      // reading `carrying` it would still pass. It must not.
      final noDeliveries = forwardGatewayPosture
          .replaceAll(RegExp(r'"inner_packets_delivered":\d+'),
              '"inner_packets_delivered":0')
          .replaceAll(RegExp(r'"delivered":\d+'), '"delivered":0');
      expect(noDeliveries, contains('"carrying":2'));
      expect(
          noDeliveries, contains('"session_states":["carrying","carrying"]'));

      final defects = winnRunEvidenceDefects(<String, String>{
        'gateway_posture.jsonl': noDeliveries,
      });
      final zero =
          defects.where((d) => d.code == 'delivered_counter_zero').toList();
      expect(
        zero,
        hasLength(1),
        reason: 'a forwarding gateway that has delivered nothing is not '
            'carriage however loudly its sessions say StateCarrying. Found: '
            '${defects.map((d) => d.code).join(", ")}',
      );
      expect(
        zero.single.detail,
        contains('carrying'),
        reason: 'and the defect must quote the state it is refusing to accept, '
            'so the reader sees WHY this is not a contradiction.',
      );
    });

    test(
        'MUTATION CONTROLS: each check goes red on its own break, and only '
        'on its own break', () {
      final good = readEvidence(linuxFullSet);
      expect(
          winnRunEvidenceDefects(<String, String>{linuxFullSet: good}), isEmpty,
          reason: 'no-mutation control.');
      expect(
        winnRunEvidenceDefects(<String, String>{
          linuxFullSet: '$good\n(reviewer note: prose, changes nothing)\n',
        }),
        isEmpty,
        reason: 'comment-only control: adding prose must not change a '
            'verdict, because prose is not a claim.',
      );

      final mutations = <String, List<Object>>{
        // code expected           regex                      replacement
        'loopback_far_end': <Object>[
          RegExp(r'"gateway_endpoint"\s*:\s*"[^"]*"'),
          '"gateway_endpoint": "127.0.0.1:46921"',
        ],
        'digest_match_full_set_false': <Object>[
          RegExp(r'"digest_match_full_set"\s*:\s*true'),
          '"digest_match_full_set": false',
        ],
        'digest_match_full_set_absent': <Object>[
          RegExp(r'"digest_match_full_set"\s*:\s*true'),
          '"digest_match_full_set_withdrawn": true',
        ],
        'rejection_counter_nonzero': <Object>[
          RegExp(r'"rx_dropped"\s*:\s*\d+'),
          '"rx_dropped": 5',
        ],
        'delivered_counter_zero': <Object>[
          RegExp(r'"(rx_datagrams_verified|rx_transport_payload_datagrams|'
              r'rx_datagrams)"\s*:\s*\d+'),
          '"rx_datagrams_verified": 0',
        ],
        'non_shipping_build_identifier': <Object>[
          RegExp(r'CLIENT / INITIATOR'),
          'CLIENT / INITIATOR package=org.winsvpn.devicecheck',
        ],
      };
      mutations.forEach((code, spec) {
        final mutated = good.replaceAll(spec[0] as RegExp, spec[1] as String);
        expect(
          mutated,
          isNot(good),
          reason: 'mutation for $code did not change the text, so this '
              'control proves nothing. Fix the pattern.',
        );
        final codes =
            winnRunEvidenceDefects(<String, String>{linuxFullSet: mutated})
                .map((d) => d.code)
                .toSet();
        expect(
          codes,
          contains(code),
          reason: 'breaking exactly one thing must produce $code. Got: '
              '${codes.join(", ")}',
        );
      });

      // The byte floor is checked separately, and in EACH DIRECTION on its
      // own. Criterion 5 says ">=4 MiB each direction"; a check that only
      // ever fires because the other direction was also short is not
      // checking "each". Starving one side at a time is what proves both
      // branches are load-bearing.
      List<WinnEvidenceDefect> starve(String key, int value) =>
          winnRunEvidenceDefects(<String, String>{
            linuxFullSet:
                good.replaceAll(RegExp('"$key"\\s*:\\s*\\d+'), '"$key": $value')
          });

      final txStarved = starve('tx_bytes', 706);
      expect(
        txStarved.where((d) => d.code == 'byte_floor_not_met').map(
              (d) => d.detail,
            ),
        anyElement(allOf(contains('sent:'), contains('706'))),
        reason: 'sent 706 bytes with the return direction untouched must '
            'still fail. Got: ${txStarved.join("; ")}',
      );
      final rxStarved = starve('rx_bytes', 172);
      expect(
        rxStarved.where((d) => d.code == 'byte_floor_not_met').map(
              (d) => d.detail,
            ),
        anyElement(allOf(contains('received:'), contains('172'))),
        reason: 'and so must 172 bytes back with the send direction '
            'untouched. Got: ${rxStarved.join("; ")}',
      );
    });

    test(
        'the loopback predicate covers the shapes an in-process far end '
        'actually takes', () {
      for (final loopback in const <String>[
        '127.0.0.1:46921',
        '127.1.2.3',
        'localhost:51833',
        '[::1]:51833',
        '::1',
        '0.0.0.0:51820',
        '[::]:40621',
      ]) {
        expect(winnEvidenceEndpointIsLoopback(loopback), isTrue,
            reason: '$loopback is a same-host far end.');
      }
      for (final real in const <String>[
        '192.168.50.104:51820',
        '203.0.113.9:51833',
        '198.51.100.4:57994',
        '[2001:db8::1]:51820',
        '8.8.8.8:53',
      ]) {
        expect(winnEvidenceEndpointIsLoopback(real), isFalse,
            reason: '$real is a real far end and must not be rejected.');
      }
    });

    test(
        'DRY RUN: the evidence set the runEvidence map already pins for '
        'Linux does NOT clear the content bar, and it is worth knowing why '
        'before promotion day', () {
      // This is the exact list the runEvidence map cites for 'linux'. Running
      // the checker over it today -- with the table all-absent, promoting
      // nothing -- is how this lane found out that CITING A CORPUS IS NOT
      // CITING A SESSION. The four files are three different runs: a clean
      // 4.001 MiB block, a 9.4 MiB bulk run that lost 2,800 datagrams to the
      // 802.11 hop, and a Flutter-app session. Pooled, the corpus asserts
      // digest_match_full_set BOTH true and false, and carries a nonzero
      // loss counter. A promotion bundle must therefore be ONE session.
      final defects = winnRunEvidenceDefectsForPaths(const <String>[
        '.winn_platform_progress/evidence/'
            'winn3_linux_20260806T194436Z_two_host_lan_gateway_session.txt',
        '.winn_platform_progress/evidence/'
            'winn3_linux_20260806T194436Z_gateway_far_end_timeline.txt',
        '.winn_platform_progress/evidence/'
            'winn3_linux_20260806T203726Z_flutter_app_shipping_path_session.txt',
        '.winn_platform_progress/evidence/'
            'winn3_linux_20260808_exact_4MiB_fullset.txt',
      ]);
      final codes = defects.map((d) => d.code).toSet();
      expect(
        codes,
        containsAll(<String>[
          'digest_match_full_set_false',
          'rejection_counter_nonzero',
        ]),
        reason: 'measured 2026-08-12. Found: '
            '${defects.map((d) => d.toString()).join("; ")}',
      );
      // Say precisely what it does NOT fail on, so nobody reads the line
      // above as "Linux never carried anything".
      expect(
        codes,
        isNot(contains('byte_floor_not_met')),
        reason: 'this corpus carries 18,855,751 / 18,840,188 bytes. The '
            'volume was never the problem.',
      );
      expect(codes, isNot(contains('loopback_far_end')));
      expect(codes, isNot(contains('non_shipping_build_identifier')));
      expect(codes, isNot(contains('delivered_counter_zero')));
    });

    test('the non-shipping identifier predicate is segment-exact', () {
      for (final bad in const <String>[
        'org.winsvpn.app.debug',
        'org.winsvpn.devicecheck',
        'group.org.winsvpn.devicecheck',
        'PacketTunnel.debug.dylib',
        'org.winsvpn.app.test',
      ]) {
        expect(winnEvidenceIdentifierIsNonShipping(bad), isTrue);
      }
      for (final fine in const <String>[
        'org.winsvpn.app',
        'org.winsvpn.app.PacketTunnel',
        'winn_protocol_dispatch_test.dart',
        'linux_winn_host.cc',
        'winn3_linux_20260808_exact_4MiB_fullset.txt',
      ]) {
        expect(winnEvidenceIdentifierIsNonShipping(fine), isFalse,
            reason: '$fine must not be mistaken for a debug variant.');
      }
    });
  });

  group('the two-sided evidence bundle: winn3-evidence-bundle/1', () {
    // Client counters alone cannot establish that anything left the device,
    // because the client is the thing under test. A bundle pairs them with
    // the gateway's own record of the same session and makes the join
    // MECHANICAL: one derived digest, one socket, one arithmetic identity,
    // one link type -- no human comparing timestamps.

    test('the payload derivation is deterministic and pinned', () {
      final seed = List<int>.generate(32, (i) => 0);
      expect(
        winnEvidencePayloadDatagram(seed, 0, 1252).length,
        1252,
        reason: 'a datagram is exactly payload_bytes_each bytes.',
      );
      const seedHex =
          '7fe16d012818f30787c33ba627bb4a89852985d9c0abb0fc75dde41d2b36c21f';
      final fixtureSeed = <int>[
        for (var i = 0; i < 64; i += 2)
          int.parse(seedHex.substring(i, i + 2), radix: 16),
      ];
      expect(
        winnEvidencePayloadDigestHex(fixtureSeed, 32, 4),
        'bff5bbb78c1be3f0393ec2377ddb0dce6b9a2de2b9058706afe0c3cb8ab49d81',
        reason: 'PINNED. This value was computed independently, outside '
            'Dart, from the written spec: datagram(i) is the first N bytes '
            'of SHA256(seed||u32be(i)||u32be(0)) || '
            'SHA256(seed||u32be(i)||u32be(1)) || ..., and the digest is '
            'SHA256 over datagrams 0..n-1 concatenated in order. If this '
            'assertion fails, the Dart implementation and the written spec '
            'have diverged and a cross-family verifier will disagree with '
            'this repository.',
      );
      expect(
        winnEvidencePayloadDigestHex(fixtureSeed, 1252, 3351),
        '7f5504e546fb247e949c6f761319c4009f8c3b2294dfa128f7c095a751c7f06c',
        reason: 'PINNED, at the real 4,195,452-byte block size. A verifier '
            'that regenerates the stream from payload_seed_hex must reach '
            'this digest without reading anything the client claimed.',
      );
    });

    test('the normative example is schema-valid', () {
      expect(
        winnEvidenceBundleShapeDefects(winnEvidenceBundleFixture())
            .map((d) => d.toString())
            .toList(),
        isEmpty,
        reason: 'the fixture IS the specification. If it does not validate, '
            'no lane can produce a bundle that does.',
      );
    });

    test('and is still refused as EVIDENCE, because no session produced it',
        () {
      final defects =
          winnEvidenceBundlePromotionDefects(winnEvidenceBundleFixture());
      expect(
        defects.map((d) => d.code).toList(),
        <String>['synthetic_bundle_marker'],
        reason: 'a schema fixture copied into the evidence directory must '
            'fail loudly rather than promote quietly. Found: '
            '${defects.map((d) => d.toString()).join("; ")}',
      );
    });

    test('a real-shaped bundle with the marker removed clears the bar', () {
      final manifest = winnEvidenceBundleFixture()
        ..remove('synthetic')
        ..['session_id'] = 'winn3-lab-session-0001';
      expect(
        winnEvidenceBundlePromotionDefects(manifest)
            .map((d) => d.toString())
            .toList(),
        isEmpty,
        reason: 'the bar has to be reachable, or the next lane weakens it '
            'instead of meeting it. Clearing this is NOT promotion: the flip '
            'is owner-reserved, and criteria 4 and 6 are declared here, not '
            'proven here.',
      );
    });

    test('MUTATION CONTROLS: each of the four joins fails closed', () {
      Map<String, Object?> base() => winnEvidenceBundleFixture()
        ..remove('synthetic')
        ..['session_id'] = 'winn3-lab-session-0001';

      Set<String> codesFor(void Function(Map<String, Object?> m) breakIt) {
        final m = base();
        breakIt(m);
        return winnEvidenceBundlePromotionDefects(m).map((d) => d.code).toSet();
      }

      expect(
        codesFor((m) => (m['correlation']! as Map)['inner_tx_bytes'] = 9999999),
        contains('join_volume_mismatch'),
        reason: 'join_volume: the byte total is tx_datagrams * '
            'payload_bytes_each, not a free parameter.',
      );
      expect(
        codesFor((m) => (m['gateway']! as Map)['observed_peer_port'] = 12345),
        contains('join_socket_mismatch'),
        reason: 'join_socket: the two artefacts must describe one socket.',
      );
      expect(
        codesFor((m) => (m['correlation']!
            as Map)['gateway_udp_payload_sha256'] = 'a' * 64),
        contains('join_digest_mismatch'),
        reason: 'join_digest: the gateway computes its own digest over what '
            'it received; if it differs from the client\'s, the client is '
            'not describing what crossed the wire.',
      );
      expect(
        codesFor((m) =>
            ((m['gateway']! as Map)['capture']! as Map)['link_type'] = 0),
        contains('join_link_loopback_capture'),
        reason: 'join_link: LINKTYPE_NULL is a loopback capture. This is a '
            'harder thing to fake than the absence of "127.0.0.1" in a log.',
      );
      expect(
        codesFor((m) =>
            ((m['gateway']! as Map)['capture']! as Map)['link_type'] = 108),
        contains('join_link_loopback_capture'),
        reason: 'LINKTYPE_LOOP is the BSD/macOS spelling of the same thing.',
      );
    });

    test('MUTATION CONTROLS: the bar itself fails closed', () {
      Map<String, Object?> base() => winnEvidenceBundleFixture()
        ..remove('synthetic')
        ..['session_id'] = 'winn3-lab-session-0001';

      Set<String> codesFor(void Function(Map<String, Object?> m) breakIt) {
        final m = base();
        breakIt(m);
        return winnEvidenceBundlePromotionDefects(m).map((d) => d.code).toSet();
      }

      expect(
        codesFor((m) =>
            (m['client']! as Map)['gateway_endpoint'] = '127.0.0.1:51833'),
        contains('loopback_far_end'),
      );
      expect(
        codesFor((m) => ((m['client']! as Map)['build']!
            as Map)['configuration'] = 'Debug'),
        contains('build_not_release'),
      );
      expect(
        codesFor((m) => ((m['client']! as Map)['build']! as Map)['app_id'] =
            'org.winsvpn.app.debug'),
        contains('non_shipping_build_identifier'),
      );
      expect(
        codesFor((m) => (m['gateway']! as Map)['host_id'] =
            (m['client']! as Map)['host_id']),
        contains('same_host_client_and_gateway'),
        reason: 'one machine is not a physical hop.',
      );
      expect(
        codesFor((m) => (m['correlation']! as Map)['delivered_packets'] = 0),
        contains('delivered_counter_zero'),
        reason: 'the iOS trap, expressed in manifest form.',
      );
      expect(
        codesFor((m) => ((m['correlation']! as Map)['rejection_counters']!
            as Map)['rx_dropped_invalid'] = 50),
        contains('rejection_counter_nonzero'),
      );
      expect(
        codesFor((m) => (m['gateway']! as Map)['artifacts'] = <String>[
              'gateway_summary.txt'
            ]),
        contains('no_gateway_side_raw_material'),
        reason: 'a summary is the gateway telling you its conclusion. The '
            'bundle needs its raw material.',
      );
      expect(
        codesFor((m) => (m['client']! as Map)['artifacts'] = <String>[
              'client_session.txt',
              'not_hashed.txt'
            ]),
        contains('artifact_unhashed'),
        reason: 'an artefact with no committed hash is one teardown away '
            'from the 2026-08-08 "genuine but uncheckable" run.',
      );
      expect(
        codesFor(
            (m) => (m['correlation']! as Map)['digest_match_full_set'] = false),
        contains('digest_match_full_set_false'),
      );
      // A SHORT session that is internally consistent must still be refused.
      // Shrinking the volume alone would also trip join_volume_mismatch, so
      // this shrinks datagrams and bytes together: the floor has to fire on
      // its own merits, not as a side effect of an arithmetic break.
      final shortSession = codesFor((m) {
        final c = m['correlation']! as Map;
        c['tx_datagrams'] = 100;
        c['inner_tx_bytes'] = 125200;
        c['inner_rx_bytes'] = 125200;
        c['delivered_packets'] = 100;
      });
      expect(shortSession, contains('byte_floor_not_met'));
      expect(
        shortSession,
        isNot(contains('join_volume_mismatch')),
        reason: '100 * 1252 == 125200, so the arithmetic still holds and the '
            'only thing wrong is that criterion 5 is a FLOOR.',
      );
      expect(
        codesFor((m) => (m['correlation']! as Map).remove('payload_seed_hex')),
        contains('missing_field'),
        reason: 'without the seed a second family cannot re-derive the '
            'digest, and the whole cross-family path collapses to reading '
            'the first family\'s number back.',
      );
      expect(
        codesFor(
            (m) => (m['correlation']! as Map)['payload_seed_hex'] = 'not-hex'),
        contains('bad_field'),
      );
    });

    test(
        'any bundle manifest committed under the evidence directory is '
        'schema-valid', () {
      const evidenceDir = '.winn_platform_progress/evidence';
      final dir = Directory(evidenceDir);
      expect(dir.existsSync(), isTrue,
          reason: '$evidenceDir is where committed evidence lives.');
      var checked = 0;
      for (final entity in dir.listSync()) {
        if (entity is! File) continue;
        if (!entity.path.endsWith('.json')) continue;
        if (entity.path.contains('.bak_')) continue;
        final objects = winnEvidenceJsonObjects(entity.readAsStringSync());
        for (final object in objects) {
          if (object['bundle_format'] == null) continue;
          checked++;
          expect(
            winnEvidenceBundleShapeDefects(object)
                .map((d) => d.toString())
                .toList(),
            isEmpty,
            reason: '${entity.path} declares itself a bundle manifest but '
                'does not validate.',
          );
        }
      }
      // Honest, and deliberately not asserted as a number: as of 2026-08-12
      // there are ZERO bundles, because no winn/3 session has ever run to the
      // bar on any platform and no forwarding gateway exists to run one
      // against. `checked` is reported so this test cannot silently become a
      // green that checked nothing once bundles do appear.
      expect(checked, greaterThanOrEqualTo(0));
    });
  });

  group('the refusal names exactly the platforms that really work', () {
    test('the supported-platform list is the table, not a hardcoded string',
        () {
      expect(
        winnSupportedPlatforms(),
        kWinnHostCapabilities.entries
            .where((e) => e.value.supported)
            .map((e) => e.key)
            .toList()
          ..sort(),
      );
    });

    test('the refusal message names every supported platform', () {
      // The failure this catches: a lane turns macOS on and the copy still
      // tells a Mac user to go find an Android phone. Deriving the sentence
      // makes that impossible rather than merely unlikely.
      final decision = resolveWinnProtocolStart(
        operatingSystem: 'ios',
        config: validWinn3Config(),
      );
      expect(decision.reason, WinnRefusalReason.unsupportedPlatform);
      for (final platform in winnSupportedPlatforms()) {
        expect(
          decision.message.toLowerCase(),
          contains(platform.toLowerCase()),
          reason: '$platform can carry winn/3 but the refusal message does not '
              'tell the user that.',
        );
      }
    });

    test('the refusal message names no platform that cannot carry winn/3', () {
      final decision = resolveWinnProtocolStart(
        operatingSystem: 'windows',
        config: validWinn3Config(),
      );
      final message = decision.message.toLowerCase();
      for (final entry in kWinnHostCapabilities.entries) {
        if (entry.value.supported) continue;
        expect(
          message,
          isNot(contains(_platformDisplayNameForTest(entry.key).toLowerCase())),
          reason: '${entry.key} cannot carry winn/3, so offering it to the '
              'user is an instruction that cannot work.',
        );
      }
    });

    test('the sentence reads correctly for one, two and three platforms', () {
      // winnSupportedPlatformsSentence is what the user reads. Exercise its
      // joining directly so the copy is not first seen when a platform lands.
      //
      // 2026-08-08: this asserted 'Android or Linux'. Both entries were
      // demoted by docs/handoff/ADJUDICATION_20260808.md, so the live table
      // now exercises the EMPTY branch, and that is what the user actually
      // reads today. Pin it -- an empty supported set producing a sentence
      // that still named a platform would be the same class of lie as the
      // capability claim itself.
      expect(winnSupportedPlatformsSentence(), 'no platform in this build');
    });

    test(
        'the joining logic still reads correctly for one, two and three '
        'names, exercised directly', () {
      // The join branches used to get their coverage incidentally, from
      // whatever the table happened to contain. That was never real coverage
      // -- it tested the table, not the joiner -- and with an empty table it
      // is no coverage at all. Exercise the pure function over a synthetic
      // list instead, so the copy a user will read on the day a platform
      // lands is proven now rather than first seen then.
      expect(
          winnPlatformsSentence(const <String>[]), 'no platform in this build');
      expect(winnPlatformsSentence(const <String>['android']), 'Android');
      expect(winnPlatformsSentence(const <String>['android', 'linux']),
          'Android or Linux');
      expect(
        winnPlatformsSentence(const <String>['android', 'linux', 'macos']),
        'Android, Linux or macOS',
      );
    });
  });

  group('protocol_params are honoured or refused, never ignored', () {
    test('post-quantum material this build cannot use is a refusal', () {
      // The reason this matters: the Linux Winn path is direct-awg carrying
      // AmneziaWG outer datagrams. datapath.Config has no ML-KEM field, so
      // starting a session while dropping this parameter would advertise
      // post-quantum support the client does not have.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{
            'mlkem768_public_key': 'BASE64',
            'kem_ciphertext': 'BASE64',
          },
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.unhonourableProtocolParams);
      expect(decision.message, contains('kem_ciphertext'));
      expect(decision.message, contains('mlkem768_public_key'));
    });

    test('the known parameters are the ones WinnEngineConfig accepts', () {
      // If this set ever grows a key that WinnEngineConfig.from does not
      // accept, the native host will throw at connect time instead. Written out
      // literally rather than composed from the library's own constants, so
      // this catches an accidental widening of either set.
      expect(
        kWinnKnownProtocolParams,
        <String>{
          'gateway_endpoint',
          'max_datagram',
          'session_id',
          'carrier',
          // The carrier profile fields. Every one is a PUBLIC transport
          // parameter; no key material has a slot here, because the profile
          // names secrets by path and the paths are device-local.
          'masque_template',
          'public_target',
          'server_name',
          'suite',
          'controller_id',
          'device_id',
          'device_pq_algorithm',
          'manifest_digest',
          'sequence_epoch',
          'max_inner_datagram',
          'privacy_profile',
          // The single-packet-authorization fields. Also all public: a mode, an
          // address to send one datagram to, and three timing scalars that must
          // match the gate. The KEY itself is not here and cannot be -- it is
          // named by a device-local path the control plane never chooses. See
          // carrierhost.TestSPAKeyPathIsNeverServed, which enforces that on the
          // schema side.
          'spa_mode',
          'spa_target',
          'spa_packet_size',
          'spa_bucket_window_seconds',
          'spa_max_skew_seconds',
        },
      );
    });

    test('no known parameter is a slot for key material', () {
      // The profile names the device ML-DSA seed and the client private key by
      // PATH, and those paths are device-local. If a key-shaped parameter ever
      // appears here, a gateway could put material into a session by serving a
      // config, which is the property this asserts is absent.
      for (final param in kWinnKnownProtocolParams) {
        expect(
          param,
          isNot(matches(
              RegExp(r'(seed|private|secret|_key$|^key|passphrase|token)'))),
          reason: '$param looks like a slot for key material; the carrier '
              'profile names secrets by path instead, and those paths are '
              'resolved on the device.',
        );
      }
    });

    test('gateway_endpoint overrides server_endpoint', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{
            'gateway_endpoint': '198.51.100.9:1234',
          },
      );
      expect(decision.supported, isTrue);
      expect(parseWinnSection(decision.iniSection)['endpoint'],
          '198.51.100.9:1234');
    });

    test('max_datagram is passed through when in range and refused when not',
        () {
      final ok = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{'max_datagram': 1400},
      );
      expect(ok.supported, isTrue);
      expect(parseWinnSection(ok.iniSection)['max_datagram'], '1400');

      for (final bad in const [31, 1501, 0, -1]) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] = <String, dynamic>{'max_datagram': bad},
        );
        expect(decision.supported, isFalse, reason: 'max_datagram $bad');
        expect(decision.reason, WinnRefusalReason.maxDatagramOutOfRange);
      }
    });

    test('an over-long or INI-forging session_id is refused', () {
      final long = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{
            'session_id': 'x' * (kWinnMaxSessionIdBytes + 1),
          },
      );
      expect(long.supported, isFalse);
      expect(long.reason, WinnRefusalReason.sessionIdTooLong);

      // A newline in a value would let the gateway append arbitrary INI keys
      // to the section -- including keys in the sections that follow it.
      final forged = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{
            'session_id': 'abc\nendpoint = 192.0.2.1:9',
          },
      );
      expect(forged.supported, isFalse);
    });

    test('a session_id within bounds is emitted verbatim', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{'session_id': 'sess-42'},
      );
      expect(decision.supported, isTrue);
      expect(parseWinnSection(decision.iniSection)['session_id'], 'sess-42');
    });

    test('an absent session_id emits no session_id key at all', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config(),
      );
      expect(parseWinnSection(decision.iniSection).containsKey('session_id'),
          isFalse);
    });
  });

  group('gateway endpoint must be an IP literal, never resolved here', () {
    test('a hostname is refused rather than looked up', () {
      // Resolving it here would put a DNS query on the unprotected path before
      // the tunnel exists, which is exactly why datapath refuses one.
      for (final host in const [
        'gateway.example.net:51820',
        'localhost:51820',
        'example.com:1',
      ]) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()..['server_endpoint'] = host,
        );
        expect(decision.supported, isFalse, reason: host);
        expect(decision.reason, WinnRefusalReason.gatewayEndpointNotIpLiteral);
      }
    });

    test('IPv4 and bracketed IPv6 literals with ports are accepted', () {
      expect(isWinnIpLiteralEndpoint('203.0.113.7:51820'), isTrue);
      expect(isWinnIpLiteralEndpoint('[2001:db8::1]:51820'), isTrue);
    });

    test('unusable literals are refused the way the engine refuses them', () {
      for (final endpoint in const [
        '', // absent
        '203.0.113.7', // no port
        '203.0.113.7:0', // zero port
        '203.0.113.7:70000', // out of range
        '0.0.0.0:51820', // unspecified
        '239.1.2.3:51820', // multicast
        '[ff02::1]:51820', // multicast v6
        '2001:db8::1:51820', // unbracketed v6
        '203.0.113.256:51820', // out-of-range octet
        '203.0.113.007:51820', // leading-zero octet
        '203.0.113.7:+51820', // leading plus; hub isdigit / Go ParseAddrPort
        '[1:::2]:51820', // invalid IPv6 the old group scanner accepted
        '[::ffff:0.0.0.0]:51820', // IPv4-mapped unspecified
        '[::ffff:224.0.0.1]:51820', // IPv4-mapped multicast
        '[fe80::1%lo0]:51820', // zone id
      ]) {
        expect(
          isWinnIpLiteralEndpoint(endpoint),
          isFalse,
          reason: '"$endpoint" is not a routable unicast IP literal with a '
              'nonzero port; datapath.validateIPLiteralEndpoint refuses it.',
        );
      }
    });
  });

  group('AmneziaWG header types come from the obfuscation the AWG engine uses',
      () {
    test('the emitted h1..h4 are the served obfuscation H1..H4', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['obfuscation'] = <String, dynamic>{
            'H1': 101,
            'H2': 202,
            'H3': 303,
            'H4': 404,
          },
      );
      final section = parseWinnSection(decision.iniSection);
      expect(section['h1'], '101');
      expect(section['h2'], '202');
      expect(section['h3'], '303');
      expect(section['h4'], '404');
    });

    test('missing obfuscation is now REFUSED — h1..h4 are mandatory for winn/3',
        () {
      // WINN_MANDATORY_HEADERS 2026-08-08: h1..h4 are REQUIRED for winn/3.
      // A blind classifier disables the transport convergence gate forever
      // (transport_observed_both_ways can never fire). The hub always serves all
      // four, so this cannot fleet-lockout; old test expected silent defaulting
      // to 11/22/33/44, which hid a disabled gate behind a working-looking tunnel.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()..remove('obfuscation'),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.headerTypesInvalid);
      expect(decision.message.toLowerCase(), contains('h1'));
      expect(decision.iniSection, isEmpty);
    });

    test('non-distinct header types are refused, not silently carried', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['obfuscation'] = <String, dynamic>{
            'H1': 11,
            'H2': 11,
            'H3': 33,
            'H4': 44,
          },
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.headerTypesInvalid);
    });

    test('out-of-range header types are refused', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['obfuscation'] = <String, dynamic>{
            'H1': 11,
            'H2': 22,
            'H3': 33,
            'H4': 0x1FFFFFFFF,
          },
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.headerTypesInvalid);
    });
  });

  group('MTU and transport conflicts', () {
    test('an MTU the native host would reject is refused here first', () {
      for (final mtu in const [0, 100, 575, 9001, 100000]) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()..['mtu'] = mtu,
        );
        expect(decision.supported, isFalse, reason: 'mtu $mtu');
        expect(decision.reason, WinnRefusalReason.mtuOutOfRange);
      }
    });

    test('the stealth Xray transport and Winn cannot both carry one tunnel',
        () {
      // VpnTunnelService.onStartCommand refuses this combination natively.
      // Refusing it here means the user gets a sentence instead of a service
      // that starts and immediately tears itself down.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()..['stealth_active'] = true,
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.stealthTransportConflict);
    });

    // ---- the stacked "stealth-chain" arrangement -------------------------
    //
    // The opt-in above it must stay opt-in: every test in this group that does
    // not name `winn_outer_transport` describes a config some hub could serve
    // today, and none of them may change behaviour.

    test('the chained value is accepted and points Winn at the Xray inbound',
        () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: stealthChainConfig(),
      );
      expect(decision.supported, isTrue,
          reason: 'The explicit stealth-chain value plus a usable Xray leg is '
              'the one arrangement in which Winn and Xray do not compete.');
      final section = parseWinnSection(decision.iniSection);
      expect(section['endpoint'], '127.0.0.1:42110',
          reason: 'The Winn engine drives the Xray inbound, not the gateway. '
              'Sending to the gateway instead would be the plain direct-awg '
              'session the censor already drops, while the config said '
              'stealth.');
      expect(section['carrier'], kWinnCarrierDirectAwg);
      expect(section['enabled'], 'true');
    });

    test('the chained section is one the native parser still accepts', () {
      // The loopback endpoint must survive the same independent check every
      // other emitted section is held to: WinnEngineConfig.from throws on a
      // bad endpoint or an unknown key rather than dropping it, so a section
      // this client emits and that host rejects is a connect-time crash.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: stealthChainConfig(),
      );
      expect(decision.supported, isTrue);
      expect(
        kotlinWinnConfigRejectionReason(
          parseWinnSection(decision.iniSection),
          mtu: 1280,
        ),
        isNull,
      );
    });

    test('a served gateway_endpoint does not escape the chain', () {
      // A hub that serves both the chained value and a real gateway endpoint
      // must not get a direct-awg session wearing a stealth label.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: stealthChainConfig()
          ..['protocol_params'] = <String, dynamic>{
            'gateway_endpoint': '203.0.113.7:51820',
          },
      );
      expect(decision.supported, isTrue);
      expect(
          parseWinnSection(decision.iniSection)['endpoint'], '127.0.0.1:42110');
    });

    test('stealth_active alone still refuses, with the chain implemented', () {
      // The regression this whole change exists NOT to introduce. Same config
      // as the refusal test above; asserted again here so a future edit to the
      // chained branch cannot quietly widen it into the default.
      for (final value in <Object?>[
        null,
        '',
        'direct-awg',
        'stealth-chained'
      ]) {
        final config = validWinn3Config()
          ..['stealth_active'] = true
          ..['xray'] = <String, dynamic>{
            'enabled': true,
            'local_port': 42110,
          };
        if (value != null) config[kWinnOuterTransportKey] = value;
        final decision = resolveWinnProtocolStartForServedConfig(
          config: config,
        );
        expect(decision.supported, isFalse, reason: 'value $value');
        expect(decision.reason, WinnRefusalReason.stealthTransportConflict,
            reason: 'value $value');
      }
    });

    test('the chained value without a leg to stack on is refused', () {
      // Each of these asked for the stack and cannot carry it. None may fall
      // through to a direct-awg start.
      final cases = <String, Map<String, dynamic>>{
        'no stealth_active': validWinn3Config()
          ..[kWinnOuterTransportKey] = kWinnOuterTransportStealthChain
          ..['xray'] = <String, dynamic>{'enabled': true, 'local_port': 42110},
        'no xray section': validWinn3Config()
          ..[kWinnOuterTransportKey] = kWinnOuterTransportStealthChain
          ..['stealth_active'] = true,
        'xray disabled': validWinn3Config()
          ..[kWinnOuterTransportKey] = kWinnOuterTransportStealthChain
          ..['stealth_active'] = true
          ..['xray'] = <String, dynamic>{'enabled': false, 'local_port': 42110},
        'no local_port': validWinn3Config()
          ..[kWinnOuterTransportKey] = kWinnOuterTransportStealthChain
          ..['stealth_active'] = true
          ..['xray'] = <String, dynamic>{'enabled': true},
        'local_port out of range': validWinn3Config()
          ..[kWinnOuterTransportKey] = kWinnOuterTransportStealthChain
          ..['stealth_active'] = true
          ..['xray'] = <String, dynamic>{'enabled': true, 'local_port': 70000},
      };
      cases.forEach((name, config) {
        final decision =
            resolveWinnProtocolStartForServedConfig(config: config);
        expect(decision.supported, isFalse, reason: name);
        expect(decision.reason, WinnRefusalReason.stealthTransportConflict,
            reason: name);
      });
    });

    test('the chain refuses a carrier other than direct-awg', () {
      // An authenticated carrier dials its own transport to the endpoint it is
      // given. Pointed at a local Xray inbound it would reach nothing, and it
      // would not be the session the gateway negotiated either way.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: stealthChainConfig()
          ..['protocol_params'] = <String, dynamic>{
            'carrier': kWinnCarrierHttp3,
          },
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.stealthTransportConflict);
    });

    test('winnConfigUsesStealthChain is what main.dart may branch on', () {
      // lib/main.dart uses exactly this to decide whether the AmneziaWG peer
      // endpoint names the real gateway (chained, rewritten to the Winn seam
      // natively) or the Xray inbound (v1 stealth). It must agree with the
      // resolver, and it must stay false for a winn/1 config no matter what
      // else is set.
      expect(winnConfigUsesStealthChain(stealthChainConfig()), isTrue);
      expect(
        winnConfigUsesStealthChain(
            validWinn3Config()..['stealth_active'] = true),
        isFalse,
      );
      expect(
        winnConfigUsesStealthChain(
            stealthChainConfig()..['protocol_version'] = kWinnProtocolV1),
        isFalse,
        reason: 'A v1 config takes the v1 stealth path, whatever the hub set.',
      );
      expect(winnConfigUsesStealthChain(validWinn3Config()), isFalse);
    });

    test('the section builder needs no chain branch of its own', () {
      // The second anti-downgrade gate derives from resolveWinnProtocolStart,
      // which is the point of its design: it gained the chained arrangement
      // without being touched. winnSectionForTunnelConfig returns
      // `decision.iniSection` verbatim once its platform gate passes, so with
      // every platform .absent since 2026-08-08 the derivation is exercised
      // one call inwards -- same bytes, no capability claim required.
      final chained =
          resolveWinnProtocolStartForServedConfig(config: stealthChainConfig());
      expect(chained.supported, isTrue, reason: chained.message);
      expect(chained.iniSection, contains('endpoint = 127.0.0.1:42110'));

      final unchained = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()..['stealth_active'] = true,
      );
      expect(
        unchained.supported,
        isFalse,
        reason: 'stealth_active without the explicit value is still a refusal.',
      );
      expect(unchained.reason, WinnRefusalReason.stealthTransportConflict);
      // And the outer gate still THROWS rather than returning an empty
      // section, which is the property that actually prevents the downgrade.
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'linux',
          config: validWinn3Config()..['stealth_active'] = true,
        ),
        throwsStateError,
      );
    });
  });

  group('the emitted section is one the native parser accepts', () {
    test('a valid start passes an independent WinnEngineConfig.from check', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{
            'max_datagram': 1400,
            'session_id': 'sess-1',
          },
      );
      expect(decision.supported, isTrue);
      expect(
        kotlinWinnConfigRejectionReason(
          parseWinnSection(decision.iniSection),
          mtu: 1280,
        ),
        isNull,
        reason: 'The section this client emits must satisfy the rules '
            'WinnEngineConfig.from applies, or the tunnel throws on the '
            'device instead of failing here.',
      );
    });

    test('the section emits no key the native parser would reject', () {
      // WinnEngineConfig.from throws on ANY key outside its own set rather
      // than dropping it, so an extra key here is a connect-time crash.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = <String, dynamic>{'session_id': 's'},
      );
      const accepted = <String>{
        'enabled',
        'endpoint',
        'carrier',
        'session_id',
        'max_datagram',
        'masque_template',
        'public_target',
        'server_name',
        'suite',
        'controller_id',
        'device_id',
        'device_pq_algorithm',
        'manifest_digest',
        'sequence_epoch',
        'max_inner_datagram',
        'privacy_profile',
        'h1',
        'h2',
        'h3',
        'h4',
        's1',
        's2',
        's3',
        's4',
      };
      expect(parseWinnSection(decision.iniSection).keys,
          everyElement(isIn(accepted)));
    });

    test('the section header is exactly the one the native host looks for', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config(),
      );
      expect(decision.iniSection.split('\n').first, '[$kWinnConfigSection]');
      expect(kWinnConfigSection, 'winn');
    });

    test('the section carries no AmneziaWG peer Endpoint line', () {
      // VpnTunnelService strips [winn] before handing the config to the AWG
      // engine, and WinnAwgLoopbackSeam.redirectPeerEndpoint then requires
      // EXACTLY ONE line whose key is "Endpoint". The [winn] key is lowercase
      // "endpoint" and lives in a stripped section, but a stray "Endpoint ="
      // here would be a second one if the strip order ever changed.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config(),
      );
      final endpointKeyLines = decision.iniSection
          .split('\n')
          .where((line) => line.split('=').first.trim() == 'Endpoint');
      expect(endpointKeyLines, isEmpty);
    });
  });

  group('winn/1 stays a strict no-op', () {
    test('an absent, blank or null protocol_version normalizes to winn/1', () {
      expect(normalizedWinnProtocolVersion(null), kWinnProtocolV1);
      expect(normalizedWinnProtocolVersion(''), kWinnProtocolV1);
      expect(normalizedWinnProtocolVersion('   '), kWinnProtocolV1);
      expect(normalizedWinnProtocolVersion(' winn/1 '), kWinnProtocolV1);
    });

    test('an unknown version is preserved, not coerced to a known one', () {
      // The dispatch switch has to be able to tell "winn/4" from "winn/1", or
      // a future protocol would silently take the AmneziaWG path.
      expect(normalizedWinnProtocolVersion('winn/4'), 'winn/4');
      expect(normalizedWinnProtocolVersion('winn/3'), kWinnProtocolV3);
      expect(normalizedWinnProtocolVersion('WINN/3'), 'WINN/3');
    });
  });

  group('the carrier is carried, never assumed', () {
    Map<String, dynamic> carrierParams({
      String carrier = kWinnCarrierHttp3,
      Map<String, dynamic> overrides = const <String, dynamic>{},
      Set<String> drop = const <String>{},
    }) {
      final params = <String, dynamic>{
        'carrier': carrier,
        'masque_template':
            'https://carrier.example/.well-known/masque/udp/{target_host}/{target_port}/',
        'public_target': '198.51.100.20:51820',
        'server_name': 'gateway.example',
        'suite': 'x25519-mlkem768',
        'controller_id': 'controller-1',
        'device_id': 'device-1',
        'device_pq_algorithm': 'mldsa65',
        'manifest_digest': 'a' * 64,
        ...overrides,
      };
      for (final key in drop) {
        params.remove(key);
      }
      return params;
    }

    test('an absent carrier still means direct-awg, and is emitted as such',
        () {
      // Every config served before the carrier field existed must behave
      // exactly as it did, and must say so rather than leave it implied.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config(),
      );
      expect(decision.supported, isTrue);
      expect(
        parseWinnSection(decision.iniSection)['carrier'],
        kWinnCarrierDirectAwg,
      );
    });

    test(
        'every winn/3 [winn] section this library emits names its carrier, '
        'and a winn/3 section cannot be emitted without one', () {
      // The carrier decides whether the session performs the post-quantum
      // carrier handshake or carries AmneziaWG datagrams straight to the
      // gateway, so it is the ONE value a reader of a captured [winn] section
      // needs to tell a direct-awg session from an authenticated one. For that
      // reason the emitted section must ALWAYS carry it: the library resolves
      // a carrier on every start (`_resolvedCarrier` normalizes an absent
      // value to direct-awg) and names that resolution in the document rather
      // than leaving it implied by an absence (lib/winn_protocol_dispatch.dart:
      // "carrier = $resolvedCarrier" is emitted unconditionally, and the
      // standalone branch emits "carrier = winn3").
      //
      // Two halves, so this is not a vacuous positive:
      //
      //  1. POSITIVE -- every served relay carrier resolves on its own merits
      //     and reaches the [winn] section named exactly as resolved, never
      //     dropped and never substituted.
      //  2. NEGATIVE -- a config that reaches the start gate with NO carrier
      //     at all still emits a carrier line (`direct-awg`). A startable
      //     winn/3 section with no carrier line cannot be produced, because
      //     such a section is ambiguous between direct-awg and a truncated
      //     one.
      //
      // `winn3` is the STANDALONE carrier and is reachable only through the
      // signed-descriptor path, which the dedicated standalone group below
      // pins (its emitted section asserts `carrier = winn3`); this loop drives
      // the two relay carriers through the served-config resolver that emits
      // every non-descriptor config.
      final relayCarriers =
          kWinnCarrierProfileCarriers.union(<String>{kWinnCarrierDirectAwg});
      expect(relayCarriers, isNotEmpty,
          reason: 'the resolver under test must have a reachable carrier to '
              'drive; winn3 is handled by the standalone group.');

      for (final carrier in relayCarriers) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] = carrierParams(carrier: carrier),
        );
        expect(decision.supported, isTrue,
            reason: 'relay carrier $carrier must resolve on its own merits: '
                '${decision.reason.code} ${decision.message}');
        expect(
          parseWinnSection(decision.iniSection)['carrier'],
          carrier,
          reason: 'the emitted [winn] section must name the carrier it '
              'resolved ($carrier), not omit it and not substitute a different '
              'one. A section that silently ran another carrier is exactly the '
              'downgrade this constant emission exists to prevent.',
        );
      }

      // The absent-carrier case is the one most likely to regress: every
      // config served before the carrier field existed lands here, and the
      // tempting "fix" is to leave the carrier implied rather than emit it.
      final absent = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config(),
      );
      expect(absent.supported, isTrue, reason: absent.message);
      expect(
        parseWinnSection(absent.iniSection)['carrier'],
        kWinnCarrierDirectAwg,
        reason: 'an absent served carrier must still resolve to AND emit '
            'direct-awg. Omitting the carrier line from a startable winn/3 '
            'section produces a document a reader cannot tell from a truncated '
            'one, so the omission is exactly the ambiguity this unconditional '
            'emission exists to prevent.',
      );
    });

    test('a complete http3 carrier reaches the section intact', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()..['protocol_params'] = carrierParams(),
      );
      expect(decision.supported, isTrue);
      final section = parseWinnSection(decision.iniSection);
      expect(section['carrier'], kWinnCarrierHttp3);
      expect(section['suite'], 'x25519-mlkem768');
      expect(section['public_target'], '198.51.100.20:51820');
      expect(section['manifest_digest'], 'a' * 64);
      expect(section['device_pq_algorithm'], 'mldsa65');
      // And the native parser accepts what was emitted.
      expect(
        kotlinWinnConfigRejectionReason(section, mtu: 1280),
        isNull,
      );
    });

    test('http2 is refused rather than downgraded, and says why', () {
      // The engine implements http2-stream. The refusal is a HOST capability:
      // its dialer takes a connected, protected TCP socket and this host opens
      // an unconnected UDP one.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = carrierParams(carrier: kWinnCarrierHttp2),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.carrierUnsupported);
      expect(decision.iniSection, isEmpty);
    });

    test('an unknown carrier is refused, never resolved to direct-awg', () {
      for (final carrier in const <String>[
        'reality-xhttp',
        'websocket-tls',
        'quic-masque-v2',
        'DIRECT-AWG-2',
      ]) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] = carrierParams(carrier: carrier),
        );
        expect(decision.supported, isFalse, reason: carrier);
        expect(decision.reason, WinnRefusalReason.carrierUnsupported);
      }
    });

    test('a carrier missing any required field is refused by name', () {
      for (final field in kWinnRequiredCarrierParams) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] = carrierParams(drop: <String>{field}),
        );
        expect(decision.supported, isFalse, reason: field);
        expect(decision.reason, WinnRefusalReason.carrierProfileIncomplete);
        expect(decision.message, contains(field));
      }
    });

    // ------------------------------- single packet authorization (SPA)

    Map<String, dynamic> spaParams({
      Map<String, dynamic> overrides = const <String, dynamic>{},
      Set<String> drop = const <String>{},
      String carrier = kWinnCarrierHttp3,
    }) =>
        carrierParams(
          carrier: carrier,
          overrides: <String, dynamic>{
            'spa_mode': 'required',
            'spa_target': '198.51.100.20:9111',
            'spa_packet_size': '256',
            'spa_bucket_window_seconds': '10',
            'spa_max_skew_seconds': '60',
            ...overrides,
          },
          drop: drop,
        );

    /// THE HEADLINE TEST. Every served knock parameter reaches the `[winn]`
    /// section this library emits, unmodified.
    ///
    /// Before this change `kWinnCarrierProfileParams` was a hand-typed list
    /// that excluded every `spa_` key, so a config carrying these five was
    /// REFUSED outright as an unknown protocol_param -- single packet
    /// authorization could not be delivered to any platform from here.
    test('every spa_ parameter survives into the [winn] section', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()..['protocol_params'] = spaParams(),
      );
      expect(decision.supported, isTrue, reason: decision.message);
      final section = parseWinnSection(decision.iniSection);
      expect(section['spa_mode'], 'required');
      expect(section['spa_target'], '198.51.100.20:9111');
      expect(section['spa_packet_size'], '256');
      expect(section['spa_bucket_window_seconds'], '10');
      expect(section['spa_max_skew_seconds'], '60');
    });

    /// `spa_key_path` is device-local and can never be served. A control plane
    /// able to choose it would be choosing which file the engine opens.
    test('spa_key_path is not a served parameter and is refused', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = carrierParams(overrides: <String, dynamic>{
            'spa_key_path': '/etc/winn/spa/spa.keys',
          }),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.unhonourableProtocolParams);
      expect(decision.message, contains('spa_key_path'));
    });

    /// A config naming no `spa_` param emits none, which is what makes adding
    /// these fields safe for every config already being served.
    test('a config without spa_ params emits no spa_ line', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()..['protocol_params'] = carrierParams(),
      );
      expect(decision.supported, isTrue);
      expect(decision.iniSection, isNot(contains('spa_')));
    });

    /// A stray `spa_` field without the mode is a REFUSAL, not a silent drop.
    /// The engine refuses it too (`ErrSPAFieldWithoutMode`); refusing here
    /// names the field before a socket has been opened.
    test('an spa_ field without spa_mode = required is refused', () {
      for (final stray
          in kWinnSpaCarrierProfileKeys.where((k) => k != 'spa_mode')) {
        for (final mode in <String>['', 'off']) {
          final decision = resolveWinnProtocolStartForServedConfig(
            config: validWinn3Config()
              ..['protocol_params'] =
                  carrierParams(overrides: <String, dynamic>{
                if (mode.isNotEmpty) 'spa_mode': mode,
                stray: stray == 'spa_target' ? '198.51.100.20:9111' : '10',
              }),
          );
          expect(decision.supported, isFalse, reason: '$stray/$mode');
          expect(decision.reason, WinnRefusalReason.spaParamsUnhonourable);
          expect(decision.message, contains(stray));
        }
      }
    });

    /// SPA rides only the HTTP/3 carrier. `knockdial.New` refuses anything but
    /// a packet-socket dialer AT CONSTRUCTION, and `direct-awg` has no carrier
    /// dialer at all, so neither can ever knock.
    test('spa_mode = required is refused on any carrier but http3', () {
      for (final carrier in <String>[
        kWinnCarrierDirectAwg,
        kWinnCarrierHttp2
      ]) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] = spaParams(carrier: carrier),
        );
        expect(decision.supported, isFalse, reason: carrier);
        // http2 is refused as an unsupported carrier before SPA is even
        // considered; direct-awg reaches the SPA gate. Either way the
        // connection stops rather than starting an unknocked session.
        expect(
          decision.reason,
          anyOf(
            WinnRefusalReason.spaParamsUnhonourable,
            WinnRefusalReason.carrierUnsupported,
          ),
          reason: carrier,
        );
      }
    });

    test('an unknown spa_mode is refused, never treated as off', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] =
              spaParams(overrides: <String, dynamic>{'spa_mode': 'advisory'}),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.spaParamsUnhonourable);
    });

    /// There is deliberately no default target: the gate may sit in front of
    /// the carrier listener or in front of the AmneziaWG gateway, and a wrong
    /// guess sends the deployment's shared credential to the wrong host.
    test('spa_target is required and must be an IP literal', () {
      for (final bad in <String>[
        'gate.example:9111',
        '198.51.100.20',
        '0.0.0.0:9111',
        '198.51.100.20:0',
      ]) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] =
                spaParams(overrides: <String, dynamic>{'spa_target': bad}),
        );
        expect(decision.supported, isFalse, reason: bad);
        expect(decision.reason, WinnRefusalReason.spaParamsUnhonourable);
      }
      final missing = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = spaParams(drop: <String>{'spa_target'}),
      );
      expect(missing.supported, isFalse);
      expect(missing.reason, WinnRefusalReason.spaParamsUnhonourable);
    });

    /// A knock must fit in ONE unfragmented datagram: a censor that already
    /// drops or flags fragmented UDP would make the knock a worse fingerprint
    /// than having no SPA at all.
    test('spa_packet_size is bounded by one datagram', () {
      for (final bad in <String>['47', '1501', '-1', 'lots']) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] =
                spaParams(overrides: <String, dynamic>{'spa_packet_size': bad}),
        );
        expect(decision.supported, isFalse, reason: bad);
        expect(decision.reason, WinnRefusalReason.spaParamsUnhonourable);
      }
    });

    /// A skew narrower than the bucket produces a knock that silently never
    /// verifies, which looks identical to a wrong key -- the single most likely
    /// misconfiguration of this whole mechanism.
    test('freshness settings that could never verify are refused', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = spaParams(overrides: <String, dynamic>{
            'spa_bucket_window_seconds': '60',
            'spa_max_skew_seconds': '10',
          }),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.spaParamsUnhonourable);
    });

    /// The optional scalars may be omitted; the engine derives them.
    test('spa_mode and spa_target alone are a complete SPA config', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = spaParams(drop: <String>{
            'spa_packet_size',
            'spa_bucket_window_seconds',
            'spa_max_skew_seconds',
          }),
      );
      expect(decision.supported, isTrue, reason: decision.message);
      final section = parseWinnSection(decision.iniSection);
      expect(section['spa_mode'], 'required');
      expect(section.containsKey('spa_packet_size'), isFalse);
    });

    /// An spa_ value cannot forge an INI key either -- same rule as every other
    /// carrier parameter, because they all come from the same verbatim
    /// pass-through.
    test('an spa_ value cannot forge an INI key or a section header', () {
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = spaParams(overrides: <String, dynamic>{
            'spa_target': '198.51.100.20:9111\nendpoint = 203.0.113.99:51820',
          }),
      );
      expect(decision.supported, isFalse);
    });

    // -------------------------------------- client capability advertisement

    /// The migration lever. A client may only claim it can knock when the
    /// platform can carry `winn/3` AND the knock key is actually on the device.
    test('the SPA capability is false unless the key is really provisioned',
        () {
      // BOTH halves are required, and since 2026-08-08 the platform half is
      // false everywhere: the adjudication demoted the last two `.present`
      // entries, so no build advertises supports_winn3_spa to the hub at all.
      //
      // That is a real behaviour change and the right one. This flag is what
      // a client tells the control plane about itself; advertising a knock
      // capability the client cannot then carry would invite exactly the
      // production-first winn/3 start the demotion exists to prevent.
      const allFalse = <String, bool>{
        'supports_winn3': false,
        'supports_winn3_descriptor': false,
        'supports_winn3_spa': false,
        'supports_winn3_dualauth': false,
      };
      for (final os in const ['android', 'ios', 'linux', 'macos', 'windows']) {
        for (final key in const [true, false]) {
          expect(
            winnClientCapabilities(operatingSystem: os, spaKeyProvisioned: key),
            allFalse,
            reason: '$os (key provisioned: $key): no platform can carry '
                'winn/3 today, so none may advertise the SPA capability. If '
                'this fails because a platform was re-promoted, the flags '
                'start flowing to the hub -- make sure that is intended.',
          );
        }
      }
      // The key half is still independently load-bearing, and stays pinned so
      // a re-promotion cannot make the capability true on the platform alone.
      // Asserted against the real predicate rather than a hardcoded platform,
      // so this keeps working in either direction.
      for (final entry in kWinnHostCapabilities.entries) {
        expect(
          winnClientCapabilities(
              operatingSystem: entry.key, spaKeyProvisioned: false),
          allFalse,
          reason: '${entry.key}: without the knock key on the device the '
              'capability is false regardless of what the table says. This '
              'is the case that would otherwise become "capability reports '
              'success while carrying nothing".',
        );
        expect(
          winnClientCapabilities(
              operatingSystem: entry.key,
              spaKeyProvisioned: true)['supports_winn3_spa'],
          entry.value.supported,
          reason: '${entry.key}: with the key present, the capability must '
              'track kWinnHostCapabilities exactly -- never a second, '
              'divergent notion of which platforms are supported.',
        );
      }
    });

    /// NEGATIVE direction of the gate, at the client. A host that cannot carry
    /// `winn/3` -- an old v1-era client, or iOS while `kWinnHostCapabilities`
    /// says `.absent` -- may not advertise a single flag that could make the
    /// hub serve winn/3, no matter what else is provisioned on the device.
    /// This is the client half of "an old client can NEVER receive a winn/3
    /// config": the hub defaults every one of these flags to false, so a client
    /// that says nothing (old) and a client that says "cannot carry" (new) get
    /// the same byte-for-byte winn/1 config.
    test('an incapable host advertises nothing that could earn it winn/3', () {
      for (final ring in const [false, true]) {
        final flags = winnClientCapabilityFlags(
          hostCanCarryWinn3: false,
          spaKeyProvisioned: true,
          descriptorRingCarried: ring,
        );
        expect(flags['supports_winn3'], isFalse,
            reason: 'a host that cannot carry any winn/3 must never advertise '
                'supports_winn3, even with the descriptor ring present. That '
                'flag is the one the hub requires before it will serve winn/3.');
        expect(flags['supports_winn3_descriptor'], isFalse,
            reason: 'ring=$ring: the descriptor flag is downstream of the host '
                'datapath; it must not be claimed without it.');
        expect(flags['supports_winn3_spa'], isFalse,
            reason: 'a host that cannot carry winn/3 cannot knock for it '
                'either, regardless of key provisioning.');
        expect(flags[kWinnClientCapabilityDualAuth], isFalse,
            reason: 'a host that cannot carry winn/3 cannot consume dual-auth '
                'keys either, even if a release define were flipped.');
      }
      // The live product today: iOS is `.absent`, so the shipping iOS binary
      // advertises supports_winn3=false and the hub can never serve it winn/3.
      expect(kWinnHostCapabilities['ios']!.supported, isFalse,
          reason: 'if iOS is ever re-promoted, this changes and every '
              'advertisement test below flips with it -- that is intended and '
              'must be a loud, reviewed change.');
      final ios = winnClientCapabilities(
          operatingSystem: 'ios',
          spaKeyProvisioned: true,
          descriptorRingCarried: true);
      expect(ios['supports_winn3'], isFalse);
      expect(ios['supports_winn3_descriptor'], isFalse);
      expect(ios['supports_winn3_spa'], isFalse);
      expect(ios[kWinnClientCapabilityDualAuth], isFalse);
    });

    /// POSITIVE direction of the gate, at the client. A host that CAN carry
    /// `winn/3` may advertise it, and only the additional facts on top --
    /// the descriptor verifier ring, the SPA key -- make the narrower flags
    /// true. Keeping the two halves pure means the eligible direction is
    /// provable without a platform being `.present` in `kWinnHostCapabilities`
    /// today.
    test('a capable host advertises exactly the winn/3 flags it can honour',
        () {
      final withEverything = winnClientCapabilityFlags(
        hostCanCarryWinn3: true,
        spaKeyProvisioned: true,
        descriptorRingCarried: true,
        dualAuthHostSupported: true,
      );
      expect(withEverything['supports_winn3'], isTrue);
      expect(withEverything['supports_winn3_descriptor'], isTrue);
      expect(withEverything['supports_winn3_spa'], isTrue);
      expect(withEverything[kWinnClientCapabilityDualAuth], isTrue);

      // Descriptor verification needs the ring, not just the host.
      final ringless = winnClientCapabilityFlags(
        hostCanCarryWinn3: true,
        spaKeyProvisioned: true,
        descriptorRingCarried: false,
      );
      expect(ringless['supports_winn3'], isTrue,
          reason: 'the host datapath is enough for AWG-carried winn/3.');
      expect(ringless['supports_winn3_descriptor'], isFalse,
          reason: 'a build with no compiled verifier ring cannot consume a '
              'signed gateway descriptor; advertising it would invite a '
              'descriptor the client then refuses fail-closed.');
      expect(ringless['supports_winn3_spa'], isTrue);
      expect(ringless[kWinnClientCapabilityDualAuth], isFalse,
          reason: 'dual-auth keys ride the signed descriptor; a ringless '
              'build cannot consume them.');

      // The knock needs the key, not just the host.
      final keyless = winnClientCapabilityFlags(
        hostCanCarryWinn3: true,
        spaKeyProvisioned: false,
        descriptorRingCarried: true,
      );
      expect(keyless['supports_winn3'], isTrue);
      expect(keyless['supports_winn3_descriptor'], isTrue);
      expect(keyless['supports_winn3_spa'], isFalse,
          reason: 'a client with no knock key would be served spa_*, name a '
              'key file that is not there, and fail every connection -- '
              '"capability reports success while carrying nothing".');
      expect(
        winnClientCapabilityFlags(
          hostCanCarryWinn3: true,
          spaKeyProvisioned: true,
          descriptorRingCarried: true,
          dualAuthHostSupported: false,
        )[kWinnClientCapabilityDualAuth],
        isFalse,
        reason: 'a host that does not emit both attestation keys must not '
            'advertise supports_winn3_dualauth.',
      );
    });

    /// The compiled-in default is fail-closed: with no `WINS_WINN3_DESCRIPTOR_PUBKEY_*`
    /// define, `winnClientCapabilities` must default `supports_winn3_descriptor`
    /// to false, so a capability that the shipping binary literally cannot
    /// honour is never advertised merely by omission of an argument.
    test('the descriptor capability defaults to the compiled ring state', () {
      // The ring is compiled in by the L4 dual-signature glue (2026-08-20),
      // so the capability wrapper must AGREE it is carried, never default
      // optimistic for a ring that is absent -- and explicitly disabling the
      // ring must advertise no descriptor capability.
      expect(
        winnDescriptorVerificationRingCarried(),
        isTrue,
        reason: 'the dual-signature lane bakes the descriptor ring into the '
            'shipping build; the test-harness empty-ring premise is gone',
      );
      for (final entry in kWinnHostCapabilities.entries) {
        final flags = winnClientCapabilities(
          operatingSystem: entry.key,
          spaKeyProvisioned: true,
        );
        expect(
          flags['supports_winn3_descriptor'],
          entry.value.supported && winnDescriptorVerificationRingCarried(),
          reason: '${entry.key}: the default must be exactly what a build '
              'with this compiled ring can honour, never optimistic.',
        );
        expect(
          winnClientCapabilities(
            operatingSystem: entry.key,
            spaKeyProvisioned: true,
            descriptorRingCarried: false,
          )['supports_winn3_descriptor'],
          isFalse,
          reason: '${entry.key}: explicitly disabling the carried ring must '
              'advertise no descriptor capability.',
        );
      }
    });

    test('descriptor ring identity binds ordered slots and exact key bytes',
        () {
      final g1 = List<int>.generate(32, (index) => index);
      final g3 = List<int>.generate(32, (index) => 255 - index);
      final ring = Winn3DescriptorKeyRing.fromEncoded(<String, String>{
        'g3': base64.encode(g3),
        'g1': base64.encode(g1),
      });
      String hex(List<int> bytes) =>
          bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
      final expected = sha256
          .convert(utf8.encode('g1=${hex(g1)}\ng3=${hex(g3)}\n'))
          .toString();
      expect(ring.compiledSlotIds, <String>['g1', 'g3']);
      expect(ring.identitySha256, expected);
      expect(ring.attestsExpectedIdentity(expected), isTrue);
      expect(ring.attestsExpectedIdentity(List<String>.filled(64, '0').join()),
          isFalse);
      expect(ring.attestsExpectedIdentity('not-a-hash'), isFalse);
    });

    /// The capability tracks `kWinnHostCapabilities` rather than a second,
    /// drifting list of platforms -- for all three flags, not just SPA.
    test(
        'the winn/3 and descriptor capabilities follow kWinnHostCapabilities '
        'exactly', () {
      for (final platform in kWinnHostCapabilities.keys) {
        expect(
          winnClientCapabilities(
              operatingSystem: platform,
              spaKeyProvisioned: true,
              descriptorRingCarried: true)['supports_winn3'],
          platformSupportsWinnProtocol(platform),
          reason: platform,
        );
        expect(
          winnClientCapabilities(
              operatingSystem: platform,
              spaKeyProvisioned: true,
              descriptorRingCarried: true)['supports_winn3_descriptor'],
          platformSupportsWinnProtocol(platform),
          reason: platform,
        );
        expect(
          winnClientCapabilities(
              operatingSystem: platform,
              spaKeyProvisioned: true,
              descriptorRingCarried: true,
              dualAuthHostSupported: true)[kWinnClientCapabilityDualAuth],
          platformSupportsWinnProtocol(platform),
          reason: '$platform: dual-auth follows the same host table, plus the '
              'opt-in define passed here as true.',
        );
      }
    });

    test('a carrier value cannot forge an INI key or a section header', () {
      // protocol_params is handed through verbatim by the control plane, so a
      // carrier value is exactly as trustworthy as the served config. A
      // newline here would forge an `endpoint` line and redirect the tunnel.
      const injections = <String>[
        'gateway.example\nendpoint = 203.0.113.99:51820',
        'gateway.example\r\nenabled = false',
        'gateway.example[Peer]',
        'gateway.example]',
      ];
      for (final injection in injections) {
        final decision = resolveWinnProtocolStartForServedConfig(
          config: validWinn3Config()
            ..['protocol_params'] = carrierParams(
              overrides: <String, dynamic>{'server_name': injection},
            ),
        );
        expect(decision.supported, isFalse, reason: injection);
        expect(decision.reason, WinnRefusalReason.carrierProfileIncomplete);
      }
    });

    test('a forged endpoint never survives into the emitted section', () {
      // The mutation form of the test above: whatever the refusal says, the
      // one thing that must never happen is a second `endpoint` line.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = carrierParams(
            overrides: <String, dynamic>{
              'controller_id': 'c\nendpoint = 203.0.113.99:51820',
            },
          ),
      );
      expect(decision.supported, isFalse);
      final endpointLines = decision.iniSection
          .split('\n')
          .where((line) => line.split('=').first.trim() == 'endpoint');
      expect(endpointLines, isEmpty);
    });

    test(
        'winnSectionForTunnelConfig throws rather than emit a plain AWG '
        'config for a carrier it cannot start', () {
      // The second anti-downgrade gate. Returning '' here would produce an
      // AmneziaWG config with no [winn] section, which VpnTunnelService starts
      // as plain AmneziaWG -- the exact silent downgrade of a session the
      // gateway negotiated as an authenticated carrier.
      //
      // Since 2026-08-08 every platform is .absent, so this now throws at the
      // capability gate with `unsupported_platform` before it ever reaches the
      // carrier check. The THROW is the property that prevents the downgrade
      // and it is unchanged, so it is still asserted here; the carrier-specific
      // refusal is asserted one call inwards, where it is still reachable.
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'linux',
          config: validWinn3Config()
            ..['protocol_params'] = carrierParams(carrier: kWinnCarrierHttp2),
        ),
        throwsA(isA<StateError>().having(
          (e) => e.message,
          'message',
          anyOf(
            contains(WinnRefusalReason.carrierUnsupported.code),
            contains(WinnRefusalReason.unsupportedPlatform.code),
          ),
        )),
        reason: 'an unstartable winn/3 config must never yield a section, '
            'whichever refusal fires first.',
      );
      final decision = resolveWinnProtocolStartForServedConfig(
        config: validWinn3Config()
          ..['protocol_params'] = carrierParams(carrier: kWinnCarrierHttp2),
      );
      expect(decision.supported, isFalse);
      expect(
        decision.reason,
        WinnRefusalReason.carrierUnsupported,
        reason: 'http2 is refused as a CARRIER on its own merits, not merely '
            'as a side effect of every platform being absent today.',
      );
    });

    test('the RELAY carrier set mirrors WinnEngineConfig', () {
      // Read off WinnEngineConfig.SUPPORTED_CARRIERS by hand. http2-stream is
      // absent on purpose and must stay absent until the host opens a
      // connected, protected TCP socket for it.
      //
      // `winn3` is deliberately NOT compared against that Kotlin set, and this
      // is not a loosened assertion. WinnEngineConfig is the RELAY engine's
      // config -- an AmneziaWG engine whose outer datagrams Winn carries -- and
      // a standalone session contains no such engine. Android routes a
      // standalone start through WinnV3SessionPlan/WinnV3Keys at
      // VpnTunnelService.startWinnV3EngineThread, never through
      // WinnEngineConfig.from, so `winn3` appearing in SUPPORTED_CARRIERS would
      // claim the relay engine can build a session it has no code for.
      expect(
        kWinnCarrierProfileCarriers.union(<String>{kWinnCarrierDirectAwg}),
        <String>{'direct-awg', 'http3-connect-udp'},
        reason: 'the relay carriers must mirror WinnEngineConfig exactly.',
      );
      expect(kWinnSupportedCarriers, isNot(contains(kWinnCarrierHttp2)));
    });

    test('winn3 is the standalone carrier and needs no carrier profile', () {
      expect(kWinnCarrierWinn3, 'winn3',
          reason: 'must equal WinsTunnelConfig.supportedWinnCarrierWinn3, '
              'WinsWinn3.carrierName, the Go archive winn3Carrier and the '
              "control plane's WINN3_CARRIER_WINN3.");
      expect(kWinnSupportedCarriers, contains(kWinnCarrierWinn3));
      expect(kWinnCarrierProfileCarriers, isNot(contains(kWinnCarrierWinn3)),
          reason: 'a standalone session dials its own transport with its own '
              'handshake and reads no MASQUE profile.');
      expect(
          kWinnCarrierProfileCarriers, isNot(contains(kWinnCarrierDirectAwg)));
      expect(kWinnCarrierProfileCarriers, contains(kWinnCarrierHttp3));
    });
  });

  // ==========================================================================
  // THE STANDALONE PATH: the signed descriptor and the [winn] section it feeds
  // ==========================================================================
  //
  // Every test here is really the same test: a v3 gateway NEVER ANSWERS a
  // datagram it could not authenticate, so each way of getting the standalone
  // config wrong produces a session that starts, reports up, and is ignored
  // forever -- which on a censored network is indistinguishable from the
  // gateway being blocked. There is no observation that distinguishes them
  // from outside, so the only defence is refusing by name before the start.
  group('the standalone winn/3 config', () {
    late SimpleKeyPair signingKey;
    late String publicKeyB64;

    setUp(() async {
      signingKey = await Ed25519().newKeyPair();
      final pub = await signingKey.extractPublicKey();
      publicKeyB64 = base64.encode(pub.bytes);
    });

    Winn3DescriptorKeyRing ringWith({String slot = 'g1'}) =>
        Winn3DescriptorKeyRing.fromEncoded(<String, String>{
          slot: publicKeyB64,
        });

    Map<String, dynamic> descriptorPayload({
      int v = kWinn3DescriptorFormatVersion,
      String kid = 'g1',
      String node = 'lab-alpha',
      String endpoint = '203.0.113.7:51820',
      String innerRouterV4 = '10.10.0.1',
      String gatewayId = 'winsgw01',
      String admissionSecretHex = 'ab',
      int iat = 1786000000,
      int ttl = 86400,
      Map<String, dynamic> overrides = const <String, dynamic>{},
    }) =>
        <String, dynamic>{
          'v': v,
          'alg': 'ed25519',
          'kid': kid,
          'node': node,
          'endpoint': endpoint,
          'inner_router_v4': innerRouterV4,
          'inner_resolver_v4': innerRouterV4,
          'static_pub': base64.encode(List<int>.filled(32, 0x53)),
          // base64 OVER THE OPERATOR'S GATEWAY-NAME TEXT, which is exactly what
          // the hub validates and exactly what the engine ends up keying with
          // after the host's single decode.
          'gateway_id': base64.encode(utf8.encode(gatewayId)),
          // base64 over the key file's 64 ASCII HEX CHARACTERS. NOT base64 of
          // the 32 decoded bytes -- that is the defect that builds a session
          // and then goes silent.
          'admission_secret':
              base64.encode(utf8.encode(admissionSecretHex * 32)),
          'admission_gen': 1,
          'tag_size': 32,
          'padding': 'bucket',
          'bucket_window_s': 10,
          'max_skew_s': 60,
          'seq': 1,
          'iat': iat,
          'not_after': iat + ttl,
          ...overrides,
        };

    Future<Map<String, dynamic>> envelopeFor(
      Map<String, dynamic> payload,
    ) async {
      final raw = utf8.encode(json.encode(payload));
      final message = <int>[
        ...utf8.encode(kWinn3DescriptorDomain),
        0x00,
        ...raw,
      ];
      final signature = await Ed25519().sign(message, keyPair: signingKey);
      return <String, dynamic>{
        'payload': base64.encode(raw),
        'sig': base64.encode(signature.bytes),
      };
    }

    /// A served config that CAN start a standalone session.
    Future<Map<String, dynamic>> standaloneConfig({
      Map<String, dynamic>? payload,
      Map<String, dynamic> overrides = const <String, dynamic>{},
    }) async {
      final config = validWinn3Config()
        ..['protocol_params'] = <String, dynamic>{'carrier': kWinnCarrierWinn3}
        ..['winn3_descriptor'] =
            await envelopeFor(payload ?? descriptorPayload())
        ..['winn3_inner_v4'] = '10.10.4.9'
        ..['winn3_static_private'] = base64.encode(List<int>.filled(32, 0x11));
      config.addAll(overrides);
      return config;
    }

    DateTime insideLifetime() =>
        DateTime.fromMillisecondsSinceEpoch(1786000100 * 1000, isUtc: true);

    Map<String, String> iniPairs(String section) {
      final pairs = <String, String>{};
      for (final line in section.split('\n')) {
        final idx = line.indexOf('=');
        if (idx < 0) continue;
        pairs[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
      }
      return pairs;
    }

    test('a verified descriptor plus device material emits every required key',
        () async {
      final config = await standaloneConfig();
      final check = await verifyWinn3Descriptor(
          config: config, ring: ringWith(), now: insideLifetime());
      expect(check.verified, isTrue, reason: check.reason);

      final decision = resolveWinnProtocolStartForServedConfig(
          config: config, winn3Descriptor: check);
      expect(decision.supported, isTrue,
          reason: '${decision.reason.code}: ${decision.message}');

      final pairs = iniPairs(decision.iniSection);
      expect(decision.iniSection.split('\n').first, '[winn]');
      // The eight keys a standalone start requires, by name.
      expect(pairs['enabled'], 'true');
      expect(pairs['carrier'], 'winn3');
      expect(pairs['endpoint'], '203.0.113.7:51820');
      expect(pairs['node'], 'lab-alpha');
      expect(pairs['selected_node'], 'lab-alpha');
      expect(pairs['inner_v4'], '10.10.4.9');
      expect(pairs['inner_router_v4'], '10.10.0.1');
      expect(
          pairs['static_private'], base64.encode(List<int>.filled(32, 0x11)));
      expect(
          pairs['gateway_static'], base64.encode(List<int>.filled(32, 0x53)));
      expect(pairs['gateway_id'], isNotNull);
      expect(pairs['admission_key'], isNotNull);

      // NO AmneziaWG PARAMETERS. There is no AmneziaWG engine in a standalone
      // session; emitting h1..h4 would make the document indistinguishable
      // from a relay one, and WinsTunnelConfig selects the AmneziaWG loopback
      // seam on exactly that shape.
      for (final key in const <String>[
        'h1',
        'h2',
        'h3',
        'h4',
        's1',
        's2',
        's3',
        's4',
        'max_datagram',
      ]) {
        expect(pairs.containsKey(key), isFalse,
            reason: '$key describes a component a standalone session does not '
                'contain.');
      }
    });

    test(
        'dual-auth keys are omitted, not refused, when the native host has not opted in',
        () async {
      final config = await standaloneConfig(
        payload: descriptorPayload(overrides: <String, dynamic>{
          'auth_ed25519': base64.encode(List<int>.filled(32, 0x21)),
          'auth_mldsa65': base64.encode(List<int>.filled(1952, 0x22)),
        }),
      );
      final check = await verifyWinn3Descriptor(
        config: config,
        ring: ringWith(),
        now: insideLifetime(),
      );
      expect(check.verified, isTrue, reason: check.reason);
      expect(check.descriptor!.hasDualAuth, isTrue);

      final decision = resolveWinnProtocolStartForServedConfig(
        config: config,
        winn3Descriptor: check,
      );
      expect(decision.supported, isTrue,
          reason: '${decision.reason.code}: ${decision.message}');
      final pairs = iniPairs(decision.iniSection);
      expect(pairs.containsKey('auth_ed25519'), isFalse);
      expect(pairs.containsKey('auth_mldsa65'), isFalse);
      expect(pairs['carrier'], 'winn3');
    });

    test('the signed descriptor must name the selected served node', () async {
      final wrongNode = await standaloneConfig(
        overrides: <String, dynamic>{'node_slug': 'lab-beta'},
      );
      final wrongNodeCheck = await verifyWinn3Descriptor(
        config: wrongNode,
        ring: ringWith(),
        now: insideLifetime(),
      );
      expect(wrongNodeCheck.verified, isTrue, reason: wrongNodeCheck.reason);

      final wrongNodeDecision = resolveWinnProtocolStartForServedConfig(
        config: wrongNode,
        winn3Descriptor: wrongNodeCheck,
      );
      expect(wrongNodeDecision.supported, isFalse);
      expect(wrongNodeDecision.reason,
          WinnRefusalReason.winn3DescriptorNodeMismatch);

      final missingNode = await standaloneConfig()
        ..remove('node_slug');
      final missingNodeCheck = await verifyWinn3Descriptor(
        config: missingNode,
        ring: ringWith(),
        now: insideLifetime(),
      );
      expect(missingNodeCheck.verified, isTrue,
          reason: missingNodeCheck.reason);

      final missingNodeDecision = resolveWinnProtocolStartForServedConfig(
        config: missingNode,
        winn3Descriptor: missingNodeCheck,
      );
      expect(missingNodeDecision.supported, isFalse);
      expect(missingNodeDecision.reason,
          WinnRefusalReason.winn3DescriptorNodeMismatch);
    });

    test('a standalone carrier plan must include a UDP path', () async {
      for (final plan in const <String>['tcp', 'tls', 'tcp,tls']) {
        final config = await standaloneConfig(
          overrides: <String, dynamic>{'winn3_carrier_classes': plan},
        );
        final check = await verifyWinn3Descriptor(
            config: config, ring: ringWith(), now: insideLifetime());
        final decision = resolveWinnProtocolStartForServedConfig(
            config: config, winn3Descriptor: check);
        expect(decision.supported, isFalse, reason: plan);
        expect(decision.reason, WinnRefusalReason.winn3FieldMalformed,
            reason: plan);
        expect(decision.iniSection, isEmpty, reason: plan);
      }

      final config = await standaloneConfig(
        overrides: <String, dynamic>{'winn3_carrier_classes': 'udp,tls'},
      );
      final check = await verifyWinn3Descriptor(
          config: config, ring: ringWith(), now: insideLifetime());
      final decision = resolveWinnProtocolStartForServedConfig(
          config: config, winn3Descriptor: check);
      expect(decision.supported, isTrue,
          reason: '${decision.reason.code}: ${decision.message}');
    });

    test('gateway_id is passed through VERBATIM as base64, never decoded',
        () async {
      // TRAP 1. The engine takes the RAW OPERATOR-STRING BYTES and the decode
      // happens exactly once, in the host that reads descriptor-shaped fields.
      // A second decode here computes a different admission tag from the same
      // operator value, and NOTHING ON THE WIRE CATCHES IT: the tag is never
      // transmitted and the gateway does not answer what it cannot verify.
      //
      // `winsgw01` is the trigger from the real defect, and it is ordinary --
      // eight characters of the base64 alphabet, so the wrong answer is a
      // plausible-looking string rather than an obvious corruption.
      const operatorName = 'winsgw01';
      final encoded = base64.encode(utf8.encode(operatorName));
      final config = await standaloneConfig(
          payload: descriptorPayload(gatewayId: operatorName));
      final check = await verifyWinn3Descriptor(
          config: config, ring: ringWith(), now: insideLifetime());
      final decision = resolveWinnProtocolStartForServedConfig(
          config: config, winn3Descriptor: check);
      final pairs = iniPairs(decision.iniSection);

      expect(pairs['gateway_id'], encoded,
          reason: 'the DESCRIPTOR ENCODING must survive to the [winn] section '
              'untouched; the host owns the single decode.');
      expect(pairs['gateway_id'], isNot(operatorName),
          reason: 'decoding here would be the second decode, which is the '
              'gateway-id-is-raw-operator-bytes defect.');
      expect(check.descriptor!.gatewayIdOperatorText, operatorName,
          reason: 'the decode is available for VALIDATION, so a malformed '
              'value is a named refusal rather than a silent session.');
    });

    test('admission_key is the descriptor value, opaque and unre-encoded',
        () async {
      // TRAP 2. Both ends must key with the key file's 64 ASCII hex characters.
      // Shipping base64 of the 32 DECODED bytes keys one end with 32 against
      // the other's 64, and the gateway then ADMITS the datagram, BUILDS a
      // session, and goes completely silent -- so a host watching for "did the
      // gateway see me" sees yes.
      final payload = descriptorPayload();
      final served = payload['admission_secret'] as String;
      expect(base64.decode(served).length, 64,
          reason:
              'the fixture must carry the hex TEXT, not the decoded bytes.');

      final config = await standaloneConfig(payload: payload);
      final check = await verifyWinn3Descriptor(
          config: config, ring: ringWith(), now: insideLifetime());
      final decision = resolveWinnProtocolStartForServedConfig(
          config: config, winn3Descriptor: check);
      expect(iniPairs(decision.iniSection)['admission_key'], served,
          reason: 'byte for byte what the descriptor carried.');
    });

    test('an unverified, absent or forged descriptor refuses by name',
        () async {
      final config = await standaloneConfig();

      // (1) The caller forgot to verify. Refusing here is what makes the
      // asynchronous step impossible to skip silently.
      var decision = resolveWinnProtocolStartForServedConfig(config: config);
      expect(decision.reason, WinnRefusalReason.winn3DescriptorUnverified);
      expect(decision.iniSection, isEmpty);

      // (2) No descriptor served at all.
      final bare = await standaloneConfig();
      bare['winn3_descriptor'] = <String, dynamic>{};
      var check = await verifyWinn3Descriptor(
          config: bare, ring: ringWith(), now: insideLifetime());
      expect(check.verified, isFalse);
      expect(check.reason, 'no-descriptor-served');
      decision = resolveWinnProtocolStartForServedConfig(
          config: bare, winn3Descriptor: check);
      expect(decision.reason, WinnRefusalReason.winn3DescriptorUnverified);

      // (3) A payload edited after signing. This is the attack the client-side
      // verification exists for: a forged descriptor hands this client an
      // attacker's static key, admission secret and endpoint in one object.
      final forged = Map<String, dynamic>.from(
          config['winn3_descriptor'] as Map<String, dynamic>);
      final tampered = descriptorPayload(endpoint: '198.51.100.66:51820');
      forged['payload'] = base64.encode(utf8.encode(json.encode(tampered)));
      final forgedConfig = await standaloneConfig();
      forgedConfig['winn3_descriptor'] = forged;
      check = await verifyWinn3Descriptor(
          config: forgedConfig, ring: ringWith(), now: insideLifetime());
      expect(check.verified, isFalse);
      expect(check.reason, 'descriptor-signature-invalid');

      // (4) A signature that verifies under a DIFFERENT slot than it claims.
      // `kid` is inside the signed bytes, so accepting a moved signature would
      // make the slot field decorative.
      check = await verifyWinn3Descriptor(
          config: config, ring: ringWith(slot: 'g2'), now: insideLifetime());
      expect(check.verified, isFalse);
      expect(check.reason, 'descriptor-signature-invalid');

      // (5) A build with no compiled key cannot tell a real descriptor from a
      // forged one, so it says so instead of accepting one.
      check = await verifyWinn3Descriptor(
          config: config,
          ring: Winn3DescriptorKeyRing.fromEncoded(const <String, String>{}),
          now: insideLifetime());
      expect(check.verified, isFalse);
      expect(check.reason, 'descriptor-no-verification-keys-compiled');
    });

    test('a v1-format or expired descriptor is refused, not partially read',
        () async {
      var config = await standaloneConfig(payload: descriptorPayload(v: 1));
      var check = await verifyWinn3Descriptor(
          config: config, ring: ringWith(), now: insideLifetime());
      expect(check.verified, isFalse);
      expect(check.reason, 'descriptor-unsupported-format-version',
          reason: 'the format bump retires every descriptor signed before '
              'inner_router_v4 joined the signed field set.');

      // A cached config can outlive its descriptor -- the client fast-connects
      // from cache -- and the hub computes an admission-key retirement floor
      // from exactly this bound, so using an expired one risks keying with a
      // retired secret.
      config = await standaloneConfig();
      check = await verifyWinn3Descriptor(
          config: config,
          ring: ringWith(),
          now: DateTime.fromMillisecondsSinceEpoch((1786000000 + 86401) * 1000,
              isUtc: true));
      expect(check.verified, isFalse);
      expect(check.reason, 'descriptor-expired');
    });

    test('a missing or malformed device half refuses by its own name',
        () async {
      final check = await verifyWinn3Descriptor(
          config: await standaloneConfig(),
          ring: ringWith(),
          now: insideLifetime());

      for (final broken in <Map<String, dynamic>>[
        <String, dynamic>{'winn3_inner_v4': ''},
        <String, dynamic>{'winn3_static_private': ''},
      ]) {
        final config = await standaloneConfig(overrides: broken);
        final decision = resolveWinnProtocolStartForServedConfig(
            config: config, winn3Descriptor: check);
        expect(decision.reason, WinnRefusalReason.winn3DeviceMaterialMissing,
            reason: 'the device half fails for its own reasons and an '
                'operator reading a diagnostic needs to know which half.');
      }

      // An inner address from the WRONG SPACE. The winn/3 tun layer drops every
      // packet whose source does not match its assignment, so an AmneziaWG
      // address here is a session that starts and carries nothing.
      for (final bad in const <String>[
        '10.8.1.3', // the AmneziaWG address, which is the tempting mistake
        '127.0.0.1',
        '0.0.0.0',
        '224.0.0.1',
        '10.10.0.1', // the gateway's own next hop: the device as its own hop
        'not-an-address',
        '10.10.0.1:51820',
      ]) {
        final config = await standaloneConfig(overrides: <String, dynamic>{
          'winn3_inner_v4': bad,
        });
        final decision = resolveWinnProtocolStartForServedConfig(
            config: config, winn3Descriptor: check);
        expect(decision.supported, isFalse, reason: 'accepted $bad');
        expect(decision.iniSection, isEmpty);
      }
    });

    test('no standalone value can forge an INI key or a section header',
        () async {
      for (final poison in const <String>[
        'AAAA\nadmission_key = attacker',
        'AAAA\n[winn]',
        'AAAA\rendpoint = 198.51.100.66:51820',
      ]) {
        final config = await standaloneConfig(
            overrides: <String, dynamic>{'winn3_static_private': poison});
        final check = await verifyWinn3Descriptor(
            config: config, ring: ringWith(), now: insideLifetime());
        final decision = resolveWinnProtocolStartForServedConfig(
            config: config, winn3Descriptor: check);
        expect(decision.supported, isFalse);
        expect(decision.iniSection, isEmpty);
      }
    });

    test('a standalone session refuses to ride the stealth chain', () async {
      // The chain works by repointing AmneziaWG's peer endpoint at a local Xray
      // inbound. A standalone session has no AmneziaWG to repoint, and its own
      // dialer aimed at a loopback inbound would neither reach the gateway nor
      // be the session the gateway negotiated.
      final config = await standaloneConfig();
      final check = await verifyWinn3Descriptor(
          config: config, ring: ringWith(), now: insideLifetime());
      final chained = stealthChainConfig()
        ..['protocol_params'] = <String, dynamic>{'carrier': kWinnCarrierWinn3}
        ..['winn3_descriptor'] = config['winn3_descriptor']
        ..['winn3_inner_v4'] = config['winn3_inner_v4']
        ..['winn3_static_private'] = config['winn3_static_private'];
      final decision = resolveWinnProtocolStartForServedConfig(
          config: chained, winn3Descriptor: check);
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.stealthTransportConflict);
    });

    test(
        'winnSectionForTunnelConfig throws rather than emit a plain AWG '
        'config for a standalone session it cannot start', () async {
      // The second anti-downgrade gate. An AmneziaWG config with no [winn]
      // section is exactly what the native service starts as plain AmneziaWG,
      // which is the silent downgrade of a v3 negotiation.
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'linux',
          config: <String, dynamic>{
            ...validWinn3Config(),
            'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
          },
        ),
        throwsStateError,
      );
    });

    test('the inner-address rule matches the control plane exactly', () {
      for (final good in const <String>[
        '10.10.0.1',
        '10.10.4.9',
        '172.31.0.5',
        '192.168.9.9',
        '1.2.3.4',
      ]) {
        expect(isWinnInnerIpv4(good), isTrue, reason: good);
      }
      for (final bad in const <String>[
        '',
        '10.10.0',
        '10.10.0.1.5',
        '10.10.0.256',
        '10.10.0.01',
        '0.0.0.0',
        '0.1.2.3',
        '127.0.0.1',
        '224.0.0.1',
        '255.255.255.255',
        'fd00::1',
        '10.10.0.1:51820',
        ' ',
      ]) {
        expect(isWinnInnerIpv4(bad), isFalse, reason: '"$bad"');
      }
    });

    test('iOS resolves a standalone winn/3 start ONLY while truly carrying',
        () async {
      // The gate in lib/winn_protocol_dispatch.dart: iOS is a CONDITIONAL
      // capability. It may resolve a standalone winn/3 start decision -- but
      // only while its native host is GENUINELY CARRYING a winn/3 datapath,
      // never from a build flag and never because a served config happens to be
      // valid on its own. This is the "iOS reports winn/3-capable only when
      // truly carrying" property, asserted in both directions.

      // (1) A compiled/test build is NOT carrying: the predicate is false, and
      //     a fully valid standalone config must refuse at the capability wrap
      //     with an EMPTY section -- nothing that could start a tunnel.
      const notCarrying = false;
      expect(winn3IosReportsCarryingCapability(trulyCarrying: notCarrying),
          isFalse);

      final validConfig = await standaloneConfig();
      final check = await verifyWinn3Descriptor(
          config: validConfig, ring: ringWith(), now: insideLifetime());
      expect(check.verified, isTrue, reason: check.reason);

      final refused = resolveIosWinn3Start(
        config: validConfig,
        winn3Descriptor: check,
        trulyCarrying: notCarrying,
      );
      expect(refused.supported, isFalse,
          reason: 'iOS must not report winn/3-capable while it is not carrying '
              'a winn/3 datapath. Producing a start here is "capability '
              'reports success while carrying nothing".');
      expect(refused.reason, WinnRefusalReason.unsupportedPlatform);
      expect(refused.iniSection, isEmpty,
          reason: 'a refused iOS start must carry no [winn] section at all.');

      // (2) The SAME config, with the carrying fact true: iOS resolves the
      //     standalone start and emits the standalone [winn] section.
      final carried = resolveIosWinn3Start(
        config: validConfig,
        winn3Descriptor: check,
        trulyCarrying: true,
      );
      expect(carried.supported, isTrue,
          reason: '${carried.reason.code}: ${carried.message}');
      final pairs = iniPairs(carried.iniSection);
      expect(pairs['carrier'], kWinnCarrierWinn3);
      expect(pairs['enabled'], 'true');
      expect(pairs['inner_v4'], '10.10.4.9');

      // (3) NEGATIVE CONTROL: the carrying flag must NOT force-support a config
      //     that is otherwise invalid. With a FORGED descriptor, even a truly
      //     carrying iOS build must still refuse -- otherwise the gate would
      //     have been replaced by a constant (the recurring survivor shape).
      final forged = Map<String, dynamic>.from(
          validConfig['winn3_descriptor'] as Map<String, dynamic>);
      forged['payload'] = base64.encode(utf8.encode(
          json.encode(descriptorPayload(endpoint: '198.51.100.66:51820'))));
      final forgedConfig = await standaloneConfig();
      forgedConfig['winn3_descriptor'] = forged;
      final badCheck = await verifyWinn3Descriptor(
          config: forgedConfig, ring: ringWith(), now: insideLifetime());
      expect(badCheck.verified, isFalse);
      final stillRefused = resolveIosWinn3Start(
        config: forgedConfig,
        winn3Descriptor: badCheck,
        trulyCarrying: true,
      );
      expect(stillRefused.supported, isFalse,
          reason:
              'a carrying iOS host must still refuse a config whose gateway '
              'record is unverified; the carrying gate alone cannot make a '
              'standalone start resolve.');
      expect(stillRefused.iniSection, isEmpty);
    });

    test(
        'without the carrying fact iOS stays not winn/3-capable, and the '
        'capability advertisement tracks the same carrying fact', () async {
      // (a) The unconditional capability path still sees iOS as .absent -- the
      //     carrying fact is NOT leaked into kWinnHostCapabilities, so a call
      //     that does not route through the wrapping gate keeps refusing.
      expect(kWinnHostCapabilities['ios']!.supported, isFalse);
      final plain = resolveWinnProtocolStart(
        operatingSystem: 'ios',
        config: await standaloneConfig(),
      );
      expect(plain.supported, isFalse);
      expect(plain.reason, WinnRefusalReason.unsupportedPlatform);

      // (b) The client capability advertisement (what iOS would tell the hub)
      //     is derived from the SAME carrying fact, never a second list.
      //     Not carrying -> advertises no winn/3 flag at all.
      final notCarrying = winnClientCapabilityFlags(
        hostCanCarryWinn3:
            winn3IosReportsCarryingCapability(trulyCarrying: false),
        spaKeyProvisioned: true,
        descriptorRingCarried: true,
      );
      expect(notCarrying['supports_winn3'], isFalse);
      expect(notCarrying['supports_winn3_descriptor'], isFalse);
      expect(notCarrying['supports_winn3_spa'], isFalse);
      expect(notCarrying[kWinnClientCapabilityDualAuth], isFalse);
      // Carrying -> advertises exactly the winn/3 flags the host can honour.
      final carrying = winnClientCapabilityFlags(
        hostCanCarryWinn3:
            winn3IosReportsCarryingCapability(trulyCarrying: true),
        spaKeyProvisioned: true,
        descriptorRingCarried: true,
      );
      expect(carrying['supports_winn3'], isTrue);
      expect(carrying['supports_winn3_descriptor'], isTrue);
      expect(carrying['supports_winn3_spa'], isTrue);
      expect(carrying[kWinnClientCapabilityDualAuth], isFalse,
          reason: 'iOS leaves WINS_WINN3_DUAL_AUTH off, so even a carrying '
              'host must advertise supports_winn3_dualauth=false.');
    });
  });

  // ==========================================================================
  // THE DISPATCH PLATFORM MATRIX AS EXECUTABLE CLAIMS
  // ==========================================================================
  //
  // kWinnHostCapabilities is a prose-backed table and several functions read it.
  // These tests pin the OBSERVABLE consequences of the table so the readers
  // cannot drift from it or from each other: the predicate verdict, the client
  // capability advertisement (including the SPA half), and the resolve gate
  // over a winn/3 server that actually demands SPA. The expectations are
  // derived from the LIVE table, never a hardcoded all-false, so the day a
  // platform is honestly re-promoted these go red loudly and have to be
  // re-earned deliberately -- the same flip-back-bar shape the entries in
  // lib/winn_protocol_dispatch.dart require.
  group('the dispatch platform matrix as executable claims', () {
    test('platformSupportsWinnProtocol returns exactly the table verdict', () {
      // Each row is one platform column of the matrix. The expectation is
      // derived ONCE from the table, then every independent reader path is held
      // to it -- the predicate, the lookup, both capability flags and the
      // resolve gate. These are DIFFERENT code paths, so the row can only stay
      // green while all of them agree with the same table; a platform that is
      // `.present` in one reader and not in another splits the row and this
      // test names the platform and the cell that moved.
      //
      // Today every entry is `.absent`, so every row is all-false. The value is
      // the coupling, which stays armed and turns red the day one reader is
      // changed without the others.
      for (final os in const ['android', 'ios', 'macos', 'windows', 'linux']) {
        final expected = kWinnHostCapabilities[os]!.supported;
        final row = <String, bool>{
          'platformSupportsWinnProtocol': platformSupportsWinnProtocol(os),
          'winnHostCapability().supported': winnHostCapability(os).supported,
          'caps.supports_winn3 (key provisioned)': winnClientCapabilities(
              operatingSystem: os, spaKeyProvisioned: true)['supports_winn3']!,
          'caps.supports_winn3_spa (key provisioned)': winnClientCapabilities(
              operatingSystem: os,
              spaKeyProvisioned: true)['supports_winn3_spa']!,
          'resolveWinnProtocolStart().supported': resolveWinnProtocolStart(
                  operatingSystem: os, config: validWinn3Config())
              .supported,
          'winnSupportedPlatforms().contains':
              winnSupportedPlatforms().contains(os),
        };
        for (final cell in row.entries) {
          expect(
            cell.value,
            expected,
            reason: '$os ${cell.key}: every reader of the platform matrix must '
                'return the table\'s verdict for that platform (expected '
                '$expected). If kWinnHostCapabilities moved, this whole row '
                'must move together -- with the committed, content-asserting '
                're-promotion evidence the entries require -- not cell by cell.',
          );
        }
      }

      // The negative half of the matrix: a platform absent from the table is
      // unsupported (the fail-closed default), and a spaced or case-folded
      // spelling of a real platform still lands on the real row rather than on
      // the unknown-platform placeholder -- otherwise the tolerance is a
      // second, drifting notion of the matrix.
      for (final unknown in const <String>[
        'fuchsia',
        'freebsd',
        'hurd',
        '',
        '   ',
        'ANDROIDX',
      ]) {
        expect(
          platformSupportsWinnProtocol(unknown),
          isFalse,
          reason: '"$unknown" has no entry in kWinnHostCapabilities, so it '
              'cannot be supported. An absent platform is the fail-closed '
              'default and must never silently become an owned one.',
        );
      }
      for (final entry in kWinnHostCapabilities.entries) {
        expect(
          platformSupportsWinnProtocol(' ${entry.key.toUpperCase()} '),
          entry.value.supported,
          reason: '${entry.key}: a spaced/case-folded spelling must resolve to '
              'the real row, not to the unknown-platform default.',
        );
      }
    });

    test(
        'a winn/3 config that demands SPA resolves only when winn3-spa is '
        'provisioned', () {
      // The claim, stated plainly: the ONE workload a provisioned client is
      // ever asked to run -- a winn/3 config whose server demands a knock
      // (spa_mode = required) -- may only resolve to a start decision in the
      // world in which the client would advertise the `winn3-spa` capability.
      // And "winn3-spa is provisioned" means exactly TWO facts: the platform
      // carries winn/3 AND the knock key is really on this device. This test
      // pins both halves of that coupling, in both directions, so a capability
      // true on either half alone splits the row and goes red.

      // The served demand. Inline rather than the group-local spaParams()
      // helper, which is closed over by another group's tests.
      final served = validWinn3Config()
        ..['protocol_params'] = <String, dynamic>{
          'carrier': kWinnCarrierHttp3,
          'masque_template':
              'https://carrier.example/.well-known/masque/udp/{target_host}/{target_port}/',
          'public_target': '198.51.100.20:51820',
          'server_name': 'gateway.example',
          'suite': 'x25519-mlkem768',
          'controller_id': 'controller-1',
          'device_id': 'device-1',
          'device_pq_algorithm': 'mldsa65',
          'manifest_digest': 'a' * 64,
          'spa_mode': kWinnSpaModeRequired,
          'spa_target': '198.51.100.20:9111',
          'spa_packet_size': '256',
          'spa_bucket_window_seconds': '10',
          'spa_max_skew_seconds': '60',
        };

      // (1) FORWARD HALF. On their own merits these served params RESOLVE, and
      //     the emitted [winn] section carries the knock the engine will send.
      //     That is the execution a winn3-spa-provisioned client is actually
      //     asked to perform. Asserting it positive is what gives the negative
      //     halves below their meaning: if this forward path were refused, a
      //     true capability flag would be advertising something that cannot
      //     run.
      final forward = resolveWinnProtocolStartForServedConfig(config: served);
      expect(forward.supported, isTrue,
          reason: '${forward.reason.code}: ${forward.message}');
      expect(parseWinnSection(forward.iniSection)['spa_mode'],
          kWinnSpaModeRequired);
      expect(parseWinnSection(forward.iniSection)['spa_target'],
          '198.51.100.20:9111');

      // (2) THE PROVISIONING GATE, in both directions. The flag the hub reads
      //     is named exactly [kWinnClientCapabilitySpa]; its value is the
      //     platform verdict AND the device key -- never either half alone. A
      //     client with the platform but no key would be served spa_*, would
      //     name a key file that is not there, and would fail every connection;
      //     a client with a key but no winn/3 carrier would advertise a knock
      //     for a protocol it cannot carry. Both are "not provisioned".
      expect(kWinnClientCapabilitySpa, 'winn3-spa',
          reason: 'the capability string this test is about is what the hub '
              'keys on; if it drifts, the test stops being about "winn3-spa".');
      // The KEY half of "provisioned" must be load-bearing even where the
      // platform IS capable. Exercised through winnClientCapabilityFlags' pure
      // form (hostCanCarryWinn3 taken directly) so it is decidable TODAY --
      // in the live matrix every platform is `.absent`, so the matrix rows
      // below can only ever see the all-false face of the coupling and would
      // not, by themselves, distinguish a capability that dropped the key
      // requirement. A mutation deleting `&& spaKeyProvisioned` is a real,
      // dangerous one: it would advertise a knock to a keyless device. It must
      // go red here.
      expect(
        winnClientCapabilityFlags(
            hostCanCarryWinn3: true,
            spaKeyProvisioned: false,
            descriptorRingCarried: true)['supports_winn3_spa'],
        isFalse,
        reason: 'a winn/3-capable host with NO knock key is not winn3-spa '
            'provisioned. Advertising the capability would have the hub serve '
            'spa_* that names a key file which is not on the device, and every '
            'connection would fail -- "capability reports success while '
            'carrying nothing".',
      );
      expect(
        winnClientCapabilityFlags(
            hostCanCarryWinn3: true,
            spaKeyProvisioned: true,
            descriptorRingCarried: true)['supports_winn3_spa'],
        isTrue,
        reason: 'a winn/3-capable host WITH the knock key is exactly what '
            '"winn3-spa is provisioned" means.',
      );
      for (final entry in kWinnHostCapabilities.entries) {
        for (final key in const [false, true]) {
          final flags = winnClientCapabilities(
            operatingSystem: entry.key,
            spaKeyProvisioned: key,
          );
          expect(
            flags['supports_winn3_spa'],
            platformSupportsWinnProtocol(entry.key) && key,
            reason: '${entry.key} key=$key: supports_winn3_spa must equal the '
                'platform verdict AND the device key, in lockstep. True on the '
                'platform alone would have the hub serve the knock to a device '
                'that cannot send it; true on the key alone advertises winn/3 '
                'on a platform that cannot carry it -- the "capability reports '
                'success while carrying nothing" failure this matrix exists to '
                'prevent.',
          );
        }
      }

      // (3) THE RESOLUTION HALF, on the production route.
      //     resolveWinnProtocolStart is the ONE gate a real connect goes
      //     through, and no platform in the matrix is provisioned today (every
      //     entry is `.absent`), so the SPA demand must refuse on EVERY
      //     platform, carrying no [winn] section a tunnel could be started
      //     from.
      //
      //     THIS IS A DELIBERATE FLIP-BACK SPEED BUMP. The day a platform is
      //     honestly re-promoted, this expectation starts failing for that
      //     platform, and the correct response is a conscious one: decide,
      //     with the re-promotion evidence the entries require, whether that
      //     device's SPA key is actually written (main.dart's
      //     `_winnSpaKeyProvisioned` is the single provisioning fact). Do not
      //     delete this expectation just to make the bar green.
      for (final entry in kWinnHostCapabilities.entries) {
        final gated = resolveWinnProtocolStart(
            operatingSystem: entry.key, config: served);
        expect(
          gated.supported,
          isFalse,
          reason: '${entry.key}: no platform in this matrix is provisioned for '
              'winn/3 (every entry is .absent), so a config that demands a '
              'knock must not resolve to a start anywhere -- resolving here is '
              'the silent start-without-knocking this gate refuses.',
        );
        expect(gated.iniSection, isEmpty,
            reason: '${entry.key}: a refused start must carry no section a '
                'tunnel could be started from.');
        expect(
          gated.reason,
          WinnRefusalReason.unsupportedPlatform,
          reason: '${entry.key}: the SPA demand is refused at the platform '
              'gate, which is exactly "not provisioned" as the capability '
              'advertisement sees it.',
        );
      }
    });
  });
}
