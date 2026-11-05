/// Per-network memory of whether the direct AmneziaWG UDP leg produced a
/// working tunnel, used to decide whether that leg should still LEAD the
/// connect attempt on this network.
///
/// ## Why this exists
///
/// The client tries transports strictly in order: direct AmneziaWG over UDP,
/// then the CDN-fronted TCP transports. Only the UDP leg reaches the gateway on
/// its real address -- Cloudflare cannot proxy arbitrary UDP, so that port
/// carries no source restriction, while TCP 80/443 are filtered to the
/// Cloudflare ranges and are invisible to a raw-IP probe.
///
/// That makes the first packet of every single connect attempt a
/// self-identifying datagram sent from the user's real address to the node's
/// real address. In this threat model the user is the one at risk, so emitting
/// that datagram again and again on a network that has already been shown to
/// swallow it is pure cost: it cannot connect, and it keeps re-advertising both
/// endpoints of the association.
///
/// ## The safety contract -- read this before changing anything here
///
/// This memory only ever REORDERS the transport list. It never removes a
/// transport, and it never shortens the set of transports attempted.
///
///   * undemoted: direct UDP, then TCP 80, then TCP 443
///   * demoted:   TCP 80, then TCP 443, then direct UDP
///
/// Both orders attempt all three. A user therefore cannot be made unreachable
/// by a wrong answer from this class -- the worst case is that a connect which
/// would have succeeded on the first leg instead succeeds on the third, costing
/// latency and nothing else. Every widening of this class must preserve that
/// property. If a future change ever makes a demotion *skip* the direct leg,
/// this stops being a safe optimisation and becomes a way to strand users.
///
/// ## Why the clock cannot hurt us
///
/// Time is used for exactly one thing: deciding when a demotion is stale enough
/// to re-probe. Both directions of clock error are safe, which matters because
/// the target hardware is cheap Android with routinely wrong clocks.
///
///   * clock far ahead -> the demotion looks stale -> we lead with UDP, i.e.
///     today's shipping behaviour.
///   * clock far behind -> the demotion never looks stale -> we lead with TCP,
///     which still connects.
///
/// Neither direction can compute a value that makes the tunnel undialable.
/// This is the specific property that a time-derived port would not have.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Schema version of the persisted document. Bump on any incompatible change;
/// [DirectUdpTransportMemory.fromJson] treats an unrecognised version as an
/// empty memory rather than failing, so a downgrade cannot wedge a client.
const int kDirectUdpMemorySchemaVersion = 1;

/// Consecutive direct-UDP failures on one network before that network's order
/// is flipped. Two, not one, so a single transient failure (a flaky access
/// point, a node restart, a handshake lost to roaming) does not cost the fast
/// path.
const int kDirectUdpNetworkStrikeThreshold = 2;

/// Consecutive direct-UDP failures across ALL networks before the order is
/// flipped everywhere. This is the tier that actually covers mobile data: a
/// carrier-NAT address moves, so the per-network scope can rotate between
/// sessions and never accumulate its own strikes. Set well above the
/// per-network threshold because it is the coarser, more easily wrong signal.
const int kDirectUdpGlobalStrikeThreshold = 6;

/// How long a demotion holds before the direct leg is allowed to lead once
/// more. This is the recovery path: a block that is lifted, a user who moved,
/// or a node that was simply down all come back automatically.
///
/// It is also the knob that bounds exposure. At 24 hours a user who connects
/// twenty times a day emits at most one leading direct-UDP datagram per day per
/// network instead of twenty. Lengthening it reduces exposure further at the
/// cost of staying on the slower transport longer after a block lifts.
const Duration kDirectUdpReprobeInterval = Duration(hours: 24);

/// Housekeeping only: entries untouched for this long are dropped on load, so
/// the document cannot grow without bound for a device that roams a lot.
/// Recovery does not depend on this -- [kDirectUdpReprobeInterval] handles it.
const Duration kDirectUdpMemoryTtl = Duration(days: 30);

/// Upper bound on tracked networks. The least recently updated is evicted.
const int kDirectUdpMaxTrackedNetworks = 16;

/// Scope used when the platform gives us nothing to fingerprint a network with.
/// It behaves like any other scope; it is not a special case, it is simply the
/// bucket that every unidentifiable network shares.
const String kDirectUdpUnknownScope = 'unknown';

/// Derives a stable, non-identifying scope token for the network the device is
/// currently attached to.
///
/// [tokens] are opaque strings supplied by the caller -- in the app they are
/// `<interface name>/<IPv4 /24 prefix>` pairs read from `NetworkInterface.list`,
/// which needs no permission on any supported platform. They are sorted and
/// deduplicated so interface enumeration order cannot change the answer, then
/// hashed, so the persisted document never contains an address.
///
/// A wrong answer here is not a correctness problem: two different networks
/// colliding on one scope, or one network splitting across two scopes, only
/// affects how quickly the memory learns. See the safety contract above.
String directUdpNetworkScope(Iterable<String> tokens) {
  final cleaned = tokens
      .map((token) => token.trim())
      .where((token) => token.isNotEmpty)
      .toSet()
      .toList()
    ..sort();
  if (cleaned.isEmpty) return kDirectUdpUnknownScope;
  final digest = sha256.convert(utf8.encode(cleaned.join('|')));
  return digest.toString().substring(0, 16);
}

/// One network's (or the global tier's) accumulated evidence.
class DirectUdpStrikeRecord {
  const DirectUdpStrikeRecord({
    required this.strikes,
    required this.updatedAtUtc,
  });

  final int strikes;
  final DateTime updatedAtUtc;

  DirectUdpStrikeRecord _incremented(DateTime now) => DirectUdpStrikeRecord(
        // Saturate rather than grow forever: past the threshold the exact count
        // carries no further meaning, and a bounded value keeps the document
        // small and the arithmetic overflow-free.
        strikes: strikes >= kDirectUdpGlobalStrikeThreshold
            ? kDirectUdpGlobalStrikeThreshold
            : strikes + 1,
        updatedAtUtc: now.toUtc(),
      );

  Map<String, dynamic> toJson() => <String, dynamic>{
        'strikes': strikes,
        'updated_at_utc': updatedAtUtc.toIso8601String(),
      };

  static DirectUdpStrikeRecord? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final strikes = raw['strikes'];
    final updatedAt = raw['updated_at_utc'];
    if (strikes is! int || strikes < 0) return null;
    if (updatedAt is! String) return null;
    final parsed = DateTime.tryParse(updatedAt);
    if (parsed == null) return null;
    return DirectUdpStrikeRecord(
      strikes: strikes > kDirectUdpGlobalStrikeThreshold
          ? kDirectUdpGlobalStrikeThreshold
          : strikes,
      updatedAtUtc: parsed.toUtc(),
    );
  }
}

/// Immutable record of where the direct UDP leg has and has not worked.
class DirectUdpTransportMemory {
  const DirectUdpTransportMemory({
    this.networks = const <String, DirectUdpStrikeRecord>{},
    this.global,
  });

  final Map<String, DirectUdpStrikeRecord> networks;
  final DirectUdpStrikeRecord? global;

  static const DirectUdpTransportMemory empty = DirectUdpTransportMemory();

  bool get isEmpty => networks.isEmpty && global == null;

  /// Whether the direct UDP leg should be moved behind the CDN-fronted TCP
  /// legs for [scope] right now.
  ///
  /// Returning false is always the safe answer -- it is exactly the shipping
  /// behaviour -- so every uncertain case resolves to false.
  bool shouldDemoteDirectUdp({
    required String scope,
    required DateTime now,
  }) {
    return _tierDemotes(networks[scope], kDirectUdpNetworkStrikeThreshold, now) ||
        _tierDemotes(global, kDirectUdpGlobalStrikeThreshold, now);
  }

  static bool _tierDemotes(
    DirectUdpStrikeRecord? record,
    int threshold,
    DateTime now,
  ) {
    if (record == null) return false;
    if (record.strikes < threshold) return false;
    // Stale enough to re-probe: let the direct leg lead once more. If it fails
    // again the strike is refreshed and the demotion holds for another
    // interval; if it works, the record is cleared outright.
    //
    // A clock that has jumped backwards makes `elapsed` negative, which is not
    // >= the interval, so the demotion simply holds. That is the safe side.
    final elapsed = now.toUtc().difference(record.updatedAtUtc);
    if (elapsed >= kDirectUdpReprobeInterval) return false;
    return true;
  }

  /// The direct UDP leg failed to produce a working tunnel on [scope].
  DirectUdpTransportMemory recordDirectUdpUnreachable({
    required String scope,
    required DateTime now,
  }) {
    final updated = Map<String, DirectUdpStrikeRecord>.from(networks);
    final existing = updated[scope];
    updated[scope] = existing == null
        ? DirectUdpStrikeRecord(strikes: 1, updatedAtUtc: now.toUtc())
        : existing._incremented(now);
    return DirectUdpTransportMemory(
      networks: _bounded(updated),
      global: global == null
          ? DirectUdpStrikeRecord(strikes: 1, updatedAtUtc: now.toUtc())
          : global!._incremented(now),
    );
  }

  /// The direct UDP leg produced a working tunnel on [scope]. This is the
  /// unambiguous signal, so it clears both tiers: the network's own evidence
  /// outright, and the global counter, which by definition is no longer a run
  /// of consecutive failures.
  DirectUdpTransportMemory recordDirectUdpReachable({
    required String scope,
    required DateTime now,
  }) {
    final updated = Map<String, DirectUdpStrikeRecord>.from(networks)
      ..remove(scope);
    return DirectUdpTransportMemory(networks: _bounded(updated), global: null);
  }

  static Map<String, DirectUdpStrikeRecord> _bounded(
    Map<String, DirectUdpStrikeRecord> source,
  ) {
    if (source.length <= kDirectUdpMaxTrackedNetworks) return source;
    final entries = source.entries.toList()
      ..sort((a, b) => b.value.updatedAtUtc.compareTo(a.value.updatedAtUtc));
    return Map<String, DirectUdpStrikeRecord>.fromEntries(
      entries.take(kDirectUdpMaxTrackedNetworks),
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'schema_version': kDirectUdpMemorySchemaVersion,
        'networks': <String, dynamic>{
          for (final entry in networks.entries) entry.key: entry.value.toJson(),
        },
        if (global != null) 'global': global!.toJson(),
      };

  /// Parses a persisted document, dropping anything expired or malformed.
  ///
  /// Every failure path yields [empty], never an exception: a corrupt file must
  /// degrade to shipping behaviour, not to a connect that cannot start.
  static DirectUdpTransportMemory fromJson(
    Object? raw, {
    required DateTime now,
  }) {
    if (raw is! Map) return empty;
    if (raw['schema_version'] != kDirectUdpMemorySchemaVersion) return empty;
    final rawNetworks = raw['networks'];
    final networks = <String, DirectUdpStrikeRecord>{};
    if (rawNetworks is Map) {
      for (final entry in rawNetworks.entries) {
        final key = entry.key;
        if (key is! String || key.isEmpty) continue;
        final record = DirectUdpStrikeRecord.fromJson(entry.value);
        if (record == null || _isExpired(record, now)) continue;
        networks[key] = record;
      }
    }
    final globalRecord = DirectUdpStrikeRecord.fromJson(raw['global']);
    return DirectUdpTransportMemory(
      networks: _bounded(networks),
      global: globalRecord == null || _isExpired(globalRecord, now)
          ? null
          : globalRecord,
    );
  }

  static bool _isExpired(DirectUdpStrikeRecord record, DateTime now) {
    final elapsed = now.toUtc().difference(record.updatedAtUtc);
    return elapsed >= kDirectUdpMemoryTtl;
  }
}
