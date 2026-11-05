/// Control-plane bootstrap resilience: the decision logic that lets a client
/// notice it has been *censored* rather than merely *unlucky*, and reach an
/// alternative control-plane endpoint if so.
///
/// This library is deliberately pure. It performs no network I/O, holds no
/// hostnames, and embeds no keys. Everything it needs is passed in. That is
/// what makes it safe to land ahead of the procurement it depends on: with no
/// discovery zone provisioned and no verifier supplied, every entry point here
/// is inert and the shipping bootstrap path is byte-for-byte unchanged.
///
/// See `docs/CONTROL_PLANE_BOOTSTRAP_RESILIENCE.md` for the threat model, the
/// procurement requirements, and the reasons behind each threshold below.
library;

import 'dart:convert';

import 'gateway_failover.dart';

// ---------------------------------------------------------------------------
// 1. Observations
// ---------------------------------------------------------------------------

/// What a single bootstrap attempt actually did, at the finest granularity the
/// caller can distinguish.
///
/// The distinctions matter because they carry very different amounts of
/// evidence. A TLS reset arriving immediately after the ClientHello is a
/// near-certain SNI filter; a TCP timeout is equally consistent with a filter,
/// a congested cell, and a phone in a lift. Collapsing them -- which is what
/// happens when everything becomes "request failed" -- is what makes naive
/// failover flap.
enum BootstrapObservation {
  /// The request completed and returned a payload the caller accepted.
  succeeded,

  /// Authoritative "no such name" for a name that is known to exist.
  dnsNameNotFound,

  /// Resolution failed some other way: SERVFAIL, REFUSED, or no reply.
  dnsResolutionFailed,

  /// Resolution succeeded but produced an address that cannot be the real
  /// origin: loopback, link-local, RFC1918, or an otherwise unroutable bogon.
  /// This is the signature of a DNS sinkhole and it is unambiguous.
  dnsAnswerUnroutable,

  /// TCP RST arrived materially sooner than the reference round-trip time
  /// allows, so it cannot have come from the origin. Injected by the path.
  tcpConnectResetInjected,

  /// TCP RST at a plausible origin round-trip time. The host is refusing; that
  /// is a server-side condition, not a censorship one.
  tcpConnectRefused,

  /// SYN went unanswered. Ambiguous: black-holed by a filter, or simply a bad
  /// radio link.
  tcpConnectTimedOut,

  /// TCP established, ClientHello sent, then reset or closed before any
  /// ServerHello. Very strong evidence of SNI-based filtering.
  tlsResetAfterClientHello,

  /// TCP established but the handshake never completed. Ambiguous.
  tlsHandshakeTimedOut,

  /// A certificate was presented and rejected: wrong name, untrusted issuer,
  /// or expired. Something terminated the connection that is not the origin.
  tlsCertificateRejected,

  /// TLS completed and HTTP returned something that is structurally not our
  /// payload -- a portal login page, an ISP notice, an HTML document where
  /// JSON was expected.
  httpInterceptionPage,

  /// An on-path block status: 403 or 451 emitted by something other than the
  /// origin, or any response carrying a block-notice body.
  httpBlockStatus,

  /// A 5xx from an origin whose certificate validated. This is our own backend
  /// having a bad day and it is emphatically *not* a censorship signal.
  httpServerError,

  /// The request exceeded its deadline without a more specific cause.
  requestTimedOut,
}

/// Result of the reference probe used to decide whether a failure was specific
/// to the gateway or general to the device's connectivity.
enum ControlProbeOutcome {
  /// The reference endpoint answered. The device has working internet, so a
  /// gateway failure observed alongside this is *specific*.
  reachable,

  /// The reference endpoint did not answer either. The device most likely has
  /// no usable connectivity; nothing about the gateway can be concluded.
  unreachable,

  /// No probe was run. Ambiguous observations cannot be escalated.
  notAttempted,
}

/// The verdict drawn from one attempt.
enum BootstrapSignal {
  /// Nothing adverse, or nothing attributable to the network path.
  none,

  /// A failure with an innocent explanation at least as likely as a hostile
  /// one. Retry; do not spend anything scarce.
  transient,

  /// Consistent with blocking, but corroboration is required before acting.
  blockSuspected,

  /// Self-evidencing: an on-path party demonstrably interfered. One
  /// observation is enough.
  blockConfirmed,
}

/// Observations whose alternative explanation is "this device has no working
/// connectivity". These, and only these, are gated behind the control probe.
///
/// Observations *outside* this set already prove a live peer was reached and
/// misbehaved, so they need no corroboration -- a forged certificate is not
/// more or less forged depending on whether some other host was reachable.
const Set<BootstrapObservation> _ambiguousObservations = {
  BootstrapObservation.dnsResolutionFailed,
  BootstrapObservation.tcpConnectTimedOut,
  BootstrapObservation.tlsHandshakeTimedOut,
  BootstrapObservation.requestTimedOut,
};

/// Whether [observation] needs a control probe before it can mean anything.
///
/// Callers should run the probe only when this returns true. Probing on every
/// failure wastes metered data and adds a request to the launch profile of
/// users who are merely on a weak cell.
bool requiresControlProbe(BootstrapObservation observation) =>
    _ambiguousObservations.contains(observation);

/// Reduce one attempt to a verdict.
///
/// The control probe acts as a *veto*, never as a promotion: it can only stop
/// an ambiguous failure from being read as censorship. It cannot turn a benign
/// observation into a hostile one. That asymmetry is deliberate -- the
/// expensive error here is a false positive, because a client that wrongly
/// decides it is censored spends fallback endpoints that are slow and costly
/// to replace.
BootstrapSignal classifyBootstrapAttempt({
  required BootstrapObservation observation,
  ControlProbeOutcome control = ControlProbeOutcome.notAttempted,
}) {
  switch (observation) {
    case BootstrapObservation.succeeded:
      return BootstrapSignal.none;

    // A 5xx behind a certificate that validated is our own outage. Reading it
    // as a block would burn every fallback for the whole user base during a
    // backend incident -- the single most expensive false positive available.
    case BootstrapObservation.httpServerError:
      return BootstrapSignal.transient;

    // The origin answered and declined the connection. Server-side.
    case BootstrapObservation.tcpConnectRefused:
      return BootstrapSignal.transient;

    // Self-evidencing interference. No corroboration required.
    case BootstrapObservation.dnsNameNotFound:
    case BootstrapObservation.dnsAnswerUnroutable:
    case BootstrapObservation.tcpConnectResetInjected:
    case BootstrapObservation.tlsResetAfterClientHello:
    case BootstrapObservation.tlsCertificateRejected:
    case BootstrapObservation.httpInterceptionPage:
    case BootstrapObservation.httpBlockStatus:
      return BootstrapSignal.blockConfirmed;

    // Ambiguous: only meaningful if the device demonstrably has internet.
    case BootstrapObservation.dnsResolutionFailed:
    case BootstrapObservation.tcpConnectTimedOut:
    case BootstrapObservation.tlsHandshakeTimedOut:
    case BootstrapObservation.requestTimedOut:
      return control == ControlProbeOutcome.reachable
          ? BootstrapSignal.blockSuspected
          : BootstrapSignal.transient;
  }
}

// ---------------------------------------------------------------------------
// 2. Hysteresis
// ---------------------------------------------------------------------------

/// Corroborating suspicions required before an ambiguous failure is treated as
/// a block. Three is chosen so that a single bad launch, and a single bad
/// network, cannot on their own spend a fallback endpoint.
const int kBlockStrikeThreshold = 3;

/// Shortest interval before a blocked endpoint is retried, doubling per
/// generation. Blocks get lifted, and a false positive that is never rechecked
/// is a permanent one.
const Duration kMinimumRecheckInterval = Duration(minutes: 15);

/// Cap on the recheck backoff. A day is long enough to stop a genuinely
/// blocked endpoint costing meaningful data, short enough that a user whose
/// country lifted a block is not stranded for a week.
const Duration kMaximumRecheckInterval = Duration(hours: 24);

/// Health of one endpoint, **scoped to one network attachment**.
///
/// Scoping is the point. Blocking is a property of the path, not of the
/// endpoint: a gateway censored on a hotel Wi-Fi is usually fine on the same
/// user's mobile data. Health kept globally lets one hostile network poison
/// the primary gateway permanently, everywhere, which is both a bug and a way
/// for a captive portal to push users onto their fallbacks on purpose.
class EndpointHealth {
  const EndpointHealth({
    required this.networkScope,
    this.strikes = 0,
    this.confirmed = false,
    this.blockedAt,
    this.recheckGeneration = 0,
  });

  /// Opaque, caller-supplied token identifying the current network attachment.
  ///
  /// It must be stable across a session on one network, different across
  /// networks, non-identifying, stored locally only, and never transmitted.
  final String networkScope;

  /// Corroborating [BootstrapSignal.blockSuspected] observations seen.
  final int strikes;

  /// Set by a single self-evidencing observation.
  final bool confirmed;

  /// When the endpoint was first considered blocked, for recheck scheduling.
  final DateTime? blockedAt;

  /// Number of failed rechecks, driving the exponential backoff.
  final int recheckGeneration;

  bool get blocked => confirmed || strikes >= kBlockStrikeThreshold;

  /// The interval that must elapse before this endpoint is retried.
  Duration get recheckInterval {
    var interval = kMinimumRecheckInterval;
    for (var i = 0; i < recheckGeneration; i++) {
      interval *= 2;
      if (interval >= kMaximumRecheckInterval) return kMaximumRecheckInterval;
    }
    return interval;
  }

  /// Whether a blocked endpoint is due for another attempt at [now].
  bool isDueForRecheck(DateTime now) {
    if (!blocked) return true;
    final since = blockedAt;
    if (since == null) return true;
    return !now.isBefore(since.add(recheckInterval));
  }
}

/// Fold one attempt into an endpoint's health.
///
/// A change of [networkScope] discards prior state rather than merging it: the
/// evidence was gathered about a different path and says nothing about this
/// one. A success clears everything, so recovery needs no separate unblock
/// path.
EndpointHealth recordBootstrapAttempt(
  EndpointHealth prior, {
  required BootstrapSignal signal,
  required String networkScope,
  required DateTime now,
}) {
  final carried = prior.networkScope == networkScope
      ? prior
      : EndpointHealth(networkScope: networkScope);

  switch (signal) {
    case BootstrapSignal.none:
      return EndpointHealth(networkScope: networkScope);

    case BootstrapSignal.transient:
      return carried;

    case BootstrapSignal.blockSuspected:
      final strikes = carried.strikes + 1;
      final nowBlocked = strikes >= kBlockStrikeThreshold;
      return EndpointHealth(
        networkScope: networkScope,
        strikes: strikes,
        confirmed: carried.confirmed,
        blockedAt: carried.blockedAt ?? (nowBlocked ? now : null),
        recheckGeneration:
            carried.blocked ? carried.recheckGeneration + 1 : carried.recheckGeneration,
      );

    case BootstrapSignal.blockConfirmed:
      return EndpointHealth(
        networkScope: networkScope,
        strikes: carried.strikes,
        confirmed: true,
        blockedAt: carried.blockedAt ?? now,
        recheckGeneration:
            carried.blocked ? carried.recheckGeneration + 1 : carried.recheckGeneration,
      );
  }
}

// ---------------------------------------------------------------------------
// 3. The discovery record
// ---------------------------------------------------------------------------

/// Wire format tag. Present so an incompatible future format fails closed
/// rather than being partially parsed.
const String kDiscoveryRecordFormat = 'v1';

/// Signature domain, constructed exactly like `internal/pqauth`'s
/// `SignDomainMessage`: `domain || 0x00 || message`. Domain separation is not
/// optional -- without it a signature made over some other project object
/// could be replayed as a discovery record.
const String kDiscoverySignatureDomain = 'winsvpn-bootstrap-discovery/v1';

/// Hard ceiling on record size. A DNS TXT string is capped at 255 bytes and an
/// unusually large TXT response is itself a distinguisher, so the format is
/// designed to fit one string with room to spare.
const int kMaxDiscoveryRecordBytes = 512;

/// Ceiling on how many endpoints one record may carry. Bounds both the record
/// size and how much a single compromised signer could steer.
const int kMaxDiscoveryEndpoints = 6;

/// Longest validity a record may claim, bounding the blast radius of a signing
/// key compromise. Mirrors the seven-day ceiling on the gateway manifest.
const Duration kMaxDiscoveryRecordLifetime = Duration(days: 7);

/// Tolerance for device clock error when checking expiry.
///
/// Mobile clocks are unreliable and a device whose clock is wrong is not an
/// edge case in this user population. Expiry is therefore a coarse backstop;
/// **sequence monotonicity is the primary anti-rollback control**, because it
/// does not depend on the device knowing what time it is.
const Duration kDiscoveryClockSkewTolerance = Duration(hours: 12);

/// Why a record was refused. Callers should treat every value as "ignore this
/// record and stay on the compiled set".
enum DiscoveryRejection {
  malformed,
  unsupportedFormat,
  tooLarge,
  noEndpoints,
  tooManyEndpoints,
  unsafeEndpoint,
  expired,
  lifetimeTooLong,
  replayedSequence,
  badSignature,
}

/// A verified discovery record.
class DiscoveryRecord {
  const DiscoveryRecord({
    required this.sequence,
    required this.expiresAt,
    required this.endpoints,
  });

  /// Monotonic counter. A record whose sequence is not greater than the
  /// highest previously accepted one is a replay.
  final int sequence;

  final DateTime expiresAt;

  /// Candidate gateway bases, in publisher-preferred order, each already
  /// screened by [isSafeHttpsGatewayUri].
  final List<String> endpoints;
}

/// Outcome of parsing: exactly one of [record] or [rejection] is non-null.
class DiscoveryParseResult {
  const DiscoveryParseResult.accepted(DiscoveryRecord this.record)
      : rejection = null;
  const DiscoveryParseResult.rejected(DiscoveryRejection this.rejection)
      : record = null;

  final DiscoveryRecord? record;
  final DiscoveryRejection? rejection;

  bool get accepted => record != null;
}

/// Verifies [signature] over [message]. Supplied by the caller so that **no
/// public key is compiled into this library**; until the owner provisions a
/// signing key there is nothing to pass and discovery cannot run.
typedef DiscoverySignatureVerifier = Future<bool> Function(
  List<int> message,
  List<int> signature,
);

/// The exact bytes a publisher signs and a client verifies: the record with its
/// trailing signature field removed, prefixed by the domain separator.
List<int> discoverySigningBytes(String signedPortion) {
  return <int>[
    ...utf8.encode(kDiscoverySignatureDomain),
    0,
    ...utf8.encode(signedPortion),
  ];
}

/// Split a raw record into its signed portion and its signature field.
///
/// Returns null when the shape is wrong. Kept separate from
/// [parseDiscoveryRecord] so the signed bytes are derived from the *raw* input
/// and never from a re-serialisation of parsed fields -- re-serialising is how
/// signature checks end up validating something other than what arrived.
({String signedPortion, List<int> signature})? splitDiscoveryRecord(
  String raw,
) {
  final trimmed = raw.trim();
  if (trimmed.isEmpty || utf8.encode(trimmed).length > kMaxDiscoveryRecordBytes) {
    return null;
  }
  final lastSeparator = trimmed.lastIndexOf('|');
  if (lastSeparator <= 0 || lastSeparator == trimmed.length - 1) return null;
  final signedPortion = trimmed.substring(0, lastSeparator);
  final encodedSignature = trimmed.substring(lastSeparator + 1);
  List<int> signature;
  try {
    signature = base64.decode(encodedSignature);
  } catch (_) {
    return null;
  }
  if (signature.isEmpty) return null;
  return (signedPortion: signedPortion, signature: signature);
}

/// Parse and structurally validate a record. **Does not check the signature**
/// -- [verifyDiscoveryRecord] is the only supported entry point for callers.
///
/// Wire shape, designed to fit a single 255-byte TXT string:
///
///     v1|<sequence>|<expiry-unix-seconds>|<host>,<host>,...|<base64 signature>
///
/// Hosts appear bare and are promoted to `https://<host>` here, so a record can
/// never smuggle a scheme, port, path, query, fragment or userinfo past the
/// screen.
DiscoveryParseResult parseDiscoveryRecord(
  String raw, {
  required DateTime now,
  required int lastAcceptedSequence,
}) {
  final split = splitDiscoveryRecord(raw);
  if (split == null) {
    return utf8.encode(raw.trim()).length > kMaxDiscoveryRecordBytes
        ? const DiscoveryParseResult.rejected(DiscoveryRejection.tooLarge)
        : const DiscoveryParseResult.rejected(DiscoveryRejection.malformed);
  }

  final fields = split.signedPortion.split('|');
  if (fields.length != 4) {
    return const DiscoveryParseResult.rejected(DiscoveryRejection.malformed);
  }
  if (fields[0] != kDiscoveryRecordFormat) {
    return const DiscoveryParseResult.rejected(
      DiscoveryRejection.unsupportedFormat,
    );
  }

  final sequence = int.tryParse(fields[1]);
  final expirySeconds = int.tryParse(fields[2]);
  if (sequence == null ||
      sequence <= 0 ||
      expirySeconds == null ||
      expirySeconds < -8640000000000 ||
      expirySeconds > 8640000000000) {
    return const DiscoveryParseResult.rejected(
      DiscoveryRejection.malformed,
    );
  }
  if (sequence <= lastAcceptedSequence) {
    return const DiscoveryParseResult.rejected(
      DiscoveryRejection.replayedSequence,
    );
  }

  final expiresAt = DateTime.fromMillisecondsSinceEpoch(
    expirySeconds * 1000,
    isUtc: true,
  );
  if (expiresAt.isBefore(now.toUtc().subtract(kDiscoveryClockSkewTolerance))) {
    return const DiscoveryParseResult.rejected(DiscoveryRejection.expired);
  }
  if (expiresAt.isAfter(now
      .toUtc()
      .add(kMaxDiscoveryRecordLifetime)
      .add(kDiscoveryClockSkewTolerance))) {
    return const DiscoveryParseResult.rejected(
      DiscoveryRejection.lifetimeTooLong,
    );
  }

  final rawHosts = fields[3]
      .split(',')
      .map((host) => host.trim())
      .where((host) => host.isNotEmpty)
      .toList();
  if (rawHosts.isEmpty) {
    return const DiscoveryParseResult.rejected(DiscoveryRejection.noEndpoints);
  }
  if (rawHosts.length > kMaxDiscoveryEndpoints) {
    return const DiscoveryParseResult.rejected(
      DiscoveryRejection.tooManyEndpoints,
    );
  }

  final endpoints = <String>[];
  for (final host in rawHosts) {
    // Reject anything that is not a bare host before composing a URL, so a
    // crafted host can neither carry its own scheme nor split the authority.
    if (host.contains('/') ||
        host.contains(':') ||
        host.contains('@') ||
        host.contains('?') ||
        host.contains('#') ||
        host != host.toLowerCase()) {
      return const DiscoveryParseResult.rejected(
        DiscoveryRejection.unsafeEndpoint,
      );
    }
    final base = 'https://$host';
    final uri = Uri.tryParse(base);
    if (uri == null || !isSafeHttpsGatewayUri(uri)) {
      return const DiscoveryParseResult.rejected(
        DiscoveryRejection.unsafeEndpoint,
      );
    }
    if (!endpoints.contains(base)) endpoints.add(base);
  }

  return DiscoveryParseResult.accepted(
    DiscoveryRecord(
      sequence: sequence,
      expiresAt: expiresAt,
      endpoints: List<String>.unmodifiable(endpoints),
    ),
  );
}

/// The only supported way to turn a raw discovery record into endpoints.
///
/// Structural validation runs first and the signature check runs last, over the
/// raw signed bytes. A record that fails for any reason yields no endpoints at
/// all: there is no partial acceptance, because a discovery channel that can be
/// steered is worse than none.
Future<DiscoveryParseResult> verifyDiscoveryRecord(
  String raw, {
  required DateTime now,
  required int lastAcceptedSequence,
  required DiscoverySignatureVerifier verifier,
}) async {
  final parsed = parseDiscoveryRecord(
    raw,
    now: now,
    lastAcceptedSequence: lastAcceptedSequence,
  );
  if (!parsed.accepted) return parsed;

  final split = splitDiscoveryRecord(raw);
  if (split == null) {
    return const DiscoveryParseResult.rejected(DiscoveryRejection.malformed);
  }

  bool valid;
  try {
    valid = await verifier(
      discoverySigningBytes(split.signedPortion),
      split.signature,
    );
  } catch (_) {
    valid = false;
  }
  return valid
      ? parsed
      : const DiscoveryParseResult.rejected(DiscoveryRejection.badSignature);
}

// ---------------------------------------------------------------------------
// 4. Ordering and budget
// ---------------------------------------------------------------------------

/// Discovered endpoints admitted per launch.
///
/// One, not many. Every endpoint a client touches is an endpoint an on-path
/// observer can attribute to this app and block, so contacting the whole
/// fallback set at once spends the entire reserve to recover from one launch --
/// and does it just as readily when the "block" was a false positive. One per
/// launch means a false positive costs exactly one endpoint, and a real block
/// costs one endpoint per launch until something works.
const int kNewEndpointsPerLaunch = 1;

/// An ordered bootstrap plan.
class BootstrapPlan {
  const BootstrapPlan({
    required this.endpoints,
    required this.shouldQueryDiscovery,
  });

  /// Endpoints to try **strictly in order, one at a time**.
  ///
  /// Sequential rather than parallel for three separate reasons, each
  /// sufficient on its own: metered mobile data; a simultaneous burst of TLS
  /// handshakes to several unrelated domains is a traffic signature no ordinary
  /// app produces; and parallel attempts reveal every fallback at once.
  final List<String> endpoints;

  /// Whether the caller should spend a discovery lookup. True only once the
  /// known set is exhausted, so an ordinary launch costs nothing extra.
  final bool shouldQueryDiscovery;
}

/// Build the attempt order for one launch.
///
/// Preference order: the endpoint that last worked *on this network*, then the
/// compiled set, then at most [newEndpointsPerLaunch] discovered endpoints.
/// Blocked endpoints are skipped until their recheck falls due.
///
/// If everything known is blocked, the plan still returns the endpoints that
/// are due for recheck rather than nothing: failing closed with an empty plan
/// would strand a client whose block was lifted.
BootstrapPlan planBootstrapAttempts({
  required List<String> compiledEndpoints,
  required String networkScope,
  required DateTime now,
  String? lastKnownGoodEndpoint,
  List<String> discoveredEndpoints = const [],
  Map<String, EndpointHealth> health = const {},
  int newEndpointsPerLaunch = kNewEndpointsPerLaunch,
}) {
  bool usable(String endpoint) {
    final state = health[endpoint];
    if (state == null) return true;
    if (state.networkScope != networkScope) return true;
    return !state.blocked || state.isDueForRecheck(now);
  }

  final ordered = <String>[];
  void add(String endpoint) {
    if (endpoint.isEmpty || ordered.contains(endpoint)) return;
    ordered.add(endpoint);
  }

  final knownGood = lastKnownGoodEndpoint;
  if (knownGood != null && usable(knownGood)) add(knownGood);
  for (final endpoint in compiledEndpoints) {
    if (usable(endpoint)) add(endpoint);
  }

  final compiledExhausted = compiledEndpoints.isNotEmpty &&
      compiledEndpoints.every((endpoint) => !usable(endpoint));

  var admitted = 0;
  if (compiledExhausted && newEndpointsPerLaunch > 0) {
    for (final endpoint in discoveredEndpoints) {
      if (admitted >= newEndpointsPerLaunch) break;
      if (!usable(endpoint) || ordered.contains(endpoint)) continue;
      add(endpoint);
      admitted++;
    }
  }

  // Nothing is usable: surface whatever is closest to due so the client is not
  // permanently stranded by its own hysteresis.
  if (ordered.isEmpty) {
    for (final endpoint in compiledEndpoints) {
      add(endpoint);
    }
  }

  return BootstrapPlan(
    endpoints: List<String>.unmodifiable(ordered),
    shouldQueryDiscovery: compiledExhausted && admitted == 0,
  );
}
