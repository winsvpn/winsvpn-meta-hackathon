/// Consuming a verified discovery record: replay floor, persistence, and the
/// merge into the gateway sweep.
///
/// ## The channel this serves
///
/// A discovery record is a signed string. Because it is signed, its transport
/// is untrusted, and because its transport is untrusted the transport is
/// **fungible** — the record is equally safe arriving over Signal, Telegram,
/// a photograph of a QR code, or read aloud over the phone and retyped. That
/// turns control-plane rotation from a network problem a censor can block into
/// a distribution problem, which is the central insight of the migration
/// design and the reason paste-in is the *primary* intake channel rather than
/// a fallback.
///
/// What a censor observes when a user pastes a record: **nothing**. There is
/// no query to block, no rendezvous host to seize, no timing pattern, because
/// the mechanism is not on the network at all. Contrast a compiled-in DoH TXT
/// lookup, which in a single unchangeable release is a fixed target whose
/// resolver set and query name are sitting in the APK.
///
/// What it does not solve: the record still has to reach the user, which is a
/// human-network problem and depends entirely on the owner's distribution and
/// rotation tempo. A signed discovery format with nobody publishing records is
/// worth nothing.
///
/// ## The floor is independent, and that is a security property
///
/// [kDiscoverySeqFloorSettingKey] is deliberately a different key from
/// `announcement_seq_floor`. Sharing one counter would let either channel
/// poison the other, and the poisoning is not hypothetical: an attacker
/// holding a valid *announcement* key can push a device's announcement floor
/// arbitrarily high (the floor rises to any verified `seq` and rejects only
/// lower values). With a shared counter that attacker would permanently deny
/// the discovery channel — the exact channel the owner needs to route around
/// them. Recovery from a poisoned announcement floor is a jump in the hub's
/// global sequence; there is no such recovery for discovery, because the
/// owner cannot reach a client that will not accept records. So the floors
/// never touch.
///
/// ## Sequence, not time, is the replay control
///
/// `iat`-style freshness is not an acceptance criterion anywhere in this
/// system. A maximum age silently blanks the channel on clock-skewed devices —
/// and skew is ordinary on the cheap hardware this service runs on — which
/// would be a self-inflicted denial of exactly the channel that exists to
/// survive denial. The record's expiry is a coarse backstop already enforced
/// by the frozen parser with a 12-hour skew tolerance; monotonic sequence is
/// the control that does not depend on the device knowing what time it is.
library;

import 'bootstrap_resilience.dart';
import 'discovery_keys.dart';
import 'gateway_failover.dart';

/// Persisted replay floor for the **discovery** channel.
///
/// Distinct from `announcement_seq_floor` on purpose — see the library docs.
/// Sequences 1–9 are reserved for pre-release testing so that a test record
/// pasted on a device can never shadow a real one; production records start
/// at 10.
const String kDiscoverySeqFloorSettingKey = 'discovery_seq_floor';

/// Persisted endpoints from the most recently accepted record.
///
/// **A display cache, not a trust anchor.** Nothing reaches the gateway sweep
/// from this list — see [DiscoveryIntake.endpointsForUse]. A tampered store can
/// make this show a wrong count or no count; it can never inject a host.
const String kDiscoveryEndpointsSettingKey = 'discovery_endpoints';

/// Persisted sequence of the record those endpoints came from, for display.
const String kDiscoveryAcceptedSeqSettingKey = 'discovery_accepted_seq';

/// The accepted records themselves, verbatim, newest first.
///
/// Stored **raw** so they can be re-verified at the moment of use rather than
/// trusted because they are on disk. This is what makes storage a
/// non-trust-boundary: a record that was edited on disk, or whose signing key
/// this build does not carry, or that has since expired, contributes no
/// endpoints at all.
const String kDiscoveryRawRecordsSettingKey = 'discovery_records_raw';

/// Field name a hub response may carry a pre-positioned record in.
///
/// Deliberately a *field on responses the client already polls* rather than a
/// route of its own. The client sends no extra request, at no new cadence, in
/// no new shape — so pre-positioning adds exactly zero bytes to what an
/// observer inside the tunnel sees, and nothing at all to what one outside it
/// sees.
const String kDiscoveryRecordResponseField = 'discovery_record';

/// How many accepted records are retained for re-verification.
///
/// More than one so that a newer record naming a host that turns out to be
/// blocked does not also destroy the previous record's still-good hosts. Small
/// because each is ~200 characters and because the endpoint cap bounds what
/// they can collectively contribute anyway.
const int kMaxRetainedDiscoveryRecords = 3;

/// Highest sequence reserved for pre-release test records.
const int kMaxDiscoveryTestSequence = 9;

/// Where a record came from. Affects **logging only** — never verification.
///
/// There is no trusted transport here and no shortcut for one. A record that
/// arrived inside the working tunnel goes through byte-identical checks to one
/// the user typed off a scrap of paper, because the entire value of signing it
/// is that its transport does not have to be trusted.
enum DiscoveryIntakeSource {
  /// The user pasted it.
  pasteIn,

  /// It rode in on a hub response the client was already polling.
  prePositioned,
}

/// The device's discovery state: how far the replay floor has advanced, and
/// which endpoints the last accepted record named.
class DiscoveryIntakeState {
  const DiscoveryIntakeState({
    this.seqFloor = 0,
    this.endpoints = const <String>[],
    this.acceptedSequence,
    this.rawRecords = const <String>[],
  });

  /// Highest sequence this device has accepted. A record must be **strictly**
  /// greater to be accepted — a record is a consumed state change, unlike an
  /// announcement, which legitimately re-arrives on several polled routes and
  /// therefore accepts equality.
  final int seqFloor;

  /// Endpoints from the most recently accepted record, in publisher-preferred
  /// order. Already screened and promoted to `https://host` by the frozen
  /// parser, so nothing here can carry a scheme, port, path or userinfo.
  final List<String> endpoints;

  /// Sequence of the record [endpoints] came from, or null if none accepted.
  final int? acceptedSequence;

  /// The accepted records verbatim, newest first, for re-verification at use.
  final List<String> rawRecords;

  bool get hasEndpoints => endpoints.isNotEmpty;

  /// Rebuild from the persisted settings map.
  ///
  /// Every field is defensively typed: this file is on disk and a corrupted or
  /// hand-edited value must degrade to "nothing discovered yet", never to a
  /// trusted endpoint.
  ///
  /// **Storage is not a trust boundary.** What is restored here is never used
  /// to steer anything — [DiscoveryIntake.endpointsForUse] re-verifies the raw
  /// records before a single host reaches the gateway sweep. The endpoint list
  /// restored here exists only so the settings screen can show a count without
  /// doing crypto on the build of a widget.
  factory DiscoveryIntakeState.restore(Map<String, dynamic> settings) {
    final rawFloor = settings[kDiscoverySeqFloorSettingKey];
    final floor = rawFloor is int && rawFloor > 0 ? rawFloor : 0;

    final rawEndpoints = settings[kDiscoveryEndpointsSettingKey];
    final endpoints = <String>[];
    if (rawEndpoints is List) {
      for (final item in rawEndpoints) {
        if (item is! String) continue;
        final value = item.trim();
        if (value.isEmpty || endpoints.contains(value)) continue;
        final uri = Uri.tryParse(value);
        if (uri == null || !isSafeHttpsGatewayUri(uri)) continue;
        endpoints.add(value);
        if (endpoints.length >= kMaxDiscoveryEndpoints) break;
      }
    }

    final rawRecordsValue = settings[kDiscoveryRawRecordsSettingKey];
    final rawRecords = <String>[];
    if (rawRecordsValue is List) {
      for (final item in rawRecordsValue) {
        if (item is! String) continue;
        final value = item.trim();
        if (value.isEmpty || rawRecords.contains(value)) continue;
        rawRecords.add(value);
        if (rawRecords.length >= kMaxRetainedDiscoveryRecords) break;
      }
    }

    final rawSeq = settings[kDiscoveryAcceptedSeqSettingKey];
    return DiscoveryIntakeState(
      seqFloor: floor,
      endpoints: List<String>.unmodifiable(endpoints),
      acceptedSequence: rawSeq is int && rawSeq > 0 ? rawSeq : null,
      rawRecords: List<String>.unmodifiable(rawRecords),
    );
  }

  /// The values to persist. Written under keys that no other channel uses.
  Map<String, Object?> toSettings() => <String, Object?>{
        kDiscoverySeqFloorSettingKey: seqFloor,
        kDiscoveryEndpointsSettingKey: List<String>.from(endpoints),
        kDiscoveryAcceptedSeqSettingKey: acceptedSequence,
        kDiscoveryRawRecordsSettingKey: List<String>.from(rawRecords),
      };
}

/// What happened to a pasted record, in terms a user interface can render.
enum DiscoveryIntakeStatus {
  /// Verified and applied. New endpoints are live for the next sweep.
  accepted,

  /// This exact record is already retained. A no-op, and the reason a hub can
  /// serve the same pre-positioned record on every poll forever without
  /// costing anything or filling the log.
  alreadyHeld,

  /// This build carries no discovery public key, so no record can ever be
  /// verified. A build mistake, not a user mistake — and permanent for this
  /// installed base.
  notProvisioned,

  /// Nothing was pasted.
  empty,

  /// Not shaped like a record: wrong field count, bad base64, wrong version
  /// tag, oversized. Overwhelmingly a truncated copy/paste.
  malformed,

  /// Already used, or older than one already applied. Pasting the same record
  /// twice lands here, and nothing changes.
  replayed,

  /// Past its expiry, or claiming a lifetime longer than the 7-day ceiling.
  expired,

  /// Endpoint list empty, over the cap, or containing something that is not a
  /// bare lowercase host.
  unsafeEndpoints,

  /// Structurally fine, but no compiled key verifies it. Either a forgery, a
  /// key newer than this build, or a record signed over the wrong bytes.
  badSignature,
}

/// The result of one paste.
class DiscoveryIntakeOutcome {
  const DiscoveryIntakeOutcome({
    required this.status,
    required this.state,
    required this.diagnostics,
    this.record,
    this.source = DiscoveryIntakeSource.pasteIn,
  });

  final DiscoveryIntakeStatus status;

  /// Where the record came from. Logging only — it played no part in whether
  /// the record was accepted.
  final DiscoveryIntakeSource source;

  /// The state after this paste. **Byte-identical to the state before it
  /// whenever [status] is not [DiscoveryIntakeStatus.accepted]** — a rejected
  /// record changes nothing at all, including the floor.
  final DiscoveryIntakeState state;

  /// Log-safe explanation of the verification attempt.
  final DiscoveryVerificationDiagnostics diagnostics;

  /// The verified record, when one was accepted.
  final DiscoveryRecord? record;

  bool get accepted => status == DiscoveryIntakeStatus.accepted;
}

/// Map a structural rejection onto the user-facing status.
DiscoveryIntakeStatus _statusForRejection(DiscoveryRejection? rejection) {
  switch (rejection) {
    case DiscoveryRejection.replayedSequence:
      return DiscoveryIntakeStatus.replayed;
    case DiscoveryRejection.expired:
    case DiscoveryRejection.lifetimeTooLong:
      return DiscoveryIntakeStatus.expired;
    case DiscoveryRejection.noEndpoints:
    case DiscoveryRejection.tooManyEndpoints:
    case DiscoveryRejection.unsafeEndpoint:
      return DiscoveryIntakeStatus.unsafeEndpoints;
    case DiscoveryRejection.badSignature:
      return DiscoveryIntakeStatus.badSignature;
    case DiscoveryRejection.malformed:
    case DiscoveryRejection.unsupportedFormat:
    case DiscoveryRejection.tooLarge:
    case null:
      return DiscoveryIntakeStatus.malformed;
  }
}

/// Verifies pasted records and advances the discovery state.
///
/// Performs no I/O and reads no clock: [now] and the current state are passed
/// in, so this is fully testable and cannot itself emit anything.
class DiscoveryIntake {
  const DiscoveryIntake(this.verifier);

  factory DiscoveryIntake.fromCompiledDefines() =>
      DiscoveryIntake(DiscoveryRecordVerifier.fromCompiledDefines());

  final DiscoveryRecordVerifier verifier;

  bool get enforcing => verifier.enforcing;

  /// Verify a record the **user pasted** and, if it is good, advance the state.
  ///
  /// The floor advances **only** on acceptance, and only from the sequence
  /// inside the signed bytes — so an attacker who can make a record fail
  /// (by corrupting it in transit, say) cannot move the floor and lock the
  /// user out of a later genuine record.
  Future<DiscoveryIntakeOutcome> acceptPastedRecord(
    String pasted, {
    required DateTime now,
    required DiscoveryIntakeState current,
  }) =>
      _ingest(pasted,
          now: now, current: current, source: DiscoveryIntakeSource.pasteIn);

  /// Verify a record that **rode in on a hub response** the client was already
  /// polling, and, if it is good, advance the state.
  ///
  /// ## Why this exists
  ///
  /// Paste-in works for whoever hears about it. This works for everyone. A
  /// user who was connected at any point before a block already holds the next
  /// record and never has to know any of this happened — no feature to
  /// discover, no out-of-band channel to obtain a record through while blocked,
  /// no action to take under stress. Paste-in remains the answer for the
  /// cold-start user who installed *after* the block; the two are complements
  /// and together they cover both populations.
  ///
  /// ## What an observer sees
  ///
  /// Nothing. The record is a **field on a response already being fetched**
  /// ([kDiscoveryRecordResponseField]), so the client issues no extra request,
  /// on no new cadence, in no new shape. Outside the tunnel it is invisible
  /// because it rides an established connection; inside it, it is invisible
  /// because there is no additional request to see.
  ///
  /// ## No trusted transport
  ///
  /// This calls the identical verification path as [acceptPastedRecord] —
  /// same domain separation, same try-all-keys, same sequence floor, same
  /// fail-closed. Arriving inside the tunnel buys a record nothing. The hub is
  /// explicitly modelled as seizable, and a seized hub that could inject
  /// endpoints merely by serving them would defeat the entire point of signing.
  ///
  /// Idempotent: a hub may serve the same record on every poll forever. The
  /// first receipt applies it; every later one is [DiscoveryIntakeStatus
  /// .alreadyHeld] and costs nothing.
  Future<DiscoveryIntakeOutcome> ingestPrePositionedRecord(
    String served, {
    required DateTime now,
    required DiscoveryIntakeState current,
  }) =>
      _ingest(served,
          now: now,
          current: current,
          source: DiscoveryIntakeSource.prePositioned);

  Future<DiscoveryIntakeOutcome> _ingest(
    String incoming, {
    required DateTime now,
    required DiscoveryIntakeState current,
    required DiscoveryIntakeSource source,
  }) async {
    final raw = incoming.trim();
    DiscoveryIntakeOutcome bare(DiscoveryIntakeStatus status) =>
        DiscoveryIntakeOutcome(
          status: status,
          state: current,
          source: source,
          diagnostics: DiscoveryVerificationDiagnostics(
            enforcing: verifier.enforcing,
            compiledSlotIds: verifier.keyRing.compiledSlotIds,
            droppedSlotIds: verifier.keyRing.droppedSlotIds,
            trials: const <DiscoveryKeyTrial>[],
          ),
        );

    if (raw.isEmpty) return bare(DiscoveryIntakeStatus.empty);

    // Idempotency fast path. Not a trust shortcut: these exact bytes are
    // already retained and will be re-verified at use like every other stored
    // record. It exists so a hub serving the same record on every poll costs
    // no crypto and produces no log noise.
    if (current.rawRecords.contains(raw)) {
      return bare(DiscoveryIntakeStatus.alreadyHeld);
    }

    final report = await verifier.verify(
      raw,
      now: now,
      lastAcceptedSequence: current.seqFloor,
    );

    if (!report.accepted) {
      final status = report.diagnostics.signatureFailure ==
              DiscoverySignatureFailure.noKeysCompiled
          ? DiscoveryIntakeStatus.notProvisioned
          : _statusForRejection(report.rejection);
      // State is returned unchanged. Not a copy with the same values -- the
      // same object, so a caller that persists unconditionally writes exactly
      // what was already there.
      return DiscoveryIntakeOutcome(
        status: status,
        state: current,
        source: source,
        diagnostics: report.diagnostics,
      );
    }

    final record = report.record!;
    return DiscoveryIntakeOutcome(
      status: DiscoveryIntakeStatus.accepted,
      source: source,
      state: DiscoveryIntakeState(
        seqFloor: record.sequence,
        endpoints: mergeDiscoveredEndpoints(
          existing: current.endpoints,
          incoming: record.endpoints,
        ),
        acceptedSequence: record.sequence,
        rawRecords: _retain(raw, current.rawRecords),
      ),
      diagnostics: report.diagnostics,
      record: record,
    );
  }

  /// The endpoints that may actually be handed to the gateway sweep.
  ///
  /// **Re-verifies every retained record against the compiled keys, right
  /// now.** Nothing on disk is trusted: a record edited in storage, signed by a
  /// key this build does not carry, or that has since expired contributes no
  /// endpoints. So a tampered store can remove trust but can never inject a
  /// host — which is why the persisted endpoint list is safe to keep purely as
  /// a display cache.
  ///
  /// Expiry is enforced here, not merely at intake, and that is deliberate: a
  /// stale steering record must die to bound the blast radius of a key
  /// compromise. Endpoints stop being used once their record ages out, which
  /// is the mechanism that makes the owner's rotation tempo load-bearing.
  ///
  /// Records are re-verified newest first and their endpoints merged, so a
  /// newer record naming a host that turns out to be blocked does not destroy
  /// an older record's still-good hosts.
  Future<List<String>> endpointsForUse(
    DiscoveryIntakeState state, {
    required DateTime now,
  }) async {
    final usable = <String>[];
    for (final raw in state.rawRecords) {
      // lastAcceptedSequence 0: the replay floor is an *intake* control, and
      // a retained record's own sequence is by definition already at the
      // floor. What is being re-checked here is authenticity and freshness.
      final report =
          await verifier.verify(raw, now: now, lastAcceptedSequence: 0);
      final record = report.record;
      if (record == null) continue;
      for (final endpoint in record.endpoints) {
        if (usable.contains(endpoint)) continue;
        if (usable.length >= kMaxDiscoveryEndpoints) break;
        usable.add(endpoint);
      }
    }
    return List<String>.unmodifiable(usable);
  }

  Future<Map<String, DateTime>> endpointLeasesForUse(
    DiscoveryIntakeState state, {
    required DateTime now,
  }) async {
    final leases = <String, DateTime>{};
    for (final raw in state.rawRecords) {
      final report = await verifier.verify(
        raw,
        now: now,
        lastAcceptedSequence: 0,
      );
      final record = report.record;
      if (record == null) continue;

      final until = record.expiresAt.add(kDiscoveryClockSkewTolerance);
      for (final endpoint in record.endpoints) {
        final prior = leases[endpoint];
        if (prior != null) {
          if (until.isAfter(prior)) leases[endpoint] = until;
          continue;
        }
        if (leases.length >= kMaxDiscoveryEndpoints) break;
        leases[endpoint] = until;
      }
    }
    return Map<String, DateTime>.unmodifiable(leases);
  }

  static List<String> _retain(String raw, List<String> existing) {
    final retained = <String>[raw];
    for (final record in existing) {
      if (retained.contains(record)) continue;
      if (retained.length >= kMaxRetainedDiscoveryRecords) break;
      retained.add(record);
    }
    return List<String>.unmodifiable(retained);
  }
}

/// Fold a newly verified record's endpoints into the discovered set.
///
/// **The newest record wins the front of the list**, because it reflects the
/// owner's most recent judgement about what is reachable. Older discovered
/// endpoints are kept behind it rather than discarded: a record naming a host
/// that turns out to be blocked should not also destroy the previous host that
/// might still work. The set is capped at [kMaxDiscoveryEndpoints], which
/// bounds both how much a single compromised signer can steer and how many
/// distinct hosts the client can ever be induced to touch.
List<String> mergeDiscoveredEndpoints({
  required List<String> existing,
  required List<String> incoming,
}) {
  final merged = <String>[];
  void add(String endpoint) {
    final value = endpoint.trim();
    if (value.isEmpty || merged.contains(value)) return;
    if (merged.length >= kMaxDiscoveryEndpoints) return;
    merged.add(value);
  }

  for (final endpoint in incoming) {
    add(endpoint);
  }
  for (final endpoint in existing) {
    add(endpoint);
  }
  return List<String>.unmodifiable(merged);
}

/// The discovered endpoints that are worth handing to the gateway sweep.
///
/// ## What happens to the compiled Tier-0 list: nothing
///
/// It is never replaced, never reordered by a record, and never removed. A
/// discovery record is **additive only**. This is the property that makes the
/// channel safe to expose to a pasted string at all: the worst a signed record
/// can do is append hosts to the tail of a list whose head the attacker cannot
/// touch, and [planBootstrapAttempts] admits those tail entries only once
/// every compiled endpoint is blocked, at most one per launch.
///
/// So a discovered endpoint costs nothing on the happy path (it is never
/// reached), and on the censored path it is spent one at a time — a false
/// positive burns exactly one host rather than the whole reserve.
///
/// Endpoints already in the compiled set are dropped here: they are swept
/// anyway, and admitting a duplicate would waste the single per-launch slot on
/// a host the client just finished failing against.
List<String> discoveredEndpointsForSweep({
  required List<String> compiledEndpoints,
  required List<String> discovered,
}) {
  final compiled = compiledEndpoints.map(gatewayBase).toSet();
  final result = <String>[];
  for (final endpoint in discovered) {
    final base = gatewayBase(endpoint);
    if (base.isEmpty || compiled.contains(base) || result.contains(base)) {
      continue;
    }
    result.add(base);
  }
  return List<String>.unmodifiable(result);
}
