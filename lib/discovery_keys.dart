/// Ed25519 trust anchors for the **control-plane discovery record**.
///
/// ## Why this file exists at all
///
/// `bootstrap_resilience.dart` ships a complete, frozen, tested v1 record
/// parser ([verifyDiscoveryRecord]) that deliberately compiles in **no key
/// material**: it takes a [DiscoverySignatureVerifier] from its caller. Until
/// today nothing in the app supplied one, so the discovery channel existed on
/// paper and could never accept a record.
///
/// That gap is not a normal missing feature. The owner ships **one** client
/// release. Publishing a record is an operation that can be performed at any
/// time in the future; *consuming* one is code, and code that is not in the
/// release can never be added to the installed base. The migration design's
/// "everything can be added later except the public key" is true of publishing
/// and false of the client — the public key without this file is 32 bytes of
/// inert decoration. See
/// `docs/handoff/UNIFIED_SIGNING_KEY_MANAGEMENT_20260806.md` §5 row 5.
///
/// ## Two key families that must never be interchangeable
///
/// The announcement family (`a1 a2 a3`, `announcement_signature.dart`) signs
/// **text**; this family (`d1 d2 d3`) signs **where the app connects**. A
/// forged announcement is a lie a user might act on; a forged discovery record
/// silently hands session traffic and account state to attacker
/// infrastructure. Those blast radii do not belong behind one secret, and the
/// announcement private key is necessarily warm on a server that a hostile
/// state can seize while the discovery private key never touches a networked
/// machine.
///
/// Separation is enforced twice over, deliberately:
///
/// 1. **Disjoint key sets** — no key is ever in both rings.
/// 2. **Disjoint domain separators** — `winsvpn-announcement/v1` versus
///    `winsvpn-bootstrap-discovery/v1`, each applied as
///    `domain || 0x00 || payload`. So even a future mistake that collapsed the
///    key sets would still not let an announcement signature verify as a
///    discovery record, or the reverse.
///
/// Both directions are asserted in `test/discovery_record_client_test.dart`
/// against vectors produced by `openssl`, not by this code.
///
/// ## Rotation: try every compiled key
///
/// The frozen v1 wire format carries **no key id** — it was sized for a
/// 255-byte DNS TXT string and a `kid` field would cost bytes for nothing.
/// Rotation therefore lives here: [DiscoveryKeyRing] tries each compiled key
/// in turn and accepts if any verifies. At most three Ed25519 verifications,
/// on an event that happens roughly once per censorship incident. For honestly
/// generated distinct keys a signature valid under two of them is
/// computationally infeasible, so "any of the owner's three discovery keys" is
/// exactly the trust statement the announcement `kid` set expresses — reached
/// without touching the frozen parser.
///
/// This library holds no key material of its own. The keys arrive as
/// `--dart-define` values; a build with none is inert and the app behaves
/// exactly as it did before, which is what makes the rollout order safe by
/// construction rather than by a flag someone has to remember to flip.
library;

import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'bootstrap_resilience.dart';

/// Slot names for the discovery key family.
///
/// **These are file and operational names only — they never appear on the
/// wire.** They exist so a human can say "publish under d2" and so a
/// diagnostic can say which slot accepted a record. Contrast the announcement
/// family, whose `kid` is carried inside the signed payload.
const List<String> kDiscoveryKeySlotIds = <String>['d1', 'd2', 'd3'];

/// Raw Ed25519 public keys are exactly 32 bytes; signatures exactly 64.
const int kDiscoveryPublicKeyBytes = 32;
const int kDiscoverySignatureBytes = 64;

/// Compiled-in public halves, base64 of the raw 32-byte key — the value
/// `openssl pkey -pubout -outform DER | tail -c 32 | base64` produces, which is
/// what the key ceremony in the key-management design emits into
/// `client_build_defines.txt`.
///
/// **All three must be set on every platform build of the one release.** D1
/// missing means no client can ever verify a record and rotation after Tier-0
/// exhaustion is impossible forever; D2/D3 missing means a single discovery
/// key becomes a permanent single point of failure for the installed base.
const String kDiscoveryPublicKeyD1 =
    String.fromEnvironment('WINS_DISCOVERY_PUBKEY_D1', defaultValue: '');
const String kDiscoveryPublicKeyD2 =
    String.fromEnvironment('WINS_DISCOVERY_PUBKEY_D2', defaultValue: '');
const String kDiscoveryPublicKeyD3 =
    String.fromEnvironment('WINS_DISCOVERY_PUBKEY_D3', defaultValue: '');

const Map<String, String> kCompiledDiscoveryPublicKeys = <String, String>{
  'd1': kDiscoveryPublicKeyD1,
  'd2': kDiscoveryPublicKeyD2,
  'd3': kDiscoveryPublicKeyD3,
};

/// Why the signature step refused a record.
///
/// Distinguished from [DiscoveryRejection] (which covers *structural* refusal)
/// so an operator can tell "this build carries no keys" apart from "this
/// record was signed by something else" — two situations with completely
/// different responses that would otherwise both read as `badSignature`.
enum DiscoverySignatureFailure {
  /// No usable key is compiled into this build, so nothing can ever verify.
  /// The feature is inert; this is not an attack, it is a build mistake.
  noKeysCompiled,

  /// The signature field did not decode to 64 bytes. Screened here, before the
  /// crypto library is touched, mirroring the announcement envelope check —
  /// `splitDiscoveryRecord` only screens for non-empty.
  malformedSignatureLength,

  /// Every compiled key was tried and none verified these bytes. Either the
  /// record was signed by a key this build does not carry (a rotation that
  /// outran the installed base), or it is a forgery, or it was signed over the
  /// wrong bytes — classically, over the signed portion *including* its
  /// trailing pipe.
  noKeyAccepted,
}

/// One key's turn at a signature.
class DiscoveryKeyTrial {
  const DiscoveryKeyTrial({
    required this.slotId,
    required this.verified,
    required this.errored,
  });

  /// `d1`, `d2` or `d3`.
  final String slotId;

  /// Whether this key accepted the bytes.
  final bool verified;

  /// Whether the crypto library threw rather than returning false. Kept
  /// separate because "the library refused to look at this" and "the signature
  /// is wrong" are different failures and only the first is a bug report.
  final bool errored;
}

/// Why a record was or was not accepted, in enough detail to debug a failed
/// paste at 2am over a messaging app.
///
/// **Deliberately says nothing an observer could use.** It names slots, not
/// keys; counts, not bytes; and it never contains the record, the signature,
/// any hostname, or any key material. The whole point of the paste-in channel
/// is that it has no network fingerprint, and a diagnostic that echoed record
/// contents into a log would start manufacturing one.
class DiscoveryVerificationDiagnostics {
  const DiscoveryVerificationDiagnostics({
    required this.enforcing,
    required this.compiledSlotIds,
    required this.droppedSlotIds,
    required this.trials,
    this.signatureFailure,
    this.acceptedSlotId,
    this.structuralRejection,
  });

  /// True when at least one well-formed key is compiled in.
  final bool enforcing;

  /// Slots that yielded a usable 32-byte key.
  final List<String> compiledSlotIds;

  /// Slots whose define was present but unusable (not base64, wrong length).
  /// A typo in a build define must degrade to "that key does not exist", never
  /// to a verifier that accepts anything — and it must be *visible*, because
  /// silently shipping two keys instead of three is exactly the kind of
  /// mistake that stays hidden until the day it matters.
  final List<String> droppedSlotIds;

  /// Each key's turn, in slot order. Empty when the record never reached the
  /// signature step.
  final List<DiscoveryKeyTrial> trials;

  /// Set when the signature step refused.
  final DiscoverySignatureFailure? signatureFailure;

  /// The slot that accepted, when one did.
  final String? acceptedSlotId;

  /// Set when the record was refused before the signature step — malformed,
  /// expired, replayed, unsafe endpoint, and so on.
  final DiscoveryRejection? structuralRejection;

  bool get accepted => acceptedSlotId != null;

  /// A short, log-safe line. Contains only slot names and enum names.
  String describe() {
    if (!enforcing) return 'discovery: no keys compiled (feature inert)';
    if (acceptedSlotId != null) {
      return 'discovery: accepted by $acceptedSlotId '
          '(compiled ${compiledSlotIds.join("/")}'
          '${droppedSlotIds.isEmpty ? "" : ", dropped ${droppedSlotIds.join("/")}"})';
    }
    final parts = <String>[
      'compiled ${compiledSlotIds.join("/")}',
      if (droppedSlotIds.isNotEmpty) 'dropped ${droppedSlotIds.join("/")}',
      if (structuralRejection != null)
        'structural ${structuralRejection!.name}',
      if (signatureFailure != null) 'signature ${signatureFailure!.name}',
      if (trials.isNotEmpty)
        'tried ${trials.map((t) => t.errored ? "${t.slotId}!" : t.slotId).join("/")}',
    ];
    return 'discovery: rejected (${parts.join("; ")})';
  }
}

/// The compiled discovery trust anchors, and the try-all-keys verifier over
/// them.
class DiscoveryKeyRing {
  DiscoveryKeyRing._(this._keys, this.droppedSlotIds);

  /// Build from a slot-id → base64 map, dropping anything unusable.
  ///
  /// An entry that is empty is simply absent (that slot was not provisioned).
  /// An entry that is present but not a well-formed raw 32-byte key is
  /// *dropped and reported* via [droppedSlotIds].
  factory DiscoveryKeyRing.fromEncoded(Map<String, String> encoded) {
    final keys = <String, List<int>>{};
    final dropped = <String>[];
    for (final slotId in kDiscoveryKeySlotIds) {
      final value = encoded[slotId];
      if (value == null || value.trim().isEmpty) continue;
      try {
        final bytes = base64.decode(value.trim());
        if (bytes.length == kDiscoveryPublicKeyBytes) {
          keys[slotId] = List<int>.unmodifiable(bytes);
        } else {
          dropped.add(slotId);
        }
      } catch (_) {
        dropped.add(slotId);
      }
    }
    return DiscoveryKeyRing._(
      Map<String, List<int>>.unmodifiable(keys),
      List<String>.unmodifiable(dropped),
    );
  }

  /// The ring this build actually ships, from the `--dart-define` values.
  factory DiscoveryKeyRing.fromCompiledDefines() =>
      DiscoveryKeyRing.fromEncoded(kCompiledDiscoveryPublicKeys);

  final Map<String, List<int>> _keys;

  /// Slots whose define was present but unusable.
  final List<String> droppedSlotIds;

  /// Slots that yielded a usable key, in `d1 d2 d3` order.
  List<String> get compiledSlotIds =>
      kDiscoveryKeySlotIds.where(_keys.containsKey).toList(growable: false);

  /// True once at least one usable key is compiled in. False means the
  /// discovery channel cannot run at all and the app keeps today's behaviour.
  bool get enforcing => _keys.isNotEmpty;

  /// Try every compiled key against [message]/[signature].
  ///
  /// [message] arrives already domain-separated by [discoverySigningBytes] —
  /// this method must never prepend a domain itself, or it would double it.
  ///
  /// Returns the accepting slot, or null. [trials] is filled in slot order.
  Future<String?> _firstSlotAccepting(
    List<int> message,
    List<int> signature,
    List<DiscoveryKeyTrial> trials,
  ) async {
    for (final slotId in kDiscoveryKeySlotIds) {
      final keyBytes = _keys[slotId];
      if (keyBytes == null) continue;
      var verified = false;
      var errored = false;
      try {
        verified = await Ed25519().verify(
          message,
          signature: Signature(
            signature,
            publicKey: SimplePublicKey(keyBytes, type: KeyPairType.ed25519),
          ),
        );
      } catch (_) {
        errored = true;
      }
      trials.add(DiscoveryKeyTrial(
        slotId: slotId,
        verified: verified,
        errored: errored,
      ));
      if (verified) return slotId;
    }
    return null;
  }
}

/// Verifies a raw discovery record against the compiled key ring, and reports
/// why when it will not.
class DiscoveryRecordVerifier {
  const DiscoveryRecordVerifier(this.keyRing);

  /// The verifier this build ships.
  factory DiscoveryRecordVerifier.fromCompiledDefines() =>
      DiscoveryRecordVerifier(DiscoveryKeyRing.fromCompiledDefines());

  final DiscoveryKeyRing keyRing;

  bool get enforcing => keyRing.enforcing;

  /// Structurally validate, then verify, a raw record.
  ///
  /// **Fails closed**: any refusal yields no endpoints at all. There is no
  /// partial acceptance, because a discovery channel that can be steered is
  /// worse than none. But the refusal is *diagnosable* — the returned
  /// [DiscoveryVerificationReport.diagnostics] says which key was tried and
  /// what went wrong, in terms safe to log.
  ///
  /// [lastAcceptedSequence] must be the **discovery** floor. Passing the
  /// announcement floor here would let one channel poison the other: an
  /// attacker holding a valid announcement key can drive that floor
  /// arbitrarily high, and a shared counter would turn that into a permanent
  /// denial of discovery — the exact channel needed to recover.
  Future<DiscoveryVerificationReport> verify(
    String raw, {
    required DateTime now,
    required int lastAcceptedSequence,
  }) async {
    final trials = <DiscoveryKeyTrial>[];
    String? acceptedSlotId;
    DiscoverySignatureFailure? failure;

    if (!keyRing.enforcing) {
      // Nothing can ever verify. Say so plainly rather than reporting a bad
      // signature, which would send an operator hunting for the wrong bug.
      return DiscoveryVerificationReport(
        result: const DiscoveryParseResult.rejected(
          DiscoveryRejection.badSignature,
        ),
        diagnostics: DiscoveryVerificationDiagnostics(
          enforcing: false,
          compiledSlotIds: keyRing.compiledSlotIds,
          droppedSlotIds: keyRing.droppedSlotIds,
          trials: const <DiscoveryKeyTrial>[],
          signatureFailure: DiscoverySignatureFailure.noKeysCompiled,
        ),
      );
    }

    final result = await verifyDiscoveryRecord(
      raw,
      now: now,
      lastAcceptedSequence: lastAcceptedSequence,
      verifier: (message, signature) async {
        // Length screen before the crypto library, harmonising with the
        // announcement envelope's `!= 64` check. `splitDiscoveryRecord` only
        // screens for non-empty, by design — the frozen library is not
        // changed to fix this; the caller is where it belongs.
        if (signature.length != kDiscoverySignatureBytes) {
          failure = DiscoverySignatureFailure.malformedSignatureLength;
          return false;
        }
        acceptedSlotId =
            await keyRing._firstSlotAccepting(message, signature, trials);
        if (acceptedSlotId == null) {
          failure = DiscoverySignatureFailure.noKeyAccepted;
          return false;
        }
        return true;
      },
    );

    // A structural refusal never reaches the verifier callback, so an empty
    // trial list with no signature failure means the record died earlier.
    final structural =
        (!result.accepted && failure == null) ? result.rejection : null;

    return DiscoveryVerificationReport(
      result: result,
      diagnostics: DiscoveryVerificationDiagnostics(
        enforcing: true,
        compiledSlotIds: keyRing.compiledSlotIds,
        droppedSlotIds: keyRing.droppedSlotIds,
        trials: List<DiscoveryKeyTrial>.unmodifiable(trials),
        signatureFailure: failure,
        acceptedSlotId: result.accepted ? acceptedSlotId : null,
        structuralRejection: structural,
      ),
    );
  }
}

/// A verification attempt and why it went the way it did.
class DiscoveryVerificationReport {
  const DiscoveryVerificationReport({
    required this.result,
    required this.diagnostics,
  });

  final DiscoveryParseResult result;
  final DiscoveryVerificationDiagnostics diagnostics;

  bool get accepted => result.accepted;
  DiscoveryRecord? get record => result.record;
  DiscoveryRejection? get rejection => result.rejection;
}
