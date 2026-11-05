/// Ed25519 authenticity for the global announcement channel.
///
/// Why this exists: the privileged announcement endpoint is gated by one
/// fleet-wide shared credential. Possession of that credential is enough to push
/// arbitrary text to every installed app inside ~60 seconds. For a population
/// under a hostile state the realistic abuse is not defacement -- it is a
/// credible-looking instruction ("service compromised, install this build",
/// "authorities have your account, delete the app"). A signature the hub cannot
/// forge without the offline private key is the only control that makes a
/// a leaked publishing credential insufficient.
///
/// This library holds **no key material**. The trusted public keys are passed
/// in by the caller, exactly like [DiscoverySignatureVerifier] in
/// `bootstrap_resilience.dart`: until the owner provisions keys there is
/// nothing to pass, and the app simply behaves as it did before.
library;

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart' show kReleaseMode;

/// Reviewed ceremony public keys for the announcement channel.
///
/// These are the PUBLIC Ed25519 halves of the announcement signing keypairs
/// (`a1` is the active signing key; `a2`/`a3` are the pre-generated offline
/// successors). They are safe in the repo and in a build log. Announcements
/// are signed OFFLINE, exactly like gateway descriptors (Fable 5.1 ruling
/// IA-CP-06, 2026-09-29): the private keys never touch the hub. The hub holds
/// only these public halves, verifies an uploaded envelope, refuses a
/// non-increasing `seq`, and serves the envelope verbatim, so this verifier
/// checks the operator tool's bytes unchanged.
///
/// Base64 of the RAW 32-byte Ed25519 public key, one per key id, exactly like
/// the descriptor ring's `kWinn3ReviewedDescriptorPubkeyG1..G3`: these are
/// the `String.fromEnvironment` defaults, so `--dart-define=WINS_ANNOUNCE_
/// PUBKEY_A*` still overrides a slot, and an empty or unusable override drops
/// that slot and fail-closes. A build with no usable keys is NOT enforcing
/// and keeps the pre-signing behaviour; the moment any real key is compiled
/// in, the app refuses to display an announcement that does not verify.
/// That is what makes the rollout order safe by construction instead of by a
/// flag someone has to remember to flip.
///
/// Release builds cannot be non-enforcing at all: compiling an empty or
/// malformed keyring into a RELEASE build throws a [StateError] at verifier
/// construction ([AnnouncementVerifier.fromCompiledDefines]). The
/// non-enforcing state is reachable only in debug/profile builds and only
/// when every slot was explicitly emptied through the build defines.
const String kReviewedAnnouncementPubkeyA1 =
    'd9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';
const String kReviewedAnnouncementPubkeyA2 =
    'Toj52qgUbbwgEBja6mtjwQYkOd76lWhoB8+hrlCINgk=';
const String kReviewedAnnouncementPubkeyA3 =
    'sFiAZSm+xTxXNA6uEWNfCMfy/rb6tn4Rtg1SMHU6GvI=';

const String _kWinsAnnouncePubkeyA1 = String.fromEnvironment(
  'WINS_ANNOUNCE_PUBKEY_A1',
  defaultValue: kReviewedAnnouncementPubkeyA1,
);
const String _kWinsAnnouncePubkeyA2 = String.fromEnvironment(
  'WINS_ANNOUNCE_PUBKEY_A2',
  defaultValue: kReviewedAnnouncementPubkeyA2,
);
const String _kWinsAnnouncePubkeyA3 = String.fromEnvironment(
  'WINS_ANNOUNCE_PUBKEY_A3',
  defaultValue: kReviewedAnnouncementPubkeyA3,
);

/// The compiled-in key set, `a1 a2 a3`, built exactly the way
/// [Winn3DescriptorKeyRing.fromCompiledDefines] builds the descriptor ring.
Map<String, String> compiledAnnouncementPublicKeys() {
  return <String, String>{
    'a1': _kWinsAnnouncePubkeyA1,
    'a2': _kWinsAnnouncePubkeyA2,
    'a3': _kWinsAnnouncePubkeyA3,
  };
}

/// Signature domain, constructed exactly like `bootstrap_resilience.dart`'s
/// [discoverySigningBytes] and `internal/pqauth`'s `SignDomainMessage`:
/// `domain || 0x00 || message`. Domain separation is not optional -- without
/// it a signature made over some other project object (a discovery record, a
/// gateway manifest) could be replayed as an announcement, and vice versa.
const String kAnnouncementSignatureDomain = 'winsvpn-announcement/v1';

/// Hard ceiling on the encoded payload. The rendered text is already capped at
/// 900 characters client-side; this bounds the work done *before* the
/// signature is checked, so an unauthenticated blob cannot cost much.
const int kMaxAnnouncementPayloadBytes = 8192;

/// Why an announcement was not accepted. Every one of these lands the client on
/// the bundled default string, which is compiled into the signed app and is
/// therefore trusted by construction.
enum AnnouncementRejection {
  /// No `announcement_signed` object at all. Either the hub predates signing,
  /// or something stripped the field. Fail closed -- see the class docs on
  /// [AnnouncementVerifier] for the residual denial-of-announcements risk.
  missingSignature,

  /// The envelope was not shaped like one: missing fields, not base64, too big.
  malformedEnvelope,

  /// The payload verified structurally but is not the JSON object we expect.
  malformedPayload,

  /// The `kid` names a key this build does not carry. This is the key-rotation
  /// stranding case: a client that predates the key now in use rejects
  /// everything, permanently and silently, until the app itself is updated.
  unknownKeyId,

  /// The signature is not valid for these bytes under that key.
  badSignature,

  /// `seq` is below the highest this device has already accepted. This is the
  /// replay control: without it, an attacker who captured any previously valid
  /// announcement could re-serve it indefinitely -- "all systems normal"
  /// during an actual outage, which is precisely when the channel matters.
  replayedSequence,

  /// Verified, but carries nothing displayable.
  emptyText,
}

/// A verified announcement. Only ever constructed after the signature checks
/// out, so every field here is authentic.
class AnnouncementEnvelope {
  const AnnouncementEnvelope({
    required this.text,
    required this.sequence,
    required this.issuedAt,
    required this.keyId,
  });

  /// The announcement text as signed. The client displays **this**, never the
  /// sibling plaintext `announcement` field -- so modifying or stripping the
  /// plaintext field changes nothing for an enforcing client.
  final String text;

  /// Monotonic counter. The hub increments it on every accepted post.
  final int sequence;

  /// When the hub signed it.
  ///
  /// Deliberately **not** an acceptance criterion. A hard maximum age would
  /// silently blank the announcement channel for every device with a skewed
  /// clock, and skew is common on the cheap Android hardware this service is
  /// used on. That would be a self-inflicted denial of exactly the channel this
  /// change exists to protect. [sequence] is the anti-replay control; `issuedAt`
  /// is provenance the owner can inspect, and is signed so it cannot be forged.
  ///
  /// There is deliberately **no** clock-skew ceiling. One was defined once,
  /// documented as if it were enforced, and referenced by nothing -- removed
  /// 2026-08-06. A bound on `iat` defends against nothing: the field sits
  /// inside the signed bytes, so an attacker without the key cannot set it at
  /// all, and an attacker holding the key has no reason to choose an absurd
  /// value. Its only realistic trigger would be a device with a wrong clock or
  /// a hub bug -- i.e. it would fail closed on precisely the users least able
  /// to diagnose it. Do not reintroduce one.
  final DateTime issuedAt;

  /// Which key signed it. Carried inside the signed bytes, so an attacker
  /// cannot relabel a payload to point at a different key.
  final String keyId;
}

/// Outcome of a verification attempt: exactly one of [envelope] or [rejection]
/// is non-null.
class AnnouncementVerification {
  const AnnouncementVerification.accepted(AnnouncementEnvelope this.envelope)
      : rejection = null;
  const AnnouncementVerification.rejected(AnnouncementRejection this.rejection)
      : envelope = null;

  final AnnouncementEnvelope? envelope;
  final AnnouncementRejection? rejection;

  bool get accepted => envelope != null;
}

/// The exact bytes the hub signs and the client verifies.
///
/// [payloadBytes] is the raw, base64-decoded payload **as it arrived** -- never
/// a re-serialisation of parsed fields. Re-serialising is how signature checks
/// end up validating something other than what was received: two JSON encoders
/// disagree about key order, unicode escaping or float formatting, and the
/// bytes verified stop being the bytes acted on. Same reasoning as
/// [splitDiscoveryRecord] in `bootstrap_resilience.dart`.
List<int> announcementSigningBytes(List<int> payloadBytes) {
  return <int>[
    ...utf8.encode(kAnnouncementSignatureDomain),
    0,
    ...payloadBytes,
  ];
}

/// Resolves the compiled announcement key defines into the `kid` -> raw
/// 32-byte Ed25519 key map the verifier trusts, applying the build-mode
/// policy. Pure so the policy itself is testable with any [defines].
///
/// Policy (see the library docs):
///
///  * RELEASE ([isReleaseBuild] true): an empty or malformed keyring is a
///    build error. Any slot that is empty or does not decode to a raw
///    32-byte Ed25519 public key throws a [StateError]; a release artifact
///    therefore always enforces.
///  * DEBUG/PROFILE: the non-enforcing (empty) state is allowed only when
///    every slot was explicitly emptied. If a slot is malformed (non-empty
///    but unusable) and no usable key remains, that is not "explicitly
///    empty" and throws too. A malformed slot alongside at least one usable
///    key is dropped, degrading to "that key does not exist".
Map<String, List<int>> compiledAnnouncementTrustedKeys({
  required bool isReleaseBuild,
  Map<String, String>? defines,
}) {
  final slots = defines ?? compiledAnnouncementPublicKeys();
  final keys = <String, List<int>>{};
  final unusable = <String>[];

  for (final entry in slots.entries) {
    final keyId = entry.key;
    final encoded = entry.value;
    if (encoded.isEmpty) {
      unusable.add('$keyId: empty');
      continue;
    }
    List<int> bytes;
    try {
      bytes = base64.decode(encoded);
    } on FormatException {
      unusable.add('$keyId: not valid base64');
      continue;
    }
    if (bytes.length != 32) {
      unusable.add('$keyId: ${bytes.length} bytes, not a raw 32-byte '
          'Ed25519 public key');
      continue;
    }
    keys[keyId] = bytes;
  }

  if (isReleaseBuild && unusable.isNotEmpty) {
    throw StateError(
      'Announcement verification keyring is misprovisioned in a release '
      'build (${unusable.join('; ')}). Every WINS_ANNOUNCE_PUBKEY_* define '
      'must be the base64 of a raw 32-byte Ed25519 public key. A release '
      'build must enforce announcement signatures; refusing to ship.',
    );
  }
  if (keys.isNotEmpty) return keys;

  // The ring is empty. Non-enforcing is only legitimate when the build
  // EXPLICITLY emptied every slot (the debug/dev escape), never from
  // malformed defines or from a release build.
  if (isReleaseBuild) {
    throw StateError(
      'Announcement verification keyring is empty in a release build. A '
      'release build must enforce announcement signatures; refusing to '
      'ship.',
    );
  }
  final allExplicitlyEmpty = slots.values.every((encoded) => encoded.isEmpty);
  if (!allExplicitlyEmpty) {
    throw StateError(
      'Announcement verification keyring resolved to no usable key from '
      'malformed defines (${unusable.join('; ')}). Non-enforcing is only '
      'allowed when every slot is explicitly emptied in a debug build.',
    );
  }
  return keys;
}

/// Verifies announcements against a fixed set of public keys compiled into the
/// signed app.
///
/// **Fail-closed, and that is deliberate.** An attacker positioned to strip the
/// `announcement_signed` field forces every client onto the bundled default --
/// a denial-of-announcements attack. Failing closed is still correct: the
/// alternative (display unsigned text) hands that same attacker the forgery
/// this whole change exists to prevent, which is strictly worse. The residual
/// risk is real and is not papered over here: a party who can strip the field
/// can suppress announcements. Note that party must already be either the hub
/// operator or inside TLS, and a seized hub can suppress announcements by
/// simply not serving them, so fail-closed concedes nothing that was not
/// already lost.
///
/// **Key rotation.** [trustedKeys] is a *set*, keyed by `kid`. Ship more keys
/// than are in use so the hub can rotate to a successor without stranding the
/// installed base. A client that predates the key it needs rejects everything
/// and shows the bundled default forever -- it cannot be told to update over
/// this channel, because this channel is what is broken. Recovery for those
/// users runs over the independent force-update gate (`min_supported_version`
/// on `/nodes`), which does not depend on announcement signing.
class AnnouncementVerifier {
  const AnnouncementVerifier(this.trustedKeys);

  /// The verifier this build actually uses: [compiledAnnouncementTrustedKeys]
  /// over the compiled defines, with [kReleaseMode] as the build-mode fact.
  /// See that function for the per-mode policy; in a release build an empty
  /// or malformed keyring throws here at construction.
  factory AnnouncementVerifier.fromCompiledDefines() {
    return AnnouncementVerifier(
      compiledAnnouncementTrustedKeys(isReleaseBuild: kReleaseMode),
    );
  }

  /// `kid` -> raw 32-byte Ed25519 public key.
  ///
  /// Empty means "not provisioned": [enforcing] is false and the caller keeps
  /// today's behaviour. That state is reachable only in debug/profile builds
  /// whose defines explicitly emptied every slot (see
  /// [compiledAnnouncementTrustedKeys]); release builds construct an
  /// enforcing verifier or throw.
  final Map<String, List<int>> trustedKeys;

  /// True once at least one real key is compiled in.
  bool get enforcing => trustedKeys.isNotEmpty;

  /// Verify the `announcement_signed` object on a hub response.
  ///
  /// [minimumSequence] is the highest sequence this device has already
  /// accepted. A payload at or above it is accepted (the same announcement
  /// legitimately arrives on all four polled routes, so equality must pass);
  /// anything below it is a replay.
  Future<AnnouncementVerification> verify(
    Map<String, dynamic> response, {
    required int minimumSequence,
  }) async {
    final raw = response['announcement_signed'];
    if (raw is! Map) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.missingSignature);
    }
    final envelope = Map<String, dynamic>.from(raw);
    final encodedPayload = envelope['payload'];
    final encodedSignature = envelope['sig'];
    if (encodedPayload is! String ||
        encodedSignature is! String ||
        encodedPayload.isEmpty ||
        encodedSignature.isEmpty) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.malformedEnvelope);
    }

    List<int> payloadBytes;
    List<int> signatureBytes;
    try {
      payloadBytes = base64.decode(encodedPayload);
      signatureBytes = base64.decode(encodedSignature);
    } catch (_) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.malformedEnvelope);
    }
    if (payloadBytes.isEmpty ||
        payloadBytes.length > kMaxAnnouncementPayloadBytes ||
        signatureBytes.length != 64) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.malformedEnvelope);
    }

    // Parse before verifying, purely to learn which key to check against.
    // This is safe: nothing here is acted on, and an attacker who names a key
    // still has to produce a valid signature under it. The authoritative `kid`
    // is the one inside the signed bytes -- the outer envelope's copy, if any,
    // is only a hint and is never trusted.
    Map<String, dynamic> payload;
    try {
      final decoded = jsonDecode(utf8.decode(payloadBytes));
      if (decoded is! Map) {
        return const AnnouncementVerification.rejected(
            AnnouncementRejection.malformedPayload);
      }
      payload = Map<String, dynamic>.from(decoded);
    } catch (_) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.malformedPayload);
    }

    final keyId = payload['kid'];
    final sequence = payload['seq'];
    final issuedAt = payload['iat'];
    final text = payload['text'];
    if (keyId is! String ||
        keyId.isEmpty ||
        sequence is! int ||
        issuedAt is! int ||
        text is! String) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.malformedPayload);
    }

    final publicKeyBytes = trustedKeys[keyId];
    if (publicKeyBytes == null) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.unknownKeyId);
    }

    bool valid;
    try {
      valid = await Ed25519().verify(
        announcementSigningBytes(payloadBytes),
        signature: Signature(
          signatureBytes,
          publicKey:
              SimplePublicKey(publicKeyBytes, type: KeyPairType.ed25519),
        ),
      );
    } catch (_) {
      valid = false;
    }
    if (!valid) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.badSignature);
    }

    // Everything below this line is authenticated.
    if (sequence < minimumSequence) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.replayedSequence);
    }
    if (text.trim().isEmpty) {
      return const AnnouncementVerification.rejected(
          AnnouncementRejection.emptyText);
    }

    return AnnouncementVerification.accepted(AnnouncementEnvelope(
      text: text,
      sequence: sequence,
      issuedAt:
          DateTime.fromMillisecondsSinceEpoch(issuedAt * 1000, isUtc: true),
      keyId: keyId,
    ));
  }
}
