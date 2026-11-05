/// Which version of Winn Protocol, and which transport, a LIVE session is
/// actually using.
///
/// ---------------------------------------------------------------------------
/// WHAT THIS FILE DOES NOT DO, and why that matters more than what it does.
///
/// `Winn Protocol®` is the name of the PRODUCT'S TUNNEL STACK, and the
/// status-line label carrying it is a product name, not a claim about wire
/// format. Nothing in this file weakens, hedges or re-attributes it, and
/// nothing here is a disclaimer about it.
///
/// What this file does NOT assert, in either direction, is how much of the
/// stack under that name is first-party at a given version. That question is
/// genuinely contested and must be settled from evidence, not from a comment.
/// The state of the evidence in THIS tree, as of 2026-08-07:
///
///   * `winn/1` selects the AmneziaWG path. `winn_protocol_dispatch.dart`'s
///     own doc comment on [kWinnProtocolV1] reads "The shipping protocol:
///     AmneziaWG, unchanged"; the `case kWinnProtocolV1:` arm in `main.dart`
///     is `break;`, commented "the strict no-op for every shipping config";
///     and `test/winn_protocol_dispatch_test.dart` has a group named
///     "winn/1 stays a strict no-op". No first-party v1 framing, handshake or
///     negotiation exists in the tree. What IS first-party on that path is
///     real but is policy and control-plane work -- the AWG obfuscation
///     policy, the parameter validator in `vpn_config_validation.dart`, the
///     transport-selection and failover ladder, and the anti-downgrade rule.
///   * `winn/3` is substantial first-party protocol engineering
///     (`winn_protocol_experimental/`), and is a CARRIER for AmneziaWG's
///     already-encrypted outer datagrams -- AWG keeps the tun and does the
///     cryptography at both versions.
///
/// If that reading is ever superseded, supersede it with a citation, not an
/// assertion. A previous lane spent a session acting on the opposite reading
/// of `winn/1` and it cost real time, which is why the evidence is written
/// down here beside the code that depends on it.
///
/// ---------------------------------------------------------------------------
/// WHAT IT DOES.
///
/// The product name deliberately does not answer a narrower question that a
/// user on a censored network needs to be able to answer: **which version is
/// carrying THIS session, and over which transport.** A user who cannot find
/// that out cannot act on it -- cannot tell whether to expect the throughput
/// of the direct path or the survivability of the stealth path, and cannot
/// report a useful fact when a session fails. This file answers exactly that,
/// additively, and nothing else.
///
/// ---------------------------------------------------------------------------
/// THE HONESTY RULE THIS FILE EXISTS TO ENFORCE.
///
/// The version is reported from the NEGOTIATED `protocol_version` of the
/// config the live tunnel actually committed -- never from a build flag, never
/// from a served config that has not started, never from a default. Three
/// values, on the same principle as `BridgeWinnState` in
/// `browser_bridge_protocol.dart` and the antivirus lane's rule that a source
/// which could not be read is different from one read and empty:
///
///   * [WinnSessionVersion.none]     -- there is no live session. NOT "v1".
///   * [WinnSessionVersion.v1]       -- the session negotiated `winn/1`.
///   * [WinnSessionVersion.v3]       -- the session negotiated `winn/3`.
///   * [WinnSessionVersion.unrecognised] -- the session negotiated something
///     this build has no name for. The app says so rather than guessing; a
///     guess here would be the exact silent-downgrade lie the dispatch seam in
///     `main.dart` refuses to tell on the wire.
///
/// In particular: **"Version 3" is never produced unless `winn/3` was the
/// negotiated value.** `test/winn_session_descriptor_test.dart` proves it, and
/// proves the paired presence rule too -- deleting the product name is not an
/// acceptable way to pass an absence check.
library;

import 'winn_protocol_dispatch.dart' show kWinnProtocolV1, kWinnProtocolV3;

/// The negotiated Winn Protocol version of a live session, honestly valued.
enum WinnSessionVersion {
  /// No live tunnel. Deliberately distinct from [v1]: "not connected" is not
  /// a protocol version, and rendering it as one would assert a session that
  /// does not exist.
  none,

  /// The session negotiated `winn/1`, which selects the AmneziaWG path.
  /// Displayed as a VERSION OF THE PRODUCT'S STACK, which is what the wire
  /// value literally is. Deliberately not annotated here as first- or
  /// third-party: see the library comment for why that is a separate,
  /// evidence-bound question.
  v1,

  /// The session negotiated `winn/3`, the first-party Winn carrier.
  v3,

  /// The session negotiated a `protocol_version` this build cannot name.
  /// Reported as unrecognised rather than defaulted, so a future or corrupted
  /// value can never be displayed as v1.
  unrecognised,
}

/// Which transport is carrying the session's outer datagrams.
enum WinnSessionTransport {
  /// No live tunnel, so no transport.
  none,

  /// The direct path. Lower overhead, more distinguishable on the wire.
  direct,

  /// The stealth transport. Higher overhead, designed to survive inspection.
  stealth,
}

/// Maps a committed session's negotiated `protocol_version` to a version.
///
/// [rawProtocolVersion] must come from the config the live tunnel COMMITTED.
/// An empty string means "no live session" and yields [WinnSessionVersion.none]
/// -- this function deliberately does NOT apply the
/// `normalizedWinnProtocolVersion` absent-means-v1 rule, because that rule
/// exists to keep old *configs* working and would, here, turn "no session" into
/// a claim that version 1 is running.
WinnSessionVersion winnSessionVersion({
  required bool isConnected,
  required String rawProtocolVersion,
}) {
  if (!isConnected) return WinnSessionVersion.none;
  final value = rawProtocolVersion.trim();
  if (value.isEmpty) return WinnSessionVersion.none;
  if (value == kWinnProtocolV1) return WinnSessionVersion.v1;
  if (value == kWinnProtocolV3) return WinnSessionVersion.v3;
  return WinnSessionVersion.unrecognised;
}

/// Which transport a live session is using.
WinnSessionTransport winnSessionTransport({
  required bool isConnected,
  required bool stealthActive,
}) {
  if (!isConnected) return WinnSessionTransport.none;
  return stealthActive
      ? WinnSessionTransport.stealth
      : WinnSessionTransport.direct;
}

/// The English source string naming the version, or `''` when there is no
/// live session.
///
/// Returned as a whole English phrase so it is a key into the hand-rolled
/// translation map in `main.dart` (this app has no ARB layer). Every string
/// this function can return MUST have an entry in that map's `my` and `de`
/// blocks; `test/winn_session_descriptor_test.dart` fails if one is missing,
/// because a Burmese user who cannot read which version they are on cannot act
/// on it.
String winnSessionVersionPhrase(WinnSessionVersion version) {
  switch (version) {
    case WinnSessionVersion.none:
      return '';
    case WinnSessionVersion.v1:
      return 'Version 1';
    case WinnSessionVersion.v3:
      return 'Version 3';
    case WinnSessionVersion.unrecognised:
      return 'Version not recognised by this app';
  }
}

/// The English source string naming the transport, or `''` when there is no
/// live session. Same translation obligation as [winnSessionVersionPhrase].
String winnSessionTransportPhrase(WinnSessionTransport transport) {
  switch (transport) {
    case WinnSessionTransport.none:
      return '';
    case WinnSessionTransport.direct:
      return 'direct transport';
    case WinnSessionTransport.stealth:
      return 'stealth transport';
  }
}

/// Every English phrase this file can put on screen. The test uses this to
/// assert the translation map covers all of them, so adding a phrase without
/// translating it fails the suite rather than silently shipping English to a
/// Burmese reader.
const List<String> kWinnSessionDetailPhrases = <String>[
  'Version 1',
  'Version 3',
  'Version not recognised by this app',
  'direct transport',
  'stealth transport',
  'Session:',
];

/// Composes the session-detail line from already-translated parts.
///
/// [translate] is `main.dart`'s `_t`. Composition happens here rather than in
/// `main.dart` so the ordering rule is testable: the two parts are joined with
/// a middot, which reads correctly in English, German and Burmese without
/// depending on either part's grammatical role.
///
/// Returns `''` when there is no live session, so the caller renders nothing
/// rather than rendering a claim about a session that is not running.
String winnSessionDetail({
  required WinnSessionVersion version,
  required WinnSessionTransport transport,
  required String Function(String) translate,
}) {
  final versionPhrase = winnSessionVersionPhrase(version);
  final transportPhrase = winnSessionTransportPhrase(transport);
  if (versionPhrase.isEmpty || transportPhrase.isEmpty) return '';
  return '${translate(versionPhrase)} · ${translate(transportPhrase)}';
}
