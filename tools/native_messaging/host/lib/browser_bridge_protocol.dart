// The message schema spoken between the browser extension and the desktop app.
//
// This file is the single source of truth for the wire contract. The extension
// lane implements the other half against it; nothing here may be changed
// without bumping [kBridgeProtocolVersion].
//
// No Flutter import: this is compiled into `bin/wins_bridge_host.dart` as well
// as into the test suite.
//
// ---------------------------------------------------------------------------
// THE DESIGN RULE THAT SHAPES EVERYTHING BELOW
// ---------------------------------------------------------------------------
//
// An extension bundle is plain JavaScript and JSON. Anyone who can install it
// can unpack it and read every byte, so the extension may hold no real
// infrastructure address in any form. Every real address stays on this side of
// the channel.
//
// The weak way to honour that is to remember not to put addresses in messages.
// The strong way -- the one taken here -- is to make an address **not
// representable**:
//
//  * Every outbound field is a closed enum, a bounded integer, a bool, or a
//    charset-validated identifier. There is no free-form outbound string. In
//    particular `detail` is a [BridgeDetailCode], not text, so a status line
//    that happened to contain the user's public IP has nowhere to go.
//  * A node is a slug, a display name and a flag. [kSlugPattern] excludes `.`
//    and `:`, so a slug cannot spell an address even if a hostile node list
//    tried.
//  * The proxy is described to the extension by **port number only**. There is
//    no host field to put `127.0.0.1` in, let alone anything else; the
//    extension supplies the loopback host itself.
//  * Integers are range-checked. A 32-bit packed IPv4 does not fit in any of
//    them.
//
// [assertOutboundIsAddressFree] then re-checks the finished message at the one
// choke point every outbound byte passes through, so a field added later by
// someone who has not read this comment is caught by a test rather than by a
// censor.

import 'browser_bridge_framing.dart';

/// Bump on any breaking change to the shapes below.
///
/// `proxyTls` and `proxyTlsPort` remain reserved false/zero keys solely because
/// the app and separately installed native host can update on different
/// schedules and the app-to-host parser uses a closed key set. They do not
/// describe a shipping TLS listener. Removing them requires a staged protocol
/// migration across the installed host population, so their inert wire shape
/// is retained without carrying the withdrawn certificate implementation.
const int kBridgeProtocolVersion = 1;

/// Reverse-DNS name of the native-messaging host.
///
/// Must match the manifest filename on every browser -- Firefox enforces this,
/// Chrome tolerates a mismatch, so the strictest rule is the one used.
const String kBridgeHostName = 'org.winsvpn.bridge';

/// Slugs are lowercase ASCII words. The excluded characters are the point:
/// no `.`, no `:`, no `/`, so no address and no URL.
final RegExp kSlugPattern = RegExp(r'^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$');

/// Upper bound on every integer the host emits.
///
/// Chosen so that a packed IPv4 (which needs the full 32 bits, up to
/// 4294967295) cannot be smuggled through an integer field. Byte counters are
/// reported in kibibytes for the same reason -- see [BridgeStatus.rxKib].
const int kMaxOutboundInteger = 1 << 24; // 16777216

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

/// Tunnel state as the extension is allowed to see it.
///
/// The vocabulary deliberately matches `WatchTunnelStatus` in
/// `lib/watch_bridge.dart` word for word, with one addition. The watch is a
/// companion to a running app and cannot observe the app being absent; a
/// browser extension outlives the app and must be able to say so, which is why
/// [appNotRunning] is distinct from [disconnected].
enum BridgeTunnelStatus {
  /// The desktop app is not running. Nothing can be requested; the extension
  /// should offer "open Win's VPN", not a connect button that will do nothing.
  appNotRunning('app_not_running'),

  /// The app is running and is not connected. Distinct from [appNotRunning]:
  /// here a connect request is meaningful.
  disconnected('disconnected'),

  connecting('connecting'),
  connected('connected'),
  disconnecting('disconnecting'),
  failed('failed'),

  /// The OS VPN consent prompt has not been granted. The extension cannot
  /// grant it and must not try; only the desktop app can ask.
  permissionRequired('permission_required'),

  /// The host cannot currently establish the truth. Treated as "not connected"
  /// by every gate in this file -- never as connected.
  unknown('unknown');

  const BridgeTunnelStatus(this.wire);

  final String wire;

  /// The single predicate the proxy gate consults. Only [connected] passes.
  bool get isCarryingTraffic => this == BridgeTunnelStatus.connected;

  static BridgeTunnelStatus fromWire(String value) {
    for (final status in BridgeTunnelStatus.values) {
      if (status.wire == value) return status;
    }
    return BridgeTunnelStatus.unknown;
  }
}

/// Why the tunnel is in the state it is in.
///
/// A closed enum rather than a string. This is the field that would otherwise
/// carry "handshake to `<NODE_ES_IP>` timed out" straight into a readable
/// extension bundle.
enum BridgeDetailCode {
  none('none'),
  appNotRunning('app_not_running'),
  permissionRequired('permission_required'),
  userRequested('user_requested'),
  handshakeIncomplete('handshake_incomplete'),
  dataPathUnproven('data_path_unproven'),
  configRejected('config_rejected'),
  networkUnavailable('network_unavailable'),
  refusedByApp('refused_by_app'),
  stateUnavailable('state_unavailable');

  const BridgeDetailCode(this.wire);

  final String wire;
}

/// Honest, three-valued statement about Winn Protocol v3.
///
/// `kWinnHostCapabilities` in `lib/winn_protocol_dispatch.dart` has macOS,
/// Windows and iOS as `WinnHostCapability.absent`. On those platforms the
/// tunnel this bridge fronts **is not using winn/3**, and the extension must
/// not imply that it is. [unavailableOnThisPlatform] is the only value the
/// host will ever emit there.
enum BridgeWinnState {
  /// The capability gate is absent for this OS. winn/3 cannot run here at all
  /// in a shipping build, connected or not.
  unavailableOnThisPlatform('unavailable_on_this_platform'),

  /// The gate is present, but the live session is not a winn/3 session.
  availableNotInUse('available_not_in_use'),

  /// The gate is present and the live session is carrying winn/3.
  inUse('in_use');

  const BridgeWinnState(this.wire);

  final String wire;
}

/// What the extension may ask for. Nothing here takes an address argument,
/// and there is deliberately no "probe node" or "measure latency" request:
/// a latency figure the extension could attribute to a node is an address
/// oracle even though it contains no address.
enum BridgeRequestType {
  hello('hello'),
  getStatus('get_status'),
  subscribe('subscribe'),
  unsubscribe('unsubscribe'),
  requestConnect('request_connect'),
  requestDisconnect('request_disconnect'),
  issueProxyCredential('issue_proxy_credential'),
  revokeProxyCredential('revoke_proxy_credential'),

  /// Ask the desktop app to pair this extension (R20 A1). The app shows an
  /// in-app confirmation with a short code; the reply is a `pairing` message
  /// carrying the same code so the user can compare the two screens.
  pairBegin('pair_begin'),

  /// Present the pairing credential this extension stored after an earlier
  /// approval. Carries a `credential` field; an empty string clears it.
  setPairing('set_pairing'),

  /// Ask the desktop app to forget this extension's pairing.
  pairForget('pair_forget');

  const BridgeRequestType(this.wire);

  final String wire;

  static BridgeRequestType? fromWire(String value) {
    for (final type in BridgeRequestType.values) {
      if (type.wire == value) return type;
    }
    return null;
  }
}

/// Whether the desktop app recognises the pairing this extension presented.
///
/// `paired` is the app's own answer for the credential the host forwarded on
/// this request; it is never inferred by the host or the extension. Unpaired
/// and revoked clients get status only: `canRequestConnect` stays false.
enum BridgePairingStatus {
  unpaired('unpaired'),
  paired('paired');

  const BridgePairingStatus(this.wire);

  final String wire;

  static BridgePairingStatus fromWire(String value) {
    for (final state in BridgePairingStatus.values) {
      if (state.wire == value) return state;
    }
    return BridgePairingStatus.unpaired;
  }
}

/// Where an extension-initiated pairing stands. Closed.
enum BridgePairingFlowState {
  /// The app is showing its confirmation; `code` is the code it shows.
  pending('pending'),

  /// The user approved in the app; `credential` is present exactly once.
  approved('approved'),

  /// The user denied, closed the dialog, or the app refused to remember it.
  denied('denied'),

  /// No answer before the pairing expired, or the pairing is unknown.
  expired('expired'),

  /// The app cannot ask right now (locked, logged out, or no UI).
  unavailable('unavailable'),

  /// Another pairing is already waiting in the app, or requests came too fast.
  busy('busy');

  const BridgePairingFlowState(this.wire);

  final String wire;
}

/// Six decimal digits. Shown on both screens, never used as a secret.
final RegExp kBridgePairingCodePattern = RegExp(r'^[0-9]{6}$');

/// The pairing credential: 32 random bytes as lowercase hex. Hex only, so the
/// outbound address guard cannot misread it.
final RegExp kBridgePairingCredentialPattern = RegExp(r'^[0-9a-f]{64}$');

/// Body of a `pairing` reply or event.
class BridgePairingReply {
  BridgePairingReply({
    required this.state,
    this.code = '',
    this.expiresInSeconds = 0,
    this.credential = '',
  }) {
    if (code.isNotEmpty && !kBridgePairingCodePattern.hasMatch(code)) {
      throw ArgumentError.value('<redacted>', 'code', 'not a pairing code');
    }
    if (credential.isNotEmpty &&
        !kBridgePairingCredentialPattern.hasMatch(credential)) {
      throw ArgumentError.value('<redacted>', 'credential', 'malformed');
    }
    if (credential.isNotEmpty && state != BridgePairingFlowState.approved) {
      throw ArgumentError.value(state, 'state', 'credential only on approval');
    }
    if (expiresInSeconds < 0 || expiresInSeconds > 3600) {
      throw RangeError.range(expiresInSeconds, 0, 3600, 'expiresInSeconds');
    }
  }

  final BridgePairingFlowState state;
  final String code;
  final int expiresInSeconds;
  final String credential;

  Map<String, Object?> toWire() => <String, Object?>{
        'state': state.wire,
        if (code.isNotEmpty) 'code': code,
        if (expiresInSeconds > 0) 'expiresInSeconds': expiresInSeconds,
        if (credential.isNotEmpty) 'credential': credential,
      };
}

/// Why a request was refused. Closed, for the same reason as
/// [BridgeDetailCode].
enum BridgeErrorCode {
  malformed('malformed'),
  unsupportedVersion('unsupported_version'),
  unknownRequest('unknown_request'),
  appNotRunning('app_not_running'),
  notPermitted('not_permitted'),
  rateLimited('rate_limited'),
  internal('internal');

  const BridgeErrorCode(this.wire);

  final String wire;
}

// ---------------------------------------------------------------------------
// Message bodies
// ---------------------------------------------------------------------------

/// One selectable location, as the extension is allowed to see it.
///
/// The desktop app's own node maps also carry `endpoint` and
/// `stealth_endpoint`. Those fields have no counterpart here and no way to
/// arrive: this class only ever reads the three it names.
class BridgeNode {
  BridgeNode({required this.slug, required String name, required this.flag})
      : name = name.trim() {
    if (!kSlugPattern.hasMatch(slug)) {
      throw ArgumentError.value(slug, 'slug', 'not a valid bridge slug');
    }
    // Defence in depth. The guard at the choke point would also catch this,
    // but rejecting at construction means a hostile node list cannot even
    // build the object. Rejected, not sanitised: silently mangling an address
    // leaves a recoverable one.
    if (containsAddressLiteral(this.name)) {
      throw ArgumentError.value(
          name, 'name', 'display name looks like an address');
    }
    if (flag.length > 8) {
      throw ArgumentError.value(flag, 'flag', 'flag too long');
    }
  }

  /// Opaque identifier. Never an address -- see [kSlugPattern].
  final String slug;

  /// Human-readable, localised; Burmese is expected here.
  final String name;

  /// Emoji or short country code.
  final String flag;

  Map<String, Object?> toWire() => <String, Object?>{
        'slug': slug,
        'name': name,
        'flag': flag,
      };
}

/// A full state snapshot. This is both the `get_status` reply and the body of
/// every pushed `status` event.
class BridgeStatus {
  const BridgeStatus({
    required this.status,
    required this.detail,
    required this.winn,
    required this.selectedSlug,
    required this.nodes,
    required this.canRequestConnect,
    required this.proxyPort,
    required this.proxyReady,
    this.proxyTls = false,
    this.proxyTlsPort = 0,
    this.rxKib = 0,
    this.txKib = 0,
    this.pairing = BridgePairingStatus.unpaired,
  });

  /// A snapshot for the case where the desktop app cannot be observed at all.
  ///
  /// Everything is closed: no nodes, no proxy, no connect affordance. This is
  /// what the host reports rather than guessing, and it is what the proxy gate
  /// sees when it refuses.
  factory BridgeStatus.appNotRunning({required BridgeWinnState winn}) {
    return BridgeStatus(
      status: BridgeTunnelStatus.appNotRunning,
      detail: BridgeDetailCode.appNotRunning,
      winn: winn,
      selectedSlug: '',
      nodes: const <BridgeNode>[],
      canRequestConnect: false,
      proxyPort: 0,
      proxyReady: false,
    );
  }

  final BridgeTunnelStatus status;
  final BridgeDetailCode detail;
  final BridgeWinnState winn;

  /// Empty, or a slug matching [kSlugPattern].
  final String selectedSlug;

  final List<BridgeNode> nodes;

  /// False whenever the desktop app would refuse to start or change a tunnel
  /// -- the local PIN gate being engaged, for instance. It is what stops the
  /// extension offering a control that would silently do nothing.
  final bool canRequestConnect;

  /// Loopback TCP port of the local proxy, or 0 when there is none.
  ///
  /// **Port only, no host.** The extension supplies `127.0.0.1` itself. There
  /// is no field here in which any other address could travel.
  final int proxyPort;

  /// True only when the proxy is listening *and* the tunnel gate would admit
  /// traffic right now. The extension uses this to decide whether to install
  /// its proxy settings at all.
  final bool proxyReady;

  /// Reserved compatibility key. Shipping writers emit false.
  final bool proxyTls;

  /// Reserved compatibility key. Shipping writers emit zero.
  final int proxyTlsPort;

  /// Session counters in kibibytes.
  ///
  /// KiB rather than bytes so the value cannot reach the 32-bit range in which
  /// a packed IPv4 lives -- see [kMaxOutboundInteger].
  final int rxKib;
  final int txKib;

  /// The app's answer for the pairing presented with this request.
  final BridgePairingStatus pairing;

  /// The same snapshot as the app answers it for one caller: control is
  /// offered only to a paired caller.
  BridgeStatus copyWithPairing(BridgePairingStatus pairing) {
    return BridgeStatus(
      status: status,
      detail: detail,
      winn: winn,
      selectedSlug: selectedSlug,
      nodes: nodes,
      canRequestConnect:
          canRequestConnect && pairing == BridgePairingStatus.paired,
      proxyPort: proxyPort,
      proxyReady: proxyReady,
      proxyTls: false,
      proxyTlsPort: 0,
      rxKib: rxKib,
      txKib: txKib,
      pairing: pairing,
    );
  }

  /// The same snapshot with the proxy facts replaced by what the host's
  /// single plaintext listener is actually doing.
  BridgeStatus copyWithProxy({
    int? proxyPort,
    bool? proxyReady,
  }) {
    return BridgeStatus(
      status: status,
      detail: detail,
      winn: winn,
      selectedSlug: selectedSlug,
      nodes: nodes,
      canRequestConnect: canRequestConnect,
      proxyPort: proxyPort ?? this.proxyPort,
      proxyReady: proxyReady ?? this.proxyReady,
      proxyTls: false,
      proxyTlsPort: 0,
      rxKib: rxKib,
      txKib: txKib,
      pairing: pairing,
    );
  }

  Map<String, Object?> toWire() => <String, Object?>{
        'status': status.wire,
        'detail': detail.wire,
        'winn': winn.wire,
        'selectedSlug': selectedSlug,
        'nodes': nodes.map((BridgeNode node) => node.toWire()).toList(),
        'canRequestConnect': canRequestConnect,
        'proxyPort': proxyPort,
        'proxyReady': proxyReady,
        'proxyTls': false,
        'proxyTlsPort': 0,
        'rxKib': rxKib,
        'txKib': txKib,
        'pairing': pairing.wire,
      };
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

/// Build a reply envelope.
///
/// [id] is echoed from the request so the extension can match replies; it is
/// generated by the extension and is opaque here, which is why it is validated
/// rather than trusted -- an extension bug that put a hostname in the id would
/// otherwise loop it straight back out through this host.
Map<String, Object?> bridgeReply({
  required String id,
  required String type,
  required Map<String, Object?> body,
}) {
  return <String, Object?>{
    'v': kBridgeProtocolVersion,
    'id': id,
    'type': type,
    'ok': true,
    ...body,
  };
}

Map<String, Object?> bridgeError({
  required String id,
  required BridgeErrorCode code,
}) {
  return <String, Object?>{
    'v': kBridgeProtocolVersion,
    'id': id,
    'type': 'error',
    'ok': false,
    'error': code.wire,
  };
}

/// Unsolicited state push. Native messaging allows the host to write whenever
/// it likes; `id` is empty because no request is being answered.
Map<String, Object?> bridgeEvent({
  required String type,
  required Map<String, Object?> body,
}) {
  return <String, Object?>{
    'v': kBridgeProtocolVersion,
    'id': '',
    'type': type,
    'ok': true,
    ...body,
  };
}

/// The id the extension chose, reduced to something safe to echo.
///
/// Anything outside `[A-Za-z0-9_-]` or longer than 64 characters is replaced
/// wholesale rather than trimmed, because a partially-scrubbed identifier is
/// still an identifier.
String sanitizeCorrelationId(Object? raw) {
  if (raw is! String) return '';
  if (raw.isEmpty || raw.length > 64) return '';
  return RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(raw) ? raw : '';
}

// ---------------------------------------------------------------------------
// The address guard
// ---------------------------------------------------------------------------

/// Dotted quad, with each octet range-checked so that a version string like
/// `1.0.14` or a decimal like `10.5` cannot trip the guard.
final RegExp _ipv4Literal = RegExp(
  r'(?<![\w.])'
  r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
  r'(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}'
  r'(?![\w.])',
);

/// IPv6, including the compressed `::` forms. Two or more `hex:` groups, or
/// any `::`, is enough to be suspicious; the guard prefers a false positive it
/// can investigate to a false negative it cannot.
final RegExp _ipv6Literal = RegExp(
  r'(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}|::[0-9a-fA-F]{1,4}',
);

/// A bare hostname with a TLD-looking tail. Catches an infrastructure FQDN
/// that is not an IP literal but is just as much an address.
final RegExp _hostnameLiteral = RegExp(
  r'(?<![\w.])[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
  r'(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})*'
  r'\.(?:com|net|org|io|dev|xyz|co|us|uk|ru|cn|sg|jp|de|fr|nl|info|top|site)'
  r'(?![\w])',
);

/// True when [value] contains anything address-shaped.
bool containsAddressLiteral(String value) {
  return _ipv4Literal.hasMatch(value) ||
      _ipv6Literal.hasMatch(value) ||
      _hostnameLiteral.hasMatch(value);
}

/// Thrown when an outbound message would carry an address.
///
/// Deliberately not an `assert`: asserts are compiled out of a release build,
/// and this check must hold in exactly the build a censor would be looking at.
class BridgeAddressLeakException implements Exception {
  const BridgeAddressLeakException(this.path, this.detail);

  /// Where in the message the offending value sits, e.g. `nodes[0].name`.
  final String path;
  final String detail;

  @override
  String toString() =>
      'BridgeAddressLeakException: $path would leak an address ($detail)';
}

/// Walk a finished outbound message and refuse anything address-shaped.
///
/// Structural rather than a grep over the serialised text: walking the decoded
/// tree means JSON's own punctuation (`"a":1,"b":2` is full of colons) cannot
/// produce a false positive, and an address cannot hide inside an escape
/// sequence that a text scan would have read differently from the parser.
///
/// Every value is checked, keys included, and any type outside the closed set
/// is rejected. That last rule is what makes a *future* field safe: a new
/// field of an unanticipated type fails here rather than shipping.
void assertOutboundIsAddressFree(Object? message, [String path = r'$']) {
  if (message == null || message is bool) return;

  if (message is int) {
    if (message.abs() > kMaxOutboundInteger) {
      throw BridgeAddressLeakException(
        path,
        'integer $message exceeds the $kMaxOutboundInteger bound, so it is '
        'wide enough to carry a packed address',
      );
    }
    return;
  }

  if (message is String) {
    if (containsAddressLiteral(message)) {
      throw BridgeAddressLeakException(path, 'string value is address-shaped');
    }
    return;
  }

  if (message is List) {
    for (var i = 0; i < message.length; i++) {
      assertOutboundIsAddressFree(message[i], '$path[$i]');
    }
    return;
  }

  if (message is Map) {
    for (final entry in message.entries) {
      final key = entry.key;
      if (key is! String) {
        throw BridgeAddressLeakException(path, 'non-string key $key');
      }
      if (containsAddressLiteral(key)) {
        throw BridgeAddressLeakException('$path.$key', 'key is address-shaped');
      }
      assertOutboundIsAddressFree(entry.value, '$path.$key');
    }
    return;
  }

  // Doubles land here on purpose. A double can hold a packed IPv4 exactly and
  // nothing in this schema needs one.
  throw BridgeAddressLeakException(
    path,
    'value of type ${message.runtimeType} is outside the closed schema',
  );
}

/// Serialise an outbound message, refusing to emit one that carries an
/// address.
///
/// **This is the choke point.** `bin/wins_bridge_host.dart` writes nothing to
/// stdout except through here, so the guard cannot be bypassed by forgetting
/// to call it at one of several call sites -- there is only one.
List<int> encodeOutboundBridgeMessage(Map<String, Object?> message) {
  assertOutboundIsAddressFree(message);
  return encodeNativeMessage(message);
}
