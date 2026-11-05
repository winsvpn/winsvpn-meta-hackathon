import 'dart:convert';

import 'signed_discovery_admission.dart';

class GatewayEndpoints {
  const GatewayEndpoints({required this.gateway});

  final String gateway;
}

bool isNodeDiscoveryPayload(String body) {
  try {
    final decoded = jsonDecode(body);
    return decoded is Map && decoded['nodes'] is List;
  } catch (_) {
    return false;
  }
}

bool nodeDiscoveryPayloadHasNodes(String body) {
  try {
    final decoded = jsonDecode(body);
    return decoded is Map &&
        decoded['nodes'] is List &&
        (decoded['nodes'] as List).isNotEmpty;
  } catch (_) {
    return false;
  }
}

String? classifyFreeVerifyTerminalFailure(int statusCode, String body) {
  if (statusCode == 429) return 'rate_limited';
  if (!const {400, 401, 403, 409, 422, 503}.contains(statusCode)) {
    return null;
  }
  try {
    final decoded = jsonDecode(body);
    if (decoded is! Map) return null;
    final detail = (decoded['detail'] ?? '').toString().trim().toLowerCase();
    if (detail.isEmpty) return null;
    if (statusCode == 503) {
      if (detail.contains('maintenance')) return 'maintenance';
      if (detail.contains('not online')) return 'offline';
      if (detail.contains('not enabled')) return 'disabled';
      return 'unavailable';
    }
    if (statusCode == 409 && detail.contains('identity collision')) {
      return 'identity_collision';
    }
    return 'rejected';
  } catch (_) {
    return null;
  }
}

String? classifyFreeStatusTerminalState(int statusCode, String body) {
  if (statusCode != 200) return null;
  try {
    final decoded = jsonDecode(body);
    if (decoded is! Map) return null;
    if (decoded['maintenance'] == true) return 'maintenance';
    final status = (decoded['status'] ?? '').toString().trim().toLowerCase();
    if (status != 'unavailable') return null;
    final enabled = decoded['free_access'] ?? decoded['freeaccess'];
    return enabled == false ? 'disabled' : 'offline';
  } catch (_) {
    return null;
  }
}

// Order is network-observable: the first front of every pre-tunnel sweep is
// the first plaintext SNI and DNS name this app emits from the user's real
// IP. Neutral fronts lead; the brand-bearing hosts are the last resort
// (C-core-5).
const String defaultGatewayBase = String.fromEnvironment(
  'WINS_GATEWAY_BASE',
  defaultValue: 'https://a.app-cloud-sync.net',
);
const String defaultHubHost = String.fromEnvironment(
  'WINS_HUB_HOST',
  defaultValue: 'hub.winsvpn.org',
);
const String _extraGatewayBasesCsv = String.fromEnvironment(
  'WINS_GATEWAY_BASES',
  defaultValue: 'https://b.app-cloud-sync.net,https://c.app-cloud-sync.net,'
      'https://d.app-cloud-sync.net,https://e.app-cloud-sync.net,'
      'https://f.app-cloud-sync.net,https://g.app-cloud-sync.net,'
      'https://h.app-cloud-sync.net,https://i.app-cloud-sync.net,'
      'https://j.app-cloud-sync.net,https://k.app-cloud-sync.net,'
      'https://l.app-cloud-sync.net,https://m.app-cloud-sync.net,'
      'https://n.app-cloud-sync.net,https://o.app-cloud-sync.net,'
      'https://p.app-cloud-sync.net,https://q.app-cloud-sync.net,'
      'https://r.app-cloud-sync.net,https://s.app-cloud-sync.net,'
      'https://t.app-cloud-sync.net,https://u.app-cloud-sync.net,'
      'https://v.app-cloud-sync.net,https://w.app-cloud-sync.net,'
      'https://x.app-cloud-sync.net,https://y.app-cloud-sync.net,'
      'https://z.app-cloud-sync.net,'
      'https://sync.winsvpn.org,https://sync.winsvpn.com',
);

List<String> get primaryStealthGateways {
  final configured = <String>[
    defaultGatewayBase,
    ..._extraGatewayBasesCsv.split(','),
    if (defaultHubHost.trim().isNotEmpty) 'https://${defaultHubHost.trim()}',
  ];
  return _uniqueInOrder(configured.map(gatewayBase));
}

String gatewayBase(String raw) {
  var value = raw.trim();
  for (final suffix in [
    '/account/status',
    '/free/verify',
    '/free/status',
    '/free/logout',
    '/legal/current',
    '/legal/accept',
    '/verify',
    '/nodes',
    '/logout',
  ]) {
    if (value.endsWith(suffix)) {
      value = value.substring(0, value.length - suffix.length);
    }
  }
  while (value.endsWith('/')) {
    value = value.substring(0, value.length - 1);
  }
  return value;
}

/// Canonical, memoised instances of the gateways compiled into this signed
/// build. [recoveryGatewayFromRecord] returns elements *of this list*, never a
/// string built out of a fetched record, so no byte of the unsigned recovery
/// record can reach a caller, a URL, a log or a diagnostic -- even if the
/// matching logic below is ever loosened.
final List<String> recoveryGatewayAllowlist =
    List<String>.unmodifiable(primaryStealthGateways);

/// The single validation point for the unsigned GitHub-hosted recovery record
/// (M-2). The record may only ever REORDER gateways already compiled into the
/// signed app, never introduce a new host, so a candidate is accepted only on
/// exact string equality with an allowlist entry: no prefix, suffix,
/// subdomain, trailing-dot or case normalisation is applied to the host.
///
/// Returns the matched compiled allowlist element, or null when the record
/// does not name one. The caller never receives record-derived text.
String? recoveryGatewayFromRecord(String body) {
  final candidates = _recordGatewayCandidates(body);
  for (final candidate in candidates) {
    for (final allowed in recoveryGatewayAllowlist) {
      if (allowed == candidate) return allowed;
    }
  }
  return null;
}

/// The only supported way to turn the recovery record into a usable gateway.
/// [fetchRecord] hands its response body straight to the allowlist check, so
/// the body never lands in caller scope, and [onRejected] deliberately takes
/// no arguments so a rejection notice can never carry record text.
///
/// Returns null -- leaving the caller on its compiled default -- for an
/// unparseable URL, any transport failure, an absent body, or a record that
/// does not name an allowlisted gateway. Only the last of those is a
/// rejection, so [onRejected] fires for that case alone.
Future<String?> resolveRecoveryGateway(
  String recordUrl, {
  required Future<String?> Function(Uri url) fetchRecord,
  void Function()? onRejected,
}) async {
  final uri = Uri.tryParse(recordUrl);
  if (uri == null) return null;
  String? body;
  try {
    body = await fetchRecord(uri);
  } catch (_) {
    return null;
  }
  if (body == null) return null;
  final gateway = recoveryGatewayFromRecord(body);
  if (gateway == null) onRejected?.call();
  return gateway;
}

/// Structural screen for a record body, kept private so that no caller can
/// obtain a host from the record without passing it through the allowlist in
/// [recoveryGatewayFromRecord]. Every non-empty line is screened; malformed
/// lines are skipped, and matches are still exact-allowlist only.
List<String> _recordGatewayCandidates(String body) {
  final clean = body.trim();
  final lower = clean.toLowerCase();
  if (clean.isEmpty || lower.contains('<!doctype') || lower.contains('<html')) {
    return const [];
  }
  final candidates = <String>[];
  final lines = clean
      .split(RegExp(r'[\r\n]+'))
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty);
  for (final line in lines) {
    if (line.contains('|')) continue;
    final gateway = gatewayBase(line);
    final uri = Uri.tryParse(gateway);
    if (gateway.isEmpty || uri == null || !_isSafeHttpsGateway(uri)) {
      continue;
    }
    candidates.add(gateway);
  }
  return candidates;
}

/// Screen for the URL the gateway-recovery record is fetched *from*, as
/// distinct from the gateways it may name.
///
/// Looser than [isSafeHttpsGatewayUri] in exactly one respect -- a path is
/// required rather than forbidden, because the record is a file and not an API
/// origin. Everything else is the same standard: https only, a real non-IP
/// host, no credentials, no non-default port, no fragment.
///
/// Exists because `WINS_RECOVERY_RECORD_URL` makes this URL build-configurable,
/// and the one thing that must not happen is a malformed override silently
/// becoming a request to an attacker-chosen host. A rejected override yields no
/// fetch at all; it never falls back to the compiled URL.
bool isSafeRecoveryRecordUrl(String raw) {
  final uri = Uri.tryParse(raw.trim());
  if (uri == null) return false;
  return uri.scheme.toLowerCase() == 'https' &&
      uri.host.isNotEmpty &&
      !_isIpLiteral(uri.host) &&
      uri.userInfo.isEmpty &&
      (!uri.hasPort || uri.port == 443) &&
      !uri.hasFragment &&
      uri.path.length > 1 &&
      uri.path.startsWith('/');
}

/// The only hosts a recovery record may ever be fetched from, compiled into
/// the signed build (B-APP-005). `WINS_RECOVERY_RECORD_URL` makes the record
/// URL build-configurable, and that fetch is issued pre-tunnel from the
/// user's real IP address, so an override must never be able to point it at
/// an arbitrary HTTPS host. `raw.githubusercontent.com` is the compiled
/// channel's host: a build may rotate the record's PATH (the part that names
/// the product), but never its host.
const Set<String> recoveryRecordHostAllowlist = <String>{
  'raw.githubusercontent.com',
};

/// The full screen a recovery-record URL must pass before this build fetches
/// it: the [isSafeRecoveryRecordUrl] shape screen plus exact, case-insensitive
/// host membership in [recoveryRecordHostAllowlist]. Matching is by equality,
/// never by suffix, so a look-alike such as
/// `raw.githubusercontent.com.evil.example` is refused.
bool isAllowedRecoveryRecordUrl(String raw) {
  if (!isSafeRecoveryRecordUrl(raw)) return false;
  final uri = Uri.tryParse(raw.trim());
  return uri != null &&
      recoveryRecordHostAllowlist.contains(uri.host.toLowerCase());
}

/// File name of the offline-signed update notice published next to the
/// recovery record. Its body is exactly the `{"payload","sig"}` envelope that
/// `tools/winn3_sign_announcement.py sign` prints.
const String kSignedUpdateNoticeFileName = 'update-notice.json';

/// Upper bound on the notice body: an announcement payload is at most 8192
/// bytes (11 KiB as base64) plus an 88-character signature.
const int kMaxSignedUpdateNoticeBytes = 16384;

/// Upper bound on the gateway-recovery record body. The record is one
/// compiled gateway URL per line (29 lines, about 1.2 KiB today); anything
/// past this cannot name a compiled gateway and is refused while it streams.
const int kMaxGatewayRecoveryRecordBytes = 16384;

/// The update-notice URL beside [recordUrl], or null when either URL fails
/// [isAllowedRecoveryRecordUrl]. Only the last path segment changes, so the
/// notice is always fetched from the compiled recovery host.
Uri? signedUpdateNoticeUrlFor(String recordUrl) {
  if (!isAllowedRecoveryRecordUrl(recordUrl)) return null;
  final Uri notice =
      Uri.parse(recordUrl.trim()).resolve(kSignedUpdateNoticeFileName);
  return isAllowedRecoveryRecordUrl(notice.toString()) ? notice : null;
}

/// The gateway-shape screen, exposed so that any *other* source of candidate
/// gateways -- notably the bootstrap discovery record in
/// `bootstrap_resilience.dart` -- is held to the byte-for-byte same standard as
/// the compiled set, rather than growing a second, subtly weaker copy of it.
///
/// Re-exported rather than reimplemented on purpose: a fallback endpoint that
/// is validated more loosely than the primary is exactly the downgrade this
/// whole area is supposed to prevent.
bool isSafeHttpsGatewayUri(Uri uri) => _isSafeHttpsGateway(uri);

bool _isSafeHttpsGateway(Uri uri) {
  return uri.scheme.toLowerCase() == 'https' &&
      uri.host.isNotEmpty &&
      !_isIpLiteral(uri.host) &&
      uri.userInfo.isEmpty &&
      (!uri.hasPort || uri.port == 443) &&
      !uri.hasQuery &&
      !uri.hasFragment &&
      (uri.path.isEmpty || uri.path == '/');
}

bool _isIpLiteral(String host) {
  final clean = host.replaceAll(RegExp(r'^\[|\]$'), '');
  if (clean.contains(':')) return true;
  final parts = clean.split('.');
  return parts.length == 4 &&
      parts.every((part) => RegExp(r'^\d{1,3}$').hasMatch(part));
}

List<String> _uniqueInOrder(Iterable<String> values) {
  final seen = <String>{};
  final ordered = <String>[];
  for (final raw in values) {
    final value = raw.trim();
    if (value.isEmpty || seen.contains(value)) continue;
    seen.add(value);
    ordered.add(value);
  }
  return ordered;
}

List<String> _gatewayUrls(Iterable<String> gateways, String suffix) {
  final urls = <String>[];
  for (final gateway in gateways) {
    final base = gatewayBase(gateway);
    final uri = Uri.tryParse(base);
    if (base.isNotEmpty && uri != null && _isSafeHttpsGateway(uri)) {
      urls.add('$base$suffix');
    }
  }
  return urls;
}

/// The gateway every sweep starts from (Claude-core-T2-1, covering
/// C-core-4): the compiled front that most recently answered on this network
/// when there is one, otherwise [activeGateway]. Serial sweeps (account status
/// at 5 s per front, free status, legal) and a new-device activation, which
/// may use exactly one origin, then start where the last sweep succeeded
/// instead of re-walking fronts this network is known to drop. Only a
/// compiled gateway can be chosen.
String preferredSweepGateway({
  required String activeGateway,
  String? lastKnownGoodGateway,
}) {
  final candidate = gatewayBase(lastKnownGoodGateway ?? '');
  if (candidate.isNotEmpty && primaryStealthGateways.contains(candidate)) {
    return candidate;
  }
  return activeGateway;
}

List<String> nodeDiscoveryUrls(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/nodes'),
    ..._gatewayUrls(primaryStealthGateways, '/nodes'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/nodes'),
  ]);
}

List<String> verifyGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/verify'),
    ..._gatewayUrls(primaryStealthGateways, '/verify'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/verify'),
  ]);
}

/// Limits enrollment attempts carrying a one-time activation secret to one
/// pinned origin.
///
/// `Future.timeout` does not cancel the underlying HTTP request. Sending the
/// same activation secret to the next failover origin after a timeout would
/// therefore leave two origins processing one reusable credential at once.
/// Existing-device bearer authentication may still use the complete verified
/// failover list; a new-device enrollment must retry from the UI with the
/// secret still present rather than fan it out across origins.
List<String> activationAttemptGateways(
  List<String> gateways, {
  required bool hasActivationSecret,
}) {
  if (!hasActivationSecret || gateways.length <= 1) {
    return List<String>.unmodifiable(gateways);
  }
  return List<String>.unmodifiable(<String>[gateways.first]);
}

List<String> accountStatusGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/account/status'),
    ..._gatewayUrls(primaryStealthGateways, '/account/status'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/account/status'),
  ]);
}

List<String> legalCurrentGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/legal/current'),
    ..._gatewayUrls(primaryStealthGateways, '/legal/current'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/legal/current'),
  ]);
}

List<String> freeVerifyGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/free/verify'),
    ..._gatewayUrls(primaryStealthGateways, '/free/verify'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/free/verify'),
  ]);
}

List<String> freeStatusGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/free/status'),
    ..._gatewayUrls(primaryStealthGateways, '/free/status'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/free/status'),
  ]);
}

List<String> freeLogoutGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/free/logout'),
    ..._gatewayUrls(primaryStealthGateways, '/free/logout'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/free/logout'),
  ]);
}

List<String> logoutGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/logout'),
    ..._gatewayUrls(primaryStealthGateways, '/logout'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/logout'),
  ]);
}

/// Account-deletion endpoints. Same stealth-gateway failover as every other
/// authenticated call, so an in-app deletion request still reaches the hub
/// where the primary gateway is censored -- Apple requires the flow to work
/// from inside the app, and a user in a censored network is exactly the user
/// most likely to need it.
List<String> accountDeletionRequestGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/account/deletion/request'),
    ..._gatewayUrls(primaryStealthGateways, '/account/deletion/request'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/account/deletion/request'),
  ]);
}

List<String> accountDeletionConfirmGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/account/deletion/confirm'),
    ..._gatewayUrls(primaryStealthGateways, '/account/deletion/confirm'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/account/deletion/confirm'),
  ]);
}

List<String> accountDeletionCancelGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/account/deletion/cancel'),
    ..._gatewayUrls(primaryStealthGateways, '/account/deletion/cancel'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/account/deletion/cancel'),
  ]);
}

List<String> accountDeletionStatusGateways(GatewayEndpoints endpoints) {
  return _uniqueInOrder([
    ..._gatewayUrls([endpoints.gateway], '/account/deletion/status'),
    ..._gatewayUrls(primaryStealthGateways, '/account/deletion/status'),
    ..._gatewayUrls(signedDiscoveryGatewayTail, '/account/deletion/status'),
  ]);
}
