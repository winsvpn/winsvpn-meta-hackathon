import 'package:flutter/foundation.dart' show debugPrint, kReleaseMode;

import 'local_security.dart';

class PreVpnGeoScene {
  const PreVpnGeoScene({
    required this.countryCode,
    required this.regionCode,
    this.latitude,
    this.longitude,
    this.mapTileUrlTemplate,
    this.mapAttributionText,
    this.mapAttributionUrl,
    this.rejectedMapTileHost,
  });

  final String countryCode;
  final String regionCode;
  final double? latitude;
  final double? longitude;
  final String? mapTileUrlTemplate;
  final String? mapAttributionText;
  final String? mapAttributionUrl;

  /// Host of a hub-supplied `map_tile_url_template` that was rejected
  /// *because of its host* rather than its shape, so the rejection can be
  /// logged and diagnosed instead of vanishing silently.
  ///
  /// Deliberately the host alone and never the template: a rejected URL can
  /// carry credentials in its userInfo, which must never reach a log.
  final String? rejectedMapTileHost;

  bool get hasCoordinates => latitude != null && longitude != null;
  bool get hasRegion => regionCode.isNotEmpty;
  bool get hasSpecificLocation => hasCoordinates || hasRegion;
}

class GeoCoordinate {
  const GeoCoordinate(this.longitude, this.latitude);

  final double longitude;
  final double latitude;
}

/// The closed allowlist of hosts the pre-VPN geo-scene lookup may ever leave
/// the device for, compiled into the signed artifact (B-APP-006).
///
/// The geo-scene request is issued on every launch -- after privacy consent,
/// but before any tunnel exists -- so its hostname is emitted in plaintext DNS
/// and in the plaintext TLS SNI, from the user's real IP address. That host
/// set is the network-observable identity of the build, and in a release
/// build it is a property of the signed artifact: `WINS_GEO_EDGE_BASES` is
/// ignored entirely there, so no build command can widen this set.
///
/// `speed.cloudflare.com` is the public coarse-geo fallback
/// ([preVpnGeoDirectSources]); the two first-party edges are the hub's own
/// origins ([preVpnGeoEdgeBases] in a release build).
const Set<String> permittedPreVpnGeoHosts = <String>{
  'www.winsvpn.org',
  'www.winsvpn.com',
  'speed.cloudflare.com',
};

/// The geo-edge origins a release build asks, in order: exactly the
/// first-party members of [permittedPreVpnGeoHosts].
const List<String> _releasePreVpnGeoEdgeBases = <String>[
  'https://www.winsvpn.org',
  'https://www.winsvpn.com',
];

/// Build-time override for the first-party origins asked for the pre-connect
/// coarse-geolocation scene, as a comma-separated list of https origins.
/// DEBUG/PROFILE ONLY (B-APP-006).
///
/// It was previously the only way to move this request off the branded
/// domain, which silently defeated the neutral-domain escape hatch:
/// re-pointing the control plane with `WINS_GATEWAY_BASE` /
/// `WINS_GATEWAY_BASES` / `WINS_HUB_HOST` does not move this request, so a
/// build that changed those and left this list alone still named the real
/// domain on every single launch. A release build now ignores the define
/// entirely (see [compiledPreVpnGeoEdgeBases]): the geo request's host set is
/// network-observable from the user's real IP, so it must be compiled into
/// the signed artifact rather than settable per build command. The define
/// remains for debug/profile testing only, and the caller logs a warning
/// while it is in effect.
/// See `docs/handoff/NETWORK_OBSERVABLE_DNS_SNI_AUDIT_20260806.md`.
const bool _hasPreVpnGeoEdgeBasesDefine =
    bool.hasEnvironment('WINS_GEO_EDGE_BASES');
const String _preVpnGeoEdgeBasesOverrideCsv = String.fromEnvironment(
  'WINS_GEO_EDGE_BASES',
  defaultValue: '',
);

/// Resolves the geo-edge origins this build asks for the pre-VPN scene, as a
/// pure function of the build mode and the define value so the rule itself is
/// testable.
///
/// A RELEASE build always asks exactly the compiled first-party edges
/// [_releasePreVpnGeoEdgeBases] -- the same shape of rule as
/// `controlPlanePinningEnforced`. Debug and profile builds honour the define
/// for testing; a set-but-unusable value still degrades to **empty** there,
/// never back to the compiled default, for the reason documented on
/// [preVpnGeoEdgeBases].
List<String> compiledPreVpnGeoEdgeBases({
  required bool isReleaseBuild,
  required bool definePresent,
  required String defineCsv,
}) {
  if (isReleaseBuild || !definePresent) {
    return _releasePreVpnGeoEdgeBases;
  }
  return parsePreVpnGeoEdgeBases(defineCsv);
}

List<String> _resolvePreVpnGeoEdgeBases() {
  assert(
    !(kReleaseMode && _hasPreVpnGeoEdgeBasesDefine),
    'WINS_GEO_EDGE_BASES is a debug/profile-only testing override. A release '
    'build asks only the compiled first-party geo edges; remove the '
    'dart-define from the release build command.',
  );
  final resolved = compiledPreVpnGeoEdgeBases(
    isReleaseBuild: kReleaseMode,
    definePresent: _hasPreVpnGeoEdgeBasesDefine,
    defineCsv: _preVpnGeoEdgeBasesOverrideCsv,
  );
  if (!kReleaseMode && _hasPreVpnGeoEdgeBasesDefine && resolved.isNotEmpty) {
    debugPrint(
      'WINS_GEO_EDGE_BASES override active in a debug/profile build: the '
      'pre-VPN geo-scene request will leave this device from its real IP for '
      '$resolved. Testing only; release builds ignore the define entirely.',
    );
  }
  return resolved;
}

/// The first-party geo-scene origins compiled into this build, in order.
///
/// In a release build this is exactly [_releasePreVpnGeoEdgeBases]; the
/// `WINS_GEO_EDGE_BASES` define cannot change it (B-APP-006). In debug and
/// profile builds a set-but-unusable override degrades to **empty** rather
/// than to the compiled default. Falling back would re-introduce the real
/// domain into a build whose whole purpose was to remove it -- the one failure
/// mode that must not be silent. An empty list costs only the first-party
/// attempt: [buildPreVpnGeoSceneSources] still yields the configured gateways
/// and the public fallback, so the feature keeps working.
final List<String> preVpnGeoEdgeBases =
    List<String>.unmodifiable(_resolvePreVpnGeoEdgeBases());

/// Splits and screens a `WINS_GEO_EDGE_BASES` value. Exposed so the screen is
/// testable and so any future caller is held to the same standard rather than
/// growing a second, weaker copy of it.
List<String> parsePreVpnGeoEdgeBases(String csv) {
  final bases = <String>[];
  final seen = <String>{};
  for (final raw in csv.split(',')) {
    final value = raw.trim();
    if (value.isEmpty) continue;
    final uri = Uri.tryParse(value);
    if (uri == null || !_isSafeGeoEdgeOrigin(uri)) continue;
    if (seen.add(uri.origin)) bases.add(uri.origin);
  }
  return bases;
}

/// The same shape screen [buildPreVpnGeoSceneSources] applies, plus a rejection
/// of paths and non-default ports: an origin is all that is ever wanted here,
/// and `/api/site/geo-scene` is appended to it.
bool _isSafeGeoEdgeOrigin(Uri uri) {
  return uri.scheme == 'https' &&
      uri.host.isNotEmpty &&
      uri.userInfo.isEmpty &&
      !uri.hasQuery &&
      !uri.hasFragment &&
      (!uri.hasPort || uri.port == 443) &&
      (uri.path.isEmpty || uri.path == '/');
}

/// Build-time override for the pre-VPN map-tile host allowlist, as a
/// comma-separated list of bare hostnames.
///
/// `map_tile_url_template` arrives from the hub in the `/api/site/geo-scene`
/// response and is fetched **before any tunnel exists**, so every tile request
/// leaves the device from the user's real IP. Left unpinned it was a
/// configuration value -- not an exploit -- with which a coerced, compromised
/// or seized control plane could point every install's pre-tunnel fetch at an
/// attacker-chosen host and harvest real IP addresses at scale. Pinning is
/// what removes that authority from the hub.
///
/// Keep in step with `WINS_MAP_TILE_URL`
/// (`lib/public_ip_map_backdrop.dart`), which supplies the compiled tile
/// endpoint, and with `WINS_GEO_EDGE_BASES` above: the hub serves tiles from
/// whichever of its own origins answered the geo-scene request
/// (`web/_worker.js`, `firstPartyMapOrigin`).
const String _compiledTrustedMapTileHostsCsv =
    'winsvpn.org,www.winsvpn.org,winsvpn.com,www.winsvpn.com';

/// Build-time override for the tile-host allowlist. DEBUG/PROFILE ONLY
/// (F-07, final audit 2026-08-28): pre-tunnel tile URLs carry approximate
/// location in the path, so the host set is network-observable from the
/// user's real IP and is compiled into the signed artifact in release
/// builds. A release build ignores the define entirely; debug/profile builds
/// keep it for testing and it still degrades to empty, never to the compiled
/// default, when set but unusable.
const bool _hasTrustedMapTileHostsDefine =
    bool.hasEnvironment('WINS_TRUSTED_MAP_TILE_HOSTS');
const String _trustedMapTileHostsOverrideCsv = String.fromEnvironment(
  'WINS_TRUSTED_MAP_TILE_HOSTS',
  defaultValue: '',
);

/// Resolves the tile-host allowlist as a pure function of the build mode and
/// the define value so the rule itself is testable (same shape as
/// [compiledPreVpnGeoEdgeBases] and `compiledTrustedUpdateHosts`).
Set<String> compiledTrustedMapTileHosts({
  required bool isReleaseBuild,
  required bool definePresent,
  required String defineCsv,
}) {
  if (isReleaseBuild || !definePresent) {
    return parseTrustedUpdateHosts(_compiledTrustedMapTileHostsCsv);
  }
  return parseTrustedUpdateHosts(defineCsv);
}

Set<String> _resolveTrustedMapTileHosts() {
  assert(
    !(kReleaseMode && _hasTrustedMapTileHostsDefine),
    'WINS_TRUSTED_MAP_TILE_HOSTS is a debug/profile-only testing override. A '
    'release build accepts pre-tunnel map tiles only from the compiled '
    'first-party hosts; remove the dart-define from the release build command.',
  );
  final resolved = compiledTrustedMapTileHosts(
    isReleaseBuild: kReleaseMode,
    definePresent: _hasTrustedMapTileHostsDefine,
    defineCsv: _trustedMapTileHostsOverrideCsv,
  );
  if (!kReleaseMode &&
      _hasTrustedMapTileHostsDefine &&
      resolved.isNotEmpty) {
    debugPrint(
      'WINS_TRUSTED_MAP_TILE_HOSTS override active in a debug/profile build: '
      'pre-tunnel tile requests carrying approximate location may leave this '
      'device for $resolved. Testing only; release builds ignore the define '
      'entirely.',
    );
  }
  return resolved;
}

/// The only hosts this build will fetch pre-VPN map tiles from.
///
/// Matched by **equality**, never by suffix. A suffix wildcard buys no
/// resilience when the hostname it serves is effectively fixed -- the hub
/// serves tiles from a known, closed set of its own origins -- while a
/// bare-zone entry such as `.winsvpn.org` would accept any dangling subdomain
/// an attacker could get pointed at them. See
/// `docs/handoff/SPEED_TEST_ALLOWLIST_EXACT_HOSTS_20260806.md`.
///
/// Deliberately degrades to **empty** rather than to the compiled default when
/// the override is set but unusable, matching [preVpnGeoEdgeBases] and
/// `_trustedUpdateHosts`. Falling back would re-introduce the branded host
/// into precisely the build trying to remove it. Empty is also the safe
/// direction: [validMapTileUrlTemplate] then rejects every hub-advertised
/// template and the compiled `WINS_MAP_TILE_URL` endpoint keeps serving the
/// map, so the feature still works with strictly less hub authority.
final Set<String> trustedMapTileHosts = Set<String>.unmodifiable(
  // Deliberately the *same* bare-host screen the force-update allowlist uses,
  // rather than a second, weaker copy of it. In a release build this is
  // always the compiled first-party set (F-07); the define cannot widen it.
  _resolveTrustedMapTileHosts(),
);

/// Upper bound on a pre-VPN geo-scene body fetched by the stock client. A
/// scene is one small JSON object (well under 1 KiB from either source); a
/// body past this is refused while it streams, like the signed update notice
/// and the gateway-recovery record. A `.timeout` alone only stops the wait.
const int kMaxPreVpnGeoSceneBytes = 65536;

const List<String> preVpnGeoDirectSources = [
  'https://speed.cloudflare.com/meta',
];

List<Uri> buildPreVpnGeoSceneSources(Iterable<String> gatewayBases) {
  final sources = <Uri>[];
  final seen = <String>{};
  for (final raw in [...preVpnGeoEdgeBases, ...gatewayBases]) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null ||
        uri.scheme != 'https' ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasQuery ||
        uri.hasFragment) {
      continue;
    }
    final source = uri.replace(path: '/api/site/geo-scene');
    if (seen.add(source.toString())) sources.add(source);
  }
  for (final raw in preVpnGeoDirectSources) {
    final uri = Uri.parse(raw);
    if (seen.add(uri.toString())) sources.add(uri);
  }
  return sources;
}

Map<String, String> preVpnGeoRequestHeaders(Uri source) {
  if (source.host != 'speed.cloudflare.com' || source.path != '/meta') {
    return const {};
  }
  return const {
    'Accept': 'application/json',
    'Origin': 'https://speed.cloudflare.com',
    'Referer': 'https://speed.cloudflare.com/',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
  };
}

PreVpnGeoScene? parsePreVpnGeoScene(Object? raw) {
  if (raw is! Map) return null;
  final country = (raw['country'] ?? raw['country_code'] ?? '')
      .toString()
      .trim()
      .toUpperCase();
  if (!RegExp(r'^[A-Z]{2}$').hasMatch(country)) return null;

  var region = (raw['region'] ?? raw['region_code'] ?? '')
      .toString()
      .trim()
      .toUpperCase();
  if (region.startsWith('$country-')) region = region.substring(3);
  if (!RegExp(r'^[A-Z0-9-]{1,8}$').hasMatch(region)) region = '';

  final latitude = _finiteCoordinate(raw['latitude'] ?? raw['lat'], -85, 85);
  final longitude =
      _finiteCoordinate(raw['longitude'] ?? raw['lon'], -180, 180);
  final mapTile = _screenMapTileUrlTemplate(raw['map_tile_url_template']);
  final mapAttributionText = _safeMapAttributionText(
    raw['map_attribution_text'],
  );
  final mapAttributionUrl = _safeMapAttributionUrl(raw['map_attribution_url']);
  final hasCoordinatePair = latitude != null && longitude != null;
  return PreVpnGeoScene(
    countryCode: country,
    regionCode: region,
    latitude: hasCoordinatePair ? latitude : null,
    longitude: hasCoordinatePair ? longitude : null,
    mapTileUrlTemplate: mapTile.template,
    mapAttributionText: mapAttributionText,
    mapAttributionUrl: mapAttributionUrl,
    rejectedMapTileHost: mapTile.untrustedHost,
  );
}

String? _safeMapAttributionText(Object? raw) {
  final value = raw?.toString().trim() ?? '';
  if (value.isEmpty ||
      value.length > 120 ||
      value.contains(RegExp(r'[\x00-\x1F]'))) {
    return null;
  }
  return value;
}

/// The only hosts a hub-supplied map attribution link may point at
/// (F-12, final audit 2026-08-28).
///
/// The attribution URL is hub-controlled data that ends up launched in the
/// user's browser on tap, so a compromised hub could aim that tap at any
/// HTTPS origin it liked -- a credential-free but perfectly usable phishing
/// redirect. The legitimate set is closed by the nature of the map: tiles
/// are first-party, the DATA is OpenStreetMap's (whose license requires the
/// attribution link), and the offline fallback renders Natural Earth. No
/// hub response ever needs a fourth origin.
const Set<String> permittedMapAttributionHosts = <String>{
  'winsvpn.org',
  'www.winsvpn.org',
  'winsvpn.com',
  'www.winsvpn.com',
  'maps.winsvpn.org',
  'openstreetmap.org',
  'www.openstreetmap.org',
  'naturalearthdata.com',
  'www.naturalearthdata.com',
};

/// Screens the hub-supplied map attribution URL: credential-free HTTPS with
/// no query or fragment, AND a host in [permittedMapAttributionHosts].
/// Rejected values leave the caller on the compiled default attribution,
/// which links OpenStreetMap's license page.
String? _safeMapAttributionUrl(Object? raw) {
  final value = raw?.toString().trim() ?? '';
  final uri = Uri.tryParse(value);
  if (uri == null ||
      uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasQuery ||
      uri.hasFragment) {
    return null;
  }
  if (!permittedMapAttributionHosts.contains(uri.host.toLowerCase())) {
    return null;
  }
  return value;
}

/// Screens a hub-supplied `map_tile_url_template`, returning it only if this
/// build is willing to fetch tiles from it before the tunnel exists.
///
/// On top of the shape checks (the `{z}`/`{x}`/`{y}` tokens, credential-free
/// HTTPS, no query or fragment) this **pins the host** to
/// [trustedMapTileHosts] by equality and requires the standard 443 port --
/// the same screen `validatedAppUpdateUrl` applies to the force-update
/// download host, for the same reason. Returns null on any rejection, which
/// leaves the caller on the compiled `WINS_MAP_TILE_URL` endpoint.
String? validMapTileUrlTemplate(Object? raw) =>
    _screenMapTileUrlTemplate(raw).template;

/// The host of a template that was rejected *only* because it is not in
/// [trustedMapTileHosts]. Null when the value was accepted, and null when it
/// was rejected for any other reason -- a shape failure is not a host failure
/// and must not be reported as one.
///
/// Exists so a rejected tile URL fails loudly enough to diagnose. Exposes the
/// host alone and never the template, which can carry credentials in its
/// userInfo.
String? untrustedMapTileHost(Object? raw) =>
    _screenMapTileUrlTemplate(raw).untrustedHost;

({String? template, String? untrustedHost}) _screenMapTileUrlTemplate(
  Object? raw,
) {
  const rejected = (template: null, untrustedHost: null);
  final value = raw?.toString().trim() ?? '';
  if (!value.contains('{z}') ||
      !value.contains('{x}') ||
      !value.contains('{y}')) {
    return rejected;
  }
  final expanded = value
      .replaceAll('{z}', '8')
      .replaceAll('{x}', '128')
      .replaceAll('{y}', '128');
  final uri = Uri.tryParse(expanded);
  if (uri == null ||
      uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasQuery ||
      uri.hasFragment ||
      uri.port != 443) {
    return rejected;
  }
  final host = uri.host.toLowerCase();
  if (!trustedMapTileHosts.contains(host)) {
    return (template: null, untrustedHost: host);
  }
  return (template: value, untrustedHost: null);
}

double? _finiteCoordinate(Object? raw, double minimum, double maximum) {
  final value = raw is num ? raw.toDouble() : double.tryParse('$raw');
  if (value == null || !value.isFinite || value < minimum || value > maximum) {
    return null;
  }
  return value;
}

GeoCoordinate? preVpnRegionCenter(String countryCode, String regionCode) {
  final country = countryCode.trim().toUpperCase();
  var region = regionCode.trim().toUpperCase();
  if (region.startsWith('$country-')) region = region.substring(3);
  return _regionCenters['$country-$region'];
}

const Map<String, GeoCoordinate> _regionCenters = {
  'US-AL': GeoCoordinate(-86.8, 32.8),
  'US-AK': GeoCoordinate(-152.4, 64.2),
  'US-AZ': GeoCoordinate(-111.9, 34.3),
  'US-AR': GeoCoordinate(-92.4, 34.9),
  'US-CA': GeoCoordinate(-119.7, 37.2),
  'US-CO': GeoCoordinate(-105.5, 39.0),
  'US-CT': GeoCoordinate(-72.7, 41.6),
  'US-DE': GeoCoordinate(-75.5, 39.0),
  'US-DC': GeoCoordinate(-77.0, 38.9),
  'US-FL': GeoCoordinate(-81.7, 27.8),
  'US-GA': GeoCoordinate(-83.4, 32.7),
  'US-HI': GeoCoordinate(-157.5, 20.8),
  'US-ID': GeoCoordinate(-114.5, 44.2),
  'US-IL': GeoCoordinate(-89.2, 40.0),
  'US-IN': GeoCoordinate(-86.1, 39.9),
  'US-IA': GeoCoordinate(-93.5, 42.1),
  'US-KS': GeoCoordinate(-98.4, 38.5),
  'US-KY': GeoCoordinate(-84.9, 37.5),
  'US-LA': GeoCoordinate(-91.8, 31.0),
  'US-ME': GeoCoordinate(-69.2, 45.3),
  'US-MD': GeoCoordinate(-76.7, 39.0),
  'US-MA': GeoCoordinate(-71.8, 42.3),
  'US-MI': GeoCoordinate(-84.6, 44.3),
  'US-MN': GeoCoordinate(-94.3, 46.3),
  'US-MS': GeoCoordinate(-89.7, 32.7),
  'US-MO': GeoCoordinate(-92.5, 38.5),
  'US-MT': GeoCoordinate(-109.6, 47.0),
  'US-NE': GeoCoordinate(-99.8, 41.5),
  'US-NV': GeoCoordinate(-116.6, 39.3),
  'US-NH': GeoCoordinate(-71.6, 43.7),
  'US-NJ': GeoCoordinate(-74.5, 40.1),
  'US-NM': GeoCoordinate(-106.0, 34.4),
  'US-NY': GeoCoordinate(-75.5, 42.9),
  'US-NC': GeoCoordinate(-79.4, 35.5),
  'US-ND': GeoCoordinate(-100.5, 47.5),
  'US-OH': GeoCoordinate(-82.8, 40.3),
  'US-OK': GeoCoordinate(-97.5, 35.6),
  'US-OR': GeoCoordinate(-120.6, 44.0),
  'US-PA': GeoCoordinate(-77.7, 40.9),
  'US-RI': GeoCoordinate(-71.5, 41.7),
  'US-SC': GeoCoordinate(-80.9, 33.8),
  'US-SD': GeoCoordinate(-100.2, 44.4),
  'US-TN': GeoCoordinate(-86.4, 35.8),
  'US-TX': GeoCoordinate(-99.3, 31.4),
  'US-UT': GeoCoordinate(-111.7, 39.3),
  'US-VT': GeoCoordinate(-72.7, 44.1),
  'US-VA': GeoCoordinate(-78.7, 37.5),
  'US-WA': GeoCoordinate(-120.7, 47.4),
  'US-WV': GeoCoordinate(-80.6, 38.6),
  'US-WI': GeoCoordinate(-89.8, 44.6),
  'US-WY': GeoCoordinate(-107.6, 43.0),
  'US-PR': GeoCoordinate(-66.5, 18.2),
  'CA-AB': GeoCoordinate(-114.5, 54.0),
  'CA-BC': GeoCoordinate(-124.5, 54.0),
  'CA-MB': GeoCoordinate(-97.4, 54.8),
  'CA-NB': GeoCoordinate(-66.5, 46.6),
  'CA-NL': GeoCoordinate(-56.0, 53.0),
  'CA-NS': GeoCoordinate(-63.0, 45.1),
  'CA-NT': GeoCoordinate(-119.0, 64.0),
  'CA-NU': GeoCoordinate(-96.0, 70.0),
  'CA-ON': GeoCoordinate(-85.0, 50.0),
  'CA-PE': GeoCoordinate(-63.4, 46.4),
  'CA-QC': GeoCoordinate(-71.8, 52.0),
  'CA-SK': GeoCoordinate(-106.0, 54.0),
  'CA-YT': GeoCoordinate(-135.0, 64.0),
  'AU-ACT': GeoCoordinate(149.1, -35.3),
  'AU-NSW': GeoCoordinate(147.0, -32.0),
  'AU-NT': GeoCoordinate(133.0, -19.0),
  'AU-QLD': GeoCoordinate(144.5, -20.0),
  'AU-SA': GeoCoordinate(135.5, -30.0),
  'AU-TAS': GeoCoordinate(146.5, -42.0),
  'AU-VIC': GeoCoordinate(144.5, -37.0),
  'AU-WA': GeoCoordinate(121.0, -25.0),
};
