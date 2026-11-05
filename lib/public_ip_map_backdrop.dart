import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:http/http.dart' as http;
import 'package:http/retry.dart' as http_retry;
import 'package:latlong2/latlong.dart';

import 'no_redirect_http.dart';
import 'offline_world_map_backdrop.dart';

/// A local map centered on coarse public-IP geolocation.
///
/// Apple platforms use MapKit through [OfflineWorldMapBackdrop]. Android,
/// Windows, and Linux use a labeled OpenStreetMap-derived tile layer through
/// the first-party cached map endpoint. The bundled Natural Earth asset
/// remains the fail-closed fallback until a valid coarse public-IP coordinate
/// pair and the first-party tile service are available.
class PublicIpMapBackdrop extends StatefulWidget {
  static const double targetRadiusMiles = 50;
  static const double _metersPerMile = 1609.344;
  static const double _equatorialMetersPerPixel = 156543.03392804097;
  static const String defaultTileUrlTemplate =
      'https://www.winsvpn.org/api/site/map-tile/{z}/{x}/{y}.png';

  // F-07 (final audit 2026-08-28): the tile endpoint is fetched PRE-TUNNEL,
  // and the tile URL itself encodes the user's approximate location, so in a
  // release build it is a property of the signed artifact -- exactly like the
  // geo edge bases (B-APP-006) and the trusted update hosts (B-APP-002).
  // `WINS_MAP_TILE_URL` is ignored entirely in release; debug/profile builds
  // keep it as a testing override.
  static const bool _hasMapTileUrlDefine =
      bool.hasEnvironment('WINS_MAP_TILE_URL');
  static const String _mapTileUrlDefineValue = String.fromEnvironment(
    'WINS_MAP_TILE_URL',
    defaultValue: '',
  );

  /// Resolves the compiled tile endpoint as a pure function of the build
  /// mode and the define value so the rule itself is testable.
  static String compiledMapTileUrlTemplate({
    required bool isReleaseBuild,
    required bool definePresent,
    required String defineValue,
  }) {
    if (isReleaseBuild || !definePresent) {
      return defaultTileUrlTemplate;
    }
    final value = defineValue.trim();
    return value.isEmpty ? defaultTileUrlTemplate : value;
  }

  static String _resolveConfiguredTileUrlTemplate() {
    assert(
      !(kReleaseMode && _hasMapTileUrlDefine),
      'WINS_MAP_TILE_URL is a debug/profile-only testing override. A release '
      'build fetches pre-tunnel map tiles only from the compiled first-party '
      'endpoint; remove the dart-define from the release build command.',
    );
    final resolved = compiledMapTileUrlTemplate(
      isReleaseBuild: kReleaseMode,
      definePresent: _hasMapTileUrlDefine,
      defineValue: _mapTileUrlDefineValue,
    );
    if (!kReleaseMode &&
        _hasMapTileUrlDefine &&
        resolved != defaultTileUrlTemplate) {
      debugPrint(
        'WINS_MAP_TILE_URL override active in a debug/profile build: '
        'pre-tunnel tile requests carrying approximate location will leave '
        'this device for $resolved. Testing only; release builds ignore the '
        'define entirely.',
      );
    }
    return resolved;
  }

  /// The tile endpoint this build asks before the tunnel exists. In a
  /// release build this is exactly [defaultTileUrlTemplate]; the
  /// `WINS_MAP_TILE_URL` define cannot change it (F-07).
  static final String configuredTileUrlTemplate =
      _resolveConfiguredTileUrlTemplate();

  static const String tileRequestIdentity =
      "WinsVPN (+https://winsvpn.org; contact: support@winsvpn.org)";

  const PublicIpMapBackdrop({
    super.key,
    required this.countryCode,
    this.regionCode = '',
    this.latitude,
    this.longitude,
    this.onAttributionTap,
    this.onOfflineAttributionTap,
    this.tileUrlTemplate = defaultTileUrlTemplate,
    this.attributionText = '© OpenStreetMap contributors',
    this.tileProvider,
  });

  final String countryCode;
  final String regionCode;
  final double? latitude;
  final double? longitude;
  final VoidCallback? onAttributionTap;
  final VoidCallback? onOfflineAttributionTap;
  final String tileUrlTemplate;
  final String attributionText;
  final TileProvider? tileProvider;

  @override
  State<PublicIpMapBackdrop> createState() => _PublicIpMapBackdropState();

  static bool isValidTileUrlTemplate(String value) {
    if (!value.contains('{z}') ||
        !value.contains('{x}') ||
        !value.contains('{y}')) {
      return false;
    }
    final expanded = value
        .replaceAll('{z}', '8')
        .replaceAll('{x}', '128')
        .replaceAll('{y}', '128');
    final uri = Uri.tryParse(expanded);
    return uri != null &&
        uri.scheme == 'https' &&
        uri.host.isNotEmpty &&
        uri.userInfo.isEmpty &&
        !uri.hasQuery &&
        !uri.hasFragment;
  }

  /// Returns the privacy-preserving fallback for a managed map provider.
  ///
  /// A failure of the first-party endpoint must fall back to the bundled map,
  /// never to a direct community tile request from the customer's IP.
  static String? fallbackTileUrlTemplate(String value) =>
      value == defaultTileUrlTemplate ? null : defaultTileUrlTemplate;

  static double targetZoomForRadius({
    required Size viewport,
    required double latitude,
    double radiusMiles = targetRadiusMiles,
  }) {
    final shortestSide =
        math.max(1.0, math.min(viewport.width, viewport.height));
    final diameterMeters = math.max(1.0, radiusMiles) * 2 * _metersPerMile;
    final targetMetersPerPixel = diameterMeters / shortestSide;
    final latitudeFactor = math.max(
      0.01,
      math.cos(latitude.clamp(-85.0, 85.0) * math.pi / 180).abs(),
    );
    final zoom = math.log(
          (_equatorialMetersPerPixel * latitudeFactor) / targetMetersPerPixel,
        ) /
        math.ln2;
    return zoom.clamp(2.0, 18.0).toDouble();
  }

  static double visibleRadiusMiles({
    required Size viewport,
    required double latitude,
    required double zoom,
  }) {
    final shortestSide =
        math.max(1.0, math.min(viewport.width, viewport.height));
    final latitudeFactor = math.max(
      0.01,
      math.cos(latitude.clamp(-85.0, 85.0) * math.pi / 180).abs(),
    );
    final metersPerPixel =
        _equatorialMetersPerPixel * latitudeFactor / math.pow(2, zoom);
    return (shortestSide / 2) * metersPerPixel / _metersPerMile;
  }
}

class _PublicIpMapBackdropState extends State<PublicIpMapBackdrop> {
  bool _usingFirstPartyFallback = false;
  bool _tilesUnavailable = false;
  bool _fallbackScheduled = false;

  // F-06 (final audit 2026-08-28): tile requests are pre-tunnel, so a
  // redirect on the FIRST hop must not be able to move them to an arbitrary
  // host -- package:http and dart:io both follow redirects by default, which
  // made the compiled/hub-advertised tile host pin enforceable only on the
  // initial URL. The tile client never follows a redirect: a 3xx fails the
  // tile, and the widget's existing fallback path takes over (first-party
  // endpoint, then the offline map). RetryClient is kept: it is flutter_map's
  // own default and only retries transient server errors; a 3xx is returned
  // to flutter_map as-is.
  http.Client? _tileHttpClient;

  @override
  void initState() {
    super.initState();
    _tileHttpClient = http_retry.RetryClient(NoRedirectClient());
  }

  @override
  void dispose() {
    _tileHttpClient?.close();
    _tileHttpClient = null;
    super.dispose();
  }

  bool get _hasCoordinates {
    final latitude = widget.latitude;
    final longitude = widget.longitude;
    return latitude != null &&
        longitude != null &&
        latitude.isFinite &&
        longitude.isFinite &&
        latitude >= -85 &&
        latitude <= 85 &&
        longitude >= -180 &&
        longitude <= 180;
  }

  Widget _offlineFallback() => OfflineWorldMapBackdrop(
        countryCode: widget.countryCode,
        regionCode: widget.regionCode,
        latitude: widget.latitude,
        longitude: widget.longitude,
        onAttributionTap:
            widget.onOfflineAttributionTap ?? widget.onAttributionTap,
      );

  String get _activeTileUrlTemplate => _usingFirstPartyFallback
      ? PublicIpMapBackdrop.defaultTileUrlTemplate
      : widget.tileUrlTemplate;

  void _handleTileError() {
    if (_fallbackScheduled || _tilesUnavailable) return;
    final fallback = PublicIpMapBackdrop.fallbackTileUrlTemplate(
      _activeTileUrlTemplate,
    );
    _fallbackScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _fallbackScheduled = false;
      if (!mounted || _tilesUnavailable) return;
      setState(() {
        if (fallback == null) {
          _tilesUnavailable = true;
        } else {
          _usingFirstPartyFallback = true;
        }
      });
    });
  }

  @override
  void didUpdateWidget(covariant PublicIpMapBackdrop oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.tileUrlTemplate != widget.tileUrlTemplate ||
        oldWidget.latitude != widget.latitude ||
        oldWidget.longitude != widget.longitude) {
      _usingFirstPartyFallback = false;
      _tilesUnavailable = false;
      _fallbackScheduled = false;
    }
  }

  Widget _approximateLocationMarker() => Semantics(
        label: 'Your approximate network location',
        child: IgnorePointer(
          child: SizedBox(
            key: const Key('approximate-location-marker'),
            width: 26,
            height: 26,
            child: Stack(
              alignment: Alignment.center,
              children: [
                Container(
                  width: 26,
                  height: 26,
                  decoration: BoxDecoration(
                    color: const Color(0x22276EF1),
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: const Color(0x66276EF1),
                      width: 1,
                    ),
                  ),
                ),
                Container(
                  width: 14,
                  height: 14,
                  decoration: BoxDecoration(
                    color: const Color(0xFF276EF1),
                    shape: BoxShape.circle,
                    border: Border.all(color: Colors.white, width: 2),
                    boxShadow: const [
                      BoxShadow(
                        color: Color(0x55276EF1),
                        blurRadius: 4,
                        spreadRadius: 1,
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      );

  @override
  Widget build(BuildContext context) {
    return KeyedSubtree(
      key: const Key('public-ip-local-map'),
      child: Builder(
        builder: (context) {
          if (!_hasCoordinates) {
            return _offlineFallback();
          }
          // This branch deliberately precedes all non-Apple tile-map setup.
          // iOS and macOS render only the native MapKit platform view.
          if (Platform.isIOS || Platform.isMacOS) {
            return OfflineWorldMapBackdrop(
              countryCode: widget.countryCode,
              regionCode: widget.regionCode,
              latitude: widget.latitude,
              longitude: widget.longitude,
              radiusMiles: PublicIpMapBackdrop.targetRadiusMiles,
              onAttributionTap: widget.onAttributionTap,
            );
          }
          if (_tilesUnavailable) {
            return _offlineFallback();
          }
          if (!PublicIpMapBackdrop.isValidTileUrlTemplate(
            widget.tileUrlTemplate,
          )) {
            return _offlineFallback();
          }

          final center = LatLng(widget.latitude!, widget.longitude!);
          return LayoutBuilder(
            builder: (context, constraints) {
              final viewport = Size(
                math.max(1, constraints.maxWidth),
                math.max(1, constraints.maxHeight),
              );
              final zoom = PublicIpMapBackdrop.targetZoomForRadius(
                viewport: viewport,
                latitude: widget.latitude!,
              );
              return ColoredBox(
                color: const Color(0xFFD9E6EC),
                child: Stack(
                  fit: StackFit.expand,
                  children: [
                    FlutterMap(
                      key: const Key('public-ip-street-map'),
                      options: MapOptions(
                        initialCenter: center,
                        initialZoom: zoom,
                        minZoom: 3,
                        maxZoom: 19,
                        keepAlive: true,
                      ),
                      children: [
                        TileLayer(
                          key: ValueKey(
                            'public-ip-city-label-tiles-'
                            '${_usingFirstPartyFallback ? 'first-party-fallback' : 'primary'}',
                          ),
                          urlTemplate: _activeTileUrlTemplate,
                          tileProvider: widget.tileProvider ??
                              (_tileHttpClient == null
                                  ? null
                                  : NetworkTileProvider(
                                      httpClient: _tileHttpClient,
                                    )),
                          userAgentPackageName:
                              PublicIpMapBackdrop.tileRequestIdentity,
                          maxNativeZoom: 19,
                          maxZoom: 19,
                          keepBuffer: 2,
                          panBuffer: 1,
                          errorTileCallback: (_, __, ___) {
                            _handleTileError();
                          },
                        ),
                        CircleLayer(
                          circles: [
                            CircleMarker(
                              key: const Key('public-ip-50-mile-radius'),
                              point: center,
                              radius: PublicIpMapBackdrop.targetRadiusMiles *
                                  PublicIpMapBackdrop._metersPerMile,
                              useRadiusInMeter: true,
                              color: const Color(0x10276EF1),
                              borderColor: const Color(0x55276EF1),
                              borderStrokeWidth: 1,
                            ),
                          ],
                        ),
                        MarkerLayer(
                          markers: [
                            Marker(
                              point: center,
                              width: 26,
                              height: 26,
                              child: _approximateLocationMarker(),
                            ),
                          ],
                        ),
                      ],
                    ),
                    const Positioned(
                      left: 10,
                      bottom: 10,
                      child: IgnorePointer(
                        child: DecoratedBox(
                          decoration: BoxDecoration(
                            color: Color(0xE6FFFFFF),
                            borderRadius: BorderRadius.all(Radius.circular(5)),
                          ),
                          child: Padding(
                            padding: EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 5,
                            ),
                            child: Text(
                              'Approximate IP location',
                              style: TextStyle(
                                color: Color(0xFF25313A),
                                fontSize: 10,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                    Positioned(
                      right: 8,
                      bottom: 8,
                      child: Material(
                        color: const Color(0xE6FFFFFF),
                        borderRadius: BorderRadius.circular(4),
                        child: InkWell(
                          onTap: widget.onAttributionTap,
                          borderRadius: BorderRadius.circular(4),
                          child: Padding(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 7,
                              vertical: 4,
                            ),
                            child: Text(
                              widget.attributionText,
                              style: const TextStyle(
                                color: Color(0xFF25313A),
                                fontSize: 10,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              );
            },
          );
        },
      ),
    );
  }
}
