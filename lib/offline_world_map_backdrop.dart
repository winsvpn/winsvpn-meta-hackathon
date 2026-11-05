import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class OfflineWorldMapBackdrop extends StatefulWidget {
  static const double defaultRadiusMiles = 50;
  static const double metersPerMile = 1609.344;

  const OfflineWorldMapBackdrop({
    super.key,
    required this.countryCode,
    this.regionCode = '',
    this.latitude,
    this.longitude,
    this.onAttributionTap,
    this.showAttribution = true,
    this.radiusMiles = defaultRadiusMiles,
  });

  final String countryCode;
  final String regionCode;
  final double? latitude;
  final double? longitude;
  final VoidCallback? onAttributionTap;
  final bool showAttribution;
  final double radiusMiles;

  @override
  State<OfflineWorldMapBackdrop> createState() =>
      _OfflineWorldMapBackdropState();
}

class _OfflineWorldMapBackdropState extends State<OfflineWorldMapBackdrop> {
  static const String _mapAsset = 'assets/wallpaper/offline_world_map.webp';
  static const Map<String, _GeoPoint> _countryCenters = {
    'US': _GeoPoint(39.0, -98.0),
    'MM': _GeoPoint(21.9, 96.0),
    'DE': _GeoPoint(51.2, 10.5),
    'FR': _GeoPoint(46.2, 2.2),
    'GB': _GeoPoint(54.0, -2.7),
    'UK': _GeoPoint(54.0, -2.7),
    'CA': _GeoPoint(56.1, -106.3),
    'AU': _GeoPoint(-25.0, 134.0),
    'SG': _GeoPoint(1.35, 103.8),
    'JP': _GeoPoint(36.2, 138.0),
    'KR': _GeoPoint(36.5, 127.8),
    'IN': _GeoPoint(22.0, 78.9),
    'TH': _GeoPoint(15.8, 101.0),
    'MY': _GeoPoint(4.2, 102.0),
    'PH': _GeoPoint(12.9, 122.9),
    'ID': _GeoPoint(-0.8, 113.9),
    'BR': _GeoPoint(-14.2, -51.9),
    'MX': _GeoPoint(23.6, -102.6),
  };

  final TransformationController _transformationController =
      TransformationController();
  String? _appliedTargetKey;
  Size? _appliedViewport;
  bool _transformScheduled = false;

  bool get _hasCoordinates {
    final latitude = widget.latitude;
    final longitude = widget.longitude;
    return latitude != null &&
        longitude != null &&
        latitude.isFinite &&
        longitude.isFinite;
  }

  bool get _hasApproximateLocation =>
      _hasCoordinates || widget.countryCode.trim().isNotEmpty;

  _GeoPoint get _center {
    if (_hasCoordinates) {
      return _GeoPoint(
        widget.latitude!.clamp(-90.0, 90.0).toDouble(),
        widget.longitude!.clamp(-180.0, 180.0).toDouble(),
      );
    }
    return _countryCenters[widget.countryCode.trim().toUpperCase()] ??
        const _GeoPoint(12, 0);
  }

  double _initialScale(Size viewport, Size mapSize) {
    final horizontalCoverage = viewport.width / mapSize.width;
    if (_hasCoordinates) {
      // Keep the same local-area span that reads well on iPad across narrow
      // phones and wide desktop windows.
      return (horizontalCoverage * 360 / 34).clamp(1.0, 10.0).toDouble();
    }
    if (_hasApproximateLocation) {
      return (horizontalCoverage * 360 / 90).clamp(2.75, 5.0).toDouble();
    }
    return (horizontalCoverage * 360 / 160).clamp(1.35, 2.5).toDouble();
  }

  String get _targetKey =>
      '${widget.countryCode}|${widget.regionCode}|${widget.latitude}|${widget.longitude}';

  @override
  void didUpdateWidget(covariant OfflineWorldMapBackdrop oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.countryCode != widget.countryCode ||
        oldWidget.regionCode != widget.regionCode ||
        oldWidget.latitude != widget.latitude ||
        oldWidget.longitude != widget.longitude) {
      _appliedTargetKey = null;
    }
  }

  @override
  void dispose() {
    _transformationController.dispose();
    super.dispose();
  }

  void _scheduleInitialTransform(Size viewport, Size mapSize) {
    if (_transformScheduled ||
        (_appliedTargetKey == _targetKey && _appliedViewport == viewport)) {
      return;
    }
    _transformScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _transformScheduled = false;
      if (!mounted) return;

      final center = _center;
      final scale = _initialScale(viewport, mapSize);
      final pointX = (center.longitude + 180.0) / 360.0 * mapSize.width;
      final pointY = (90.0 - center.latitude) / 180.0 * mapSize.height;
      final minimumX = viewport.width - mapSize.width * scale;
      final minimumY = viewport.height - mapSize.height * scale;
      final translateX =
          (viewport.width / 2 - pointX * scale).clamp(minimumX, 0.0);
      final translateY =
          (viewport.height / 2 - pointY * scale).clamp(minimumY, 0.0);

      _transformationController.value = Matrix4.identity()
        ..setEntry(0, 0, scale)
        ..setEntry(1, 1, scale)
        ..setEntry(2, 2, scale)
        ..setEntry(0, 3, translateX)
        ..setEntry(1, 3, translateY);
      _appliedTargetKey = _targetKey;
      _appliedViewport = viewport;
    });
  }

  @override
  Widget build(BuildContext context) {
    final center = _center;
    if (_hasCoordinates && (Platform.isIOS || Platform.isMacOS)) {
      final creationParams = <String, dynamic>{
        'latitude': center.latitude,
        'longitude': center.longitude,
        'radiusMeters':
            widget.radiusMiles * OfflineWorldMapBackdrop.metersPerMile,
      };
      final mapKey = ValueKey(
        'apple-map-${center.latitude.toStringAsFixed(4)}-'
        '${center.longitude.toStringAsFixed(4)}',
      );
      if (Platform.isIOS) {
        return Semantics(
          label: 'Your approximate network location',
          child: UiKitView(
            key: mapKey,
            viewType: 'winsvpn/apple-map',
            creationParams: creationParams,
            creationParamsCodec: const StandardMessageCodec(),
          ),
        );
      }
      return Semantics(
        label: 'Your approximate network location',
        child: AppKitView(
          key: mapKey,
          viewType: 'winsvpn/apple-map',
          creationParams: creationParams,
          creationParamsCodec: const StandardMessageCodec(),
        ),
      );
    }
    return ColoredBox(
      color: const Color(0xFF8DC5DE),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final viewport = Size(constraints.maxWidth, constraints.maxHeight);
          final mapWidth = math.max(viewport.width, viewport.height * 2);
          final mapSize = Size(mapWidth, mapWidth / 2);
          final markerX = (center.longitude + 180.0) / 360.0 * mapSize.width;
          final markerY = (90.0 - center.latitude) / 180.0 * mapSize.height;
          _scheduleInitialTransform(viewport, mapSize);

          return Stack(
            fit: StackFit.expand,
            children: [
              InteractiveViewer(
                transformationController: _transformationController,
                constrained: false,
                minScale: 1,
                maxScale: 10,
                boundaryMargin: EdgeInsets.zero,
                clipBehavior: Clip.hardEdge,
                child: SizedBox.fromSize(
                  size: mapSize,
                  child: Stack(
                    fit: StackFit.expand,
                    children: [
                      Image.asset(
                        _mapAsset,
                        fit: BoxFit.fill,
                        filterQuality: FilterQuality.high,
                      ),
                    ],
                  ),
                ),
              ),
              if (_hasApproximateLocation)
                AnimatedBuilder(
                  animation: _transformationController,
                  builder: (context, child) {
                    final markerPoint = MatrixUtils.transformPoint(
                      _transformationController.value,
                      Offset(markerX, markerY),
                    );
                    return Positioned(
                      left: markerPoint.dx - 13,
                      top: markerPoint.dy - 13,
                      width: 26,
                      height: 26,
                      child: child!,
                    );
                  },
                  child: Semantics(
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
                                border: Border.all(
                                  color: Colors.white,
                                  width: 2,
                                ),
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
                  ),
                ),
              if (widget.showAttribution)
                Positioned(
                  right: 8,
                  bottom: 8,
                  child: Material(
                    color: const Color(0xDDF7FAFC),
                    borderRadius: BorderRadius.circular(4),
                    child: InkWell(
                      onTap: widget.onAttributionTap,
                      borderRadius: BorderRadius.circular(4),
                      child: const Padding(
                        padding:
                            EdgeInsets.symmetric(horizontal: 7, vertical: 4),
                        child: Text(
                          'Natural Earth (public domain)',
                          style: TextStyle(
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
          );
        },
      ),
    );
  }
}

class _GeoPoint {
  const _GeoPoint(this.latitude, this.longitude);

  final double latitude;
  final double longitude;
}
